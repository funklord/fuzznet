/*
 * A fuzz harness for a note as another host wrote it, `notes/note.c`: its
 * META, a record's content, and its PAYLOAD, a blob's plaintext once
 * opened (sec 514). A note shared to a contact or a group, and every note
 * a user's other hosts write, arrives from a writer this host does not
 * control, and the listing walks its labels and a list's items.
 *
 * Each case makes a random meta and a random payload -- a title, a text
 * (a checklist's items half the time) and labels -- writes both, and bends
 * them as line_fuzz does. Every open and every walk reads a copy that ends
 * where an unreadable page begins, so a read past the end faults in any
 * build.
 *
 * THE PROPERTIES:
 *   1. A META opens as written, and a bent one that opens writes back as
 *      exactly its bytes: one encoding.
 *   2. A PAYLOAD opens as written, and a bent one that opens writes back as
 *      exactly its bytes, its three lengths tiling it.
 *   3. THE WALKS END: a payload that opens has every label and every item
 *      walked within its own bytes, the items stopping clean or refused.
 *
 * FLOORS: a run in which no bent meta or payload opened, or none was
 * refused, has not tested what it claims.
 */

#include "../note.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define FUZZ_DEFAULT_CASES 10000u
#define FUZZ_MIN_CASES 1000u
#define PAYLOAD_CAP 4096u

static int failures;

static void fail(const char *what, unsigned long c)
{
	failures++;
	if (failures <= 10)
		fprintf(stderr, "  FAIL note_fuzz.c: case %lu: %s\n", c, what);
}

static uint64_t state = 0x510e527fade682d1ull;

static uint64_t next(void)
{
	state ^= state << 13;
	state ^= state >> 7;
	state ^= state << 17;
	return state;
}

static void fill(uint8_t *b, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		b[i] = (uint8_t)next();
}

/* Bend `b`, `len` bytes of `cap`, and return its new length; never the
 * bytes unchanged. */
static size_t bend(uint8_t *b, size_t len, size_t cap)
{
	static uint8_t was[PAYLOAD_CAP + 64u];
	size_t k, i, j;
	uint8_t t;

	memcpy(was, b, len);
	switch (next() % 5u) {
	case 1:
		if (len)
			return (size_t)(next() % len);
		break;
	case 2:
		if (len < cap) {
			for (k = 1u + next() % 8u; k > 0u && len < cap; k--)
				b[len++] = (uint8_t)next();
			return len;
		}
		break;
	case 3:
		if (len >= 8u) {
			i = next() % (len - 4u);
			for (j = 0; j < 4u && i + j + 4u < len && b[i + j] == b[i + j + 4u]; j++)
				;
			if (j < 4u && i + j + 4u < len) {
				memmove(b + i + 4u, b + i, len - i - 4u);
				return len;
			}
		}
		break;
	case 4:
		if (len >= 2u) {
			i = next() % len;
			j = next() % len;
			if (b[i] != b[j]) {
				t = b[i];
				b[i] = b[j];
				b[j] = t;
				return len;
			}
		}
		break;
	default:
		break;
	}
	for (k = 1u + next() % 2u; k > 0u && len; k--)
		b[next() % len] ^= (uint8_t)(1u << (next() % 8u));
	if (len && memcmp(b, was, len) == 0)
		b[next() % len] ^= 0x01u;
	return len;
}

/* ---- the page an over-read meets ---------------------------------------- */

static uint8_t *guarded_end;

static void guard(void)
{
	long page = sysconf(_SC_PAGESIZE);
	size_t room;
	uint8_t *map;

	if (page <= 0)
		abort();
	room = ((PAYLOAD_CAP + 64u + (size_t)page - 1u) / (size_t)page) * (size_t)page;
	map = mmap(NULL, room + (size_t)page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
	           -1, 0);
	if (map == MAP_FAILED || mprotect(map + room, (size_t)page, PROT_NONE) != 0)
		abort();
	guarded_end = map + room;
}

static const uint8_t *guarded(const uint8_t *bytes, size_t len)
{
	memcpy(guarded_end - len, bytes, len);
	return guarded_end - len;
}

/* EVERY LABEL AND ITEM of `n`, each within the `len` bytes at `base`: 0
 * when one lies outside them, or the walk did not end. */
static int walks_within(const fzn_note_t *n, const uint8_t *base, size_t len)
{
	size_t i, count = fzn_note_label_count(n), cursor = 0, steps = 0;
	const uint8_t *l;
	size_t l_len;
	fzn_note_item_t item;
	fzn_note_err_t err;

	for (i = 0; i < count; i++) {
		if (fzn_note_label(n, i, &l, &l_len) != FZN_NOTE_OK)
			return 0;
		if (l < base || l + l_len > base + len)
			return 0;
	}
	while ((err = fzn_note_item_next(n, &cursor, &item)) == FZN_NOTE_OK) {
		if (item.text < base || item.text + item.text_len > base + len || ++steps > len)
			return 0;
	}
	return err == FZN_NOTE_ERR_SHORT || err == FZN_NOTE_ERR_PARTITION;
}

int main(int argc, char **argv)
{
	static uint8_t meta[FZN_NOTE_META_LEN + 64u], again[PAYLOAD_CAP + 64u];
	static uint8_t payload[PAYLOAD_CAP + 64u], text[2048], title[FZN_NOTE_TITLE_MAX];
	static uint8_t labels[256];
	unsigned long cases = FUZZ_DEFAULT_CASES, c;
	unsigned long meta_opened = 0, meta_refused = 0, payload_opened = 0, payload_refused = 0;

	if (argc > 1)
		cases = strtoul(argv[1], NULL, 10);
	if (cases < FUZZ_MIN_CASES)
		cases = FUZZ_MIN_CASES;
	guard();

	for (c = 0; c < cases; c++) {
		fzn_note_meta_t m, mback;
		fzn_note_t n, nback;
		uint16_t type = (uint16_t)(1u + next() % 4u);
		size_t len = 0, k, i, again_len = 0, text_len = 0, labels_len = 0;

		/* 1: A META. */
		memset(&m, 0, sizeof(m));
		m.created_at_ms = next() >> (next() % 64u);
		m.edited_at_ms = next() >> (next() % 64u);
		m.colour = (uint32_t)next();
		m.flags = (uint8_t)(next() & FZN_NOTE_META_FLAGS_KNOWN);
		fill(m.content.root, sizeof(m.content.root));
		fill(m.content.key, sizeof(m.content.key));
		m.content.length = FZN_NOTE_PAYLOAD_HEADER_LEN
		                   + next() % (FZN_NOTE_PAYLOAD_MAX - FZN_NOTE_PAYLOAD_HEADER_LEN + 1u);
		if (fzn_note_meta_write(&m, meta) != FZN_NOTE_OK
		    || fzn_note_meta_open(type, guarded(meta, FZN_NOTE_META_LEN), FZN_NOTE_META_LEN,
		                          &mback)
		               != FZN_NOTE_OK
		    || memcmp(&mback.content, &m.content, sizeof(m.content)) != 0
		    || mback.flags != m.flags || mback.colour != m.colour
		    || mback.created_at_ms != m.created_at_ms || mback.edited_at_ms != m.edited_at_ms)
			fail("a meta did not open as written", c);
		k = bend(meta, FZN_NOTE_META_LEN, sizeof(meta));
		if (fzn_note_meta_open(type, guarded(meta, k), k, &mback) != FZN_NOTE_OK) {
			meta_refused++;
		} else {
			meta_opened++;
			if (k != FZN_NOTE_META_LEN || fzn_note_meta_write(&mback, again) != FZN_NOTE_OK
			    || memcmp(again, meta, FZN_NOTE_META_LEN) != 0)
				fail("a bent meta opened that is not the one encoding of its fields", c);
		}

		/* 2: A PAYLOAD -- a list's items half the time -- and labels. */
		memset(&n, 0, sizeof(n));
		n.title_len = (size_t)(next() % 64u);
		fill(title, n.title_len);
		n.title = title;
		if (next() & 1u) {
			size_t items = (size_t)(next() % 8u);

			for (i = 0; i < items; i++) {
				uint8_t t[40];
				size_t t_len = (size_t)(next() % sizeof(t));

				fill(t, t_len);
				(void)fzn_note_item_put(text, sizeof(text), &text_len, (uint8_t)(next() & 1u),
				                        t, t_len);
			}
		} else {
			text_len = (size_t)(next() % 512u);
			fill(text, text_len);
		}
		n.text = text;
		n.text_len = text_len;
		for (i = (size_t)(next() % 4u); i > 0; i--) {
			size_t one = 1u + (size_t)(next() % 12u);

			if (labels_len + one + 1u > sizeof(labels))
				break;
			if (labels_len)
				labels[labels_len++] = 0u;
			for (k = 0; k < one; k++)
				labels[labels_len++] = (uint8_t)('a' + next() % 26u);
		}
		n.labels = labels;
		n.labels_len = labels_len;
		if (fzn_note_payload_write(&n, payload, PAYLOAD_CAP, &len) != FZN_NOTE_OK) {
			fail("a payload made would not write", c);
			continue;
		}
		{
			const uint8_t *at = guarded(payload, len);

			if (fzn_note_payload_open(at, len, &nback) != FZN_NOTE_OK
			    || nback.title_len != n.title_len || nback.text_len != n.text_len
			    || nback.labels_len != n.labels_len
			    || memcmp(nback.text, n.text, n.text_len) != 0 || !walks_within(&nback, at, len))
				fail("a payload did not open as written, or its walks left it", c);
		}
		k = bend(payload, len, PAYLOAD_CAP);
		{
			const uint8_t *at = guarded(payload, k);

			if (fzn_note_payload_open(at, k, &nback) != FZN_NOTE_OK) {
				payload_refused++;
				continue;
			}
			payload_opened++;
			if (!walks_within(&nback, at, k))
				fail("a bent payload opened whose labels or items left its bytes", c);
			if (fzn_note_payload_write(&nback, again, PAYLOAD_CAP, &again_len) != FZN_NOTE_OK
			    || again_len != k || memcmp(again, payload, k) != 0)
				fail("a bent payload opened that is not the one encoding of its fields", c);
		}
	}

	if (meta_opened == 0u || meta_refused == 0u)
		fail("FLOOR: no bent meta opened, or none was refused", cases);
	if (payload_opened == 0u || payload_refused == 0u)
		fail("FLOOR: no bent payload opened, or none was refused", cases);
	printf("note_fuzz: %lu cases, bent metas %lu opened %lu refused, bent payloads %lu opened "
	       "%lu refused, %d failure(s)\n",
	       cases, meta_opened, meta_refused, payload_opened, payload_refused, failures);
	return failures ? 1 : 0;
}
