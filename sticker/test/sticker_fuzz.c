/*
 * A fuzz harness for what a contact sends of a sticker, `sticker/pack.c`:
 * the pack, a file that arrives from them (sec 797), and the reference a
 * line's text carries (sec 680). Both are read on this host from bytes a
 * contact wrote.
 *
 * Each case bends a pack built from a spec of three stickers, and a
 * reference made at random, as line_fuzz bends: bits flipped, cut short,
 * grown, a slice repeated or two bytes swapped. Every open and parse reads
 * a copy that ends where an unreadable page begins, so a read past the
 * end faults in any build.
 *
 * THE PROPERTIES:
 *   1. A PACK OPENS AS BUILT, and a bent one that opens is one building
 *      accepts again: its manifest, with its art and sound taken from the
 *      data area it opened with, builds -- so opening keeps no rule that
 *      building does not, and every offset it took lies inside the area.
 *   2. A REFERENCE PARSES AS FORMATTED, and a bent `fzn:` one that parses
 *      is the one spelling of its parse, its hex read as lower case.
 *
 * FLOORS: a run in which no bent pack opened or none was refused, or no
 * bent reference parsed or none was refused, has not tested what it
 * claims.
 */

#include "../pack.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define FUZZ_DEFAULT_CASES 20000u
#define FUZZ_MIN_CASES 2000u
#define PACK_CAP 4096u

/* Where a reference's two hex fields lie: after "fzn:sticker/", and after
 * the first and its "/". */
#define REF_ROOT_AT 12u
#define REF_HEX_END (REF_ROOT_AT + 2u * FZN_STICKER_ROOT_LEN + 1u + 2u * FZN_STICKER_KEY_LEN)

static int failures;

static void fail(const char *what, unsigned long c)
{
	failures++;
	if (failures <= 10)
		fprintf(stderr, "  FAIL sticker_fuzz.c: case %lu: %s\n", c, what);
}

static uint64_t state = 0x3c6ef372fe94f82bull;

static uint64_t next(void)
{
	state ^= state << 13;
	state ^= state >> 7;
	state ^= state << 17;
	return state;
}

/* Bend `b`, `len` bytes of `cap`, and return its new length; never the
 * bytes unchanged. */
static size_t bend(uint8_t *b, size_t len, size_t cap)
{
	static uint8_t was[PACK_CAP + 64u];
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
	/* AS MANY PAGES AS THE LONGEST COPY NEEDS, then the one nobody reads. */
	room = ((PACK_CAP + 64u + (size_t)page - 1u) / (size_t)page) * (size_t)page;
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

/* ---- the pack ------------------------------------------------------------ */

static const char SPEC[] =
        "name  cats and their moods\n"
        "sticker 1 static\n"
        "description a ginger cat waving hello\n"
        "keyword wave\n"
        "keyword hello there\n"
        "inline png 128 128 art/wave.png\n"
        "thumb  png  64  64 art/wave-thumb.png\n"
        "sticker 2 animated big sound\n"
        "description the same cat spinning very fast\n"
        "main lottie 320 320 art/spin.json\n"
        "sound art/spin.ogg\n"
        "sticker 7 message\n"
        "description a cat holding a sign\n"
        "main png 240 240 art/sign.png\n"
        "text 12 10 20 200 40\n";

/* ROOM FOR THE STICKERS, the caller's since sec 702: a bent count past
 * it is a read that says so. */
#define ROOM 16u
static fzn_sticker_entry_t m_room[ROOM], opened_room[ROOM];
static fzn_sticker_manifest_t m = { "", 0, 0, m_room, ROOM, 0 },
                              opened = { "", 0, 0, opened_room, ROOM, 0 };
static const uint8_t *art[ROOM][FZN_STICKER_RENDITIONS_MAX];
static uint32_t art_len[ROOM][FZN_STICKER_RENDITIONS_MAX];
static const uint8_t *sound[ROOM];
static uint32_t sound_len[ROOM];

static int build(const fzn_sticker_manifest_t *mm, uint8_t *out, size_t cap, size_t *len)
{
	return fzn_sticker_pack_build(mm, (const uint8_t *const(*)[FZN_STICKER_RENDITIONS_MAX])art,
	                              (const uint32_t(*)[FZN_STICKER_RENDITIONS_MAX])art_len,
	                              (const uint8_t *const *)sound, sound_len, out, cap, len);
}

/* Each rendition and sound of `mm` as its slice of `data`; 0 when one lies
 * outside it. */
static int art_from(const fzn_sticker_manifest_t *mm, const uint8_t *data, size_t data_len)
{
	size_t i, r;

	memset(art, 0, sizeof(art));
	memset(art_len, 0, sizeof(art_len));
	memset(sound, 0, sizeof(sound));
	memset(sound_len, 0, sizeof(sound_len));
	for (i = 0; i < mm->count; i++) {
		const fzn_sticker_entry_t *e = &mm->entries[i];

		for (r = 0; r < e->rendition_count; r++) {
			if (e->renditions[r].offset > data_len
			    || e->renditions[r].len > data_len - e->renditions[r].offset)
				return 0;
			art[i][r] = data + e->renditions[r].offset;
			art_len[i][r] = e->renditions[r].len;
		}
		if (e->audio_len) {
			if (e->audio_offset > data_len || e->audio_len > data_len - e->audio_offset)
				return 0;
			sound[i] = data + e->audio_offset;
			sound_len[i] = e->audio_len;
		}
	}
	return 1;
}

/* ---- the reference --------------------------------------------------------- */

static void a_ref(fzn_sticker_ref_t *ref)
{
	size_t i;

	memset(ref, 0, sizeof(*ref));
	for (i = 0; i < FZN_STICKER_ROOT_LEN; i++)
		ref->root[i] = (uint8_t)next();
	for (i = 0; i < FZN_STICKER_KEY_LEN; i++)
		ref->key[i] = (uint8_t)next();
	ref->length = 1u + (next() >> (next() % 64u)) % UINT64_MAX;
	ref->id = 1u + (next() >> (next() % 64u)) % UINT64_MAX;
	/* A DESCRIPTION OPTIONAL since sec 702: none, now and then. */
	ref->description_len = (size_t)(next() % (FZN_STICKER_DESC_MAX + 1u));
	for (i = 0; i < ref->description_len; i++)
		ref->description[i] = (char)(0x20u + next() % 0x5fu);
}

int main(int argc, char **argv)
{
	static uint8_t pack[PACK_CAP], bent[PACK_CAP + 64u], again[PACK_CAP];
	static char text[FZN_STICKER_REF_MAX + 64u], ref_bent[FZN_STICKER_REF_MAX + 64u];
	static char ref_again[FZN_STICKER_REF_MAX + 64u];
	unsigned long cases = FUZZ_DEFAULT_CASES, c;
	unsigned long pack_opened = 0, pack_refused = 0, ref_parsed = 0, ref_refused = 0;
	const uint8_t *data = NULL;
	size_t pack_len = 0, data_len = 0, i;
	char err[128];

	if (argc > 1)
		cases = strtoul(argv[1], NULL, 10);
	if (cases < FUZZ_MIN_CASES)
		cases = FUZZ_MIN_CASES;
	guard();

	/* THE PACK, built once: each file a few bytes saying which it is. */
	if (!fzn_sticker_spec_parse(SPEC, sizeof(SPEC) - 1u, &m, err, sizeof(err))) {
		fprintf(stderr, "sticker_fuzz: the spec would not parse: %s\n", err);
		return 1;
	}
	{
		static uint8_t files[ROOM][FZN_STICKER_RENDITIONS_MAX + 1u][16];
		size_t r;

		for (i = 0; i < m.count; i++) {
			for (r = 0; r < m.entries[i].rendition_count; r++) {
				memset(files[i][r], (int)('A' + i * 8u + r), sizeof(files[i][r]));
				art[i][r] = files[i][r];
				art_len[i][r] = (uint32_t)(5u + r);
			}
			if (m.entries[i].audio_path_len) {
				memset(files[i][FZN_STICKER_RENDITIONS_MAX], 'z', 16u);
				sound[i] = files[i][FZN_STICKER_RENDITIONS_MAX];
				sound_len[i] = 9u;
			}
		}
		if (!build(&m, pack, sizeof(pack), &pack_len)) {
			fprintf(stderr, "sticker_fuzz: the spec's pack would not build\n");
			return 1;
		}
	}

	for (c = 0; c < cases; c++) {
		fzn_sticker_ref_t ref, back;
		size_t n, len = 0, again_len = 0;

		/* 1: THE PACK. */
		if (!fzn_sticker_pack_open(guarded(pack, pack_len), pack_len, &opened, &data,
		                           &data_len)
		    || opened.count != m.count)
			fail("the pack did not open as built", c);
		memcpy(bent, pack, pack_len);
		n = bend(bent, pack_len, sizeof(bent));
		if (!fzn_sticker_pack_open(guarded(bent, n), n, &opened, &data, &data_len)) {
			pack_refused++;
			/* A COUNT ASKED FOR is one past the room, and nothing else. */
			if (opened.count && !FZN_STICKER_TOO_SMALL(&opened))
				fail("a refused pack left a count that asks for no room", c);
		} else {
			pack_opened++;
			if (!art_from(&opened, data, data_len))
				fail("a bent pack opened with art outside its data area", c);
			else if (!build(&opened, again, sizeof(again), &again_len))
				fail("a bent pack opened that building refuses", c);
		}

		/* 2: A REFERENCE. */
		a_ref(&ref);
		if (!fzn_sticker_ref_format(&ref, text, sizeof(text), &len)) {
			fail("a reference of every field in range would not format", c);
			continue;
		}
		if (!fzn_sticker_ref_parse((const char *)guarded((const uint8_t *)text, len), len,
		                           &back)
		    || memcmp(back.root, ref.root, sizeof(ref.root)) != 0
		    || memcmp(back.key, ref.key, sizeof(ref.key)) != 0 || back.length != ref.length
		    || back.id != ref.id || back.description_len != ref.description_len
		    || memcmp(back.description, ref.description, ref.description_len) != 0)
			fail("a formatted reference did not parse as itself", c);
		memcpy(ref_bent, text, len);
		n = bend((uint8_t *)ref_bent, len, sizeof(ref_bent));
		if (!fzn_sticker_ref_parse((const char *)guarded((const uint8_t *)ref_bent, n), n,
		                           &back)) {
			ref_refused++;
			continue;
		}
		ref_parsed++;
		if (n < 4u || memcmp(ref_bent, "fzn:", 4u) != 0)
			continue;	/* fuzzypickles' carries no length: no one spelling here */
		for (i = REF_ROOT_AT; i < REF_HEX_END && i < n; i++)
			if (ref_bent[i] >= 'A' && ref_bent[i] <= 'F')
				ref_bent[i] = (char)(ref_bent[i] - 'A' + 'a');
		if (!fzn_sticker_ref_format(&back, ref_again, sizeof(ref_again), &again_len))
			fail("a bent reference parsed to fields formatting refuses", c);
		else if (again_len != n || memcmp(ref_again, ref_bent, n) != 0)
			fail("a bent reference parsed that is not the one spelling of its parse", c);
	}

	if (pack_opened == 0u || pack_refused == 0u)
		fail("FLOOR: no bent pack opened, or none was refused", cases);
	if (ref_parsed == 0u || ref_refused == 0u)
		fail("FLOOR: no bent reference parsed, or none was refused", cases);
	printf("sticker_fuzz: %lu cases, bent packs %lu opened %lu refused, bent references %lu "
	       "parsed %lu refused, %d failure(s)\n",
	       cases, pack_opened, pack_refused, ref_parsed, ref_refused, failures);
	return failures ? 1 : 0;
}
