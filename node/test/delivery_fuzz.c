/*
 * A fuzz harness for a contact's delivery, `fzn_node_messages_contact`:
 * sec 689's journey 2, 1:1 chat. A contact's host sends a line, and this
 * host files it IN under that contact.
 *
 * WHY THIS ONE. The delivery is the contact's to write, every byte, from
 * outside the user's own estate, and what it admits is a line in one of the
 * user's conversations. The claim is that a delivery files exactly one line,
 * under the contact it came from, with exactly the text it carries -- and
 * that a bent one files nothing else.
 *
 * THE PEER LIES BY MUTATION. Each case builds a well-formed delivery -- an
 * id, a time and a printable text -- and bends it with even odds: bits
 * flipped, cut short, grown, the text's length at its extremes, a slice
 * repeated or two bytes swapped.
 *
 * THE PROPERTIES:
 *   1. A WELL-FORMED DELIVERY IS FILED: answered DELIVERED for its own id,
 *      held, and listed IN under the contact with exactly its text.
 *   2. A BENT ONE FILES ONLY WHAT IT SAYS: answered nothing, or DELIVERED
 *      for the id its bytes carry; any line filed is IN, under the contact,
 *      its text the request's tail exactly and no longer than
 *      FZN_MESSAGE_TEXT_MAX.
 *   3. NOTHING UNDER ANOTHER CONTACT, ever.
 *   4. ONCE: the same bytes again file nothing more.
 *
 * FLOORS: a run that never filed through a bent delivery, never refused one,
 * or never filed a well-formed one has not tested what it claims.
 */

#include "../messages.h"
#include "../../chain/sign_monocypher.h"
#include "../../session/aead_monocypher.h"
#include "../../session/hash_monocypher.h"
#include "../../wire/bytes.h"

#include <monocypher-ed25519.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 3000u
#define FUZZ_MIN_CASES 1000u
/* A FRESH STORE every this many cases, so the in-memory tables never fill. */
#define CASES_A_STORE 40u

static int failures;

static void fail(const char *what, unsigned long c)
{
	failures++;
	if (failures <= 10)
		fprintf(stderr, "  FAIL delivery_fuzz.c: case %lu: %s\n", c, what);
}

/* ---- a generator, seeded ---------------------------------------------- */

static uint64_t state = 0x9e3779b97f4a7c15ull;

static uint64_t next(void)
{
	state ^= state << 13;
	state ^= state >> 7;
	state ^= state << 17;
	return state;
}

static uint8_t rng_counter;

static int counter_fill(void *ctx, uint8_t *out, size_t len)
{
	size_t i;

	(void)ctx;
	for (i = 0; i < len; i++)
		out[i] = (uint8_t)(rng_counter++ * 37u + 11u);
	return 1;
}

static const fzn_random_ops_t RNG = { counter_fill, NULL };

static uint64_t clock_ms = 1791460800000ull;

static uint64_t now_ms(void)
{
	return clock_ms += 1000u;
}

/* ---- a persist store in memory, as messages_test's -------------------- */

#define ROWS 1024u

typedef struct row {
	int used;
	fzn_persist_slot_t slot;
	int has_subject;
	uint8_t subject[FZN_PUBKEY_LEN];
	size_t len;
	uint8_t bytes[1280];
} row_t;

static row_t rows[ROWS];

static row_t *find(fzn_persist_slot_t slot, const uint8_t *subject)
{
	size_t i;

	for (i = 0; i < ROWS; i++)
		if (rows[i].used && rows[i].slot == slot && rows[i].has_subject == (subject != NULL)
		    && (!subject || memcmp(rows[i].subject, subject, FZN_PUBKEY_LEN) == 0))
			return &rows[i];
	return NULL;
}

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	row_t *r = find(slot, subject);

	(void)ctx;
	if (!r || r->len > cap)
		return 0;
	memcpy(out, r->bytes, r->len);
	*len = r->len;
	return 1;
}

static int mem_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                    const uint8_t *bytes, size_t len)
{
	row_t *r = find(slot, subject);
	size_t i;

	(void)ctx;
	if (len > sizeof(rows[0].bytes))
		return 0;
	for (i = 0; !r && i < ROWS; i++)
		if (!rows[i].used)
			r = &rows[i];
	if (!r)
		return 0;
	r->used = 1;
	r->slot = slot;
	r->has_subject = subject != NULL;
	if (subject)
		memcpy(r->subject, subject, FZN_PUBKEY_LEN);
	memcpy(r->bytes, bytes, len);
	r->len = len;
	return 1;
}

static int mem_list(void *ctx, fzn_persist_slot_t slot, uint8_t *out, size_t max, size_t *count)
{
	size_t i, n = 0;

	(void)ctx;
	for (i = 0; i < ROWS; i++)
		if (rows[i].used && rows[i].slot == slot && rows[i].has_subject) {
			if (n >= max)
				return 0;
			memcpy(out + (n * FZN_PUBKEY_LEN), rows[i].subject, FZN_PUBKEY_LEN);
			n++;
		}
	*count = n;
	return 1;
}

static int mem_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	row_t *r = find(slot, subject);

	(void)ctx;
	if (r)
		memset(r, 0, sizeof(*r));
	return 1;
}

/* ---- a record store in memory ------------------------------------------ */

#define RECS 512u

static struct rec {
	uint8_t issuer[FZN_PUBKEY_LEN];
	uint32_t stream;
	uint64_t seq;
	size_t len;
	uint8_t bytes[FZN_RECORD_MAX_LEN];
} recs[RECS];
static size_t n_recs;

static int rec_put(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream, uint64_t seq,
                   const uint8_t *bytes, size_t len)
{
	(void)ctx;
	if (n_recs >= RECS || len > FZN_RECORD_MAX_LEN)
		return 0;
	memcpy(recs[n_recs].issuer, issuer, FZN_PUBKEY_LEN);
	recs[n_recs].stream = stream;
	recs[n_recs].seq = seq;
	recs[n_recs].len = len;
	memcpy(recs[n_recs].bytes, bytes, len);
	n_recs++;
	return 1;
}

static int rec_get(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream, uint64_t seq,
                   uint8_t *out, size_t cap, size_t *len_out, int *found_out)
{
	size_t i;

	(void)ctx;
	*found_out = 0;
	for (i = 0; i < n_recs; i++)
		if (recs[i].seq == seq && recs[i].stream == stream
		    && memcmp(recs[i].issuer, issuer, FZN_PUBKEY_LEN) == 0) {
			*found_out = 1;
			if (recs[i].len > cap)
				return 0;
			memcpy(out, recs[i].bytes, recs[i].len);
			*len_out = recs[i].len;
			return 1;
		}
	return 1;
}

static fzn_record_store_ops_t rops = { rec_put, rec_get, NULL, NULL };

/* ---- this host, and its contacts ---------------------------------------- */

static fzn_sign_monocypher_t key;
static fzn_sign_ops_t sign;
static uint8_t pub[FZN_PUBKEY_LEN];
static fzn_persist_ops_t store_ops;
static fzn_node_journal_t journal;
static fzn_node_messages_t nm;
static fzn_aead_ops_t AEAD;
static fzn_hash_ops_t HASH;
static uint8_t X[FZN_PUBKEY_LEN], Y[FZN_PUBKEY_LEN];

static void host_up(void)
{
	uint8_t seed[32];

	memset(rows, 0, sizeof(rows));
	n_recs = 0;
	memset(&nm, 0, sizeof(nm));
	memset(seed, 0x11, sizeof(seed));
	crypto_ed25519_key_pair(key.secret_key, pub, seed);
	key.can_sign = 1;
	fzn_sign_monocypher_init(&sign, &key);
	store_ops.load = mem_load;
	store_ops.save = mem_save;
	store_ops.list = mem_list;
	store_ops.remove = mem_remove;
	store_ops.ctx = NULL;
	(void)fzn_node_journal_init_store(&journal, &rops, &sign, &HASH);
	(void)fzn_node_journal_follow_stream(&journal, pub, FZN_MESSAGE_STREAM, NULL);
	nm.m.store = &store_ops;
	nm.m.journal = &journal;
	nm.m.issuer = pub;
	nm.m.sign = &sign;
	nm.m.rng = &RNG;
	nm.m.aead = &AEAD;
	nm.m.hash = &HASH;
	nm.m.now = now_ms;
	nm.m.devices = (const uint8_t(*)[FZN_PUBKEY_LEN])&pub;
	nm.m.device_count = 1u;
}

/* ---- the delivery, built and bent -------------------------------------- */

#define REQUEST_MAX (FZN_NODE_MESSAGES_DELIVER_HEAD_LEN + FZN_MESSAGE_TEXT_MAX + 64u)

static size_t build(uint8_t *out, uint8_t id[FZN_MESSAGE_ID_LEN], uint8_t *text, size_t *text_len)
{
	size_t i, n = (size_t)(next() % 200u);

	for (i = 0; i < FZN_MESSAGE_ID_LEN; i++)
		id[i] = (uint8_t)next();
	for (i = 0; i < n; i++)
		text[i] = (uint8_t)(' ' + next() % 95u);
	*text_len = n;
	out[0] = FZN_NODE_MESSAGES_VERSION;
	out[1] = FZN_NODE_MESSAGES_DELIVER;
	memcpy(out + 2, id, FZN_MESSAGE_ID_LEN);
	fzn_put_be64(out + 2 + FZN_MESSAGE_ID_LEN, clock_ms);
	fzn_put_be16(out + 2 + FZN_MESSAGE_ID_LEN + 8, (uint16_t)n);
	memcpy(out + FZN_NODE_MESSAGES_DELIVER_HEAD_LEN, text, n);
	return FZN_NODE_MESSAGES_DELIVER_HEAD_LEN + n;
}

static size_t bend(uint8_t *b, size_t len)
{
	size_t k, i, j;
	uint8_t t;

	switch (next() % 6u) {
	case 0:
		for (k = 1u + next() % 4u; k > 0u && len; k--)
			b[next() % len] ^= (uint8_t)(1u << (next() % 8u));
		return len;
	case 1:
		return len ? (size_t)(next() % len) : 0u;
	case 2:
		for (k = 1u + next() % 16u; k > 0u && len < REQUEST_MAX; k--)
			b[len++] = (uint8_t)next();
		return len;
	case 3:
		if (len >= FZN_NODE_MESSAGES_DELIVER_HEAD_LEN)
			fzn_put_be16(b + 2 + FZN_MESSAGE_ID_LEN + 8,
			             (uint16_t)((next() & 1u) ? 0xffffu : FZN_MESSAGE_TEXT_MAX + 1u));
		return len;
	case 4:
		if (len >= 8u) {
			i = next() % (len - 4u);
			memmove(b + i + 4u, b + i, len - i - 4u);
		}
		return len;
	default:
		if (len >= 2u) {
			i = next() % len;
			j = next() % len;
			t = b[i];
			b[i] = b[j];
			b[j] = t;
		}
		return len;
	}
}

/* How many lines a contact's conversation lists, and whether `id` is among
 * them IN with exactly `text`. */
static size_t listed(const uint8_t contact[FZN_PUBKEY_LEN], const uint8_t *id,
                     const uint8_t *text, size_t text_len, int *found)
{
	static fzn_message_t page[FZN_MESSAGES_PAGE_MAX];
	size_t count = 0, i;
	int more = 0;

	*found = 0;
	if (fzn_messages_page(&nm.m, contact, 0u, page, FZN_MESSAGES_PAGE_MAX, &count, &more)
	    != FZN_MESSAGES_OK)
		return (size_t)-1;
	for (i = 0; id && i < count; i++)
		if (memcmp(page[i].id, id, FZN_MESSAGE_ID_LEN) == 0 && page[i].direction == FZN_MESSAGE_IN
		    && page[i].text_len == text_len && memcmp(page[i].text, text, text_len) == 0)
			*found = 1;
	return count;
}

int main(int argc, char **argv)
{
	static uint8_t req[REQUEST_MAX], text[FZN_MESSAGE_TEXT_MAX + 1u];
	uint8_t id[FZN_MESSAGE_ID_LEN], reply[FZN_NODE_MESSAGES_DELIVERED_LEN + 8u];
	unsigned long cases = FUZZ_DEFAULT_CASES, c;
	unsigned long filed_plain = 0, filed_bent = 0, refused = 0;

	if (argc > 1)
		cases = strtoul(argv[1], NULL, 10);
	if (cases < FUZZ_MIN_CASES)
		cases = FUZZ_MIN_CASES;
	fzn_aead_monocypher_init(&AEAD);
	fzn_hash_monocypher_init(&HASH);
	memset(X, 0x5a, sizeof(X));
	memset(Y, 0x6b, sizeof(Y));

	for (c = 0; c < cases; c++) {
		size_t text_len = 0, len, got, before, after, again, text_field;
		int bent, found = 0;

		if (c % CASES_A_STORE == 0u)
			host_up();
		len = build(req, id, text, &text_len);
		bent = (int)(next() & 1u);
		if (bent)
			len = bend(req, len);
		before = listed(X, NULL, NULL, 0u, &found);
		got = fzn_node_messages_contact(&nm, X, 1, req, len, reply, sizeof(reply));
		after = listed(X, NULL, NULL, 0u, &found);

		/* 3. NOTHING UNDER ANOTHER CONTACT. */
		if (listed(Y, NULL, NULL, 0u, &found) != 0u)
			fail("a line was filed under a contact that sent nothing", c);
		if (!bent) {
			/* 1. A WELL-FORMED DELIVERY IS FILED. */
			(void)listed(X, id, text, text_len, &found);
			if (got != FZN_NODE_MESSAGES_DELIVERED_LEN || reply[1] != FZN_NODE_MESSAGES_DELIVERED
			    || memcmp(reply + 2, id, FZN_MESSAGE_ID_LEN) != 0
			    || reply[2 + FZN_MESSAGE_ID_LEN] != FZN_NODE_MESSAGES_HELD || !found)
				fail("a well-formed delivery was not filed and answered held", c);
			else
				filed_plain++;
		} else if (got == 0u) {
			refused++;
			if (after != before)
				fail("a refused delivery filed a line", c);
		} else {
			/* 2. A BENT ONE FILES ONLY WHAT IT SAYS. */
			if (got != FZN_NODE_MESSAGES_DELIVERED_LEN
			    || memcmp(reply + 2, req + 2, FZN_MESSAGE_ID_LEN) != 0)
				fail("a bent delivery was answered for another id, or at another length", c);
			text_field = fzn_get_be16(req + 2 + FZN_MESSAGE_ID_LEN + 8);
			if (text_field > FZN_MESSAGE_TEXT_MAX
			    || len != FZN_NODE_MESSAGES_DELIVER_HEAD_LEN + text_field)
				fail("a delivery whose length disagrees with its text was taken", c);
			if (after > before) {
				(void)listed(X, req + 2, req + FZN_NODE_MESSAGES_DELIVER_HEAD_LEN, text_field,
				             &found);
				if (!found)
					fail("a bent delivery filed a line other than the one it carries", c);
				else
					filed_bent++;
			}
		}
		/* 4. ONCE. */
		(void)fzn_node_messages_contact(&nm, X, 1, req, len, reply, sizeof(reply));
		again = listed(X, NULL, NULL, 0u, &found);
		if (again != after)
			fail("the same delivery again filed another line", c);
	}

	if (filed_plain == 0u)
		fail("no well-formed delivery was filed", cases);
	if (filed_bent == 0u)
		fail("no bent delivery was filed: the mutations never reached the filing", cases);
	if (refused == 0u)
		fail("no bent delivery was refused: the shape check was never met", cases);
	printf("delivery_fuzz: %lu cases, %lu filed whole, %lu filed bent, %lu refused, %d "
	       "failure(s)\n",
	       cases, filed_plain, filed_bent, refused, failures);
	return failures ? 1 : 0;
}
