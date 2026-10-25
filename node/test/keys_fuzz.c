/*
 * A fuzz harness for keys carried between the user's devices,
 * `fzn_node_messages_remote`: sec 689's journey 2, 1:1 chat. A member
 * GIVEs the conversation keys it drew and WANTs those it lacks, and a
 * conversation's lines open only under those keys.
 *
 * WHY THIS ONE. The keys are what keep a conversation's text private, and
 * the claim in messages.h is that a gift can neither replace a key nor be
 * filed under a device other than its giver's. A member that lies -- one
 * lost, or a bug in one -- would otherwise put words in another device's
 * lines or swap a month's key for its own.
 *
 * Each case sends a well-formed GIVE, WANT or HOLDS, or a bent one, from
 * one of the user's two other devices, the places drawn from a small pool
 * so that gifts collide. A MODEL of the keys held is kept beside the store:
 * a request the situ layout admits is applied to the model, and one it
 * does not changes nothing.
 *
 * THE PROPERTIES:
 *   1. AS THE GIVER'S OWN: a GIVE files each key under its sender, and only
 *      where none is held; a key held stays as it was. GIVEN counts each
 *      entry once, taken or refused.
 *   2. NOTHING ELSE MOVES: after every request, every place the model knows
 *      of, under each of the three devices, holds exactly the model's key or
 *      none.
 *   3. WANT ANSWERS WHAT IS HELD: the reply carries, in order, exactly the
 *      asked places held here, each with its key, and its length says so.
 *   4. REFUSED IS NOTHING: a request the layout does not admit is answered
 *      with nothing.
 *
 * FLOORS: a run with no key taken, none refused for holding another, no
 * WANT answered with a key, and no bent request admitted has not tested
 * what it claims.
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
#define CASES_A_STORE 60u

static int failures;

static void fail(const char *what, unsigned long c)
{
	failures++;
	if (failures <= 10)
		fprintf(stderr, "  FAIL keys_fuzz.c: case %lu: %s\n", c, what);
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

/* ---- the model ----------------------------------------------------------- */

#define PLACE_LEN (FZN_PUBKEY_LEN + 4u)
#define MODEL_MAX 2048u

static struct held {
	uint8_t place[PLACE_LEN];
	uint8_t device[FZN_PUBKEY_LEN];
	uint8_t key[FZN_CONVERSATION_KEY_LEN];
} model[MODEL_MAX];
static size_t n_model;
/* Every place seen, to probe under each device. */
static uint8_t places[MODEL_MAX][PLACE_LEN];
static size_t n_places;

static uint8_t S1[FZN_PUBKEY_LEN], S2[FZN_PUBKEY_LEN];
static uint8_t devices[3][FZN_PUBKEY_LEN];

static struct held *model_at(const uint8_t *place, const uint8_t *device)
{
	size_t i;

	for (i = 0; i < n_model; i++)
		if (memcmp(model[i].place, place, PLACE_LEN) == 0
		    && memcmp(model[i].device, device, FZN_PUBKEY_LEN) == 0)
			return &model[i];
	return NULL;
}

static void place_seen(const uint8_t *place)
{
	size_t i;

	for (i = 0; i < n_places; i++)
		if (memcmp(places[i], place, PLACE_LEN) == 0)
			return;
	if (n_places < MODEL_MAX)
		memcpy(places[n_places++], place, PLACE_LEN);
}

/* 2. Every place seen, under each device, as the model says. */
static int store_is_model(void)
{
	uint8_t held_key[FZN_CONVERSATION_KEY_LEN];
	size_t i, d;

	for (i = 0; i < n_places; i++)
		for (d = 0; d < 3u; d++) {
			const struct held *h = model_at(places[i], devices[d]);
			int got = fzn_messages_key_get(&nm.m, places[i], fzn_get_be32(places[i] + FZN_PUBKEY_LEN),
			                               devices[d], held_key);

			if (got != (h != NULL) || (h && memcmp(held_key, h->key, sizeof(held_key)) != 0))
				return 0;
		}
	return 1;
}

/* ---- the requests ---------------------------------------------------------- */

#define REQUEST_MAX 1024u
#define GIVE_ENTRY_LEN (PLACE_LEN + FZN_CONVERSATION_KEY_LEN)

static uint8_t pool_contact[3][FZN_PUBKEY_LEN];

static void a_place(uint8_t *at)
{
	memcpy(at, pool_contact[next() % 3u], FZN_PUBKEY_LEN);
	fzn_put_be32(at + FZN_PUBKEY_LEN, (uint32_t)(660u + next() % 3u));
}

/* A key from a pool of four per place, so gifts agree and disagree. */
static void a_key(uint8_t *at)
{
	memset(at, (int)(0x30u + next() % 4u), FZN_CONVERSATION_KEY_LEN);
}

static size_t build(uint8_t *b, uint8_t type, size_t n)
{
	size_t i, at = FZN_NODE_MESSAGES_HEAD_LEN;

	b[0] = FZN_NODE_MESSAGES_VERSION;
	b[1] = type;
	b[2] = (uint8_t)n;
	if (type == FZN_NODE_MESSAGES_HOLDS) {
		memcpy(b + 2, pool_contact[next() % 3u], FZN_PUBKEY_LEN);
		for (i = 0; i < FZN_BUCKETS_ID_LEN; i++)
			b[2 + FZN_PUBKEY_LEN + i] = (uint8_t)next();
		return FZN_NODE_MESSAGES_HOLDS_LEN;
	}
	for (i = 0; i < n; i++) {
		a_place(b + at);
		if (type == FZN_NODE_MESSAGES_GIVE) {
			a_key(b + at + PLACE_LEN);
			at += GIVE_ENTRY_LEN;
		} else {
			memcpy(b + at + PLACE_LEN, devices[next() % 3u], FZN_PUBKEY_LEN);
			at += FZN_NODE_MESSAGES_ENTRY_LEN;
		}
	}
	return at;
}

static size_t bend(uint8_t *b, size_t len)
{
	size_t k, i;

	switch (next() % 6u) {
	case 5:
		/* A COUNT PAST THE MOST, its body grown to agree with it. */
		if (len >= FZN_NODE_MESSAGES_HEAD_LEN && b[1] != FZN_NODE_MESSAGES_HOLDS) {
			size_t entry = b[1] == FZN_NODE_MESSAGES_GIVE ? GIVE_ENTRY_LEN
			                                              : FZN_NODE_MESSAGES_ENTRY_LEN;

			b[2] = (uint8_t)(FZN_NODE_MESSAGES_PER + 1u + next() % 4u);
			len = FZN_NODE_MESSAGES_HEAD_LEN + (size_t)b[2] * entry;
			for (i = FZN_NODE_MESSAGES_HEAD_LEN; i + entry <= len; i += entry)
				memcpy(b + i, b + FZN_NODE_MESSAGES_HEAD_LEN, entry);
		}
		return len;
	case 0:
		for (k = 1u + next() % 3u; k > 0u && len; k--)
			b[next() % len] ^= (uint8_t)(1u << (next() % 8u));
		return len;
	case 1:
		return len ? (size_t)(next() % len) : 0u;
	case 2:
		for (k = 1u + next() % 40u; k > 0u && len < REQUEST_MAX; k--)
			b[len++] = (uint8_t)next();
		return len;
	case 3:
		b[2] = (uint8_t)(next() % 11u);
		return len;
	default:
		i = next() % 3u;
		b[i] ^= (uint8_t)(1u << (next() % 8u));
		return len;
	}
}

/* What the layout admits, `messages/keys.situ` and `deliver.situ`: the
 * type and its length. */
static int admitted(const uint8_t *b, size_t len)
{
	size_t n;

	if (len < FZN_NODE_MESSAGES_HEAD_LEN || b[0] != FZN_NODE_MESSAGES_VERSION)
		return 0;
	if (b[1] == FZN_NODE_MESSAGES_HOLDS)
		return len == FZN_NODE_MESSAGES_HOLDS_LEN;
	n = b[2];
	if (n == 0u || n > FZN_NODE_MESSAGES_PER)
		return 0;
	if (b[1] == FZN_NODE_MESSAGES_GIVE)
		return len == FZN_NODE_MESSAGES_HEAD_LEN + n * GIVE_ENTRY_LEN;
	if (b[1] == FZN_NODE_MESSAGES_WANT)
		return len == FZN_NODE_MESSAGES_HEAD_LEN + n * FZN_NODE_MESSAGES_ENTRY_LEN;
	return 0;
}

int main(int argc, char **argv)
{
	static uint8_t req[REQUEST_MAX], reply[FZN_NODE_MESSAGES_REPLY_MAX + 64u];
	static const uint8_t types[3] = { FZN_NODE_MESSAGES_GIVE, FZN_NODE_MESSAGES_WANT,
		                          FZN_NODE_MESSAGES_HOLDS };
	unsigned long cases = FUZZ_DEFAULT_CASES, c;
	unsigned long taken = 0, refused = 0, answered = 0, bent_admitted = 0;

	if (argc > 1)
		cases = strtoul(argv[1], NULL, 10);
	if (cases < FUZZ_MIN_CASES)
		cases = FUZZ_MIN_CASES;
	fzn_aead_monocypher_init(&AEAD);
	fzn_hash_monocypher_init(&HASH);
	memcpy(pool_contact[0], X, FZN_PUBKEY_LEN);
	memcpy(pool_contact[1], Y, FZN_PUBKEY_LEN);
	memset(pool_contact[2], 0x7c, FZN_PUBKEY_LEN);
	memset(S1, 0x21, sizeof(S1));
	memset(S2, 0x42, sizeof(S2));

	for (c = 0; c < cases; c++) {
		const uint8_t *sender = (next() & 1u) ? S1 : S2;
		size_t len, got, i, n;
		uint8_t type = types[next() % 3u];
		int bent;

		if (c % CASES_A_STORE == 0u) {
			host_up();
			memcpy(devices[0], pub, FZN_PUBKEY_LEN);
			memcpy(devices[1], S1, FZN_PUBKEY_LEN);
			memcpy(devices[2], S2, FZN_PUBKEY_LEN);
			nm.m.devices = (const uint8_t(*)[FZN_PUBKEY_LEN])devices;
			nm.m.device_count = 3u;
			n_model = 0;
			n_places = 0;
		}
		len = build(req, type, 1u + next() % FZN_NODE_MESSAGES_PER);
		bent = (int)(next() & 1u);
		if (bent)
			len = bend(req, len);
		if (bent && admitted(req, len))
			bent_admitted++;
		/* The places this request names, to probe whatever it does. */
		if (len >= FZN_NODE_MESSAGES_HEAD_LEN && req[1] != FZN_NODE_MESSAGES_HOLDS)
			for (i = FZN_NODE_MESSAGES_HEAD_LEN; i + PLACE_LEN <= len;
			     i += req[1] == FZN_NODE_MESSAGES_GIVE ? GIVE_ENTRY_LEN
			                                         : FZN_NODE_MESSAGES_ENTRY_LEN)
				place_seen(req + i);

		got = fzn_node_messages_remote(&nm, sender, req, len, reply, sizeof(reply));

		if (!admitted(req, len)) {
			/* 4. REFUSED IS NOTHING. */
			if (got != 0u)
				fail("a request the layout does not admit was answered", c);
		} else if (req[1] == FZN_NODE_MESSAGES_GIVE) {
			/* 1. AS THE GIVER'S OWN, in the model. */
			size_t want_taken = 0, want_refused = 0;

			n = req[2];
			for (i = 0; i < n; i++) {
				const uint8_t *e = req + FZN_NODE_MESSAGES_HEAD_LEN + i * GIVE_ENTRY_LEN;
				struct held *h = model_at(e, sender);

				if (!h && n_model < MODEL_MAX) {
					h = &model[n_model++];
					memcpy(h->place, e, PLACE_LEN);
					memcpy(h->device, sender, FZN_PUBKEY_LEN);
					memcpy(h->key, e + PLACE_LEN, FZN_CONVERSATION_KEY_LEN);
					want_taken++;
				} else if (h && memcmp(h->key, e + PLACE_LEN, FZN_CONVERSATION_KEY_LEN) == 0) {
					want_taken++;
				} else {
					want_refused++;
				}
			}
			taken += want_taken;
			refused += want_refused;
			if (got != FZN_NODE_MESSAGES_GIVEN_LEN || reply[0] != FZN_NODE_MESSAGES_VERSION
			    || reply[1] != FZN_NODE_MESSAGES_GIVEN || reply[2] != want_taken
			    || reply[3] != want_refused)
				fail("a GIVE was not answered with what it took and refused", c);
		} else if (req[1] == FZN_NODE_MESSAGES_WANT) {
			/* 3. WANT ANSWERS WHAT IS HELD. */
			size_t at = FZN_NODE_MESSAGES_HEAD_LEN, held = 0;
			int ok = got >= FZN_NODE_MESSAGES_HEAD_LEN && reply[0] == FZN_NODE_MESSAGES_VERSION
			         && reply[1] == FZN_NODE_MESSAGES_KEYS;

			n = req[2];
			for (i = 0; ok && i < n; i++) {
				const uint8_t *e = req + FZN_NODE_MESSAGES_HEAD_LEN + i * FZN_NODE_MESSAGES_ENTRY_LEN;
				const struct held *h = model_at(e, e + PLACE_LEN);

				if (!h)
					continue;
				ok = at + FZN_NODE_MESSAGES_HELD_LEN <= got
				     && memcmp(reply + at, e, FZN_NODE_MESSAGES_ENTRY_LEN) == 0
				     && memcmp(reply + at + FZN_NODE_MESSAGES_ENTRY_LEN, h->key,
				               FZN_CONVERSATION_KEY_LEN) == 0;
				at += FZN_NODE_MESSAGES_HELD_LEN;
				held++;
			}
			if (!ok || got != at || reply[2] != held)
				fail("a WANT was not answered with exactly the asked keys held", c);
			if (held)
				answered++;
		} else if (got != FZN_NODE_MESSAGES_HOLDING_LEN || reply[1] != FZN_NODE_MESSAGES_HOLDING
		           || memcmp(reply + 2, req + 2 + FZN_PUBKEY_LEN, FZN_BUCKETS_ID_LEN) != 0) {
			fail("a HOLDS was not answered for its item", c);
		}

		/* 2. NOTHING ELSE MOVES. */
		if (!store_is_model())
			fail("a key is held that the model does not hold, or differs from it", c);
	}

	if (taken == 0u)
		fail("no key was taken", cases);
	if (refused == 0u)
		fail("no key was refused for one held: the first-held rule was never asked", cases);
	if (answered == 0u)
		fail("no WANT was answered with a key", cases);
	if (bent_admitted == 0u)
		fail("no bent request was admitted: the mutations never reached the handlers", cases);
	printf("keys_fuzz: %lu cases, %lu keys taken, %lu refused, %lu WANTs answered, %lu bent "
	       "admitted, %d failure(s)\n",
	       cases, taken, refused, answered, bent_admitted, failures);
	return failures ? 1 : 0;
}
