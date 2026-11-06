/* node votes_test -- a value changed by the estate's k, sec 909: a voter's newest
 * vote, counted by standing against k, none older than the value in force.
 */

#include "../votes.h"
#include "../../state/setting.h"
#include "../../messages/line.h"
#include "../../log/retain.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
static int checks;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL votes_test.c:%d: %s\n", __LINE__, what);      \
		}                                                                              \
	} while (0)

static void mac(uint8_t out[FZN_SIG_LEN], uint8_t key, const uint8_t *msg, size_t len)
{
	uint64_t h = 0xcbf29ce484222325ull ^ key;
	size_t i;

	for (i = 0; i < len; i++)
		h = (h ^ msg[i]) * 0x100000001b3ull;
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h = (h ^ (uint64_t)i) * 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 56);
	}
}

static uint8_t signing_as;

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t len)
{
	(void)ctx;
	mac(sig, signing_as, msg, len);
	return 1;
}

static int stub_verify(void *ctx, const uint8_t pk[FZN_PUBKEY_LEN], const uint8_t *msg, size_t len,
                       const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	mac(want, pk[0], msg, len);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

static const fzn_sign_ops_t SIGN = { stub_verify, stub_sign, NULL };

static int mix_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint64_t h = 0x84222325cbf29ce4ull;
	size_t i;

	(void)ctx;
	for (i = 0; i < in_len; i++)
		h = (h ^ in[i]) * 0x100000001b3ull;
	for (i = 0; i < out_len; i++) {
		h = (h ^ (uint64_t)i) * 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 40);
	}
	return 1;
}

static const fzn_hash_ops_t HASH = { mix_hash, NULL };

/* ---- a store per node ---------------------------------------------------- */

#define ROWS 400

struct row {
	int used;
	fzn_persist_slot_t slot;
	uint8_t subject[FZN_PUBKEY_LEN];
	uint8_t bytes[FZN_BUCKETS_ITEM_MAX + 64u];
	size_t len;
};

struct mem {
	struct row rows[ROWS];
	/* The save that fails, counting from 1; 0 for none. */
	int fail_at, saves;
};

static struct row *row_of(struct mem *m, fzn_persist_slot_t slot, const uint8_t *subject, int make)
{
	int i, free_one = -1;

	for (i = 0; i < ROWS; i++) {
		if (!m->rows[i].used) {
			if (free_one < 0)
				free_one = i;
			continue;
		}
		if (m->rows[i].slot == slot && memcmp(m->rows[i].subject, subject, FZN_PUBKEY_LEN) == 0)
			return &m->rows[i];
	}
	if (!make || free_one < 0)
		return NULL;
	m->rows[free_one].used = 1;
	m->rows[free_one].slot = slot;
	memcpy(m->rows[free_one].subject, subject, FZN_PUBKEY_LEN);
	return &m->rows[free_one];
}

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	struct row *r = row_of((struct mem *)ctx, slot, subject, 0);

	if (!r || r->len > cap)
		return 0;
	memcpy(out, r->bytes, r->len);
	*len = r->len;
	return 1;
}

static int mem_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                    const uint8_t *bytes, size_t len)
{
	struct mem *m = (struct mem *)ctx;
	struct row *r;

	if (m->fail_at && ++m->saves == m->fail_at)
		return 0;
	r = row_of(m, slot, subject, 1);
	if (!r || len > sizeof(r->bytes))
		return 0;
	memcpy(r->bytes, bytes, len);
	r->len = len;
	return 1;
}

static int mem_list(void *ctx, fzn_persist_slot_t slot, uint8_t *out, size_t max, size_t *count)
{
	struct mem *m = (struct mem *)ctx;
	size_t n = 0;
	int i;

	for (i = 0; i < ROWS; i++)
		if (m->rows[i].used && m->rows[i].slot == slot) {
			if (n >= max)
				return 0;
			memcpy(out + n * FZN_PUBKEY_LEN, m->rows[i].subject, FZN_PUBKEY_LEN);
			n++;
		}
	*count = n;
	return 1;
}

static int mem_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	struct row *r = row_of((struct mem *)ctx, slot, subject, 0);

	if (r)
		memset(r, 0, sizeof(*r));
	return 1;
}


/* ---- the cases ------------------------------------------------------------ */

static struct mem node;
static const fzn_persist_ops_t STORE = { mem_load, mem_save, mem_list, mem_remove, &node, NULL };
static const fzn_buckets_t B = { &STORE, &HASH };
static fzn_node_identity_t me;
static uint64_t clock_ms = 1793500000000ull; /* 2026-11 */

static uint64_t now_ms(void)
{
	return clock_ms;
}

static fzn_node_records_t nr;
static uint8_t target[FZN_PUBKEY_LEN];
static uint64_t in_force_ms;
static char carried_value[32];
static int n_carried, votable_too = 1;
static const uint8_t KEY[] = "relay/enabled";
#define KEY_LEN 13u
#define NO_STANDING 0xccu

static int stands(void *ctx, const uint8_t voter[FZN_PUBKEY_LEN])
{
	(void)ctx;
	return voter[0] != NO_STANDING;
}

static int votable(void *ctx, const uint8_t *key, size_t key_len, uint64_t *ms)
{
	(void)ctx;
	(void)key;
	(void)key_len;
	*ms = in_force_ms;
	return votable_too;
}

static void carried(void *ctx, const uint8_t *key, size_t key_len, const uint8_t *value,
                    size_t value_len)
{
	(void)ctx;
	(void)key;
	(void)key_len;
	snprintf(carried_value, sizeof(carried_value), "%.*s", (int)value_len, (const char *)value);
	n_carried++;
}

static const fzn_node_vote_ops_t OPS = { NULL, stands, votable, carried };

static int vote(uint8_t host, const char *value)
{
	memset(me.pubkey, host, FZN_PUBKEY_LEN);
	signing_as = host;
	clock_ms += 1000u;
	return fzn_node_vote(&nr, target, KEY, KEY_LEN, (const uint8_t *)value, strlen(value))
	       == FZN_NODE_RECORDS_OK;
}

static long count(size_t k)
{
	n_carried = 0;
	carried_value[0] = '\0';
	return fzn_node_votes_count(&nr, target, k, &OPS);
}

static void reset(void)
{
	memset(&node, 0, sizeof(node));
	in_force_ms = 0;
	votable_too = 1;
}

int main(void)
{
	static uint8_t other[FZN_PUBKEY_LEN];

	me.sign = &SIGN;
	nr.b = &B;
	nr.verify = &SIGN;
	nr.id = &me;
	nr.now_ms = now_ms;
	memset(target, 0x77, sizeof(target));
	memset(other, 0x78, sizeof(other));

	CHECK(count(2u) == 0, "no votes carry nothing");
	CHECK(vote(0xa1u, "off") && count(2u) == 0 && !n_carried, "one of two does not carry");
	CHECK(vote(0xa1u, "off") && count(2u) == 0, "nor the same voter twice");
	CHECK(vote(0xa2u, "off") && count(2u) == 1 && !strcmp(carried_value, "off"), "two of two do");

	/* ---- a voter's newest is its vote */
	reset();
	CHECK(vote(0xa1u, "off") && vote(0xa2u, "off") && vote(0xa2u, "on") && count(2u) == 0,
	      "a voter that changed its mind no longer counts for the old");
	CHECK(vote(0xa1u, "on") && count(2u) == 1 && !strcmp(carried_value, "on"), "and counts for the new");

	/* ---- who is counted */
	reset();
	CHECK(vote(0xa1u, "off") && vote(NO_STANDING, "off") && count(2u) == 0,
	      "a voter with no standing is not counted");

	/* ---- what is counted */
	reset();
	CHECK(vote(0xa1u, "off") && vote(0xa2u, "off"), "two votes");
	in_force_ms = clock_ms + 1u;
	CHECK(count(2u) == 0, "older than the value in force, they count for nothing");
	in_force_ms = 0;
	votable_too = 0;
	CHECK(count(2u) == 0, "a value the profile gives to no vote is not changed by one");

	/* ---- another host's */
	reset();
	memset(me.pubkey, 0xa1, FZN_PUBKEY_LEN);
	signing_as = 0xa1u;
	CHECK(fzn_node_vote(&nr, other, KEY, KEY_LEN, (const uint8_t *)"off", 3u) == FZN_NODE_RECORDS_OK,
	      "a vote for another host");
	CHECK(vote(0xa2u, "off") && count(2u) == 0, "is not this host's");

	/* ---- refused */
	{
		static uint8_t long_key[FZN_SETTING_KEY_MAX];

		memset(long_key, 'k', sizeof(long_key));
		CHECK(fzn_node_vote(&nr, target, long_key, FZN_NODE_VOTE_KEY_MAX + 1u,
		                    (const uint8_t *)"x", 1u)
		              == FZN_NODE_RECORDS_MALFORMED,
		      "a key past a vote's room");
		CHECK(fzn_node_votes_count(&nr, target, 0u, &OPS) == -1, "a k of nothing");
	}
	printf("votes_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
