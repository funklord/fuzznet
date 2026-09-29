/* Tests for chain/root_log.c: the entry's layout, admission, and the two
 * questions a removal asks -- does an act lie on the chain up to the cut, and
 * has the root signed two entries at one seq. project.md sec 404. */

#include "../root_log.h"
#include "../../wire/bytes.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

#if defined(__GNUC__)
#define FZN_CHECK_PRINTF __attribute__((format(printf, 3, 4)))
#else
#define FZN_CHECK_PRINTF
#endif

static void check_at(int ok, int line, const char *fmt, ...) FZN_CHECK_PRINTF;

static void check_at(int ok, int line, const char *fmt, ...)
{
	va_list ap;

	checks++;
	if (ok)
		return;
	failures++;
	fprintf(stderr, "  FAIL root_log_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

/* The toy MAC the chain suites use: a key's identity is its first byte, and
 * a signature is an FNV expansion over that byte and the message. What is
 * under test is which key and which bytes are asked, not cryptography. */
static void mac(uint8_t out[FZN_SIG_LEN], uint8_t identity, const uint8_t *msg, size_t len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	h ^= (uint64_t)identity;
	h *= 0x100000001b3ull;
	for (i = 0; i < len; i++) {
		h ^= (uint64_t)msg[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h ^= (uint64_t)i + 1u;
		h *= 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 56);
	}
}

static uint8_t signing_as;

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	(void)ctx;
	mac(sig, signing_as, msg, msg_len);
	return 1;
}

static int stub_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	mac(want, pubkey[0], msg, msg_len);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	(void)ctx;
	if (!out || !in || out_len == 0)
		return 0;
	for (i = 0; i < in_len; i++) {
		h ^= (uint64_t)in[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < out_len; i++) {
		h ^= (uint64_t)i + 1u;
		h *= 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 56);
	}
	return 1;
}

static const fzn_sign_ops_t SIGN = { stub_verify, stub_sign, NULL };
static const fzn_hash_ops_t HASH = { stub_hash, NULL };

/* A key whose identity byte is `id`, the rest varying with position. */
static void key(uint8_t out[FZN_PUBKEY_LEN], uint8_t id)
{
	size_t i;

	out[0] = id;
	for (i = 1; i < FZN_PUBKEY_LEN; i++)
		out[i] = (uint8_t)(id ^ (uint8_t)i);
}

/* An act's hash, named by a seed: acts are opaque to the log. */
static void act_of(uint8_t out[FZN_ROOT_ACT_ID_LEN], uint8_t seed)
{
	memset(out, seed, FZN_ROOT_ACT_ID_LEN);
	out[0] = 0xa0u;
}

/* One entry: `root` logs act `seed` at `seq` after `prev`, into `out`, and
 * its id into `id`. */
static void entry(uint8_t out[FZN_ROOT_ACT_LEN], uint8_t id[FZN_ROOT_ACT_ID_LEN], uint8_t root,
                  uint64_t seq, const uint8_t *prev, uint8_t seed)
{
	uint8_t r[FZN_PUBKEY_LEN], a[FZN_ROOT_ACT_ID_LEN];

	key(r, root);
	act_of(a, seed);
	signing_as = root;
	CHECK(fzn_root_act_issue(r, seq, prev, (uint8_t)FZN_ROOT_ACT_GRANT, a, &SIGN, out)
	              == FZN_ROOT_LOG_OK,
	      "fixture: entry %u/%u would not sign", (unsigned)root, (unsigned)seq);
	stub_hash(NULL, id, FZN_ROOT_ACT_ID_LEN, out, FZN_ROOT_ACT_LEN);
}

static void test_the_layout(void)
{
	uint8_t e[FZN_ROOT_ACT_LEN], id[FZN_ROOT_ACT_ID_LEN], bad[FZN_ROOT_ACT_LEN];
	uint8_t r[FZN_PUBKEY_LEN], a[FZN_ROOT_ACT_ID_LEN];
	fzn_root_act_t v;

	entry(e, id, 7, 0, NULL, 1);
	key(r, 7);
	act_of(a, 1);
	CHECK(fzn_root_act_open(e, sizeof(e), &v) == FZN_ROOT_LOG_OK,
	      "an entry would not open");
	CHECK(e[0] == 1u && e[1] == (uint8_t)FZN_OBJECT_ROOT_ACT && e[1] == 139u,
	      "version or object byte is not where the table says");
	CHECK(memcmp(fzn_root_act_root(v), r, FZN_PUBKEY_LEN) == 0 && fzn_root_act_seq(v) == 0u
	              && fzn_root_act_kind(v) == (uint8_t)FZN_ROOT_ACT_GRANT
	              && memcmp(fzn_root_act_act(v), a, sizeof(a)) == 0,
	      "an entry's fields did not read back");
	CHECK(e[74] == (uint8_t)FZN_ROOT_ACT_GRANT && e[75] == 0xa0u,
	      "the kind or the act is not at 74 and 75");

	/* THE CHAIN'S SHAPE: seq 0 names nothing, every later seq names one. */
	memcpy(bad, e, sizeof(bad));
	bad[FZN_ROOT_ACT_OFF_PREV] = 1u;
	CHECK(fzn_root_act_open(bad, sizeof(bad), &v) == FZN_ROOT_LOG_ERR_SHAPE,
	      "a first entry naming a predecessor opened");
	memcpy(bad, e, sizeof(bad));
	bad[FZN_ROOT_ACT_OFF_SEQ + 7u] = 1u;
	CHECK(fzn_root_act_open(bad, sizeof(bad), &v) == FZN_ROOT_LOG_ERR_SHAPE,
	      "a later entry naming no predecessor opened");
	memcpy(bad, e, sizeof(bad));
	bad[FZN_ROOT_ACT_OFF_KIND] = 0u;
	CHECK(fzn_root_act_open(bad, sizeof(bad), &v) == FZN_ROOT_LOG_ERR_SHAPE,
	      "an entry of kind 0 opened");
	bad[FZN_ROOT_ACT_OFF_KIND] = 6u;
	CHECK(fzn_root_act_open(bad, sizeof(bad), &v) == FZN_ROOT_LOG_ERR_SHAPE,
	      "an entry of an unknown kind opened");
	CHECK(fzn_root_act_open(e, sizeof(e) - 1u, &v) == FZN_ROOT_LOG_ERR_SHAPE,
	      "a short entry opened");
	signing_as = 7;
	CHECK(fzn_root_act_issue(r, 1, NULL, (uint8_t)FZN_ROOT_ACT_GRANT, a, &SIGN, bad)
	              == FZN_ROOT_LOG_ERR_MALFORMED,
	      "a later entry with no predecessor was minted");
}

static void test_admission(void)
{
	static fzn_root_log_entry_t entries[2];
	fzn_root_log_t log;
	uint8_t e0[FZN_ROOT_ACT_LEN], e1[FZN_ROOT_ACT_LEN], e2[FZN_ROOT_ACT_LEN];
	uint8_t id0[FZN_ROOT_ACT_ID_LEN], id1[FZN_ROOT_ACT_ID_LEN], id2[FZN_ROOT_ACT_ID_LEN];

	CHECK(fzn_root_log_init(&log, entries, 2) == FZN_ROOT_LOG_OK, "init");
	entry(e0, id0, 7, 0, NULL, 1);
	entry(e1, id1, 7, 1, id0, 2);
	entry(e2, id2, 7, 2, id1, 3);
	CHECK(fzn_root_log_admit(&log, e0, sizeof(e0), &SIGN, &HASH) == FZN_ROOT_LOG_OK
	              && fzn_root_log_admit(&log, e0, sizeof(e0), &SIGN, &HASH) == FZN_ROOT_LOG_OK
	              && log.used == 1u,
	      "admitting one entry twice was not idempotent");
	e1[FZN_ROOT_ACT_OFF_SIGNATURE] ^= 1u;
	CHECK(fzn_root_log_admit(&log, e1, sizeof(e1), &SIGN, &HASH) == FZN_ROOT_LOG_ERR_SIGNATURE
	              && log.used == 1u,
	      "an entry with a broken signature was kept");
	e1[FZN_ROOT_ACT_OFF_SIGNATURE] ^= 1u;
	/* SIGNED BY ANOTHER KEY than the root it names. */
	{
		uint8_t forged[FZN_ROOT_ACT_LEN];

		memcpy(forged, e1, sizeof(forged));
		mac(forged + FZN_ROOT_ACT_OFF_SIGNATURE, 9, forged, FZN_ROOT_ACT_BODY_LEN);
		CHECK(fzn_root_log_admit(&log, forged, sizeof(forged), &SIGN, &HASH)
		              == FZN_ROOT_LOG_ERR_SIGNATURE,
		      "an entry signed by another key than its root was kept");
	}
	CHECK(fzn_root_log_admit(&log, e1, sizeof(e1), &SIGN, &HASH) == FZN_ROOT_LOG_OK
	              && fzn_root_log_admit(&log, e2, sizeof(e2), &SIGN, &HASH)
	                         == FZN_ROOT_LOG_ERR_FULL
	              && log.used == 2u,
	      "a full log took a third entry, or refused the second");
}

/* THE CUT. Root 7 logs acts 1, 2 and 3 in a chain; a removal cutting at the
 * second entry keeps acts 1 and 2 and loses 3. Admitted last-first, since a
 * log is a set and arrival order says nothing. */
static void test_the_cut(void)
{
	static fzn_root_log_entry_t entries[8];
	fzn_root_log_t log;
	uint8_t e0[FZN_ROOT_ACT_LEN], e1[FZN_ROOT_ACT_LEN], e2[FZN_ROOT_ACT_LEN];
	uint8_t id0[FZN_ROOT_ACT_ID_LEN], id1[FZN_ROOT_ACT_ID_LEN], id2[FZN_ROOT_ACT_ID_LEN];
	uint8_t seven[FZN_PUBKEY_LEN], eight[FZN_PUBKEY_LEN];
	uint8_t a1[FZN_ROOT_ACT_ID_LEN], a2[FZN_ROOT_ACT_ID_LEN], a3[FZN_ROOT_ACT_ID_LEN];
	uint8_t a9[FZN_ROOT_ACT_ID_LEN];

	key(seven, 7);
	key(eight, 8);
	act_of(a1, 1);
	act_of(a2, 2);
	act_of(a3, 3);
	act_of(a9, 9);
	entry(e0, id0, 7, 0, NULL, 1);
	entry(e1, id1, 7, 1, id0, 2);
	entry(e2, id2, 7, 2, id1, 3);
	CHECK(fzn_root_log_init(&log, entries, 8) == FZN_ROOT_LOG_OK
	              && fzn_root_log_admit(&log, e2, sizeof(e2), &SIGN, &HASH) == FZN_ROOT_LOG_OK
	              && fzn_root_log_admit(&log, e1, sizeof(e1), &SIGN, &HASH) == FZN_ROOT_LOG_OK
	              && fzn_root_log_admit(&log, e0, sizeof(e0), &SIGN, &HASH) == FZN_ROOT_LOG_OK,
	      "fixture: a chain of three");
	CHECK(fzn_root_log_stands(&log, seven, id1, a1) && fzn_root_log_stands(&log, seven, id1, a2),
	      "an act before the cut, or the cut's own, did not stand");
	CHECK(!fzn_root_log_stands(&log, seven, id1, a3),
	      "an act after the cut stood");
	CHECK(fzn_root_log_stands(&log, seven, id2, a3),
	      "the last act did not stand under a cut at the end");
	CHECK(!fzn_root_log_stands(&log, seven, id1, a9), "an act never logged stood");
	CHECK(!fzn_root_log_stands(&log, eight, id1, a1),
	      "another root's cut reached this root's acts");
	CHECK(!fzn_root_log_forked(&log, seven), "a straight chain was called a fork");

	/* A FORK: a second entry at seq 1, as a thief replaying from seq 0
	 * makes. Seen as a fork; its act does not stand under the honest cut,
	 * and the honest history before the fork stands under either. */
	{
		uint8_t f1[FZN_ROOT_ACT_LEN], fid[FZN_ROOT_ACT_ID_LEN];

		entry(f1, fid, 7, 1, id0, 9);
		CHECK(fzn_root_log_admit(&log, f1, sizeof(f1), &SIGN, &HASH) == FZN_ROOT_LOG_OK,
		      "a fork was refused rather than kept as evidence");
		CHECK(fzn_root_log_forked(&log, seven), "two entries at one seq were not a fork");
		CHECK(!fzn_root_log_stands(&log, seven, id2, a9),
		      "an act on a fork stood under the honest cut");
		CHECK(fzn_root_log_stands(&log, seven, fid, a1),
		      "the history shared before the fork did not stand");
	}
}

/* A BROKEN CHAIN DOES NOT STAND: a missing link, a link that skips a seq, and
 * a link to another root's entry. */
static void test_a_broken_chain(void)
{
	static fzn_root_log_entry_t entries[8];
	fzn_root_log_t log;
	uint8_t e0[FZN_ROOT_ACT_LEN], e1[FZN_ROOT_ACT_LEN], e2[FZN_ROOT_ACT_LEN];
	uint8_t skip[FZN_ROOT_ACT_LEN], other[FZN_ROOT_ACT_LEN];
	uint8_t id0[FZN_ROOT_ACT_ID_LEN], id1[FZN_ROOT_ACT_ID_LEN], id2[FZN_ROOT_ACT_ID_LEN];
	uint8_t sid[FZN_ROOT_ACT_ID_LEN], oid[FZN_ROOT_ACT_ID_LEN];
	uint8_t seven[FZN_PUBKEY_LEN], eight[FZN_PUBKEY_LEN], a1[FZN_ROOT_ACT_ID_LEN];

	key(seven, 7);
	key(eight, 8);
	act_of(a1, 1);
	entry(e0, id0, 7, 0, NULL, 1);
	entry(e1, id1, 7, 1, id0, 2);
	entry(e2, id2, 7, 2, id1, 3);
	entry(skip, sid, 7, 3, id0, 4);
	entry(other, oid, 8, 2, id1, 5);
	CHECK(fzn_root_log_init(&log, entries, 8) == FZN_ROOT_LOG_OK
	              && fzn_root_log_admit(&log, e0, sizeof(e0), &SIGN, &HASH) == FZN_ROOT_LOG_OK
	              && fzn_root_log_admit(&log, e2, sizeof(e2), &SIGN, &HASH) == FZN_ROOT_LOG_OK,
	      "fixture: a chain with its middle missing");
	CHECK(!fzn_root_log_stands(&log, seven, id2, a1),
	      "an act behind a link this log does not hold stood");
	CHECK(fzn_root_log_admit(&log, e1, sizeof(e1), &SIGN, &HASH) == FZN_ROOT_LOG_OK
	              && fzn_root_log_stands(&log, seven, id2, a1),
	      "the control: with the link held the act did not stand");
	CHECK(fzn_root_log_admit(&log, skip, sizeof(skip), &SIGN, &HASH) == FZN_ROOT_LOG_OK
	              && !fzn_root_log_stands(&log, seven, sid, a1),
	      "a link that skips a seq was followed");
	CHECK(fzn_root_log_admit(&log, other, sizeof(other), &SIGN, &HASH) == FZN_ROOT_LOG_OK
	              && !fzn_root_log_stands(&log, eight, oid, a1),
	      "a chain was followed into another root's entries");
}

int main(void)
{
	test_the_layout();
	test_admission();
	test_the_cut();
	test_a_broken_chain();
	printf("root_log_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
