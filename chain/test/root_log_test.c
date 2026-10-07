/* Tests for chain/root_log.c: the root set, its removals and their cuts
 * (sec 405), the estate's k (sec 418) and its retention rules (sec 476).
 *
 * The root log's own entries are gone since sec 509 -- the journal is the act
 * log, and `node/test/node_journal_test.c` tests a cut, a fork and a store
 * edited underneath -- so a removal's cut is asked here of the act-log stub. */

#include "../root_log.h"
#include "../revocation.h"
#include "../../wire/bytes.h"
#include "acts_stub.h"

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

/* ---- the root set, sec 405 ------------------------------------------- */

/* A signed root-set record into `out`, its id into `id`. */
static size_t change(uint8_t *out, uint8_t id[FZN_ROOT_ACT_ID_LEN], int remove, uint8_t signer,
                     uint8_t subject, const uint8_t *cut)
{
	uint8_t a[FZN_PUBKEY_LEN], b[FZN_PUBKEY_LEN];
	size_t len = remove ? FZN_ROOT_REMOVE_LEN : FZN_ROOT_ADD_LEN;

	key(a, signer);
	key(b, subject);
	signing_as = signer;
	CHECK((remove ? fzn_root_remove_issue(a, b, cut, &SIGN, out)
	              : fzn_root_add_issue(a, b, &SIGN, out)) == FZN_ROOT_LOG_OK,
	      "fixture: a root-set record would not sign");
	stub_hash(NULL, id, FZN_ROOT_ACT_ID_LEN, out, len);
	return len;
}

/* `root` logs the act `act` after the entry `prev` in `log`, the act-log stub
 * (`acts_stub.h`, sec 509); the entry's id into `id`. */
static void logged(acts_stub_t *log, uint8_t id[FZN_ROOT_ACT_ID_LEN], uint8_t root,
                   const uint8_t *prev, const uint8_t act[FZN_ROOT_ACT_ID_LEN])
{
	uint8_t r[FZN_PUBKEY_LEN];

	key(r, root);
	CHECK(acts_stub_log(log, r, prev, act, id), "fixture: an act logged");
}

/* The log's act-log ops, which the root set asks since sec 506: a fresh
 * pair per call, so two logs in one expression do not share one. */
#define ACTS_OF(log) (acts_stub_ops((log), &acts_scratch[acts_turn ^= 1u]), \
                      (const fzn_act_log_ops_t *)&acts_scratch[acts_turn])
static fzn_act_log_ops_t acts_scratch[2];
static unsigned acts_turn;

static int stands_key(const fzn_root_set_t *set, acts_stub_t *log, uint8_t id)
{
	uint8_t k[FZN_PUBKEY_LEN];

	key(k, id);
	return fzn_root_set_stands(set, log ? ACTS_OF(log) : NULL, k);
}

static int counts_act(const fzn_root_set_t *set, acts_stub_t *log, uint8_t root,
                      const uint8_t act[FZN_ROOT_ACT_ID_LEN])
{
	uint8_t k[FZN_PUBKEY_LEN];

	key(k, root);
	return fzn_root_set_counts(set, log ? ACTS_OF(log) : NULL, k, act);
}

/* THE THEFT, told in the order it happens and judged from the records.
 *
 * Genesis root 1 adds root 2 and grants act 10. A thief holding root 1's key
 * then adds root 3 and grants act 11, both logged after. Root 2 removes root
 * 1 at the cut after act 10. So: root 1's acts up to the cut still count --
 * root 2 stays a root, act 10 stays granted -- and nothing after does: root 3
 * was never a root, act 11 was never granted, and root 3's removal of root 2
 * counts for nothing. Every order of the four records gives that. */
static void test_the_theft(void)
{
	static acts_stub_t log;
	static fzn_root_change_t changes[4];
	uint8_t recs[4][FZN_ROOT_REMOVE_LEN], rids[4][FZN_ROOT_ACT_ID_LEN];
	size_t lens[4];
	uint8_t e0[FZN_ROOT_ACT_ID_LEN], e1[FZN_ROOT_ACT_ID_LEN], e2[FZN_ROOT_ACT_ID_LEN];
	uint8_t e3[FZN_ROOT_ACT_ID_LEN], t0[FZN_ROOT_ACT_ID_LEN], h0[FZN_ROOT_ACT_ID_LEN];
	uint8_t a10[FZN_ROOT_ACT_ID_LEN], a11[FZN_ROOT_ACT_ID_LEN], genesis[FZN_PUBKEY_LEN];
	static const uint8_t orders[4][4] = {
		{ 0, 1, 2, 3 }, { 3, 2, 1, 0 }, { 2, 0, 3, 1 }, { 1, 3, 0, 2 }
	};
	fzn_root_set_t set;
	size_t o, i;

	act_of(a10, 10);
	act_of(a11, 11);
	key(genesis, 1);
	memset(&log, 0, sizeof(log));
	lens[0] = change(recs[0], rids[0], 0, 1, 2, NULL);	/* 1 adds 2 */
	lens[1] = change(recs[1], rids[1], 0, 1, 3, NULL);	/* the thief: 1 adds 3 */
	logged(&log, e0, 1, NULL, rids[0]);
	logged(&log, e1, 1, e0, a10);
	logged(&log, e2, 1, e1, rids[1]);
	logged(&log, e3, 1, e2, a11);
	lens[2] = change(recs[2], rids[2], 1, 2, 1, e1);	/* 2 removes 1 at e1 */
	logged(&log, h0, 2, NULL, rids[2]);
	lens[3] = change(recs[3], rids[3], 1, 3, 2, NULL);	/* 3 removes 2 */
	logged(&log, t0, 3, NULL, rids[3]);

	for (o = 0; o < 4u; o++) {
		CHECK(fzn_root_set_init(&set, genesis, changes, 4) == FZN_ROOT_LOG_OK, "fixture: set");
		for (i = 0; i < 4u; i++)
			CHECK(fzn_root_set_admit(&set, recs[orders[o][i]], lens[orders[o][i]], &SIGN,
			                         &HASH) == FZN_ROOT_LOG_OK,
			      "order %zu: a record was refused", o);
		CHECK(!stands_key(&set, &log, 1) && fzn_root_set_member(&set, ACTS_OF(&log), genesis),
		      "order %zu: the removed genesis root still stands, or stopped being a member",
		      o);
		CHECK(stands_key(&set, &log, 2),
		      "order %zu: the root added before the cut does not stand", o);
		CHECK(counts_act(&set, &log, 1, a10),
		      "order %zu: the genesis root's act before the cut does not count", o);
		CHECK(!counts_act(&set, &log, 1, a11),
		      "order %zu: the genesis root's act after the cut still counts", o);
		CHECK(!stands_key(&set, &log, 3),
		      "order %zu: the root the thief added after the cut stands", o);
	}
}

/* REMOVALS WIN: two roots removing each other both fall, and nothing either
 * did afterwards counts. With no cut nothing of the removed root stands; the
 * control is that before the removals both stood. */
static void test_mutual_removal(void)
{
	static acts_stub_t log;
	static fzn_root_change_t changes[4];
	uint8_t add[FZN_ROOT_ADD_LEN], r12[FZN_ROOT_REMOVE_LEN], r21[FZN_ROOT_REMOVE_LEN];
	uint8_t id_add[FZN_ROOT_ACT_ID_LEN], id12[FZN_ROOT_ACT_ID_LEN], id21[FZN_ROOT_ACT_ID_LEN];
	uint8_t e0[FZN_ROOT_ACT_ID_LEN], genesis[FZN_PUBKEY_LEN];
	fzn_root_set_t set;

	key(genesis, 1);
	memset(&log, 0, sizeof(log));
	CHECK(fzn_root_set_init(&set, genesis, changes, 4) == FZN_ROOT_LOG_OK, "fixture");
	change(add, id_add, 0, 1, 2, NULL);
	logged(&log, e0, 1, NULL, id_add);
	CHECK(fzn_root_set_admit(&set, add, sizeof(add), &SIGN, &HASH) == FZN_ROOT_LOG_OK
	              && stands_key(&set, &log, 1) && stands_key(&set, &log, 2),
	      "the control: before any removal both roots did not stand");
	change(r12, id12, 1, 1, 2, NULL);
	change(r21, id21, 1, 2, 1, e0);
	CHECK(fzn_root_set_admit(&set, r12, sizeof(r12), &SIGN, &HASH) == FZN_ROOT_LOG_OK
	              && fzn_root_set_admit(&set, r21, sizeof(r21), &SIGN, &HASH) == FZN_ROOT_LOG_OK,
	      "fixture: the removals");
	CHECK(!stands_key(&set, &log, 1) && !stands_key(&set, &log, 2),
	      "two roots removing each other did not both fall");

	/* WITH NO CUTS THE ROUNDS NEVER SETTLE: 1's removal of 2 takes away
	 * nothing 1 did, 2's removal of 1 takes away 1's add of 2, which takes
	 * away 2's removal of 1, and round it goes. The set takes every removal
	 * any round saw, and both still fall. */
	CHECK(fzn_root_set_init(&set, genesis, changes, 4) == FZN_ROOT_LOG_OK
	              && fzn_root_set_admit(&set, add, sizeof(add), &SIGN, &HASH) == FZN_ROOT_LOG_OK
	              && fzn_root_set_admit(&set, r12, sizeof(r12), &SIGN, &HASH) == FZN_ROOT_LOG_OK,
	      "fixture: a set with no cuts");
	change(r21, id21, 1, 2, 1, NULL);
	CHECK(fzn_root_set_admit(&set, r21, sizeof(r21), &SIGN, &HASH) == FZN_ROOT_LOG_OK
	              && !stands_key(&set, &log, 1) && !stands_key(&set, &log, 2),
	      "a set that never settles did not fall toward removal");
}

/* A REMOVED ROOT WITH NO LOG, OR NO CUT, KEEPS NOTHING, and the set refuses
 * what it should: a bad signature, a stranger's object, a capacity past its
 * bound; and one record admitted twice is kept once. */
static void test_the_set_refuses(void)
{
	static fzn_root_change_t changes[FZN_ROOT_SET_MAX + 1u];
	static acts_stub_t log;
	uint8_t add[FZN_ROOT_ADD_LEN], rem[FZN_ROOT_REMOVE_LEN], id[FZN_ROOT_ACT_ID_LEN];
	uint8_t e0[FZN_ROOT_ACT_ID_LEN], a10[FZN_ROOT_ACT_ID_LEN], genesis[FZN_PUBKEY_LEN];
	fzn_root_set_t set;

	key(genesis, 1);
	act_of(a10, 10);
	CHECK(fzn_root_set_init(&set, genesis, changes, FZN_ROOT_SET_MAX + 1u)
	              == FZN_ROOT_LOG_ERR_MALFORMED,
	      "a set past its bound was accepted");
	memset(&log, 0, sizeof(log));
	CHECK(fzn_root_set_init(&set, genesis, changes, 4) == FZN_ROOT_LOG_OK, "fixture");
	CHECK(stands_key(&set, &log, 1) && !stands_key(&set, &log, 9),
	      "the genesis root does not stand alone, or a stranger does");
	change(add, id, 0, 1, 2, NULL);
	CHECK(fzn_root_set_admit(&set, add, sizeof(add), &SIGN, &HASH) == FZN_ROOT_LOG_OK
	              && fzn_root_set_admit(&set, add, sizeof(add), &SIGN, &HASH) == FZN_ROOT_LOG_OK
	              && set.used == 1u,
	      "one record admitted twice was not kept once");
	add[FZN_ROOT_ADD_BODY_LEN] ^= 1u;
	CHECK(fzn_root_set_admit(&set, add, sizeof(add), &SIGN, &HASH)
	              == FZN_ROOT_LOG_ERR_SIGNATURE,
	      "a root-add with a broken signature was kept");
	add[1] = (uint8_t)FZN_OBJECT_REVOCATION;
	CHECK(fzn_root_set_admit(&set, add, sizeof(add), &SIGN, &HASH) == FZN_ROOT_LOG_ERR_SHAPE,
	      "another object was read as a root-set record");
	/* THE GENESIS ROOT REMOVED AT A CUT, judged with and without the log:
	 * with it the act before the cut counts; without it nothing can be
	 * shown to stand. And a removal naming no cut keeps nothing. */
	logged(&log, e0, 1, NULL, a10);
	change(rem, id, 1, 2, 1, e0);
	CHECK(fzn_root_set_admit(&set, rem, sizeof(rem), &SIGN, &HASH) == FZN_ROOT_LOG_OK
	              && counts_act(&set, &log, 1, a10) && !counts_act(&set, NULL, 1, a10),
	      "an act before the cut did not count with the log, or counted without it");
	change(rem, id, 1, 2, 1, NULL);
	CHECK(fzn_root_set_admit(&set, rem, sizeof(rem), &SIGN, &HASH) == FZN_ROOT_LOG_OK
	              && !counts_act(&set, &log, 1, a10),
	      "under a second removal naming no cut, an act of the removed root counted");
}

/* ---- the estate's k, sec 418 ------------------------------------------ */

/* Setting `k` by root `setter` after the setting whose record is `after`
 * (NULL for none), into `out`. */
static void setting(uint8_t out[FZN_QUORUM_SET_LEN], uint8_t setter, uint8_t k,
                    const uint8_t *after)
{
	uint8_t who[FZN_PUBKEY_LEN], replaces[FZN_ROOT_ACT_ID_LEN];

	key(who, setter);
	if (after)
		stub_hash(NULL, replaces, sizeof(replaces), after, FZN_QUORUM_SET_LEN);
	signing_as = setter;
	CHECK(fzn_quorum_set_issue(who, k, after ? replaces : NULL, &SIGN, out) == FZN_ROOT_LOG_OK,
	      "a setting of k would not issue");
}

/* Setter seed 9 is removed with nothing kept; every other key's acts count. */
static int counts_but_nine(void *ctx, const uint8_t root[FZN_PUBKEY_LEN],
                           const uint8_t act[FZN_ROOT_ACT_ID_LEN])
{
	(void)ctx;
	(void)act;
	return root[0] != 9u;
}

static int member_any(void *ctx, const uint8_t key_bytes[FZN_PUBKEY_LEN])
{
	(void)ctx;
	(void)key_bytes;
	return 1;
}

/* THE RULE. No setting: the fallback. A and B set 3 and 2 without seeing
 * each other: 3, whichever order they are held in. C replaces A with 1:
 * B's 2 is now the higher current one. D replaces B with 1: 1. A setting
 * by a root whose acts no longer count changes nothing. A setting of 0, a
 * foreign object and a forged signature are refused. */
static void test_the_estates_k(void)
{
	static uint8_t held[5][FZN_QUORUM_SET_LEN], swapped[2][FZN_QUORUM_SET_LEN];
	static const fzn_root_ops_t SET = { member_any, counts_but_nine, NULL };
	uint8_t bad[FZN_QUORUM_SET_LEN], who[FZN_PUBKEY_LEN], winner[FZN_ROOT_ACT_ID_LEN];
	uint8_t a_id[FZN_ROOT_ACT_ID_LEN], k = 0;

	CHECK(fzn_quorum_resolve((const uint8_t *)held, 0, NULL, &HASH, 2u) == 2u,
	      "no setting did not answer the fallback");
	setting(held[0], 1, 3, NULL);
	setting(held[1], 2, 2, NULL);
	CHECK(fzn_quorum_resolve((const uint8_t *)held, 2, NULL, &HASH, 1u) == 3u,
	      "between concurrent settings of 3 and 2, the higher did not win");
	memcpy(swapped[0], held[1], FZN_QUORUM_SET_LEN);
	memcpy(swapped[1], held[0], FZN_QUORUM_SET_LEN);
	CHECK(fzn_quorum_resolve((const uint8_t *)swapped, 2, NULL, &HASH, 1u) == 3u,
	      "the order the settings are held in changed k");
	CHECK(fzn_quorum_winner((const uint8_t *)held, 2, NULL, &HASH, &k, winner) && k == 3u
	              && stub_hash(NULL, a_id, sizeof(a_id), held[0], FZN_QUORUM_SET_LEN)
	              && memcmp(winner, a_id, sizeof(a_id)) == 0,
	      "the winner is not A's setting, by its hash");
	setting(held[2], 1, 1, held[0]);
	CHECK(fzn_quorum_resolve((const uint8_t *)held, 3, NULL, &HASH, 5u) == 2u,
	      "C replacing A did not leave B's 2 as the higher current setting");
	setting(held[3], 2, 1, held[1]);
	CHECK(fzn_quorum_resolve((const uint8_t *)held, 4, NULL, &HASH, 5u) == 1u,
	      "with A and B both replaced by settings of 1, k is not 1");
	setting(held[4], 9, 7, NULL);
	CHECK(fzn_quorum_resolve((const uint8_t *)held, 5, NULL, &HASH, 5u) == 7u
	              && fzn_quorum_resolve((const uint8_t *)held, 5, &SET, &HASH, 5u) == 1u,
	      "a removed root's setting of 7 counted, or the control did not count it");

	setting(bad, 1, 3, NULL);
	CHECK(fzn_quorum_set_check(bad, sizeof(bad), &SIGN) == FZN_ROOT_LOG_OK,
	      "a sound setting did not check");
	key(who, 1);
	CHECK(fzn_quorum_set_issue(who, 0, NULL, &SIGN, bad) == FZN_ROOT_LOG_ERR_MALFORMED,
	      "a setting of 0 was issued");
	setting(bad, 1, 3, NULL);
	bad[FZN_QUORUM_SET_OFF_K] = 0u;
	CHECK(fzn_quorum_set_check(bad, sizeof(bad), &SIGN) == FZN_ROOT_LOG_ERR_SHAPE,
	      "a setting of 0 was taken");
	setting(bad, 1, 3, NULL);
	bad[1] = (uint8_t)FZN_OBJECT_ROOT_ADD;
	CHECK(fzn_quorum_set_check(bad, sizeof(bad), &SIGN) == FZN_ROOT_LOG_ERR_SHAPE,
	      "another object was taken as a setting");
	setting(bad, 1, 3, NULL);
	bad[FZN_QUORUM_SET_OFF_K] = 4u;
	CHECK(fzn_quorum_set_check(bad, sizeof(bad), &SIGN) == FZN_ROOT_LOG_ERR_SIGNATURE,
	      "a setting whose k was changed after signing was taken");
}

/* One estate retention rule by root `setter` replacing `after` (NULL for
 * none); `text` NULL removes `after`. */
static void rule_record(uint8_t out[FZN_RETENTION_SET_LEN], uint8_t setter, const char *text,
                        const uint8_t *after)
{
	uint8_t who[FZN_PUBKEY_LEN], replaces[FZN_ROOT_ACT_ID_LEN];

	key(who, setter);
	if (after)
		stub_hash(NULL, replaces, sizeof(replaces), after, FZN_RETENTION_SET_LEN);
	signing_as = setter;
	CHECK(fzn_retention_set_issue(who, text, text ? strlen(text) : 0u, after ? replaces : NULL,
	                              &SIGN, out)
	              == FZN_ROOT_LOG_OK,
	      "a retention record would not issue");
}

static char seen_rules[8][FZN_RETENTION_SET_TEXT_MAX];
static size_t seen_count;

static void collect(void *ctx, const char *text, size_t len,
                    const uint8_t id[FZN_ROOT_ACT_ID_LEN])
{
	(void)ctx;
	(void)id;
	if (seen_count < 8u && len < FZN_RETENTION_SET_TEXT_MAX)
		memcpy(seen_rules[seen_count++], text, len + 1u);
}

/* The estate's rules as `count` records resolve, joined by `|`. */
static const char *rules_of(const uint8_t *records, size_t count, const fzn_root_ops_t *roots)
{
	static char joined[1024];
	size_t i;
	int n;

	seen_count = 0;
	joined[0] = '\0';
	n = fzn_retention_current(records, count, roots, &HASH, collect, NULL);
	if (n < 0)
		return "refused";
	for (i = 0; i < seen_count; i++) {
		if (i)
			strcat(joined, "|");
		strcat(joined, seen_rules[i]);
	}
	return (size_t)n == seen_count ? joined : "miscounted";
}

/* THE ESTATE'S RETENTION RULES, sec 476. A and B add rules without seeing
 * each other: both stand, whatever order they are held in. C removes A's:
 * B's alone. D changes B's: D's alone. A removed root's rule does not
 * count. A removal naming nothing, an unprintable byte, padding that is
 * not zero, another object and a forged signature are refused. */
static void test_the_estates_retention(void)
{
	static uint8_t held[5][FZN_RETENTION_SET_LEN], swapped[2][FZN_RETENTION_SET_LEN];
	static const fzn_root_ops_t SET = { member_any, counts_but_nine, NULL };
	uint8_t bad[FZN_RETENTION_SET_LEN], who[FZN_PUBKEY_LEN];
	const char *both;

	CHECK(strcmp(rules_of((const uint8_t *)held, 0, NULL), "") == 0, "no record, no rules");
	rule_record(held[0], 1, "prune * age 30d", NULL);
	rule_record(held[1], 2, "keep * level=CEW age 90d", NULL);
	both = rules_of((const uint8_t *)held, 2, NULL);
	CHECK(strstr(both, "prune * age 30d") && strstr(both, "keep * level=CEW age 90d")
	              && strlen(both) == strlen("prune * age 30d|keep * level=CEW age 90d"),
	      "two roots' rules set without seeing each other did not both stand");
	memcpy(swapped[0], held[1], FZN_RETENTION_SET_LEN);
	memcpy(swapped[1], held[0], FZN_RETENTION_SET_LEN);
	CHECK(strcmp(rules_of((const uint8_t *)swapped, 2, NULL), both) == 0,
	      "the order the records are held in changed the rules or their order");
	rule_record(held[2], 1, NULL, held[0]);
	CHECK(strcmp(rules_of((const uint8_t *)held, 3, NULL), "keep * level=CEW age 90d") == 0,
	      "removing A's rule did not leave B's alone");
	rule_record(held[3], 2, "keep * level=CEW age 180d", held[1]);
	CHECK(strcmp(rules_of((const uint8_t *)held, 4, NULL), "keep * level=CEW age 180d") == 0,
	      "changing B's rule did not leave the change alone");
	rule_record(held[4], 9, "prune * age 1d", NULL);
	CHECK(strstr(rules_of((const uint8_t *)held, 5, NULL), "prune * age 1d")
	              && strcmp(rules_of((const uint8_t *)held, 5, &SET), "keep * level=CEW age 180d")
	                         == 0,
	      "a removed root's rule counted, or the control did not count it");

	rule_record(bad, 1, "prune * age 30d", NULL);
	CHECK(fzn_retention_set_check(bad, sizeof(bad), &SIGN) == FZN_ROOT_LOG_OK,
	      "a sound record did not check");
	key(who, 1);
	CHECK(fzn_retention_set_issue(who, NULL, 0u, NULL, &SIGN, bad) == FZN_ROOT_LOG_ERR_MALFORMED
	              && fzn_retention_set_issue(who, "a\tb", 3u, NULL, &SIGN, bad)
	                         == FZN_ROOT_LOG_ERR_MALFORMED,
	      "a removal naming nothing, or an unprintable byte, was issued");
	rule_record(bad, 1, "prune * age 30d", NULL);
	memset(bad + FZN_RETENTION_SET_OFF_TEXT, 0, FZN_RETENTION_SET_TEXT_MAX);
	CHECK(fzn_retention_set_check(bad, sizeof(bad), &SIGN) == FZN_ROOT_LOG_ERR_SHAPE,
	      "a record with no text replacing nothing was taken");
	rule_record(bad, 1, "prune * age 30d", NULL);
	bad[FZN_RETENTION_SET_OFF_TEXT + 100u] = 'x';
	CHECK(fzn_retention_set_check(bad, sizeof(bad), &SIGN) == FZN_ROOT_LOG_ERR_SHAPE,
	      "a byte past the text's end was taken");
	rule_record(bad, 1, "prune * age 30d", NULL);
	bad[1] = (uint8_t)FZN_OBJECT_QUORUM_SET;
	CHECK(fzn_retention_set_check(bad, sizeof(bad), &SIGN) == FZN_ROOT_LOG_ERR_SHAPE,
	      "another object was taken as a retention record");
	rule_record(bad, 1, "prune * age 30d", NULL);
	bad[FZN_RETENTION_SET_OFF_TEXT + 12u] = '9';
	CHECK(fzn_retention_set_check(bad, sizeof(bad), &SIGN) == FZN_ROOT_LOG_ERR_SIGNATURE,
	      "a rule changed after signing was taken");
}

int main(void)
{
	test_the_theft();
	test_mutual_removal();
	test_the_set_refuses();
	test_the_estates_k();
	test_the_estates_retention();
	printf("root_log_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
