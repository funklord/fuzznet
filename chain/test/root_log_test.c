/* Tests for chain/root_log.c: the entry's layout, admission, and the two
 * questions a removal asks -- does an act lie on the chain up to the cut, and
 * has the root signed two entries at one seq. project.md sec 404. */

#include "../root_log.h"
#include "../revocation.h"
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
	/* THE FIRST VALUE PAST THE LAST KIND, named from the enum so a kind
	 * added later moves it: it was 6 until sec 418 made 6 a setting. */
	bad[FZN_ROOT_ACT_OFF_KIND] = (uint8_t)(FZN_ROOT_ACT_SETTING + 1u);
	CHECK(fzn_root_act_open(bad, sizeof(bad), &v) == FZN_ROOT_LOG_ERR_SHAPE,
	      "an entry of an unknown kind opened");
	bad[FZN_ROOT_ACT_OFF_KIND] = (uint8_t)FZN_ROOT_ACT_SETTING;
	CHECK(fzn_root_act_open(bad, sizeof(bad), &v) == FZN_ROOT_LOG_OK,
	      "an entry of the setting kind was refused for its kind");
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

/* A log entry by `root` at `seq` after `prev`, naming the act `act`, admitted
 * into `log`; its id into `id`. */
static void logged(fzn_root_log_t *log, uint8_t id[FZN_ROOT_ACT_ID_LEN], uint8_t root,
                   uint64_t seq, const uint8_t *prev, const uint8_t act[FZN_ROOT_ACT_ID_LEN])
{
	uint8_t r[FZN_PUBKEY_LEN], e[FZN_ROOT_ACT_LEN];

	key(r, root);
	signing_as = root;
	CHECK(fzn_root_act_issue(r, seq, prev, (uint8_t)FZN_ROOT_ACT_GRANT, act, &SIGN, e)
	              == FZN_ROOT_LOG_OK
	              && fzn_root_log_admit(log, e, sizeof(e), &SIGN, &HASH) == FZN_ROOT_LOG_OK,
	      "fixture: a log entry");
	stub_hash(NULL, id, FZN_ROOT_ACT_ID_LEN, e, sizeof(e));
}

static int stands_key(const fzn_root_set_t *set, const fzn_root_log_t *log, uint8_t id)
{
	uint8_t k[FZN_PUBKEY_LEN];

	key(k, id);
	return fzn_root_set_stands(set, log, k);
}

static int counts_act(const fzn_root_set_t *set, const fzn_root_log_t *log, uint8_t root,
                      const uint8_t act[FZN_ROOT_ACT_ID_LEN])
{
	uint8_t k[FZN_PUBKEY_LEN];

	key(k, root);
	return fzn_root_set_counts(set, log, k, act);
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
	static fzn_root_log_entry_t entries[8];
	static fzn_root_change_t changes[4];
	uint8_t recs[4][FZN_ROOT_REMOVE_LEN], rids[4][FZN_ROOT_ACT_ID_LEN];
	size_t lens[4];
	uint8_t e0[FZN_ROOT_ACT_ID_LEN], e1[FZN_ROOT_ACT_ID_LEN], e2[FZN_ROOT_ACT_ID_LEN];
	uint8_t e3[FZN_ROOT_ACT_ID_LEN], t0[FZN_ROOT_ACT_ID_LEN], h0[FZN_ROOT_ACT_ID_LEN];
	uint8_t a10[FZN_ROOT_ACT_ID_LEN], a11[FZN_ROOT_ACT_ID_LEN], genesis[FZN_PUBKEY_LEN];
	static const uint8_t orders[4][4] = {
		{ 0, 1, 2, 3 }, { 3, 2, 1, 0 }, { 2, 0, 3, 1 }, { 1, 3, 0, 2 }
	};
	fzn_root_log_t log;
	fzn_root_set_t set;
	size_t o, i;

	act_of(a10, 10);
	act_of(a11, 11);
	key(genesis, 1);
	CHECK(fzn_root_log_init(&log, entries, 8) == FZN_ROOT_LOG_OK, "fixture: log");
	lens[0] = change(recs[0], rids[0], 0, 1, 2, NULL);	/* 1 adds 2 */
	lens[1] = change(recs[1], rids[1], 0, 1, 3, NULL);	/* the thief: 1 adds 3 */
	logged(&log, e0, 1, 0, NULL, rids[0]);
	logged(&log, e1, 1, 1, e0, a10);
	logged(&log, e2, 1, 2, e1, rids[1]);
	logged(&log, e3, 1, 3, e2, a11);
	lens[2] = change(recs[2], rids[2], 1, 2, 1, e1);	/* 2 removes 1 at e1 */
	logged(&log, h0, 2, 0, NULL, rids[2]);
	lens[3] = change(recs[3], rids[3], 1, 3, 2, NULL);	/* 3 removes 2 */
	logged(&log, t0, 3, 0, NULL, rids[3]);

	for (o = 0; o < 4u; o++) {
		CHECK(fzn_root_set_init(&set, genesis, changes, 4) == FZN_ROOT_LOG_OK, "fixture: set");
		for (i = 0; i < 4u; i++)
			CHECK(fzn_root_set_admit(&set, recs[orders[o][i]], lens[orders[o][i]], &SIGN,
			                         &HASH) == FZN_ROOT_LOG_OK,
			      "order %zu: a record was refused", o);
		CHECK(!stands_key(&set, &log, 1) && fzn_root_set_member(&set, &log, genesis),
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
	static fzn_root_log_entry_t entries[4];
	static fzn_root_change_t changes[4];
	uint8_t add[FZN_ROOT_ADD_LEN], r12[FZN_ROOT_REMOVE_LEN], r21[FZN_ROOT_REMOVE_LEN];
	uint8_t id_add[FZN_ROOT_ACT_ID_LEN], id12[FZN_ROOT_ACT_ID_LEN], id21[FZN_ROOT_ACT_ID_LEN];
	uint8_t e0[FZN_ROOT_ACT_ID_LEN], genesis[FZN_PUBKEY_LEN];
	fzn_root_log_t log;
	fzn_root_set_t set;

	key(genesis, 1);
	CHECK(fzn_root_log_init(&log, entries, 4) == FZN_ROOT_LOG_OK
	              && fzn_root_set_init(&set, genesis, changes, 4) == FZN_ROOT_LOG_OK,
	      "fixture");
	change(add, id_add, 0, 1, 2, NULL);
	logged(&log, e0, 1, 0, NULL, id_add);
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
	static fzn_root_log_entry_t entries[4];
	uint8_t add[FZN_ROOT_ADD_LEN], rem[FZN_ROOT_REMOVE_LEN], id[FZN_ROOT_ACT_ID_LEN];
	uint8_t e0[FZN_ROOT_ACT_ID_LEN], a10[FZN_ROOT_ACT_ID_LEN], genesis[FZN_PUBKEY_LEN];
	fzn_root_log_t log;
	fzn_root_set_t set;

	key(genesis, 1);
	act_of(a10, 10);
	CHECK(fzn_root_set_init(&set, genesis, changes, FZN_ROOT_SET_MAX + 1u)
	              == FZN_ROOT_LOG_ERR_MALFORMED,
	      "a set past its bound was accepted");
	CHECK(fzn_root_set_init(&set, genesis, changes, 4) == FZN_ROOT_LOG_OK
	              && fzn_root_log_init(&log, entries, 4) == FZN_ROOT_LOG_OK,
	      "fixture");
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
	add[1] = (uint8_t)FZN_OBJECT_ROOT_ACT;
	CHECK(fzn_root_set_admit(&set, add, sizeof(add), &SIGN, &HASH) == FZN_ROOT_LOG_ERR_SHAPE,
	      "another object was read as a root-set record");
	/* THE GENESIS ROOT REMOVED AT A CUT, judged with and without the log:
	 * with it the act before the cut counts; without it nothing can be
	 * shown to stand. And a removal naming no cut keeps nothing. */
	logged(&log, e0, 1, 0, NULL, a10);
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
	test_the_layout();
	test_admission();
	test_the_cut();
	test_a_broken_chain();
	test_the_theft();
	test_mutual_removal();
	test_the_set_refuses();
	test_the_estates_k();
	test_the_estates_retention();
	printf("root_log_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
