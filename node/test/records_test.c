/* node records_test -- a host's records, sec 814: a record is a setting its
 * host signs about itself, kept a month at a time in the records kind of
 * the buckets; filed only as its setter signed it and where it belongs;
 * written and listed by the local verbs. A stub signature keyed by a key's
 * first byte, as contact_devices_test's, since which key signed is what is
 * tested. */

#include "../records.h"
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
			fprintf(stderr, "  FAIL records_test.c:%d: %s\n", __LINE__, what);      \
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

static char reply[2048];

static size_t said(const fzn_node_records_t *nr, fzn_origin_t origin, const char *line)
{
	fzn_request_t req;

	memset(reply, 0, sizeof(reply));
	if (!fzn_vocabulary_split((const uint8_t *)line, strlen(line), &req))
		return 0;
	return fzn_node_records_local((void *)nr, origin, &req, reply, sizeof(reply));
}

static int replied(const char *start)
{
	return strncmp(reply, start, strlen(start)) == 0;
}

/* A record `by` signs about `about`, at `at` ms, into `out`. */
static size_t a_record(uint8_t *out, uint8_t by, uint8_t about, fzn_scope_t scope, uint64_t at,
                       const char *key, const char *value)
{
	uint8_t setter[FZN_PUBKEY_LEN], subject[FZN_PUBKEY_LEN];
	size_t len = 0;

	memset(setter, by, sizeof(setter));
	memset(subject, about, sizeof(subject));
	signing_as = by;
	if (fzn_setting_issue_ranked(setter, &SIGN, scope, subject, at, (const uint8_t *)key,
	                             strlen(key), 1, (const uint8_t *)value, strlen(value),
	                             FZN_SETTING_RANK_HOST, out, &len)
	    != FZN_SETTING_OK)
		return 0;
	return len;
}

static void test_a_record_filed(void)
{
	fzn_node_records_t nr = { &B, &SIGN, NULL, NULL, NULL, NULL };
	uint8_t item[FZN_SETTING_MAX], subject[FZN_PUBKEY_LEN], other[FZN_PUBKEY_LEN];
	uint32_t month = 0, at = fzn_message_epoch_of(clock_ms);
	size_t len;
	fzn_bucket_t bucket;

	memset(&node, 0, sizeof(node));
	memset(other, 0x33, sizeof(other));
	len = a_record(item, 0x22, 0x22, FZN_SCOPE_HOST, clock_ms, "seen/wlan0/aa-bb", "1");
	CHECK(len && fzn_node_records_place(&nr, item, len, subject, &month, NULL)
	              && subject[0] == 0x22 && month == at,
	      "a host's record of itself was not placed under it, in its month");
	CHECK(fzn_node_records_file(&nr, subject, month, item, len) == FZN_NODE_APPLY_APPLIED
	              && fzn_buckets_bucket(&B, FZN_BUCKETS_RECORDS, subject, month, &bucket)
	                         == FZN_BUCKETS_OK
	              && bucket.count == 1u,
	      "a record was not filed into its bucket");
	CHECK(fzn_node_records_file(&nr, subject, month, item, len) == FZN_NODE_APPLY_APPLIED
	              && fzn_buckets_bucket(&B, FZN_BUCKETS_RECORDS, subject, month, &bucket)
	                         == FZN_BUCKETS_OK
	              && bucket.count == 1u,
	      "a record filed twice was counted twice");

	/* WHERE IT DOES NOT BELONG: another host's bucket, another month. */
	CHECK(fzn_node_records_file(&nr, other, month, item, len) == FZN_NODE_APPLY_REFUSED
	              && fzn_node_records_file(&nr, subject, month + 1u, item, len)
	                         == FZN_NODE_APPLY_REFUSED,
	      "a record was filed under another host, or another month");
	/* NOT A RECORD: about another host, estate-scoped, or changed. */
	len = a_record(item, 0x22, 0x33, FZN_SCOPE_HOST, clock_ms, "seen/x", "1");
	CHECK(len && !fzn_node_records_place(&nr, item, len, subject, &month, NULL)
	              && fzn_node_records_file(&nr, subject, at, item, len) == FZN_NODE_APPLY_REFUSED,
	      "a host's word about another host was taken as a record");
	len = a_record(item, 0x22, 0x22, FZN_SCOPE_ESTATE, clock_ms, "seen/x", "1");
	CHECK(len && !fzn_node_records_place(&nr, item, len, subject, &month, NULL),
	      "an estate setting was taken as a record");
	len = a_record(item, 0x22, 0x22, FZN_SCOPE_HOST, clock_ms, "seen/x", "1");
	item[len - 1u] ^= 1u;
	memset(subject, 0x22, sizeof(subject));
	CHECK(fzn_node_records_file(&nr, subject, at, item, len) == FZN_NODE_APPLY_REFUSED,
	      "a record changed after signing was filed");
	/* A MONTH LET GO is not taken back. */
	item[len - 1u] ^= 1u;
	CHECK(fzn_buckets_drop(&B, FZN_BUCKETS_RECORDS, subject, at) == FZN_BUCKETS_OK
	              && fzn_node_records_file(&nr, subject, at, item, len) == FZN_NODE_APPLY_APPLIED
	              && fzn_buckets_bucket(&B, FZN_BUCKETS_RECORDS, subject, at, &bucket)
	                         == FZN_BUCKETS_OK
	              && bucket.count == 0u,
	      "a record of a month let go was taken back");
}

static void test_the_verbs(void)
{
	fzn_node_records_t nr = { &B, &SIGN, &me, now_ms, NULL, NULL };
	char want[256];
	size_t i, shown = 0, rest = 0;
	int more = 0, more2 = 1;
	unsigned long long from = 0;

	memset(&node, 0, sizeof(node));
	memset(&me, 0, sizeof(me));
	memset(me.pubkey, 0x44, sizeof(me.pubkey));
	me.sign = &SIGN;
	signing_as = 0x44;

	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "add record seen/wlan0/aa-bb station%20one")
	              && replied("ok"),
	      "a record was not added");
	clock_ms += 1000u;
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "add record seen/wlan0/aa-bb station one")
	              && replied("ok"),
	      "the same key observed again was not added");
	(void)snprintf(want, sizeof(want), "ok 0 2 0 %s", "4444");
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "list record self") && replied(want)
	              && strstr(reply, ",seen/wlan0/aa-bb,1793500000000,station%20one")
	              && strstr(reply, ",seen/wlan0/aa-bb,1793500001000,station%20one"),
	      "both records of one key were not listed, each with its time");
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "list record") && replied("ok 0 2 0 "),
	      "every host's records were not listed");
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER,
	           "list record 3333333333333333333333333333333333333333333333333333333333333333")
	              && replied("ok 0 0 0"),
	      "another host's records were listed for a host with none");
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "list record self 1") && replied("ok 1 1 0 "),
	      "the listing from 1 was not the second record alone");
	CHECK(said(&nr, FZN_ORIGIN_LOCAL, "list record") && replied("denied")
	              && said(&nr, FZN_ORIGIN_LOCAL, "add record a/b 1") && replied("denied"),
	      "another user listed or added records");
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "add record Bad:Key 1") && replied("malformed")
	              && said(&nr, FZN_ORIGIN_SAME_USER, "add record a/b") && replied("malformed")
	              && said(&nr, FZN_ORIGIN_SAME_USER, "list record self x") && replied("malformed"),
	      "a key out of shape, no value, or a FROM not a number was answered");
	/* TWENTY RECORDS, more than a reply holds: whole pages, MORE said. */
	for (i = 0; i < 20u; i++) {
		char line[64];

		clock_ms += 1000u;
		(void)snprintf(line, sizeof(line), "add record seen/eth0/host-%zu leased", i);
		(void)said(&nr, FZN_ORIGIN_SAME_USER, line);
	}
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "list record")
	              && sscanf(reply, "ok %llu %zu %d", &from, &shown, &more) == 3 && more == 1
	              && shown > 0u && shown < 22u && strlen(reply) <= FZN_REPLY_MAX,
	      "twenty-two records did not page, or a page outgrew a reply");
	{
		char line[64];

		(void)snprintf(line, sizeof(line), "list record %zu", shown);
		CHECK(said(&nr, FZN_ORIGIN_SAME_USER, line)
		              && sscanf(reply, "ok %llu %zu %d", &from, &rest, &more2) == 3,
		      "the second page was not answered");
	}
	CHECK(shown + rest <= 22u, "pages listed more records than were written");
	/* THE NEWEST OF A KEY, sec 816: of any host, of one, and none. */
	(void)snprintf(want, sizeof(want), "ok %s,seen/wlan0/aa-bb,1793500001000,station%%20one",
	               "4444444444444444444444444444444444444444444444444444444444444444");
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "get record seen/wlan0/aa-bb") && replied(want)
	              && said(&nr, FZN_ORIGIN_SAME_USER, "get record seen/wlan0/aa-bb self")
	              && replied(want),
	      "the newest record of a key was not the later of its two");
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "get record seen/none") && replied("ok absent")
	              && said(&nr, FZN_ORIGIN_SAME_USER,
	                      "get record seen/wlan0/aa-bb "
	                      "3333333333333333333333333333333333333333333333333333333333333333")
	              && replied("ok absent"),
	      "a key with no record, or a host with none of it, was not absent");
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "get record") && replied("malformed")
	              && said(&nr, FZN_ORIGIN_SAME_USER, "get record a/b zz") && replied("malformed")
	              && said(&nr, FZN_ORIGIN_LOCAL, "get record a/b") && replied("denied"),
	      "get record with no key, a bad host, or another user's was answered");
	/* A NODE THAT ONLY KEEPS OTHERS' writes none. */
	nr.id = NULL;
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "add record a/b 1") && replied("unsupported"),
	      "a node with no writer added a record");
}

static fzn_retain_rule_t rule(const char *text)
{
	fzn_retain_rule_t r;

	memset(&r, 0, sizeof(r));
	(void)fzn_retain_parse(text, strlen(text), &r);
	return r;
}

/* Every record of `key` held, of any host. */
static size_t held_of(const fzn_node_records_t *nr, const char *key)
{
	char want[96];
	size_t n = 0;
	const char *at = reply;

	(void)said(nr, FZN_ORIGIN_SAME_USER, "list record");
	(void)snprintf(want, sizeof(want), ",%s,", key);
	while ((at = strstr(at, want)) != NULL) {
		n++;
		at++;
	}
	return n;
}

/* TRIMMED BY THE RULES, sec 815. */
static void test_the_trim(void)
{
	fzn_node_records_t nr = { &B, &SIGN, &me, now_ms, NULL, NULL };
	fzn_retain_rule_t rules[4];
	size_t gone = 0, i;
	uint8_t item[FZN_SETTING_MAX], other[FZN_PUBKEY_LEN];
	size_t len;

	memset(&node, 0, sizeof(node));
	memset(&me, 0, sizeof(me));
	memset(me.pubkey, 0x44, sizeof(me.pubkey));
	me.sign = &SIGN;
	memset(other, 0x55, sizeof(other));
	clock_ms = 1793500000000ull;
	signing_as = 0x44;
	/* FIVE OF ONE STATION, a second apart; two of another; and one lease. */
	for (i = 0; i < 5u; i++, clock_ms += 1000u)
		(void)said(&nr, FZN_ORIGIN_SAME_USER, "add record seen/wlan0/aa 1");
	for (i = 0; i < 2u; i++, clock_ms += 1000u)
		(void)said(&nr, FZN_ORIGIN_SAME_USER, "add record seen/wlan0/bb 1");
	(void)said(&nr, FZN_ORIGIN_SAME_USER, "add record lease/eth0/cc 1");
	/* AND ANOTHER HOST'S, the same station. */
	len = a_record(item, 0x55, 0x55, FZN_SCOPE_HOST, clock_ms, "seen/wlan0/aa", "1");
	CHECK(fzn_node_records_file(&nr, other, fzn_message_epoch_of(clock_ms), item, len)
	              == FZN_NODE_APPLY_APPLIED,
	      "fixture: another host's record of the same station");
	signing_as = 0x44;

	/* NO RULE, nothing goes. */
	CHECK(fzn_node_records_trim(&nr, NULL, 0, clock_ms, &gone) == FZN_NODE_RECORDS_OK
	              && gone == 0u && held_of(&nr, "seen/wlan0/aa") == 6u,
	      "with no rule, a record went");
	/* A COUNT, each key's newest per host: two of aa here stay, the other
	 * host's one stays, bb's two and the lease stay. */
	rules[0] = rule("prune records text=seen/ count 2");
	CHECK(rules[0].data == FZN_RETAIN_RECORDS
	              && fzn_node_records_trim(&nr, rules, 1, clock_ms, &gone) == FZN_NODE_RECORDS_OK
	              && gone == 3u && held_of(&nr, "seen/wlan0/aa") == 3u
	              && held_of(&nr, "seen/wlan0/bb") == 2u && held_of(&nr, "lease/eth0/cc") == 1u,
	      "a count of 2 did not keep each key's newest two, per host");
	/* AN AGE, of one host's alone: this host's older than 2 s go -- aa's
	 * two at 4 s and 3 s -- and bb's at 2 s and 1 s, the lease and the
	 * other host's stay. */
	{
		char text[160];

		(void)snprintf(text, sizeof(text), "prune records source=%s age 2s",
		               "4444444444444444444444444444444444444444444444444444444444444444");
		rules[0] = rule(text);
	}
	CHECK(rules[0].has_source
	              && fzn_node_records_trim(&nr, rules, 1, clock_ms, &gone) == FZN_NODE_RECORDS_OK
	              && held_of(&nr, "seen/wlan0/aa") == 1u && held_of(&nr, "seen/wlan0/bb") == 2u
	              && held_of(&nr, "lease/eth0/cc") == 1u,
	      "an age of this host's did not take its old records alone, and leave the other "
	      "host's");
	/* A KEEP PROTECTS against a policy that drops. */
	rules[0] = rule("policy records drop");
	rules[1] = rule("keep records text=lease/ count 1");
	CHECK(rules[0].kind == FZN_RETAIN_POLICY && rules[1].kind == FZN_RETAIN_KEEP
	              && fzn_node_records_trim(&nr, rules, 2, clock_ms, &gone) == FZN_NODE_RECORDS_OK
	              && held_of(&nr, "lease/eth0/cc") == 1u && held_of(&nr, "seen/wlan0/bb") == 0u
	              && held_of(&nr, "seen/wlan0/aa") == 0u,
	      "a drop policy did not take what no keep held, or took what one did");
	/* A RECORD LET GO stays counted in its bucket, and reads as held to the
	 * reconcile, so no peer's copy is fetched or pushed back (sec 572). */
	{
		uint8_t id[FZN_BUCKETS_ID_LEN];

		CHECK(fzn_buckets_id(&HASH, item, len, id)
		              && fzn_buckets_has(&B, FZN_BUCKETS_RECORDS, id)
		              && held_of(&nr, "seen/wlan0/aa") == 0u,
		      "a record let go did not read as held to the reconcile, or was still listed");
	}
}

/* UNDER A KEY'S PREFIX, sec 861: one interface's stations, not every
 * record held; FROM counts what the prefix selects. */
static void test_a_listing_under_a_prefix(void)
{
	fzn_node_records_t nr = { &B, &SIGN, &me, now_ms, NULL, NULL };

	memset(&node, 0, sizeof(node));
	memset(&me, 0, sizeof(me));
	memset(me.pubkey, 0x44, sizeof(me.pubkey));
	me.sign = &SIGN;
	clock_ms = 1793500000000ull;
	signing_as = 0x44;
	(void)said(&nr, FZN_ORIGIN_SAME_USER, "add record seen/wlan0/aa 1");
	clock_ms += 1000u;
	(void)said(&nr, FZN_ORIGIN_SAME_USER, "add record seen/wlan0/bb 1");
	clock_ms += 1000u;
	(void)said(&nr, FZN_ORIGIN_SAME_USER, "add record seen/wlan1/cc 1");
	(void)said(&nr, FZN_ORIGIN_SAME_USER, "add record lease/eth0/dd 1");
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "list record self under seen/wlan0/")
	              && replied("ok 0 2 0 ") && strstr(reply, ",seen/wlan0/aa,")
	              && strstr(reply, ",seen/wlan0/bb,") && !strstr(reply, "wlan1")
	              && !strstr(reply, "lease"),
	      "one interface's records were not listed alone");
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "list record under seen/") && replied("ok 0 3 0 ")
	              && !strstr(reply, "lease"),
	      "every host's records under a prefix were not listed alone");
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "list record under seen/ 2") && replied("ok 2 1 0 ")
	              && strstr(reply, ",seen/wlan1/cc,"),
	      "FROM did not count what the prefix selects");
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "list record under nothing/") && replied("ok 0 0 0"),
	      "a prefix nothing has listed something");
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "list record under") && replied("malformed")
	              && said(&nr, FZN_ORIGIN_SAME_USER, "list record under SEEN/")
	              && replied("malformed"),
	      "a missing or out-of-shape prefix was taken");
}

/* A CLEAR `by` signs about itself at `at` ms: a list member out. */
static size_t a_clear(uint8_t *out, uint8_t by, uint64_t at, const char *key)
{
	uint8_t setter[FZN_PUBKEY_LEN];
	size_t len = 0;

	memset(setter, by, sizeof(setter));
	signing_as = by;
	if (fzn_setting_issue_ranked(setter, &SIGN, FZN_SCOPE_HOST, setter, at,
	                             (const uint8_t *)key, strlen(key), 0, NULL, 0u,
	                             FZN_SETTING_RANK_HOST, out, &len)
	    != FZN_SETTING_OK)
		return 0;
	return len;
}

/* LISTS, sec 854: records under `list/NAME/`, a member in while the newest
 * record of its key -- any host's, ties by the greater host -- is set. */
static void test_the_lists(void)
{
	fzn_node_records_t nr = { &B, &SIGN, &me, now_ms, NULL, NULL };
	fzn_retain_rule_t rules[2];
	uint8_t item[FZN_SETTING_MAX], other[FZN_PUBKEY_LEN];
	size_t len, gone = 0;

	memset(&node, 0, sizeof(node));
	memset(&me, 0, sizeof(me));
	memset(me.pubkey, 0x44, sizeof(me.pubkey));
	me.sign = &SIGN;
	memset(other, 0x55, sizeof(other));
	clock_ms = 1793500000000ull;
	signing_as = 0x44;

	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "get listed allow aa-bb") && replied("ok absent"),
	      "a member never listed was not absent");
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "add listed allow aa-bb the%20kitchen")
	              && replied("ok"),
	      "a member with a value was not added");
	clock_ms += 1000u;
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "add listed allow cc") && replied("ok"),
	      "a member with no value was not added");
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "get listed allow aa-bb")
	              && strcmp(reply, "ok in the%20kitchen\n") == 0,
	      "a member in did not read as in, with its value");
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "list listed allow")
	              && strcmp(reply, "ok 0 2 0 aa-bb,the%20kitchen cc,\n") == 0,
	      "the list's members were not listed, by member");
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "list listed allow 1")
	              && strcmp(reply, "ok 1 1 0 cc,\n") == 0,
	      "FROM did not page the members");
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "list listed deny")
	              && strcmp(reply, "ok 0 0 0\n") == 0,
	      "another list held this one's members");
	clock_ms += 1000u;
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "remove listed allow cc") && replied("ok")
	              && said(&nr, FZN_ORIGIN_SAME_USER, "get listed allow cc") && replied("ok out")
	              && said(&nr, FZN_ORIGIN_SAME_USER, "list listed allow")
	              && strcmp(reply, "ok 0 1 0 aa-bb,the%20kitchen\n") == 0,
	      "a member removed was still in");

	/* ANOTHER HOST'S NEWER CLEAR takes a member out here: a list is the
	 * estate's, resolved newest first. */
	clock_ms += 1000u;
	len = a_clear(item, 0x55, clock_ms, "list/allow/aa-bb");
	CHECK(fzn_node_records_file(&nr, other, fzn_message_epoch_of(clock_ms), item, len)
	              == FZN_NODE_APPLY_APPLIED
	              && said(&nr, FZN_ORIGIN_SAME_USER, "get listed allow aa-bb")
	              && replied("ok out"),
	      "another host's newer removal did not take the member out");
	/* AND A TIE, ONE MS: the greater host decides, here 0x55's clear over
	 * 0x44's add of the same moment. */
	signing_as = 0x44;
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "add listed allow aa-bb") && replied("ok")
	              && said(&nr, FZN_ORIGIN_SAME_USER, "get listed allow aa-bb")
	              && replied("ok out"),
	      "of two changes in one ms, the lesser host's won");
	clock_ms += 1000u;
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "add listed allow aa-bb") && replied("ok")
	              && said(&nr, FZN_ORIGIN_SAME_USER, "get listed allow aa-bb")
	              && strcmp(reply, "ok in\n") == 0,
	      "a member added again after its removal was not in");

	/* A LIST IS NEVER TRIMMED AWAY: a drop policy takes the superseded
	 * records and leaves each member's deciding one. aa-bb's four (two
	 * here, one of 0x55's, one more here) leave one; cc's two leave one. */
	rules[0] = rule("policy records drop");
	CHECK(fzn_node_records_trim(&nr, rules, 1, clock_ms, &gone) == FZN_NODE_RECORDS_OK
	              && held_of(&nr, "list/allow/aa-bb") == 1u && held_of(&nr, "list/allow/cc") == 1u
	              && said(&nr, FZN_ORIGIN_SAME_USER, "get listed allow aa-bb")
	              && strcmp(reply, "ok in\n") == 0
	              && said(&nr, FZN_ORIGIN_SAME_USER, "get listed allow cc") && replied("ok out"),
	      "a trim took a member's deciding record, or kept what it superseded");

	/* REFUSED: another user, a `/` in a name or member, a key too long, and
	 * a value on a removal. */
	CHECK(said(&nr, FZN_ORIGIN_LOCAL, "list listed allow") && replied("denied"),
	      "another user listed a list");
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "add listed al/low aa") && replied("malformed")
	              && said(&nr, FZN_ORIGIN_SAME_USER, "add listed allow a/b")
	              && replied("malformed"),
	      "a `/` in a name or member was taken");
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER,
	           "add listed allow "
	           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	              && replied("malformed"),
	      "a member past a key's length was taken");
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "remove listed allow aa-bb why")
	              && replied("malformed"),
	      "a removal with a value was taken");
}

/* A KEEP NAMING A LIST, sec 855: the records whose key holds a member in
 * the list are kept, and the rest go by the policy. Taken out of the list,
 * a station's records are no longer kept. */
static void test_a_keep_by_list(void)
{
	fzn_node_records_t nr = { &B, &SIGN, &me, now_ms, NULL, NULL };
	fzn_retain_rule_t rules[2];
	size_t gone = 0, i;

	memset(&node, 0, sizeof(node));
	memset(&me, 0, sizeof(me));
	memset(me.pubkey, 0x44, sizeof(me.pubkey));
	me.sign = &SIGN;
	clock_ms = 1793500000000ull;
	signing_as = 0x44;
	(void)said(&nr, FZN_ORIGIN_SAME_USER, "add listed allow aa-bb");
	for (i = 0; i < 3u; i++, clock_ms += 1000u) {
		(void)said(&nr, FZN_ORIGIN_SAME_USER, "add record seen/wlan0/aa-bb 1");
		(void)said(&nr, FZN_ORIGIN_SAME_USER, "add record seen/wlan0/cc-dd 1");
	}
	(void)said(&nr, FZN_ORIGIN_SAME_USER, "add record seen/wlan0/aa-bbx 1");
	rules[0] = rule("policy records drop");
	rules[1] = rule("keep records text=seen/ list=allow count 2");
	CHECK(rules[1].list[0] == 'a'
	              && fzn_node_records_trim(&nr, rules, 2, clock_ms, &gone) == FZN_NODE_RECORDS_OK
	              && held_of(&nr, "seen/wlan0/aa-bb") == 2u
	              && held_of(&nr, "seen/wlan0/cc-dd") == 0u
	              && held_of(&nr, "seen/wlan0/aa-bbx") == 0u
	              && held_of(&nr, "list/allow/aa-bb") == 1u,
	      "a keep naming a list did not keep its members' newest two alone, by whole word");
	clock_ms += 1000u;
	(void)said(&nr, FZN_ORIGIN_SAME_USER, "remove listed allow aa-bb");
	CHECK(fzn_node_records_trim(&nr, rules, 2, clock_ms, &gone) == FZN_NODE_RECORDS_OK
	              && held_of(&nr, "seen/wlan0/aa-bb") == 0u
	              && said(&nr, FZN_ORIGIN_SAME_USER, "get listed allow aa-bb")
	              && replied("ok out"),
	      "a station taken out of the list was still kept by it");
}

/* THE RULES' WORDS, sec 815: what parses, what does not, and the text it
 * writes back. */
static void test_the_rules(void)
{
	static const char *const GOOD[] = {
		"prune records age 30d",
		"prune records text=seen/ count 10",
		"keep records source=4444444444444444444444444444444444444444444444444444444444444444"
		" age 7d",
		"policy records drop",
		"keep records text=seen/ list=allow count 5",
	};
	static const char *const BAD[] = {
		"prune records size 1M",
		"prune records copy age 1d",
		"prune records contact=all age 1d",
		"prune records level=E age 1d",
		"prune records default age 1d",
		"prune * list=allow age 1d",
		"prune messages list=allow age 1d",
		"keep records list=al/low age 1d",
		"keep records list= age 1d",
	};
	size_t i;

	for (i = 0; i < sizeof(GOOD) / sizeof(GOOD[0]); i++) {
		fzn_retain_rule_t r;
		char back[512];
		size_t n = 0;

		memset(&r, 0, sizeof(r));
		CHECK(fzn_retain_parse(GOOD[i], strlen(GOOD[i]), &r) == FZN_RETAIN_OK
		              && r.data == FZN_RETAIN_RECORDS
		              && fzn_retain_text(&r, back, sizeof(back), &n) == FZN_RETAIN_OK
		              && n == strlen(GOOD[i]) && memcmp(back, GOOD[i], n) == 0,
		      GOOD[i]);
	}
	for (i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++) {
		fzn_retain_rule_t r;

		CHECK(fzn_retain_parse(BAD[i], strlen(BAD[i]), &r) == FZN_RETAIN_ERR_MALFORMED, BAD[i]);
	}
}

int main(void)
{
	test_a_record_filed();
	test_the_verbs();
	test_the_trim();
	test_the_rules();
	test_the_lists();
	test_a_keep_by_list();
	test_a_listing_under_a_prefix();
	if (failures) {
		fprintf(stderr, "node records_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("node records_test: all %d checks passed\n", checks);
	return 0;
}
