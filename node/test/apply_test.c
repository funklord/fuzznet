/* Tests for node/apply.c: a node's journal applied to its subsystems.
 * sec 503.
 *
 * ONE NODE'S JOURNAL, filled by hand, in a scratch directory of its own under
 * /tmp, made and removed by name. The signer is a keyed mixing function keyed
 * by the first byte of the public key, as roster_test's is: an object verifies
 * under the key it was signed as and no other.
 */

#include "../apply.h"
#include "../roster.h"
#include "../settings.h"
#include "../succession.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;
static int checks;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL apply_test.c:%d: %s\n", __LINE__, what);        \
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

static const fzn_sign_ops_t SIGN = { stub_verify, stub_sign, NULL };
static const fzn_hash_ops_t HASH = { mix_hash, NULL };

/* ---- an in-memory persist store ---------------------------------------- */

#define ROWS 64

static struct row {
	int used;
	fzn_persist_slot_t slot;
	uint8_t subject[FZN_PUBKEY_LEN];
	uint8_t bytes[2048];
	size_t len;
} rows[ROWS];

static struct row *row_of(fzn_persist_slot_t slot, const uint8_t *subject, int make)
{
	int i, free_one = -1;

	for (i = 0; i < ROWS; i++) {
		if (!rows[i].used) {
			if (free_one < 0)
				free_one = i;
			continue;
		}
		if (rows[i].slot == slot && memcmp(rows[i].subject, subject, FZN_PUBKEY_LEN) == 0)
			return &rows[i];
	}
	if (!make || free_one < 0)
		return NULL;
	rows[free_one].used = 1;
	rows[free_one].slot = slot;
	memcpy(rows[free_one].subject, subject, FZN_PUBKEY_LEN);
	return &rows[free_one];
}

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	struct row *r = row_of(slot, subject, 0);

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
	struct row *r;

	(void)ctx;
	if (len > sizeof(r->bytes))
		return 0;
	r = row_of(slot, subject, 1);
	if (!r)
		return 0;
	memcpy(r->bytes, bytes, len);
	r->len = len;
	return 1;
}

static int mem_list(void *ctx, fzn_persist_slot_t slot, uint8_t *out, size_t max, size_t *count)
{
	int i;

	(void)ctx;
	*count = 0;
	for (i = 0; i < ROWS && *count < max; i++)
		if (rows[i].used && rows[i].slot == slot)
			memcpy(out + (*count)++ * FZN_PUBKEY_LEN, rows[i].subject, FZN_PUBKEY_LEN);
	return 1;
}

/* ---- fixtures ---------------------------------------------------------- */

static void key(uint8_t out[FZN_PUBKEY_LEN], uint8_t seed)
{
	size_t i;

	for (i = 0; i < FZN_PUBKEY_LEN; i++)
		out[i] = (uint8_t)(seed + i * 3u);
	out[0] = seed;
}

static char dir[128];
static uint8_t used_writers[8];
static size_t n_used;

/* `writer` appends `object` to its estate stream in `nj`. */
static int put(fzn_node_journal_t *nj, uint8_t writer, const uint8_t *object, size_t len)
{
	uint8_t k[FZN_PUBKEY_LEN];
	size_t i;

	for (i = 0; i < n_used && used_writers[i] != writer; i++)
		;
	if (i == n_used)
		used_writers[n_used++] = writer;
	key(k, writer);
	signing_as = writer;
	return fzn_node_journal_append_object(nj, k, &SIGN, object, len, 1u, NULL)
	       == FZN_NODE_JOURNAL_OK;
}

static void test_the_journal_applied(void)
{
	static fzn_node_journal_t nj;
	static fzn_node_roster_t roster;
	static fzn_node_successions_t ns;
	static fzn_revocation_t rev_entries[8];
	static fzn_node_apply_t ap;
	fzn_revocation_store_t revs;
	fzn_persist_ops_t store = { 0 };
	fzn_node_apply_tally_t t;
	fzn_cap_id_t cap;
	uint8_t r[FZN_PUBKEY_LEN], m[FZN_PUBKEY_LEN], s[FZN_PUBKEY_LEN], alice[FZN_PUBKEY_LEN];
	uint8_t bob[FZN_PUBKEY_LEN], d[FZN_PUBKEY_LEN], d2[FZN_PUBKEY_LEN], now[FZN_PUBKEY_LEN];
	uint8_t hop[FZN_HOP_LEN], obj[FZN_ROSTER_MAX_LEN], inc[FZN_ROSTER_INCARNATION_LEN];
	uint8_t succ[FZN_SUCCESSION_LEN];
	size_t len = 0;

	store.load = mem_load;
	store.save = mem_save;
	store.list = mem_list;
	memset(&cap, 0x61, sizeof(cap));
	key(r, 0x10);
	key(m, 0x20);
	key(s, 0x30);
	key(alice, 0x40);
	key(bob, 0x50);
	key(d, 0x60);
	key(d2, 0x70);
	memset(inc, 0x0e, sizeof(inc));
	CHECK(fzn_node_journal_init(&nj, dir, &SIGN, &HASH) == FZN_NODE_JOURNAL_OK
	              && fzn_revocation_store_init(&revs, rev_entries, 8) == FZN_CHAIN_OK
	              && fzn_node_roster_init(&roster, r, &cap, &SIGN, NULL, &HASH)
	                         == FZN_NODE_ROSTER_OK
	              && fzn_node_successions_init(&ns, &HASH) == FZN_NODE_REVOKE_OK,
	      "fixture: the journal and the subsystems");
	memset(&ap, 0, sizeof(ap));
	ap.journal = &nj;
	ap.revocations = &revs;
	ap.roster = &roster;
	ap.successions = &ns;
	ap.store = &store;
	ap.root = r;
	ap.capability = &cap;
	ap.sign = &SIGN;
	ap.hash = &HASH;

	/* M's STREAM FIRST, so its roster record meets no grant on the first
	 * pass: M adds alice. Then R's: the grant to M, and a succession. */
	signing_as = 0x20;
	CHECK(fzn_roster_issue_add(m, alice, inc, 1u, &SIGN, obj, sizeof(obj), &len)
	              == FZN_ROSTER_OK
	              && put(&nj, 0x20, obj, len),
	      "fixture: M's roster record in M's stream");
	signing_as = 0x10;
	CHECK(fzn_chain_mint(r, m, &cap, 100u, FZN_NO_EXPIRY, 0, &SIGN, hop) == FZN_CHAIN_OK
	              && put(&nj, 0x10, hop, sizeof(hop)),
	      "fixture: R's grant to M in R's stream");
	signing_as = 0x10;
	CHECK(fzn_succession_issue(r, d, d2, NULL, &SIGN, succ) == FZN_CHAIN_OK
	              && put(&nj, 0x10, succ, sizeof(succ)),
	      "fixture: R's succession of D in R's stream");

	CHECK(fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK && t.grants == 1u
	              && t.applied == 2u && t.refused == 0u && t.waiting == 0u,
	      "one round did not apply R's grant and then M's record that waited on it");
	CHECK(fzn_node_roster_standing(&roster, alice, &revs, 2u) == FZN_ROSTER_ACTIVE,
	      "M's contact, applied from the journal, is not active");
	CHECK(fzn_node_successions_resolve(&ns, &revs, r, d, now)
	              && memcmp(now, d2, FZN_PUBKEY_LEN) == 0,
	      "R's succession, applied from the journal, does not read D through");
	{
		uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
		size_t n = 9;

		CHECK(fzn_node_apply_chain(&ap, m, &cap, hops, &n) && n == 1u
		              && memcmp(hops[0], hop, FZN_HOP_LEN) == 0
		              && fzn_node_apply_chain(&ap, r, &cap, hops, &n) && n == 0u
		              && !fzn_node_apply_chain(&ap, s, &cap, hops, &n),
		      "the index did not rebuild M's chain, a root's empty one, and no stranger's");
	}

	/* A STRANGER'S RECORD, with no chain anywhere: it waits. */
	signing_as = 0x30;
	CHECK(fzn_roster_issue_add(s, bob, inc, 2u, &SIGN, obj, sizeof(obj), &len) == FZN_ROSTER_OK
	              && put(&nj, 0x30, obj, len)
	              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK && t.waiting == 1u
	              && t.applied == 0u
	              && fzn_node_roster_standing(&roster, bob, &revs, 2u) == FZN_ROSTER_ABSENT,
	      "a record with no chain did not wait, or counted");

	/* A KIND THE BODY DOES NOT CARRY: refused, and the stream goes on. */
	{
		uint8_t subject[FZN_SUBJECT_LEN];

		memset(subject, 0x11, sizeof(subject));
		signing_as = 0x20;
		CHECK(fzn_node_journal_append(&nj, m, &SIGN, (uint32_t)FZN_OBJECT_SUCCESSION, subject,
		                              hop, sizeof(hop), 1u, NULL) == FZN_NODE_JOURNAL_OK
		              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK && t.refused == 1u,
		      "a record whose kind its body's tag denies was not refused");
	}

	/* AND AGAIN: nothing new is applied. */
	CHECK(fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK && t.applied == 0u
	              && t.grants == 0u && t.refused == 0u,
	      "a second round applied something again");
	fzn_node_journal_close(&nj);
}

/* ---- settings, judged, sec 540 -------------------------------------------- */

static int setting_by(fzn_node_journal_t *nj, uint8_t setter, fzn_scope_t scope, uint8_t about,
                      uint64_t version, const char *k, int set, const char *value)
{
	uint8_t who[FZN_PUBKEY_LEN], subject[FZN_SUBJECT_LEN], obj[FZN_SETTING_MAX];
	size_t len = 0;

	key(who, setter);
	key(subject, about);
	signing_as = setter;
	return fzn_setting_issue(who, &SIGN, scope, subject, version, (const uint8_t *)k, strlen(k),
	                         set, (const uint8_t *)value, value ? strlen(value) : 0u, obj, &len)
	               == FZN_SETTING_OK
	       && put(nj, setter, obj, len);
}

static int in_force(const fzn_node_settings_t *ns, fzn_scope_t scope, uint8_t about,
                    const char *k, const char *want, fzn_setting_rank_t want_rank)
{
	uint8_t subject[FZN_SUBJECT_LEN], value[FZN_SETTING_VALUE_MAX];
	fzn_setting_rank_t rank = FZN_SETTING_RANK_HOST;
	size_t len = 0;

	key(subject, about);
	if (!fzn_node_settings_get(ns, scope, subject, (const uint8_t *)k, strlen(k), value, &len,
	                           &rank))
		return want == NULL;
	return want && len == strlen(want) && memcmp(value, want, len) == 0 && rank == want_rank;
}

/* Whether `n` bytes of `needle` occur in `hay`. */
static int holds(const uint8_t *hay, size_t len, const char *needle, size_t n)
{
	size_t i;

	for (i = 0; i + n <= len; i++)
		if (memcmp(hay + i, needle, n) == 0)
			return 1;
	return 0;
}

static size_t values_seen;

static void count_value(void *ctx, const fzn_setting_t *s, fzn_setting_rank_t rank)
{
	(void)ctx;
	(void)s;
	(void)rank;
	values_seen++;
}

static uint64_t clock_now(void)
{
	return 1000u;
}

static char reply[2048];

static size_t said(fzn_node_settings_t *ns, fzn_origin_t origin, const char *line)
{
	fzn_request_t req;

	memset(reply, 0, sizeof(reply));
	if (!fzn_vocabulary_split((const uint8_t *)line, strlen(line), &req))
		return 0;
	return fzn_node_settings_local(ns, origin, &req, reply, sizeof(reply));
}

static int replied(const char *start)
{
	return strncmp(reply, start, strlen(start)) == 0;
}

static void test_settings_judged(void)
{
	static fzn_node_journal_t nj;
	static fzn_revocation_t rev_entries[8];
	static fzn_revocation_admin_t admins[4];
	static fzn_node_apply_t ap;
	static fzn_node_settings_t ns;
	static fzn_node_identity_t me;
	fzn_revocation_store_t revs;
	fzn_persist_ops_t store = { 0 };
	fzn_node_apply_tally_t t;
	fzn_cap_id_t cap, admin_cap;
	uint8_t r[FZN_PUBKEY_LEN], m[FZN_PUBKEY_LEN], a[FZN_PUBKEY_LEN], hop[FZN_HOP_LEN];
	uint8_t estate[FZN_SUBJECT_LEN];
	uint64_t before;

	store.load = mem_load;
	store.save = mem_save;
	store.list = mem_list;
	memset(&cap, 0x61, sizeof(cap));
	memset(&admin_cap, 0x62, sizeof(admin_cap));
	key(r, 0x91);
	key(m, 0x92);
	key(a, 0x93);
	memcpy(estate, r, sizeof(estate));
	CHECK(fzn_node_journal_init(&nj, dir, &SIGN, &HASH) == FZN_NODE_JOURNAL_OK
	              && fzn_revocation_store_init(&revs, rev_entries, 8) == FZN_CHAIN_OK
	              && fzn_revocation_store_set_quorum(&revs, 1u, &admin_cap, admins, 4u)
	                         == FZN_CHAIN_OK,
	      "fixture: a journal, and a revocation store that knows the admin capability");
	memset(&ap, 0, sizeof(ap));
	ap.journal = &nj;
	ap.revocations = &revs;
	ap.store = &store;
	ap.root = r;
	ap.capability = &cap;
	ap.admin_capability = &admin_cap;
	ap.sign = &SIGN;
	ap.hash = &HASH;
	ap.settings = &ns;
	ap.now = clock_now;
	memset(&ns, 0, sizeof(ns));
	ns.store = &store;
	ns.hash = &HASH;
	ns.verify = &SIGN;
	ns.apply = &ap;
	ns.estate = estate;

	/* THE GRANTS: R makes M a member and A an admin. */
	signing_as = 0x91;
	CHECK(fzn_chain_mint(r, m, &cap, 100u, FZN_NO_EXPIRY, 0, &SIGN, hop) == FZN_CHAIN_OK
	              && put(&nj, 0x91, hop, sizeof(hop))
	              && fzn_chain_mint(r, a, &admin_cap, 100u, FZN_NO_EXPIRY, 0, &SIGN, hop)
	                         == FZN_CHAIN_OK
	              && put(&nj, 0x91, hop, sizeof(hop)),
	      "fixture: R's grants to M, a member, and to A, an admin");
	CHECK(setting_by(&nj, 0x91, FZN_SCOPE_ESTATE, 0x91, 1u, "retention/a", 1,
	                 "prune messages age 30d")
	              && setting_by(&nj, 0x92, FZN_SCOPE_HOST, 0x92, 1u, "net/mtu", 1, "1500")
	              && setting_by(&nj, 0x92, FZN_SCOPE_ESTATE, 0x91, 1u, "net/mtu", 1, "9000")
	              && setting_by(&nj, 0x92, FZN_SCOPE_HOST, 0x93, 1u, "net/mtu", 1, "1")
	              && setting_by(&nj, 0x93, FZN_SCOPE_HOST, 0x92, 1u, "net/mtu", 1, "1400")
	              && setting_by(&nj, 0x94, FZN_SCOPE_HOST, 0x94, 1u, "net/mtu", 1, "7"),
	      "fixture: settings by the root, the member, the admin and a stranger");
	CHECK(fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK && t.applied == 3u
	              && t.refused == 2u && t.waiting == 1u,
	      "the root's, the member's own and the admin's applied; the member's of the estate "
	      "and of another host refused; the stranger's waiting");
	CHECK(in_force(&ns, FZN_SCOPE_ESTATE, 0x91, "retention/a", "prune messages age 30d",
	               FZN_SETTING_RANK_ROOT),
	      "the root's estate setting is not in force at the root's rank");
	CHECK(in_force(&ns, FZN_SCOPE_HOST, 0x92, "net/mtu", "1400", FZN_SETTING_RANK_ADMIN)
	              && in_force(&ns, FZN_SCOPE_ESTATE, 0x91, "net/mtu", NULL, FZN_SETTING_RANK_HOST)
	              && in_force(&ns, FZN_SCOPE_HOST, 0x93, "net/mtu", NULL, FZN_SETTING_RANK_HOST),
	      "the admin's value is not in force over the member's own, or a refused one is");

	/* THE ADMIN'S CLEAR withdraws its layer and no more. */
	CHECK(setting_by(&nj, 0x93, FZN_SCOPE_HOST, 0x92, 2u, "net/mtu", 0, NULL)
	              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK
	              && in_force(&ns, FZN_SCOPE_HOST, 0x92, "net/mtu", "1500", FZN_SETTING_RANK_HOST),
	      "the admin's clear did not leave the member's own value in force again");
	/* WITHIN A RANK THE HIGHER VERSION, and an older one is stale. */
	CHECK(setting_by(&nj, 0x92, FZN_SCOPE_HOST, 0x92, 3u, "net/mtu", 1, "1600")
	              && setting_by(&nj, 0x92, FZN_SCOPE_HOST, 0x92, 2u, "net/mtu", 1, "1700")
	              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK && t.refused == 0u
	              && in_force(&ns, FZN_SCOPE_HOST, 0x92, "net/mtu", "1600", FZN_SETTING_RANK_HOST),
	      "an older version replaced a newer one at the member's rank");
	values_seen = 0;
	CHECK(fzn_node_settings_each(&ns, count_value, NULL) == FZN_NODE_SETTINGS_OK
	              && values_seen == 2u,
	      "the walk did not hand each value in force once: the estate's rule and the member's");

	/* A NODE'S OWN WRITE, judged before it is written: the root may set the
	 * estate's cell, and a member may not, and leaves nothing in its
	 * stream. */
	ns.journal = &nj;
	ns.id = &me;
	ns.now = clock_now;
	memset(&me, 0, sizeof(me));
	me.sign = &SIGN;
	memcpy(me.pubkey, r, FZN_PUBKEY_LEN);
	signing_as = 0x91;
	CHECK(fzn_node_settings_write(&ns, FZN_SCOPE_ESTATE, estate, (const uint8_t *)"k", 1u, 1,
	                              (const uint8_t *)"v", 1u)
	              == FZN_NODE_SETTINGS_OK
	              && in_force(&ns, FZN_SCOPE_ESTATE, 0x91, "k", "v", FZN_SETTING_RANK_ROOT),
	      "the root's own write is not in force at once");
	memcpy(me.pubkey, m, FZN_PUBKEY_LEN);
	signing_as = 0x92;
	before = fzn_node_journal_received(&nj, m, FZN_NODE_JOURNAL_STREAM);
	CHECK(fzn_node_settings_write(&ns, FZN_SCOPE_ESTATE, estate, (const uint8_t *)"k", 1u, 1,
	                              (const uint8_t *)"w", 1u)
	              == FZN_NODE_SETTINGS_REFUSED
	              && fzn_node_journal_received(&nj, m, FZN_NODE_JOURNAL_STREAM) == before
	              && in_force(&ns, FZN_SCOPE_ESTATE, 0x91, "k", "v", FZN_SETTING_RANK_ROOT),
	      "a member's write to the estate was not refused before its stream");
	CHECK(fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK && t.refused == 0u
	              && in_force(&ns, FZN_SCOPE_ESTATE, 0x91, "k", "v", FZN_SETTING_RANK_ROOT),
	      "the root's own write, applied again from its stream, was not the same");

	/* THE VERBS, as the root's own user. */
	{
		static const char DIGITS[] = "0123456789abcdef";
		char line[256], m_hex[2u * FZN_PUBKEY_LEN + 1u];
		size_t i;

		for (i = 0; i < FZN_PUBKEY_LEN; i++) {
			m_hex[i * 2u] = DIGITS[m[i] >> 4];
			m_hex[(i * 2u) + 1u] = DIGITS[m[i] & 15u];
		}
		m_hex[2u * FZN_PUBKEY_LEN] = '\0';
		memcpy(me.pubkey, r, FZN_PUBKEY_LEN);
		signing_as = 0x91;
		CHECK(said(&ns, FZN_ORIGIN_SAME_USER,
		           "set setting estate retention/b prune messages age 60d")
		              && replied("ok")
		              && said(&ns, FZN_ORIGIN_SAME_USER, "get setting estate retention/b")
		              && strcmp(reply, "ok root prune%20messages%20age%2060d\n") == 0,
		      "a value set by the verb is not got back, at the root's rank, escaped");
		(void)snprintf(line, sizeof(line), "set setting host=%s net/mtu 1300", m_hex);
		CHECK(said(&ns, FZN_ORIGIN_SAME_USER, line) && replied("ok")
		              && in_force(&ns, FZN_SCOPE_HOST, 0x92, "net/mtu", "1300",
		                          FZN_SETTING_RANK_ROOT),
		      "the root did not set another host's cell over the host's own value");
		CHECK(said(&ns, FZN_ORIGIN_SAME_USER, "list setting") && replied("ok 0 4 0 ")
		              && strstr(reply, ",retention/b,root,") && strstr(reply, ",net/mtu,root,")
		              && strstr(reply, "host,"),
		      "the listing does not hand the four values in force, each with its rank");
		CHECK(said(&ns, FZN_ORIGIN_SAME_USER, "remove setting estate retention/b")
		              && replied("ok")
		              && said(&ns, FZN_ORIGIN_SAME_USER, "get setting estate retention/b")
		              && strcmp(reply, "ok absent\n") == 0,
		      "a removed setting is still got");
		CHECK(said(&ns, FZN_ORIGIN_LOCAL, "set setting estate x 1") && replied("denied")
		              && said(&ns, FZN_ORIGIN_SAME_USER, "set setting estate Bad 1")
		              && replied("malformed")
		              && said(&ns, FZN_ORIGIN_SAME_USER, "set setting nowhere x 1")
		              && replied("malformed")
		              && said(&ns, FZN_ORIGIN_SAME_USER, "set thing x 1") == 0u,
		      "another user, a bad key or scope, or another subject was not refused or passed");
	}

	/* THE ESTATE'S k, sec 542: a root's to set. An admin's value is held
	 * at its rank and not counted; a root's is; a value that is no count
	 * leaves the fallback. */
	CHECK(setting_by(&nj, 0x93, FZN_SCOPE_ESTATE, 0x91, 1u, "revocation/k", 1, "5")
	              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK
	              && in_force(&ns, FZN_SCOPE_ESTATE, 0x91, "revocation/k", "5",
	                          FZN_SETTING_RANK_ADMIN)
	              && fzn_node_settings_quorum(&ns, 2u) == 2u,
	      "an admin's k counted");
	CHECK(setting_by(&nj, 0x91, FZN_SCOPE_ESTATE, 0x91, 2u, "revocation/k", 1, "3")
	              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK
	              && fzn_node_settings_quorum(&ns, 2u) == 3u,
	      "a root's k did not count");
	CHECK(setting_by(&nj, 0x91, FZN_SCOPE_ESTATE, 0x91, 3u, "revocation/k", 1, "0")
	              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK
	              && fzn_node_settings_quorum(&ns, 2u) == 2u
	              && setting_by(&nj, 0x91, FZN_SCOPE_ESTATE, 0x91, 4u, "revocation/k", 1, "2x")
	              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK
	              && fzn_node_settings_quorum(&ns, 2u) == 2u
	              && setting_by(&nj, 0x91, FZN_SCOPE_ESTATE, 0x91, 5u, "revocation/k", 1, "256")
	              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK
	              && fzn_node_settings_quorum(&ns, 2u) == 2u,
	      "a k of 0, of no count, or past 255 was counted");

	/* A SETTING IN ANOTHER KEY'S STREAM: the root's object, carried as the
	 * admin's record, is judged by nobody's standing -- refused. */
	{
		uint8_t obj[FZN_SETTING_MAX];
		size_t len = 0;

		signing_as = 0x91;
		CHECK(fzn_setting_issue(r, &SIGN, FZN_SCOPE_ESTATE, estate, 1u, (const uint8_t *)"z",
		                        1u, 1, (const uint8_t *)"1", 1u, obj, &len)
		                      == FZN_SETTING_OK
		              && put(&nj, 0x93, obj, len) && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK
		              && t.refused == 1u
		              && in_force(&ns, FZN_SCOPE_ESTATE, 0x91, "z", NULL, FZN_SETTING_RANK_HOST),
		      "a setting carried in another key's stream was applied");
	}
	/* AN ADMIN CHAIN THE INDEX FINDS AND THE STORE DOES NOT ADMIT: A, whose
	 * grant cannot be passed on, grants the admin capability to X. */
	{
		uint8_t x[FZN_PUBKEY_LEN];

		key(x, 0x95);
		signing_as = 0x93;
		CHECK(fzn_chain_mint(a, x, &admin_cap, 100u, FZN_NO_EXPIRY, 0, &SIGN, hop) == FZN_CHAIN_OK
		              && put(&nj, 0x93, hop, sizeof(hop))
		              && setting_by(&nj, 0x95, FZN_SCOPE_ESTATE, 0x91, 1u, "y", 1, "1")
		              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK && t.refused == 1u
		              && in_force(&ns, FZN_SCOPE_ESTATE, 0x91, "y", NULL, FZN_SETTING_RANK_HOST),
		      "a chain under the admin capability that does not verify ranked as an admin's");
	}
	/* A ROW UNDER ANOTHER CELL'S PLACE is not that cell's: the estate's
	 * rule copied over the root's row for the member's cell, which then
	 * falls to the member's own value. */
	{
		struct row *from = NULL, *to = NULL;
		size_t i;

		for (i = 0; i < ROWS; i++) {
			if (!rows[i].used || rows[i].slot != FZN_PERSIST_SETTING || rows[i].len < 2u
			    || rows[i].bytes[0] != (uint8_t)FZN_SETTING_RANK_ROOT)
				continue;
			if (holds(rows[i].bytes, rows[i].len, "retention/a", 11u))
				from = &rows[i];
			else if (holds(rows[i].bytes, rows[i].len, "net/mtu", 7u))
				to = &rows[i];
		}
		CHECK(from && to, "fixture: the root's rows for the estate's rule and the member's cell");
		if (from && to) {
			memcpy(to->bytes, from->bytes, from->len);
			to->len = from->len;
			CHECK(in_force(&ns, FZN_SCOPE_HOST, 0x92, "net/mtu", "1600", FZN_SETTING_RANK_HOST),
			      "a row copied under another cell's place answered for that cell");
		}
	}
	fzn_node_journal_close(&nj);
}

int main(void)
{
	char path[512];
	size_t i;

	snprintf(dir, sizeof(dir), "/tmp/fzn-apply-test-%ld", (long)getpid());
	if (mkdir(dir, 0700) != 0) {
		fprintf(stderr, "apply_test: could not make %s\n", dir);
		return 1;
	}
	test_the_journal_applied();
	test_settings_judged();
	/* EVERY STREAM FILE, BY NAME, then the directory. */
	for (i = 0; i < n_used; i++) {
		static const char DIGITS[] = "0123456789abcdef";
		uint8_t k[FZN_PUBKEY_LEN];
		char hex[FZN_PUBKEY_LEN * 2u + 1u];
		size_t j;

		key(k, used_writers[i]);
		for (j = 0; j < FZN_PUBKEY_LEN; j++) {
			hex[j * 2u] = DIGITS[k[j] >> 4];
			hex[j * 2u + 1u] = DIGITS[k[j] & 0x0fu];
		}
		hex[FZN_PUBKEY_LEN * 2u] = '\0';
		snprintf(path, sizeof(path), "%s/%s-%08lx.rec", dir, hex,
		         (unsigned long)FZN_NODE_JOURNAL_STREAM);
		(void)unlink(path);
	}
	CHECK(rmdir(dir) == 0, "the scratch directory would not go: a file the suite did not name");
	if (failures) {
		fprintf(stderr, "apply_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("apply_test: all %d checks passed\n", checks);
	return 0;
}
