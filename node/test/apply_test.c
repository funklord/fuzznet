/* Tests for node/apply.c: a node's journal applied to its subsystems.
 * sec 503.
 *
 * ONE NODE'S JOURNAL, filled by hand, in a scratch directory of its own under
 * /tmp, made and removed by name. The signer is a keyed mixing function keyed
 * by the first byte of the public key, as roster_test's is: an object verifies
 * under the key it was signed as and no other.
 */

#include "../apply.h"
#include "../holdings.h"
#include "../roster.h"
#include "../settings.h"
#include "../siblings.h"
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

/* Forget a row, for a case that planted one. */
static void mem_remove_row(fzn_persist_slot_t slot, const uint8_t *subject)
{
	struct row *r = row_of(slot, subject, 0);

	if (r)
		memset(r, 0, sizeof(*r));
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
	/* THE GRANTS KEPT, sec 545: a fresh context, with no journal round at
	 * all, rebuilds M's chain from the store alone. */
	{
		static fzn_node_apply_t fresh;
		uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
		size_t n = 9, loaded = 9;

		fresh = ap;
		fresh.grants_used = 0;
		CHECK(!fzn_node_apply_chain(&fresh, m, &cap, hops, &n)
		              && fzn_node_apply_load_grants(&fresh, &loaded) && loaded == 1u
		              && fzn_node_apply_chain(&fresh, m, &cap, hops, &n) && n == 1u
		              && memcmp(hops[0], hop, FZN_HOP_LEN) == 0
		              && fzn_node_apply_load_grants(&fresh, &loaded) && loaded == 0u,
		      "a fresh context did not rebuild M's chain from the kept grants, or loaded "
		      "one twice");
		/* A HOP UNDER ANOTHER'S PLACE is refused, not loaded. */
		{
			uint8_t wrong[FZN_PUBKEY_LEN];

			memset(wrong, 0x5c, sizeof(wrong));
			fresh.grants_used = 0;
			CHECK(mem_save(NULL, FZN_PERSIST_GRANT, wrong, hop, FZN_HOP_LEN)
			              && !fzn_node_apply_load_grants(&fresh, &loaded),
			      "a grant row filed under another hop's place was loaded");
			mem_remove_row(FZN_PERSIST_GRANT, wrong);
		}
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

/* Objects taken out of a store, in the order its holdings hand them. */
struct snap {
	uint8_t (*objects)[1024];
	size_t *lens;
	size_t max, n;
};

static int snap_one(void *ctx, const uint8_t id[FZN_HOLDINGS_ID_LEN], const uint8_t *object,
                    size_t len)
{
	struct snap *s = (struct snap *)ctx;

	(void)id;
	if (s->n >= s->max || len > 1024u)
		return 0;
	memcpy(s->objects[s->n], object, len);
	s->lens[s->n++] = len;
	return 1;
}

/* The settings' clock, which the clears case moves. */
static uint64_t clock_at = 1000u;

static uint64_t clock_now(void)
{
	return clock_at;
}

static int mem_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	(void)ctx;
	mem_remove_row(slot, subject);
	return 1;
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
	/* STAMPED IN MILLISECONDS, sec 561: the record the write appended
	 * carries the settings clock -- seconds -- times a thousand. */
	{
		static uint8_t buf[FZN_RECORD_MAX_LEN];
		fzn_record_t rec;

		CHECK(fzn_record_store_get(&nj.store, r, FZN_NODE_JOURNAL_STREAM,
		                           fzn_node_journal_received(&nj, r, FZN_NODE_JOURNAL_STREAM),
		                           buf, sizeof(buf), &rec) == FZN_RECORD_STORE_OK
		              && fzn_record_kind(rec) == (uint32_t)FZN_OBJECT_SETTING
		              && fzn_record_issued_at(rec) == clock_now() * 1000u,
		      "a setting's record was not stamped in milliseconds");
	}
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

	/* THE JOURNAL'S WINDOW, sec 548: 60 days until set, an admin's value
	 * counts, and one that is no count of days leaves 60. */
	CHECK(fzn_node_settings_window_days(&ns) == 60u
	              && setting_by(&nj, 0x93, FZN_SCOPE_ESTATE, 0x91, 1u, "journal/window", 1, "30")
	              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK
	              && fzn_node_settings_window_days(&ns) == 30u,
	      "the window was not 60 unset, or an admin's 30 did not count");
	CHECK(setting_by(&nj, 0x93, FZN_SCOPE_ESTATE, 0x91, 2u, "journal/window", 1, "0")
	              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK
	              && fzn_node_settings_window_days(&ns) == 60u
	              && setting_by(&nj, 0x93, FZN_SCOPE_ESTATE, 0x91, 3u, "journal/window", 1,
	                            "36501")
	              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK
	              && fzn_node_settings_window_days(&ns) == 60u
	              && setting_by(&nj, 0x93, FZN_SCOPE_ESTATE, 0x91, 4u, "journal/window", 1,
	                            "36500")
	              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK
	              && fzn_node_settings_window_days(&ns) == 36500u,
	      "a window of 0 or past 36500 days counted, or 36500 did not");

	/* THE ARCHIVE'S REPLICAS, sec 592: 2 until set, 1 to 16 counted. */
	CHECK(fzn_node_settings_replicas(&ns) == 2u
	              && setting_by(&nj, 0x93, FZN_SCOPE_ESTATE, 0x91, 1u, "archive/replicas", 1, "3")
	              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK
	              && fzn_node_settings_replicas(&ns) == 3u
	              && setting_by(&nj, 0x93, FZN_SCOPE_ESTATE, 0x91, 2u, "archive/replicas", 1, "17")
	              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK
	              && fzn_node_settings_replicas(&ns) == 2u
	              && setting_by(&nj, 0x93, FZN_SCOPE_ESTATE, 0x91, 3u, "archive/replicas", 1, "16")
	              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK
	              && fzn_node_settings_replicas(&ns) == 16u,
	      "replicas were not 2 unset, 3 set, 2 past 16, or 16 at the bound");

	/* A MEMBER'S ADDRESS, sec 579: its own host cell, `HOST PORT`. */
	{
		uint8_t member[FZN_SUBJECT_LEN];
		char host[FZN_NODE_SETTINGS_HOST_MAX + 1u];
		uint16_t port = 0;

		key(member, 0x92);
		CHECK(!fzn_node_settings_address(&ns, member, host, &port)
		              && setting_by(&nj, 0x92, FZN_SCOPE_HOST, 0x92, 1u, "net/address", 1,
		                            "fe80::1 47000")
		              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK
		              && fzn_node_settings_address(&ns, member, host, &port)
		              && strcmp(host, "fe80::1") == 0 && port == 47000u,
		      "a member's address was found unset, or its own was not read");
		CHECK(setting_by(&nj, 0x92, FZN_SCOPE_HOST, 0x92, 2u, "net/address", 1, "a.example 0")
		              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK
		              && !fzn_node_settings_address(&ns, member, host, &port)
		              && setting_by(&nj, 0x92, FZN_SCOPE_HOST, 0x92, 3u, "net/address", 1,
		                            "a.example 65536")
		              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK
		              && !fzn_node_settings_address(&ns, member, host, &port)
		              && setting_by(&nj, 0x92, FZN_SCOPE_HOST, 0x92, 4u, "net/address", 1,
		                            "a/b 1")
		              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK
		              && !fzn_node_settings_address(&ns, member, host, &port)
		              && setting_by(&nj, 0x92, FZN_SCOPE_HOST, 0x92, 5u, "net/address", 1,
		                            "a.example")
		              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK
		              && !fzn_node_settings_address(&ns, member, host, &port)
		              && setting_by(&nj, 0x92, FZN_SCOPE_HOST, 0x92, 6u, "net/address", 1,
		                            " 1")
		              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK
		              && !fzn_node_settings_address(&ns, member, host, &port)
		              && setting_by(&nj, 0x92, FZN_SCOPE_HOST, 0x92, 7u, "net/address", 1,
		                            "a.example 65535")
		              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK
		              && fzn_node_settings_address(&ns, member, host, &port)
		              && strcmp(host, "a.example") == 0 && port == 65535u,
		      "a port of 0 or past 65535, a host with a slash, no port or no host was read, "
		      "or 65535 was not");
	}

	/* A SIBLING'S PREKEY, sec 579: kept when its carrier is its host and a
	 * member; the newest per host; a stranger's waits. */
	{
		uint8_t member[FZN_PUBKEY_LEN], other[FZN_PUBKEY_LEN], stranger[FZN_PUBKEY_LEN];
		uint8_t agree[FZN_PREKEY_LEN], pk[FZN_PREKEY_LEN_TOTAL], older[FZN_PREKEY_LEN_TOTAL];
		uint8_t newer[FZN_PREKEY_LEN_TOTAL], kept[FZN_PREKEY_LEN_TOTAL];
		uint8_t hosts[FZN_NODE_SIBLINGS_MAX][FZN_PUBKEY_LEN];
		size_t count = 0;

		key(member, 0x92);
		key(other, 0x94);
		key(stranger, 0x97);
		memset(agree, 0x5e, sizeof(agree));
		signing_as = 0x92;
		CHECK(fzn_prekey_issue(member, agree, 2000u, &SIGN, pk) == FZN_PREKEY_OK
		              && fzn_prekey_issue(member, agree, 1000u, &SIGN, older) == FZN_PREKEY_OK
		              && fzn_prekey_issue(member, agree, 3000u, &SIGN, newer) == FZN_PREKEY_OK,
		      "fixture: three of M's prekey records");
		CHECK(fzn_node_siblings_prekey(&store, member, kept) == FZN_NODE_SIBLINGS_BACKEND
		              && put(&nj, 0x92, pk, sizeof(pk))
		              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK
		              && fzn_node_siblings_prekey(&store, member, kept) == FZN_NODE_SIBLINGS_OK
		              && memcmp(kept, pk, sizeof(pk)) == 0,
		      "a member's own prekey, carried in its stream, was not kept");
		signing_as = 0x94;
		CHECK(fzn_prekey_issue(other, agree, 2000u, &SIGN, kept) == FZN_PREKEY_OK
		              && put(&nj, 0x92, kept, sizeof(kept))
		              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK
		              && fzn_node_siblings_prekey(&store, other, kept)
		                         == FZN_NODE_SIBLINGS_BACKEND,
		      "a prekey a member carried about another host was kept");
		signing_as = 0x97;
		CHECK(fzn_prekey_issue(stranger, agree, 2000u, &SIGN, kept) == FZN_PREKEY_OK
		              && put(&nj, 0x97, kept, sizeof(kept))
		              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK && t.waiting >= 1u
		              && fzn_node_siblings_prekey(&store, stranger, kept)
		                         == FZN_NODE_SIBLINGS_BACKEND,
		      "a stranger's prekey did not wait for a chain");
		CHECK(put(&nj, 0x92, older, sizeof(older))
		              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK
		              && fzn_node_siblings_prekey(&store, member, kept) == FZN_NODE_SIBLINGS_OK
		              && memcmp(kept, pk, sizeof(pk)) == 0
		              && put(&nj, 0x92, newer, sizeof(newer))
		              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK
		              && fzn_node_siblings_prekey(&store, member, kept) == FZN_NODE_SIBLINGS_OK
		              && memcmp(kept, newer, sizeof(newer)) == 0,
		      "an older prekey replaced the newer, or a newer one did not");
		CHECK(fzn_node_siblings_list(&store, hosts, FZN_NODE_SIBLINGS_MAX, &count)
		                      == FZN_NODE_SIBLINGS_OK
		              && count == 1u && memcmp(hosts[0], member, FZN_PUBKEY_LEN) == 0,
		      "the siblings listed were not M alone");
	}

	/* A GRANT THAT MAY BE PASSED ON IS WALKED FIRST, sec 579: K joined
	 * through R with a delegable grant, and M, a sibling, paired K too. M's
	 * grant is indexed first; K's chain is still R's one hop. */
	{
		uint8_t k[FZN_PUBKEY_LEN], chain[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
		size_t n = 0;

		key(k, 0x96);
		signing_as = 0x92;
		CHECK(fzn_chain_mint(m, k, &cap, 100u, FZN_NO_EXPIRY, 0, &SIGN, hop) == FZN_CHAIN_OK
		              && put(&nj, 0x92, hop, sizeof(hop))
		              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK,
		      "fixture: M pairs K");
		signing_as = 0x91;
		CHECK(fzn_chain_mint(r, k, &cap, 100u, FZN_NO_EXPIRY, 1, &SIGN, hop) == FZN_CHAIN_OK
		              && put(&nj, 0x91, hop, sizeof(hop))
		              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK,
		      "fixture: R grants K a delegable grant, as a join is");
		CHECK(fzn_node_apply_chain(&ap, k, &cap, chain, &n) && n == 1u
		              && memcmp(chain[0], hop, FZN_HOP_LEN) == 0,
		      "K's chain was walked through a sibling's grant, not its own delegable one");
	}

	/* CLEARS FORGOTTEN, sec 549. The root sets c/x and clears it at 5000.
	 * Until the window has passed the clear stands against a late older
	 * set; once it has, the clear goes and the late set is taken. A set is
	 * never forgotten, and a clear in a row of the older shape starts its
	 * window when it is first found. A write's version is no lower than
	 * the clock. */
	{
		size_t forgot = 0, i;
		struct row *legacy = NULL;

		store.remove = mem_remove;
		clock_at = 5000u;
		CHECK(setting_by(&nj, 0x91, FZN_SCOPE_ESTATE, 0x91, 10u, "c/x", 1, "on")
		              && setting_by(&nj, 0x91, FZN_SCOPE_ESTATE, 0x91, 11u, "c/x", 0, NULL)
		              && setting_by(&nj, 0x91, FZN_SCOPE_ESTATE, 0x91, 10u, "c/y", 0, NULL)
		              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK
		              && in_force(&ns, FZN_SCOPE_ESTATE, 0x91, "c/x", NULL,
		                          FZN_SETTING_RANK_HOST),
		      "fixture: the root sets c/x and clears it, and clears c/y, at 5000");
		for (i = 0; i < ROWS; i++)
			if (rows[i].used && rows[i].slot == FZN_PERSIST_SETTING
			    && holds(rows[i].bytes, rows[i].len, "c/y", 3u) && rows[i].len > 9u) {
				legacy = &rows[i];
				legacy->bytes[0] &= 0x7fu;
				memmove(legacy->bytes + 1u, legacy->bytes + 9u, legacy->len - 9u);
				legacy->len -= 8u;
			}
		CHECK(legacy != NULL, "fixture: c/y's clear rewritten in the older shape");
		clock_at = 6000u;
		CHECK(fzn_node_settings_forget_clears(&ns, 5000u, &forgot) == FZN_NODE_SETTINGS_OK
		              && setting_by(&nj, 0x91, FZN_SCOPE_ESTATE, 0x91, 9u, "c/x", 1, "late")
		              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK
		              && in_force(&ns, FZN_SCOPE_ESTATE, 0x91, "c/x", NULL,
		                          FZN_SETTING_RANK_HOST),
		      "a clear inside the window was forgotten, and a late older set took the cell");
		CHECK(legacy->used && (legacy->bytes[0] & 0x80u) && legacy->len > 9u
		              && fzn_get_be64(legacy->bytes + 1u) == 6000u,
		      "a clear of the older shape did not start its window when first found");
		CHECK(fzn_node_settings_forget_clears(&ns, 5001u, &forgot) == FZN_NODE_SETTINGS_OK
		              && forgot >= 1u
		              && setting_by(&nj, 0x91, FZN_SCOPE_ESTATE, 0x91, 8u, "c/x", 1, "later")
		              && fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK
		              && in_force(&ns, FZN_SCOPE_ESTATE, 0x91, "c/x", "later",
		                          FZN_SETTING_RANK_ROOT)
		              && legacy->used,
		      "a clear past the window stood, or the older-shaped one went before its window");
		CHECK(fzn_node_settings_forget_clears(&ns, UINT64_MAX, &forgot) == FZN_NODE_SETTINGS_OK
		              && !legacy->used
		              && in_force(&ns, FZN_SCOPE_ESTATE, 0x91, "c/x", "later",
		                          FZN_SETTING_RANK_ROOT)
		              && in_force(&ns, FZN_SCOPE_ESTATE, 0x91, "k", "v", FZN_SETTING_RANK_ROOT),
		      "a set was forgotten, or a clear past every window was not");
		memcpy(me.pubkey, r, FZN_PUBKEY_LEN);
		signing_as = 0x91;
		CHECK(fzn_node_settings_write(&ns, FZN_SCOPE_ESTATE, estate, (const uint8_t *)"c/w",
		                              3u, 1, (const uint8_t *)"1", 1u) == FZN_NODE_SETTINGS_OK
		              && said(&ns, FZN_ORIGIN_SAME_USER, "list setting")
		              && strstr(reply, ",c/w,root,6000,") != NULL,
		      "a write's version was below the clock");
		clock_at = 1000u;
	}

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
	/* RECONCILED FROM NOTHING, sec 550: every object this node holds, by
	 * class, handed one at a time to a node that holds none -- a fresh
	 * apply context over an emptied store -- until a pass changes nothing.
	 * Every class's digest is then the source's, order of arrival
	 * notwithstanding; and a grant with one byte changed is refused and
	 * changes nothing. */
	{
		static uint8_t objects[128][1024];
		static size_t lens[128];
		static struct row saved[ROWS];
		static fzn_node_apply_t ap2;
		static fzn_node_settings_t ns2;
		static fzn_revocation_t rev_entries2[8];
		static fzn_revocation_admin_t admins2[4];
		uint8_t want[FZN_HOLDINGS_CLASSES][FZN_HOLDINGS_ID_LEN], got[FZN_HOLDINGS_ID_LEN];
		size_t want_count[FZN_HOLDINGS_CLASSES], got_count = 0, n = 0, i, pass, c;
		fzn_revocation_store_t revs2;
		struct snap s = { objects, lens, 128u, 0u };
		int ok = 1, same = 0;
		fzn_node_apply_outcome_t forged;

		/* THIS ESTATE'S STATE ONLY: the roster and succession rows an
		 * earlier case left in the shared store are another root's. */
		memcpy(saved, rows, sizeof(rows));
		for (i = 0; i < ROWS; i++)
			if (rows[i].used
			    && (rows[i].slot == FZN_PERSIST_ROSTER || rows[i].slot == FZN_PERSIST_SUCCESSION))
				memset(&rows[i], 0, sizeof(rows[i]));
		for (c = 0; c < FZN_HOLDINGS_CLASSES; c++)
			ok = ok
			     && fzn_holdings_digest(&store, &HASH, (fzn_holdings_class_t)c, want[c],
			                            &want_count[c]) == FZN_HOLDINGS_OK
			     && fzn_holdings_each(&store, &HASH, (fzn_holdings_class_t)c, snap_one, &s,
			                          NULL) == FZN_HOLDINGS_OK;
		n = s.n;
		CHECK(ok && n < 128u && want_count[FZN_HOLDINGS_GRANTS] >= 2u
		              && want_count[FZN_HOLDINGS_SETTINGS] >= 4u,
		      "fixture: this node's grants and settings, digested and taken out");
		memset(rows, 0, sizeof(rows));
		memset(&ap2, 0, sizeof(ap2));
		CHECK(fzn_revocation_store_init(&revs2, rev_entries2, 8) == FZN_CHAIN_OK
		              && fzn_revocation_store_set_quorum(&revs2, 1u, &admin_cap, admins2, 4u)
		                         == FZN_CHAIN_OK,
		      "fixture: a node that holds nothing");
		ap2.journal = &nj;
		ap2.revocations = &revs2;
		ap2.store = &store;
		ap2.root = r;
		ap2.capability = &cap;
		ap2.admin_capability = &admin_cap;
		ap2.sign = &SIGN;
		ap2.hash = &HASH;
		ap2.settings = &ns2;
		ap2.roots = ap.roots;
		ap2.roster = ap.roster;
		ap2.successions = ap.successions;
		ap2.now = clock_now;
		ns2 = ns;
		ns2.apply = &ap2;
		/* THE LAST FIRST, so a setting arrives before the grant that ranks
		 * its setter, and waits for it. */
		for (pass = 0; pass < 8u && !same; pass++) {
			for (i = n; i-- > 0u;)
				(void)fzn_node_apply_object(&ap2, objects[i], lens[i], &t);
			same = 1;
			for (c = 0; c < FZN_HOLDINGS_CLASSES; c++)
				same = same
				       && fzn_holdings_digest(&store, &HASH, (fzn_holdings_class_t)c, got,
				                              &got_count) == FZN_HOLDINGS_OK
				       && got_count == want_count[c] && memcmp(got, want[c], sizeof(got)) == 0;
		}
		CHECK(same && pass > 1u,
		      "a node holding nothing did not come to every class's digest by objects alone");
		memcpy(objects[n], objects[0], lens[0]);
		objects[n][lens[0] - 1u] ^= 1u;
		forged = fzn_node_apply_object(&ap2, objects[n], lens[0], &t);
		CHECK(forged == FZN_NODE_APPLY_REFUSED
		              && fzn_holdings_digest(&store, &HASH, FZN_HOLDINGS_GRANTS, got, &got_count)
		                         == FZN_HOLDINGS_OK
		              && memcmp(got, want[FZN_HOLDINGS_GRANTS], sizeof(got)) == 0,
		      "an object with a byte changed was taken, or changed the digest");
		memcpy(rows, saved, sizeof(rows));
	}
	/* A ROW UNDER ANOTHER CELL'S PLACE is not that cell's: the estate's
	 * rule copied over the root's row for the member's cell, which then
	 * falls to the member's own value. */
	{
		struct row *from = NULL, *to = NULL;
		size_t i;

		for (i = 0; i < ROWS; i++) {
			if (!rows[i].used || rows[i].slot != FZN_PERSIST_SETTING || rows[i].len < 2u
			    || (rows[i].bytes[0] & 0x7fu) != (uint8_t)FZN_SETTING_RANK_ROOT)
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

/* Plant `n` bytes as a row of `slot` under a subject made from `seed`. */
static void plant(fzn_persist_slot_t slot, uint8_t seed, const uint8_t *bytes, size_t n)
{
	uint8_t subject[FZN_PUBKEY_LEN];

	memset(subject, seed, sizeof(subject));
	(void)mem_save(NULL, slot, subject, bytes, n);
}

/* A hop-shaped object: the right version, tag and length, `fill` behind. */
static void fake_hop(uint8_t out[FZN_HOP_LEN], uint8_t fill)
{
	memset(out, fill, FZN_HOP_LEN);
	out[0] = FZN_SIGNED_VERSION;
	out[1] = FZN_OBJECT_HOP;
}

/* HOLDINGS, sec 550: a class is the rows of its slot that hold its object.
 * Three grants planted in one order and then in another give one digest; a
 * row of another tag or length is passed over; a different set gives a
 * different digest; the ids come back ascending and are found; a setting
 * row of either shape reads past its head. */
static void test_holdings(void)
{
	fzn_persist_ops_t store = { 0 };
	uint8_t hops[3][FZN_HOP_LEN], bad[FZN_HOP_LEN], d1[FZN_HOLDINGS_ID_LEN];
	uint8_t d2[FZN_HOLDINGS_ID_LEN], d3[FZN_HOLDINGS_ID_LEN], ids[8][FZN_HOLDINGS_ID_LEN];
	uint8_t setting[1u + 8u + 4u], old_shape[1u + 4u];
	size_t n1 = 0, n2 = 0, n = 0, i;
	int ascending = 1, found = 1;

	store.load = mem_load;
	store.save = mem_save;
	store.list = mem_list;
	memset(rows, 0, sizeof(rows));
	for (i = 0; i < 3u; i++)
		fake_hop(hops[i], (uint8_t)(0x10u + i));
	fake_hop(bad, 0x20);
	bad[1] = FZN_OBJECT_REVOCATION;
	for (i = 0; i < 3u; i++)
		plant(FZN_PERSIST_GRANT, (uint8_t)(1u + i), hops[i], FZN_HOP_LEN);
	plant(FZN_PERSIST_GRANT, 9u, bad, FZN_HOP_LEN);
	plant(FZN_PERSIST_GRANT, 10u, hops[0], FZN_HOP_LEN - 1u);
	CHECK(fzn_holdings_digest(&store, &HASH, FZN_HOLDINGS_GRANTS, d1, &n1) == FZN_HOLDINGS_OK
	              && n1 == 3u,
	      "the grants class was not the three grants alone");
	memset(rows, 0, sizeof(rows));
	plant(FZN_PERSIST_GRANT, 7u, hops[2], FZN_HOP_LEN);
	plant(FZN_PERSIST_GRANT, 5u, hops[0], FZN_HOP_LEN);
	plant(FZN_PERSIST_GRANT, 6u, hops[1], FZN_HOP_LEN);
	CHECK(fzn_holdings_digest(&store, &HASH, FZN_HOLDINGS_GRANTS, d2, &n2) == FZN_HOLDINGS_OK
	              && n2 == 3u && memcmp(d1, d2, sizeof(d1)) == 0,
	      "the same grants in another order gave another digest");
	CHECK(fzn_holdings_ids(&store, &HASH, FZN_HOLDINGS_GRANTS, ids, 8u, &n) == FZN_HOLDINGS_OK
	              && n == 3u,
	      "the grants' ids were not listed");
	for (i = 1; i < n; i++)
		ascending &= memcmp(ids[i - 1u], ids[i], FZN_HOLDINGS_ID_LEN) < 0;
	for (i = 0; i < n; i++)
		found &= fzn_holdings_among((const uint8_t(*)[FZN_HOLDINGS_ID_LEN])ids, n, ids[i]);
	CHECK(ascending && found
	              && !fzn_holdings_among((const uint8_t(*)[FZN_HOLDINGS_ID_LEN])ids, n, d1)
	              && fzn_holdings_ids(&store, &HASH, FZN_HOLDINGS_GRANTS, ids, 2u, &n)
	                         == FZN_HOLDINGS_FULL,
	      "the ids were not ascending and found, or a short list was not FULL");
	plant(FZN_PERSIST_GRANT, 8u, bad, FZN_HOP_LEN);
	bad[1] = FZN_OBJECT_HOP;
	plant(FZN_PERSIST_GRANT, 8u, bad, FZN_HOP_LEN);
	CHECK(fzn_holdings_digest(&store, &HASH, FZN_HOLDINGS_GRANTS, d3, &n) == FZN_HOLDINGS_OK
	              && n == 4u && memcmp(d3, d1, sizeof(d1)) != 0,
	      "a fourth grant left the digest as it was");
	/* SETTINGS: a stamped row and one of the older shape, each read past
	 * its head; the object itself is the same four bytes. */
	setting[0] = 0x80u | (uint8_t)FZN_SETTING_RANK_ROOT;
	memset(setting + 1, 0, 8);
	setting[9] = FZN_SIGNED_VERSION;
	setting[10] = FZN_OBJECT_SETTING;
	setting[11] = 0x41;
	setting[12] = 0x42;
	old_shape[0] = (uint8_t)FZN_SETTING_RANK_ROOT;
	memcpy(old_shape + 1, setting + 9, 4);
	plant(FZN_PERSIST_SETTING, 1u, setting, sizeof(setting));
	CHECK(fzn_holdings_digest(&store, &HASH, FZN_HOLDINGS_SETTINGS, d1, &n1) == FZN_HOLDINGS_OK
	              && n1 == 1u,
	      "a stamped setting row was not read");
	memset(rows, 0, sizeof(rows));
	plant(FZN_PERSIST_SETTING, 1u, old_shape, sizeof(old_shape));
	CHECK(fzn_holdings_digest(&store, &HASH, FZN_HOLDINGS_SETTINGS, d2, &n2) == FZN_HOLDINGS_OK
	              && n2 == 1u && memcmp(d1, d2, sizeof(d1)) == 0,
	      "a setting row of the older shape was read as another object");
	memset(rows, 0, sizeof(rows));
}

/* A CAPABILITY HELD, sec 567: a root holds it; a key granted it by a root,
 * its grant applied from the journal, holds it while the grant stands; a
 * stranger, a key granted another capability, and one whose grant has
 * expired do not. */
static void test_a_capability_held(void)
{
	static fzn_node_journal_t nj;
	static fzn_revocation_t rev_entries[8];
	static fzn_node_apply_t ap;
	fzn_revocation_store_t revs;
	fzn_persist_ops_t store = { 0 };
	fzn_node_apply_tally_t t;
	fzn_cap_id_t cap, retention;
	uint8_t r[FZN_PUBKEY_LEN], m[FZN_PUBKEY_LEN], o[FZN_PUBKEY_LEN], e[FZN_PUBKEY_LEN];
	uint8_t s[FZN_PUBKEY_LEN], hop[FZN_HOP_LEN];

	store.load = mem_load;
	store.save = mem_save;
	store.list = mem_list;
	memset(&cap, 0x71, sizeof(cap));
	memset(&retention, 0x72, sizeof(retention));
	key(r, 0xa1);
	key(m, 0xa2);
	key(o, 0xa3);
	key(e, 0xa4);
	key(s, 0xa5);
	CHECK(fzn_node_journal_init(&nj, dir, &SIGN, &HASH) == FZN_NODE_JOURNAL_OK
	              && fzn_revocation_store_init(&revs, rev_entries, 8) == FZN_CHAIN_OK,
	      "fixture: a journal and a revocation store");
	memset(&ap, 0, sizeof(ap));
	ap.journal = &nj;
	ap.revocations = &revs;
	ap.store = &store;
	ap.root = r;
	ap.capability = &cap;
	ap.sign = &SIGN;
	ap.hash = &HASH;
	ap.now = clock_now;
	clock_at = 1000u;
	signing_as = 0xa1;
	CHECK(fzn_chain_mint(r, m, &retention, 100u, FZN_NO_EXPIRY, 0, &SIGN, hop) == FZN_CHAIN_OK
	              && put(&nj, 0xa1, hop, sizeof(hop))
	              && fzn_chain_mint(r, o, &cap, 100u, FZN_NO_EXPIRY, 0, &SIGN, hop)
	                         == FZN_CHAIN_OK
	              && put(&nj, 0xa1, hop, sizeof(hop))
	              && fzn_chain_mint(r, e, &retention, 100u, 500u, 0, &SIGN, hop) == FZN_CHAIN_OK
	              && put(&nj, 0xa1, hop, sizeof(hop)),
	      "fixture: R grants M the capability, O another, and E the capability until 500");
	CHECK(fzn_node_apply_round(&ap, &t) == FZN_NODE_PULL_OK && t.grants == 3u,
	      "fixture: the three grants applied");
	CHECK(fzn_node_apply_holds(&ap, r, &retention) && fzn_node_apply_holds(&ap, m, &retention),
	      "the root, or the key it granted the capability, does not hold it");
	CHECK(!fzn_node_apply_holds(&ap, s, &retention) && !fzn_node_apply_holds(&ap, o, &retention)
	              && fzn_node_apply_holds(&ap, o, &cap),
	      "a stranger, or a key granted another capability, holds it");
	CHECK(!fzn_node_apply_holds(&ap, e, &retention),
	      "a key whose grant expired at 500 holds it at 1000");
	clock_at = 400u;
	CHECK(fzn_node_apply_holds(&ap, e, &retention), "and before 500 it does not hold it");
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
	test_holdings();
	test_a_capability_held();
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
