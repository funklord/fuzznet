/*
 * A fuzz harness for the estate's acts, `node/apply.h`: sec 689's estate
 * journey. Every object of the root log, the votes, the confirmations, the
 * retention settings, the roster and the successions reaches a node by one
 * door, `fzn_node_apply_object` -- reconciliation's, and the journal's for
 * each record's body -- and that door hands each to the subsystem that judges
 * its kind.
 *
 * WHY THIS ONE. These are what decide who is in the estate and with what
 * standing: a vote taken that should not have been revokes a device, a root
 * record admitted wrongly hands the estate over. Sec 689 found none of them
 * fuzzed.
 *
 * THE PROPERTY, stated so nothing passes it by accident: genuine objects are
 * offered in a fixed order, and between them bent copies and forgeries. At
 * the end the node must conclude exactly what a node that saw the genuine
 * objects alone concludes -- the estate's k, which roots stand, its
 * retention rules, whether M is revoked, C's place on the roster, who M is
 * now, and the standing of every key involved -- and its store must hold
 * the same rows, byte for byte, but in two slots. The root log (slot 13)
 * and the grant index keep every properly signed record and judge it when
 * read (sec 418, 545), so a stranger's signed record is kept there by
 * design; what it may not do is change a conclusion.
 *
 * THE LIARS. Mutation alone tests only the first guard in front of a
 * signature (sec 691's lesson), so there are coherent ones too:
 * - a genuine object with a signed byte changed after signing;
 * - each kind properly signed by a key nobody granted anything;
 * - each kind properly signed by a member with no admin standing;
 * - a stranger's own grants, properly signed by the stranger -- what a host
 *   that may put anything into the journal or a reconcile answer can make.
 *
 * FLOORS: a run that refused nothing, or offered no forgery of a kind, has
 * not tested what it claims.
 *
 * The fixtures are apply_test's and reconcile_fuzz's: the keyed mixing
 * signer -- an object verifies under the key it was signed as and no other
 * -- and an in-memory store.
 */

#include "../apply.h"
#include "../roots.h"
#include "../roster.h"
#include "../succession.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 2000u
#define FUZZ_MIN_CASES 500u

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

static void key(uint8_t out[FZN_PUBKEY_LEN], uint8_t seed)
{
	size_t i;

	for (i = 0; i < FZN_PUBKEY_LEN; i++)
		out[i] = (uint8_t)(seed + i * 3u);
	out[0] = seed;
}

/* ---- a store per node ---------------------------------------------------- */

#define ROWS 160

struct row {
	int used;
	fzn_persist_slot_t slot;
	uint8_t subject[FZN_PUBKEY_LEN];
	uint8_t bytes[4096];
	size_t len;
};

struct mem {
	struct row rows[ROWS];
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
	struct row *r;

	if (len > sizeof(r->bytes))
		return 0;
	r = row_of((struct mem *)ctx, slot, subject, 1);
	if (!r)
		return 0;
	memcpy(r->bytes, bytes, len);
	r->len = len;
	return 1;
}

static int mem_list(void *ctx, fzn_persist_slot_t slot, uint8_t *out, size_t max, size_t *count)
{
	struct mem *m = (struct mem *)ctx;
	int i;

	*count = 0;
	for (i = 0; i < ROWS; i++)
		if (m->rows[i].used && m->rows[i].slot == slot) {
			if (*count >= max)
				return 0;
			memcpy(out + (*count)++ * FZN_PUBKEY_LEN, m->rows[i].subject, FZN_PUBKEY_LEN);
		}
	return 1;
}

static int mem_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	struct row *r = row_of((struct mem *)ctx, slot, subject, 0);

	if (r)
		memset(r, 0, sizeof(*r));
	return 1;
}

/* ---- a node ---------------------------------------------------------------- */

static fzn_cap_id_t cap, admin_cap;
static uint8_t root_key[FZN_PUBKEY_LEN];

typedef struct node {
	struct mem mem;
	fzn_persist_ops_t store;
	fzn_node_apply_t ap;
	fzn_revocation_store_t revs;
	fzn_revocation_t rev_entries[16];
	fzn_revocation_admin_t admins[8];
	fzn_revocation_confirm_t confirms[16];
	fzn_node_roots_t roots;
	fzn_node_roster_t roster;
	fzn_node_successions_t successions;
} node_t;

static uint64_t clock_now(void)
{
	return 1000u;
}

static int node_up(node_t *n)
{
	memset(n, 0, sizeof(*n));
	n->store.load = mem_load;
	n->store.save = mem_save;
	n->store.list = mem_list;
	n->store.remove = mem_remove;
	n->store.ctx = &n->mem;
	if (fzn_revocation_store_init(&n->revs, n->rev_entries, 16) != FZN_CHAIN_OK
	    || fzn_revocation_store_set_quorum(&n->revs, 2u, &admin_cap, n->admins, 8u)
	               != FZN_CHAIN_OK
	    || fzn_revocation_store_set_confirmations(&n->revs, n->confirms, 16u, &HASH)
	               != FZN_CHAIN_OK
	    || fzn_node_roots_init(&n->roots, root_key, &SIGN, &HASH) != FZN_NODE_ROOTS_OK
	    || fzn_node_roots_attach(&n->roots, &n->revs) != FZN_NODE_ROOTS_OK
	    || fzn_node_roster_init(&n->roster, root_key, &cap, &SIGN, &n->roots.ops, &HASH)
	               != FZN_NODE_ROSTER_OK
	    || fzn_node_successions_init(&n->successions, &HASH) != FZN_NODE_REVOKE_OK)
		return 0;
	n->ap.revocations = &n->revs;
	n->ap.roots = &n->roots;
	n->ap.roster = &n->roster;
	n->ap.successions = &n->successions;
	n->ap.store = &n->store;
	n->ap.root = root_key;
	n->ap.capability = &cap;
	n->ap.admin_capability = &admin_cap;
	n->ap.sign = &SIGN;
	n->ap.hash = &HASH;
	n->ap.now = clock_now;
	return 1;
}

static fzn_node_apply_outcome_t give(node_t *n, const uint8_t *object, size_t len)
{
	fzn_node_apply_tally_t t;

	memset(&t, 0, sizeof(t));
	return fzn_node_apply_object(&n->ap, object, len, &t);
}

/* ---- the objects ----------------------------------------------------------- */

#define OBJECT_MAX 1024u
#define GENUINE_MAX 16u
#define FORGED_MAX 48u

struct object {
	const char *what;
	uint8_t bytes[OBJECT_MAX];
	size_t len;
};

static struct object genuine[GENUINE_MAX], forged[FORGED_MAX];
static size_t n_genuine, n_forged;

/* THE KEYS: R the root, M a member, A1 and A2 admins, R2 a root R adds, C a
 * contact, D2 the key M is succeeded by, X a stranger. */
enum { R = 0x91, M = 0x92, A1 = 0x93, A2 = 0x94, R2 = 0x95, D2 = 0x96, C = 0x70, X = 0x99 };

static struct object *slot_of(struct object *list, size_t *n, size_t max, const char *what)
{
	if (*n >= max)
		return NULL;
	list[*n].what = what;
	list[*n].len = 0;
	return &list[(*n)++];
}

static int hop_as(struct object *o, uint8_t from, uint8_t to, const fzn_cap_id_t *c,
                  int delegable)
{
	uint8_t a[FZN_PUBKEY_LEN], b[FZN_PUBKEY_LEN];

	key(a, from);
	key(b, to);
	signing_as = from;
	o->len = FZN_HOP_LEN;
	return o && fzn_chain_mint(a, b, c, 100u, FZN_NO_EXPIRY, delegable, &SIGN, o->bytes)
	                    == FZN_CHAIN_OK;
}

static int hop(struct object *o, uint8_t from, uint8_t to, const fzn_cap_id_t *c)
{
	return hop_as(o, from, to, c, 0);
}

static int vote(struct object *o, uint8_t by, uint8_t against)
{
	uint8_t a[FZN_PUBKEY_LEN], b[FZN_PUBKEY_LEN], cut[FZN_REVOCATION_ID_LEN];

	memset(cut, 0, sizeof(cut));
	key(a, by);
	key(b, against);
	signing_as = by;
	o->len = FZN_REVOCATION_LEN;
	return o && fzn_revocation_issue(a, &cap, b, 200u, 0u, cut, &SIGN, o->bytes) == FZN_CHAIN_OK;
}

static int confirm(struct object *o, uint8_t by, const struct object *grant)
{
	uint8_t a[FZN_PUBKEY_LEN], id[FZN_REVOCATION_ID_LEN];

	key(a, by);
	signing_as = by;
	o->len = FZN_ADMIN_CONFIRM_LEN;
	return o && mix_hash(NULL, id, sizeof(id), grant->bytes, grant->len)
	       && fzn_admin_confirm_issue(a, id, &SIGN, o->bytes) == FZN_CHAIN_OK;
}

/* A RECORD'S ID, the hash every later record that replaces it names. */
static void id_of(const struct object *o, uint8_t id[FZN_ROOT_ACT_ID_LEN])
{
	(void)mix_hash(NULL, id, FZN_ROOT_ACT_ID_LEN, o->bytes, o->len);
}

/* `text`, or with `text` NULL the removal of `replaces`. */
static int retention_after(struct object *o, uint8_t by, const char *text,
                           const struct object *replaces)
{
	uint8_t a[FZN_PUBKEY_LEN], id[FZN_ROOT_ACT_ID_LEN];

	key(a, by);
	if (replaces)
		id_of(replaces, id);
	signing_as = by;
	o->len = FZN_RETENTION_SET_LEN;
	return o && fzn_retention_set_issue(a, text, text ? strlen(text) : 0u, replaces ? id : NULL,
	                                    &SIGN, o->bytes) == FZN_ROOT_LOG_OK;
}

static int retention(struct object *o, uint8_t by, const char *text)
{
	return retention_after(o, by, text, NULL);
}

static int roster(struct object *o, uint8_t by, int add, uint64_t seq)
{
	uint8_t a[FZN_PUBKEY_LEN], s[FZN_PUBKEY_LEN], inc[FZN_ROSTER_INCARNATION_LEN];

	key(a, by);
	key(s, C);
	memset(inc, 0x0e, sizeof(inc));
	signing_as = by;
	return o
	       && (add ? fzn_roster_issue_add(a, s, inc, seq, &SIGN, o->bytes, sizeof(o->bytes),
	                                      &o->len)
	               : fzn_roster_issue_remove(a, s, inc, seq, &SIGN, o->bytes, sizeof(o->bytes),
	                                         &o->len))
	                  == FZN_ROSTER_OK;
}

static int succession(struct object *o, uint8_t by)
{
	uint8_t a[FZN_PUBKEY_LEN], old[FZN_PUBKEY_LEN], fresh[FZN_PUBKEY_LEN];

	key(a, by);
	key(old, M);
	key(fresh, D2);
	signing_as = by;
	o->len = FZN_SUCCESSION_LEN;
	return o && fzn_succession_issue(a, old, fresh, NULL, &SIGN, o->bytes) == FZN_CHAIN_OK;
}

static int root_add(struct object *o, uint8_t by, uint8_t added)
{
	uint8_t a[FZN_PUBKEY_LEN], b[FZN_PUBKEY_LEN];

	key(a, by);
	key(b, added);
	signing_as = by;
	o->len = FZN_ROOT_ADD_LEN;
	return o && fzn_root_add_issue(a, b, &SIGN, o->bytes) == FZN_ROOT_LOG_OK;
}

static int quorum_after(struct object *o, uint8_t by, uint8_t k, const struct object *replaces)
{
	uint8_t a[FZN_PUBKEY_LEN], id[FZN_ROOT_ACT_ID_LEN];

	key(a, by);
	if (replaces)
		id_of(replaces, id);
	signing_as = by;
	o->len = FZN_QUORUM_SET_LEN;
	return o && fzn_quorum_set_issue(a, k, replaces ? id : NULL, &SIGN, o->bytes)
	                    == FZN_ROOT_LOG_OK;
}

static int quorum(struct object *o, uint8_t by, uint8_t k)
{
	return quorum_after(o, by, k, NULL);
}

#define G(what) slot_of(genuine, &n_genuine, GENUINE_MAX, what)
#define F(what) slot_of(forged, &n_forged, FORGED_MAX, what)

/* THE ESTATE'S ACTS, in the order a journal might hand them over, and every
 * lie told about them. */
static int the_objects(void)
{
	const struct object *a2_grant, *r_k, *r_retention;
	size_t i, honest;

	if (!hop(G("R grants M"), R, M, &cap) || !hop(G("R grants A1 admin"), R, A1, &admin_cap)
	    || !hop(G("R grants A2 admin"), R, A2, &admin_cap))
		return 0;
	a2_grant = &genuine[n_genuine - 1u];
	if (!quorum(G("R sets k 2"), R, 2u))
		return 0;
	r_k = &genuine[n_genuine - 1u];
	if (!root_add(G("R adds R2"), R, R2) || !retention(G("R's retention"), R, "keep * age 30d"))
		return 0;
	r_retention = &genuine[n_genuine - 1u];
	if (0
	    || !retention(G("A1's retention"), A1, "prune * age 90d")
	    || !vote(G("R votes against M"), R, M) || !vote(G("A1 votes against M"), A1, M)
	    || !confirm(G("A1 confirms A2"), A1, a2_grant) || !roster(G("R adds C"), R, 1, 1u)
	    || !roster(G("M removes C"), M, 0, 2u) || !succession(G("R succeeds M"), R))
		return 0;
	honest = n_genuine;

	/* A SIGNED BYTE CHANGED after signing, every genuine object. */
	for (i = 0; i < honest; i++) {
		struct object *o = F("a signed byte changed");

		if (!o)
			return 0;
		*o = genuine[i];
		o->what = "a signed byte changed";
		o->bytes[o->len - FZN_SIG_LEN - 1u] ^= 0x01u;
	}
	/* A STRANGER'S, properly signed. */
	if (!quorum(F("X sets k 1"), X, 1u) || !root_add(F("X adds X"), X, X)
	    || !retention(F("X's retention"), X, "prune * age 1d")
	    || !vote(F("X votes against A1"), X, A1) || !confirm(F("X confirms A2"), X, a2_grant)
	    || !roster(F("X adds C"), X, 1, 3u) || !succession(F("X succeeds M"), X))
		return 0;
	/* AND THE SAME, NAMING THE ROOT'S OWN as replaced: what a liar who wants
	 * k or a rule changed signs, rather than a rival nobody resolves to. */
	if (!quorum_after(F("X replaces R's k with 1"), X, 1u, r_k)
	    || !quorum_after(F("M replaces R's k with 1"), M, 1u, r_k)
	    || !retention_after(F("X replaces R's rule"), X, "prune * age 1d", r_retention)
	    || !retention_after(F("X removes R's rule"), X, NULL, r_retention)
	    || !retention_after(F("M removes R's rule"), M, NULL, r_retention))
		return 0;
	/* A MEMBER'S, properly signed, of what only a root or an admin may do. */
	if (!quorum(F("M sets k 1"), M, 1u) || !root_add(F("M adds X"), M, X)
	    || !retention(F("M's retention"), M, "prune * age 1d")
	    || !vote(F("M votes against A1"), M, A1) || !confirm(F("M confirms A2"), M, a2_grant)
	    || !succession(F("M succeeds M"), M))
		return 0;
	/* A STRANGER'S OWN GRANTS, properly signed: X grants itself admin, and
	 * grants Y, a key of its own, the member capability. */
	if (!hop(F("X grants X admin"), X, X, &admin_cap) || !hop(F("X grants 0x9a"), X, 0x9a, &cap))
		return 0;
	/* AND X'S GRANTS OF WHAT THE ESTATE ALREADY GRANTED: X names A1 and M as
	 * its own grantees, of the capabilities R gave them, delegable and not.
	 * A walk up from A1 that took X's grant would never reach a root. */
	if (!hop_as(F("X grants A1 admin, delegable"), X, A1, &admin_cap, 1)
	    || !hop(F("X grants A1 admin"), X, A1, &admin_cap)
	    || !hop_as(F("X grants M, delegable"), X, M, &cap, 1))
		return 0;
	return 1;
}

/* ---- the generator and the lie ------------------------------------------ */

static uint32_t rng;

static uint32_t next(void)
{
	rng ^= rng << 13;
	rng ^= rng >> 17;
	rng ^= rng << 5;
	return rng;
}

static uint32_t below(uint32_t n)
{
	return n ? next() % n : 0u;
}

static size_t bend(uint8_t *buf, size_t len, size_t room)
{
	size_t i, at, n, b;

	switch (below(6u)) {
	case 0:
		for (i = 1u + below(4u); i > 0 && len; i--)
			buf[below((uint32_t)len)] ^= (uint8_t)(1u << below(8u));
		return len;
	case 1:
		return len ? below((uint32_t)len) : 0u;
	case 2:
		n = below(64u);
		for (i = 0; i < n && len < room; i++)
			buf[len++] = (uint8_t)next();
		return len;
	case 3:
		if (len >= 2u) {
			at = below((uint32_t)(len - 1u));
			b = below(2u) ? 0xffu : 0x00u;
			buf[at] = (uint8_t)b;
			buf[at + 1u] = (uint8_t)b;
		}
		return len;
	case 4:
		if (len >= 2u) {
			at = below((uint32_t)len);
			n = 1u + below((uint32_t)(len - at));
			if (len + n <= room) {
				memmove(buf + at + n, buf + at, len - at);
				len += n;
			}
		}
		return len;
	default:
		if (len >= 2u) {
			uint8_t t;

			at = below((uint32_t)len);
			b = below((uint32_t)len);
			t = buf[at];
			buf[at] = buf[b];
			buf[b] = t;
		}
		return len;
	}
}

/* ---- the run ------------------------------------------------------------- */

static node_t reference, n;

struct coverage {
	unsigned long bent, bent_refused, forged_offered, forged_refused;
	unsigned long per_forgery[FORGED_MAX];
};
static struct coverage cov;

/* THE TWO SLOTS THAT KEEP WHAT THEY HAVE NOT JUDGED, passed over. */
static int judged_row(const struct row *r)
{
	return r->used && r->slot != FZN_PERSIST_ROOT_CHANGE && r->slot != FZN_PERSIST_GRANT;
}

/* EVERY JUDGED ROW OF `x` IN `y`, the same bytes, and as many. */
static int same_rows(const struct mem *x, const struct mem *y, const struct row **odd)
{
	size_t i, j, nx = 0, ny = 0;

	for (i = 0; i < ROWS; i++) {
		nx += (size_t)judged_row(&x->rows[i]);
		ny += (size_t)judged_row(&y->rows[i]);
	}
	for (i = 0; i < ROWS; i++) {
		const struct row *r = &x->rows[i];

		if (!judged_row(r))
			continue;
		for (j = 0; j < ROWS; j++) {
			const struct row *s = &y->rows[j];

			if (s->used && s->slot == r->slot && s->len == r->len
			    && memcmp(s->subject, r->subject, FZN_PUBKEY_LEN) == 0
			    && memcmp(s->bytes, r->bytes, r->len) == 0)
				break;
		}
		if (j == ROWS) {
			*odd = r;
			return 0;
		}
	}
	*odd = NULL;
	return nx == ny;
}

/* WHAT A NODE CONCLUDES, every question the estate's acts answer. */
#define VERDICT_KEYS 6
struct verdict {
	uint8_t k;
	size_t n_roots;
	uint8_t roots[8][FZN_PUBKEY_LEN];
	size_t n_rules, unread;
	fzn_retain_rule_t rules[8];
	uint8_t m_revoked[FZN_CHAIN_MAX_HOPS];
	int c_standing;
	int m_succeeded;
	uint8_t m_now[FZN_PUBKEY_LEN];
	int judged[VERDICT_KEYS];
	int rank[VERDICT_KEYS];
};

static int conclude(node_t *x, struct verdict *v)
{
	static const uint8_t asked[VERDICT_KEYS] = { R, M, A1, A2, X, 0x9a };
	uint8_t grantor[1][FZN_PUBKEY_LEN], grantee[1][FZN_PUBKEY_LEN], c[FZN_PUBKEY_LEN];
	size_t i;

	memset(v, 0, sizeof(*v));
	v->k = fzn_node_roots_quorum(&x->roots, 1u);
	v->n_roots = fzn_node_roots_standing(&x->roots, v->roots, 8u);
	if (fzn_node_roots_retention(&x->roots, v->rules, 8u, &v->n_rules, &v->unread)
	    != FZN_NODE_ROOTS_OK)
		return 0;
	key(grantor[0], R);
	key(grantee[0], M);
	fzn_revocation_covers_links(&x->revs, (const uint8_t (*)[FZN_PUBKEY_LEN])grantor,
	                            (const uint8_t (*)[FZN_PUBKEY_LEN])grantee, 1u, &cap,
	                            v->m_revoked);
	v->m_revoked[0] = v->m_revoked[0] != 0u;
	key(c, C);
	v->c_standing = (int)fzn_node_roster_standing(&x->roster, c, &x->revs, v->k);
	v->m_succeeded = fzn_node_successions_resolve(&x->successions, &x->revs, root_key,
	                                              grantee[0], v->m_now);
	for (i = 0; i < VERDICT_KEYS; i++) {
		uint8_t who[FZN_PUBKEY_LEN];
		fzn_setting_rank_t rank = (fzn_setting_rank_t)0;

		key(who, asked[i]);
		v->judged[i] = fzn_node_apply_rank(&x->ap, who, FZN_SCOPE_ESTATE, root_key, &rank);
		v->rank[i] = v->judged[i] == 1 ? (int)rank : -1;
	}
	return 1;
}

static struct verdict expected;

/* WHERE `got` AND THE REFERENCE PART, named, or NULL where they agree. */
static const char *parted(const struct verdict *got)
{
	const struct verdict *e = &expected;
	size_t i;

	if (got->k != e->k)
		return "the estate's k";
	if (got->n_roots != e->n_roots || memcmp(got->roots, e->roots, sizeof(e->roots)) != 0)
		return "the roots that stand";
	if (got->n_rules != e->n_rules || got->unread != e->unread
	    || memcmp(got->rules, e->rules, sizeof(e->rules)) != 0)
		return "the retention rules";
	if (got->m_revoked[0] != e->m_revoked[0])
		return "whether M is revoked";
	if (got->c_standing != e->c_standing)
		return "C's place on the roster";
	if (got->m_succeeded != e->m_succeeded
	    || (e->m_succeeded && memcmp(got->m_now, e->m_now, FZN_PUBKEY_LEN) != 0))
		return "who M is now";
	for (i = 0; i < VERDICT_KEYS; i++)
		if (got->judged[i] != e->judged[i] || got->rank[i] != e->rank[i])
			return "a key's standing";
	return NULL;
}

/* ONE LIE, offered: a bent copy of a genuine object, or a forgery. A forgery
 * taken fails the case at once, naming it. */
static int lie(void)
{
	static uint8_t buf[OBJECT_MAX + 64];
	fzn_node_apply_outcome_t got;
	size_t len, which;

	if (below(2u)) {
		which = below((uint32_t)n_genuine);
		len = genuine[which].len;
		memcpy(buf, genuine[which].bytes, len);
		len = bend(buf, len, sizeof(buf));
		cov.bent++;
		if (give(&n, buf, len) == FZN_NODE_APPLY_REFUSED)
			cov.bent_refused++;
		return 1;
	}
	which = below((uint32_t)n_forged);
	cov.forged_offered++;
	cov.per_forgery[which]++;
	got = give(&n, forged[which].bytes, forged[which].len);
	/* KEPT IS NOT TAKEN where a slot keeps the unjudged: the verdict, at the
	 * end, is what says whether it was taken. */
	if (got != FZN_NODE_APPLY_APPLIED)
		cov.forged_refused++;
	return 1;
}

static int fuzz_one(unsigned long c)
{
	const struct row *odd = NULL;
	size_t i, k;

	rng = (uint32_t)(c * 2654435761u) ^ 0x85ebca6bu;
	if (!rng)
		rng = 1u;
	if (!node_up(&n)) {
		printf("votes_fuzz: case %lu: the node would not come up\n", c);
		return 0;
	}
	for (i = 0; i < n_genuine; i++) {
		if (below(2u))
			for (k = 1u + below(3u); k > 0; k--)
				if (!lie())
					return 0;
		(void)give(&n, genuine[i].bytes, genuine[i].len);
	}
	for (k = below(4u); k > 0; k--)
		if (!lie())
			return 0;
	{
		struct verdict got;
		const char *where;

		if (!conclude(&n, &got)) {
			printf("votes_fuzz: case %lu: the node's conclusions would not read\n", c);
			return 0;
		}
		where = parted(&got);
		if (where) {
			printf("votes_fuzz: case %lu: the node concludes otherwise than the reference "
			       "about %s\n", c, where);
			return 0;
		}
	}
	if (!same_rows(&reference.mem, &n.mem, &odd) || (odd = NULL, !same_rows(&n.mem,
	                                                                         &reference.mem,
	                                                                         &odd))) {
		printf("votes_fuzz: case %lu: the store is not what the genuine objects alone make "
		       "-- a row of slot %d %s\n", c, odd ? (int)odd->slot : -1,
		       odd ? "differs" : "count differs");
		return 0;
	}
	return 1;
}

/* THE TABLES FILLED FIRST, sec 700: a stranger's grants, root-adds and
 * settings of k, more of each than the table that would keep it holds,
 * offered before every genuine act. Kept and judged on read, they took every
 * place, and R's own grant and root-add after them were refused. */
static int filled_first(void)
{
	static struct object o;
	struct verdict got;
	const struct row *odd = NULL;
	const char *where;
	size_t i;

	if (!node_up(&n))
		return 0;
	for (i = 0; i < 300u; i++) {
		uint8_t from[FZN_PUBKEY_LEN], to[FZN_PUBKEY_LEN];

		key(from, X);
		key(to, (uint8_t)i);
		to[1] = (uint8_t)(i >> 8);
		to[2] = 0xee;
		signing_as = X;
		o.len = FZN_HOP_LEN;
		if (fzn_chain_mint(from, to, &cap, 100u, FZN_NO_EXPIRY, 0, &SIGN, o.bytes)
		    != FZN_CHAIN_OK)
			return 0;
		(void)give(&n, o.bytes, o.len);
		if (i >= 100u)
			continue;
		if (!root_add(&o, X, (uint8_t)i))
			return 0;
		(void)give(&n, o.bytes, o.len);
		if (!quorum_after(&o, X, (uint8_t)(1u + i % 9u), NULL))
			return 0;
		(void)give(&n, o.bytes, o.len);
	}
	for (i = 0; i < n_genuine; i++)
		(void)give(&n, genuine[i].bytes, genuine[i].len);
	if (!conclude(&n, &got))
		return 0;
	where = parted(&got);
	if (where || !same_rows(&reference.mem, &n.mem, &odd) || !same_rows(&n.mem, &reference.mem,
	                                                                    &odd)) {
		printf("votes_fuzz: with the tables filled first by a stranger, the node concludes "
		       "otherwise about %s\n", where ? where : "its rows");
		return 0;
	}
	return 1;
}

static unsigned long floor_of(unsigned long cases, unsigned long per)
{
	unsigned long f = cases / per;

	return f ? f : 1u;
}

int main(int argc, char **argv)
{
	unsigned long cases = FUZZ_DEFAULT_CASES, c;
	size_t i;

	memset(cap.b, 0x61, sizeof(cap.b));
	memset(admin_cap.b, 0x62, sizeof(admin_cap.b));
	key(root_key, R);
	if (!the_objects()) {
		printf("votes_fuzz: the objects would not be made\n");
		return 1;
	}
	/* THE REFERENCE, and each genuine object shown to apply in it: a
	 * fixture that refuses its own acts tests nothing. */
	if (!node_up(&reference)) {
		printf("votes_fuzz: the reference would not come up\n");
		return 1;
	}
	for (i = 0; i < n_genuine; i++)
		if (give(&reference, genuine[i].bytes, genuine[i].len) != FZN_NODE_APPLY_APPLIED) {
			printf("votes_fuzz: the genuine object \"%s\" did not apply\n", genuine[i].what);
			return 1;
		}
	/* AND WHAT IT CONCLUDES, each act shown to have counted: a reference in
	 * which nothing took effect would agree with a node that took nothing. */
	{
		uint8_t m_key[FZN_PUBKEY_LEN], d2[FZN_PUBKEY_LEN];

		key(m_key, M);
		key(d2, D2);
		if (!conclude(&reference, &expected) || expected.k != 2u || expected.n_roots != 2u
		    || expected.n_rules != 2u || !expected.m_revoked[0] || !expected.m_succeeded
		    || memcmp(expected.m_now, d2, FZN_PUBKEY_LEN) != 0
		    || expected.rank[2] != (int)FZN_SETTING_RANK_ADMIN
		    || expected.rank[0] != (int)FZN_SETTING_RANK_ROOT || expected.judged[4] == 1) {
			printf("votes_fuzz: the reference does not conclude what its acts say: k %u, "
			       "%zu roots, %zu rules, M revoked %u, M succeeded %d, A1's rank %d, R's "
			       "%d, X judged %d\n", (unsigned)expected.k, expected.n_roots,
			       expected.n_rules, (unsigned)expected.m_revoked[0], expected.m_succeeded,
			       expected.rank[2], expected.rank[0], expected.judged[4]);
			return 1;
		}
		(void)m_key;
	}
	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
	}
	if (cases < FUZZ_MIN_CASES) {
		printf("votes_fuzz: %lu cases is below FUZZ_MIN_CASES (%u), so this run will not "
		       "report success. Re-run with %u or more.\n", cases, (unsigned)FUZZ_MIN_CASES,
		       (unsigned)FUZZ_MIN_CASES);
		return 1;
	}
	for (c = 0; c < cases; c++)
		if (!fuzz_one(c + 1u)) {
			printf("votes_fuzz: FAILED on case %lu\n", c + 1u);
			return 1;
		}
	if (!filled_first()) {
		printf("votes_fuzz: FAILED with the tables filled first\n");
		return 1;
	}
	for (i = 0; i < n_forged; i++)
		if (cov.per_forgery[i] < floor_of(cases, 400u)) {
			printf("votes_fuzz: REACHED TOO LITTLE -- the forgery \"%s\" offered %lu times "
			       "in %lu cases\n", forged[i].what, cov.per_forgery[i], cases);
			return 1;
		}
	if (cov.bent_refused < floor_of(cases, 4u)) {
		printf("votes_fuzz: REACHED TOO LITTLE -- %lu of %lu bent copies refused in %lu "
		       "cases\n", cov.bent_refused, cov.bent, cases);
		return 1;
	}
	printf("votes_fuzz: %lu cases, %zu genuine objects, %lu bent copies (%lu refused), %lu "
	       "forgeries of %zu kinds offered and none taken; every store came to the "
	       "reference\n", cases, n_genuine, cov.bent, cov.bent_refused, cov.forged_offered,
	       n_forged);
	return 0;
}
