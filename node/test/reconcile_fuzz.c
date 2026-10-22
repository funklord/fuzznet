/*
 * A fuzz harness for reconciliation, `node/reconcile.h`: sec 689's estate
 * journey. Every round a node brings what it holds of the estate's signed
 * objects -- grants, settings, votes, roots -- up to what a peer holds.
 *
 * WHY THIS ONE. A round reads the peer's digests, id pages, objects and a
 * stream's base, every byte the peer's, and applies what it fetched. The
 * claim, `node/reconcile.h`'s own: reconciliation is a union of signed
 * objects, judged as a journal record is judged, so a peer can hold this
 * node back but never put into it anything it did not sign properly.
 *
 * THE PEER LIES BY MUTATION. A, the root's node, is honest and holds two
 * grants and a few settings; each answer it gives B is bent with even odds,
 * as exchange_fuzz bends them.
 *
 * THE PROPERTY, stated so that nothing can pass it by accident: after a bent
 * round, ONE HONEST ROUND BRINGS B TO EXACTLY A. Reconciliation never takes
 * anything away, so an object B took that A does not hold would leave B
 * different from A for good; and a bent round that left B unable to take
 * the honest one would show the same way. And the server's answer to a bent
 * request is bounded by its cap and the same twice.
 *
 * FLOORS: a run that never applied through a bent answer, never refused,
 * or never answered a bent request has not tested what it claims.
 *
 * The fixtures are reconcile_test's, copied: the keyed mixing signer, the
 * in-memory store and the node set up as an apply context.
 */

#include "../reconcile.h"
#include "../settings.h"

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

#define ROWS 64

struct row {
	int used;
	fzn_persist_slot_t slot;
	uint8_t subject[FZN_PUBKEY_LEN];
	uint8_t bytes[2048];
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
static uint8_t root_key[FZN_PUBKEY_LEN], estate[FZN_SUBJECT_LEN];

typedef struct node {
	struct mem mem;
	fzn_persist_ops_t store;
	fzn_node_apply_t ap;
	fzn_node_settings_t ns;
	fzn_revocation_store_t revs;
	fzn_revocation_t rev_entries[8];
	fzn_revocation_admin_t admins[4];
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
	if (fzn_revocation_store_init(&n->revs, n->rev_entries, 8) != FZN_CHAIN_OK
	    || fzn_revocation_store_set_quorum(&n->revs, 1u, &admin_cap, n->admins, 4u)
	               != FZN_CHAIN_OK)
		return 0;
	n->ap.revocations = &n->revs;
	n->ap.store = &n->store;
	n->ap.root = root_key;
	n->ap.capability = &cap;
	n->ap.admin_capability = &admin_cap;
	n->ap.sign = &SIGN;
	n->ap.hash = &HASH;
	n->ap.settings = &n->ns;
	n->ap.now = clock_now;
	n->ns.store = &n->store;
	n->ns.hash = &HASH;
	n->ns.verify = &SIGN;
	n->ns.apply = &n->ap;
	n->ns.estate = estate;
	return 1;
}

/* Apply one object `signer` signs to `n`, as if it had come any way at all. */
static int give(node_t *n, const uint8_t *object, size_t len)
{
	fzn_node_apply_tally_t t;

	memset(&t, 0, sizeof(t));
	return fzn_node_apply_object(&n->ap, object, len, &t) == FZN_NODE_APPLY_APPLIED;
}

static int grant(node_t *n, uint8_t grantor, uint8_t grantee, const fzn_cap_id_t *c)
{
	uint8_t from[FZN_PUBKEY_LEN], to[FZN_PUBKEY_LEN], hop[FZN_HOP_LEN];

	key(from, grantor);
	key(to, grantee);
	signing_as = grantor;
	return fzn_chain_mint(from, to, c, 100u, FZN_NO_EXPIRY, 0, &SIGN, hop) == FZN_CHAIN_OK
	       && give(n, hop, sizeof(hop));
}

static int setting(node_t *n, uint8_t setter, fzn_scope_t scope, uint8_t about, const char *k,
                   const char *value)
{
	uint8_t who[FZN_PUBKEY_LEN], subject[FZN_SUBJECT_LEN], obj[FZN_SETTING_MAX];
	size_t len = 0;

	key(who, setter);
	key(subject, about);
	signing_as = setter;
	return fzn_setting_issue(who, &SIGN, scope, subject, 1u, (const uint8_t *)k, strlen(k), 1,
	                         (const uint8_t *)value, strlen(value), obj, &len)
	               == FZN_SETTING_OK
	       && give(n, obj, len);
}

/* ---- the peer, honest and otherwise -------------------------------------- */

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

/* ---- the peer ------------------------------------------------------------- */

static node_t a, b;
static int bending, bent_this, forging;

/* THE COHERENT LIAR, which mutation alone never is: it lists the id of an
 * object of its own making on an id page, and serves that object when it is
 * asked for. Only the signature and the signer's standing stand in its way,
 * since the id check -- an object applied only under an id asked for -- is
 * what it satisfies on purpose. Two forgeries: a setting whose bytes were
 * changed after the root signed it, and one properly signed by a key the
 * estate never granted. */
#define FORGERIES 2
static uint8_t forged[FORGERIES][FZN_SETTING_MAX];
static size_t forged_len[FORGERIES];
static uint8_t forged_id[FORGERIES][FZN_HOLDINGS_ID_LEN];
static size_t forging_which;
static size_t answer_cap;

struct coverage {
	unsigned long bent, applied_bent, refused, answered_bent, forged_listed, forged_served;
};
static struct coverage cov;

/* REAL REQUESTS, kept from the honest rounds, for the bent ones to start
 * from: random bytes after a version and a type parse as nothing. */
#define POOL 64
static uint8_t pool[POOL][512];
static size_t pool_len[POOL], pooled;

static int ask(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
               size_t reply_cap, size_t *reply_len)
{
	size_t room = reply_cap < answer_cap ? reply_cap : answer_cap;

	(void)ctx;
	if (!bending && pooled < POOL && request_len <= sizeof(pool[0])) {
		memcpy(pool[pooled], request, request_len);
		pool_len[pooled++] = request_len;
	}
	*reply_len = fzn_reconcile_answer(&a.store, &HASH, a.ap.journal, request, request_len, reply,
	                                  room);
	if (*reply_len && forging) {
		const uint8_t *fid = forged_id[forging_which];

		if (reply[1] == FZN_RECONCILE_IDS && reply[2] == FZN_HOLDINGS_SETTINGS
		    && *reply_len + FZN_HOLDINGS_ID_LEN <= reply_cap) {
			/* THE FORGED ID, in its ascending place, the counts made to
			 * agree. */
			uint16_t count = fzn_get_be16(reply + 11);
			size_t at = FZN_RECONCILE_IDS_HEAD_LEN, i;

			for (i = 0; i < count; i++, at += FZN_HOLDINGS_ID_LEN)
				if (memcmp(reply + at, fid, FZN_HOLDINGS_ID_LEN) > 0)
					break;
			memmove(reply + at + FZN_HOLDINGS_ID_LEN, reply + at, *reply_len - at);
			memcpy(reply + at, fid, FZN_HOLDINGS_ID_LEN);
			fzn_put_be16(reply + 11, (uint16_t)(count + 1u));
			fzn_put_be32(reply + 3, fzn_get_be32(reply + 3) + 1u);
			*reply_len += FZN_HOLDINGS_ID_LEN;
			cov.forged_listed++;
		} else if (reply[1] == FZN_RECONCILE_OBJECTS && request_len >= 4u
		           && *reply_len + 2u + forged_len[forging_which] <= reply_cap) {
			size_t i, n = request[3];

			for (i = 0; i < n && 4u + (i + 1u) * FZN_HOLDINGS_ID_LEN <= request_len; i++)
				if (memcmp(request + 4u + i * FZN_HOLDINGS_ID_LEN, fid,
				           FZN_HOLDINGS_ID_LEN) == 0) {
					/* ASKED FOR, SO SERVED. */
					fzn_put_be16(reply + *reply_len, (uint16_t)forged_len[forging_which]);
					memcpy(reply + *reply_len + 2u, forged[forging_which],
					       forged_len[forging_which]);
					*reply_len += 2u + forged_len[forging_which];
					fzn_put_be16(reply + 3, (uint16_t)(fzn_get_be16(reply + 3) + 1u));
					cov.forged_served++;
					break;
				}
		}
		return 1;
	}
	if (*reply_len && bending && below(2u)) {
		*reply_len = bend(reply, *reply_len, reply_cap);
		cov.bent++;
		bent_this = 1;
	}
	return *reply_len != 0u;
}

static int same(node_t *x, node_t *y)
{
	size_t c, nx = 0, ny = 0;
	uint8_t dx[FZN_HOLDINGS_ID_LEN], dy[FZN_HOLDINGS_ID_LEN];

	for (c = 0; c < FZN_HOLDINGS_CLASSES; c++)
		if (fzn_holdings_digest(&x->store, &HASH, (fzn_holdings_class_t)c, dx, &nx)
		            != FZN_HOLDINGS_OK
		    || fzn_holdings_digest(&y->store, &HASH, (fzn_holdings_class_t)c, dy, &ny)
		               != FZN_HOLDINGS_OK
		    || nx != ny || memcmp(dx, dy, sizeof(dx)) != 0)
			return 0;
	return 1;
}

static uint8_t reply[1u << 16];

static int the_estate(void)
{
	char k[8];
	size_t i;

	if (!node_up(&a) || !node_up(&b) || !grant(&a, 0x91, 0x92, &cap)
	    || !grant(&a, 0x91, 0x93, &admin_cap))
		return 0;
	for (i = 0; i < 1u + below(6u); i++) {
		(void)snprintf(k, sizeof(k), "k%zu", i);
		if (!setting(&a, 0x91, FZN_SCOPE_ESTATE, 0x91, k, "v"))
			return 0;
	}
	return 1;
}

static int fuzz_one(unsigned long c)
{
	fzn_reconcile_tally_t t;

	rng = (uint32_t)(c * 2654435761u) ^ 0x85ebca6bu;
	if (!rng)
		rng = 1u;
	bent_this = 0;
	if (!the_estate()) {
		printf("reconcile_fuzz: case %lu: the estate would not set up\n", c);
		return 0;
	}
	if (pooled && below(3u) == 0u) {
		/* A BENT REQUEST at a random cap: bounded, the same twice. */
		static uint8_t first[1u << 16], second[1u << 16];
		uint8_t req[512 + 64];
		size_t len, cap_at, l1, l2, at = below((uint32_t)pooled);

		len = pool_len[at];
		memcpy(req, pool[at], len);
		len = bend(req, len, sizeof(req));
		cap_at = 1u + below(sizeof(first) - 1u);
		l1 = fzn_reconcile_answer(&a.store, &HASH, a.ap.journal, req, len, first, cap_at);
		l2 = fzn_reconcile_answer(&a.store, &HASH, a.ap.journal, req, len, second, cap_at);
		if (l1 > cap_at || l1 != l2 || memcmp(first, second, l1) != 0) {
			printf("reconcile_fuzz: case %lu: an answer of %zu at a cap of %zu, or not the "
			       "same twice (%zu)\n", c, l1, cap_at, l2);
			return 0;
		}
		if (l1)
			cov.answered_bent++;
		return 1;
	}
	answer_cap = below(2u) ? sizeof(reply) : FZN_RECONCILE_REPLY_MIN + below(4096u);
	forging = below(3u) == 0u;
	forging_which = below(FORGERIES);
	bending = !forging;
	memset(&t, 0, sizeof(t));
	(void)fzn_reconcile_round(&b.ap, NULL, ask, NULL, reply, sizeof(reply), &t);
	if (bent_this && t.applied)
		cov.applied_bent++;
	if (t.refused)
		cov.refused++;
	/* THE HONEST ROUND: B comes to exactly A. */
	bending = 0;
	forging = 0;
	answer_cap = sizeof(reply);
	memset(&t, 0, sizeof(t));
	if (fzn_reconcile_round(&b.ap, NULL, ask, NULL, reply, sizeof(reply), &t) != FZN_RECONCILE_OK
	    || !same(&a, &b)) {
		printf("reconcile_fuzz: case %lu: after a bent round and an honest one, B is not A "
		       "(%zu applied, %zu refused, %zu lacked)\n", c, t.applied, t.refused, t.lacked);
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

	memset(cap.b, 0x61, sizeof(cap.b));
	memset(admin_cap.b, 0x62, sizeof(admin_cap.b));
	key(root_key, 0x91);
	memcpy(estate, root_key, sizeof(estate));
	{
		uint8_t who[FZN_PUBKEY_LEN], subject[FZN_SUBJECT_LEN];

		/* THE TWO FORGERIES: the root's setting with a signed byte changed,
		 * and one signed by 0x99, whom nobody granted anything. */
		key(subject, 0x91);
		key(who, 0x91);
		signing_as = 0x91;
		if (fzn_setting_issue(who, &SIGN, FZN_SCOPE_ESTATE, subject, 7u, (const uint8_t *)"kf",
		                      2u, 1, (const uint8_t *)"forged", 6u, forged[0], &forged_len[0])
		            != FZN_SETTING_OK)
			return 1;
		forged[0][forged_len[0] - FZN_SIG_LEN - 1u] ^= 0x01u;
		key(who, 0x99);
		signing_as = 0x99;
		if (fzn_setting_issue(who, &SIGN, FZN_SCOPE_ESTATE, subject, 7u, (const uint8_t *)"kf",
		                      2u, 1, (const uint8_t *)"forged", 6u, forged[1], &forged_len[1])
		            != FZN_SETTING_OK)
			return 1;
		if (!mix_hash(NULL, forged_id[0], FZN_HOLDINGS_ID_LEN, forged[0], forged_len[0])
		    || !mix_hash(NULL, forged_id[1], FZN_HOLDINGS_ID_LEN, forged[1], forged_len[1]))
			return 1;
	}
	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
	}
	if (cases < FUZZ_MIN_CASES) {
		printf("reconcile_fuzz: %lu cases is below FUZZ_MIN_CASES (%u), so this run will "
		       "not report success. Re-run with %u or more.\n", cases,
		       (unsigned)FUZZ_MIN_CASES, (unsigned)FUZZ_MIN_CASES);
		return 1;
	}
	for (c = 0; c < cases; c++)
		if (!fuzz_one(c + 1u)) {
			printf("reconcile_fuzz: FAILED on case %lu\n", c + 1u);
			return 1;
		}
	if (cov.applied_bent < floor_of(cases, 40u) || cov.refused < floor_of(cases, 40u)
	    || cov.answered_bent < floor_of(cases, 40u) || cov.forged_served < floor_of(cases, 40u)) {
		printf("reconcile_fuzz: REACHED TOO LITTLE -- %lu bent, %lu applied through a bent "
		       "answer, %lu refused, %lu bent requests answered, %lu forgeries listed and %lu "
		       "served, in %lu cases\n", cov.bent, cov.applied_bent, cov.refused,
		       cov.answered_bent, cov.forged_listed, cov.forged_served, cases);
		return 1;
	}
	printf("reconcile_fuzz: %lu cases, %lu bent answers, %lu applied through one, %lu "
	       "refused, %lu bent requests answered, %lu forgeries served; every honest round "
	       "after came to A\n", cases, cov.bent, cov.applied_bent, cov.refused,
	       cov.answered_bent, cov.forged_served);
	return 0;
}
