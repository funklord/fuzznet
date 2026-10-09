/* Tests for node/reconcile.c: one node's estate state brought up to a
 * peer's. sec 551.
 *
 * TWO NODES IN ONE PROCESS, each its own in-memory store and apply context.
 * A asks B by calling B's answer directly. The signer is a keyed mixing
 * function keyed by the first byte of the public key, as apply_test's is: an
 * object verifies under the key it was signed as and no other.
 */

#include "../reconcile.h"
#include "../settings.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL reconcile_test.c:%d: %s\n", __LINE__, what);    \
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

struct peer {
	node_t *node;
	size_t cap;     /* the answering side's reply buffer, at most */
	int lie;        /* 1: a byte of every object sent changed; 2: an id left out */
	size_t asked;
};

static int ask(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
               size_t reply_cap, size_t *reply_len)
{
	struct peer *p = (struct peer *)ctx;
	size_t room = reply_cap < p->cap ? reply_cap : p->cap;

	p->asked++;
	*reply_len = fzn_reconcile_answer(&p->node->store, &HASH, p->node->ap.journal, request,
	                                  request_len, reply, room);
	if (!*reply_len)
		return 0;
	if (p->lie == 1 && reply[1] == FZN_RECONCILE_OBJECTS) {
		/* A BYTE OF EVERY OBJECT changed, inside its signed range. */
		size_t at = FZN_RECONCILE_OBJECTS_HEAD_LEN, i;

		for (i = 0; i < fzn_get_be16(reply + 3); i++) {
			reply[at + 2u + 10u] ^= 1u;
			at += 2u + fzn_get_be16(reply + at);
		}
	}
	if (p->lie == 2 && reply[1] == FZN_RECONCILE_IDS && fzn_get_be16(reply + 11) > 0u) {
		/* THE LAST ID LEFT OUT of every page, and the total said so. */
		uint16_t count = fzn_get_be16(reply + 11);

		fzn_put_be16(reply + 11, (uint16_t)(count - 1u));
		*reply_len -= FZN_HOLDINGS_ID_LEN;
	}
	return 1;
}

static int same(node_t *a, node_t *b)
{
	size_t c, na = 0, nb = 0;
	uint8_t da[FZN_HOLDINGS_ID_LEN], db[FZN_HOLDINGS_ID_LEN];

	for (c = 0; c < FZN_HOLDINGS_CLASSES; c++)
		if (fzn_holdings_digest(&a->store, &HASH, (fzn_holdings_class_t)c, da, &na)
		            != FZN_HOLDINGS_OK
		    || fzn_holdings_digest(&b->store, &HASH, (fzn_holdings_class_t)c, db, &nb)
		               != FZN_HOLDINGS_OK
		    || na != nb || memcmp(da, db, sizeof(da)) != 0)
			return 0;
	return 1;
}

static size_t held(node_t *n, fzn_holdings_class_t c)
{
	uint8_t d[FZN_HOLDINGS_ID_LEN];
	size_t count = 0;

	return fzn_holdings_digest(&n->store, &HASH, c, d, &count) == FZN_HOLDINGS_OK ? count : 0u;
}

static uint8_t reply[1u << 16];

/* A, the root's node, holds two grants and twenty settings: the root's and
 * the admin's of the estate, the member's of its own host, and seventeen more
 * of the root's. B holds nothing, reconciles from A, and comes to every
 * digest of A's; a second round asks one message and fetches nothing. C does
 * the same over the smallest reply buffer either side may use, which holds
 * fewer settings than were asked for, so the rest are asked again. */
static void test_a_node_comes_to_its_peer(void)
{
	static node_t a, b, c;
	struct peer pa = { &a, sizeof(reply), 0, 0 };
	fzn_reconcile_tally_t t;
	char k[16];
	int i, ok;

	ok = node_up(&a) && node_up(&b) && node_up(&c) && grant(&a, 0x91, 0x92, &cap)
	     && grant(&a, 0x91, 0x93, &admin_cap)
	     && setting(&a, 0x91, FZN_SCOPE_ESTATE, 0x91, "root/a", "1")
	     && setting(&a, 0x93, FZN_SCOPE_ESTATE, 0x91, "admin/b", "2")
	     && setting(&a, 0x92, FZN_SCOPE_HOST, 0x92, "own/c", "3");
	for (i = 0; ok && i < 17; i++) {
		(void)snprintf(k, sizeof(k), "more/%d", i);
		ok = setting(&a, 0x91, FZN_SCOPE_ESTATE, 0x91, k, "x");
	}
	CHECK(ok && held(&a, FZN_HOLDINGS_GRANTS) == 2u && held(&a, FZN_HOLDINGS_SETTINGS) == 20u,
	      "fixture: A holds two grants and twenty settings");
	CHECK(fzn_reconcile_round(&b.ap, NULL, ask, &pa, reply, sizeof(reply), &t) == FZN_RECONCILE_OK
	              && t.classes == 2u && t.lacked == 22u && t.applied == 22u && t.waiting == 0u
	              && t.refused == 0u && same(&a, &b),
	      "a node holding nothing did not come to its peer's digests in one round");
	pa.asked = 0;
	CHECK(fzn_reconcile_round(&b.ap, NULL, ask, &pa, reply, sizeof(reply), &t) == FZN_RECONCILE_OK
	              && t.classes == 0u && t.lacked == 0u && pa.asked == 1u,
	      "a round with nothing to do asked more than the digest, or fetched");
	pa.cap = FZN_RECONCILE_REPLY_MIN;
	pa.asked = 0;
	CHECK(fzn_reconcile_round(&c.ap, NULL, ask, &pa, reply, sizeof(reply), &t) == FZN_RECONCILE_OK
	              && t.applied == 22u && same(&a, &c) && pa.asked > 5u,
	      "over the smallest reply buffer the round did not page, re-ask and arrive");
}

/* A PEER THAT CHANGES WHAT IT SENDS has every object refused and nothing
 * kept; one that LEAVES AN OBJECT OUT leaves a gap the next peer fills --
 * omission repaired by reconciliation, the holder's point in sec 550. A
 * reply buffer under the floor is refused. */
static void test_a_dishonest_peer(void)
{
	static node_t a, b;
	struct peer liar = { &a, sizeof(reply), 1, 0 };
	struct peer omitter = { &a, sizeof(reply), 2, 0 };
	struct peer honest = { &a, sizeof(reply), 0, 0 };
	fzn_reconcile_tally_t t;

	CHECK(node_up(&a) && node_up(&b) && grant(&a, 0x91, 0x92, &cap)
	              && grant(&a, 0x91, 0x93, &admin_cap)
	              && setting(&a, 0x91, FZN_SCOPE_ESTATE, 0x91, "k", "v"),
	      "fixture: A holds two grants and a setting");
	CHECK(fzn_reconcile_round(&b.ap, NULL, ask, &liar, reply, sizeof(reply), &t) == FZN_RECONCILE_OK
	              && t.applied == 0u && t.refused == 3u && held(&b, FZN_HOLDINGS_GRANTS) == 0u
	              && held(&b, FZN_HOLDINGS_SETTINGS) == 0u,
	      "an object changed on the way was taken");
	CHECK(fzn_reconcile_round(&b.ap, NULL, ask, &omitter, reply, sizeof(reply), &t)
	                      == FZN_RECONCILE_OK
	              && held(&b, FZN_HOLDINGS_GRANTS) == 1u && held(&b, FZN_HOLDINGS_SETTINGS) == 0u
	              && !same(&a, &b),
	      "fixture: a peer leaving the last id of each page out leaves a grant and the setting");
	CHECK(fzn_reconcile_round(&b.ap, NULL, ask, &honest, reply, sizeof(reply), &t) == FZN_RECONCILE_OK
	              && t.lacked == 2u && same(&a, &b),
	      "the next peer did not fill the gap the first left");
	CHECK(fzn_reconcile_round(&b.ap, NULL, ask, &honest, reply, FZN_RECONCILE_REPLY_MIN - 1u, &t)
	              == FZN_RECONCILE_ERR_MALFORMED,
	      "a reply buffer under the floor was accepted");
}

/* ---- a record store per journal --------------------------------------------- */

#define RECORDS 80

struct recs {
	struct {
		int used;
		uint8_t issuer[FZN_PUBKEY_LEN];
		uint32_t stream;
		uint64_t seq;
		uint8_t bytes[FZN_RECORD_MAX_LEN];
		size_t len;
	} r[RECORDS];
};

static int rec_put(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream, uint64_t seq,
                   const uint8_t *bytes, size_t len)
{
	struct recs *s = (struct recs *)ctx;
	size_t i;

	for (i = 0; i < RECORDS && s->r[i].used; i++)
		;
	if (i == RECORDS || len > FZN_RECORD_MAX_LEN)
		return 0;
	s->r[i].used = 1;
	memcpy(s->r[i].issuer, issuer, FZN_PUBKEY_LEN);
	s->r[i].stream = stream;
	s->r[i].seq = seq;
	memcpy(s->r[i].bytes, bytes, len);
	s->r[i].len = len;
	return 1;
}

static int rec_get(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream, uint64_t seq,
                   uint8_t *out, size_t out_cap, size_t *len_out, int *found_out)
{
	struct recs *s = (struct recs *)ctx;
	size_t i;

	*found_out = 0;
	for (i = 0; i < RECORDS; i++)
		if (s->r[i].used && s->r[i].stream == stream && s->r[i].seq == seq
		    && memcmp(s->r[i].issuer, issuer, FZN_PUBKEY_LEN) == 0) {
			*found_out = 1;
			if (s->r[i].len > out_cap)
				return 0;
			memcpy(out, s->r[i].bytes, s->r[i].len);
			*len_out = s->r[i].len;
			return 1;
		}
	return 0;
}

static int rec_cut(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream, uint64_t from,
                   uint64_t below)
{
	struct recs *s = (struct recs *)ctx;
	size_t i;

	for (i = 0; i < RECORDS; i++)
		if (s->r[i].used && s->r[i].stream == stream && s->r[i].seq >= from
		    && s->r[i].seq < below && memcmp(s->r[i].issuer, issuer, FZN_PUBKEY_LEN) == 0)
			s->r[i].used = 0;
	return 1;
}

static int journal_ask(void *ctx, const uint8_t *request, size_t request_len, uint8_t *out,
                       size_t out_cap, size_t *out_len)
{
	*out_len = fzn_node_journal_answer((fzn_node_journal_t *)ctx, request, request_len, out,
	                                   out_cap);
	return *out_len != 0u;
}

static int append_n(fzn_node_journal_t *nj, uint8_t writer, uint32_t stream, size_t n)
{
	uint8_t issuer[FZN_PUBKEY_LEN], subject[FZN_SUBJECT_LEN], body = 1u;
	size_t i;

	key(issuer, writer);
	signing_as = writer;
	for (i = 0; i < n; i++) {
		memset(subject, (int)(0x30u + i), sizeof(subject));
		if (fzn_node_journal_append_on(nj, issuer, stream, &SIGN, (uint32_t)FZN_OBJECT_HOP,
		                               subject, &body, 1u, 1000u, NULL)
		    != FZN_NODE_JOURNAL_OK)
			return 0;
	}
	return 1;
}

/* A STREAM BEHIND A PEER'S BASE, over the exchange, sec 552. A's journal
 * holds writer V's thirty acts and B pulls the first two; A cuts below the
 * twenty-eighth. B's pull finds V's stream missing and names it; B asks A
 * where it starts, pages a bridge of twenty-five spine entries over the
 * smallest reply buffer, and moves up to A's base, pulling on from there.
 * A notes stream, which keeps no spine, takes a base with no bridge. */
static void test_a_stream_behind_a_peers_base(void)
{
	static node_t a, b;
	static struct recs ra, rb;
	static fzn_node_journal_t ja, jb;
	static const fzn_record_store_ops_t OPS_A = { rec_put, rec_get, &ra, rec_cut };
	static const fzn_record_store_ops_t OPS_B = { rec_put, rec_get, &rb, rec_cut };
	struct peer pa = { &a, FZN_RECONCILE_REPLY_MIN, 0, 0 };
	uint8_t v[FZN_PUBKEY_LEN];
	fzn_exchange_tally_t t;
	uint64_t base = 0;
	size_t n = 0;

	key(v, 0x5c);
	CHECK(node_up(&a) && node_up(&b)
	              && fzn_node_journal_init_store(&ja, &OPS_A, &SIGN, &HASH) == FZN_NODE_JOURNAL_OK
	              && fzn_node_journal_init_store(&jb, &OPS_B, &SIGN, &HASH) == FZN_NODE_JOURNAL_OK,
	      "fixture: two nodes with journals");
	ja.keep = &a.store;
	jb.keep = &b.store;
	a.ap.journal = &ja;
	b.ap.journal = &jb;
	CHECK(append_n(&ja, 0x5c, FZN_NODE_JOURNAL_STREAM, 2u)
	              && fzn_node_journal_follow(&jb, v, NULL) == FZN_NODE_JOURNAL_OK
	              && fzn_node_journal_pull(&jb, journal_ask, &ja, reply, sizeof(reply), &t)
	                         == FZN_EXCHANGE_OK
	              && t.learned == 2u,
	      "fixture: B pulls V's first two from A");
	CHECK(append_n(&ja, 0x5c, FZN_NODE_JOURNAL_STREAM, 28u)
	              && fzn_node_journal_cut(&ja, v, FZN_NODE_JOURNAL_STREAM, 28u, &n)
	                         == FZN_NODE_JOURNAL_OK
	              && n == 27u
	              && fzn_node_journal_pull(&jb, journal_ask, &ja, reply, sizeof(reply), &t)
	                         == FZN_EXCHANGE_OK
	              && t.missing == 1u && memcmp(t.missed[0].issuer, v, FZN_PUBKEY_LEN) == 0
	              && t.missed[0].stream == FZN_NODE_JOURNAL_STREAM,
	      "B's pull past A's cut did not name V's stream missing");
	CHECK(fzn_reconcile_rebase(&jb, ask, &pa, NULL, 0u, v, FZN_NODE_JOURNAL_STREAM, reply, sizeof(reply),
	                           &base, NULL) == FZN_RECONCILE_OK
	              && base == 28u && pa.asked == 2u
	              && fzn_node_journal_received(&jb, v, FZN_NODE_JOURNAL_STREAM) == 27u,
	      "B did not page A's bridge and move up to its base");
	CHECK(fzn_node_journal_pull(&jb, journal_ask, &ja, reply, sizeof(reply), &t)
	                      == FZN_EXCHANGE_OK
	              && t.learned == 3u && t.missing == 0u,
	      "B did not pull on from A's base");
	pa.asked = 0;
	CHECK(fzn_reconcile_rebase(&jb, ask, &pa, NULL, 0u, v, FZN_NODE_JOURNAL_STREAM, reply, sizeof(reply),
	                           &base, NULL) == FZN_RECONCILE_OK
	              && base == 0u && pa.asked == 1u,
	      "a stream not behind the peer's base moved, or asked more than once");
	/* A NOTES STREAM: a base, no bridge. */
	CHECK(append_n(&ja, 0x5c, 0u, 1u)
	              && fzn_node_journal_follow_stream(&jb, v, 0u, NULL) == FZN_NODE_JOURNAL_OK
	              && fzn_node_journal_pull(&jb, journal_ask, &ja, reply, sizeof(reply), &t)
	                         == FZN_EXCHANGE_OK
	              && append_n(&ja, 0x5c, 0u, 3u)
	              && fzn_node_journal_cut(&ja, v, 0u, 4u, &n) == FZN_NODE_JOURNAL_OK
	              && fzn_reconcile_rebase(&jb, ask, &pa, NULL, 0u, v, 0u, reply, sizeof(reply), &base, NULL)
	                         == FZN_RECONCILE_OK
	              && base == 4u && fzn_node_journal_received(&jb, v, 0u) == 3u,
	      "a notes stream behind A's base did not move up with no bridge");
}

/* A STAND-IN FOR THE NOTES STORE: a claim is kept as its own row unless its
 * fourth byte is 0x99, the mark of a writer not admitted, which waits. */
static fzn_node_apply_outcome_t stub_file(void *ctx, const uint8_t *record, size_t len)
{
	node_t *n = (node_t *)ctx;
	uint8_t row[FZN_PERSIST_HEAD_LEN + 64u];

	if (len > 64u)
		return FZN_NODE_APPLY_REFUSED;
	if (record[3] == 0x99u)
		return FZN_NODE_APPLY_WAITING;
	row[0] = 1u;
	row[1] = 1u;
	memcpy(row + FZN_PERSIST_HEAD_LEN, record, len);
	return mem_save(&n->mem, FZN_PERSIST_NOTE, record + 2, row, FZN_PERSIST_HEAD_LEN + len)
	               ? FZN_NODE_APPLY_APPLIED
	               : FZN_NODE_APPLY_NOT_SAVED;
}

/* A note-claim-shaped row of `n`'s: a record's version and tag, `fill`. */
static void claim(node_t *n, uint8_t fill)
{
	uint8_t row[FZN_PERSIST_HEAD_LEN + 48u];

	memset(row, fill, sizeof(row));
	row[0] = 1u;
	row[1] = 1u;
	row[FZN_PERSIST_HEAD_LEN] = FZN_SIGNED_VERSION;
	row[FZN_PERSIST_HEAD_LEN + 1u] = FZN_OBJECT_RECORD;
	(void)mem_save(&n->mem, FZN_PERSIST_NOTE, row + FZN_PERSIST_HEAD_LEN + 2u, row, sizeof(row));
}

/* NOTE CLAIMS, sec 555: the last class, filed by the notes store's own path.
 * With no notes store the class is passed over and nothing is lacked; with
 * one, A's three claims are fetched, two filed and the third -- a writer
 * not admitted -- waiting, and asked for again the next round. */
static void test_note_claims(void)
{
	static node_t a, b;
	struct peer pa = { &a, sizeof(reply), 0, 0 };
	fzn_reconcile_notes_t notes = { stub_file, &b };
	fzn_reconcile_tally_t t;

	CHECK(node_up(&a) && node_up(&b), "fixture: two nodes");
	claim(&a, 0x11);
	claim(&a, 0x22);
	claim(&a, 0x99);
	CHECK(held(&a, FZN_HOLDINGS_NOTES) == 3u, "fixture: A holds three note claims");
	CHECK(fzn_reconcile_round(&b.ap, NULL, ask, &pa, reply, sizeof(reply), &t) == FZN_RECONCILE_OK
	              && t.classes == 0u && t.lacked == 0u && held(&b, FZN_HOLDINGS_NOTES) == 0u,
	      "with no notes store the claims were fetched");
	CHECK(fzn_reconcile_round(&b.ap, &notes, ask, &pa, reply, sizeof(reply), &t)
	                      == FZN_RECONCILE_OK
	              && t.lacked == 3u && t.applied == 2u && t.waiting == 1u
	              && held(&b, FZN_HOLDINGS_NOTES) == 2u,
	      "the claims were not filed by the notes path, the stranger's waiting");
	CHECK(fzn_reconcile_round(&b.ap, &notes, ask, &pa, reply, sizeof(reply), &t)
	                      == FZN_RECONCILE_OK
	              && t.lacked == 1u && t.waiting == 1u,
	      "the waiting claim was not asked for again");
}

/* A peer that answers like `struct peer`'s but changes one subject of every
 * BASE reply's fourth entry. */
static int lying_base_ask(void *ctx, const uint8_t *request, size_t request_len, uint8_t *out,
                          size_t out_cap, size_t *out_len)
{
	if (!ask(ctx, request, request_len, out, out_cap, out_len))
		return 0;
	if (out[1] == FZN_RECONCILE_BASE && fzn_get_be16(out + 50) > 3u)
		out[FZN_RECONCILE_BASE_HEAD_LEN + (3u * FZN_NODE_JOURNAL_SPINE_ENTRY) + 64u] ^= 1u;
	return 1;
}

static int silent_ask(void *ctx, const uint8_t *request, size_t request_len, uint8_t *out,
                      size_t out_cap, size_t *out_len)
{
	(void)ctx;
	(void)request;
	(void)request_len;
	(void)out;
	(void)out_cap;
	*out_len = 0;
	return 0;
}

/* A BRIDGE WITNESSED, sec 557. A holds writer V's thirty and cuts below the
 * twenty-eighth; W pulled all thirty first and keeps them. B1, at two,
 * moves up to A's base with W confirming every entry from its records. A
 * peer serving A's bridge with one subject changed meets W's disagreement:
 * CONFLICT, and B2 does not move -- though without W the same bridge moves
 * it, unconfirmed, which is what the witness is for. A witness that does
 * not answer confirms nothing. */
static void test_a_bridge_witnessed(void)
{
	static node_t a, w, b1, b2;
	static struct recs ra, rw, rb1, rb2;
	static fzn_node_journal_t ja, jw, jb1, jb2;
	static const fzn_record_store_ops_t OPS_A = { rec_put, rec_get, &ra, rec_cut };
	static const fzn_record_store_ops_t OPS_W = { rec_put, rec_get, &rw, rec_cut };
	static const fzn_record_store_ops_t OPS_B1 = { rec_put, rec_get, &rb1, rec_cut };
	static const fzn_record_store_ops_t OPS_B2 = { rec_put, rec_get, &rb2, rec_cut };
	struct peer pa = { &a, sizeof(reply), 0, 0 }, pw = { &w, sizeof(reply), 0, 0 };
	fzn_reconcile_witness_t by_w = { ask, &pw }, mute = { silent_ask, NULL };
	uint8_t v[FZN_PUBKEY_LEN];
	fzn_exchange_tally_t t;
	uint64_t base = 0;
	size_t n = 0, confirmed = 9;

	key(v, 0x5d);
	CHECK(node_up(&a) && node_up(&w) && node_up(&b1) && node_up(&b2)
	              && fzn_node_journal_init_store(&ja, &OPS_A, &SIGN, &HASH) == FZN_NODE_JOURNAL_OK
	              && fzn_node_journal_init_store(&jw, &OPS_W, &SIGN, &HASH) == FZN_NODE_JOURNAL_OK
	              && fzn_node_journal_init_store(&jb1, &OPS_B1, &SIGN, &HASH)
	                         == FZN_NODE_JOURNAL_OK
	              && fzn_node_journal_init_store(&jb2, &OPS_B2, &SIGN, &HASH)
	                         == FZN_NODE_JOURNAL_OK,
	      "fixture: four journals");
	ja.keep = &a.store;
	jw.keep = &w.store;
	jb1.keep = &b1.store;
	jb2.keep = &b2.store;
	a.ap.journal = &ja;
	w.ap.journal = &jw;
	CHECK(append_n(&ja, 0x5d, FZN_NODE_JOURNAL_STREAM, 2u)
	              && fzn_node_journal_follow(&jb1, v, NULL) == FZN_NODE_JOURNAL_OK
	              && fzn_node_journal_follow(&jb2, v, NULL) == FZN_NODE_JOURNAL_OK
	              && fzn_node_journal_pull(&jb1, journal_ask, &ja, reply, sizeof(reply), &t)
	                         == FZN_EXCHANGE_OK
	              && fzn_node_journal_pull(&jb2, journal_ask, &ja, reply, sizeof(reply), &t)
	                         == FZN_EXCHANGE_OK
	              && append_n(&ja, 0x5d, FZN_NODE_JOURNAL_STREAM, 28u)
	              && fzn_node_journal_follow(&jw, v, NULL) == FZN_NODE_JOURNAL_OK
	              && fzn_node_journal_pull(&jw, journal_ask, &ja, reply, sizeof(reply), &t)
	                         == FZN_EXCHANGE_OK
	              && t.learned == 30u
	              && fzn_node_journal_cut(&ja, v, FZN_NODE_JOURNAL_STREAM, 28u, &n)
	                         == FZN_NODE_JOURNAL_OK,
	      "fixture: B1 and B2 at two, W at thirty, A cut below the twenty-eighth");
	CHECK(fzn_reconcile_rebase(&jb1, ask, &pa, &by_w, 1u, v, FZN_NODE_JOURNAL_STREAM, reply,
	                           sizeof(reply), &base, &confirmed) == FZN_RECONCILE_OK
	              && base == 28u && confirmed == 1u
	              && fzn_node_journal_received(&jb1, v, FZN_NODE_JOURNAL_STREAM) == 27u,
	      "an honest bridge was not confirmed by the witness, or did not move B1");
	CHECK(fzn_reconcile_rebase(&jb2, lying_base_ask, &pa, &by_w, 1u, v, FZN_NODE_JOURNAL_STREAM,
	                           reply, sizeof(reply), &base, &confirmed)
	                      == FZN_RECONCILE_ERR_CONFLICT
	              && base == 0u
	              && fzn_node_journal_received(&jb2, v, FZN_NODE_JOURNAL_STREAM) == 2u,
	      "a bridge with a subject changed was not refused by the witness, or moved B2");
	CHECK(fzn_reconcile_rebase(&jb2, lying_base_ask, &pa, &mute, 1u, v, FZN_NODE_JOURNAL_STREAM,
	                           reply, sizeof(reply), &base, &confirmed) == FZN_RECONCILE_OK
	              && base == 28u && confirmed == 0u,
	      "with no witness answering, the same bridge did not move B2 unconfirmed");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	CHECK(0, "deliberate");
	CHECK(failures == before + 1, "a failing check was not counted");
	failures = before;
	checks -= 1;
}

int main(void)
{
	memset(&cap, 0x61, sizeof(cap));
	memset(&admin_cap, 0x62, sizeof(admin_cap));
	key(root_key, 0x91);
	memcpy(estate, root_key, sizeof(estate));
	test_the_suite_can_tell_pass_from_fail();
	test_a_node_comes_to_its_peer();
	test_a_dishonest_peer();
	test_a_stream_behind_a_peers_base();
	test_note_claims();
	test_a_bridge_witnessed();
	if (failures) {
		fprintf(stderr, "reconcile_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("reconcile_test: all %d checks passed\n", checks);
	return 0;
}
