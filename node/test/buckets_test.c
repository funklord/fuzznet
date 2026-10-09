/* Tests for node/buckets.c, and for node/reconcile.c's exchange of them:
 * what a node holds of an append-only kind, by bucket. sec 564.
 *
 * TWO NODES IN ONE PROCESS, each its own in-memory store. A asks B by
 * calling B's answer directly. Items here are opaque bytes and the filer
 * keeps whatever hashes to its id: judging an item is its kind's business
 * (`node/messages_test` judges lines), and this file is about holding and
 * moving them.
 *
 * HOW IT TERMINATES: no forks, fixed loops, a fixed store of rows.
 */

#include "../buckets.h"
#include "../reconcile.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL buckets_test.c:%d: %s\n", __LINE__, what);      \
		}                                                                              \
	} while (0)

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

static size_t rows_in(const struct mem *m, fzn_persist_slot_t slot)
{
	size_t n = 0;
	int i;

	for (i = 0; i < ROWS; i++)
		n += m->rows[i].used && m->rows[i].slot == slot;
	return n;
}

static struct mem mem_a, mem_b;
static fzn_persist_ops_t store_a = { mem_load, mem_save, mem_list, mem_remove, &mem_a };
static fzn_persist_ops_t store_b = { mem_load, mem_save, mem_list, mem_remove, &mem_b };
static const fzn_buckets_t A = { &store_a, &HASH };
static const fzn_buckets_t B = { &store_b, &HASH };

static void fresh(void)
{
	memset(&mem_a, 0, sizeof(mem_a));
	memset(&mem_b, 0, sizeof(mem_b));
}

static void subject_of(uint8_t out[FZN_PUBKEY_LEN], uint8_t seed)
{
	size_t i;

	for (i = 0; i < FZN_PUBKEY_LEN; i++)
		out[i] = (uint8_t)(seed * 7u + i);
}

/* Item `n`: `len` bytes that differ from every other n's. */
static size_t item_of(uint8_t *out, unsigned n, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		out[i] = (uint8_t)(n * 31u + i * 7u + (i >> 8));
	out[0] = (uint8_t)n;
	out[1] = (uint8_t)(n >> 8);
	return len;
}

static int add_n(const fzn_buckets_t *b, const uint8_t subject[FZN_PUBKEY_LEN], uint32_t month,
                 unsigned n, size_t len)
{
	uint8_t item[FZN_BUCKETS_ITEM_MAX];

	return fzn_buckets_add(b, FZN_BUCKETS_MESSAGES, subject, month, item, item_of(item, n, len),
	                       NULL)
	       == FZN_BUCKETS_OK;
}

/* ---- holding ----------------------------------------------------------------- */

static void test_an_item_is_held_once(void)
{
	uint8_t s[FZN_PUBKEY_LEN], item[64], id[FZN_BUCKETS_ID_LEN], out[FZN_BUCKETS_ITEM_MAX];
	uint8_t got_subject[FZN_PUBKEY_LEN];
	uint32_t got_month = 0;
	size_t len = item_of(item, 1u, 40u), got = 0;
	fzn_bucket_t k;
	int added = -1;

	fresh();
	subject_of(s, 1);
	CHECK(fzn_buckets_add(&A, FZN_BUCKETS_MESSAGES, s, 680u, item, len, &added) == FZN_BUCKETS_OK
	              && added == 1,
	      "an item was not taken");
	CHECK(fzn_buckets_id(&HASH, item, len, id) && fzn_buckets_has(&A, FZN_BUCKETS_MESSAGES, id),
	      "an item taken is not held");
	CHECK(fzn_buckets_item(&A, FZN_BUCKETS_MESSAGES, id, out, sizeof(out), &got, got_subject,
	                       &got_month)
	                      == FZN_BUCKETS_OK
	              && got == len && memcmp(out, item, len) == 0
	              && memcmp(got_subject, s, sizeof(s)) == 0 && got_month == 680u,
	      "an item does not read back as it was taken, under its bucket");
	CHECK(fzn_buckets_add(&A, FZN_BUCKETS_MESSAGES, s, 680u, item, len, &added) == FZN_BUCKETS_OK
	              && added == 0,
	      "an item taken twice was not taken once");
	CHECK(fzn_buckets_bucket(&A, FZN_BUCKETS_MESSAGES, s, 680u, &k) == FZN_BUCKETS_OK
	              && k.count == 1u,
	      "an item taken twice is counted twice");
	CHECK(fzn_buckets_add(&A, FZN_BUCKETS_KINDS, s, 680u, item, len, NULL)
	                      == FZN_BUCKETS_MALFORMED
	              && fzn_buckets_add(&A, FZN_BUCKETS_MESSAGES, s, 680u, item, 0u, NULL)
	                         == FZN_BUCKETS_MALFORMED
	              && fzn_buckets_add(&A, FZN_BUCKETS_MESSAGES, s, 680u, out,
	                                 FZN_BUCKETS_ITEM_MAX + 1u, NULL)
	                         == FZN_BUCKETS_MALFORMED,
	      "an unknown kind, an empty item or an oversized one was taken");
}

/* THE DIGEST IS THE SET'S, whatever order it was learned in -- and moves
 * when the set does. */
static void test_a_digest_is_the_set_s(void)
{
	uint8_t s[FZN_PUBKEY_LEN];
	fzn_bucket_t a, b;

	fresh();
	subject_of(s, 2);
	CHECK(add_n(&A, s, 700u, 1u, 30u) && add_n(&A, s, 700u, 2u, 30u) && add_n(&A, s, 700u, 3u, 30u)
	              && add_n(&B, s, 700u, 3u, 30u) && add_n(&B, s, 700u, 1u, 30u)
	              && add_n(&B, s, 700u, 2u, 30u),
	      "fixture: three items each, in two orders");
	CHECK(fzn_buckets_bucket(&A, FZN_BUCKETS_MESSAGES, s, 700u, &a) == FZN_BUCKETS_OK
	              && fzn_buckets_bucket(&B, FZN_BUCKETS_MESSAGES, s, 700u, &b) == FZN_BUCKETS_OK
	              && a.count == 3u && b.count == 3u
	              && memcmp(a.digest, b.digest, sizeof(a.digest)) == 0,
	      "the same items in another order digest otherwise");
	CHECK(add_n(&B, s, 700u, 4u, 30u)
	              && fzn_buckets_bucket(&B, FZN_BUCKETS_MESSAGES, s, 700u, &b) == FZN_BUCKETS_OK
	              && memcmp(a.digest, b.digest, sizeof(a.digest)) != 0,
	      "a fourth item left the digest where it was");
	CHECK(fzn_buckets_bucket(&A, FZN_BUCKETS_MESSAGES, s, 701u, &b) == FZN_BUCKETS_OK
	              && b.count == 0u && memcmp(a.digest, b.digest, sizeof(a.digest)) != 0,
	      "an empty month digests as a full one");
}

/* IDS BY PAGE, across a chunk's end, in the order they were taken. */
static void test_ids_page_across_chunks(void)
{
	static uint8_t ids[80][FZN_BUCKETS_ID_LEN];
	uint8_t s[FZN_PUBKEY_LEN], item[64], id[FZN_BUCKETS_ID_LEN];
	uint64_t total = 0;
	size_t n = 0, m = 0;
	unsigned i;
	int all = 1, ordered = 1;

	fresh();
	subject_of(s, 3);
	for (i = 0; i < 70u; i++)
		all &= add_n(&A, s, 702u, i, 20u);
	CHECK(all, "fixture: seventy items in one bucket");
	CHECK(fzn_buckets_ids(&A, FZN_BUCKETS_MESSAGES, s, 702u, 0u, ids, 50u, &n, &total)
	                      == FZN_BUCKETS_OK
	              && n == 50u && total == 70u
	              && fzn_buckets_ids(&A, FZN_BUCKETS_MESSAGES, s, 702u, 50u, ids + 50, 30u, &m,
	                                 &total)
	                         == FZN_BUCKETS_OK
	              && m == 20u,
	      "seventy ids do not page as fifty and twenty");
	for (i = 0; i < 70u; i++) {
		fzn_buckets_id(&HASH, item, item_of(item, i, 20u), id);
		ordered &= memcmp(ids[i], id, sizeof(id)) == 0;
	}
	CHECK(ordered, "the ids are not the items' in the order they were taken");
	CHECK(rows_in(&mem_a, FZN_PERSIST_BUCKET_IDS) == 2u,
	      "seventy ids are not two chunks of at most sixty-four");
}

static void test_buckets_list_in_order(void)
{
	fzn_bucket_t out[8];
	uint8_t s1[FZN_PUBKEY_LEN], s2[FZN_PUBKEY_LEN];
	size_t n = 0;

	fresh();
	subject_of(s1, 9);
	subject_of(s2, 4);
	CHECK(add_n(&A, s1, 705u, 1u, 20u) && add_n(&A, s2, 706u, 2u, 20u)
	              && add_n(&A, s2, 704u, 3u, 20u),
	      "fixture: three buckets");
	CHECK(fzn_buckets_list(&A, FZN_BUCKETS_MESSAGES, out, 8u, &n) == FZN_BUCKETS_OK && n == 3u,
	      "three buckets do not list as three");
	CHECK(n == 3u && memcmp(out[0].subject, out[1].subject, FZN_PUBKEY_LEN) == 0
	              && out[0].month == 704u && out[1].month == 706u
	              && memcmp(out[1].subject, out[2].subject, FZN_PUBKEY_LEN) < 0,
	      "buckets do not list by subject and then month");
	CHECK(fzn_buckets_list(&A, FZN_BUCKETS_MESSAGES, out, 2u, &n) == FZN_BUCKETS_FULL,
	      "three buckets listed into room for two was not full");
}

static void test_a_bucket_let_go_is_gone(void)
{
	uint8_t s[FZN_PUBKEY_LEN], item[64], id[FZN_BUCKETS_ID_LEN], ids[4][FZN_BUCKETS_ID_LEN];
	fzn_bucket_t out[4];
	uint64_t total = 1;
	size_t n = 9, len;

	fresh();
	subject_of(s, 5);
	CHECK(add_n(&A, s, 710u, 1u, 20u) && add_n(&A, s, 710u, 2u, 20u)
	              && add_n(&A, s, 711u, 3u, 20u),
	      "fixture: two buckets");
	len = item_of(item, 1u, 20u);
	fzn_buckets_id(&HASH, item, len, id);
	CHECK(fzn_buckets_drop(&A, FZN_BUCKETS_MESSAGES, s, 710u) == FZN_BUCKETS_OK
	              && fzn_buckets_gone(&A, FZN_BUCKETS_MESSAGES, s, 710u)
	              && !fzn_buckets_gone(&A, FZN_BUCKETS_MESSAGES, s, 711u),
	      "a bucket let go is not gone, or its neighbour is");
	CHECK(!fzn_buckets_has(&A, FZN_BUCKETS_MESSAGES, id)
	              && rows_in(&mem_a, FZN_PERSIST_BUCKET_ITEM) == 1u,
	      "a gone bucket's items are still held");
	CHECK(fzn_buckets_add(&A, FZN_BUCKETS_MESSAGES, s, 710u, item, len, NULL) == FZN_BUCKETS_GONE
	              && !fzn_buckets_has(&A, FZN_BUCKETS_MESSAGES, id),
	      "a gone bucket took an item again");
	CHECK(fzn_buckets_list(&A, FZN_BUCKETS_MESSAGES, out, 4u, &n) == FZN_BUCKETS_OK && n == 1u
	              && out[0].month == 711u,
	      "a gone bucket is still listed");
	CHECK(fzn_buckets_ids(&A, FZN_BUCKETS_MESSAGES, s, 710u, 0u, ids, 4u, &n, &total)
	                      == FZN_BUCKETS_OK
	              && n == 0u && total == 0u,
	      "a gone bucket still names ids");
}

/* A CRASH PART WAY THROUGH A TAKING, at each save in turn: the item, its
 * chunk, its count, its mark. Taken again, it is held and counted once. */
static void test_a_crash_part_way_is_taken_once(void)
{
	uint8_t s[FZN_PUBKEY_LEN], item[64], id[FZN_BUCKETS_ID_LEN];
	size_t len;
	int at, all = 1;

	subject_of(s, 6);
	len = item_of(item, 7u, 30u);
	fzn_buckets_id(&HASH, item, len, id);
	for (at = 1; at <= 4; at++) {
		fzn_bucket_t k;

		fresh();
		/* One item first, so the crash lands in a chunk already begun. */
		add_n(&A, s, 720u, 1u, 30u);
		mem_a.saves = 0;
		mem_a.fail_at = at;
		all &= fzn_buckets_add(&A, FZN_BUCKETS_MESSAGES, s, 720u, item, len, NULL)
		       == FZN_BUCKETS_BACKEND;
		mem_a.fail_at = 0;
		all &= !fzn_buckets_has(&A, FZN_BUCKETS_MESSAGES, id);
		all &= fzn_buckets_add(&A, FZN_BUCKETS_MESSAGES, s, 720u, item, len, NULL)
		       == FZN_BUCKETS_OK;
		all &= fzn_buckets_has(&A, FZN_BUCKETS_MESSAGES, id);
		all &= fzn_buckets_bucket(&A, FZN_BUCKETS_MESSAGES, s, 720u, &k) == FZN_BUCKETS_OK
		       && k.count == 2u;
		if (!all)
			fprintf(stderr, "    crash at save %d\n", at);
	}
	CHECK(all, "an item whose taking crashed part way is not held once, counted once");
}

/* THE SAME AT A CHUNK'S END: sixty-four held, the sixty-fifth crashes
 * after its count and before its mark, and is not counted again. */
static void test_a_crash_at_a_chunk_s_end(void)
{
	uint8_t s[FZN_PUBKEY_LEN], item[64];
	fzn_bucket_t k;
	unsigned i;
	int all = 1;

	fresh();
	subject_of(s, 8);
	for (i = 0; i < FZN_BUCKETS_CHUNK - 1u; i++)
		all &= add_n(&A, s, 721u, i, 20u);
	mem_a.saves = 0;
	mem_a.fail_at = 4;
	all &= fzn_buckets_add(&A, FZN_BUCKETS_MESSAGES, s, 721u, item, item_of(item, 99u, 20u), NULL)
	       == FZN_BUCKETS_BACKEND;
	mem_a.fail_at = 0;
	all &= add_n(&A, s, 721u, 99u, 20u) && add_n(&A, s, 721u, 100u, 20u);
	CHECK(all && fzn_buckets_bucket(&A, FZN_BUCKETS_MESSAGES, s, 721u, &k) == FZN_BUCKETS_OK
	              && k.count == FZN_BUCKETS_CHUNK + 1u,
	      "the chunk's last id, crashed before its mark, was counted twice");
}

/* ---- the exchange ------------------------------------------------------------ */

static uint8_t answer_buf[8192];
/* The asked node's store, and a reply size it answers within. */
static struct asked {
	const fzn_persist_ops_t *store;
	size_t cap;
	int lie; /* 1: flip a byte of every item sent */
	size_t asks;
	const fzn_reconcile_gate_t *gate; /* the asked node's, NULL for none */
} asked;

static int ask(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
               size_t reply_cap, size_t *reply_len)
{
	struct asked *a = (struct asked *)ctx;
	size_t cap = a->cap && a->cap < reply_cap ? a->cap : reply_cap;
	size_t n = fzn_reconcile_answer_gated(a->store, &HASH, NULL, a->gate, request, request_len,
	                                      answer_buf, cap);

	a->asks++;
	if (!n)
		return 0;
	if (a->lie && n > FZN_RECONCILE_ITEM_HEAD_LEN && answer_buf[1] == FZN_RECONCILE_ITEM)
		answer_buf[FZN_RECONCILE_ITEM_HEAD_LEN] ^= 0x01u;
	memcpy(reply, answer_buf, n);
	*reply_len = n;
	return 1;
}

/* The filer: whatever hashes to its id is kept under the bucket it came
 * from, unless the subject is the one refused. */
static uint8_t refused_subject[FZN_PUBKEY_LEN];
static int wanted_months_below;

static fzn_node_apply_outcome_t keep_it(void *ctx, const uint8_t subject[FZN_PUBKEY_LEN],
                                        uint32_t month, const uint8_t *item, size_t len)
{
	if (memcmp(subject, refused_subject, FZN_PUBKEY_LEN) == 0)
		return FZN_NODE_APPLY_REFUSED;
	return fzn_buckets_add((const fzn_buckets_t *)ctx, FZN_BUCKETS_MESSAGES, subject, month, item,
	                       len, NULL)
	                       == FZN_BUCKETS_OK
	               ? FZN_NODE_APPLY_APPLIED
	               : FZN_NODE_APPLY_NOT_SAVED;
}

static int months_wanted(void *ctx, const uint8_t subject[FZN_PUBKEY_LEN], uint32_t month)
{
	(void)ctx;
	(void)subject;
	return wanted_months_below == 0 || month < (uint32_t)wanted_months_below;
}

static fzn_reconcile_err_t round_b_from_a(fzn_reconcile_bucket_tally_t *t, size_t cap)
{
	static uint8_t reply[8192];
	fzn_reconcile_filer_t filer = { keep_it, months_wanted, (void *)&B, NULL, NULL, NULL };

	asked.store = &store_a;
	asked.cap = cap;
	asked.asks = 0;
	return fzn_reconcile_buckets(&B, FZN_BUCKETS_MESSAGES, &filer, ask, &asked, reply,
	                             sizeof(reply), t);
}

static int same_buckets(void)
{
	static fzn_bucket_t a[64], b[64];
	size_t na = 0, nb = 0, i;

	if (fzn_buckets_list(&A, FZN_BUCKETS_MESSAGES, a, 64u, &na) != FZN_BUCKETS_OK
	    || fzn_buckets_list(&B, FZN_BUCKETS_MESSAGES, b, 64u, &nb) != FZN_BUCKETS_OK || na != nb)
		return 0;
	for (i = 0; i < na; i++)
		if (a[i].count != b[i].count || memcmp(a[i].digest, b[i].digest, FZN_BUCKETS_ID_LEN) != 0)
			return 0;
	return 1;
}

/* FROM NOTHING: B takes every bucket A holds, and a second round finds
 * nothing to take. */
static void test_a_node_takes_a_peer_s_buckets(void)
{
	uint8_t s1[FZN_PUBKEY_LEN], s2[FZN_PUBKEY_LEN];
	fzn_reconcile_bucket_tally_t t;
	unsigned i;
	int all = 1;

	fresh();
	memset(refused_subject, 0xff, sizeof(refused_subject));
	wanted_months_below = 0;
	asked.lie = 0;
	subject_of(s1, 10);
	subject_of(s2, 11);
	for (i = 0; i < 70u; i++)
		all &= add_n(&A, s1, 730u, i, 25u);
	all &= add_n(&A, s2, 731u, 200u, 25u) && add_n(&A, s2, 732u, 201u, 25u);
	all &= add_n(&B, s1, 730u, 5u, 25u);
	CHECK(all, "fixture: three buckets at A, one item of one at B");
	CHECK(round_b_from_a(&t, 0u) == FZN_RECONCILE_OK && t.buckets == 3u && t.lacked == 71u
	              && t.applied == 71u && t.refused == 0u,
	      "B did not take the 71 items it lacked of three buckets");
	CHECK(same_buckets(), "after a round B's buckets are not A's");
	CHECK(round_b_from_a(&t, 0u) == FZN_RECONCILE_OK && t.buckets == 0u && t.lacked == 0u,
	      "a second round found something to take");
	CHECK(asked.asks == 1u, "a round over agreeing buckets asked more than the listing");
}

/* OVER THE SMALLEST REPLY: buckets, ids and an item larger than one reply,
 * each in pieces. */
static void test_pieces_over_the_smallest_reply(void)
{
	uint8_t s[FZN_PUBKEY_LEN];
	fzn_reconcile_bucket_tally_t t;
	fzn_reconcile_err_t err;
	unsigned i;
	int all = 1;

	fresh();
	asked.lie = 0;
	wanted_months_below = 0;
	subject_of(s, 12);
	for (i = 0; i < 30u; i++)
		all &= add_n(&A, s, (uint32_t)(740u + i), i, 25u);
	for (i = 0; i < 80u; i++)
		all &= add_n(&A, s, 739u, 100u + i, 25u);
	all &= add_n(&A, s, 738u, 500u, FZN_BUCKETS_ITEM_MAX);
	CHECK(all, "fixture: 32 buckets, one of 80 ids, one item of 4096 bytes");
	err = round_b_from_a(&t, FZN_RECONCILE_REPLY_MIN);
	if (err != FZN_RECONCILE_OK || t.applied != 111u)
		fprintf(stderr, "    %s: %zu buckets, %zu lacked, %zu applied, %zu refused, %zu full\n",
		        fzn_reconcile_err_str(err), t.buckets, t.lacked, t.applied, t.refused, t.full);
	CHECK(err == FZN_RECONCILE_OK && t.applied == 111u && same_buckets(),
	      "over the smallest reply B did not take all 111 items");
}

/* A PEER THAT CHANGES WHAT IT SENDS has every item refused, nothing kept;
 * a filer's refusal is counted; a bucket gone here, or not wanted, is
 * passed over and never asked for. */
static void test_what_is_not_taken(void)
{
	uint8_t s1[FZN_PUBKEY_LEN], s2[FZN_PUBKEY_LEN];
	fzn_reconcile_bucket_tally_t t;
	fzn_bucket_t k;

	fresh();
	wanted_months_below = 0;
	subject_of(s1, 13);
	subject_of(s2, 14);
	CHECK(add_n(&A, s1, 750u, 1u, 25u) && add_n(&A, s1, 750u, 2u, 25u)
	              && add_n(&A, s2, 751u, 3u, 25u) && add_n(&A, s2, 752u, 4u, 25u),
	      "fixture: three buckets at A");
	asked.lie = 1;
	CHECK(round_b_from_a(&t, 0u) == FZN_RECONCILE_OK && t.refused == 4u && t.applied == 0u
	              && fzn_buckets_bucket(&B, FZN_BUCKETS_MESSAGES, s1, 750u, &k) == FZN_BUCKETS_OK
	              && k.count == 0u,
	      "items that are not their ids were kept");
	asked.lie = 0;
	memcpy(refused_subject, s1, sizeof(refused_subject));
	CHECK(fzn_buckets_drop(&B, FZN_BUCKETS_MESSAGES, s2, 751u) == FZN_BUCKETS_OK,
	      "fixture: B let 751 go");
	wanted_months_below = 752;
	CHECK(round_b_from_a(&t, 0u) == FZN_RECONCILE_OK && t.refused == 2u && t.applied == 0u
	              && t.passed == 2u && t.lacked == 2u,
	      "a refusal, a gone bucket and an unwanted one were not each kept from");
	memset(refused_subject, 0xff, sizeof(refused_subject));
}

/* THE GATE, sec 567: a caller is served only the buckets it may hold.
 * One it may not is not listed, names no ids, and its items answer as not
 * held -- even asked for by id, as a caller that learned one elsewhere
 * would. */
static uint8_t barred[FZN_PUBKEY_LEN];

static int serves_but_barred(void *ctx, fzn_buckets_kind_t kind,
                             const uint8_t subject[FZN_PUBKEY_LEN])
{
	(void)ctx;
	return kind == FZN_BUCKETS_MESSAGES && memcmp(subject, barred, FZN_PUBKEY_LEN) != 0;
}

static void test_a_gate_serves_only_what_it_may(void)
{
	static uint8_t request[FZN_RECONCILE_ITEM_QUERY_LEN], reply[8192];
	uint8_t s1[FZN_PUBKEY_LEN], s2[FZN_PUBKEY_LEN], item[64], id[FZN_BUCKETS_ID_LEN];
	fzn_reconcile_gate_t gate = { serves_but_barred, NULL };
	fzn_reconcile_bucket_tally_t t;
	fzn_bucket_t k;
	size_t n;

	fresh();
	asked.lie = 0;
	wanted_months_below = 0;
	memset(refused_subject, 0xff, sizeof(refused_subject));
	subject_of(s1, 15);
	subject_of(s2, 16);
	memcpy(barred, s1, sizeof(barred));
	CHECK(add_n(&A, s1, 760u, 1u, 25u) && add_n(&A, s1, 761u, 2u, 25u)
	              && add_n(&A, s2, 760u, 3u, 25u),
	      "fixture: two buckets of a barred subject, one of another, at A");
	asked.gate = &gate;
	CHECK(round_b_from_a(&t, 0u) == FZN_RECONCILE_OK && t.buckets == 1u && t.applied == 1u
	              && fzn_buckets_bucket(&B, FZN_BUCKETS_MESSAGES, s1, 760u, &k) == FZN_BUCKETS_OK
	              && k.count == 0u,
	      "a round through the gate took more than the one bucket it may hold");
	n = item_of(item, 1u, 25u);
	fzn_buckets_id(&HASH, item, n, id);
	request[0] = (uint8_t)FZN_RECONCILE_VERSION;
	request[1] = (uint8_t)FZN_RECONCILE_ITEM_QUERY;
	request[2] = (uint8_t)FZN_BUCKETS_MESSAGES;
	memcpy(request + 3u, id, sizeof(id));
	memset(request + 35u, 0, 4u);
	n = fzn_reconcile_answer_gated(&store_a, &HASH, NULL, &gate, request, sizeof(request), reply,
	                               sizeof(reply));
	CHECK(n == FZN_RECONCILE_ITEM_HEAD_LEN && reply[1] == FZN_RECONCILE_ITEM && reply[35] == 0u
	              && reply[36] == 0u && reply[37] == 0u && reply[38] == 0u,
	      "a barred item asked for by its id was handed over");
	n = fzn_reconcile_answer(&store_a, &HASH, NULL, request, sizeof(request), reply,
	                         sizeof(reply));
	CHECK(n > FZN_RECONCILE_ITEM_HEAD_LEN,
	      "with no gate the same item is not served: the check above proved nothing");
	{
		uint8_t q[FZN_RECONCILE_BUCKET_IDS_QUERY_LEN];

		q[0] = (uint8_t)FZN_RECONCILE_VERSION;
		q[1] = (uint8_t)FZN_RECONCILE_BUCKET_IDS_QUERY;
		q[2] = (uint8_t)FZN_BUCKETS_MESSAGES;
		memcpy(q + 3u, s1, FZN_PUBKEY_LEN);
		q[35] = 0u;
		q[36] = 0u;
		q[37] = (uint8_t)(760u >> 8);
		q[38] = (uint8_t)760u;
		memset(q + 39u, 0, 4u);
		n = fzn_reconcile_answer_gated(&store_a, &HASH, NULL, &gate, q, sizeof(q), reply,
		                               sizeof(reply));
		CHECK(n == FZN_RECONCILE_BUCKET_IDS_HEAD_LEN && reply[1] == FZN_RECONCILE_BUCKET_IDS
		              && reply[42] == 0u,
		      "a barred bucket's ids, asked for directly, were named");
		n = fzn_reconcile_answer(&store_a, &HASH, NULL, q, sizeof(q), reply, sizeof(reply));
		CHECK(n == FZN_RECONCILE_BUCKET_IDS_HEAD_LEN + FZN_BUCKETS_ID_LEN,
		      "with no gate the bucket names no id: the check above proved nothing");
	}
	asked.gate = NULL;
	CHECK(round_b_from_a(&t, 0u) == FZN_RECONCILE_OK && t.applied == 2u,
	      "without the gate B did not take the two barred buckets' items");
}

/* ---- push, sec 569: B cannot reach A, so A sends ------------------------ */

static uint8_t sender_a[FZN_PUBKEY_LEN];

/* B ANSWERING A, taking what A pushes: `taking` 0 takes none; `flip` 1
 * changes a byte of the next piece in flight; `drop` > 0 loses that many
 * puts unanswered, as a hop broken off. */
static struct receiving {
	int taking, flip, drop;
	size_t puts, bytes;
} receiving;

static int to_b(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
                size_t reply_cap, size_t *reply_len)
{
	static uint8_t copy[FZN_RECONCILE_ITEM_PUT_HEAD_LEN + FZN_RECONCILE_PIECE_MAX];
	fzn_reconcile_filer_t filer = { keep_it, months_wanted, (void *)&B, NULL, NULL, NULL };
	fzn_reconcile_server_t srv;
	size_t n;

	(void)ctx;
	memset(&srv, 0, sizeof(srv));
	srv.store = &store_b;
	srv.hash = &HASH;
	srv.takers[FZN_BUCKETS_MESSAGES] = receiving.taking ? &filer : NULL;
	srv.sender = sender_a;
	if (request_len >= 2u && request[1] == FZN_RECONCILE_ITEM_PUT) {
		receiving.puts++;
		if (request_len > FZN_RECONCILE_ITEM_PUT_HEAD_LEN)
			receiving.bytes += request_len - FZN_RECONCILE_ITEM_PUT_HEAD_LEN;
		/* ONLY A PIECE CARRYING BYTES is lost, so the loss lands mid-item. */
		if (receiving.drop > 0 && request_len > FZN_RECONCILE_ITEM_PUT_HEAD_LEN) {
			receiving.drop--;
			/* THE PIECE ARRIVES, its answer does not. */
			(void)fzn_reconcile_serve(&srv, request, request_len, reply, reply_cap);
			return 0;
		}
		if (receiving.flip && request_len > FZN_RECONCILE_ITEM_PUT_HEAD_LEN
		    && request_len <= sizeof(copy)) {
			memcpy(copy, request, request_len);
			copy[FZN_RECONCILE_ITEM_PUT_HEAD_LEN] ^= 0x01u;
			request = copy;
		}
	}
	n = fzn_reconcile_serve(&srv, request, request_len, reply, reply_cap);
	if (!n)
		return 0;
	*reply_len = n;
	return 1;
}

static fzn_reconcile_err_t push_a_to_b(fzn_reconcile_bucket_tally_t *t)
{
	static uint8_t reply[FZN_RECONCILE_REPLY_MIN];

	return fzn_reconcile_push(&A, FZN_BUCKETS_MESSAGES, NULL, NULL, NULL, to_b, NULL, reply,
	                          sizeof(reply), t);
}

static void test_a_push_brings_a_peer_up(void)
{
	uint8_t s1[FZN_PUBKEY_LEN], s2[FZN_PUBKEY_LEN];
	fzn_reconcile_bucket_tally_t t;
	fzn_reconcile_err_t err;
	unsigned i;
	int all = 1;

	fresh();
	memset(sender_a, 0xa0, sizeof(sender_a));
	memset(refused_subject, 0xff, sizeof(refused_subject));
	memset(&receiving, 0, sizeof(receiving));
	receiving.taking = 1;
	wanted_months_below = 0;
	subject_of(s1, 20);
	subject_of(s2, 21);
	for (i = 0; i < 70u; i++)
		all &= add_n(&A, s1, 770u, i, 25u);
	all &= add_n(&A, s2, 771u, 300u, FZN_BUCKETS_ITEM_MAX) && add_n(&A, s2, 772u, 301u, 25u);
	all &= add_n(&B, s1, 770u, 5u, 25u);
	CHECK(all, "fixture: three buckets at A, one item of one at B");
	err = push_a_to_b(&t);
	if (err != FZN_RECONCILE_OK || t.sent != 71u)
		fprintf(stderr, "    %s: %zu buckets, %zu lacked, %zu sent, %zu held, %zu refused\n",
		        fzn_reconcile_err_str(err), t.buckets, t.lacked, t.sent, t.held, t.refused);
	CHECK(err == FZN_RECONCILE_OK && t.buckets == 3u && t.lacked == 71u && t.sent == 71u
	              && t.refused == 0u && same_buckets(),
	      "a push did not bring B's buckets up to A's, the 4096-byte item in pieces");
	receiving.puts = 0;
	CHECK(push_a_to_b(&t) == FZN_RECONCILE_OK && t.buckets == 0u && receiving.puts == 0u,
	      "a second push sent anything");
}

static void test_what_a_push_does_not_leave(void)
{
	uint8_t s1[FZN_PUBKEY_LEN], s2[FZN_PUBKEY_LEN];
	fzn_reconcile_bucket_tally_t t;
	fzn_bucket_t k;

	fresh();
	memset(sender_a, 0xa0, sizeof(sender_a));
	memset(refused_subject, 0xff, sizeof(refused_subject));
	memset(&receiving, 0, sizeof(receiving));
	wanted_months_below = 0;
	subject_of(s1, 22);
	subject_of(s2, 23);
	CHECK(add_n(&A, s1, 780u, 1u, 25u) && add_n(&A, s2, 781u, 2u, 25u)
	              && add_n(&A, s2, 782u, 3u, FZN_BUCKETS_ITEM_MAX),
	      "fixture: three buckets at A");
	/* A RECEIVER TAKING NO PUSHES says not wanted, at the first piece. */
	CHECK(push_a_to_b(&t) == FZN_RECONCILE_OK && t.passed == 3u && t.sent == 0u
	              && receiving.puts == 3u && receiving.bytes == 0u,
	      "a receiver taking no pushes kept something, or was sent a byte");
	receiving.taking = 1;
	/* A CHANGED BYTE: the whole is not its id, and nothing is kept. */
	receiving.flip = 1;
	CHECK(push_a_to_b(&t) == FZN_RECONCILE_OK && t.refused == 3u && t.sent == 0u
	              && fzn_buckets_bucket(&B, FZN_BUCKETS_MESSAGES, s1, 780u, &k) == FZN_BUCKETS_OK
	              && k.count == 0u,
	      "a pushed item that is not its id was kept");
	receiving.flip = 0;
	/* GONE, OR NOT WANTED, at the first piece; the rest kept. */
	CHECK(fzn_buckets_drop(&B, FZN_BUCKETS_MESSAGES, s1, 780u) == FZN_BUCKETS_OK,
	      "fixture: B let 780 go");
	wanted_months_below = 782;
	receiving.bytes = 0;
	CHECK(push_a_to_b(&t) == FZN_RECONCILE_OK && t.passed == 2u && t.sent == 1u
	              && receiving.bytes == 25u,
	      "a gone bucket and an unwanted one were sent a byte, or the third not kept");
	wanted_months_below = 0;
	/* BROKEN OFF after a piece, the push resumes where B holds it. */
	receiving.drop = 1;
	CHECK(push_a_to_b(&t) == FZN_RECONCILE_ERR_NO_ANSWER,
	      "fixture: a push broken off after its first piece of bytes");
	receiving.bytes = 0;
	CHECK(push_a_to_b(&t) == FZN_RECONCILE_OK && t.sent == 1u
	              && receiving.bytes == FZN_BUCKETS_ITEM_MAX - FZN_RECONCILE_PIECE_MAX
	              && fzn_buckets_bucket(&B, FZN_BUCKETS_MESSAGES, s2, 782u, &k) == FZN_BUCKETS_OK
	              && k.count == 1u,
	      "the next push resent what B held, or did not finish the item");
}

/* ---- large items, sec 570: kept by their kind, in pieces ---------------- */

/* A KIND THAT KEEPS ITS OWN ITEMS, in memory: a few items each node holds,
 * named by id, and one staging area per node. */
#define LARGE_ITEMS 4u
#define LARGE_LEN 50000u

struct large {
	const fzn_buckets_t *b;
	struct {
		int used;
		uint8_t id[FZN_BUCKETS_ID_LEN];
		size_t len;
		uint8_t bytes[LARGE_LEN];
	} items[LARGE_ITEMS];
	uint8_t staging[LARGE_LEN];
	uint8_t staging_id[FZN_BUCKETS_ID_LEN];
	size_t staged;
	int refuse_stage;
};

static struct large large_a, large_b;

static int large_read(void *ctx, const uint8_t *ref, size_t ref_len, uint64_t offset,
                      uint8_t *out, size_t n)
{
	struct large *l = (struct large *)ctx;
	size_t i;

	if (ref_len != FZN_BUCKETS_ID_LEN)
		return 0;
	for (i = 0; i < LARGE_ITEMS; i++)
		if (l->items[i].used && memcmp(l->items[i].id, ref, FZN_BUCKETS_ID_LEN) == 0) {
			if (offset > l->items[i].len || n > l->items[i].len - offset)
				return 0;
			memcpy(out, l->items[i].bytes + offset, n);
			return 1;
		}
	return 0;
}

static int large_stage(void *ctx, const uint8_t id[FZN_BUCKETS_ID_LEN], uint64_t total,
                       uint64_t offset, const uint8_t *bytes, size_t n)
{
	struct large *l = (struct large *)ctx;

	if (l->refuse_stage || total > LARGE_LEN)
		return 0;
	if (offset == 0u) {
		memcpy(l->staging_id, id, FZN_BUCKETS_ID_LEN);
		l->staged = 0;
	}
	if (memcmp(l->staging_id, id, FZN_BUCKETS_ID_LEN) != 0 || offset != l->staged
	    || n > total - offset)
		return 0;
	memcpy(l->staging + offset, bytes, n);
	l->staged += n;
	return 1;
}

/* Keep `bytes` as one of `l`'s items, and take it into its bucket. */
static int large_keep(struct large *l, const uint8_t *subject, uint32_t month,
                      const uint8_t *bytes, size_t len, const uint8_t id[FZN_BUCKETS_ID_LEN])
{
	size_t i;

	for (i = 0; i < LARGE_ITEMS && l->items[i].used; i++)
		;
	if (i == LARGE_ITEMS)
		return 0;
	l->items[i].used = 1;
	memcpy(l->items[i].id, id, FZN_BUCKETS_ID_LEN);
	l->items[i].len = len;
	memcpy(l->items[i].bytes, bytes, len);
	return fzn_buckets_add_ref(l->b, FZN_BUCKETS_LOGS, subject, month, id, len, id,
	                           FZN_BUCKETS_ID_LEN, NULL)
	       == FZN_BUCKETS_OK;
}

static fzn_node_apply_outcome_t large_finish(void *ctx, const uint8_t subject[FZN_PUBKEY_LEN],
                                             uint32_t month, const uint8_t id[FZN_BUCKETS_ID_LEN],
                                             uint64_t total)
{
	struct large *l = (struct large *)ctx;
	uint8_t got[FZN_BUCKETS_ID_LEN];

	/* THE WHOLE, checked here: the kind holds the bytes. */
	if (l->staged != total || memcmp(l->staging_id, id, FZN_BUCKETS_ID_LEN) != 0
	    || !fzn_buckets_id(&HASH, l->staging, l->staged, got)
	    || memcmp(got, id, FZN_BUCKETS_ID_LEN) != 0)
		return FZN_NODE_APPLY_REFUSED;
	return large_keep(l, subject, month, l->staging, l->staged, id) ? FZN_NODE_APPLY_APPLIED
	                                                                 : FZN_NODE_APPLY_NOT_SAVED;
}

static fzn_node_apply_outcome_t large_file(void *ctx, const uint8_t subject[FZN_PUBKEY_LEN],
                                           uint32_t month, const uint8_t *item, size_t len)
{
	struct large *l = (struct large *)ctx;

	return fzn_buckets_add(l->b, FZN_BUCKETS_LOGS, subject, month, item, len, NULL)
	                       == FZN_BUCKETS_OK
	               ? FZN_NODE_APPLY_APPLIED
	               : FZN_NODE_APPLY_NOT_SAVED;
}

static const fzn_reconcile_filer_t LARGE_A = { large_file, NULL, &large_a, large_stage,
	                                       large_finish, large_read };
static const fzn_reconcile_filer_t LARGE_B = { large_file, NULL, &large_b, large_stage,
	                                       large_finish, large_read };

/* A ASKED BY B, serving its large items through its kind. */
static int large_ask(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
                     size_t reply_cap, size_t *reply_len)
{
	fzn_reconcile_server_t srv;
	size_t n;

	(void)ctx;
	memset(&srv, 0, sizeof(srv));
	srv.store = &store_a;
	srv.hash = &HASH;
	srv.takers[FZN_BUCKETS_LOGS] = &LARGE_A;
	n = fzn_reconcile_serve(&srv, request, request_len, answer_buf,
	                        reply_cap < FZN_RECONCILE_REPLY_MIN ? reply_cap
	                                                            : FZN_RECONCILE_REPLY_MIN);
	if (!n)
		return 0;
	if (asked.lie && n > FZN_RECONCILE_ITEM_HEAD_LEN && answer_buf[1] == FZN_RECONCILE_ITEM)
		answer_buf[FZN_RECONCILE_ITEM_HEAD_LEN] ^= 0x01u;
	memcpy(reply, answer_buf, n);
	*reply_len = n;
	return 1;
}

/* B ASKED BY A, taking A's pushed large items through its kind. */
static int large_to_b(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
                      size_t reply_cap, size_t *reply_len)
{
	fzn_reconcile_server_t srv;
	size_t n;

	(void)ctx;
	memset(&srv, 0, sizeof(srv));
	srv.store = &store_b;
	srv.hash = &HASH;
	srv.takers[FZN_BUCKETS_LOGS] = receiving.taking ? &LARGE_B : NULL;
	srv.sender = sender_a;
	n = fzn_reconcile_serve(&srv, request, request_len, reply, reply_cap);
	if (!n)
		return 0;
	*reply_len = n;
	return 1;
}

static void large_fresh(void)
{
	fresh();
	memset(&large_a, 0, sizeof(large_a));
	memset(&large_b, 0, sizeof(large_b));
	large_a.b = &A;
	large_b.b = &B;
	memset(sender_a, 0xa0, sizeof(sender_a));
	asked.lie = 0;
}

static int add_large_small(const uint8_t *subject);

/* A large item and a small one at A, in one bucket of the logs kind. */
static int large_fixture(uint8_t subject[FZN_PUBKEY_LEN], uint8_t id[FZN_BUCKETS_ID_LEN])
{
	static uint8_t big[LARGE_LEN];
	size_t i;

	subject_of(subject, 30);
	for (i = 0; i < sizeof(big); i++)
		big[i] = (uint8_t)(i * 131u + (i >> 9));
	return fzn_buckets_id(&HASH, big, sizeof(big), id)
	       && large_keep(&large_a, subject, 790u, big, sizeof(big), id)
	       && add_large_small(subject);
}

static int add_large_small(const uint8_t *subject)
{
	uint8_t item[64];

	return fzn_buckets_add(&A, FZN_BUCKETS_LOGS, subject, 790u, item, item_of(item, 7u, 40u),
	                       NULL)
	       == FZN_BUCKETS_OK;
}

static void test_large_items_pulled_and_pushed(void)
{
	static uint8_t reply[8192];
	uint8_t s1[FZN_PUBKEY_LEN], id[FZN_BUCKETS_ID_LEN];
	fzn_reconcile_filer_t no_large = { large_file, NULL, &large_b, NULL, NULL, NULL };
	fzn_reconcile_bucket_tally_t t;
	fzn_bucket_t a, b;
	fzn_reconcile_err_t err;

	/* PULLED over the smallest reply: some 25 pieces, staged by the kind,
	 * checked whole, and kept by ref. */
	large_fresh();
	CHECK(large_fixture(s1, id), "fixture: a large item and a small one at A");
	err = fzn_reconcile_buckets(&B, FZN_BUCKETS_LOGS, &LARGE_B, large_ask, NULL, reply,
	                            sizeof(reply), &t);
	CHECK(err == FZN_RECONCILE_OK && t.applied == 2u && t.refused == 0u
	              && fzn_buckets_has(&B, FZN_BUCKETS_LOGS, id) && large_b.items[0].used
	              && large_b.items[0].len == LARGE_LEN
	              && memcmp(large_b.items[0].bytes, large_a.items[0].bytes, LARGE_LEN) == 0
	              && fzn_buckets_bucket(&A, FZN_BUCKETS_LOGS, s1, 790u, &a) == FZN_BUCKETS_OK
	              && fzn_buckets_bucket(&B, FZN_BUCKETS_LOGS, s1, 790u, &b) == FZN_BUCKETS_OK
	              && memcmp(a.digest, b.digest, sizeof(a.digest)) == 0,
	      "B did not pull the large item whole, or its bucket is not A's");
	CHECK(fzn_buckets_item(&B, FZN_BUCKETS_LOGS, id, reply, sizeof(reply), &t.lacked, NULL,
	                       NULL)
	              == FZN_BUCKETS_LARGE,
	      "the large item is held in a row, not by its kind");
	/* A LIAR'S CHANGED BYTE fails the kind's check, and nothing is kept. */
	large_fresh();
	CHECK(large_fixture(s1, id), "fixture: again");
	asked.lie = 1;
	CHECK(fzn_reconcile_buckets(&B, FZN_BUCKETS_LOGS, &LARGE_B, large_ask, NULL, reply,
	                            sizeof(reply), &t)
	                      == FZN_RECONCILE_OK
	              && t.refused == 2u && !fzn_buckets_has(&B, FZN_BUCKETS_LOGS, id)
	              && !large_b.items[0].used,
	      "a large item with a changed byte was kept");
	asked.lie = 0;
	/* A KIND WITH NO LARGE HOOKS refuses it at its first piece. */
	CHECK(fzn_reconcile_buckets(&B, FZN_BUCKETS_LOGS, &no_large, large_ask, NULL, reply,
	                            sizeof(reply), &t)
	                      == FZN_RECONCILE_OK
	              && t.refused == 1u && t.applied == 1u && !fzn_buckets_has(&B, FZN_BUCKETS_LOGS, id),
	      "a kind that takes no large items took one");

	/* PUSHED: read through A's kind, staged through B's. */
	large_fresh();
	CHECK(large_fixture(s1, id), "fixture: again, to push");
	memset(&receiving, 0, sizeof(receiving));
	receiving.taking = 1;
	CHECK(fzn_reconcile_push(&A, FZN_BUCKETS_LOGS, NULL, &LARGE_A, NULL, large_to_b, NULL, reply,
	                         FZN_RECONCILE_REPLY_MIN, &t)
	                      == FZN_RECONCILE_OK
	              && t.sent == 2u && t.refused == 0u && fzn_buckets_has(&B, FZN_BUCKETS_LOGS, id)
	              && large_b.items[0].used
	              && memcmp(large_b.items[0].bytes, large_a.items[0].bytes, LARGE_LEN) == 0,
	      "A did not push the large item whole");
	/* A PUSHER WITHOUT ITS KIND'S READER sends only what rows hold. */
	large_fresh();
	CHECK(large_fixture(s1, id), "fixture: again, to push without a reader");
	CHECK(fzn_reconcile_push(&A, FZN_BUCKETS_LOGS, NULL, NULL, NULL, large_to_b, NULL, reply,
	                         FZN_RECONCILE_REPLY_MIN, &t)
	                      == FZN_RECONCILE_OK
	              && t.sent == 1u && !fzn_buckets_has(&B, FZN_BUCKETS_LOGS, id),
	      "a pusher with no reader sent a large item, or not the small one");
	/* A RECEIVER STAGING NOTHING refuses it whole, keeps the small one. */
	large_fresh();
	CHECK(large_fixture(s1, id), "fixture: again, to a receiver that will not stage");
	large_b.refuse_stage = 1;
	CHECK(fzn_reconcile_push(&A, FZN_BUCKETS_LOGS, NULL, &LARGE_A, NULL, large_to_b, NULL, reply,
	                         FZN_RECONCILE_REPLY_MIN, &t)
	                      == FZN_RECONCILE_OK
	              && t.sent == 1u && t.refused == 1u && !fzn_buckets_has(&B, FZN_BUCKETS_LOGS, id),
	      "a receiver that would not stage kept the large item");
}

int main(void)
{
	test_an_item_is_held_once();
	test_a_digest_is_the_set_s();
	test_ids_page_across_chunks();
	test_buckets_list_in_order();
	test_a_bucket_let_go_is_gone();
	test_a_crash_part_way_is_taken_once();
	test_a_crash_at_a_chunk_s_end();
	test_a_node_takes_a_peer_s_buckets();
	test_pieces_over_the_smallest_reply();
	test_what_is_not_taken();
	test_a_gate_serves_only_what_it_may();
	test_a_push_brings_a_peer_up();
	test_what_a_push_does_not_leave();
	test_large_items_pulled_and_pushed();
	printf("buckets_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
