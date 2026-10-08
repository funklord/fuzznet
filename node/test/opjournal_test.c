/* opjournal_test -- the operation journal, secs 523 and 524: every write
 * through the ops it wraps entered by hash, the bytes kept beside it except
 * a secret's, a removal erasing its row's history, the state replayed as it
 * stood at any entry, and generations that each open with a snapshot and
 * are dropped whole. */

#include "../opjournal.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (ok)
		return;
	failures++;
	fprintf(stderr, "  FAIL opjournal_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, what)

/* ---- a hash and a toy signer ---------------------------------------------- */

static int toy_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	(void)ctx;
	for (i = 0; i < in_len; i++) {
		h ^= in[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < out_len; i++) {
		h ^= (uint64_t)i + 0x9e3779b97f4a7c15ull;
		h *= 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 32);
	}
	return 1;
}

static const fzn_hash_ops_t HASH = { toy_hash, NULL };
static uint8_t SELF[FZN_PUBKEY_LEN];

static int toy_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	(void)ctx;
	return toy_hash(NULL, sig, FZN_SIG_LEN, msg, msg_len);
}

static int toy_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                      size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	(void)pubkey;
	toy_hash(NULL, want, sizeof(want), msg, msg_len);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

static const fzn_sign_ops_t SIGN = { toy_verify, toy_sign, NULL };

static uint64_t clock_ms = 1000u;

static uint64_t now_ms(void)
{
	return clock_ms++;
}

/* ---- a persist store in memory -------------------------------------------- */

#define ROWS 64u

typedef struct row {
	int used;
	fzn_persist_slot_t slot;
	int has_subject;
	uint8_t subject[FZN_PUBKEY_LEN];
	size_t len;
	uint8_t bytes[256];
} row_t;

typedef struct mem {
	row_t rows[ROWS];
} mem_t;

static row_t *find(mem_t *m, fzn_persist_slot_t slot, const uint8_t *subject)
{
	size_t i;

	for (i = 0; i < ROWS; i++)
		if (m->rows[i].used && m->rows[i].slot == slot
		    && m->rows[i].has_subject == (subject != NULL)
		    && (!subject || memcmp(m->rows[i].subject, subject, FZN_PUBKEY_LEN) == 0))
			return &m->rows[i];
	return NULL;
}

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	row_t *r = find((mem_t *)ctx, slot, subject);

	if (!r || r->len > cap)
		return 0;
	memcpy(out, r->bytes, r->len);
	*len = r->len;
	return 1;
}

static int mem_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                    const uint8_t *bytes, size_t len)
{
	mem_t *m = (mem_t *)ctx;
	row_t *r = find(m, slot, subject);
	size_t i;

	if (len > sizeof(r->bytes))
		return 0;
	for (i = 0; !r && i < ROWS; i++)
		if (!m->rows[i].used)
			r = &m->rows[i];
	if (!r)
		return 0;
	r->used = 1;
	r->slot = slot;
	r->has_subject = subject != NULL;
	if (subject)
		memcpy(r->subject, subject, FZN_PUBKEY_LEN);
	memcpy(r->bytes, bytes, len);
	r->len = len;
	return 1;
}

static int mem_list(void *ctx, fzn_persist_slot_t slot, uint8_t *out, size_t max, size_t *count)
{
	mem_t *m = (mem_t *)ctx;
	size_t i, n = 0;

	for (i = 0; i < ROWS; i++)
		if (m->rows[i].used && m->rows[i].slot == slot && m->rows[i].has_subject) {
			if (n >= max)
				return 0;
			memcpy(out + (n * FZN_PUBKEY_LEN), m->rows[i].subject, FZN_PUBKEY_LEN);
			n++;
		}
	*count = n;
	return 1;
}

static int mem_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	row_t *r = find((mem_t *)ctx, slot, subject);

	if (r)
		memset(r, 0, sizeof(*r));
	return 1;
}

static size_t rows_in(mem_t *m, fzn_persist_slot_t slot)
{
	size_t i, n = 0;

	for (i = 0; i < ROWS; i++)
		n += m->rows[i].used && m->rows[i].slot == slot;
	return n;
}

/* ---- generations in memory: a record store and a journal each ------------- */

#define RECS 48u
#define GENS FZN_OPJOURNAL_GENERATIONS_MAX

typedef struct gen {
	uint64_t generation;	/* the one this place holds, 0 for none */
	struct rec {
		uint64_t seq;
		size_t len;
		uint8_t bytes[FZN_RECORD_MAX_LEN];
	} recs[RECS];
	size_t n;
	fzn_node_journal_t nj;
} gen_t;

static gen_t gens[GENS];
static int recs_refuse;
static size_t opened, dropped;

static int rec_put(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream, uint64_t seq,
                   const uint8_t *bytes, size_t len)
{
	gen_t *g = (gen_t *)ctx;

	(void)issuer;
	(void)stream;
	if (recs_refuse || g->n >= RECS)
		return 0;
	g->recs[g->n].seq = seq;
	g->recs[g->n].len = len;
	memcpy(g->recs[g->n].bytes, bytes, len);
	g->n++;
	return 1;
}

static int rec_get(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream, uint64_t seq,
                   uint8_t *out, size_t cap, size_t *len_out, int *found_out)
{
	gen_t *g = (gen_t *)ctx;
	size_t i;

	(void)issuer;
	(void)stream;
	*found_out = 0;
	for (i = 0; i < g->n; i++)
		if (g->recs[i].seq == seq) {
			*found_out = 1;
			if (g->recs[i].len > cap)
				return 0;
			memcpy(out, g->recs[i].bytes, g->recs[i].len);
			*len_out = g->recs[i].len;
			return 1;
		}
	return 1;
}

static fzn_record_store_ops_t rops[GENS];

/* OPEN generation `generation`: the place it holds, emptied if it held
 * another, with a journal over it replaying what it holds. */
static fzn_node_journal_t *gen_open(void *ctx, uint64_t generation)
{
	gen_t *g = &gens[generation % GENS];

	(void)ctx;
	if (g->generation != generation) {
		memset(g, 0, sizeof(*g));
		g->generation = generation;
	}
	rops[generation % GENS].put = rec_put;
	rops[generation % GENS].get = rec_get;
	rops[generation % GENS].ctx = g;
	if (fzn_node_journal_init_store(&g->nj, &rops[generation % GENS], &SIGN, &HASH)
	            != FZN_NODE_JOURNAL_OK
	    || fzn_node_journal_follow_stream(&g->nj, SELF, FZN_OPJOURNAL_STREAM, NULL)
	               != FZN_NODE_JOURNAL_OK)
		return NULL;
	opened++;
	return &g->nj;
}

static void gen_drop(void *ctx, uint64_t generation)
{
	(void)ctx;
	if (gens[generation % GENS].generation == generation)
		memset(&gens[generation % GENS], 0, sizeof(gens[0]));
	dropped++;
}

static int gen_held(uint64_t generation)
{
	return gens[generation % GENS].generation == generation;
}

/* ---- fixtures ------------------------------------------------------------------- */

static mem_t base, replayed;
static fzn_opjournal_t oj;
static fzn_persist_ops_t base_ops, ops, into;

/* The journal's fields, over `base` as it stands, without starting it. */
static void wire_up(void)
{
	base_ops.load = mem_load;
	base_ops.save = mem_save;
	base_ops.list = mem_list;
	base_ops.remove = mem_remove;
	base_ops.ctx = &base;
	into = base_ops;
	into.ctx = &replayed;
	memset(&oj, 0, sizeof(oj));
	oj.generations.open = gen_open;
	oj.generations.drop = gen_drop;
	oj.keep = 2u;
	oj.base = &base_ops;
	oj.issuer = SELF;
	oj.sign = &SIGN;
	oj.hash = &HASH;
	oj.now = now_ms;
	fzn_opjournal_ops(&oj, &ops);
}

/* Everything empty, and the journal started: generation 1, opened over an
 * empty store, so its snapshot is the OPENED entry alone. */
static void setup(void)
{
	memset(&base, 0, sizeof(base));
	memset(&replayed, 0, sizeof(replayed));
	memset(gens, 0, sizeof(gens));
	recs_refuse = 0;
	opened = dropped = 0;
	wire_up();
	(void)fzn_opjournal_start(&oj);
}

static int holds(mem_t *m, fzn_persist_slot_t slot, const uint8_t *subject, const char *text)
{
	row_t *r = find(m, slot, subject);

	return r && r->len == strlen(text) && memcmp(r->bytes, text, r->len) == 0;
}

static int save(fzn_persist_slot_t slot, const uint8_t *subject, const char *text)
{
	return ops.save(ops.ctx, slot, subject, (const uint8_t *)text, strlen(text));
}

/* Entries in the newest generation, its OPENED entry among them. */
static uint64_t entries(void)
{
	return fzn_opjournal_entries(&oj, 0u);
}

/* ---- cases ---------------------------------------------------------------------- */

static void test_the_entry(void)
{
	fzn_opjournal_entry_t e, back;
	uint8_t b[FZN_OPJOURNAL_ENTRY_LEN];

	memset(&e, 0, sizeof(e));
	e.op = FZN_OPJOURNAL_OP_SAVE;
	e.slot = (uint8_t)FZN_PERSIST_CONTACT;
	e.flags = FZN_OPJOURNAL_HAS_SUBJECT | FZN_OPJOURNAL_BYTES_KEPT;
	memset(e.subject, 0x5a, sizeof(e.subject));
	memset(e.hash, 0x3c, sizeof(e.hash));
	e.length = 77u;
	CHECK(fzn_opjournal_entry_write(&e, b) && b[0] == 1u && b[2] == FZN_PERSIST_CONTACT
	              && b[71] == 77u && fzn_opjournal_entry_open(b, sizeof(b), &back)
	              && memcmp(&back, &e, sizeof(e)) == 0,
	      "an entry reads back as written, 72 bytes at the schema's offsets");
	CHECK(!fzn_opjournal_entry_open(b, sizeof(b) - 1u, &back), "a short entry is refused");
	b[0] = 2u;
	CHECK(!fzn_opjournal_entry_open(b, sizeof(b), &back), "and an unknown version");
	b[0] = 1u;
	b[1] = 4u;
	CHECK(!fzn_opjournal_entry_open(b, sizeof(b), &back), "and an unknown op");
	b[1] = 1u;
	b[3] = 4u;
	CHECK(!fzn_opjournal_entry_open(b, sizeof(b), &back), "and an unknown flag");
	e.flags = 4u;
	CHECK(!fzn_opjournal_entry_write(&e, b), "which is not written either");
}

static void test_writes_and_replay(void)
{
	uint8_t alice[FZN_PUBKEY_LEN], bob[FZN_PUBKEY_LEN];
	fzn_opjournal_replay_tally_t t;
	size_t kept;

	setup();
	memset(alice, 0xa1, sizeof(alice));
	memset(bob, 0xb2, sizeof(bob));
	CHECK(save(FZN_PERSIST_CONTACT, alice, "alice v1") && save(FZN_PERSIST_CONTACT, bob, "bob")
	              && save(FZN_PERSIST_CONTACT, alice, "alice v2")
	              && save(FZN_PERSIST_TRUST, NULL, "the anchor")
	              && save(FZN_PERSIST_OWN_PREKEY, NULL, "a secret"),
	      "fixture: five writes through the journal");
	CHECK(holds(&base, FZN_PERSIST_CONTACT, alice, "alice v2")
	              && holds(&base, FZN_PERSIST_OWN_PREKEY, NULL, "a secret"),
	      "every write reaches the store it wraps, unchanged");
	CHECK(entries() == 6u && oj.unrecorded == 0u,
	      "and is one entry each, after the empty snapshot's OPENED");
	kept = rows_in(&base, FZN_PERSIST_OP_BYTES);
	CHECK(kept == 4u, "the bytes of four are kept beside them, the secret's not");
	{
		fzn_opjournal_entry_t e;
		uint8_t buf[FZN_RECORD_MAX_LEN];
		fzn_record_t rec;
		static const uint8_t zero[32];

		CHECK(fzn_record_store_get(&gens[1].nj.store, SELF, FZN_OPJOURNAL_STREAM, 6u, buf,
		                           sizeof(buf), &rec)
		                      == FZN_RECORD_STORE_OK
		              && fzn_opjournal_entry_open(fzn_record_body(rec), fzn_record_body_len(rec),
		                                          &e)
		              && e.slot == FZN_PERSIST_OWN_PREKEY && !(e.flags & FZN_OPJOURNAL_BYTES_KEPT)
		              && memcmp(e.hash, zero, sizeof(zero)) == 0 && e.length == 0u,
		      "the secret's entry says a write happened, with no hash and no length");
	}
	CHECK(fzn_opjournal_replay(&oj, 0u, 2u, &into, &t) && t.saved == 1u
	              && holds(&replayed, FZN_PERSIST_CONTACT, alice, "alice v1")
	              && !find(&replayed, FZN_PERSIST_CONTACT, bob),
	      "replayed to the first entry, the state is alice's first write alone");
	memset(&replayed, 0, sizeof(replayed));
	CHECK(fzn_opjournal_replay(&oj, 0u, 99u, &into, &t) && t.saved == 4u && t.skipped == 1u
	              && holds(&replayed, FZN_PERSIST_CONTACT, alice, "alice v2")
	              && holds(&replayed, FZN_PERSIST_CONTACT, bob, "bob")
	              && holds(&replayed, FZN_PERSIST_TRUST, NULL, "the anchor")
	              && !find(&replayed, FZN_PERSIST_OWN_PREKEY, NULL),
	      "replayed whole, the replayable slots are as they stand, the secret not rebuilt");
}

static void test_a_removal_erases_its_history(void)
{
	uint8_t alice[FZN_PUBKEY_LEN], bob[FZN_PUBKEY_LEN];
	fzn_opjournal_replay_tally_t t;

	setup();
	memset(alice, 0xa1, sizeof(alice));
	memset(bob, 0xb2, sizeof(bob));
	CHECK(save(FZN_PERSIST_CONTACT, alice, "alice v1") && save(FZN_PERSIST_CONTACT, alice, "alice v2")
	              && save(FZN_PERSIST_CONTACT, bob, "bob")
	              && rows_in(&base, FZN_PERSIST_OP_BYTES) == 3u,
	      "fixture: two versions of alice and one of bob, kept");
	CHECK(ops.remove(ops.ctx, FZN_PERSIST_CONTACT, alice)
	              && !find(&base, FZN_PERSIST_CONTACT, alice) && entries() == 5u
	              && rows_in(&base, FZN_PERSIST_OP_BYTES) == 1u,
	      "removing alice erases both versions' bytes, and enters the removal");
	CHECK(fzn_opjournal_replay(&oj, 0u, 3u, &into, &t) && t.saved == 0u && t.missing == 2u
	              && !find(&replayed, FZN_PERSIST_CONTACT, alice),
	      "so even replayed to before the removal, alice's content is gone, and counted");
	memset(&replayed, 0, sizeof(replayed));
	CHECK(fzn_opjournal_replay(&oj, 0u, 99u, &into, &t) && t.saved == 1u && t.removed == 1u
	              && holds(&replayed, FZN_PERSIST_CONTACT, bob, "bob"),
	      "while bob's history is untouched");
}

static void test_tampered_bytes_are_not_believed(void)
{
	uint8_t alice[FZN_PUBKEY_LEN];
	fzn_opjournal_replay_tally_t t;
	size_t i;

	setup();
	memset(alice, 0xa1, sizeof(alice));
	CHECK(save(FZN_PERSIST_CONTACT, alice, "alice"), "fixture: one write");
	for (i = 0; i < ROWS; i++)
		if (base.rows[i].used && base.rows[i].slot == FZN_PERSIST_OP_BYTES)
			base.rows[i].bytes[0] ^= 1u;
	CHECK(fzn_opjournal_replay(&oj, 0u, 99u, &into, &t) && t.saved == 0u && t.missing == 1u
	              && !find(&replayed, FZN_PERSIST_CONTACT, alice),
	      "kept bytes that no longer match their entry's hash are not replayed");
}

static void test_a_journal_that_refuses(void)
{
	uint8_t alice[FZN_PUBKEY_LEN];

	setup();
	memset(alice, 0xa1, sizeof(alice));
	recs_refuse = 1;
	CHECK(save(FZN_PERSIST_CONTACT, alice, "alice") && holds(&base, FZN_PERSIST_CONTACT, alice,
	                                                        "alice")
	              && oj.unrecorded == 1u && entries() == 1u,
	      "a write whose entry will not take is still made, and counted unrecorded");
	CHECK(rows_in(&base, FZN_PERSIST_OP_BYTES) == 0u && oj.kept == 0u,
	      "and the bytes kept for it are taken back out, and counted out");
	recs_refuse = 0;
	CHECK(save(FZN_PERSIST_CONTACT, alice, "alice again") && entries() == 2u
	              && oj.unrecorded == 1u && rows_in(&base, FZN_PERSIST_OP_BYTES) == 1u,
	      "and the next write is the entry after OPENED, not one past a record never kept");
}

/* THE BUDGET: past it the oldest kept bytes go first, their entries stay,
 * and a restart counts what is held again. */
static void test_the_budget(void)
{
	uint8_t a[FZN_PUBKEY_LEN], b[FZN_PUBKEY_LEN], c[FZN_PUBKEY_LEN];
	fzn_opjournal_replay_tally_t t;

	setup();
	oj.budget = 20u;
	memset(a, 0xa1, sizeof(a));
	memset(b, 0xb2, sizeof(b));
	memset(c, 0xc3, sizeof(c));
	CHECK(save(FZN_PERSIST_CONTACT, a, "aaaaaaaaaa") && save(FZN_PERSIST_CONTACT, b, "bbbbbbbbbb")
	              && oj.kept == 20u && rows_in(&base, FZN_PERSIST_OP_BYTES) == 2u,
	      "fixture: twenty bytes kept, the budget");
	CHECK(save(FZN_PERSIST_CONTACT, c, "cccccccccc") && oj.kept == 20u
	              && rows_in(&base, FZN_PERSIST_OP_BYTES) == 2u && entries() == 4u,
	      "ten more past the budget erase the oldest ten, and every entry stays");
	CHECK(fzn_opjournal_replay(&oj, 0u, 99u, &into, &t) && t.saved == 2u && t.missing == 1u
	              && !find(&replayed, FZN_PERSIST_CONTACT, a)
	              && holds(&replayed, FZN_PERSIST_CONTACT, c, "cccccccccc"),
	      "so a replay rebuilds the two kept and counts the first missing");
	oj.kept = 0u;
	oj.oldest = 0u;
	CHECK(fzn_opjournal_start(&oj) && oj.kept == 20u && oj.oldest_generation == 1u
	              && oj.oldest == 3u,
	      "a restart counts the kept bytes again, from the oldest still held");
}

/* ---- generations, sec 524 ---------------------------------------------------- */

/* THE FIRST GENERATION OPENS WITH A SNAPSHOT of what was written before the
 * journal was turned on, so it replays alone -- a secret aside. */
static void test_the_first_generation_takes_a_snapshot(void)
{
	uint8_t alice[FZN_PUBKEY_LEN];
	fzn_opjournal_replay_tally_t t;
	fzn_opjournal_entry_t e;
	uint8_t buf[FZN_RECORD_MAX_LEN];
	fzn_record_t rec;

	memset(&base, 0, sizeof(base));
	memset(&replayed, 0, sizeof(replayed));
	memset(gens, 0, sizeof(gens));
	memset(alice, 0xa1, sizeof(alice));
	wire_up();
	CHECK(base_ops.save(&base, FZN_PERSIST_CONTACT, alice, (const uint8_t *)"alice", 5u)
	              && base_ops.save(&base, FZN_PERSIST_TRUST, NULL, (const uint8_t *)"anchor", 6u)
	              && base_ops.save(&base, FZN_PERSIST_OWN_PREKEY, NULL,
	                               (const uint8_t *)"secret", 6u),
	      "fixture: three rows written before the journal");
	CHECK(fzn_opjournal_start(&oj) && oj.first == 1u && oj.last == 1u && entries() == 3u
	              && rows_in(&base, FZN_PERSIST_OP_BYTES) == 2u && oj.kept == 11u,
	      "started, generation 1 snapshots the two rows that keep bytes, and not the secret");
	CHECK(fzn_record_store_get(&gens[1].nj.store, SELF, FZN_OPJOURNAL_STREAM, 3u, buf,
	                           sizeof(buf), &rec)
	                      == FZN_RECORD_STORE_OK
	              && fzn_opjournal_entry_open(fzn_record_body(rec), fzn_record_body_len(rec), &e)
	              && e.op == FZN_OPJOURNAL_OP_OPENED && e.length == 2u,
	      "and its OPENED entry counts them");
	CHECK(fzn_opjournal_replay(&oj, 0u, 99u, &into, &t) && t.saved == 2u
	              && holds(&replayed, FZN_PERSIST_CONTACT, alice, "alice")
	              && holds(&replayed, FZN_PERSIST_TRUST, NULL, "anchor")
	              && !find(&replayed, FZN_PERSIST_OWN_PREKEY, NULL),
	      "so a replay rebuilds what was there before any write it entered");
}

/* ROTATION: the next generation opens with a snapshot of the state, the
 * oldest past `keep` is dropped whole, bytes and all, and each generation
 * replays alone. */
static void test_generations_rotate(void)
{
	uint8_t a[FZN_PUBKEY_LEN], b[FZN_PUBKEY_LEN], c[FZN_PUBKEY_LEN];
	fzn_opjournal_replay_tally_t t;

	setup();
	oj.rotate_at = 3u;
	memset(a, 0xa1, sizeof(a));
	memset(b, 0xb2, sizeof(b));
	memset(c, 0xc3, sizeof(c));
	CHECK(save(FZN_PERSIST_CONTACT, a, "a1") && save(FZN_PERSIST_CONTACT, b, "b1")
	              && oj.last == 1u && entries() == 3u,
	      "fixture: generation 1, short of its three writes");
	CHECK(save(FZN_PERSIST_CONTACT, a, "a2") && oj.first == 1u && oj.last == 2u
	              && entries() == 3u,
	      "the third write opens generation 2, a snapshot of two rows and its OPENED");
	CHECK(fzn_opjournal_replay(&oj, 2u, 99u, &into, &t) && t.saved == 2u
	              && holds(&replayed, FZN_PERSIST_CONTACT, a, "a2")
	              && holds(&replayed, FZN_PERSIST_CONTACT, b, "b1"),
	      "generation 2 replays alone to the state");
	memset(&replayed, 0, sizeof(replayed));
	CHECK(fzn_opjournal_replay(&oj, 1u, 2u, &into, &t) && t.saved == 1u
	              && holds(&replayed, FZN_PERSIST_CONTACT, a, "a1")
	              && !find(&replayed, FZN_PERSIST_CONTACT, b),
	      "and generation 1 still replays to a point before it");
	CHECK(save(FZN_PERSIST_CONTACT, c, "c1") && save(FZN_PERSIST_CONTACT, c, "c2")
	              && oj.last == 2u,
	      "the snapshot does not count toward a generation's writes");
	CHECK(save(FZN_PERSIST_CONTACT, c, "c3") && oj.first == 2u && oj.last == 3u
	              && entries() == 4u && dropped == 1u && !gen_held(1u) && gen_held(2u)
	              && gen_held(3u),
	      "generation 3 opens, and generation 1, past the two kept, is dropped whole");
	CHECK(rows_in(&base, FZN_PERSIST_OP_BYTES) == 8u && oj.kept == 16u,
	      "with its bytes: generation 2's five and generation 3's three are what is kept");
	CHECK(save(FZN_PERSIST_CONTACT, c, "c4") && oj.last == 3u,
	      "and a snapshot as large as a generation does not rotate on the next write");
	memset(&replayed, 0, sizeof(replayed));
	CHECK(!fzn_opjournal_replay(&oj, 1u, 99u, &into, &t),
	      "a dropped generation is not replayed");
	CHECK(ops.remove(ops.ctx, FZN_PERSIST_CONTACT, a)
	              && rows_in(&base, FZN_PERSIST_OP_BYTES) == 7u,
	      "removing a erases its bytes from both generations' snapshots");
	CHECK(fzn_opjournal_replay(&oj, 2u, 99u, &into, &t) && t.missing == 1u
	              && !find(&replayed, FZN_PERSIST_CONTACT, a),
	      "so neither replays it");
}

/* A SNAPSHOT A CRASH CUT SHORT is dropped at start: its generation has no
 * OPENED entry, so it would replay to something that was never the state. */
static void test_a_cut_short_snapshot_is_dropped(void)
{
	uint8_t a[FZN_PUBKEY_LEN];
	fzn_opjournal_entry_t e;
	uint8_t body[FZN_OPJOURNAL_ENTRY_LEN];
	fzn_node_journal_t *nj;
	fzn_opjournal_replay_tally_t t;

	setup();
	memset(a, 0xa1, sizeof(a));
	CHECK(save(FZN_PERSIST_CONTACT, a, "a1"), "fixture: generation 1 holds a write");
	/* WHAT A CRASH LEAVES: generation 2 holding one snapshot entry and no
	 * OPENED, written as the rotation would have. */
	nj = gen_open(NULL, 2u);
	memset(&e, 0, sizeof(e));
	e.op = FZN_OPJOURNAL_OP_SAVE;
	e.slot = (uint8_t)FZN_PERSIST_CONTACT;
	e.flags = FZN_OPJOURNAL_HAS_SUBJECT;
	memcpy(e.subject, a, sizeof(a));
	CHECK(nj && fzn_opjournal_entry_write(&e, body)
	              && fzn_node_journal_append_on(nj, SELF, FZN_OPJOURNAL_STREAM, &SIGN,
	                                            FZN_OPJOURNAL_KIND, e.subject, body,
	                                            sizeof(body), 1u, NULL)
	                         == FZN_NODE_JOURNAL_OK,
	      "fixture: generation 2, its snapshot cut short");
	/* HELD AS IT IS, it does not replay: its snapshot is not whole. */
	oj.last = 2u;
	oj.journals[2u % GENS] = nj;
	CHECK(!fzn_opjournal_replay(&oj, 2u, 99u, &into, &t),
	      "a generation with no OPENED entry is refused a replay");
	oj.last = 1u;
	oj.journals[2u % GENS] = NULL;
	wire_up();
	oj.first = 1u;
	oj.last = 2u;
	dropped = 0;
	CHECK(fzn_opjournal_start(&oj) && oj.first == 1u && oj.last == 1u && dropped == 1u
	              && !gen_held(2u),
	      "a restart drops it, and generation 1 is the newest again");
	CHECK(save(FZN_PERSIST_CONTACT, a, "a2") && entries() == 3u,
	      "where the next write is entered");
}

/* A ROTATION THAT CANNOT TAKE A WHOLE SNAPSHOT is put off, counted, and not
 * tried again on every write. */
static void test_a_rotation_is_put_off(void)
{
	uint8_t a[FZN_PUBKEY_LEN];
	size_t before, i;
	int ok = 1;

	setup();
	oj.rotate_at = 8u;
	memset(a, 0xa1, sizeof(a));
	base_ops.list = NULL;
	before = opened;
	for (i = 0; i < 8u; i++)
		ok &= save(FZN_PERSIST_CONTACT, a, "a");
	CHECK(ok && oj.last == 1u && oj.unrotated == 1u && opened == before + 1u && dropped == 1u,
	      "a store that cannot list leaves generation 1 the newest, the attempt dropped");
	CHECK(save(FZN_PERSIST_CONTACT, a, "a") && oj.unrotated == 1u && opened == before + 1u,
	      "and the next write does not try again at once");
	base_ops.list = mem_list;
	CHECK(save(FZN_PERSIST_CONTACT, a, "a") && oj.last == 2u,
	      "a quarter of a generation on, it does");
}

static void test_keep_is_bounded(void)
{
	setup();
	wire_up();
	oj.keep = 0u;
	CHECK(!fzn_opjournal_start(&oj), "keeping no generation is refused");
	oj.keep = FZN_OPJOURNAL_GENERATIONS_MAX;
	CHECK(!fzn_opjournal_start(&oj),
	      "and keeping as many as can be open, which leaves a rotation nowhere to go");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	check_at(0, __LINE__, "deliberate");
	CHECK(failures == before + 1, "a failure counts");
	failures = before;
	checks -= 1;
}

int main(void)
{
	memset(SELF, 0x11, sizeof(SELF));
	test_the_suite_can_tell_pass_from_fail();
	test_the_entry();
	test_writes_and_replay();
	test_a_removal_erases_its_history();
	test_tampered_bytes_are_not_believed();
	test_a_journal_that_refuses();
	test_the_budget();
	test_the_first_generation_takes_a_snapshot();
	test_generations_rotate();
	test_a_cut_short_snapshot_is_dropped();
	test_a_rotation_is_put_off();
	test_keep_is_bounded();
	if (failures) {
		fprintf(stderr, "opjournal_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("opjournal_test: all %d checks passed\n", checks);
	return 0;
}
