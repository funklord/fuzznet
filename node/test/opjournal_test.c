/* opjournal_test -- the operation journal, sec 523: every write through the
 * ops it wraps entered by hash, the bytes kept beside it except a secret's,
 * a removal erasing its row's history, and the state replayed as it stood at
 * any entry. */

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

/* ---- a record store in memory, for the journal ------------------------------- */

#define RECS 64u

static struct rec {
	uint64_t seq;
	size_t len;
	uint8_t bytes[FZN_RECORD_MAX_LEN];
} recs[RECS];
static size_t n_recs;
static int recs_refuse;

static int rec_put(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream, uint64_t seq,
                   const uint8_t *bytes, size_t len)
{
	(void)ctx;
	(void)issuer;
	(void)stream;
	if (recs_refuse || n_recs >= RECS)
		return 0;
	recs[n_recs].seq = seq;
	recs[n_recs].len = len;
	memcpy(recs[n_recs].bytes, bytes, len);
	n_recs++;
	return 1;
}

static int rec_get(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream, uint64_t seq,
                   uint8_t *out, size_t cap, size_t *len_out, int *found_out)
{
	size_t i;

	(void)ctx;
	(void)issuer;
	(void)stream;
	*found_out = 0;
	for (i = 0; i < n_recs; i++)
		if (recs[i].seq == seq) {
			*found_out = 1;
			if (recs[i].len > cap)
				return 0;
			memcpy(out, recs[i].bytes, recs[i].len);
			*len_out = recs[i].len;
			return 1;
		}
	return 1;
}

/* ---- fixtures ------------------------------------------------------------------- */

static mem_t base, replayed;
static fzn_node_journal_t nj;
static fzn_record_store_ops_t rops = { rec_put, rec_get, NULL };
static fzn_opjournal_t oj;
static fzn_persist_ops_t base_ops, ops, into;

static void setup(void)
{
	memset(&base, 0, sizeof(base));
	memset(&replayed, 0, sizeof(replayed));
	memset(recs, 0, sizeof(recs));
	n_recs = 0;
	recs_refuse = 0;
	base_ops.load = mem_load;
	base_ops.save = mem_save;
	base_ops.list = mem_list;
	base_ops.remove = mem_remove;
	base_ops.ctx = &base;
	into = base_ops;
	into.ctx = &replayed;
	memset(&oj, 0, sizeof(oj));
	(void)fzn_node_journal_init_store(&nj, &rops, &SIGN, &HASH);
	oj.journal = &nj;
	oj.base = &base_ops;
	oj.issuer = SELF;
	oj.sign = &SIGN;
	oj.hash = &HASH;
	oj.now = now_ms;
	fzn_opjournal_ops(&oj, &ops);
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

static uint64_t entries(void)
{
	return fzn_node_journal_received(&nj, SELF, FZN_OPJOURNAL_STREAM);
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
	b[1] = 3u;
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
	CHECK(entries() == 5u && oj.unrecorded == 0u, "and is one entry each");
	kept = rows_in(&base, FZN_PERSIST_OP_BYTES);
	CHECK(kept == 4u, "the bytes of four are kept beside them, the secret's not");
	{
		fzn_opjournal_entry_t e;
		uint8_t buf[FZN_RECORD_MAX_LEN];
		fzn_record_t rec;
		static const uint8_t zero[32];

		CHECK(fzn_record_store_get(&nj.store, SELF, FZN_OPJOURNAL_STREAM, 5u, buf, sizeof(buf),
		                           &rec)
		                      == FZN_RECORD_STORE_OK
		              && fzn_opjournal_entry_open(fzn_record_body(rec), fzn_record_body_len(rec),
		                                          &e)
		              && e.slot == FZN_PERSIST_OWN_PREKEY && !(e.flags & FZN_OPJOURNAL_BYTES_KEPT)
		              && memcmp(e.hash, zero, sizeof(zero)) == 0 && e.length == 0u,
		      "the secret's entry says a write happened, with no hash and no length");
	}
	CHECK(fzn_opjournal_replay(&oj, 1u, &into, &t) && t.saved == 1u
	              && holds(&replayed, FZN_PERSIST_CONTACT, alice, "alice v1")
	              && !find(&replayed, FZN_PERSIST_CONTACT, bob),
	      "replayed to the first entry, the state is alice's first write alone");
	memset(&replayed, 0, sizeof(replayed));
	CHECK(fzn_opjournal_replay(&oj, 99u, &into, &t) && t.saved == 4u && t.skipped == 1u
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
	              && !find(&base, FZN_PERSIST_CONTACT, alice) && entries() == 4u
	              && rows_in(&base, FZN_PERSIST_OP_BYTES) == 1u,
	      "removing alice erases both versions' bytes, and enters the removal");
	CHECK(fzn_opjournal_replay(&oj, 2u, &into, &t) && t.saved == 0u && t.missing == 2u
	              && !find(&replayed, FZN_PERSIST_CONTACT, alice),
	      "so even replayed to before the removal, alice's content is gone, and counted");
	memset(&replayed, 0, sizeof(replayed));
	CHECK(fzn_opjournal_replay(&oj, 99u, &into, &t) && t.saved == 1u && t.removed == 1u
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
	CHECK(fzn_opjournal_replay(&oj, 99u, &into, &t) && t.saved == 0u && t.missing == 1u
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
	              && oj.unrecorded == 1u && entries() == 0u,
	      "a write whose entry will not take is still made, and counted unrecorded");
	recs_refuse = 0;
	CHECK(save(FZN_PERSIST_CONTACT, alice, "alice again") && entries() == 1u
	              && oj.unrecorded == 1u,
	      "and the next write is the journal's first entry, not one past a record never kept");
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
	              && rows_in(&base, FZN_PERSIST_OP_BYTES) == 2u && entries() == 3u,
	      "ten more past the budget erase the oldest ten, and every entry stays");
	CHECK(fzn_opjournal_replay(&oj, 99u, &into, &t) && t.saved == 2u && t.missing == 1u
	              && !find(&replayed, FZN_PERSIST_CONTACT, a)
	              && holds(&replayed, FZN_PERSIST_CONTACT, c, "cccccccccc"),
	      "so a replay rebuilds the two kept and counts the first missing");
	oj.kept = 0u;
	oj.oldest = 0u;
	CHECK(fzn_opjournal_start(&oj) && oj.kept == 20u && oj.oldest == 2u,
	      "a restart counts the kept bytes again, from the oldest still held");
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
	if (failures) {
		fprintf(stderr, "opjournal_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("opjournal_test: all %d checks passed\n", checks);
	return 0;
}
