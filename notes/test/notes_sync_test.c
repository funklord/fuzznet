/* notes_sync_test -- two nodes' notes converging: an index, then only the
 * records a node lacks or holds older, admitted as any record is. sec 432.
 *
 * Two stores in one process over `persist/`'s seam in memory, each its own
 * table, and the "peer" is a function handing a request to the other store's
 * `fzn_notes_sync_answer` -- so a case can shrink a reply, push a record
 * nobody asked for, or answer with junk. The signer is a toy whose public key
 * is its secret. */

#include "../author.h"
#include "blob_stub.h"
#include "chain_stub.h"
#include "../purge.h"
#include "../received.h"
#include "../share.h"
#include "../sync.h"

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
	fprintf(stderr, "  FAIL notes_sync_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, what)

/* ---- a hash, a toy signer, randomness ----------------------------------- */

static void fnv(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len, uint8_t *out,
                size_t out_len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	for (i = 0; i < a_len; i++) {
		h ^= a[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < b_len; i++) {
		h ^= b[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < out_len; i++) {
		h ^= (uint64_t)i + 0x9e3779b97f4a7c15ull;
		h *= 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 32);
	}
}

static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	(void)ctx;
	fnv(in, in_len, NULL, 0, out, out_len);
	return 1;
}

static const fzn_hash_ops_t HASH = { stub_hash, NULL };

static int toy_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	fnv((const uint8_t *)ctx, FZN_PUBKEY_LEN, msg, msg_len, sig, FZN_SIG_LEN);
	return 1;
}

static int toy_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                      size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	fnv(pubkey, FZN_PUBKEY_LEN, msg, msg_len, want, sizeof(want));
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

static uint8_t KEY_A[FZN_PUBKEY_LEN], KEY_B[FZN_PUBKEY_LEN];

static uint64_t counter = 3;

static int counter_fill(void *ctx, uint8_t *out, size_t len)
{
	size_t i;

	(void)ctx;
	for (i = 0; i < len; i++)
		out[i] = (uint8_t)((counter * 131u + i * 7u) >> (i % 5u));
	counter++;
	return 1;
}

static const fzn_random_ops_t RNG = { counter_fill, NULL };

/* ---- persist over memory, one table per store --------------------------- */

#define MEM_ROWS 128u

struct row {
	int used;
	fzn_persist_slot_t slot;
	int has_subject;
	uint8_t subject[FZN_PUBKEY_LEN];
	/* Room for a shared note's row: a sharer and a claim key before the
	 * record. sec 437. */
	uint8_t bytes[FZN_PERSIST_HEAD_LEN + (2u * FZN_PUBKEY_LEN) + FZN_RECORD_MAX_LEN];
	size_t len;
};

struct table {
	struct row rows[MEM_ROWS];
};

static struct row *find(struct table *t, fzn_persist_slot_t slot, const uint8_t *subject)
{
	size_t i;

	for (i = 0; i < MEM_ROWS; i++)
		if (t->rows[i].used && t->rows[i].slot == slot
		    && t->rows[i].has_subject == (subject != NULL)
		    && (!subject || memcmp(t->rows[i].subject, subject, FZN_PUBKEY_LEN) == 0))
			return &t->rows[i];
	return NULL;
}

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	struct row *r = find((struct table *)ctx, slot, subject);

	if (!r || r->len > cap)
		return 0;
	memcpy(out, r->bytes, r->len);
	*len = r->len;
	return 1;
}

static int mem_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                    const uint8_t *bytes, size_t len)
{
	struct table *t = (struct table *)ctx;
	struct row *r = find(t, slot, subject);
	size_t i;

	for (i = 0; !r && i < MEM_ROWS; i++)
		if (!t->rows[i].used)
			r = &t->rows[i];
	if (!r || len > sizeof(r->bytes))
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
	struct table *t = (struct table *)ctx;
	size_t i, n = 0;

	for (i = 0; i < MEM_ROWS; i++)
		if (t->rows[i].used && t->rows[i].slot == slot && t->rows[i].has_subject) {
			if (n == max)
				return 0;
			memcpy(out + (n * FZN_PUBKEY_LEN), t->rows[i].subject, FZN_PUBKEY_LEN);
			n++;
		}
	*count = n;
	return 1;
}

static int mem_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	struct row *r = find((struct table *)ctx, slot, subject);

	if (r)
		r->used = 0;
	return 1;
}

/* A REMOVAL THAT FAILS FOR A NOTE while `refuse_note_removal` is set: the
 * erase after a purge's last answer, failing. */
static int refuse_note_removal;

static int remove_unless_note(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	if (refuse_note_removal && slot == FZN_PERSIST_NOTE)
		return 0;
	return mem_remove(ctx, slot, subject);
}

static struct table table_a, table_b;
static fzn_persist_ops_t ops_a = { mem_load, mem_save, mem_list, mem_remove, &table_a };
static fzn_persist_ops_t ops_b = { mem_load, mem_save, mem_list, mem_remove, &table_b };
static fzn_notes_store_t store_a, store_b;

/* ---- writing notes on A -------------------------------------------------- */

static fzn_notes_writer_t writers[2];
static fzn_notes_view_t view;
static fzn_sign_ops_t sign_a = { toy_verify, toy_sign, KEY_A };
static fzn_sign_ops_t sign_b = { toy_verify, toy_sign, KEY_B };

static fzn_notes_policy_t both(void)
{
	memcpy(writers[0].key, KEY_A, FZN_PUBKEY_LEN);
	memcpy(writers[1].key, KEY_B, FZN_PUBKEY_LEN);
	return fzn_notes_policy_writers(writers, 2u);
}

static fzn_notes_author_t author_on(fzn_notes_store_t *store, uint8_t *key, fzn_sign_ops_t *sign)
{
	fzn_notes_author_t a;

	a.store = store;
	a.view = &view;
	a.issuer = key;
	a.sign = sign;
	a.rng = &RNG;
	a.policy = both();
	blob_stub_attach(&a);
	chain_stub_attach(&a);
	return a;
}

static int write(fzn_notes_author_t *a, const char *title, uint8_t id[FZN_TREE_ID_LEN])
{
	static const uint8_t top[FZN_TREE_ID_LEN];
	fzn_note_t note;

	memset(&note, 0, sizeof(note));
	note.title = (const uint8_t *)title;
	note.title_len = strlen(title);
	return fzn_notes_create(a, top, FZN_NOTE_TYPE_NOTE, &note, 1u, id) == FZN_NOTES_OK;
}

static size_t held(fzn_notes_store_t *store)
{
	uint8_t keys[FZN_NOTES_MAX][FZN_PUBKEY_LEN];
	size_t n = 0;

	return fzn_notes_claims(store, keys, FZN_NOTES_MAX, &n) == FZN_NOTES_OK ? n : 0u;
}

static int title_is(fzn_notes_store_t *store, const uint8_t id[FZN_TREE_ID_LEN],
                    const uint8_t *writer, const char *title)
{
	uint8_t out[FZN_RECORD_MAX_LEN];
	size_t len = 0;
	fzn_record_t rec;
	fzn_tree_node_t node;
	const uint8_t *t;
	size_t t_len = 0;

	return fzn_notes_get(store, id, writer, out, sizeof(out), &len) == FZN_NOTES_OK
	       && fzn_record_open(out, len, &rec) == FZN_RECORD_OK
	       && fzn_tree_open(rec, &node) == FZN_TREE_OK
	       && (t = blob_stub_title(&node, &t_len)) != NULL && t_len == strlen(title)
	       && memcmp(t, title, t_len) == 0;
}

/* ---- the peer ------------------------------------------------------------ */

typedef struct peer {
	const fzn_notes_store_t *store;
	size_t cap;        /* below the puller's own, or 0 */
	int junk;          /* answer with nonsense */
	int quiet;         /* answer nothing */
	int push;          /* answer a records query with a record of `push_id` */
	uint8_t push_id[FZN_TREE_ID_LEN];
	unsigned asked;
	const uint8_t *sender; /* who the asker is, to the answering store */
} peer_t;

static int ask(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
               size_t reply_cap, size_t *reply_len)
{
	peer_t *p = (peer_t *)ctx;
	size_t cap = p->cap && p->cap < reply_cap ? p->cap : reply_cap;

	p->asked++;
	if (p->quiet)
		return 0;
	if (p->junk) {
		memset(reply, 0x02, 9u);
		*reply_len = 9u;
		return 1;
	}
	*reply_len = fzn_notes_sync_answer(p->store, both(), p->sender, 1u, request, request_len,
	                                   reply, cap);
	if (p->push && request_len >= 3u && request[1] == FZN_NOTES_SYNC_RECORDS_QUERY) {
		/* A RECORD NOBODY ASKED FOR, in place of what was. */
		uint8_t record[FZN_RECORD_MAX_LEN];
		size_t len = 0;

		if (fzn_notes_get(p->store, p->push_id, KEY_A, record, sizeof(record), &len)
		    == FZN_NOTES_OK) {
			reply[2] = 1u;
			reply[3] = (uint8_t)(len >> 8);
			reply[4] = (uint8_t)len;
			memcpy(reply + 5, record, len);
			*reply_len = 5u + len;
		}
	}
	return *reply_len > 0u;
}

/* ---- cases --------------------------------------------------------------- */

static void reset(void)
{
	memset(&table_a, 0, sizeof(table_a));
	memset(&table_b, 0, sizeof(table_b));
}

static void test_converge(void)
{
	fzn_notes_author_t a = author_on(&store_a, KEY_A, &sign_a);
	peer_t from_a = { &store_a, 0, 0, 0, 0, { 0 }, 0, NULL };
	peer_t from_b = { &store_b, 0, 0, 0, 0, { 0 }, 0, NULL };
	fzn_notes_sync_tally_t t;
	uint8_t one[FZN_TREE_ID_LEN], two[FZN_TREE_ID_LEN], three[FZN_TREE_ID_LEN];
	fzn_note_t with;

	reset();
	CHECK(write(&a, "one", one) && write(&a, "two", two) && write(&a, "three", three),
	      "fixture: three notes on A");
	CHECK(fzn_notes_sync_pull(&store_b, both(), &sign_b, ask, &from_a, &t) == FZN_NOTES_SYNC_OK
	              && t.offered == 3u && t.fetched == 3u && t.learned == 3u && t.refused == 0u
	              && held(&store_b) == 3u,
	      "B pulls A's three notes");
	CHECK(title_is(&store_b, two, KEY_A, "two"), "and holds them as A wrote them");
	CHECK(fzn_notes_sync_pull(&store_b, both(), &sign_b, ask, &from_a, &t) == FZN_NOTES_SYNC_OK
	              && t.offered == 3u && t.fetched == 0u && t.learned == 0u,
	      "a second pull fetches nothing: the index says B is current");

	memset(&with, 0, sizeof(with));
	with.title = (const uint8_t *)"two, renamed";
	with.title_len = 12u;
	CHECK(fzn_notes_edit(&a, two, FZN_NOTES_EDIT_TITLE, &with, 0u, 0u, 2u) == FZN_NOTES_OK,
	      "fixture: A renames one");
	CHECK(fzn_notes_sync_pull(&store_b, both(), &sign_b, ask, &from_a, &t) == FZN_NOTES_SYNC_OK
	              && t.fetched == 1u && t.learned == 1u
	              && title_is(&store_b, two, KEY_A, "two, renamed"),
	      "after an edit, only the edited claim travels");
	CHECK(fzn_notes_sync_pull(&store_a, both(), &sign_a, ask, &from_b, &t) == FZN_NOTES_SYNC_OK
	              && t.offered == 3u && t.fetched == 0u,
	      "and A, pulling from B, finds nothing newer");

	CHECK(fzn_notes_sync_pull(&store_b, fzn_notes_policy_writers(writers + 1, 1u), &sign_b, ask,
	                          &from_a, &t)
	                      == FZN_NOTES_SYNC_OK
	              && t.learned == 0u,
	      "fixture: nothing to learn");
	reset();
	CHECK(write(&a, "one", one), "fixture: a note on A");
	CHECK(fzn_notes_sync_pull(&store_b, fzn_notes_policy_writers(writers + 1, 1u), &sign_b, ask,
	                          &from_a, &t)
	                      == FZN_NOTES_SYNC_OK
	              && t.fetched == 1u && t.refused == 1u && t.learned == 0u && held(&store_b) == 0u,
	      "a node B does not admit has its notes fetched and refused");
}

static void test_purge_rules(void)
{
	fzn_notes_author_t a = author_on(&store_a, KEY_A, &sign_a);
	peer_t from_a = { &store_a, 0, 0, 0, 0, { 0 }, 0, NULL };
	fzn_notes_sync_tally_t t;
	fzn_notes_writer_t ask_b;
	uint8_t x[FZN_TREE_ID_LEN], y[FZN_TREE_ID_LEN];
	int complete = 0;
	size_t erased = 0;
	fzn_note_t with;

	reset();
	memcpy(ask_b.key, KEY_B, FZN_PUBKEY_LEN);
	CHECK(write(&a, "x", x) && write(&a, "y", y), "fixture: two notes on A");
	CHECK(fzn_notes_sync_pull(&store_b, both(), &sign_b, ask, &from_a, &t) == FZN_NOTES_SYNC_OK
	              && held(&store_b) == 2u,
	      "fixture: B holds both");

	/* THE RESURRECTION: A purges x asking B; B consents and erases; A's
	 * next round must not hand x back. */
	CHECK(fzn_notes_purge_add(&store_a, x, fzn_notes_asking(&ask_b, 1u), 5u, &complete)
	                      == FZN_NOTES_OK
	              && !complete,
	      "fixture: A purges x, asking B");
	CHECK(fzn_notes_erase_note(&store_b, x, &erased) == FZN_NOTES_OK && erased == 1u,
	      "fixture: B consents and erases x");
	CHECK(fzn_notes_sync_pull(&store_b, both(), &sign_b, ask, &from_a, &t) == FZN_NOTES_SYNC_OK
	              && t.offered == 1u && held(&store_b) == 1u,
	      "A's index leaves out a note pending purge, so B does not take it back");

	/* AND THE PULLER'S SIDE: B is purging y, A edits it. */
	CHECK(fzn_notes_purge_add(&store_b, y, fzn_notes_asking(&ask_b, 1u), 6u, &complete)
	                      == FZN_NOTES_OK,
	      "fixture: B purges y");
	memset(&with, 0, sizeof(with));
	with.title = (const uint8_t *)"y again";
	with.title_len = 7u;
	CHECK(fzn_notes_edit(&a, y, FZN_NOTES_EDIT_TITLE, &with, 0u, 0u, 7u) == FZN_NOTES_OK,
	      "fixture: A edits y");
	CHECK(fzn_notes_sync_pull(&store_b, both(), &sign_b, ask, &from_a, &t) == FZN_NOTES_SYNC_OK
	              && t.fetched == 1u && t.refused == 1u && t.learned == 0u
	              && title_is(&store_b, y, KEY_A, "y"),
	      "a note this node is purging is refused when it arrives");
}

static void test_peers_that_misbehave(void)
{
	fzn_notes_author_t a = author_on(&store_a, KEY_A, &sign_a);
	peer_t junk = { &store_a, 0, 1, 0, 0, { 0 }, 0, NULL };
	peer_t quiet = { &store_a, 0, 0, 1, 0, { 0 }, 0, NULL };
	peer_t pusher = { &store_a, 0, 0, 0, 1, { 0 }, 0, NULL };
	fzn_notes_sync_tally_t t;
	uint8_t one[FZN_TREE_ID_LEN], two[FZN_TREE_ID_LEN];
	peer_t from_a = { &store_a, 0, 0, 0, 0, { 0 }, 0, NULL };

	reset();
	CHECK(write(&a, "one", one) && write(&a, "two", two), "fixture: two notes on A");
	CHECK(fzn_notes_sync_pull(&store_b, both(), &sign_b, ask, &junk, &t) == FZN_NOTES_SYNC_SHAPE
	              && held(&store_b) == 0u,
	      "a peer answering nonsense is SHAPE, and nothing is taken");
	CHECK(fzn_notes_sync_pull(&store_b, both(), &sign_b, ask, &quiet, &t)
	              == FZN_NOTES_SYNC_NO_ANSWER,
	      "a peer answering nothing is no answer");
	/* B is given `one`, then asks for `two` and is pushed `one` instead. */
	CHECK(fzn_notes_sync_pull(&store_b, both(), &sign_b, ask, &from_a, &t) == FZN_NOTES_SYNC_OK
	              && fzn_notes_erase_note(&store_b, two, NULL) == FZN_NOTES_OK
	              && fzn_notes_erase_note(&store_b, one, NULL) == FZN_NOTES_OK,
	      "fixture: B empty again");
	memcpy(pusher.push_id, one, sizeof(one));
	CHECK(fzn_notes_sync_pull(&store_b, both(), &sign_b, ask, &pusher, &t) == FZN_NOTES_SYNC_OK
	              && t.refused == 0u,
	      "fixture: a record asked for is taken");
	CHECK(fzn_notes_erase_note(&store_b, two, NULL) == FZN_NOTES_OK, "fixture: B lacks two");
	CHECK(fzn_notes_sync_pull(&store_b, both(), &sign_b, ask, &pusher, &t) == FZN_NOTES_SYNC_OK
	              && t.fetched == 1u && t.refused == 1u
	              && !title_is(&store_b, two, KEY_A, "two"),
	      "a record the puller did not ask for is refused: a pull is not a push");
}

static void test_paging(void)
{
	fzn_notes_author_t a = author_on(&store_a, KEY_A, &sign_a);
	peer_t small = { &store_a, FZN_NOTES_SYNC_INDEX_HEAD_LEN + (2u * FZN_NOTES_SYNC_CLAIM_LEN),
		         0, 0, 0, { 0 }, 0, NULL };
	peer_t one_record = { &store_a, FZN_NOTES_SYNC_LIST_HEAD_LEN + 2u + 400u, 0, 0, 0, { 0 }, 0, NULL };
	fzn_notes_sync_tally_t t;
	uint8_t id[FZN_TREE_ID_LEN];
	char title[16];
	size_t i, rounds = 0;
	int ok = 1;

	reset();
	for (i = 0; i < 7u && ok; i++) {
		snprintf(title, sizeof(title), "note %zu", i);
		ok = write(&a, title, id);
	}
	CHECK(ok, "fixture: seven notes on A");
	/* AN INDEX OF TWO CLAIMS A PAGE: four pages, and every claim arrives. The
	 * records then come whole, at the puller's own reply size. */
	small.cap = FZN_NOTES_SYNC_INDEX_HEAD_LEN + (2u * FZN_NOTES_SYNC_CLAIM_LEN);
	CHECK(fzn_notes_sync_pull(&store_b, both(), &sign_b, ask, &small, &t) == FZN_NOTES_SYNC_OK
	              && t.offered == 7u && small.asked >= 4u,
	      "the index pages two claims at a time, every page asked for");
	/* RECORDS ONE AT A TIME: a batch arrives in part, and later rounds
	 * bring the rest. */
	reset();
	for (i = 0; i < 7u; i++) {
		snprintf(title, sizeof(title), "note %zu", i);
		(void)write(&a, title, id);
	}
	while (held(&store_b) < 7u && rounds++ < 10u)
		if (fzn_notes_sync_pull(&store_b, both(), &sign_b, ask, &one_record, &t)
		    != FZN_NOTES_SYNC_OK)
			break;
	CHECK(held(&store_b) == 7u && rounds > 1u && rounds <= 8u,
	      "a reply holding one record at a time converges over rounds");
}

static void test_purge_conversation(void)
{
	fzn_notes_author_t a = author_on(&store_a, KEY_A, &sign_a);
	fzn_notes_author_t b = author_on(&store_b, KEY_B, &sign_b);
	/* A pulls from B: every request reaches B's store as from A. */
	peer_t b_for_a = { &store_b, 0, 0, 0, 0, { 0 }, 0, KEY_A };
	peer_t a_for_b = { &store_a, 0, 0, 0, 0, { 0 }, 0, KEY_B };
	peer_t stranger = { &store_b, 0, 0, 0, 0, { 0 }, 0, NULL };
	peer_t junk = { &store_b, 0, 1, 0, 0, { 0 }, 0, KEY_A };
	fzn_notes_sync_tally_t t;
	fzn_notes_purge_tally_t pt;
	fzn_notes_writer_t pin;
	uint8_t x[FZN_TREE_ID_LEN], y[FZN_TREE_ID_LEN], partners[4][FZN_PUBKEY_LEN];
	uint8_t stranger_key[FZN_PUBKEY_LEN];
	size_t n = 0;
	int complete = 0;

	reset();
	memset(stranger_key, 0x77, sizeof(stranger_key));
	stranger.sender = stranger_key;
	CHECK(write(&a, "x", x) && write(&b, "y", y), "fixture: x on A, y on B");
	CHECK(fzn_notes_sync_pull(&store_a, both(), &sign_a, ask, &b_for_a, &t) == FZN_NOTES_SYNC_OK
	              && fzn_notes_sync_pull(&store_b, both(), &sign_b, ask, &a_for_b, &t)
	                         == FZN_NOTES_SYNC_OK
	              && held(&store_a) == 2u && held(&store_b) == 2u,
	      "fixture: both hold both");
	CHECK(fzn_notes_partners(&store_b, partners, 4u, &n) == FZN_NOTES_OK && n == 1u
	              && memcmp(partners[0], KEY_A, FZN_PUBKEY_LEN) == 0,
	      "B recorded A, which pulled from it, as a partner");

	/* ---- A's purge, carried to B by A */
	memcpy(pin.key, KEY_B, FZN_PUBKEY_LEN);
	CHECK(fzn_notes_purge_add(&store_a, x, fzn_notes_asking(&pin, 1u), 9u, &complete)
	                      == FZN_NOTES_OK
	              && !complete,
	      "fixture: A purges x, pinning B");
	CHECK(fzn_notes_sync_purges(&store_a, both(), KEY_B, ask, &stranger, &pt) == FZN_NOTES_SYNC_OK
	              && pt.asked == 1u && pt.refused == 1u && pt.finished == 0u
	              && held(&store_b) == 2u && fzn_notes_purge_pending(&store_a, x),
	      "a node B does not admit is answered not erased, and the purge waits");
	CHECK(fzn_notes_sync_purges(&store_a, both(), KEY_B, ask, &b_for_a, &pt) == FZN_NOTES_SYNC_OK
	              && pt.asked == 1u && pt.erased == 1u && pt.finished == 1u
	              && held(&store_b) == 1u && held(&store_a) == 1u
	              && !fzn_notes_purge_pending(&store_a, x),
	      "B erases x for A, and A's purge completes and erases its own copy");

	/* ---- B's purge, pinning its partner A, taken by A's pull */
	memcpy(pin.key, KEY_A, FZN_PUBKEY_LEN);
	CHECK(fzn_notes_purge_add(&store_b, y, fzn_notes_asking(&pin, 1u), 9u, &complete)
	                      == FZN_NOTES_OK,
	      "fixture: B purges y, pinning A");
	CHECK(fzn_notes_sync_purges(&store_a, fzn_notes_policy_writers(writers, 1u), KEY_B, ask,
	                            &b_for_a, &pt)
	                      == FZN_NOTES_SYNC_OK
	              && pt.taken == 0u && pt.declined == 1u && held(&store_a) == 1u,
	      "a host A does not admit has its purge declined, and A keeps y");
	CHECK(fzn_notes_sync_purges(&store_a, both(), KEY_B, ask, &b_for_a, &pt) == FZN_NOTES_SYNC_OK
	              && pt.taken == 1u && held(&store_a) == 0u && held(&store_b) == 0u
	              && !fzn_notes_purge_pending(&store_b, y),
	      "A takes B's purge through its own pull, and B's purge completes");
	CHECK(fzn_notes_sync_purges(&store_a, both(), KEY_B, ask, &b_for_a, &pt) == FZN_NOTES_SYNC_OK
	              && pt.asked == 0u && pt.taken == 0u,
	      "and a round with nothing pending asks nothing");

	/* ---- a store that cannot forget, and nonsense */
	{
		fzn_persist_ops_t no_remove = ops_b;
		fzn_notes_store_t fixed;
		peer_t fixed_for_a = { &fixed, 0, 0, 0, 0, { 0 }, 0, KEY_A };

		CHECK(write(&a, "z", x), "fixture: z on A");
		CHECK(fzn_notes_sync_pull(&store_b, both(), &sign_b, ask, &a_for_b, &t)
		              == FZN_NOTES_SYNC_OK,
		      "fixture: B holds z");
		memcpy(pin.key, KEY_B, FZN_PUBKEY_LEN);
		CHECK(fzn_notes_purge_add(&store_a, x, fzn_notes_asking(&pin, 1u), 9u, &complete)
		              == FZN_NOTES_OK,
		      "fixture: A purges z");
		no_remove.remove = NULL;
		CHECK(fzn_notes_store_init(&fixed, &no_remove, &HASH) == FZN_NOTES_OK
		              && fzn_notes_sync_purges(&store_a, both(), KEY_B, ask, &fixed_for_a, &pt)
		                         == FZN_NOTES_SYNC_OK
		              && pt.refused == 1u && fzn_notes_purge_pending(&store_a, x),
		      "a store that cannot forget answers not erased");
		CHECK(fzn_notes_sync_purges(&store_a, both(), KEY_B, ask, &junk, &pt)
		              == FZN_NOTES_SYNC_SHAPE,
		      "nonsense in answer is SHAPE");
	}

	/* ---- AN ERASE THAT FAILS AFTER THE LAST ANSWER, reported by
	 * fuzzypickles: B erases w for A and A records the answer, then A's own
	 * erase fails. Every pinned host has answered, so no question is owed;
	 * the next round must finish the purge anyway rather than hold w and its
	 * queue slot for good. */
	{
		static fzn_persist_ops_t flaky;
		static fzn_notes_store_t on_a;
		uint8_t w[FZN_TREE_ID_LEN];

		flaky = ops_a;
		flaky.remove = remove_unless_note;
		CHECK(fzn_notes_sync_purges(&store_a, both(), KEY_B, ask, &b_for_a, &pt)
		                      == FZN_NOTES_SYNC_OK
		              && !fzn_notes_purge_pending(&store_a, x),
		      "fixture: A's purge of z, which B could not forget, finished with B that can");
		CHECK(fzn_notes_store_init(&on_a, &flaky, &HASH) == FZN_NOTES_OK
		              && write(&a, "w", w)
		              && fzn_notes_sync_pull(&store_b, both(), &sign_b, ask, &a_for_b, &t)
		                         == FZN_NOTES_SYNC_OK,
		      "fixture: w on A and B");
		memcpy(pin.key, KEY_B, FZN_PUBKEY_LEN);
		refuse_note_removal = 1;
		CHECK(fzn_notes_purge_add(&on_a, w, fzn_notes_asking(&pin, 1u), 9u, &complete)
		                      == FZN_NOTES_OK
		              && fzn_notes_sync_purges(&on_a, both(), KEY_B, ask, &b_for_a, &pt)
		                         == FZN_NOTES_SYNC_STORE
		              && fzn_notes_purge_pending(&on_a, w),
		      "fixture: B erased w and A's own erase failed, the purge still queued");
		refuse_note_removal = 0;
		CHECK(fzn_notes_sync_purges(&on_a, both(), KEY_B, ask, &b_for_a, &pt)
		                      == FZN_NOTES_SYNC_OK
		              && pt.finished == 1u && pt.asked == 0u && !fzn_notes_purge_pending(&on_a, w),
		      "a purge every pinned host had answered was never finished after its erase "
		      "failed");
	}
}

/* ---- shares, sec 436 ------------------------------------------------------ */

static int write_under(fzn_notes_author_t *a, const uint8_t parent[FZN_TREE_ID_LEN],
                       const char *title, uint8_t id[FZN_TREE_ID_LEN])
{
	fzn_note_t note;

	memset(&note, 0, sizeof(note));
	note.title = (const uint8_t *)title;
	note.title_len = strlen(title);
	return fzn_notes_create(a, parent, FZN_NOTE_TYPE_NOTE, &note, 1u, id) == FZN_NOTES_OK;
}

static int has_id(const uint8_t (*ids)[FZN_TREE_ID_LEN], size_t n, const uint8_t *id)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (memcmp(ids[i], id, FZN_TREE_ID_LEN) == 0)
			return 1;
	return 0;
}

/* A contact's pull: answered by the scoped server over `scope`. */
typedef struct scoped_peer {
	const fzn_notes_store_t *store;
	const fzn_notes_sync_scope_t *scope;
} scoped_peer_t;

static int ask_scoped(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
                      size_t reply_cap, size_t *reply_len)
{
	scoped_peer_t *p = (scoped_peer_t *)ctx;

	*reply_len = fzn_notes_sync_answer_scoped(p->store, p->scope, request, request_len, reply,
	                                          reply_cap);
	return *reply_len > 0u;
}

static void test_share_table(void)
{
	uint8_t key_c[FZN_PUBKEY_LEN], f[FZN_TREE_ID_LEN], g[FZN_TREE_ID_LEN];
	uint8_t with[4][FZN_TREE_ID_LEN];
	fzn_notes_share_t all[4];
	fzn_cap_id_t one, two, plain;
	size_t n = 0, i;

	reset();
	memset(key_c, 0xc3, sizeof(key_c));
	memset(f, 0x11, sizeof(f));
	memset(g, 0x22, sizeof(g));
	CHECK(fzn_notes_share_capability(7u, 9u, &HASH, &one) == FZN_NOTES_OK
	              && fzn_notes_share_capability(7u, 9u, &HASH, &two) == FZN_NOTES_OK
	              && memcmp(one.b, two.b, FZN_CAP_ID_LEN) == 0,
	      "the share capability is one capability, whatever is shared");
	CHECK(fzn_service_capability(7u, 9u, NULL, 0, &HASH, &plain) == FZN_CHAIN_OK
	              && memcmp(one.b, plain.b, FZN_CAP_ID_LEN) != 0,
	      "and it is not the node's remote capability");
	CHECK(fzn_notes_share_capability(8u, 9u, &HASH, &two) == FZN_NOTES_OK
	              && memcmp(one.b, two.b, FZN_CAP_ID_LEN) != 0,
	      "nor another service's");

	CHECK(fzn_notes_share_add(&store_a, f, key_c, 5u) == FZN_NOTES_OK
	              && fzn_notes_share_add(&store_a, g, key_c, 6u) == FZN_NOTES_OK
	              && fzn_notes_share_add(&store_a, f, KEY_B, 7u) == FZN_NOTES_OK,
	      "two subtrees shared with C, one with B");
	CHECK(fzn_notes_share_add(&store_a, f, key_c, 99u) == FZN_NOTES_OK
	              && fzn_notes_share_list(&store_a, all, 4u, &n) == FZN_NOTES_OK && n == 3u,
	      "sharing again keeps one row");
	for (i = 0; i < n; i++)
		if (memcmp(all[i].subtree, f, FZN_TREE_ID_LEN) == 0
		    && memcmp(all[i].contact, key_c, FZN_PUBKEY_LEN) == 0)
			CHECK(all[i].shared_at_ms == 5u, "and keeps when it was shared");
	CHECK(fzn_notes_share_with(&store_a, key_c, with, 4u, &n) == FZN_NOTES_OK && n == 2u
	              && has_id((const uint8_t (*)[FZN_TREE_ID_LEN])with, n, f)
	              && has_id((const uint8_t (*)[FZN_TREE_ID_LEN])with, n, g),
	      "C is shared both");
	CHECK(fzn_notes_share_with(&store_a, KEY_A, with, 4u, &n) == FZN_NOTES_OK && n == 0u,
	      "and a key shared nothing has nothing");
	CHECK(fzn_notes_share_remove(&store_a, g, key_c) == FZN_NOTES_OK
	              && fzn_notes_share_with(&store_a, key_c, with, 4u, &n) == FZN_NOTES_OK
	              && n == 1u && memcmp(with[0], f, FZN_TREE_ID_LEN) == 0,
	      "unsharing one subtree leaves the other");
	CHECK(fzn_notes_share_remove(&store_a, g, key_c) == FZN_NOTES_ERR_ABSENT,
	      "unsharing it again is ABSENT");

	/* A ROW FILED UNDER ANOTHER PAIR'S KEY is a share nobody made: copy B's
	 * row under a key of its own and it must not be listed. */
	{
		struct row *r = NULL;
		uint8_t subject[FZN_PUBKEY_LEN];

		for (i = 0; i < MEM_ROWS; i++)
			if (table_a.rows[i].used && table_a.rows[i].slot == FZN_PERSIST_NOTE_SHARE
			    && table_a.rows[i].len > FZN_PERSIST_HEAD_LEN + FZN_TREE_ID_LEN
			    && memcmp(table_a.rows[i].bytes + FZN_PERSIST_HEAD_LEN + FZN_TREE_ID_LEN,
			              KEY_B, FZN_PUBKEY_LEN) == 0)
				r = &table_a.rows[i];
		memset(subject, 0x5a, sizeof(subject));
		CHECK(r && mem_save(&table_a, FZN_PERSIST_NOTE_SHARE, subject, r->bytes, r->len),
		      "fixture: B's row copied under another key");
		CHECK(fzn_notes_share_list(&store_a, all, 4u, &n) == FZN_NOTES_OK && n == 2u,
		      "and the copy is not a share");
	}
}

static void test_share_scope(void)
{
	fzn_notes_author_t a = author_on(&store_a, KEY_A, &sign_a);
	uint8_t f[FZN_TREE_ID_LEN], g[FZN_TREE_ID_LEN], h[FZN_TREE_ID_LEN], o[FZN_TREE_ID_LEN];
	static uint8_t reach[FZN_NOTES_MAX][FZN_TREE_ID_LEN];
	uint8_t seeds[2][FZN_TREE_ID_LEN];
	uint8_t keys[FZN_NOTES_MAX][FZN_PUBKEY_LEN];
	uint8_t request[FZN_NOTES_SYNC_LIST_HEAD_LEN + (4u * FZN_PUBKEY_LEN)];
	static uint8_t reply[FZN_NOTES_SYNC_REPLY_MAX];
	uint8_t purge[FZN_NOTES_SYNC_PURGE_LEN];
	uint8_t partners[4][FZN_PUBKEY_LEN];
	fzn_notes_sync_scope_t scope;
	scoped_peer_t from_a = { &store_a, &scope };
	fzn_notes_sync_tally_t t;
	size_t n = 0, i;

	reset();
	CHECK(write(&a, "folder", f) && write_under(&a, f, "child", g)
	              && write_under(&a, g, "grandchild", h) && write(&a, "other", o),
	      "fixture: F above G above H, and O beside F");
	CHECK(fzn_notes_view_load(&store_a, &view) == FZN_NOTES_OK, "fixture: A's view");
	memcpy(seeds[0], f, FZN_TREE_ID_LEN);
	n = fzn_notes_share_reach(&view, (const uint8_t (*)[FZN_TREE_ID_LEN])seeds, 1u, reach,
	                          FZN_NOTES_MAX);
	CHECK(n == 3u && has_id((const uint8_t (*)[FZN_TREE_ID_LEN])reach, n, f)
	              && has_id((const uint8_t (*)[FZN_TREE_ID_LEN])reach, n, g)
	              && has_id((const uint8_t (*)[FZN_TREE_ID_LEN])reach, n, h),
	      "a share of F reaches F, G and H");
	CHECK(!has_id((const uint8_t (*)[FZN_TREE_ID_LEN])reach, n, o), "and not O");
	memcpy(seeds[0], g, FZN_TREE_ID_LEN);
	memcpy(seeds[1], f, FZN_TREE_ID_LEN);
	CHECK(fzn_notes_share_reach(&view, (const uint8_t (*)[FZN_TREE_ID_LEN])seeds, 2u, reach,
	                            FZN_NOTES_MAX)
	              == 3u,
	      "two shares, one inside the other, reach each note once");
	n = fzn_notes_share_reach(&view, (const uint8_t (*)[FZN_TREE_ID_LEN])seeds, 1u, reach,
	                          FZN_NOTES_MAX);
	CHECK(n == 2u && !has_id((const uint8_t (*)[FZN_TREE_ID_LEN])reach, n, f),
	      "a share of G reaches G and H, not its parent");
	CHECK(fzn_notes_share_reach(&view, (const uint8_t (*)[FZN_TREE_ID_LEN])seeds, 1u, reach, 1u)
	              == 1u,
	      "and no more than the room given");

	/* THE CONTACT PULLS the scope of G and nothing else. */
	scope.ids = (const uint8_t (*)[FZN_TREE_ID_LEN])reach;
	scope.count = n;
	CHECK(fzn_notes_sync_pull(&store_b, both(), &sign_b, ask_scoped, &from_a, &t)
	                      == FZN_NOTES_SYNC_OK
	              && t.offered == 2u && t.learned == 2u && held(&store_b) == 2u
	              && title_is(&store_b, g, KEY_A, "child")
	              && title_is(&store_b, h, KEY_A, "grandchild"),
	      "a contact pulling a share of G gets G and H");
	CHECK(!title_is(&store_b, f, KEY_A, "folder") && !title_is(&store_b, o, KEY_A, "other"),
	      "and neither F nor O");

	/* ASKED BY KEY for every claim A holds, it still answers the scope's. */
	CHECK(fzn_notes_claims(&store_a, keys, FZN_NOTES_MAX, &n) == FZN_NOTES_OK && n == 4u,
	      "fixture: A's four claim keys");
	request[0] = FZN_NOTES_SYNC_VERSION;
	request[1] = FZN_NOTES_SYNC_RECORDS_QUERY;
	request[2] = 4u;
	for (i = 0; i < 4u; i++)
		memcpy(request + FZN_NOTES_SYNC_LIST_HEAD_LEN + (i * FZN_PUBKEY_LEN), keys[i],
		       FZN_PUBKEY_LEN);
	CHECK(fzn_notes_sync_answer_scoped(&store_a, &scope, request, sizeof(request), reply,
	                                   sizeof(reply))
	                      > 0u
	              && reply[2] == 2u,
	      "a records query naming every key is answered with the two shared");
	scope.count = 0;
	CHECK(fzn_notes_sync_answer_scoped(&store_a, &scope, request, sizeof(request), reply,
	                                   sizeof(reply))
	                      > 0u
	              && reply[2] == 0u,
	      "and an empty scope answers none");

	purge[0] = FZN_NOTES_SYNC_VERSION;
	purge[1] = FZN_NOTES_SYNC_PURGE;
	memcpy(purge + 2, g, FZN_TREE_ID_LEN);
	scope.count = 2u;
	CHECK(fzn_notes_sync_answer_scoped(&store_a, &scope, purge, sizeof(purge), reply,
	                                   sizeof(reply))
	              == 0u,
	      "a contact's PURGE is not answered");
	CHECK(fzn_notes_partners(&store_a, partners, 4u, &n) == FZN_NOTES_OK && n == 0u,
	      "and a contact's pull made it no partner");
}

/* ---- a share received, sec 437 ------------------------------------------ */

/* A sharer that names only A as a writer, whatever else it serves. */
static int ask_liar(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
                    size_t reply_cap, size_t *reply_len)
{
	if (request_len == FZN_NOTES_SYNC_WRITERS_QUERY_LEN
	    && request[1] == FZN_NOTES_SYNC_WRITERS_QUERY && reply_cap >= 3u + FZN_PUBKEY_LEN) {
		reply[0] = FZN_NOTES_SYNC_VERSION;
		reply[1] = FZN_NOTES_SYNC_WRITERS;
		reply[2] = 1u;
		memcpy(reply + 3, KEY_A, FZN_PUBKEY_LEN);
		*reply_len = 3u + FZN_PUBKEY_LEN;
		return 1;
	}
	return ask_scoped(ctx, request, request_len, reply, reply_cap, reply_len);
}

/* A sharer whose writers answer is `junk_len` bytes of nonsense, its count
 * byte `junk_count` when that is set. */
static size_t junk_len;
static int junk_count = -1;

static int ask_junk(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
                    size_t reply_cap, size_t *reply_len)
{
	/* ONLY THE WRITERS ANSWER IS JUNK: the rest is the honest sharer's,
	 * so a refusal is the writers check's and nothing after it. */
	if (ctx && !(request_len == FZN_NOTES_SYNC_WRITERS_QUERY_LEN
	             && request[1] == FZN_NOTES_SYNC_WRITERS_QUERY))
		return ask_scoped(ctx, request, request_len, reply, reply_cap, reply_len);
	if (reply_cap < junk_len)
		return 0;
	reply[0] = FZN_NOTES_SYNC_VERSION;
	reply[1] = FZN_NOTES_SYNC_WRITERS;
	memset(reply + 2, 0x41, junk_len - 2u);
	if (junk_count >= 0 && junk_len > 2u)
		reply[2] = (uint8_t)junk_count;
	*reply_len = junk_len;
	return 1;
}

static void test_received(void)
{
	fzn_notes_author_t a = author_on(&store_a, KEY_A, &sign_a);
	fzn_notes_author_t b_on_a = author_on(&store_a, KEY_B, &sign_b);
	uint8_t f[FZN_TREE_ID_LEN], g[FZN_TREE_ID_LEN], h[FZN_TREE_ID_LEN], o[FZN_TREE_ID_LEN];
	uint8_t by_b[FZN_TREE_ID_LEN];
	static uint8_t reach[FZN_NOTES_MAX][FZN_TREE_ID_LEN];
	uint8_t seed[1][FZN_TREE_ID_LEN];
	fzn_notes_sync_scope_t scope;
	scoped_peer_t from_a = { &store_a, &scope };
	fzn_notes_received_t seam, other_seam;
	fzn_persist_ops_t seam_ops, other_ops;
	fzn_notes_store_t from_alice, from_bob;
	fzn_notes_sync_tally_t t;
	const fzn_tree_node_t *top[8];
	size_t n = 0, i, removed = 0;
	uint64_t seq = 0;
	int cut = 0;

	reset();
	CHECK(write(&a, "folder", f) && write_under(&a, f, "child", g)
	              && write_under(&a, g, "grandchild", h) && write(&a, "other", o)
	              && write_under(&b_on_a, g, "by b", by_b),
	      "fixture: on A, F above G above H, O beside F, and B's note under G");
	CHECK(fzn_notes_view_load(&store_a, &view) == FZN_NOTES_OK, "fixture: A's view");
	memcpy(seed[0], g, FZN_TREE_ID_LEN);
	scope.ids = (const uint8_t (*)[FZN_TREE_ID_LEN])reach;
	scope.count = fzn_notes_share_reach(&view, (const uint8_t (*)[FZN_TREE_ID_LEN])seed, 1u,
	                                    reach, FZN_NOTES_MAX);
	CHECK(scope.count == 3u, "fixture: a share of G reaches G, H and B's note");

	CHECK(fzn_notes_received_ops(&seam, &ops_b, &HASH, KEY_A, &seam_ops) == FZN_NOTES_OK
	              && fzn_notes_store_init(&from_alice, &seam_ops, &HASH) == FZN_NOTES_OK
	              && fzn_notes_received_ops(&other_seam, &ops_b, &HASH, KEY_B, &other_ops)
	                         == FZN_NOTES_OK
	              && fzn_notes_store_init(&from_bob, &other_ops, &HASH) == FZN_NOTES_OK,
	      "B opens A's tree and another sharer's over its own store");
	CHECK(fzn_notes_received_ops(&seam, NULL, &HASH, KEY_A, &seam_ops)
	              == FZN_NOTES_ERR_MALFORMED,
	      "and a seam over nothing is refused");
	CHECK(fzn_notes_received_ops(&seam, &ops_b, &HASH, KEY_A, &seam_ops) == FZN_NOTES_OK,
	      "fixture: the seam again");

	CHECK(fzn_notes_sync_pull_shared(&from_alice, &sign_b, ask_scoped, &from_a, &t)
	                      == FZN_NOTES_SYNC_OK
	              && t.learned == 3u && t.refused == 0u && held(&from_alice) == 3u,
	      "B pulls what A shared, both writers' notes, into A's tree");
	CHECK(title_is(&from_alice, h, KEY_A, "grandchild")
	              && title_is(&from_alice, by_b, KEY_B, "by b"),
	      "and holds them as they were written");
	CHECK(held(&store_b) == 0u, "while B's own tree holds none of them");
	CHECK(held(&from_bob) == 0u, "nor does another sharer's");

	/* THE SHARED TOP SURFACES IN A'S TREE, not in B's own. */
	CHECK(fzn_notes_view_load(&from_alice, &view) == FZN_NOTES_OK
	              && fzn_notes_top_level(&view, top, 8u, &n, &cut) == FZN_NOTES_OK && n == 3u,
	      "the view's top level is the wrong question: every shared note is unreachable");
	n = fzn_notes_received_roots(&view, top, 8u);
	CHECK(n == 1u && memcmp(top[0]->id, g, FZN_TREE_ID_LEN) == 0,
	      "the shared subtree's root is the one root of A's tree on B");
	CHECK(fzn_notes_received_roots(&view, top, 0u) == 0u, "and no more than the room given");

	/* A SECOND PULL is current. */
	CHECK(fzn_notes_sync_pull_shared(&from_alice, &sign_b, ask_scoped, &from_a, &t)
	                      == FZN_NOTES_SYNC_OK
	              && t.fetched == 0u,
	      "a second pull fetches nothing");

	/* EACH WRITER ONCE: A wrote two of the three, B one. */
	{
		uint8_t q[FZN_NOTES_SYNC_WRITERS_QUERY_LEN] = { FZN_NOTES_SYNC_VERSION,
			                                       FZN_NOTES_SYNC_WRITERS_QUERY };
		static uint8_t out[FZN_NOTES_SYNC_REPLY_MAX];

		CHECK(fzn_notes_sync_answer_scoped(&store_a, &scope, q, sizeof(q), out, sizeof(out))
		                      == 3u + (2u * FZN_PUBKEY_LEN)
		              && out[2] == 2u,
		      "the sharer names its two writers, each once");
		CHECK(fzn_notes_sync_answer(&store_a, both(), KEY_B, 1u, q, sizeof(q), out,
		                            sizeof(out))
		              == 0u,
		      "and a member's sync does not answer a writers query");
	}

	/* ANOTHER SHARER'S TREE survives forgetting A's. */
	{
		uint8_t blob[FZN_PERSIST_HEAD_LEN + 1u], claim[FZN_PUBKEY_LEN];

		memset(claim, 0x2d, sizeof(claim));
		CHECK(fzn_persist_head_write(blob, sizeof(blob), 1u, FZN_PERSIST_BLOB_NOTE)
		                      == FZN_PERSIST_OK
		              && other_ops.save(other_ops.ctx, FZN_PERSIST_NOTE, claim, blob,
		                                sizeof(blob)),
		      "fixture: a row in another sharer's tree");
	}

	/* ONLY THE WRITERS THE SHARER NAMES. */
	CHECK(fzn_notes_received_forget(&ops_b, KEY_A, &removed) == FZN_NOTES_OK && removed == 3u
	              && held(&from_alice) == 0u,
	      "forgetting A's share removes its three notes");
	{
		uint8_t keys[2][FZN_PUBKEY_LEN];
		size_t left = 0;

		CHECK(other_ops.list(other_ops.ctx, FZN_PERSIST_NOTE, (uint8_t *)keys, 2u, &left)
		              && left == 1u,
		      "and leaves the other sharer's");
	}
	CHECK(fzn_notes_sync_pull_shared(&from_alice, &sign_b, ask_liar, &from_a, &t)
	                      == FZN_NOTES_SYNC_OK
	              && t.learned == 2u && t.refused == 1u
	              && !title_is(&from_alice, by_b, KEY_B, "by b"),
	      "a writer the sharer does not name has its note refused");

	/* READ-ONLY: nothing but notes is held in a sharer's tree. */
	{
		uint8_t blob[16] = { 0 };

		CHECK(!from_alice.ops->save(from_alice.ops->ctx, FZN_PERSIST_NOTE_PURGE, KEY_B, blob,
		                            sizeof(blob)),
		      "nothing but a note is saved in A's tree");
	}

	/* A ROW COPIED UNDER ANOTHER KEY is not listed twice. */
	{
		struct row *r = NULL;
		uint8_t subject[FZN_PUBKEY_LEN];

		for (i = 0; i < MEM_ROWS && !r; i++)
			if (table_b.rows[i].used && table_b.rows[i].slot == FZN_PERSIST_SHARED_NOTE)
				r = &table_b.rows[i];
		memset(subject, 0x6b, sizeof(subject));
		CHECK(r && mem_save(&table_b, FZN_PERSIST_SHARED_NOTE, subject, r->bytes, r->len),
		      "fixture: a row copied under another key");
		CHECK(held(&from_alice) == 2u, "and A's tree still holds two");
	}

	/* WHAT THE WRITERS ANSWER MAY NOT BE. */
	junk_len = 2u;
	CHECK(fzn_notes_sync_pull_shared(&from_alice, &sign_b, ask_junk, NULL, &t)
	              == FZN_NOTES_SYNC_SHAPE,
	      "a writers answer with no count is SHAPE");
	junk_len = 3u + FZN_PUBKEY_LEN + 1u;
	CHECK(fzn_notes_sync_pull_shared(&from_alice, &sign_b, ask_junk, NULL, &t)
	              == FZN_NOTES_SYNC_SHAPE,
	      "a writers answer whose count is past the bound is SHAPE");
	/* ONLY THE LENGTH CHECK can refuse this one: a count within the bound,
	 * naming two keys where one arrived. */
	junk_count = 2;
	junk_len = 3u + FZN_PUBKEY_LEN;
	CHECK(fzn_notes_sync_pull_shared(&from_alice, &sign_b, ask_junk, &from_a, &t)
	              == FZN_NOTES_SYNC_SHAPE,
	      "a writers answer naming two keys with one present is SHAPE");
	junk_count = -1;
	scope.count = 0;
	CHECK(fzn_notes_sync_pull_shared(&from_alice, &sign_b, ask_scoped, &from_a, &t)
	                      == FZN_NOTES_SYNC_OK
	              && t.offered == 0u,
	      "an empty share names no writers and pulls nothing");
	(void)o;
}

/* ---- pushing, sec 446 ----------------------------------------------------- */

/* B, serving a push from A: its index, and taking what A pushes, admitted
 * by `pushee_policy`. `flip` alters a pushed record's last byte. */
static fzn_notes_policy_t pushee_policy;
static int flip;

static int ask_pushee(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
                      size_t reply_cap, size_t *reply_len)
{
	static uint8_t copy[FZN_NOTES_SYNC_PUSH_HEAD_LEN + FZN_RECORD_MAX_LEN];

	(void)ctx;
	if (flip && request_len > FZN_NOTES_SYNC_PUSH_HEAD_LEN && request_len <= sizeof(copy)
	    && request[1] == FZN_NOTES_SYNC_PUSH) {
		memcpy(copy, request, request_len);
		copy[request_len - 1u] ^= 0x01u;
		request = copy;
	}
	*reply_len = fzn_notes_sync_take(&store_b, pushee_policy, &sign_b, KEY_A, request,
	                                 request_len, reply, reply_cap);
	if (!*reply_len)
		*reply_len = fzn_notes_sync_answer(&store_b, pushee_policy, KEY_A, 1u, request,
		                                   request_len, reply, reply_cap);
	return *reply_len > 0u;
}

static void test_push(void)
{
	fzn_notes_author_t a = author_on(&store_a, KEY_A, &sign_a);
	uint8_t one[FZN_TREE_ID_LEN], two[FZN_TREE_ID_LEN];
	fzn_notes_push_tally_t t;
	fzn_note_t with;
	int complete = 0;
	fzn_notes_writer_t ask_a;

	reset();
	pushee_policy = both();
	flip = 0;
	CHECK(write(&a, "one", one) && write(&a, "two", two), "fixture: two notes on A");
	CHECK(fzn_notes_sync_push(&store_a, ask_pushee, NULL, &t) == FZN_NOTES_SYNC_OK
	              && t.offered == 2u && t.taken == 2u && t.refused == 0u && held(&store_b) == 2u,
	      "A pushes its two notes, and B takes them");
	CHECK(title_is(&store_b, two, KEY_A, "two"), "as A wrote them");
	CHECK(fzn_notes_sync_push(&store_a, ask_pushee, NULL, &t) == FZN_NOTES_SYNC_OK
	              && t.offered == 0u,
	      "a second push offers nothing: B's index says it is current");
	memset(&with, 0, sizeof(with));
	with.title = (const uint8_t *)"two, renamed";
	with.title_len = 12u;
	CHECK(fzn_notes_edit(&a, two, FZN_NOTES_EDIT_TITLE, &with, 0u, 0u, 2u) == FZN_NOTES_OK,
	      "fixture: A renames one");
	CHECK(fzn_notes_sync_push(&store_a, ask_pushee, NULL, &t) == FZN_NOTES_SYNC_OK
	              && t.offered == 1u && t.taken == 1u
	              && title_is(&store_b, two, KEY_A, "two, renamed"),
	      "after an edit, only the edited claim is pushed");

	/* REFUSED: a sender B does not admit, a forged record, a note B is
	 * purging. */
	reset();
	CHECK(write(&a, "three", one), "fixture: a note on A");
	(void)both(); /* fills `writers`, of which B alone is the second */
	pushee_policy = fzn_notes_policy_writers(writers + 1, 1u);
	CHECK(fzn_notes_sync_push(&store_a, ask_pushee, NULL, &t) == FZN_NOTES_SYNC_OK
	              && t.offered == 1u && t.refused == 1u && held(&store_b) == 0u,
	      "a sender B does not admit has its push refused");
	pushee_policy = both();
	flip = 1;
	CHECK(fzn_notes_sync_push(&store_a, ask_pushee, NULL, &t) == FZN_NOTES_SYNC_OK
	              && t.refused == 1u && held(&store_b) == 0u,
	      "a record altered on the way is refused");
	flip = 0;
	memcpy(ask_a.key, KEY_A, FZN_PUBKEY_LEN);
	CHECK(fzn_notes_purge_add(&store_b, one, fzn_notes_asking(&ask_a, 1u), 5u, &complete)
	              == FZN_NOTES_OK,
	      "fixture: B purging the note");
	CHECK(fzn_notes_sync_push(&store_a, ask_pushee, NULL, &t) == FZN_NOTES_SYNC_OK
	              && t.refused == 1u && held(&store_b) == 0u,
	      "a note B is purging is not pushed back into it");
	{
		uint8_t bad[5] = { FZN_NOTES_SYNC_VERSION, FZN_NOTES_SYNC_PUSH, 0, 9, 0 };
		uint8_t out[8];

		CHECK(fzn_notes_sync_take(&store_b, both(), &sign_b, KEY_A, bad, sizeof(bad), out,
		                          sizeof(out))
		                      == FZN_NOTES_SYNC_PUSHED_LEN
		              && out[2] == FZN_NOTES_SYNC_PUSH_REFUSED,
		      "a push whose length disagrees with its record is refused, and answered");
		/* THE SENDER IS VOUCHED FOR, apart from the record: A's own record,
		 * which B admits, pushed by a key B does not. */
		{
			static uint8_t push[FZN_NOTES_SYNC_PUSH_HEAD_LEN + FZN_RECORD_MAX_LEN];
			uint8_t stranger[FZN_PUBKEY_LEN], four[FZN_TREE_ID_LEN];
			size_t len = 0;

			memset(stranger, 0xd5, sizeof(stranger));
			push[0] = FZN_NOTES_SYNC_VERSION;
			push[1] = FZN_NOTES_SYNC_PUSH;
			CHECK(write(&a, "four", four)
			              && fzn_notes_get(&store_a, four, KEY_A,
			                               push + FZN_NOTES_SYNC_PUSH_HEAD_LEN, FZN_RECORD_MAX_LEN,
			                               &len)
			                         == FZN_NOTES_OK,
			      "fixture: a new record of A's");
			push[2] = (uint8_t)(len >> 8);
			push[3] = (uint8_t)len;
			CHECK(fzn_notes_sync_take(&store_b, both(), &sign_b, stranger, push,
			                          FZN_NOTES_SYNC_PUSH_HEAD_LEN + len, out, sizeof(out))
			                      == FZN_NOTES_SYNC_PUSHED_LEN
			              && out[2] == FZN_NOTES_SYNC_PUSH_REFUSED,
			      "a record B would admit, pushed by a sender it does not, is refused");
			CHECK(fzn_notes_sync_take(&store_b, both(), &sign_b, KEY_A, push,
			                          FZN_NOTES_SYNC_PUSH_HEAD_LEN + len, out, sizeof(out))
			                      == FZN_NOTES_SYNC_PUSHED_LEN
			              && out[2] == FZN_NOTES_SYNC_PUSH_TAKEN,
			      "and taken from A");
		}
		CHECK(fzn_notes_sync_take(&store_b, both(), &sign_b, KEY_A, (const uint8_t *)"\x02\x01",
		                          2u, out, sizeof(out))
		              == 0u,
		      "what is not a push falls through");
	}
}

int main(void)
{
	memset(KEY_A, 0xa1, sizeof(KEY_A));
	memset(KEY_B, 0xb2, sizeof(KEY_B));
	CHECK(fzn_notes_store_init(&store_a, &ops_a, &HASH) == FZN_NOTES_OK
	              && fzn_notes_store_init(&store_b, &ops_b, &HASH) == FZN_NOTES_OK,
	      "two stores open");

	test_converge();
	test_purge_rules();
	test_peers_that_misbehave();
	test_paging();
	test_purge_conversation();
	test_share_table();
	test_share_scope();
	test_received();
	test_push();

	if (failures) {
		fprintf(stderr, "notes_sync_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("notes_sync_test: all %d checks passed\n", checks);
	return 0;
}
