/* notes_sync_test -- two nodes' notes converging: an index, then only the
 * records a node lacks or holds older, admitted as any record is. sec 432.
 *
 * Two stores in one process over `persist/`'s seam in memory, each its own
 * table, and the "peer" is a function handing a request to the other store's
 * `fzn_notes_sync_answer` -- so a case can shrink a reply, push a record
 * nobody asked for, or answer with junk. The signer is a toy whose public key
 * is its secret. */

#include "../author.h"
#include "../purge.h"
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
	uint8_t bytes[FZN_PERSIST_HEAD_LEN + FZN_RECORD_MAX_LEN];
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
	fzn_note_t note;

	return fzn_notes_get(store, id, writer, out, sizeof(out), &len) == FZN_NOTES_OK
	       && fzn_record_open(out, len, &rec) == FZN_RECORD_OK
	       && fzn_tree_open(rec, &node) == FZN_TREE_OK
	       && fzn_note_open(node.content_type, node.content, node.content_len, &note)
	                  == FZN_NOTE_OK
	       && note.title_len == strlen(title) && memcmp(note.title, title, note.title_len) == 0;
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

	if (failures) {
		fprintf(stderr, "notes_sync_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("notes_sync_test: all %d checks passed\n", checks);
	return 0;
}
