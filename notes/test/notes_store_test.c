/* notes_store_test -- the notes model's store and view: who may write a note, how a
 * claim supersedes, what a host holds, and the tree it reads back. sec 425.
 *
 * The signer is a toy whose "public key" is its secret: a signature is a hash
 * of the key and the message. That is enough for what is under test -- a
 * record whose bytes or issuer moved stops verifying -- and needs no binding.
 * The backend is `persist/`'s seam over memory, with list and remove, and a
 * switch to take remove away. */

#include "../store.h"
#include "../author.h"
#include "../purge.h"
#include "../import.h"
#include "../text.h"
#include "../view.h"
#include "blob_stub.h"
#include "chain_stub.h"

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
	fprintf(stderr, "  FAIL notes_store_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, what)

/* Where a purge row's host count sits, past its two times: purge.c's
 * OFF_COUNT, restated so a case can damage it. */
#define OFF_COUNT_FOR_TEST 16u

/* ---- a hash, and a signer built on it ----------------------------------- */

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

static const fzn_sign_ops_t VERIFY = { toy_verify, NULL, NULL };

static uint8_t KEY_A[FZN_PUBKEY_LEN], KEY_B[FZN_PUBKEY_LEN], KEY_C[FZN_PUBKEY_LEN];

/* ---- a persist backend over memory --------------------------------------- */

#define MEM_ROWS 300u

struct row {
	int used;
	fzn_persist_slot_t slot;
	int has_subject;
	uint8_t subject[FZN_PUBKEY_LEN];
	uint8_t bytes[FZN_PERSIST_HEAD_LEN + FZN_RECORD_MAX_LEN];
	size_t len;
};

static struct row rows[MEM_ROWS];

static struct row *find(fzn_persist_slot_t slot, const uint8_t *subject)
{
	size_t i;

	for (i = 0; i < MEM_ROWS; i++)
		if (rows[i].used && rows[i].slot == slot && rows[i].has_subject == (subject != NULL)
		    && (!subject || memcmp(rows[i].subject, subject, FZN_PUBKEY_LEN) == 0))
			return &rows[i];
	return NULL;
}

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	struct row *r = find(slot, subject);

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
	struct row *r = find(slot, subject);
	size_t i;

	(void)ctx;
	if (len > sizeof(r->bytes))
		return 0;
	for (i = 0; !r && i < MEM_ROWS; i++)
		if (!rows[i].used)
			r = &rows[i];
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
	size_t i, n = 0;

	(void)ctx;
	for (i = 0; i < MEM_ROWS; i++)
		if (rows[i].used && rows[i].slot == slot && rows[i].has_subject) {
			if (n == max)
				return 0;
			memcpy(out + (n * FZN_PUBKEY_LEN), rows[i].subject, FZN_PUBKEY_LEN);
			n++;
		}
	*count = n;
	return 1;
}

static int mem_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	struct row *r = find(slot, subject);

	(void)ctx;
	if (r)
		r->used = 0;
	return 1;
}

static fzn_persist_ops_t OPS = { mem_load, mem_save, mem_list, mem_remove, NULL };
static fzn_notes_store_t store;

static void wipe(void)
{
	memset(rows, 0, sizeof(rows));
}

/* ---- records ------------------------------------------------------------- */

static uint8_t buf[8][FZN_RECORD_MAX_LEN];
static size_t buf_len[8];

/* A node record by `key`, about note `id`, under `parent`, into buf[slot]. */
static size_t node_of(int slot, uint8_t *key, uint8_t id, uint8_t parent, uint64_t seq,
                      uint32_t kind, uint32_t stream, const char *content)
{
	uint8_t subject[FZN_SUBJECT_LEN], up[FZN_TREE_ID_LEN], body[FZN_RECORD_BODY_MAX];
	fzn_sign_ops_t signer = { NULL, toy_sign, NULL };
	size_t body_len = 0, len = 0;

	signer.ctx = key;
	memset(subject, 0, sizeof(subject));
	subject[0] = id;
	memset(up, 0, sizeof(up));
	up[0] = parent;
	if (fzn_tree_body(up, 100u * id, FZN_NOTE_TYPE_NOTE, (const uint8_t *)content,
	                  strlen(content), body, sizeof(body), &body_len) != FZN_TREE_OK
	    || fzn_record_sign(key, subject, stream, kind, seq, NULL, 1000u, body, body_len, &signer,
	                       buf[slot], FZN_RECORD_MAX_LEN, &len) != FZN_RECORD_OK) {
		CHECK(0, "fixture: a node record would not sign");
		return 0;
	}
	buf_len[slot] = len;
	return len;
}

static size_t note_of(int slot, uint8_t *key, uint8_t id, uint8_t parent, uint64_t seq,
                      const char *content)
{
	return node_of(slot, key, id, parent, seq, FZN_NOTE_KIND, FZN_NOTE_STREAM, content);
}

static fzn_notes_writer_t writers[2];

static fzn_notes_policy_t own_hosts(void)
{
	memcpy(writers[0].key, KEY_A, FZN_PUBKEY_LEN);
	memcpy(writers[1].key, KEY_B, FZN_PUBKEY_LEN);
	return fzn_notes_policy_writers(writers, 2u);
}

static fzn_notes_err_t put(int slot, int *wrote)
{
	fzn_notes_denial_t why;

	return fzn_notes_put(&store, buf[slot], buf_len[slot], own_hosts(), &VERIFY, wrote, &why);
}

static uint8_t subject_of(uint8_t id, uint8_t out[FZN_SUBJECT_LEN])
{
	memset(out, 0, FZN_SUBJECT_LEN);
	out[0] = id;
	return id;
}

/* ---- cases --------------------------------------------------------------- */

static void test_admission(void)
{
	fzn_notes_policy_t none, empty;
	fzn_notes_denial_t why;

	memset(&none, 0, sizeof(none));
	empty = fzn_notes_policy_writers(NULL, 0u);
	note_of(0, KEY_A, 1, 0, 1, "a");

	CHECK(fzn_notes_admit(own_hosts(), buf[0], buf_len[0], &VERIFY, &why) == FZN_NOTES_ADMITTED
	              && why == FZN_NOTES_DENIAL_NONE,
	      "a sibling's note is admitted");
	CHECK(fzn_notes_admit(none, buf[0], buf_len[0], &VERIFY, &why) == FZN_NOTES_DENIED
	              && why == FZN_NOTES_DENIAL_POLICY_UNSPELLED,
	      "a zeroed policy denies, before the record is read");
	CHECK(fzn_notes_admit(empty, buf[0], buf_len[0], &VERIFY, &why) == FZN_NOTES_DENIED
	              && why == FZN_NOTES_DENIAL_NOT_ADMITTED,
	      "an empty admitted set denies");
	CHECK(fzn_notes_admit(own_hosts(), buf[0], 10u, &VERIFY, &why) == FZN_NOTES_DENIED
	              && why == FZN_NOTES_DENIAL_MALFORMED,
	      "ten bytes are not a record");

	node_of(1, KEY_A, 1, 0, 1, FZN_NOTE_KIND + 1u, FZN_NOTE_STREAM, "a");
	CHECK(fzn_notes_admit(own_hosts(), buf[1], buf_len[1], &VERIFY, &why) == FZN_NOTES_DENIED
	              && why == FZN_NOTES_DENIAL_KIND,
	      "a sibling's record of another kind is not a note");
	node_of(1, KEY_A, 1, 0, 1, FZN_NOTE_KIND, FZN_NOTE_STREAM + 1u, "a");
	CHECK(fzn_notes_admit(own_hosts(), buf[1], buf_len[1], &VERIFY, &why) == FZN_NOTES_DENIED
	              && why == FZN_NOTES_DENIAL_KIND,
	      "a note record on another stream is refused");

	note_of(1, KEY_A, 1, 0, 1, "a");
	buf[1][buf_len[1] - 1u] ^= 0x01u;
	CHECK(fzn_notes_admit(own_hosts(), buf[1], buf_len[1], &VERIFY, &why) == FZN_NOTES_DENIED
	              && why == FZN_NOTES_DENIAL_SIGNATURE,
	      "a record whose signature moved is refused");

	note_of(1, KEY_C, 1, 0, 1, "a");
	CHECK(fzn_notes_admit(own_hosts(), buf[1], buf_len[1], &VERIFY, &why) == FZN_NOTES_DENIED
	              && why == FZN_NOTES_DENIAL_NOT_ADMITTED,
	      "a stranger with a good signature is refused");
	CHECK(fzn_notes_put(&store, buf[1], buf_len[1], own_hosts(), &VERIFY, NULL, &why)
	              == FZN_NOTES_ERR_DENIED
	              && why == FZN_NOTES_DENIAL_NOT_ADMITTED,
	      "and put asks the same question itself");
}

static void test_supersession(void)
{
	uint8_t id[FZN_SUBJECT_LEN], out[FZN_RECORD_MAX_LEN];
	fzn_record_t rec;
	size_t len = 0;
	int wrote = -1;

	wipe();
	subject_of(2, id);
	note_of(0, KEY_A, 2, 0, 5, "five");
	CHECK(put(0, &wrote) == FZN_NOTES_OK && wrote == 1, "a new claim is written");
	CHECK(fzn_notes_get(&store, id, KEY_A, out, sizeof(out), &len) == FZN_NOTES_OK
	              && len == buf_len[0] && memcmp(out, buf[0], len) == 0,
	      "and reads back byte for byte");
	CHECK(fzn_notes_get(&store, id, KEY_B, out, sizeof(out), &len) == FZN_NOTES_ERR_ABSENT,
	      "another writer's claim on it is not held");

	note_of(1, KEY_A, 2, 0, 3, "three");
	CHECK(put(1, &wrote) == FZN_NOTES_OK && wrote == 0, "an older record is OK and writes nothing");
	CHECK(put(0, &wrote) == FZN_NOTES_OK && wrote == 0, "the same record again writes nothing");
	CHECK(fzn_notes_get(&store, id, KEY_A, out, sizeof(out), &len) == FZN_NOTES_OK
	              && fzn_record_open(out, len, &rec) == FZN_RECORD_OK
	              && fzn_record_seq(rec) == 5u,
	      "and the newer one is still held");

	note_of(1, KEY_A, 2, 0, 5, "another five");
	CHECK(put(1, &wrote) == FZN_NOTES_ERR_EQUIVOCATION && wrote == 0,
	      "two records at one sequence are equivocation");

	note_of(1, KEY_A, 2, 0, 7, "seven");
	CHECK(put(1, &wrote) == FZN_NOTES_OK && wrote == 1, "a newer record replaces");
	CHECK(fzn_notes_get(&store, id, KEY_A, out, sizeof(out), &len) == FZN_NOTES_OK
	              && fzn_record_open(out, len, &rec) == FZN_RECORD_OK
	              && fzn_record_seq(rec) == 7u,
	      "and is what is read");
}

static void test_damage_and_misplacement(void)
{
	uint8_t id[FZN_SUBJECT_LEN], key[FZN_PUBKEY_LEN], other[FZN_PUBKEY_LEN];
	uint8_t out[FZN_RECORD_MAX_LEN];
	struct row *r, *s;
	size_t len = 0;
	int wrote = 0;

	wipe();
	subject_of(3, id);
	note_of(0, KEY_A, 3, 0, 4, "four");
	note_of(1, KEY_A, 4, 0, 4, "another note");
	CHECK(put(0, NULL) == FZN_NOTES_OK && put(1, NULL) == FZN_NOTES_OK, "fixture: two notes");
	CHECK(fzn_notes_claim_key(&store, id, KEY_A, key) == FZN_NOTES_OK, "fixture: a claim key");
	subject_of(4, id);
	CHECK(fzn_notes_claim_key(&store, id, KEY_A, other) == FZN_NOTES_OK, "fixture: another");
	r = find(FZN_PERSIST_NOTE, key);
	s = find(FZN_PERSIST_NOTE, other);
	CHECK(r && s, "fixture: both rows held");
	if (!r || !s)
		return;

	/* ANOTHER CLAIM'S RECORD UNDER THIS KEY: well signed, wrongly filed. */
	{
		struct row keep = *r;

		memcpy(r->bytes, s->bytes, s->len);
		r->len = s->len;
		CHECK(fzn_notes_get_key(&store, key, out, sizeof(out), &len) == FZN_NOTES_ERR_SHAPE,
		      "another claim's record under a key is refused");
		*r = keep;
	}
	/* A HELD RECORD THAT WILL NOT OPEN does not freeze its note. */
	r->bytes[FZN_PERSIST_HEAD_LEN] ^= 0xffu;
	subject_of(3, id);
	CHECK(fzn_notes_get(&store, id, KEY_A, out, sizeof(out), &len) == FZN_NOTES_ERR_SHAPE,
	      "a damaged record reads as damage");
	note_of(2, KEY_A, 3, 0, 2, "an older record, but readable");
	CHECK(put(2, &wrote) == FZN_NOTES_OK && wrote == 1
	              && fzn_notes_get(&store, id, KEY_A, out, sizeof(out), &len) == FZN_NOTES_OK,
	      "and a good record replaces it");
}

static void test_capacity_and_erase(void)
{
	uint8_t id[FZN_SUBJECT_LEN], out[FZN_RECORD_MAX_LEN];
	fzn_persist_ops_t no_remove = OPS;
	fzn_notes_store_t fixed;
	size_t i, len = 0;
	int ok = 1, wrote = 0;

	wipe();
	for (i = 0; i < FZN_NOTES_MAX && ok; i++) {
		uint8_t key[FZN_PUBKEY_LEN];

		/* One writer per claim keeps every note id unique without
		 * running out of single-byte ids. */
		memcpy(key, KEY_A, sizeof(key));
		key[31] = (uint8_t)i;
		memcpy(writers[0].key, key, FZN_PUBKEY_LEN);
		note_of(0, key, 9, 0, 1, "x");
		ok = fzn_notes_put(&store, buf[0], buf_len[0], fzn_notes_policy_writers(writers, 1u),
		                   &VERIFY, NULL, NULL)
		     == FZN_NOTES_OK;
	}
	CHECK(ok, "fixture: the store fills to its bound");
	note_of(1, KEY_A, 10, 0, 1, "one too many");
	CHECK(put(1, NULL) == FZN_NOTES_ERR_FULL, "one claim past the bound is refused");
	subject_of(10, id);
	CHECK(fzn_notes_get(&store, id, KEY_A, out, sizeof(out), &len) == FZN_NOTES_ERR_ABSENT,
	      "and nothing was written for it");
	memcpy(writers[0].key, KEY_A, FZN_PUBKEY_LEN);
	{
		uint8_t key[FZN_PUBKEY_LEN];

		memcpy(key, KEY_A, sizeof(key));
		key[31] = 0u;
		memcpy(writers[0].key, key, FZN_PUBKEY_LEN);
		note_of(0, key, 9, 0, 2, "an edit at the bound");
		CHECK(fzn_notes_put(&store, buf[0], buf_len[0], fzn_notes_policy_writers(writers, 1u),
		                    &VERIFY, &wrote, NULL)
		              == FZN_NOTES_OK
		              && wrote == 1,
		      "an edit of a held claim is not a new claim, at the bound too");
		subject_of(9, id);
		CHECK(fzn_notes_erase(&store, id, key) == FZN_NOTES_OK
		              && fzn_notes_get(&store, id, key, out, sizeof(out), &len)
		                         == FZN_NOTES_ERR_ABSENT,
		      "an erased claim is gone");
		CHECK(put(1, NULL) == FZN_NOTES_OK, "and its room is free again");
		no_remove.remove = NULL;
		CHECK(fzn_notes_store_init(&fixed, &no_remove, &HASH) == FZN_NOTES_OK
		              && fzn_notes_erase(&fixed, id, key) == FZN_NOTES_ERR_UNSUPPORTED,
		      "a backend that cannot forget says so");
	}
	{
		fzn_persist_ops_t no_list = OPS;

		no_list.list = NULL;
		CHECK(fzn_notes_store_init(&fixed, &no_list, &HASH) == FZN_NOTES_ERR_MALFORMED,
		      "a backend that cannot list is refused at init");
	}
}

static void test_the_view(void)
{
	static fzn_notes_view_t view;
	const fzn_tree_node_t *out[16];
	uint8_t root[FZN_TREE_ID_LEN], up[FZN_TREE_ID_LEN], contested[4][FZN_TREE_ID_LEN];
	size_t n = 0, i, reach = 0;
	int cut = 0;

	wipe();
	memset(root, 0, sizeof(root));
	/* A folder (1) at the root with two children (2, 3); 4 claims a parent
	 * nobody holds; 5 and 6 point at each other. */
	note_of(0, KEY_A, 1, 0, 1, "folder");
	CHECK(put(0, NULL) == FZN_NOTES_OK, "fixture: 1");
	note_of(0, KEY_A, 3, 1, 2, "second child");
	CHECK(put(0, NULL) == FZN_NOTES_OK, "fixture: 3");
	note_of(0, KEY_A, 2, 1, 3, "first child");
	CHECK(put(0, NULL) == FZN_NOTES_OK, "fixture: 2");
	note_of(0, KEY_A, 4, 77, 4, "orphan");
	CHECK(put(0, NULL) == FZN_NOTES_OK, "fixture: 4");
	note_of(0, KEY_A, 5, 6, 5, "cycle a");
	CHECK(put(0, NULL) == FZN_NOTES_OK, "fixture: 5");
	note_of(0, KEY_A, 6, 5, 6, "cycle b");
	CHECK(put(0, NULL) == FZN_NOTES_OK, "fixture: 6");

	CHECK(fzn_notes_view_load(&store, &view) == FZN_NOTES_OK && view.count == 6u
	              && view.unreadable == 0u,
	      "the view holds six nodes");
	for (i = 0; i < view.count; i++)
		reach += (size_t)fzn_notes_reachable(&view, i);
	CHECK(reach == 3u, "the root reaches the folder and its two children");
	memset(up, 0, sizeof(up));
	up[0] = 1;
	CHECK(fzn_notes_children(&view, up, out, 16u, &n, &cut) == FZN_NOTES_OK && n == 2u && !cut
	              && out[0]->id[0] == 2u && out[1]->id[0] == 3u,
	      "the folder's children come in sibling order");
	CHECK(fzn_notes_top_level(&view, out, 16u, &n, &cut) == FZN_NOTES_OK && n == 4u && !cut
	              && out[0]->id[0] == 1u,
	      "top level is the folder, then the orphan and both halves of the cycle");
	CHECK(fzn_notes_top_level(&view, out, 2u, &n, &cut) == FZN_NOTES_OK && n == 2u && cut,
	      "a top level that does not fit says so");

	/* TWO WRITERS: one agrees on the place, one moves the note. */
	note_of(1, KEY_B, 2, 1, 1, "B's copy, same place");
	CHECK(put(1, NULL) == FZN_NOTES_OK, "fixture: B's claim on 2");
	CHECK(fzn_notes_view_load(&store, &view) == FZN_NOTES_OK && view.count == 7u
	              && fzn_notes_contested(&view, contested, 4u) == 0u,
	      "two writers agreeing on a note's place are not a contest");
	CHECK(fzn_notes_children(&view, up, out, 16u, &n, &cut) == FZN_NOTES_OK && n == 3u,
	      "and the note is under the folder twice, once per claim");
	note_of(1, KEY_B, 2, 0, 2, "B moved it to the root");
	CHECK(put(1, NULL) == FZN_NOTES_OK, "fixture: B moves 2");
	CHECK(fzn_notes_view_load(&store, &view) == FZN_NOTES_OK
	              && fzn_notes_contested(&view, contested, 4u) == 1u && contested[0][0] == 2u,
	      "a note under two parents is contested, once");
	CHECK(fzn_notes_children(&view, root, out, 16u, &n, &cut) == FZN_NOTES_OK && n == 2u,
	      "and shows at the root as well as in the folder");

	/* A CLAIM THAT WILL NOT READ AS A NODE is counted. */
	{
		struct row *r = NULL;

		for (i = 0; i < MEM_ROWS && !r; i++)
			if (rows[i].used && rows[i].slot == FZN_PERSIST_NOTE)
				r = &rows[i];
		if (r)
			r->bytes[FZN_PERSIST_HEAD_LEN + 10u] ^= 0x01u;
		CHECK(fzn_notes_view_load(&store, &view) == FZN_NOTES_OK && view.count == 6u
		              && view.unreadable == 1u,
		      "a damaged claim is counted as unreadable, not dropped silently");
	}
	{
		fzn_notes_view_t *v = &view;

		wipe();
		CHECK(fzn_notes_view_load(&store, v) == FZN_NOTES_OK && v->count == 0u
		              && fzn_notes_top_level(v, out, 16u, &n, &cut) == FZN_NOTES_OK && n == 0u,
		      "an empty store is an empty view");
	}
}

/* ---- authoring, sec 426 ---------------------------------------------------- */

static uint64_t counter = 7;

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

static int zero_fill(void *ctx, uint8_t *out, size_t len)
{
	(void)ctx;
	memset(out, 0, len);
	return 1;
}

static fzn_notes_view_t author_view;

static fzn_notes_author_t author_as(uint8_t *key, fzn_sign_ops_t *ops)
{
	fzn_notes_author_t a;

	ops->verify = toy_verify;
	ops->sign = toy_sign;
	ops->ctx = key;
	a.store = &store;
	a.view = &author_view;
	a.issuer = key;
	a.sign = ops;
	a.rng = &RNG;
	a.policy = own_hosts();
	blob_stub_attach(&a);
	chain_stub_attach(&a);
	return a;
}

static fzn_note_t titled(const char *title, const char *text)
{
	fzn_note_t n;

	memset(&n, 0, sizeof(n));
	n.title = (const uint8_t *)title;
	n.title_len = strlen(title);
	n.text = (const uint8_t *)text;
	n.text_len = strlen(text);
	return n;
}

/* This host's own claim on `id`, opened: its node, and its note -- the
 * payload's fields with the meta's flags, colour and times beside them, and
 * the content's reference in `own_ref`. */
static fzn_note_blob_ref_t own_ref;

static int own(uint8_t *key, const uint8_t id[FZN_TREE_ID_LEN], fzn_record_t *rec,
               fzn_tree_node_t *node, fzn_note_t *note)
{
	static uint8_t out[FZN_RECORD_MAX_LEN], payload[FZN_NOTE_PAYLOAD_MAX];
	fzn_note_meta_t meta;
	size_t len = 0;

	if (fzn_notes_get(&store, id, key, out, sizeof(out), &len) != FZN_NOTES_OK
	    || fzn_record_open(out, len, rec) != FZN_RECORD_OK
	    || fzn_tree_open(*rec, node) != FZN_TREE_OK
	    || fzn_notes_read(&store, blob_stub_open, NULL, node, &meta, payload, sizeof(payload), note)
	               != FZN_NOTES_OK)
		return 0;
	note->flags = meta.flags;
	note->colour = meta.colour;
	note->created_at_ms = meta.created_at_ms;
	note->edited_at_ms = meta.edited_at_ms;
	own_ref = meta.content;
	return 1;
}

static int says(const fzn_note_t *n, const char *title, const char *text)
{
	return n->title_len == strlen(title) && memcmp(n->title, title, n->title_len) == 0
	       && n->text_len == strlen(text) && memcmp(n->text, text, n->text_len) == 0;
}

static void test_authoring(void)
{
	fzn_sign_ops_t ops_a, ops_b, ops_c;
	fzn_notes_author_t a = author_as(KEY_A, &ops_a), b = author_as(KEY_B, &ops_b);
	fzn_notes_author_t c = author_as(KEY_C, &ops_c);
	uint8_t root[FZN_TREE_ID_LEN], folder[FZN_TREE_ID_LEN], one[FZN_TREE_ID_LEN];
	uint8_t two[FZN_TREE_ID_LEN], theirs[FZN_TREE_ID_LEN], stray[FZN_TREE_ID_LEN];
	fzn_note_t note, with;
	fzn_record_t rec;
	fzn_tree_node_t node;
	uint64_t seq_before;
	size_t n = 0;
	int cut = 0;
	const fzn_tree_node_t *out[8];

	wipe();
	memset(root, 0, sizeof(root));

	/* ---- create */
	note = titled("milk", "two pints");
	CHECK(fzn_notes_create(&a, root, FZN_NOTE_TYPE_NOTE, &note, 5000u, one) == FZN_NOTES_OK,
	      "a note is created");
	CHECK(own(KEY_A, one, &rec, &node, &note) && says(&note, "milk", "two pints")
	              && note.created_at_ms == 5000u && note.edited_at_ms == 5000u
	              && fzn_tree_is_root(node.parent),
	      "it holds its fields and its times, at the top level");
	note = titled("milk", "two pints");
	CHECK(fzn_notes_create(&a, root, FZN_NOTE_TYPE_NOTE, &note, 5001u, two) == FZN_NOTES_OK
	              && memcmp(one, two, sizeof(one)) != 0,
	      "the same text again is a second note, with its own id");
	CHECK(fzn_notes_view_load(&store, &author_view) == FZN_NOTES_OK
	              && fzn_notes_children(&author_view, root, out, 8u, &n, &cut) == FZN_NOTES_OK
	              && n == 2u && memcmp(out[0]->id, one, sizeof(one)) == 0,
	      "and comes after the first");
	memset(&note, 0, sizeof(note));
	CHECK(fzn_notes_create(&a, root, FZN_NOTE_TYPE_FOLDER, &note, 5002u, folder)
	              == FZN_NOTES_OK,
	      "a folder is created");
	note = titled("a folder", "with text");
	CHECK(fzn_notes_create(&a, root, FZN_NOTE_TYPE_FOLDER, &note, 5003u, stray)
	              == FZN_NOTES_ERR_MALFORMED,
	      "a folder holding text is refused at creation");
	CHECK(fzn_notes_create(&a, root, FZN_NOTE_TYPE_ATTACHMENT, &note, 5003u, stray)
	              == FZN_NOTES_ERR_MALFORMED,
	      "a type this build may not write is refused");
	note = titled("from a stranger", "");
	{
		size_t chained = chain_stub.chained;

		CHECK(fzn_notes_create(&c, root, FZN_NOTE_TYPE_NOTE, &note, 5003u, stray)
		                      == FZN_NOTES_ERR_DENIED
		              && chain_stub.chained == chained,
		      "a host outside its own admitted set cannot write a note, nor chain one");
	}

	/* ---- the chain, sec 517: every record the next of this host's
	 * stream, naming the one before; nothing written when the chain is
	 * missing or refuses. */
	{
		fzn_notes_author_t unchained = a;
		static const uint8_t zero[FZN_RECORD_ID_LEN];
		size_t chained = chain_stub.chained, i;
		uint64_t first_seq = 0;

		/* `own` reads into one buffer, so the first sequence is kept
		 * before the second record is read over it. */
		CHECK(own(KEY_A, one, &rec, &node, &note) && (first_seq = fzn_record_seq(rec)) > 0u
		              && own(KEY_A, two, &rec, &node, &note)
		              && fzn_record_seq(rec) == first_seq + 1u
		              && memcmp(fzn_record_prev(rec), zero, sizeof(zero)) != 0,
		      "the second note's record follows the first's, naming one before it");
		unchained.chain = NULL;
		note = titled("unchained", "");
		CHECK(fzn_notes_create(&unchained, root, FZN_NOTE_TYPE_NOTE, &note, 5004u, stray)
		                      == FZN_NOTES_ERR_MALFORMED
		              && chain_stub.chained == chained,
		      "an author with no chain writes nothing");
		chain_stub.refuse = 1;
		CHECK(fzn_notes_create(&a, root, FZN_NOTE_TYPE_NOTE, &note, 5004u, stray)
		                      == FZN_NOTES_ERR_BACKEND
		              && fzn_notes_view_load(&store, &author_view) == FZN_NOTES_OK
		              && fzn_notes_children(&author_view, root, out, 8u, &n, &cut)
		                         == FZN_NOTES_OK
		              && n == 3u,
		      "a chain that will not write leaves no note in the index");
		chain_stub.refuse = 0;
		/* A STORE FROM BEFORE THE CHAIN: its record of a note at a sequence
		 * past where the chain stands. Said, not silently dropped. */
		for (i = 0; i < chain_stub.count; i++)
			if (memcmp(chain_stub.issuer[i], KEY_A, FZN_PUBKEY_LEN) == 0)
				break;
		if (i < chain_stub.count) {
			uint64_t was = chain_stub.seq[i];

			/* Below `two`'s record, and on no sequence another of
			 * `two`'s records holds. */
			chain_stub.seq[i] = 0;
			CHECK(fzn_notes_edit(&a, two, 0u, NULL, FZN_NOTE_FLAG_PINNED, 0u, 5005u)
			              == FZN_NOTES_ERR_SHAPE,
			      "an edit the index holds a later record of is refused, not dropped");
			chain_stub.seq[i] = was;
		}
	}

	/* ---- edit */
	CHECK(own(KEY_A, one, &rec, &node, &note), "fixture: the first note");
	seq_before = fzn_record_seq(rec);
	with = titled("oat milk", "");
	CHECK(fzn_notes_edit(&a, one, FZN_NOTES_EDIT_TITLE, &with, 0u, 0u, 6000u) == FZN_NOTES_OK
	              && own(KEY_A, one, &rec, &node, &note) && says(&note, "oat milk", "two pints")
	              && note.created_at_ms == 5000u && note.edited_at_ms == 6000u
	              && fzn_record_seq(rec) > seq_before && fzn_tree_is_root(node.parent),
	      "a rename keeps the text, the creation time and the place");
	CHECK(fzn_notes_edit(&a, one, 0u, NULL, FZN_NOTE_FLAG_TRASHED | FZN_NOTE_FLAG_PINNED, 0u,
	                     6001u)
	              == FZN_NOTES_OK
	              && own(KEY_A, one, &rec, &node, &note)
	              && (note.flags & FZN_NOTE_FLAG_TRASHED) && (note.flags & FZN_NOTE_FLAG_PINNED),
	      "a note is trashed and pinned");
	with = titled("", "three pints");
	CHECK(fzn_notes_edit(&a, one, FZN_NOTES_EDIT_TEXT, &with, 0u, 0u, 6002u) == FZN_NOTES_OK
	              && own(KEY_A, one, &rec, &node, &note) && says(&note, "oat milk", "three pints")
	              && (note.flags & FZN_NOTE_FLAG_TRASHED) && (note.flags & FZN_NOTE_FLAG_PINNED),
	      "editing the text neither un-trashes nor unpins it");
	CHECK(fzn_notes_edit(&a, one, 0u, NULL, 0u, FZN_NOTE_FLAG_TRASHED, 6003u) == FZN_NOTES_OK
	              && own(KEY_A, one, &rec, &node, &note)
	              && !(note.flags & FZN_NOTE_FLAG_TRASHED) && (note.flags & FZN_NOTE_FLAG_PINNED),
	      "and is brought back from the trash, still pinned");
	/* ---- the content is a blob, sec 514: a text of any length up to the
	 * payload's bound is sealed whole; a flag edit keeps the reference, a
	 * content edit seals a new one, and a note whose content is not here
	 * can be flagged and not edited. */
	{
		static uint8_t long_text[5000];
		fzn_note_blob_ref_t first;

		memset(long_text, 'x', sizeof(long_text));
		memset(&with, 0, sizeof(with));
		with.text = long_text;
		with.text_len = sizeof(long_text);
		CHECK(fzn_notes_edit(&a, one, FZN_NOTES_EDIT_TEXT, &with, 0u, 0u, 6004u)
		              == FZN_NOTES_OK
		              && own(KEY_A, one, &rec, &node, &note) && note.text_len == 5000u
		              && note.title_len == 8u && memcmp(note.title, "oat milk", 8u) == 0
		              && own_ref.length == 9u + 8u + 5000u,
		      "a long text is sealed whole beside the title");
		first = own_ref;
		CHECK(fzn_notes_edit(&a, one, 0u, NULL, 0u, FZN_NOTE_FLAG_PINNED, 6005u) == FZN_NOTES_OK
		              && own(KEY_A, one, &rec, &node, &note)
		              && memcmp(&own_ref, &first, sizeof(first)) == 0,
		      "unpinning keeps the reference: the same content under the same key");
		with = titled("", "short again");
		CHECK(fzn_notes_edit(&a, one, FZN_NOTES_EDIT_TEXT, &with, 0u, 0u, 6006u)
		              == FZN_NOTES_OK
		              && own(KEY_A, one, &rec, &node, &note)
		              && says(&note, "oat milk", "short again")
		              && memcmp(own_ref.root, first.root, sizeof(first.root)) != 0,
		      "and a text edit seals a new blob");
		blob_stub.refuse = 1;
		with = titled("", "unsealed");
		CHECK(fzn_notes_edit(&a, one, FZN_NOTES_EDIT_TEXT, &with, 0u, 0u, 6007u)
		              != FZN_NOTES_OK
		              && own(KEY_A, one, &rec, &node, &note)
		              && says(&note, "oat milk", "short again"),
		      "a seal that fails writes nothing");
		blob_stub.refuse = 0;
		with = titled("gone", "soon");
		CHECK(fzn_notes_create(&a, root, FZN_NOTE_TYPE_NOTE, &with, 6008u, stray)
		              == FZN_NOTES_OK
		              && own(KEY_A, stray, &rec, &node, &note),
		      "fixture: a note whose content is about to go");
		blob_stub_drop(&own_ref);
		with = titled("renamed", "");
		CHECK(fzn_notes_edit(&a, stray, FZN_NOTES_EDIT_TITLE, &with, 0u, 0u, 6009u)
		              == FZN_NOTES_ERR_PENDING,
		      "a note whose content is not here cannot have it edited");
		CHECK(fzn_notes_edit(&a, stray, 0u, NULL, FZN_NOTE_FLAG_TRASHED, 0u, 6010u)
		              == FZN_NOTES_OK
		              && !own(KEY_A, stray, &rec, &node, &note),
		      "and can still be trashed, its content still not here");
	}
	CHECK(fzn_notes_edit(&a, one, 0u, NULL, FZN_NOTE_FLAG_TRASHED, FZN_NOTE_FLAG_TRASHED, 1u)
	              == FZN_NOTES_ERR_MALFORMED,
	      "setting and clearing one flag at once is refused");
	CHECK(fzn_notes_edit(&a, one, 0u, NULL, 0x08u, 0u, 1u) == FZN_NOTES_ERR_MALFORMED,
	      "version 1's blob flag is no flag an edit may set");
	CHECK(fzn_notes_edit(&a, one, 0u, NULL, 0u, 0u, 1u) == FZN_NOTES_ERR_MALFORMED,
	      "an edit that changes nothing is refused");
	CHECK(fzn_notes_edit(&a, root, 0u, NULL, FZN_NOTE_FLAG_PINNED, 0u, 1u)
	              == FZN_NOTES_ERR_ABSENT,
	      "the root is not a note");
	memset(stray, 0x77, sizeof(stray));
	CHECK(fzn_notes_edit(&a, stray, 0u, NULL, FZN_NOTE_FLAG_PINNED, 0u, 1u)
	              == FZN_NOTES_ERR_ABSENT,
	      "a note nobody holds is absent");

	/* ---- labels survive an edit that does not name them, as fuzzypickles
	 * found theirs did not (their sec 146) */
	{
		static const uint8_t labels[] = { 'h', 'o', 'm', 'e', 0, 'd', 'a', 'i', 'r', 'y' };
		uint8_t tagged[FZN_TREE_ID_LEN];
		const uint8_t *label = NULL;
		size_t label_len = 0;

		note = titled("cheese", "cheddar");
		note.labels = labels;
		note.labels_len = sizeof(labels);
		CHECK(fzn_notes_create(&a, root, FZN_NOTE_TYPE_NOTE, &note, 6500u, tagged)
		              == FZN_NOTES_OK,
		      "fixture: a note with two labels");
		with = titled("brie", "");
		CHECK(fzn_notes_edit(&a, tagged, FZN_NOTES_EDIT_TITLE, &with, 0u, 0u, 6600u)
		              == FZN_NOTES_OK
		              && own(KEY_A, tagged, &rec, &node, &note)
		              && note.labels_len == sizeof(labels)
		              && memcmp(note.labels, labels, sizeof(labels)) == 0
		              && fzn_note_label_count(&note) == 2u,
		      "a rename keeps the note's labels");
		memset(&with, 0, sizeof(with));
		with.labels = labels + 5;
		with.labels_len = 5u;
		CHECK(fzn_notes_edit(&a, tagged, FZN_NOTES_EDIT_LABELS, &with, 0u, 0u, 6700u)
		              == FZN_NOTES_OK
		              && own(KEY_A, tagged, &rec, &node, &note)
		              && fzn_note_label_count(&note) == 1u
		              && fzn_note_label(&note, 0u, &label, &label_len) == FZN_NOTE_OK
		              && label_len == 5u && memcmp(label, "dairy", 5u) == 0
		              && says(&note, "brie", "cheddar"),
		      "and an edit naming them replaces them, keeping the rest");
	}

	/* ---- another writer's note */
	note = titled("B's note", "from the phone");
	CHECK(fzn_notes_create(&b, folder, FZN_NOTE_TYPE_NOTE, &note, 7000u, theirs)
	              == FZN_NOTES_OK,
	      "a sibling writes a note into the folder");
	with = titled("renamed here", "");
	CHECK(fzn_notes_edit(&a, theirs, FZN_NOTES_EDIT_TITLE, &with, 0u, 0u, 7100u)
	              == FZN_NOTES_OK
	              && own(KEY_A, theirs, &rec, &node, &note)
	              && says(&note, "renamed here", "from the phone")
	              && note.created_at_ms == 7000u
	              && memcmp(node.parent, folder, sizeof(folder)) == 0,
	      "this host's edit of it keeps its text, its creation and its place");
	CHECK(own(KEY_B, theirs, &rec, &node, &note) && says(&note, "B's note", "from the phone"),
	      "and joins the sibling's claim rather than replacing it");
	CHECK(fzn_notes_edit(&a, theirs, 0u, NULL, FZN_NOTE_FLAG_PINNED, 0u, 7200u) == FZN_NOTES_OK
	              && own(KEY_A, theirs, &rec, &node, &note)
	              && says(&note, "renamed here", "from the phone"),
	      "a second edit starts from this host's own claim, not the sibling's");

	/* ---- move */
	CHECK(fzn_notes_move(&a, two, folder, 8000u) == FZN_NOTES_OK
	              && own(KEY_A, two, &rec, &node, &note)
	              && memcmp(node.parent, folder, sizeof(folder)) == 0
	              && says(&note, "milk", "two pints") && note.edited_at_ms == 8000u,
	      "a move changes the parent and keeps the note");
	CHECK(fzn_notes_view_load(&store, &author_view) == FZN_NOTES_OK
	              && fzn_notes_children(&author_view, folder, out, 8u, &n, &cut) == FZN_NOTES_OK
	              && n == 3u && memcmp(out[2]->id, two, sizeof(two)) == 0,
	      "and puts it last among the folder's children");
	CHECK(fzn_notes_move(&a, two, two, 8001u) == FZN_NOTES_ERR_MALFORMED,
	      "a note is not its own parent");
	/* NOR UNDER ITS OWN DESCENDANT, sec 453: `two` is in the folder now,
	 * and `deep` under `two`. */
	{
		uint8_t deep[FZN_TREE_ID_LEN];

		note = titled("deep", "");
		CHECK(fzn_notes_create(&a, two, FZN_NOTE_TYPE_NOTE, &note, 8002u, deep)
		              == FZN_NOTES_OK,
		      "fixture: a note under the moved one");
		CHECK(fzn_notes_move(&a, folder, two, 8003u) == FZN_NOTES_ERR_MALFORMED,
		      "a folder does not move under its own child");
		CHECK(fzn_notes_move(&a, folder, deep, 8003u) == FZN_NOTES_ERR_MALFORMED
		              && own(KEY_A, folder, &rec, &node, &note)
		              && memcmp(node.parent, root, sizeof(root)) == 0,
		      "nor under its grandchild, and it stays where it was");
		CHECK(fzn_notes_move(&a, deep, folder, 8004u) == FZN_NOTES_OK,
		      "while a note moves up under its own ancestor");
	}
	CHECK(fzn_notes_move(&a, stray, folder, 8001u) == FZN_NOTES_ERR_ABSENT,
	      "a note nobody holds does not move");

	/* ---- a random source that answers zeros does not make the root */
	{
		static const fzn_random_ops_t zeros = { zero_fill, NULL };
		fzn_notes_author_t z = a;

		z.rng = &zeros;
		note = titled("zeros", "");
		CHECK(fzn_notes_create(&z, root, FZN_NOTE_TYPE_NOTE, &note, 8500u, stray)
		              == FZN_NOTES_OK
		              && !fzn_tree_is_root(stray),
		      "an all-zero id is not taken: that is the root");
	}

	/* ---- a note this build cannot read is not edited */
	{
		uint8_t subject[FZN_SUBJECT_LEN], body[FZN_RECORD_BODY_MAX], bad[8];
		fzn_sign_ops_t signer = { NULL, toy_sign, KEY_B };
		size_t body_len = 0, len = 0;

		memset(bad, 0xee, sizeof(bad));
		memset(subject, 0x66, sizeof(subject));
		CHECK(fzn_tree_body(folder, 1u, 0x7777u, bad, sizeof(bad), body, sizeof(body),
		                    &body_len)
		                      == FZN_TREE_OK
		              && fzn_record_sign(KEY_B, subject, FZN_NOTE_STREAM, FZN_NOTE_KIND, 900u, NULL,
		                                 1u, body, body_len, &signer, buf[0], FZN_RECORD_MAX_LEN,
		                                 &len)
		                         == FZN_RECORD_OK,
		      "fixture: a node from a newer host this build cannot read");
		buf_len[0] = len;
		CHECK(put(0, NULL) == FZN_NOTES_OK, "fixture: it is held");
		CHECK(fzn_notes_edit(&a, subject, 0u, NULL, FZN_NOTE_FLAG_PINNED, 0u, 9000u)
		              == FZN_NOTES_ERR_SHAPE,
		      "editing it is refused rather than writing its fields back empty");
		CHECK(fzn_notes_get(&store, subject, KEY_A, buf[1], FZN_RECORD_MAX_LEN, &len)
		              == FZN_NOTES_ERR_ABSENT,
		      "and nothing was written for it");
	}
}

/* ---- purge, sec 427 ---------------------------------------------------- */

static int held_claims(const uint8_t id[FZN_TREE_ID_LEN])
{
	uint8_t out[FZN_RECORD_MAX_LEN];
	size_t len = 0;

	return (fzn_notes_get(&store, id, KEY_A, out, sizeof(out), &len) == FZN_NOTES_OK)
	       + (fzn_notes_get(&store, id, KEY_B, out, sizeof(out), &len) == FZN_NOTES_OK);
}

/* Heard from lately: KEY_C while `hear_c` is set, nobody else. */
static int hear_c;
static unsigned heard_asked;

static int heard_stub(void *ctx, const uint8_t host[FZN_PUBKEY_LEN], uint64_t now_ms)
{
	(void)ctx;
	(void)now_ms;
	heard_asked++;
	return hear_c && memcmp(host, KEY_C, FZN_PUBKEY_LEN) == 0;
}

static void test_purge(void)
{
	fzn_sign_ops_t ops_a, ops_b;
	fzn_notes_author_t a = author_as(KEY_A, &ops_a), b = author_as(KEY_B, &ops_b);
	fzn_notes_writer_t hosts[3];
	fzn_notes_asking_t zeroed;
	fzn_notes_purge_t p;
	uint8_t root[FZN_TREE_ID_LEN], one[FZN_TREE_ID_LEN], two[FZN_TREE_ID_LEN];
	uint8_t three[FZN_TREE_ID_LEN], due[4][FZN_TREE_ID_LEN];
	fzn_note_t note;
	size_t n = 0, erased = 0;
	int complete = -1;

	wipe();
	memset(root, 0, sizeof(root));
	memset(&zeroed, 0, sizeof(zeroed));
	memcpy(hosts[0].key, KEY_B, FZN_PUBKEY_LEN);
	memcpy(hosts[1].key, KEY_C, FZN_PUBKEY_LEN);
	memcpy(hosts[2].key, KEY_B, FZN_PUBKEY_LEN);
	note = titled("to go", "");
	CHECK(fzn_notes_create(&a, root, FZN_NOTE_TYPE_NOTE, &note, 1u, one) == FZN_NOTES_OK,
	      "fixture: a note");
	/* B edits it too, so it carries two claims. */
	CHECK(fzn_notes_edit(&b, one, 0u, NULL, FZN_NOTE_FLAG_PINNED, 0u, 2u) == FZN_NOTES_OK
	              && held_claims(one) == 2,
	      "fixture: two writers' claims on it");

	CHECK(fzn_notes_purge_add(&store, one, zeroed, 10u, &complete) == FZN_NOTES_ERR_MALFORMED
	              && complete == 0 && !fzn_notes_purge_pending(&store, one),
	      "an unspelled set is refused, not read as nobody to ask");
	CHECK(fzn_notes_purge_add(&store, one, fzn_notes_asking(hosts, 3u), 10u, &complete)
	              == FZN_NOTES_OK
	              && complete == 0 && fzn_notes_purge_pending(&store, one),
	      "a purge is queued");
	CHECK(fzn_notes_purge_get(&store, one, &p) == FZN_NOTES_OK && p.asked_count == 2u
	              && p.queued_at_ms == 10u,
	      "with a host named twice asked once");
	CHECK(fzn_notes_purge_add(&store, one, fzn_notes_asking(hosts, 1u), 11u, &complete)
	              == FZN_NOTES_OK
	              && fzn_notes_purge_get(&store, one, &p) == FZN_NOTES_OK && p.asked_count == 2u
	              && p.queued_at_ms == 10u,
	      "queuing it again keeps the set pinned the first time");

	CHECK(fzn_notes_purge_answer(&store, one, KEY_A, &complete) == FZN_NOTES_OK && !complete,
	      "a host outside the pinned set does not advance it");
	CHECK(fzn_notes_purge_answer(&store, one, KEY_B, &complete) == FZN_NOTES_OK && !complete,
	      "one answer of two is not consent");
	CHECK(fzn_notes_purge_answer(&store, one, KEY_C, &complete) == FZN_NOTES_OK && complete,
	      "the last answer is");
	CHECK(fzn_notes_purge_answer(&store, one, KEY_C, &complete) == FZN_NOTES_OK && complete,
	      "and answering again changes nothing");
	{
		fzn_persist_ops_t no_remove = OPS;
		fzn_notes_store_t fixed;

		no_remove.remove = NULL;
		CHECK(fzn_notes_store_init(&fixed, &no_remove, &HASH) == FZN_NOTES_OK
		              && fzn_notes_purge_finish(&fixed, one) == FZN_NOTES_ERR_UNSUPPORTED
		              && fzn_notes_erase_note(&fixed, one, &erased) == FZN_NOTES_ERR_UNSUPPORTED
		              && fzn_notes_purge_pending(&store, one) && held_claims(one) == 2
		              && !fzn_notes_purged(&store, one),
		      "a store that cannot forget does not finish, keeps the purge, and marks nothing");
	}
	/* B's record of the note, kept to offer again once it is purged. */
	{
		static uint8_t kept[FZN_RECORD_MAX_LEN];
		size_t kept_len = 0;
		int wrote = 1;

		CHECK(fzn_notes_get(&store, one, KEY_B, kept, sizeof(kept), &kept_len) == FZN_NOTES_OK,
		      "fixture: B's record of the note");
		note = titled("bystander", "");
		CHECK(fzn_notes_create(&a, root, FZN_NOTE_TYPE_NOTE, &note, 4u, three) == FZN_NOTES_OK,
		      "fixture: a note nobody is purging");
		CHECK(fzn_notes_purge_finish(&store, one) == FZN_NOTES_OK && held_claims(one) == 0
		              && !fzn_notes_purge_pending(&store, one),
		      "finishing erases every writer's claim, then the purge");
		CHECK(held_claims(three) == 1, "and leaves every other note alone");
		/* THE MARK, sec 518: the note's records are still in its writers'
		 * streams, and none of them is filed again. */
		CHECK(fzn_notes_purged(&store, one) && !fzn_notes_purged(&store, three),
		      "the purged note is marked, and the bystander is not");
		CHECK(fzn_notes_put(&store, kept, kept_len, own_hosts(), &VERIFY, &wrote, NULL)
		                      == FZN_NOTES_ERR_PURGED
		              && held_claims(one) == 0,
		      "a record of the purged note offered again is refused, and nothing is filed");
		CHECK(fzn_notes_edit(&b, three, 0u, NULL, FZN_NOTE_FLAG_PINNED, 0u, 5u) == FZN_NOTES_OK
		              && held_claims(three) == 2,
		      "while another note takes a new writer's record as before");
	}

	/* ---- retry */
	note = titled("second", "");
	CHECK(fzn_notes_create(&a, root, FZN_NOTE_TYPE_NOTE, &note, 3u, two) == FZN_NOTES_OK
	              && fzn_notes_purge_add(&store, two, fzn_notes_asking(hosts, 2u), 100u,
	                                     &complete)
	                         == FZN_NOTES_OK,
	      "fixture: a second purge");
	CHECK(fzn_notes_purge_due(&store, 1000u, due, 4u, &n) == FZN_NOTES_OK && n == 1u
	              && memcmp(due[0], two, sizeof(two)) == 0,
	      "a purge never asked is due");
	CHECK(fzn_notes_purge_due(&store, 1000u + FZN_NOTES_PURGE_RETRY_MS - 1u, due, 4u, &n)
	                      == FZN_NOTES_OK
	              && n == 0u,
	      "and not again before the retry interval");
	CHECK(fzn_notes_purge_due(&store, 1000u + FZN_NOTES_PURGE_RETRY_MS, due, 4u, &n)
	                      == FZN_NOTES_OK
	              && n == 1u,
	      "but at it");
	/* A CLOCK SET BACK, sec 469: the stamp is now in the future. A purge
	 * waiting for the clock to reach it would be wedged until it did --
	 * fuzzypickles met that on a phone booted years ahead -- so it is due at
	 * once and stamped again from the clock as it now reads. */
	CHECK(fzn_notes_purge_due(&store, 500u, due, 4u, &n) == FZN_NOTES_OK && n == 1u,
	      "a purge stamped in the future is due at once, not when the clock reaches it");
	CHECK(fzn_notes_purge_due(&store, 500u + FZN_NOTES_PURGE_RETRY_MS - 1u, due, 4u, &n)
	                      == FZN_NOTES_OK
	              && n == 0u,
	      "and is stamped again, so it is not asked again before an interval from then");

	/* ---- releasing what the silent pin, sec 472 */
	{
		uint8_t four[FZN_TREE_ID_LEN];
		size_t released = 9, finished = 9;

		CHECK(fzn_notes_purge_release(&store, 100u + 1000u, 1000u, heard_stub, NULL, &released,
		                              &finished)
		                      == FZN_NOTES_OK
		              && released == 0u && finished == 0u && fzn_notes_purge_pending(&store, two),
		      "a purge exactly the age old releases nobody");
		hear_c = 1;
		CHECK(fzn_notes_purge_release(&store, 100u + 1001u, 1000u, heard_stub, NULL, &released,
		                              &finished)
		                      == FZN_NOTES_OK
		              && released == 1u && finished == 0u && fzn_notes_purge_pending(&store, two)
		              && fzn_notes_purge_get(&store, two, &p) == FZN_NOTES_OK
		              && p.answered[0] && !p.answered[1],
		      "past it, the silent host is released and one heard from lately still pins");
		hear_c = 0;
		CHECK(fzn_notes_purge_release(&store, 100u + 1001u, 1000u, heard_stub, NULL, &released,
		                              &finished)
		                      == FZN_NOTES_OK
		              && released == 1u && finished == 1u && !fzn_notes_purge_pending(&store, two)
		              && held_claims(two) == 0,
		      "and once every host is answered or silent, the purge finishes");

		note = titled("fourth", "");
		CHECK(fzn_notes_create(&a, root, FZN_NOTE_TYPE_NOTE, &note, 5u, four) == FZN_NOTES_OK
		              && fzn_notes_purge_add(&store, four, fzn_notes_asking(hosts, 2u),
		                                     1000000u, &complete)
		                         == FZN_NOTES_OK,
		      "fixture: a purge queued while the clock read far ahead");
		heard_asked = 0;
		CHECK(fzn_notes_purge_release(&store, 5000u, 1000u, heard_stub, NULL, &released,
		                              &finished)
		                      == FZN_NOTES_OK
		              && released == 0u && heard_asked == 0u
		              && fzn_notes_purge_get(&store, four, &p) == FZN_NOTES_OK
		              && p.queued_at_ms == 5000u,
		      "a purge queued in the future is stamped again from now, releasing nobody");
		CHECK(fzn_notes_purge_release(&store, 6001u, 1000u, heard_stub, NULL, &released,
		                              &finished)
		                      == FZN_NOTES_OK
		              && finished == 1u && !fzn_notes_purge_pending(&store, four),
		      "and ages from then, not from the clock that was wrong");

		/* EVERY HOST ANSWERED AND NOTHING FINISHED IT -- the erase after the
		 * last answer failed, as fuzzypickles found theirs could. Nobody is
		 * left to release, and the purge must finish anyway. */
		{
			uint8_t five[FZN_TREE_ID_LEN];

			note = titled("fifth", "");
			CHECK(fzn_notes_create(&a, root, FZN_NOTE_TYPE_NOTE, &note, 6u, five) == FZN_NOTES_OK
			              && fzn_notes_purge_add(&store, five, fzn_notes_asking(hosts, 2u), 6001u,
			                                     &complete) == FZN_NOTES_OK
			              && fzn_notes_purge_answer(&store, five, KEY_B, &complete) == FZN_NOTES_OK
			              && fzn_notes_purge_answer(&store, five, KEY_C, &complete) == FZN_NOTES_OK
			              && complete && fzn_notes_purge_pending(&store, five),
			      "fixture: a purge every host answered, its erase never made");
			CHECK(fzn_notes_purge_release(&store, 6001u + 1001u, 1000u, heard_stub, NULL,
			                              &released, &finished) == FZN_NOTES_OK
			              && released == 0u && finished == 1u
			              && !fzn_notes_purge_pending(&store, five) && held_claims(five) == 0,
			      "a purge every host had answered was never finished by a release");
		}
		CHECK(fzn_notes_purge_release(&store, 6001u, 1000u, NULL, NULL, &released, &finished)
		              == FZN_NOTES_ERR_MALFORMED,
		      "with no measure of who was heard, nothing is released");
	}

	/* ---- the bound */
	{
		uint8_t id[FZN_TREE_ID_LEN];
		size_t i;
		int ok = 1;

		uint8_t queued[FZN_NOTES_PURGE_MAX][FZN_TREE_ID_LEN];

		CHECK(fzn_notes_purge_list(&store, queued, FZN_NOTES_PURGE_MAX, &n) == FZN_NOTES_OK
		              && n == 0u,
		      "fixture: the queue is empty, every purge above finished");
		memset(id, 0x40, sizeof(id));
		for (i = 0; i < FZN_NOTES_PURGE_MAX && ok; i++) {
			id[0] = (uint8_t)i;
			ok = fzn_notes_purge_add(&store, id, fzn_notes_asking(hosts, 1u), 7u, &complete)
			     == FZN_NOTES_OK;
		}
		CHECK(ok, "fixture: the queue fills to its bound");
		id[0] = 0xffu;
		CHECK(fzn_notes_purge_add(&store, id, fzn_notes_asking(hosts, 1u), 7u, &complete)
		              == FZN_NOTES_ERR_FULL
		              && !fzn_notes_purge_pending(&store, id),
		      "one purge past the bound is refused, and nothing queued");
	}

	/* ---- a host on its own */
	CHECK(fzn_notes_purge_add(&store, root, fzn_notes_asking(NULL, 0u), 5u, &complete)
	                      == FZN_NOTES_OK
	              && complete && !fzn_notes_purge_pending(&store, root),
	      "nobody to ask is consent at once, with nothing queued");

	/* ---- emptying the trash */
	wipe();
	note = titled("trashed", "");
	CHECK(fzn_notes_create(&a, root, FZN_NOTE_TYPE_NOTE, &note, 1u, one) == FZN_NOTES_OK
	              && fzn_notes_edit(&a, one, 0u, NULL, FZN_NOTE_FLAG_TRASHED, 0u, 2u)
	                         == FZN_NOTES_OK,
	      "fixture: a trashed note of A's");
	note = titled("kept", "");
	CHECK(fzn_notes_create(&a, root, FZN_NOTE_TYPE_NOTE, &note, 3u, two) == FZN_NOTES_OK,
	      "fixture: a note of A's not trashed");
	note = titled("B's trash", "");
	CHECK(fzn_notes_create(&b, root, FZN_NOTE_TYPE_NOTE, &note, 4u, three) == FZN_NOTES_OK
	              && fzn_notes_edit(&b, three, 0u, NULL, FZN_NOTE_FLAG_TRASHED, 0u, 5u)
	                         == FZN_NOTES_OK,
	      "fixture: a trashed note of B's");
	CHECK(fzn_notes_purge_trash(&store, &author_view, KEY_A, fzn_notes_asking(hosts, 1u), 9u,
	                            &n)
	                      == FZN_NOTES_OK
	              && n == 1u && fzn_notes_purge_pending(&store, one)
	              && !fzn_notes_purge_pending(&store, two)
	              && !fzn_notes_purge_pending(&store, three),
	      "emptying A's trash queues A's trashed note and nothing else");
	CHECK(fzn_notes_purge_trash(&store, &author_view, KEY_A, zeroed, 9u, &n)
	              == FZN_NOTES_ERR_MALFORMED,
	      "and refuses an unspelled set");
	CHECK(fzn_notes_purge_trash(&store, &author_view, KEY_B, fzn_notes_asking(NULL, 0u), 9u,
	                            &n)
	                      == FZN_NOTES_OK
	              && n == 1u && fzn_notes_get(&store, three, KEY_B, buf[0], FZN_RECORD_MAX_LEN,
	                                          &erased)
	                                     == FZN_NOTES_ERR_ABSENT
	              && !fzn_notes_purge_pending(&store, three),
	      "a host on its own empties its trash at once");

	/* ---- a purge row that will not read still holds the note back */
	{
		struct row *r = find(FZN_PERSIST_NOTE_PURGE, one);

		if (r)
			r->bytes[FZN_PERSIST_HEAD_LEN + OFF_COUNT_FOR_TEST] = 0u;
		CHECK(r && fzn_notes_purge_get(&store, one, &p) == FZN_NOTES_ERR_SHAPE
		              && fzn_notes_purge_pending(&store, one),
		      "a damaged purge still counts as pending");
	}
}

/* ---- import, sec 429 ---------------------------------------------------- */

/* What a parser handed over, copied out of its scratch. */
static struct got {
	uint16_t type;
	uint8_t title[64], text[64], labels[64];
	size_t title_len, text_len, labels_len;
	uint8_t flags;
	uint64_t created;
} got[8];
static size_t got_count;
static size_t got_long_len;
static int refusals[8];
static size_t refusal_count;

static int collect(void *ctx, const fzn_notes_import_entry_t *e)
{
	struct got *g = &got[got_count % 8u];

	(void)ctx;
	got_count++;
	got_long_len = e->text_len;
	g->type = e->content_type;
	g->title_len = e->title_len < 64u ? e->title_len : 64u;
	g->text_len = e->text_len < 64u ? e->text_len : 64u;
	g->labels_len = e->labels_len < 64u ? e->labels_len : 64u;
	memcpy(g->title, e->title, g->title_len);
	memcpy(g->text, e->text, g->text_len);
	memcpy(g->labels, e->labels, g->labels_len);
	g->flags = e->flags;
	g->created = e->created_at_ms;
	return 0;
}

static void note_refusal(void *ctx, fzn_notes_import_refusal_t why, const uint8_t *t, size_t n)
{
	(void)ctx;
	(void)t;
	(void)n;
	refusals[refusal_count % 8u] = (int)why;
	refusal_count++;
}

static void reset_collect(void)
{
	got_count = 0;
	refusal_count = 0;
	memset(got, 0, sizeof(got));
}

static fzn_notes_err_t keep(const char *json)
{
	return fzn_notes_import_keep((const uint8_t *)json, strlen(json), collect, NULL,
	                             note_refusal, NULL);
}

static int is(const uint8_t *b, size_t n, const char *want)
{
	return n == strlen(want) && memcmp(b, want, n) == 0;
}

static uint8_t big[(2u * FZN_NOTE_TEXT_MAX) + 4096u];

static void test_import_parsing(void)
{
	size_t i, n;

	/* ---- Keep */
	reset_collect();
	CHECK(keep("{\"color\":\"DEFAULT\",\"isTrashed\":false,\"isPinned\":true,"
	           "\"isArchived\":false,\"textContent\":\"two pints\",\"title\":\"milk\","
	           "\"createdTimestampUsec\":1700000000123456,"
	           "\"labels\":[{\"name\":\"home\"},{\"name\":\"dairy\"}]}")
	              == FZN_NOTES_OK
	              && got_count == 1u && refusal_count == 0u,
	      "a Keep note is parsed");
	CHECK(got[0].type == FZN_NOTE_TYPE_NOTE && is(got[0].title, got[0].title_len, "milk")
	              && is(got[0].text, got[0].text_len, "two pints")
	              && got[0].flags == FZN_NOTE_FLAG_PINNED && got[0].created == 1700000000123u,
	      "with its title, text, pin and creation time");
	CHECK(got[0].labels_len == 10u && memcmp(got[0].labels, "home\0dairy", 10u) == 0,
	      "and both its labels, separated as a note's are");
	reset_collect();
	CHECK(keep("{\"attachments\":[{\"title\":\"not this\"}],\"title\":\"real\"}")
	              == FZN_NOTES_OK
	              && got_count == 1u && is(got[0].title, got[0].title_len, "real"),
	      "a key inside an attachment is not the note's");
	reset_collect();
	CHECK(keep("{\"title\":\"caf\\u00e9 \\ud83d\\ude00\"}") == FZN_NOTES_OK
	              && got_count == 1u
	              && is(got[0].title, got[0].title_len, "caf\xc3\xa9 \xf0\x9f\x98\x80"),
	      "\\u escapes decode to UTF-8, a surrogate pair as one character");
	reset_collect();
	CHECK(keep("{\"title\":\"half \\ud83d a pair\"}") == FZN_NOTES_OK && got_count == 0u
	              && refusal_count == 1u && refusals[0] == FZN_NOTES_IMPORT_UNPARSED,
	      "a lone surrogate refuses the note, which is named");
	reset_collect();
	CHECK(keep("{\"title\":\"a \\u0000 in it\"}") == FZN_NOTES_OK && got_count == 0u
	              && refusal_count == 1u && refusals[0] == FZN_NOTES_IMPORT_UNPARSED,
	      "a \\u0000 refuses its note: a title holds no NUL");
	{
		static const char raw[] = "{\"title\":\"a\0b\"}";

		reset_collect();
		CHECK(fzn_notes_import_keep((const uint8_t *)raw, sizeof(raw) - 1u, collect, NULL,
		                            note_refusal, NULL)
		                      == FZN_NOTES_OK
		              && got_count == 0u && refusal_count == 1u,
		      "as does a raw NUL byte inside a Keep string");
	}
	{
		static const char nul_ics[] = "BEGIN:VJOURNAL\r\nSUMMARY:a\0b\r\nEND:VJOURNAL\r\n";

		reset_collect();
		CHECK(fzn_notes_import_knotes((const uint8_t *)nul_ics, sizeof(nul_ics) - 1u,
		                              collect, NULL, note_refusal, NULL)
		                      == FZN_NOTES_OK
		              && got_count == 0u && refusal_count == 1u
		              && refusals[0] == FZN_NOTES_IMPORT_UNPARSED,
		      "and so does a NUL in a KNotes value");
	}
	reset_collect();
	CHECK(keep("{\"title\":\"shop\",\"textContent\":\"\",\"listContent\":["
	           "{\"text\":\"eggs\",\"isChecked\":true},"
	           "{\"text\":\"bread\",\"isChecked\":false}]}")
	              == FZN_NOTES_OK
	              && got_count == 1u && got[0].type == FZN_NOTE_TYPE_LIST,
	      "a Keep checklist is a list");
	{
		fzn_note_t list;
		fzn_note_item_t item;
		size_t cursor = 0;

		memset(&list, 0, sizeof(list));
		list.text = got[0].text;
		list.text_len = got[0].text_len;
		CHECK(fzn_note_item_next(&list, &cursor, &item) == FZN_NOTE_OK
		              && is(item.text, item.text_len, "eggs")
		              && item.flags == FZN_NOTE_ITEM_FLAG_CHECKED
		              && fzn_note_item_next(&list, &cursor, &item) == FZN_NOTE_OK
		              && is(item.text, item.text_len, "bread") && item.flags == 0u
		              && fzn_note_item_next(&list, &cursor, &item) == FZN_NOTE_ERR_SHORT,
		      "with its two items and their ticks");
	}
	reset_collect();
	CHECK(keep("{\"color\":\"RED\"}") == FZN_NOTES_OK && got_count == 0u
	              && refusal_count == 1u,
	      "an empty note is refused, not imported");
	/* A TEXT PAST THE BOUND is refused whole, never cut. */
	{
		static const char head[] = "{\"title\":\"huge\",\"textContent\":\"";

		n = sizeof(head) - 1u;
		memcpy(big, head, n);
	}
	for (i = 0; i < FZN_NOTE_TEXT_MAX + 10u; i++)
		big[n++] = 'x';
	memcpy(big + n, "\"}", 2u);
	n += 2u;
	reset_collect();
	CHECK(fzn_notes_import_keep(big, n, collect, NULL, note_refusal, NULL) == FZN_NOTES_OK
	              && got_count == 0u && refusal_count == 1u
	              && refusals[0] == FZN_NOTES_IMPORT_TOO_LONG,
	      "a text past the bound is refused as too long");

	/* ---- KNotes */
	{
		static const char ics[] =
		        "BEGIN:VCALENDAR\r\n"
		        "BEGIN:VJOURNAL\r\n"
		        "SUMMARY;LANGUAGE=en:first\\, really\r\n"
		        "DESCRIPTION:line one\\nline \r\n"
		        " two\r\n"
		        "CREATED:20231114T221320Z\r\n"
		        "END:VJOURNAL\r\n"
		        "BEGIN:VJOURNAL\r\n"
		        "summary:second\r\n"
		        "DTSTAMP:20240101T000000Z\r\n"
		        "END:VJOURNAL\r\n"
		        "BEGIN:VJOURNAL\r\n"
		        "SUMMARY:never ended\r\n";

		reset_collect();
		CHECK(fzn_notes_import_knotes((const uint8_t *)ics, sizeof(ics) - 1u, collect, NULL,
		                              note_refusal, NULL)
		                      == FZN_NOTES_OK
		              && got_count == 2u,
		      "two KNotes journals are parsed");
		CHECK(is(got[0].title, got[0].title_len, "first, really")
		              && is(got[0].text, got[0].text_len, "line one\nline two")
		              && got[0].created == 1700000000000u,
		      "unfolded and unescaped, with the creation time");
		CHECK(is(got[1].title, got[1].title_len, "second") && got[1].created == 0u,
		      "a lower-case property name is read, and DTSTAMP is not a creation time");
		CHECK(refusal_count == 1u && refusals[0] == FZN_NOTES_IMPORT_UNPARSED,
		      "a journal never ended is refused, not taken half");
	}
	/* A LONG DESCRIPTION, FOLDED, TAKEN WHOLE: fuzzypickles' copy cut it at
	 * 8 KiB without a word. */
	{
		static const char head[] = "BEGIN:VJOURNAL\r\nSUMMARY:long\r\nDESCRIPTION:";

		n = sizeof(head) - 1u;
		memcpy(big, head, n);
	}
	for (i = 0; i < 20000u; i++) {
		big[n++] = (uint8_t)('a' + (i % 26u));
		if (i % 70u == 69u) {
			memcpy(big + n, "\r\n ", 3u);
			n += 3u;
		}
	}
	{
		static const char tail[] = "\r\nEND:VJOURNAL\r\n";

		memcpy(big + n, tail, sizeof(tail) - 1u);
		n += sizeof(tail) - 1u;
	}
	reset_collect();
	CHECK(fzn_notes_import_knotes(big, n, collect, NULL, note_refusal, NULL) == FZN_NOTES_OK
	              && got_count == 1u && got_long_len == 20000u,
	      "a 20,000-byte folded description arrives whole");
}

static void test_import_run(void)
{
	fzn_sign_ops_t ops_a;
	fzn_notes_author_t a = author_as(KEY_A, &ops_a);
	fzn_notes_import_run_t run;
	uint8_t root[FZN_TREE_ID_LEN];
	static uint8_t payload[FZN_NOTE_PAYLOAD_MAX];
	fzn_note_t note;
	fzn_note_meta_t meta;
	size_t i, found = 0;
	static const char dated[] = "{\"title\":\"dated\",\"textContent\":\"x\","
	                            "\"createdTimestampUsec\":1600000000000000}";
	static const char undated[] = "{\"title\":\"undated\",\"textContent\":\"y\"}";

	wipe();
	memset(root, 0, sizeof(root));
	memset(&run, 0, sizeof(run));
	run.author = &a;
	note = titled("Imported", "");
	memset(&note, 0, sizeof(note));
	CHECK(fzn_notes_create(&a, root, FZN_NOTE_TYPE_FOLDER, &note, 1u, run.folder)
	              == FZN_NOTES_OK,
	      "fixture: a folder for the import");
	run.now_ms = 9000u;

	CHECK(fzn_notes_import_keep((const uint8_t *)dated, sizeof(dated) - 1u,
	                            fzn_notes_import_take, &run, fzn_notes_import_refuse, &run)
	                      == FZN_NOTES_OK
	              && fzn_notes_import_keep((const uint8_t *)undated, sizeof(undated) - 1u,
	                                       fzn_notes_import_take, &run, fzn_notes_import_refuse,
	                                       &run)
	                         == FZN_NOTES_OK
	              && run.imported == 2u && run.undated == 1u && run.refused == 0u,
	      "two notes are imported, one undated");
	CHECK(fzn_notes_view_load(&store, &author_view) == FZN_NOTES_OK, "fixture: the view");
	for (i = 0; i < author_view.count; i++)
		if (fzn_notes_read(&store, blob_stub_open, NULL, &author_view.nodes[i], &meta, payload,
		                   sizeof(payload), &note)
		            == FZN_NOTES_OK
		    && is(note.title, note.title_len, "dated")
		    && meta.created_at_ms == 1600000000000u && meta.edited_at_ms == 9000u
		    && memcmp(author_view.nodes[i].parent, run.folder, FZN_TREE_ID_LEN) == 0)
			found++;
	CHECK(found == 1u, "the dated note keeps its source's creation time, in the folder");

	CHECK(fzn_notes_import_keep((const uint8_t *)dated, sizeof(dated) - 1u,
	                            fzn_notes_import_take, &run, fzn_notes_import_refuse, &run)
	                      == FZN_NOTES_OK
	              && fzn_notes_import_keep((const uint8_t *)undated, sizeof(undated) - 1u,
	                                       fzn_notes_import_take, &run, fzn_notes_import_refuse,
	                                       &run)
	                         == FZN_NOTES_OK
	              && run.imported == 3u && run.already == 1u && run.undated == 2u,
	      "a second import recognises the dated note and cannot recognise the undated one");
	{
		static const char twin[] = "{\"title\":\"dated twin\",\"textContent\":\"z\","
		                           "\"createdTimestampUsec\":1600000000000000}";

		CHECK(fzn_notes_import_keep((const uint8_t *)twin, sizeof(twin) - 1u,
		                            fzn_notes_import_take, &run, fzn_notes_import_refuse, &run)
		                      == FZN_NOTES_OK
		              && run.imported == 4u && run.already == 1u,
		      "a note made in the same millisecond under another title is imported");

		/* ---- a held note whose content is not here, sec 577 */
		{
			fzn_note_blob_ref_t ref;
			size_t kept_len = 0;
			int dropped = 0;

			CHECK(fzn_notes_view_load(&store, &author_view) == FZN_NOTES_OK, "fixture: view");
			for (i = 0; i < author_view.count && !dropped; i++)
				if (fzn_notes_read(&store, blob_stub_open, NULL, &author_view.nodes[i], &meta,
				                   payload, sizeof(payload), &note)
				            == FZN_NOTES_OK
				    && is(note.title, note.title_len, "dated")
				    && fzn_notes_ref_of(&author_view.nodes[i], &ref)) {
					size_t slot = (((size_t)ref.root[0] << 8) | ref.root[1]);

					kept_len = blob_stub.len[slot - 1u];
					blob_stub_drop(&ref);
					dropped = 1;
				}
			CHECK(dropped, "fixture: the dated note's content dropped, as never fetched");
			run.on_refused = note_refusal;
			refusal_count = 0;
			CHECK(fzn_notes_import_keep((const uint8_t *)dated, sizeof(dated) - 1u,
			                            fzn_notes_import_take, &run, fzn_notes_import_refuse,
			                            &run)
			                      == FZN_NOTES_OK
			              && run.imported == 4u && run.already == 1u && run.refused == 1u
			              && refusal_count == 1u && refusals[0] == FZN_NOTES_IMPORT_PENDING,
			      "a note made at a held note's time, that note's content not here, is "
			      "refused as pending and not imported again");
			CHECK(fzn_notes_import_keep((const uint8_t *)twin, sizeof(twin) - 1u,
			                            fzn_notes_import_take, &run, fzn_notes_import_refuse,
			                            &run)
			                      == FZN_NOTES_OK
			              && run.imported == 4u && run.already == 2u && run.refused == 1u,
			      "the same time's other note, read and matching, is recognised all the same");
			if (dropped)
				blob_stub.len[(((size_t)ref.root[0] << 8) | ref.root[1]) - 1u] = kept_len;
			CHECK(fzn_notes_import_keep((const uint8_t *)dated, sizeof(dated) - 1u,
			                            fzn_notes_import_take, &run, fzn_notes_import_refuse,
			                            &run)
			                      == FZN_NOTES_OK
			              && run.imported == 4u && run.already == 3u && run.refused == 1u,
			      "once the content is here, importing again recognises it");
			run.on_refused = NULL;
			run.refused = 0;
		}
	}

	/* ---- a long text is sealed whole, and refused when the seal fails */
	{
		static const char head[] = "{\"title\":\"long\",\"createdTimestampUsec\":5,"
		                           "\"textContent\":\"";
		size_t n = sizeof(head) - 1u;

		memcpy(big, head, n);
		for (i = 0; i < 5000u; i++)
			big[n++] = 'z';
		memcpy(big + n, "\"}", 2u);
		n += 2u;
		run.imported = run.refused = 0;
		blob_stub.refuse = 1;
		CHECK(fzn_notes_import_keep(big, n, fzn_notes_import_take, &run,
		                            fzn_notes_import_refuse, &run)
		                      == FZN_NOTES_OK
		              && run.refused == 1u && run.imported == 0u,
		      "a note whose content will not seal is refused");
		blob_stub.refuse = 0;
		CHECK(fzn_notes_import_keep(big, n, fzn_notes_import_take, &run,
		                            fzn_notes_import_refuse, &run)
		                      == FZN_NOTES_OK
		              && run.imported == 1u,
		      "with a seal that works, it is imported");
		CHECK(fzn_notes_view_load(&store, &author_view) == FZN_NOTES_OK, "fixture: view");
		found = 0;
		for (i = 0; i < author_view.count; i++)
			if (fzn_notes_read(&store, blob_stub_open, NULL, &author_view.nodes[i], &meta, payload,
			                   sizeof(payload), &note)
			            == FZN_NOTES_OK
			    && is(note.title, note.title_len, "long") && note.text_len == 5000u)
				found++;
		CHECK(found == 1u, "its whole text sealed");
	}
}

int main(void)
{
	memset(KEY_A, 0xa1, sizeof(KEY_A));
	memset(KEY_B, 0xb2, sizeof(KEY_B));
	memset(KEY_C, 0xc3, sizeof(KEY_C));
	CHECK(fzn_notes_store_init(&store, &OPS, &HASH) == FZN_NOTES_OK, "the store opens");

	test_admission();
	test_supersession();
	test_damage_and_misplacement();
	test_capacity_and_erase();
	test_the_view();
	test_authoring();
	test_purge();
	test_import_parsing();
	test_import_run();

	if (failures) {
		fprintf(stderr, "notes_store_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("notes_store_test: all %d checks passed\n", checks);
	return 0;
}
