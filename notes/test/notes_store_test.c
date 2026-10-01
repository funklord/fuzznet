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
#include "../view.h"

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
	    || fzn_record_sign(key, subject, stream, kind, seq, 1000u, body, body_len, &signer,
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

static void test_the_sequence(void)
{
	uint64_t seq = 0;
	struct row *r;

	wipe();
	CHECK(fzn_notes_next_seq(&store, KEY_A, &seq) == FZN_NOTES_OK && seq == 1u,
	      "the first sequence is 1");
	CHECK(fzn_notes_next_seq(&store, KEY_A, &seq) == FZN_NOTES_OK && seq == 2u,
	      "and the next is 2");
	note_of(0, KEY_A, 5, 0, 9, "signed at nine");
	note_of(1, KEY_B, 6, 0, 50, "a sibling's, at fifty");
	CHECK(put(0, NULL) == FZN_NOTES_OK && put(1, NULL) == FZN_NOTES_OK, "fixture: two records");
	r = find(FZN_PERSIST_NOTE_SEQ, NULL);
	CHECK(r != NULL, "fixture: the counter is held");
	if (r)
		r->used = 0;
	CHECK(fzn_notes_next_seq(&store, KEY_A, &seq) == FZN_NOTES_OK && seq == 10u,
	      "a lost counter resumes past this host's own held records");
	CHECK(fzn_notes_next_seq(&store, KEY_A, &seq) == FZN_NOTES_OK && seq == 11u,
	      "and goes on from there");
	r = find(FZN_PERSIST_NOTE_SEQ, NULL);
	if (r)
		r->bytes[1] ^= 0x7fu;
	CHECK(fzn_notes_next_seq(&store, KEY_A, &seq) == FZN_NOTES_ERR_SHAPE,
	      "a counter that will not read is refused, not restarted");
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

/* This host's own claim on `id`, opened: its node and its note. */
static int own(uint8_t *key, const uint8_t id[FZN_TREE_ID_LEN], fzn_record_t *rec,
               fzn_tree_node_t *node, fzn_note_t *note)
{
	static uint8_t out[FZN_RECORD_MAX_LEN];
	size_t len = 0;

	return fzn_notes_get(&store, id, key, out, sizeof(out), &len) == FZN_NOTES_OK
	       && fzn_record_open(out, len, rec) == FZN_RECORD_OK
	       && fzn_tree_open(*rec, node) == FZN_TREE_OK
	       && fzn_note_open(node->content_type, node->content, node->content_len, note)
	                  == FZN_NOTE_OK;
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
	CHECK(fzn_notes_create(&c, root, FZN_NOTE_TYPE_NOTE, &note, 5003u, stray)
	              == FZN_NOTES_ERR_DENIED,
	      "a host outside its own admitted set cannot write a note");

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
	{
		fzn_note_blob_ref_t ref;
		uint8_t field[FZN_NOTE_BLOB_REF_LEN];

		memset(&ref, 0x5a, sizeof(ref));
		ref.length = 5000u;
		CHECK(fzn_note_blob_ref_write(&ref, field) == FZN_NOTE_OK, "fixture: a reference");
		memset(&with, 0, sizeof(with));
		with.text = field;
		with.text_len = sizeof(field);
		with.flags = FZN_NOTE_FLAG_TEXT_IS_BLOB;
		CHECK(fzn_notes_edit(&a, one, FZN_NOTES_EDIT_TEXT, &with, 0u, 0u, 6004u)
		              == FZN_NOTES_OK
		              && own(KEY_A, one, &rec, &node, &note)
		              && (note.flags & FZN_NOTE_FLAG_TEXT_IS_BLOB)
		              && fzn_note_blob_ref(&note, &ref) == FZN_NOTE_OK && ref.length == 5000u,
		      "a long text goes in as its reference, with the flag that says so");
		with = titled("", "short again");
		CHECK(fzn_notes_edit(&a, one, FZN_NOTES_EDIT_TEXT, &with, 0u, 0u, 6005u)
		              == FZN_NOTES_OK
		              && own(KEY_A, one, &rec, &node, &note)
		              && !(note.flags & FZN_NOTE_FLAG_TEXT_IS_BLOB)
		              && says(&note, "oat milk", "short again"),
		      "and an inline text clears it");
	}
	CHECK(fzn_notes_edit(&a, one, 0u, NULL, FZN_NOTE_FLAG_TRASHED, FZN_NOTE_FLAG_TRASHED, 1u)
	              == FZN_NOTES_ERR_MALFORMED,
	      "setting and clearing one flag at once is refused");
	CHECK(fzn_notes_edit(&a, one, 0u, NULL, FZN_NOTE_FLAG_TEXT_IS_BLOB, 0u, 1u)
	              == FZN_NOTES_ERR_MALFORMED,
	      "the blob flag does not move without the text");
	/* A PLAIN TEXT OF EXACTLY A REFERENCE'S WIDTH is where the flag alone
	 * would pass every shape check and turn prose into a "reference". */
	{
		static const char seventy_two[] = "123456789012345678901234567890123456789012345678901234567890123456789012";

		with = titled("", seventy_two);
		CHECK(sizeof(seventy_two) - 1u == FZN_NOTE_BLOB_REF_LEN
		              && fzn_notes_edit(&a, one, FZN_NOTES_EDIT_TEXT, &with, 0u, 0u, 6006u)
		                         == FZN_NOTES_OK,
		      "fixture: a plain text of 72 bytes");
		CHECK(fzn_notes_edit(&a, one, 0u, NULL, FZN_NOTE_FLAG_TEXT_IS_BLOB, 0u, 6007u)
		              == FZN_NOTES_ERR_MALFORMED
		              && own(KEY_A, one, &rec, &node, &note)
		              && !(note.flags & FZN_NOTE_FLAG_TEXT_IS_BLOB),
		      "the blob flag alone does not make a 72-byte text a reference");
	}
	CHECK(fzn_notes_edit(&a, one, 0u, NULL, 0u, 0u, 1u) == FZN_NOTES_ERR_MALFORMED,
	      "an edit that changes nothing is refused");
	CHECK(fzn_notes_edit(&a, root, 0u, NULL, FZN_NOTE_FLAG_PINNED, 0u, 1u)
	              == FZN_NOTES_ERR_ABSENT,
	      "the root is not a note");
	memset(stray, 0x77, sizeof(stray));
	CHECK(fzn_notes_edit(&a, stray, 0u, NULL, FZN_NOTE_FLAG_PINNED, 0u, 1u)
	              == FZN_NOTES_ERR_ABSENT,
	      "a note nobody holds is absent");

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
		              && fzn_record_sign(KEY_B, subject, FZN_NOTE_STREAM, FZN_NOTE_KIND, 900u,
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
	test_the_sequence();
	test_the_view();
	test_authoring();

	if (failures) {
		fprintf(stderr, "notes_store_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("notes_store_test: all %d checks passed\n", checks);
	return 0;
}
