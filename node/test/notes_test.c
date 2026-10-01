/* notes_test -- a node's notes as verbs: add, set, list, get and emptying the
 * trash, through `fzn_node_notes_local` as a local client's line reaches it.
 * sec 431.
 *
 * The signer is a toy whose "public key" is its secret: a signature is a hash
 * of the key and the message, enough for admission to tell writers apart. The
 * backend is `persist/`'s seam over memory, and the long-text hooks are a toy
 * blob store, so a long text's seal and open are exercised without a shelf. */

#define _POSIX_C_SOURCE 200809L

#include "../notes.h"
#include "../../notes/text.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (ok)
		return;
	failures++;
	fprintf(stderr, "  FAIL notes_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, what)

/* ---- a hash, a toy signer, and randomness --------------------------------- */

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

static uint8_t SELF[FZN_PUBKEY_LEN], PEER[FZN_PUBKEY_LEN];

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

static fzn_sign_ops_t SIGN = { toy_verify, toy_sign, SELF };

static uint64_t counter = 11;

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

static uint64_t clock_ms = 1000;

static uint64_t now_ms(void)
{
	return clock_ms++;
}

/* ---- a persist backend over memory -------------------------------------- */

#define MEM_ROWS 128u

struct row {
	int used;
	fzn_persist_slot_t slot;
	int has_subject;
	uint8_t subject[FZN_PUBKEY_LEN];
	uint8_t bytes[FZN_PERSIST_HEAD_LEN + FZN_RECORD_MAX_LEN];
	size_t len;
};

static struct row rows[MEM_ROWS];

static struct row *find_row(fzn_persist_slot_t slot, const uint8_t *subject)
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
	struct row *r = find_row(slot, subject);

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
	struct row *r = find_row(slot, subject);
	size_t i;

	(void)ctx;
	for (i = 0; !r && i < MEM_ROWS; i++)
		if (!rows[i].used)
			r = &rows[i];
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
	struct row *r = find_row(slot, subject);

	(void)ctx;
	if (r)
		r->used = 0;
	return 1;
}

static fzn_persist_ops_t OPS = { mem_load, mem_save, mem_list, mem_remove, NULL };

/* ---- a toy blob store for long texts ------------------------------------- */

static uint8_t blob[FZN_NOTE_TEXT_MAX];
static size_t blob_len;

static int toy_seal(void *ctx, const uint8_t *text, size_t len, fzn_note_blob_ref_t *ref)
{
	(void)ctx;
	memcpy(blob, text, len);
	blob_len = len;
	memset(ref, 0x5e, sizeof(*ref));
	ref->length = len;
	return 1;
}

static int toy_open(void *ctx, const fzn_note_blob_ref_t *ref, uint8_t *out, size_t cap,
                    size_t *out_len)
{
	(void)ctx;
	if (ref->length != blob_len || cap < blob_len)
		return 0;
	memcpy(out, blob, blob_len);
	*out_len = blob_len;
	return 1;
}

/* ---- asking -------------------------------------------------------------- */

static fzn_node_notes_t notes;
static char reply[FZN_REPLY_MAX + 1u];
static size_t reply_len;

/* Ask `line` as the node's own user, unless `origin` says otherwise. */
static fzn_reply_t ask_as(fzn_origin_t origin, const char *line)
{
	fzn_request_t request;
	const uint8_t *detail = NULL;
	size_t detail_len = 0;

	memset(&request, 0, sizeof(request));
	if (!fzn_vocabulary_split((const uint8_t *)line, strlen(line), &request))
		return FZN_REPLY_NONE;
	memset(reply, 0, sizeof(reply));
	reply_len = fzn_node_notes_local(&notes, origin, &request, reply, sizeof(reply) - 1u);
	if (reply_len == 0u)
		return FZN_REPLY_NONE;
	if (reply[reply_len - 1u] == '\n')
		reply_len--;
	reply[reply_len] = '\0';
	return fzn_reply_of((const uint8_t *)reply, reply_len, &detail, &detail_len);
}

static fzn_reply_t ask(const char *line)
{
	return ask_as(FZN_ORIGIN_SAME_USER, line);
}

/* The reply's detail, past "ok ". */
static const char *detail_of(void)
{
	const char *sp = strchr(reply, ' ');

	return sp ? sp + 1 : "";
}

static void take_id(char out[65])
{
	snprintf(out, 65, "%.64s", detail_of());
}

static int has(const char *needle)
{
	return strstr(reply, needle) != NULL;
}

static void setup(size_t peers)
{
	memset(rows, 0, sizeof(rows));
	CHECK(fzn_node_notes_init(&notes, &OPS, &HASH, &SIGN, &RNG, SELF,
	                          (const uint8_t (*)[FZN_PUBKEY_LEN])PEER, peers,
	                          (const uint8_t (*)[FZN_PUBKEY_LEN])PEER, peers, now_ms)
	              == FZN_NOTES_OK,
	      "the node's notes open");
}

/* ---- cases --------------------------------------------------------------- */

static void test_add_list_get(void)
{
	char milk[65], shop[65], eggs[65], line[256];

	setup(0);
	CHECK(ask("add note top milk") == FZN_REPLY_OK && strlen(detail_of()) == 64u,
	      "a note is added, answering its id");
	take_id(milk);
	CHECK(ask("add folder top Shop") == FZN_REPLY_OK, "a folder is added");
	take_id(shop);
	snprintf(line, sizeof(line), "add note %s eggs and, 100%% fresh", shop);
	CHECK(ask(line) == FZN_REPLY_OK, "a note is added inside the folder");
	take_id(eggs);

	CHECK(ask("list note top") == FZN_REPLY_OK && !strncmp(detail_of(), "2 0 ", 4u)
	              && has(milk) && has(shop) && !has(eggs),
	      "the top level lists the note and the folder, not the folder's child");
	CHECK(strstr(reply, milk) < strstr(reply, shop), "in the order they were added");
	snprintf(line, sizeof(line), "%s,1,0,1,0,milk", milk);
	CHECK(has(line), "an item is id, type, flags, reachable, contested and title");
	snprintf(line, sizeof(line), "list note %s", shop);
	CHECK(ask(line) == FZN_REPLY_OK && !strncmp(detail_of(), "1 0 ", 4u)
	              && has("eggs%20and%2c%20100%25%20fresh"),
	      "the folder's child is listed, its title escaped");

	snprintf(line, sizeof(line), "get note %s", milk);
	CHECK(ask(line) == FZN_REPLY_OK && !strncmp(detail_of(), "1 0 ", 4u) && has(" inline 0 milk"),
	      "get answers the type, flags, times, parent, text length and title");
	snprintf(line, sizeof(line), "set note %s title oat milk", milk);
	CHECK(ask(line) == FZN_REPLY_OK, "a rename");
	snprintf(line, sizeof(line), "set note %s text two pints, cold", milk);
	CHECK(ask(line) == FZN_REPLY_OK, "a text");
	snprintf(line, sizeof(line), "get note %s text", milk);
	CHECK(ask(line) == FZN_REPLY_OK && !strcmp(detail_of(), "15 0 two%20pints%2c%20cold"),
	      "the text reads back, escaped, from the start");
	snprintf(line, sizeof(line), "get note %s text 11", milk);
	CHECK(ask(line) == FZN_REPLY_OK && !strcmp(detail_of(), "15 11 cold"),
	      "and from an offset");
	snprintf(line, sizeof(line), "get note %s", milk);
	CHECK(ask(line) == FZN_REPLY_OK && has(" inline 15 oat%20milk"),
	      "and the rename kept the text");

	snprintf(line, sizeof(line), "set note %s pin", milk);
	CHECK(ask(line) == FZN_REPLY_OK, "a pin");
	snprintf(line, sizeof(line), "get note %s", milk);
	CHECK(ask(line) == FZN_REPLY_OK && !strncmp(detail_of(), "1 1 ", 4u), "is a flag of 1");
	snprintf(line, sizeof(line), "set note %s parent %s", milk, shop);
	CHECK(ask(line) == FZN_REPLY_OK, "a move");
	snprintf(line, sizeof(line), "list note %s", shop);
	CHECK(ask(line) == FZN_REPLY_OK && !strncmp(detail_of(), "2 0 ", 4u) && has(milk),
	      "puts the note in the folder");

	CHECK(ask("get note nothex") == FZN_REPLY_MALFORMED, "an id that is not one is malformed");
	CHECK(ask("get note 0000000000000000000000000000000000000000000000000000000000000077")
	              == FZN_REPLY_ERROR,
	      "a note nobody holds is an error");
	snprintf(line, sizeof(line), "set note %s colour red", milk);
	CHECK(ask(line) == FZN_REPLY_MALFORMED, "a field there is no verb for is malformed");
	CHECK(ask_as(FZN_ORIGIN_LOCAL, "list note top") == FZN_REPLY_DENIED,
	      "another user is denied, reads included");
	CHECK(ask("get vote 0") == FZN_REPLY_NONE && ask("list peer") == FZN_REPLY_NONE,
	      "other subjects fall through to the node's other verbs");
}

static void test_long_text(void)
{
	static uint8_t big[5000];
	char note[65], line[512], path[64], out[64];
	FILE *f;
	size_t i, n;

	setup(0);
	for (i = 0; i < sizeof(big); i++)
		big[i] = (uint8_t)('a' + (i % 26u));
	snprintf(path, sizeof(path), "/tmp/fzn-notes-test-%ld.in", (long)getpid());
	snprintf(out, sizeof(out), "/tmp/fzn-notes-test-%ld.out", (long)getpid());
	f = fopen(path, "wb");
	CHECK(f && fwrite(big, 1u, sizeof(big), f) == sizeof(big), "fixture: a 5000-byte file");
	if (f)
		(void)fclose(f);

	CHECK(ask("add note top long") == FZN_REPLY_OK, "fixture: a note");
	take_id(note);
	snprintf(line, sizeof(line), "set note %s file %s", note, path);
	CHECK(ask(line) == FZN_REPLY_ERROR, "a text too long for inline, with no seal, is refused");

	notes.seal = toy_seal;
	notes.open = toy_open;
	CHECK(ask(line) == FZN_REPLY_OK && blob_len == sizeof(big),
	      "with a seal, the file's text is sealed whole");
	snprintf(line, sizeof(line), "get note %s", note);
	CHECK(ask(line) == FZN_REPLY_OK && has(" blob 5000 long"), "the note says blob, 5000 bytes");
	snprintf(line, sizeof(line), "get note %s text", note);
	CHECK(ask(line) == FZN_REPLY_ERROR, "a blob is not paged as inline text");
	snprintf(line, sizeof(line), "get note %s file %s", note, out);
	CHECK(ask(line) == FZN_REPLY_OK && !strcmp(detail_of(), "5000"),
	      "it is written to a file, opened from its blob");
	{
		static uint8_t back[6000];

		f = fopen(out, "rb");
		n = f ? fread(back, 1u, sizeof(back), f) : 0u;
		if (f)
			(void)fclose(f);
		CHECK(n == sizeof(big) && memcmp(back, big, n) == 0, "byte for byte");
	}
	{
		struct stat st;

		CHECK(stat(out, &st) == 0 && (st.st_mode & 077) == 0,
		      "into a file only its owner can read");
	}
	snprintf(line, sizeof(line), "set note %s text short again", note);
	CHECK(ask(line) == FZN_REPLY_OK, "an inline text replaces it");
	snprintf(line, sizeof(line), "get note %s", note);
	CHECK(ask(line) == FZN_REPLY_OK && has(" inline 11 long"), "and the note is inline again");
	CHECK(remove(path) == 0 && remove(out) == 0, "the scratch files are removed");
}

static void test_paging(void)
{
	char line[256];
	size_t i, first = 0, from;
	unsigned long total = 0, at = 0;

	setup(0);
	for (i = 0; i < 40u; i++) {
		snprintf(line, sizeof(line), "add note top a rather long title for note number %02zu",
		         i);
		CHECK(ask(line) == FZN_REPLY_OK, "fixture: forty notes");
	}
	CHECK(ask("list note top") == FZN_REPLY_OK
	              && sscanf(detail_of(), "%lu %lu", &total, &at) == 2 && total == 40u
	              && at == 0u,
	      "a page says the total and where it starts");
	for (i = 0; i < reply_len; i++)
		first += reply[i] == ' ';
	first -= 2u; /* the head's two fields */
	CHECK(first > 0u && first < 40u && reply_len <= FZN_REPLY_MAX,
	      "it holds some notes, not all, and fits a line");
	from = first;
	snprintf(line, sizeof(line), "list note top %zu", from);
	CHECK(ask(line) == FZN_REPLY_OK && sscanf(detail_of(), "%lu %lu", &total, &at) == 2
	              && at == from,
	      "the next page starts where the last ended");
	CHECK(ask("list note top 41") == FZN_REPLY_MALFORMED, "past the end is malformed");
}

static void test_trash(void)
{
	char a[65], b[65], line[256];

	setup(0);
	CHECK(ask("add note top keep") == FZN_REPLY_OK, "fixture: a note kept");
	take_id(a);
	CHECK(ask("add note top bin") == FZN_REPLY_OK, "fixture: a note to bin");
	take_id(b);
	snprintf(line, sizeof(line), "set note %s trash", b);
	CHECK(ask(line) == FZN_REPLY_OK, "it is trashed");
	CHECK(ask("remove note trash") == FZN_REPLY_OK && !strcmp(detail_of(), "1 0"),
	      "a node with no paired nodes empties its trash at once");
	CHECK(ask("list note top") == FZN_REPLY_OK && has(a) && !has(b), "and the note is gone");

	setup(1);
	CHECK(ask("add note top bin") == FZN_REPLY_OK, "fixture: a note to bin");
	take_id(b);
	snprintf(line, sizeof(line), "set note %s trash", b);
	CHECK(ask(line) == FZN_REPLY_OK, "it is trashed");
	CHECK(ask("remove note trash") == FZN_REPLY_OK && !strcmp(detail_of(), "1 1"),
	      "with a paired node to ask, the purge waits");
	CHECK(ask("list note top") == FZN_REPLY_OK && has(b), "and the note is still held");

	/* A PARTNER IS ASKED TOO: a node paired to this one that has pulled
	 * from it holds copies, though this node does not pull from it. */
	memset(rows, 0, sizeof(rows));
	CHECK(fzn_node_notes_init(&notes, &OPS, &HASH, &SIGN, &RNG, SELF,
	                          (const uint8_t (*)[FZN_PUBKEY_LEN])PEER, 1u, NULL, 0u, now_ms)
	              == FZN_NOTES_OK,
	      "fixture: a node pulling from nobody, with one paired node");
	{
		uint8_t query[FZN_NOTES_SYNC_INDEX_QUERY_LEN] = { FZN_NOTES_SYNC_VERSION,
			                                          FZN_NOTES_SYNC_INDEX_QUERY, 0, 0 };
		uint8_t out[FZN_NOTES_SYNC_REPLY_MAX];

		CHECK(fzn_node_notes_remote(&notes, PEER, query, sizeof(query), out, sizeof(out))
		              > 0u,
		      "fixture: the paired node pulls this one's index");
	}
	CHECK(ask("add note top bin") == FZN_REPLY_OK, "fixture: a note to bin");
	take_id(b);
	snprintf(line, sizeof(line), "set note %s trash", b);
	CHECK(ask(line) == FZN_REPLY_OK, "it is trashed");
	CHECK(ask("remove note trash") == FZN_REPLY_OK && !strcmp(detail_of(), "1 1")
	              && notes.fresh,
	      "the partner is pinned, the purge waits, and the node is told to converse now");
	CHECK(ask("remove note bin") == FZN_REPLY_MALFORMED, "only the trash is emptied");
}

static void test_admission(void)
{
	setup(0);
	notes.author.policy = fzn_notes_policy_writers(notes.admitted + 1, 0u);
	CHECK(ask("add note top refused") == FZN_REPLY_ERROR,
	      "a node outside its own admitted set cannot write a note");
}

int main(void)
{
	memset(SELF, 0x51, sizeof(SELF));
	memset(PEER, 0x9e, sizeof(PEER));

	test_add_list_get();
	test_long_text();
	test_paging();
	test_trash();
	test_admission();

	if (failures) {
		fprintf(stderr, "notes_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("notes_test: all %d checks passed\n", checks);
	return 0;
}
