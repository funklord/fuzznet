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
#include "../journal.h"
#include "../../contact/contact.h"
#include "../../contact/group.h"
#include "../../notes/received.h"
#include "../../notes/text.h"
#include "../../notes/test/blob_stub.h"
#include "../../notes/test/chain_stub.h"

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

/* Every note's content is sealed, sec 514: the node's shelf, stubbed. */
static void hooks(void)
{
	notes.seal = blob_stub_seal;
	notes.open = blob_stub_open;
	notes.text_ctx = NULL;
	notes.chain = chain_stub_chain;
	notes.chain_ctx = NULL;
}

static void setup(size_t peers)
{
	memset(rows, 0, sizeof(rows));
	CHECK(fzn_node_notes_init(&notes, &OPS, &HASH, &SIGN, &RNG, SELF,
	                          (const uint8_t (*)[FZN_PUBKEY_LEN])PEER, peers,
	                          (const uint8_t (*)[FZN_PUBKEY_LEN])PEER, peers, now_ms)
	              == FZN_NOTES_OK,
	      "the node's notes open");
	hooks();
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
	CHECK(ask(line) == FZN_REPLY_OK && !strncmp(detail_of(), "1 0 ", 4u) && has(" blob 0 milk"),
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
	CHECK(ask(line) == FZN_REPLY_OK && has(" blob 15 oat%20milk"),
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
	notes.seal = NULL;
	CHECK(ask(line) == FZN_REPLY_ERROR, "with no seal, no text is written");
	hooks();
	CHECK(ask(line) == FZN_REPLY_OK, "with one, the file's text is sealed whole");
	snprintf(line, sizeof(line), "get note %s", note);
	CHECK(ask(line) == FZN_REPLY_OK && has(" blob 5000 long"), "the note says blob, 5000 bytes");
	snprintf(line, sizeof(line), "get note %s text", note);
	CHECK(ask(line) == FZN_REPLY_OK && !strncmp(detail_of(), "5000 0 abcdef", 13u),
	      "and is paged as any text is");
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
	CHECK(ask(line) == FZN_REPLY_OK, "a short text replaces it");
	snprintf(line, sizeof(line), "get note %s", note);
	CHECK(ask(line) == FZN_REPLY_OK && has(" blob 11 long"), "in a blob of its own");

	/* NOT HERE YET, sec 514: a note whose blob this node lacks lists by its
	 * meta, marked pending, with no title; its text is not read, and its
	 * content not edited, while pinning it still is. */
	{
		uint8_t root[FZN_BLOB_HASH_LEN];
		fzn_note_blob_ref_t ref;
		char item[100];

		blob_stub_last_root(root);
		memcpy(ref.root, root, sizeof(root));
		blob_stub_drop(&ref);
		snprintf(line, sizeof(line), "get note %s", note);
		CHECK(ask(line) == FZN_REPLY_OK && has(" pending ") && !has("long"),
		      "get says pending, and no title");
		snprintf(item, sizeof(item), "%s,1,%u,1,0,", note, FZN_NODE_NOTES_LIST_PENDING);
		CHECK(ask("list note top") == FZN_REPLY_OK && has(item),
		      "the listing marks it pending, untitled");
		snprintf(line, sizeof(line), "get note %s text", note);
		CHECK(ask(line) == FZN_REPLY_ERROR && has("not here yet"), "its text is not read");
		snprintf(line, sizeof(line), "set note %s title renamed", note);
		CHECK(ask(line) == FZN_REPLY_ERROR, "its title is not edited");
		snprintf(line, sizeof(line), "set note %s pin", note);
		CHECK(ask(line) == FZN_REPLY_OK, "and it is pinned all the same");
	}
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
	CHECK(ask("list note top") == FZN_REPLY_OK && !has(b),
	      "the note pending purge is left out of the listing");
	snprintf(line, sizeof(line), "get note %s", b);
	CHECK(ask(line) == FZN_REPLY_OK, "though it is still held");
	/* A NODE PULLED FROM THAT NEVER ANSWERS, sec 472: released a month
	 * after the purge was queued, and not a moment before. */
	{
		size_t released = 9, finished = 9;

		/* The test clock ticks each time it is read, so a second's margin. */
		clock_ms += FZN_NODE_NOTES_PARTNER_AGE_MS - 1000u;
		CHECK(fzn_node_notes_release_purges(&notes, &released, &finished) && released == 0u
		              && ask(line) == FZN_REPLY_OK,
		      "a second short of a month, the purge still waits");
		clock_ms += 2000u;
		CHECK(fzn_node_notes_release_purges(&notes, &released, &finished) && released == 1u
		              && finished == 1u && ask(line) == FZN_REPLY_ERROR,
		      "past it, the silent node is released and the note is gone");
		CHECK(!fzn_node_notes_release_purges(NULL, &released, &finished),
		      "no node, no release");
	}

	/* A PARTNER IS ASKED TOO: a node paired to this one that has pulled
	 * from it holds copies, though this node does not pull from it. */
	memset(rows, 0, sizeof(rows));
	CHECK(fzn_node_notes_init(&notes, &OPS, &HASH, &SIGN, &RNG, SELF,
	                          (const uint8_t (*)[FZN_PUBKEY_LEN])PEER, 1u, NULL, 0u, now_ms)
	              == FZN_NOTES_OK,
	      "fixture: a node pulling from nobody, with one paired node");
	hooks();
	{
		uint8_t query[FZN_NOTES_SYNC_PURGES_QUERY_LEN] = { FZN_NOTES_SYNC_VERSION,
			                                           FZN_NOTES_SYNC_PURGES_QUERY };
		uint8_t out[FZN_NOTES_SYNC_REPLY_MAX];

		CHECK(fzn_node_notes_remote(&notes, PEER, 0, query, sizeof(query), out, sizeof(out))
		              > 0u,
		      "fixture: the paired node asks for this one's purges");
	}
	CHECK(ask("add note top bin") == FZN_REPLY_OK, "fixture: a note to bin");
	take_id(b);
	snprintf(line, sizeof(line), "set note %s trash", b);
	CHECK(ask(line) == FZN_REPLY_OK, "it is trashed");
	CHECK(ask("remove note trash") == FZN_REPLY_OK && !strcmp(detail_of(), "1 1")
	              && notes.fresh,
	      "the partner is pinned, the purge waits, and the node is told to converse now");

	/* A PARTNER STILL PULLING KEEPS ITS PIN, sec 472: it will answer. */
	{
		uint8_t query[FZN_NOTES_SYNC_PURGES_QUERY_LEN] = { FZN_NOTES_SYNC_VERSION,
			                                           FZN_NOTES_SYNC_PURGES_QUERY };
		uint8_t out[FZN_NOTES_SYNC_REPLY_MAX];
		size_t released = 9, finished = 9;

		clock_ms += FZN_NODE_NOTES_PARTNER_AGE_MS;
		CHECK(fzn_node_notes_remote(&notes, PEER, 0, query, sizeof(query), out, sizeof(out))
		              > 0u,
		      "fixture: the partner asks again, a month on");
		clock_ms += 1000u;
		CHECK(fzn_node_notes_release_purges(&notes, &released, &finished) && released == 0u,
		      "a month after the purge, a partner heard from lately is not released");
	}
	{
		char first[65];

		memcpy(first, b, sizeof(first));
		/* A PARTNER GONE A MONTH IS NOT PINNED, and releases what it pinned. */
		clock_ms += FZN_NODE_NOTES_PARTNER_AGE_MS + 1000u;
		CHECK(ask("add note top bin later") == FZN_REPLY_OK, "fixture: another note to bin");
		take_id(b);
		snprintf(line, sizeof(line), "set note %s trash", b);
		CHECK(ask(line) == FZN_REPLY_OK, "it is trashed");
		CHECK(ask("remove note trash") == FZN_REPLY_OK && !strcmp(detail_of(), "1 0"),
		      "emptying again releases the earlier purge from the partner gone since, "
		      "and the new one pins nobody");
		snprintf(line, sizeof(line), "get note %s", first);
		CHECK(ask(line) == FZN_REPLY_ERROR, "the earlier note is gone");
		snprintf(line, sizeof(line), "get note %s", b);
		CHECK(ask(line) == FZN_REPLY_ERROR, "and so is the new one");
	}
	CHECK(ask("remove note bin") == FZN_REPLY_MALFORMED, "only the trash is emptied");

	/* A FULL QUEUE OF DELETIONS IS SAID AS ONE, sec 484, not as a note
	 * that does not fit. With a paired node every purge waits, so the
	 * queue fills at its bound. */
	{
		char id[65];
		size_t i;
		int ok = 1;

		setup(1);
		for (i = 0; i <= FZN_NOTES_PURGE_MAX && ok; i++) {
			ok = ask("add note top doomed") == FZN_REPLY_OK;
			take_id(id);
			snprintf(line, sizeof(line), "set note %s trash", id);
			ok = ok && ask(line) == FZN_REPLY_OK;
		}
		CHECK(ok, "fixture: a note past the purge queue's bound, trashed");
		CHECK(ask("remove note trash") == FZN_REPLY_ERROR && has("deletions")
		              && !has("note"),
		      "a full queue of deletions was not said as one");
	}
}

static void test_admission(void)
{
	setup(0);
	notes.author.policy = fzn_notes_policy_writers(notes.admitted + 1, 0u);
	CHECK(ask("add note top refused") == FZN_REPLY_ERROR,
	      "a node outside its own admitted set cannot write a note");
}

/* How many claims a remote index answer names, or -1 for none. */
static int indexed(const uint8_t *sender, int shared)
{
	uint8_t query[FZN_NOTES_SYNC_INDEX_QUERY_LEN] = { FZN_NOTES_SYNC_VERSION,
		                                          FZN_NOTES_SYNC_INDEX_QUERY, 0, 0 };
	static uint8_t out[FZN_NOTES_SYNC_REPLY_MAX];
	size_t n = fzn_node_notes_remote(&notes, sender, shared, query, sizeof(query), out,
	                                 sizeof(out));

	if (n < FZN_NOTES_SYNC_INDEX_HEAD_LEN)
		return -1;
	return (int)((n - FZN_NOTES_SYNC_INDEX_HEAD_LEN) / FZN_NOTES_SYNC_CLAIM_LEN);
}

/* SHARES, sec 436: the table's verbs, and a contact's request answered with
 * only what is shared with it. */
static void test_share(void)
{
	uint8_t carol[FZN_PUBKEY_LEN];
	char f[65], g[65], o[65], line[200], want[200];

	setup(1);
	memset(carol, 0xc4, sizeof(carol));
	CHECK(fzn_contact_add(&OPS, carol, "carol", 5u, 1u) == FZN_CONTACT_OK,
	      "fixture: the contact carol");
	CHECK(ask("add folder top shared") == FZN_REPLY_OK, "fixture: a folder");
	take_id(f);
	snprintf(line, sizeof(line), "add note %s inside", f);
	CHECK(ask(line) == FZN_REPLY_OK, "fixture: a note in it");
	take_id(g);
	CHECK(ask("add note top private") == FZN_REPLY_OK, "fixture: a note outside it");
	take_id(o);

	snprintf(line, sizeof(line), "add share %s carol", f);
	CHECK(ask_as(FZN_ORIGIN_LOCAL, line) == FZN_REPLY_DENIED,
	      "a service-group member may not share the user's notes");
	CHECK(ask("add share top carol") == FZN_REPLY_MALFORMED, "the top is no subtree");
	snprintf(line, sizeof(line), "add share %s nobody", f);
	CHECK(ask(line) == FZN_REPLY_ERROR, "a name that is no contact is refused");
	snprintf(line, sizeof(line), "add share %s carol",
	         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
	CHECK(ask(line) == FZN_REPLY_ERROR, "a note this node does not hold is refused");
	CHECK(ask("list share") == FZN_REPLY_OK && !strcmp(detail_of(), "0 0"),
	      "and none of those shared anything");

	CHECK(indexed(carol, 1) == 0, "before sharing, carol is offered nothing");
	snprintf(line, sizeof(line), "add share %s carol", f);
	CHECK(ask(line) == FZN_REPLY_OK, "the folder is shared with carol");
	snprintf(want, sizeof(want), "1 0 %s,carol", f);
	CHECK(ask("list share") == FZN_REPLY_OK && !strcmp(detail_of(), want),
	      "list share names the subtree and the contact");
	CHECK(indexed(carol, 1) == 2, "carol is offered the folder and the note in it");
	CHECK(indexed(PEER, 1) == 0, "a contact shared nothing is offered nothing");
	/* A MEMBER IS OFFERED NOTHING HERE, sec 519: its notes come in the
	 * journal, and its INDEX goes unanswered. */
	CHECK(indexed(PEER, 0) == -1, "while a member's index goes unanswered");

	snprintf(line, sizeof(line), "set note %s parent top", g);
	CHECK(ask(line) == FZN_REPLY_OK && indexed(carol, 1) == 1,
	      "a note moved out of the shared folder stops being offered");
	snprintf(line, sizeof(line), "set note %s parent %s", o, f);
	CHECK(ask(line) == FZN_REPLY_OK && indexed(carol, 1) == 2,
	      "and one moved in starts");

	/* ITS TEXTS, sec 438: a blob is carol's to fetch only while a note in
	 * her share has it. g is outside the folder now. */
	{
		static uint8_t big[5000];
		uint8_t root[FZN_BLOB_HASH_LEN];
		char path[64];
		FILE *fp;

		memset(big, 'q', sizeof(big));
		snprintf(path, sizeof(path), "/tmp/fzn-notes-share-%ld.in", (long)getpid());
		fp = fopen(path, "wb");
		CHECK(fp && fwrite(big, 1u, sizeof(big), fp) == sizeof(big), "fixture: a long file");
		if (fp)
			(void)fclose(fp);
		snprintf(line, sizeof(line), "set note %s file %s", g, path);
		CHECK(ask(line) == FZN_REPLY_OK, "fixture: g's text a blob");
		blob_stub_last_root(root);
		CHECK(!fzn_node_notes_shares_blob(&notes, carol, root),
		      "a blob of a note outside the share is not carol's");
		snprintf(line, sizeof(line), "set note %s parent %s", g, f);
		CHECK(ask(line) == FZN_REPLY_OK && fzn_node_notes_shares_blob(&notes, carol, root),
		      "moved into the shared folder, its blob is");
		CHECK(!fzn_node_notes_shares_blob(&notes, PEER, root),
		      "and not another contact's");
		root[0] ^= 1u;
		CHECK(!fzn_node_notes_shares_blob(&notes, carol, root), "nor another root");
		(void)unlink(path);
	}

	CHECK(fzn_contact_remove(&OPS, carol) == FZN_CONTACT_OK, "fixture: carol forgotten");
	CHECK(ask("list share") == FZN_REPLY_OK && has(",c4c4c4c4"),
	      "a share whose contact was forgotten names the key");
	CHECK(fzn_contact_add(&OPS, carol, "carol", 5u, 1u) == FZN_CONTACT_OK,
	      "fixture: carol again");
	snprintf(line, sizeof(line), "remove share %s carol", f);
	CHECK(ask(line) == FZN_REPLY_OK && indexed(carol, 1) == 0,
	      "unshared, carol is offered nothing");
	CHECK(ask(line) == FZN_REPLY_ERROR, "and unsharing again is refused");
}

/* GROUP SHARES, sec 471: a subtree shared with `@NAME` reaches whoever is
 * in the group when they ask, and nobody once they leave. */
static void test_group_share(void)
{
	uint8_t carol[FZN_PUBKEY_LEN], dave[FZN_PUBKEY_LEN];
	static fzn_group_t family;
	char f[65], line[200], want[200], gid_hex[65];
	size_t i;

	setup(1);
	memset(carol, 0xc4, sizeof(carol));
	memset(dave, 0xd4, sizeof(dave));
	CHECK(fzn_contact_add(&OPS, carol, "carol", 5u, 1u) == FZN_CONTACT_OK
	              && fzn_contact_add(&OPS, dave, "dave", 4u, 1u) == FZN_CONTACT_OK
	              && fzn_group_add(&OPS, &RNG, "family", 6u, 1u) == FZN_CONTACT_OK
	              && fzn_group_join(&OPS, "family", 6u, carol) == FZN_CONTACT_OK
	              && fzn_group_find(&OPS, "family", 6u, &family) == FZN_CONTACT_OK,
	      "fixture: carol in the group family, dave in none");
	CHECK(ask("add folder top shared") == FZN_REPLY_OK, "fixture: a folder");
	take_id(f);
	snprintf(line, sizeof(line), "add note %s inside", f);
	CHECK(ask(line) == FZN_REPLY_OK, "fixture: a note in it");

	snprintf(line, sizeof(line), "add share %s @nobody", f);
	CHECK(ask(line) == FZN_REPLY_ERROR, "a group that is not there is refused");
	snprintf(line, sizeof(line), "add share %s @family", f);
	CHECK(ask(line) == FZN_REPLY_OK, "the folder is shared with the group");
	snprintf(want, sizeof(want), "1 0 %s,@family", f);
	CHECK(ask("list share") == FZN_REPLY_OK && !strcmp(detail_of(), want),
	      "list share names the group as it was named");
	CHECK(indexed(carol, 1) == 2, "a member is offered the folder and its note");
	CHECK(indexed(dave, 1) == 0, "a contact in no group is offered nothing");

	CHECK(fzn_group_join(&OPS, "family", 6u, dave) == FZN_CONTACT_OK
	              && indexed(dave, 1) == 2,
	      "a member added is served at once");
	CHECK(fzn_group_leave(&OPS, "family", 6u, carol) == FZN_CONTACT_OK
	              && indexed(carol, 1) == 0,
	      "and one who leaves is served nothing at once");

	snprintf(line, sizeof(line), "add share %s carol", f);
	CHECK(ask(line) == FZN_REPLY_OK && indexed(carol, 1) == 2,
	      "a contact's own share and a group's are separate rows");
	CHECK(fzn_group_remove(&OPS, "family", 6u) == FZN_CONTACT_OK
	              && indexed(dave, 1) == 0,
	      "a group removed reaches nobody");
	/* BY ITS ID, sec 516: the name is gone with the group, and is no
	 * identity to work one out from. */
	snprintf(line, sizeof(line), "remove share %s @family", f);
	CHECK(ask(line) == FZN_REPLY_ERROR, "a removed group's name finds nothing");
	for (i = 0; i < FZN_PUBKEY_LEN; i++)
		snprintf(gid_hex + (2u * i), 3u, "%02x", family.id[i]);
	snprintf(line, sizeof(line), "remove share %s %s", f, gid_hex);
	CHECK(ask(line) == FZN_REPLY_OK, "and its share is taken away by the id list share prints");
	snprintf(want, sizeof(want), "1 0 %s,carol", f);
	CHECK(ask("list share") == FZN_REPLY_OK && !strcmp(detail_of(), want),
	      "leaving carol's own");
}

/* READING A SHARER'S TREE, sec 437: `list shared` and `get shared` over
 * the notes carol shared, which pulling filed in her tree. */
static void test_shared_reads(void)
{
	uint8_t carol[FZN_PUBKEY_LEN], hid[FZN_TREE_ID_LEN], gid[FZN_TREE_ID_LEN];
	uint8_t record[FZN_RECORD_MAX_LEN];
	char f[65], g[65], h[65], line[200], want[200];
	fzn_notes_received_t seam;
	fzn_persist_ops_t ops;
	fzn_notes_store_t tree;
	size_t len = 0, i;
	int wrote = 0;

	setup(0);
	memset(carol, 0xc4, sizeof(carol));
	CHECK(fzn_contact_add(&OPS, carol, "carol", 5u, 1u) == FZN_CONTACT_OK,
	      "fixture: the contact carol");
	/* WRITTEN HERE, COPIED INTO CAROL'S TREE: G and H, not their parent F,
	 * as a share of G arrives. */
	CHECK(ask("add folder top folder") == FZN_REPLY_OK, "fixture: F");
	take_id(f);
	snprintf(line, sizeof(line), "add note %s child", f);
	CHECK(ask(line) == FZN_REPLY_OK, "fixture: G under F");
	take_id(g);
	snprintf(line, sizeof(line), "add note %s grandchild", g);
	CHECK(ask(line) == FZN_REPLY_OK, "fixture: H under G");
	take_id(h);
	CHECK(fzn_notes_received_ops(&seam, &OPS, &HASH, carol, &ops) == FZN_NOTES_OK
	              && fzn_notes_store_init(&tree, &ops, &HASH) == FZN_NOTES_OK,
	      "fixture: carol's tree");
	for (i = 0; i < FZN_TREE_ID_LEN; i++) {
		unsigned v;

		(void)sscanf(g + (2u * i), "%2x", &v);
		gid[i] = (uint8_t)v;
		(void)sscanf(h + (2u * i), "%2x", &v);
		hid[i] = (uint8_t)v;
	}
	CHECK(fzn_notes_get(&notes.store, gid, SELF, record, sizeof(record), &len) == FZN_NOTES_OK
	              && fzn_notes_put(&tree, record, len, notes.author.policy, &SIGN, &wrote, NULL)
	                         == FZN_NOTES_OK
	              && fzn_notes_get(&notes.store, hid, SELF, record, sizeof(record), &len)
	                         == FZN_NOTES_OK
	              && fzn_notes_put(&tree, record, len, notes.author.policy, &SIGN, &wrote, NULL)
	                         == FZN_NOTES_OK,
	      "fixture: G and H in carol's tree");

	snprintf(want, sizeof(want), "1 0 %s,", g);
	CHECK(ask("list shared carol top") == FZN_REPLY_OK && !strncmp(detail_of(), want, strlen(want))
	              && has(",child"),
	      "the top of carol's tree is G alone, the root of what she shared");
	CHECK(!has(f), "and not this node's own F");
	snprintf(line, sizeof(line), "list shared carol %s", g);
	CHECK(ask(line) == FZN_REPLY_OK && has(h) && has(",grandchild"), "G's child is listed");
	snprintf(line, sizeof(line), "get shared carol %s", h);
	CHECK(ask(line) == FZN_REPLY_OK && has(" grandchild"), "and read");
	snprintf(line, sizeof(line), "get shared carol %s", f);
	CHECK(ask(line) == FZN_REPLY_ERROR, "a note carol did not share is not in her tree");
	CHECK(ask("list note top") == FZN_REPLY_OK && !strncmp(detail_of(), "1 0", 3u),
	      "this node's own top still holds only its F");
	CHECK(ask("list shared nobody top") == FZN_REPLY_ERROR, "a name that is no contact is refused");
	CHECK(ask("list shared") == FZN_REPLY_MALFORMED, "a listing with no name is malformed");
	CHECK(ask_as(FZN_ORIGIN_LOCAL, "list shared carol top") == FZN_REPLY_DENIED,
	      "another user reads carol's tree");
	CHECK(ask("set shared carol top") == FZN_REPLY_NONE, "and nothing writes it");
}

/* `add import`, sec 440: a Takeout directory, a KNotes calendar, and what
 * either refuses, named. Scratch is named and removed by name. */
static int put_file(const char *path, const char *text, size_t len)
{
	FILE *f = fopen(path, "wb");
	int ok = f && fwrite(text, 1u, len, f) == len;

	if (f)
		ok = (fclose(f) == 0) && ok;
	return ok;
}

static void test_import(void)
{
	static const char milk[] = "{\"title\":\"milk\",\"textContent\":\"two pints\","
	                           "\"createdTimestampUsec\":1700000000123456}";
	static const char eggs[] = "{\"title\":\"eggs\",\"textContent\":\"a dozen\","
	                           "\"createdTimestampUsec\":1700000000999000}";
	static const char ics[] = "BEGIN:VCALENDAR\r\n"
	                          "BEGIN:VJOURNAL\r\nSUMMARY:first\r\nDESCRIPTION:one\r\n"
	                          "CREATED:20231114T221320Z\r\nEND:VJOURNAL\r\n"
	                          "BEGIN:VJOURNAL\r\nSUMMARY:second\r\nEND:VJOURNAL\r\n"
	                          "END:VCALENDAR\r\n";
	char dir[64], f_milk[96], f_eggs[96], f_junk[96], f_photo[96], f_big[96], f_ics[96];
	char f_txt[96], folder[65], line[400];
	static char big[FZN_NODE_NOTES_IMPORT_FILE_MAX + 2u];

	setup(0);
	snprintf(dir, sizeof(dir), "/tmp/fzn-notes-import-%ld", (long)getpid());
	snprintf(f_milk, sizeof(f_milk), "%s/milk.json", dir);
	snprintf(f_eggs, sizeof(f_eggs), "%s/eggs.json", dir);
	snprintf(f_junk, sizeof(f_junk), "%s/junk.json", dir);
	snprintf(f_photo, sizeof(f_photo), "%s/photo.jpg", dir);
	snprintf(f_big, sizeof(f_big), "%s.big.json", dir);
	snprintf(f_ics, sizeof(f_ics), "%s.ics", dir);
	snprintf(f_txt, sizeof(f_txt), "%s.txt", dir);
	CHECK(mkdir(dir, 0700) == 0 && put_file(f_milk, milk, sizeof(milk) - 1u)
	              && put_file(f_eggs, eggs, sizeof(eggs) - 1u) && put_file(f_junk, "nope", 4u)
	              && put_file(f_photo, "\xff\xd8", 2u) && put_file(f_ics, ics, sizeof(ics) - 1u)
	              && put_file(f_txt, "x", 1u),
	      "fixture: a Takeout directory, a calendar and a text file");
	CHECK(ask("add folder top Imported") == FZN_REPLY_OK, "fixture: a folder to import into");
	take_id(folder);

	snprintf(line, sizeof(line), "add import %s %s", folder, dir);
	CHECK(ask_as(FZN_ORIGIN_LOCAL, line) == FZN_REPLY_DENIED,
	      "another user may not make the node read a path");
	CHECK(ask(line) == FZN_REPLY_OK && !strncmp(detail_of(), "2 0 0 1 ", 8u),
	      "a Takeout imports its two notes and refuses the one that will not parse");
	CHECK(ask(line) == FZN_REPLY_OK && !strncmp(detail_of(), "0 2 0 1", 7u),
	      "a second import recognises both and writes nothing");
	snprintf(line, sizeof(line), "add import %s %s", folder, f_ics);
	CHECK(ask(line) == FZN_REPLY_OK && !strcmp(detail_of(), "2 0 1 0"),
	      "a KNotes calendar imports both journals, one of them undated");
	snprintf(line, sizeof(line), "list note %s", folder);
	CHECK(ask(line) == FZN_REPLY_OK && !strncmp(detail_of(), "4 0", 3u) && has(",milk")
	              && has(",eggs") && has(",first") && has(",second"),
	      "all four are in the folder");

	/* PAST THE BOUND, REFUSED AND NAMED BY ITS FILE, never cut. */
	memset(big, ' ', sizeof(big));
	CHECK(put_file(f_big, big, FZN_NODE_NOTES_IMPORT_FILE_MAX + 1u),
	      "fixture: a Keep file one byte past the bound");
	snprintf(line, sizeof(line), "add import %s %s", folder, f_big);
	CHECK(ask(line) == FZN_REPLY_OK && !strncmp(detail_of(), "0 0 0 1 ", 8u)
	              && has("big.json"),
	      "a file past the bound is refused and named");

	snprintf(line, sizeof(line), "add import %s %s", folder, f_txt);
	CHECK(ask(line) == FZN_REPLY_MALFORMED, "a file that is no export is malformed");
	snprintf(line, sizeof(line), "add import %s %s.none", folder, dir);
	CHECK(ask(line) == FZN_REPLY_ERROR, "a path that is not there is refused");
	snprintf(line, sizeof(line), "add import %s %s", "11111111111111111111111111111111"
	                                                   "11111111111111111111111111111111",
	         f_ics);
	CHECK(ask(line) == FZN_REPLY_ERROR, "a folder this node does not hold is refused");
	CHECK(ask("add import top") == FZN_REPLY_MALFORMED, "no path is malformed");

	(void)unlink(f_milk);
	(void)unlink(f_eggs);
	(void)unlink(f_junk);
	(void)unlink(f_photo);
	(void)unlink(f_big);
	(void)unlink(f_ics);
	(void)unlink(f_txt);
	CHECK(rmdir(dir) == 0, "the scratch directory is left empty and removed");
}

/* CHECKLISTS, sec 442: made, filled, ticked, reworded and emptied through
 * the verbs, and a list long enough to need a blob read back through it. */
static void test_checklist(void)
{
	char list[65], note[65], line[600];
	static char long_item[401];
	int i;

	setup(0);
	CHECK(ask("add list top shopping") == FZN_REPLY_OK, "a checklist is made");
	take_id(list);
	snprintf(line, sizeof(line), "get note %s items", list);
	CHECK(ask(line) == FZN_REPLY_OK && !strcmp(detail_of(), "0 0"), "it starts empty");
	snprintf(line, sizeof(line), "add item %s milk, two pints", list);
	CHECK(ask(line) == FZN_REPLY_OK, "an item is added");
	snprintf(line, sizeof(line), "add item %s eggs", list);
	CHECK(ask(line) == FZN_REPLY_OK, "and another");
	snprintf(line, sizeof(line), "get note %s items", list);
	CHECK(ask(line) == FZN_REPLY_OK && !strcmp(detail_of(), "2 0 0,milk%2c%20two%20pints 0,eggs"),
	      "both listed in order, unchecked, escaped so each stays one field");
	snprintf(line, sizeof(line), "set note %s item 1 check", list);
	CHECK(ask(line) == FZN_REPLY_OK, "the second is ticked");
	snprintf(line, sizeof(line), "set note %s item 0 text oat milk", list);
	CHECK(ask(line) == FZN_REPLY_OK, "the first is reworded");
	snprintf(line, sizeof(line), "get note %s items", list);
	CHECK(ask(line) == FZN_REPLY_OK && !strcmp(detail_of(), "2 0 0,oat%20milk 1,eggs"),
	      "the tick and the rewording are both kept, and nothing else moved");
	snprintf(line, sizeof(line), "get note %s items 1", list);
	CHECK(ask(line) == FZN_REPLY_OK && !strcmp(detail_of(), "2 1 1,eggs"), "a page from item 1");
	snprintf(line, sizeof(line), "set note %s item 1 uncheck", list);
	CHECK(ask(line) == FZN_REPLY_OK, "unticked");
	snprintf(line, sizeof(line), "remove item %s 0", list);
	CHECK(ask(line) == FZN_REPLY_OK, "the first removed");
	snprintf(line, sizeof(line), "get note %s items", list);
	CHECK(ask(line) == FZN_REPLY_OK && !strcmp(detail_of(), "1 0 0,eggs"),
	      "one item is left, unticked");
	snprintf(line, sizeof(line), "remove item %s 5", list);
	CHECK(ask(line) == FZN_REPLY_ERROR, "an item that is not there is refused");
	snprintf(line, sizeof(line), "set note %s item 3 check", list);
	CHECK(ask(line) == FZN_REPLY_ERROR, "and cannot be ticked");
	snprintf(line, sizeof(line), "set note %s item 7 text far away", list);
	CHECK(ask(line) == FZN_REPLY_ERROR, "nor reworded into being past the end");
	snprintf(line, sizeof(line), "set note %s item 0 frobnicate", list);
	CHECK(ask(line) == FZN_REPLY_MALFORMED, "a change that is none is malformed");
	snprintf(line, sizeof(line), "add item %s", list);
	CHECK(ask(line) == FZN_REPLY_MALFORMED, "an item with no text is malformed");
	snprintf(line, sizeof(line), "add item %s x", list);
	CHECK(ask_as(FZN_ORIGIN_LOCAL, line) == FZN_REPLY_DENIED, "another user may not add one");
	/* A CHECKLIST'S TEXT IS ITS ITEMS, and not set over them. */
	snprintf(line, sizeof(line), "set note %s text [ ] eggs", list);
	CHECK(ask(line) == FZN_REPLY_ERROR, "a checklist's text is not set over its items");
	snprintf(line, sizeof(line), "get note %s items", list);
	CHECK(ask(line) == FZN_REPLY_OK && !strcmp(detail_of(), "1 0 0,eggs"),
	      "and its items are as they were");

	CHECK(ask("add note top plain") == FZN_REPLY_OK, "fixture: a note that is no list");
	take_id(note);
	snprintf(line, sizeof(line), "add item %s x", note);
	CHECK(ask(line) == FZN_REPLY_ERROR, "a note that is no checklist takes no items");
	snprintf(line, sizeof(line), "get note %s items", note);
	CHECK(ask(line) == FZN_REPLY_ERROR, "and lists none");

	/* LONG ITEMS are sealed and read back through the blob, as any are. */
	memset(long_item, 'z', sizeof(long_item) - 1u);
	for (i = 0; i < 4; i++) {
		snprintf(line, sizeof(line), "add item %s %s", list, long_item);
		CHECK(ask(line) == FZN_REPLY_OK, "a long item is added");
	}
	snprintf(line, sizeof(line), "get note %s", list);
	CHECK(ask(line) == FZN_REPLY_OK && has(" blob "), "the list's items went into a blob");
	snprintf(line, sizeof(line), "set note %s item 4 check", list);
	CHECK(ask(line) == FZN_REPLY_OK, "an item in the blob is ticked");
	snprintf(line, sizeof(line), "get note %s items 4", list);
	CHECK(ask(line) == FZN_REPLY_OK && !strncmp(detail_of(), "5 4 1,zzzz", 10u),
	      "and reads back ticked from the blob");
}

/* COLLECTING TEXTS, sec 443: a blob is kept while a note names it, in this
 * node's tree or a sharer's, and the verb drives the node's collect hook. */
static uint8_t offered[3][FZN_BLOB_HASH_LEN];
static int decisions[3];

static int fake_collect(void *ctx, int (*keep)(void *keep_ctx, const uint8_t *root),
                        void *keep_ctx, size_t *kept, size_t *removed)
{
	size_t i;

	(void)ctx;
	*kept = 0;
	*removed = 0;
	for (i = 0; i < 3u; i++) {
		decisions[i] = keep(keep_ctx, offered[i]);
		if (decisions[i])
			(*kept)++;
		else
			(*removed)++;
	}
	return 1;
}

static void test_collecting_texts(void)
{
	static char long_text[5001];
	uint8_t carol[FZN_PUBKEY_LEN], blob_root[FZN_BLOB_HASH_LEN], gid[FZN_TREE_ID_LEN];
	uint8_t record[FZN_RECORD_MAX_LEN];
	char note[65], line[800];
	fzn_notes_received_t seam;
	fzn_persist_ops_t ops;
	fzn_notes_store_t tree;
	size_t len = 0, i;
	int wrote = 0;

	setup(0);
	memset(blob_root, 0x5e, sizeof(blob_root));
	CHECK(!fzn_node_notes_names_blob(&notes, blob_root), "no note names a text yet");
	CHECK(ask("remove text unused") == FZN_REPLY_ERROR,
	      "with no collect hook, the node says it keeps none");
	CHECK(ask("add note top long") == FZN_REPLY_OK, "fixture: a note");
	take_id(note);
	memset(long_text, 'w', sizeof(long_text) - 1u);
	{
		char path[64];
		FILE *f;

		snprintf(path, sizeof(path), "/tmp/fzn-notes-collect-%ld.in", (long)getpid());
		f = fopen(path, "wb");
		CHECK(f && fwrite(long_text, 1u, sizeof(long_text) - 1u, f) > 0u, "fixture: a file");
		if (f)
			(void)fclose(f);
		snprintf(line, sizeof(line), "set note %s file %s", note, path);
		CHECK(ask(line) == FZN_REPLY_OK, "fixture: the note's text sealed into a blob");
		(void)unlink(path);
		blob_stub_last_root(blob_root);
	}
	CHECK(fzn_node_notes_names_blob(&notes, blob_root), "this node's note names its blob");

	/* THE SAME ROOT NAMED ONLY IN A SHARER'S TREE is still kept. */
	for (i = 0; i < FZN_TREE_ID_LEN; i++) {
		unsigned v;

		(void)sscanf(note + (2u * i), "%2x", &v);
		gid[i] = (uint8_t)v;
	}
	memset(carol, 0xc4, sizeof(carol));
	CHECK(fzn_notes_received_ops(&seam, &OPS, &HASH, carol, &ops) == FZN_NOTES_OK
	              && fzn_notes_store_init(&tree, &ops, &HASH) == FZN_NOTES_OK
	              && fzn_notes_get(&notes.store, gid, SELF, record, sizeof(record), &len)
	                         == FZN_NOTES_OK
	              && fzn_notes_put(&tree, record, len, notes.author.policy, &SIGN, &wrote, NULL)
	                         == FZN_NOTES_OK,
	      "fixture: the note also in carol's tree");
	CHECK(fzn_notes_erase(&notes.store, gid, SELF) == FZN_NOTES_OK,
	      "fixture: and gone from this node's own");
	CHECK(fzn_node_notes_names_blob(&notes, blob_root),
	      "a blob named only in a sharer's tree is kept");
	CHECK(fzn_notes_received_forget(&OPS, carol, &len) == FZN_NOTES_OK
	              && !fzn_node_notes_names_blob(&notes, blob_root),
	      "and once the share is forgotten, nothing names it");

	/* THE VERB: the hook is asked about each root, and the counts answer. */
	memset(offered[1], 0x11, FZN_BLOB_HASH_LEN);
	memset(offered[2], 0x22, FZN_BLOB_HASH_LEN);
	notes.collect = fake_collect;
	CHECK(ask("add note top again") == FZN_REPLY_OK, "fixture: another note");
	take_id(note);
	{
		char path[64];
		FILE *f;

		snprintf(path, sizeof(path), "/tmp/fzn-notes-collect-%ld.in", (long)getpid());
		f = fopen(path, "wb");
		CHECK(f && fwrite(long_text, 1u, sizeof(long_text) - 1u, f) > 0u, "fixture: a file");
		if (f)
			(void)fclose(f);
		snprintf(line, sizeof(line), "set note %s file %s", note, path);
		CHECK(ask(line) == FZN_REPLY_OK, "fixture: its text a blob");
		(void)unlink(path);
		blob_stub_last_root(offered[0]);
	}
	CHECK(ask_as(FZN_ORIGIN_LOCAL, "remove text unused") == FZN_REPLY_DENIED,
	      "another user may not collect");
	CHECK(ask("remove text") == FZN_REPLY_MALFORMED, "a collection of nothing named is malformed");
	CHECK(ask("remove text unused") == FZN_REPLY_OK && !strcmp(detail_of(), "2 1")
	              && decisions[0] && !decisions[1] && !decisions[2],
	      "the named blob is kept and the two nothing names removed");
	notes.collect = NULL;
}

/* MEMBERS PROVED BY CHAINS JOIN THE ADMITTED SET, sec 445: added once,
 * replaced each round, and never at the cost of the set the node opened with. */
static int admits(const uint8_t *key)
{
	size_t i;

	for (i = 0; i < notes.author.policy.admitted_count; i++)
		if (!memcmp(notes.author.policy.admitted[i].key, key, FZN_PUBKEY_LEN))
			return 1;
	return 0;
}

static void test_members_join_the_admitted_set(void)
{
	static uint8_t keys[FZN_NODE_NOTES_WRITERS + 2u][FZN_PUBKEY_LEN];
	size_t i;

	setup(1);
	memset(keys[0], 0x71, FZN_PUBKEY_LEN);
	memset(keys[1], 0x72, FZN_PUBKEY_LEN);
	memcpy(keys[2], PEER, FZN_PUBKEY_LEN);
	CHECK(fzn_node_notes_admit_members(&notes, (const uint8_t (*)[FZN_PUBKEY_LEN])keys, 3u) == 2u
	              && admits(keys[0]) && admits(keys[1]) && admits(PEER) && admits(SELF),
	      "two members are added, a key already admitted is not added twice");
	CHECK(fzn_node_notes_admit_members(&notes, (const uint8_t (*)[FZN_PUBKEY_LEN])keys + 1, 1u)
	                      == 1u
	              && !admits(keys[0]) && admits(keys[1]),
	      "the next round replaces the members, so one no longer listed drops out");
	CHECK(fzn_node_notes_admit_members(&notes, NULL, 0u) == 0u && admits(SELF) && admits(PEER)
	              && !admits(keys[1]),
	      "and with none, the node's own set remains");
	for (i = 0; i < FZN_NODE_NOTES_WRITERS + 2u; i++)
		memset(keys[i], (int)(0x80u + i), FZN_PUBKEY_LEN);
	CHECK(fzn_node_notes_admit_members(&notes, (const uint8_t (*)[FZN_PUBKEY_LEN])keys,
	                                   FZN_NODE_NOTES_WRITERS + 2u)
	                      == FZN_NODE_NOTES_WRITERS - 1u
	              && admits(SELF) && admits(PEER),
	      "past the room, the rest are not admitted and the node's own set is kept");
}

/* PUSHED TEXTS, sec 448: one node in the test is both ends, so the fake
 * shelf knows which side asks -- the pusher holds the text whole, the server
 * takes it span by span. */
static int serving;
static unsigned spans_taken;
static uint64_t span_firsts[8];

static int fake_place(void *ctx, const uint8_t *root, uint64_t length, const uint8_t *data,
                      size_t data_len, int *complete)
{
	(void)ctx;
	(void)root;
	(void)length;
	if (!serving) {
		*complete = 1; /* the pusher holds it whole */
		return 1;
	}
	if (data) {
		if (data_len != 6u || memcmp(data, "SPAN:", 5u) != 0 || spans_taken >= 8u)
			return 0;
		span_firsts[spans_taken++] = (uint64_t)(data[5] - '0');
	}
	*complete = spans_taken >= 3u;
	return 1;
}

static int fake_span(void *ctx, const uint8_t *root, uint64_t first, uint8_t *out, size_t cap,
                     size_t *out_len, uint64_t *count)
{
	(void)ctx;
	(void)root;
	if (cap < 6u || first > 2u)
		return 0;
	memcpy(out, "SPAN:", 5u);
	out[5] = (uint8_t)('0' + first);
	*out_len = 6u;
	*count = 1u;
	return 1;
}

static const uint8_t *pushing_as;

static int ask_self(void *ctx, const uint8_t *request, size_t request_len, uint8_t *answer_buf,
                    size_t answer_cap, size_t *answer_len)
{
	(void)ctx;
	serving = 1;
	*answer_len = fzn_node_notes_remote(&notes, pushing_as, 0, request, request_len, answer_buf,
	                                    answer_cap);
	serving = 0;
	return *answer_len > 0u;
}

/* ---- a record store in memory, under a real journal, sec 517 ------------- */

#define REC_SLOTS 16u

static struct rec_slot {
	uint8_t issuer[FZN_PUBKEY_LEN];
	uint32_t stream;
	uint64_t seq;
	size_t len;
	uint8_t bytes[FZN_RECORD_MAX_LEN];
} rec_slots[REC_SLOTS];
static size_t rec_count;

static int rec_put(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream, uint64_t seq,
                   const uint8_t *bytes, size_t len)
{
	struct rec_slot *s;

	(void)ctx;
	if (rec_count >= REC_SLOTS || len > FZN_RECORD_MAX_LEN)
		return 0;
	s = &rec_slots[rec_count++];
	memcpy(s->issuer, issuer, FZN_PUBKEY_LEN);
	s->stream = stream;
	s->seq = seq;
	s->len = len;
	memcpy(s->bytes, bytes, len);
	return 1;
}

static int rec_get(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream, uint64_t seq,
                   uint8_t *out, size_t cap, size_t *len_out, int *found_out)
{
	size_t i;

	(void)ctx;
	*found_out = 0;
	for (i = 0; i < rec_count; i++)
		if (rec_slots[i].stream == stream && rec_slots[i].seq == seq
		    && memcmp(rec_slots[i].issuer, issuer, FZN_PUBKEY_LEN) == 0) {
			*found_out = 1;
			if (rec_slots[i].len > cap)
				return 0;
			memcpy(out, rec_slots[i].bytes, rec_slots[i].len);
			*len_out = rec_slots[i].len;
			return 1;
		}
	return 1;
}

/* What fuzznetd's `journal_chain` does: the next record of stream 0. */
static int journal_chain(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN],
                         const fzn_sign_ops_t *sign, uint32_t kind,
                         const uint8_t subject[FZN_SUBJECT_LEN],
                         const uint8_t *body, size_t body_len, uint64_t now_ms, uint8_t *record,
                         size_t cap, size_t *record_len)
{
	return fzn_node_journal_write((fzn_node_journal_t *)ctx, issuer, FZN_NOTE_STREAM, sign, kind,
	                              subject, body, body_len, now_ms, record, cap, record_len, NULL)
	       == FZN_NODE_JOURNAL_OK;
}

/* THE HISTORY, sec 517: through the node's verbs, every write is the next
 * record of this node's stream 0 in a real journal, naming the hash of the
 * one before; the index holds the last of them; and with no journal, no note
 * is written and the reply says why. */
static void test_the_journal_chain(void)
{
	static fzn_node_journal_t nj;
	static fzn_record_store_ops_t rops = { rec_put, rec_get, NULL };
	static uint8_t held[FZN_RECORD_MAX_LEN];
	uint8_t id[FZN_TREE_ID_LEN], prev[FZN_RECORD_ID_LEN];
	char note[65], line[200];
	size_t i, held_len = 0;
	int chained = 1;

	setup(0);
	memset(rec_slots, 0, sizeof(rec_slots));
	rec_count = 0;
	CHECK(fzn_node_journal_init_store(&nj, &rops, &SIGN, &HASH) == FZN_NODE_JOURNAL_OK,
	      "fixture: a journal over a store in memory");
	notes.chain = journal_chain;
	notes.chain_ctx = &nj;
	CHECK(ask("add note top first") == FZN_REPLY_OK, "fixture: a note");
	take_id(note);
	snprintf(line, sizeof(line), "set note %s title second", note);
	CHECK(ask(line) == FZN_REPLY_OK, "fixture: a rename");
	snprintf(line, sizeof(line), "set note %s pin", note);
	CHECK(ask(line) == FZN_REPLY_OK, "fixture: a pin");
	CHECK(fzn_node_journal_received(&nj, SELF, FZN_NOTE_STREAM) == 3u && rec_count == 3u,
	      "three writes are three records of this node's stream 0");
	for (i = 0; i < 3u; i++) {
		fzn_record_t rec;

		if (fzn_record_open(rec_slots[i].bytes, rec_slots[i].len, &rec) != FZN_RECORD_OK
		    || fzn_record_seq(rec) != i + 1u || fzn_record_kind(rec) != FZN_NOTE_KIND
		    || (i > 0u && memcmp(fzn_record_prev(rec), prev, sizeof(prev)) != 0))
			chained = 0;
		stub_hash(NULL, prev, sizeof(prev), rec_slots[i].bytes, rec_slots[i].len);
	}
	CHECK(chained, "each names the hash of the one before");
	for (i = 0; i < FZN_TREE_ID_LEN; i++) {
		unsigned v;

		(void)sscanf(note + (2u * i), "%2x", &v);
		id[i] = (uint8_t)v;
	}
	CHECK(fzn_notes_get(&notes.store, id, SELF, held, sizeof(held), &held_len) == FZN_NOTES_OK
	              && held_len == rec_slots[2].len
	              && memcmp(held, rec_slots[2].bytes, held_len) == 0,
	      "and the index holds the last of them, byte for byte");

	notes.chain = NULL;
	snprintf(line, sizeof(line), "set note %s title third", note);
	CHECK(ask(line) == FZN_REPLY_ERROR && has("journal") && rec_count == 3u,
	      "with no journal, no note is written, and the reply says so");
	fzn_node_journal_close(&nj);
	hooks();
}

/* Read a note record of `key`'s stream 0 out of the memory store. */
static int read_rec(void *ctx, const uint8_t key[FZN_PUBKEY_LEN], uint64_t seq, uint8_t *out,
                    size_t cap, size_t *out_len)
{
	int found = 0;

	return rec_get(ctx, key, FZN_NOTE_STREAM, seq, out, cap, out_len, &found) && found;
}

/* A NOTE `writer` WROTE, as the next record of its stream 0 in `nj`: a
 * payload sealed through the blob stub, and the meta naming it. */
static int note_by(fzn_node_journal_t *nj, const uint8_t writer[FZN_PUBKEY_LEN],
                   const fzn_sign_ops_t *sign, const uint8_t id[FZN_TREE_ID_LEN],
                   const char *title)
{
	static const uint8_t top[FZN_TREE_ID_LEN];
	uint8_t payload[64], content[FZN_NOTE_META_LEN], body[FZN_RECORD_BODY_MAX];
	static uint8_t record[FZN_RECORD_MAX_LEN];
	fzn_note_meta_t meta;
	fzn_note_t fields;
	size_t len = 0, body_len = 0;

	memset(&fields, 0, sizeof(fields));
	fields.title = (const uint8_t *)title;
	fields.title_len = strlen(title);
	memset(&meta, 0, sizeof(meta));
	return fzn_note_payload_write(&fields, payload, sizeof(payload), &len) == FZN_NOTE_OK
	       && blob_stub_seal(NULL, payload, len, &meta.content)
	       && fzn_note_meta_write(&meta, content) == FZN_NOTE_OK
	       && fzn_tree_body(top, 1000u, FZN_NOTE_TYPE_NOTE, content, sizeof(content), body,
	                        sizeof(body), &body_len)
	                  == FZN_TREE_OK
	       && fzn_node_journal_write(nj, writer, FZN_NOTE_STREAM, sign, FZN_NOTE_KIND, id, body,
	                                 body_len, 1u, record, sizeof(record), &len, NULL)
	                  == FZN_NODE_JOURNAL_OK;
}

/* THE INDEX FED FROM A STREAM, sec 519: a sibling's note filed from its
 * stream; its purge record acted on, and told again in this node's own; the
 * stream fed again from the start without the note coming back; and a writer
 * not admitted yet waiting at its cursor until it is. */
static void test_the_feed(void)
{
	static fzn_node_journal_t nj;
	static fzn_record_store_ops_t rops = { rec_put, rec_get, NULL };
	static const uint8_t mark[1] = { 1u };
	static uint8_t record[FZN_RECORD_MAX_LEN];
	uint8_t id[FZN_TREE_ID_LEN], other_id[FZN_TREE_ID_LEN], stranger[FZN_PUBKEY_LEN];
	fzn_sign_ops_t as_peer = { toy_verify, toy_sign, PEER };
	fzn_sign_ops_t as_stranger = { toy_verify, toy_sign, stranger };
	fzn_node_notes_index_tally_t t;
	uint64_t at = 0, again = 0, waits = 0, own_before;
	size_t len = 0;

	setup(1);
	memset(rec_slots, 0, sizeof(rec_slots));
	rec_count = 0;
	memset(id, 0x41, sizeof(id));
	memset(other_id, 0x42, sizeof(other_id));
	memset(stranger, 0x5a, sizeof(stranger));
	CHECK(fzn_node_journal_init_store(&nj, &rops, &SIGN, &HASH) == FZN_NODE_JOURNAL_OK
	              && note_by(&nj, PEER, &as_peer, id, "theirs"),
	      "fixture: the paired node's note, the first record of its stream 0");
	notes.chain = journal_chain;
	notes.chain_ctx = &nj;

	CHECK(fzn_node_notes_index_stream(&notes, read_rec, NULL, PEER, &at,
	                                  fzn_node_journal_received(&nj, PEER, FZN_NOTE_STREAM), &t)
	                      == FZN_NOTES_OK
	              && t.filed == 1u && at == 1u
	              && ask("list note top") == FZN_REPLY_OK && has(",theirs"),
	      "a sibling's note is filed from its stream, and listed");
	CHECK(fzn_node_notes_index_stream(&notes, read_rec, NULL, PEER, &at, 1u, &t) == FZN_NOTES_OK
	              && t.filed == 0u && t.held == 0u && at == 1u,
	      "fed again from its cursor, nothing is filed twice");

	own_before = fzn_node_journal_received(&nj, SELF, FZN_NOTE_STREAM);
	CHECK(fzn_node_journal_write(&nj, PEER, FZN_NOTE_STREAM, &as_peer, FZN_NOTE_PURGE_KIND, id,
	                             mark, sizeof(mark), 2u, record, sizeof(record), &len, NULL)
	                      == FZN_NODE_JOURNAL_OK
	              && fzn_node_notes_index_stream(&notes, read_rec, NULL, PEER, &at,
	                                             fzn_node_journal_received(&nj, PEER,
	                                                                       FZN_NOTE_STREAM),
	                                             &t)
	                         == FZN_NOTES_OK
	              && t.purged == 1u && at == 2u && fzn_notes_purged(&notes.store, id)
	              && ask("list note top") == FZN_REPLY_OK && !has(",theirs"),
	      "its purge record purges the note here: marked, and no longer listed");
	CHECK(fzn_node_journal_received(&nj, SELF, FZN_NOTE_STREAM) == own_before + 1u,
	      "and this node says so in its own stream, once");

	CHECK(fzn_node_notes_index_stream(&notes, read_rec, NULL, PEER, &again, 2u, &t)
	                      == FZN_NOTES_OK
	              && t.filed == 0u && t.purged == 2u && again == 2u
	              && fzn_node_journal_received(&nj, SELF, FZN_NOTE_STREAM) == own_before + 1u
	              && ask("list note top") == FZN_REPLY_OK && !has(",theirs"),
	      "fed again from the start, the purged note is not filed again, nor told again");

	/* A PURGE FROM A WRITER NOT ADMITTED waits too, and purges nothing:
	 * who may ask a note to go is who may write one. */
	{
		uint8_t ours[FZN_TREE_ID_LEN], outsider[FZN_PUBKEY_LEN];
		fzn_sign_ops_t as_outsider = { toy_verify, toy_sign, outsider };
		char hexid[65];
		uint64_t cut = 0;
		size_t i;

		memset(outsider, 0x6b, sizeof(outsider));
		CHECK(ask("add note top ours") == FZN_REPLY_OK, "fixture: a note of this node's");
		take_id(hexid);
		for (i = 0; i < FZN_TREE_ID_LEN; i++) {
			unsigned v;

			(void)sscanf(hexid + (2u * i), "%2x", &v);
			ours[i] = (uint8_t)v;
		}
		CHECK(fzn_node_journal_write(&nj, outsider, FZN_NOTE_STREAM, &as_outsider,
		                             FZN_NOTE_PURGE_KIND, ours, mark, sizeof(mark), 3u, record,
		                             sizeof(record), &len, NULL)
		                      == FZN_NODE_JOURNAL_OK
		              && fzn_node_notes_index_stream(&notes, read_rec, NULL, outsider, &cut, 1u,
		                                             &t)
		                         == FZN_NOTES_OK
		              && t.waiting && t.purged == 0u && cut == 0u
		              && !fzn_notes_purged(&notes.store, ours)
		              && ask("list note top") == FZN_REPLY_OK && has(",ours"),
		      "a purge from a writer not admitted waits, and the note stays");
	}
	CHECK(note_by(&nj, stranger, &as_stranger, other_id, "unproved")
	              && fzn_node_notes_index_stream(&notes, read_rec, NULL, stranger, &waits, 1u,
	                                             &t)
	                         == FZN_NOTES_OK
	              && t.waiting && waits == 0u,
	      "a writer not admitted yet waits at its cursor");
	CHECK(fzn_node_notes_admit_members(&notes, (const uint8_t (*)[FZN_PUBKEY_LEN])stranger, 1u)
	                      == 1u
	              && fzn_node_notes_index_stream(&notes, read_rec, NULL, stranger, &waits, 1u,
	                                             &t)
	                         == FZN_NOTES_OK
	              && t.filed == 1u && waits == 1u,
	      "and is filed once it is proved a member");
	fzn_node_journal_close(&nj);
	hooks();
}

static void test_pushing_texts(void)
{
	static char long_text[5001];
	char note[65], line[200], path[64];
	fzn_node_notes_text_tally_t t;
	uint8_t stranger[FZN_PUBKEY_LEN];
	FILE *f;

	setup(1);
	memset(long_text, 'v', sizeof(long_text) - 1u);
	snprintf(path, sizeof(path), "/tmp/fzn-notes-push-%ld.in", (long)getpid());
	f = fopen(path, "wb");
	CHECK(f && fwrite(long_text, 1u, sizeof(long_text) - 1u, f) > 0u, "fixture: a long file");
	if (f)
		(void)fclose(f);
	CHECK(ask("add note top long") == FZN_REPLY_OK, "fixture: a note");
	take_id(note);
	snprintf(line, sizeof(line), "set note %s file %s", note, path);
	CHECK(ask(line) == FZN_REPLY_OK, "fixture: its text a blob");
	(void)unlink(path);

	CHECK(fzn_node_notes_push_texts(&notes, ask_self, NULL, &t) == 1 && t.offered == 0u,
	      "with no shelf hooks, nothing is offered");
	notes.place = fake_place;
	notes.span = fake_span;
	spans_taken = 0;
	pushing_as = PEER;
	CHECK(fzn_node_notes_push_texts(&notes, ask_self, NULL, &t) == 1 && t.offered == 1u
	              && t.pushed == 1u && t.spans == 3u && t.refused == 0u,
	      "a wanted text is pushed span by span until it is whole");
	CHECK(spans_taken == 3u && span_firsts[0] == 0u && span_firsts[1] == 1u
	              && span_firsts[2] == 2u,
	      "the spans arrive in order, each once");
	CHECK(fzn_node_notes_push_texts(&notes, ask_self, NULL, &t) == 1 && t.offered == 1u
	              && t.pushed == 0u && t.spans == 0u,
	      "a text the peer holds whole is offered and not sent");
	memset(stranger, 0xd6, sizeof(stranger));
	pushing_as = stranger;
	spans_taken = 0;
	CHECK(fzn_node_notes_push_texts(&notes, ask_self, NULL, &t) == 1 && t.refused == 1u
	              && spans_taken == 0u,
	      "a sender the server does not admit is refused");
	pushing_as = PEER;
	{
		uint8_t req[2u + FZN_BLOB_HASH_LEN + 8u], out[8];
		size_t n;

		req[0] = FZN_NOTES_SYNC_VERSION;
		req[1] = FZN_NOTES_SYNC_TEXT_PUSH;
		memset(req + 2, 0x5e, FZN_BLOB_HASH_LEN);
		memset(req + 2 + FZN_BLOB_HASH_LEN, 0, 8u);
		req[2 + FZN_BLOB_HASH_LEN + 7] = 9u;
		serving = 1;
		n = fzn_node_notes_remote(&notes, PEER, 0, req, sizeof(req), out, sizeof(out));
		CHECK(n == 3u && out[2] == 0u, "a text at a length no note names is refused");
		notes.place = NULL;
		req[2 + FZN_BLOB_HASH_LEN + 7] = 0u;
		n = fzn_node_notes_remote(&notes, PEER, 0, req, sizeof(req), out, sizeof(out));
		CHECK(n == 3u && out[2] == 0u, "and a node with no shelf refuses every text");
		serving = 0;
		CHECK(fzn_node_notes_remote(&notes, PEER, 1, req, sizeof(req), out, sizeof(out)) == 0u,
		      "and a contact's request is no push at all");
	}
	notes.place = NULL;
	notes.span = NULL;
}

/* AN UN-PAIRED PARTNER IS NOT PINNED, sec 451: a node admitted from the live
 * peer table, which pulled and so is a partner, then dropped from it. */
static void test_unpaired_partner(void)
{
	char b[65], line[200];
	uint8_t query[FZN_NOTES_SYNC_PURGES_QUERY_LEN] = { FZN_NOTES_SYNC_VERSION,
		                                           FZN_NOTES_SYNC_PURGES_QUERY };
	uint8_t out[FZN_NOTES_SYNC_REPLY_MAX];

	setup(0);
	CHECK(fzn_node_notes_admit_members(&notes, (const uint8_t (*)[FZN_PUBKEY_LEN])PEER, 1u)
	                      == 1u
	              && fzn_node_notes_remote(&notes, PEER, 0, query, sizeof(query), out,
	                                       sizeof(out))
	                         > 0u,
	      "fixture: a paired node, admitted from the live table, asks for its purges");
	CHECK(ask("add note top bin") == FZN_REPLY_OK, "fixture: a note to bin");
	take_id(b);
	snprintf(line, sizeof(line), "set note %s trash", b);
	CHECK(ask(line) == FZN_REPLY_OK, "fixture: it is trashed");
	CHECK(fzn_node_notes_admit_members(&notes, NULL, 0u) == 0u,
	      "fixture: the node is un-paired");
	CHECK(ask("remove note trash") == FZN_REPLY_OK && !strcmp(detail_of(), "1 0"),
	      "the un-paired partner pins nothing, and the purge goes at once");
	snprintf(line, sizeof(line), "get note %s", b);
	CHECK(ask(line) == FZN_REPLY_ERROR, "and the note is gone");
}

/* A PARTNER SEEN WHILE THE CLOCK READ YEARS AHEAD, sec 470: once the clock
 * is set back it ages from the new time, rather than being pinned until the
 * clock catches up -- the shape of fuzzypickles' sec 156 defect. */
static void test_a_partner_seen_in_the_future_ages_from_now(void)
{
	char b[65], line[200];
	uint8_t query[FZN_NOTES_SYNC_PURGES_QUERY_LEN] = { FZN_NOTES_SYNC_VERSION,
		                                           FZN_NOTES_SYNC_PURGES_QUERY };
	uint8_t out[FZN_NOTES_SYNC_REPLY_MAX];
	const uint64_t back = clock_ms;

	setup(0);
	clock_ms = back + (10ull * 365u * 24u * 3600u * 1000u);
	CHECK(fzn_node_notes_admit_members(&notes, (const uint8_t (*)[FZN_PUBKEY_LEN])PEER, 1u)
	                      == 1u
	              && fzn_node_notes_remote(&notes, PEER, 0, query, sizeof(query), out,
	                                       sizeof(out))
	                         > 0u,
	      "fixture: a partner asks while this node's clock reads ten years ahead");
	clock_ms = back;
	CHECK(ask("add note top bin") == FZN_REPLY_OK, "fixture: the clock set back, a note to bin");
	take_id(b);
	snprintf(line, sizeof(line), "set note %s trash", b);
	CHECK(ask(line) == FZN_REPLY_OK && ask("remove note trash") == FZN_REPLY_OK
	              && !strcmp(detail_of(), "1 1"),
	      "the partner is pinned: it was seen, and the stamp now reads as today");
	clock_ms = back + FZN_NODE_NOTES_PARTNER_AGE_MS + 1000u;
	CHECK(ask("add note top bin later") == FZN_REPLY_OK, "fixture: a month on, another note");
	take_id(b);
	snprintf(line, sizeof(line), "set note %s trash", b);
	CHECK(ask(line) == FZN_REPLY_OK && ask("remove note trash") == FZN_REPLY_OK
	              && !strcmp(detail_of(), "1 0"),
	      "a month after the clock was set back, the silent partner pins nothing new and is "
	      "released from what it pinned -- not ten years on");
	clock_ms = back;
}

/* A WRITE THAT TAKES TELLS THE DAEMON TO CONVERSE NOW, sec 449; a read, a
 * refusal and a write by somebody else's origin do not. */
static void test_writes_mark_fresh(void)
{
	char note[65], line[200];

	setup(1);
	CHECK(!notes.fresh, "fixture: a new node is not fresh");
	CHECK(ask("add note top milk") == FZN_REPLY_OK && notes.fresh, "an add marks it fresh");
	take_id(note);
	notes.fresh = 0;
	CHECK(ask("list note top") == FZN_REPLY_OK && !notes.fresh, "a read does not");
	snprintf(line, sizeof(line), "get note %s", note);
	CHECK(ask(line) == FZN_REPLY_OK && !notes.fresh, "nor does a get");
	CHECK(ask("set note 00 text nothing") != FZN_REPLY_OK && !notes.fresh,
	      "a refused write does not");
	snprintf(line, sizeof(line), "set note %s text oat milk", note);
	CHECK(ask(line) == FZN_REPLY_OK && notes.fresh, "an edit does, whose reply is a bare ok");
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
	test_share();
	test_group_share();
	test_shared_reads();
	test_import();
	test_checklist();
	test_collecting_texts();
	test_members_join_the_admitted_set();
	test_pushing_texts();
	test_the_journal_chain();
	test_the_feed();
	test_writes_mark_fresh();
	test_unpaired_partner();
	test_a_partner_seen_in_the_future_ages_from_now();

	if (failures) {
		fprintf(stderr, "notes_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("notes_test: all %d checks passed\n", checks);
	return 0;
}
