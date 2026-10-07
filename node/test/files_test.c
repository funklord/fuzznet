/* Tests for node/files.c: the node's files, blobs of any size. sec 490.
 *
 * WHAT IS ASKED: a file put comes back byte for byte under its key, and
 * under no other; a file past a text's 256 KiB and across several spans is
 * put as readily as one byte; the store holds exactly its four files per
 * blob and lists only the whole ones; a delete removes every one, and not
 * while a transfer holds the root; a leaf changed on disk is not exported.
 *
 * The stubs are shelf_test.c's: a mixing hash and a stream cipher with a
 * tag, which are not cryptography and need not be -- what is checked is that
 * the right bytes reach the right calls and come back.
 */

#define _POSIX_C_SOURCE 200809L

#include "../files.h"
#include "../../contact/contact.h"
#include "../../contact/group.h"

#include <dirent.h>
#include <fcntl.h>
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
	fprintf(stderr, "  FAIL files_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, what)

static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	(void)ctx;
	if (!out || !in)
		return 0;

	h ^= (uint64_t)out_len;
	h *= 0x100000001b3ull;
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

static void stream(const uint8_t *key, const uint8_t *nonce, uint8_t *text, size_t len)
{
	uint64_t h = 0x243f6a8885a308d3ull;
	size_t i;

	for (i = 0; i < FZN_AEAD_KEY_LEN; i++) {
		h ^= key[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < FZN_AEAD_NONCE_LEN; i++) {
		h ^= nonce[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < len; i++) {
		h ^= (uint64_t)i;
		h *= 0x100000001b3ull;
		text[i] ^= (uint8_t)(h >> 24);
	}
}

static void tag_over(const uint8_t *key, const uint8_t *nonce, const uint8_t *aad,
                     size_t aad_len, const uint8_t *text, size_t text_len,
                     uint8_t tag[FZN_AEAD_TAG_LEN])
{
	uint64_t h = 0xff51afd7ed558ccdull;
	size_t i;

	for (i = 0; i < FZN_AEAD_KEY_LEN; i++) {
		h ^= key[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < FZN_AEAD_NONCE_LEN; i++) {
		h ^= nonce[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < aad_len; i++) {
		h ^= aad[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < text_len; i++) {
		h ^= text[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < FZN_AEAD_TAG_LEN; i++) {
		h ^= (uint64_t)i + 0x2545f4914f6cdd1dull;
		h *= 0x100000001b3ull;
		tag[i] = (uint8_t)(h >> 40);
	}
}

static int stub_seal(void *ctx, const uint8_t key[FZN_AEAD_KEY_LEN],
                     const uint8_t nonce[FZN_AEAD_NONCE_LEN], const uint8_t *aad,
                     size_t aad_len, uint8_t *text, size_t text_len,
                     uint8_t tag[FZN_AEAD_TAG_LEN])
{
	(void)ctx;
	stream(key, nonce, text, text_len);
	tag_over(key, nonce, aad, aad_len, text, text_len, tag);
	return 1;
}

static int stub_open(void *ctx, const uint8_t key[FZN_AEAD_KEY_LEN],
                     const uint8_t nonce[FZN_AEAD_NONCE_LEN], const uint8_t *aad,
                     size_t aad_len, uint8_t *text, size_t text_len,
                     const uint8_t tag[FZN_AEAD_TAG_LEN])
{
	uint8_t want[FZN_AEAD_TAG_LEN];

	(void)ctx;
	tag_over(key, nonce, aad, aad_len, text, text_len, want);
	if (memcmp(want, tag, FZN_AEAD_TAG_LEN) != 0)
		return 0;
	stream(key, nonce, text, text_len);
	return 1;
}

static const fzn_hash_ops_t HASH = { stub_hash, NULL };
static const fzn_aead_ops_t AEAD = { stub_seal, stub_open, NULL };

/* A random source that never repeats itself. */
static uint64_t counter = 1;

static int counter_fill(void *ctx, uint8_t *out, size_t len)
{
	size_t i;

	(void)ctx;
	for (i = 0; i < len; i++)
		out[i] = (uint8_t)((counter * 131u + i * 7u) >> (i % 8u));
	counter++;
	return 1;
}


static const fzn_random_ops_t RNG = { counter_fill, NULL };


static char top[64], dir[96], src_path[128], out_path[128];

/* A source file of `len` bytes that do not repeat, so a leaf in the wrong
 * place reads back wrong. */
static int make_source(const char *path, size_t len)
{
	FILE *f = fopen(path, "wb");
	uint32_t s = 7u;
	size_t i;

	if (!f)
		return 0;
	for (i = 0; i < len; i++) {
		s = (s * 1103515245u) + 12345u;
		(void)fputc((int)(s >> 16), f);
	}
	return fclose(f) == 0;
}

static int same_files(const char *a, const char *b)
{
	FILE *fa = fopen(a, "rb"), *fb = fopen(b, "rb");
	int ca, cb, same = fa && fb;

	while (same) {
		ca = fgetc(fa);
		cb = fgetc(fb);
		if (ca != cb)
			same = 0;
		if (ca == EOF || cb == EOF)
			break;
	}
	if (fa)
		(void)fclose(fa);
	if (fb)
		(void)fclose(fb);
	return same;
}

static size_t entries(const char *path)
{
	DIR *d = opendir(path);
	struct dirent *e;
	size_t n = 0;

	if (!d)
		return 0;
	while ((e = readdir(d)) != NULL)
		if (strcmp(e->d_name, ".") && strcmp(e->d_name, ".."))
			n++;
	(void)closedir(d);
	return n;
}

static size_t verb(fzn_node_files_t *files, fzn_verb_t parsed, fzn_origin_t origin,
                   const char *arg, char *reply, size_t cap)
{
	fzn_request_t r;

	memset(&r, 0, sizeof(r));
	r.parsed = parsed;
	r.arg = (const uint8_t *)arg;
	r.arg_len = strlen(arg);
	return fzn_node_files_local(files, origin, &r, reply, cap);
}

/* A STORE IN MEMORY, for the contacts, the groups and the share rows. */
struct mem_entry {
	int used;
	fzn_persist_slot_t slot;
	uint8_t subject[FZN_PUBKEY_LEN];
	uint8_t bytes[512];
	size_t len;
};
static struct mem_entry mem[128];

static struct mem_entry *mem_find(fzn_persist_slot_t slot, const uint8_t *subject, int make)
{
	size_t i;
	struct mem_entry *free_one = NULL;

	for (i = 0; i < sizeof(mem) / sizeof(mem[0]); i++) {
		if (!mem[i].used) {
			if (!free_one)
				free_one = &mem[i];
			continue;
		}
		if (mem[i].slot == slot && memcmp(mem[i].subject, subject, FZN_PUBKEY_LEN) == 0)
			return &mem[i];
	}
	if (!make || !free_one)
		return NULL;
	memset(free_one, 0, sizeof(*free_one));
	free_one->used = 1;
	free_one->slot = slot;
	memcpy(free_one->subject, subject, FZN_PUBKEY_LEN);
	return free_one;
}

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	struct mem_entry *x = mem_find(slot, subject, 0);

	(void)ctx;
	if (!x || x->len > cap)
		return 0;
	memcpy(out, x->bytes, x->len);
	*len = x->len;
	return 1;
}

static int mem_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                    const uint8_t *bytes, size_t len)
{
	struct mem_entry *x;

	(void)ctx;
	if (len > sizeof(x->bytes) || !(x = mem_find(slot, subject, 1)))
		return 0;
	memcpy(x->bytes, bytes, len);
	x->len = len;
	return 1;
}

static int mem_list(void *ctx, fzn_persist_slot_t slot, uint8_t *out, size_t max, size_t *count)
{
	size_t i, n = 0;

	(void)ctx;
	for (i = 0; i < sizeof(mem) / sizeof(mem[0]); i++)
		if (mem[i].used && mem[i].slot == slot) {
			if (n >= max)
				return 0;
			memcpy(out + (n * FZN_PUBKEY_LEN), mem[i].subject, FZN_PUBKEY_LEN);
			n++;
		}
	*count = n;
	return 1;
}

static int mem_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	struct mem_entry *x = mem_find(slot, subject, 0);

	(void)ctx;
	if (x)
		x->used = 0;
	return 1;
}

static const fzn_persist_ops_t STORE = { mem_load, mem_save, mem_list, mem_remove, NULL };

static size_t rows(fzn_persist_slot_t slot)
{
	size_t i, n = 0;

	for (i = 0; i < sizeof(mem) / sizeof(mem[0]); i++)
		n += (size_t)(mem[i].used && mem[i].slot == slot);
	return n;
}

/* The root at the head of a reference in hex. */
static int hex_root(const char *hex, uint8_t root[FZN_BLOB_HASH_LEN])
{
	size_t i;
	unsigned v;

	for (i = 0; i < FZN_BLOB_HASH_LEN; i++) {
		if (sscanf(hex + (2u * i), "%2x", &v) != 1)
			return 0;
		root[i] = (uint8_t)v;
	}
	return 1;
}

/* Flip one byte of `<dir>/<root hex><suffix>` at `offset`. */
static int flip(const char *in, const uint8_t root[FZN_BLOB_HASH_LEN], const char *suffix,
                long offset)
{
	char path[300], hex[FZN_BLOB_HASH_LEN * 2u + 1u];
	uint8_t b = 0;
	size_t i;
	int fd, ok;

	for (i = 0; i < FZN_BLOB_HASH_LEN; i++)
		(void)snprintf(hex + (2u * i), 3u, "%02x", root[i]);
	(void)snprintf(path, sizeof(path), "%s/%s%s", in, hex, suffix);
	fd = open(path, O_RDWR);
	if (fd < 0)
		return 0;
	ok = pread(fd, &b, 1u, offset) == 1;
	b ^= 0x5au;
	ok = ok && pwrite(fd, &b, 1u, offset) == 1;
	return close(fd) == 0 && ok;
}

/* A PEER: another store answering as the node would, the shelf's "absent"
 * for a root it does not hold; a byte of every DATA flipped when `lie`. */
struct peer {
	const fzn_node_files_t *files;
	int lie;
	size_t asked;
};

static int peer_ask(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
                    size_t reply_cap, size_t *reply_len)
{
	struct peer *p = (struct peer *)ctx;

	p->asked++;
	*reply_len = fzn_node_files_answer(p->files, request, request_len, reply, reply_cap);
	if (*reply_len == 0u && reply_cap >= 6u) {
		memcpy(reply, "absent", 6u);
		*reply_len = 6u;
	}
	if (p->lie && *reply_len > 200u && reply[0] != 'a')
		reply[*reply_len - 9u] ^= 1u;
	return 1;
}

/* A QUEUED PEER, sec 494: answers at once from a store and holds replies
 * until polled, so several requests are really out at once. `silent` answers
 * the HAVE and nothing after; `lie` flips a byte of every DATA. */
#define QUEUE 64u
struct queued {
	const fzn_node_files_t *files;
	int silent, lie;
	uint32_t next;
	size_t head, tail, deepest, wants;
	uint32_t msg[QUEUE];
	size_t len[QUEUE];
	uint8_t reply[QUEUE][FZN_NODE_FILES_REPLY_MAX];
};

/* Replies held across every queued peer, and the most there ever were. */
static size_t out_now, out_most;

static int queued_send(void *ctx, const uint8_t *request, size_t request_len, uint32_t *msg)
{
	struct queued *q = (struct queued *)ctx;
	size_t at = q->tail % QUEUE, n;
	fzn_msg_type_t type;

	*msg = ++q->next;
	if (fzn_msg_peek(request, request_len, &type) == FZN_MSG_OK && type == FZN_MSG_WANT) {
		q->wants++;
		if (q->silent)
			return 1;
	}
	n = fzn_node_files_answer(q->files, request, request_len, q->reply[at],
	                          sizeof(q->reply[at]));
	if (n == 0u || q->tail - q->head >= QUEUE)
		return 1;
	if (q->lie && n > 200u)
		q->reply[at][n - 9u] ^= 1u;
	q->msg[at] = *msg;
	q->len[at] = n;
	q->tail++;
	if (q->tail - q->head > q->deepest)
		q->deepest = q->tail - q->head;
	if (++out_now > out_most)
		out_most = out_now;
	return 1;
}

static int queued_poll(void *ctx, uint8_t *reply, size_t cap, size_t *len, uint32_t *msg,
                       unsigned timeout_ms)
{
	struct queued *q = (struct queued *)ctx;
	size_t at = q->head % QUEUE;

	(void)timeout_ms;
	if (q->head == q->tail || q->len[at] > cap)
		return 0;
	memcpy(reply, q->reply[at], q->len[at]);
	*len = q->len[at];
	*msg = q->msg[at];
	q->head++;
	out_now--;
	return 1;
}

/* A clock that moves half a second a reading, so a deadline passes within a
 * test's few calls. */
static uint64_t fake_ms;
static uint64_t fake_clock(void)
{
	return fake_ms += 500u;
}

/* A verb of this node's own user, its reply as a string without the line's
 * end. 0 when nothing was answered. */
static size_t said(fzn_node_files_t *files, fzn_verb_t parsed, const char *arg, char *reply,
                   size_t cap)
{
	size_t n = verb(files, parsed, FZN_ORIGIN_SAME_USER, arg, reply, cap - 1u);

	while (n && (reply[n - 1u] == '\n' || reply[n - 1u] == '\r'))
		n--;
	reply[n] = '\0';
	return n;
}

int main(void)
{
	static const size_t SIZES[] = { 1u, 1024u, 1025u, (70u * 1024u) + 17u, 300u * 1024u };
	static fzn_node_files_t F;
	fzn_node_file_ref_t refs[5], wrong;
	uint8_t roots[8][FZN_BLOB_HASH_LEN];
	char path[256], reply[600], line[400];
	size_t i, count = 0;
	uint64_t length = 0;
	int all = 1;

	(void)snprintf(top, sizeof(top), "/tmp/fzn-files-test-XXXXXX");
	if (!mkdtemp(top)) {
		fprintf(stderr, "  FAIL files_test.c: no scratch directory\n");
		return 1;
	}
	(void)snprintf(dir, sizeof(dir), "%s/files", top);
	(void)snprintf(src_path, sizeof(src_path), "%s/source", top);
	(void)snprintf(out_path, sizeof(out_path), "%s/out", top);
	CHECK(fzn_node_files_init(&F, dir, &HASH, &AEAD, &RNG) == FZN_NODE_FILES_OK,
	      "the store opens");

	/* PUT AND EXPORTED, every size, byte for byte. */
	for (i = 0; i < sizeof(SIZES) / sizeof(SIZES[0]); i++) {
		all = all && make_source(src_path, SIZES[i])
		      && fzn_node_files_put(&F, src_path, &refs[i]) == FZN_NODE_FILES_OK
		      && refs[i].length == SIZES[i]
		      && fzn_node_files_held(&F, refs[i].root, &length) == FZN_NODE_FILES_OK
		      && length == SIZES[i]
		      && fzn_node_files_export(&F, &refs[i], out_path) == FZN_NODE_FILES_OK
		      && same_files(src_path, out_path);
		(void)remove(out_path);
	}
	CHECK(all, "a file of 1 byte to 300 KiB did not come back byte for byte");
	CHECK(entries(dir) == 4u * (sizeof(SIZES) / sizeof(SIZES[0])),
	      "the store does not hold four files a blob and nothing else");
	CHECK(fzn_node_files_list(&F, roots, 8u, &count) == FZN_NODE_FILES_OK && count == 5u
	              && memcmp(roots[0], roots[1], FZN_BLOB_HASH_LEN) < 0
	              && memcmp(roots[3], roots[4], FZN_BLOB_HASH_LEN) < 0,
	      "the list is not every whole blob, in order of root");

	/* UNDER NO OTHER KEY, and not over a file that is there. */
	wrong = refs[3];
	wrong.key[0] ^= 1u;
	CHECK(fzn_node_files_export(&F, &wrong, out_path) == FZN_NODE_FILES_ERR_CRYPTO
	              && access(out_path, F_OK) != 0,
	      "a file opened under another key, or a partial export was left");
	CHECK(make_source(out_path, 3u)
	              && fzn_node_files_export(&F, &refs[3], out_path) == FZN_NODE_FILES_ERR_EXISTS,
	      "an export wrote over a file that was there");
	(void)remove(out_path);

	/* REFUSED TO PUT: an empty file, a missing one. */
	CHECK(make_source(src_path, 0u)
	              && fzn_node_files_put(&F, src_path, &wrong) == FZN_NODE_FILES_ERR_SIZE
	              && fzn_node_files_put(&F, "/nonexistent/x", &wrong) == FZN_NODE_FILES_ERR_ABSENT
	              && entries(dir) == 20u,
	      "an empty or missing file was put, or left something behind");

	/* A LEAF CHANGED ON DISK is not exported as the file. */
	{
		char hex[FZN_BLOB_HASH_LEN * 2u + 1u];
		int fd;
		uint8_t b = 0;

		for (i = 0; i < FZN_BLOB_HASH_LEN; i++)
			(void)snprintf(hex + (2u * i), 3u, "%02x", refs[2].root[i]);
		(void)snprintf(path, sizeof(path), "%s/%s", dir, hex);
		fd = open(path, O_RDWR);
		CHECK(fd >= 0 && pread(fd, &b, 1u, 100) == 1 && (b ^= 0x5au, 1)
		              && pwrite(fd, &b, 1u, 100) == 1 && close(fd) == 0,
		      "fixture: a byte of the first leaf changed");
		CHECK(fzn_node_files_export(&F, &refs[2], out_path) == FZN_NODE_FILES_ERR_CRYPTO
		              && access(out_path, F_OK) != 0,
		      "a leaf changed on disk was exported, or left half");
	}

	/* NOT HELD WITHOUT ITS TREE: a blob whose tree is gone cannot prove
	 * a span, so it is not whole. */
	{
		char hex[FZN_BLOB_HASH_LEN * 2u + 1u], aside[300];

		for (i = 0; i < FZN_BLOB_HASH_LEN; i++)
			(void)snprintf(hex + (2u * i), 3u, "%02x", refs[3].root[i]);
		(void)snprintf(path, sizeof(path), "%s/%s.tree", dir, hex);
		(void)snprintf(aside, sizeof(aside), "%s/aside", top);
		{
			int moved = rename(path, aside) == 0;
			int held_without = fzn_node_files_held(&F, refs[3].root, &length)
			                   != FZN_NODE_FILES_ERR_ABSENT;

			/* BACK WHATEVER WAS SEEN, so a failure here leaves no file
			 * outside the store for the cleanup to trip on. */
			CHECK(moved && !held_without && rename(aside, path) == 0
			              && fzn_node_files_held(&F, refs[3].root, &length)
			                         == FZN_NODE_FILES_OK,
			      "a blob was held with its tree gone, or not when it came back");
			(void)rename(aside, path);
		}
	}

	/* DELETED, every file, and not while a transfer holds it. */
	CHECK(fzn_node_files_busy(&F, refs[4].root, 1) == FZN_NODE_FILES_OK
	              && fzn_node_files_remove(&F, refs[4].root) == FZN_NODE_FILES_ERR_BUSY
	              && fzn_node_files_held(&F, refs[4].root, &length) == FZN_NODE_FILES_OK,
	      "a blob a transfer holds was deleted");
	CHECK(fzn_node_files_busy(&F, refs[4].root, 0) == FZN_NODE_FILES_OK
	              && fzn_node_files_remove(&F, refs[4].root) == FZN_NODE_FILES_OK
	              && fzn_node_files_held(&F, refs[4].root, &length) == FZN_NODE_FILES_ERR_ABSENT
	              && entries(dir) == 16u
	              && fzn_node_files_remove(&F, refs[4].root) == FZN_NODE_FILES_ERR_ABSENT,
	      "a delete left a file of the blob, or deleted it twice");

	/* THE VERBS. */
	CHECK(make_source(src_path, 5000u)
	              && verb(&F, FZN_VERB_PUT, FZN_ORIGIN_LOCAL, "file x", reply, sizeof(reply))
	              && strncmp(reply, "denied", 6) == 0,
	      "a put by another user was taken");
	(void)snprintf(line, sizeof(line), "file %s", src_path);
	CHECK(said(&F, FZN_VERB_PUT, line, reply, sizeof(reply))
	              && strncmp(reply, "ok ", 3) == 0 && strlen(reply) == 3u + 144u,
	      "put file did not answer a reference");
	{
		char ref_hex[145];

		memcpy(ref_hex, reply + 3, 144u);
		ref_hex[144] = '\0';
		(void)snprintf(line, sizeof(line), "file %s %s", ref_hex, out_path);
		CHECK(said(&F, FZN_VERB_GET, line, reply, sizeof(reply))
		              && strncmp(reply, "ok", 2) == 0 && same_files(src_path, out_path),
		      "get file did not export what put file sealed");
		(void)remove(out_path);
		CHECK(said(&F, FZN_VERB_LIST, "file", reply, sizeof(reply))
		              && strncmp(reply, "ok 5 0 ", 7) == 0 && strstr(reply, ",5000") != NULL,
		      "list file did not name the five whole blobs and their lengths");
		ref_hex[64] = '\0';
		(void)snprintf(line, sizeof(line), "file %s", ref_hex);
		CHECK(verb(&F, FZN_VERB_REMOVE, FZN_ORIGIN_SAME_USER, line, reply, sizeof(reply))
		              && strncmp(reply, "ok", 2) == 0 && entries(dir) == 16u,
		      "remove file did not delete it");
	}
	CHECK(verb(&F, FZN_VERB_GET, FZN_ORIGIN_SAME_USER, "file 00", reply, sizeof(reply))
	              && strncmp(reply, "malformed", 9) == 0
	              && verb(&F, FZN_VERB_GET, FZN_ORIGIN_SAME_USER, "text 00", reply, sizeof(reply))
	                         == 0u
	              && verb(&F, FZN_VERB_GET, FZN_ORIGIN_SAME_USER, "files", reply, sizeof(reply))
	                         == 0u,
	      "a malformed reference was not said, or another subject was taken");

	/* ---- CARRIED, sec 491: B fetches what A holds. */
	{
		static fzn_node_files_t B;
		char dir_b[128], b_out[160];
		struct peer a_peer = { &F, 0, 0 };
		uint8_t want_roots[4][FZN_BLOB_HASH_LEN];
		uint64_t want_lengths[4], placed = 0, total = 0;
		fzn_node_file_ref_t big;

		(void)snprintf(dir_b, sizeof(dir_b), "%s/b", top);
		(void)snprintf(b_out, sizeof(b_out), "%s/b_out", top);
		CHECK(make_source(src_path, (300u * 1024u) + 5u)
		              && fzn_node_files_put(&F, src_path, &big) == FZN_NODE_FILES_OK
		              && fzn_node_files_init(&B, dir_b, &HASH, &AEAD, &RNG) == FZN_NODE_FILES_OK,
		      "fixture: A holds a file of 301 leaves, B an empty store");
		CHECK(fzn_node_files_fetch(&B, big.root, peer_ask, &a_peer, 1000u, &placed)
		              == FZN_NODE_FILES_ERR_ABSENT,
		      "a file never wanted was fetched");
		CHECK(fzn_node_files_want(&B, big.root, big.length) == FZN_NODE_FILES_OK
		              && fzn_node_files_wanted(&B, want_roots, want_lengths, 4u) == 1u
		              && memcmp(want_roots[0], big.root, FZN_BLOB_HASH_LEN) == 0
		              && want_lengths[0] == big.length,
		      "the want is not its length on disk");

		/* A PEER CHANGING A LEAF: nothing placed. */
		a_peer.lie = 1;
		CHECK(fzn_node_files_fetch(&B, big.root, peer_ask, &a_peer, 1000u, &placed)
		              == FZN_NODE_FILES_ERR_UNVERIFIED
		              && placed == 0u,
		      "a span changed on the way was placed");
		a_peer.lie = 0;

		/* A BUDGET, THEN THE REST: resumed, not begun again. */
		CHECK(fzn_node_files_fetch(&B, big.root, peer_ask, &a_peer, 50u, &placed)
		              == FZN_NODE_FILES_ERR_ABSENT
		              && placed >= 50u && placed < 301u
		              && fzn_node_files_held(&B, big.root, &length) == FZN_NODE_FILES_ERR_ABSENT,
		      "a fetch past its budget, or a part held as whole");
		total = placed;
		a_peer.asked = 0;
		CHECK(fzn_node_files_fetch(&B, big.root, peer_ask, &a_peer, 1000u, &placed)
		              == FZN_NODE_FILES_OK
		              && total + placed == 301u
		              && fzn_node_files_held(&B, big.root, &length) == FZN_NODE_FILES_OK
		              && length == big.length
		              && fzn_node_files_wanted(&B, NULL, NULL, 0) == 0u,
		      "the rest was not fetched, or what was here was fetched again");
		CHECK(fzn_node_files_export(&B, &big, b_out) == FZN_NODE_FILES_OK
		              && same_files(src_path, b_out),
		      "the fetched file did not export as the one put");
		(void)remove(b_out);

		/* ---- THE SCRUB, sec 492, over B's copy. */
		{
			uint64_t dropped = 9;
			int checked = 0;

			CHECK(fzn_node_files_verify(&B, big.root, &dropped) == FZN_NODE_FILES_OK
			              && dropped == 0u
			              && fzn_node_files_held(&B, big.root, &length) == FZN_NODE_FILES_OK,
			      "an intact file was not found intact");
			/* ONE LEAF CHANGED: exactly it dropped, and fetched back alone. */
			CHECK(flip(dir_b, big.root, "", (5L * 1056L) + 40L)
			              && fzn_node_files_verify(&B, big.root, &dropped) == FZN_NODE_FILES_OK
			              && dropped == 1u
			              && fzn_node_files_held(&B, big.root, &length)
			                         == FZN_NODE_FILES_ERR_ABSENT
			              && fzn_node_files_wanted(&B, NULL, NULL, 0) == 1u,
			      "a changed leaf was not the one leaf dropped, or the file stayed held");
			CHECK(fzn_node_files_fetch(&B, big.root, peer_ask, &a_peer, 1000u, &placed)
			              == FZN_NODE_FILES_OK
			              && placed == 1u
			              && fzn_node_files_export(&B, &big, b_out) == FZN_NODE_FILES_OK
			              && same_files(src_path, b_out),
			      "the dropped leaf was not fetched back alone, or the file did not export");
			(void)remove(b_out);
			/* ONLY THE TREE CHANGED: rebuilt, nothing dropped. */
			CHECK(flip(dir_b, big.root, ".tree", 7L * 32L)
			              && fzn_node_files_verify(&B, big.root, &dropped) == FZN_NODE_FILES_OK
			              && dropped == 0u
			              && fzn_node_files_verify(&B, big.root, &dropped) == FZN_NODE_FILES_OK
			              && dropped == 0u
			              && fzn_node_files_held(&B, big.root, &length) == FZN_NODE_FILES_OK,
			      "a changed tree was not rebuilt from leaves that fold");
			/* REBUILT, NOT ONLY PASSED OVER: a leaf changed now is found by
			 * the tree, which it could not be with a node of it wrong. */
			CHECK(flip(dir_b, big.root, "", (12L * 1056L) + 40L)
			              && fzn_node_files_verify(&B, big.root, &dropped) == FZN_NODE_FILES_OK
			              && dropped == 1u
			              && fzn_node_files_fetch(&B, big.root, peer_ask, &a_peer, 1000u, &placed)
			                         == FZN_NODE_FILES_OK
			              && placed == 1u,
			      "the tree was passed over rather than rebuilt");
			/* A LEAF AND THE TREE: nothing says which is right, so all goes. */
			CHECK(flip(dir_b, big.root, "", (9L * 1056L) + 40L)
			              && flip(dir_b, big.root, ".tree", 3L * 32L)
			              && fzn_node_files_verify(&B, big.root, &dropped) == FZN_NODE_FILES_OK
			              && dropped == 301u
			              && fzn_node_files_fetch(&B, big.root, peer_ask, &a_peer, 1000u, &placed)
			                         == FZN_NODE_FILES_OK
			              && placed == 301u,
			      "with the tree wrong too every leaf was not dropped, or not fetched back");
			/* THE STEP moves on, wrapping. */
			{
				uint8_t first[FZN_BLOB_HASH_LEN];

				CHECK(fzn_node_files_scrub_step(&F, &checked, &dropped) == FZN_NODE_FILES_OK
				              && checked == 1
				              && (memcpy(first, F.scrub_after, sizeof(first)), 1)
				              && fzn_node_files_scrub_step(&F, &checked, &dropped)
				                         == FZN_NODE_FILES_OK
				              && checked == 1
				              && memcmp(first, F.scrub_after, sizeof(first)) != 0,
				      "two scrub steps did not check two files");
			}
		}

		/* ---- SEVERAL PEERS AT ONCE, sec 494. */
		{
			static struct queued good, good2, silent, liar;
			fzn_node_files_peer_t peers[2];
			size_t holders = 0;

			memset(&good, 0, sizeof(good));
			memset(&good2, 0, sizeof(good2));
			good.files = good2.files = &F;
			peers[0].send = queued_send;
			peers[0].poll = queued_poll;
			peers[0].ctx = &good;
			peers[1] = peers[0];
			peers[1].ctx = &good2;
			(void)fzn_node_files_remove(&B, big.root);
			out_now = out_most = 0;
			CHECK(fzn_node_files_want(&B, big.root, big.length) == FZN_NODE_FILES_OK
			              && fzn_node_files_fetch_many(&B, big.root, peers, 2u, fake_clock,
			                                           16u, 1000u, &placed, &holders)
			                         == FZN_NODE_FILES_OK
			              && placed == 301u && holders == 2u && good.wants >= 1u
			              && good2.wants >= 1u && out_most > 1u,
			      "two peers did not both serve spans, or never more than one was out");

			/* ONE SILENT: its spans expire and go to the other. */
			memset(&silent, 0, sizeof(silent));
			memset(&good, 0, sizeof(good));
			silent.files = good.files = &F;
			silent.silent = 1;
			peers[0].ctx = &silent;
			peers[1].ctx = &good;
			(void)fzn_node_files_remove(&B, big.root);
			CHECK(fzn_node_files_want(&B, big.root, big.length) == FZN_NODE_FILES_OK
			              && fzn_node_files_fetch_many(&B, big.root, peers, 2u, fake_clock,
			                                           16u, 1000u, &placed, &holders)
			                         == FZN_NODE_FILES_OK
			              && placed == 301u && silent.wants >= 1u && silent.wants <= 8u,
			      "a silent peer stopped the fetch, or was asked without end");

			/* ONE LYING: its spans refused and asked of the other. */
			memset(&liar, 0, sizeof(liar));
			memset(&good, 0, sizeof(good));
			liar.files = good.files = &F;
			liar.lie = 1;
			peers[0].ctx = &liar;
			(void)fzn_node_files_remove(&B, big.root);
			CHECK(fzn_node_files_want(&B, big.root, big.length) == FZN_NODE_FILES_OK
			              && fzn_node_files_fetch_many(&B, big.root, peers, 2u, fake_clock,
			                                           16u, 1000u, &placed, &holders)
			                         == FZN_NODE_FILES_OK
			              && placed == 301u && liar.wants >= 1u && liar.wants <= 3u
			              && fzn_node_files_export(&B, &big, b_out) == FZN_NODE_FILES_OK
			              && same_files(src_path, b_out),
			      "a lying peer put a leaf down, or the file did not come whole from the other");
			(void)remove(b_out);
		}

		/* B SERVES IT ON, from the tree it built. */
		{
			static fzn_node_files_t C;
			char dir_c[128];
			struct peer b_peer = { &B, 0, 0 };

			(void)snprintf(dir_c, sizeof(dir_c), "%s/c", top);
			CHECK(fzn_node_files_init(&C, dir_c, &HASH, &AEAD, &RNG) == FZN_NODE_FILES_OK
			              && fzn_node_files_want(&C, big.root, big.length) == FZN_NODE_FILES_OK
			              && fzn_node_files_fetch(&C, big.root, peer_ask, &b_peer, 1000u,
			                                      &placed) == FZN_NODE_FILES_OK
			              && placed == 301u,
			      "C did not fetch the file from B, which fetched it");
			(void)fzn_node_files_remove(&C, big.root);
			CHECK(rmdir(dir_c) == 0, "C's directory empties");
		}

		/* A PEER HOLDING NOTHING, and a want taken back. */
		{
			uint8_t nobody[FZN_BLOB_HASH_LEN];

			memset(nobody, 0x77, sizeof(nobody));
			CHECK(fzn_node_files_want(&B, nobody, 5000u) == FZN_NODE_FILES_OK
			              && fzn_node_files_fetch(&B, nobody, peer_ask, &a_peer, 1000u, &placed)
			                         == FZN_NODE_FILES_ERR_NOT_THERE
			              && fzn_node_files_remove(&B, nobody) == FZN_NODE_FILES_OK
			              && fzn_node_files_wanted(&B, NULL, NULL, 0) == 0u,
			      "a peer holding nothing was not said, or the want stayed");
		}
		(void)fzn_node_files_remove(&B, big.root);
		(void)fzn_node_files_remove(&F, big.root);
		CHECK(rmdir(dir_b) == 0, "B's directory empties");
	}

	/* ---- TIERS, sec 493: who besides the members may fetch a file. */
	{
		uint8_t bob[FZN_PUBKEY_LEN], carol[FZN_PUBKEY_LEN], fam[FZN_PUBKEY_LEN];
		uint8_t q[FZN_MSG_WANT_LEN], answer_[FZN_NODE_FILES_REPLY_MAX];
		uint8_t pub_root[FZN_BLOB_HASH_LEN];
		fzn_node_file_ref_t t;
		size_t qlen = 0, n = 0;
		char root_hex[FZN_BLOB_HASH_LEN * 2u + 1u];

		memset(bob, 0xb0, sizeof(bob));
		memset(carol, 0xc4, sizeof(carol));
		F.store = &STORE;
		CHECK(make_source(src_path, 4000u) && fzn_node_files_put(&F, src_path, &t)
		                                              == FZN_NODE_FILES_OK
		              && fzn_contact_add(&STORE, bob, "bob", 3u, 1u) == FZN_CONTACT_OK
		              && fzn_contact_add(&STORE, carol, "carol", 5u, 1u) == FZN_CONTACT_OK
		              && fzn_group_add(&STORE, &HASH, "fam", 3u, 1u) == FZN_CONTACT_OK
		              && fzn_group_join(&STORE, &HASH, "fam", 3u, carol) == FZN_CONTACT_OK
		              && fzn_group_id(&HASH, "fam", 3u, fam) == FZN_CONTACT_OK
		              && fzn_msg_have_query_encode(t.root, q, sizeof(q), &qlen) == FZN_MSG_OK,
		      "fixture: a file, bob, carol in the group fam, and a question for the file");
		for (i = 0; i < FZN_BLOB_HASH_LEN; i++)
			(void)snprintf(root_hex + (2u * i), 3u, "%02x", t.root[i]);

		CHECK(!fzn_node_files_shared_with(&F, t.root, bob)
		              && fzn_node_files_answer_shared(&F, bob, q, qlen, answer_, sizeof(answer_))
		                         == 0u
		              && fzn_node_files_answer(&F, q, qlen, answer_, sizeof(answer_)) > 0u,
		      "a private file was served to a contact, or not to a member");
		(void)snprintf(line, sizeof(line), "file %s public", root_hex);
		CHECK(said(&F, FZN_VERB_SET, line, reply, sizeof(reply)) && strcmp(reply, "ok") == 0
		              && fzn_node_files_shared_with(&F, t.root, bob)
		              && fzn_node_files_shared_with(&F, t.root, carol)
		              && fzn_node_files_answer_shared(&F, bob, q, qlen, answer_, sizeof(answer_))
		                         > 0u,
		      "a public file was not served to every contact");
		(void)snprintf(line, sizeof(line), "file %s private", root_hex);
		CHECK(said(&F, FZN_VERB_SET, line, reply, sizeof(reply)) && strcmp(reply, "ok") == 0
		              && !fzn_node_files_shared_with(&F, t.root, bob)
		              && said(&F, FZN_VERB_SET, line, reply, sizeof(reply))
		              && strcmp(reply, "ok") == 0,
		      "made private, the file was still served, or private twice refused");
		(void)snprintf(line, sizeof(line), "file %s bob", root_hex);
		CHECK(said(&F, FZN_VERB_GRANT, line, reply, sizeof(reply)) && strcmp(reply, "ok") == 0
		              && fzn_node_files_shared_with(&F, t.root, bob)
		              && !fzn_node_files_shared_with(&F, t.root, carol)
		              && said(&F, FZN_VERB_LIST, "file", reply, sizeof(reply))
		              && strstr(reply, ",4000,shared") != NULL,
		      "shared with bob, it was not bob's alone, or not listed as shared");
		(void)snprintf(line, sizeof(line), "file %s @fam", root_hex);
		CHECK(said(&F, FZN_VERB_GRANT, line, reply, sizeof(reply)) && strcmp(reply, "ok") == 0
		              && fzn_node_files_shared_with(&F, t.root, carol)
		              && fzn_node_files_shares_of(&F, t.root, NULL, 0, &n) == FZN_NODE_FILES_OK
		              && n == 2u,
		      "shared with the group, carol in it could not fetch it");
		CHECK(fzn_node_files_forget(&F, fam, &n) == FZN_NODE_FILES_OK && n == 1u
		              && !fzn_node_files_shared_with(&F, t.root, carol)
		              && fzn_node_files_shared_with(&F, t.root, bob),
		      "a group forgotten still reached its member, or took bob's share with it");
		(void)snprintf(line, sizeof(line), "file %s bob", root_hex);
		CHECK(said(&F, FZN_VERB_REVOKE, line, reply, sizeof(reply)) && strcmp(reply, "ok") == 0
		              && !fzn_node_files_shared_with(&F, t.root, bob)
		              && said(&F, FZN_VERB_REVOKE, line, reply, sizeof(reply))
		              && strncmp(reply, "error", 5) == 0,
		      "revoked, bob still fetched it, or revoking twice was not said");
		(void)snprintf(line, sizeof(line), "file %s dave", root_hex);
		CHECK(said(&F, FZN_VERB_GRANT, line, reply, sizeof(reply))
		              && strncmp(reply, "error", 5) == 0,
		      "a file was shared with a name that is no contact");
		/* PUT PUBLIC, and deleting a file deletes its rows. */
		(void)snprintf(line, sizeof(line), "file %s public", src_path);
		CHECK(said(&F, FZN_VERB_PUT, line, reply, sizeof(reply)) && strncmp(reply, "ok ", 3) == 0
		              && hex_root(reply + 3, pub_root)
		              && said(&F, FZN_VERB_LIST, "file", reply, sizeof(reply))
		              && strstr(reply, ",public") != NULL && rows(FZN_PERSIST_FILE_SHARE) == 1u,
		      "put public did not make the file public");
		(void)snprintf(line, sizeof(line), "file %s bob", root_hex);
		CHECK(said(&F, FZN_VERB_GRANT, line, reply, sizeof(reply))
		              && rows(FZN_PERSIST_FILE_SHARE) == 2u
		              && fzn_node_files_remove(&F, t.root) == FZN_NODE_FILES_OK
		              && rows(FZN_PERSIST_FILE_SHARE) == 1u,
		      "a file deleted left its share rows");
		/* A ROW FILED UNDER ANOTHER KEY reaches nobody. */
		{
			size_t k, before = 0;


			CHECK(fzn_node_files_shares_of(&F, pub_root, NULL, 0, &before) == FZN_NODE_FILES_OK
			              && before == 1u,
			      "fixture: the public file's one row");
			for (k = 0; k < sizeof(mem) / sizeof(mem[0]); k++)
				if (mem[k].used && mem[k].slot == FZN_PERSIST_FILE_SHARE)
					mem[k].subject[0] ^= 1u;
			CHECK(fzn_node_files_shares_of(&F, pub_root, NULL, 0, &n) == FZN_NODE_FILES_OK
			              && n == 0u,
			      "a row copied under another key was read as a share");
		}
		F.store = NULL;
		for (i = 0; i < sizeof(mem) / sizeof(mem[0]); i++)
			mem[i].used = 0;
		count = 0;
		if (fzn_node_files_list(&F, roots, 8u, &count) == FZN_NODE_FILES_OK)
			for (i = 0; i < count && i < 8u; i++)
				if (memcmp(roots[i], refs[0].root, FZN_BLOB_HASH_LEN)
				    && memcmp(roots[i], refs[1].root, FZN_BLOB_HASH_LEN)
				    && memcmp(roots[i], refs[2].root, FZN_BLOB_HASH_LEN)
				    && memcmp(roots[i], refs[3].root, FZN_BLOB_HASH_LEN))
					(void)fzn_node_files_remove(&F, roots[i]);
	}

	/* REMOVED BY NAME, and what is left is an assertion. */
	for (i = 0; i < 4u; i++)
		(void)fzn_node_files_remove(&F, refs[i].root);
	(void)remove(src_path);
	CHECK(entries(dir) == 0u && rmdir(dir) == 0 && rmdir(top) == 0,
	      "the scratch directories empty, and go");
	if (failures) {
		fprintf(stderr, "files_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("files_test: all %d checks passed\n", checks);
	return 0;
}
