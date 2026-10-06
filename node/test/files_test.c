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
