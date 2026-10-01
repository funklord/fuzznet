/* shelf_test -- the node's shelf of long notes' texts: sealed onto it, served
 * from it, and fetched from one shelf by another through the four messages of
 * `spool/message.h`. sec 424.
 *
 * TWO SHELVES IN ONE PROCESS, and the "peer" is a function: `ask` hands the
 * request to the other shelf's `fzn_node_shelf_answer` and returns what it
 * wrote. That is the whole of the remote hop as far as the shelf can tell,
 * and it is what lets a test lie, go quiet, or shrink the reply on purpose.
 *
 * The hash and the AEAD are blob_test's stubs, copied as text_test copies
 * them: what is under test is which leaves travel and what is believed. */

#define _POSIX_C_SOURCE 200809L

#include "../shelf.h"

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
	fprintf(stderr, "  FAIL shelf_test.c:%d: %s\n", line, what);
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

/* ---- the peer ---------------------------------------------------------- */

typedef struct peer {
	const fzn_node_shelf_t *shelf;
	/* The reply the peer may write, below the fetcher's own. */
	size_t cap;
	/* Requests seen, and WANTs among them. */
	unsigned asked;
	unsigned wants;
	/* Go quiet after this many requests; 0 never. */
	unsigned quiet_after;
	/* Flip a byte in the first leaf of the DATA answering WANT number
	 * `lie_on` (from 1); 0 never. */
	unsigned lie_on;
} peer_t;

static int ask(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
               size_t reply_cap, size_t *reply_len)
{
	peer_t *p = (peer_t *)ctx;
	fzn_msg_type_t type;
	size_t cap = p->cap && p->cap < reply_cap ? p->cap : reply_cap;

	p->asked++;
	if (p->quiet_after && p->asked > p->quiet_after)
		return 0;
	if (fzn_msg_peek(request, request_len, &type) == FZN_MSG_OK && type == FZN_MSG_WANT)
		p->wants++;
	*reply_len = fzn_node_shelf_answer(p->shelf, request, request_len, reply, cap);
	if (p->lie_on && type == FZN_MSG_WANT && p->wants == p->lie_on && *reply_len > 0u)
		reply[*reply_len - 1u] ^= 0x40u;
	return *reply_len > 0u;
}

/* ---- scratch, named and removed by name ------------------------------- */

static char top[64], dir_a[96], dir_b[96], dir_c[96];

/* Every root a case puts or fetches, so cleanup removes files it can name. */
static uint8_t roots[16][FZN_BLOB_HASH_LEN];
static size_t root_count;

static void remember(const uint8_t root[FZN_BLOB_HASH_LEN])
{
	if (root_count < 16u)
		memcpy(roots[root_count++], root, FZN_BLOB_HASH_LEN);
}

static void file_of(const char *dir, const uint8_t root[FZN_BLOB_HASH_LEN], const char *suffix,
                    char *out, size_t cap)
{
	char hex[FZN_BLOB_HASH_LEN * 2u + 1u];
	size_t i;

	for (i = 0; i < FZN_BLOB_HASH_LEN; i++)
		(void)snprintf(hex + (i * 2u), 3u, "%02x", root[i]);
	(void)snprintf(out, cap, "%s/%s%s", dir, hex, suffix);
}

static int exists(const char *path)
{
	struct stat st;

	return stat(path, &st) == 0;
}

/* The text: every byte a function of its position, so a misplaced leaf shows. */
static uint8_t text_a[FZN_NOTE_TEXT_MAX], text_b[FZN_NOTE_TEXT_MAX];
static uint8_t out[FZN_NOTE_TEXT_MAX];

static void fill(uint8_t *text, size_t len, unsigned salt)
{
	size_t i;

	for (i = 0; i < len; i++)
		text[i] = (uint8_t)('a' + ((i * 7u + salt) % 26u));
}

static fzn_node_shelf_t A, B, C;

static int same_bytes(const char *x, const char *y)
{
	static uint8_t bx[FZN_NOTE_TEXT_LEAVES_MAX * FZN_BLOB_SEALED_MAX];
	static uint8_t by[sizeof(bx)];
	FILE *fx = fopen(x, "rb"), *fy = fopen(y, "rb");
	size_t nx = 0, ny = 0;

	if (fx) {
		nx = fread(bx, 1u, sizeof(bx), fx);
		(void)fclose(fx);
	}
	if (fy) {
		ny = fread(by, 1u, sizeof(by), fy);
		(void)fclose(fy);
	}
	return fx && fy && nx == ny && nx > 0u && memcmp(bx, by, nx) == 0;
}

/* ---- cases -------------------------------------------------------------- */

static fzn_note_blob_ref_t small, big;

static void test_a_put_text_is_held_and_opens(void)
{
	uint64_t length = 0;
	size_t len = 0;
	fzn_note_err_t terr;
	char path[600];

	fill(text_a, 3000u, 1u);
	CHECK(fzn_node_shelf_put(&A, text_a, 3000u, &small) == FZN_NODE_SHELF_OK,
	      "a 3000-byte text is put");
	remember(small.root);
	CHECK(small.length == 3000u, "the reference states the length");
	CHECK(fzn_node_shelf_held(&A, small.root, &length) == FZN_NODE_SHELF_OK && length == 3000u,
	      "the putting shelf holds it, at its length");
	CHECK(fzn_node_shelf_open(&A, &small, out, sizeof(out), &len, &terr) == FZN_NODE_SHELF_OK
	              && len == 3000u && memcmp(out, text_a, 3000u) == 0,
	      "and it opens back to the text");
	(void)snprintf(path, sizeof(path), "%s/put", dir_a);
	CHECK(!exists(path), "nothing is left under the working name");
	CHECK(fzn_node_shelf_held(&B, small.root, &length) == FZN_NODE_SHELF_ERR_ABSENT,
	      "another shelf does not hold it");
}

static void test_a_fetch_brings_the_text_across(void)
{
	peer_t p = { &A, 0, 0, 0, 0, 0 };
	char pa[600], pb[600];
	uint64_t length = 0;
	size_t len = 0;
	fzn_note_err_t terr;

	CHECK(fzn_node_shelf_fetch(&B, small.root, small.length, ask, &p) == FZN_NODE_SHELF_OK,
	      "B fetches the text from A");
	CHECK(fzn_node_shelf_held(&B, small.root, &length) == FZN_NODE_SHELF_OK && length == 3000u,
	      "B holds all of it, at its length");
	CHECK(fzn_node_shelf_open(&B, &small, out, sizeof(out), &len, &terr) == FZN_NODE_SHELF_OK
	              && len == 3000u && memcmp(out, text_a, 3000u) == 0,
	      "and B opens it to A's text");
	file_of(dir_a, small.root, "", pa, sizeof(pa));
	file_of(dir_b, small.root, "", pb, sizeof(pb));
	CHECK(same_bytes(pa, pb), "B's sealed leaves are A's, byte for byte");
	CHECK(p.wants == 1u, "three leaves are one span: one WANT");
	p.asked = 0;
	CHECK(fzn_node_shelf_fetch(&B, small.root, small.length, ask, &p) == FZN_NODE_SHELF_OK
	              && p.asked == 0u,
	      "a text already here costs no question");
}

static void test_a_long_text_travels_in_spans(void)
{
	/* FORTY LEAVES, so more than one span of FZN_NODE_SHELF_SPAN. */
	const size_t len_big = (40u * FZN_BLOB_LEAF_SIZE) - 100u;
	peer_t p = { &A, 0, 0, 0, 0, 0 };
	size_t len = 0;
	fzn_note_err_t terr;

	fill(text_b, len_big, 5u);
	CHECK(fzn_node_shelf_put(&A, text_b, len_big, &big) == FZN_NODE_SHELF_OK,
	      "a forty-leaf text is put");
	remember(big.root);
	CHECK(fzn_node_shelf_fetch(&B, big.root, big.length, ask, &p) == FZN_NODE_SHELF_OK,
	      "and fetched");
	CHECK(p.wants >= 3u, "in more than two spans");
	CHECK(fzn_node_shelf_open(&B, &big, out, sizeof(out), &len, &terr) == FZN_NODE_SHELF_OK
	              && len == len_big && memcmp(out, text_b, len_big) == 0,
	      "and it opens whole");
}

static void test_a_small_reply_gets_a_smaller_span(void)
{
	/* ROOM FOR TWO LEAVES AND A PROOF, NOT SIXTEEN: the server halves the
	 * span until its DATA fits, rather than answering nothing. */
	peer_t p = { &A, 2u * (FZN_BLOB_SEALED_MAX + 4u) + 400u, 0, 0, 0, 0 };

	CHECK(fzn_node_shelf_fetch(&C, big.root, big.length, ask, &p) == FZN_NODE_SHELF_OK,
	      "C fetches the long text through a small reply");
	CHECK(p.wants >= 20u, "two leaves a span at most: twenty WANTs or more");
}

static void test_nothing_is_created_for_a_named_root(void)
{
	uint8_t nobody[FZN_BLOB_HASH_LEN];
	peer_t p = { &A, 0, 0, 0, 0, 0 };
	char path[600];

	memset(nobody, 0x5a, sizeof(nobody));
	file_of(dir_b, nobody, ".len", path, sizeof(path));
	CHECK(fzn_node_shelf_fetch(&B, nobody, 3000u, ask, &p) == FZN_NODE_SHELF_ERR_ABSENT,
	      "a root the peer does not hold is absent");
	file_of(dir_a, nobody, "", path, sizeof(path));
	CHECK(!exists(path), "and the peer created no file for it");
	file_of(dir_a, nobody, ".bits", path, sizeof(path));
	CHECK(!exists(path), "nor a sidecar");
	remember(nobody);
}

static void test_a_lying_peer_writes_nothing_and_the_fetch_resumes(void)
{
	peer_t liar = { &A, 0, 0, 0, 0, 2u };
	peer_t honest = { &A, 0, 0, 0, 0, 0 };
	fzn_node_shelf_t D;
	char dir_d[96], path[600];
	size_t len = 0;
	fzn_note_err_t terr;
	uint64_t length = 0;

	(void)snprintf(dir_d, sizeof(dir_d), "%s/d", top);
	CHECK(fzn_node_shelf_init(&D, dir_d, &HASH, &AEAD, &RNG) == FZN_NODE_SHELF_OK, "D opens");
	CHECK(fzn_node_shelf_fetch(&D, big.root, big.length, ask, &liar)
	              == FZN_NODE_SHELF_ERR_UNVERIFIED,
	      "a leaf flipped in transit does not prove");
	CHECK(fzn_node_shelf_held(&D, big.root, &length) == FZN_NODE_SHELF_ERR_ABSENT,
	      "and D does not hold the text");
	CHECK(fzn_node_shelf_fetch(&D, big.root, big.length, ask, &honest) == FZN_NODE_SHELF_OK,
	      "an honest peer completes it");
	CHECK(honest.wants == 2u, "the first span was kept; only the rest is asked for");
	CHECK(fzn_node_shelf_open(&D, &big, out, sizeof(out), &len, &terr) == FZN_NODE_SHELF_OK
	              && memcmp(out, text_b, big.length) == 0,
	      "and it opens whole");
	file_of(dir_d, big.root, "", path, sizeof(path));
	(void)remove(path);
	file_of(dir_d, big.root, ".bits", path, sizeof(path));
	(void)remove(path);
	file_of(dir_d, big.root, ".len", path, sizeof(path));
	(void)remove(path);
	CHECK(rmdir(dir_d) == 0, "D's directory empties");
}

static void test_a_peer_going_quiet_is_resumed(void)
{
	peer_t quiet = { &A, 0, 0, 0, 2u, 0 };
	peer_t honest = { &A, 0, 0, 0, 0, 0 };
	fzn_node_shelf_t E;
	char dir_e[96], path[600];

	(void)snprintf(dir_e, sizeof(dir_e), "%s/e", top);
	CHECK(fzn_node_shelf_init(&E, dir_e, &HASH, &AEAD, &RNG) == FZN_NODE_SHELF_OK, "E opens");
	CHECK(fzn_node_shelf_fetch(&E, big.root, big.length, ask, &quiet)
	              == FZN_NODE_SHELF_ERR_NO_ANSWER,
	      "a peer that stops answering is no answer");
	CHECK(quiet.wants == 1u, "after one span");
	CHECK(fzn_node_shelf_fetch(&E, big.root, big.length, ask, &honest) == FZN_NODE_SHELF_OK
	              && honest.wants == 2u,
	      "and the next fetch asks only for the two spans not here");
	file_of(dir_e, big.root, "", path, sizeof(path));
	(void)remove(path);
	file_of(dir_e, big.root, ".bits", path, sizeof(path));
	(void)remove(path);
	file_of(dir_e, big.root, ".len", path, sizeof(path));
	(void)remove(path);
	CHECK(rmdir(dir_e) == 0, "E's directory empties");
}

static void test_a_wrong_length_does_not_prove(void)
{
	peer_t p = { &A, 0, 0, 0, 0, 0 };
	fzn_node_shelf_t F;
	char dir_f[96], path[600];
	uint64_t length = 0;

	(void)snprintf(dir_f, sizeof(dir_f), "%s/f", top);
	CHECK(fzn_node_shelf_init(&F, dir_f, &HASH, &AEAD, &RNG) == FZN_NODE_SHELF_OK, "F opens");
	/* THE SAME LEAF COUNT, so only the last leaf's length differs. */
	CHECK(fzn_node_shelf_fetch(&F, small.root, small.length + 1u, ask, &p)
	              == FZN_NODE_SHELF_ERR_UNVERIFIED,
	      "a length one past the text's does not prove");
	CHECK(fzn_node_shelf_held(&F, small.root, &length) == FZN_NODE_SHELF_ERR_ABSENT,
	      "and the text is not held at it");
	CHECK(fzn_node_shelf_fetch(&F, small.root, small.length, ask, &p) == FZN_NODE_SHELF_OK
	              && fzn_node_shelf_held(&F, small.root, &length) == FZN_NODE_SHELF_OK
	              && length == small.length,
	      "the note's own length then fetches it, and is what is written down");
	CHECK(fzn_node_shelf_fetch(&F, small.root, small.length - 1u, ask, &p)
	              == FZN_NODE_SHELF_ERR_MALFORMED,
	      "and a whole text here refuses another length for its root");
	/* A LAST LEAF HERE AND A HOLE BEFORE IT: leaf 0 forgotten in the
	 * sidecar, so the text is not whole and only the last leaf's own
	 * proof stands for the length. Another length for the same leaf
	 * count must not be written down over it. */
	{
		FILE *bits;
		uint8_t byte = 0;

		file_of(dir_f, small.root, ".bits", path, sizeof(path));
		bits = fopen(path, "r+b");
		CHECK(bits && fseek(bits, 1L + FZN_BLOB_HASH_LEN + 8L, SEEK_SET) == 0
		              && fread(&byte, 1u, 1u, bits) == 1u,
		      "fixture: F's sidecar reads");
		byte &= (uint8_t)~1u;
		CHECK(bits && fseek(bits, 1L + FZN_BLOB_HASH_LEN + 8L, SEEK_SET) == 0
		              && fwrite(&byte, 1u, 1u, bits) == 1u,
		      "fixture: leaf 0 is forgotten");
		if (bits)
			(void)fclose(bits);
		CHECK(fzn_node_shelf_held(&F, small.root, &length) == FZN_NODE_SHELF_ERR_ABSENT,
		      "fixture: F no longer holds all of it");
		CHECK(fzn_node_shelf_fetch(&F, small.root, small.length - 1u, ask, &p)
		              == FZN_NODE_SHELF_ERR_MALFORMED,
		      "a last leaf here refuses another length for its root");
		CHECK(fzn_node_shelf_fetch(&F, small.root, small.length, ask, &p)
		              == FZN_NODE_SHELF_OK
		              && fzn_node_shelf_held(&F, small.root, &length) == FZN_NODE_SHELF_OK
		              && length == small.length,
		      "and its own length completes it");
	}
	file_of(dir_f, small.root, "", path, sizeof(path));
	(void)remove(path);
	file_of(dir_f, small.root, ".bits", path, sizeof(path));
	(void)remove(path);
	file_of(dir_f, small.root, ".len", path, sizeof(path));
	(void)remove(path);
	CHECK(rmdir(dir_f) == 0, "F's directory empties");
}

static void test_a_partial_holder_serves_nothing(void)
{
	peer_t quiet = { &A, 0, 0, 0, 2u, 0 };
	peer_t from_g = { NULL, 0, 0, 0, 0, 0 };
	fzn_node_shelf_t G, H;
	char dir_g[96], dir_h[96], path[600];

	(void)snprintf(dir_g, sizeof(dir_g), "%s/g", top);
	(void)snprintf(dir_h, sizeof(dir_h), "%s/h", top);
	CHECK(fzn_node_shelf_init(&G, dir_g, &HASH, &AEAD, &RNG) == FZN_NODE_SHELF_OK
	              && fzn_node_shelf_init(&H, dir_h, &HASH, &AEAD, &RNG) == FZN_NODE_SHELF_OK,
	      "G and H open");
	(void)fzn_node_shelf_fetch(&G, big.root, big.length, ask, &quiet);
	from_g.shelf = &G;
	/* A PROOF NEEDS THE HASHES OF LEAVES G DOES NOT HAVE. */
	CHECK(fzn_node_shelf_fetch(&H, big.root, big.length, ask, &from_g)
	              == FZN_NODE_SHELF_ERR_ABSENT,
	      "a shelf part way through a fetch answers as if it held nothing");
	CHECK(from_g.wants == 0u, "and is never asked for a span");
	file_of(dir_g, big.root, "", path, sizeof(path));
	(void)remove(path);
	file_of(dir_g, big.root, ".bits", path, sizeof(path));
	(void)remove(path);
	file_of(dir_g, big.root, ".len", path, sizeof(path));
	(void)remove(path);
	file_of(dir_h, big.root, "", path, sizeof(path));
	(void)remove(path);
	file_of(dir_h, big.root, ".bits", path, sizeof(path));
	(void)remove(path);
	file_of(dir_h, big.root, ".len", path, sizeof(path));
	(void)remove(path);
	CHECK(rmdir(dir_g) == 0 && rmdir(dir_h) == 0, "G's and H's directories empty");
}

static void test_the_answer_falls_through_for_what_is_not_a_question(void)
{
	static const uint8_t verb[] = "get vote 0";
	uint8_t reply[FZN_NODE_SHELF_REPLY_MAX], have[FZN_MSG_HAVE_LEN(1)];
	uint8_t cookie[FZN_MSG_COOKIE_LEN] = { 0 };
	fzn_spool_range_t r = { 0, 3 };
	size_t len = 0;

	CHECK(fzn_node_shelf_answer(&A, verb, sizeof(verb) - 1u, reply, sizeof(reply)) == 0u,
	      "a verb is not the shelf's: it falls through");
	CHECK(fzn_msg_have_encode(small.root, 3u, cookie, &r, 1u, have, sizeof(have), &len)
	              == FZN_MSG_OK
	              && fzn_node_shelf_answer(&A, have, len, reply, sizeof(reply)) == 0u,
	      "a HAVE is an answer, not a question");
}

static void test_wants_are_remembered_until_fetched(void)
{
	peer_t p = { &A, 0, 0, 0, 0, 0 };
	fzn_node_shelf_t W;
	char dir_w[96], path[600];
	size_t i, live = 0;

	(void)snprintf(dir_w, sizeof(dir_w), "%s/w", top);
	CHECK(fzn_node_shelf_init(&W, dir_w, &HASH, &AEAD, &RNG) == FZN_NODE_SHELF_OK, "W opens");
	CHECK(fzn_node_shelf_want(&W, small.root, small.length) == FZN_NODE_SHELF_OK
	              && fzn_node_shelf_want(&W, small.root, small.length) == FZN_NODE_SHELF_OK,
	      "a text is wanted, twice");
	for (i = 0; i < FZN_NODE_SHELF_WANTS; i++)
		live += W.wants[i].live ? 1u : 0u;
	CHECK(live == 1u, "and remembered once");
	CHECK(W.fresh, "and the shelf says a want is new");
	CHECK(fzn_node_shelf_fetch_wants(&W, ask, &p) == 1u, "one want completes");
	CHECK(fzn_node_shelf_fetch_wants(&W, ask, &p) == 0u, "and is forgotten");
	CHECK(fzn_node_shelf_want(&W, small.root, small.length) == FZN_NODE_SHELF_OK
	              && !W.wants[0].live,
	      "a text already here is not remembered");
	CHECK(fzn_node_shelf_want(&W, small.root, 0u) == FZN_NODE_SHELF_ERR_MALFORMED,
	      "nor is a length of zero");
	file_of(dir_w, small.root, "", path, sizeof(path));
	(void)remove(path);
	file_of(dir_w, small.root, ".bits", path, sizeof(path));
	(void)remove(path);
	file_of(dir_w, small.root, ".len", path, sizeof(path));
	(void)remove(path);
	CHECK(rmdir(dir_w) == 0, "W's directory empties");
}

/* ---- the verbs ---------------------------------------------------------- */

static size_t verb(fzn_node_shelf_t *shelf, fzn_verb_t parsed, fzn_origin_t origin,
                   const char *arg, char *reply, size_t cap)
{
	fzn_request_t r;

	memset(&r, 0, sizeof(r));
	r.parsed = parsed;
	r.arg = (const uint8_t *)arg;
	r.arg_len = strlen(arg);
	return fzn_node_shelf_local(shelf, origin, &r, reply, cap);
}

/* A reply line, without the terminator the split does not take. */
static size_t line_of(const char *reply, size_t len)
{
	return len > 0u && reply[len - 1u] == '\n' ? len - 1u : len;
}

static int says(const char *reply, size_t len, fzn_reply_t kind, const char *detail)
{
	const uint8_t *d = NULL;
	size_t d_len = 0;

	len = line_of(reply, len);
	if (fzn_reply_of((const uint8_t *)reply, len, &d, &d_len) != kind)
		return 0;
	if (!detail)
		return 1;
	return d_len >= strlen(detail) && memcmp(d, detail, strlen(detail)) == 0;
}

static void test_the_verbs(void)
{
	char reply[FZN_REPLY_MAX + 1u], arg[700], file[600];
	const uint8_t *d = NULL;
	size_t len, d_len = 0;
	fzn_note_blob_ref_t ref;
	FILE *f;

	(void)snprintf(file, sizeof(file), "%s/in.txt", top);
	f = fopen(file, "wb");
	CHECK(f && fwrite(text_a, 1u, 2500u, f) == 2500u, "an input file is written");
	if (f)
		(void)fclose(f);

	(void)snprintf(arg, sizeof(arg), "text %s", file);
	len = verb(&A, FZN_VERB_PUT, FZN_ORIGIN_SAME_USER, arg, reply, sizeof(reply));
	CHECK(fzn_reply_of((const uint8_t *)reply, line_of(reply, len), &d, &d_len) == FZN_REPLY_OK
	              && d_len == FZN_NOTE_BLOB_REF_LEN * 2u,
	      "put text answers a reference, in hex");
	memset(&ref, 0, sizeof(ref));
	if (d_len == FZN_NOTE_BLOB_REF_LEN * 2u) {
		size_t i;

		for (i = 0; i < FZN_BLOB_HASH_LEN; i++) {
			unsigned v = 0;

			(void)sscanf((const char *)d + (i * 2u), "%2x", &v);
			ref.root[i] = (uint8_t)v;
		}
		remember(ref.root);
		(void)snprintf(arg, sizeof(arg), "text %.*s", (int)d_len, (const char *)d);
	}
	len = verb(&A, FZN_VERB_GET, FZN_ORIGIN_SAME_USER, arg, reply, sizeof(reply));
	CHECK(says(reply, len, FZN_REPLY_OK, "here 2500"), "get text opens it, at its length");
	len = verb(&B, FZN_VERB_GET, FZN_ORIGIN_SAME_USER, arg, reply, sizeof(reply));
	CHECK(says(reply, len, FZN_REPLY_OK, "pending"), "on a shelf without it, pending");
	len = verb(&B, FZN_VERB_FETCH, FZN_ORIGIN_SAME_USER, arg, reply, sizeof(reply));
	CHECK(says(reply, len, FZN_REPLY_OK, NULL), "fetch text is taken");
	{
		peer_t p = { &A, 0, 0, 0, 0, 0 };

		CHECK(fzn_node_shelf_fetch_wants(&B, ask, &p) == 1u, "and fetched on the next round");
	}
	len = verb(&B, FZN_VERB_GET, FZN_ORIGIN_SAME_USER, arg, reply, sizeof(reply));
	CHECK(says(reply, len, FZN_REPLY_OK, "here 2500"), "after which B opens it");

	len = verb(&A, FZN_VERB_GET, FZN_ORIGIN_LOCAL, arg, reply, sizeof(reply));
	CHECK(says(reply, len, FZN_REPLY_DENIED, NULL), "another user is denied");
	len = verb(&A, FZN_VERB_GET, FZN_ORIGIN_SAME_USER, "text 00", reply, sizeof(reply));
	CHECK(says(reply, len, FZN_REPLY_MALFORMED, NULL), "a short reference is malformed");
	(void)snprintf(arg, sizeof(arg), "text %s/none", top);
	len = verb(&A, FZN_VERB_PUT, FZN_ORIGIN_SAME_USER, arg, reply, sizeof(reply));
	CHECK(says(reply, len, FZN_REPLY_ERROR, NULL), "a file that is not there is an error");
	CHECK(verb(&A, FZN_VERB_GET, FZN_ORIGIN_SAME_USER, "vote 0", reply, sizeof(reply)) == 0u,
	      "get vote is not the shelf's");
	CHECK(verb(&A, FZN_VERB_LIST, FZN_ORIGIN_SAME_USER, "text x", reply, sizeof(reply)) == 0u,
	      "nor list text");
	CHECK(remove(file) == 0, "the input file is removed");
}

/* ---- main ---------------------------------------------------------------- */

static void clean(const char *dir)
{
	static const char *const SUFFIX[] = { "", ".bits", ".len", ".len.new" };
	char path[600];
	size_t i, s;

	for (i = 0; i < root_count; i++)
		for (s = 0; s < sizeof(SUFFIX) / sizeof(SUFFIX[0]); s++) {
			file_of(dir, roots[i], SUFFIX[s], path, sizeof(path));
			(void)remove(path);
		}
}

int main(void)
{
	(void)snprintf(top, sizeof(top), "/tmp/fzn-shelf-test-XXXXXX");
	if (!mkdtemp(top)) {
		fprintf(stderr, "  FAIL shelf_test.c: no scratch directory\n");
		return 1;
	}
	(void)snprintf(dir_a, sizeof(dir_a), "%s/a", top);
	(void)snprintf(dir_b, sizeof(dir_b), "%s/b", top);
	(void)snprintf(dir_c, sizeof(dir_c), "%s/c", top);
	CHECK(fzn_node_shelf_init(&A, dir_a, &HASH, &AEAD, &RNG) == FZN_NODE_SHELF_OK
	              && fzn_node_shelf_init(&B, dir_b, &HASH, &AEAD, &RNG) == FZN_NODE_SHELF_OK
	              && fzn_node_shelf_init(&C, dir_c, &HASH, &AEAD, &RNG) == FZN_NODE_SHELF_OK,
	      "three shelves open");
	CHECK(fzn_node_shelf_init(&A, "", &HASH, &AEAD, &RNG) == FZN_NODE_SHELF_ERR_MALFORMED,
	      "an empty directory name is refused");
	(void)fzn_node_shelf_init(&A, dir_a, &HASH, &AEAD, &RNG);

	test_a_put_text_is_held_and_opens();
	test_a_fetch_brings_the_text_across();
	test_a_long_text_travels_in_spans();
	test_a_small_reply_gets_a_smaller_span();
	test_nothing_is_created_for_a_named_root();
	test_a_lying_peer_writes_nothing_and_the_fetch_resumes();
	test_a_peer_going_quiet_is_resumed();
	test_a_wrong_length_does_not_prove();
	test_a_partial_holder_serves_nothing();
	test_the_answer_falls_through_for_what_is_not_a_question();
	test_wants_are_remembered_until_fetched();
	test_the_verbs();

	/* REMOVED BY NAME, AND WHAT IS LEFT IS AN ASSERTION. */
	clean(dir_a);
	clean(dir_b);
	clean(dir_c);
	CHECK(rmdir(dir_a) == 0 && rmdir(dir_b) == 0 && rmdir(dir_c) == 0 && rmdir(top) == 0,
	      "the scratch directories empty, and go");

	if (failures) {
		fprintf(stderr, "shelf_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("shelf_test: all %d checks passed\n", checks);
	return 0;
}
