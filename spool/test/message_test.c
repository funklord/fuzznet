/* Tests for spool/message.c.
 *
 * THE ROUND TRIPS ARE THE CHEAP HALF. What this file exists for is the two
 * claims message.h makes about the rest of `spool/` -- that a plan encodes
 * without modification, and that a parsed DATA hands straight to a store --
 * because those are sentences about interoperation that nothing else checks,
 * and a header claim no test holds is wrong the moment somebody edits either
 * side.
 *
 * The refusals are chosen so a wrong answer is a REACHABLE attack rather
 * than an untidy decode: a have-set truncated instead of refused, a length
 * table that runs past the buffer, a HAVE accepted by the WANT parser.
 */

#include "../message.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

#if defined(__GNUC__)
#define FZN_CHECK_PRINTF __attribute__((format(printf, 3, 4)))
#else
#define FZN_CHECK_PRINTF
#endif

static void check_at(int ok, int line, const char *fmt, ...) FZN_CHECK_PRINTF;

static void check_at(int ok, int line, const char *fmt, ...)
{
	va_list ap;

	checks++;
	if (ok)
		return;
	failures++;
	fprintf(stderr, "  FAIL message_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

/* ---- the same stub hash the rest of spool/ tests with ------------------ */

static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	(void)ctx;
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

static const fzn_hash_ops_t HASH = { stub_hash, NULL };

/* ---- a blob, so the store can be handed what the parser produced ------- */

#define TEST_LEAVES 8u
#define SPAN_FIRST 4u
#define SPAN_COUNT 4u

static uint8_t sealed[TEST_LEAVES][FZN_BLOB_SEALED_MAX];
static size_t sealed_len[TEST_LEAVES];
static uint8_t leaf_hash[TEST_LEAVES][FZN_BLOB_HASH_LEN];
static uint8_t root[FZN_BLOB_HASH_LEN];
static uint8_t span_proof[FZN_BLOB_MAX_DEPTH * FZN_BLOB_HASH_LEN];
static unsigned span_proof_len;

static int build_blob(void)
{
	fzn_blob_tree_t tree;
	unsigned i;

	fzn_blob_tree_init(&tree);
	for (i = 0; i < TEST_LEAVES; i++) {
		size_t j;

		/* Mixed lengths, so the length table is doing real work: a
		 * fixture of equal-length leaves cannot tell a parser that
		 * reads the table from one that assumes a stride. */
		sealed_len[i] = 48u + i * 7u;
		for (j = 0; j < sealed_len[i]; j++)
			sealed[i][j] = (uint8_t)((i * 37u) + j + 1u);
		if (fzn_blob_leaf_hash(&HASH, sealed[i], sealed_len[i], leaf_hash[i])
		    != FZN_BLOB_OK)
			return 0;
		if (fzn_blob_tree_push(&HASH, &tree, leaf_hash[i]) != FZN_BLOB_OK)
			return 0;
	}
	if (fzn_blob_tree_root(&HASH, &tree, root) != FZN_BLOB_OK)
		return 0;
	return fzn_blob_span_proof_build(&HASH, leaf_hash[0], TEST_LEAVES, SPAN_FIRST, SPAN_COUNT,
	                                 span_proof, sizeof(span_proof), &span_proof_len)
	       == FZN_BLOB_OK;
}

static int nop_read(void *c, uint64_t o, uint8_t *b, size_t n)
{
	(void)c; (void)o; (void)b; (void)n;
	return 1;
}

static uint8_t disk[TEST_LEAVES * FZN_BLOB_SEALED_MAX];

static int disk_write(void *c, uint64_t o, const uint8_t *b, size_t n)
{
	(void)c;
	if (o + n > sizeof(disk))
		return 0;
	memcpy(disk + o, b, n);
	return 1;
}

static const fzn_spool_ops_t OPS = { nop_read, disk_write, NULL, NULL };

static const uint8_t COOKIE[FZN_MSG_COOKIE_LEN] = { 0xa1, 0xb2, 0xc3, 0xd4, 0x05, 0x06, 0x07,
                                                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                                                    0x0f, 0x10 };

static uint8_t buf[8192];

/* ---- round trips ------------------------------------------------------- */

static void test_a_have_query_survives_a_round_trip(void)
{
	uint8_t back[FZN_BLOB_HASH_LEN];
	fzn_msg_type_t type;
	size_t len = 0;

	CHECK(fzn_msg_have_query_encode(root, buf, sizeof(buf), &len) == FZN_MSG_OK,
	      "a have_query did not encode");
	CHECK(len == FZN_MSG_HAVE_QUERY_LEN, "a have_query is %zu bytes, not %u", len,
	      FZN_MSG_HAVE_QUERY_LEN);
	CHECK(fzn_msg_peek(buf, len, &type) == FZN_MSG_OK && type == FZN_MSG_HAVE_QUERY,
	      "peek did not name a have_query");
	CHECK(fzn_msg_have_query_parse(buf, len, back) == FZN_MSG_OK,
	      "a have_query did not parse");
	CHECK(memcmp(back, root, FZN_BLOB_HASH_LEN) == 0, "the root did not survive");
}

static void test_a_want_survives_a_round_trip(void)
{
	uint8_t back_root[FZN_BLOB_HASH_LEN], back_cookie[FZN_MSG_COOKIE_LEN];
	uint32_t transfer = 0;
	uint64_t first = 0, count = 0;
	fzn_msg_type_t type;
	size_t len = 0;

	CHECK(fzn_msg_want_encode(0xdeadbeefu, COOKIE, root, SPAN_FIRST, SPAN_COUNT, buf,
	                          sizeof(buf), &len) == FZN_MSG_OK,
	      "a want did not encode");
	CHECK(len == FZN_MSG_WANT_LEN, "a want is %zu bytes, not %u", len, FZN_MSG_WANT_LEN);
	CHECK(fzn_msg_peek(buf, len, &type) == FZN_MSG_OK && type == FZN_MSG_WANT,
	      "peek did not name a want");
	CHECK(fzn_msg_want_parse(buf, len, &transfer, back_cookie, back_root, &first, &count)
	              == FZN_MSG_OK,
	      "a want did not parse");
	CHECK(transfer == 0xdeadbeefu, "the transfer id did not survive");
	CHECK(memcmp(back_cookie, COOKIE, FZN_MSG_COOKIE_LEN) == 0, "the cookie did not survive");
	CHECK(memcmp(back_root, root, FZN_BLOB_HASH_LEN) == 0, "the root did not survive");
	CHECK(first == SPAN_FIRST && count == SPAN_COUNT, "the span did not survive: %llu+%llu",
	      (unsigned long long)first, (unsigned long long)count);
}

/* THE FIRST OF THE TWO INTEROPERATION CLAIMS: a plan encodes unmodified.
 *
 * message.h says `fzn_spool_plan_offer` already produces this message's body
 * and the encoder has nothing to compute. That is only true while both sides
 * agree about the range type, so the fixture is a REAL plan rather than
 * ranges typed out here -- typed ranges would pass with the planner
 * removed. */
static void test_a_plan_encodes_and_decodes_unmodified(void)
{
	fzn_spool_t spool;
	const uint8_t *span[SPAN_COUNT];
	size_t span_len[SPAN_COUNT];
	fzn_spool_range_t peer_want[1] = { { 0, TEST_LEAVES } };
	fzn_spool_range_t offer[8], back[8];
	uint8_t map[FZN_SPOOL_BITMAP_LEN(TEST_LEAVES)];
	uint8_t back_root[FZN_BLOB_HASH_LEN], back_cookie[FZN_MSG_COOKIE_LEN];
	uint64_t leaf_count = 0;
	size_t offer_count = 0, back_count = 0, len = 0, at;

	memset(map, 0, sizeof(map));
	CHECK(fzn_spool_open(&spool, root, TEST_LEAVES, map, sizeof(map), &OPS) == FZN_SPOOL_OK,
	      "the spool did not open");
	for (at = 0; at < SPAN_COUNT; at++) {
		span[at] = sealed[SPAN_FIRST + at];
		span_len[at] = sealed_len[SPAN_FIRST + at];
	}
	CHECK(fzn_spool_place_span(&spool, &HASH, SPAN_FIRST, SPAN_COUNT, span, span_len,
	                           span_proof, span_proof_len) == FZN_SPOOL_OK,
	      "the span did not place");

	/* A peer asks for the whole blob; the planner answers with what this
	 * host actually holds. The fixture is the PLANNER'S output, not ranges
	 * typed here -- typed ranges would pass with the planner removed. */
	CHECK(fzn_spool_plan_offer(&spool, peer_want, 1, FZN_MSG_MAX_SPAN, offer, 8, &offer_count)
	              == FZN_SPOOL_OK,
	      "the offer plan failed");
	CHECK(offer_count == 1, "a contiguous half-blob planned %zu ranges, not one", offer_count);
	CHECK(offer[0].first == SPAN_FIRST && offer[0].count == SPAN_COUNT,
	      "the planner offered %llu+%llu", (unsigned long long)offer[0].first,
	      (unsigned long long)offer[0].count);

	CHECK(fzn_msg_have_encode(root, TEST_LEAVES, COOKIE, offer, offer_count, buf,
	                          sizeof(buf), &len) == FZN_MSG_OK,
	      "a have did not encode");
	CHECK(len == FZN_MSG_HAVE_LEN(offer_count), "a have of %zu ranges is %zu bytes",
	      offer_count, len);
	/* The claim in message.h that a contiguous prefix is one range and 16
	 * bytes whatever the blob's size, rather than a 512 KiB bitmap. */
	CHECK(len == FZN_MSG_HAVE_OFF_RANGES + FZN_MSG_RANGE_LEN,
	      "a contiguous have is %zu bytes", len);

	CHECK(fzn_msg_have_parse(buf, len, back_root, &leaf_count, back_cookie, back, 8,
	                         &back_count) == FZN_MSG_OK,
	      "a have did not parse");
	CHECK(back_count == offer_count, "%zu ranges went out and %zu came back", offer_count,
	      back_count);
	CHECK(leaf_count == TEST_LEAVES, "the leaf count did not survive");
	CHECK(memcmp(back_root, root, FZN_BLOB_HASH_LEN) == 0, "the root did not survive");
	CHECK(memcmp(back_cookie, COOKIE, FZN_MSG_COOKIE_LEN) == 0, "the cookie did not survive");
	for (at = 0; at < back_count; at++)
		CHECK(back[at].first == offer[at].first && back[at].count == offer[at].count,
		      "range %zu changed: %llu+%llu became %llu+%llu", at,
		      (unsigned long long)offer[at].first, (unsigned long long)offer[at].count,
		      (unsigned long long)back[at].first, (unsigned long long)back[at].count);
}

/* THE SECOND CLAIM: a parsed DATA hands straight to a store.
 *
 * message.h says `out_sealed` and `out_sealed_len` are the same pair
 * `fzn_spool_place_span` takes, in the same order, so a relay copies
 * nothing. The only way to hold that sentence is to do it -- encode a span,
 * parse it, and place the arrays the parser produced without touching
 * them. */
static void test_a_parsed_data_places_without_being_touched(void)
{
	fzn_spool_t spool;
	uint8_t map[FZN_SPOOL_BITMAP_LEN(TEST_LEAVES)];
	const uint8_t *span[SPAN_COUNT], *out_span[SPAN_COUNT], *back_proof = NULL;
	size_t span_len[SPAN_COUNT], out_span_len[SPAN_COUNT], len = 0;
	uint32_t transfer = 0;
	uint64_t first = 0, count = 0;
	unsigned proof_count = 0;
	fzn_msg_type_t type;
	size_t at;

	for (at = 0; at < SPAN_COUNT; at++) {
		span[at] = sealed[SPAN_FIRST + at];
		span_len[at] = sealed_len[SPAN_FIRST + at];
	}

	CHECK(fzn_msg_data_encode(0x01020304u, SPAN_FIRST, SPAN_COUNT, span_proof, span_proof_len,
	                          span, span_len, buf, sizeof(buf), &len) == FZN_MSG_OK,
	      "a data did not encode");
	CHECK(fzn_msg_peek(buf, len, &type) == FZN_MSG_OK && type == FZN_MSG_DATA,
	      "peek did not name a data");
	CHECK(fzn_msg_data_parse(buf, len, &transfer, &first, &count, &back_proof, &proof_count,
	                         out_span, out_span_len, SPAN_COUNT) == FZN_MSG_OK,
	      "a data did not parse");
	CHECK(transfer == 0x01020304u, "the transfer id did not survive");
	CHECK(first == SPAN_FIRST && count == SPAN_COUNT, "the span did not survive");
	CHECK(proof_count == span_proof_len, "%u proof siblings went out and %u came back",
	      span_proof_len, proof_count);

	/* The leaves must be byte-identical AND must point into the message
	 * rather than at the fixture, which is what "without copying" means. */
	for (at = 0; at < SPAN_COUNT; at++) {
		CHECK(out_span_len[at] == span_len[at], "leaf %zu changed length", at);
		CHECK(memcmp(out_span[at], span[at], span_len[at]) == 0, "leaf %zu changed", at);
		CHECK(out_span[at] >= buf && out_span[at] < buf + len,
		      "leaf %zu points outside the message, so something copied", at);
	}

	memset(map, 0, sizeof(map));
	CHECK(fzn_spool_open(&spool, root, TEST_LEAVES, map, sizeof(map), &OPS) == FZN_SPOOL_OK,
	      "the spool did not open");
	CHECK(fzn_spool_place_span(&spool, &HASH, first, count, out_span, out_span_len,
	                           back_proof, proof_count) == FZN_SPOOL_OK,
	      "the store refused what the parser produced");
	CHECK(spool.have == SPAN_COUNT, "%llu leaves landed, not %u",
	      (unsigned long long)spool.have, SPAN_COUNT);
}

/* ---- the refusals ------------------------------------------------------ */

/* The type byte earning its place. A seal proves the peer wrote the bytes
 * and not which question they answer, so every parser must refuse another
 * type outright -- otherwise a HAVE and a WANT of compatible length are one
 * message with two readings. */
static void test_a_parser_refuses_another_type(void)
{
	fzn_spool_range_t ranges[2] = { { 0, 4 }, { 6, 2 } };
	uint8_t back_root[FZN_BLOB_HASH_LEN], back_cookie[FZN_MSG_COOKIE_LEN];
	uint32_t transfer = 0;
	uint64_t a = 0, b = 0;
	size_t len = 0;

	CHECK(fzn_msg_have_encode(root, TEST_LEAVES, COOKIE, ranges, 2, buf, sizeof(buf), &len)
	              == FZN_MSG_OK,
	      "a two-range have did not encode");
	CHECK(len == FZN_MSG_WANT_LEN + 22u, "the fixture is no longer want-length-adjacent");
	CHECK(fzn_msg_want_parse(buf, FZN_MSG_WANT_LEN, &transfer, back_cookie, back_root, &a, &b)
	              == FZN_MSG_ERR_MALFORMED,
	      "a have was read as a want");
	CHECK(fzn_msg_have_query_parse(buf, FZN_MSG_HAVE_QUERY_LEN, back_root)
	              == FZN_MSG_ERR_MALFORMED,
	      "a have was read as a have_query");
}

static void test_peek_refuses_a_version_and_a_type_it_does_not_know(void)
{
	fzn_msg_type_t type;
	size_t len = 0;

	CHECK(fzn_msg_have_query_encode(root, buf, sizeof(buf), &len) == FZN_MSG_OK,
	      "the fixture did not encode");
	buf[FZN_MSG_OFF_VERSION] = FZN_MSG_VERSION + 1u;
	CHECK(fzn_msg_peek(buf, len, &type) == FZN_MSG_ERR_MALFORMED,
	      "peek accepted a future version");
	buf[FZN_MSG_OFF_VERSION] = FZN_MSG_VERSION;
	buf[FZN_MSG_OFF_TYPE] = 9u;
	CHECK(fzn_msg_peek(buf, len, &type) == FZN_MSG_ERR_MALFORMED,
	      "peek accepted an unknown type");
	CHECK(fzn_msg_peek(buf, 1u, &type) == FZN_MSG_ERR_MALFORMED,
	      "peek read a one-byte message");
}

/* Sec 25's rule, on this vocabulary: the cheapest message a stranger can
 * forge must not be the one that buys the most work. */
static void test_a_message_naming_nothing_is_refused(void)
{
	fzn_spool_range_t none[1] = { { 0, 0 } };
	size_t len = 0;

	CHECK(fzn_msg_want_encode(1u, COOKIE, root, 0, 0, buf, sizeof(buf), &len)
	              == FZN_MSG_ERR_EMPTY,
	      "a want of no leaves encoded");
	CHECK(fzn_msg_have_encode(root, TEST_LEAVES, COOKIE, none, 0, buf, sizeof(buf), &len)
	              == FZN_MSG_ERR_EMPTY,
	      "a have of no ranges encoded");
	CHECK(fzn_msg_have_encode(root, TEST_LEAVES, COOKIE, none, 1, buf, sizeof(buf), &len)
	              == FZN_MSG_ERR_EMPTY,
	      "a have carrying an empty range encoded");
	CHECK(fzn_msg_data_encode(1u, 0, 0, span_proof, span_proof_len, NULL, NULL, buf,
	                          sizeof(buf), &len) == FZN_MSG_ERR_MALFORMED,
	      "a data with no leaves encoded");
}

/* A ceiling, because the peer chooses the number -- sec 25's second rule. */
static void test_a_count_past_a_ceiling_is_refused(void)
{
	size_t len = 0;

	CHECK(fzn_msg_want_encode(1u, COOKIE, root, 0, FZN_MSG_MAX_SPAN + 1u, buf, sizeof(buf),
	                          &len) == FZN_MSG_ERR_TOO_LARGE,
	      "a want past the span ceiling encoded");
	CHECK(fzn_msg_want_encode(1u, COOKIE, root, 0, FZN_MSG_MAX_SPAN, buf, sizeof(buf), &len)
	              == FZN_MSG_OK,
	      "a want AT the span ceiling was refused");
	/* The ceiling on the wire, not only in the encoder: a peer writes the
	 * count itself and never calls our encoder. */
	buf[FZN_MSG_WANT_OFF_COUNT + 7u] = (uint8_t)(FZN_MSG_MAX_SPAN + 1u);
	{
		uint8_t r[FZN_BLOB_HASH_LEN], c[FZN_MSG_COOKIE_LEN];
		uint32_t t = 0;
		uint64_t a = 0, b = 0;

		CHECK(fzn_msg_want_parse(buf, len, &t, c, r, &a, &b) == FZN_MSG_ERR_TOO_LARGE,
		      "a want past the span ceiling parsed");
	}
}

/* TOO_LARGE and never a truncation. A have-set silently shortened reports a
 * peer as holding less than it does, and the transfer re-fetches leaves that
 * were available all along -- green in every round trip, and slow forever. */
static void test_an_oversized_have_is_refused_rather_than_truncated(void)
{
	fzn_spool_range_t ranges[3] = { { 0, 2 }, { 3, 1 }, { 5, 3 } };
	fzn_spool_range_t back[3];
	uint8_t back_root[FZN_BLOB_HASH_LEN], back_cookie[FZN_MSG_COOKIE_LEN];
	uint64_t leaf_count = 0;
	size_t len = 0, back_count = 99;

	CHECK(fzn_msg_have_encode(root, TEST_LEAVES, COOKIE, ranges, 3, buf, sizeof(buf), &len)
	              == FZN_MSG_OK,
	      "a three-range have did not encode");
	memset(back, 0, sizeof(back));
	CHECK(fzn_msg_have_parse(buf, len, back_root, &leaf_count, back_cookie, back, 2,
	                         &back_count) == FZN_MSG_ERR_TOO_LARGE,
	      "a have larger than the caller's array was accepted");
	/* The control. Without it this case passes just as happily against a
	 * parser that refuses everything, and against one that writes two
	 * ranges and then returns an error. */
	CHECK(back_count == 99, "a refused have still reported a count");
	CHECK(back[0].count == 0 && back[1].count == 0,
	      "a refused have wrote ranges into the caller's array");
	CHECK(fzn_msg_have_parse(buf, len, back_root, &leaf_count, back_cookie, back, 3,
	                         &back_count) == FZN_MSG_OK && back_count == 3,
	      "the same have was refused with room for it");
}

/* A trailing byte is a second encoding of one message. A receiver that
 * de-duplicates by bytes sees two questions where a peer asked one. */
static void test_a_trailing_byte_is_refused(void)
{
	uint8_t back[FZN_BLOB_HASH_LEN];
	size_t len = 0;

	CHECK(fzn_msg_have_query_encode(root, buf, sizeof(buf), &len) == FZN_MSG_OK,
	      "the fixture did not encode");
	buf[len] = 0;
	CHECK(fzn_msg_have_query_parse(buf, len + 1u, back) == FZN_MSG_ERR_MALFORMED,
	      "a have_query with a trailing byte parsed");
	CHECK(fzn_msg_have_query_parse(buf, len - 1u, back) == FZN_MSG_ERR_MALFORMED,
	      "a short have_query parsed");
}

/* The length table is a peer's arithmetic, and it is the one place in this
 * file where getting it wrong is a read past the buffer rather than a wrong
 * answer. */
static void test_a_length_table_cannot_reach_past_the_message(void)
{
	const uint8_t *span[SPAN_COUNT], *out_span[SPAN_COUNT], *back_proof = NULL;
	size_t span_len[SPAN_COUNT], out_span_len[SPAN_COUNT], len = 0, table, at;
	uint32_t transfer = 0;
	uint64_t first = 0, count = 0;
	unsigned proof_count = 0;

	for (at = 0; at < SPAN_COUNT; at++) {
		span[at] = sealed[SPAN_FIRST + at];
		span_len[at] = sealed_len[SPAN_FIRST + at];
	}
	CHECK(fzn_msg_data_encode(1u, SPAN_FIRST, SPAN_COUNT, span_proof, span_proof_len, span,
	                          span_len, buf, sizeof(buf), &len) == FZN_MSG_OK,
	      "the fixture did not encode");
	table = FZN_MSG_DATA_OFF_PROOF + (size_t)span_proof_len * FZN_BLOB_HASH_LEN;

	/* One leaf claiming the whole address space. Summed naively this
	 * wraps and compares small. */
	memset(buf + table, 0xff, 4u);
	CHECK(fzn_msg_data_parse(buf, len, &transfer, &first, &count, &back_proof, &proof_count,
	                         out_span, out_span_len, SPAN_COUNT) == FZN_MSG_ERR_MALFORMED,
	      "a leaf length of 0xffffffff parsed");

	/* One byte longer than the message holds. */
	CHECK(fzn_msg_data_encode(1u, SPAN_FIRST, SPAN_COUNT, span_proof, span_proof_len, span,
	                          span_len, buf, sizeof(buf), &len) == FZN_MSG_OK,
	      "the fixture did not re-encode");
	buf[table + 3u] = (uint8_t)(buf[table + 3u] + 1u);
	CHECK(fzn_msg_data_parse(buf, len, &transfer, &first, &count, &back_proof, &proof_count,
	                         out_span, out_span_len, SPAN_COUNT) == FZN_MSG_ERR_MALFORMED,
	      "a length table one byte over the message parsed");

	/* A TRAILING BYTE PAST THE LAST LEAF, which separates the two length
	 * checks: every individual length still fits, so only the exact
	 * comparison at the end can refuse this. Without a case that only one
	 * guard can catch, a sabotage of either reports the other's work. */
	CHECK(fzn_msg_data_encode(1u, SPAN_FIRST, SPAN_COUNT, span_proof, span_proof_len, span,
	                          span_len, buf, sizeof(buf), &len) == FZN_MSG_OK,
	      "the fixture did not re-encode");
	buf[len] = 0x5a;
	CHECK(fzn_msg_data_parse(buf, len + 1u, &transfer, &first, &count, &back_proof,
	                         &proof_count, out_span, out_span_len, SPAN_COUNT)
	              == FZN_MSG_ERR_MALFORMED,
	      "a data with a trailing byte parsed");

	/* A zero-length leaf: no data, and a hole in a span the store would
	 * then be asked to verify. */
	CHECK(fzn_msg_data_encode(1u, SPAN_FIRST, SPAN_COUNT, span_proof, span_proof_len, span,
	                          span_len, buf, sizeof(buf), &len) == FZN_MSG_OK,
	      "the fixture did not re-encode");
	memset(buf + table, 0, 4u);
	CHECK(fzn_msg_data_parse(buf, len, &transfer, &first, &count, &back_proof, &proof_count,
	                         out_span, out_span_len, SPAN_COUNT) == FZN_MSG_ERR_MALFORMED,
	      "a zero-length leaf parsed");
}

static void test_a_range_outside_the_blob_is_refused(void)
{
	fzn_spool_range_t bad[1] = { { TEST_LEAVES - 1u, 4 } };
	fzn_spool_range_t back[2];
	fzn_spool_range_t good[1] = { { 0, 2 } };
	uint8_t back_root[FZN_BLOB_HASH_LEN], back_cookie[FZN_MSG_COOKIE_LEN];
	uint64_t leaf_count = 0;
	size_t len = 0, back_count = 0;

	CHECK(fzn_msg_have_encode(root, TEST_LEAVES, COOKIE, bad, 1, buf, sizeof(buf), &len)
	              == FZN_MSG_ERR_MALFORMED,
	      "a range past the blob's end encoded");

	/* And on the wire, since a peer never calls our encoder. */
	CHECK(fzn_msg_have_encode(root, TEST_LEAVES, COOKIE, good, 1, buf, sizeof(buf), &len)
	              == FZN_MSG_OK,
	      "the fixture did not encode");
	buf[FZN_MSG_HAVE_OFF_RANGES + 15u] = 0xffu;
	CHECK(fzn_msg_have_parse(buf, len, back_root, &leaf_count, back_cookie, back, 2,
	                         &back_count) == FZN_MSG_ERR_MALFORMED,
	      "a range past the blob's end parsed");

	/* A leaf count of zero is a blob nobody can address. */
	CHECK(fzn_msg_have_encode(root, 0, COOKIE, good, 1, buf, sizeof(buf), &len)
	              == FZN_MSG_ERR_MALFORMED,
	      "a have over an empty blob encoded");
}

static void test_a_short_buffer_is_reported_and_not_written(void)
{
	fzn_spool_range_t ranges[2] = { { 0, 2 }, { 4, 4 } };
	uint8_t small[FZN_MSG_WANT_LEN];
	size_t len = 99;

	memset(small, 0xee, sizeof(small));
	CHECK(fzn_msg_have_encode(root, TEST_LEAVES, COOKIE, ranges, 2, small, sizeof(small),
	                          &len) == FZN_MSG_ERR_TOO_LARGE,
	      "a have encoded into a buffer too small for it");
	CHECK(len == 99, "a refused encode still reported a length");
	CHECK(small[0] == 0xee, "a refused encode wrote a header anyway");
	CHECK(fzn_msg_have_query_encode(root, small, FZN_MSG_HAVE_QUERY_LEN - 1u, &len)
	              == FZN_MSG_ERR_TOO_LARGE,
	      "a have_query encoded one byte short");
	CHECK(small[0] == 0xee, "a refused have_query wrote a header anyway");
}

/* A span that IS the whole tree needs no siblings, so zero is a legitimate
 * proof length and not a missing argument. */
static void test_a_proofless_span_round_trips(void)
{
	const uint8_t *span[2], *out_span[2], *back_proof = (const uint8_t *)1;
	size_t span_len[2], out_span_len[2], len = 0;
	uint32_t transfer = 0;
	uint64_t first = 0, count = 0;
	unsigned proof_count = 99;

	span[0] = sealed[0];
	span_len[0] = sealed_len[0];
	span[1] = sealed[1];
	span_len[1] = sealed_len[1];
	CHECK(fzn_msg_data_encode(7u, 0, 2, NULL, 0, span, span_len, buf, sizeof(buf), &len)
	              == FZN_MSG_OK,
	      "a proofless data did not encode");
	CHECK(fzn_msg_data_parse(buf, len, &transfer, &first, &count, &back_proof, &proof_count,
	                         out_span, out_span_len, 2) == FZN_MSG_OK,
	      "a proofless data did not parse");
	CHECK(proof_count == 0, "a proofless data reported %u siblings", proof_count);
	CHECK(back_proof == NULL, "a proofless data handed back a proof pointer");
	CHECK(out_span_len[0] == span_len[0] && out_span_len[1] == span_len[1],
	      "the leaves did not survive a proofless data");
}

int main(void)
{
	if (!build_blob()) {
		fprintf(stderr, "message_test: the fixture did not build\n");
		return 1;
	}

	test_a_have_query_survives_a_round_trip();
	test_a_want_survives_a_round_trip();
	test_a_plan_encodes_and_decodes_unmodified();
	test_a_parsed_data_places_without_being_touched();
	test_a_parser_refuses_another_type();
	test_peek_refuses_a_version_and_a_type_it_does_not_know();
	test_a_message_naming_nothing_is_refused();
	test_a_count_past_a_ceiling_is_refused();
	test_an_oversized_have_is_refused_rather_than_truncated();
	test_a_trailing_byte_is_refused();
	test_a_length_table_cannot_reach_past_the_message();
	test_a_range_outside_the_blob_is_refused();
	test_a_short_buffer_is_reported_and_not_written();
	test_a_proofless_span_round_trips();

	printf("message_test: %d checks, %d failures\n", checks, failures);
	return failures != 0;
}
