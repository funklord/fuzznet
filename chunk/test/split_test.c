/* Tests for chunk/split.c, and for the two halves of sec 4.4 agreeing.
 *
 * The round trip is the point of this file. Either half can be tested
 * alone and both can be self-consistently wrong -- a splitter that shortens
 * a middle piece and a reassembler that accepts one would pass their own
 * suites and lose bytes together. So the cases below cut a payload with
 * split.c and feed the pieces to reassembly.c, in order and out of order,
 * and compare what comes back with what went in.
 */

#include "../reassembly.h"
#include "../split.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* How long a half-finished message may hold a slot. Generous, because what
 * these cases test is the bound EXISTING -- a zero expiry no longer means
 * for ever -- rather than any particular value of it. */
#define REASM_MAX_HOLD 1000000u

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
	fprintf(stderr, "  FAIL split_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

static void test_plan_arithmetic(void)
{
	fzn_split_t p;

	CHECK(fzn_split_plan(10, 4, &p) == FZN_SPLIT_OK, "plan refused");
	CHECK(p.chunks == 3, "chunks %u, wanted 3", p.chunks);
	CHECK(p.chunk_size == 4, "stride %zu, wanted 4", p.chunk_size);
	CHECK(p.buffer_needed == 12, "buffer %zu, wanted 12 (stride times count)",
	      p.buffer_needed);

	/* An exact multiple must not produce a trailing empty piece. */
	CHECK(fzn_split_plan(8, 4, &p) == FZN_SPLIT_OK, "plan refused");
	CHECK(p.chunks == 2, "an exact multiple produced %u pieces, wanted 2", p.chunks);

	/* One piece: the stride is the message, not max_payload, so
	 * buffer_needed is what the message actually costs. */
	CHECK(fzn_split_plan(3, 100, &p) == FZN_SPLIT_OK, "plan refused");
	CHECK(p.chunks == 1 && p.chunk_size == 3 && p.buffer_needed == 3,
	      "a single-piece plan asked for %zu bytes, wanted 3", p.buffer_needed);

	CHECK(fzn_split_plan(0, 4, &p) == FZN_SPLIT_ERR_MALFORMED,
	      "an empty message was planned, which reassembly will not accept");
	CHECK(fzn_split_plan(10, 0, &p) == FZN_SPLIT_ERR_MALFORMED, "a zero stride planned");
	CHECK(fzn_split_plan(10, 4, NULL) == FZN_SPLIT_ERR_MALFORMED, "null out accepted");
}

static void test_plan_refuses_more_pieces_than_a_receiver_tracks(void)
{
	fzn_split_t p;

	CHECK(fzn_split_plan(FZN_REASM_MAX_CHUNKS * 4u, 4, &p) == FZN_SPLIT_OK,
	      "a message of exactly the ceiling was refused");
	CHECK(p.chunks == FZN_REASM_MAX_CHUNKS, "chunks %u at the ceiling", p.chunks);

	CHECK(fzn_split_plan(FZN_REASM_MAX_CHUNKS * 4u + 1u, 4, &p) == FZN_SPLIT_ERR_TOO_LARGE,
	      "a message past the ceiling was planned, to be refused at the far end");
}

static void test_offsets_tile_the_message(void)
{
	fzn_split_t p;
	size_t offset, len, seen = 0, expect = 0;

	/* Every byte is in exactly one piece, and the pieces are contiguous.
	 * A gap or an overlap is how a reassembled message ends up with a
	 * hole or with the wrong bytes in it. */
	CHECK(fzn_split_plan(10, 4, &p) == FZN_SPLIT_OK, "plan refused");
	for (uint16_t i = 0; i < p.chunks; i++) {
		CHECK(fzn_split_at(&p, i, &offset, &len) == FZN_SPLIT_OK, "piece %u", i);
		CHECK(offset == expect, "piece %u starts at %zu, wanted %zu", i, offset, expect);
		CHECK(len > 0, "piece %u is empty", i);
		expect = offset + len;
		seen += len;
	}
	CHECK(seen == 10, "the pieces cover %zu bytes, wanted 10", seen);
	CHECK(expect == 10, "the last piece ends at %zu, wanted 10", expect);

	CHECK(fzn_split_at(&p, p.chunks, &offset, &len) == FZN_SPLIT_ERR_MALFORMED,
	      "an index past the plan was answered");
}

static void test_split_at_bad_arguments(void)
{
	fzn_split_t p, empty;
	size_t offset, len;

	/* Added because branch coverage said every one of these guards had
	 * only ever gone one way. `fzn_split_plan` had its bad arguments
	 * tested and `fzn_split_at` did not -- the same gap coverage found in
	 * fzn_revocation_merge, and the same cause: two functions written
	 * together, only one of them thought about twice. */
	CHECK(fzn_split_plan(10, 4, &p) == FZN_SPLIT_OK, "plan refused");

	CHECK(fzn_split_at(NULL, 0, &offset, &len) == FZN_SPLIT_ERR_MALFORMED,
	      "a null plan was answered");
	CHECK(fzn_split_at(&p, 0, NULL, &len) == FZN_SPLIT_ERR_MALFORMED,
	      "a null offset was answered");
	CHECK(fzn_split_at(&p, 0, &offset, NULL) == FZN_SPLIT_ERR_MALFORMED,
	      "a null length was answered");

	/* A zeroed plan, which is what a caller gets by declaring one and
	 * forgetting to fill it. Answering that would hand back an offset
	 * into a message that was never planned. */
	memset(&empty, 0, sizeof(empty));
	CHECK(fzn_split_at(&empty, 0, &offset, &len) == FZN_SPLIT_ERR_MALFORMED,
	      "a zeroed plan was answered");

	empty = p;
	empty.chunk_size = 0;
	CHECK(fzn_split_at(&empty, 0, &offset, &len) == FZN_SPLIT_ERR_MALFORMED,
	      "a plan with a zero stride was answered");
}

/* Cut `total` bytes with split.c, hand the pieces to reassembly.c in the
 * given order, and compare. Returns 1 on a clean round trip. */
static int round_trip(size_t total, size_t max_payload, int reverse)
{
	fzn_split_t p;
	fzn_reasm_t table;
	fzn_partial_t slots[1];
	fzn_partial_t *done = NULL;
	static uint8_t payload[2048];
	static uint8_t storage[4096];
	uint8_t sender[FZN_SENDER_LEN];
	size_t offset, len;

	if (total > sizeof(payload))
		return 0;
	for (size_t i = 0; i < total; i++)
		payload[i] = (uint8_t)(i * 7u + 1u);
	memset(sender, 0xa1, sizeof(sender));

	if (fzn_split_plan(total, max_payload, &p) != FZN_SPLIT_OK)
		return 0;
	if (p.buffer_needed > sizeof(storage))
		return 0;

	if (fzn_reasm_slot_init(&slots[0], storage, sizeof(storage)) != FZN_REASM_OK)
		return 0;
	if (fzn_reasm_init(&table, slots, 1, 1, REASM_MAX_HOLD) != FZN_REASM_OK)
		return 0;

	for (uint16_t k = 0; k < p.chunks; k++) {
		uint16_t i = reverse ? (uint16_t)(p.chunks - 1u - k) : k;

		if (fzn_split_at(&p, i, &offset, &len) != FZN_SPLIT_OK)
			return 0;
		if (fzn_reasm_accept(&table, sender, 1, i, p.chunks, payload + offset, len, 0,
		                     100, &done) != FZN_REASM_OK)
			return 0;
	}

	if (!done)
		return 0;
	if (done->bytes != total)
		return 0;

	return memcmp(done->buf, payload, total) == 0;
}

static void test_round_trip(void)
{
	/* Shapes chosen for their edges: exact multiples, a remainder of one,
	 * a single piece, and a message that is one byte over a boundary. */
	const size_t sizes[] = { 1, 7, 8, 9, 63, 64, 65, 100, 511, 1000 };

	for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
		CHECK(round_trip(sizes[i], 8, 0), "in-order round trip failed at %zu bytes",
		      sizes[i]);
		CHECK(round_trip(sizes[i], 64, 0), "in-order round trip failed at %zu/64",
		      sizes[i]);
	}
}

static void test_round_trip_out_of_order(void)
{
	const size_t sizes[] = { 9, 65, 100, 1000 };

	/* Reversed is the hard direction: the LAST piece arrives first, and
	 * reassembly refuses to let a short piece set the stride. A splitter
	 * that made the last piece the same length as the rest would pass the
	 * in-order test and fail here, which is why both exist. */
	for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++)
		CHECK(round_trip(sizes[i], 8, 1) == 0,
		      "a reversed round trip succeeded at %zu bytes -- reassembly is "
		      "supposed to refuse a last-chunk-first arrival",
		      sizes[i]);
}

/* The payload ceiling, which is the schema's rather than this module's.
 *
 * `wire/frame.situ` says `u16 length [max = 1024]`, so a stride above that
 * plans datagrams no receiver will validate. Nothing checked it until now
 * and nothing else on the send path could: there is no encoder yet, so
 * `fzn_split_plan` is the last place the mistake is catchable.
 *
 * THE CASE THAT MATTERS IS THE MIDDLE ONE. A caller doing the arithmetic the
 * header describes -- Ethernet's 1500, less 28 for IP and UDP, less 144 of
 * frame overhead -- gets 1328, and 1328 is a perfectly reasonable number
 * that produces an entirely invalid plan. It is not a hostile input or an
 * edge case; it is what a correct-looking caller computes. */
static void test_plan_refuses_a_stride_no_frame_can_carry(void)
{
	fzn_split_t plan;

	CHECK(fzn_split_plan(4096, FZN_SPLIT_MAX_PAYLOAD, &plan) == FZN_SPLIT_OK,
	      "the ceiling itself was refused, so the bound is off by one");
	CHECK(plan.chunk_size == FZN_SPLIT_MAX_PAYLOAD,
	      "a stride at the ceiling was not honoured");

	CHECK(fzn_split_plan(4096, FZN_SPLIT_MAX_PAYLOAD + 1u, &plan) ==
	              FZN_SPLIT_ERR_PAYLOAD_TOO_LARGE,
	      "one byte over the ceiling was accepted");

	/* The MTU-derived caller. */
	CHECK(fzn_split_plan(65536, 1500u - 28u - 144u, &plan) == FZN_SPLIT_ERR_PAYLOAD_TOO_LARGE,
	      "a stride sized from a 1500-byte MTU was accepted, which is the bug this "
	      "test exists for");

	/* Distinct from the other refusal, and both reachable, so that neither
	 * error is a synonym for the other. A single-piece message far over
	 * the ceiling must complain about the stride, not about the count. */
	CHECK(fzn_split_plan(2000, 2000, &plan) == FZN_SPLIT_ERR_PAYLOAD_TOO_LARGE,
	      "a one-piece message over the ceiling was refused for the wrong reason");
	CHECK(fzn_split_plan(FZN_SPLIT_MAX_PAYLOAD * (FZN_REASM_MAX_CHUNKS + 1u), 1, &plan) ==
	              FZN_SPLIT_ERR_TOO_LARGE,
	      "too many pieces was refused for the wrong reason");

	/* And the ceiling is not applied to `total`. A large message cut into
	 * legal strides is legal, and confusing the two bounds would refuse
	 * every message bigger than one datagram. */
	CHECK(fzn_split_plan(64u * 1024u, 1024, &plan) == FZN_SPLIT_OK,
	      "a 64 KiB message in legal strides was refused");
	CHECK(plan.chunks == 64, "a 64 KiB message did not come to 64 pieces of 1024");
}

/* A plan whose fields disagree with one another.
 *
 * fzn_split_at already validated `chunks` and `chunk_size`, so it had decided
 * the plan was untrusted -- and then read `total` as though it were not. The
 * last piece's length is `total - start`, and that subtraction underflows.
 *
 * WHY IT MATTERS MORE THAN IT LOOKS. This function does not copy anything. It
 * hands a caller an offset and a length for the caller to copy with, so a
 * length of 2^64 - 290 returned alongside FZN_SPLIT_OK puts the overread at
 * the call site, in somebody else's project, with nothing there to suggest
 * this function was the source.
 *
 * The state is built by hand because fzn_split_plan cannot produce it, which
 * is the same position chunk/test/reassembly_test.c is in for the offset
 * guard, and the same answer: a check nothing exercises is one nobody knows
 * works. */
static void test_a_plan_whose_fields_disagree_is_refused(void)
{
	fzn_split_t plan;
	size_t offset = 0, len = 0;

	/* Ten bytes, claimed in pieces of a hundred. */
	memset(&plan, 0, sizeof(plan));
	plan.total = 10;
	plan.chunk_size = 100;
	plan.chunks = 4;
	plan.buffer_needed = 400;
	CHECK(fzn_split_at(&plan, 3, &offset, &len) == FZN_SPLIT_ERR_MALFORMED,
	      "a stride larger than the whole message was accepted");
	CHECK(len == 0, "a length of %zu was written for a refused call", len);

	/* A stride that fits, but an index whose piece starts past the end:
	 * 30 bytes in strides of 10 cannot have a piece 5. This is the half
	 * the first check does not reach, and it is the one that would still
	 * underflow if only `chunk_size > total` were tested. */
	memset(&plan, 0, sizeof(plan));
	plan.total = 30;
	plan.chunk_size = 10;
	plan.chunks = 8;
	CHECK(fzn_split_at(&plan, 5, &offset, &len) == FZN_SPLIT_ERR_MALFORMED,
	      "a piece starting past the end of the message was accepted");

	/* A COUNT THAT AGREES WITH NEITHER, AND THE ONLY CASE THAT REACHES THE
	 * CHECK FOR IT.
	 *
	 * Both cases above are refused by an EARLIER guard -- the first by the
	 * stride bound, the second by the start-inside-the-message bound -- and
	 * both return the same MALFORMED either way, so neither one could tell
	 * whether the count agreement was tested at all. Measured 2026-09-03:
	 * removing it left the whole suite green.
	 *
	 * Ten bytes in strides of four is three pieces; this plan claims a
	 * hundred. Index 2 clears every other guard -- the stride fits, the
	 * piece starts at 8 which is inside the message, and 2 is below 100 --
	 * so this line is the only thing that refuses it.
	 *
	 * WHAT IT COSTS IS OFF-MODULE. Accepted, the answer is offset 8 length
	 * 4 over a ten-byte message: index 2 is not the last of a hundred, so
	 * it gets a full stride rather than the two bytes that remain, and the
	 * caller copies from two bytes past the end of its own message. */
	memset(&plan, 0, sizeof(plan));
	plan.total = 10;
	plan.chunk_size = 4;
	plan.chunks = 100;
	offset = 0;
	len = 0;
	CHECK(fzn_split_at(&plan, 2, &offset, &len) == FZN_SPLIT_ERR_MALFORMED,
	      "a plan whose count agrees with neither its total nor its stride was "
	      "accepted, and the piece it describes runs past the message");
	CHECK(len == 0, "a length of %zu was written for a refused call", len);
	CHECK(offset + len <= 10u,
	      "the refused piece spans [%zu, %zu) of a ten-byte message", offset,
	      offset + len);

	/* And the guard refuses nothing a real plan produces. Every index of
	 * a genuine plan must still answer, including the last, which is the
	 * one the underflow lived on. */
	CHECK(fzn_split_plan(100, 8, &plan) == FZN_SPLIT_OK, "the real plan was refused");
	for (uint16_t i = 0; i < plan.chunks; i++)
		CHECK(fzn_split_at(&plan, i, &offset, &len) == FZN_SPLIT_OK,
		      "piece %u of a genuine plan was refused by the agreement check", i);
	CHECK(fzn_split_at(&plan, (uint16_t)(plan.chunks - 1u), &offset, &len) ==
	              FZN_SPLIT_OK &&
	              len == 100u - offset,
	      "the last piece of a genuine plan came back wrong");

	/* A single-piece message, where chunk_size == total exactly and an
	 * off-by-one in the bound would refuse it. */
	CHECK(fzn_split_plan(10, 16, &plan) == FZN_SPLIT_OK, "a one-piece plan was refused");
	CHECK(fzn_split_at(&plan, 0, &offset, &len) == FZN_SPLIT_OK && offset == 0 &&
	              len == 10,
	      "the only piece of a one-piece message came back wrong");
}

/* The positive control: round_trip returns 0 for every kind of failure,
 * including refusals, so a test that only asserted failures would pass
 * against a split.c that did nothing. */
static void test_the_suite_can_tell_pass_from_fail(void)
{
	CHECK(round_trip(100, 8, 0),
	      "the positive control fails, so nothing above proves anything");
}

int main(void)
{
	test_plan_arithmetic();
	test_plan_refuses_more_pieces_than_a_receiver_tracks();
	test_plan_refuses_a_stride_no_frame_can_carry();
	test_offsets_tile_the_message();
	test_split_at_bad_arguments();
	test_round_trip();
	test_round_trip_out_of_order();
	test_a_plan_whose_fields_disagree_is_refused();
	test_the_suite_can_tell_pass_from_fail();

	printf("split_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
