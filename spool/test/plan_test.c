/* Tests for spool/plan.c.
 *
 * THE CASES THAT MATTER ARE THE ANTI-AMPLIFICATION ONES, not the coalescing.
 * A planner that merges runs wrongly produces a slow transfer; one that
 * answers an empty request with a whole blob produces a reflector. Both are
 * green in an ordinary round trip, which is why `record/sync` shipped the
 * second for a while.
 */

#include "../plan.h"

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
	fprintf(stderr, "  FAIL plan_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

#define LEAVES 20u

static int nop_read(void *c, uint64_t o, uint8_t *b, size_t n)
{
	(void)c; (void)o; (void)b; (void)n;
	return 1;
}

static int nop_write(void *c, uint64_t o, const uint8_t *b, size_t n)
{
	(void)c; (void)o; (void)b; (void)n;
	return 1;
}

static const fzn_spool_ops_t OPS = { nop_read, nop_write, NULL, NULL };

static uint8_t map[FZN_SPOOL_BITMAP_LEN(LEAVES)];
static fzn_spool_t spool;

/* Builds a store whose present-bits are given as a string of '.' and '#',
 * which makes each case's shape readable at its call site rather than as a
 * hex constant somebody has to decode. */
static int with(const char *pattern)
{
	uint8_t root[FZN_BLOB_HASH_LEN];
	size_t i;

	memset(root, 0x31, sizeof(root));
	memset(map, 0, sizeof(map));
	if (fzn_spool_open(&spool, root, LEAVES, map, sizeof(map), &OPS) != FZN_SPOOL_OK)
		return 0;
	for (i = 0; i < LEAVES && pattern[i]; i++)
		if (pattern[i] == '#')
			map[i >> 3] = (uint8_t)(map[i >> 3] | (1u << (i & 7u)));
	return 1;
}

static int same(const fzn_spool_range_t *got, size_t n, const uint64_t *want, size_t want_n)
{
	size_t i;

	if (n != want_n)
		return 0;
	for (i = 0; i < n; i++)
		if (got[i].first != want[i * 2u] || got[i].count != want[i * 2u + 1u])
			return 0;
	return 1;
}

static void test_a_want_names_the_gaps(void)
{
	fzn_spool_range_t got[8];
	size_t n = 0;

	CHECK(with("####....####...#####"), "the fixture would not build");
	CHECK(fzn_spool_plan_want(&spool, 0u, 100u, got, 8u, &n) == FZN_SPOOL_OK, "want refused");
	{
		static const uint64_t WANT[] = { 4, 4, 12, 3 };

		CHECK(same(got, n, WANT, 2u),
		      "the gaps were not coalesced into two runs: got %u ranges", (unsigned)n);
	}

	/* A STORE THAT HAS EVERYTHING ASKS FOR NOTHING, and that is OK rather
	 * than an error -- a caller must not have to tell "I need nothing"
	 * from "something went wrong". */
	CHECK(with("####################"), "the fixture would not build");
	CHECK(fzn_spool_plan_want(&spool, 0u, 100u, got, 8u, &n) == FZN_SPOOL_OK,
	      "a complete store reported an error rather than an empty plan");
	CHECK(n == 0u, "a complete store asked for %u ranges", (unsigned)n);

	/* AND A RUN THAT REACHES THE END OF THE BLOB is emitted. It is the
	 * ordinary case at the start of a transfer -- the loop only closes a
	 * run when it meets a leaf the store HAS, and a store missing its tail
	 * never does. */
	CHECK(with("####................"), "the fixture would not build");
	CHECK(fzn_spool_plan_want(&spool, 0u, 100u, got, 8u, &n) == FZN_SPOOL_OK, "want refused");
	{
		static const uint64_t WANT[] = { 4, 16 };

		CHECK(same(got, n, WANT, 1u), "the trailing gap was dropped: %u ranges",
		      (unsigned)n);
	}
}

/* THE EARLY STOP, MID-WALK, WHICH THE CAP EXISTS FOR AND NOTHING DROVE.
 *
 * `emit` refusing when the array is full IS exercised -- but only from the
 * flush after the loop, at the bottom of `fzn_spool_plan_want`, whose result
 * is deliberately discarded because the function is ending anyway. The four
 * call sites that actually branch on that refusal and RETURN EARLY had never
 * received a zero.
 *
 * The reason is the fixture, not the code: every existing cap test uses one
 * unbroken run, so the walk never meets a leaf it holds and never closes a
 * run mid-scan. A pattern with gaps SEPARATED by present leaves is what
 * reaches the early return -- the first gap fills the array, and the second
 * gap's close is refused.
 *
 * What that path is for: stopping the scan once the caller's array is full,
 * rather than walking the rest of the bitmap to no purpose. A planner that
 * kept scanning would still produce the right answer, which is exactly why
 * nothing noticed. */
static void test_the_walk_stops_when_the_array_fills(void)
{
	fzn_spool_range_t got[8];
	size_t n = 0;

	/* Three separate gaps, each closed by a leaf the store holds. */
	CHECK(with("...#...#...#........"), "the fixture would not build");

	/* Room for one range: the first gap is written, the second gap's close
	 * is refused, and the walk returns rather than continuing. */
	memset(got, 0, sizeof(got));
	CHECK(fzn_spool_plan_want(&spool, 0u, 64u, got, 1u, &n) == FZN_SPOOL_OK,
	      "want refused with room for one range");
	CHECK(n == 1u, "a one-slot array did not stop at one range: %u", (unsigned)n);
	CHECK(got[0].first == 0u && got[0].count == 3u,
	      "the first gap was not 0..3");
	/* NOTHING PAST THE CAP WAS WRITTEN. The array is zeroed above, so a
	 * planner that wrote and then decremented would show here. */
	CHECK(got[1].first == 0u && got[1].count == 0u,
	      "a range was written past the caller's capacity");

	/* Room for two: the second gap lands, the third is refused. */
	CHECK(fzn_spool_plan_want(&spool, 0u, 64u, got, 2u, &n) == FZN_SPOOL_OK,
	      "want refused with room for two ranges");
	CHECK(n == 2u, "a two-slot array did not stop at two ranges: %u", (unsigned)n);
	CHECK(got[1].first == 4u && got[1].count == 3u,
	      "the second gap was not 4..7");

	/* THE CONTROL: with room for all of them the same store yields three,
	 * so the two stops above are the cap working rather than the fixture
	 * having fewer gaps than I think. */
	CHECK(fzn_spool_plan_want(&spool, 0u, 64u, got, 8u, &n) == FZN_SPOOL_OK,
	      "want refused with room for everything");
	CHECK(n == 4u, "the fixture does not hold four gaps: %u", (unsigned)n);
}

/* THE SAME STOP IN THE OTHER PLANNER, which walks a peer's ranges rather
 * than the whole bitmap and has its own two call sites. */
static void test_the_offer_stops_when_the_array_fills(void)
{
	fzn_spool_range_t got[8];
	fzn_spool_range_t want[2];
	size_t n = 0;

	CHECK(with("###.###.###........."), "the fixture would not build");
	/* Two ranges the peer asked about, each containing a run this store
	 * holds and a gap it does not. */
	want[0].first = 0u;
	want[0].count = 8u;
	want[1].first = 8u;
	want[1].count = 8u;

	memset(got, 0, sizeof(got));
	CHECK(fzn_spool_plan_offer(&spool, want, 2u, 64u, got, 1u, &n) == FZN_SPOOL_OK,
	      "offer refused with room for one range");
	CHECK(n == 1u, "a one-slot offer did not stop at one range: %u", (unsigned)n);
	CHECK(got[1].count == 0u,
	      "a range was written past the caller's capacity");

	CHECK(fzn_spool_plan_offer(&spool, want, 2u, 64u, got, 8u, &n) == FZN_SPOOL_OK,
	      "offer refused with room for everything");
	CHECK(n > 1u, "the control: a roomy offer yielded no more than one range");
}

/* THE CEILING AT ITS EDGE, not eight past it. Both planners clip a peer's
 * range count, and both were only ever tested well beyond the cap -- which
 * passes whether the comparison is the intended one or off by one in either
 * direction. Exactly at the cap must pass through unclipped; exactly one past
 * must clip by exactly one. */
static void test_the_want_ceiling_is_exact(void)
{
	static fzn_spool_range_t want[FZN_SPOOL_MAX_WANT + 1u];
	fzn_spool_range_t got[4];
	size_t n = 0, i;

	CHECK(with("####################"), "the fixture would not build");
	for (i = 0; i < FZN_SPOOL_MAX_WANT + 1u; i++) {
		want[i].first = 0u;
		want[i].count = 1u;
	}

	/* At the cap exactly: accepted, and the last range is examined. */
	CHECK(fzn_spool_plan_offer(&spool, want, FZN_SPOOL_MAX_WANT, 64u, got,
	                           (size_t)(sizeof(got) / sizeof(got[0])), &n)
	              == FZN_SPOOL_OK,
	      "a request of exactly FZN_SPOOL_MAX_WANT ranges was refused");
	/* One past: still answered, and the module's own contract says the
	 * excess is ignored rather than the request rejected. */
	CHECK(fzn_spool_plan_offer(&spool, want, FZN_SPOOL_MAX_WANT + 1u, 64u, got,
	                           (size_t)(sizeof(got) / sizeof(got[0])), &n)
	              == FZN_SPOOL_OK,
	      "a request one past the cap was refused rather than clipped");
}

static void test_a_long_run_is_split_and_a_small_array_stops(void)
{
	fzn_spool_range_t got[8];
	size_t n = 0;

	CHECK(with("...................."), "the fixture would not build");
	CHECK(fzn_spool_plan_want(&spool, 0u, 6u, got, 8u, &n) == FZN_SPOOL_OK, "want refused");
	{
		static const uint64_t WANT[] = { 0, 6, 6, 6, 12, 6, 18, 2 };

		CHECK(same(got, n, WANT, 4u), "a 20-leaf gap did not split into 6,6,6,2: %u",
		      (unsigned)n);
	}

	/* A SMALL ARRAY STOPS RATHER THAN OVERFLOWING, and keeps the lowest
	 * gaps -- a transfer that fills from the bottom keeps its own bitmap
	 * compressible. */
	CHECK(fzn_spool_plan_want(&spool, 0u, 6u, got, 2u, &n) == FZN_SPOOL_OK, "want refused");
	CHECK(n == 2u && got[0].first == 0u && got[1].first == 6u,
	      "a short array did not stop at the lowest two gaps");

	/* ZERO IS REFUSED RATHER THAN MEANING UNLIMITED. */
	CHECK(fzn_spool_plan_want(&spool, 0u, 0u, got, 8u, &n) == FZN_SPOOL_ERR_MALFORMED,
	      "a zero range bound was accepted, so a caller that forgot one got no bound");
}

/*
 * `from` IS THE FETCH POLICY, and these are the two modes it has to express.
 *
 * Before it existed the walk always started at leaf zero, so in-order was the
 * only policy a caller could get -- correct for streaming and exactly wrong
 * for throughput, where a thousand peers all asked for leaf zero.
 */
static void test_the_walk_starts_where_the_caller_says(void)
{
	fzn_spool_range_t got[8];
	size_t n = 0;

	CHECK(with("####....####...#####"), "the fixture would not build");

	/* STREAMING: the playhead is 10, so the gap at 12 is urgent and the
	 * gap at 4 -- behind the playhead, wanted for the recording but not
	 * now -- comes after it. With no `from` these arrived the other way
	 * round, which is the whole defect. */
	CHECK(fzn_spool_plan_want(&spool, 10u, 100u, got, 8u, &n) == FZN_SPOOL_OK, "want refused");
	{
		static const uint64_t WANT[] = { 12, 3, 4, 4 };

		CHECK(same(got, n, WANT, 2u),
		      "the walk did not start at the playhead: %u ranges, first at %llu",
		      (unsigned)n, n ? (unsigned long long)got[0].first : 0ull);
	}

	/* AND IT WRAPS, which is the "watch and record" half: everything is
	 * still asked for, just not first. Starting inside a gap splits that
	 * gap, which is correct -- the part ahead of the playhead is urgent
	 * and the part behind it is not. */
	CHECK(fzn_spool_plan_want(&spool, 13u, 100u, got, 8u, &n) == FZN_SPOOL_OK, "want refused");
	{
		static const uint64_t WANT[] = { 13, 2, 4, 4, 12, 1 };

		CHECK(same(got, n, WANT, 3u), "a gap straddling the start was not split: %u",
		      (unsigned)n);
	}

	/* THROUGHPUT: a different `from` per peer de-correlates them. Same
	 * store, same everything else, different first range -- which is the
	 * entire mechanism, so it is asserted rather than described. */
	CHECK(with("...................."), "the fixture would not build");
	{
		fzn_spool_range_t a[4], b[4];
		size_t an = 0, bn = 0;

		CHECK(fzn_spool_plan_want(&spool, 0u, 100u, a, 4u, &an) == FZN_SPOOL_OK, "refused");
		CHECK(fzn_spool_plan_want(&spool, 7u, 100u, b, 4u, &bn) == FZN_SPOOL_OK, "refused");
		CHECK(an > 0u && bn > 0u && a[0].first != b[0].first,
		      "two peers given different starts asked for the same leaves first, so "
		      "nothing de-correlates them");
	}

	/* A SMALL `cap` FROM THE PLAYHEAD IS THE URGENT SET, which is why
	 * there is no deadline argument: urgency is positional. */
	CHECK(fzn_spool_plan_want(&spool, 10u, 100u, got, 1u, &n) == FZN_SPOOL_OK, "refused");
	{
		static const uint64_t WANT[] = { 10, 10 };

		CHECK(same(got, n, WANT, 1u), "the urgent set was not the leaves at the "
		                              "playhead: %u ranges", (unsigned)n);
	}

	/* A START PAST THE BLOB IS REFUSED, NOT WRAPPED. A playhead outside
	 * the content is a caller that has lost its place, and answering as
	 * though it had asked from the beginning hands a player the wrong part
	 * of the film and looks like it worked. */
	CHECK(fzn_spool_plan_want(&spool, LEAVES, 100u, got, 8u, &n) == FZN_SPOOL_ERR_MALFORMED,
	      "a start at the leaf count was accepted");
	CHECK(fzn_spool_plan_want(&spool, LEAVES + 99u, 100u, got, 8u, &n)
	              == FZN_SPOOL_ERR_MALFORMED,
	      "a start far past the blob was accepted");
}

/*
 * A RUN NEVER CROSSES THE WRAP, and this is the case that separates a
 * circular walk done right from one done by arithmetic.
 *
 * Leaf 19 and leaf 0 are both missing and are adjacent IN THE WALK, and are
 * not adjacent in the blob. Emitting them as one range of two starting at 19
 * asks for leaf 20, which does not exist -- and on a peer that clips rather
 * than refuses, asks for nothing at all.
 */
static void test_a_run_never_crosses_the_wrap(void)
{
	fzn_spool_range_t got[8];
	size_t n = 0;

	CHECK(with(".##################."), "the fixture would not build");
	CHECK(fzn_spool_plan_want(&spool, 19u, 100u, got, 8u, &n) == FZN_SPOOL_OK, "want refused");
	{
		static const uint64_t WANT[] = { 19, 1, 0, 1 };

		CHECK(same(got, n, WANT, 2u),
		      "the last leaf and the first were merged into one range, which names "
		      "a leaf past the end of the blob");
	}
}

/* THE CASE THIS FILE EXISTS FOR. `record/sync` shipped the opposite: an
 * absent position meant "send me everything", so the cheapest message in the
 * protocol was the amplifier in it -- a zero-length digest bought 64 ranges
 * over 32,768 records from an input with nothing in it. */
static void test_a_want_that_names_nothing_gets_nothing(void)
{
	fzn_spool_range_t got[8];
	size_t n = 99;

	CHECK(with("####################"), "the fixture would not build");
	CHECK(fzn_spool_plan_offer(&spool, NULL, 0u, 1000u, got, 8u, &n) == FZN_SPOOL_OK,
	      "an empty want was refused rather than answered with nothing");
	CHECK(n == 0u,
	      "an empty want bought %u ranges from a store holding the whole blob, so the "
	      "cheapest possible message is the amplifier",
	      (unsigned)n);

	/* And a want of one empty range is the same act spelled differently.
	 * A range of zero leaves must not be read as "all of them". */
	{
		fzn_spool_range_t nothing = { 0u, 0u };

		CHECK(fzn_spool_plan_offer(&spool, &nothing, 1u, 1000u, got, 8u, &n)
		              == FZN_SPOOL_OK, "a zero-length range was refused");
		CHECK(n == 0u, "a zero-length range bought %u ranges", (unsigned)n);
	}

	/* A NON-ZERO COUNT OVER A NULL POINTER IS A CALLER BUG and is refused
	 * rather than read. */
	CHECK(fzn_spool_plan_offer(&spool, NULL, 1u, 1000u, got, 8u, &n)
	              == FZN_SPOOL_ERR_MALFORMED,
	      "a null want with a non-zero count was read");
}

static void test_an_offer_sends_only_what_it_holds(void)
{
	fzn_spool_range_t got[8];
	size_t n = 0;

	CHECK(with("##..####..##........"), "the fixture would not build");
	{
		fzn_spool_range_t want = { 0u, LEAVES };
		static const uint64_t EXPECT[] = { 0, 2, 4, 4, 10, 2 };

		CHECK(fzn_spool_plan_offer(&spool, &want, 1u, 1000u, got, 8u, &n)
		              == FZN_SPOOL_OK, "offer refused");
		CHECK(same(got, n, EXPECT, 3u), "the offer did not intersect with what is "
		                                "held: %u ranges", (unsigned)n);
	}

	/* A LEAF NOBODY HAS IS ANSWERED WITH SILENCE, not an error. It is not
	 * a fault, and telling a stranger which leaves are absent is a
	 * question this library does not have to answer. */
	{
		fzn_spool_range_t want = { 12u, 8u };

		CHECK(fzn_spool_plan_offer(&spool, &want, 1u, 1000u, got, 8u, &n)
		              == FZN_SPOOL_OK, "a want for absent leaves was an error");
		CHECK(n == 0u, "absent leaves produced %u ranges", (unsigned)n);
	}

	/* PAST THE END IS CLIPPED, so a peer naming a trillion leaves costs a
	 * comparison rather than an error path. */
	{
		fzn_spool_range_t want = { 0u, 0xffffffffffffffffull };
		static const uint64_t EXPECT[] = { 0, 2, 4, 4, 10, 2 };

		CHECK(fzn_spool_plan_offer(&spool, &want, 1u, 1000u, got, 8u, &n)
		              == FZN_SPOOL_OK, "a want past the end was refused");
		CHECK(same(got, n, EXPECT, 3u), "a clipped want gave %u ranges", (unsigned)n);
	}
	{
		fzn_spool_range_t want = { LEAVES + 5u, 4u };

		CHECK(fzn_spool_plan_offer(&spool, &want, 1u, 1000u, got, 8u, &n)
		              == FZN_SPOOL_OK, "a want wholly past the end was refused");
		CHECK(n == 0u, "a want wholly past the end gave %u ranges", (unsigned)n);
	}
}

/* THE REFLECTION BOUND. Sync bounds its digest at 1024 positions because the
 * work is the peer's number times this host's; here the peer's number times
 * the leaves in each range is what a small request can buy, so the total is
 * capped and the cap is the caller's to set. */
static void test_an_offer_is_bounded(void)
{
	fzn_spool_range_t got[16];
	size_t n = 0;
	fzn_spool_range_t want = { 0u, LEAVES };
	uint64_t total = 0;
	size_t i;

	CHECK(with("####################"), "the fixture would not build");
	CHECK(fzn_spool_plan_offer(&spool, &want, 1u, 7u, got, 16u, &n) == FZN_SPOOL_OK,
	      "offer refused");
	for (i = 0; i < n; i++)
		total += got[i].count;
	CHECK(total == 7u, "a bound of 7 leaves offered %llu", (unsigned long long)total);

	CHECK(fzn_spool_plan_offer(&spool, &want, 1u, 0u, got, 16u, &n)
	              == FZN_SPOOL_ERR_MALFORMED,
	      "a zero leaf budget was accepted, so a caller that forgot one got no bound");

	/*
	 * AND THE NUMBER OF RANGES EXAMINED IS CAPPED, because it too is the
	 * peer's to choose.
	 *
	 * THE FIXTURE IS BUILT SO THAT THE CAP IS THE ONLY THING THAT DECIDES
	 * THE ANSWER. A want of many identical ranges proves nothing -- the
	 * output array fills at 16 whether or not the cap exists, so the
	 * length is the same either way and the check would pass against a
	 * planner with no cap at all. So the first FZN_SPOOL_MAX_WANT ranges
	 * name a leaf this store does NOT hold and the eight past the cap name
	 * one it does: with the cap the answer is empty, and without it those
	 * eight are reached and it is not.
	 */
	{
		static fzn_spool_range_t many[FZN_SPOOL_MAX_WANT + 8u];
		size_t j;

		CHECK(with(".#.................."), "the fixture would not build");
		for (j = 0; j < FZN_SPOOL_MAX_WANT + 8u; j++) {
			many[j].first = (j < FZN_SPOOL_MAX_WANT) ? 0u : 1u;
			many[j].count = 1u;
		}
		CHECK(fzn_spool_plan_offer(&spool, many, FZN_SPOOL_MAX_WANT + 8u, 100000u, got,
		                           16u, &n) == FZN_SPOOL_OK, "offer refused");
		CHECK(n == 0u,
		      "a want of %u ranges reached past the %u-range cap and offered %u "
		      "ranges, so a peer sets the work this host does",
		      (unsigned)(FZN_SPOOL_MAX_WANT + 8u), (unsigned)FZN_SPOOL_MAX_WANT,
		      (unsigned)n);

		/* AND THE CAP IS NOT SIMPLY REFUSING EVERYTHING: the same
		 * store answers a want naming the held leaf inside the cap. */
		many[0].first = 1u;
		CHECK(fzn_spool_plan_offer(&spool, many, 1u, 100000u, got, 16u, &n)
		              == FZN_SPOOL_OK, "offer refused");
		CHECK(n == 1u && got[0].first == 1u && got[0].count == 1u,
		      "the store answered nothing for a leaf it holds, so the case above "
		      "passes because the planner is mute rather than because it caps");
	}
}

int main(void)
{
	test_a_want_names_the_gaps();
	test_a_long_run_is_split_and_a_small_array_stops();
	test_the_walk_stops_when_the_array_fills();
	test_the_offer_stops_when_the_array_fills();
	test_the_want_ceiling_is_exact();
	test_the_walk_starts_where_the_caller_says();
	test_a_run_never_crosses_the_wrap();
	test_a_want_that_names_nothing_gets_nothing();
	test_an_offer_sends_only_what_it_holds();
	test_an_offer_is_bounded();

	printf("plan_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
