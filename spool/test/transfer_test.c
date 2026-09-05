/* Tests for spool/transfer.c.
 *
 * THE TWO-PEER TEST IS WHY THIS FILE EXISTS. Every other case here can be
 * written with one peer and would pass against a transfer that records
 * nothing -- project.md sec 107 has fuzzypickles' measurement of exactly
 * that, a suite with two correctly-named tests for the property and no
 * peer count that could observe it.
 *
 * Their two fixture details are followed literally, because both are about
 * whether the fixture reaches the branch rather than whether the assertion
 * is right:
 *
 *   - THE WINDOW MUST BE OPENED FIRST. It starts at one, so a second ask is
 *     refused for a WINDOW reason and never reaches the assignment question.
 *     One clean batch and a delivery first, then ask twice.
 *   - NOTHING MAY DIFFER BETWEEN THE TWO PEERS but identity. Same `from`,
 *     same granularity, same store -- so the pending record is the only
 *     thing that can produce two different answers.
 *
 * The third detail is this tree's own and cost an API change: an internal
 * cursor advancing past each assignment would ALSO produce disjoint ranges,
 * so the test passed with the pending record removed. `from` is the
 * caller's now and transfer.h says why.
 */

#include "../transfer.h"

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
	fprintf(stderr, "  FAIL transfer_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

/* ---- the fixture: a real blob, so `delivered` can be verified ---------- */

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

#define LEAVES 16u
#define SLOTS 8u

static uint8_t sealed[LEAVES][FZN_BLOB_SEALED_MAX];
static size_t sealed_len[LEAVES];
static uint8_t leaf_hash[LEAVES][FZN_BLOB_HASH_LEN];
static uint8_t root[FZN_BLOB_HASH_LEN];
static uint8_t proof[LEAVES][FZN_BLOB_MAX_DEPTH * FZN_BLOB_HASH_LEN];
static unsigned proof_len[LEAVES];

static int build_blob(void)
{
	fzn_blob_tree_t tree;
	unsigned i;

	fzn_blob_tree_init(&tree);
	for (i = 0; i < LEAVES; i++) {
		size_t j;

		sealed_len[i] = 48u + i * 3u;
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
	for (i = 0; i < LEAVES; i++) {
		if (fzn_blob_proof_build(&HASH, leaf_hash[0], LEAVES, i, proof[i],
		                         sizeof(proof[i]), &proof_len[i]) != FZN_BLOB_OK)
			return 0;
	}
	return 1;
}

static uint8_t disk[LEAVES * FZN_BLOB_SEALED_MAX];

static int disk_read(void *c, uint64_t o, uint8_t *b, size_t n)
{
	(void)c;
	if (o + n > sizeof(disk))
		return 0;
	memcpy(b, disk + o, n);
	return 1;
}

static int disk_write(void *c, uint64_t o, const uint8_t *b, size_t n)
{
	(void)c;
	if (o + n > sizeof(disk))
		return 0;
	memcpy(disk + o, b, n);
	return 1;
}

static const fzn_spool_ops_t OPS = { disk_read, disk_write, NULL, NULL };

static fzn_spool_t spool;
static uint8_t map[FZN_SPOOL_BITMAP_LEN(LEAVES)];
static fzn_transfer_assign_t slots[SLOTS];
static fzn_transfer_t transfer;

/* A fresh, empty transfer over a fresh, empty spool. */
static int fresh(size_t cap)
{
	memset(map, 0, sizeof(map));
	memset(disk, 0, sizeof(disk));
	if (fzn_spool_open(&spool, root, LEAVES, map, sizeof(map), &OPS) != FZN_SPOOL_OK)
		return 0;
	return fzn_transfer_open(&transfer, &spool, slots, cap) == FZN_TRANSFER_OK;
}

/* Places a range for real, so the store genuinely holds it. */
static int place(uint64_t first, uint64_t count)
{
	uint64_t i;

	for (i = 0; i < count; i++) {
		if (fzn_spool_place(&spool, &HASH, first + i, sealed[first + i],
		                    sealed_len[first + i], proof[first + i],
		                    proof_len[first + i]) != FZN_SPOOL_OK)
			return 0;
	}
	return 1;
}

/* One clean batch, placed and acknowledged. The window is 1 on a fresh
 * transfer, so this is what makes a second ask reach the assignment
 * question instead of being refused for a window reason. */
static int open_the_window(void)
{
	fzn_spool_range_t got;

	if (fzn_transfer_next_want(&transfer, 1u, 0u, 2u, 100u, &got) != FZN_TRANSFER_OK)
		return 0;
	if (!place(got.first, got.count))
		return 0;
	if (fzn_transfer_delivered(&transfer, 1u, got.first, got.count) != FZN_TRANSFER_OK)
		return 0;
	return fzn_transfer_window(&transfer) >= 2u;
}

/* ---- the one that needs two peers -------------------------------------- */

static void test_two_peers_on_one_transfer_get_disjoint_work(void)
{
	fzn_spool_range_t a, b;

	CHECK(fresh(SLOTS), "the fixture did not open");
	CHECK(open_the_window(), "the window did not open, so the second ask is refused early");
	CHECK(fzn_transfer_window(&transfer) >= 2u, "the window is %u, so this test cannot ask twice",
	      fzn_transfer_window(&transfer));

	/* Identical in everything but the peer number. */
	CHECK(fzn_transfer_next_want(&transfer, 7u, 0u, 2u, 100u, &a) == FZN_TRANSFER_OK,
	      "the first peer got nothing");
	CHECK(fzn_transfer_next_want(&transfer, 9u, 0u, 2u, 100u, &b) == FZN_TRANSFER_OK,
	      "the second peer got nothing");

	CHECK(!(a.first == b.first && a.count == b.count),
	      "both peers were handed %llu+%llu -- the assignment was not recorded",
	      (unsigned long long)a.first, (unsigned long long)a.count);
	CHECK(a.first + a.count <= b.first || b.first + b.count <= a.first,
	      "the ranges overlap: %llu+%llu and %llu+%llu",
	      (unsigned long long)a.first, (unsigned long long)a.count,
	      (unsigned long long)b.first, (unsigned long long)b.count);
	CHECK(fzn_transfer_in_flight(&transfer) == 2u, "%zu in flight, not 2",
	      fzn_transfer_in_flight(&transfer));
}

/* And the same question after a peer goes quiet: the range must come back
 * to somebody. One peer suffices HERE because what is under test is the
 * drop rather than the exclusion. */
static void test_an_abandoned_range_returns_to_the_want_list(void)
{
	fzn_spool_range_t first, again;

	CHECK(fresh(SLOTS), "the fixture did not open");
	CHECK(fzn_transfer_next_want(&transfer, 3u, 0u, 2u, 100u, &first) == FZN_TRANSFER_OK,
	      "the first ask got nothing");
	CHECK(fzn_transfer_failed(&transfer, 3u, first.first, first.count) == FZN_TRANSFER_OK,
	      "the failure was not accepted");
	CHECK(fzn_transfer_in_flight(&transfer) == 0u, "the slot was not freed");

	CHECK(fzn_transfer_next_want(&transfer, 4u, 0u, 2u, 100u, &again) == FZN_TRANSFER_OK,
	      "the abandoned range was not offered again");
	CHECK(again.first == first.first && again.count == first.count,
	      "a different range came back: %llu+%llu, not %llu+%llu",
	      (unsigned long long)again.first, (unsigned long long)again.count,
	      (unsigned long long)first.first, (unsigned long long)first.count);
}

/* NONE DOES NOT MEAN COMPLETE, and a caller that reads it as "done" stalls
 * with the blob unfinished and a peer holding every missing byte.
 *
 * fuzzypickles shipped exactly this and reported it 2026-09-05: their driver
 * was correct throughout and answered "nothing left to ask this peer for"
 * because everything missing was marked as already asked. What made it
 * invisible was that no fixture in their tree had ever put more in flight
 * than the opening burst -- the whole suite sat on one side of a threshold
 * nobody had named.
 *
 * The arrangement here is the smallest one where the question exists: a
 * window wider than the free ranges left, so every candidate is pending and
 * `next_want` correctly refuses. `expire` is the only thing that gets the
 * range back, which is what makes the distinction between NONE and FULL
 * load-bearing rather than cosmetic. */
static void test_none_is_not_completion_and_expiry_is_the_way_out(void)
{
	fzn_spool_range_t got, again;
	uint64_t i;

	CHECK(fresh(2u), "the fixture did not open");

	/* One clean batch of eight, which opens the window to two. */
	CHECK(fzn_transfer_next_want(&transfer, 1u, 0u, 8u, 100u, &got) == FZN_TRANSFER_OK,
	      "the first ask was refused");
	CHECK(got.count == 8u, "the first range is %llu leaves, not 8",
	      (unsigned long long)got.count);
	for (i = 0; i < got.count; i++)
		CHECK(fzn_spool_place(&spool, &HASH, got.first + i, sealed[got.first + i],
		                      sealed_len[got.first + i], proof[got.first + i],
		                      proof_len[got.first + i]) == FZN_SPOOL_OK,
		      "placing leaf %llu failed", (unsigned long long)(got.first + i));
	CHECK(fzn_transfer_delivered(&transfer, 1u, got.first, got.count) == FZN_TRANSFER_OK,
	      "the delivery was refused");
	CHECK(fzn_transfer_window(&transfer) == 2u, "the window is %u, not 2",
	      fzn_transfer_window(&transfer));

	/* The remaining half, asked for and outstanding. */
	CHECK(fzn_transfer_next_want(&transfer, 1u, 0u, 8u, 50u, &got) == FZN_TRANSFER_OK,
	      "the second ask was refused");
	CHECK(fzn_transfer_in_flight(&transfer) == 1u, "%zu in flight, not 1",
	      fzn_transfer_in_flight(&transfer));

	/* THE TRAP. The window has room, so this is not FULL; every range that
	 * remains is assigned, so it is NONE -- and the blob is not done. */
	CHECK(fzn_transfer_next_want(&transfer, 2u, 0u, 8u, 50u, &again) == FZN_TRANSFER_NONE,
	      "a range already assigned was handed to a second peer");
	CHECK(!fzn_spool_complete(&spool),
	      "the fixture is complete, so NONE here would be honest and this case is vacuous");
	CHECK(fzn_transfer_in_flight(&transfer) == 1u, "the refused ask changed what is in flight");

	/* And the way out is the deadline, not another ask. */
	CHECK(fzn_transfer_expire(&transfer, 49u) == 0u, "an early expiry dropped something");
	CHECK(fzn_transfer_next_want(&transfer, 2u, 0u, 8u, 100u, &again) == FZN_TRANSFER_NONE,
	      "the range came back before its deadline");
	CHECK(fzn_transfer_expire(&transfer, 50u) == 1u, "the stalled range was not dropped");
	CHECK(fzn_transfer_next_want(&transfer, 2u, 0u, 8u, 100u, &again) == FZN_TRANSFER_OK,
	      "the abandoned range was not offered to the second peer");
	CHECK(again.first == got.first && again.count == got.count,
	      "a different range came back: %llu+%llu, not %llu+%llu",
	      (unsigned long long)again.first, (unsigned long long)again.count,
	      (unsigned long long)got.first, (unsigned long long)got.count);
}

/* ---- the window -------------------------------------------------------- */

static void test_the_window_starts_at_one_and_refuses_a_second_ask(void)
{
	fzn_spool_range_t got;

	CHECK(fresh(SLOTS), "the fixture did not open");
	CHECK(fzn_transfer_window(&transfer) == 1u, "the window starts at %u, not 1",
	      fzn_transfer_window(&transfer));
	CHECK(fzn_transfer_next_want(&transfer, 1u, 0u, 2u, 100u, &got) == FZN_TRANSFER_OK,
	      "the first ask was refused");
	CHECK(fzn_transfer_next_want(&transfer, 2u, 0u, 2u, 100u, &got) == FZN_TRANSFER_FULL,
	      "a second ask was allowed with the window at one");
}

/* ONE PER WINDOW OF SUCCESSES, NOT ONE PER SUCCESS. The difference is slow
 * start, which this deliberately does not do, and the two are
 * indistinguishable at window one -- so the case has to run past it. */
static void test_the_window_opens_once_per_window_of_successes(void)
{
	fzn_spool_range_t got;
	unsigned before;
	int step;

	CHECK(fresh(SLOTS), "the fixture did not open");
	CHECK(open_the_window(), "the window did not open");
	CHECK(fzn_transfer_window(&transfer) == 2u, "one success took the window to %u, not 2",
	      fzn_transfer_window(&transfer));

	/* At window 2 it must take TWO successes to reach 3. */
	before = fzn_transfer_window(&transfer);
	for (step = 0; step < 2; step++) {
		CHECK(fzn_transfer_next_want(&transfer, 5u, 0u, 2u, 100u, &got) == FZN_TRANSFER_OK,
		      "ask %d was refused", step);
		CHECK(place(got.first, got.count), "placing %llu+%llu failed",
		      (unsigned long long)got.first, (unsigned long long)got.count);
		CHECK(fzn_transfer_delivered(&transfer, 5u, got.first, got.count)
		              == FZN_TRANSFER_OK,
		      "delivery %d was refused", step);
		if (step == 0)
			CHECK(fzn_transfer_window(&transfer) == before,
			      "one success at window %u opened it to %u -- that is slow start",
			      before, fzn_transfer_window(&transfer));
	}
	CHECK(fzn_transfer_window(&transfer) == before + 1u,
	      "two successes at window %u gave %u, not %u", before,
	      fzn_transfer_window(&transfer), before + 1u);
}

static void test_the_window_halves_and_never_reaches_zero(void)
{
	fzn_spool_range_t got;
	int i;

	CHECK(fresh(SLOTS), "the fixture did not open");
	/* Open it to 4 the honest way: 1 success to 2, then 2 more to 3, then
	 * 3 more to 4. */
	for (i = 0; i < 6; i++) {
		if (fzn_transfer_next_want(&transfer, 1u, 0u, 1u, 100u, &got) != FZN_TRANSFER_OK)
			break;
		if (!place(got.first, got.count))
			break;
		if (fzn_transfer_delivered(&transfer, 1u, got.first, got.count)
		    != FZN_TRANSFER_OK)
			break;
	}
	CHECK(fzn_transfer_window(&transfer) == 4u, "six successes gave a window of %u, not 4",
	      fzn_transfer_window(&transfer));

	CHECK(fzn_transfer_next_want(&transfer, 1u, 0u, 1u, 100u, &got) == FZN_TRANSFER_OK,
	      "the ask before the loss was refused");
	CHECK(fzn_transfer_failed(&transfer, 1u, got.first, got.count) == FZN_TRANSFER_OK,
	      "the loss was not accepted");
	CHECK(fzn_transfer_window(&transfer) == 2u, "4 halved to %u, not 2",
	      fzn_transfer_window(&transfer));

	/* Down to the floor, and it must stop there rather than reaching zero:
	 * a transfer that can ask for nothing can never learn the path came
	 * back. */
	for (i = 0; i < 4; i++) {
		if (fzn_transfer_next_want(&transfer, 1u, 0u, 1u, 100u, &got) != FZN_TRANSFER_OK)
			break;
		(void)fzn_transfer_failed(&transfer, 1u, got.first, got.count);
	}
	CHECK(fzn_transfer_window(&transfer) == 1u, "the window bottomed out at %u, not 1",
	      fzn_transfer_window(&transfer));
	CHECK(fzn_transfer_next_want(&transfer, 1u, 0u, 1u, 100u, &got) == FZN_TRANSFER_OK,
	      "a transfer at the floor could not ask for anything");
}

/* ONE DECREASE PER LOSS EVENT. A stalled peer holding four batches is one
 * failure; charging four would put the window on the floor for a single
 * event, which is what AIMD exists to avoid. */
static void test_expiry_costs_one_halving_however_many_it_drops(void)
{
	fzn_spool_range_t got;
	int i;
	size_t dropped;

	CHECK(fresh(SLOTS), "the fixture did not open");
	for (i = 0; i < 6; i++) {
		if (fzn_transfer_next_want(&transfer, 1u, 0u, 1u, 100u, &got) != FZN_TRANSFER_OK)
			break;
		if (!place(got.first, got.count))
			break;
		(void)fzn_transfer_delivered(&transfer, 1u, got.first, got.count);
	}
	CHECK(fzn_transfer_window(&transfer) == 4u, "the window is %u, not 4",
	      fzn_transfer_window(&transfer));

	for (i = 0; i < 4; i++)
		CHECK(fzn_transfer_next_want(&transfer, 2u, 0u, 1u, 50u, &got) == FZN_TRANSFER_OK,
		      "ask %d before the stall was refused", i);
	CHECK(fzn_transfer_in_flight(&transfer) == 4u, "%zu in flight, not 4",
	      fzn_transfer_in_flight(&transfer));

	CHECK(fzn_transfer_expire(&transfer, 49u) == 0u, "a deadline in the future expired");
	CHECK(fzn_transfer_in_flight(&transfer) == 4u, "an early expiry dropped something");
	CHECK(fzn_transfer_window(&transfer) == 4u, "an early expiry moved the window");

	dropped = fzn_transfer_expire(&transfer, 50u);
	CHECK(dropped == 4u, "%zu dropped, not 4", dropped);
	CHECK(fzn_transfer_in_flight(&transfer) == 0u, "%zu still in flight",
	      fzn_transfer_in_flight(&transfer));
	CHECK(fzn_transfer_window(&transfer) == 2u,
	      "four expiries took the window to %u -- that is four halvings, not one",
	      fzn_transfer_window(&transfer));
}

/* ---- the refusals ------------------------------------------------------ */

/* Congestion control must not open on work that did not happen. This is the
 * REFUSE arm of the store check, which is the arm a suite full of honest
 * callers never exercises. */
static void test_delivery_is_verified_against_the_store(void)
{
	fzn_spool_range_t got;
	unsigned window_before;

	CHECK(fresh(SLOTS), "the fixture did not open");
	CHECK(fzn_transfer_next_want(&transfer, 1u, 0u, 2u, 100u, &got) == FZN_TRANSFER_OK,
	      "the ask was refused");
	window_before = fzn_transfer_window(&transfer);

	/* Claimed without placing anything. */
	CHECK(fzn_transfer_delivered(&transfer, 1u, got.first, got.count)
	              == FZN_TRANSFER_ERR_UNKNOWN,
	      "a delivery the store cannot confirm was accepted");
	CHECK(fzn_transfer_in_flight(&transfer) == 1u,
	      "a refused delivery freed the slot anyway");
	CHECK(fzn_transfer_window(&transfer) == window_before,
	      "a refused delivery opened the window from %u to %u", window_before,
	      fzn_transfer_window(&transfer));

	/* And a PARTIAL placement is still not a delivery -- the case that
	 * separates a real check from one that samples the first leaf. */
	CHECK(place(got.first, 1u), "placing one leaf failed");
	CHECK(fzn_transfer_delivered(&transfer, 1u, got.first, got.count)
	              == FZN_TRANSFER_ERR_UNKNOWN,
	      "a partially placed range was accepted as delivered");

	CHECK(place(got.first, got.count), "placing the rest failed");
	CHECK(fzn_transfer_delivered(&transfer, 1u, got.first, got.count) == FZN_TRANSFER_OK,
	      "a genuine delivery was refused");
}

static void test_an_answer_naming_no_assignment_is_refused(void)
{
	fzn_spool_range_t got;

	CHECK(fresh(SLOTS), "the fixture did not open");
	CHECK(fzn_transfer_next_want(&transfer, 1u, 0u, 2u, 100u, &got) == FZN_TRANSFER_OK,
	      "the ask was refused");

	/* The right range from the wrong peer. */
	CHECK(fzn_transfer_delivered(&transfer, 2u, got.first, got.count)
	              == FZN_TRANSFER_ERR_UNKNOWN,
	      "a peer answered for an assignment it was never given");
	CHECK(fzn_transfer_failed(&transfer, 2u, got.first, got.count) == FZN_TRANSFER_ERR_UNKNOWN,
	      "a peer failed an assignment it was never given");
	/* The right peer, a range it was not asked for. */
	CHECK(fzn_transfer_failed(&transfer, 1u, got.first + 1u, got.count)
	              == FZN_TRANSFER_ERR_UNKNOWN,
	      "a peer failed a range it was not asked for");
	CHECK(fzn_transfer_in_flight(&transfer) == 1u, "a refused answer freed a slot");
}

static void test_a_complete_blob_asks_for_nothing(void)
{
	fzn_spool_range_t got;

	CHECK(fresh(SLOTS), "the fixture did not open");
	CHECK(place(0u, LEAVES), "filling the blob failed");
	CHECK(fzn_spool_complete(&spool), "the fixture is not complete");
	CHECK(fzn_transfer_next_want(&transfer, 1u, 0u, 2u, 100u, &got) == FZN_TRANSFER_NONE,
	      "a complete blob still wanted something");
}

static void test_every_guard_refuses_its_own_argument(void)
{
	fzn_spool_range_t got;
	fzn_spool_t empty;

	CHECK(fzn_transfer_open(NULL, &spool, slots, SLOTS) == FZN_TRANSFER_ERR_MALFORMED,
	      "open took a null transfer");
	CHECK(fzn_transfer_open(&transfer, NULL, slots, SLOTS) == FZN_TRANSFER_ERR_MALFORMED,
	      "open took a null spool");
	CHECK(fzn_transfer_open(&transfer, &spool, NULL, SLOTS) == FZN_TRANSFER_ERR_MALFORMED,
	      "open took a null slot array");
	CHECK(fzn_transfer_open(&transfer, &spool, slots, 0u) == FZN_TRANSFER_ERR_MALFORMED,
	      "open took a zero capacity");
	CHECK(fzn_transfer_open(&transfer, &spool, slots, (size_t)FZN_TRANSFER_MAX_SLOTS + 1u)
	              == FZN_TRANSFER_ERR_MALFORMED,
	      "open took a capacity past the ceiling");

	memset(&empty, 0, sizeof(empty));
	CHECK(fzn_transfer_open(&transfer, &empty, slots, SLOTS) == FZN_TRANSFER_ERR_MALFORMED,
	      "open took a spool that was never opened");

	CHECK(fresh(SLOTS), "the fixture did not open");
	CHECK(fzn_transfer_next_want(&transfer, 1u, 0u, 0u, 100u, &got)
	              == FZN_TRANSFER_ERR_MALFORMED,
	      "a zero granularity was read as no bound");
	CHECK(fzn_transfer_next_want(&transfer, 1u, 0u, 2u, 100u, NULL)
	              == FZN_TRANSFER_ERR_MALFORMED,
	      "next_want took a null out");
	CHECK(fzn_transfer_window(NULL) == 0u, "window took a null transfer");
	CHECK(fzn_transfer_in_flight(NULL) == 0u, "in_flight took a null transfer");
	CHECK(fzn_transfer_expire(NULL, 1u) == 0u, "expire took a null transfer");
	CHECK(fzn_transfer_err_str(FZN_TRANSFER_NONE) != NULL, "err_str returned null");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	CHECK(0, "deliberate");
	if (failures == before + 1) {
		failures = before;
		return;
	}
	fprintf(stderr, "  the positive control did not register\n");
	failures = before + 1;
}

int main(void)
{
	if (!build_blob()) {
		fprintf(stderr, "transfer_test: the fixture did not build\n");
		return 1;
	}

	test_two_peers_on_one_transfer_get_disjoint_work();
	test_an_abandoned_range_returns_to_the_want_list();
	test_none_is_not_completion_and_expiry_is_the_way_out();
	test_the_window_starts_at_one_and_refuses_a_second_ask();
	test_the_window_opens_once_per_window_of_successes();
	test_the_window_halves_and_never_reaches_zero();
	test_expiry_costs_one_halving_however_many_it_drops();
	test_delivery_is_verified_against_the_store();
	test_an_answer_naming_no_assignment_is_refused();
	test_a_complete_blob_asks_for_nothing();
	test_every_guard_refuses_its_own_argument();
	test_the_suite_can_tell_pass_from_fail();

	printf("transfer_test: %d checks, %d failures\n", checks, failures);
	return failures != 0;
}
