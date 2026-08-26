/* The hop budget, and the fact that it is not authenticated.
 *
 * Every case here exists because the budget is attacker-controlled: it sits
 * before the tag's coverage, necessarily, since a relay decrements it. So the
 * tests are about what a host does with a number a stranger may have written,
 * and the important one is the inflated budget -- trusting it turns one
 * datagram into an amplifier.
 */

#include "../relay.h"

#include "frame.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void expect(int ok, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL: %s\n", what);
	}
}

static void expect_err(fzn_relay_err_t got, fzn_relay_err_t want, const char *what)
{
	checks++;
	if (got != want) {
		failures++;
		printf("  FAIL: %s -- got \"%s\", wanted \"%s\"\n", what, fzn_relay_err_str(got),
		       fzn_relay_err_str(want));
	}
}

/* The hop header is five bytes: version, hops_left, three reserved zeroes. */
static void build(uint8_t *frame, size_t len, uint8_t version, uint8_t hops)
{
	memset(frame, 0, len);
	frame[0] = version;
	frame[1] = hops;
}

int main(void)
{
	uint8_t frame[SITU_FZN_FRAME_SIZE_MIN];
	uint8_t budget;

	/* An ordinary frame. */
	build(frame, sizeof(frame), 1, 4);
	expect_err(fzn_relay_budget(frame, sizeof(frame), FZN_RELAY_MAX_HOPS, &budget),
	           FZN_RELAY_OK, "reading an ordinary budget");
	expect(budget == 4, "which is what the frame says");

	/* THE CLAMP, which is the whole security content. A stranger can write
	 * 255 into a frame it did not create; believing it turns one datagram
	 * into as many forwards as the network has paths. */
	build(frame, sizeof(frame), 1, 255);
	expect_err(fzn_relay_budget(frame, sizeof(frame), FZN_RELAY_MAX_HOPS, &budget),
	           FZN_RELAY_OK, "reading an inflated budget");
	expect(budget == FZN_RELAY_MAX_HOPS, "an inflated budget must be clamped, not believed");

	/* A host with a tighter ceiling gets its own. */
	expect_err(fzn_relay_budget(frame, sizeof(frame), 2, &budget), FZN_RELAY_OK,
	           "a host with its own ceiling");
	expect(budget == 2, "which must be honoured over the library default");

	/* SPENDING. The clamped value goes back, so an amplifier is cut at the
	 * first honest host rather than surviving to the last. */
	build(frame, sizeof(frame), 1, 255);
	expect_err(fzn_relay_spend(frame, sizeof(frame), FZN_RELAY_MAX_HOPS), FZN_RELAY_OK,
	           "spending a hop of an inflated budget");
	expect(frame[1] == FZN_RELAY_MAX_HOPS - 1u,
	       "the frame must leave with a believable budget, not a decremented lie");

	build(frame, sizeof(frame), 1, 3);
	expect_err(fzn_relay_spend(frame, sizeof(frame), FZN_RELAY_MAX_HOPS), FZN_RELAY_OK,
	           "spending an ordinary hop");
	expect(frame[1] == 2, "which decrements by exactly one");

	/* EXHAUSTION LEAVES THE FRAME ALONE, so a caller that ignores the
	 * return value forwards what it received rather than something worse. */
	build(frame, sizeof(frame), 1, 0);
	expect_err(fzn_relay_spend(frame, sizeof(frame), FZN_RELAY_MAX_HOPS),
	           FZN_RELAY_ERR_EXHAUSTED, "spending a spent budget");
	expect(frame[1] == 0, "a refused spend must not have altered the frame");

	build(frame, sizeof(frame), 1, 1);
	expect_err(fzn_relay_spend(frame, sizeof(frame), FZN_RELAY_MAX_HOPS), FZN_RELAY_OK,
	           "the last hop");
	expect(frame[1] == 0, "leaves nothing");
	expect_err(fzn_relay_spend(frame, sizeof(frame), FZN_RELAY_MAX_HOPS),
	           FZN_RELAY_ERR_EXHAUSTED, "and the next is refused");

	/* A ceiling of zero means this host forwards nothing, which is a
	 * legitimate configuration and must not be mistaken for an error. */
	build(frame, sizeof(frame), 1, 5);
	expect_err(fzn_relay_budget(frame, sizeof(frame), 0, &budget), FZN_RELAY_OK,
	           "a host that relays nothing");
	expect(budget == 0, "reports no budget");
	expect_err(fzn_relay_spend(frame, sizeof(frame), 0), FZN_RELAY_ERR_EXHAUSTED,
	           "and refuses to forward");
	expect(frame[1] == 5, "without touching the frame");

	/* SHAPE. An unknown version is refused: a relay forwarding one would be
	 * moving bytes it cannot reason about at all. */
	build(frame, sizeof(frame), 2, 4);
	expect_err(fzn_relay_budget(frame, sizeof(frame), FZN_RELAY_MAX_HOPS, &budget),
	           FZN_RELAY_ERR_SHAPE, "a frame of an unknown version");

	/* Reserved bytes must be zero, and the hop validator says so. */
	build(frame, sizeof(frame), 1, 4);
	frame[3] = 0x7f;
	expect_err(fzn_relay_budget(frame, sizeof(frame), FZN_RELAY_MAX_HOPS, &budget),
	           FZN_RELAY_ERR_SHAPE, "a frame with a non-zero reserved byte");

	build(frame, sizeof(frame), 1, 4);
	expect_err(fzn_relay_budget(frame, 2, FZN_RELAY_MAX_HOPS, &budget), FZN_RELAY_ERR_SHAPE,
	           "something too short to hold a hop header");

	/* Arguments. */
	expect_err(fzn_relay_budget(NULL, sizeof(frame), FZN_RELAY_MAX_HOPS, &budget),
	           FZN_RELAY_ERR_MALFORMED, "a null frame");
	expect_err(fzn_relay_budget(frame, sizeof(frame), FZN_RELAY_MAX_HOPS, NULL),
	           FZN_RELAY_ERR_MALFORMED, "nowhere to answer");
	expect_err(fzn_relay_spend(NULL, sizeof(frame), FZN_RELAY_MAX_HOPS),
	           FZN_RELAY_ERR_MALFORMED, "spending from a null frame");

	printf("relay_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
