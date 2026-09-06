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

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void expect_at(int ok, int line, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		fprintf(stderr, "  FAIL relay_test.c:%d: %s\n", line, what);
	}
}

#define expect(ok, what) expect_at((ok) ? 1 : 0, __LINE__, (what))

static void expect_err(fzn_relay_err_t got, fzn_relay_err_t want, const char *what)
{
	checks++;
	if (got != want) {
		failures++;
		fprintf(stderr, "  FAIL relay_test.c: %s -- got \"%s\", wanted \"%s\"\n", what, fzn_relay_err_str(got),
		       fzn_relay_err_str(want));
	}
}

/* The hop header is five bytes: version, hops_left, a big-endian u16 service
 * hint, one reserved zero. The hint was two of three reserved bytes until
 * sec 153, which is why every frame built before it parses as unhinted. */
static void build(uint8_t *frame, size_t len, uint8_t version, uint8_t hops)
{
	memset(frame, 0, len);
	frame[0] = version;
	frame[1] = hops;
}

static void build_hinted(uint8_t *frame, size_t len, uint8_t hops, uint16_t service)
{
	build(frame, len, 1, hops);
	/* Written as bytes rather than through the generated setter, so the
	 * test states the wire position instead of agreeing with the accessor
	 * about it. An accessor that moved would still agree with itself. */
	frame[2] = (uint8_t)(service >> 8);
	frame[3] = (uint8_t)(service & 0xffu);
}

int main(void)
{
	uint8_t frame[SITU_FZN_FRAME_SIZE_MIN];
	uint8_t budget;
	uint16_t service;

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

	/* THE RESERVED BYTE THAT IS LEFT must still be zero, and the hop
	 * validator still says so. It is byte 4 now; bytes 2 and 3 became the
	 * service hint in sec 153, and the case below asserts that they are no
	 * longer refused -- which is the half that would go untested if this
	 * one were merely moved. */
	build(frame, sizeof(frame), 1, 4);
	frame[4] = 0x7f;
	expect_err(fzn_relay_budget(frame, sizeof(frame), FZN_RELAY_MAX_HOPS, &budget),
	           FZN_RELAY_ERR_SHAPE, "a frame with a non-zero reserved byte");

	/* AND THE TWO BYTES THAT STOPPED BEING RESERVED must now be accepted.
	 * Byte 3 refused before sec 153 and carries the hint's low half now, so
	 * a validator that had not been regenerated would refuse every hinted
	 * frame -- silently, since a refusal to relay looks like a policy. */
	build(frame, sizeof(frame), 1, 4);
	frame[2] = 0x7f;
	frame[3] = 0x7f;
	expect_err(fzn_relay_budget(frame, sizeof(frame), FZN_RELAY_MAX_HOPS, &budget),
	           FZN_RELAY_OK, "a hinted frame is not malformed");

	build(frame, sizeof(frame), 1, 4);
	expect_err(fzn_relay_budget(frame, 2, FZN_RELAY_MAX_HOPS, &budget), FZN_RELAY_ERR_SHAPE,
	           "something too short to hold a hop header");

	/* A LENGTH THAT DOES NOT SURVIVE THE CAST, which is the guard nothing
	 * here reached.
	 *
	 * `situ_msg_init` takes a `uint32_t`, so a `size_t` length above
	 * UINT32_MAX truncates on the way in. Every bounds check downstream is
	 * then computed against a number that is not the buffer's length.
	 * Measured 2026-09-03: deleting the guard left the whole suite green,
	 * because no case in the tree ever passed a length above UINT32_MAX.
	 *
	 * THE BUFFER IS REAL AND THE LENGTH IS THE LIE, so a sabotaged run
	 * reads only bytes this frame actually has -- the truncated value is
	 * `sizeof(frame)`, a length the frame genuinely is. So without the
	 * guard the call SUCCEEDS and hands back a budget, which is the
	 * failure. A case that instead crashed would be measuring the
	 * sanitizer.
	 *
	 * Guarded on the model, because the cast is lossless where `size_t` is
	 * 32 bits and there is then nothing here to test. */
#if SIZE_MAX > UINT32_MAX
	build(frame, sizeof(frame), 1, 4);
	budget = 0xeeu;
	expect_err(fzn_relay_budget(frame, ((size_t)UINT32_MAX + 1u) + sizeof(frame),
	                            FZN_RELAY_MAX_HOPS, &budget),
	           FZN_RELAY_ERR_SHAPE,
	           "a length past what the message header can hold was truncated rather "
	           "than refused");
	expect(budget == 0xeeu, "and the refusal wrote no budget");
#endif

	/* ---------------------------------------------------------------
	 * THE SUBSYSTEM HINT, sec 153.
	 *
	 * A relay cannot open a frame, so the service in the capability -- the
	 * only authoritative one -- is unreadable to it. The hint is what a
	 * per-subsystem policy reads, and every case below is about the fact
	 * that it is a CLAIM: unauthenticated, sender-written, and worth
	 * exactly the relay's own budget.
	 */

	/* Read back big-endian, from the bytes rather than the accessor. */
	build_hinted(frame, sizeof(frame), 4, 0x1234u);
	expect_err(fzn_relay_service(frame, sizeof(frame), &service), FZN_RELAY_OK,
	           "reading a hint");
	expect(service == 0x1234u, "the hint is a big-endian u16 at offset 2");

	/* A FRAME BUILT BEFORE THE FIELD EXISTED reads as unclassified. This is
	 * the whole of the compatibility claim: those bytes were reserved and
	 * must_be_zero, so every frame ever written has zeros there. */
	build(frame, sizeof(frame), 1, 4);
	service = 0xeeeeu;
	expect_err(fzn_relay_service(frame, sizeof(frame), &service), FZN_RELAY_OK,
	           "reading an unhinted frame");
	expect(service == FZN_RELAY_SERVICE_NONE,
	       "an old frame's zeroes must mean unclassified, not a service");

	/* THE POLICY. First match wins, and the matched ceiling clamps exactly
	 * as `allowed` does. */
	{
		const fzn_relay_policy_t policy[] = {
			{ 7u, 2u },      /* a subsystem this host carries barely */
			{ 9u, 6u },      /* one it carries further */
			{ 7u, 8u },      /* shadowed: first match wins */
			{ FZN_RELAY_SERVICE_NONE, 1u }, /* unclassified traffic */
		};
		const size_t n = sizeof(policy) / sizeof(policy[0]);

		build_hinted(frame, sizeof(frame), 255, 7u);
		expect_err(fzn_relay_budget_policy(frame, sizeof(frame), policy, n, 4u, &budget),
		           FZN_RELAY_OK, "a hinted frame against a policy");
		expect(budget == 2u, "the matched ceiling clamps an inflated budget");

		build_hinted(frame, sizeof(frame), 255, 9u);
		expect_err(fzn_relay_budget_policy(frame, sizeof(frame), policy, n, 4u, &budget),
		           FZN_RELAY_OK, "a different subsystem");
		expect(budget == 6u, "gets its own ceiling");

		/* A SUBSYSTEM THE TABLE DOES NOT NAME takes the fallback, which
		 * is how a host says what it does about traffic it has no
		 * opinion on. */
		build_hinted(frame, sizeof(frame), 255, 11u);
		expect_err(fzn_relay_budget_policy(frame, sizeof(frame), policy, n, 4u, &budget),
		           FZN_RELAY_OK, "an unnamed subsystem");
		expect(budget == 4u, "falls back rather than being refused");

		/* Unclassified is a class the table may name like any other. */
		build(frame, sizeof(frame), 1, 255);
		expect_err(fzn_relay_budget_policy(frame, sizeof(frame), policy, n, 4u, &budget),
		           FZN_RELAY_OK, "unclassified traffic");
		expect(budget == 1u, "takes the entry naming FZN_RELAY_SERVICE_NONE");

		/* The frame's own claim still clamps downwards: a policy is a
		 * ceiling, never a grant. */
		build_hinted(frame, sizeof(frame), 1, 9u);
		expect_err(fzn_relay_budget_policy(frame, sizeof(frame), policy, n, 4u, &budget),
		           FZN_RELAY_OK, "a modest frame in a generous class");
		expect(budget == 1u, "a policy is a ceiling and not a grant");

		/* SPENDING THROUGH A POLICY, and the two things it must not do:
		 * believe an inflated budget, and touch the hint. */
		build_hinted(frame, sizeof(frame), 255, 9u);
		expect_err(fzn_relay_spend_policy(frame, sizeof(frame), policy, n, 4u),
		           FZN_RELAY_OK, "spending under a policy");
		expect(frame[1] == 5u, "the clamped ceiling is what decrements");
		expect(frame[2] == 0x00u && frame[3] == 0x09u,
		       "a relay must not rewrite the hint -- relabelling is laundering");
	}

	/* AN ALLOWANCE OF ZERO IS A REFUSAL AND NOT AN EXHAUSTION, and the
	 * distinction is the reason FZN_RELAY_ERR_REFUSED exists. Both stop the
	 * frame; only one of them is a decision somebody made. */
	{
		const fzn_relay_policy_t refuse[] = { { 7u, 0u } };

		build_hinted(frame, sizeof(frame), 5, 7u);
		expect_err(fzn_relay_budget_policy(frame, sizeof(frame), refuse, 1, 4u, &budget),
		           FZN_RELAY_ERR_REFUSED, "a subsystem this host does not carry");
		expect_err(fzn_relay_spend_policy(frame, sizeof(frame), refuse, 1, 4u),
		           FZN_RELAY_ERR_REFUSED, "and refuses to forward");
		expect(frame[1] == 5, "leaving the frame untouched");

		/* The same frame under a fallback of zero -- a host that carries
		 * only what it has named. */
		build_hinted(frame, sizeof(frame), 5, 99u);
		expect_err(fzn_relay_spend_policy(frame, sizeof(frame), refuse, 1, 0u),
		           FZN_RELAY_ERR_REFUSED, "a fallback of zero carries nothing else");
		expect(frame[1] == 5, "and touches nothing");

		/* A SPENT FRAME IN A CARRIED CLASS is still EXHAUSTED, which is
		 * what makes the two errors independent rather than two names
		 * for a stopped frame. */
		build_hinted(frame, sizeof(frame), 0, 9u);
		expect_err(fzn_relay_spend_policy(frame, sizeof(frame), refuse, 1, 4u),
		           FZN_RELAY_ERR_EXHAUSTED,
		           "a spent budget in a carried class is exhausted, not refused");
	}

	/* NO TABLE MEANS EVERY FRAME TAKES THE FALLBACK, which is exactly
	 * `fzn_relay_budget` -- so a host with no per-subsystem policy needs no
	 * special case, and an empty table is not an error. */
	build_hinted(frame, sizeof(frame), 255, 7u);
	expect_err(fzn_relay_budget_policy(frame, sizeof(frame), NULL, 0, 3u, &budget),
	           FZN_RELAY_OK, "no policy at all");
	expect(budget == 3u, "every frame takes the fallback");
	{
		const fzn_relay_policy_t empty[] = { { 0u, 0u } };

		expect_err(fzn_relay_budget_policy(frame, sizeof(frame), empty, 0, 3u, &budget),
		           FZN_RELAY_OK, "a table of length zero");
		expect(budget == 3u, "is read as no policy rather than as its first entry");
	}

	/* A FORGED HINT COSTS THE RELAY AND NOTHING ELSE, which is this
	 * feature's whole security claim stated as a case. The frame below
	 * claims a generously-carried subsystem; a relay believes it, because
	 * a relay has nothing else to believe. What the sender did NOT buy is
	 * anything at the recipient, whose authorization comes from the sealed
	 * capability -- asserted where that can be asserted, in seal_test.c,
	 * since it needs a key. */
	{
		const fzn_relay_policy_t policy[] = { { 9u, 8u } };

		build_hinted(frame, sizeof(frame), 8, 9u);
		expect_err(fzn_relay_budget_policy(frame, sizeof(frame), policy, 1, 1u, &budget),
		           FZN_RELAY_OK, "a frame claiming a well-carried subsystem");
		expect(budget == 8u,
		       "is carried on its claim -- a relay cannot check it, and that is the price");
	}

	/* Shape and arguments, for the reader as much as for the code: an
	 * unparseable hop header must not yield a hint either. */
	build(frame, sizeof(frame), 2, 4);
	expect_err(fzn_relay_service(frame, sizeof(frame), &service), FZN_RELAY_ERR_SHAPE,
	           "a hint out of a frame of an unknown version");
	build(frame, sizeof(frame), 1, 4);
	frame[4] = 0x01;
	expect_err(fzn_relay_service(frame, sizeof(frame), &service), FZN_RELAY_ERR_SHAPE,
	           "a hint out of a frame with a non-zero reserved byte");
	expect_err(fzn_relay_service(NULL, sizeof(frame), &service), FZN_RELAY_ERR_MALFORMED,
	           "a hint out of a null frame");
	build(frame, sizeof(frame), 1, 4);
	expect_err(fzn_relay_service(frame, sizeof(frame), NULL), FZN_RELAY_ERR_MALFORMED,
	           "nowhere to answer with a hint");
	expect_err(fzn_relay_budget_policy(NULL, sizeof(frame), NULL, 0, 4u, &budget),
	           FZN_RELAY_ERR_MALFORMED, "a policy against a null frame");
	expect_err(fzn_relay_budget_policy(frame, sizeof(frame), NULL, 0, 4u, NULL),
	           FZN_RELAY_ERR_MALFORMED, "nowhere to answer with a budget");
	expect_err(fzn_relay_spend_policy(NULL, sizeof(frame), NULL, 0, 4u),
	           FZN_RELAY_ERR_MALFORMED, "spending a policy from a null frame");

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
