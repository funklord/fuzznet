/* A fuzz harness for the hop budget.
 *
 * THIS IS THE MOST ATTACKER-CONTROLLED FIELD IN THE PROTOCOL, and `relay.h`
 * says so in as many words: "IT IS OUTSIDE THE AUTHENTICATED REGION,
 * NECESSARILY ... the budget is mutable in flight by anyone", and "a stranger
 * can write 255 into the budget of a frame it did not create". The tag covers
 * `head` and the sealed region; `hop` sits before both, because a relay has to
 * decrement it and a field the tag covered could not be changed without
 * invalidating the frame.
 *
 * So every byte this module reads is a byte anybody on the path may choose,
 * and until sec 233 no harness in this tree reached it. `frame/test/
 * receive_fuzz.c` does not mention relay; nothing did.
 *
 * THE PROPERTIES ARE THE HEADER'S OWN SENTENCES, and each is asserted for
 * EVERY input rather than for a chosen one -- which is the difference from
 * `wire/test/seal_test.c`, where the round trip is exercised on frames this
 * library built:
 *
 *   - the clamp. "The answer is never larger than `allowed`, whatever the
 *     frame says, which is the whole of the clamp." A frame claiming 255 is
 *     exactly the amplifier this exists to stop.
 *   - clamp THEN decrement. "a frame arriving with an inflated budget leaves
 *     with a believable one -- an amplifier is stopped at the first honest
 *     host rather than at the last." So a spend must strictly lower what the
 *     next reader sees, never raise it.
 *   - a refusal leaves the frame alone. "a caller that ignores the return
 *     value forwards something no worse than it received" -- asserted by
 *     memcmp over the whole buffer, not over the field.
 *   - an empty policy IS `fzn_relay_budget`. "A null or empty table is not
 *     malformed: it means every frame takes `fallback`, which is exactly
 *     `fzn_relay_budget`." Two functions, one answer, asserted equal in both
 *     the code and the value.
 *   - the hint is not rewritten by a spend, which the header states and
 *     nothing checked.
 *
 * NOTHING HERE KNOWS AN OFFSET. Frames are built through the generated
 * accessors and read back through the public API, so this asserts the
 * contract rather than the encoding and does not have to move when the layout
 * does.
 */

#include "../relay.h"
#include "../generated/frame.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u
#define FUZZ_MIN_CASES 1000u

#define FRAME_MAX 48u

struct coverage {
	unsigned long accepted;
	unsigned long refused;
	unsigned long inflated;
	unsigned long spent;
	unsigned long exhausted;
	unsigned long policy_hit;
	unsigned long policy_fallback;
	unsigned long declined;
	unsigned long random_bytes;
};

static uint32_t next_rand(uint32_t *seed)
{
	*seed = (*seed * 1103515245u) + 12345u;
	return (*seed >> 16) & 0x7fffu;
}

/* A frame whose hop header is well formed, with a budget and hint the caller
 * chooses. Built through the generated setters: a harness that wrote byte 1
 * by hand would be asserting an offset rather than a contract, and this
 * module's own header records what raw-offset knowledge in a consumer cost. */
static int build_frame(uint8_t *frame, size_t len, uint8_t hops, uint16_t hint)
{
	situ_msg_t msg;
	situ_view_t hv;

	if (len < SITU_FZN_HOP_SIZE_MAX)
		return 0;
	memset(frame, 0, len);
	situ_msg_init(&msg, frame, (uint32_t)len);
	if (situ_fzn_hop_view(&msg, 0, &hv) != SITU_OK)
		return 0;
	situ_fzn_hop_version_set(hv, 1u);
	situ_fzn_hop_hops_left_set(hv, hops);
	situ_fzn_hop_service_hint_set(hv, hint);
	return situ_fzn_hop_validate(hv) == SITU_OK;
}

static int fuzz_one(uint32_t seed, struct coverage *cov)
{
	uint8_t frame[FRAME_MAX], before[FRAME_MAX];
	size_t len;
	uint8_t allowed, hops, got = 0, again = 0;
	uint16_t hint, service_before = 0, service_after = 0;
	fzn_relay_err_t err;
	int well_formed;

	len = (size_t)(next_rand(&seed) % (FRAME_MAX + 1u));

	/* SMALL NUMBERS HALF THE TIME. The interesting states are at the
	 * boundary -- a budget of zero, a ceiling of zero, a claim one above
	 * what this host allows -- and drawing uniformly from 0..255 reaches
	 * them about eight times in two thousand, which is a floor cleared by
	 * luck rather than by coverage. */
	allowed = (uint8_t)((next_rand(&seed) & 1u) ? (next_rand(&seed) % 4u)
	                                            : (next_rand(&seed) & 0xffu));
	hops = (uint8_t)((next_rand(&seed) & 1u) ? (next_rand(&seed) % 4u)
	                                         : (next_rand(&seed) & 0xffu));
	hint = (uint16_t)((next_rand(&seed) & 1u) ? (next_rand(&seed) % 4u)
	                                          : (next_rand(&seed) & 0xffffu));

	/* HALF THE CASES ARE RANDOM BYTES, because the frames a relay is handed
	 * are whatever arrived. The other half are well formed, or the accept
	 * path below would be reached by luck. */
	if (next_rand(&seed) & 1u) {
		size_t i;

		for (i = 0; i < len; i++)
			frame[i] = (uint8_t)(next_rand(&seed) & 0xffu);
		well_formed = 0;
		cov->random_bytes++;
	} else {
		well_formed = build_frame(frame, len, hops, hint);
	}

	memcpy(before, frame, len ? len : 1u);

	/* ---- THE CLAMP, for every input that is answered at all. */
	err = fzn_relay_budget(frame, len, allowed, &got);
	if (err == FZN_RELAY_OK) {
		cov->accepted++;
		if (got > allowed) {
			printf("relay_fuzz: budget answered %u with a ceiling of %u -- the "
			       "clamp is the whole of what this module does\n",
			       (unsigned)got, (unsigned)allowed);
			return 0;
		}
		if (well_formed && hops > allowed)
			cov->inflated++;
	} else {
		cov->refused++;
	}

	/* ---- AN EMPTY POLICY IS `fzn_relay_budget`, ABOVE ZERO. The header
	 * says an empty table "means every frame takes `fallback`, which is
	 * exactly `fzn_relay_budget`" -- and that is true of the CEILING and
	 * not of the status, because a ceiling of zero is a policy saying this
	 * host does not carry the subsystem. `FZN_RELAY_ERR_REFUSED` exists to
	 * keep that apart from EXHAUSTED, "which is every frame's ordinary end
	 * and says nothing about this host".
	 *
	 * The first version of this case asserted the equivalence flatly and
	 * failed on its first run against a fallback of zero. The code was
	 * right; sec 233 added the clause the header was missing. */
	{
		uint8_t via_policy = 0;
		fzn_relay_err_t perr;

		perr = fzn_relay_budget_policy(frame, len, NULL, 0u, allowed, &via_policy);
		if (allowed == 0u) {
			if (err == FZN_RELAY_OK && perr != FZN_RELAY_ERR_REFUSED) {
				printf("relay_fuzz: a ceiling of zero answered %d rather than "
				       "REFUSED, so a host declining a subsystem is "
				       "indistinguishable from a frame reaching its end\n",
				       (int)perr);
				return 0;
			}
			cov->declined++;
		} else if (perr != err || (err == FZN_RELAY_OK && via_policy != got)) {
			printf("relay_fuzz: an empty policy answered %d/%u where the plain "
			       "call answered %d/%u\n",
			       (int)perr, (unsigned)via_policy, (int)err, (unsigned)got);
			return 0;
		}
	}

	/* ---- A POLICY WITH A TABLE. First match wins and a hint naming
	 * nothing takes the fallback; either way the clamp still holds. */
	{
		fzn_relay_policy_t table[2];
		uint8_t via_policy = 0;
		uint8_t fallback = (uint8_t)(next_rand(&seed) & 0xffu);
		fzn_relay_err_t perr;

		/* HALF THE TABLES NAME THIS FRAME'S SUBSYSTEM AND HALF DO NOT,
		 * or the fallback arm -- "how a host says what it does with
		 * subsystems it has no opinion about" -- is never taken. */
		if (next_rand(&seed) & 1u)
			table[0].service = hint;
		else
			table[0].service = (uint16_t)(hint + 0x4000u);
		table[0].allowed = (uint8_t)(next_rand(&seed) & 0xffu);
		table[1].service = (uint16_t)(hint + 0x2000u);
		table[1].allowed = (uint8_t)(next_rand(&seed) & 0xffu);

		perr = fzn_relay_budget_policy(frame, len, table, 2u, fallback, &via_policy);
		if (perr == FZN_RELAY_OK) {
			uint16_t seen = 0;
			uint8_t ceiling;

			if (fzn_relay_service(frame, len, &seen) != FZN_RELAY_OK) {
				printf("relay_fuzz: a frame whose budget was answered has no "
				       "readable service hint\n");
				return 0;
			}
			if (seen == table[0].service) {
				ceiling = table[0].allowed;
				cov->policy_hit++;
			} else if (seen == table[1].service) {
				ceiling = table[1].allowed;
				cov->policy_hit++;
			} else {
				ceiling = fallback;
				cov->policy_fallback++;
			}
			if (via_policy > ceiling) {
				printf("relay_fuzz: a policy answered %u against a ceiling of "
				       "%u for service %u\n",
				       (unsigned)via_policy, (unsigned)ceiling, (unsigned)seen);
				return 0;
			}
		}
	}

	/* ---- SPEND: clamps first, then decrements, and a refusal leaves the
	 * buffer exactly as it found it. */
	if (len) {
		uint8_t was = got;
		fzn_relay_err_t serr;

		(void)fzn_relay_service(frame, len, &service_before);
		serr = fzn_relay_spend(frame, len, allowed);
		if (serr == FZN_RELAY_OK) {
			cov->spent++;
			if (fzn_relay_budget(frame, len, allowed, &again) != FZN_RELAY_OK) {
				printf("relay_fuzz: a frame stopped being readable after a "
				       "spend this module performed\n");
				return 0;
			}
			if (again >= was) {
				printf("relay_fuzz: a spend left the budget at %u where it was "
				       "%u -- clamp then decrement means the next reader must "
				       "see less\n",
				       (unsigned)again, (unsigned)was);
				return 0;
			}
			/* THE HINT IS NOT REWRITTEN. relay.h states it and
			 * nothing checked it. */
			(void)fzn_relay_service(frame, len, &service_after);
			if (service_after != service_before) {
				printf("relay_fuzz: a spend rewrote the service hint, %u to "
				       "%u\n",
				       (unsigned)service_before, (unsigned)service_after);
				return 0;
			}
		} else {
			if (serr == FZN_RELAY_ERR_EXHAUSTED)
				cov->exhausted++;
			if (memcmp(before, frame, len) != 0) {
				printf("relay_fuzz: a refused spend changed the frame, so a "
				       "caller ignoring the return value forwards something "
				       "worse than it received\n");
				return 0;
			}
		}
	}

	return 1;
}

#ifdef FZN_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint32_t seed = 1u;
	size_t i;
	struct coverage cov = { 0, 0, 0, 0, 0, 0, 0, 0, 0 };

	for (i = 0; i < size; i++)
		seed = (seed * 31u) + data[i];
	if (seed == 0u)
		seed = 1u;
	(void)fuzz_one(seed, &cov);
	return 0;
}
#else

static unsigned long floor_of(unsigned long cases, unsigned long per)
{
	unsigned long f = cases / per;

	return f == 0u ? 1u : f;
}

int main(int argc, char **argv)
{
	unsigned long cases = FUZZ_DEFAULT_CASES;
	struct coverage cov = { 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	unsigned long i;

	if (argc > 1)
		cases = strtoul(argv[1], NULL, 10);
	if (cases < FUZZ_MIN_CASES) {
		printf("relay_fuzz: %lu cases is below the floor of %u, at which the\n"
		       "relay_fuzz: coverage checks below are cleared by luck.\n",
		       cases, FUZZ_MIN_CASES);
		return 1;
	}

	for (i = 0; i < cases; i++) {
		if (!fuzz_one((uint32_t)(i + 1u), &cov))
			return 1;
	}

	/* FLOORS ON WHAT WAS REACHED. A run that never saw an INFLATED budget
	 * never tested the clamp against the case it exists for -- a stranger
	 * writing a number larger than this host allows -- and one that never
	 * refused a spend never watched a frame come back untouched. */
	if (cov.accepted < floor_of(cases, 8u) || cov.refused < floor_of(cases, 8u)
	    || cov.inflated < floor_of(cases, 20u) || cov.spent < floor_of(cases, 20u)
	    || cov.exhausted < floor_of(cases, 50u)
	    || cov.policy_hit < floor_of(cases, 50u)
	    || cov.policy_fallback < floor_of(cases, 50u)
	    || cov.declined < floor_of(cases, 200u)) {
		printf("relay_fuzz: REACHED TOO LITTLE -- %lu accepted, %lu refused, "
		       "%lu inflated, %lu spent, %lu exhausted, %lu policy hits, "
		       "%lu fallbacks in %lu cases.\n",
		       cov.accepted, cov.refused, cov.inflated, cov.spent, cov.exhausted,
		       cov.policy_hit, cov.policy_fallback, cases);
		return 1;
	}

	printf("relay_fuzz: %lu cases (%lu random byte strings), %lu answered, "
	       "%lu refused, %lu inflated budgets clamped, %lu spends, %lu exhausted, "
	       "%lu policy hits, %lu fallbacks, %lu subsystems declined\n",
	       cases, cov.random_bytes, cov.accepted, cov.refused, cov.inflated, cov.spent,
	       cov.exhausted, cov.policy_hit, cov.policy_fallback, cov.declined);
	return 0;
}
#endif
