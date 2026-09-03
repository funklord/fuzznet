/* Tests for chain/authz.c: the decision a receiver makes before it trusts a
 * record's issuer.
 *
 * THE CASE THIS FILE EXISTS FOR IS THE ONE THAT CANNOT BE SPELLED. A zeroed
 * policy must deny -- not because a caller would write one deliberately, but
 * because a `memset`, a global nobody initialised, or a struct returned from
 * a path that forgot to assign all produce exactly that, and every one of
 * them must land on "no". Everything else here is a guard around it.
 *
 * The stub signer is keyed on identity, as chain_test.c's is and for the same
 * reason: a verifier whose verdict does not depend on who signed makes "this
 * chain grants that capability" a claim with no observable content.
 */

#include "../authz.h"

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
	fprintf(stderr, "  FAIL authz_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)
#define REQUIRE(cond, ...)                                   \
	do {                                                 \
		int require_ok = (cond) ? 1 : 0;             \
		check_at(require_ok, __LINE__, __VA_ARGS__); \
		if (!require_ok)                             \
			return;                              \
	} while (0)

static uint8_t signing_as;

static void mac(uint8_t out[FZN_SIG_LEN], uint8_t identity, const uint8_t *msg, size_t len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	h ^= identity;
	h *= 0x100000001b3ull;
	for (i = 0; i < len; i++) {
		h ^= msg[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h ^= (uint64_t)i + 0x9e3779b97f4a7c15ull;
		h *= 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 24);
	}
}

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	(void)ctx;
	mac(sig, signing_as, msg, msg_len);
	return 1;
}

static int stub_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	mac(want, pubkey[0], msg, msg_len);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

static const fzn_sign_ops_t OPS = { stub_verify, stub_sign, NULL };

static void key(uint8_t out[FZN_PUBKEY_LEN], uint8_t seed)
{
	size_t i;

	for (i = 0; i < FZN_PUBKEY_LEN; i++)
		out[i] = (uint8_t)(seed + (i * 7u));
}

static void cap_id(fzn_cap_id_t *out, uint8_t seed)
{
	size_t i;

	for (i = 0; i < FZN_CAP_ID_LEN; i++)
		out->b[i] = (uint8_t)(seed + (i * 11u));
}

struct fixture {
	uint8_t bytes[FZN_HOP_LEN];
	fzn_chain_hop_t hop;
	uint8_t root[FZN_PUBKEY_LEN];
	fzn_cap_id_t cap;
	fzn_revocation_store_t store;
	fzn_revocation_t storage[2];
};

static int build(struct fixture *f)
{
	uint8_t grantee[FZN_PUBKEY_LEN];

	key(f->root, 0x11);
	key(grantee, 0x22);
	cap_id(&f->cap, 0x33);
	signing_as = 0x11;
	if (fzn_chain_mint(f->root, grantee, &f->cap, 100, 5000, 1, &OPS, f->bytes)
	    != FZN_CHAIN_OK)
		return 0;
	if (fzn_hop_open(f->bytes, FZN_HOP_LEN, &f->hop) != FZN_CHAIN_OK)
		return 0;
	return fzn_revocation_store_init(&f->store, f->storage, 2) == FZN_CHAIN_OK;
}

/* ---- the cases -------------------------------------------------------- */

static void test_a_zeroed_policy_denies(void)
{
	struct fixture f;
	fzn_authz_policy_t zeroed;

	REQUIRE(build(&f), "the fixture does not build");
	memset(&zeroed, 0, sizeof(zeroed));

	/* THE WHOLE DESIGN, IN ONE ASSERTION. A memset policy is what a
	 * consumer produces by forgetting, and it must not read as "this kind
	 * needs no capability". If this ever returns GRANTED_UNGUARDED, every
	 * unguarded path in every consumer becomes reachable by omission. */
	CHECK(fzn_authz_decide(zeroed, FZN_ORIGIN_REMOTE, &f.hop, 1, f.root, 1000, &OPS, &f.store)
	              == FZN_AUTHZ_DENIED,
	      "a zeroed policy did not deny, so absence reads as not-required");

	/* And with no chain either, which is the state a fresh host is in. */
	CHECK(fzn_authz_decide(zeroed, FZN_ORIGIN_REMOTE, NULL, 0, f.root, 1000, &OPS, &f.store)
	              == FZN_AUTHZ_DENIED,
	      "a zeroed policy with no chain did not deny");

	/* A HALF-FILLED POLICY, WHICH IS THE ONLY STATE `spelled` DECIDES
	 * ALONE.
	 *
	 * The two assertions above are satisfied by the ORIGIN gate: a zeroed
	 * `origins` reaches nothing, so a memset policy denies on that count
	 * whether `spelled` is consulted or not. authz.h says so approvingly
	 * -- "a forgotten policy now denies on two independent counts rather
	 * than one" -- and that redundancy is exactly what hid the fact that
	 * only one of the two counts was under test. Measured 2026-09-03:
	 * deleting the `spelled` check left the whole suite green.
	 *
	 * A consumer filling `origins` and forgetting `spelled` is not the
	 * memset case, and it is the likelier mistake of the two: `origins`
	 * is the field a reader thinks about, because it is the one the
	 * arity change made them pass. With the check gone this reaches the
	 * origin gate, passes it, finds `guarded` clear and answers
	 * GRANTED_UNGUARDED -- which is the whole failure the header opens
	 * with, arriving through the half-filled struct rather than the
	 * empty one. */
	{
		fzn_authz_policy_t half;

		memset(&half, 0, sizeof(half));
		half.origins = FZN_ORIGIN_ANY;

		CHECK(fzn_authz_decide(half, FZN_ORIGIN_REMOTE, &f.hop, 1, f.root, 1000,
		                       &OPS, &f.store) == FZN_AUTHZ_DENIED,
		      "a policy whose origins were filled and whose `spelled` was not "
		      "did not deny -- so forgetting the one field that says a policy "
		      "was written at all reads as not-required");

		/* THE CONTROL, and without it the refusal above is satisfied by
		 * an origin mask that admits nothing. The same struct with
		 * `spelled` set is the unguarded policy it was meant to be, and
		 * answers so. */
		half.spelled = 1;
		CHECK(fzn_authz_decide(half, FZN_ORIGIN_REMOTE, &f.hop, 1, f.root, 1000,
		                       &OPS, &f.store) == FZN_AUTHZ_GRANTED_UNGUARDED,
		      "the same policy with `spelled` set did not grant, so the refusal "
		      "above is the origin mask rather than the spelled check");
	}
}

static void test_denied_is_zero(void)
{
	/* A verdict a caller stores in a zeroed struct, or reads before
	 * assignment, must be the safe one. Asserted on the value rather than
	 * on the name, because the name is what a reader checks and the value
	 * is what a memset produces. */
	CHECK((int)FZN_AUTHZ_DENIED == 0, "denial is not the zero verdict");
	CHECK((int)FZN_AUTHZ_GRANTED_BY_CHAIN != 0 && (int)FZN_AUTHZ_GRANTED_UNGUARDED != 0,
	      "a grant shares the zero value with denial");
}

static void test_a_required_capability_with_no_chain_denies(void)
{
	struct fixture f;

	REQUIRE(build(&f), "the fixture does not build");

	/* THE CASE FUZZYPICKLES NAMED. "I hold no chain for this issuer" is an
	 * ordinary state, not an error, and it must not be confusable with
	 * "this kind needs no capability". */
	CHECK(fzn_authz_decide(fzn_authz_requires(&f.cap, FZN_ORIGIN_ANY), FZN_ORIGIN_REMOTE, NULL, 0, f.root, 1000, &OPS, &f.store)
	              == FZN_AUTHZ_DENIED,
	      "a required capability with no chain was granted");
	CHECK(fzn_authz_decide(fzn_authz_requires(&f.cap, FZN_ORIGIN_ANY), FZN_ORIGIN_REMOTE, &f.hop, 0, f.root, 1000, &OPS,
	                       &f.store) == FZN_AUTHZ_DENIED,
	      "a required capability with an empty chain was granted");
}

static void test_a_good_chain_grants_and_says_how(void)
{
	struct fixture f;

	REQUIRE(build(&f), "the fixture does not build");

	CHECK(fzn_authz_decide(fzn_authz_requires(&f.cap, FZN_ORIGIN_ANY), FZN_ORIGIN_REMOTE, &f.hop, 1, f.root, 1000, &OPS,
	                       &f.store) == FZN_AUTHZ_GRANTED_BY_CHAIN,
	      "a valid chain for the required capability was refused, so every denial "
	      "above proves nothing");

	/* AND THE TWO GRANTS ARE DISTINGUISHABLE, which is what lets a
	 * consumer's log separate "authorised" from "not guarded" -- and lets
	 * somebody find every unguarded path by grepping for one value. */
	CHECK(fzn_authz_decide(fzn_authz_unguarded(FZN_ORIGIN_ANY), FZN_ORIGIN_REMOTE, NULL, 0, f.root, 1000, &OPS, &f.store)
	              == FZN_AUTHZ_GRANTED_UNGUARDED,
	      "an explicitly unguarded kind did not report itself as unguarded");
	CHECK(FZN_AUTHZ_GRANTED_BY_CHAIN != FZN_AUTHZ_GRANTED_UNGUARDED,
	      "the two grants share a value, so a log cannot tell them apart");
}

/*
 * THE CASE THE ORIGIN CHECK EXISTS FOR, and it is the UNGUARDED one.
 *
 * A consumer saying "this kind needs no capability" means it locally --
 * netcfgd's local policy is deliberately open enough that a distribution
 * could put every user in its group. Without an origin the same sentence
 * also admits the entire network, which is the failure its decision 0128 was
 * written to prevent. So the assertion is not merely that a scoped policy
 * denies, but that it denies a kind that is otherwise WIDE OPEN.
 */
static void test_an_unguarded_kind_is_still_bounded_by_where_it_arrived(void)
{
	struct fixture f;
	fzn_authz_policy_t local_only;

	REQUIRE(build(&f), "the fixture does not build");
	local_only = fzn_authz_unguarded(FZN_ORIGIN_BIT(FZN_ORIGIN_SAME_USER)
	                                 | FZN_ORIGIN_BIT(FZN_ORIGIN_LOCAL));

	CHECK(fzn_authz_decide(local_only, FZN_ORIGIN_REMOTE, NULL, 0, f.root, 1000, &OPS,
	                       &f.store) == FZN_AUTHZ_DENIED,
	      "a kind needing no capability was reachable from the network, so an "
	      "openly-local policy is an open network policy");

	/* AND IT IS NOT SIMPLY MUTE: the same policy grants from the two
	 * origins it names. Without this the case above passes against a
	 * decision that denies everything. */
	CHECK(fzn_authz_decide(local_only, FZN_ORIGIN_LOCAL, NULL, 0, f.root, 1000, &OPS,
	                       &f.store) == FZN_AUTHZ_GRANTED_UNGUARDED,
	      "a local-only policy refused a local request too");
	CHECK(fzn_authz_decide(local_only, FZN_ORIGIN_SAME_USER, NULL, 0, f.root, 1000, &OPS,
	                       &f.store) == FZN_AUTHZ_GRANTED_UNGUARDED,
	      "a policy naming SAME_USER refused one");

	/* A GUARDED KIND IS BOUNDED THE SAME WAY, so the check is not a
	 * property of the unguarded branch alone -- a valid chain from a
	 * disallowed origin is still a denial. */
	{
		fzn_authz_policy_t local_cap =
		        fzn_authz_requires(&f.cap, FZN_ORIGIN_BIT(FZN_ORIGIN_LOCAL));

		CHECK(fzn_authz_decide(local_cap, FZN_ORIGIN_REMOTE, &f.hop, 1, f.root, 1000,
		                       &OPS, &f.store) == FZN_AUTHZ_DENIED,
		      "a valid chain was accepted from an origin the policy excludes");
		CHECK(fzn_authz_decide(local_cap, FZN_ORIGIN_LOCAL, &f.hop, 1, f.root, 1000,
		                       &OPS, &f.store) == FZN_AUTHZ_GRANTED_BY_CHAIN,
		      "the same chain was refused from the origin the policy names, so the "
		      "denial above proves nothing");
	}
}

/* NOT STATED DENIES, and cannot be admitted by a caller who sets every bit.
 * An origin a caller did not observe is not an origin. */
static void test_an_unobserved_origin_denies(void)
{
	struct fixture f;

	REQUIRE(build(&f), "the fixture does not build");

	CHECK(fzn_authz_decide(fzn_authz_unguarded(FZN_ORIGIN_ANY), FZN_ORIGIN_NONE, NULL, 0,
	                       f.root, 1000, &OPS, &f.store) == FZN_AUTHZ_DENIED,
	      "a caller that stated no origin was admitted by a policy naming every one");
	CHECK(fzn_authz_decide(fzn_authz_unguarded(0xffffffffu), FZN_ORIGIN_NONE, NULL, 0,
	                       f.root, 1000, &OPS, &f.store) == FZN_AUTHZ_DENIED,
	      "setting every bit admitted the one origin that means 'not observed'");

	/* A POLICY REACHABLE FROM NOWHERE DENIES WHATEVER ELSE IT SAYS, which
	 * is what makes a zeroed struct fail on two independent counts rather
	 * than one. Spelled and unguarded, so `spelled` cannot be what denies
	 * -- otherwise this case would pass without an origin check existing. */
	{
		fzn_authz_policy_t nowhere = fzn_authz_unguarded(0u);

		CHECK(fzn_authz_decide(nowhere, FZN_ORIGIN_LOCAL, NULL, 0, f.root, 1000, &OPS,
		                       &f.store) == FZN_AUTHZ_DENIED,
		      "a policy reachable from no origin granted anyway");
	}

	/* AND THE EXPLANATION AGREES WITH THE ENFORCEMENT. The predicate is
	 * for a consumer's log; if it could disagree with the decision it
	 * would be a log that lies about why. */
	{
		fzn_authz_policy_t local_only = fzn_authz_unguarded(FZN_ORIGIN_BIT(FZN_ORIGIN_LOCAL));

		CHECK(!fzn_authz_origin_permitted(local_only, FZN_ORIGIN_REMOTE),
		      "the predicate permitted an origin the decision denies");
		CHECK(fzn_authz_origin_permitted(local_only, FZN_ORIGIN_LOCAL),
		      "the predicate refused an origin the decision grants");
		CHECK(!fzn_authz_origin_permitted(local_only, FZN_ORIGIN_NONE),
		      "the predicate permitted an unobserved origin");
	}
}

static void test_a_chain_for_another_capability_denies(void)
{
	struct fixture f;
	fzn_cap_id_t other;

	REQUIRE(build(&f), "the fixture does not build");
	cap_id(&other, 0x44);

	/* The chain is valid and grants something. It does not grant THIS. */
	CHECK(fzn_authz_decide(fzn_authz_requires(&other, FZN_ORIGIN_ANY), FZN_ORIGIN_REMOTE, &f.hop, 1, f.root, 1000, &OPS,
	                       &f.store) == FZN_AUTHZ_DENIED,
	      "a chain granting one capability authorised a different one");
}

static void test_every_refusal_of_the_verifier_is_a_denial(void)
{
	struct fixture f;
	uint8_t wrong_root[FZN_PUBKEY_LEN];

	REQUIRE(build(&f), "the fixture does not build");
	key(wrong_root, 0x99);

	/* Collapsed to DENIED rather than passed through, so a caller cannot
	 * treat a nonzero error code as truthy. Each of these is a distinct
	 * refusal inside fzn_chain_verify and all of them are one answer
	 * here. */
	CHECK(fzn_authz_decide(fzn_authz_requires(&f.cap, FZN_ORIGIN_ANY), FZN_ORIGIN_REMOTE, &f.hop, 1, wrong_root, 1000, &OPS,
	                       &f.store) == FZN_AUTHZ_DENIED,
	      "a chain under a foreign root was granted");
	CHECK(fzn_authz_decide(fzn_authz_requires(&f.cap, FZN_ORIGIN_ANY), FZN_ORIGIN_REMOTE, &f.hop, 1, NULL, 1000, &OPS, &f.store)
	              == FZN_AUTHZ_DENIED,
	      "a null root was granted");
	CHECK(fzn_authz_decide(fzn_authz_requires(&f.cap, FZN_ORIGIN_ANY), FZN_ORIGIN_REMOTE, &f.hop, 1, f.root, 1000, NULL,
	                       &f.store) == FZN_AUTHZ_DENIED,
	      "a null signer was granted");
	CHECK(fzn_authz_decide(fzn_authz_requires(&f.cap, FZN_ORIGIN_ANY), FZN_ORIGIN_REMOTE, &f.hop, 1, f.root, 9000, &OPS,
	                       &f.store) == FZN_AUTHZ_DENIED,
	      "an expired chain was granted");

	/* An unguarded kind grants without any of those mattering, which is
	 * the point of saying so out loud -- and is why the constructor is a
	 * call somebody has to write. */
	CHECK(fzn_authz_decide(fzn_authz_unguarded(FZN_ORIGIN_ANY), FZN_ORIGIN_REMOTE, NULL, 0, NULL, 9000, NULL, NULL)
	              == FZN_AUTHZ_GRANTED_UNGUARDED,
	      "an unguarded kind was denied for reasons that cannot apply to it");
}

static void test_a_null_capability_does_not_guard_nothing(void)
{
	struct fixture f;

	REQUIRE(build(&f), "the fixture does not build");

	/* `fzn_authz_requires(NULL, FZN_ORIGIN_ANY)` is a caller that has not decided. It must
	 * not become an unguarded policy by accident: the capability is left
	 * as zeroes, which no chain in this library grants. */
	CHECK(fzn_authz_decide(fzn_authz_requires(NULL, FZN_ORIGIN_ANY), FZN_ORIGIN_REMOTE, &f.hop, 1, f.root, 1000, &OPS,
	                       &f.store) == FZN_AUTHZ_DENIED,
	      "requiring a null capability granted, so an undecided caller is unguarded");
}

static void test_the_verdicts_render(void)
{
	CHECK(strcmp(fzn_authz_verdict_str(FZN_AUTHZ_DENIED), "denied") == 0,
	      "denied does not render");
	CHECK(strcmp(fzn_authz_verdict_str((fzn_authz_verdict_t)44), "unknown") == 0,
	      "a value that is not an enumerator does not render as unknown");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	check_at(0, __LINE__, "deliberate");
	CHECK(failures == before + 1, "a failing check did not count");
	failures = before;
	checks -= 1;
}

int main(void)
{
	test_a_zeroed_policy_denies();
	test_denied_is_zero();
	test_a_required_capability_with_no_chain_denies();
	test_a_good_chain_grants_and_says_how();
	test_an_unguarded_kind_is_still_bounded_by_where_it_arrived();
	test_an_unobserved_origin_denies();
	test_a_chain_for_another_capability_denies();
	test_every_refusal_of_the_verifier_is_a_denial();
	test_a_null_capability_does_not_guard_nothing();
	test_the_verdicts_render();
	test_the_suite_can_tell_pass_from_fail();

	printf("authz_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
