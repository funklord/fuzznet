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

static void cap_id(uint8_t out[FZN_CAP_ID_LEN], uint8_t seed)
{
	size_t i;

	for (i = 0; i < FZN_CAP_ID_LEN; i++)
		out[i] = (uint8_t)(seed + (i * 11u));
}

struct fixture {
	uint8_t bytes[FZN_HOP_LEN];
	fzn_chain_hop_t hop;
	uint8_t root[FZN_PUBKEY_LEN];
	uint8_t cap[FZN_CAP_ID_LEN];
	fzn_revocation_store_t store;
	fzn_revocation_t storage[2];
};

static int build(struct fixture *f)
{
	uint8_t grantee[FZN_PUBKEY_LEN];

	key(f->root, 0x11);
	key(grantee, 0x22);
	cap_id(f->cap, 0x33);
	signing_as = 0x11;
	if (fzn_chain_mint(f->root, grantee, f->cap, 100, 5000, 1, &OPS, f->bytes)
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
	CHECK(fzn_authz_decide(zeroed, &f.hop, 1, f.root, 1000, &OPS, &f.store)
	              == FZN_AUTHZ_DENIED,
	      "a zeroed policy did not deny, so absence reads as not-required");

	/* And with no chain either, which is the state a fresh host is in. */
	CHECK(fzn_authz_decide(zeroed, NULL, 0, f.root, 1000, &OPS, &f.store)
	              == FZN_AUTHZ_DENIED,
	      "a zeroed policy with no chain did not deny");
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
	CHECK(fzn_authz_decide(fzn_authz_requires(f.cap), NULL, 0, f.root, 1000, &OPS, &f.store)
	              == FZN_AUTHZ_DENIED,
	      "a required capability with no chain was granted");
	CHECK(fzn_authz_decide(fzn_authz_requires(f.cap), &f.hop, 0, f.root, 1000, &OPS,
	                       &f.store) == FZN_AUTHZ_DENIED,
	      "a required capability with an empty chain was granted");
}

static void test_a_good_chain_grants_and_says_how(void)
{
	struct fixture f;

	REQUIRE(build(&f), "the fixture does not build");

	CHECK(fzn_authz_decide(fzn_authz_requires(f.cap), &f.hop, 1, f.root, 1000, &OPS,
	                       &f.store) == FZN_AUTHZ_GRANTED_BY_CHAIN,
	      "a valid chain for the required capability was refused, so every denial "
	      "above proves nothing");

	/* AND THE TWO GRANTS ARE DISTINGUISHABLE, which is what lets a
	 * consumer's log separate "authorised" from "not guarded" -- and lets
	 * somebody find every unguarded path by grepping for one value. */
	CHECK(fzn_authz_decide(fzn_authz_unguarded(), NULL, 0, f.root, 1000, &OPS, &f.store)
	              == FZN_AUTHZ_GRANTED_UNGUARDED,
	      "an explicitly unguarded kind did not report itself as unguarded");
	CHECK(FZN_AUTHZ_GRANTED_BY_CHAIN != FZN_AUTHZ_GRANTED_UNGUARDED,
	      "the two grants share a value, so a log cannot tell them apart");
}

static void test_a_chain_for_another_capability_denies(void)
{
	struct fixture f;
	uint8_t other[FZN_CAP_ID_LEN];

	REQUIRE(build(&f), "the fixture does not build");
	cap_id(other, 0x44);

	/* The chain is valid and grants something. It does not grant THIS. */
	CHECK(fzn_authz_decide(fzn_authz_requires(other), &f.hop, 1, f.root, 1000, &OPS,
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
	CHECK(fzn_authz_decide(fzn_authz_requires(f.cap), &f.hop, 1, wrong_root, 1000, &OPS,
	                       &f.store) == FZN_AUTHZ_DENIED,
	      "a chain under a foreign root was granted");
	CHECK(fzn_authz_decide(fzn_authz_requires(f.cap), &f.hop, 1, NULL, 1000, &OPS, &f.store)
	              == FZN_AUTHZ_DENIED,
	      "a null root was granted");
	CHECK(fzn_authz_decide(fzn_authz_requires(f.cap), &f.hop, 1, f.root, 1000, NULL,
	                       &f.store) == FZN_AUTHZ_DENIED,
	      "a null signer was granted");
	CHECK(fzn_authz_decide(fzn_authz_requires(f.cap), &f.hop, 1, f.root, 9000, &OPS,
	                       &f.store) == FZN_AUTHZ_DENIED,
	      "an expired chain was granted");

	/* An unguarded kind grants without any of those mattering, which is
	 * the point of saying so out loud -- and is why the constructor is a
	 * call somebody has to write. */
	CHECK(fzn_authz_decide(fzn_authz_unguarded(), NULL, 0, NULL, 9000, NULL, NULL)
	              == FZN_AUTHZ_GRANTED_UNGUARDED,
	      "an unguarded kind was denied for reasons that cannot apply to it");
}

static void test_a_null_capability_does_not_guard_nothing(void)
{
	struct fixture f;

	REQUIRE(build(&f), "the fixture does not build");

	/* `fzn_authz_requires(NULL)` is a caller that has not decided. It must
	 * not become an unguarded policy by accident: the capability is left
	 * as zeroes, which no chain in this library grants. */
	CHECK(fzn_authz_decide(fzn_authz_requires(NULL), &f.hop, 1, f.root, 1000, &OPS,
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
	test_a_chain_for_another_capability_denies();
	test_every_refusal_of_the_verifier_is_a_denial();
	test_a_null_capability_does_not_guard_nothing();
	test_the_verdicts_render();
	test_the_suite_can_tell_pass_from_fail();

	printf("authz_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
