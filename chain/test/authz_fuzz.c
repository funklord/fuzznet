/*
 * A fuzz harness for chain/authz.c, against a decision table written from
 * its header.
 *
 * `fzn_authz_decide` is a pure decision: a policy, an origin and an optional
 * chain in, a verdict out. `authz.h` states the whole of it as sentences,
 * and those sentences are the oracle here:
 *
 *   - an unspelled policy denies;
 *   - an origin the policy does not name denies, before any capability;
 *   - an unguarded policy grants UNGUARDED, distinct from a chain grant
 *     "because a consumer's log must be able to tell authorised from not
 *     guarded";
 *   - a guarded policy with no chain denies -- "an ordinary state rather than
 *     an error, and exactly the case that must not be confusable with no
 *     capability required";
 *   - a guarded policy with a chain that verifies FOR ITS CAPABILITY grants
 *     BY_CHAIN, and a chain for a different capability, an expired chain, a
 *     null root or a null signer all deny.
 *
 * THE ORACLE NEVER ASKS THE LIBRARY WHETHER A CHAIN VERIFIES. The harness
 * mints every chain itself, so it knows which capability it grants and when
 * it expires, and the expected verdict is computed from that knowledge and
 * the policy alone. A model that called `fzn_chain_verify` to decide what
 * `fzn_authz_decide` should say would be checking the decision layer against
 * the thing it wraps, which is most of it.
 *
 * AND THE POLARITY IS ASSERTED SEPARATELY FROM THE TABLE, because it is a
 * different guarantee: zero denies and every non-zero value grants. The
 * header records why -- "adding DENIED_BY_ORIGIN as a nonzero enumerator
 * would turn a refusal into a grant at every site" that reads the verdict as
 * a truth value. So every denial must be exactly zero and every grant must be
 * exactly one of the two named enumerators, whatever the table says the
 * verdict should be. A verdict of 3 that the table did not predict is a
 * grant nobody named, and that is the finding this check exists for.
 */

#include "../authz.h"
#include "../chain.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u
#define FUZZ_MIN_CASES 1000u

/* ---- the signer chain_test.c uses ---------------------------------------- */

static void mac(uint8_t out[FZN_SIG_LEN], uint8_t identity, const uint8_t *msg, size_t len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	h ^= (uint64_t)identity;
	h *= 0x100000001b3ull;
	for (i = 0; i < len; i++) {
		h ^= (uint64_t)msg[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h ^= (uint64_t)i + 1u;
		h *= 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 56);
	}
}

struct stub {
	uint8_t identity;
};

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	struct stub *s = ctx;

	mac(sig, s->identity, msg, msg_len);
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

static void expand(uint8_t *out, size_t len, uint8_t seed)
{
	size_t i;

	out[0] = seed;
	for (i = 1; i < len; i++)
		out[i] = (uint8_t)(seed ^ (uint8_t)i);
}

/* ---- the shapes a case can take ------------------------------------------ */

enum chain_kind { NO_CHAIN, RIGHT_CAP, WRONG_CAP, EXPIRED, CHAIN_KINDS };
enum policy_kind { UNSPELLED, UNGUARDED, GUARDED, POLICY_KINDS };

struct coverage {
	unsigned long denied_unspelled;
	unsigned long denied_origin;
	unsigned long granted_unguarded;
	unsigned long denied_no_chain;
	unsigned long granted_by_chain;
	unsigned long denied_wrong_cap;
	unsigned long denied_expired;
	unsigned long denied_null_arg;
};

static uint32_t next(uint32_t *state)
{
	*state ^= *state << 13;
	*state ^= *state >> 17;
	*state ^= *state << 5;
	return *state;
}

static const char *kind_name(int k)
{
	switch (k) {
	case NO_CHAIN: return "no chain";
	case RIGHT_CAP: return "a chain for the right capability";
	case WRONG_CAP: return "a chain for the wrong capability";
	case EXPIRED: return "an expired chain";
	}
	return "?";
}

static int fuzz_one(uint32_t seed, struct coverage *cov)
{
	uint32_t state = seed;
	struct stub stub;
	fzn_sign_ops_t sign;
	uint8_t root[FZN_PUBKEY_LEN], grantee[FZN_PUBKEY_LEN], bytes[FZN_HOP_LEN];
	fzn_cap_id_t cap_a, cap_b;
	fzn_chain_hop_t hop;
	fzn_authz_policy_t policy;
	fzn_authz_verdict_t got, want;
	/* WEIGHTED, so the rows that need a chain are common. Drawn uniformly,
	 * an unspelled policy and an unnamed origin together denied 77 of 100
	 * cases before any chain was looked at, and the floors on the chain
	 * rows failed at two or three per cent -- every verdict matched, over
	 * a fixture that mostly asked the two cheapest questions. */
	unsigned draw = next(&state) % 8u;
	int pkind = draw == 0u ? UNSPELLED : draw == 1u ? UNGUARDED : GUARDED;
	int ckind = (int)(next(&state) % CHAIN_KINDS);
	fzn_origin_t origin = (fzn_origin_t)(1u + (next(&state) % 3u));
	unsigned origins = (next(&state) % 4u) == 0u ? (next(&state) & FZN_ORIGIN_ANY)
	                                              : FZN_ORIGIN_ANY;

	if ((next(&state) % 12u) == 0u)
		origin = FZN_ORIGIN_NONE;
	int null_root = (next(&state) % 16u) == 0u;
	int null_sign = (next(&state) % 16u) == 0u;
	uint64_t now = 100u;
	const char *why = "";

	expand(root, FZN_PUBKEY_LEN, 0);
	expand(grantee, FZN_PUBKEY_LEN, 1);
	expand(cap_a.b, FZN_CAP_ID_LEN, 0x30);
	expand(cap_b.b, FZN_CAP_ID_LEN, 0x31);
	stub.identity = 0;
	sign.sign = stub_sign;
	sign.verify = stub_verify;
	sign.ctx = &stub;

	/* THE POLICY, by the two constructors the header says are the only
	 * two ways to spell one, or zeroed for the way to not spell one. */
	memset(&policy, 0, sizeof(policy));
	if (pkind == UNGUARDED)
		policy = fzn_authz_unguarded(origins);
	else if (pkind == GUARDED)
		policy = fzn_authz_requires(&cap_a, origins);

	/* THE CHAIN, minted here so its properties are known without asking. */
	if (ckind != NO_CHAIN) {
		const fzn_cap_id_t *cap = ckind == WRONG_CAP ? &cap_b : &cap_a;
		uint64_t issued = ckind == EXPIRED ? 10u : now;
		uint64_t expires = ckind == EXPIRED ? 50u : now + 10u;

		if (fzn_chain_mint(root, grantee, cap, issued, expires, 0, &sign, bytes) !=
		    FZN_CHAIN_OK || fzn_hop_open(bytes, FZN_HOP_LEN, &hop) != FZN_CHAIN_OK) {
			printf("  MODEL: the fixture could not mint a hop\n");
			return 1;
		}
	}

	/* THE TABLE. Each line is a sentence of authz.h, in the order the
	 * header gives them. */
	if (pkind == UNSPELLED) {
		want = FZN_AUTHZ_DENIED; why = "unspelled"; cov->denied_unspelled++;
	} else if (origin == FZN_ORIGIN_NONE || !(origins & FZN_ORIGIN_BIT(origin))) {
		want = FZN_AUTHZ_DENIED; why = "origin not named"; cov->denied_origin++;
	} else if (pkind == UNGUARDED) {
		want = FZN_AUTHZ_GRANTED_UNGUARDED; why = "unguarded"; cov->granted_unguarded++;
	} else if (ckind == NO_CHAIN) {
		want = FZN_AUTHZ_DENIED; why = "no chain where one is required";
		cov->denied_no_chain++;
	} else if (null_root || null_sign) {
		want = FZN_AUTHZ_DENIED; why = "null root or signer"; cov->denied_null_arg++;
	} else if (ckind == RIGHT_CAP) {
		want = FZN_AUTHZ_GRANTED_BY_CHAIN; why = "verified for the capability";
		cov->granted_by_chain++;
	} else if (ckind == WRONG_CAP) {
		want = FZN_AUTHZ_DENIED; why = "wrong capability"; cov->denied_wrong_cap++;
	} else {
		want = FZN_AUTHZ_DENIED; why = "expired"; cov->denied_expired++;
	}

	got = fzn_authz_decide(policy, origin, ckind == NO_CHAIN ? NULL : &hop,
	                       ckind == NO_CHAIN ? 0u : 1u, null_root ? NULL : root, now,
	                       null_sign ? NULL : &sign, NULL, NULL);

	if (got != want) {
		printf("  MODEL: %s policy, origin %d in mask %#x, %s%s -> verdict %d, and "
		       "the header says %d (%s)\n",
		       pkind == UNSPELLED ? "an unspelled" : pkind == UNGUARDED ? "an unguarded"
		                                                                  : "a guarded",
		       (int)origin, origins, kind_name(ckind),
		       null_root ? ", null root" : null_sign ? ", null signer" : "",
		       (int)got, (int)want, why);
		return 1;
	}

	/* THE POLARITY, apart from the table. */
	if (got != FZN_AUTHZ_DENIED && got != FZN_AUTHZ_GRANTED_BY_CHAIN &&
	    got != FZN_AUTHZ_GRANTED_UNGUARDED) {
		printf("  MODEL: verdict %d is not one of the three named, so a consumer "
		       "reading it as a truth value would read a grant nobody defined\n",
		       (int)got);
		return 1;
	}
	if ((got != FZN_AUTHZ_DENIED) != (want != FZN_AUTHZ_DENIED)) {
		printf("  MODEL: the verdict's truth value disagrees with the table\n");
		return 1;
	}
	if (fzn_authz_origin_permitted(policy, origin) !=
	    (pkind != UNSPELLED && origin != FZN_ORIGIN_NONE &&
	     (origins & FZN_ORIGIN_BIT(origin)) != 0u)) {
		printf("  MODEL: origin_permitted disagrees with the mask, so a log would "
		       "name the wrong reason\n");
		return 1;
	}
	return 0;
}

#ifdef FZN_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint32_t seed = 1u;
	size_t i;
	struct coverage cov = { 0, 0, 0, 0, 0, 0, 0, 0 };

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
	struct coverage cov = { 0, 0, 0, 0, 0, 0, 0, 0 };
	unsigned long c;

	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
	}
	if (cases < FUZZ_MIN_CASES) {
		printf("authz_fuzz: %lu cases is below FUZZ_MIN_CASES (%u).\n", cases,
		       (unsigned)FUZZ_MIN_CASES);
		return 1;
	}

	for (c = 0; c < cases; c++) {
		if (fuzz_one((uint32_t)c + 1u, &cov)) {
			printf("authz_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	/* EVERY ROW OF THE TABLE MUST HAVE BEEN REACHED. A run where no
	 * chain granted has tested only refusals, and one where no wrong
	 * capability denied has not separated "a chain" from "the chain". */
	if (cov.denied_unspelled < floor_of(cases, 10u) || cov.denied_origin < floor_of(cases, 10u)
	    || cov.granted_unguarded < floor_of(cases, 20u)
	    || cov.denied_no_chain < floor_of(cases, 20u)
	    || cov.granted_by_chain < floor_of(cases, 40u)
	    || cov.denied_wrong_cap < floor_of(cases, 40u)
	    || cov.denied_expired < floor_of(cases, 40u)
	    || cov.denied_null_arg < floor_of(cases, 200u)) {
		printf("authz_fuzz: REACHED TOO LITTLE -- %lu unspelled, %lu origin, %lu "
		       "unguarded, %lu no chain, %lu by chain, %lu wrong cap, %lu expired, "
		       "%lu null arg, in %lu cases.\n",
		       cov.denied_unspelled, cov.denied_origin, cov.granted_unguarded,
		       cov.denied_no_chain, cov.granted_by_chain, cov.denied_wrong_cap,
		       cov.denied_expired, cov.denied_null_arg, cases);
		return 1;
	}

	printf("authz_fuzz: %lu cases -- denied %lu unspelled, %lu by origin, %lu with "
	       "no chain, %lu wrong capability, %lu expired, %lu null argument; granted "
	       "%lu unguarded, %lu by chain; every verdict matched the table and its "
	       "polarity\n",
	       cases, cov.denied_unspelled, cov.denied_origin, cov.denied_no_chain,
	       cov.denied_wrong_cap, cov.denied_expired, cov.denied_null_arg,
	       cov.granted_unguarded, cov.granted_by_chain);
	return 0;
}
#endif
