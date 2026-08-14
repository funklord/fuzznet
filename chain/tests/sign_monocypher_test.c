/* A real Ed25519 round trip through chain.h's signer seam.
 *
 * Built only when MONOCYPHER_DIR is set (see the Makefile), because
 * Monocypher is not vendored here yet. It exists because chain_test.c
 * drives every path in chain.c with a stub that answers on demand, and a
 * stub proves the LOGIC and nothing about the binding: a seam that has only
 * ever had a fake behind it is a seam nobody has checked. This is the
 * positive control for it.
 *
 * Concretely, it is what catches an argument order swapped between
 * Monocypher's convention and ours -- crypto_eddsa_check returns 0 for
 * good, the seam wants nonzero for good -- which no amount of stub testing
 * can see, and which would make every signature verify or none.
 */

#include "../sign_monocypher.h"

#include <monocypher.h>
#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check(int ok, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL: %s\n", what);
	}
}

/* A deterministic seed. Not secret, not random, and deliberately neither:
 * a test that generated a key from the system entropy pool would be a test
 * whose failures could not be reproduced from the source alone. */
static void seed_bytes(uint8_t out[32], uint8_t v)
{
	memset(out, v, 32);
}

int main(void)
{
	uint8_t seed[32], pubkey[FZN_PUBKEY_LEN];
	uint8_t other_seed[32], other_pub[FZN_PUBKEY_LEN];
	fzn_sign_monocypher_t signer, verifier;
	fzn_sign_ops_t ops, verify_only;
	fzn_chain_hop_t hop;
	fzn_chain_t out;
	uint8_t grantee[FZN_PUBKEY_LEN], cap[FZN_CAP_ID_LEN];
	static const uint8_t region[] = "hop 0, as the schema would lay it out";
	const size_t region_len = sizeof(region) - 1;

	memset(&signer, 0, sizeof(signer));
	seed_bytes(seed, 0x11);
	crypto_eddsa_key_pair(signer.secret_key, pubkey, seed);
	signer.can_sign = 1;
	fzn_sign_monocypher_init(&ops, &signer);

	memset(grantee, 0xaa, sizeof(grantee));
	memset(cap, 0xc0, sizeof(cap));

	/* Mint under a real key, then verify with a real check. If the two
	 * conventions disagree this is where it shows. */
	check(fzn_chain_mint(pubkey, grantee, cap, 1000, FZN_NO_EXPIRY, 0, region, region_len,
	                     &ops, &hop) == FZN_OK,
	      "minting with a real Ed25519 key failed");
	check(fzn_chain_verify(&hop, 1, pubkey, cap, 2000, &ops, NULL, 0, &out) == FZN_OK,
	      "a genuinely signed hop did not verify");

	/* The negative half, and it is the one that matters. If mono_verify
	 * had the sense of crypto_eddsa_check backwards, the case above would
	 * still pass and this would not -- so a suite with only the case above
	 * would report a working binding either way. */
	hop.signature[0] ^= 0x01;
	check(fzn_chain_verify(&hop, 1, pubkey, cap, 2000, &ops, NULL, 0, &out) ==
	              FZN_ERR_CHAIN_INVALID,
	      "a tampered signature verified");
	hop.signature[0] ^= 0x01;

	/* Signed bytes are covered too, not just the signature. */
	{
		static uint8_t tampered[sizeof(region)];
		memcpy(tampered, region, region_len);
		tampered[0] ^= 0x01;
		hop.signed_region = tampered;
		check(fzn_chain_verify(&hop, 1, pubkey, cap, 2000, &ops, NULL, 0, &out) ==
		              FZN_ERR_CHAIN_INVALID,
		      "a modified signed region verified");
		hop.signed_region = region;
	}

	/* A different key must not open it. */
	seed_bytes(other_seed, 0x22);
	{
		uint8_t other_sk[FZN_SECRET_KEY_LEN];
		crypto_eddsa_key_pair(other_sk, other_pub, other_seed);
		crypto_wipe(other_sk, sizeof(other_sk));
	}
	check(fzn_chain_verify(&hop, 1, other_pub, cap, 2000, &ops, NULL, 0, &out) ==
	              FZN_ERR_WRONG_ROOT,
	      "a hop verified under somebody else's root");

	/* A verify-only signer refuses to sign rather than signing with a
	 * zeroed key -- which would be a real signature under a real public
	 * key that nobody owns, and a verifier would accept it. */
	memset(&verifier, 0, sizeof(verifier));
	fzn_sign_monocypher_init(&verify_only, &verifier);
	check(fzn_chain_mint(pubkey, grantee, cap, 1000, FZN_NO_EXPIRY, 0, region, region_len,
	                     &verify_only, &hop) == FZN_ERR_CHAIN_INVALID,
	      "a verify-only signer signed with a zeroed key");
	/* ...but it still verifies, which is the whole point of holding no key. */
	check(fzn_chain_mint(pubkey, grantee, cap, 1000, FZN_NO_EXPIRY, 0, region, region_len,
	                     &ops, &hop) == FZN_OK,
	      "re-minting failed");
	check(fzn_chain_verify(&hop, 1, pubkey, cap, 2000, &verify_only, NULL, 0, &out) == FZN_OK,
	      "a verify-only signer could not verify");

	fzn_sign_monocypher_wipe(&signer);
	check(signer.can_sign == 0, "wipe left the signer able to sign");

	printf("sign_monocypher_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
