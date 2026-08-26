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

/* IS FZN_SECRET_KEY_LEN BIG ENOUGH FOR THE PRIMITIVE IT FEEDS?
 *
 * Nothing asked until now. The constant appears in exactly two places -- the
 * `secret_key` field of `fzn_sign_monocypher_t` and a buffer in this file --
 * and BOTH TRACK IT, so changing it moves the declaration and its only users
 * together and every test still passes. Found by mutation: 64 to 65 and 64 to
 * 63 both leave the whole suite green, with the Monocypher bindings built.
 * Undersized, `crypto_eddsa_key_pair` writes past the field into whatever
 * follows it in the struct.
 *
 * Monocypher cannot be asserted against at compile time. It declares
 * `crypto_eddsa_key_pair(uint8_t secret_key[64], ...)` and defines no size
 * macros, and an array parameter decays to a pointer, so the 64 is not a
 * symbol anything can compare with. That leaves measuring what it writes.
 *
 * The canary sits PAST the end of a buffer of exactly FZN_SECRET_KEY_LEN, so
 * a constant smaller than what Monocypher writes is caught by the write
 * landing in it. This says the size is sufficient; it cannot say it is
 * necessary, and a value too large is harmless here in a way too small is
 * not. */
static void check_secret_key_len(void)
{
	uint8_t buf[FZN_SECRET_KEY_LEN + 16];
	uint8_t pubkey[FZN_PUBKEY_LEN];
	uint8_t seed[32];
	int intact = 1;

	memset(seed, 0x11, sizeof(seed));
	memset(buf, 0, sizeof(buf));
	memset(buf + FZN_SECRET_KEY_LEN, 0xA5, 16);

	crypto_eddsa_key_pair(buf, pubkey, seed);

	for (size_t i = FZN_SECRET_KEY_LEN; i < sizeof(buf); i++)
		if (buf[i] != 0xA5u) {
			intact = 0;
			break;
		}
	check(intact, "crypto_eddsa_key_pair wrote past FZN_SECRET_KEY_LEN bytes");
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
	check_secret_key_len();

	crypto_eddsa_key_pair(signer.secret_key, pubkey, seed);
	signer.can_sign = 1;
	fzn_sign_monocypher_init(&ops, &signer);

	memset(grantee, 0xaa, sizeof(grantee));
	memset(cap, 0xc0, sizeof(cap));

	/* Mint under a real key, then verify with a real check. If the two
	 * conventions disagree this is where it shows. */
	check(fzn_chain_mint(pubkey, grantee, cap, 1000, FZN_NO_EXPIRY, 0, region, region_len,
	                     &ops, &hop) == FZN_CHAIN_OK,
	      "minting with a real Ed25519 key failed");
	check(fzn_chain_verify(&hop, 1, pubkey, cap, 2000, &ops, NULL, 0, &out) == FZN_CHAIN_OK,
	      "a genuinely signed hop did not verify");

	/* The negative half, and it is the one that matters. If mono_verify
	 * had the sense of crypto_eddsa_check backwards, the case above would
	 * still pass and this would not -- so a suite with only the case above
	 * would report a working binding either way. */
	hop.signature[0] ^= 0x01;
	check(fzn_chain_verify(&hop, 1, pubkey, cap, 2000, &ops, NULL, 0, &out) ==
	              FZN_CHAIN_ERR_CHAIN_INVALID,
	      "a tampered signature verified");
	hop.signature[0] ^= 0x01;

	/* Signed bytes are covered too, not just the signature. */
	{
		static uint8_t tampered[sizeof(region)];
		memcpy(tampered, region, region_len);
		tampered[0] ^= 0x01;
		hop.signed_region = tampered;
		check(fzn_chain_verify(&hop, 1, pubkey, cap, 2000, &ops, NULL, 0, &out) ==
		              FZN_CHAIN_ERR_CHAIN_INVALID,
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
	              FZN_CHAIN_ERR_WRONG_ROOT,
	      "a hop verified under somebody else's root");

	/* A verify-only signer refuses to sign rather than signing with a
	 * zeroed key -- which would be a real signature under a real public
	 * key that nobody owns, and a verifier would accept it. */
	memset(&verifier, 0, sizeof(verifier));
	fzn_sign_monocypher_init(&verify_only, &verifier);
	check(fzn_chain_mint(pubkey, grantee, cap, 1000, FZN_NO_EXPIRY, 0, region, region_len,
	                     &verify_only, &hop) == FZN_CHAIN_ERR_CHAIN_INVALID,
	      "a verify-only signer signed with a zeroed key");
	/* ...but it still verifies, which is the whole point of holding no key. */
	check(fzn_chain_mint(pubkey, grantee, cap, 1000, FZN_NO_EXPIRY, 0, region, region_len,
	                     &ops, &hop) == FZN_CHAIN_OK,
	      "re-minting failed");
	check(fzn_chain_verify(&hop, 1, pubkey, cap, 2000, &verify_only, NULL, 0, &out) == FZN_CHAIN_OK,
	      "a verify-only signer could not verify");

	fzn_sign_monocypher_wipe(&signer);
	check(signer.can_sign == 0, "wipe left the signer able to sign");

	/* The guards, which nothing reached until `make coverage` could see
	 * this file at all. It is built only when MONOCYPHER_DIR names a
	 * checkout, and `SRCS` did not list it, so the target written to refuse
	 * an unexercised source could not refuse this one.
	 *
	 * `!state->can_sign` is the one that matters. A signer with no key must
	 * refuse rather than sign with a buffer of zeroes: that would produce a
	 * valid signature under the public key a zero secret derives, a real
	 * key owned by nobody, which a verifier would accept. */
	{
		fzn_sign_monocypher_t empty;
		/* `empty_ops` rather than `ops`, which shadowed the signer set up
		 * at the top of main. The compiler said so under -Wshadow from
		 * the moment this block was added and the build output was being
		 * read for "error" and "FAIL", neither of which a warning is. */
		fzn_sign_ops_t empty_ops;
		uint8_t sig[FZN_SIG_LEN];
		static const uint8_t msg[] = "a message";

		memset(&empty, 0, sizeof(empty));
		fzn_sign_monocypher_init(&empty_ops, &empty);
		check(empty_ops.sign(&empty, sig, msg, sizeof(msg) - 1) == 0,
		      "a signer holding no key signed anyway");
		check(empty_ops.sign(NULL, sig, msg, sizeof(msg) - 1) == 0,
		      "a null signer state signed");

		/* Both `init` and `wipe` accept a null and must simply return. */
		fzn_sign_monocypher_init(NULL, &empty);
		check(1, "init with a null ops did not crash");
		fzn_sign_monocypher_wipe(NULL);
		check(1, "wipe with a null state did not crash");
	}

	printf("sign_monocypher_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
