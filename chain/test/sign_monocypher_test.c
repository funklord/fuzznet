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
 *
 * IT ALSO RUNS THE FORGERY ONCE UNDER A REAL PRIMITIVE (2026-08-27). The
 * stub suites take a genuinely signed hop, rewrite one field, keep the
 * signature byte-identical and require a refusal -- the attack chain.h's
 * design note describes. They do it per field, which is where that belongs.
 * Doing it once here is what stops the whole argument resting on a toy MAC
 * agreeing with itself: the bytes below were signed by Ed25519 and the
 * refusal is Ed25519's.
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
	uint8_t bytes[FZN_HOP_LEN], genuine[FZN_HOP_LEN];
	fzn_chain_hop_t hop;
	fzn_chain_t out;
	uint8_t grantee[FZN_PUBKEY_LEN];
	fzn_cap_id_t cap;

	memset(&signer, 0, sizeof(signer));
	seed_bytes(seed, 0x11);
	check_secret_key_len();

	crypto_eddsa_key_pair(signer.secret_key, pubkey, seed);
	signer.can_sign = 1;
	fzn_sign_monocypher_init(&ops, &signer);

	memset(grantee, 0xaa, sizeof(grantee));
	memset(cap.b, 0xc0, sizeof(cap));

	/* Mint under a real key, then verify with a real check. If the two
	 * conventions disagree this is where it shows. */
	check(fzn_chain_mint(pubkey, grantee, &cap, 1000, FZN_NO_EXPIRY, 0, &ops, bytes) ==
	              FZN_CHAIN_OK,
	      "minting with a real Ed25519 key failed");
	check(fzn_hop_open(bytes, FZN_HOP_LEN, &hop) == FZN_CHAIN_OK,
	      "a hop minted with a real key does not open");
	check(fzn_chain_verify(&hop, 1, pubkey, &cap, 2000, &ops, NULL, &out) == FZN_CHAIN_OK,
	      "a genuinely signed hop did not verify");
	memcpy(genuine, bytes, FZN_HOP_LEN);

	/* The negative half, and it is the one that matters. If mono_verify
	 * had the sense of crypto_eddsa_check backwards, the case above would
	 * still pass and this would not -- so a suite with only the case above
	 * would report a working binding either way. */
	bytes[FZN_HOP_OFF_SIGNATURE] ^= 0x01;
	check(fzn_chain_verify(&hop, 1, pubkey, &cap, 2000, &ops, NULL, &out) ==
	              FZN_CHAIN_ERR_CHAIN_INVALID,
	      "a tampered signature verified");
	memcpy(bytes, genuine, FZN_HOP_LEN);

	/* THE FORGERY chain.h's DESIGN NOTE DESCRIBES, UNDER REAL ED25519
	 * RATHER THAN A STUB.
	 *
	 * The stub suites run this attack once per field, which is where it
	 * belongs -- they are cheap and they can name what they mutated. This
	 * runs it against the primitive that will actually be deployed, so
	 * that the whole argument does not rest on a toy MAC agreeing with
	 * itself. Every rewrite keeps the 64 signature bytes byte-identical,
	 * which is exactly what the old design permitted, because the fields
	 * it decided from were a separate struct nothing compared with the
	 * signed bytes.
	 *
	 * The positive control is the verification above: these same bytes,
	 * unmodified, verified under this same key a moment ago. */
	{
		/* Whole fields, not single bytes. A one-byte poke into
		 * `issued_at` or `expires_at` produces a nearby number rather
		 * than the value an attacker wants, and the refusal then comes
		 * from the date check instead of from the signature -- the
		 * right answer for the wrong reason, which is the thing this
		 * file exists to avoid reporting. */
		static const struct {
			const char *what;
			size_t off;
			size_t len;
			uint8_t value;
		} FORGERY[] = {
			{ "grantee rewritten to the attacker's key", FZN_HOP_OFF_GRANTEE,
			  FZN_PUBKEY_LEN, 0xee },
			{ "capability rewritten to another", FZN_HOP_OFF_CAPABILITY,
			  FZN_CAP_ID_LEN, 0xff },
			{ "delegable flipped on", FZN_HOP_OFF_DELEGABLE, 1u, 1u },
			{ "issued_at re-dated", FZN_HOP_OFF_ISSUED_AT, 8u, 0x7f },
		};

		for (size_t i = 0; i < sizeof(FORGERY) / sizeof(FORGERY[0]); i++) {
			fzn_chain_hop_t forged;

			memcpy(bytes, genuine, FZN_HOP_LEN);
			memset(bytes + FORGERY[i].off, FORGERY[i].value, FORGERY[i].len);
			check(memcmp(bytes, genuine, FZN_HOP_LEN) != 0,
			      "a forgery case changed nothing, so it tests nothing");
			check(memcmp(bytes + FZN_HOP_OFF_SIGNATURE,
			             genuine + FZN_HOP_OFF_SIGNATURE, FZN_SIG_LEN) == 0,
			      "a forgery case altered the signature, so it is not reuse");
			check(fzn_hop_open(bytes, FZN_HOP_LEN, &forged) == FZN_CHAIN_OK,
			      "a forged hop no longer opens, so the case below would be "
			      "about its shape rather than about its signature");
			check(fzn_chain_verify(&forged, 1, pubkey, &cap, 2000, &ops, NULL,
			                       &out) == FZN_CHAIN_ERR_CHAIN_INVALID,
			      "a genuine Ed25519 signature was reused over rewritten bytes "
			      "and the chain verified");
		}
		memcpy(bytes, genuine, FZN_HOP_LEN);
	}

	/* EXPIRES_AT needs a hop that has one, so it gets its own. The attack
	 * is to turn a time-boxed grant into a permanent one by writing
	 * FZN_NO_EXPIRY over the field, and FZN_NO_EXPIRY is zero -- so the
	 * forged hop skips the date check entirely and only the signature is
	 * left to refuse it. */
	{
		uint8_t boxed[FZN_HOP_LEN];
		fzn_chain_hop_t forged;

		check(fzn_chain_mint(pubkey, grantee, &cap, 1000, 1500, 0, &ops, boxed) ==
		              FZN_CHAIN_OK,
		      "minting a time-boxed grant failed");
		check(fzn_hop_open(boxed, FZN_HOP_LEN, &forged) == FZN_CHAIN_OK, "open");
		check(fzn_chain_verify(&forged, 1, pubkey, &cap, 1400, &ops, NULL, &out) ==
		              FZN_CHAIN_OK,
		      "the control for the expiry forgery does not verify while it is live");
		check(fzn_chain_verify(&forged, 1, pubkey, &cap, 2000, &ops, NULL, &out) ==
		              FZN_CHAIN_ERR_EXPIRED,
		      "the grant did not expire, so there is nothing to forge past");

		memset(boxed + FZN_HOP_OFF_EXPIRES_AT, 0, 8);
		check(fzn_hop_open(boxed, FZN_HOP_LEN, &forged) == FZN_CHAIN_OK, "open");
		check(fzn_chain_verify(&forged, 1, pubkey, &cap, 2000, &ops, NULL, &out) ==
		              FZN_CHAIN_ERR_CHAIN_INVALID,
		      "expires_at was rewritten to FZN_NO_EXPIRY under a genuine Ed25519 "
		      "signature and the expired grant verified");
	}

	/* A different key must not open it. */
	seed_bytes(other_seed, 0x22);
	{
		uint8_t other_sk[FZN_SECRET_KEY_LEN];
		crypto_eddsa_key_pair(other_sk, other_pub, other_seed);
		crypto_wipe(other_sk, sizeof(other_sk));
	}
	check(fzn_chain_verify(&hop, 1, other_pub, &cap, 1500, &ops, NULL, &out) ==
	              FZN_CHAIN_ERR_WRONG_ROOT,
	      "a hop verified under somebody else's root");

	/* A verify-only signer refuses to sign rather than signing with a
	 * zeroed key -- which would be a real signature under a real public
	 * key that nobody owns, and a verifier would accept it. */
	memset(&verifier, 0, sizeof(verifier));
	fzn_sign_monocypher_init(&verify_only, &verifier);
	check(fzn_chain_mint(pubkey, grantee, &cap, 1000, FZN_NO_EXPIRY, 0, &verify_only,
	                     bytes) == FZN_CHAIN_ERR_CHAIN_INVALID,
	      "a verify-only signer signed with a zeroed key");
	/* ...but it still verifies, which is the whole point of holding no key. */
	check(fzn_chain_mint(pubkey, grantee, &cap, 1000, FZN_NO_EXPIRY, 0, &ops, bytes) ==
	              FZN_CHAIN_OK,
	      "re-minting failed");
	check(fzn_hop_open(bytes, FZN_HOP_LEN, &hop) == FZN_CHAIN_OK,
	      "the re-minted hop does not open");
	check(fzn_chain_verify(&hop, 1, pubkey, &cap, 2000, &verify_only, NULL, &out) == FZN_CHAIN_OK,
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
