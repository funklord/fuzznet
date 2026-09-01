/* ONE MINTED HOP, RECOMPUTED FROM THE LAYOUT TABLE IN chain.h.
 *
 * WHAT WAS MISSING, MEASURED FIRST. `FZN_HOP_OFF_GRANTOR` and
 * `FZN_HOP_OFF_GRANTEE` were exchanged -- 2 and 34, both 32-byte fields, so
 * every length is unchanged and the mutation is a pure layout change -- and
 * the suite stayed green. All 64 binaries. The same swap of
 * `FZN_HOP_OFF_ISSUED_AT` and `FZN_HOP_OFF_EXPIRES_AT` also survived.
 *
 * Every chain test mints with this library and verifies with this library, so
 * the offsets cancel out of both sides of every comparison. That is the same
 * blindness project.md sec 45 records for the domain labels, one layer up: not
 * a missing assertion inside a module, but a whole ARTIFACT that only ever
 * meets itself.
 *
 * WHY IT MATTERS MORE HERE THAN FOR A LABEL. A hop is a signed certificate
 * that travels between hosts and carries authority. chain.h prints the offset
 * table and says exactly what it is for: "two implementations which agree on
 * this table cannot produce different bytes for the same grant, which is
 * exactly what a signature over them requires". THAT IS A CLAIM ABOUT A SECOND
 * IMPLEMENTATION, and until this file the table was a comment -- a consumer
 * that read it and a library that drifted from it would produce hops that each
 * verified at home and nowhere else.
 *
 * `wire/test/constants_test.c` is the nearest thing that existed, and it is
 * worth saying why it does not cover this. It compares hand-written constants
 * against the GENERATED ones from `wire/frame.situ`, for the four modules that
 * share a field with the frame. A hop is a chain certificate rather than a
 * frame field, so it has no generated counterpart to disagree with -- which is
 * precisely why nothing noticed.
 *
 * THE AUTHORITY IS THE HEADER'S TABLE, with the limit `session_kat_test`
 * states: this compares the library against its own documented layout, not
 * against an independently produced artifact, so it cannot catch a table that
 * is itself wrong. It catches the code drifting from the table, and the table
 * is what a consumer implements.
 *
 * WHY A VECTOR IS POSSIBLE AT ALL. Ed25519 signing is deterministic -- no
 * nonce is drawn -- so a hop minted from a fixed seed and fixed inputs is
 * reproducible without the API growing any way to supply randomness. The same
 * property golden_frame_test gets from `fzn_random_ops_t`, obtained here for
 * free from the primitive.
 *
 * GATED ON MONOCYPHER because it needs the real Ed25519.
 */

#include "../chain.h"

#include "../sign_monocypher.h"

#include "monocypher.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check(int ok, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		fprintf(stderr, "  FAIL: %s\n", what);
	}
}

/* The inputs. Fixed and not secret -- a seed, so the keypair is reproducible
 * without this file holding a private key it did not derive. */
#define SEED_BYTE 0x2bu

static const uint8_t GRANTEE[FZN_PUBKEY_LEN] = {
	0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
	0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60,
	0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
	0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
};

static const fzn_cap_id_t CAPABILITY = { {
	0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
	0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0,
	0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
	0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
} };

/* Chosen so the two timestamps differ in EVERY byte. Exchanging the two
 * offsets was one of the mutations that survived, and two round numbers would
 * have let a swap through wherever their bytes happened to agree. */
#define ISSUED_AT  0x0102030405060708u
#define EXPIRES_AT 0xf1e2d3c4b5a69788u
#define DELEGABLE  1

/*
 * THE LAYOUT, WRITTEN OUT FROM chain.h's TABLE:
 *
 *     offset  size  field
 *          0     1  version    (= FZN_SIGNED_VERSION)
 *          1     1  object     (= FZN_OBJECT_HOP)
 *          2    32  grantor
 *         34    32  grantee
 *         66    32  capability
 *         98     8  issued_at
 *        106     8  expires_at
 *        114     1  delegable
 *        115    64  signature over bytes 0..114
 *
 * The offsets are written as LITERALS rather than through FZN_HOP_OFF_*, and
 * the two byte values as literals rather than through FZN_SIGNED_VERSION and
 * FZN_OBJECT_HOP. That is the whole point: a constant shared between the code
 * and its own test cannot detect a change to itself, and the mutations that
 * survived moved exactly those macros. The timestamps are written big-endian
 * by hand for the same reason.
 */
static void expected_hop(const uint8_t secret_key[64], const uint8_t grantor[FZN_PUBKEY_LEN],
                         uint8_t out[FZN_HOP_LEN])
{
	unsigned i;

	out[0] = 1u;   /* version */
	out[1] = 128u; /* object: hop */
	memcpy(out + 2, grantor, 32);
	memcpy(out + 34, GRANTEE, 32);
	memcpy(out + 66, CAPABILITY.b, 32);
	for (i = 0u; i < 8u; i++) {
		out[98 + i] = (uint8_t)(((uint64_t)ISSUED_AT) >> (8u * (7u - i)));
		out[106 + i] = (uint8_t)(((uint64_t)EXPIRES_AT) >> (8u * (7u - i)));
	}
	out[114] = 1u; /* delegable */

	/* Over bytes 0 through 114 inclusive -- the whole body, version and
	 * object byte included, which chain.h says neither could be added
	 * later without breaking every signature already issued. */
	crypto_eddsa_sign(out + 115, secret_key, out, 115);
}

int main(void)
{
	fzn_sign_ops_t ops;
	fzn_sign_monocypher_t signer;
	uint8_t seed[32];
	uint8_t grantor[FZN_PUBKEY_LEN];
	uint8_t want[FZN_HOP_LEN];
	uint8_t got[FZN_HOP_LEN];

	memset(seed, SEED_BYTE, sizeof(seed));
	crypto_eddsa_key_pair(signer.secret_key, grantor, seed);
	signer.can_sign = 1;
	fzn_sign_monocypher_init(&ops, &signer);

	/* The constants the layout depends on, stated here and asserted equal.
	 * This is `chain_fuzz.c`'s oracle pattern and costs no run time: if
	 * FZN_HOP_LEN or the body length moves, the build stops rather than
	 * the comparison below quietly measuring a different thing. */
	check(FZN_HOP_LEN == 179u, "a hop is 179 bytes");
	check(FZN_HOP_BODY_LEN == 115u, "the signed body is 115 bytes");
	check(FZN_SIG_LEN == 64, "the signature is 64 bytes");

	expected_hop(signer.secret_key, grantor, want);

	check(fzn_chain_mint(grantor, GRANTEE, &CAPABILITY, ISSUED_AT, EXPIRES_AT, DELEGABLE,
	                     &ops, got)
	              == FZN_CHAIN_OK,
	      "the hop mints");

	/* THE WHOLE ARTIFACT, not a field at a time. Comparing field by field
	 * through the library's own offsets would reintroduce exactly the
	 * blindness this file exists to remove. */
	check(memcmp(got, want, FZN_HOP_LEN) == 0,
	      "the minted hop is the bytes chain.h's table specifies");

	/* WHERE IT DISAGREES, if it does -- so a failure names a field rather
	 * than sending the reader to a hex dump. Only run on failure, since on
	 * success there is nothing to say. */
	if (memcmp(got, want, FZN_HOP_LEN) != 0) {
		size_t i;
		for (i = 0; i < FZN_HOP_LEN; i++)
			if (got[i] != want[i]) {
				fprintf(stderr, "  first difference at offset %zu: "
				                "got 0x%02x want 0x%02x\n",
				        i, got[i], want[i]);
				break;
			}
	}

	/* THE CONTROLS. Without these the comparison above is satisfied by a
	 * mint that wrote nothing, and by a layout in which the two 32-byte
	 * public keys or the two timestamps are interchangeable -- which is
	 * precisely what the surviving mutations exchanged. */
	{
		uint8_t zero[FZN_HOP_LEN];
		memset(zero, 0, sizeof(zero));
		check(memcmp(want, zero, FZN_HOP_LEN) != 0, "the hop is not all zero");
		check(memcmp(grantor, GRANTEE, FZN_PUBKEY_LEN) != 0,
		      "grantor and grantee differ, so exchanging them is visible");
		check(ISSUED_AT != EXPIRES_AT,
		      "the timestamps differ, so exchanging them is visible");
	}

	fzn_sign_monocypher_wipe(&signer);

	if (failures == 0)
		printf("hop_kat_test: %d checks OK\n", checks);
	else
		fprintf(stderr, "hop_kat_test: %d of %d FAILED\n", failures, checks);
	return failures ? 1 : 0;
}
