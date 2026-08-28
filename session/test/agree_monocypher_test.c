/* Tests for session/agree_monocypher.c: real X25519 behind the seam.
 *
 * THE FIVE LOW-ORDER POINTS ARE PUBLISHED CONSTANTS, not values this tree
 * generated, which is what makes them evidence rather than a second copy of
 * the implementation's opinion. A peer sending one of these gets a shared
 * secret every attacker already knows -- and Monocypher 4 does not report it,
 * because `crypto_x25519` stopped returning a status in 4.0. The binding
 * detects it by the documented route, an all-zero output, and this file is
 * where that route stops being a claim from a manual.
 */

#include "../agree.h"
#include "../agree_monocypher.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void expect(int ok, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		fprintf(stderr, "  FAIL: %s\n", what);
	}
}

/* The small-order points of Curve25519, as published. */
static const uint8_t LOW_ORDER[5][FZN_AGREE_PUBLIC_LEN] = {
	{ 0 },
	{ 1 },
	{ 0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3,
	  0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32,
	  0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00 },
	{ 0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1,
	  0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c,
	  0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57 },
	{ 0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
};

int main(void)
{
	fzn_agree_ops_t ops;
	fzn_agree_secret_t alice, bob;
	uint8_t alice_secret[FZN_AGREE_SECRET_LEN], bob_secret[FZN_AGREE_SECRET_LEN];
	uint8_t shared_a[FZN_AGREE_SHARED_LEN], shared_b[FZN_AGREE_SHARED_LEN];
	unsigned i;

	fzn_agree_monocypher_init(&ops);
	expect(ops.public_of != NULL && ops.agree != NULL,
	       "the binding installed no ops, so nothing below is testing X25519");

	memset(&alice, 0, sizeof(alice));
	memset(&bob, 0, sizeof(bob));
	for (i = 0; i < FZN_AGREE_SECRET_LEN; i++) {
		alice_secret[i] = (uint8_t)(i + 3u);
		bob_secret[i] = (uint8_t)((i * 5u) + 11u);
	}

	expect(fzn_agree_secret_install(&alice, &ops, alice_secret) == FZN_AGREE_OK,
	       "installing alice refused");
	expect(fzn_agree_secret_install(&bob, &ops, bob_secret) == FZN_AGREE_OK,
	       "installing bob refused");
	expect(fzn_agree_secret_public(&alice) != NULL && fzn_agree_secret_public(&bob) != NULL,
	       "an installed secret offered no public key");

	if (!fzn_agree_secret_public(&alice) || !fzn_agree_secret_public(&bob)) {
		printf("agree_monocypher_test: %d checks, %d failure(s)\n", checks, failures);
		return 1;
	}

	/* THE PROPERTY THAT MAKES IT A KEY AGREEMENT AT ALL. Two hosts that
	 * have never met derive the same secret from opposite halves. */
	expect(fzn_agree_shared(&alice, &ops, fzn_agree_secret_public(&bob), shared_a)
	               == FZN_AGREE_OK, "alice could not agree with bob");
	expect(fzn_agree_shared(&bob, &ops, fzn_agree_secret_public(&alice), shared_b)
	               == FZN_AGREE_OK, "bob could not agree with alice");
	expect(memcmp(shared_a, shared_b, FZN_AGREE_SHARED_LEN) == 0,
	       "the two sides derived different secrets, so this is not an agreement");

	/* And it is not a constant: a different peer gives a different secret,
	 * which a stub returning fixed bytes would also have to pass. */
	{
		uint8_t other_secret[FZN_AGREE_SECRET_LEN];
		fzn_agree_secret_t other;
		uint8_t shared_c[FZN_AGREE_SHARED_LEN];

		memset(&other, 0, sizeof(other));
		for (i = 0; i < FZN_AGREE_SECRET_LEN; i++)
			other_secret[i] = (uint8_t)((i * 7u) + 29u);
		expect(fzn_agree_secret_install(&other, &ops, other_secret) == FZN_AGREE_OK,
		       "installing a third party refused");
		if (fzn_agree_secret_public(&other)) {
			expect(fzn_agree_shared(&alice, &ops, fzn_agree_secret_public(&other),
			                        shared_c) == FZN_AGREE_OK,
			       "alice could not agree with a third party");
			expect(memcmp(shared_a, shared_c, FZN_AGREE_SHARED_LEN) != 0,
			       "two different peers gave alice the same shared secret");
		}
	}

	/* THE LOW-ORDER REFUSAL, against every published point. Monocypher 4
	 * does not report these; the binding detects the all-zero output that
	 * its documentation names, and this is where that stops being a claim
	 * read from a manual. */
	for (i = 0; i < 5u; i++) {
		uint8_t out[FZN_AGREE_SHARED_LEN];
		unsigned j;
		int all_zero = 1;

		memset(out, 0x77, sizeof(out));
		expect(fzn_agree_shared(&alice, &ops, LOW_ORDER[i], out)
		               == FZN_AGREE_ERR_DEGENERATE,
		       "a low-order peer key produced a usable shared secret");
		for (j = 0; j < FZN_AGREE_SHARED_LEN; j++)
			if (out[j] != 0u)
				all_zero = 0;
		expect(all_zero, "a refused agreement left the attacker's constant in the buffer");
	}

	/* THE CONTROL, and it is what stops the loop above passing for a
	 * binding that refuses everything. */
	expect(fzn_agree_shared(&alice, &ops, fzn_agree_secret_public(&bob), shared_a)
	               == FZN_AGREE_OK,
	       "an honest peer key was refused, so the refusals above prove nothing");

	printf("agree_monocypher_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
