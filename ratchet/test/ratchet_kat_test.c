/* THE RATCHET STEP, RECOMPUTED FROM THE SPECIFICATION.
 *
 * WHY THIS FILE EXISTS. `fuzznet-ratchet1` survived a mutation to
 * `fuzznet-ratchet9` with the whole suite green -- 64 binaries, no failure.
 * Every ratchet test advances a chain and checks the result against another
 * advance of the same chain by the same code, so the label cancels out of both
 * sides of every comparison this library makes. See project.md sec 45 for the
 * sweep that found it and for why a domain label is blind in exactly this way.
 *
 * It is not a small constant. ratchet.c's own comment says why the version
 * digit is IN the label: if the step's shape changes, changing the label makes
 * old and new peers derive different keys and fail to talk, "which is the
 * correct failure", against the alternative of "two peers agreeing on a key by
 * hashing different things", found months later. That argument only holds if
 * the label is what the other peer thinks it is, and until this file nothing
 * anywhere held it to a value.
 *
 * THE AUTHORITY IS THE SPECIFICATION, not an independently produced vector --
 * the same limit `session/test/session_kat_test.c` states at length and for
 * the same reason. `expected_step` is written from ratchet.h and computes with
 * Monocypher directly, never calling fzn_ratchet. The label is repeated as a
 * literal rather than included, because a constant shared between code and its
 * own test cannot detect a change to itself.
 *
 * GATED ON MONOCYPHER because it needs the real BLAKE2b.
 */

#include "../ratchet.h"

#include "../../session/hash_monocypher.h"

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

/*
 * From ratchet.h and ratchet.c's derivation:
 *
 *   derived(64)    = BLAKE2b( label(16) | chain key(32) )
 *   message key    = derived[0..32]
 *   next chain key = derived[32..64]
 *
 * ONE hash producing both halves, which is the same construction
 * commitment.c uses for the root and for the same reason: the shared input is
 * what binds the two outputs to each other rather than leaving the second
 * merely accompanying the first.
 */
static void expected_step(const uint8_t chain_key[FZN_CHAIN_KEY_LEN],
                          uint8_t mk_out[FZN_MESSAGE_KEY_LEN],
                          uint8_t next_out[FZN_CHAIN_KEY_LEN])
{
	static const char RATCHET_LABEL[16] = "fuzznet-ratchet1";
	uint8_t input[16 + FZN_CHAIN_KEY_LEN];
	uint8_t derived[FZN_MESSAGE_KEY_LEN + FZN_CHAIN_KEY_LEN];

	memcpy(input, RATCHET_LABEL, 16);
	memcpy(input + 16, chain_key, FZN_CHAIN_KEY_LEN);
	crypto_blake2b(derived, sizeof(derived), input, sizeof(input));

	memcpy(mk_out, derived, FZN_MESSAGE_KEY_LEN);
	memcpy(next_out, derived + FZN_MESSAGE_KEY_LEN, FZN_CHAIN_KEY_LEN);

	crypto_wipe(input, sizeof(input));
	crypto_wipe(derived, sizeof(derived));
}

static const uint8_t CHAIN0[FZN_CHAIN_KEY_LEN] = {
	0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
	0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
	0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
	0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
};

int main(void)
{
	fzn_hash_ops_t hash;
	uint8_t chain[FZN_CHAIN_KEY_LEN];
	uint8_t want_mk[FZN_MESSAGE_KEY_LEN], want_next[FZN_CHAIN_KEY_LEN];
	uint8_t got_mk[FZN_MESSAGE_KEY_LEN], got_next[FZN_CHAIN_KEY_LEN];
	int step;

	fzn_hash_monocypher_init(&hash);

	/* THREE STEPS, not one. A single step pins the label and the split; a
	 * chain pins that the SECOND step's input is the first step's next
	 * chain key rather than anything else that happens to be 32 bytes --
	 * which is the part a reimplementation gets wrong, and the part that
	 * makes this a ratchet rather than a repeated hash. */
	memcpy(chain, CHAIN0, sizeof(chain));
	for (step = 0; step < 3; step++) {
		expected_step(chain, want_mk, want_next);

		check(fzn_ratchet_derive(&hash, chain, got_mk, got_next) == FZN_RATCHET_OK,
		      "the step derives");
		check(memcmp(got_mk, want_mk, sizeof(want_mk)) == 0,
		      "the message key is the one the documented step produces");
		check(memcmp(got_next, want_next, sizeof(want_next)) == 0,
		      "the next chain key is the one the documented step produces");

		/* THE CONTROL. Without it every comparison above is satisfied by
		 * a derivation that returned zeroes, or by one whose two halves
		 * are the same bytes. */
		check(memcmp(want_mk, want_next, FZN_CHAIN_KEY_LEN) != 0,
		      "the two halves of the step are not the same 32 bytes");
		check(memcmp(want_next, chain, FZN_CHAIN_KEY_LEN) != 0,
		      "the chain actually moved");

		memcpy(chain, got_next, sizeof(chain));
	}

	if (failures == 0)
		printf("ratchet_kat_test: %d checks OK\n", checks);
	else
		fprintf(stderr, "ratchet_kat_test: %d of %d FAILED\n", failures, checks);
	return failures ? 1 : 0;
}
