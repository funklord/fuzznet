/* X25519, from Monocypher. See session/agree.h for the seam.
 *
 * MONOCYPHER 4 DOES NOT REPORT A LOW-ORDER PEER KEY, and the first draft of
 * this file said it did. `crypto_x25519` returned `int` in Monocypher 3 and
 * returns `void` in 4.0.3, which is the version this tree vendors -- checked
 * in `monocypher/src/monocypher.h` after the compiler refused the code
 * written from memory of the older API. A description of an interface
 * standing in for the interface, which is the same error this project spent
 * an evening cataloguing about layouts.
 *
 * SO THE CHECK IS HERE, because the reason for it did not go away. A
 * low-order peer key yields a shared secret the attacker chose, and that
 * secret goes into a transcript that derives a key commitment -- a commitment
 * over an attacker-chosen constant commits to nothing. Monocypher's own
 * documentation names the detection: the shared secret comes out ALL ZERO.
 * Verified against a run rather than taken from the manual, in
 * session/test/agree_test.c.
 *
 * The comparison is constant-time and accumulates over all 32 bytes. Not
 * because the timing leaks anything an attacker does not already know -- they
 * chose the key -- but because `constant_time.h` argues that a comparison of
 * secret-derived bytes written the careless way is the one somebody copies.
 */

#include "agree.h"

#include "monocypher.h"

static int mono_public_of(void *ctx, uint8_t public_out[FZN_AGREE_PUBLIC_LEN],
                          const uint8_t secret[FZN_AGREE_SECRET_LEN])
{
	(void)ctx;
	crypto_x25519_public_key(public_out, secret);
	return 1;
}

static int mono_agree(void *ctx, uint8_t shared_out[FZN_AGREE_SHARED_LEN],
                      const uint8_t secret[FZN_AGREE_SECRET_LEN],
                      const uint8_t peer_public[FZN_AGREE_PUBLIC_LEN])
{
	uint8_t any = 0;
	unsigned i;

	(void)ctx;
	crypto_x25519(shared_out, secret, peer_public);

	for (i = 0; i < FZN_AGREE_SHARED_LEN; i++)
		any = (uint8_t)(any | shared_out[i]);
	return any != 0;
}

void fzn_agree_monocypher_init(fzn_agree_ops_t *ops)
{
	if (!ops)
		return;
	ops->public_of = mono_public_of;
	ops->agree = mono_agree;
	ops->ctx = NULL;
}
