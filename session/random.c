/* See random.h. */

#include "random.h"

#include <string.h>

int fzn_nonce_next(const fzn_random_ops_t *rng, uint8_t out[FZN_AEAD_NONCE_LEN])
{
	if (!rng || !rng->fill || !out)
		return 0;

	if (!rng->fill(rng->ctx, out, FZN_AEAD_NONCE_LEN)) {
		/* Cleared on failure so that a caller who ignores the return
		 * value sends zeroes rather than whatever the source managed
		 * before it gave up -- which could be most of a nonce, and a
		 * partly-fresh nonce is the case that looks fine in a capture.
		 * Zeroes are wrong in a way somebody notices. */
		memset(out, 0, FZN_AEAD_NONCE_LEN);
		return 0;
	}

	return 1;
}
