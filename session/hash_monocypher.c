/* BLAKE2b behind commitment.h's hash seam. See hash_monocypher.h. */

#include "hash_monocypher.h"

#include <monocypher.h>

/* Monocypher's crypto_blake2b takes the output length and returns nothing;
 * the seam wants nonzero for success, so the only failure this can report
 * is a length Monocypher will not produce.
 *
 * Bounded here rather than trusted: BLAKE2b's digest length lives in its
 * parameter block, so asking for a length outside 1..64 is not a smaller
 * hash, it is a different function or an assertion inside the library. The
 * seam is called with FZN_DERIVED_LEN today, which is 64, but a caller is
 * not obliged to know that. */
/* THE LARGEST DERIVATION IN THIS LIBRARY MUST FIT WHAT BLAKE2b CAN PRODUCE,
 * and this is the cheapest place to say so: 64 is the parameter block's
 * maximum, not a limit chosen here, so a derivation that outgrows it cannot
 * be served by this binding at all.
 *
 * IT IS A BUILD ERROR RATHER THAN A REFUSAL AT RUN TIME. `commitment_test.c`
 * already catches the growth by counting what the seam is asked for -- that
 * is where the guard lives and it is a better one, because it holds with no
 * Monocypher present at all. This adds only earliness: the constant is the
 * thing compared, so growing it stops the build of the binding that could
 * not serve it, in the tree that grew it.
 *
 * The comparison is sound in the way `evidence.md` requires of an assertion
 * like this: it weighs the CONSTANT the caller passes, not a buffer size
 * that would stay true while the request shrank. */
#include "commitment.h"

_Static_assert(FZN_DERIVED_LEN <= 64,
               "a derivation has outgrown BLAKE2b's maximum output length");

static int mono_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	(void)ctx;

	if (!out || !in || out_len == 0 || out_len > 64)
		return 0;

	crypto_blake2b(out, out_len, in, in_len);
	return 1;
}

void fzn_hash_monocypher_init(fzn_hash_ops_t *ops)
{
	if (!ops)
		return;

	ops->hash = mono_hash;
	ops->ctx = NULL;
}
