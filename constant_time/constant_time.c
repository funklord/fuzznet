/* See constant_time.h. */

#include "constant_time.h"

#include <stdint.h>

/* Written out rather than taken from a library because project.md sec 4.5
 * vendors exactly one dependency and this is four lines.
 *
 * `volatile` on the accumulator is what stops a compiler noticing the
 * result is a boolean and reintroducing the early exit it was written to
 * avoid. -Os is an optimiser like any other, and this is the one place in
 * the library where being outsmarted is a vulnerability rather than a
 * surprise. */
int fzn_ct_memeq(const void *a, const void *b, size_t len)
{
	const uint8_t *pa = (const uint8_t *)a;
	const uint8_t *pb = (const uint8_t *)b;
	volatile uint8_t diff = 0;

	for (size_t i = 0; i < len; i++)
		diff |= (uint8_t)(pa[i] ^ pb[i]);

	return diff == 0;
}
