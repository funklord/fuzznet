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

	/* A NULL SIDE IS "NOT EQUAL", NOT A CRASH.
	 *
	 * `fzn_wipe` in this same file documents that NULL is fine, and nothing
	 * said what this one did -- so a consumer reading the header met one
	 * convention and got the other. It segfaulted. This header exists
	 * precisely so consumers compare secrets with it directly rather than
	 * reaching for `memcmp`, which makes an undocumented crash on NULL the
	 * wrong thing for it to have.
	 *
	 * Answering "not equal" rather than "equal" because every caller here
	 * is asking an authorization question, and the safe reply to one asked
	 * with a missing operand is no. `len == 0` keeps answering equal, which
	 * it already did and which no caller depends on. */
	if (!pa || !pb)
		return len == 0;

	for (size_t i = 0; i < len; i++)
		diff |= (uint8_t)(pa[i] ^ pb[i]);

	return diff == 0;
}

/* See constant_time.h for why this exists and which of the two protections
 * does the work. */
void fzn_wipe(void *p, size_t len)
{
	volatile uint8_t *q = (volatile uint8_t *)p;

	if (!p)
		return;

	for (size_t i = 0; i < len; i++)
		q[i] = 0;
}
