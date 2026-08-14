/* Constant-time comparison, which this library owes its consumers.
 *
 * project.md sec 4.4a is unusually direct about it: "Key-committing AEAD is
 * not optional, and neither is a constant-time tag comparison. The extern
 * codec owns the first; THIS LIBRARY OWNS THE SECOND AND MUST NOT LEAVE IT
 * TO THE CONSUMER."
 *
 * It lives here rather than in chain.h, which is where it started, because
 * of what that sentence obliges. A consumer verifying a tag needs this
 * function; if the only header that declares it is the capability model,
 * then getting a constant-time memcmp means including chains, hops,
 * delegation and revocation, and the obvious response to that is to write
 * their own -- which is exactly what sec 4.4a forbids leaving them to do.
 * Handing somebody the right thing under an obvious name is the whole
 * mechanism, and a name they have to dig for is not one.
 *
 * It also fixes the dependency direction. Everything may depend on this;
 * this depends on nothing but the C standard headers. `frame/` and `chunk/`
 * could not have reached the old declaration without depending on `chain/`,
 * which is backwards -- the capability model is a consumer of primitives,
 * not a home for them.
 *
 * NOT every comparison should use it, and the library is deliberate about
 * which do. frame/freshness.c compares nonces with plain memcmp and says
 * why: a nonce travels in the clear in the header, so there is nothing to
 * leak, and the return value already reveals more than any timing signal
 * would. Reaching for the careful function everywhere reads as ritual and
 * makes it impossible to see which comparisons are load-bearing.
 */

#ifndef FZN_CONSTANT_TIME_H
#define FZN_CONSTANT_TIME_H

#include <stddef.h>

/* Nonzero when the two buffers are equal over `len` bytes.
 *
 * Constant time in the LENGTH and in the DATA: it accumulates differences
 * and tests once, rather than returning at the first mismatch. A memcmp
 * returns as soon as two bytes differ, which turns "how long did that take"
 * into "how many leading bytes matched" -- a tag oracle wherever the
 * attacker chooses one side. */
int fzn_ct_memeq(const void *a, const void *b, size_t len);

#endif /* FZN_CONSTANT_TIME_H */
