/* getrandom(2), the system half of random.h.
 *
 * A file of its own so that random.c holds the rule and links with no
 * platform dependency, exactly as local/peer.c and local/peer_linux.c are
 * split. Everything here is plumbing.
 *
 * Linux only, and not pretended otherwise. On anything else this refuses
 * rather than substituting something -- the same choice local/peer_linux.c
 * makes, and for a stronger reason: a stub that returned plausible bytes
 * would be a nonce source with no entropy in it, and every frame it sealed
 * would be forgeable.
 */

#if defined(__linux__)

#include "random.h"

#include <errno.h>
#include <sys/random.h>

static int linux_fill(void *ctx, uint8_t *out, size_t len)
{
	size_t got = 0;

	(void)ctx;
	if (!out)
		return 0;

	/* LOOPED, because getrandom may return fewer bytes than asked for --
	 * it is documented to, for requests over 256 bytes and on a signal --
	 * and the failure mode of not looping is a buffer whose tail is
	 * whatever the caller left there. */
	while (got < len) {
		ssize_t n = getrandom(out + got, len - got, 0);

		if (n < 0) {
			/* A signal is not a failure of the source. Anything
			 * else is, and there is no second attempt at a
			 * different source: see random.h. */
			if (errno == EINTR)
				continue;
			return 0;
		}
		if (n == 0)
			return 0;
		got += (size_t)n;
	}

	return 1;
}

void fzn_random_system_init(fzn_random_ops_t *ops)
{
	if (!ops)
		return;

	ops->fill = linux_fill;
	ops->ctx = NULL;
}

#else

#include "random.h"

void fzn_random_system_init(fzn_random_ops_t *ops)
{
	if (!ops)
		return;

	/* Null rather than a weak source. `fzn_nonce_next` refuses a null
	 * `fill`, so a consumer on a platform this does not cover fails at
	 * the first nonce instead of sealing with something predictable. */
	ops->fill = NULL;
	ops->ctx = NULL;
}

#endif
