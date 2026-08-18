/* The nonce source, and the rule it exists to hold.
 *
 * Two halves, tested differently. The RULE -- all or nothing, never a
 * fallback -- is checked with stub sources that fail in each way a real one
 * can, because a real source cannot be made to fail on demand. The SYSTEM
 * half is checked against getrandom itself, where the only things worth
 * asserting are that it fills what it was asked for and does not repeat.
 */

#include "../random.h"
#include "../random_system.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check(int ok, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL: %s\n", what);
	}
}

/* A source that writes some bytes and then fails, which is the shape of a
 * short read and the reason `fill` is all-or-nothing. */
static int partial_fill(void *ctx, uint8_t *out, size_t len)
{
	size_t stop = *(size_t *)ctx;

	for (size_t i = 0; i < len && i < stop; i++)
		out[i] = 0xab;
	return 0;
}

static int refusing_fill(void *ctx, uint8_t *out, size_t len)
{
	(void)ctx;
	(void)out;
	(void)len;
	return 0;
}

static int counting_fill(void *ctx, uint8_t *out, size_t len)
{
	unsigned *n = (unsigned *)ctx;

	for (size_t i = 0; i < len; i++)
		out[i] = (uint8_t)(*n + i);
	(*n)++;
	return 1;
}

int main(void)
{
	uint8_t nonce[FZN_AEAD_NONCE_LEN], again[FZN_AEAD_NONCE_LEN];
	fzn_random_ops_t ops;

	/* THE RULE: a source that fails leaves nothing usable behind. */
	{
		size_t stop = FZN_AEAD_NONCE_LEN - 1u; /* one byte short */
		fzn_random_ops_t partial = { partial_fill, &stop };
		fzn_random_ops_t refusing = { refusing_fill, NULL };
		uint8_t zero[FZN_AEAD_NONCE_LEN];

		memset(zero, 0, sizeof(zero));
		memset(nonce, 0x5a, sizeof(nonce));
		check(fzn_nonce_next(&partial, nonce) == 0,
		      "a source that filled all but one byte reported success");
		check(memcmp(nonce, zero, sizeof(nonce)) == 0,
		      "a failed source left most of a nonce in the buffer, which is the "
		      "case that looks fine in a capture");

		memset(nonce, 0x5a, sizeof(nonce));
		check(fzn_nonce_next(&refusing, nonce) == 0, "a refusing source reported success");
		check(memcmp(nonce, zero, sizeof(nonce)) == 0, "a refusing source left the buffer");
	}

	/* Arguments, including the one that matters: a null `fill` is what a
	 * platform without a source leaves behind, and it must refuse rather
	 * than crash or succeed. */
	{
		fzn_random_ops_t none = { NULL, NULL };
		unsigned n = 0;
		fzn_random_ops_t counting = { counting_fill, &n };

		check(fzn_nonce_next(&none, nonce) == 0, "an ops with no fill produced a nonce");
		check(fzn_nonce_next(NULL, nonce) == 0, "a null ops produced a nonce");
		check(fzn_nonce_next(&counting, NULL) == 0, "a null out was accepted");
		check(n == 0, "the source was called despite a null out");

		/* And a working source is not refused, so the checks above are
		 * not passing because everything is refused. */
		check(fzn_nonce_next(&counting, nonce) == 1, "a working source was refused");
		check(n == 1, "the source was not called");
	}

	/* THE SYSTEM HALF. */
	fzn_random_system_init(&ops);
	fzn_random_system_init(NULL);
	check(1, "init with a null ops did not crash");

#if defined(__linux__)
	check(ops.fill != NULL, "no system source on a platform that has one");

	memset(nonce, 0, sizeof(nonce));
	memset(again, 0, sizeof(again));
	check(fzn_nonce_next(&ops, nonce) == 1, "the system source refused");
	check(fzn_nonce_next(&ops, again) == 1, "the system source refused a second time");

	/* Two nonces that matched would mean a source with no entropy in it.
	 * The chance of a false failure here is 2^-192, which is smaller than
	 * the chance of the machine being wrong about anything else. */
	check(memcmp(nonce, again, sizeof(nonce)) != 0,
	      "two consecutive nonces were identical");

	/* The source's own null guard, reached directly because
	 * `fzn_nonce_next` checks `out` first and so never hands it one. A
	 * consumer using the ops directly -- to fill a key, say -- is the
	 * caller that would. */
	check(ops.fill(ops.ctx, NULL, FZN_AEAD_NONCE_LEN) == 0,
	      "the system source accepted a null buffer");

	/* An all-zero nonce is not proof of a bad source, but it is what an
	 * untouched buffer looks like, and this test wrote zeroes first. */
	{
		uint8_t zero[FZN_AEAD_NONCE_LEN];

		memset(zero, 0, sizeof(zero));
		check(memcmp(nonce, zero, sizeof(nonce)) != 0,
		      "the buffer was returned untouched");
	}
#else
	check(ops.fill == NULL,
	      "a platform without a source offered one, which would be a nonce with no "
	      "entropy in it");
	check(fzn_nonce_next(&ops, nonce) == 0, "a platform without a source produced a nonce");
#endif

	printf("random_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
