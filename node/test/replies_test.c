/* node replies_test -- the replies a node sent, kept a few seconds so a
 * resent request is answered without being run again, sec 737: found by
 * sender, message and bytes; expired; bounded in entries and in bytes. A
 * toy hash, since the digest only has to tell requests apart. */

#include "../replies.h"

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                    \
	do {                                                                                 \
		checks++;                                                                    \
		if (!(cond)) {                                                               \
			failures++;                                                          \
			fprintf(stderr, "  FAIL replies_test.c:%d: %s\n", __LINE__, what);     \
		}                                                                            \
	} while (0)

static int toy(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	(void)ctx;
	for (i = 0; i < in_len; i++)
		h = (h ^ in[i]) * 0x100000001b3ull;
	for (i = 0; i < out_len; i++) {
		h = (h ^ (uint64_t)i) * 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 56);
	}
	return 1;
}

static const fzn_hash_ops_t TOY = { toy, NULL };

#define B(s) (const uint8_t *)(s), strlen(s)

int main(void)
{
	static fzn_node_reply_kept_t kept[4];
	fzn_node_replies_t r;
	uint8_t a[32], b[32];
	const uint8_t *got;
	size_t len = 0;
	int i;

	memset(a, 0xaa, sizeof(a));
	memset(b, 0xbb, sizeof(b));
	CHECK(!fzn_node_replies_init(&r, kept, 4u, 0u, 6u, &TOY)
	              && fzn_node_replies_init(&r, kept, 4u, 64u, 6u, &TOY),
	      "a bound of no bytes was taken, or a sound one refused");

	/* FOUND BY ALL THREE, and by nothing less. */
	fzn_node_replies_keep(&r, a, 7u, 0u, B("ping"), 100u, B("pong"));
	got = fzn_node_replies_find(&r, a, 7u, B("ping"), 101u, &len);
	CHECK(got && len == 4u && memcmp(got, "pong", 4u) == 0, "a kept reply was not found");
	CHECK(!fzn_node_replies_find(&r, b, 7u, B("ping"), 101u, &len)
	              && !fzn_node_replies_find(&r, a, 8u, B("ping"), 101u, &len)
	              && !fzn_node_replies_find(&r, a, 7u, B("pinG"), 101u, &len),
	      "another sender, message or request was answered with this one's reply");

	/* A PIECE FOUND BY SENDER, MESSAGE AND EXPIRY, sec 741, and by nothing
	 * less: a host started again stamps another expiry, and an expiry of
	 * 0 tells no request from another. */
	fzn_node_replies_keep(&r, b, 9u, 2000u, B("whole"), 100u, B("done"));
	got = fzn_node_replies_find_piece(&r, b, 9u, 2000u, 102u, &len);
	CHECK(got && len == 4u && memcmp(got, "done", 4u) == 0,
	      "a piece of an answered request did not find its reply");
	CHECK(!fzn_node_replies_find_piece(&r, a, 9u, 2000u, 102u, &len)
	              && !fzn_node_replies_find_piece(&r, b, 8u, 2000u, 102u, &len)
	              && !fzn_node_replies_find_piece(&r, b, 9u, 2001u, 102u, &len)
	              && !fzn_node_replies_find_piece(&r, a, 7u, 0u, 102u, &len),
	      "a piece was answered with another request's reply, or by an expiry of 0");

	/* EXPIRED past its time, and before its time too: a clock stepped back
	 * keeps nothing it cannot place. */
	CHECK(fzn_node_replies_find(&r, a, 7u, B("ping"), 106u, &len)
	              && !fzn_node_replies_find(&r, a, 7u, B("ping"), 107u, &len) && r.n == 0u,
	      "a reply was found past its time, or not let go");
	fzn_node_replies_keep(&r, a, 7u, 0u, B("ping"), 100u, B("pong"));
	CHECK(!fzn_node_replies_find(&r, a, 7u, B("ping"), 99u, &len) && r.n == 0u,
	      "a reply kept in a later second was found by an earlier clock");

	/* BOUNDED IN ENTRIES: four, then the oldest goes. */
	for (i = 0; i < 5; i++)
		fzn_node_replies_keep(&r, a, (uint32_t)i, 0u, B("ping"), 200u, B("pong"));
	CHECK(r.n == 4u && !fzn_node_replies_find(&r, a, 0u, B("ping"), 200u, &len)
	              && fzn_node_replies_find(&r, a, 4u, B("ping"), 200u, &len),
	      "past four entries the oldest was not the one let go");

	/* BOUNDED IN BYTES: 64 in all, so a 40-byte reply lets older ones go,
	 * and one larger than the whole bound is not kept. */
	fzn_node_replies_keep(&r, b, 1u, 0u, B("big"), 200u,
	                      B("0123456789012345678901234567890123456789"));
	CHECK(r.bytes <= 64u && fzn_node_replies_find(&r, b, 1u, B("big"), 200u, &len)
	              && len == 40u,
	      "a reply past the byte bound was not made room for");
	fzn_node_replies_keep(&r, b, 2u, 0u, B("huge"), 200u,
	                      B("01234567890123456789012345678901234567890123456789012345678901234"));
	CHECK(!fzn_node_replies_find(&r, b, 2u, B("huge"), 200u, &len) && r.bytes <= 64u,
	      "a reply larger than the whole bound was kept");

	fzn_node_replies_free(&r);
	CHECK(r.n == 0u && r.bytes == 0u, "the replies were not all let go");
	/* THE SUITE CAN FAIL. */
	{
		int before = failures;

		CHECK(0, "deliberate");
		failures = before;
	}
	if (failures) {
		fprintf(stderr, "node replies_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("node replies_test: all %d checks passed\n", checks);
	return 0;
}
