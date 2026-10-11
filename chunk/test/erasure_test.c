/* Tests for chunk/erasure.c: k data pieces and m parity, any k rebuilding.
 * sec 594. */

#include "../erasure.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL erasure_test.c:%d: %s\n", __LINE__, what);      \
		}                                                                              \
	} while (0)

static uint8_t data[70000], back[70000];
static uint8_t pieces[FZN_ERASURE_PIECES_MAX * 70000u];

static void fill(size_t len, unsigned seed)
{
	uint32_t x = 0x9e3779b9u ^ seed;
	size_t i;

	for (i = 0; i < len; i++) {
		x ^= x << 13;
		x ^= x >> 17;
		x ^= x << 5;
		data[i] = (uint8_t)x;
	}
}

/* Whether every way of losing `lose` of the k + m pieces rebuilds. */
static int every_loss(unsigned k, unsigned m, size_t len, unsigned lose)
{
	const uint8_t *held[FZN_ERASURE_PIECES_MAX];
	size_t plen = fzn_erasure_piece_len(len, k);
	unsigned n = k + m, mask, i, bits;

	for (mask = 0; mask < (1u << n); mask++) {
		for (bits = 0, i = 0; i < n; i++)
			bits += (mask >> i) & 1u;
		if (bits != lose)
			continue;
		for (i = 0; i < n; i++)
			held[i] = (mask >> i) & 1u ? NULL : pieces + (size_t)i * plen;
		memset(back, 0, len);
		if (fzn_erasure_decode(k, m, held, len, back) != FZN_ERASURE_OK
		    || memcmp(back, data, len) != 0)
			return 0;
	}
	return 1;
}

static void test_four_and_two(void)
{
	static const size_t LENS[] = { 1u, 3u, 4u, 5u, 1000u, 65537u };
	const uint8_t *held[6];
	size_t i, plen;
	int ok = 1, three = 1;

	for (i = 0; i < sizeof(LENS) / sizeof(LENS[0]); i++) {
		fill(LENS[i], (unsigned)i);
		ok = ok && fzn_erasure_encode(4u, 2u, data, LENS[i], pieces) == FZN_ERASURE_OK
		     && every_loss(4u, 2u, LENS[i], 0u) && every_loss(4u, 2u, LENS[i], 1u)
		     && every_loss(4u, 2u, LENS[i], 2u);
	}
	CHECK(ok, "4 + 2 did not rebuild from every four of the six pieces, at every length");

	/* THE DATA PIECES ARE THE DATA: systematic. */
	fill(1000u, 7u);
	plen = fzn_erasure_piece_len(1000u, 4u);
	CHECK(plen == 250u && fzn_erasure_encode(4u, 2u, data, 1000u, pieces) == FZN_ERASURE_OK
	              && memcmp(pieces, data, 1000u) == 0,
	      "the data pieces are not the data itself, laid end to end");

	/* THREE LOST IS TOO MANY. */
	for (i = 0; i < 6u; i++)
		held[i] = pieces + i * plen;
	held[0] = held[3] = held[5] = NULL;
	three = fzn_erasure_decode(4u, 2u, held, 1000u, back) == FZN_ERASURE_ERR_TOO_FEW;
	CHECK(three, "three of six lost rebuilt, or said other than too few");

	/* A PIECE WRONG IN A BYTE REBUILDS WRONG: the caller's hash finds it. */
	for (i = 0; i < 6u; i++)
		held[i] = pieces + i * plen;
	held[0] = held[1] = NULL;
	pieces[4u * plen + 3u] ^= 0x40u;
	CHECK(fzn_erasure_decode(4u, 2u, held, 1000u, back) == FZN_ERASURE_OK
	              && memcmp(back, data, 1000u) != 0,
	      "a parity piece changed in a byte rebuilt the same buffer");
}

static void test_other_shapes(void)
{
	int ok;

	fill(777u, 11u);
	ok = fzn_erasure_encode(1u, 1u, data, 777u, pieces) == FZN_ERASURE_OK
	     && every_loss(1u, 1u, 777u, 1u);
	CHECK(ok && memcmp(pieces + 777u, data, 777u) == 0,
	      "1 + 1 is not a mirror, or did not rebuild from either");
	fill(5000u, 12u);
	ok = fzn_erasure_encode(8u, 4u, data, 5000u, pieces) == FZN_ERASURE_OK
	     && every_loss(8u, 4u, 5000u, 4u);
	CHECK(ok, "8 + 4 did not rebuild from every eight of the twelve");
	fill(3000u, 13u);
	CHECK(fzn_erasure_encode(24u, 8u, data, 3000u, pieces) == FZN_ERASURE_OK,
	      "the largest shape would not encode");
	{
		const uint8_t *held[FZN_ERASURE_PIECES_MAX];
		size_t plen = fzn_erasure_piece_len(3000u, 24u), i;

		for (i = 0; i < 32u; i++)
			held[i] = i < 8u ? NULL : pieces + i * plen;
		CHECK(fzn_erasure_decode(24u, 8u, held, 3000u, back) == FZN_ERASURE_OK
		              && memcmp(back, data, 3000u) == 0,
		      "24 + 8 did not rebuild with eight data pieces lost");
	}
}

static void test_refusals(void)
{
	const uint8_t *held[2] = { data, data };

	CHECK(fzn_erasure_encode(0u, 2u, data, 10u, pieces) == FZN_ERASURE_ERR_MALFORMED
	              && fzn_erasure_encode(4u, 0u, data, 10u, pieces) == FZN_ERASURE_ERR_MALFORMED
	              && fzn_erasure_encode(30u, 3u, data, 10u, pieces) == FZN_ERASURE_ERR_MALFORMED
	              && fzn_erasure_encode(4u, 2u, data, 0u, pieces) == FZN_ERASURE_ERR_MALFORMED
	              && fzn_erasure_encode(4u, 2u, NULL, 10u, pieces) == FZN_ERASURE_ERR_MALFORMED
	              && fzn_erasure_decode(1u, 1u, NULL, 10u, back) == FZN_ERASURE_ERR_MALFORMED
	              && fzn_erasure_decode(1u, 1u, held, 10u, NULL) == FZN_ERASURE_ERR_MALFORMED,
	      "a shape of no data or no parity, past the most pieces, of no length, or a null "
	      "was taken");
	CHECK(fzn_erasure_piece_len(10u, 4u) == 3u && fzn_erasure_piece_len(12u, 4u) == 3u
	              && fzn_erasure_piece_len(0u, 4u) == 0u && fzn_erasure_piece_len(5u, 0u) == 0u,
	      "a piece's length is not the length over k rounded up");
}

int main(void)
{
	test_four_and_two();
	test_other_shapes();
	test_refusals();
	if (failures) {
		fprintf(stderr, "erasure_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("erasure_test: all %d checks passed\n", checks);
	return 0;
}
