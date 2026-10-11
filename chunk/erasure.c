#include "erasure.h"

#include <string.h>

const char *fzn_erasure_err_str(fzn_erasure_err_t err)
{
	switch (err) {
	case FZN_ERASURE_OK:
		return "ok";
	case FZN_ERASURE_ERR_MALFORMED:
		return "malformed";
	case FZN_ERASURE_ERR_TOO_FEW:
		return "fewer pieces than it takes to rebuild";
	}
	return "unknown";
}

/* ---- GF(2^8), 0x11d ----------------------------------------------------- */

static uint8_t gf_exp[512];
static uint8_t gf_log[256];
static int gf_ready;

static void gf_init(void)
{
	unsigned x = 1, i;

	if (gf_ready)
		return;
	for (i = 0; i < 255u; i++) {
		gf_exp[i] = (uint8_t)x;
		gf_log[x] = (uint8_t)i;
		x <<= 1;
		if (x & 0x100u)
			x ^= 0x11du;
	}
	/* DOUBLED, so a product's exponent needs no reduction. */
	for (i = 255u; i < 512u; i++)
		gf_exp[i] = gf_exp[i - 255u];
	gf_ready = 1;
}

static uint8_t gf_mul(uint8_t a, uint8_t b)
{
	if (!a || !b)
		return 0;
	return gf_exp[gf_log[a] + gf_log[b]];
}

/* The inverse of a nonzero element. */
static uint8_t gf_inv(uint8_t a)
{
	return gf_exp[255u - gf_log[a]];
}

/* Row `r` of the generator matrix, column `c`: the identity for a data
 * piece, the Cauchy matrix 1 / (x + y) for a parity piece. */
static uint8_t generator(unsigned k, unsigned r, unsigned c)
{
	if (r < k)
		return (uint8_t)(r == c);
	return gf_inv((uint8_t)(r ^ c));
}

/* ---- the codec ------------------------------------------------------------ */

size_t fzn_erasure_piece_len(size_t len, unsigned k)
{
	if (!k || !len)
		return 0;
	return len / k + (len % k != 0u);
}

static int shape_ok(unsigned k, unsigned m, size_t len)
{
	return k && m && k + m <= FZN_ERASURE_PIECES_MAX && len;
}

fzn_erasure_err_t fzn_erasure_encode(unsigned k, unsigned m, const uint8_t *data, size_t len,
                                     uint8_t *pieces)
{
	size_t plen = fzn_erasure_piece_len(len, k), b;
	unsigned j, c;

	if (!shape_ok(k, m, len) || !data || !pieces)
		return FZN_ERASURE_ERR_MALFORMED;
	gf_init();
	/* THE DATA PIECES ARE THE DATA, the last padded with zeros. */
	memset(pieces, 0, (size_t)k * plen);
	memcpy(pieces, data, len);
	for (j = 0; j < m; j++) {
		uint8_t *parity = pieces + (size_t)(k + j) * plen;

		memset(parity, 0, plen);
		for (c = 0; c < k; c++) {
			uint8_t coef = generator(k, k + j, c);
			const uint8_t *piece = pieces + (size_t)c * plen;

			for (b = 0; b < plen; b++)
				parity[b] ^= gf_mul(coef, piece[b]);
		}
	}
	return FZN_ERASURE_OK;
}

fzn_erasure_err_t fzn_erasure_decode(unsigned k, unsigned m, const uint8_t *const *pieces,
                                     size_t len, uint8_t *out)
{
	uint8_t a[FZN_ERASURE_PIECES_MAX][FZN_ERASURE_PIECES_MAX];
	uint8_t inv[FZN_ERASURE_PIECES_MAX][FZN_ERASURE_PIECES_MAX];
	unsigned rows[FZN_ERASURE_PIECES_MAX], n = 0, r, c, i, p;
	size_t plen = fzn_erasure_piece_len(len, k), b, done = 0;

	if (!shape_ok(k, m, len) || !pieces || !out)
		return FZN_ERASURE_ERR_MALFORMED;
	gf_init();
	for (i = 0; i < k + m && n < k; i++)
		if (pieces[i])
			rows[n++] = i;
	if (n < k)
		return FZN_ERASURE_ERR_TOO_FEW;
	/* THE k ROWS HELD, and the identity beside them, Gauss-Jordan: the rows
	 * of any k pieces are independent, so a pivot is always found. */
	for (r = 0; r < k; r++)
		for (c = 0; c < k; c++) {
			a[r][c] = generator(k, rows[r], c);
			inv[r][c] = (uint8_t)(r == c);
		}
	for (c = 0; c < k; c++) {
		uint8_t scale;

		for (p = c; p < k && !a[p][c]; p++)
			;
		if (p == k)
			return FZN_ERASURE_ERR_MALFORMED;
		if (p != c)
			for (i = 0; i < k; i++) {
				uint8_t t = a[p][i];

				a[p][i] = a[c][i];
				a[c][i] = t;
				t = inv[p][i];
				inv[p][i] = inv[c][i];
				inv[c][i] = t;
			}
		scale = gf_inv(a[c][c]);
		for (i = 0; i < k; i++) {
			a[c][i] = gf_mul(a[c][i], scale);
			inv[c][i] = gf_mul(inv[c][i], scale);
		}
		for (r = 0; r < k; r++) {
			uint8_t f = a[r][c];

			if (r == c || !f)
				continue;
			for (i = 0; i < k; i++) {
				a[r][i] ^= gf_mul(f, a[c][i]);
				inv[r][i] ^= gf_mul(f, inv[c][i]);
			}
		}
	}
	/* DATA PIECE d IS ROW d OF THE INVERSE OVER THE PIECES HELD, written
	 * out as far as `len` reaches. */
	for (r = 0; r < k && done < len; r++) {
		size_t want = len - done < plen ? len - done : plen;

		for (b = 0; b < want; b++) {
			uint8_t v = 0;

			for (i = 0; i < k; i++)
				v ^= gf_mul(inv[r][i], pieces[rows[i]][b]);
			out[done + b] = v;
		}
		done += want;
	}
	return FZN_ERASURE_OK;
}
