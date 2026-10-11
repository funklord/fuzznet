/*
 * ERASURE CODING: a buffer as k data pieces and m parity pieces, any k of
 * which rebuild it. sec 594, the holder's of 2026-10-11: 4 + 2 over
 * archived log segments, after the whole replicas of sec 592.
 *
 * Reed-Solomon over GF(2^8), the polynomial x^8 + x^4 + x^3 + x^2 + 1
 * (0x11d). SYSTEMATIC: the data pieces are the buffer itself, cut into k
 * pieces of `fzn_erasure_piece_len` bytes, the last padded with zeros; so
 * while every data piece is held nothing is computed to read it back. The
 * parity pieces are a Cauchy matrix's rows over the data: parity j is the
 * sum over i of data i times 1 / (x_j + y_i), x_j = k + j and y_i = i. Any
 * k rows of the identity stacked on a Cauchy matrix are independent, so
 * any k pieces -- data, parity, or both -- invert to the data.
 *
 * A PIECE IS NOT CHECKED HERE. A piece wrong in a byte rebuilds a buffer
 * wrong in bytes; the caller holds what the buffer must hash to (an
 * archived segment's bucket id) and checks the rebuild against it, trying
 * another k of the pieces when it does not hold. That is the layer that
 * knows what right means.
 *
 * Pure: no I/O, no allocation. The caller owns every buffer.
 */
#ifndef FZN_CHUNK_ERASURE_H
#define FZN_CHUNK_ERASURE_H

#include <stddef.h>
#include <stdint.h>

typedef enum fzn_erasure_err {
	FZN_ERASURE_OK = 0,
	/* A null, k of 0, m of 0, more than FZN_ERASURE_PIECES_MAX pieces in
	 * all, or a length of 0. */
	FZN_ERASURE_ERR_MALFORMED = -1,
	/* Fewer than k pieces given to rebuild from. */
	FZN_ERASURE_ERR_TOO_FEW = -2
} fzn_erasure_err_t;

const char *fzn_erasure_err_str(fzn_erasure_err_t err);

/* The most pieces, data and parity together, one buffer is cut into. */
#define FZN_ERASURE_PIECES_MAX 32u

/* One piece's length for a buffer of `len` bytes cut into `k`: len / k,
 * rounded up. 0 for a k or a len of 0. */
size_t fzn_erasure_piece_len(size_t len, unsigned k);

/*
 * CUT AND CODE `data`, `len` bytes, into `k` data pieces and `m` parity
 * pieces of `fzn_erasure_piece_len(len, k)` bytes each, laid end to end in
 * `pieces` -- the data pieces first, piece i at i times the piece length --
 * which must hold (k + m) of them.
 */
fzn_erasure_err_t fzn_erasure_encode(unsigned k, unsigned m, const uint8_t *data, size_t len,
                                     uint8_t *pieces);

/*
 * REBUILD `len` bytes into `out` from the pieces held: `pieces[i]` the
 * piece at index i (0 to k + m - 1), NULL for one not held, each
 * `fzn_erasure_piece_len(len, k)` bytes. The first k held are used. TOO_FEW
 * with fewer than k held.
 */
fzn_erasure_err_t fzn_erasure_decode(unsigned k, unsigned m, const uint8_t *const *pieces,
                                     size_t len, uint8_t *out);

#endif /* FZN_CHUNK_ERASURE_H */
