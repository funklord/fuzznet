/*
 * AN ITEM AS ERASURE-CODED PIECES ON DISK, sec 595: the second stage of the
 * erasure coding planned in sec 594. An archived item -- a log segment's,
 * `node/log_buckets.h` -- cut by `chunk/erasure.h` into k data pieces and m
 * parity, each a file `IDHEX.INDEX.piece` in a directory, laid out as
 * `chunk/piece.situ`: a head naming the item, its kind, its length, k, m
 * and the piece's index, then the piece.
 *
 * REBUILT AND CHECKED HERE. Every piece present is read and its head held
 * to its name and to the others'; any k rebuild the item, and the rebuild
 * is kept only when it hashes to the item's id (`fzn_buckets_id`). A piece
 * wrong in a byte rebuilds an item that does not, so other k are tried,
 * which is what having m more than k is for.
 *
 * Where the pieces go -- which host keeps which -- is stage 3's.
 */
#ifndef FZN_NODE_PIECES_H
#define FZN_NODE_PIECES_H

#include <stddef.h>
#include <stdint.h>

#include "buckets.h"

typedef enum fzn_pieces_err {
	FZN_PIECES_OK = 0,
	/* A null, a shape `chunk/erasure.h` refuses, or a name that will not
	 * fit. */
	FZN_PIECES_ERR_MALFORMED = -1,
	/* A file or directory would not be made, written or read. */
	FZN_PIECES_ERR_FILE = -2,
	/* Fewer than k pieces present that agree with one another. */
	FZN_PIECES_ERR_TOO_FEW = -3,
	/* k or more present, and no k of them rebuilds to the id. */
	FZN_PIECES_ERR_NO_MATCH = -4
} fzn_pieces_err_t;

const char *fzn_pieces_err_str(fzn_pieces_err_t err);

/* A piece's head, `chunk/piece.situ`: everything before its bytes. */
#define FZN_PIECE_HEAD_LEN 49u

/*
 * CUT `item`, `len` bytes of `kind` whose id is `id`, into `k` data pieces
 * and `m` parity, each written into `dir` -- made 0700 when absent -- as
 * `IDHEX.INDEX.piece`, beside its name and renamed into place, so a piece
 * under its name is always whole. `*written` counts them.
 */
fzn_pieces_err_t fzn_pieces_cut(const char *dir, uint8_t kind,
                                const uint8_t id[FZN_BUCKETS_ID_LEN], const uint8_t *item,
                                size_t len, unsigned k, unsigned m, size_t *written);

/*
 * WHICH PIECES OF `id` ARE IN `dir`: bit i of `*mask` for the piece at
 * index i, its file present under its name. Nothing is read.
 */
fzn_pieces_err_t fzn_pieces_held(const char *dir, const uint8_t id[FZN_BUCKETS_ID_LEN],
                                 uint32_t *mask);

/*
 * KEEP ONE PIECE, `bytes` whole as `chunk/piece.situ` lays it out, into
 * `dir` under the name its head gives -- the item's id and its index, both
 * into `item_id` and `*index` -- written beside it and renamed into place.
 * MALFORMED for a head that is not a piece's: a version not 1, a kind not one
 * whose items are cut, k + m past 32, an index past k + m, or a piece not its
 * item's length over k. Whether it belongs to its item only the rebuild
 * can say.
 */
fzn_pieces_err_t fzn_pieces_keep(const char *dir, const uint8_t *bytes, size_t len,
                                 uint8_t item_id[FZN_BUCKETS_ID_LEN], unsigned *index);

/*
 * REBUILD the item `id` of `kind` from the pieces in `dir` into `out` (room
 * for `cap`), `*len` bytes, checked against `id` under `hash`. `*used` (may
 * be NULL) is the mask of the k pieces the rebuild came from.
 */
fzn_pieces_err_t fzn_pieces_rebuild(const char *dir, uint8_t kind,
                                    const uint8_t id[FZN_BUCKETS_ID_LEN],
                                    const fzn_hash_ops_t *hash, uint8_t *out, size_t cap,
                                    size_t *len, uint32_t *used);

#endif /* FZN_NODE_PIECES_H */
