/* A blob's tree kept outside memory, for a seeder of a large blob. sec 490.
 *
 * WHY. A server answering a WANT owes a proof, and `fzn_blob_proof_build`
 * builds one from every leaf hash -- 32 bytes per KiB of blob, which is
 * 128 MiB for a 4 GiB file. A text of 256 leaves can afford that; a file
 * store cannot. So the tree is written out once, as leaves are pushed in
 * order, and a proof reads the few nodes it needs back.
 *
 * WHAT IS KEPT: every PERFECT subtree, level by level. Level L holds
 * floor(n / 2^L) nodes, node j the apex over leaves [j * 2^L, (j+1) * 2^L);
 * level 0 is the leaf hashes. The tree is RFC 6962's left-complete one
 * (`blob.h`), so every subtree its descent visits either is one of these or
 * folds from them along its ragged right edge -- at most one node per level.
 * The whole is a little under 2n hashes.
 *
 * ONE DESCENT FOR BOTH. A proof is `fzn_blob_span_proof_from` with this
 * module's subtree root, so its shape is the array builder's by construction
 * rather than by a second implementation agreeing with it.
 *
 * NO I/O OF ITS OWN: the caller's `read` and `write` at byte offsets, so a
 * file, a test's buffer or anything else carries the levels.
 */

#ifndef FZN_BLOB_LEVELS_H
#define FZN_BLOB_LEVELS_H

#include <stddef.h>
#include <stdint.h>

#include "blob.h"

typedef struct fzn_blob_levels_io {
	/* `len` bytes at `offset`: 1 on success. */
	int (*read)(void *ctx, uint64_t offset, uint8_t *out, size_t len);
	int (*write)(void *ctx, uint64_t offset, const uint8_t *in, size_t len);
	void *ctx;
} fzn_blob_levels_io_t;

/* The bytes the levels of a blob of `leaves` take; 0 for none or too many. */
uint64_t fzn_blob_levels_bytes(uint64_t leaves);

/* WRITING THEM, a leaf at a time in order. `pending` holds each level's last
 * left node until its right sibling arrives. */
typedef struct fzn_blob_levels_builder {
	uint64_t leaves;
	uint64_t pushed;
	uint8_t pending[FZN_BLOB_MAX_DEPTH][FZN_BLOB_HASH_LEN];
} fzn_blob_levels_builder_t;

fzn_blob_err_t fzn_blob_levels_begin(fzn_blob_levels_builder_t *builder, uint64_t leaves);

/* Leaf `builder->pushed`'s hash, written, and every perfect node it completes.
 * FULL past the leaf count begun with. */
fzn_blob_err_t fzn_blob_levels_push(const fzn_hash_ops_t *hash,
                                    fzn_blob_levels_builder_t *builder,
                                    const fzn_blob_levels_io_t *io,
                                    const uint8_t leaf_hash[FZN_BLOB_HASH_LEN]);

/* READING THEM: the levels of a blob of `leaves` behind `io`. */
typedef struct fzn_blob_levels {
	const fzn_hash_ops_t *hash;
	const fzn_blob_levels_io_t *io;
	uint64_t leaves;
} fzn_blob_levels_t;

/* A `fzn_blob_subtree_t`, `ctx` a `fzn_blob_levels_t`: the apex over
 * `[lo, lo + n)`, read where it is perfect and folded where it is not. */
fzn_blob_err_t fzn_blob_levels_subtree(void *ctx, uint64_t lo, uint64_t n,
                                       uint8_t out[FZN_BLOB_HASH_LEN]);

/* The leaf hash at `index`, as level 0 holds it. */
fzn_blob_err_t fzn_blob_levels_leaf(const fzn_blob_levels_t *levels, uint64_t index,
                                    uint8_t out[FZN_BLOB_HASH_LEN]);

/* A canonical span's proof, `fzn_blob_span_proof_build`'s, from the levels. */
fzn_blob_err_t fzn_blob_levels_span_proof(const fzn_blob_levels_t *levels, uint64_t first,
                                          uint64_t count, uint8_t *out, size_t out_cap,
                                          unsigned *out_count);

#endif /* FZN_BLOB_LEVELS_H */
