/* See levels.h. */

#include "levels.h"

#include <string.h>

/* The offset of level `level`'s first node, in nodes. */
static uint64_t level_at(uint64_t leaves, unsigned level)
{
	uint64_t at = 0;
	unsigned l;

	for (l = 0; l < level; l++)
		at += leaves >> l;
	return at;
}

uint64_t fzn_blob_levels_bytes(uint64_t leaves)
{
	unsigned levels = 0;

	if (leaves == 0u || leaves > FZN_BLOB_MAX_LEAVES)
		return 0;
	while (levels < FZN_BLOB_MAX_DEPTH && (leaves >> levels) != 0u)
		levels++;
	return level_at(leaves, levels) * FZN_BLOB_HASH_LEN;
}

fzn_blob_err_t fzn_blob_levels_begin(fzn_blob_levels_builder_t *builder, uint64_t leaves)
{
	if (!builder || leaves == 0u || leaves > FZN_BLOB_MAX_LEAVES)
		return FZN_BLOB_ERR_MALFORMED;
	memset(builder, 0, sizeof(*builder));
	builder->leaves = leaves;
	return FZN_BLOB_OK;
}

static int put_node(const fzn_blob_levels_io_t *io, uint64_t leaves, unsigned level,
                    uint64_t index, const uint8_t node[FZN_BLOB_HASH_LEN])
{
	return io->write(io->ctx, (level_at(leaves, level) + index) * FZN_BLOB_HASH_LEN, node,
	                 FZN_BLOB_HASH_LEN);
}

fzn_blob_err_t fzn_blob_levels_push(const fzn_hash_ops_t *hash,
                                    fzn_blob_levels_builder_t *builder,
                                    const fzn_blob_levels_io_t *io,
                                    const uint8_t leaf_hash[FZN_BLOB_HASH_LEN])
{
	uint8_t node[FZN_BLOB_HASH_LEN];
	uint64_t index;
	unsigned level = 0;
	fzn_blob_err_t err;

	if (!hash || !builder || !io || !io->write || !leaf_hash)
		return FZN_BLOB_ERR_MALFORMED;
	if (builder->pushed >= builder->leaves)
		return FZN_BLOB_ERR_FULL;
	index = builder->pushed++;
	memcpy(node, leaf_hash, sizeof(node));
	/* EACH NODE WRITTEN, and carried up while it is a right child: node
	 * `index` at `level` completes its parent exactly when it is odd. */
	for (;;) {
		if (!put_node(io, builder->leaves, level, index, node))
			return FZN_BLOB_ERR_IO;
		if ((index & 1u) == 0u) {
			memcpy(builder->pending[level], node, sizeof(node));
			return FZN_BLOB_OK;
		}
		if (level + 1u >= FZN_BLOB_MAX_DEPTH)
			return FZN_BLOB_ERR_SHAPE;
		err = fzn_blob_node_hash(hash, builder->pending[level], node, node);
		if (err != FZN_BLOB_OK)
			return err;
		level++;
		index >>= 1;
	}
}

static uint64_t split_below(uint64_t n)
{
	uint64_t k = 1u;

	while ((k << 1) < n)
		k <<= 1;
	return k;
}

fzn_blob_err_t fzn_blob_levels_subtree(void *ctx, uint64_t lo, uint64_t n,
                                       uint8_t out[FZN_BLOB_HASH_LEN])
{
	const fzn_blob_levels_t *levels = (const fzn_blob_levels_t *)ctx;
	uint8_t left[FZN_BLOB_HASH_LEN];
	unsigned level = 0;
	uint64_t k;
	fzn_blob_err_t err;

	if (!levels || !levels->hash || !levels->io || !levels->io->read || !out || n == 0u
	    || lo > levels->leaves || n > levels->leaves - lo)
		return FZN_BLOB_ERR_MALFORMED;
	/* PERFECT AND ALIGNED: one node, read. The descent only ever asks for
	 * ranges whose start is a multiple of their power-of-two size. */
	if ((n & (n - 1u)) == 0u && (lo & (n - 1u)) == 0u) {
		while ((((uint64_t)1) << level) < n)
			level++;
		return levels->io->read(levels->io->ctx,
		                        (level_at(levels->leaves, level) + (lo >> level))
		                                * FZN_BLOB_HASH_LEN,
		                        out, FZN_BLOB_HASH_LEN)
		               ? FZN_BLOB_OK
		               : FZN_BLOB_ERR_IO;
	}
	/* THE RAGGED RIGHT EDGE: split as the tree does, the left part perfect,
	 * the right folded the same way. At most one fold per level. */
	k = split_below(n);
	err = fzn_blob_levels_subtree(ctx, lo, k, left);
	if (err != FZN_BLOB_OK)
		return err;
	err = fzn_blob_levels_subtree(ctx, lo + k, n - k, out);
	if (err != FZN_BLOB_OK)
		return err;
	return fzn_blob_node_hash(levels->hash, left, out, out);
}

fzn_blob_err_t fzn_blob_levels_leaf(const fzn_blob_levels_t *levels, uint64_t index,
                                    uint8_t out[FZN_BLOB_HASH_LEN])
{
	if (!levels || index >= levels->leaves)
		return FZN_BLOB_ERR_MALFORMED;
	return fzn_blob_levels_subtree((void *)(uintptr_t)levels, index, 1u, out);
}

fzn_blob_err_t fzn_blob_levels_span_proof(const fzn_blob_levels_t *levels, uint64_t first,
                                          uint64_t count, uint8_t *out, size_t out_cap,
                                          unsigned *out_count)
{
	if (!levels)
		return FZN_BLOB_ERR_MALFORMED;
	return fzn_blob_span_proof_from(fzn_blob_levels_subtree, (void *)(uintptr_t)levels,
	                                levels->leaves, first, count, out, out_cap, out_count);
}
