/* Re-checking stored bytes against a cell reference. Reasoning in scrub.h. */

#include "scrub.h"

#include <string.h>

const char *fzn_scrub_err_str(fzn_scrub_err_t err)
{
	switch (err) {
	case FZN_SCRUB_OK:
		return "ok";
	case FZN_SCRUB_ERR_MALFORMED:
		return "malformed";
	case FZN_SCRUB_DONE:
		return "done";
	case FZN_SCRUB_ERR_BACKEND:
		return "backend";
	}
	return "unknown";
}

static int bit_get(const uint8_t *map, uint64_t index)
{
	return (map[index / 8u] >> (index % 8u)) & 1u;
}

static void bit_set(uint8_t *map, uint64_t index)
{
	map[index / 8u] |= (uint8_t)(1u << (index % 8u));
}

static void bit_clear(uint8_t *map, uint64_t index)
{
	map[index / 8u] &= (uint8_t)~(1u << (index % 8u));
}

/* The cell starting at `first`, as `plan.c` would emit it: the largest
 * canonical span at that offset that is no wider than a cell. Zero only for
 * an offset past the end, which callers do not produce. */
static uint64_t cell_len(uint64_t leaves, uint64_t first)
{
	return fzn_blob_span_largest_at(leaves, first, FZN_SCRUB_CELL);
}

uint64_t fzn_scrub_cells(uint64_t leaves)
{
	uint64_t first = 0u, cells = 0u;

	/* Terminates because every cell is at least one leaf, so `first`
	 * strictly increases and is bounded by `leaves`. */
	while (first < leaves) {
		uint64_t len = cell_len(leaves, first);

		if (len == 0u)
			break;
		first += len;
		cells++;
	}
	return cells;
}

fzn_scrub_err_t fzn_scrub_open(fzn_scrub_t *scrub, fzn_spool_t *spool, uint8_t *roots,
                               uint64_t cells, uint8_t *sealed, size_t sealed_len)
{
	uint64_t need;

	if (!scrub || !spool || !roots || !sealed)
		return FZN_SCRUB_ERR_MALFORMED;
	if (spool->leaves == 0u || !spool->present)
		return FZN_SCRUB_ERR_MALFORMED;

	need = fzn_scrub_cells(spool->leaves);
	if (cells < need || sealed_len < FZN_SCRUB_SEALED_LEN(need))
		return FZN_SCRUB_ERR_MALFORMED;

	/* The reference starts empty and the seals start clear, because a
	 * caller's uninitialised buffer must not read as a set of hashes
	 * anything was ever checked against. */
	memset(roots, 0, (size_t)need * FZN_BLOB_HASH_LEN);
	memset(sealed, 0, FZN_SCRUB_SEALED_LEN(need));

	scrub->spool = spool;
	scrub->roots = roots;
	scrub->sealed = sealed;
	scrub->cells = need;
	scrub->seal_cell = 0u;
	scrub->seal_first = 0u;
	scrub->step_cell = 0u;
	scrub->step_first = 0u;
	return FZN_SCRUB_OK;
}

/* Every leaf of the cell present. */
static int cell_is_whole(const fzn_spool_t *spool, uint64_t first, uint64_t count)
{
	uint64_t i;

	for (i = 0; i < count; i++) {
		if (!fzn_spool_has(spool, first + i))
			return 0;
	}
	return 1;
}

/* Reads the cell back and folds its SLOTS into a reference digest.
 *
 * THE SLOT, NOT THE LEAF, and that is forced rather than chosen.
 * `fzn_spool_read` documents that it returns the STRIDE and not the leaf's
 * own length, "because a store does not know it -- the sealed length lives
 * in the blob's own framing and the last leaf is short." So this file cannot
 * reproduce a leaf hash, and therefore cannot produce anything comparable
 * with the blob's root.
 *
 * It does not need to. The reference only has to change when the bytes
 * change, and a digest over the fixed-width slots does that exactly: sealing
 * and stepping fold the same bytes the same way, so a difference is rot and
 * nothing else. What is lost is the ability to check the reference against
 * the root -- see scrub.h, which is why sealing must be prompt.
 *
 * FZN_SCRUB_ERR_BACKEND if a leaf the bitmap claims cannot be read. */
static fzn_scrub_err_t cell_digest(const fzn_spool_t *spool, const fzn_hash_ops_t *hash,
                                   uint64_t first, uint64_t count,
                                   uint8_t out[FZN_BLOB_HASH_LEN])
{
	uint8_t slot_hashes[FZN_SCRUB_CELL * FZN_BLOB_HASH_LEN];
	uint8_t slot[FZN_BLOB_SEALED_MAX];
	uint64_t i;

	if (count > FZN_SCRUB_CELL)
		return FZN_SCRUB_ERR_MALFORMED;

	for (i = 0; i < count; i++) {
		size_t len = 0u;

		if (fzn_spool_read(spool, first + i, slot, sizeof(slot), &len) != FZN_SPOOL_OK)
			return FZN_SCRUB_ERR_BACKEND;
		/* The whole slot, whatever the leaf inside it is. `place`
		 * fills the tail of a short leaf, so these bytes are defined
		 * rather than whatever the medium held. */
		if (fzn_blob_leaf_hash(hash, slot, len, slot_hashes + i * FZN_BLOB_HASH_LEN)
		    != FZN_BLOB_OK)
			return FZN_SCRUB_ERR_BACKEND;
	}
	if (fzn_blob_span_root(hash, slot_hashes, count, out) != FZN_BLOB_OK)
		return FZN_SCRUB_ERR_BACKEND;
	return FZN_SCRUB_OK;
}

/* Advances a (cell, first) cursor by one cell, wrapping at the end. */
static void advance(const fzn_scrub_t *scrub, uint64_t *cell, uint64_t *first, uint64_t len)
{
	*first += len;
	*cell += 1u;
	if (*cell >= scrub->cells || *first >= scrub->spool->leaves) {
		*cell = 0u;
		*first = 0u;
	}
}

fzn_scrub_err_t fzn_scrub_seal(fzn_scrub_t *scrub, const fzn_hash_ops_t *hash, uint64_t limit,
                               uint64_t *out_sealed)
{
	uint64_t looked = 0u, sealed_now = 0u;

	if (out_sealed)
		*out_sealed = 0u;
	if (!scrub || !scrub->spool || !scrub->roots || !scrub->sealed || !hash)
		return FZN_SCRUB_ERR_MALFORMED;
	if (limit == 0u)
		return FZN_SCRUB_ERR_MALFORMED;

	/* Bounded by `limit` cells LOOKED AT rather than sealed, so a pass
	 * over a blob with nothing new to seal costs `limit` bitmap walks and
	 * returns, instead of scanning to the end looking for work. */
	while (looked < limit) {
		uint64_t first = scrub->seal_first;
		uint64_t cell = scrub->seal_cell;
		uint64_t len = cell_len(scrub->spool->leaves, first);

		if (len == 0u)
			return FZN_SCRUB_ERR_MALFORMED;
		looked++;

		if (!bit_get(scrub->sealed, cell) && cell_is_whole(scrub->spool, first, len)) {
			uint8_t root[FZN_BLOB_HASH_LEN];
			fzn_scrub_err_t err = cell_digest(scrub->spool, hash, first, len, root);

			if (err != FZN_SCRUB_OK)
				return err;
			memcpy(scrub->roots + cell * FZN_BLOB_HASH_LEN, root, FZN_BLOB_HASH_LEN);
			bit_set(scrub->sealed, cell);
			sealed_now++;
		}

		advance(scrub, &scrub->seal_cell, &scrub->seal_first, len);
		if (scrub->seal_cell == 0u && scrub->seal_first == 0u) {
			if (out_sealed)
				*out_sealed = sealed_now;
			return FZN_SCRUB_DONE;
		}
	}

	if (out_sealed)
		*out_sealed = sealed_now;
	return FZN_SCRUB_OK;
}

fzn_scrub_err_t fzn_scrub_step(fzn_scrub_t *scrub, const fzn_hash_ops_t *hash, uint64_t limit,
                               uint64_t *out_checked, uint64_t *out_dropped)
{
	uint64_t looked = 0u, checked = 0u, dropped = 0u;

	if (out_checked)
		*out_checked = 0u;
	if (out_dropped)
		*out_dropped = 0u;
	if (!scrub || !scrub->spool || !scrub->roots || !scrub->sealed || !hash)
		return FZN_SCRUB_ERR_MALFORMED;
	if (limit == 0u)
		return FZN_SCRUB_ERR_MALFORMED;

	while (looked < limit) {
		uint64_t first = scrub->step_first;
		uint64_t cell = scrub->step_cell;
		uint64_t len = cell_len(scrub->spool->leaves, first);
		uint8_t root[FZN_BLOB_HASH_LEN];

		if (len == 0u)
			return FZN_SCRUB_ERR_MALFORMED;
		looked++;

		/* An unsealed cell has no reference, and a cell that has lost
		 * leaves since it was sealed is mid-repair. Neither is a
		 * fault, and checking either would compare against nothing. */
		if (bit_get(scrub->sealed, cell) && cell_is_whole(scrub->spool, first, len)) {
			fzn_scrub_err_t err = cell_digest(scrub->spool, hash, first, len, root);

			if (err != FZN_SCRUB_OK)
				return err;
			checked++;
			if (memcmp(root, scrub->roots + cell * FZN_BLOB_HASH_LEN,
			           FZN_BLOB_HASH_LEN) != 0) {
				/* The whole of repair: the leaves go back on
				 * the want-list and the seal goes with them,
				 * so the cell is resealed from bytes a peer
				 * proved rather than from these. */
				(void)fzn_spool_forget(scrub->spool, first, len);
				bit_clear(scrub->sealed, cell);
				dropped++;
			}
		}

		advance(scrub, &scrub->step_cell, &scrub->step_first, len);
		if (scrub->step_cell == 0u && scrub->step_first == 0u) {
			if (out_checked)
				*out_checked = checked;
			if (out_dropped)
				*out_dropped = dropped;
			return FZN_SCRUB_DONE;
		}
	}

	if (out_checked)
		*out_checked = checked;
	if (out_dropped)
		*out_dropped = dropped;
	return FZN_SCRUB_OK;
}
