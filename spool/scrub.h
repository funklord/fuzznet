/* Re-checking bytes that were verified once, a long time ago.
 *
 * project.md sec 102 lists `scrub` among the filestore pieces this library
 * lacked. It is the RAID and ZFS sense of the word: read what is stored and
 * confirm it is still what it claimed to be.
 *
 * NOT THE OTHER SENSE. This tree already uses "scrub" for wiping a secret
 * from a host -- sec 45's sim scenarios, where scrubbing a peer is an attack
 * being modelled, and `spool.h` uses it for a length check. Prose rather
 * than symbols, so nothing collides, but the two meanings are opposite in
 * intent and merging them in a reader's head is the hazard. Nothing here
 * wipes anything. fuzzypickles report their tree spells the security sense
 * `crypto_wipe` throughout and uses this word only as this file does, so
 * the ambiguity is entirely inside this tree.
 *
 * WHAT THE BITMAP ACTUALLY CLAIMS, and it is less than it looks. A set bit
 * says a leaf was verified AT THE MOMENT IT WAS PLACED. `fzn_spool_place`
 * checks a leaf against a proof the sender supplied and then keeps nothing:
 * no leaf hash, no proof, no copy. Between that write and the next read the
 * bytes are protected by the filesystem and by nothing this library knows
 * about -- a truncated file, a backend reporting a short write as success, a
 * restored backup, a resumed transfer over a file somebody edited. The
 * bitmap goes on saying "present" through all of it.
 *
 * Sec 102 records why the bitmap cannot be re-derived from the file: a
 * partial blob is a sparse file, a hole reads back as zeros, and a
 * legitimate zero leaf reads the same. Presence is not recoverable from
 * content. This answers the other half -- content is checkable, against a
 * reference this file keeps.
 *
 * THE REFERENCE IS ONE HASH PER CELL, AND THE PRICE IS WHY.
 *
 *     retained, per byte of content        cost      what it buys
 *     nothing                              0         complete blobs only,
 *                                                    all-or-nothing verdict
 *     one hash per CELL (this file)        0.049%    partial blobs, and a
 *                                                    verdict per 64 leaves
 *     the whole upper tree                 0.098%    the same, without
 *                                                    recomputing internals
 *     every internal node and leaf hash    6.250%    O(depth) per single leaf
 *
 * Measured in this tree's constants rather than taken from anywhere: a
 * 1024-byte leaf, a 32-byte hash, 64 leaves to a cell. **2 MiB of reference
 * for a 4 GiB blob.** fuzzypickles reached the same shape from their side
 * and report 6.4% and about 0.1% for the two middle rows; both re-derive
 * here, and the cheapest row is this file's because the upper internal nodes
 * are recomputed from the cell roots on demand rather than stored.
 *
 * The first row is what this file nearly was, and the reason it is not is
 * that 0.049% buys partial-blob scrubbing and a 64-leaf repair instead of a
 * whole-blob one. That is not a trade so much as a price nobody would refuse.
 *
 * A CELL IS THE FINEST UNIT LOCAL DATA CAN PROVE. Going finer needs a
 * reference per leaf, which is the 6.250% row. Going finer WITHOUT storing
 * one is possible and is a conversation rather than a store operation -- ask
 * a peer for the span root of half a cell, compare, descend -- so it belongs
 * to `spool/message.h`. fuzzypickles state the same boundary from the
 * opposite side: they localise to a batch and no further, and "the batch
 * boundary is where local knowledge runs out."
 *
 * THE GRID IS THE ONE `spool/plan.c` ALREADY EMITS. Cells are the canonical
 * decomposition of the tree at up to FZN_SCRUB_CELL leaves -- exactly what
 * `fzn_spool_plan_want` produces with that `max_per_range`, and exactly what
 * `fzn_blob_span_root` can roll up. Deliberately NOT tied to request
 * granularity, which `spool/transfer.h` leaves to the caller per request: a
 * blob fetched one leaf at a time and a blob fetched in spans have the same
 * cells, because a storage grid that depended on how the bytes arrived could
 * not be rebuilt after a restart.
 *
 * THE REFERENCE IS OVER SLOTS, NOT LEAVES, AND THAT IS FORCED. This was
 * written to fold true leaf hashes and to offer a second pass recomputing
 * the blob's root from stored bytes -- the definitive check, needing no
 * reference at all. It does not exist, because it cannot: `fzn_spool_read`
 * returns the STRIDE and not the leaf's own length, and says why in its own
 * comment -- "a store does not know it; the sealed length lives in the
 * blob's own framing and the last leaf is short."
 *
 * So nothing here can reproduce a leaf hash, and nothing here can produce a
 * value comparable with `spool->root`. The reference is a digest over the
 * fixed-width SLOTS instead, which needs no lengths and answers the only
 * question this file asks: have these bytes changed since they were
 * believed. Sealing and stepping fold the same bytes the same way.
 *
 * **A WHOLE-TREE CHECK IS THE CALLER'S AND IS STILL AVAILABLE**, because the
 * caller has the one thing missing. Resolve each leaf's length from the
 * manifest, `fzn_spool_read` the slot, `fzn_blob_leaf_hash` that many bytes,
 * `fzn_blob_tree_push`, and compare `fzn_blob_tree_root` with the root the
 * spool was opened on. Four existing functions and a loop; what it is not is
 * a store operation, because the store is precisely the layer that does not
 * know the lengths.
 *
 * That check is worth having where sealing cannot be trusted to be prompt,
 * which is the next paragraph.
 *
 * SEALING IS AUTHENTIC BY CONSTRUCTION, AND ONLY IF IT IS PROMPT. A cell's
 * root is computed from stored leaves once every leaf of it is present.
 * Nothing re-verifies it against the blob root, and nothing needs to: every
 * one of those leaves was proved against the root by `fzn_spool_place` when
 * it arrived. **A cell sealed late records whatever is on disk then**, so a
 * caller that seals hours after placement has recorded rot as truth. Seal
 * after placing, and use `fzn_attest_*` below where that discipline cannot
 * be relied on -- it is the check that needs no discipline at all.
 *
 * THE CALLER DRIVES EVERY PASS, in bounded steps, the same shape
 * `fzn_transfer_expire` has: a 4 GiB blob is 4 GiB of reads and a call that
 * did all of it would block whoever called it for as long as the disk takes.
 *
 * AND A SCRUB NOTHING CALLS IS NOT DETECTION. fuzzypickles paid for that:
 * their store had the verb for a long time, it found rot reliably when
 * somebody ran it, and nothing ran it. Their daemon now does one bounded
 * slice every 30 seconds. This file cannot schedule itself -- it has no
 * clock, by the same rule as everywhere else here -- so the obligation
 * passes to the consumer, and it is stated here because a header is where
 * somebody will look for it.
 */

#ifndef FZN_SCRUB_H
#define FZN_SCRUB_H

#include "spool.h"

/* Leaves to a cell.
 *
 * The same 64 as a verification batch, and NOT for the same reason, which is
 * worth separating because the numbers agreeing is a coincidence worth
 * knowing about rather than a dependency. `FZN_MSG_MAX_SPAN` is 64 because
 * that bounds unverified bytes held for a stranger (sec 106). This is 64
 * because it sets the repair unit -- one rotted byte costs a re-fetch of one
 * cell -- and the reference cost, which is one hash per cell. Changing
 * either does not require changing the other.
 */
#define FZN_SCRUB_CELL 64u

/* A safe upper bound on the cells a blob decomposes into, for sizing the
 * caller's arrays. Not exact: the canonical decomposition of a tree whose
 * leaf count is not a multiple of the cell size ends in a tail of smaller
 * cells, one per set bit below the cell size. `fzn_scrub_cells` returns the
 * exact number, and `transfer_test`-style exhaustive cases pin that this
 * bound is never exceeded. */
#define FZN_SCRUB_MAX_CELLS(leaves) (((size_t)(leaves) / FZN_SCRUB_CELL) + 7u)
#define FZN_SCRUB_SEALED_LEN(cells) (((size_t)(cells) + 7u) / 8u)

typedef enum fzn_scrub_err {
	FZN_SCRUB_OK = 0,
	FZN_SCRUB_ERR_MALFORMED,
	/* The pass reached the last cell. ORDINARY, and its own code so a
	 * stepping caller stops without treating the end as a fault -- the
	 * same reason `fzn_transfer_next_want` separates NONE from FULL. */
	FZN_SCRUB_DONE,
	/* A leaf the bitmap claims could not be read back. Distinct from
	 * CORRUPT because the store failed to answer rather than answering
	 * wrongly, and a caller may retry one and not the other. */
	FZN_SCRUB_ERR_BACKEND,
} fzn_scrub_err_t;

const char *fzn_scrub_err_str(fzn_scrub_err_t err);

/* The exact number of cells a blob of `leaves` leaves decomposes into. */
uint64_t fzn_scrub_cells(uint64_t leaves);

typedef struct fzn_scrub {
	fzn_spool_t *spool;
	/* `cells` hashes, the caller's. */
	uint8_t *roots;
	/* One bit per cell, the caller's. */
	uint8_t *sealed;
	uint64_t cells;
	/* Two independent passes over the same grid, so a caller may seal
	 * newly-arrived cells and re-check old ones without either resetting
	 * the other. */
	uint64_t seal_cell;
	uint64_t seal_first;
	uint64_t step_cell;
	uint64_t step_first;
} fzn_scrub_t;

fzn_scrub_err_t fzn_scrub_open(fzn_scrub_t *scrub, fzn_spool_t *spool, uint8_t *roots,
                               uint64_t cells, uint8_t *sealed, size_t sealed_len);

/*
 * Records a reference hash for every cell now held in full and not yet
 * sealed, up to `limit` cells, and reports how many were sealed.
 *
 * Cells that are not held in full are SKIPPED rather than refused: a partial
 * cell is mid-transfer, and there is nothing wrong with it. The pass wraps to
 * the start after the last cell, so a caller looping this alongside a
 * transfer keeps picking up cells as they complete.
 */
fzn_scrub_err_t fzn_scrub_seal(fzn_scrub_t *scrub, const fzn_hash_ops_t *hash, uint64_t limit,
                               uint64_t *out_sealed);

/*
 * Re-reads up to `limit` sealed cells and compares them with their reference.
 *
 * A cell that no longer matches has its leaves returned to the store's
 * want-list with `fzn_spool_forget` and its seal cleared, so the next
 * `fzn_spool_plan_want` asks for them again and a peer re-supplies them
 * verified. That is the whole of repair, and it is the same property
 * `spool/transfer.h` relies on: nothing has to return a range to a want-list
 * because clearing the bits IS the return.
 *
 * `out_checked` counts cells read, `out_dropped` counts cells that failed.
 * Both may be NULL.
 */
fzn_scrub_err_t fzn_scrub_step(fzn_scrub_t *scrub, const fzn_hash_ops_t *hash, uint64_t limit,
                               uint64_t *out_checked, uint64_t *out_dropped);

#endif /* FZN_SCRUB_H */
