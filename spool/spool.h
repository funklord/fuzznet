#ifndef FZN_SPOOL_H
#define FZN_SPOOL_H

/*
 * Where a blob's sealed leaves live while it is being assembled, and after.
 *
 * THIS IS THE PART A CONSUMER SHOULD NOT HAVE TO WRITE. `blob/` gives a
 * Merkle tree, a keyless verifier and a per-leaf AEAD; what it does not give
 * is somewhere to put a leaf that arrived out of order, a way to know which
 * of a million are still missing, or a way to resume after a restart. Three
 * consumers each writing a sparse file, a completion bitmap and a resume
 * path is three chances to get resumption wrong, and the failure mode is a
 * transfer that silently restarts from zero.
 *
 * A SUBSYSTEM, NOT THE CORE. This allocates and it writes files -- both of
 * which `blob/` deliberately does not -- so it is separately compiled and
 * separately disableable, like `persist/persist_file.c`. A target with no
 * filesystem builds `blob/` and drops this; `blob/` neither includes nor
 * references it.
 *
 * IT DOES NOT KNOW HOW LEAVES ARRIVE, and that is what makes it buildable
 * before the transfer protocol exists. A leaf is bytes plus an index; where
 * they came from -- a datagram, a file, a peer that offered them -- is the
 * consumer's. This was nearly deferred on the belief that a store needs the
 * protocol first, which was the same assumption that nearly had a handshake
 * frame invented for the sender ephemeral, and was wrong the same way.
 *
 * WHAT IT REFUSES TO DO IS THE POINT. It never accepts a leaf it has not
 * verified against the root, so a peer cannot fill a host's disk with
 * garbage that later fails to assemble. That check is `blob/`'s and is
 * KEYLESS -- a relay running this store serves bytes it cannot read, which
 * is the property the whole ciphertext-Merkle ordering exists for.
 */

#include <stddef.h>
#include <stdint.h>

#include "../blob/blob.h"

/*
 * The largest blob this will assemble, and it is a POLICY rather than a
 * limit of the format.
 *
 * `blob/` bounds a tree at 2^40 leaves, a terabyte, because that is where a
 * crafted proof stops being able to make a verifier loop. A store has a
 * different question to answer: how much disk a single unfinished transfer
 * may occupy, and how large the completion bitmap it holds in memory grows.
 * At one bit per leaf, 2^40 leaves is a 128 GiB bitmap, which is not a
 * bound, it is an outage.
 *
 * 2^22 leaves is 4 GiB of content and a 512 KiB bitmap -- large enough for
 * anything these projects move and small enough that a host can hold several
 * transfers without thinking about it. A consumer wanting more raises it
 * deliberately and pays the bitmap.
 */
#define FZN_SPOOL_MAX_LEAVES (1u << 22)

typedef enum fzn_spool_err {
	FZN_SPOOL_OK = 0,
	FZN_SPOOL_ERR_MALFORMED,
	/* Past FZN_SPOOL_MAX_LEAVES, or a leaf index past the blob's own
	 * count. A peer's number, and refused before anything is allocated or
	 * written -- which is the whole reason the ceiling is checked here
	 * rather than at the first write. */
	FZN_SPOOL_ERR_TOO_LARGE,
	/* The leaf does not verify against the root. A peer's bytes, expected,
	 * and the reason this store cannot be filled with garbage. */
	FZN_SPOOL_ERR_UNVERIFIED,
	/* The backend refused: no space, no permission, a short write. */
	FZN_SPOOL_ERR_BACKEND,
	/* Asked for a leaf this store does not have yet. Ordinary during a
	 * transfer and its own code, so a caller can tell it from a read that
	 * failed. */
	FZN_SPOOL_ERR_ABSENT,
} fzn_spool_err_t;

const char *fzn_spool_err_str(fzn_spool_err_t err);

/*
 * The backend seam, so the store's POLICY -- verify, place, track, resume --
 * is separable from where the bytes physically go.
 *
 * `read_at` and `write_at` are positional and take no seek, because a store
 * with concurrent readers cannot share a file offset. A memory backend, a
 * plain file, a preallocated partition and an mmap all fit; the default is
 * `spool/spool_file.c`.
 *
 * `sync` is separate from `write_at` and is called at completion rather than
 * per leaf: a fsync per 1 KiB leaf would make a transfer disk-bound for a
 * durability nobody asked for, and a partially written spool is recoverable
 * by construction -- every leaf is re-fetchable and the bitmap says which.
 */
typedef struct fzn_spool_ops {
	int (*read_at)(void *ctx, uint64_t offset, uint8_t *out, size_t len);
	int (*write_at)(void *ctx, uint64_t offset, const uint8_t *bytes, size_t len);
	int (*sync)(void *ctx);
	void *ctx;
} fzn_spool_ops_t;

/*
 * One blob being assembled.
 *
 * `present` is the caller's bitmap, one bit per leaf, which is why this
 * struct allocates nothing itself: a consumer that wants three concurrent
 * transfers sizes three bitmaps and knows exactly what they cost. The
 * SUBSYSTEM may allocate -- `spool_file.c` does -- but the bookkeeping does
 * not, which keeps the resumable half usable on a target with no heap and a
 * fixed buffer.
 */
typedef struct fzn_spool {
	uint8_t root[FZN_BLOB_HASH_LEN];
	uint64_t leaves;
	uint64_t have;
	uint8_t *present;
	size_t present_len;
	const fzn_spool_ops_t *ops;
} fzn_spool_t;

/* Bytes of bitmap a blob of `leaves` leaves needs. */
#define FZN_SPOOL_BITMAP_LEN(leaves) (((size_t)(leaves) + 7u) / 8u)

/*
 * Opens a spool over a caller's bitmap.
 *
 * `present` may carry a PREVIOUS RUN'S bitmap, which is the resume path and
 * the reason it is the caller's: this module does not decide where a bitmap
 * is kept between restarts, and `persist/` is the obvious place. `have` is
 * recomputed from the bits rather than trusted from a caller, so a bitmap
 * that was truncated mid-write cannot claim a blob is complete.
 */
fzn_spool_err_t fzn_spool_open(fzn_spool_t *spool, const uint8_t root[FZN_BLOB_HASH_LEN],
                               uint64_t leaves, uint8_t *present, size_t present_len,
                               const fzn_spool_ops_t *ops);

/*
 * Places one sealed leaf, having verified it against the root first.
 *
 * VERIFICATION BEFORE PLACEMENT, ALWAYS, and it is the ordering that makes
 * this safe to point at a stranger. A store that wrote first and checked
 * later would let anyone fill a disk; one that checks first cannot be made
 * to write a byte it has not proved belongs to the blob the caller asked
 * for. `hash` and the proof are `blob/`'s keyless verifier, so a relay with
 * no content key runs this path unchanged.
 *
 * A leaf already present is accepted and NOT rewritten -- a duplicate is
 * ordinary on a lossy transport, and rewriting would turn a duplicate into
 * disk traffic.
 */
fzn_spool_err_t fzn_spool_place(fzn_spool_t *spool, const fzn_hash_ops_t *hash, uint64_t index,
                                const uint8_t *sealed, size_t sealed_len,
                                const uint8_t *proof, unsigned proof_len);

/* Reads a leaf back, sealed, for a relay serving it on. FZN_SPOOL_ERR_ABSENT
 * if this store does not hold it yet. */
fzn_spool_err_t fzn_spool_read(const fzn_spool_t *spool, uint64_t index, uint8_t *out,
                               size_t cap, size_t *len);

int fzn_spool_has(const fzn_spool_t *spool, uint64_t index);
int fzn_spool_complete(const fzn_spool_t *spool);

/*
 * The next leaf this store still needs, at or after `from`. Returns
 * FZN_SPOOL_ERR_ABSENT when there are none left, which is how a caller walks
 * the gaps without asking about every index.
 */
fzn_spool_err_t fzn_spool_next_missing(const fzn_spool_t *spool, uint64_t from, uint64_t *out);

#endif /* FZN_SPOOL_H */
