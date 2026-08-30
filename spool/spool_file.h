/* Declared beside the backend, as persist/persist_file.h is. */
#ifndef FZN_SPOOL_FILE_H
#define FZN_SPOOL_FILE_H

#include "spool.h"

/*
 * A sparse-file backend for one blob's leaves, and the DEFAULT one.
 *
 * WHY POSITIONAL READS AND WRITES RATHER THAN mmap, since mmap is what a
 * BitTorrent-shaped store usually reaches for and is what was asked about.
 * Both fit this seam; the reasoning is recorded so that swapping later is a
 * measurement rather than a rewrite.
 *
 *   - A leaf is 1056 bytes. One `pwrite` per leaf against a network that
 *     delivered it is a syscall dwarfed by the packet that carried it, so
 *     the syscall count mmap saves is not the cost that matters here.
 *   - mmap's failure mode is worse. A mapping over a file another process
 *     truncates raises SIGBUS at the faulting instruction, which is a crash
 *     rather than a return value -- and this store is deliberately pointed
 *     at bytes from strangers, so its failure paths want to be returnable.
 *   - A 4 GiB mapping on a 32-bit target is not addressable at all, and
 *     `netcfgd` runs on routers.
 *
 * mmap earns its place when the same pages are read repeatedly -- a seeder
 * serving one popular blob -- and that is exactly the case a second backend
 * can serve without this one changing, which is what the seam is for.
 *
 * NOT PRE-ALLOCATED, DELIBERATELY. `ftruncate` to the blob's full length
 * would make the file's size meaningful and let a resume sanity-check it,
 * and it is not done: on a filesystem without sparse support -- or with
 * `fallocate` semantics that reserve -- it would allocate the whole blob
 * before a single leaf arrived, which turns a 4 GiB transfer into a 4 GiB
 * commitment on the first packet. `pwrite` extends the file as leaves land,
 * and the bitmap remains the only thing that says what is present.
 */
#define FZN_SPOOL_FILE_PATH_MAX 512u

typedef struct fzn_spool_file {
	int fd;
	/* The sidecar's path, derived at open. Held rather than recomputed so
	 * that a checkpoint cannot be pointed somewhere else by a caller
	 * passing a different string the second time. */
	char bits[FZN_SPOOL_FILE_PATH_MAX];
	fzn_spool_ops_t ops;
} fzn_spool_file_t;

/*
 * Opens or creates the file at `path`. Returns its ops, or NULL.
 *
 * Mode 0600. The bytes are sealed leaves rather than plaintext, so this is
 * not the secret a prekey is -- but a partially assembled blob still says
 * what a host is fetching, and a consumer that wants to serve it on can
 * widen the mode itself. Defaulting narrow and letting a caller open it is
 * the direction that fails safe.
 */
const fzn_spool_ops_t *fzn_spool_file_open(fzn_spool_file_t *file, const char *path);

/* Closes the descriptor. Safe on a struct that never opened. */
void fzn_spool_file_close(fzn_spool_file_t *file);

/*
 * THE BITMAP, WHICH IS THE OTHER HALF OF RESUMING AND WAS MISSING.
 *
 * `spool/spool.c` keeps the bitmap in a buffer the caller lends it, which is
 * what makes the policy core -- and it deliberately does not say where that
 * buffer comes from between restarts. Nothing said. A consumer was therefore
 * left to invent a format for the one piece of state a transfer cannot
 * resume without, which is the same intimacy the backend exists to spare
 * them.
 *
 * It does not go through `persist/`: that contract is fixed records of at
 * most FZN_PERSIST_MAX bytes, and a bitmap at this library's ceiling is
 * 512 KiB. So it is a SIDECAR beside the spool file, `<path>.bits`.
 *
 * WHAT THE SIDECAR CARRIES BESIDES THE BITS, and why. A bitmap is opaque --
 * `fzn_spool_open` takes a root and a bitmap and has no way to tell that
 * they belong together, so a bitmap restored for the WRONG BLOB makes the
 * store report leaves present that hold another blob's ciphertext. The
 * transfer then completes, never re-requests them, and hands back a corrupt
 * blob: exactly the failure the module's write-then-set-the-bit ordering
 * exists to prevent, arriving by the one door that ordering does not cover.
 * The sidecar therefore names the root and the leaf count, and a resume
 * refuses anything that does not match.
 */

/*
 * Fills `present` from the sidecar, or leaves it ZEROED.
 *
 * FZN_SPOOL_OK when a matching bitmap was restored, FZN_SPOOL_ERR_ABSENT
 * when there was nothing to restore or what was there belongs to another
 * blob. The buffer is zeroed FIRST in every path, so a caller that ignores
 * the return value starts a fresh transfer rather than resuming onto
 * whatever its buffer held -- the direction that costs bandwidth rather than
 * correctness.
 */
fzn_spool_err_t fzn_spool_file_resume(const fzn_spool_file_t *file,
                                      const uint8_t root[FZN_BLOB_HASH_LEN], uint64_t leaves,
                                      uint8_t *present, size_t present_len);

/*
 * Writes the sidecar for `spool`, atomically.
 *
 * SYNCS THE DATA FIRST, and that ordering is the whole safety property
 * rather than tidiness. A bitmap that is STALE-FEWER costs a re-request of
 * leaves already held -- bandwidth, and a correct blob. A bitmap that is
 * STALE-MORE claims leaves whose bytes never reached the disk, and those are
 * never asked for again. So the fsync is done here rather than left to a
 * caller who would have to know to do it in that order; `persist.h` records
 * the same asymmetry for send and receive chains.
 *
 * Call it when a transfer pauses or at whatever interval a consumer likes --
 * not per leaf, which would make a transfer disk-bound for a guarantee it
 * does not need.
 */
fzn_spool_err_t fzn_spool_file_checkpoint(const fzn_spool_file_t *file,
                                          const fzn_spool_t *spool);

#endif /* FZN_SPOOL_FILE_H */
