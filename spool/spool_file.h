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
typedef struct fzn_spool_file {
	int fd;
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

#endif /* FZN_SPOOL_FILE_H */
