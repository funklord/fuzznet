/*
 * The claim, held as an advisory lock on a file.
 *
 * project.md sec 132. `flock` is what makes the whole arrangement safe: the
 * kernel drops the lock when the last descriptor referring to it is closed,
 * and every descriptor is closed when a process ends -- SIGKILL and a crash
 * included. So the release is the death rather than an inference about it,
 * and the process that acquires next can resume the previous owner's ratchet
 * chains knowing it is not racing a live holder.
 *
 * WHY `flock` RATHER THAN `fcntl` RECORD LOCKS. POSIX record locks are
 * released when the process closes ANY descriptor for the file, so a library
 * that opened the store for an unrelated read and closed it would silently
 * drop the claim -- a footgun this design cannot survive, since dropping the
 * claim is dropping the exclusivity a ratchet depends on. `flock` is owned
 * by the open file description, so nothing else's `close` can reach it.
 * Linux's `F_OFD_SETLK` fixes the same problem and is not portable to the
 * BSDs, which `flock` is.
 *
 * THE FORK HAZARD, WHICH IS REAL AND NOT HYPOTHETICAL. `fork` copies the
 * descriptor table and the copy refers to the SAME open file description, so
 * a forked child holds the same lock -- and the kernel releases it only when
 * BOTH have closed. A daemon that forks and lets the parent exit therefore
 * hands its claim to a child that may not know it has one, and a child that
 * outlives a killed parent keeps the whole host from taking over. The
 * descriptor is opened O_CLOEXEC so the common fork-then-exec case is
 * covered; a bare fork is not, and a caller that forks without exec must
 * close it in the child. There is no way to make that automatic, so it is
 * written down here.
 *
 * NOT OVER NFS. `flock` there has historically been emulated or ignored, and
 * an emulation that fails to release on death removes the one property this
 * is chosen for -- leaving a dead holder's claim standing for ever, which is
 * worse than having no claim at all. The identity directory belongs on a
 * local filesystem, and this backend cannot check that for the caller.
 */
#ifndef FZN_CLAIM_FILE_H
#define FZN_CLAIM_FILE_H

#include "claim.h"

typedef struct fzn_claim_file {
	int fd;
} fzn_claim_file_t;

/*
 * Open `path`, creating it if absent, and fill `ops_out` with a backend over
 * it. Does not take the claim.
 *
 * THE FILE'S CONTENT IS NEVER READ OR WRITTEN. It exists only to be
 * something the kernel can associate a lock with, so nothing is stored in it
 * and a caller may not use it for anything else -- a truncation or a rewrite
 * by somebody treating it as a pid file does not disturb the lock, but it
 * does invite a second mechanism to grow beside this one.
 *
 * `ops_out` points at `claim_file`, so both must outlive the claim.
 *
 * Returns FZN_CLAIM_ERR_BACKEND when the file cannot be opened, which is a
 * real condition rather than a caller bug: a directory that does not exist
 * yet, or one this user may not write. */
fzn_claim_err_t fzn_claim_file_open(fzn_claim_file_t *claim_file, const char *path,
                                    fzn_claim_ops_t *ops_out);

/* Close the descriptor, releasing the claim if it is held.
 *
 * Idempotent, so a cleanup path may call it without asking whether an open
 * succeeded. */
fzn_claim_err_t fzn_claim_file_close(fzn_claim_file_t *claim_file);

#endif
