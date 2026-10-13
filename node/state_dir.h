/*
 * A NODE'S STATE DIRECTORY, copied out and wiped, project.md sec 620:
 * fuzzypickles' identity backup and reset (their secs 110 and 111) brought
 * into fuzznet as step 3d of sec 608.
 *
 * BACKUP COPIES EVERYTHING, with no export format and deliberately none: a
 * restore is the files copied back, and a format would be one more thing to
 * get wrong for the one operation that cannot be retried. The destination
 * must be a directory of this user's, mode 0700 and empty, since what is
 * copied includes the identity's seed; a partial copy is a failure.
 *
 * WIPE REMOVES EVERY REGULAR FILE under the directory, and nothing else:
 * no directory, no link, and nothing a link points at -- the walk never
 * follows one. It is the one deletion here over a computed path, so the
 * path is checked first: not empty, not `/`, and a directory itself rather
 * than a link to one.
 */
#ifndef FZN_NODE_STATE_DIR_H
#define FZN_NODE_STATE_DIR_H

#include <stddef.h>

/* WHETHER `dir` MAY RECEIVE A BACKUP: a directory, not a link, owned by
 * this process's user, mode 0700 exactly, and empty. 1 yes; 0 with `*why`. */
int fzn_state_dir_backup_ok(const char *dir, const char **why);

/* COPY every regular file and directory under `from` into `to`, which
 * exists: files created anew at mode 0600 and directories at 0700, so
 * nothing in `to` is overwritten. Anything else under `from` -- a link, a
 * socket -- fails the copy, as does any file not copied whole. 1 copied,
 * `*files` of them; 0 with `*why`, what was written left in place. */
int fzn_state_dir_copy(const char *from, const char *to, size_t *files, const char **why);

/* WHETHER `dir` MAY BE WIPED: named, not the filesystem's root, and a
 * directory itself rather than a link to one. Asks and deletes nothing, so
 * a test may ask it of `/`. */
int fzn_state_dir_wipe_ok(const char *dir, const char **why);

/* WIPE every regular file under `dir`, once `fzn_state_dir_wipe_ok` allows
 * it, `*files` of them: each truncated, then unlinked. Directories and links
 * stay; no link is followed. 1 done; 0 with `*why` -- `dir` not one this may
 * wipe, or a file that would not go. */
int fzn_state_dir_wipe(const char *dir, size_t *files, const char **why);

#endif /* FZN_NODE_STATE_DIR_H */
