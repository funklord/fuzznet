/* Declared beside the backend, as session/aead_monocypher.h is. */
#ifndef FZN_PERSIST_FILE_H
#define FZN_PERSIST_FILE_H

#include "persist.h"

/*
 * A POSIX file-backed store, and the DEFAULT one -- a consumer should not
 * have to write this to use the library.
 *
 * `dir` must outlive the ops and must exist; this creates files inside it and
 * never the directory itself, because creating a directory tree is a policy
 * question (which mode, which owner, whose umask) that belongs to whoever
 * runs the daemon.
 *
 * SEPARATELY COMPILED AND SEPARATELY DISABLEABLE. A target with no filesystem
 * builds without this translation unit and loses nothing else; `persist.h`
 * and everything above it neither include nor reference it.
 */
/* Declared, not included. sec 209. */
struct flog_t;

typedef struct fzn_persist_file {
	const char *dir;
	fzn_persist_ops_t ops;
	/* Where this store says what happened, or NULL for silence. */
	struct flog_t *log;
} fzn_persist_file_t;

/*
 * Give this store somewhere to say what happened, or NULL to silence it.
 *
 * sec 220, and THIS IS THE SEAM WITH THE WIDEST GAP BETWEEN WHAT IT KNOWS AND
 * WHAT IT RETURNS. `load` and `save` are `int`: eleven distinct failures in
 * the save path and five in the load path all leave as `0`, and `errno` --
 * which says whether the disk is full, the directory read-only, or the
 * filesystem out of inodes -- is discarded at the boundary.
 *
 * THE PAIR THAT MATTERS MOST IS IN `load`, and it is not an error at all in
 * one direction. A slot with no file yet and a slot holding a file LARGER
 * THAN THE CALLER'S BUFFER both return `0`. The first is a host's first run.
 * The second is a file in this store's directory, under this store's naming,
 * that this library did not write -- and the comment on that refusal already
 * says "a caller sizing at FZN_PERSIST_MAX should never see this unless the
 * file is not ours". So the module knows the difference and has had no way to
 * say it. ENOENT is reported at INFO and everything else at ERR or WARN.
 *
 * WHAT IS PERSISTED IS WHAT MAKES THE SEVERITIES WHAT THEY ARE: a trust
 * anchor and a prekey secret. A save that fails leaves the previous bytes
 * intact -- the rename is atomic and that is the point -- so nothing is
 * corrupted and the new state is simply not durable, which a host discovers
 * on its next start by re-anchoring. At ERR.
 *
 * Subsystem `persist/file`. The log is borrowed and must outlive this one,
 * and `fzn_persist_file_init` clears it, so set it after init.
 *
 * AN INIT FAILURE IS NOT REPORTED HERE, and the limit is worth stating rather
 * than working around. `fzn_persist_file_init` returns NULL for an absent
 * `dir` or one too deep for a bounded path, and at that moment there is
 * nowhere to put a line: the caller cannot have set a log on a struct whose
 * fields are still whatever its memory held. The NULL is unambiguous -- those
 * are the only two things it means -- which is why this costs nothing.
 */
void fzn_persist_file_set_log(fzn_persist_file_t *store, struct flog_t *log);

/* Point `store` at `dir`. Returns its ops, or NULL if `dir` is absent or too
 * long for a bounded path -- nothing here allocates, so a path has a
 * ceiling and a caller is told rather than truncated. */
const fzn_persist_ops_t *fzn_persist_file_init(fzn_persist_file_t *store, const char *dir);

#endif /* FZN_PERSIST_FILE_H */
