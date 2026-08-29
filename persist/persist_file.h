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
typedef struct fzn_persist_file {
	const char *dir;
	fzn_persist_ops_t ops;
} fzn_persist_file_t;

/* Point `store` at `dir`. Returns its ops, or NULL if `dir` is absent or too
 * long for a bounded path -- nothing here allocates, so a path has a
 * ceiling and a caller is told rather than truncated. */
const fzn_persist_ops_t *fzn_persist_file_init(fzn_persist_file_t *store, const char *dir);

#endif /* FZN_PERSIST_FILE_H */
