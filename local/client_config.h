/*
 * A CLIENT'S OWN CONFIGURATION, project.md sec 908: one small file per client, the
 * holder's. A client has no store, and needs "where is my daemon" before it can
 * reach one, so what it starts with lives beside it: `KEY VALUE` lines, only that
 * client writing them, so nothing to lock or agree. Written whole through a temporary
 * and a rename, so a reader never meets half of one.
 *
 * A PRESET goes through `fzn_preset_apply`, as a daemon's does, by the ops below.
 */
#ifndef FZN_LOCAL_CLIENT_CONFIG_H
#define FZN_LOCAL_CLIENT_CONFIG_H

#include <stddef.h>

#include "../node/presets.h"

typedef struct fzn_client_config_row {
	char *key;
	char *value;
} fzn_client_config_row_t;

typedef struct fzn_client_config {
	char *path;
	fzn_client_config_row_t *rows;
	size_t n, cap;
} fzn_client_config_t;

/* READ `path` into `c`: a file that is not there is an empty configuration. 1, or 0
 * with no memory or a file that will not read. */
int fzn_client_config_load(fzn_client_config_t *c, const char *path);

/* THE VALUE OF `key`, or NULL. */
const char *fzn_client_config_get(const fzn_client_config_t *c, const char *key);

/* SET, in memory and on disk. 1, or 0 for a key or value out of shape, or a file
 * not written. A key is one word, a value one line. */
int fzn_client_config_set(fzn_client_config_t *c, const char *key, const char *value);

/* `c` as what a preset writes through. */
void fzn_client_config_ops(fzn_client_config_t *c, fzn_preset_ops_t *ops);

void fzn_client_config_free(fzn_client_config_t *c);

#endif /* FZN_LOCAL_CLIENT_CONFIG_H */
