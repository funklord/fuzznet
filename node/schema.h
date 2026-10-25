/*
 * THE SETTINGS FUZZNET DECLARES, and an extension's beside them, sec 686:
 * `state/schema.h` is the entry. Every cell fuzznet reads is here, from the
 * readers in `node/settings.c`, `node/daemon.c`, `node/admin.c` and
 * `node/stickers.c`; an extension's (`node/daemon.h`) are asked after, and a
 * key both claim is refused when the daemon starts.
 *
 * THE VERBS, any local caller's -- a declaration says nothing of anybody's
 * configuration:
 *
 *   list schema [PREFIX] [FROM]
 *                           the declared keys PREFIX opens, fuzznet's and
 *                           then the extension's: `ok TOTAL FROM KEY,TYPE,
 *                           SCOPES,MIN,MAX,DEFAULT,UNIT,FLAGS,SUMMARY ...`,
 *                           as many as fit one reply from the FROMth. A
 *                           FROM is all digits; anything else a PREFIX.
 *                           SCOPES is `estate`, `host` or `estate+host`;
 *                           FLAGS `restart`, `sensitive`, `advanced` and
 *                           `verb` joined by `+`, or `-`; DEFAULT, UNIT and
 *                           SUMMARY escaped (`local/escape.h`), `-` when
 *                           empty. A key ending in `/` is a family.
 *   get schema KEY          the one row KEY is, a family's instance
 *                           answered as its family: `ok ROW`.
 */
#ifndef FZN_NODE_SCHEMA_H
#define FZN_NODE_SCHEMA_H

#include <stddef.h>
#include <stdint.h>

#include "../state/schema.h"
#include "../local/vocabulary.h"
#include "../chain/authz.h"

/* FUZZNET'S OWN, in the order `list schema` gives them. */
extern const fzn_schema_entry_t fzn_node_schema_own[];
extern const size_t fzn_node_schema_own_n;

typedef struct fzn_node_schema {
	/* An extension's declarations, NULL and 0 for none. */
	const fzn_schema_entry_t *extra;
	size_t n_extra;
} fzn_node_schema_t;

/* THE ENTRY `key` IS, fuzznet's first; NULL when nobody declares it. */
const fzn_schema_entry_t *fzn_node_schema_find(const fzn_node_schema_t *schema, const uint8_t *key,
                                               size_t len);

/* AN EXTENSION'S DECLARATIONS, before they are taken: NULL when every one
 * has a key, a type and a scope and none claims a cell fuzznet or an
 * earlier one of them declares; else the first offending key. */
const char *fzn_node_schema_refused(const fzn_schema_entry_t *extra, size_t n);

/* A LOG LEVEL BY NAME OR LETTER, as `log/level` and `--log-level` take it:
 * 1 (critical) to 8 (trace), or 0 for neither. */
int fzn_node_schema_log_level(const uint8_t *value, size_t len);

/* The verbs above; 0 for a request that is not one. */
size_t fzn_node_schema_local(void *ctx, fzn_origin_t origin, const fzn_request_t *request,
                             char *reply, size_t cap);

#endif /* FZN_NODE_SCHEMA_H */
