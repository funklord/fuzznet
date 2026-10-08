/* The estate's configuration on a node: settings kept at their rank, the one
 * in force read, a node's own written into the journal, and the verbs.
 * project.md sec 540, stage 2 of sec 535; `state/setting.h` is the object.
 *
 * EVERY NODE HOLDS EVERY CELL. A setting is an act in its setter's estate
 * stream (stream 1), so every member that follows the estate applies it, and
 * every admin node is a source and a backup of every other's configuration,
 * a host's own local configuration among it -- the holder's of 2026-10-08.
 *
 * ONE ROW PER (CELL, RANK) in persist slot FZN_PERSIST_SETTING, the setting
 * that stands at that rank as its setter signed it. The value IN FORCE is the
 * highest rank whose standing setting sets one; a clear at a rank withdraws
 * that rank's layer and no more.
 *
 * A RANK IS JUDGED, never claimed: `fzn_node_apply_rank` decides it from the
 * setter's standing -- a root, an admin by a chain that verifies, or the host
 * writing its own host-scoped cell by its member chain -- and a node's own
 * write is judged by the same call before it is written, so the writer and
 * every node applying the record agree.
 *
 * THE VERBS, for this node's own user (remote use is sec 535's stage 3):
 *
 *     set setting SCOPE KEY VALUE     VALUE the rest of the line, %XX undone
 *     remove setting SCOPE KEY        a clear, at this node's rank
 *     get setting SCOPE KEY           ok RANK VALUE, or `absent`
 *     list setting [FROM]             ok FROM SHOWN MORE, then each standing
 *                                     value as SCOPE,ABOUT,KEY,RANK,VERSION,VALUE
 *
 * SCOPE is `estate`, `host` (this node) or `host=KEYHEX` (another node, which
 * takes an admin's or a root's standing). RANK is `root`, `admin` or `host`.
 */

#ifndef FZN_NODE_SETTINGS_H
#define FZN_NODE_SETTINGS_H

#include <stddef.h>
#include <stdint.h>

#include "journal.h"
#include "provision.h"
#include "../chain/authz.h"
#include "../local/vocabulary.h"
#include "../persist/persist.h"
#include "../state/setting.h"

/* The most rows one walk of the settings reads: every cell at every rank. */
#define FZN_NODE_SETTINGS_ROWS 1024u

struct fzn_node_apply;

typedef enum fzn_node_settings_err {
	FZN_NODE_SETTINGS_OK = 0,
	FZN_NODE_SETTINGS_MALFORMED = -1, /* a null, or a key or value out of shape */
	FZN_NODE_SETTINGS_REFUSED = -2,   /* not a setting, or this setter may not set it */
	FZN_NODE_SETTINGS_STALE = -3,     /* older than the one standing at its rank */
	FZN_NODE_SETTINGS_BACKEND = -4,   /* the store refused, or cannot list */
	FZN_NODE_SETTINGS_JOURNAL = -5    /* the journal refused the record */
} fzn_node_settings_err_t;

const char *fzn_node_settings_err_str(fzn_node_settings_err_t err);

typedef struct fzn_node_settings {
	const fzn_persist_ops_t *store;
	const fzn_hash_ops_t *hash;
	/* What opens a setting: its `verify` is used. */
	const fzn_sign_ops_t *verify;
	/* WRITING, all three NULL on a node that only applies others': */
	fzn_node_journal_t *journal;
	const fzn_node_identity_t *id;
	/* What judges a rank, this node's own included. */
	struct fzn_node_apply *apply;
	/* The estate's root, which an estate-scoped setting is about. */
	const uint8_t *estate;
	uint64_t (*now)(void);
} fzn_node_settings_t;

/*
 * KEEP `bytes` (a setting, `len` bytes) at `rank`, already judged: OK when it
 * now stands at that rank or is the very setting standing, STALE when the one
 * standing supersedes it, REFUSED for bytes that do not open.
 */
fzn_node_settings_err_t fzn_node_settings_learn(const fzn_node_settings_t *ns,
                                                const uint8_t *bytes, size_t len,
                                                fzn_setting_rank_t rank);

/*
 * THE VALUE IN FORCE for the cell (`scope`, `about`, `key`): 1 with it in
 * `value` (FZN_SETTING_VALUE_MAX bytes), its length and its rank, or 0 when
 * no rank sets one -- the caller's default stands.
 */
int fzn_node_settings_get(const fzn_node_settings_t *ns, fzn_scope_t scope,
                          const uint8_t about[FZN_SUBJECT_LEN], const uint8_t *key,
                          size_t key_len, uint8_t *value, size_t *value_len,
                          fzn_setting_rank_t *rank);

/* One value in force: its setting as it stands, and its rank. */
typedef void (*fzn_node_settings_each_fn)(void *ctx, const fzn_setting_t *s,
                                          fzn_setting_rank_t rank);

/*
 * EVERY VALUE IN FORCE, each once, to `each`: BACKEND when the store cannot
 * list, or holds more than FZN_NODE_SETTINGS_ROWS rows.
 */
fzn_node_settings_err_t fzn_node_settings_each(const fzn_node_settings_t *ns,
                                               fzn_node_settings_each_fn each, void *ctx);

/*
 * WRITE A SETTING as this node: judged first (REFUSED when this node may not
 * set that cell), then signed at one past every version held for the cell,
 * written into this node's estate stream, and kept. `set` 0 is a clear.
 */
fzn_node_settings_err_t fzn_node_settings_write(const fzn_node_settings_t *ns,
                                                fzn_scope_t scope,
                                                const uint8_t about[FZN_SUBJECT_LEN],
                                                const uint8_t *key, size_t key_len, int set,
                                                const uint8_t *value, size_t value_len);

/* A RETENTION RULE'S KEY, sec 541: `retention/` and 32 hex digits of a hash
 * of the rule's canonical text (`log/retain.h`), so one rule is one cell
 * however it was spelt. 0 when the hash refuses. */
#define FZN_NODE_SETTINGS_RULE_KEY_LEN (10u + 32u)
int fzn_node_settings_rule_key(const fzn_hash_ops_t *hash, const char *text, size_t len,
                               uint8_t key[FZN_NODE_SETTINGS_RULE_KEY_LEN]);

/* THIS HOST'S OLDER RULES INTO ITS SETTINGS, sec 541: each rule kept in
 * persist slot FZN_PERSIST_LOG_RULE (`log/rules.h`) written as the host
 * `about`'s setting, then taken out of the slot. A rule this node may not
 * write as a setting stays where it was. `*moved` counts the rules moved. */
fzn_node_settings_err_t fzn_node_settings_take_rules(const fzn_node_settings_t *ns,
                                                     const uint8_t about[FZN_SUBJECT_LEN],
                                                     size_t *moved);

/* The verbs above; 0 for a request that is not one. */
size_t fzn_node_settings_local(void *ctx, fzn_origin_t origin, const fzn_request_t *request,
                               char *reply, size_t reply_cap);

#endif /* FZN_NODE_SETTINGS_H */
