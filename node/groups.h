/*
 * GROUPS AS A HOST USES THEM, project.md sec 626: this host's names for the
 * groups it holds, the acts it makes on its user's behalf, the verbs, and
 * the membership a grant to a group reads. The log is `node/group_log.h`.
 *
 * A NAME IS THIS HOST'S, never the log's (sec 516): `add group NAME` makes
 * a group and names it here; a group learned from another member's host is
 * named here by the first 8 bytes of its id in hex until somebody renames
 * it. A grant names a group as `@NAME`, which no contact name can be.
 *
 * A MEMBER IS A USER, by root, so a member is added by contact name -- a
 * contact's key is its user's root (sec 614). The verbs, all this node's
 * own user's:
 *
 *     add group NAME                   a group made, this user its admin
 *     remove group NAME                left; its name and shares forgotten
 *     add member GROUP CONTACT         an admin's
 *     remove member GROUP CONTACT      an admin's
 *     add admin GROUP CONTACT          a proposal, or an approval of one
 *     remove admin GROUP CONTACT       the same
 *     set group GROUP backfill 0|1     an admin's
 *     list group [FROM]                ok TOTAL FROM NAME,COUNT ..., those this user is in
 *     get group NAME                   ok COUNT MEMBER ..., an admin as *NAME
 */
#ifndef FZN_NODE_GROUPS_H
#define FZN_NODE_GROUPS_H

#include <stddef.h>
#include <stdint.h>

#include "group_log.h"
#include "../contact/contact.h"
#include "../local/vocabulary.h"
#include "../session/random.h"

/* ---- names ---------------------------------------------------------------- */

/* The group this host names `name`. NAME when it is not a contact name;
 * ABSENT when no group is named so. */
fzn_contact_err_t fzn_node_group_find(const fzn_persist_ops_t *store, const char *name,
                                      size_t len, uint8_t id[FZN_GROUP_ID_LEN]);

/* This host's name for `id`, NUL ended in `name`. ABSENT when unnamed. */
fzn_contact_err_t fzn_node_group_name(const fzn_persist_ops_t *store,
                                      const uint8_t id[FZN_GROUP_ID_LEN],
                                      char name[FZN_CONTACT_NAME_MAX + 1u], size_t *len);

/* NAME `id` so here. TAKEN when another group has the name. */
fzn_contact_err_t fzn_node_group_rename(const fzn_persist_ops_t *store,
                                        const uint8_t id[FZN_GROUP_ID_LEN], const char *name,
                                        size_t len);

/* ---- membership ----------------------------------------------------------- */

/* THE GROUPS `root` IS A MEMBER OF, among those held, `cap` of them: what
 * a grant to a group is read through, at the request. */
fzn_contact_err_t fzn_node_group_ids_of(const fzn_persist_ops_t *store,
                                        const uint8_t root[FZN_PUBKEY_LEN],
                                        uint8_t (*ids)[FZN_GROUP_ID_LEN], size_t cap,
                                        size_t *count);

/* ---- acting --------------------------------------------------------------- */

typedef struct fzn_node_groups {
	fzn_group_log_ops_t log;
	/* SIGNS AS THIS HOST, whose proof `signer` gives: the user's root,
	 * this host's record and the root's chain to it. 0 when it has none,
	 * and then no act can be made. */
	const fzn_sign_ops_t *host_sign;
	int (*signer)(void *ctx, fzn_contact_device_t *out);
	void *signer_ctx;
	const fzn_random_ops_t *rng;
	uint64_t (*clock)(void); /* seconds */
	/* A GROUP'S SHARES FORGOTTEN, when it is forgotten here (sec 478):
	 * 0 when they would not all go, and the group then stays. */
	int (*forget)(void *ctx, const uint8_t id[FZN_GROUP_ID_LEN]);
	void *forget_ctx;
	/* AN ACT MADE HERE, for the daemon to carry to the members' hosts. */
	void (*acted)(void *ctx, const uint8_t id[FZN_GROUP_ID_LEN]);
	void *acted_ctx;
} fzn_node_groups_t;

/* MAKE AN ACT on `id`'s head -- or with `id` NULL a new group, its id into
 * `made` -- signed as this host, and offered to the log. */
fzn_group_log_err_t fzn_node_groups_act(const fzn_node_groups_t *g, uint8_t kind,
                                        const uint8_t *id, const uint8_t subject[FZN_PUBKEY_LEN],
                                        uint8_t setting, uint64_t value,
                                        uint8_t made[FZN_GROUP_ID_LEN]);

/* THE VERBS above: 0 when the request is none of them. */
size_t fzn_node_groups_local(const fzn_node_groups_t *g, const fzn_request_t *request,
                             char *reply, size_t cap);

#endif /* FZN_NODE_GROUPS_H */
