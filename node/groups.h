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
 *     add group NAME                   a group made, this user its admin: ok ID
 *     remove group NAME                left; its name and shares forgotten
 *     add member GROUP CONTACT         an admin's
 *     remove member GROUP CONTACT      an admin's
 *     add admin GROUP CONTACT          a proposal, or an approval of one
 *     remove admin GROUP CONTACT       the same
 *     set group GROUP backfill 0|1     an admin's
 *     list group [FROM]                ok TOTAL FROM NAME,COUNT,ID,ADMIN,LINES ..., those this
 *                                      user is in; ID the group's, 64 hex (sec 647); ADMIN 1
 *                                      where this user may change it (sec 927); LINES how many
 *                                      are held here, so a client skips a group not moved
 *                                      (sec 929)
 *     get group NAME                   ok COUNT MEMBER ..., an admin as *NAME; stops where
 *                                      the reply fills, COUNT still all of them
 *     get group NAME member [FROM]     ok TOTAL FROM MEMBER ..., paged (sec 927)
 *     get group NAME water [FROM]      ok TOTAL FROM MINE MEMBER,HOST,HAVE,AT ...:
 *                                      MINE this host's lines in the group; for
 *                                      each other host, how many of them it
 *                                      last said it holds and when that
 *                                      changed, ms, `-,-` for one that has said
 *                                      nothing here (sec 911)
 *     get epoch GROUP                  ok EPOCH held|none, this host's secret
 *
 * GROUP, and NAME where a group is found, is this host's name for it or
 * its id as 64 hex, as `list group` prints it (sec 647); so is `@GROUP`
 * wherever a grant, a share or a line names a group.
 */
#ifndef FZN_NODE_GROUPS_H
#define FZN_NODE_GROUPS_H

#include <stddef.h>
#include <stdint.h>

#include "group_lines.h"
#include "group_log.h"
#include "../contact/contact.h"
#include "../local/vocabulary.h"
#include "../session/aead.h"
#include "../session/agree.h"
#include "../session/random.h"

/* ---- names ---------------------------------------------------------------- */

/* The group this host names `name`, or whose id `name` is as 64 hex (sec
 * 647) -- among the groups this host names either way. NAME when it is
 * neither a contact name nor an id; ABSENT when no group is found. */
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

/* THE GROUPS `root` IS A MEMBER OF, among those held, into `out`, grown to
 * hold them (sec 773): what a grant to a group is read through, at the
 * request. */
/* WHEN `member` JOINED group `id`, sec 804, as a floor in milliseconds: the end
 * of the second of its last ADD act, or of the CREATE act for the user who made
 * it (`fzn_node_group_floor_ms`). A MEMBER WHOSE JOINING THIS HOST CANNOT SEE --
 * no such act read -- is UINT64_MAX, withheld everything: taken as there from
 * the start it was handed the history a share kept from later members, the one
 * error sec 22 cannot undo. */
uint64_t fzn_node_group_floor_ms(uint64_t joined_at_s);
uint64_t fzn_node_group_joined_ms(const fzn_persist_ops_t *store, const fzn_hash_ops_t *hash,
                                  const uint8_t id[FZN_GROUP_ID_LEN], const fzn_group_t *g,
                                  const uint8_t *member);

fzn_contact_err_t fzn_node_group_ids_of(const fzn_persist_ops_t *store,
                                        const uint8_t root[FZN_PUBKEY_LEN],
                                        fzn_group_held_t *out);

/* WHOSE HOST `host` IS, as a group knows: a host some group held here lists
 * for a member, in a group `self` -- this user's root -- is a member of
 * too. Its member's root into `owner`; 0 when no such group holds it.
 * sec 630: what lets a member's host be served as its member. */
int fzn_node_group_host_owner(const fzn_persist_ops_t *store, const uint8_t self[FZN_PUBKEY_LEN],
                              const uint8_t host[FZN_PUBKEY_LEN], uint8_t owner[FZN_PUBKEY_LEN]);

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
	/* SEALING AND OPENING EPOCH SECRETS, sec 627: this host's prekey
	 * secret opens a box sealed to it. NULL agree: this host keeps none. */
	const fzn_agree_ops_t *agree;
	const fzn_aead_ops_t *aead;
	const fzn_agree_secret_t *agree_secret;
	/* THE LINES HELD HERE, sec 911, for what members say they hold. NULL:
	 * this host keeps none. */
	const fzn_group_lines_t *lines;
} fzn_node_groups_t;

/* MAKE AN ACT on `id`'s head -- or with `id` NULL a new group, its id into
 * `made` -- signed as this host, and offered to the log. */
fzn_group_log_err_t fzn_node_groups_act(const fzn_node_groups_t *g, uint8_t kind,
                                        const uint8_t *id, const uint8_t subject[FZN_PUBKEY_LEN],
                                        uint8_t setting, uint64_t value,
                                        uint8_t made[FZN_GROUP_ID_LEN]);

/* A GROUP LEARNED FROM ANOTHER HOST, named here if it is not yet, sec 837:
 * by the name its maker gave it, carried in its CREATE act, where that
 * name is free here -- and otherwise, or for a group made before the name
 * was carried, by its id's first 8 bytes in hex, as before. Its user may
 * rename it either way. OK when it is named. */
fzn_contact_err_t fzn_node_groups_name_learned(const fzn_node_groups_t *g,
                                               const uint8_t id[FZN_GROUP_ID_LEN]);

/* ---- epochs, sec 627 ----------------------------------------------------- */

/* EPOCH `epoch` OF GROUP `id`'s SECRET, as this host holds it: ABSENT when
 * it was never opened here. Kept in FZN_PERSIST_GROUP_EPOCH, core. */
fzn_group_log_err_t fzn_node_groups_secret(const fzn_node_groups_t *g,
                                           const uint8_t id[FZN_GROUP_ID_LEN], uint32_t epoch,
                                           uint8_t out[FZN_GROUP_SECRET_LEN]);

/* THIS HOST'S DUTIES TO GROUP `id`, each act made counted into `*made`:
 *
 *   - a member's host not yet among the group's hosts names itself (HOST);
 *   - a secret sealed to it and not yet opened here is opened and kept;
 *   - the current epoch with no secret yet gets one, drawn here (KEYS);
 *   - a host not given the current epoch is sealed it, by a host that
 *     holds it (KEYS);
 *   - while the group backfills, a host is given the epoch before the
 *     oldest it holds, as far back as the group keeps (KEYS).
 *
 * Anything this host cannot do -- it holds no secret, it is not a member
 * -- is left to a host that can. */
fzn_group_log_err_t fzn_node_groups_tend(const fzn_node_groups_t *g,
                                         const uint8_t id[FZN_GROUP_ID_LEN], size_t *made);

/* THE VERBS above: 0 when the request is none of them. */
size_t fzn_node_groups_local(const fzn_node_groups_t *g, const fzn_request_t *request,
                             char *reply, size_t cap);

#endif /* FZN_NODE_GROUPS_H */
