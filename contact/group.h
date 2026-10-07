/* Groups of contacts, so a subtree can be shared with several at once.
 * sec 471: the holder's "a group share is a grant per member" (sec 435),
 * built now on the holder's word of 2026-10-03.
 *
 * A GROUP IS A NAME AND ITS MEMBERS' KEYS, kept by the node beside its
 * contacts. Its name follows a contact name's rule; a share names a group as
 * `@NAME`, which no contact name can be, so the two never collide.
 *
 * A GROUP'S ID IS RANDOM, drawn when it is made and filed with it, sec 516.
 * It was a hash of the name until then, which made the name the group's
 * identity: a group removed and made again under its name inherited every
 * share row left under the old one, and no group could ever be renamed.
 * Names are labels, resolved to ids only where a person types one. Groups
 * made before keep their hashed ids, which are ids like any other.
 *
 * A GROUP SHARE IS ONE ROW, NOT ONE PER MEMBER. The share table
 * (`notes/share.h`) holds it under the group's id, and a
 * contact asking reaches its own rows and those of every group it is in --
 * read at the moment it asks. So a member added is served at once and a
 * member removed is not, with no rows to keep in step. Each member still
 * fetches under its own grant (`grant share`): that is the "grant per
 * member", the share capability's chain being per contact.
 *
 * CORE, as the share table is (`persist/persist.h`): membership decides who
 * reads a shared subtree, so a group rolled back re-admits a member removed
 * from it -- a door.
 */

#ifndef FZN_CONTACT_GROUP_H
#define FZN_CONTACT_GROUP_H

#include <stddef.h>
#include <stdint.h>

#include "contact.h"
#include "../session/random.h"

#define FZN_GROUP_MEMBERS_MAX 64u
#define FZN_GROUPS_MAX 32u

typedef struct fzn_group {
	uint8_t id[FZN_PUBKEY_LEN];
	char name[FZN_CONTACT_NAME_MAX + 1u];
	size_t name_len;
	size_t count;
	uint8_t members[FZN_GROUP_MEMBERS_MAX][FZN_PUBKEY_LEN];
	uint64_t made_at_ms;
} fzn_group_t;

/* A new, empty group under an id drawn from `rng`. TAKEN when one has the
 * name; FULL past FZN_GROUPS_MAX; BACKEND when `rng` draws nothing, or an id
 * already filed. */
fzn_contact_err_t fzn_group_add(const fzn_persist_ops_t *store, const fzn_random_ops_t *rng,
                                const char *name, size_t len, uint64_t now_ms);

fzn_contact_err_t fzn_group_remove(const fzn_persist_ops_t *store, const char *name,
                                   size_t len);

/* The group named `name`, by reading every group: a name is a label, not
 * where a group is filed. NAME when it is not a contact name. */
fzn_contact_err_t fzn_group_find(const fzn_persist_ops_t *store, const char *name, size_t len,
                                 fzn_group_t *out);

/* The group filed under `id`. */
fzn_contact_err_t fzn_group_get(const fzn_persist_ops_t *store,
                                const uint8_t id[FZN_PUBKEY_LEN], fzn_group_t *out);

/* `key` into the group, or out of it. Joining twice keeps one; FULL past
 * FZN_GROUP_MEMBERS_MAX; leaving a group one is not in is ABSENT. */
fzn_contact_err_t fzn_group_join(const fzn_persist_ops_t *store, const char *name, size_t len,
                                 const uint8_t key[FZN_PUBKEY_LEN]);
fzn_contact_err_t fzn_group_leave(const fzn_persist_ops_t *store, const char *name, size_t len,
                                  const uint8_t key[FZN_PUBKEY_LEN]);

/* Every group, in name order, `cap` of them. */
fzn_contact_err_t fzn_group_list(const fzn_persist_ops_t *store, fzn_group_t *out, size_t cap,
                                 size_t *count);

/* The ids of the groups `key` is in, `cap` of them. */
fzn_contact_err_t fzn_group_ids_of(const fzn_persist_ops_t *store,
                                   const uint8_t key[FZN_PUBKEY_LEN],
                                   uint8_t (*out)[FZN_PUBKEY_LEN], size_t cap, size_t *count);

#endif /* FZN_CONTACT_GROUP_H */
