/* Contacts: the keys outside the estate a node knows by name. sec 435.
 *
 * THE COPYRIGHT HOLDER'S MODEL (sec 430): one list of contacts, each
 * differentiated only by the capabilities granted to it -- no friend list
 * beside it -- and every relation across estates a capability granted to an
 * outside key. So a contact is a key and a name, and nothing else: what a
 * contact may do is the chains issued to it, which live and are revoked
 * where every chain is. A contact entry by itself grants nothing.
 *
 * TWO LISTS, SPLIT BY THE ESTATE'S BOUNDARY. Members -- this node, the
 * estate's roots, the nodes paired to it -- are inside; contacts are
 * outside, and a key is never both. This module stores contacts and checks
 * only what it can see, a name's shape and that one name belongs to one key;
 * refusing a member's key is the caller's, which holds the membership.
 *
 * NAMES ARE fuzzypickles' PEER NAMES: 1 to 32 characters of [A-Za-z0-9_].
 * The same rule in both trees, so a contact moves between them unchanged and
 * a name is one word on a command line.
 */

#ifndef FZN_CONTACT_H
#define FZN_CONTACT_H

#include <stddef.h>
#include <stdint.h>

#include "../persist/persist.h"

#define FZN_CONTACT_NAME_MAX 32u
#define FZN_CONTACTS_MAX 64u

typedef enum fzn_contact_err {
	FZN_CONTACT_OK = 0,
	FZN_CONTACT_ERR_MALFORMED = -1, /* a null */
	FZN_CONTACT_ERR_NAME = -2,      /* a name not of [A-Za-z0-9_], or not 1 to 32 */
	FZN_CONTACT_ERR_TAKEN = -3,     /* the name is another key's */
	FZN_CONTACT_ERR_ABSENT = -4,    /* no such contact */
	FZN_CONTACT_ERR_FULL = -5,      /* FZN_CONTACTS_MAX are held */
	FZN_CONTACT_ERR_BACKEND = -6,   /* the store refused, or cannot list */
	FZN_CONTACT_ERR_SHAPE = -7      /* a held entry will not read */
} fzn_contact_err_t;

const char *fzn_contact_err_str(fzn_contact_err_t err);

typedef struct fzn_contact {
	uint8_t key[FZN_PUBKEY_LEN];
	char name[FZN_CONTACT_NAME_MAX + 1u];
	size_t name_len;
	uint64_t added_at_ms;
} fzn_contact_t;

/* Whether `name` is a contact name. */
int fzn_contact_name_ok(const char *name, size_t len);

/* Add `key` as `name`, or rename it when it is held. TAKEN when another key
 * has the name; FULL past FZN_CONTACTS_MAX. A rename keeps when it was added. */
fzn_contact_err_t fzn_contact_add(const fzn_persist_ops_t *store,
                                  const uint8_t key[FZN_PUBKEY_LEN], const char *name,
                                  size_t name_len, uint64_t now_ms);

fzn_contact_err_t fzn_contact_get(const fzn_persist_ops_t *store,
                                  const uint8_t key[FZN_PUBKEY_LEN], fzn_contact_t *out);

/* The contact named `name`. */
fzn_contact_err_t fzn_contact_find(const fzn_persist_ops_t *store, const char *name,
                                   size_t name_len, fzn_contact_t *out);

/* Forget a contact. What was granted to it is NOT revoked here: a grant is a
 * chain, revoked as chains are. ABSENT when there was none. */
fzn_contact_err_t fzn_contact_remove(const fzn_persist_ops_t *store,
                                     const uint8_t key[FZN_PUBKEY_LEN]);

/* Every contact, `cap` of them, in name order. */
fzn_contact_err_t fzn_contact_list(const fzn_persist_ops_t *store, fzn_contact_t *out,
                                   size_t cap, size_t *count);

#endif /* FZN_CONTACT_H */
