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
 * only what it can see, a name's shape; refusing a member's key is the
 * caller's, which holds the membership.
 *
 * A KEY IDENTIFIES AND A NAME PRESENTS, sec 893. Two contacts may share a
 * name: hosts apart name people without hearing each other, and no host may
 * rename a person behind its user. So a name that fits two is AMBIGUOUS where
 * it is used, and refused there rather than guessed, and every verb taking a
 * name takes the key too.
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
/* THE ROOM A CALLER MAY START WITH, not a limit, sec 704: a user's contacts
 * are walked however many they are. Past 64 a contact was once refused as
 * FULL, and a listing of more stopped short. */
#define FZN_CONTACTS_MAX 64u

typedef enum fzn_contact_err {
	FZN_CONTACT_OK = 0,
	FZN_CONTACT_ERR_MALFORMED = -1, /* a null */
	FZN_CONTACT_ERR_NAME = -2,      /* a name not of [A-Za-z0-9_], or not 1 to 32 */
	FZN_CONTACT_ERR_TAKEN = -3,     /* a group's name is another group's */
	FZN_CONTACT_ERR_ABSENT = -4,    /* no such contact */
	FZN_CONTACT_ERR_FULL = -5,      /* no longer answered, sec 704; kept for its value */
	FZN_CONTACT_ERR_BACKEND = -6,   /* the store refused, or cannot list */
	FZN_CONTACT_ERR_SHAPE = -7,     /* a held entry will not read */
	FZN_CONTACT_ERR_ROOM = -8,      /* more held than the caller's room */
	FZN_CONTACT_ERR_AMBIGUOUS = -9  /* the name is several contacts' */
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

/* THE NAME THE `nth` (from 1) OF SEVERAL GROUPS CALLED `name` GOES BY, sec 890:
 * `name` itself for the first, `name_N` for the rest, `name` cut to fit, into
 * `out` (FZN_CONTACT_NAME_MAX bytes). Its length, or 0 for a name that is
 * none or an `nth` of 0. */
size_t fzn_contact_name_nth(const char *name, size_t len, size_t nth,
                            char out[FZN_CONTACT_NAME_MAX]);

/* Add `key` as `name`, or rename it when it is held; another key having the
 * name stops neither, sec 893. A rename keeps when it was added. */
fzn_contact_err_t fzn_contact_add(const fzn_persist_ops_t *store,
                                  const uint8_t key[FZN_PUBKEY_LEN], const char *name,
                                  size_t name_len, uint64_t now_ms);

fzn_contact_err_t fzn_contact_get(const fzn_persist_ops_t *store,
                                  const uint8_t key[FZN_PUBKEY_LEN], fzn_contact_t *out);

/* THE CONTACT `name` MEANS: one so named, or one whose key `name` is, as 64
 * hex, which no name can be. AMBIGUOUS when two are so named, sec 893, and
 * `out` is then not filled. */
fzn_contact_err_t fzn_contact_find(const fzn_persist_ops_t *store, const char *name,
                                   size_t name_len, fzn_contact_t *out);

/* EVERY KEY BUT `except` (may be NULL) NAMED `name`, sec 893: the first `cap`
 * into `keys`, `*count` how many there are. */
fzn_contact_err_t fzn_contact_named(const fzn_persist_ops_t *store, const char *name,
                                    size_t name_len, const uint8_t *except,
                                    uint8_t (*keys)[FZN_PUBKEY_LEN], size_t cap, size_t *count);

/* Forget a contact. What was granted to it is NOT revoked here: a grant is a
 * chain, revoked as chains are. ABSENT when there was none. */
fzn_contact_err_t fzn_contact_remove(const fzn_persist_ops_t *store,
                                     const uint8_t key[FZN_PUBKEY_LEN]);

/* Every contact, in name order, into `cap`: ROOM with `*count` the number
 * held when that is more, so the caller can give room and list again --
 * never the first so many. sec 704. */
fzn_contact_err_t fzn_contact_list(const fzn_persist_ops_t *store, fzn_contact_t *out,
                                   size_t cap, size_t *count);

/* EVERY CONTACT, to `fn` one at a time, in the store's order and with no
 * room to run past; `fn` answers 1 to go on. It must not add or remove a
 * contact while walking. BACKEND when the store cannot walk. sec 704. */
fzn_contact_err_t fzn_contact_each(const fzn_persist_ops_t *store,
                                   int (*fn)(void *ctx, const fzn_contact_t *c), void *ctx);

#endif /* FZN_CONTACT_H */
