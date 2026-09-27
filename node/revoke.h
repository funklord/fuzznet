/* A node revoking the grants it minted, and keeping what it revoked.
 *
 * sec 1: "a stolen device is something you revoke rather than a password you
 * change". `chain/revocation.h` has had the record, the signing and a store
 * that verifies on admission since sec 13, and the node consulted none of it:
 * `node/remote.c` passed NULL revocations to every decision. sec 379 could
 * cut a device off by forgetting its peer record, which is enough for a device
 * paired to one node and nothing more -- a grant honoured anywhere else has no
 * peer record to forget. This is revocation proper. sec 380.
 *
 * THE STORE CANNOT BE SAVED, SO THE RECORDS ARE. `fzn_revocation_store_t`
 * keeps "a hash and a flag, never a record" -- deliberately, so the hot path
 * compares rather than verifies -- which means there is nothing in it to
 * persist and re-trust. What a node persists is each record it ISSUED, and at
 * start every one is admitted again through `fzn_revocation_admit`, the same
 * verification a revocation arriving from anywhere gets. A node's own must
 * survive a restart on the node, or a restart re-admits every device it
 * revoked; and those a member LEARNED from its root are kept the same way, in
 * their own slot, so a restart with the root unreachable still denies them
 * (sec 384).
 *
 * ONE RECORD PER GRANTEE: the latest this node issued for it. A node grants
 * one capability (sec 376), so a grantee is one (issuer, capability, grantee)
 * triple, and the latest record is what a restart must re-establish.
 *
 * A NODE THAT JOINED AN ESTATE REVOKES THROUGH ITS CHAIN. A root-issued
 * revocation is checked against the pinned root; a member's is admitted with
 * `fzn_revocation_offer_chain`, presenting the chain from the root that makes
 * it the grantor -- the same `fzn_node_authority_t` it pairs with, and the
 * same standing, since revoking a descendant is the inverse of granting one
 * (`chain/revocation.h`). The record is signed by the member's own key and
 * names it as issuer. sec 385.
 */

#ifndef FZN_NODE_REVOKE_H
#define FZN_NODE_REVOKE_H

#include <stddef.h>
#include <stdint.h>

#include "caller.h"
#include "pair.h"
#include "provision.h"
#include "../chain/revocation.h"
#include "../persist/persist.h"

typedef enum fzn_node_revoke_err {
	FZN_NODE_REVOKE_OK = 0,
	FZN_NODE_REVOKE_MALFORMED = -1,
	/* This node has no standing to revoke: it is not its own root and
	 * holds no chain from the root that it may pass on. */
	FZN_NODE_REVOKE_NOT_ROOT = -2,
	/* Already revoked by this node. Not a failure of the request -- the
	 * grantee is revoked -- and its own code so a caller can say so. */
	FZN_NODE_REVOKE_ALREADY = -3,
	/* The record would not mint, or the store would not admit it -- full
	 * being the case that matters, since a revocation store never evicts. */
	FZN_NODE_REVOKE_STORE_REFUSED = -4,
	/* Revoked, or un-revoked, in the running store and not saved: in force
	 * until a restart, and forgotten by one. */
	FZN_NODE_REVOKE_NOT_SAVED = -5,
	/* Un-revoking a grantee this node holds no revocation of in force. */
	FZN_NODE_REVOKE_NOT_REVOKED = -6
} fzn_node_revoke_err_t;

const char *fzn_node_revoke_err_str(fzn_node_revoke_err_t err);

/* Revoke `grantee`'s grant of `capability` from this node. `root` is the root
 * the node verifies against: this node's own key when `authority` is NULL,
 * the estate root otherwise, with `authority` the node's chain from it -- as
 * `fzn_node_pair` takes them. The record is
 * admitted into `revocations` FIRST and saved second: a revocation in force
 * and unsaved is a smaller failure than one saved and not in force, which
 * would be the operator told a device is cut off while the node serves it. */
fzn_node_revoke_err_t fzn_node_revoke(const fzn_node_identity_t *id,
                                      const uint8_t root[FZN_PUBKEY_LEN],
                                      const fzn_node_authority_t *authority,
                                      const fzn_cap_id_t *capability,
                                      const uint8_t grantee[FZN_PUBKEY_LEN], uint64_t now,
                                      fzn_revocation_store_t *revocations,
                                      const fzn_persist_ops_t *store);

/* UNDO this node's revocation of `grantee`: mint the withdrawal naming the
 * record held in slot 9, admit it, and save it in that record's place. sec 386.
 *
 * The same standing as revoking, and the same order -- in force first, saved
 * second. A later `fzn_node_revoke` of the grantee then supersedes the
 * revocation this undid, which is what admission requires of a re-revocation.
 *
 * WHAT IT DOES NOT DO: tell anybody. A member that pulled the revocation
 * learns the withdrawal on its next pull, because `get revocation` serves slot
 * 9 and the withdrawal is now what slot 9 holds (sec 384). A host that learned
 * the revocation any other way keeps it; `chain/revocation.h` says why no
 * manifest carries withdrawals. */
fzn_node_revoke_err_t fzn_node_unrevoke(const fzn_node_identity_t *id,
                                        const uint8_t root[FZN_PUBKEY_LEN],
                                        const fzn_node_authority_t *authority,
                                        const uint8_t grantee[FZN_PUBKEY_LEN], uint64_t now,
                                        fzn_revocation_store_t *revocations,
                                        const fzn_persist_ops_t *store);

/* At start: admit every revocation this node ISSUED (slot 9) and every one it
 * LEARNED from its estate root (slot 10), from `store` into `revocations`,
 * verified against `root`. OK with nothing stored.
 *
 * A record that will not admit FAILS THE LOAD rather than being skipped: a
 * node that quietly re-admitted a device it had revoked is the failure this
 * prevents.
 *
 * A record issued by `root` is admitted as the root's. One issued by the
 * grantee of `authority` -- this member's own, sec 385 -- is admitted with that
 * chain when it withdraws the capability the chain carries. That includes a
 * record the node issued as its own root before it joined: it is still the
 * node's signed word that the grantee is cut off, and honouring it errs
 * toward denial, the one direction a revocation may err in. Any other record
 * is skipped and not counted -- one for a capability the chain does not carry
 * could never admit, and a node holding no chain (`authority` NULL, as for a
 * root) has nothing to verify its own pre-join records against (sec 383). */
fzn_persist_err_t fzn_node_revocations_load(const fzn_persist_ops_t *store,
                                            fzn_revocation_store_t *revocations,
                                            const uint8_t root[FZN_PUBKEY_LEN],
                                            const fzn_node_authority_t *authority,
                                            const fzn_sign_ops_t *sign,
                                            const fzn_hash_ops_t *hash, size_t *count);

/* The revocation this node issued for `grantee`, into `record` -- what a
 * member asking `get revocation` is served. 1 when one is held. */
int fzn_node_issued_revocation(const fzn_persist_ops_t *store,
                               const uint8_t grantee[FZN_PUBKEY_LEN],
                               uint8_t record[FZN_REVOCATION_LEN]);

/*
 * PULL THE ROOT'S REVOCATIONS INTO A MEMBER NODE. sec 384.
 *
 * fuzzypickles pushes: whoever mints a revocation sends it to every
 * registered sibling, which works because siblings register each other both
 * ways at join, addresses included. fuzznet's hop runs one way -- a caller
 * asks a node -- and a joined node already holds the pairing that makes it
 * its root's caller, while the root holds the node only as a peer it serves
 * and has no address for it (a pairing carries none, sec 377). So a member
 * ASKS: `get revocation` over `caller`, page by page, until the root's stated
 * total is reached.
 *
 * WHAT ARRIVES IS VERIFIED, NOT TRUSTED. Each record is admitted as root-
 * issued -- `fzn_revocation_offer_root` against `root` -- so a record the
 * root did not sign admits nothing. What admits is saved as slot 10 under its
 * grantee, so a restart with the root unreachable still denies it.
 *
 * `learned` counts records admitted and saved. A page that will not parse,
 * or a record that will not admit, stops the pull with an error rather than
 * carrying on past it.
 */
typedef enum fzn_node_pull_err {
	FZN_NODE_PULL_OK = 0,
	FZN_NODE_PULL_MALFORMED = -1,
	/* The root did not answer, or answered something other than `ok`. */
	FZN_NODE_PULL_NO_ANSWER = -2,
	/* A page did not parse as the grammar says it should. */
	FZN_NODE_PULL_SHAPE = -3,
	/* A record would not admit as the root's, or the running store is full. */
	FZN_NODE_PULL_REFUSED = -4,
	/* Admitted and not saved: in force until a restart. */
	FZN_NODE_PULL_NOT_SAVED = -5
} fzn_node_pull_err_t;

const char *fzn_node_pull_err_str(fzn_node_pull_err_t err);

/* ONE PAGE OF A PULL, absorbed: `reply` is the root's answer to
 * `get revocation FROM`, a reply line. Admits and saves what it carries, adds
 * to `*learned`, and sets `*next` and `*total` so a caller knows whether to
 * ask again and from where. Split from the pull for the reason sec 369 split
 * `fzn_caller_ask`: a consumer with its own poll loop sends, returns to the
 * loop, and absorbs the answer when the socket says one is there, and a test
 * that turns the root's loop by hand can do the same. */
fzn_node_pull_err_t fzn_node_revocations_absorb(const uint8_t *reply, size_t reply_len,
                                                size_t from,
                                                const uint8_t root[FZN_PUBKEY_LEN],
                                                const fzn_sign_ops_t *sign,
                                                const fzn_hash_ops_t *hash,
                                                fzn_revocation_store_t *revocations,
                                                const fzn_persist_ops_t *store,
                                                size_t *learned, size_t *next, size_t *total);

fzn_node_pull_err_t fzn_node_revocations_pull(fzn_caller_t *caller,
                                              const uint8_t root[FZN_PUBKEY_LEN],
                                              const fzn_sign_ops_t *sign,
                                              const fzn_hash_ops_t *hash, uint64_t now,
                                              fzn_revocation_store_t *revocations,
                                              const fzn_persist_ops_t *store,
                                              size_t *learned);

/* The most revocations `fzn_node_revocations_load` enumerates in one call. */
#define FZN_NODE_REVOCATIONS_MAX 256u

#endif /* FZN_NODE_REVOKE_H */
