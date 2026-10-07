/* A node's successions: kept, carried, minted. project.md sec 499.
 *
 * `chain/succession.h` is the record and its rule (sec 498). This is the node:
 * the successions it holds, in slot 30 with their issuers' admin chains, the
 * one that writes a new one, and the one that confirms another's.
 *
 * THEY TRAVEL AS THE VOTES DO: a succession is its issuer's act, in its
 * issuer's journal, and a reader admits it with the issuer's chain through
 * the admission votes take (`fzn_node_votes_take`), because a succession is
 * judged by the same store that judges the votes (sec 505).
 *
 * THE ERRORS ARE `fzn_node_revoke_err_t`'s: a succession fails in the ways a
 * vote does -- no standing, refused, not saved -- and a second enum would be
 * the same words under another name.
 */

#ifndef FZN_NODE_SUCCESSION_H
#define FZN_NODE_SUCCESSION_H

#include <stddef.h>
#include <stdint.h>

#include "revoke.h"
#include "../chain/succession.h"
#include "../persist/persist.h"

/* The most successions a node keeps. A re-key is an owner's deliberate act
 * after a theft; an estate that has done sixty-four has other problems. */
#define FZN_NODE_SUCCESSIONS_MAX 64u

typedef struct fzn_node_successions {
	fzn_succession_set_t set;
	fzn_succession_t entries[FZN_NODE_SUCCESSIONS_MAX];
} fzn_node_successions_t;

struct fzn_node_roots;

/* Empty, naming records by `hash`, which must outlive it. MALFORMED for
 * none. */
fzn_node_revoke_err_t fzn_node_successions_init(fzn_node_successions_t *ns,
                                                const fzn_hash_ops_t *hash);

/* At start: admit every succession in slot 30 into `ns`, its issuer's chain
 * into `revocations`. One that will not read or admit FAILS the load, as a
 * vote does (sec 380). `count` is how many were admitted. */
fzn_persist_err_t fzn_node_successions_load(fzn_node_successions_t *ns,
                                            const fzn_persist_ops_t *store,
                                            fzn_revocation_store_t *revocations,
                                            const uint8_t root[FZN_PUBKEY_LEN],
                                            const fzn_sign_ops_t *sign, size_t *count);

/* LEARN ONE: admit `record` with its issuer's chain (`hop_count` hops, none
 * for a root) and save it. STORE_REFUSED for one admission refuses,
 * NOT_SAVED for one admitted and not saved. */
fzn_node_revoke_err_t fzn_node_successions_learn(fzn_node_successions_t *ns,
                                                 const fzn_persist_ops_t *store,
                                                 fzn_revocation_store_t *revocations,
                                                 const uint8_t root[FZN_PUBKEY_LEN],
                                                 const fzn_sign_ops_t *sign,
                                                 const uint8_t record[FZN_SUCCESSION_LEN],
                                                 const uint8_t (*hops)[FZN_HOP_LEN],
                                                 size_t hop_count);

/* ONE ROW of slot 30 by its subject: the record and the chain beside it. 1
 * when it loaded and every hop opens. What the load reads. */
int fzn_node_succession_get(const fzn_persist_ops_t *store, const uint8_t subject[FZN_PUBKEY_LEN],
                            uint8_t record[FZN_SUCCESSION_LEN],
                            uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN], size_t *hop_count);

/* MINT ONE: `old` is succeeded by `new_key`, trusted up to `cut` (NULL for
 * none). As this node's acting root when it is one, else as an admin on
 * `mine`, its admin chain; logged under whichever key signs, as every act is
 * since sec 497; then learned. NOT_ROOT for a node that is neither. The new
 * record's id lands in `id` (may be NULL). */
fzn_node_revoke_err_t fzn_node_succession_issue(fzn_node_successions_t *ns,
                                                struct fzn_node_roots *roots,
                                                const fzn_persist_ops_t *store,
                                                const fzn_node_identity_t *id,
                                                const fzn_node_admin_chain_t *mine,
                                                fzn_revocation_store_t *revocations,
                                                const uint8_t root[FZN_PUBKEY_LEN],
                                                const uint8_t old[FZN_PUBKEY_LEN],
                                                const uint8_t new_key[FZN_PUBKEY_LEN],
                                                const uint8_t cut[FZN_SUCCESSION_ID_LEN],
                                                uint8_t id_out[FZN_SUCCESSION_ID_LEN]);

/* WHO `key` IS NOW, through the successions this node holds and judges by
 * `revocations`: `fzn_succession_resolve`. */
int fzn_node_successions_resolve(const fzn_node_successions_t *ns,
                                 const fzn_revocation_store_t *revocations,
                                 const uint8_t root[FZN_PUBKEY_LEN],
                                 const uint8_t key[FZN_PUBKEY_LEN],
                                 uint8_t out[FZN_PUBKEY_LEN]);

#endif /* FZN_NODE_SUCCESSION_H */
