/* The estate's members, proved by their chains, so a note written by one
 * reaches a node that is not paired with it. sec 445.
 *
 * THE GAP, sec 432's: a node admits notes from itself and the nodes it is
 * paired with -- those it pulls from and those it serves. In an estate of
 * three, B pulling from R and C pulling from R, a note C wrote reaches R and
 * is refused at B: C is a member, and B has no way to know it.
 *
 * THE ANSWER IS PROOF-CARRYING, as sec 432 named it: B asks R for R's
 * members, each with the capability chain R holds for it, and B admits a key
 * only when that chain verifies against B's OWN estate root, for the remote
 * capability, with B's own revocations applied. R vouches for nothing; the
 * chain is the proof, so a node that lies about its members can name only
 * keys the estate's root actually granted.
 *
 * ASKED ONLY BY MEMBERS. The question rides the remote hop under the remote
 * capability; a contact's requests reach only the shared notes (sec 436) and
 * never this answer, and a contact is never listed, since a share's chain is
 * not membership.
 *
 * A CHAIN THROUGH ANOTHER ROOT IS NOT ADMITTED. One that starts at a root
 * the genesis added (sec 411) needs that root's proof to verify against the
 * estate's root, and a peer record keeps the chain and not the proof; such a
 * member's notes are refused at B as before, and the refusal is counted.
 *
 * Two messages in the notes sync family, version 2, `notes/sync.situ`'s
 * types 11 and 12:
 *
 *   MEMBERS_QUERY   version | type | from u16
 *   MEMBERS         version | type | total u16 | from u16 | count u8 |
 *                   count x ( key 32 | hop_count u8 | hop_count x hop 179 )
 */

#ifndef FZN_NODE_MEMBERS_H
#define FZN_NODE_MEMBERS_H

#include <stddef.h>
#include <stdint.h>

#include "remote.h"

#define FZN_NODE_MEMBERS_QUERY 11u
#define FZN_NODE_MEMBERS_REPLY 12u
#define FZN_NODE_MEMBERS_QUERY_LEN 4u
#define FZN_NODE_MEMBERS_HEAD_LEN 7u

/* THE SERVER: answer a MEMBERS_QUERY from the peers this node holds, a page
 * as large as `reply_cap` takes. Contacts are left out. 0 for anything else,
 * so a caller dispatching on the first byte falls through. */
size_t fzn_node_members_answer(const fzn_node_config_t *config, const fzn_node_peer_t *peers,
                               size_t peer_count, const uint8_t *request, size_t request_len,
                               uint8_t *reply, size_t reply_cap);

/* How a puller asks: send `request`, fill `reply`. Nonzero on an answer. */
typedef int (*fzn_node_members_ask_t)(void *ctx, const uint8_t *request, size_t request_len,
                                      uint8_t *reply, size_t reply_cap, size_t *reply_len);

typedef enum fzn_node_members_err {
	FZN_NODE_MEMBERS_OK = 0,
	FZN_NODE_MEMBERS_ERR_MALFORMED = -1,
	FZN_NODE_MEMBERS_ERR_NO_ANSWER = -2, /* the peer did not answer */
	FZN_NODE_MEMBERS_ERR_SHAPE = -3      /* it answered with something else */
} fzn_node_members_err_t;

const char *fzn_node_members_err_str(fzn_node_members_err_t err);

/* THE PULLER: every member the peer `ask` reaches lists, each admitted into
 * `out` only when its chain verifies against `root` for `capability` at
 * `now` under `revocations` and names that key. `*count` keys, at most
 * `cap`; `*refused` counts the entries that did not prove, and those past
 * `cap`. */
fzn_node_members_err_t fzn_node_members_pull(fzn_node_members_ask_t ask, void *ask_ctx,
                                             const uint8_t root[FZN_PUBKEY_LEN],
                                             const fzn_cap_id_t *capability, uint64_t now,
                                             const fzn_sign_ops_t *sign,
                                             const fzn_revocation_store_t *revocations,
                                             uint8_t (*out)[FZN_PUBKEY_LEN], size_t cap,
                                             size_t *count, size_t *refused);

#endif /* FZN_NODE_MEMBERS_H */
