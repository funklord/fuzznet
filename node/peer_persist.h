/* Packing a remote peer the node serves, so a restart does not un-pair every
 * device.
 *
 * WHY THIS IS A FILE. `persist/persist.h` is the inventory of what must
 * survive a restart, and `fzn_node_peer_t` was in NEITHER of its lists --
 * not among the four that MUST be kept, not among the five recorded as
 * recoverable and deliberately unserved. That header opens by naming exactly
 * this hazard: "absence reading as not-required, where the absent thing is a
 * file". Its own table had the hole.
 *
 * WHAT LOSING ONE COSTS. `fuzznetd` binds the remote hop and serves nobody
 * until `fzn_node_state_t.peers` is filled, and nothing filled it from disk.
 * A peer's session keys and its capability chain come from an out-of-band
 * pairing card (`provision/provision.h`), so nothing re-derives them: losing
 * the set means pairing every device again. raidcfgd asked for the shape of
 * this on 2026-09-22 and reported finding none, which is how the gap
 * surfaced.
 *
 * WHY NOT IN `persist/`, WHERE THE OTHER FORMATS LIVE. `fzn_node_peer_t` is
 * declared in `node/remote.h`, which includes `wire/seal.h` -- the one module
 * in this library that depends on generated code, isolated there so every
 * other source builds and ships without situ. Including it from `persist.h`
 * would spend that isolation to save a file. So the SEAM and the inventory
 * stay there, the head format is shared from there, and the format for this
 * one type lives here beside the type.
 *
 * A PEER IS PACKED IN THE CLEAR, exactly as `persist.h` says of a prekey
 * secret, and for the same reason: what protects it is the backend's
 * permissions, a keystore or an enclave, and encrypting under a key stored
 * beside it would be theatre. This blob carries `recv_key` and `recv_ckey`,
 * so it deserves whatever the trust anchor and the agree secret get.
 */

#ifndef FZN_NODE_PEER_PERSIST_H
#define FZN_NODE_PEER_PERSIST_H

#include <stddef.h>
#include <stdint.h>

#include "remote.h"
#include "../persist/persist.h"

/* The longest blob `fzn_node_peer_pack` produces: the head, the identity and
 * the two session keys, the hop count, and up to FZN_CHAIN_MAX_HOPS hops.
 *
 * DELIBERATELY NOT FOLDED INTO FZN_PERSIST_MAX -- `persist.h` records why.
 * A host serving no remote peers should not carry a 1.5 KB buffer to store a
 * 42-byte trust anchor. */
#define FZN_NODE_PEER_BODY_FIXED \
	((size_t)FZN_PUBKEY_LEN + (size_t)FZN_AEAD_KEY_LEN + \
	 (size_t)FZN_COMMITMENT_KEY_LEN + 1u)
#define FZN_NODE_PEER_BLOB_MAX \
	((size_t)FZN_PERSIST_HEAD_LEN + FZN_NODE_PEER_BODY_FIXED + \
	 ((size_t)FZN_CHAIN_MAX_HOPS * (size_t)FZN_HOP_LEN))

/* Pack `peer` into `out`, writing the length. FZN_PERSIST_ERR_MALFORMED for a
 * null argument or a hop count past FZN_CHAIN_MAX_HOPS -- a peer this library
 * would refuse to verify is not one it will write down, because a blob that
 * cannot be opened is worse than an absent one: it reads as a peer that
 * exists and will not work. */
fzn_persist_err_t fzn_node_peer_pack(const fzn_node_peer_t *peer, uint8_t *out,
                                     size_t cap, size_t *len);

/* Open one. FZN_PERSIST_ERR_SHAPE for a wrong version, a wrong tag, a hop
 * count past the maximum, or a length that is not EXACTLY head plus body for
 * the hop count the blob declares.
 *
 * THE LENGTH IS CHECKED AGAINST THE DECLARED HOP COUNT, which is the only
 * interesting thing here: the count is inside the body, so it is read first
 * and then the whole record's length is required to agree with it. A blob
 * claiming eight hops and carrying two is refused rather than opened with
 * six hops of whatever followed it in the file. */
fzn_persist_err_t fzn_node_peer_open(const uint8_t *bytes, size_t len,
                                     fzn_node_peer_t *out);

#endif /* FZN_NODE_PEER_PERSIST_H */
