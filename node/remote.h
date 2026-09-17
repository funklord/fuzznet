/* The remote access method over the UDP datagram carrier: authenticate a
 * sealed frame and authorise its sender as FZN_ORIGIN_REMOTE.
 *
 * Unlike the local hops, the kernel vouches for nobody across the network, so
 * authentication is cryptographic: the frame opens only under the session key
 * the two parties agreed (out-of-band, from pinned prekeys -- this library has
 * no wire handshake, session/session.h), so a frame that opens is one this
 * peer sealed. Authorisation is then a capability that chains to the node's
 * pinned root, decided by fzn_authz_decide with FZN_ORIGIN_REMOTE.
 *
 * The session keys and the peer's capability chain are PROVISIONED -- how they
 * are distributed (the pairing card, where the root signing key lives) is the
 * copyright holder's decision and out of scope here; this consumes a
 * fzn_node_peer_t a caller filled. The daemon looks a peer up by the sender in
 * the frame's clear header and calls this.
 *
 * WHAT THIS DOES NOT YET DO, named as the next work rather than a gap: seal a
 * reply back to the caller (the reverse session and fzn_seal_build), and the
 * replay window (frame/freshness.h) -- this checks the expiry a command
 * carries but does not yet record a nonce, so the daemon that owns per-peer
 * state owns replay. sec 299 lists the same for the transport below it.
 */

#ifndef FZN_NODE_REMOTE_H
#define FZN_NODE_REMOTE_H

#include <stddef.h>
#include <stdint.h>

#include "node.h"
#include "../wire/seal.h"
#include "../chain/chain.h"
#include "../session/commitment.h"

/* A provisioned remote peer: its identity, the session key that opens its
 * frames, and the capability chain it holds. Filled out of band. */
typedef struct fzn_node_peer {
	uint8_t sender[FZN_PUBKEY_LEN];
	uint8_t recv_key[FZN_AEAD_KEY_LEN];
	uint8_t recv_ckey[FZN_COMMITMENT_KEY_LEN];
	/* The capability chain this peer holds, as the raw hop bytes it owns.
	 * fzn_chain_hop_t is only a view over such bytes, so the peer stores the
	 * bytes and serve_datagram opens the views locally -- a peer copied by
	 * value stays self-contained. */
	uint8_t hop_bytes[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	size_t hop_count;
} fzn_node_peer_t;

/* How serving one datagram ended. GRANTED and DENIED both authenticated the
 * sender -- the frame opened -- and differ only in the authorisation.
 * DROPPED means the frame did not authenticate: a sender that is not this
 * peer's, a seal that did not open, or a stale command. A dropped frame gets
 * no reply, which denies an attacker an oracle. */
typedef enum fzn_node_remote_result {
	FZN_NODE_REMOTE_GRANTED = 0,
	FZN_NODE_REMOTE_DENIED = 1,
	FZN_NODE_REMOTE_DROPPED = -1
} fzn_node_remote_result_t;

/* Authenticate and authorise one received datagram. `frame` is decrypted in
 * place by the seal, so it must be the received buffer. On GRANTED or DENIED,
 * `opened` (if non-NULL) holds the decoded request. `sign` verifies the
 * capability chain's signatures and may be NULL only if the peer holds no
 * chain, which then denies. */
fzn_node_remote_result_t fzn_node_serve_datagram(const fzn_node_config_t *config,
                                                 const fzn_node_peer_t *peer,
                                                 const fzn_hash_ops_t *hash,
                                                 const fzn_aead_ops_t *aead,
                                                 const fzn_sign_ops_t *sign,
                                                 uint64_t now, uint8_t *frame,
                                                 size_t frame_len,
                                                 fzn_opened_t *opened);

#endif
