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
 * Replies go back the same way: fzn_node_seal_reply seals a response under the
 * peer's session, which the caller opens with the key it seals with (the
 * session key is symmetric). The replay window is wired now: fzn_node_serve_
 * datagram admits the authenticated frame's nonce into a fzn_replay_window_t
 * the caller owns (frame/freshness.h), which does freshness and replay in one
 * call and refuses a nonce already seen. sec 303.
 */

#ifndef FZN_NODE_REMOTE_H
#define FZN_NODE_REMOTE_H

#include <stddef.h>
#include <stdint.h>

#include "node.h"
#include "../wire/seal.h"
#include "../chain/chain.h"
#include "../session/commitment.h"
#include "../frame/freshness.h"

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
 * place by the seal, so it must be the received buffer. `replay` is the
 * receiver's window (frame/freshness.h); the frame's nonce is admitted into
 * it, so a replayed frame is dropped and a command with no expiry is refused.
 * On GRANTED or DENIED, `opened` (if non-NULL) holds the decoded request. `sign` verifies the
 * capability chain's signatures and may be NULL only if the peer holds no
 * chain, which then denies. */
fzn_node_remote_result_t fzn_node_serve_datagram(const fzn_node_config_t *config,
                                                 const fzn_node_peer_t *peer,
                                                 const fzn_hash_ops_t *hash,
                                                 const fzn_aead_ops_t *aead,
                                                 const fzn_sign_ops_t *sign,
                                                 fzn_replay_window_t *replay,
                                                 uint64_t now, uint8_t *frame,
                                                 size_t frame_len,
                                                 fzn_opened_t *opened);

/* Seal a reply from this node back to `peer`, under the session that opened
 * the peer's frames. The session key is symmetric, so the caller opens the
 * reply with the key it seals requests with. `node_pubkey` is the node's
 * identity, which the caller established the session with and reads as the
 * reply's sender; a reply carries no capability. `msg` lets a caller
 * correlate the reply with its request. Returns 0 on success, -1 otherwise. */
int fzn_node_seal_reply(const fzn_node_peer_t *peer,
                        const uint8_t node_pubkey[FZN_PUBKEY_LEN],
                        const uint8_t *payload, size_t payload_len,
                        uint32_t msg, uint64_t expires_at,
                        const fzn_hash_ops_t *hash, const fzn_random_ops_t *rng,
                        const fzn_aead_ops_t *aead, uint8_t *out, size_t out_cap,
                        size_t *out_len);

/* ONE PIECE OF A REPLY THAT DOES NOT FIT IN A FRAME.
 *
 * A frame carries at most FZN_SPLIT_MAX_PAYLOAD bytes, so a reply larger
 * than that travels as several frames SHARING A `msg` and differing in
 * `index`, which is what `wire/frame.situ` has carried since it was written
 * -- `fzn_seal_build` has always taken `index` and `chunks`. Nothing in the
 * node used them: `fzn_node_seal_reply` hardcoded index 0 of 1, so a handler
 * could answer with one frame or not at all.
 *
 * REPORTED BY raidcfgd 2026-09-22, measured in their tree: their smallest
 * `status` reading is 3,230 bytes against a 512-byte cap, and their largest
 * 21,772. They stopped rather than write a bridge that could not carry one,
 * which is the right way round -- the cap was fuzznet's to answer for.
 *
 * `chunks` is how many pieces the whole reply is and `index` which this one
 * is. THE KIND IS DERIVED rather than passed: `chunks == 1` seals
 * FZN_KIND_UNIT and anything more seals FZN_KIND_CHUNK, so a caller cannot
 * produce a CHUNK frame claiming to be the only piece, or a UNIT frame that
 * is one of several. A receiver reads `kind` to know which it is holding,
 * and those two states disagreeing is not a thing this library should let a
 * caller construct.
 *
 * `index >= chunks` is refused, as is `chunks == 0` -- by `fzn_seal_build`,
 * which owns that rule and widens the comparison so the zero case falls out
 * of it rather than needing one of its own. Use `chunk/split.h` to
 * compute the pieces: `fzn_split_plan` bounds the count at
 * FZN_REASM_MAX_CHUNKS, which is what a receiver will reassemble, so a plan
 * that plans is a reply that can arrive. */
int fzn_node_seal_reply_chunk(const fzn_node_peer_t *peer,
                              const uint8_t node_pubkey[FZN_PUBKEY_LEN],
                              const uint8_t *payload, size_t payload_len,
                              uint32_t msg, uint16_t index, uint16_t chunks,
                              uint64_t expires_at,
                              const fzn_hash_ops_t *hash,
                              const fzn_random_ops_t *rng,
                              const fzn_aead_ops_t *aead, uint8_t *out,
                              size_t out_cap, size_t *out_len);

#endif
