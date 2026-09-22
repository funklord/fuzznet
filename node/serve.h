/* The running node: the sockets it listens on and, for the remote hop, the
 * provisioned peers and crypto it needs. A per-user node sets listen_fd and
 * leaves udp_fd at -1; a node that also answers the network sets both and
 * fills the remote fields. Assemble a fzn_node_state_t and call fzn_node_run;
 * fuzznetd.c is the daemon that does exactly that from its arguments.
 *
 * The loop body fzn_node_run_once is exposed so a test can drive one
 * poll-and-dispatch iteration over real sockets without a running daemon and
 * without a fork -- the poll timeout bounds it, so nothing here can hang a
 * suite.
 */

#ifndef FZN_NODE_SERVE_H
#define FZN_NODE_SERVE_H

#include <stddef.h>
#include <stdint.h>

#include "node.h"
#include "remote.h"
#include "../frame/freshness.h"

/* The most reply payload a handler may return for the node to seal. */
#define FZN_NODE_REPLY_MAX 512u

typedef struct fzn_node_state {
	fzn_node_config_t config;
	int listen_fd;	/* the AF_UNIX listener, or -1 */
	int udp_fd;	/* the UDP socket, or -1 */
	/* Used only when udp_fd >= 0: the provisioned remote peers and the
	 * crypto that opens their frames. */
	const fzn_node_peer_t *peers;
	size_t peer_count;
	const fzn_hash_ops_t *hash;
	const fzn_aead_ops_t *aead;
	const fzn_sign_ops_t *sign;
	/* The receiver's replay window (frame/freshness.h), owned by the
	 * consumer and fed by every peer -- the nonce is globally unique, so
	 * one window serves all. A remote frame is dropped if it is absent. */
	fzn_replay_window_t *replay;
	/* The current time, for command expiry and chain validity. */
	uint64_t (*clock)(void);
	/* The random source and this node's identity, needed to seal a reply.
	 * Leave rng NULL and no reply is sent even if the handler returns one. */
	const fzn_random_ops_t *rng;
	uint8_t node_pubkey[FZN_PUBKEY_LEN];
	/* Called after a remote caller is authenticated and decided -- GRANTED
	 * or DENIED; a DROPPED frame never authenticated, so nothing is handed
	 * up. The handler may write up to `reply_cap` bytes of reply payload
	 * into `reply` and return the length; the node seals that reply to the
	 * caller and sends it. Return 0 for no reply -- a denial, or a request
	 * needing none. This is the seam where a consumer's handler (its
	 * vocabulary) acts; NULL to only authenticate and authorise. */
	size_t (*on_remote)(void *ctx, fzn_node_remote_result_t result,
	                    const fzn_opened_t *req, uint8_t *reply,
	                    size_t reply_cap);
	void *on_remote_ctx;
	/* The same seam on the LOCAL access method, which had none until the
	 * node started handing its request line on. `node/local.h` carries the
	 * contract and the one way it differs from `on_remote`: it is not
	 * called for a denied caller.
	 *
	 * The asymmetry in the TYPES is not an oversight either. A remote reply
	 * is a payload this node seals, so it is bytes; a local reply is
	 * written straight to a stream socket the caller is reading as text,
	 * so it is `char` and the handler owns its terminator. Giving them one
	 * type would mean one of the two lying about what it produces. */
	size_t (*on_local)(void *ctx, fzn_authz_verdict_t verdict,
	                   fzn_origin_t origin, const fzn_peer_t *peer,
	                   const uint8_t *request, size_t request_len,
	                   char *reply, size_t reply_cap);
	void *on_local_ctx;
} fzn_node_state_t;

/* The provisioned remote peer whose identity is `sender`, or NULL. Pure. */
const fzn_node_peer_t *fzn_node_find_peer(const fzn_node_peer_t *peers,
                                          size_t count,
                                          const uint8_t sender[FZN_PUBKEY_LEN]);

/* One poll-and-dispatch iteration, waiting at most timeout_ms (-1 blocks).
 * Accepts a ready local connection and serves it, receives a ready datagram
 * and serves it. Returns the number of descriptors served, 0 on a timeout. */
int fzn_node_run_once(fzn_node_state_t *state, int timeout_ms);

/* Run the node until the process is signalled -- the daemon body. It calls
 * fzn_node_run_once forever with no timeout; nothing here stops it, which is
 * what a daemon is, so a caller that needs to stop drives run_once itself. */
void fzn_node_run(fzn_node_state_t *state);

#endif
