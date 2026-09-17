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
	/* The current time, for command expiry and chain validity. */
	uint64_t (*clock)(void);
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
