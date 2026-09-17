/* The local access methods over the AF_UNIX listener: serve one accepted
 * connection. The kernel has already authenticated the peer -- its uid and
 * groups are on the descriptor -- so this determines SAME_USER or LOCAL from
 * `node.h`, reads one request line through `local/line.h`, authorises, and
 * writes a one-line status. The daemon (fuzznetd) accepts and calls this;
 * the sealed remote method is node/remote.h.
 *
 * The request line is NOT parsed. Defining request verbs is the holder's
 * vocabulary decision (sec 5); the node authenticates, authorises and
 * answers with its status, which is generic rather than a command set.
 */

#ifndef FZN_NODE_LOCAL_H
#define FZN_NODE_LOCAL_H

#include <stddef.h>

#include "node.h"
#include "../local/peer.h"

/* Build the one-line status response for a decided caller into out[cap],
 * newline included. Returns the length written, or 0 if it would not fit.
 * Pure: no descriptor, so it is tested directly. */
size_t fzn_node_status_line(fzn_authz_verdict_t verdict, fzn_origin_t origin,
                            char *out, size_t cap);

/* Serve one accepted local connection. `peer` is the credentials
 * fzn_socket_accept returned with `fd`. Reads one request line (under a
 * receive timeout so an idle client cannot wedge the caller), authorises the
 * peer's origin, and writes the status. OK and DENIED both wrote a response. */
fzn_node_serve_err_t fzn_node_serve_local(const fzn_node_config_t *config,
                                          int fd, const fzn_peer_t *peer);

#endif
