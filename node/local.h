/* The local access methods over the AF_UNIX listener: serve one accepted
 * connection. The kernel has already authenticated the peer -- its uid and
 * groups are on the descriptor -- so this determines SAME_USER or LOCAL from
 * `node.h`, reads one request line through `local/line.h`, authorises, and
 * writes a one-line status. The daemon (fuzznetd) accepts and calls this;
 * the sealed remote method is node/remote.h.
 *
 * The request line is READ AND HANDED ON, never interpreted. What a verb
 * MEANS is sec 5's line and stays outside this library: the node
 * authenticates, authorises, and passes the bytes to a consumer's handler,
 * which is where a vocabulary lives. With no handler the node answers with
 * its own status, which is generic rather than a command set.
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

/* The largest reply a local handler may write. The same 512 as the remote
 * seam's FZN_NODE_REPLY_MAX, because the two answer the same question and a
 * consumer that has learned one bound should not have to learn a second. The
 * node's own status line is far shorter; this bounds what a CONSUMER says. */
#define FZN_NODE_LOCAL_REPLY_MAX 512u

/* A consumer's local handler -- the seam sec 5 has always pointed at.
 *
 * WHY IT EXISTS. `node/serve.h` gave the REMOTE access method `on_remote`,
 * "where a consumer's handler -- its verbs -- plugs in", and the local method
 * had no equivalent. It read a request line, bounded it, framed it and threw
 * it away: the body carried a literal `(void)line;`. So the one access method
 * whose peer the KERNEL has already named was the one with nowhere to put a
 * verb, and a consumer wanting `local/vocabulary.h`'s gid-to-verb bound --
 * raidcfgd's requirement, and the reason that module exists at all -- could
 * not reach it from the node.
 *
 * WHAT IT DOES NOT DO, which is the half sec 5 governs. The node still never
 * learns what a verb means. `request` is bytes with a length, exactly the
 * shape `fzn_vocabulary_admit` takes, and this library cannot tell `status`
 * from `destroy` and must not learn. The consumer's table is the consumer's.
 *
 * `verdict` and `origin` are what the node decided, so a handler refusing on
 * its own account need not re-derive them, and `peer` is the kernel's
 * credentials -- which is precisely what a vocabulary check needs.
 *
 * Return the bytes written into `reply`, or 0 to let the node answer with its
 * status line. A handler claiming more than `reply_cap` is treated as having
 * written nothing, on `fzn_node_status_line`'s principle: a reply that does
 * not fit is not truncated into a different reply.
 *
 * NOT CALLED ON A DENIAL, and that diverges from `on_remote` on purpose. The
 * remote loop calls its handler for any result that is not DROPPED, a denied
 * one included, and seals whatever comes back. Here a denial is the node's
 * whole answer; letting a handler write to a caller the node has just refused
 * would let a seam widen the decision it was given to observe. The cost is
 * that a handler cannot log its own denials, which is the cheaper of the two
 * -- the other direction costs a denial its meaning. */
typedef size_t (*fzn_node_local_handler_t)(void *ctx,
                                           fzn_authz_verdict_t verdict,
                                           fzn_origin_t origin,
                                           const fzn_peer_t *peer,
                                           const uint8_t *request,
                                           size_t request_len,
                                           char *reply, size_t reply_cap);

/* Serve one accepted local connection. `peer` is the credentials
 * fzn_socket_accept returned with `fd`. Reads one request line (under a
 * receive timeout so an idle client cannot wedge the caller), authorises the
 * peer's origin, hands the line to `on_local` when there is one and the
 * caller was not denied, and writes the reply -- the handler's if it wrote
 * one, the node's status line otherwise. `on_local` may be NULL, with `ctx`
 * then unused. OK and DENIED both wrote a response. */
fzn_node_serve_err_t fzn_node_serve_local(const fzn_node_config_t *config,
                                          int fd, const fzn_peer_t *peer,
                                          fzn_node_local_handler_t on_local,
                                          void *ctx);

#endif
