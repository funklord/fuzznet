/* fuzznet's own verbs, answered by a node about itself.
 *
 * `node/local.h` gives a node a local handler and `local/vocabulary.h` gives
 * fuzznet its verbs, and until this file no handler answered any of them: a
 * node with no consumer handler answered every line with its status, so
 * `add` and `status` got the same reply. This is the handler a node installs
 * when the verbs it serves are fuzznet's own. sec 378.
 *
 * WHAT IT SERVES:
 *
 *     status            the node's own status line (it returns 0, which is
 *                       how `node/local.h` asks the node to answer itself)
 *     add peer HEX      pair a device into the RUNNING node: `node/pair.h`,
 *                       then the live peer set is reloaded from the store,
 *                       and the answer is `ok FZN1:...`, the card
 *     remove peer KEY   un-pair one: the store forgets it and the live set
 *                       is reloaded, so its next frame finds no session
 *     list peer [FROM]  `ok TOTAL FROM KEY ...`, paged rather than cut
 *                       short, since sixty-four keys do not fit one line
 *     revoke peer KEY   revoke the grant this node gave KEY: `node/revoke.h`
 *                       issues the signed record, the running store takes
 *                       it, and it is saved. Any key, not only a current
 *                       peer -- a grant outlives the peer record it came
 *                       with. `ok KEY`, and `ok KEY already` when it was.
 *
 * Every other verb of fuzznet's, and any verb that is not, is answered
 * `unsupported` -- a node saying it does not serve a verb is a different fact
 * from its status, and answering status for `get` was a node saying "fine" to
 * a request it ignored.
 *
 * A MUTATING VERB NEEDS THE NODE'S OWN USER. `fzn_verb_mutates` answers it,
 * and a caller whose origin is not FZN_ORIGIN_SAME_USER -- a member of the
 * service group -- is answered `denied`. That is raidcfgd's rule, the reason
 * `local/vocabulary.h` exists: a group that may connect is not thereby a group
 * that may change the node. A deployment wanting group members to pair writes
 * its own handler with its own `fzn_verb_rule_t` table.
 *
 * THE STORE IS THE LIVE SET'S SOURCE. After pairing, the peers are reloaded
 * with `fzn_node_peers_load` rather than appended in memory, so what the node
 * serves is exactly what it would serve after a restart -- two ways to arrive
 * at one set would be two sets.
 */

#ifndef FZN_NODE_ADMIN_H
#define FZN_NODE_ADMIN_H

#include <stddef.h>
#include <stdint.h>

#include "local.h"
#include "pair.h"
#include "revoke.h"
#include "serve.h"

typedef struct fzn_node_admin {
	/* The running node. Its `peers` and `peer_count` are replaced after a
	 * pairing; its config supplies the root and the capability granted. */
	fzn_node_state_t *state;
	/* A writable view of the array `state->peers` points into, and its
	 * capacity. The state holds it as const, which is right for the loop
	 * that reads it and is why the one writer keeps its own handle. */
	fzn_node_peer_t *peers;
	size_t peers_cap;
	const fzn_node_identity_t *id;
	const fzn_persist_ops_t *store;
	/* How long a card stays worth accepting, from when it is made. */
	uint64_t card_lifetime;
	/* The running revocation store, the one `state->config.revocations`
	 * points at; NULL and `revoke` is unsupported. */
	fzn_revocation_store_t *revocations;
} fzn_node_admin_t;

/* A `fzn_node_local_handler_t`; `ctx` is a `fzn_node_admin_t`. */
size_t fzn_node_admin_handle(void *ctx, fzn_authz_verdict_t verdict, fzn_origin_t origin,
                             const fzn_peer_t *peer, const fzn_request_t *request,
                             char *reply, size_t reply_cap);

/*
 * The same verbs to a REMOTE caller, as `fzn_node_state_t.on_remote`; `ctx` is
 * a `fzn_node_admin_t`. sec 381.
 *
 * ONE GRAMMAR ON BOTH HOPS, because sec 2 has every node speak "the same
 * language" with "only minor role differences": a request payload is a line
 * of `local/vocabulary.h`'s grammar and the reply is a reply line, the same
 * bytes a local caller sends and reads. The minor difference is authority.
 *
 * A REMOTE CALLER MAY NOT CHANGE THE NODE. Its capability grants it the use of
 * this node; it does not make it the node's own user, and a mutating verb
 * that a group member is refused locally is not granted to a device over the
 * network. `status` and `list peer` are served; anything mutating is
 * `denied`, and anything else `unsupported`.
 *
 * A DENIED OR DROPPED CALLER GETS NOTHING. The node calls this for DENIED as
 * well as GRANTED (`node/serve.h`), and answering a caller the chain refused
 * would tell a stranger which node it reached; silence is the answer
 * `node/remote.h` already gives one whose frames never opened.
 */
size_t fzn_node_admin_remote(void *ctx, fzn_node_remote_result_t result,
                             const fzn_opened_t *req, uint8_t *reply, size_t reply_cap);

#endif /* FZN_NODE_ADMIN_H */
