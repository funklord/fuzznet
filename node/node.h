/* The node's access core: who a caller is, and whether they may be served.
 *
 * This is fuzznetd's heart and it is transport-free and crypto-free, the way
 * `local/peer.h` is: everything here is decided from a `fzn_peer_t` a caller
 * filled or an origin a caller determined, so all three access methods are
 * testable without a socket, a datagram or a key. The IO that feeds it lives
 * beside it -- `node/local.c` for the two credentialled hops over
 * `local/socket.h`, `node/remote.c` for the sealed hop over `net/udp.h` -- and
 * the daemon that runs the loop is `fuzznetd`.
 *
 * THE THREE ACCESS METHODS, which are three ways of AUTHENTICATING and one way
 * of AUTHORISING:
 *
 *   - SAME_USER: the caller is the node's own user, established by the uid the
 *     kernel put on the local socket. The per-user node of sec 128.
 *   - LOCAL: the caller is a member of the node's service group, established
 *     by the supplementary groups `local/peer.h` reads. The group-gated root
 *     daemon of sec 2, hop 2.
 *   - REMOTE: the caller presented a capability that chains to the node's
 *     pinned root, established by `fzn_authz_decide`. Hop 3.
 *
 * The local two are authenticated by the KERNEL before a byte is parsed, so
 * they are served unguarded -- admitted for being who they are, carrying no
 * capability. The remote one is authenticated by the CAPABILITY, because the
 * kernel vouches for nobody across the network. That split is netcfgd's
 * decision 0128, and `fzn_authz_decide` enforces the origin before the
 * capability so a policy meant locally cannot reach the wire.
 */

#ifndef FZN_NODE_H
#define FZN_NODE_H

#include <stdint.h>

#include "../local/peer.h"
#include "../chain/authz.h"

typedef struct fzn_node_config {
	/* The node's own uid. A caller whose uid matches is SAME_USER. */
	uint32_t uid;
	/* The group a LOCAL caller must belong to, read only when
	 * has_service_gid is set. */
	uint32_t service_gid;
	int has_service_gid;
	/* Which local origins this node serves, an origin bit mask
	 * (FZN_ORIGIN_BIT). A per-user node serves SAME_USER; a
	 * group-serving one adds LOCAL. A caller whose origin is not in
	 * the mask is denied even though the kernel authenticated it. */
	unsigned local_origins;
	/* Whether this node answers the remote hop, and the capability it
	 * requires there. Local callers carry no capability; a remote
	 * caller carries one that must chain to `root`. */
	int serves_remote;
	fzn_cap_id_t remote_capability;
	uint8_t root[FZN_PUBKEY_LEN];
	/* THE REVOCATIONS A REMOTE CALLER'S CHAIN IS CHECKED AGAINST, or NULL
	 * for none. Beside `root` because the two are one question -- which
	 * grants does this node's trust still honour -- and until sec 380 the
	 * remote path passed NULL, so a revoked grant was honoured for as long
	 * as its peer record stood. Borrowed; it must outlive the config. */
	const fzn_revocation_store_t *revocations;
} fzn_node_config_t;

/* How serving one caller ended. OK and DENIED both mean a response was
 * written: the node authenticated and authorised the caller and answered,
 * and they differ only in the answer. The negatives mean no response was
 * written. */
typedef enum fzn_node_serve_err {
	FZN_NODE_SERVE_OK = 0,
	FZN_NODE_SERVE_DENIED = 1,
	FZN_NODE_SERVE_MALFORMED = -1,
	FZN_NODE_SERVE_IO = -2
} fzn_node_serve_err_t;

/* The access method a LOCAL peer arrived by, from its credentials alone:
 * SAME_USER if it is the node's own user, LOCAL if it is a member of the
 * service group, NONE otherwise -- including when the group list could not be
 * established, since an unknown list denies rather than guesses. REMOTE is
 * never returned here: a remote caller does not arrive on a credentialled
 * socket. uid is checked first, so the node's own user is SAME_USER even when
 * it is also in the service group. */
fzn_origin_t fzn_node_local_origin(const fzn_node_config_t *config,
                                   const fzn_peer_t *peer);

/* Whether a caller of `origin` may be served. A local origin the node serves
 * is granted unguarded, having been authenticated by the kernel; one it does
 * not serve is denied. A REMOTE caller must present a capability chaining to
 * the node's root: `hops`, `now`, `sign`, `revocations` and `manifest` go
 * straight to fzn_authz_decide, and are unused for the local origins. */
fzn_authz_verdict_t fzn_node_decide(const fzn_node_config_t *config,
                                    fzn_origin_t origin,
                                    const fzn_chain_hop_t *hops, size_t hop_count,
                                    uint64_t now, const fzn_sign_ops_t *sign,
                                    const fzn_revocation_store_t *revocations,
                                    const fzn_manifest_state_t *manifest);

#endif
