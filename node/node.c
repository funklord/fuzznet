/* See node.h. */

#include "node.h"

#include <string.h>

fzn_origin_t fzn_node_local_origin(const fzn_node_config_t *config,
                                   const fzn_peer_t *peer)
{
	if (!config || !peer)
		return FZN_ORIGIN_NONE;
	/* The node's own user first, so being also in the service group does
	 * not demote SAME_USER to LOCAL. */
	if (peer->uid == config->uid)
		return FZN_ORIGIN_SAME_USER;
	if (config->has_service_gid &&
	    fzn_peer_group_verdict(peer, config->service_gid) == FZN_PEER_MEMBER)
		return FZN_ORIGIN_LOCAL;
	return FZN_ORIGIN_NONE;
}

fzn_authz_verdict_t fzn_node_decide(const fzn_node_config_t *config,
                                    fzn_origin_t origin,
                                    const fzn_chain_hop_t *hops, size_t hop_count,
                                    uint64_t now, const fzn_sign_ops_t *sign,
                                    const fzn_revocation_store_t *revocations,
                                    const fzn_manifest_state_t *manifest)
{
	fzn_authz_policy_t policy;

	if (!config)
		return FZN_AUTHZ_DENIED;

	if (origin == FZN_ORIGIN_SAME_USER || origin == FZN_ORIGIN_LOCAL) {
		/* Kernel-authenticated: granted unguarded if the node serves
		 * this local origin, denied otherwise. No chain is consulted,
		 * so sign, root and hops may all be absent. */
		policy = fzn_authz_unguarded(config->local_origins);
		return fzn_authz_decide(policy, origin, NULL, 0, config->root,
		                        now, sign, revocations, manifest);
	}

	if (origin == FZN_ORIGIN_REMOTE && config->serves_remote) {
		policy = fzn_authz_requires(&config->remote_capability,
		                           FZN_ORIGIN_BIT(FZN_ORIGIN_REMOTE));
		return fzn_authz_decide(policy, origin, hops, hop_count,
		                        config->root, now, sign, revocations,
		                        manifest);
	}

	/* NONE, or a remote caller this node does not serve. Deny through a
	 * policy that reaches nothing rather than inventing a verdict. */
	policy = fzn_authz_unguarded(0);
	return fzn_authz_decide(policy, origin, NULL, 0, config->root,
	                        now, sign, revocations, manifest);
}

int fzn_node_request_shared(const fzn_node_config_t *config, const uint8_t *capability)
{
	return config && capability && config->has_share
	       && memcmp(capability, config->share_capability.b, FZN_CAP_ID_LEN) == 0;
}

fzn_authz_verdict_t fzn_node_decide_share(const fzn_node_config_t *config,
                                          const fzn_chain_hop_t *hops, size_t hop_count,
                                          uint64_t now, const fzn_sign_ops_t *sign,
                                          const fzn_revocation_store_t *revocations)
{
	fzn_authz_policy_t policy;
	fzn_revocation_store_t own;

	if (!config || !config->has_share || !config->serves_remote)
		return FZN_AUTHZ_DENIED;
	policy = fzn_authz_requires(&config->share_capability, FZN_ORIGIN_BIT(FZN_ORIGIN_REMOTE));
	/* A SHARE CHAIN STARTS AT THIS NODE'S OWN KEY, sec 436, and the
	 * estate's root set (sec 406) names the estate's roots: with it, the
	 * chain verifier takes the set as the anchor and refuses every chain a
	 * member granted -- WRONG_ROOT, measured in sec 614 on a member that is
	 * no root. So the set is left out and `share_root` anchors the chain;
	 * the store's revocations of hops still apply. */
	if (revocations && revocations->roots) {
		own = *revocations;
		own.roots = NULL;
		revocations = &own;
	}
	return fzn_authz_decide(policy, FZN_ORIGIN_REMOTE, hops, hop_count, config->share_root,
	                        now, sign, revocations, NULL);
}
