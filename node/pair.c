/* See pair.h. */

#include "pair.h"

#include "peer_persist.h"
#include "../constant_time/constant_time.h"

#include <string.h>

const char *fzn_node_pair_err_str(fzn_node_pair_err_t err)
{
	switch (err) {
	case FZN_NODE_PAIR_OK:
		return "ok";
	case FZN_NODE_PAIR_MALFORMED:
		return "malformed";
	case FZN_NODE_PAIR_NOT_ROOT:
		return "this node is not its own root, so its grants would not chain";
	case FZN_NODE_PAIR_DEVICE:
		return "the device's prekey did not verify or no session would establish";
	case FZN_NODE_PAIR_STORE:
		return "the store refused the paired device";
	case FZN_NODE_PAIR_CARD:
		return "the device is saved and its card could not be made";
	}
	return "unknown";
}

fzn_node_pair_err_t fzn_node_pair(const fzn_node_identity_t *id,
                                  const uint8_t root[FZN_PUBKEY_LEN],
                                  const fzn_cap_id_t *cap, const fzn_persist_ops_t *store,
                                  fzn_prekey_record_t device, uint64_t now,
                                  uint64_t card_expires_at, uint8_t *card, size_t card_cap,
                                  size_t *card_len)
{
	fzn_node_peer_t peer;

	if (!id || !root || !cap || !store || !store->save || !device.bytes || !card
	    || !card_len)
		return FZN_NODE_PAIR_MALFORMED;
	*card_len = 0;

	/* CHECKED BEFORE ANYTHING IS DERIVED. `fzn_node_make_card` mints with
	 * this node's key as root; if that is not the root the node verifies
	 * against, the device would pair and then be refused on its first
	 * request, which is the failure that looks like the network. */
	if (memcmp(root, id->pubkey, FZN_PUBKEY_LEN) != 0)
		return FZN_NODE_PAIR_NOT_ROOT;

	memset(&peer, 0, sizeof(peer));
	if (fzn_node_provision_peer(id, device, cap, now, FZN_NO_EXPIRY, now, &peer)
	    != FZN_NODE_PROVISION_OK)
		return FZN_NODE_PAIR_DEVICE;

	/* SAVED BEFORE THE CARD IS MADE, so no card ever exists for a device
	 * the node does not hold. The other order would hand out a card and
	 * then, on a full disk, forget the device -- a pairing that works on
	 * the device's side and nowhere else. `peer` holds the session keys, so
	 * it is wiped rather than cleared on both paths. */
	if (fzn_node_peer_save(store, &peer) != FZN_PERSIST_OK) {
		fzn_wipe(&peer, sizeof(peer));
		return FZN_NODE_PAIR_STORE;
	}
	fzn_wipe(&peer, sizeof(peer));

	if (fzn_node_make_card(id, device.host, cap, now, FZN_NO_EXPIRY, card_expires_at, card,
	                       card_cap, card_len)
	    != FZN_NODE_PROVISION_OK) {
		*card_len = 0;
		return FZN_NODE_PAIR_CARD;
	}
	return FZN_NODE_PAIR_OK;
}
