/* See pair.h. */

#include "pair.h"

#include "peer_persist.h"
#include "../constant_time/constant_time.h"

#include "../provision/provision.h"

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
	case FZN_NODE_PAIR_REFUSED:
		return "the card did not verify, was made for another device, or gave no session";
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

/* ---- the device's side ------------------------------------------------ */

fzn_node_pair_err_t fzn_node_pairing_accept(const fzn_node_identity_t *device,
                                            const uint8_t *card, size_t card_len,
                                            uint64_t now, const fzn_persist_ops_t *store,
                                            fzn_node_pairing_t *out)
{
	fzn_node_pairing_t p;
	fzn_provision_card_t opened;
	uint8_t blob[FZN_NODE_PAIRING_BLOB_LEN];
	size_t len = 0;
	int saved;

	if (!device || !card || !store || !store->save || !out)
		return FZN_NODE_PAIR_MALFORMED;
	memset(&p, 0, sizeof(p));

	/* `fzn_node_accept_card` verifies the envelope, that the grant inside
	 * is THIS device's (sec 377), pins the node's prekey and derives the
	 * session. The hop and capability are then read from the same bytes
	 * it verified, not decoded a second time from a copy. */
	if (fzn_node_accept_card(device, card, card_len, now, p.send_key, p.send_ckey, p.root,
	                         NULL) != FZN_NODE_PROVISION_OK
	    || fzn_provision_open(card, card_len, &opened) != FZN_PROVISION_OK) {
		fzn_wipe(&p, sizeof(p));
		return FZN_NODE_PAIR_REFUSED;
	}
	memcpy(p.hop, opened.hop, FZN_HOP_LEN);
	memcpy(p.capability.b, opened.hop + FZN_HOP_OFF_CAPABILITY, FZN_CAP_ID_LEN);

	if (fzn_node_pairing_pack(&p, blob, sizeof(blob), &len) != FZN_PERSIST_OK) {
		fzn_wipe(&p, sizeof(p));
		return FZN_NODE_PAIR_MALFORMED;
	}
	saved = store->save(store->ctx, FZN_PERSIST_PAIRED_NODE, p.root, blob, len);
	fzn_wipe(blob, sizeof(blob));
	if (!saved) {
		fzn_wipe(&p, sizeof(p));
		return FZN_NODE_PAIR_STORE;
	}
	*out = p;
	fzn_wipe(&p, sizeof(p));
	return FZN_NODE_PAIR_OK;
}

/* root | capability | send_key | send_ckey | hop, fixed, after the shared
 * head. The session keys are in the clear for the reason `persist.h` gives
 * for every secret it stores: what protects them is the backend. */
#define OFF_ROOT ((size_t)FZN_PERSIST_HEAD_LEN)
#define OFF_CAP (OFF_ROOT + FZN_PUBKEY_LEN)
#define OFF_KEY (OFF_CAP + FZN_CAP_ID_LEN)
#define OFF_CKEY (OFF_KEY + FZN_AEAD_KEY_LEN)
#define OFF_HOP (OFF_CKEY + FZN_COMMITMENT_KEY_LEN)

_Static_assert(OFF_HOP + FZN_HOP_LEN == FZN_NODE_PAIRING_BLOB_LEN,
               "the pairing blob's offsets do not add up to its length");

fzn_persist_err_t fzn_node_pairing_pack(const fzn_node_pairing_t *pairing, uint8_t *out,
                                        size_t cap, size_t *len)
{
	fzn_persist_err_t err;

	if (!pairing || !out || !len)
		return FZN_PERSIST_ERR_MALFORMED;
	err = fzn_persist_head_write(out, cap, FZN_NODE_PAIRING_BODY_LEN,
	                             FZN_PERSIST_BLOB_PAIRING);
	if (err != FZN_PERSIST_OK)
		return err;
	memcpy(out + OFF_ROOT, pairing->root, FZN_PUBKEY_LEN);
	memcpy(out + OFF_CAP, pairing->capability.b, FZN_CAP_ID_LEN);
	memcpy(out + OFF_KEY, pairing->send_key, FZN_AEAD_KEY_LEN);
	memcpy(out + OFF_CKEY, pairing->send_ckey, FZN_COMMITMENT_KEY_LEN);
	memcpy(out + OFF_HOP, pairing->hop, FZN_HOP_LEN);
	*len = FZN_NODE_PAIRING_BLOB_LEN;
	return FZN_PERSIST_OK;
}

fzn_persist_err_t fzn_node_pairing_open(const uint8_t *bytes, size_t len,
                                        fzn_node_pairing_t *out)
{
	fzn_persist_err_t err;
	fzn_chain_hop_t hop;

	if (!bytes || !out)
		return FZN_PERSIST_ERR_MALFORMED;
	err = fzn_persist_head_check(bytes, len, FZN_NODE_PAIRING_BODY_LEN,
	                             FZN_PERSIST_BLOB_PAIRING);
	if (err != FZN_PERSIST_OK)
		return err;
	/* THE HOP MUST BE A HOP, AND ITS CAPABILITY THE ONE STORED BESIDE IT.
	 * Two copies of one fact in one blob is a second encoding unless they
	 * are required to agree -- `persist.c`'s head check refuses a trailing
	 * byte for the same reason. */
	if (fzn_hop_open(bytes + OFF_HOP, FZN_HOP_LEN, &hop) != FZN_CHAIN_OK
	    || memcmp(bytes + OFF_HOP + FZN_HOP_OFF_CAPABILITY, bytes + OFF_CAP, FZN_CAP_ID_LEN)
	               != 0)
		return FZN_PERSIST_ERR_SHAPE;
	memcpy(out->root, bytes + OFF_ROOT, FZN_PUBKEY_LEN);
	memcpy(out->capability.b, bytes + OFF_CAP, FZN_CAP_ID_LEN);
	memcpy(out->send_key, bytes + OFF_KEY, FZN_AEAD_KEY_LEN);
	memcpy(out->send_ckey, bytes + OFF_CKEY, FZN_COMMITMENT_KEY_LEN);
	memcpy(out->hop, bytes + OFF_HOP, FZN_HOP_LEN);
	return FZN_PERSIST_OK;
}

fzn_persist_err_t fzn_node_pairing_load(const fzn_persist_ops_t *store,
                                        const uint8_t root[FZN_PUBKEY_LEN],
                                        fzn_node_pairing_t *out)
{
	uint8_t blob[FZN_NODE_PAIRING_BLOB_LEN];
	fzn_node_pairing_t p;
	fzn_persist_err_t err;
	size_t len = 0;

	if (!store || !store->load || !root || !out)
		return FZN_PERSIST_ERR_MALFORMED;
	if (!store->load(store->ctx, FZN_PERSIST_PAIRED_NODE, root, blob, sizeof(blob), &len))
		return FZN_PERSIST_ERR_BACKEND;
	err = fzn_node_pairing_open(blob, len, &p);
	fzn_wipe(blob, sizeof(blob));
	if (err != FZN_PERSIST_OK)
		return err;
	/* FILED UNDER ONE NODE AND NAMING ANOTHER is a corrupt store or a
	 * placed file, and sealing to it would send this device's requests
	 * under keys meant for somebody else -- the check `fzn_node_peers_load`
	 * makes for the node's view, made here for the device's. */
	if (memcmp(p.root, root, FZN_PUBKEY_LEN) != 0) {
		fzn_wipe(&p, sizeof(p));
		return FZN_PERSIST_ERR_SHAPE;
	}
	*out = p;
	fzn_wipe(&p, sizeof(p));
	return FZN_PERSIST_OK;
}

void fzn_node_pairing_caller(const fzn_node_pairing_t *pairing,
                             const uint8_t self[FZN_PUBKEY_LEN], fzn_caller_t *caller)
{
	if (!pairing || !self || !caller)
		return;
	memcpy(caller->sender, self, FZN_PUBKEY_LEN);
	caller->capability = pairing->capability;
	memcpy(caller->send_key, pairing->send_key, FZN_AEAD_KEY_LEN);
	memcpy(caller->send_ckey, pairing->send_ckey, FZN_COMMITMENT_KEY_LEN);
}
