/* See provision.h. */

#include "provision.h"

#include <string.h>

#include "../chain/chain.h"
#include "../provision/provision.h"

fzn_node_provision_err_t fzn_node_provision_peer(const fzn_node_identity_t *id,
                                                 fzn_prekey_record_t device_prekey,
                                                 const fzn_cap_id_t *cap,
                                                 uint64_t issued_at,
                                                 uint64_t expires_at, uint64_t now,
                                                 fzn_node_peer_t *out)
{
	fzn_prekey_peer_t pinned;
	uint8_t recv_key[FZN_AEAD_KEY_LEN];
	uint8_t recv_ckey[FZN_COMMITMENT_KEY_LEN];
	uint8_t hop_bytes[FZN_HOP_LEN];

	if (!id || !id->agree_secret || !cap || !out)
		return FZN_NODE_PROVISION_MALFORMED;

	/* The prekey proves the device's authorship of its own X25519 key. */
	fzn_prekey_peer_init(&pinned);
	if (fzn_prekey_pin(&pinned, device_prekey, id->sign, FZN_TRUST_PINNED, now)
	    != FZN_PREKEY_OK)
		return FZN_NODE_PROVISION_UNTRUSTED;

	/* The session that opens this device's frames. */
	if (fzn_session_establish(id->agree_secret, id->agree, id->hash, id->pubkey,
	                          device_prekey.host, pinned.prekey, recv_key,
	                          recv_ckey) != FZN_SESSION_OK)
		return FZN_NODE_PROVISION_SESSION;

	/* The capability, minted with this node as root and the device as
	 * grantee. */
	if (fzn_chain_mint(id->pubkey, device_prekey.host, cap, issued_at,
	                   expires_at, 0, id->sign, hop_bytes) != FZN_CHAIN_OK)
		return FZN_NODE_PROVISION_MINT;

	memset(out, 0, sizeof(*out));
	memcpy(out->sender, device_prekey.host, FZN_PUBKEY_LEN);
	memcpy(out->recv_key, recv_key, FZN_AEAD_KEY_LEN);
	memcpy(out->recv_ckey, recv_ckey, FZN_COMMITMENT_KEY_LEN);
	memcpy(out->hop_bytes[0], hop_bytes, FZN_HOP_LEN);
	out->hop_count = 1u;
	return FZN_NODE_PROVISION_OK;
}

fzn_node_provision_err_t fzn_node_make_card(const fzn_node_identity_t *id,
                                            const uint8_t device[FZN_PUBKEY_LEN],
                                            const fzn_cap_id_t *cap,
                                            uint64_t issued_at, uint64_t expires_at,
                                            uint64_t card_expires_at, uint8_t *out,
                                            size_t cap_bytes, size_t *out_len)
{
	uint8_t hop_bytes[FZN_HOP_LEN];

	if (!id || !device || !cap || !out || !out_len)
		return FZN_NODE_PROVISION_MALFORMED;

	if (fzn_chain_mint(id->pubkey, device, cap, issued_at, expires_at, 0,
	                   id->sign, hop_bytes) != FZN_CHAIN_OK)
		return FZN_NODE_PROVISION_MINT;

	/* The card carries the node's root, the device's capability hop, and
	 * the node's prekey so the device can agree a session with it. */
	if (fzn_provision_pack(id->pubkey, hop_bytes, id->prekey_record,
	                       card_expires_at, id->sign, out, cap_bytes, out_len)
	    != FZN_PROVISION_OK)
		return FZN_NODE_PROVISION_CARD;
	return FZN_NODE_PROVISION_OK;
}

fzn_node_provision_err_t fzn_node_accept_card(const fzn_node_identity_t *device,
                                              const uint8_t *card_bytes,
                                              size_t card_len, uint64_t now,
                                              uint8_t send_key[FZN_AEAD_KEY_LEN],
                                              uint8_t send_ckey[FZN_COMMITMENT_KEY_LEN],
                                              uint8_t root_out[FZN_PUBKEY_LEN],
                                              fzn_chain_hop_t *hop_out)
{
	fzn_provision_card_t card;
	fzn_prekey_record_t node_prekey;
	fzn_prekey_peer_t pinned;
	fzn_chain_hop_t hop;
	fzn_cap_id_t granted;
	fzn_chain_t chain;

	if (!device || !device->agree_secret || !card_bytes || !send_key ||
	    !send_ckey || !root_out)
		return FZN_NODE_PROVISION_MALFORMED;

	/* Open the card and verify its envelope under the root it names. */
	if (fzn_provision_open(card_bytes, card_len, &card) != FZN_PROVISION_OK)
		return FZN_NODE_PROVISION_CARD;
	if (fzn_provision_verify(card, device->sign, now) != FZN_PROVISION_OK)
		return FZN_NODE_PROVISION_CARD;

	/* THE GRANT MUST BE THIS DEVICE'S, which nothing here checked. The
	 * envelope proves the card is whole and signed by the root it names --
	 * any card proves that about itself -- and says nothing about whom it
	 * was made for. A device handed another device's card accepted it,
	 * derived a session the node has no peer for, and failed on its first
	 * request in a way that looks like the network. So the hop is verified
	 * under the card's root, for the capability it carries, and its grantee
	 * must be this device. Checked before anything is pinned or derived.
	 * sec 377. */
	if (fzn_hop_open(card.hop, FZN_HOP_LEN, &hop) != FZN_CHAIN_OK)
		return FZN_NODE_PROVISION_CARD;
	memcpy(granted.b, card.hop + FZN_HOP_OFF_CAPABILITY, FZN_CAP_ID_LEN);
	if (fzn_chain_verify(&hop, 1, card.root, &granted, now, device->sign, NULL, NULL,
	                     &chain) != FZN_CHAIN_OK
	    || memcmp(chain.grantee, device->pubkey, FZN_PUBKEY_LEN) != 0)
		return FZN_NODE_PROVISION_NOT_MINE;

	/* Pin the node's prekey the card carried, proving its authorship. */
	if (fzn_prekey_open(card.prekey, FZN_PREKEY_LEN_TOTAL, &node_prekey)
	    != FZN_PREKEY_OK)
		return FZN_NODE_PROVISION_CARD;
	fzn_prekey_peer_init(&pinned);
	if (fzn_prekey_pin(&pinned, node_prekey, device->sign, FZN_TRUST_PINNED,
	                   now) != FZN_PREKEY_OK)
		return FZN_NODE_PROVISION_UNTRUSTED;

	/* The session this device seals to the node with -- the same key the
	 * node derived on its side, by X25519 symmetry. */
	if (fzn_session_establish(device->agree_secret, device->agree, device->hash,
	                          device->pubkey, card.root, pinned.prekey, send_key,
	                          send_ckey) != FZN_SESSION_OK)
		return FZN_NODE_PROVISION_SESSION;

	memcpy(root_out, card.root, FZN_PUBKEY_LEN);
	if (hop_out &&
	    fzn_hop_open(card.hop, FZN_HOP_LEN, hop_out) != FZN_CHAIN_OK)
		return FZN_NODE_PROVISION_MINT;
	return FZN_NODE_PROVISION_OK;
}
