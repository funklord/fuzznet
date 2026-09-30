/* See provision.h. */

#include "provision.h"

#include <string.h>

#include "../chain/chain.h"
#include "../chain/root_log.h"
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
	return fzn_node_card_pack(id, id->pubkey, (const uint8_t (*)[FZN_HOP_LEN])hop_bytes, 1u,
	                          card_expires_at, out, cap_bytes, out_len);
}

fzn_node_provision_err_t fzn_node_card_pack(const fzn_node_identity_t *id,
                                            const uint8_t root[FZN_PUBKEY_LEN],
                                            const uint8_t (*chain)[FZN_HOP_LEN],
                                            size_t hop_count, uint64_t card_expires_at,
                                            uint8_t *out, size_t cap_bytes, size_t *out_len)
{
	if (!id || !root || !chain || !out || !out_len)
		return FZN_NODE_PROVISION_MALFORMED;
	/* The card carries the estate's root, the chain to the device, and this
	 * node's prekey so the device can agree a session with it -- sealed by
	 * this node, its sponsor. */
	if (fzn_provision_pack(root, chain, hop_count, NULL, 0, id->prekey_record, card_expires_at,
	                       id->sign, out, cap_bytes, out_len)
	    != FZN_PROVISION_OK)
		return FZN_NODE_PROVISION_CARD;
	return FZN_NODE_PROVISION_OK;
}

fzn_node_provision_err_t fzn_node_accept_card(const fzn_node_identity_t *device,
                                              const uint8_t *card_bytes,
                                              size_t card_len, uint64_t now,
                                              uint8_t send_key[FZN_AEAD_KEY_LEN],
                                              uint8_t send_ckey[FZN_COMMITMENT_KEY_LEN],
                                              uint8_t node_out[FZN_PUBKEY_LEN],
                                              fzn_chain_hop_t *hop_out)
{
	fzn_provision_card_t card;
	fzn_prekey_record_t node_prekey;
	fzn_prekey_peer_t pinned;
	fzn_chain_hop_t hops[FZN_CHAIN_MAX_HOPS];
	fzn_cap_id_t granted;
	fzn_chain_t chain;
	const uint8_t *chain_root;
	size_t i;

	if (!device || !device->agree_secret || !card_bytes || !send_key ||
	    !send_ckey || !node_out)
		return FZN_NODE_PROVISION_MALFORMED;

	/* Open the card and verify it binds one sponsor to a chain from the
	 * root it names (`fzn_provision_verify`). */
	if (fzn_provision_open(card_bytes, card_len, &card) != FZN_PROVISION_OK)
		return FZN_NODE_PROVISION_CARD;
	if (fzn_provision_verify(card, device->sign, now) != FZN_PROVISION_OK)
		return FZN_NODE_PROVISION_CARD;

	/* THE GRANT MUST BE THIS DEVICE'S, which nothing here checked. The
	 * envelope proves the card is whole and signed by the root it names --
	 * any card proves that about itself -- and says nothing about whom it
	 * was made for. A device handed another device's card accepted it,
	 * derived a session the node has no peer for, and failed on its first
	 * request in a way that looks like the network. So the WHOLE chain is
	 * verified under the card's root, for the capability it carries, and
	 * its last grantee must be this device. Checked before anything is
	 * pinned or derived. sec 377, and the whole chain since sec 391. */
	for (i = 0; i < card.hop_count; i++)
		if (fzn_hop_open(card.chain + i * FZN_HOP_LEN, FZN_HOP_LEN, &hops[i])
		    != FZN_CHAIN_OK)
			return FZN_NODE_PROVISION_CARD;
	memcpy(granted.b, card.hop + FZN_HOP_OFF_CAPABILITY, FZN_CAP_ID_LEN);
	/* A CHAIN FROM ANOTHER ROOT starts where the card's proof ends: the
	 * subject of its last root-add, which `fzn_provision_verify` has walked
	 * from the estate's root and matched to the first hop's grantor (sec
	 * 410). The chain is verified under that root, and nothing else is. */
	chain_root = card.root;
	if (card.proof_count)
		chain_root = card.proof + (card.proof_count - 1u) * FZN_PROVISION_PROOF_ITEM_LEN
		             + FZN_ROOT_SET_OFF_SUBJECT;
	if (fzn_chain_verify(hops, card.hop_count, chain_root, &granted, now, device->sign, NULL,
	                     NULL, &chain) != FZN_CHAIN_OK
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

	/* The session this device seals to the SPONSOR with -- the node that
	 * granted the last hop and whose prekey this is, not the estate's root,
	 * which may be offline. The same key the node derived on its side, by
	 * X25519 symmetry. */
	if (fzn_session_establish(device->agree_secret, device->agree, device->hash,
	                          device->pubkey, node_prekey.host, pinned.prekey, send_key,
	                          send_ckey) != FZN_SESSION_OK)
		return FZN_NODE_PROVISION_SESSION;

	memcpy(node_out, node_prekey.host, FZN_PUBKEY_LEN);
	if (hop_out &&
	    fzn_hop_open(card.hop, FZN_HOP_LEN, hop_out) != FZN_CHAIN_OK)
		return FZN_NODE_PROVISION_MINT;
	return FZN_NODE_PROVISION_OK;
}
