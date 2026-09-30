/* See pair.h. */

#include "pair.h"

#include "peer_persist.h"
#include "roots.h"
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
	case FZN_NODE_PAIR_CANNOT_JOIN:
		return "the grant cannot be passed on, or this node belongs to an estate already";
	}
	return "unknown";
}

fzn_node_pair_err_t fzn_node_pair(const fzn_node_identity_t *id,
                                  const uint8_t root[FZN_PUBKEY_LEN],
                                  const fzn_cap_id_t *cap,
                                  const fzn_node_authority_t *authority, int delegable,
                                  const fzn_persist_ops_t *store,
                                  fzn_prekey_record_t device, uint64_t now,
                                  uint64_t card_expires_at, uint8_t *card, size_t card_cap,
                                  size_t *card_len)
{
	fzn_node_peer_t peer;
	uint8_t hop[FZN_HOP_LEN];
	uint8_t chain[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	uint64_t expires_at = FZN_NO_EXPIRY;
	size_t own = authority ? authority->hop_count : 0u;
	size_t i;

	if (!id || !root || !cap || !store || !store->save || !device.bytes || !card
	    || !card_len || (authority && (!authority->hops || authority->hop_count == 0u)))
		return FZN_NODE_PAIR_MALFORMED;
	if (authority && authority->proof_count && !authority->proof)
		return FZN_NODE_PAIR_MALFORMED;
	*card_len = 0;

	/* CHECKED BEFORE ANYTHING IS DERIVED. A node that is not the root
	 * grants only through a chain from the root that it may pass on;
	 * otherwise the device would pair and then be refused on its first
	 * request, which is the failure that looks like the network. */
	if (!authority) {
		if (memcmp(root, id->pubkey, FZN_PUBKEY_LEN) != 0)
			return FZN_NODE_PAIR_NOT_ROOT;
	} else {
		fzn_chain_hop_t views[FZN_CHAIN_MAX_HOPS];
		fzn_chain_t verdict;
		const uint8_t *from = NULL;

		if (own + 1u > FZN_CHAIN_MAX_HOPS)
			return FZN_NODE_PAIR_NOT_ROOT;
		/* THE ROOT THE CHAIN STARTS AT: the estate's, or the one the proof
		 * reaches from it -- walked as the device will walk it, so no
		 * card is made that the device would refuse. */
		if (fzn_provision_proof_end(root, (const uint8_t *)authority->proof,
		                            authority->proof_count, id->sign, &from)
		    != FZN_PROVISION_OK)
			return FZN_NODE_PAIR_NOT_ROOT;
		for (i = 0; i < own; i++)
			if (fzn_hop_open(authority->hops[i], FZN_HOP_LEN, &views[i]) != FZN_CHAIN_OK)
				return FZN_NODE_PAIR_NOT_ROOT;
		if (fzn_chain_verify(views, own, from, cap, now, id->sign, NULL, NULL, &verdict)
		            != FZN_CHAIN_OK
		    || memcmp(verdict.grantee, id->pubkey, FZN_PUBKEY_LEN) != 0
		    || !fzn_hop_delegable(views[own - 1u]))
			return FZN_NODE_PAIR_NOT_ROOT;
		/* A GRANT CANNOT OUTLIVE THE ONE IT CAME FROM. */
		expires_at = verdict.expires_at;
	}

	/* THE SESSION, from the device's prekey. `fzn_node_provision_peer`
	 * also mints a hop, which is replaced below: the node mints the one
	 * it grants itself, with the delegable bit and the expiry its own
	 * chain allows. */
	memset(&peer, 0, sizeof(peer));
	if (fzn_node_provision_peer(id, device, cap, now, FZN_NO_EXPIRY, now, &peer)
	    != FZN_NODE_PROVISION_OK)
		return FZN_NODE_PAIR_DEVICE;
	if (fzn_chain_mint(id->pubkey, device.host, cap, now, expires_at, delegable ? 1 : 0,
	                   id->sign, hop)
	    != FZN_CHAIN_OK) {
		fzn_wipe(&peer, sizeof(peer));
		return FZN_NODE_PAIR_DEVICE;
	}
	/* THE WHOLE CHAIN ON THE NODE'S SIDE: root to this node, then this node
	 * to the device -- what the node's own decision, against the root it
	 * pinned, has to verify. */
	for (i = 0; i < own; i++) {
		memcpy(peer.hop_bytes[i], authority->hops[i], FZN_HOP_LEN);
		memcpy(chain[i], authority->hops[i], FZN_HOP_LEN);
	}
	memcpy(peer.hop_bytes[own], hop, FZN_HOP_LEN);
	memcpy(chain[own], hop, FZN_HOP_LEN);
	peer.hop_count = own + 1u;

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

	/* THE CARD CARRIES THE SAME CHAIN, so the device -- or a node joining
	 * through this one -- can check it back to the root it pins (sec 391). */
	if (fzn_node_card_pack(id, root, (const uint8_t (*)[FZN_HOP_LEN])chain, own + 1u,
	                       authority ? authority->proof : NULL,
	                       authority ? authority->proof_count : 0u, card_expires_at, card,
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
	uint8_t blob[FZN_NODE_PAIRING_BLOB_MAX];
	size_t len = 0, i;
	int saved;

	if (!device || !card || !store || !store->save || !out)
		return FZN_NODE_PAIR_MALFORMED;
	memset(&p, 0, sizeof(p));

	/* `fzn_node_accept_card` verifies the envelope, that the grant inside
	 * is THIS device's (sec 377), pins the node's prekey and derives the
	 * session. The chain and capability are then read from the same bytes
	 * it verified, not decoded a second time from a copy. */
	if (fzn_node_accept_card(device, card, card_len, now, p.send_key, p.send_ckey, p.node,
	                         NULL) != FZN_NODE_PROVISION_OK
	    || fzn_provision_open(card, card_len, &opened) != FZN_PROVISION_OK) {
		fzn_wipe(&p, sizeof(p));
		return FZN_NODE_PAIR_REFUSED;
	}
	/* THE PROOF IS SAVED BEFORE THE PAIRING, so a pairing never outlives
	 * the root-adds its chain depends on: a node that loads the pairing and
	 * not the root its chain starts at would refuse its own grant. */
	for (i = 0; i < opened.proof_count; i++)
		if (fzn_node_roots_save(store, device->hash,
		                        opened.proof + i * FZN_PROVISION_PROOF_ITEM_LEN,
		                        FZN_PROVISION_PROOF_ITEM_LEN) != FZN_NODE_ROOTS_OK) {
			fzn_wipe(&p, sizeof(p));
			return FZN_NODE_PAIR_STORE;
		}
	memcpy(p.chain, opened.chain, opened.hop_count * FZN_HOP_LEN);
	p.hop_count = opened.hop_count;
	memcpy(p.capability.b, opened.hop + FZN_HOP_OFF_CAPABILITY, FZN_CAP_ID_LEN);

	if (fzn_node_pairing_pack(&p, blob, sizeof(blob), &len) != FZN_PERSIST_OK) {
		fzn_wipe(&p, sizeof(p));
		return FZN_NODE_PAIR_MALFORMED;
	}
	saved = store->save(store->ctx, FZN_PERSIST_PAIRED_NODE, p.node, blob, len);
	fzn_wipe(blob, sizeof(blob));
	if (!saved) {
		fzn_wipe(&p, sizeof(p));
		return FZN_NODE_PAIR_STORE;
	}
	*out = p;
	fzn_wipe(&p, sizeof(p));
	return FZN_NODE_PAIR_OK;
}

/* node | capability | send_key | send_ckey | hop_count | chain, after the
 * shared head. The session keys are in the clear for the reason `persist.h`
 * gives for every secret it stores: what protects them is the backend. */
#define OFF_NODE ((size_t)FZN_PERSIST_HEAD_LEN)
#define OFF_CAP (OFF_NODE + FZN_PUBKEY_LEN)
#define OFF_KEY (OFF_CAP + FZN_CAP_ID_LEN)
#define OFF_CKEY (OFF_KEY + FZN_AEAD_KEY_LEN)
#define OFF_HOP_COUNT (OFF_CKEY + FZN_COMMITMENT_KEY_LEN)
#define OFF_CHAIN (OFF_HOP_COUNT + 1u)

_Static_assert(OFF_CHAIN + FZN_CHAIN_MAX_HOPS * FZN_HOP_LEN == FZN_NODE_PAIRING_BLOB_MAX,
               "the pairing blob's offsets do not add up to its length");

fzn_node_pair_err_t fzn_node_join(const fzn_node_identity_t *id, const uint8_t *card,
                                  size_t card_len, uint64_t now,
                                  const fzn_persist_ops_t *store, fzn_trust_t *trust,
                                  fzn_node_pairing_t *out)
{
	fzn_provision_card_t opened;
	fzn_chain_hop_t hop;
	fzn_trust_t pinned;
	uint8_t blob[FZN_PERSIST_MAX];
	size_t len = 0;
	fzn_node_pair_err_t err;

	if (!id || !card || !store || !store->save || !trust || !out)
		return FZN_NODE_PAIR_MALFORMED;

	/* EVERYTHING THAT CAN REFUSE IS ASKED BEFORE ANYTHING IS WRITTEN: the
	 * grant must be delegable, and the anchor must accept the pin -- tried
	 * on a copy, so a refusal leaves the caller's trust as it was. */
	if (fzn_provision_open(card, card_len, &opened) != FZN_PROVISION_OK
	    || fzn_hop_open(opened.hop, FZN_HOP_LEN, &hop) != FZN_CHAIN_OK)
		return FZN_NODE_PAIR_REFUSED;
	if (!fzn_hop_delegable(hop))
		return FZN_NODE_PAIR_CANNOT_JOIN;
	pinned = *trust;
	if (fzn_trust_pin(&pinned, opened.root) != FZN_TRUST_OK)
		return FZN_NODE_PAIR_CANNOT_JOIN;

	err = fzn_node_pairing_accept(id, card, card_len, now, store, out);
	if (err != FZN_NODE_PAIR_OK)
		return err;
	/* THE ANCHOR LAST. A pairing saved with the anchor unsaved is a node
	 * that restarts self-rooted and holding a pairing it cannot use --
	 * reported, and fixed by joining again; the other order would restart
	 * a node pinned to an estate it holds no grant in. */
	if (fzn_persist_trust_pack(&pinned, blob, sizeof(blob), &len) != FZN_PERSIST_OK
	    || !store->save(store->ctx, FZN_PERSIST_TRUST, NULL, blob, len))
		return FZN_NODE_PAIR_STORE;
	*trust = pinned;
	return FZN_NODE_PAIR_OK;
}

fzn_persist_err_t fzn_node_pairing_pack(const fzn_node_pairing_t *pairing, uint8_t *out,
                                        size_t cap, size_t *len)
{
	fzn_persist_err_t err;
	size_t n;

	if (!pairing || !out || !len)
		return FZN_PERSIST_ERR_MALFORMED;
	n = pairing->hop_count;
	if (n == 0u || n > FZN_CHAIN_MAX_HOPS)
		return FZN_PERSIST_ERR_SHAPE;
	err = fzn_persist_head_write(out, cap, FZN_NODE_PAIRING_BODY_LEN(n),
	                             FZN_PERSIST_BLOB_PAIRING);
	if (err != FZN_PERSIST_OK)
		return err;
	memcpy(out + OFF_NODE, pairing->node, FZN_PUBKEY_LEN);
	memcpy(out + OFF_CAP, pairing->capability.b, FZN_CAP_ID_LEN);
	memcpy(out + OFF_KEY, pairing->send_key, FZN_AEAD_KEY_LEN);
	memcpy(out + OFF_CKEY, pairing->send_ckey, FZN_COMMITMENT_KEY_LEN);
	out[OFF_HOP_COUNT] = (uint8_t)n;
	memcpy(out + OFF_CHAIN, pairing->chain, n * FZN_HOP_LEN);
	*len = (size_t)FZN_PERSIST_HEAD_LEN + FZN_NODE_PAIRING_BODY_LEN(n);
	return FZN_PERSIST_OK;
}

fzn_persist_err_t fzn_node_pairing_open(const uint8_t *bytes, size_t len,
                                        fzn_node_pairing_t *out)
{
	fzn_persist_err_t err;
	fzn_chain_hop_t hop;
	size_t n, i;

	if (!bytes || !out)
		return FZN_PERSIST_ERR_MALFORMED;
	if (len <= OFF_HOP_COUNT)
		return FZN_PERSIST_ERR_SHAPE;
	n = bytes[OFF_HOP_COUNT];
	if (n == 0u || n > FZN_CHAIN_MAX_HOPS)
		return FZN_PERSIST_ERR_SHAPE;
	err = fzn_persist_head_check(bytes, len, FZN_NODE_PAIRING_BODY_LEN(n),
	                             FZN_PERSIST_BLOB_PAIRING);
	if (err != FZN_PERSIST_OK)
		return err;
	/* EVERY HOP MUST BE A HOP, AND THE LAST ONE'S CAPABILITY THE ONE STORED
	 * BESIDE IT. Two copies of one fact in one blob is a second encoding
	 * unless they are required to agree -- `persist.c`'s head check refuses
	 * a trailing byte for the same reason. */
	for (i = 0; i < n; i++)
		if (fzn_hop_open(bytes + OFF_CHAIN + i * FZN_HOP_LEN, FZN_HOP_LEN, &hop)
		    != FZN_CHAIN_OK)
			return FZN_PERSIST_ERR_SHAPE;
	if (memcmp(bytes + OFF_CHAIN + (n - 1u) * FZN_HOP_LEN + FZN_HOP_OFF_CAPABILITY,
	           bytes + OFF_CAP, FZN_CAP_ID_LEN) != 0)
		return FZN_PERSIST_ERR_SHAPE;
	memset(out, 0, sizeof(*out));
	memcpy(out->node, bytes + OFF_NODE, FZN_PUBKEY_LEN);
	memcpy(out->capability.b, bytes + OFF_CAP, FZN_CAP_ID_LEN);
	memcpy(out->send_key, bytes + OFF_KEY, FZN_AEAD_KEY_LEN);
	memcpy(out->send_ckey, bytes + OFF_CKEY, FZN_COMMITMENT_KEY_LEN);
	out->hop_count = n;
	memcpy(out->chain, bytes + OFF_CHAIN, n * FZN_HOP_LEN);
	return FZN_PERSIST_OK;
}

fzn_persist_err_t fzn_node_pairing_load(const fzn_persist_ops_t *store,
                                        const uint8_t node[FZN_PUBKEY_LEN],
                                        fzn_node_pairing_t *out)
{
	uint8_t blob[FZN_NODE_PAIRING_BLOB_MAX];
	fzn_node_pairing_t p;
	fzn_persist_err_t err;
	size_t len = 0;

	if (!store || !store->load || !node || !out)
		return FZN_PERSIST_ERR_MALFORMED;
	if (!store->load(store->ctx, FZN_PERSIST_PAIRED_NODE, node, blob, sizeof(blob), &len))
		return FZN_PERSIST_ERR_BACKEND;
	err = fzn_node_pairing_open(blob, len, &p);
	fzn_wipe(blob, sizeof(blob));
	if (err != FZN_PERSIST_OK)
		return err;
	/* FILED UNDER ONE NODE AND NAMING ANOTHER is a corrupt store or a
	 * placed file, and sealing to it would send this device's requests
	 * under keys meant for somebody else -- the check `fzn_node_peers_load`
	 * makes for the node's view, made here for the device's. */
	if (memcmp(p.node, node, FZN_PUBKEY_LEN) != 0) {
		fzn_wipe(&p, sizeof(p));
		return FZN_PERSIST_ERR_SHAPE;
	}
	*out = p;
	fzn_wipe(&p, sizeof(p));
	return FZN_PERSIST_OK;
}

fzn_persist_err_t fzn_node_pairing_estate(const fzn_persist_ops_t *store,
                                          const uint8_t root[FZN_PUBKEY_LEN],
                                          const uint8_t self[FZN_PUBKEY_LEN],
                                          fzn_node_pairing_t *out)
{
	uint8_t subjects[16u * FZN_PUBKEY_LEN];
	size_t found = 0, i;

	if (!store || !store->list || !store->load || !root || !self || !out)
		return FZN_PERSIST_ERR_MALFORMED;
	if (!store->list(store->ctx, FZN_PERSIST_PAIRED_NODE, subjects, 16u, &found))
		return FZN_PERSIST_ERR_BACKEND;
	for (i = 0; i < found && i < 16u; i++) {
		fzn_node_pairing_t p;
		fzn_chain_hop_t first, last;

		if (fzn_node_pairing_load(store, subjects + i * FZN_PUBKEY_LEN, &p) != FZN_PERSIST_OK)
			continue;
		if (fzn_hop_open(p.chain[0], FZN_HOP_LEN, &first) == FZN_CHAIN_OK
		    && fzn_hop_open(p.chain[p.hop_count - 1u], FZN_HOP_LEN, &last) == FZN_CHAIN_OK
		    && memcmp(fzn_hop_grantor(first), root, FZN_PUBKEY_LEN) == 0
		    && memcmp(fzn_hop_grantee(last), self, FZN_PUBKEY_LEN) == 0
		    && fzn_hop_delegable(last)) {
			*out = p;
			fzn_wipe(&p, sizeof(p));
			return FZN_PERSIST_OK;
		}
		fzn_wipe(&p, sizeof(p));
	}
	return FZN_PERSIST_ERR_ABSENT;
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
