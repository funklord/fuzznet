/* Provisioning the remote hop: turning a device into a peer the node can
 * serve, and the pairing card that carries a node's anchor to a device.
 *
 * The remote hop authenticates a caller by a session that opens its frames
 * and authorises it by a capability chaining to the node's root (node/remote.h).
 * Both are established out of band, and this is the out of band: a node
 * provisions a device it has the prekey of into a fzn_node_peer_t, and hands
 * that device a card -- the node's root, the node's prekey, and the device's
 * minted capability, signed -- so the device can establish its own session and
 * know what it holds. sec 301.
 *
 * "Server and client is a matter of perspective" (sec 2): both parties are a
 * fzn_node_identity_t, and the device provisions itself from the card with the
 * same primitives the node used to build it.
 */

#ifndef FZN_NODE_PROVISION_H
#define FZN_NODE_PROVISION_H

#include <stddef.h>
#include <stdint.h>

#include "remote.h"
#include "../session/agree.h"
#include "../session/session.h"
#include "../prekey/prekey.h"

/* A node's own material. The device that provisions itself from a card is a
 * fzn_node_identity_t too, from its own point of view. */
typedef struct fzn_node_identity {
	/* The Ed25519 identity, which is this node's root when it mints. */
	uint8_t pubkey[FZN_PUBKEY_LEN];
	/* The X25519 secret behind the sessions, and the signed prekey a card
	 * carries so a device can agree with it. */
	const fzn_agree_secret_t *agree_secret;
	uint8_t prekey_record[FZN_PREKEY_LEN_TOTAL];
	/* Signs as root and verifies; hashes; agrees. */
	const fzn_sign_ops_t *sign;
	const fzn_hash_ops_t *hash;
	const fzn_agree_ops_t *agree;
} fzn_node_identity_t;

typedef enum fzn_node_provision_err {
	FZN_NODE_PROVISION_OK = 0,
	FZN_NODE_PROVISION_MALFORMED = -1,
	/* The peer's prekey did not verify -- authorship unproven. */
	FZN_NODE_PROVISION_UNTRUSTED = -2,
	/* The session would not establish. */
	FZN_NODE_PROVISION_SESSION = -3,
	/* The capability would not mint or the hop would not open. */
	FZN_NODE_PROVISION_MINT = -4,
	/* A card would not pack, open or verify. */
	FZN_NODE_PROVISION_CARD = -5
} fzn_node_provision_err_t;

/* Provision `device_prekey`'s owner into `out` -- the session that opens its
 * frames and the capability `cap`, minted with this node as root. The node
 * calls this for a device whose prekey reached it out of band; afterwards the
 * remote hop serves that device. */
fzn_node_provision_err_t fzn_node_provision_peer(const fzn_node_identity_t *id,
                                                 fzn_prekey_record_t device_prekey,
                                                 const fzn_cap_id_t *cap,
                                                 uint64_t issued_at,
                                                 uint64_t expires_at, uint64_t now,
                                                 fzn_node_peer_t *out);

/* Build the pairing card a node hands a device: its root, its prekey, and the
 * capability `cap` minted for `device`, signed. `card_expires_at` bounds the
 * card itself (0 is never). Writes at most `cap_bytes`, setting *out_len. */
fzn_node_provision_err_t fzn_node_make_card(const fzn_node_identity_t *id,
                                            const uint8_t device[FZN_PUBKEY_LEN],
                                            const fzn_cap_id_t *cap,
                                            uint64_t issued_at, uint64_t expires_at,
                                            uint64_t card_expires_at, uint8_t *out,
                                            size_t cap_bytes, size_t *out_len);

/* The device side: open and verify a card, pin the node's prekey, and
 * establish the session this device seals to the node with. Fills the send
 * key and commitment key, the root the card names, and (if non-NULL) the
 * device's own capability hop from the card. */
fzn_node_provision_err_t fzn_node_accept_card(const fzn_node_identity_t *device,
                                              const uint8_t *card_bytes,
                                              size_t card_len, uint64_t now,
                                              uint8_t send_key[FZN_AEAD_KEY_LEN],
                                              uint8_t send_ckey[FZN_COMMITMENT_KEY_LEN],
                                              uint8_t root_out[FZN_PUBKEY_LEN],
                                              fzn_chain_hop_t *hop_out);

#endif
