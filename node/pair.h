/* Pairing one device: provision it, save it, and make its card -- in the order
 * that cannot leave a card for a pairing the node forgot.
 *
 * `node/provision.h` has the three steps and nothing composed them outside a
 * test, so `fuzznetd` composed them in its main -- where no suite could reach
 * them, which is exactly how that main came to require a capability nobody
 * could hold (sec 376). The composition lives here so the suite that checks it
 * is checking the code the daemon runs.
 *
 * WHAT THE DEVICE IS GRANTED IS `cap`, and the caller should pass the one its
 * remote hop requires -- `fzn_node_config_t.remote_capability`. A grant the
 * node does not check is a grant for nothing, and the relation is asserted in
 * `node/test/pair_test.c` by the node's own authorisation check rather than by
 * comparing two capability ids.
 *
 * THE GRANT DOES NOT EXPIRE; THE CARD DOES. A lost device is revoked, which
 * is the capability model's answer (sec 1); the card carries no secret, so its
 * own expiry bounds how long a copy of it stays worth accepting, not what it
 * reveals.
 */

#ifndef FZN_NODE_PAIR_H
#define FZN_NODE_PAIR_H

#include <stddef.h>
#include <stdint.h>

#include "caller.h"
#include "provision.h"
#include "../persist/persist.h"

typedef enum fzn_node_pair_err {
	FZN_NODE_PAIR_OK = 0,
	FZN_NODE_PAIR_MALFORMED = -1,
	/* This node may not grant: it is not the root and holds no chain from
	 * the root that verifies, names it, and may be passed on. */
	FZN_NODE_PAIR_NOT_ROOT = -2,
	/* The device's prekey record did not verify, or no session would
	 * establish with it. Nothing was saved. */
	FZN_NODE_PAIR_DEVICE = -3,
	/* The store refused the peer. Nothing was minted for the device. */
	FZN_NODE_PAIR_STORE = -4,
	/* The peer is saved and the card could not be made. Pairing again is
	 * safe: the peer is re-derived and saved over itself. */
	FZN_NODE_PAIR_CARD = -5,
	/* The DEVICE'S side: the card did not verify, was made for another
	 * device, or no session would establish from it. Nothing was saved. */
	FZN_NODE_PAIR_REFUSED = -6,
	/* A JOIN refused: the card's grant cannot be passed on, or this node
	 * is anchored to an estate already. A self-root is the one anchor a
	 * join may replace (sec 136). */
	FZN_NODE_PAIR_CANNOT_JOIN = -7
} fzn_node_pair_err_t;

const char *fzn_node_pair_err_str(fzn_node_pair_err_t err);

/*
 * WHERE A NODE'S RIGHT TO GRANT COMES FROM. sec 383.
 *
 * NULL means the node IS the estate root, which is sec 376's node and every
 * node that has not joined an estate. Otherwise `hops` is the node's own
 * chain from the root -- the grant it was paired into the estate with --
 * and pairing EXTENDS it, which is fuzzypickles' delegate branch
 * (`fzp_capability_grant`'s non-vault path): a host that holds a grant it
 * may pass on appends a hop signed with its own key. The chain must verify
 * under the root for the capability being granted, name this node as its
 * last grantee, and end in a delegable hop, or the pairing is refused.
 */
typedef struct fzn_node_authority {
	const uint8_t (*hops)[FZN_HOP_LEN];
	size_t hop_count;
} fzn_node_authority_t;

/* Pair `device` to this node. `root` is the root this node verifies against:
 * this node's own key when `authority` is NULL, the estate root otherwise.
 * `delegable` lets the device pass the grant on -- what a node being paired
 * INTO an estate receives, and what an ordinary device does not. On success
 * the peer is in `store`, holding the whole chain from the root, and `card`
 * holds the packed card, `*card_len` bytes of at most `card_cap`.
 *
 * THE CARD IS THE SAME EITHER WAY. It names the node the device talks to,
 * signed by that node, with the one hop the node minted; the device pins the
 * node and never needs the chain above it. Only the node's side changes. */
fzn_node_pair_err_t fzn_node_pair(const fzn_node_identity_t *id,
                                  const uint8_t root[FZN_PUBKEY_LEN],
                                  const fzn_cap_id_t *cap,
                                  const fzn_node_authority_t *authority, int delegable,
                                  const fzn_persist_ops_t *store,
                                  fzn_prekey_record_t device, uint64_t now,
                                  uint64_t card_expires_at, uint8_t *card, size_t card_cap,
                                  size_t *card_len);

/* ---- the device's side ------------------------------------------------ */

/*
 * A pairing as the DEVICE holds it: which node, what it is granted there, and
 * the session it seals to that node with. sec 377.
 *
 * NO ADDRESS. Where the node is on the network is a location, and it changes
 * without the pairing changing; the link and location subsystems own finding
 * it. A pairing is the credential, and a stored address beside it would be
 * the first thing to go stale while looking authoritative.
 *
 * The hop is kept so the device can say what it holds; the node does not need
 * it presented, having stored it when it paired the device.
 */
typedef struct fzn_node_pairing {
	uint8_t root[FZN_PUBKEY_LEN];
	fzn_cap_id_t capability;
	uint8_t send_key[FZN_AEAD_KEY_LEN];
	uint8_t send_ckey[FZN_COMMITMENT_KEY_LEN];
	uint8_t hop[FZN_HOP_LEN];
} fzn_node_pairing_t;

#define FZN_NODE_PAIRING_BODY_LEN \
	((size_t)FZN_PUBKEY_LEN + (size_t)FZN_CAP_ID_LEN + (size_t)FZN_AEAD_KEY_LEN + \
	 (size_t)FZN_COMMITMENT_KEY_LEN + (size_t)FZN_HOP_LEN)
#define FZN_NODE_PAIRING_BLOB_LEN ((size_t)FZN_PERSIST_HEAD_LEN + FZN_NODE_PAIRING_BODY_LEN)

/* Accept a node's card on this device and save the pairing under the node's
 * root, replacing any earlier pairing to that node. `out` receives it. The
 * card must verify, carry a grant to THIS device, and establish a session;
 * anything else is FZN_NODE_PAIR_REFUSED with nothing saved. */
fzn_node_pair_err_t fzn_node_pairing_accept(const fzn_node_identity_t *device,
                                            const uint8_t *card, size_t card_len,
                                            uint64_t now, const fzn_persist_ops_t *store,
                                            fzn_node_pairing_t *out);

fzn_persist_err_t fzn_node_pairing_pack(const fzn_node_pairing_t *pairing, uint8_t *out,
                                        size_t cap, size_t *len);
fzn_persist_err_t fzn_node_pairing_open(const uint8_t *bytes, size_t len,
                                        fzn_node_pairing_t *out);

/* The pairing to the node whose root is `root`. The stored root must equal
 * the one it is filed under, or it is refused as SHAPE. */
fzn_persist_err_t fzn_node_pairing_load(const fzn_persist_ops_t *store,
                                        const uint8_t root[FZN_PUBKEY_LEN],
                                        fzn_node_pairing_t *out);

/*
 * JOIN THE ESTATE WHOSE ROOT MADE THIS CARD. sec 383.
 *
 * The node's side of being paired INTO an estate: accept the card as any
 * device does, then pin the card's root as this node's anchor in `trust`
 * and save it. From then on the node verifies against that root, and its
 * right to grant is the delegable hop the card carried -- `pairing->hop`,
 * as a one-hop `fzn_node_authority_t`.
 *
 * A JOIN IS A PIN REPLACING A SELF-ROOT, which is the transition sec 136
 * built `FZN_TRUST_SELF` for; any other anchor refuses it, since no host is
 * on two estates (sec 28). The grant must be delegable: a joined node serves
 * only devices it pairs itself -- a session is per pair -- so a node that
 * could not pass its grant on could serve nobody.
 *
 * DEVICES PAIRED UNDER THE OLD SELF-ROOT STOP BEING SERVED. Their chains
 * root at this node's own key and the node now verifies against the
 * estate's; they are paired again through the estate. That is the invariant
 * working, not a migration to perform.
 *
 * ONLY THROUGH THE ROOT. A card carries one hop and names its signer as
 * root, so a card from a delegate would make the node pin the delegate.
 * Joining through a delegate needs the card to carry the chain above it,
 * which is a change to the card's layout and is not made here.
 */
fzn_node_pair_err_t fzn_node_join(const fzn_node_identity_t *id, const uint8_t *card,
                                  size_t card_len, uint64_t now,
                                  const fzn_persist_ops_t *store, fzn_trust_t *trust,
                                  fzn_node_pairing_t *out);

/* Fill the credential half of a caller from a pairing: its sender (this
 * device, `self`), capability and session keys. The socket, the node's
 * address and the ops are the caller's to set; see the header on addresses. */
void fzn_node_pairing_caller(const fzn_node_pairing_t *pairing,
                             const uint8_t self[FZN_PUBKEY_LEN], fzn_caller_t *caller);

#endif /* FZN_NODE_PAIR_H */
