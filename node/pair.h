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
 *
 * A CHAIN FROM ANOTHER ROOT, sec 411: `proof` holds the root-adds from the
 * estate's root to the root `hops` starts at, and the card a pairing makes
 * carries them, so a device pinning the estate's root accepts the chain
 * (sec 410). NULL and 0 when `hops` starts at the estate's root, which is
 * every authority before sec 411 -- so an authority is zeroed before it is
 * filled, and a field left unset is no proof rather than garbage.
 */
typedef struct fzn_node_authority {
	const uint8_t (*hops)[FZN_HOP_LEN];
	size_t hop_count;
	const uint8_t (*proof)[FZN_PROVISION_PROOF_ITEM_LEN];
	size_t proof_count;
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
 * THE WHOLE CHAIN IS KEPT, from the estate's root to this device, as the card
 * carried it. A device does not present it -- the node stored its side when it
 * paired the device -- but a NODE that joined an estate grants through it:
 * it is that node's authority (`fzn_node_authority_t`). `node` is the node
 * this pairing is to, the card's sponsor; the estate's root is the first
 * hop's grantor, and a joined node pins it separately (sec 391).
 */
typedef struct fzn_node_pairing {
	uint8_t node[FZN_PUBKEY_LEN];
	fzn_cap_id_t capability;
	uint8_t send_key[FZN_AEAD_KEY_LEN];
	uint8_t send_ckey[FZN_COMMITMENT_KEY_LEN];
	size_t hop_count;
	uint8_t chain[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
} fzn_node_pairing_t;

/* The stored form: node | capability | send_key | send_ckey | hop_count |
 * chain, after the shared head. `persist/persist.situ` states it. */
#define FZN_NODE_PAIRING_BODY_LEN(n) \
	((size_t)FZN_PUBKEY_LEN + (size_t)FZN_CAP_ID_LEN + (size_t)FZN_AEAD_KEY_LEN + \
	 (size_t)FZN_COMMITMENT_KEY_LEN + 1u + (size_t)(n) * (size_t)FZN_HOP_LEN)
#define FZN_NODE_PAIRING_BLOB_MAX \
	((size_t)FZN_PERSIST_HEAD_LEN + FZN_NODE_PAIRING_BODY_LEN(FZN_CHAIN_MAX_HOPS))

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

/* The pairing to the node whose key is `node`. The stored node must equal the
 * one it is filed under, or it is refused as SHAPE. */
fzn_persist_err_t fzn_node_pairing_load(const fzn_persist_ops_t *store,
                                        const uint8_t node[FZN_PUBKEY_LEN],
                                        fzn_node_pairing_t *out);

/* THE PAIRING A JOINED NODE GRANTS THROUGH: the one whose chain starts at the
 * estate's `root`, ends in a hop to `self`, and may be passed on. Found by that
 * shape rather than by key, because since sec 391 a node joins through
 * whichever member admitted it and the pairing is filed under that member.
 * FZN_PERSIST_ERR_ABSENT when this node holds none -- it has not joined, or
 * joined and lost the pairing. */
fzn_persist_err_t fzn_node_pairing_estate(const fzn_persist_ops_t *store,
                                          const uint8_t root[FZN_PUBKEY_LEN],
                                          const uint8_t self[FZN_PUBKEY_LEN],
                                          fzn_node_pairing_t *out);

/*
 * JOIN THE ESTATE THIS CARD NAMES. sec 383, and through any member since 391.
 *
 * The node's side of being paired INTO an estate: accept the card as any
 * device does, then pin the card's root as this node's anchor in `trust`
 * and save it. From then on the node verifies against that root, and its
 * right to grant is the chain the card carried, ending in a delegable hop to
 * this node -- `pairing->chain`, as a `fzn_node_authority_t`.
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
 * THROUGH ANY MEMBER ENTITLED TO ADMIT. The card names the estate's root and
 * carries the whole chain, sealed by the member that granted the last hop
 * (sec 391), so the joining node pins the root and holds the member's chain
 * plus its own hop as its authority. The root need not be online. Until sec
 * 391 a card carried one hop and named its signer as root, so joining
 * through a member would have pinned the member.
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
