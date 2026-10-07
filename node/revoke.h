/* A node revoking the grants it minted, and keeping what it revoked.
 *
 * sec 1: "a stolen device is something you revoke rather than a password you
 * change". `chain/revocation.h` has had the record, the signing and a store
 * that verifies on admission since sec 13, and the node consulted none of it:
 * `node/remote.c` passed NULL revocations to every decision. sec 379 could
 * cut a device off by forgetting its peer record, which is enough for a device
 * paired to one node and nothing more -- a grant honoured anywhere else has no
 * peer record to forget. This is revocation proper. sec 380.
 *
 * THE STORE CANNOT BE SAVED, SO THE RECORDS ARE. `fzn_revocation_store_t`
 * keeps "a hash and a flag, never a record" -- deliberately, so the hot path
 * compares rather than verifies -- which means there is nothing in it to
 * persist and re-trust. What a node persists is each record it ISSUED, and at
 * start every one is admitted again through `fzn_revocation_admit`, the same
 * verification a revocation arriving from anywhere gets. A node's own must
 * survive a restart on the node, or a restart re-admits every device it
 * revoked; and those a member LEARNED from its root are kept the same way, in
 * their own slot, so a restart with the root unreachable still denies them
 * (sec 384).
 *
 * ONE RECORD PER GRANTEE: the latest this node issued for it. A node grants
 * one capability (sec 376), so a grantee is one (issuer, capability, grantee)
 * triple, and the latest record is what a restart must re-establish.
 *
 * A NODE THAT JOINED AN ESTATE REVOKES THROUGH ITS CHAIN. A root-issued
 * revocation is checked against the pinned root; a member's is admitted with
 * `fzn_revocation_offer_chain`, presenting the chain from the root that makes
 * it the grantor -- the same `fzn_node_authority_t` it pairs with, and the
 * same standing, since revoking a descendant is the inverse of granting one
 * (`chain/revocation.h`). The record is signed by the member's own key and
 * names it as issuer. sec 385.
 */

#ifndef FZN_NODE_REVOKE_H
#define FZN_NODE_REVOKE_H

#include <stddef.h>
#include <stdint.h>

#include "caller.h"
#include "pair.h"
#include "../chain/succession.h"
#include "provision.h"
#include "../chain/revocation.h"
#include "../chain/root_log.h"
#include "../roster/roster.h"
#include "../persist/persist.h"

typedef enum fzn_node_revoke_err {
	FZN_NODE_REVOKE_OK = 0,
	FZN_NODE_REVOKE_MALFORMED = -1,
	/* This node has no standing to revoke: it is not its own root and
	 * holds no chain from the root that it may pass on. */
	FZN_NODE_REVOKE_NOT_ROOT = -2,
	/* Already revoked by this node. Not a failure of the request -- the
	 * grantee is revoked -- and its own code so a caller can say so. */
	FZN_NODE_REVOKE_ALREADY = -3,
	/* The record would not mint, or the store would not admit it -- full
	 * being the case that matters, since a revocation store never evicts. */
	FZN_NODE_REVOKE_STORE_REFUSED = -4,
	/* Revoked, or un-revoked, in the running store and not saved: in force
	 * until a restart, and forgotten by one. */
	FZN_NODE_REVOKE_NOT_SAVED = -5,
	/* Un-revoking a grantee this node holds no revocation of in force. */
	FZN_NODE_REVOKE_NOT_REVOKED = -6,
	/* An admin chain that does not verify for the admin capability from a
	 * root, name this node, or end delegable. sec 416. */
	FZN_NODE_REVOKE_NOT_ADMIN = -7
} fzn_node_revoke_err_t;

const char *fzn_node_revoke_err_str(fzn_node_revoke_err_t err);

/* Declared, not included: `node/roots.h` includes this header. */
struct fzn_node_roots;

/* `roots`, on all three: where the vote is logged as this node's act, sec
 * 504, and so carried in its journal; NULL logs nothing.
 *
 * Revoke `grantee`'s grant of `capability` from this node. `root` is the root
 * the node verifies against: this node's own key when `authority` is NULL,
 * the estate root otherwise, with `authority` the node's chain from it -- as
 * `fzn_node_pair` takes them. The record is
 * admitted into `revocations` FIRST and saved second: a revocation in force
 * and unsaved is a smaller failure than one saved and not in force, which
 * would be the operator told a device is cut off while the node serves it. */
fzn_node_revoke_err_t fzn_node_revoke(struct fzn_node_roots *roots,
                                      const fzn_node_identity_t *id,
                                      const uint8_t root[FZN_PUBKEY_LEN],
                                      const fzn_node_authority_t *authority,
                                      const fzn_cap_id_t *capability,
                                      const uint8_t grantee[FZN_PUBKEY_LEN], uint64_t now,
                                      fzn_revocation_store_t *revocations,
                                      const fzn_persist_ops_t *store);

/* REVOKE, DRAWING A LINE. sec 497. As `fzn_node_revoke`, whose vote trusts
 * nothing of the grantee's, but naming `cut` -- the id of the last entry of
 * the grantee's act log this node still trusts, or NULL for none.
 *
 * OVER A VOTE OF THIS NODE'S STILL LIVE, it MOVES THE LINE: a reissue
 * superseding the held vote, with the new cut. That is how an owner who
 * learns when a device was taken says so without first undoing its vote.
 * ALREADY when the held vote already draws this line. */
fzn_node_revoke_err_t fzn_node_revoke_at(struct fzn_node_roots *roots,
                                      const fzn_node_identity_t *id,
                                         const uint8_t root[FZN_PUBKEY_LEN],
                                         const fzn_node_authority_t *authority,
                                         const fzn_cap_id_t *capability,
                                         const uint8_t grantee[FZN_PUBKEY_LEN], uint64_t now,
                                         const uint8_t cut[FZN_REVOCATION_ID_LEN],
                                         fzn_revocation_store_t *revocations,
                                         const fzn_persist_ops_t *store);

/* UNDO this node's revocation of `grantee`: mint the withdrawal naming the
 * record held in slot 9, admit it, and save it in that record's place. sec 386.
 *
 * The same standing as revoking, and the same order -- in force first, saved
 * second. A later `fzn_node_revoke` of the grantee then supersedes the
 * revocation this undid, which is what admission requires of a re-revocation.
 *
 * HOW IT IS TOLD: with `roots`, the withdrawal is logged as this node's act
 * and so enters its journal, which every peer following it applies (sec
 * 505). A host that learned the revocation any other way keeps it;
 * `chain/revocation.h` says why no manifest carries withdrawals. */
fzn_node_revoke_err_t fzn_node_unrevoke(struct fzn_node_roots *roots,
                                      const fzn_node_identity_t *id,
                                        const uint8_t root[FZN_PUBKEY_LEN],
                                        const fzn_node_authority_t *authority,
                                        const uint8_t grantee[FZN_PUBKEY_LEN], uint64_t now,
                                        fzn_revocation_store_t *revocations,
                                        const fzn_persist_ops_t *store);

/* Save a confirmation this node signed, with `authority` -- its admin chain,
 * or NULL as a root -- so a restart re-admits it. sec 415. */
fzn_node_revoke_err_t fzn_node_confirm_save(const fzn_persist_ops_t *store,
                                            const fzn_hash_ops_t *hash,
                                            const uint8_t record[FZN_ADMIN_CONFIRM_LEN],
                                            const fzn_node_authority_t *authority);

/* At start: admit every revocation this node ISSUED (slot 9) and every vote
 * it learned with its chain (slot 11, sec 399) -- its root's among them since
 * sec 506 retired slot 10 -- from `store` into `revocations`,
 * verified against `root`, and -- when the store keeps a confirmation table --
 * every admin confirmation (slot 15, sec 415). OK with nothing stored.
 *
 * A record that will not admit FAILS THE LOAD rather than being skipped: a
 * node that quietly re-admitted a device it had revoked is the failure this
 * prevents.
 *
 * A record issued by `root` is admitted as the root's. One issued by the
 * grantee of `authority` -- this member's own, sec 385 -- is admitted with that
 * chain when it withdraws the capability the chain carries. That includes a
 * record the node issued as its own root before it joined: it is still the
 * node's signed word that the grantee is cut off, and honouring it errs
 * toward denial, the one direction a revocation may err in. Any other record
 * is skipped and not counted -- one for a capability the chain does not carry
 * could never admit, and a node holding no chain (`authority` NULL, as for a
 * root) has nothing to verify its own pre-join records against (sec 383).
 *
 * `admin` is this node's admin chain, or NULL (sec 416): a record it issued
 * for a capability `authority` does not carry is admitted on that chain, as
 * the admin vote it was, when the store knows the admin capability. */
fzn_persist_err_t fzn_node_revocations_load(const fzn_persist_ops_t *store,
                                            fzn_revocation_store_t *revocations,
                                            const uint8_t root[FZN_PUBKEY_LEN],
                                            const fzn_node_authority_t *authority,
                                            const fzn_node_authority_t *admin,
                                            const fzn_sign_ops_t *sign,
                                            const fzn_hash_ops_t *hash, size_t *count);

/* The revocation this node issued for `grantee`, into `record`, from slot 9.
 * 1 when one is held. */
int fzn_node_issued_revocation(const fzn_persist_ops_t *store,
                               const uint8_t grantee[FZN_PUBKEY_LEN],
                               uint8_t record[FZN_REVOCATION_LEN]);

/*
 * WHAT APPLYING AN OBJECT COMES TO. sec 384 named these for the pull of a
 * root's revocations; since sec 505 the journal carries every act and
 * `fzn_node_votes_take` and `node/apply.h` report in them.
 */
typedef enum fzn_node_pull_err {
	FZN_NODE_PULL_OK = 0,
	FZN_NODE_PULL_MALFORMED = -1,
	/* The root did not answer, or answered something other than `ok`. */
	FZN_NODE_PULL_NO_ANSWER = -2,
	/* A page did not parse as the grammar says it should. */
	FZN_NODE_PULL_SHAPE = -3,
	/* A record would not admit as the root's, or the running store is full. */
	FZN_NODE_PULL_REFUSED = -4,
	/* Admitted and not saved: in force until a restart. */
	FZN_NODE_PULL_NOT_SAVED = -5
} fzn_node_pull_err_t;

const char *fzn_node_pull_err_str(fzn_node_pull_err_t err);

/* The most revocations `fzn_node_revocations_load` enumerates in one call. */
#define FZN_NODE_REVOCATIONS_MAX 256u

/*
 * VOTES, AND HOW THEY ARE ADMITTED. sec 399, carried by the journal since
 * sec 505.
 *
 * Under a quorum above one (sec 397) a revocation is a vote, and a host needs
 * k of them from distinct entitled issuers -- so what one node signs has to
 * reach the next. Every vote, withdrawal, confirmation (sec 415), admin's
 * retention setting (sec 479), contact's roster record (sec 489) and
 * succession (sec 499) is its signer's act and so in its signer's journal;
 * a node applies each with the chain that entitles its signer, rebuilt from
 * the grants it holds (`node/apply.h`).
 *
 * WHAT ARRIVES IS VERIFIED, NOT TRUSTED: each vote is admitted with its
 * chain, `fzn_revocation_offer_chain`, or as the root's when it carries none.
 * One admission refuses -- a stranger's, a stale copy, a second chain for one
 * admin -- is COUNTED AND SKIPPED rather than stopping the rest. A full store
 * stops it, since everything after would be refused the same way.
 *
 * What admits, and is what the store now holds for its triple, is saved as
 * slot 11 under a hash of the triple, so a restart re-admits it. A stale copy
 * that admission accepts without taking -- a revocation already withdrawn --
 * is not saved over the newer record. A confirmation is saved in slot 15
 * under the record's hash.
 */

/* What admission carries: the object being admitted, where its kind is
 * learned into, and the counts so far. Zero it before the first. */
struct fzn_node_roots;
struct fzn_node_roster;

typedef struct fzn_node_vote_pull {
	int pending;
	/* The pending item is a confirmation, in `confirm`, not a vote. */
	int confirming;
	uint8_t confirm[FZN_ADMIN_CONFIRM_LEN];
	/* Or an admin's retention record, sec 479, in `retention`, learned into
	 * `roots` -- NULL refuses every one, counted. */
	int retaining;
	uint8_t retention[FZN_RETENTION_SET_LEN];
	struct fzn_node_roots *roots;
	/* Or a contact's roster record, sec 489, learned into `roster` --
	 * NULL refuses every one, counted. */
	int rostering;
	uint8_t roster_record[FZN_ROSTER_MIN_LEN];
	struct fzn_node_roster *roster;
	/* Or a succession, sec 499, learned into `successions` -- NULL refuses
	 * every one, counted. */
	int succeeding;
	uint8_t succession[FZN_SUCCESSION_LEN];
	struct fzn_node_successions *successions;
	uint8_t record[FZN_REVOCATION_LEN];
	uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	size_t hop_count;
	size_t learned;
	size_t refused;
} fzn_node_vote_pull_t;

/* ONE OBJECT: `item` is the letter for its kind -- 'r' a vote or
 * withdrawal, 'c' a confirmation, 't' an admin's retention setting, 'o' a
 * roster record, 's' a succession, the letters the retired vote stream
 * carried them under -- and `hops` its signer's chain, none for a root.
 * Admitted and saved, counted in `pull`'s learned and refused. What the
 * journal's receiver calls, sec 503. */
fzn_node_pull_err_t fzn_node_votes_take(fzn_node_vote_pull_t *pull, char item,
                                        const uint8_t *object, size_t len,
                                        const uint8_t (*hops)[FZN_HOP_LEN], size_t hop_count,
                                        const uint8_t root[FZN_PUBKEY_LEN],
                                        const fzn_sign_ops_t *sign, const fzn_hash_ops_t *hash,
                                        fzn_revocation_store_t *revocations,
                                        const fzn_persist_ops_t *store);

/*
 * ADMINS AT THE NODE: HOLDING, GRANTING, CONFIRMING. sec 416.
 *
 * AN ADMIN CHAIN is a chain from a root to this node's identity for the
 * estate's admin capability, its last hop delegable, so the node may both vote
 * as an admin and grant admin onward. A node holds at most one, in the core
 * slot 16, and votes on it: `fzn_node_revoke` takes it as its authority, and
 * the load re-admits the records it issued on it.
 *
 * A GRANT is minted by this node's acting root when it has one -- one hop from
 * that root, logged in its log as a grant -- and otherwise by this node as an
 * admin, extending its own admin chain by a hop. What it hands the grantee is
 * the whole chain; the grantee installs it with `fzn_node_admin_chain_set`,
 * which verifies it before keeping it. A grant by a non-root counts only once
 * k - 1 other admins confirm it (sec 414).
 *
 * A CONFIRMATION names a hop by its hash. This node signs it as its acting
 * root when it has one -- logged as a grant, since confirming an admin is part
 * of making one -- and otherwise as an admin, showing its admin chain. It is
 * admitted into the running store, saved, and logged as this node's act.
 */
struct fzn_node_roots;

/* An admin chain held: its hops, and an authority over them to pass where a
 * `fzn_node_authority_t` is taken. `authority.hops` points into `hops`, so
 * set it again after copying one of these -- `fzn_node_admin_chain_view`. */
typedef struct fzn_node_admin_chain {
	uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	size_t hop_count;
	fzn_node_authority_t authority;
} fzn_node_admin_chain_t;

/* The authority over `chain`, or NULL when it holds no hops. */
const fzn_node_authority_t *fzn_node_admin_chain_view(fzn_node_admin_chain_t *chain);

/* This node's admin chain from slot 16. 1 loaded, 0 none stored, -1 a row that
 * will not read. */
int fzn_node_admin_chain_load(const fzn_persist_ops_t *store, fzn_node_admin_chain_t *out);

/* Install `hops` as this node's admin chain: verified from `root` (or any root
 * `revocations`' set names) for `admin_capability` as of `now`, naming `id` as
 * its last grantee and ending delegable, then saved. NOT_ADMIN when it does
 * not verify. */
fzn_node_revoke_err_t fzn_node_admin_chain_set(const fzn_persist_ops_t *store,
                                               const fzn_revocation_store_t *revocations,
                                               const fzn_node_identity_t *id,
                                               const uint8_t root[FZN_PUBKEY_LEN],
                                               const fzn_cap_id_t *admin_capability,
                                               const uint8_t (*hops)[FZN_HOP_LEN],
                                               size_t hop_count, uint64_t now,
                                               fzn_node_admin_chain_t *out);

/* Grant admin to `grantee`: as this node's acting root (`roots`, may be NULL),
 * or else through `mine`, this node's admin chain (NULL for none). `out`
 * receives the grantee's whole chain, `*out_count` hops. NOT_ROOT when this
 * node is neither; MALFORMED when the chain would be too long. */
fzn_node_revoke_err_t fzn_node_admin_grant(struct fzn_node_roots *roots,
                                           const fzn_persist_ops_t *store,
                                           const fzn_node_identity_t *id,
                                           const fzn_node_admin_chain_t *mine,
                                           const fzn_cap_id_t *admin_capability,
                                           const uint8_t grantee[FZN_PUBKEY_LEN], uint64_t now,
                                           uint8_t out[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN],
                                           size_t *out_count);

/* CONFIRM ANY RECORD BY ITS HASH, `grant`: the act inside
 * `fzn_node_admin_confirm`, which hashes a hop first. What a succession's
 * confirmation calls with the succession's id (sec 499); the rule a
 * confirmation counts by is the reader's, `fzn_revocation_confirmed`. */
fzn_node_revoke_err_t fzn_node_confirm_act(struct fzn_node_roots *roots,
                                           const fzn_persist_ops_t *store,
                                           const fzn_node_identity_t *id,
                                           const fzn_node_admin_chain_t *mine,
                                           const uint8_t root[FZN_PUBKEY_LEN],
                                           const uint8_t grant[FZN_REVOCATION_ID_LEN],
                                           fzn_revocation_store_t *revocations);

/* Confirm the admin grant `hop`, as this node's acting root or through `mine`,
 * admit it into `revocations` and save it. NOT_ROOT when this node is neither;
 * STORE_REFUSED when the store will not take it. */
fzn_node_revoke_err_t fzn_node_admin_confirm(struct fzn_node_roots *roots,
                                             const fzn_persist_ops_t *store,
                                             const fzn_node_identity_t *id,
                                             const fzn_node_admin_chain_t *mine,
                                             const uint8_t root[FZN_PUBKEY_LEN],
                                             const uint8_t hop[FZN_HOP_LEN],
                                             fzn_revocation_store_t *revocations);

#endif /* FZN_NODE_REVOKE_H */
