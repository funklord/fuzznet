/* A node's contacts as the user's roster, carried between the estate's
 * members. sec 489.
 *
 * WHAT IT CLOSES. The node's contact list (`contact/contact.h`, sec 435) was
 * one node's: a contact added on a laptop never reached the phone in the
 * same estate, and one removed on the phone went on being served by the
 * laptop. `roster/roster.h` (secs 388, 395, 413) is the replicated form of
 * exactly that list -- removal that stays removed under any concurrency,
 * suspension at once, retirement by k distinct writers -- and until now only
 * fuzzypickles carried it. The holder decided 2026-10-06 that the node's
 * contacts BECOME roster records: an add and a removal are roster records
 * this node signs, and members pull them from any peer as votes travel
 * (sec 399).
 *
 * TWO THINGS, KEPT APART. The roster says whether a key is a contact --
 * ACTIVE, SUSPENDED, RETIRED or ABSENT, judged at read time against the
 * revocations this node holds and the estate's k. The contact list goes on
 * holding a NAME for a key, which is this node's: a name is a setting, and
 * roster settings are laid out and refused until their resolution is
 * decided (`roster.h`), so names do not travel. A contact added on another
 * member arrives here with a name made from its key, `c_` and the first 8
 * hex digits, which `add contact NAME KEY` renames.
 *
 * WHO WRITES: this node as the estate's root, alone, or as a member on its
 * chain from the root for the capability the remote hop grants
 * (`config.remote_capability`) -- the chain it pairs and revokes with. A
 * node that is neither writes nothing, and its contacts stay its own.
 *
 * KEPT IN CORE SLOT 28, each record with its writer's chain under the
 * record's hash, so a restart re-admits exactly what was admitted. Core,
 * because a removal rolled back is a removed contact served again: the
 * holder's test for core.
 *
 * WHAT IS NOT HERE. A retired contact's data is not deleted after a hold
 * period (sec 394's decision 5): the holder decided 2026-10-06 that a
 * removed contact's shares stay (sec 478), and deleting on retirement is
 * left until it is asked for.
 */

#ifndef FZN_NODE_ROSTER_H
#define FZN_NODE_ROSTER_H

#include <stddef.h>
#include <stdint.h>

#include "pair.h"
#include "provision.h"
#include "../persist/persist.h"
#include "../roster/roster.h"
#include "../session/random.h"

/* Incarnations a node holds: two for each of FZN_CONTACTS_MAX contacts, for
 * a contact removed and added again. */
#define FZN_NODE_ROSTER_ENTRIES 128u
/* Writers: the estate's members that write contacts, each chain once. */
#define FZN_NODE_ROSTER_WRITERS 32u
/* Records a node keeps and serves: the vote stream lists each of its slots
 * up to FZN_NODE_REVOCATIONS_MAX, which this matches -- an add and a removal
 * or two for each of FZN_CONTACTS_MAX contacts, with room for re-adds. */
#define FZN_NODE_ROSTER_RECORDS 256u

typedef enum fzn_node_roster_err {
	FZN_NODE_ROSTER_OK = 0,
	FZN_NODE_ROSTER_MALFORMED = -1,
	/* This node is not the root and holds no chain for the capability, so
	 * it writes no record anybody would admit. */
	FZN_NODE_ROSTER_NO_STANDING = -2,
	/* The record would not admit: its signature, its writer's standing, a
	 * conflicting add, or a table full. */
	FZN_NODE_ROSTER_REFUSED = -3,
	/* Admitted and not saved: in force until a restart. */
	FZN_NODE_ROSTER_NOT_SAVED = -4,
	/* Removing a key that has no active incarnation here. */
	FZN_NODE_ROSTER_ABSENT = -5,
	/* The store would not list or read. */
	FZN_NODE_ROSTER_STORE = -6,
	/* In force and saved, and not in this root's log: it would fall at the
	 * root's removal (sec 413). */
	FZN_NODE_ROSTER_NOT_LOGGED = -7
} fzn_node_roster_err_t;

const char *fzn_node_roster_err_str(fzn_node_roster_err_t err);

typedef struct fzn_node_roster {
	fzn_roster_t roster;
	fzn_roster_entry_t entries[FZN_NODE_ROSTER_ENTRIES];
	fzn_roster_writer_t writers[FZN_NODE_ROSTER_WRITERS];
	uint8_t root[FZN_PUBKEY_LEN];
	fzn_cap_id_t capability;
	fzn_roster_authority_t authority;
	/* What a record is filed under in slot 28: its hash. */
	const fzn_hash_ops_t *hash;
	/* TOLD OF EACH RECORD THIS NODE WRITES, once it is in force and saved,
	 * or NULL. sec 413 asks a node writing as a root to log each record
	 * as its act, kind FZN_ROOT_ACT_ROSTER, so a removal of that root
	 * keeps what it wrote before the cut; `fzn_node_admin_log_roster` is
	 * that. 1 when done, or nothing to do. */
	int (*wrote)(void *ctx, const uint8_t *record, size_t len);
	void *wrote_ctx;
} fzn_node_roster_t;

/* `root` the estate's root this node verifies against, `capability` the one
 * a writer's chain must carry, `sign` the verifier, and -- both or neither --
 * `roots` the estate's root set and `hash`, as `fzn_roster_authority_t`
 * takes them. */
fzn_node_roster_err_t fzn_node_roster_init(fzn_node_roster_t *nr,
                                           const uint8_t root[FZN_PUBKEY_LEN],
                                           const fzn_cap_id_t *capability,
                                           const fzn_sign_ops_t *sign,
                                           const fzn_root_ops_t *roots,
                                           const fzn_hash_ops_t *hash);

/* At start: every record slot 28 holds, admitted with its chain. A record
 * that will not admit is skipped and not counted -- one written under a root
 * this node has since left, say -- since refusing to start over it would
 * cost every contact this node has; `*count` is what admitted. */
fzn_node_roster_err_t fzn_node_roster_load(fzn_node_roster_t *nr,
                                           const fzn_persist_ops_t *store, size_t *count);

/* A record and its writer's chain from a peer: admitted, then saved. */
fzn_node_roster_err_t fzn_node_roster_learn(fzn_node_roster_t *nr,
                                            const fzn_persist_ops_t *store,
                                            const uint8_t *record, size_t record_len,
                                            const uint8_t (*hops)[FZN_HOP_LEN],
                                            size_t hop_count);

/* THIS NODE'S ACT: an add of `subject` -- a new incarnation, from `rng` --
 * or, `add` 0, a removal of its active incarnation as `revocations` and `k`
 * judge it (ABSENT when it has none to remove). Signed by `id`, on
 * `authority` as a member or alone as the root (`authority` NULL), admitted
 * and saved. An add of a subject already ACTIVE writes nothing and answers
 * OK. A removal of a subject SUSPENDED by another member removes that
 * incarnation too: that is the second member confirming, and k of them
 * retire it (`roster.h`). */
fzn_node_roster_err_t fzn_node_roster_write(fzn_node_roster_t *nr,
                                            const fzn_persist_ops_t *store,
                                            const fzn_node_identity_t *id,
                                            const fzn_node_authority_t *authority,
                                            const fzn_random_ops_t *rng,
                                            const uint8_t subject[FZN_PUBKEY_LEN], int add,
                                            const fzn_revocation_store_t *revocations,
                                            size_t k);

/* WHAT `subject` IS HERE: ACTIVE when any incarnation is; otherwise RETIRED
 * when any is, SUSPENDED when any is, ABSENT when none is held or every
 * writer is revoked. */
fzn_roster_state_t fzn_node_roster_standing(const fzn_node_roster_t *nr,
                                            const uint8_t subject[FZN_PUBKEY_LEN],
                                            const fzn_revocation_store_t *revocations,
                                            size_t k);

/* Every subject with an incarnation held, once each, at most `cap`. */
size_t fzn_node_roster_subjects(const fzn_node_roster_t *nr, uint8_t (*out)[FZN_PUBKEY_LEN],
                                size_t cap);

/* THE RECORD FILED UNDER `id` in slot 28, and its writer's chain, as the
 * vote stream serves it. 1 when one reads. */
int fzn_node_roster_get(const fzn_persist_ops_t *store, const uint8_t id[FZN_PUBKEY_LEN],
                        uint8_t record[FZN_ROSTER_MIN_LEN], uint8_t (*hops)[FZN_HOP_LEN],
                        size_t *hop_count);

/* NAMES FOR WHAT ARRIVED, sec 489: every ACTIVE subject the contact list has
 * no name for gets `c_` and the first 8 hex digits of its key -- or more
 * digits, while that name is another key's. `*named` counts them. A subject
 * that is one of `members` (`member` answers 1) is never named: a member is
 * never a contact. */
fzn_node_roster_err_t fzn_node_roster_name_arrivals(const fzn_node_roster_t *nr,
                                                    const fzn_persist_ops_t *store,
                                                    const fzn_revocation_store_t *revocations,
                                                    size_t k,
                                                    int (*member)(void *ctx,
                                                                  const uint8_t *key),
                                                    void *member_ctx, uint64_t now_ms,
                                                    size_t *named);

/* CONTACTS FROM BEFORE, sec 489: every contact the list names whose key has
 * no incarnation held is written as this node's add, so a node upgraded
 * with contacts carries them. A key with any incarnation -- one removed on
 * another member included -- is left as it is. `*written` counts adds. */
fzn_node_roster_err_t fzn_node_roster_carry_names(fzn_node_roster_t *nr,
                                                  const fzn_persist_ops_t *store,
                                                  const fzn_node_identity_t *id,
                                                  const fzn_node_authority_t *authority,
                                                  const fzn_random_ops_t *rng,
                                                  size_t *written);

#endif /* FZN_NODE_ROSTER_H */
