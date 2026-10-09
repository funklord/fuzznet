/* What a node does with the journal it holds: each object applied to the
 * subsystem that keeps its kind. project.md sec 503, stage 3b of sec 500.
 *
 * `node/journal.h` keeps and moves the estate streams; since sec 502 each
 * record's body is a signed object whole, under its tag. This reads every
 * stream from what has been applied to what has been received and hands each
 * object on:
 *
 *     a grant's hop          to the grant index below
 *     a root change or a     to the roots (`fzn_node_roots_learn`)
 *       setting of k, or a root's retention setting
 *     a vote, a withdrawal,  to `fzn_node_votes_take`, with the signer's
 *       a confirmation, an     chain rebuilt from the index -- the
 *       admin's retention      admission the retired vote stream's items
 *       setting, a roster      took, sec 505
 *       record, a succession
 *
 * CHAINS ARE NOT CARRIED, THEY ARE REBUILT. A grant is itself an act, logged
 * by its grantor (sec 497) and so in the grantor's stream; the index holds
 * every grant applied, and a signer's chain is walked up through it, grantee
 * to grantor, until a root. A root needs none.
 *
 * AN OBJECT WHOSE CHAIN IS NOT HERE YET WAITS, its stream stopped there and
 * not marked applied, because a grant in another stream may arrive later in
 * this round or the next. One that has a chain and is still refused is marked
 * applied and skipped: asking again would refuse it again. Passes repeat
 * within a round while one makes progress, so a grant applied in one stream
 * releases a vote waiting in another.
 *
 * APPLYING IS IDEMPOTENT, as every subsystem's admission is, so a restart --
 * whose journal replays with nothing yet marked applied -- applies everything
 * again and changes nothing.
 *
 * ONE INDEX PER JOURNAL. A grant is marked applied in the journal once, and
 * only the context that applied it holds it in its index, so a second
 * context over the same journal never sees it and every vote under it waits
 * for ever. The daemon keeps one context; a caller wanting another over the
 * same journal carries the index across (sec 505).
 */

#ifndef FZN_NODE_APPLY_H
#define FZN_NODE_APPLY_H

#include <stddef.h>
#include <stdint.h>

#include "journal.h"
#include "revoke.h"
#include "../state/setting.h"

/* The most grants the index holds: every pairing and admin grant in the
 * estate, each once. */
#define FZN_NODE_APPLY_GRANTS_MAX 256u

/* The most passes over the streams one round makes. Each pass applies
 * whatever the last one released; this many releases a chain as deep as a
 * chain may be, with one to spare. */
#define FZN_NODE_APPLY_PASSES (FZN_CHAIN_MAX_HOPS + 1u)

typedef struct fzn_node_grant {
	uint8_t hop[FZN_HOP_LEN];
	uint8_t grantor[FZN_PUBKEY_LEN];
	uint8_t grantee[FZN_PUBKEY_LEN];
	fzn_cap_id_t capability;
} fzn_node_grant_t;

struct fzn_node_roots;
struct fzn_node_roster;
struct fzn_node_successions;

typedef struct fzn_node_apply {
	fzn_node_journal_t *journal;
	fzn_revocation_store_t *revocations;
	struct fzn_node_roots *roots;        /* NULL: the pinned root alone */
	struct fzn_node_roster *roster;      /* NULL: roster records refused */
	struct fzn_node_successions *successions;  /* NULL: successions refused */
	struct fzn_node_settings *settings;  /* NULL: settings refused, sec 540 */
	/* The clock a member chain's expiry is judged at; NULL judges none
	 * expired. */
	uint64_t (*now)(void);
	const fzn_persist_ops_t *store;
	const uint8_t *root;                 /* the pinned root */
	const fzn_cap_id_t *capability;      /* a member's grant */
	const fzn_cap_id_t *admin_capability;  /* an admin's grant, or NULL */
	const fzn_sign_ops_t *sign;
	const fzn_hash_ops_t *hash;
	fzn_node_grant_t grants[FZN_NODE_APPLY_GRANTS_MAX];
	size_t grants_used;
} fzn_node_apply_t;

typedef struct fzn_node_apply_tally {
	size_t applied;   /* objects a subsystem took */
	size_t grants;    /* grants indexed */
	size_t refused;   /* objects refused with a chain, or of no kind applied */
	size_t waiting;   /* streams stopped at an object whose chain is not here */
} fzn_node_apply_tally_t;

/* ONE ROUND: every followed stream, from applied to received, in passes until
 * one makes no progress. MALFORMED for a context missing its journal, store,
 * revocations, root, capability, signer or hash; NOT_SAVED when a subsystem
 * admitted an object and could not keep it; REFUSED when the revocation
 * store is full, the object left unmarked for the next round. */
fzn_node_pull_err_t fzn_node_apply_round(fzn_node_apply_t *ap, fzn_node_apply_tally_t *tally);

typedef enum fzn_node_apply_outcome {
	FZN_NODE_APPLY_APPLIED = 0,
	/* Its signer's chain is not here yet; offered again, it may apply. */
	FZN_NODE_APPLY_WAITING = 1,
	/* Judged and refused, or of no kind applied. */
	FZN_NODE_APPLY_REFUSED = 2,
	/* Admitted and not kept: the store would not, or a table is full. */
	FZN_NODE_APPLY_NOT_SAVED = 3
} fzn_node_apply_outcome_t;

/*
 * ONE OBJECT ALONE, sec 550: an estate object that came by reconciliation
 * rather than in a journal record, judged exactly as one in a record is --
 * by the same switch, under the chain of its OWN signer, read from the
 * object (a revocation's issuer, every other kind's byte 2). A record's
 * issuer and its object's signer are one key on every honest path, so the
 * object needs no record around it to say who signed it.
 */
fzn_node_apply_outcome_t fzn_node_apply_object(fzn_node_apply_t *ap, const uint8_t *object,
                                               size_t len, fzn_node_apply_tally_t *tally);

/*
 * THE GRANT INDEX FROM THE STORE, sec 545: every grant kept in slot
 * FZN_PERSIST_GRANT added to the index, so chains are rebuilt without
 * replaying a journal that may have been cut. Called before the first
 * round. 1 with `*loaded` counting the grants added; 0 when the store
 * cannot list, holds more than FZN_NODE_APPLY_GRANTS_MAX, or a row is not a
 * grant -- refused rather than half loaded.
 */
int fzn_node_apply_load_grants(fzn_node_apply_t *ap, size_t *loaded);

/* A SIGNER'S CHAIN for `capability`, from the index: the grants walked up
 * from `key` to a root, root first, into `hops`. 1 with `*hop_count` set --
 * zero for a root -- or 0 when the index does not reach a root from `key`. */
int fzn_node_apply_chain(const fzn_node_apply_t *ap, const uint8_t key[FZN_PUBKEY_LEN],
                         const fzn_cap_id_t *capability,
                         uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN], size_t *hop_count);

/* WHETHER `key` HOLDS `capability`, sec 567: a root does; any other key by a
 * chain from a root among the grants this node indexed, verified now --
 * expired or revoked, it does not. */
int fzn_node_apply_holds(const fzn_node_apply_t *ap, const uint8_t key[FZN_PUBKEY_LEN],
                         const fzn_cap_id_t *capability);

/*
 * A SETTER'S RANK for a setting of `scope` about `about`, sec 540: ROOT for a
 * root; ADMIN for a key whose admin chain, from the index, the revocation
 * store admits; HOST for a key setting its own host-scoped cell whose member
 * chain verifies. 1 with `*rank` set; 0 when no chain reaches a root yet, so
 * the setting waits; -1 when a chain is here and grants neither. A node's own
 * write is judged by this before it is written (`node/settings.h`).
 */
int fzn_node_apply_rank(const fzn_node_apply_t *ap, const uint8_t key[FZN_PUBKEY_LEN],
                        fzn_scope_t scope, const uint8_t about[FZN_SUBJECT_LEN],
                        fzn_setting_rank_t *rank);

#endif /* FZN_NODE_APPLY_H */
