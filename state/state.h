/* What is true now, from the records admitted so far.
 *
 * A permission, a rule and a configuration setting are the same object at
 * this layer: a value some issuer set, for some subject, of some kind, and
 * the current one is whichever that issuer set most recently. sec 5 says the
 * SHAPE of a permission graph is configuration rather than design, so this
 * file resolves records into current values and interprets none of them.
 *
 * WHAT THIS ADDS OVER `record/journal.h`. The journal answers "have I got it,
 * and have I applied it" -- positions in a stream. This answers "what does it
 * currently say", which is a different question and the one a consumer asks
 * on every decision. A host that has applied every record still needs
 * somewhere to look up the answer.
 *
 * ORDER WITHIN AN ISSUER, NEVER ACROSS. `record.h` numbers each issuer's
 * records from 1, which totally orders one issuer's statements and orders no
 * two issuers against each other. So a later statement from the SAME issuer
 * supersedes; a statement from a DIFFERENT issuer about something already set
 * is a **conflict**, reported and not resolved.
 *
 * REFUSING TO RESOLVE A CONFLICT IS THE POINT, and it is not indecision.
 * Picking a winner needs a rule -- highest priority, lowest key, most recent
 * clock -- and every such rule is one consumer's policy. Silently taking the
 * newest would mean any authorised issuer could overwrite any other's
 * settings and nobody would see it happen; silently keeping the oldest is
 * first-writer-wins, which is equally a policy and quietly freezes a value
 * nobody can change. So `fzn_state_apply` reports `FZN_STATE_ERR_CONFLICT`
 * and changes nothing, and a consumer that HAS a rule applies it and calls
 * `fzn_state_resolve`, which is deliberate in the way `fzn_journal_anchor` is
 * deliberate. Most consumers will never see one: a subject with a single
 * writer cannot conflict.
 *
 * AUTHORISATION IS NOT HERE. Whether an issuer may set this subject is a
 * capability question, answered by `fzn_chain_verify` against a capability
 * the consumer maps from `kind`. A caller that applies a record it has not
 * authorised has skipped a step this file cannot see -- exactly as
 * `journal.h` cannot see an unverified record being admitted.
 *
 * THE BODY IS NOT COPIED. An entry points at the caller's bytes, as a chain
 * hop points at its signed region, because nothing here allocates (sec 2).
 * **The caller must keep a body alive for as long as the entry refers to
 * it.** A body that goes away leaves an entry pointing at freed memory, and
 * this file has no way to know.
 */

#ifndef FZN_STATE_H
#define FZN_STATE_H

#include "../record/record.h"

#include <stddef.h>
#include <stdint.h>

typedef enum fzn_state_err {
	FZN_STATE_OK = 0,
	FZN_STATE_ERR_MALFORMED = -1,
	/* No room for another subject. Refused rather than evicted: dropping a
	 * setting to make room for another silently reverts it to whatever a
	 * consumer's default is, which is the kind of change nobody can trace
	 * back to the moment it happened. */
	FZN_STATE_ERR_FULL = -2,
	/* An older statement from the issuer that already holds this. Not a
	 * fault -- a re-delivered record produces one -- and distinguished from
	 * OK so a caller can tell a change from an echo. */
	FZN_STATE_ERR_STALE = -3,
	/* A different issuer already holds this subject and kind. See the
	 * header: reported, never resolved here. */
	FZN_STATE_ERR_CONFLICT = -4,
	/* Nothing is set for this subject and kind. */
	FZN_STATE_ERR_ABSENT = -5,
} fzn_state_err_t;

/* One current value. `issuer` and `seq` are kept so that a caller can see WHO
 * set it and HOW RECENTLY -- which is what makes a conflict explicable rather
 * than merely detected. */
typedef struct fzn_state_entry {
	uint8_t subject[FZN_SUBJECT_LEN];
	uint32_t kind;
	uint8_t issuer[FZN_PUBKEY_LEN];
	uint64_t seq;
	const uint8_t *body;
	size_t body_len;
	int live;
} fzn_state_entry_t;

typedef struct fzn_state {
	fzn_state_entry_t *entries;
	size_t capacity;
	size_t used;
} fzn_state_t;

/* Point a state at caller-owned entries. */
fzn_state_err_t fzn_state_init(fzn_state_t *state, fzn_state_entry_t *entries, size_t capacity);

/* Make this record the current value for its subject and kind.
 *
 * The record is not verified and not authorised here; both are the caller's,
 * and both must have happened already. */
fzn_state_err_t fzn_state_apply(fzn_state_t *state, const fzn_record_t *record);

/* Apply a record over an existing entry held by a DIFFERENT issuer.
 *
 * The escape hatch for a consumer that has a conflict rule and has applied
 * it. Separate from `fzn_state_apply` so that resolving a conflict is always
 * a thing somebody wrote, never something that happened. */
fzn_state_err_t fzn_state_resolve(fzn_state_t *state, const fzn_record_t *record);

/* Forget a subject and kind, if the issuer clearing it is the one that set it
 * and its sequence is newer. Deletion has no meaning at this layer -- a
 * consumer that wants a record to mean "unset" maps a `kind` to that and
 * calls this. */
fzn_state_err_t fzn_state_clear(fzn_state_t *state, const uint8_t subject[FZN_SUBJECT_LEN],
                                 uint32_t kind, const uint8_t issuer[FZN_PUBKEY_LEN],
                                 uint64_t seq);

/* The current entry, or NULL. */
const fzn_state_entry_t *fzn_state_get(const fzn_state_t *state,
                                        const uint8_t subject[FZN_SUBJECT_LEN], uint32_t kind);

/* How many subjects are currently set. */
size_t fzn_state_count(const fzn_state_t *state);

/* A short name for `fzn_state_err_t`. Never NULL. */
const char *fzn_state_err_str(fzn_state_err_t err);

#endif /* FZN_STATE_H */
