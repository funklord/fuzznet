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
 * THE PROPERTY THIS FILE EXISTS TO HOLD. The value of a cell is a function of
 * the SET of records applied to it, never of the order they arrived in. Two
 * hosts that have admitted the same records answer the same question the same
 * way, whatever order the network handed them over in. The only permitted
 * departure is a record this file REFUSES, and the error code is what reports
 * it -- a refusal is visible, a silent reordering is not.
 *
 * A WRITER IS (ISSUER, STREAM), NOT AN ISSUER. `record.h` numbers each
 * issuer's records from 1 PER STREAM, so `seq` is unique within
 * (issuer, stream) and not within issuer. Two streams of one issuer are
 * therefore exactly as incomparable as two issuers, and comparing their
 * sequences is comparing two rulers with no shared zero.
 *
 * Measured, before `stream` was read here: applying stream 7 seq 100 and then
 * stream 9 seq 100 left stream 7's value, and the same two records in the
 * other order left stream 9's. Same record set, two answers, no error either
 * way -- so two hosts holding identical records held different permissions.
 * That is the property above failing, and it is why the writer is the pair.
 *
 * ORDER WITHIN A WRITER, NEVER ACROSS. A later statement from the SAME
 * (issuer, stream) supersedes. A statement about something already set is,
 * from a DIFFERENT issuer, a **conflict**; from a different stream of the
 * SAME issuer, **cross-stream contention**. Both are reported and neither is
 * resolved.
 *
 * REFUSING TO RESOLVE A CONFLICT IS THE POINT, and it is not indecision.
 * Picking a winner needs a rule -- highest priority, lowest key, most recent
 * clock -- and every such rule is one consumer's policy. Silently taking the
 * newest would mean any authorised issuer could overwrite any other's
 * settings and nobody would see it happen; silently keeping the oldest is
 * first-writer-wins, which is equally a policy and quietly freezes a value
 * nobody can change. So `fzn_state_apply` reports the contention and changes
 * nothing, and a consumer that HAS a rule applies it and calls
 * `fzn_state_resolve`, which is deliberate in the way `fzn_journal_anchor` is
 * deliberate. Most consumers will never see a CONFLICT: a subject with a
 * single writer cannot conflict.
 *
 * THE KEY IS (SUBJECT, KIND), AND THE STREAM IS NOT PART OF IT. The stream is
 * stored for ordering and writer identity, and a cell is still found by
 * subject and kind alone. Keying by (subject, kind, stream) was rejected
 * twice over: `fzn_state_get` would no longer know which of several cells is
 * the value, and -- the serious half -- two DIFFERENT issuers writing on
 * different streams would land in different cells and both succeed, so no
 * conflict would ever be reported again. That is the security property of
 * this file, deleted by a lookup change.
 *
 * A CELL IS A REGISTER HOLDING (WRITER, SEQ, VALUE-OR-ABSENCE), MERGED BY
 * MAX-SEQ WITHIN ONE WRITER, AND `fzn_state_clear` IS AN APPLY WHOSE VALUE IS
 * ABSENCE. One rule, not two: a cleared cell keeps its subject, kind, issuer,
 * stream and the clearing sequence, and a later record meets exactly the same
 * decision table a live cell offers.
 *
 * That is why clearing is a tombstone rather than an erasure. Measured, when
 * `fzn_state_clear` wiped the entry: a record fifty sequences BELOW the clear
 * was accepted afterwards and set the value again, because with the sequence
 * gone there was nothing left to call it stale. A revocation that any replay
 * undoes is not a revocation. Keeping the sequence is what refuses the
 * replay, and keeping the writer is what still refuses a stranger.
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
	/* No room for another subject, and no tombstone left to forget. A LIVE
	 * setting is refused rather than evicted: dropping one to make room for
	 * another silently reverts it to whatever a consumer's default is,
	 * which is the kind of change nobody can trace back to the moment it
	 * happened. */
	FZN_STATE_ERR_FULL = -2,
	/* An older statement from the writer that already holds this. Not a
	 * fault -- a re-delivered record produces one -- and distinguished from
	 * OK so a caller can tell a change from an echo. */
	FZN_STATE_ERR_STALE = -3,
	/* A different ISSUER already holds this subject and kind. See the
	 * header: reported, never resolved here. */
	FZN_STATE_ERR_CONFLICT = -4,
	/* Nothing is set for this subject and kind. */
	FZN_STATE_ERR_ABSENT = -5,
	/* The same issuer already holds this subject and kind, from one of its
	 * OTHER streams. Their sequences are numbered independently, so there
	 * is nothing to compare and this file will not invent an order.
	 *
	 * NOT FOLDED INTO CONFLICT, deliberately, though both mean "two writers
	 * and no way to order them". A cross-ISSUER conflict is exceptional --
	 * a subject with a single writer cannot produce one -- so a consumer
	 * can reasonably alarm on it. Cross-STREAM contention is SYSTEMATIC for
	 * a consumer that lays its streams out so that two of them touch one
	 * subject: it will see this constantly and correctly. Folding the two
	 * would bury the rare alarmable case inside a common expected one,
	 * which takes away the exact thing CONFLICT exists to give. */
	FZN_STATE_ERR_CROSS_STREAM = -6,
} fzn_state_err_t;

/* One cell.
 *
 * `issuer`, `stream` and `seq` are the writer and its position, kept so that
 * a caller can see WHO set it and HOW RECENTLY -- which is what makes
 * contention explicable rather than merely detected.
 *
 * `live` is 0 for a tombstone: a cell that has been cleared, still naming its
 * writer and the sequence that cleared it, with `body` NULL and `body_len`
 * zero. `fzn_state_get` does not return one and `fzn_state_count` does not
 * count one.
 *
 * `stream` costs nothing here. Measured on x86-64 before and after it was
 * added: `sizeof(fzn_state_entry_t)` is 104 both ways, because there was a
 * four-byte hole between `issuer` and the eight-byte-aligned `seq` and the
 * new field fills it. That is a note about this layout on this machine and
 * not a promise -- nothing in this library depends on the number, so there is
 * no static assertion to break someone's 32-bit build over. */
typedef struct fzn_state_entry {
	uint8_t subject[FZN_SUBJECT_LEN];
	uint32_t kind;
	uint32_t stream;
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
	uint64_t forgotten;
} fzn_state_t;

/* Point a state at caller-owned entries. */
fzn_state_err_t fzn_state_init(fzn_state_t *state, fzn_state_entry_t *entries, size_t capacity);

/* Make this record the current value for its subject and kind.
 *
 * The record is not verified and not authorised here; both are the caller's,
 * and both must have happened already. */
fzn_state_err_t fzn_state_apply(fzn_state_t *state, const fzn_record_t *record);

/* Apply a record over an existing cell held by a DIFFERENT writer.
 *
 * The escape hatch for a consumer that has a contention rule and has applied
 * it. Separate from `fzn_state_apply` so that resolving contention is always
 * a thing somebody wrote, never something that happened. It overrides both
 * kinds -- a different issuer and a different stream of the same issuer --
 * because they are the same problem and a consumer with a rule for one has
 * had to answer the other.
 *
 * IDEMPOTENT, AND `FZN_STATE_ERR_STALE` IS THE ORDINARY ANSWER on a host that
 * already holds the winner. A rule is applied across a whole network, and
 * some hosts will have heard the winning writer first and be right already --
 * so a caller that treats anything but OK as failure will report a fault on
 * exactly the hosts that had nothing wrong with them. Found by running a
 * uniform rule across a simulated network, where half the hosts answered
 * STALE because they were already correct. */
fzn_state_err_t fzn_state_resolve(fzn_state_t *state, const fzn_record_t *record);

/* Forget a subject and kind, leaving a tombstone.
 *
 * Deletion has no meaning at this layer -- a consumer that wants a record to
 * mean "unset" maps a `kind` to that and calls this with the record that says
 * so. The cell keeps that record's issuer, stream and sequence, so a replay
 * of anything at or below it is STALE exactly as it would be over a live
 * value, and a later record from the same writer sets the subject again.
 *
 * TAKES THE RECORD, NOT ITS FIELDS. This used to take
 * (subject, kind, issuer, seq) loose, which is two adjacent uint32 arguments
 * and two adjacent 32-byte arrays -- either pair swaps at a call site with
 * nothing to say so, and adding `stream` would have made the first pair a
 * triple. The record already carries every field, and it is the object the
 * caller has.
 *
 * A clear against a subject with no cell is `FZN_STATE_ERR_ABSENT` and
 * allocates nothing: an absence that nothing has ever written is what a fresh
 * state is full of, and spending a slot to say so would let a stream of
 * clears fill a state that holds no values. It is the same position a
 * consumer is in when a tombstone has been forgotten for capacity, and the
 * fail-safe argument there covers it -- see `fzn_state_forgotten`. */
fzn_state_err_t fzn_state_clear(fzn_state_t *state, const fzn_record_t *record);

/* The current value, or NULL. NULL for a tombstone as well as for a subject
 * nothing has ever set: a caller asking what a subject says must not have to
 * know that this file remembers who unset it. */
const fzn_state_entry_t *fzn_state_get(const fzn_state_t *state,
                                        const uint8_t subject[FZN_SUBJECT_LEN], uint32_t kind);

/* How many subjects are currently set. Tombstones are not counted. */
size_t fzn_state_count(const fzn_state_t *state);

/* How many tombstones have been evicted to make room over this state's life.
 *
 * A tombstone holds a slot, so a state can be full of cells that hold no
 * value. When a NEW subject needs one and there is none, a tombstone is
 * forgotten and counted; a live setting is still never evicted.
 *
 * THE FAIL-SAFE ARGUMENT, which is why the two are not treated alike.
 * Refusing a live write can drop a REVOCATION -- the permission stays granted
 * and nobody is told. Forgetting a tombstone can at worst readmit a replay of
 * a record older than the clear, which `fzn_journal_admit` already refuses on
 * its own account. So the two errors are not symmetric and the eviction
 * policy is not a preference.
 *
 * Counted rather than silent, for the reason `fzn_log_dropped` is: a bound
 * that is being hit and never reported reads exactly like one that is not. */
uint64_t fzn_state_forgotten(const fzn_state_t *state);

/* A short name for `fzn_state_err_t`. Never NULL. */
const char *fzn_state_err_str(fzn_state_err_t err);

#endif /* FZN_STATE_H */
