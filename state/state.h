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
 * REFUSED HAS AN EXACT SPELLING, so that the sentence above can be checked
 * rather than believed: a code whose name carries `ERR_` stored nothing, and
 * `FZN_STATE_OK` and `FZN_STATE_ABSENT` both stored. Those are the only two
 * that store. `FZN_STATE_ABSENT` used to be `FZN_STATE_ERR_ABSENT` and used
 * to be a refusal; it is renamed because it no longer refuses, and leaving
 * `ERR_` on it would have made this paragraph's rule the one thing in the
 * file that had to be remembered instead of read.
 *
 * THE CLEAR PATH IS WHERE THIS WAS FALSE, and every gap in it failed in the
 * direction where a revocation does not land. Measured 2026-08-27 over the
 * two-record set { apply(alice, stream 7, seq 5, "GRANT"),
 * clear(alice, stream 7, seq 10, "REVOKE") }:
 *
 *	apply(5)=ok       clear(10)=ok      -> count 0, NULL   (revoked)
 *	clear(10)=ABSENT  apply(5)=ok       -> count 1, "GRANT" (granted)
 *
 * One record set, two permissions, and the refusal was byte-identical to
 * clearing a subject nobody had ever set -- so a consumer could not tell "your
 * revocation was dropped" from "there was nothing to revoke". A clear now
 * lands whether or not the thing it supersedes has arrived; see
 * `fzn_state_clear`. Journal contiguity makes the reordering unreachable
 * within a gated stream, which is not a defence: nothing in this paragraph
 * requires journal gating, and `record.h` names the locally-authored case as
 * this file's ordinary use.
 *
 * FOUR ENTRY POINTS, BECAUSE THERE ARE TWO INDEPENDENT AXES. What is being
 * written is one question -- a value, or absence -- and whose cell is being
 * written is another:
 *
 *	                    set a value        clear to absence
 *	the cell's writer   fzn_state_apply    fzn_state_clear
 *	over another writer fzn_state_resolve  fzn_state_resolve_clear
 *
 * The bottom right was missing until 2026-08-27, and its absence was the
 * second half of the same defect. There was no way to clear a cell held by
 * somebody else: `fzn_state_clear` answered CONFLICT, and `fzn_state_resolve`
 * -- the only call that returned OK -- stored the revocation as a LIVE
 * SETTING, so `fzn_state_get` handed the permission back with the revocation
 * as its value and the subject read as granted, by the revoker. A consumer
 * had no correct call to make.
 *
 * THEY ARE FOUR NAMES RATHER THAN TWO WITH A FLAG, for the reason `chain.h`
 * gives about its pinned root: one function with an optional pin is a
 * function somebody calls without the pin. Overriding another writer is the
 * dangerous half of each axis and it has to be typed out; a caller that wants
 * it names it, and a caller that does not cannot reach it by leaving an
 * argument at its default.
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
 * WHICH OF THOSE TWO A RECORD IS TOLD IS ORDER-DEPENDENT, AND THE COUNTS ARE
 * NOT COMPARABLE ACROSS HOSTS. This is a limit of the design rather than a
 * defect with a fix, and it is written down because the paragraph on
 * `FZN_STATE_ERR_CROSS_STREAM` below builds an alarming policy on the
 * distinction and would otherwise be read as promising more than it can.
 *
 * Measured 2026-08-27 over all six orders of three records at one sequence --
 * alice on stream 1, alice on stream 2, bob -- all naming one subject:
 *
 *	alice/1, alice/2, bob  -> ok, CROSS_STREAM, CONFLICT
 *	bob, alice/1, alice/2  -> ok, CONFLICT,     CONFLICT
 *
 * Two hosts holding that identical record set raise different alarm counts
 * depending on the order the packets arrived in.
 *
 * THE CAUSE IS THE CELL, NOT THE COMPARISON. A cell holds ONE writer, so an
 * arriving record can only be compared against that one, and which writer
 * holds the cell is first-writer-wins among writers that have no shared zero
 * -- which is already this file's documented policy, three paragraphs up, and
 * already makes the VALUE order-dependent in the same case. Converging the
 * two counts would need every writer that ever contended for a cell to be
 * remembered, which is unbounded storage in a module that allocates nothing
 * (sec 2); a bounded loser list would go order-dependent the moment it
 * overflowed, which trades a divergence a consumer can see for one it cannot.
 * So no mechanism was invented for it.
 *
 * WHAT IS SAFE TO RELY ON, and it is what a consumer actually needs: a record
 * from a writer other than the one holding the cell is ALWAYS refused as one
 * of these two, never as `FZN_STATE_ERR_STALE` and never accepted. That is
 * order-independent and is the property that keeps a stranger out. What is
 * not order-independent is which of the two names it, so an alarm keyed on
 * counting CONFLICTs is a per-host figure and comparing two hosts' totals is
 * comparing two rulers again. A consumer wanting a host-comparable alarm has
 * to key it on something it holds itself -- the set of distinct writers it
 * admitted records from for a subject, say -- because this file does not keep
 * one.
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
 * THE BODY IS NOT COPIED, AND IT IS ONE LIFETIME RATHER THAN TWO. Nothing
 * here allocates (sec 2), so an entry points at bytes somebody else owns --
 * and since `record.h` made a record a VIEW over its own encoding, those
 * bytes are the record's. **Keeping the record's buffer alive keeps the body
 * alive**, and there is no second object to track: a caller that holds the
 * buffer a record was opened from has already done everything this file
 * needs. A buffer that goes away leaves an entry pointing at freed memory,
 * and this file has no way to know.
 *
 * That used to be the weaker sentence it could be. A record carried a body
 * POINTER a caller set by hand, beside a `body_len` a caller also set, and
 * the two could disagree with each other and with what was signed -- so a
 * caller had a body to keep alive, a record to keep consistent, and a
 * signature that bound neither.
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
	/* NOT A REFUSAL, AND THE ONE CODE HERE THAT STORED SOMETHING WITHOUT
	 * BEING `FZN_STATE_OK`. A clear arrived for a subject and kind nothing
	 * had set, and it LANDED: a tombstone was created naming the clearing
	 * writer and its sequence, so anything at or below that sequence is
	 * refused afterwards exactly as it would be over a value. This says
	 * what was true before the clear, which is the question a revoker
	 * wants answered -- it has just learnt that the grant it is revoking
	 * had not reached this host, which usually means the journal is behind
	 * or the grant was forgotten for capacity.
	 *
	 * It was `FZN_STATE_ERR_ABSENT` and it did refuse, storing nothing.
	 * That dropped the revocation, and the header records the two orders
	 * that then held two different permissions. The value is unchanged at
	 * -5 so that `fzn_state_err_str`'s pinned code count does not move; the
	 * spelling changed because a code that stores must not read as a code
	 * that refuses.
	 *
	 * A CALLER THAT TREATS ANYTHING BUT OK AS FAILURE will log a fault
	 * here on a clear that worked. That is the noisy direction rather than
	 * the dangerous one, and the mistake has been made in this tree once
	 * already: a simulated network reported a fault on every host that
	 * `fzn_state_resolve` answered STALE, which were the hosts that were
	 * already right. Read the code, do not test it for zero. */
	FZN_STATE_ABSENT = -5,
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
	 * which takes away the exact thing CONFLICT exists to give.
	 *
	 * THE ALARM IS PER HOST, NOT COMPARABLE BETWEEN TWO. Which of these two
	 * codes a given record is told depends on which writer got to the cell
	 * first. The header measures it: two hosts with one record set raised
	 * one CROSS_STREAM and one CONFLICT in one order, and two CONFLICTs in
	 * another. The distinction above is still worth having and every
	 * individual answer is still true; what it will not support is
	 * subtracting one host's totals from another's. */
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
 * IT SETS A VALUE. A consumer holding a record that MEANS "unset" wants
 * `fzn_state_resolve_clear`, not this: passing a revocation here stores it as
 * the subject's live value, which reads as a grant. Named here because that
 * is the mistake this pair made available for as long as the fourth entry
 * point was missing.
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
 * A CLEAR AGAINST A SUBJECT WITH NO CELL TAKES A SLOT AND LEAVES A TOMBSTONE,
 * answering `FZN_STATE_ABSENT` -- which reports what was there before and not
 * a refusal. A revocation that arrives before the grant it supersedes is the
 * whole reason: without the tombstone the clear stored nothing, and the grant
 * then landed behind it and stood. The header has the two orders and the two
 * different permissions they produced.
 *
 * THE EARLIER DESIGN REFUSED IT, on the argument that it "spends a slot to
 * record an absence" and that a stream of clears could fill a state holding
 * no values. The first half is true and is the price; the second half does
 * not survive being weighed against `slot`, which forgets a tombstone before
 * it refuses a new subject. So a state full of tombstones still admits every
 * live setting offered to it, and the flood the argument feared costs
 * evictions rather than service -- while a flood of live records for junk
 * subjects, which the old rule permitted freely, could not be evicted at all
 * and was strictly worse. What the old rule bought was a slot; what it cost
 * was a revocation that silently did not land, and those are not the same
 * size.
 *
 * `FZN_STATE_ERR_FULL` IS STILL POSSIBLE HERE, and it is the one place a
 * clear can fail to land. It needs every slot to hold a LIVE setting, since
 * anything else is evictable. There is no better answer available: the only
 * remaining move would be to evict a live setting, which reverts it to a
 * consumer's default with nothing to trace -- see `fzn_state_forgotten` for
 * why that is the worse of the two. It is at least visible, which is what the
 * header's invariant asks of a departure. */
fzn_state_err_t fzn_state_clear(fzn_state_t *state, const fzn_record_t *record);

/* Clear a cell held by a DIFFERENT writer, leaving that writer's tombstone.
 *
 * `fzn_state_resolve` for the clearing axis, and the fourth of the four
 * entry points the header tabulates. Same escape hatch, same contract, same
 * two kinds of contention overridden -- a different issuer and a different
 * stream of the same issuer -- and the same reason for being its own name
 * rather than a flag on `fzn_state_clear`.
 *
 * WHY IT HAD TO EXIST. Bob revoking alice's grant had no correct call before
 * 2026-08-27. `fzn_state_clear` answered `FZN_STATE_ERR_CONFLICT` and changed
 * nothing, which drops the revocation; `fzn_state_resolve` answered OK and
 * stored bob's revocation as a LIVE setting, so `fzn_state_get` returned it
 * and the subject read as GRANTED, with the revocation as the granted value
 * and bob as the issuer who granted it. Measured, both of them. A consumer
 * following the header's own advice -- "a consumer that HAS a rule applies it
 * and calls `fzn_state_resolve`" -- reached the second of those, which is why
 * this is a gap in the library rather than a mistake available to callers.
 *
 * The header claimed resolve covered both kinds of contention. That was true
 * of setting a value and false of clearing one, and clearing is the direction
 * where being wrong leaves a permission standing.
 *
 * IDEMPOTENT, AND STALE IS AN ORDINARY ANSWER, exactly as for
 * `fzn_state_resolve`: a rule applied across a network meets hosts that are
 * already correct. */
fzn_state_err_t fzn_state_resolve_clear(fzn_state_t *state, const fzn_record_t *record);

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
