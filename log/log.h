/* A bounded log of records, and what to say when retention has eaten one.
 *
 * The first piece absorbed from fuzzypickles' log subsystem (project.md sec
 * 5). What came across is the part their own measurement identified as
 * general -- **sequencing, retention and serving a range** -- and what did
 * not is the part it identified as specific: `append_log.c`'s line format,
 * `"<seq> <escaped text>"`, which is an encoding choice and the one netcfgd
 * would reject, its stated product property being greppable JSON. A body
 * here is opaque bytes, as everywhere else in `record/`.
 *
 * A STREAM IS (ISSUER, STREAM) HERE TOO, so one issuer's telemetry and its
 * configuration history age out independently rather than competing for the
 * same slots -- and a recipient entitled to one and not the other keeps a
 * contiguous position in what it may see. See `record/record.h`.
 *
 * A LOG EVICTS. THE JOURNAL AND THE STATE DO NOT, and the difference is the
 * design, not an inconsistency:
 *
 *   - `record/journal.h` refuses a full journal, because forgetting an issuer
 *     readmits everything it ever sent.
 *   - `state/state.h` refuses a full state, because dropping a setting
 *     reverts it to a default nobody can trace.
 *   - A log is a **stream**, and losing its oldest entries is its normal
 *     condition rather than a failure. A log that refused to accept anything
 *     once full would stop recording exactly when something interesting
 *     started happening.
 *
 * So this evicts the oldest and counts what it dropped. What it does NOT do
 * is remember where it now starts. This comment claimed it did for as long as
 * the module has existed, `fzn_log_t` never had such a field, and
 * `fzn_log_get` derived GONE from `fzn_log_range` -- the oldest entry
 * CURRENTLY HELD -- which is wrong in both directions:
 *
 *   - Everything for a stream evicted leaves `first == 0`, so the guard fell
 *     through and the answer was ABSENT. The peer then asks for ever, which
 *     is precisely the failure the next paragraph says this module exists to
 *     prevent.
 *   - A sequence never seen but below the oldest held answered GONE, with
 *     `dropped == 0`. The consumer calls `fzn_journal_anchor` and accepts an
 *     IRREVERSIBLE loss that never happened.
 *   - A hole in the middle answered ABSENT for something evicted, since
 *     append takes any order and eviction is by append order across every
 *     stream in the log.
 *
 * `dropped` could not have rescued it either: it is one count for the whole
 * log, it does not say which sequences went, and `fzn_log_get` never read it.
 * It is a health number, not an answer.
 *
 * WHY "GONE" IS THE POINT. `record/sync.h` plans a fetch from what a peer
 * says it holds, and `record/journal.h` refuses a jump so that a hole is
 * never silently accepted. Put those together without this and a host that
 * fell far behind asks for a sequence nobody has any more, for ever, and
 * neither side can tell that from a lost datagram. `GONE` is what turns that
 * into a decision: the consumer re-anchors (`fzn_journal_anchor`) and accepts
 * that it missed some, deliberately.
 *
 * WHERE GONE COMES FROM: THE JOURNAL'S POSITION, AND NO NEW STATE HERE.
 * `record/journal.h` already keeps `received` per (issuer, stream) -- the
 * highest CONTIGUOUS sequence this host has taken in -- it is already
 * bounded, and it already refuses rather than evicting. That number is
 * exactly the line between the two answers:
 *
 *   seq <= received, and this log does not hold it  ->  evicted   ->  GONE
 *   seq >  received                                 ->  not seen  ->  ABSENT
 *
 * Exact, O(1), and it answers the two cases nothing derived from what is
 * still held can answer: a HOLE IN THE MIDDLE, which eviction by append order
 * produces as soon as two streams share a log, and a HOLE AT THE TOP, which
 * catch-up back-fill produces for the same reason.
 *
 * A PER-(ISSUER, STREAM) FLOOR TABLE WAS DESIGNED AND THEN OVERTURNED, and it
 * is recorded here so that nobody rebuilds it. A floor is monotone and can
 * never shrink, so a floor the table had to forget is a lost GONE -- and
 * `stream` is a uint32 the issuer picks freely, so ONE authorised issuer
 * mints four billion floors at one record each. That is the exhaustion
 * `record/journal.h` closed by refusing to adopt an issuer implicitly, one
 * level WORSE rather than one level down: a journal entry costs an attacker a
 * whole stream, a floor costs it a single record. And a prefix floor cannot
 * express a hole at the top at all, so it would still have been wrong.
 *
 * THE POSITION IS A PARAMETER, NOT A CONVENTION, and that was the decision to
 * make here. `fzn_log_get` takes the journal and will not answer without one.
 * The alternative was to leave the signature alone, keep returning ABSENT,
 * and document a two-call protocol in which the CONSUMER consults
 * `fzn_journal_next` -- which keeps the two modules independent, which this
 * header used to prize. It was rejected on three grounds:
 *
 *   - A caller that forgets the second call gets ABSENT, which is a
 *     legitimate answer. Nothing can distinguish "correctly absent" from "did
 *     not ask": not a test, not the style gate, not review. A wrong answer
 *     that is indistinguishable from a right one is not one anybody finds.
 *   - This tree has already been bitten by a protection held by convention.
 *     `record/sync.h` asserted that "record/journal.h already makes adopting
 *     an issuer deliberate", which was true of the door sync guarded and
 *     false of the one beside it; a PUSHED record walked through the gap
 *     until somebody measured it. Two modules each believing the other holds
 *     a property is the shape being avoided.
 *   - The comparison above is one line, and it is the line an off-by-one gets
 *     wrong. Written here it is written once and tested once. Written at
 *     every call site it is tested nowhere.
 *
 * The coupling it costs was measured before it was accepted, and it is one
 * way: `record/journal.h` includes `record/record.h` and nothing else of
 * ours, this header already included `record/record.h`, and nothing under
 * `record/` includes this file -- so there is no cycle to break. A NULL
 * journal is MALFORMED rather than "no position known", because an optional
 * parameter is the convention above wearing a parameter's clothes: it
 * compiles, it answers ABSENT, and nobody can tell.
 *
 * ONE SEQUENCE AT THE VERY TOP IS ANSWERED CONSERVATIVELY. The position is
 * read through `fzn_journal_next`, the accessor `record/journal.h` publishes,
 * rather than by reaching into its entries: reading `received` directly means
 * copying its keyed lookup, and what "highest contiguous" means is that
 * module's to define rather than this one's to re-derive. `next` SATURATES --
 * it answers UINT64_MAX for a stream that has run to the top, rather than
 * wrapping to the reserved zero -- so `next == UINT64_MAX` cannot tell
 * `received == UINT64_MAX - 1` from `received == UINT64_MAX`. This module
 * takes ABSENT for that one sequence, which is the safe half of the
 * ambiguity: a false ABSENT costs another request, while a false GONE costs
 * an `fzn_journal_anchor` nobody can undo. Closing it needs an accessor
 * `record/journal.h` does not have, and adding one is that module's to do.
 *
 * A HOLE IN A LOG IS TOLERABLE AND A HOLE IN A PERMISSION STREAM IS NOT, and
 * this library needs no flag for that. fuzzypickles' append log takes any
 * entry whose sequence exceeds its high-water mark, so a jump loses the
 * entries between and it does not mind. `record/journal.h` refuses the jump.
 * A log consumer that accepts the loss calls `fzn_journal_anchor`, which is
 * deliberate; a permission consumer never does. **The existing API already
 * expresses both**, which is why nothing here takes a policy argument.
 *
 * NO `live` FLAG, AND ITS ABSENCE IS THE SAME FINDING AS THE MISSING
 * DEAD-SLOT SCAN. One was here, copied from `state/`, where entries genuinely
 * die because `fzn_state_clear` kills them. Nothing here ever marks an entry
 * dead: a log has no clear, only eviction, and eviction overwrites in place.
 * So every entry below `used` was live by construction, the flag carried no
 * information, and three filters tested it on every comparison.
 *
 * It was in this public struct, so a consumer could read it -- and would have
 * read `1` for ever. Removing it is the honest version. If a `forget` ever
 * arrives, the flag and the scan come back together, because that is when
 * either starts meaning anything.
 *
 * THE BODIES ARE NOT COPIED, as in `state/`: an entry points at the caller's
 * bytes and the caller must keep them alive for as long as the entry does.
 * An entry that is evicted stops referring to anything.
 */

#ifndef FZN_LOG_H
#define FZN_LOG_H

#include "../record/journal.h"
#include "../record/record.h"

#include <stddef.h>
#include <stdint.h>

typedef enum fzn_log_err {
	FZN_LOG_OK = 0,
	FZN_LOG_ERR_MALFORMED = -1,
	/* Already held. A re-delivery produces one and it is not a fault. */
	FZN_LOG_ERR_DUPLICATE = -2,
	/* Retention removed it: the sequence is at or below the journal's
	 * `received` for this stream and this log no longer holds it. The
	 * answer that lets a lagging peer stop asking. */
	FZN_LOG_ERR_GONE = -3,
	/* Not held, and not evicted either -- above the journal's `received`,
	 * so it has not arrived here yet and asking again may well help. */
	FZN_LOG_ERR_ABSENT = -4,
} fzn_log_err_t;

typedef struct fzn_log_entry {
	uint8_t issuer[FZN_PUBKEY_LEN];
	uint32_t stream;
	uint64_t seq;
	uint64_t stamp; /* append order, so eviction needs no clock */
	const uint8_t *body;
	size_t body_len;
	uint32_t kind;
} fzn_log_entry_t;

typedef struct fzn_log {
	fzn_log_entry_t *entries;
	size_t capacity;
	size_t used;
	uint64_t next_stamp;
	uint64_t dropped;
} fzn_log_t;

/* Point a log at caller-owned entries. */
fzn_log_err_t fzn_log_init(fzn_log_t *log, fzn_log_entry_t *entries, size_t capacity);

/* Append a record, evicting the oldest if there is no room.
 *
 * Eviction is by APPEND ORDER rather than by sequence or by time: sequences
 * are per issuer and do not order two issuers against each other, and a clock
 * is something this library does not consult for ordering anywhere. */
fzn_log_err_t fzn_log_append(fzn_log_t *log, const fzn_record_t *record);

/* The entry for this issuer and sequence, judged against a journal position.
 *
 * `journal` says where this host has got to for the same (issuer, stream),
 * and it is what separates the two failures: `FZN_LOG_ERR_GONE` when the
 * sequence is at or below `received` and this log no longer holds it,
 * `FZN_LOG_ERR_ABSENT` when it is above. The distinction is the whole reason
 * a caller asks, and the header comment says why the position is a parameter
 * rather than a second call the caller is trusted to remember.
 *
 * A NULL journal is `FZN_LOG_ERR_MALFORMED`, and so is one whose `used` runs
 * past its capacity. `fzn_journal_next` answers 1 for a corrupt journal,
 * which is also its answer for a stream nobody follows, so a log that took
 * that at face value would call every eviction ABSENT and put the peer back
 * into the ask-for-ever loop this module exists to break. */
fzn_log_err_t fzn_log_get(const fzn_log_t *log, const fzn_journal_t *journal,
                           const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream, uint64_t seq,
                           const fzn_log_entry_t **out);

/* What this log still holds for an issuer. Both are zero when it holds
 * nothing from it.
 *
 * NOT A RETENTION BOUNDARY, and it is worth saying because `fzn_log_get`
 * treated it as one and was wrong in three separate ways. `first` is the
 * oldest entry PRESENT: it is zero for a stream that has been evicted
 * entirely, it sits above any hole eviction left in the middle, and it says
 * nothing at all about what this host received. Whether a sequence is gone or
 * has yet to arrive is `fzn_log_get`'s question, and it needs a journal to
 * answer it. */
void fzn_log_range(const fzn_log_t *log, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream,
                   uint64_t *first, uint64_t *last);

/* Entries after `since`, oldest first, for answering a peer's request.
 *
 * Oldest first because that is the order a receiver can admit them in:
 * `fzn_journal_admit` advances by one and refuses a jump, so newest-first
 * would be refused entry by entry. */
size_t fzn_log_read_since(const fzn_log_t *log, const uint8_t issuer[FZN_PUBKEY_LEN],
                          uint32_t stream, uint64_t since, const fzn_log_entry_t **out,
                          size_t out_cap);

/* How many entries retention has dropped over this log's life. Exposed
 * because a consumer that is losing entries faster than it serves them wants
 * to know before somebody asks why the history has holes. */
uint64_t fzn_log_dropped(const fzn_log_t *log);

/* A short name for `fzn_log_err_t`. Never NULL. */
const char *fzn_log_err_str(fzn_log_err_t err);

#endif /* FZN_LOG_H */
