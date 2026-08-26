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
 * So this evicts the oldest, counts what it dropped, and -- the part that
 * matters -- **remembers where it now starts**, so that a peer asking for
 * something evicted is told `FZN_LOG_ERR_GONE` rather than being left to
 * wonder.
 *
 * WHY "GONE" IS THE POINT. `record/sync.h` plans a fetch from what a peer
 * says it holds, and `record/journal.h` refuses a jump so that a hole is
 * never silently accepted. Put those together without this and a host that
 * fell far behind asks for a sequence nobody has any more, for ever, and
 * neither side can tell that from a lost datagram. `GONE` is what turns that
 * into a decision: the consumer re-anchors (`fzn_journal_anchor`) and accepts
 * that it missed some, deliberately.
 *
 * A HOLE IN A LOG IS TOLERABLE AND A HOLE IN A PERMISSION STREAM IS NOT, and
 * this library needs no flag for that. fuzzypickles' append log takes any
 * entry whose sequence exceeds its high-water mark, so a jump loses the
 * entries between and it does not mind. `record/journal.h` refuses the jump.
 * A log consumer that accepts the loss calls `fzn_journal_anchor`, which is
 * deliberate; a permission consumer never does. **The existing API already
 * expresses both**, which is why nothing here takes a policy argument.
 *
 * THE BODIES ARE NOT COPIED, as in `state/`: an entry points at the caller's
 * bytes and the caller must keep them alive for as long as the entry does.
 * An entry that is evicted stops referring to anything.
 */

#ifndef FZN_LOG_H
#define FZN_LOG_H

#include "../record/record.h"

#include <stddef.h>
#include <stdint.h>

typedef enum fzn_log_err {
	FZN_LOG_OK = 0,
	FZN_LOG_ERR_MALFORMED = -1,
	/* Already held. A re-delivery produces one and it is not a fault. */
	FZN_LOG_ERR_DUPLICATE = -2,
	/* Retention removed it: the sequence asked for is below where this log
	 * now starts. The answer that lets a lagging peer stop asking. */
	FZN_LOG_ERR_GONE = -3,
	/* Not held, and not evicted either -- above what this log has. */
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
	int live;
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

/* The entry for this issuer and sequence.
 *
 * Returns `FZN_LOG_ERR_GONE` when the sequence is below the oldest this log
 * still holds for that issuer, and `FZN_LOG_ERR_ABSENT` when it is above the
 * newest. The distinction is the whole reason a caller asks. */
fzn_log_err_t fzn_log_get(const fzn_log_t *log, const uint8_t issuer[FZN_PUBKEY_LEN],
                           uint32_t stream, uint64_t seq, const fzn_log_entry_t **out);

/* What this log still holds for an issuer. Both are zero when it holds
 * nothing from it. */
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
