/* What to ask a peer for, and what to offer it.
 *
 * This is the distribution layer's decision and nothing else. It does not
 * send, does not schedule, does not encode, and does not decide whether a
 * record it fetches will turn out to be authorised. Given what this host
 * holds and what a peer says it holds, it answers: **which ranges are
 * missing, and which way round.**
 *
 * WHY THAT IS THE WHOLE OF IT. sec 2 keeps transport out of this library and
 * sec 5 keeps the permission graph's shape out. What is left when both are
 * removed is a comparison of two sets of positions -- and that comparison is
 * identical in all three consumers, which is exactly the test sec 5 sets for
 * admitting anything. A consumer supplies its own timers, its own choice of
 * peer, and its own framing; `wire/seal.h` and `chunk/` are already there for
 * the last of those.
 *
 * PULL, NOT PUSH, is the shape this supports first, because it survives loss
 * without acknowledgements: a host that missed a record asks again next time
 * it compares. `fzn_sync_offer` exists for the other direction, so a host
 * that knows a peer is behind can send without being asked, but nothing here
 * requires it.
 *
 * A NEW ISSUER IS NOT FOLLOWED AUTOMATICALLY. If a peer advertises an issuer
 * this host has never seen, that is reported as a COUNT and never as a
 * request. Fetching from a stranger because a peer mentioned them is how one
 * compromised peer fills every journal in the network with issuers nobody
 * chose, and `record/journal.h` already makes adopting an issuer deliberate
 * -- `fzn_journal_anchor`. This file does not quietly undo that.
 *
 * EVERY BOUND IS REPORTED. A plan that did not fit says so, rather than
 * returning a short list that looks complete: a truncated plan silently
 * dropped is a range nobody asks for again.
 */

#ifndef FZN_SYNC_H
#define FZN_SYNC_H

#include "journal.h"

#include <stddef.h>
#include <stdint.h>

typedef enum fzn_sync_err {
	FZN_SYNC_OK = 0,
	FZN_SYNC_ERR_MALFORMED = -1,
} fzn_sync_err_t;

/* One issuer's position, as a peer reports it. This is what a host puts on
 * the wire to say what it has; how it is encoded is the consumer's, for the
 * reason `record.h` gives about signed regions. */
typedef struct fzn_sync_position {
	uint8_t issuer[FZN_PUBKEY_LEN];
	uint64_t received;
} fzn_sync_position_t;

/* A range of one issuer's records, wanted or offered.
 *
 * `count` is bounded by the caller rather than left open, because "send me
 * everything from 1" is a request a stranger can make of every host at once.
 * The reply to a bounded request is a bounded amount of work, and the next
 * comparison asks for the next window. */
typedef struct fzn_sync_request {
	uint8_t issuer[FZN_PUBKEY_LEN];
	uint64_t from;
	uint64_t count;
} fzn_sync_request_t;

/* What a comparison produced, including what it could not fit.
 *
 * `unknown_issuers` is issuers the peer follows and this host does not. It is
 * deliberately a number and not a list of requests: adopting one is
 * `fzn_journal_anchor`, which is a decision, and a consumer that wants the
 * identities can read them from the positions it was given. */
typedef struct fzn_sync_plan {
	size_t request_count;
	size_t unknown_issuers;
	size_t truncated;
} fzn_sync_plan_t;

/* This host's own positions, to send to a peer. Returns how many were
 * written, and never more than `out_cap`. */
size_t fzn_sync_digest(const fzn_journal_t *journal, fzn_sync_position_t *out, size_t out_cap);

/* What this host should ask the peer for: ranges the peer has and it does
 * not, for issuers it already follows.
 *
 * `max_per_request` bounds each range. Zero is refused rather than meaning
 * unlimited, for the reason `fzn_reasm_init` refuses a zero quota: an
 * unlimited default is the one a caller gets by forgetting the field. */
fzn_sync_err_t fzn_sync_plan_fetch(const fzn_journal_t *journal,
                                    const fzn_sync_position_t *theirs, size_t their_count,
                                    uint64_t max_per_request, fzn_sync_request_t *out,
                                    size_t out_cap, fzn_sync_plan_t *plan);

/* The mirror: ranges this host has and the peer does not, so it can send
 * without waiting to be asked. An issuer the peer has never seen IS offered
 * here -- offering is not adopting, and the peer still decides. */
fzn_sync_err_t fzn_sync_plan_offer(const fzn_journal_t *journal,
                                    const fzn_sync_position_t *theirs, size_t their_count,
                                    uint64_t max_per_request, fzn_sync_request_t *out,
                                    size_t out_cap, fzn_sync_plan_t *plan);

/* A short name for `fzn_sync_err_t`. Never NULL. */
const char *fzn_sync_err_str(fzn_sync_err_t err);

#endif /* FZN_SYNC_H */
