/* What this host has received from each issuer, and what it has applied.
 *
 * Reception and finalisation are different questions and this file keeps them
 * apart, because every distributed configuration bug lives in the gap between
 * them. "I have the record" and "I have acted on it" diverge whenever applying
 * can fail, be deferred, or need a reboot -- and a system that tracks only the
 * first cannot tell a sibling that is behind from one that is broken.
 *
 * ORDER COMES FROM SEQUENCES, NOT CLOCKS. Each issuer numbers its own records
 * from 1 upwards. Per issuer rather than globally because a global sequence
 * needs consensus and this design has none: two hosts that never speak must
 * still be able to issue. `issued_at` exists for display and policy and is
 * never consulted here, because clocks disagree and sequences do not.
 *
 * A GAP IS NOT AN ERROR, IT IS AN INSTRUCTION. `FZN_JOURNAL_ERR_GAP` means a
 * record arrived that is real, in order, and too far ahead -- so something in
 * between exists and has not been seen. That is exactly the condition a
 * distribution layer acts on, by asking for what is missing. It is reported
 * rather than papered over, and `fzn_journal_next` says what to ask for. A
 * journal that silently accepted the jump would leave a hole nobody could
 * later detect, which is how a permission that was revoked comes back.
 *
 * WHAT IT DOES NOT DO. It does not verify signatures -- `record.h` does. It
 * does not decide whether an issuer may say a thing -- a capability does. It
 * does not store records: it stores the two numbers that say what is needed
 * next, so that a consumer may hold the bodies wherever it likes, in memory,
 * on disk, or not at all.
 */

#ifndef FZN_JOURNAL_H
#define FZN_JOURNAL_H

#include "record.h"

#include <stddef.h>
#include <stdint.h>

typedef enum fzn_journal_err {
	FZN_JOURNAL_OK = 0,
	FZN_JOURNAL_ERR_MALFORMED = -1,
	/* Seen before. Not a fault: a distribution layer that asks two
	 * siblings for the same range gets one of these, and dropping it
	 * quietly is correct. Distinguished from OK so a caller can tell a new
	 * statement from an echo without storing it twice. */
	FZN_JOURNAL_ERR_DUPLICATE = -2,
	/* Ahead of what is held. Something in between exists. See the header
	 * comment: this is the distribution layer's cue, not a refusal to be
	 * retried unchanged. */
	FZN_JOURNAL_ERR_GAP = -3,
	/* No room to track another issuer.
	 *
	 * REFUSED RATHER THAN EVICTED, for the reason `frame/freshness.h`
	 * refuses a full replay window: dropping an issuer to make room forgets
	 * what was seen from it, and the next record from that issuer is then
	 * accepted at any sequence -- which readmits everything it ever sent.
	 * A visible refusal a consumer can alarm on is the smaller harm. */
	FZN_JOURNAL_ERR_FULL = -4,
	/* Nothing has been received from this issuer, so there is nothing to
	 * confirm applied. */
	FZN_JOURNAL_ERR_UNKNOWN_ISSUER = -5,
	/* Confirming further than was received. A consumer claiming to have
	 * applied a record it never got is a bug worth naming rather than
	 * clamping, because the alternative is a sibling reporting itself up to
	 * date on records nobody sent it. */
	FZN_JOURNAL_ERR_NOT_RECEIVED = -6,
} fzn_journal_err_t;

/* One issuer's position. `received` is the highest CONTIGUOUS sequence held:
 * contiguous, so that it doubles as "everything up to here is present". */
typedef struct fzn_journal_entry {
	uint8_t issuer[FZN_PUBKEY_LEN];
	uint64_t received;
	uint64_t applied;
	int live;
} fzn_journal_entry_t;

typedef struct fzn_journal {
	fzn_journal_entry_t *entries;
	size_t capacity;
	size_t used;
} fzn_journal_t;

/* Point a journal at caller-owned entries. */
fzn_journal_err_t fzn_journal_init(fzn_journal_t *journal, fzn_journal_entry_t *entries,
                                    size_t capacity);

/* Offer a record's position. Advances `received` by exactly one on success.
 *
 * The record itself is not stored and not verified here; a caller that admits
 * an unverified record has skipped a step this module cannot see. */
fzn_journal_err_t fzn_journal_admit(fzn_journal_t *journal,
                                     const uint8_t issuer[FZN_PUBKEY_LEN], uint64_t seq);

/* Start following an issuer from `seq`, deliberately.
 *
 * A new issuer's first record is a decision rather than a fact: accepting
 * whatever sequence arrives lets a stranger start at a large number and
 * suppress everything real that follows, while insisting on 1 makes it
 * impossible to join a stream already in progress. So the choice is the
 * caller's and it is explicit -- which is also what makes a deliberate
 * re-anchor after a restore distinguishable from a gap.
 *
 * `seq` of ZERO means "follow this issuer from the beginning": an entry with
 * nothing received yet. That is what the reservation of sequence zero is for,
 * and it is what a host does when it decides to care about an issuer it has
 * heard of but never received from -- which `record/sync.h` requires before
 * it will fetch anything, deliberately. Anchoring at zero twice is a
 * duplicate rather than a rewind. */
fzn_journal_err_t fzn_journal_anchor(fzn_journal_t *journal,
                                      const uint8_t issuer[FZN_PUBKEY_LEN], uint64_t seq);

/* Record that everything up to `seq` from this issuer has been APPLIED.
 *
 * Separate from admission because that is the whole point of the file: a
 * sibling that has received a rule and not yet applied it is in a different
 * state from one that has, and only the second is safe to depend on. */
fzn_journal_err_t fzn_journal_confirm(fzn_journal_t *journal,
                                      const uint8_t issuer[FZN_PUBKEY_LEN], uint64_t seq);

/* The sequence this host wants next from `issuer`, which is what a
 * distribution layer asks for. Returns 1 for an issuer never seen. */
uint64_t fzn_journal_next(const fzn_journal_t *journal, const uint8_t issuer[FZN_PUBKEY_LEN]);

/* How far behind applying is: received minus applied, zero when settled. */
uint64_t fzn_journal_pending(const fzn_journal_t *journal,
                             const uint8_t issuer[FZN_PUBKEY_LEN]);

/* A short name for `fzn_journal_err_t`. Never NULL. */
const char *fzn_journal_err_str(fzn_journal_err_t err);

#endif /* FZN_JOURNAL_H */
