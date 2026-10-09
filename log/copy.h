/* Copies of another host's log, kept here. sec 483: sec 428's replicated
 * copies, as the holder settled them on 2026-10-05 -- opt-in per node, and
 * only whole packed segments, each verified before it is kept. POSIX, built
 * with FZN_LOG_PACK, which the verifying needs.
 *
 * WHAT TRAVELS: a host's PACKED segments, byte for byte, never its current
 * file or a segment not yet packed. A packed segment is closed, chained and
 * -- since sec 482 -- signed by the host that packed it, so a copy can be
 * checked by whoever holds it and needs nothing from the host to stay
 * checkable. Four messages of gathering's version-4 family
 * (`log/gather.situ`):
 *
 *     segments_query  a program's packed segments closed after a key
 *     segments        their names and sizes, oldest first
 *     part_query      a segment's bytes from an offset
 *     part            as many as fit a reply
 *
 * WHO MAY ASK is the caller's, as for gathering (sec 463): fuzznetd answers
 * members, and only at `--log-scope=estate`.
 *
 * WHAT IS KEPT, by the puller, in a directory per source host: a segment
 * fetched whole, then verified -- it chains from the last one kept (the
 * first from the prev its own trailer names), and it is SIGNED BY THE
 * SOURCE HOST'S KEY, the key the puller asked. A segment that fails is
 * refused and the pull of that program stops there, since every later one
 * chains from it. Only then is it renamed into place and the chain's head
 * written, so a copy directory holds only what verified.
 *
 * PUSHED, sec 488: a host that is seldom reachable sends the same segments
 * itself, to a member that takes copies of that program. Four more messages
 * of the family:
 *
 *     push_query  whether the member takes this program's copies
 *     push_at     whether, and the newest it holds of the sender's
 *     push_part   some bytes of a segment, at an offset
 *     push_took   more (and how much is held), kept, refused, or held
 *
 * The receiver keeps a pushed segment under the SENDER's key -- the key the
 * hop authenticated, which nothing in the message can name otherwise -- and
 * verifies it exactly as a pulled one, so a member pushing another host's
 * history is refused as a puller asking the wrong host would be. A part the
 * receiver cannot place is answered with what it holds, and the pusher goes
 * on from there, so a push broken off resumes on the next round.
 *
 * Copies are removed by retention rules that name them (`log/retain.h`'s
 * `copy`), whole: a copy is the source's bytes under the source's
 * signature, and thinning it would leave neither.
 */

#ifndef FZN_LOG_COPY_H
#define FZN_LOG_COPY_H

#include <stddef.h>
#include <stdint.h>

#include "gather.h"
#include "pack.h"

#define FZN_LOG_COPY_SEGMENTS_QUERY 5u
#define FZN_LOG_COPY_SEGMENTS 6u
#define FZN_LOG_COPY_PART_QUERY 7u
#define FZN_LOG_COPY_PART 8u
#define FZN_LOG_COPY_PUSH_QUERY 9u
#define FZN_LOG_COPY_PUSH_AT 10u
#define FZN_LOG_COPY_PUSH_PART 11u
#define FZN_LOG_COPY_PUSH_TOOK 12u
/* What a push_took says, `fzn_log_copy_took` in `log/gather.situ`. */
#define FZN_LOG_COPY_TOOK_MORE 0u
#define FZN_LOG_COPY_TOOK_KEPT 1u
#define FZN_LOG_COPY_TOOK_REFUSED 2u
#define FZN_LOG_COPY_TOOK_HELD 3u
/* Bytes one pushed part carries at most: a request is put back together up
 * to 32 KiB (sec 447), and a part's head and envelope ride with it. */
#define FZN_LOG_COPY_PUSH_PART_MAX (16u * 1024u)
/* A segment one copy fetches at most: past it, refused rather than held in
 * memory, as `log/pack.h`'s retention read is bounded. */
#define FZN_LOG_COPY_SEGMENT_MAX (64u * 1024u * 1024u)
/* Segments one listing names; a longer list is paged by the key. */
#define FZN_LOG_COPY_LIST_MAX 64u

typedef enum fzn_log_copy_err {
	FZN_LOG_COPY_OK = 0,
	FZN_LOG_COPY_ERR_MALFORMED = -1, /* a null, a name that is not a segment's */
	FZN_LOG_COPY_ERR_NO_ANSWER = -2, /* the host did not answer */
	FZN_LOG_COPY_ERR_REFUSED = -3,   /* it answered with something else */
	FZN_LOG_COPY_ERR_FILE = -4,      /* the copy directory would not write */
	FZN_LOG_COPY_ERR_VERIFY = -5,    /* a segment did not chain or was not the host's */
	FZN_LOG_COPY_ERR_DECLINED = -6   /* the member takes no copies of that program */
} fzn_log_copy_err_t;

const char *fzn_log_copy_err_str(fzn_log_copy_err_t err);

/* A PACKED SEGMENT'S NAME, `PROGRAM.TIME.PID.log.zst`, read: its closing
 * time in microseconds, or 0 for a name that is not one. sec 571. */
uint64_t fzn_log_copy_packed_time(const char *name);

/* `path` and every directory above it, owner-only: nonzero when it is
 * there afterwards. sec 571. */
int fzn_log_copy_make_dir(const char *path);

/* THE HOST'S ANSWER to a segments or part query, from the log in `dir`. 0
 * when `request` is neither, so a caller dispatching on the first bytes
 * falls through. */
size_t fzn_log_copy_answer(const char *dir, const uint8_t *request, size_t request_len,
                           uint8_t *reply, size_t reply_cap);

/* What one pull did. */
typedef struct fzn_log_copy_tally {
	size_t copied;        /* segments verified and kept */
	size_t bytes;         /* their size */
	char refused[256];    /* the segment a pull stopped at, or "" */
} fzn_log_copy_tally_t;

/* THE PULLER: `program`'s packed segments from the host `ask` reaches,
 * whose key is `host`, into `copy_dir` -- created when absent -- each
 * fetched, verified as the header says and kept. VERIFY, naming the
 * segment, at the first that fails. */
fzn_log_copy_err_t fzn_log_copy_pull(fzn_gather_ask_t ask, void *ask_ctx, const char *program,
                                     const uint8_t host[FZN_LOG_PACK_HASH_LEN],
                                     const char *copy_dir, const fzn_hash_ops_t *hash,
                                     const fzn_sign_ops_t *sign, fzn_log_copy_tally_t *tally);

/* THE PUSHER, sec 488: `program`'s packed segments in `dir`, newer than the
 * newest the member `ask` reaches holds, sent to it a part at a time, oldest
 * first, until `budget` bytes have gone -- the rest on the next call, from
 * where the member says it is. `tally` counts the segments it kept and the
 * bytes sent. DECLINED when the member takes no copies of it; VERIFY, naming
 * the segment, when it refused one. */
fzn_log_copy_err_t fzn_log_copy_push(fzn_gather_ask_t ask, void *ask_ctx, const char *dir,
                                     const char *program, size_t budget,
                                     fzn_log_copy_tally_t *tally);

/* What one pushed message did, for the receiver to say. */
typedef struct fzn_log_copy_took_note {
	int kept;          /* a segment verified and kept */
	int refused;       /* a segment whole and refused */
	char name[256];    /* which, when either */
} fzn_log_copy_took_note_t;

/* THE RECEIVER, sec 488: the answer to a push_query or a push_part from the
 * member `sender`, keeping what verifies in `dir/copy/SENDERHEX` -- for the
 * programs in `programs` alone, the ones this node takes copies of. 0 when
 * `request` is neither, so a caller dispatching on the first bytes falls
 * through. `note` says what it kept or refused. */
size_t fzn_log_copy_take(const char *dir, const uint8_t sender[FZN_LOG_PACK_HASH_LEN],
                         const char *const *programs, size_t n_programs,
                         const fzn_hash_ops_t *hash, const fzn_sign_ops_t *sign,
                         const uint8_t *request, size_t request_len, uint8_t *reply,
                         size_t reply_cap, fzn_log_copy_took_note_t *note);

/* `dir/copy/HOSTHEX`, the directory a copy of `host`'s log is kept in. */
int fzn_log_copy_dir(const char *dir, const uint8_t host[FZN_LOG_PACK_HASH_LEN], char *out,
                     size_t cap);

#endif /* FZN_LOG_COPY_H */
