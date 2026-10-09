/* Copies of another host's log, kept here: where they live, and what a
 * packed segment's name says. sec 483's copies, as the holder settled them
 * on 2026-10-05 -- only whole packed segments, each verified before it is
 * kept -- carried since sec 573 by the bucket exchange (`node/log_buckets.h`)
 * rather than by messages of their own. POSIX, built with FZN_LOG_PACK.
 *
 * RETIRED, sec 573: the four pull messages of sec 483 and the four push
 * messages of sec 488 (gather's types 5 to 12), the puller, the pusher, the
 * receiver and the host's answer, and fuzznetd's `--log-copy` and
 * `--log-push`. The holder's rule is that every transfer mode keeps both a
 * pull and a push (sec 568), and the bucket exchange keeps both for every
 * kind; what a node holds of other hosts' logs is its retention rules' and
 * its retention capability's to say (secs 566, 567), not a flag's.
 *
 * WHAT STAYS is where a copy is kept -- `dir/copy/HOSTHEX/`, a directory
 * per source host, owner-only -- and the one name a copy has: its source's
 * `PROGRAM.TIME.PID.log.zst`. Copies are removed by retention rules that
 * name them (`log/retain.h`'s `copy`), whole.
 */

#ifndef FZN_LOG_COPY_H
#define FZN_LOG_COPY_H

#include <stddef.h>
#include <stdint.h>

#include "pack.h"

/* A PACKED SEGMENT'S NAME, `PROGRAM.TIME.PID.log.zst`, read: its closing
 * time in microseconds, or 0 for a name that is not one. sec 571. */
uint64_t fzn_log_copy_packed_time(const char *name);

/* `path` and every directory above it, owner-only: nonzero when it is
 * there afterwards. sec 571. */
int fzn_log_copy_make_dir(const char *path);

/* `dir/copy/HOSTHEX`, the directory a copy of `host`'s log is kept in. */
int fzn_log_copy_dir(const char *dir, const uint8_t host[FZN_LOG_PACK_HASH_LEN], char *out,
                     size_t cap);

#endif /* FZN_LOG_COPY_H */
