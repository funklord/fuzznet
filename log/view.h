/* The shortened view of a log: what a reader sees, not what is kept. sec
 * 467, sec 428's viewer.
 *
 * SEC 428: "a viewer shortens for display only: it hides fields equal to the
 * previous line's ... along the tree estate / machine / user /
 * program[instance] / subsystem, and the file keeps all of it." So this
 * writes nothing anybody parses; the classic line stays the format, and this
 * is how a person reads a run of them.
 *
 * WHAT IT HIDES, entry by entry against the one before:
 *
 *   - THE DATE becomes a line of its own, `-- 2026-10-02 --`, written when
 *     it changes; each entry then shows the time of day.
 *   - THE TREE -- host, user, program, instance (`pid@start`), subsystem --
 *     is shown from the first field that differs from the previous entry's,
 *     down: a new instance shows its subsystem though the subsystem is the
 *     same, since below a changed field nothing is "the same as above".
 *   - THE POSITION AND THE LEVEL are always shown, `#1834 W`: the position
 *     is what a grep for the instance field ends on.
 *   - CAUSES only when there are any, as the cause's instance field -- what
 *     a grep would follow -- and the origin's when it is another entry.
 *   - THE TEXT always, escaped as the line escapes it.
 *
 *     -- 2026-10-02 --
 *     12:34:56.789123 nabbe root fuzznetd 4121@1727778896123 #1834 W notes/sync a record refused
 *     12:34:56.790011 #1835 I notes/push 1 record to R
 *     12:34:57.002233 #1836 I 1 record from R
 */

#ifndef FZN_LOG_VIEW_H
#define FZN_LOG_VIEW_H

#include <stddef.h>
#include <stdint.h>

#include "entry.h"

/* `cur` shown after `prev` (NULL for the first), each with the host its
 * line showed: one or two lines into `out`, each ending in a newline, the
 * whole NUL-terminated; `*len` the bytes written. ROOM, and nothing left,
 * when they do not fit. */
fzn_entry_err_t fzn_entry_view(const fzn_entry_t *prev, const char *prev_host,
                               const fzn_entry_t *cur, const char *cur_host, char *out, size_t cap,
                               size_t *len);

#endif /* FZN_LOG_VIEW_H */
