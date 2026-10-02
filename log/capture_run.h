/* Running an external program and capturing what it prints. sec 441.
 *
 * The POSIX half of `log/capture.h`, built where the toolchain has fork,
 * exec, pipes and poll (FZN_CAPTURE_RUN, auto by default). Sec 428 settled
 * that relaying a tool's output is one shared function rather than one per
 * daemon; this is the part each daemon would otherwise hand-roll, and the
 * part that goes wrong in ways nobody sees until a tool hangs.
 *
 *   - STDIN IS /dev/null, so a tool that asks a question gets end of file
 *     rather than waiting for ever on a daemon's terminal.
 *   - BOTH STREAMS ARE READ AS THEY ARRIVE, through poll, so a tool that
 *     fills one pipe while the caller waits on the other cannot deadlock.
 *   - THE DEADLINE KILLS THE TOOL'S WHOLE PROCESS GROUP. It is started in a
 *     group of its own, so what it spawned goes with it; a grandchild that
 *     left the group and kept the pipes open is read until the deadline and
 *     no further.
 *   - A TOOL THAT COULD NOT BE STARTED IS SAID AS SUCH, with the errno exec
 *     gave, through a close-on-exec pipe -- not as exit 127, which a tool
 *     that ran can return too.
 *   - IT IS REAPED, every path, so no zombie outlives the call.
 *
 * Its descriptors are close-on-exec where it opens them, and the caller's
 * own are the caller's business: a daemon that leaves descriptors
 * inheritable hands them to every tool it runs, here or anywhere.
 */

#ifndef FZN_LOG_CAPTURE_RUN_H
#define FZN_LOG_CAPTURE_RUN_H

#include <stdint.h>

#include "capture.h"

/* Run `argv` -- `argv[0]` found on PATH, NULL-terminated -- feeding what it
 * prints to `capture` and finishing it, and say how it ended in `*end`,
 * `*code` and `*elapsed_ms`. `deadline_ms` of 0 is no deadline. FZN_CAPTURE_OK
 * whenever the outcome is known, a tool that failed included; MALFORMED only
 * for a null. */
fzn_capture_err_t fzn_capture_run(fzn_capture_t *capture, const char *const *argv,
                                  uint64_t deadline_ms, fzn_capture_end_t *end, int *code,
                                  uint64_t *elapsed_ms);

#endif /* FZN_LOG_CAPTURE_RUN_H */
