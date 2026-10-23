/*
 * `list log [FROM] [LEVEL]`, sec 711: what this daemon has logged, newest
 * first, read from its flight recorder (`log/ring.h`), the verb sec 689
 * found logs lacked and fuzzypickles' client waits for.
 *
 *     ok TOTAL FROM TIME,L,SUBSYSTEM,CUT,TEXT ...
 *
 * TOTAL is how many entries the ring holds at LEVEL or more severe, and
 * FROM how many of the newest this page passed over; a client pages by
 * asking again from FROM plus the entries it was given, as `list contact`
 * is paged. Each entry: its time in microseconds since the epoch, UTC; its
 * level's letter as the classic line writes it (C E W N I V D T); its
 * subsystem; 1 when its text was cut to fit one reply, else 0; and its text
 * %XX-escaped (`local/escape.h`). LEVEL is a letter too, I by default: the
 * ring keeps debug as well, and a client showing activity wants it out.
 * `ok 0 0` is "nothing logged yet".
 *
 * THE RING IS THIS PROCESS'S, a fixed 256 KiB with the oldest records
 * evicted, so this reads what this daemon said since it started, as far
 * back as the ring reaches -- not the files of earlier runs.
 *
 * The node's own user's alone, as `list transfer` is: a log can say
 * anything the node knows.
 */
#ifndef FZN_NODE_LOG_LIST_H
#define FZN_NODE_LOG_LIST_H

#include <stddef.h>

#include "../chain/authz.h"
#include "../local/vocabulary.h"
#include "../log/ring.h"

/* The answer to `request` if it is `list log`, into `reply` (`cap`
 * bytes), its length; 0 for any other request. `ring` NULL is answered
 * that this node keeps no log to read. */
size_t fzn_node_log_list_local(const fzn_ring_t *ring, fzn_origin_t origin,
                               const fzn_request_t *request, char *reply, size_t cap);

#endif /* FZN_NODE_LOG_LIST_H */
