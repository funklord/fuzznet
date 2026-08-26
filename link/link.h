/* What each link is actually doing, as opposed to what it claimed.
 *
 * Absorbed from fuzzypickles' `link.c` (project.md sec 5), the companion to
 * `sched/`: this measures, that chooses. Their header states the claim this
 * exists to make true, and it is kept --
 *
 *   "A LINK is one transport over one address. A peer advertising several
 *   addresses, or one address reachable by more than one transport, is
 *   several links, each with its own measured latency and availability,
 *   competing on cost."
 *
 * -- and the shape is chosen so that is literally true rather than merely
 * intended: **nothing here knows what any transport IS**. There is no branch
 * on a transport tag anywhere, and adding one -- a radio, a tunnel, a relay
 * hop -- is registering another link rather than extending this file. A link
 * is a `uint32_t` the consumer chose.
 *
 * THE DECLARED METRIC IS A PRIOR; MEASUREMENT IS EVIDENCE. A far end's
 * declared cost is what it believed about its own addresses when it wrote
 * them, and a network degrades paths in ways no static declaration expresses
 * and the far end may never learn. So a link is registered WITH its prior and
 * the estimate starts there, and every observation moves it -- evidence
 * dominating gradually rather than at some threshold nobody can name.
 *
 * WHY THE PRIOR IS SEEDED RATHER THAN SPECIAL-CASED. The obvious shape is a
 * sample count and a branch: report the declaration until there is enough
 * evidence, then report the measurement. That has a cliff in it, and worse, it
 * has to answer "what latency does an unmeasured link have?" -- and the honest
 * answer, zero, makes a link nobody has ever used look infinitely fast and win
 * every selection in `sched/`. Seeding the estimate with the prior removes the
 * question: there is always a number, and it starts out being the one the far
 * end asserted.
 *
 * WHAT IS NOT HERE, and the second one is a trap worth carrying across from
 * their header:
 *
 *   - **The choice.** `sched/` makes it, from a snapshot this produces.
 *   - **Congestion control.** It reads the same loss and round-trip signals
 *     and is a separate piece of work. The trap: once a controller is
 *     throttling a HEALTHY path correctly, it looks to a table like this one
 *     exactly like a degrading link -- and telling those apart does not arise
 *     while everything is uncontrolled, so a design that assumed it could
 *     would be untestable today.
 *   - **Any I/O.** Nothing here sends, receives or waits.
 */

#ifndef FZN_LINK_H
#define FZN_LINK_H

#include "../sched/sched.h"

#include <stddef.h>
#include <stdint.h>

typedef enum fzn_link_err {
	FZN_LINK_OK = 0,
	FZN_LINK_ERR_MALFORMED = -1,
	/* No room for another link. Refused rather than evicted: forgetting a
	 * link discards its measurements, so the next selection treats a known
	 * bad path as freshly plausible. */
	FZN_LINK_ERR_FULL = -2,
	/* This id is registered already. */
	FZN_LINK_ERR_DUPLICATE = -3,
	/* No link with this id. */
	FZN_LINK_ERR_ABSENT = -4,
} fzn_link_err_t;

/* How quickly evidence displaces the prior.
 *
 * A new observation is worth one part in eight, so a link needs roughly a
 * dozen consistent samples to move most of the way. Chosen to be slow enough
 * that one late packet does not condemn a good path and fast enough that a
 * path which has genuinely gone is not chosen for a minute -- and stated as a
 * shift so the arithmetic stays integer, since nothing in this library uses
 * floating point. */
#define FZN_LINK_SMOOTH_SHIFT 3u

typedef struct fzn_link_entry {
	uint32_t id;
	uint32_t metric;
	uint32_t latency_ms;
	uint16_t loss_permille;
	uint32_t mtu;
	uint64_t observations;
	uint64_t last_seen;
	int usable;
	int live;
} fzn_link_entry_t;

typedef struct fzn_link_table {
	fzn_link_entry_t *entries;
	size_t capacity;
	size_t used;
} fzn_link_table_t;

fzn_link_err_t fzn_link_table_init(fzn_link_table_t *table, fzn_link_entry_t *entries,
                                    size_t capacity);

/* Add a link, with what the far end declared about it.
 *
 * `latency_ms` and `loss_permille` are the prior -- the estimate starts there
 * and observations move it. A consumer with no declaration at all should pass
 * a pessimistic guess rather than zero, for the reason in the header: a link
 * asserted to be instant wins every selection until something disproves it. */
fzn_link_err_t fzn_link_register(fzn_link_table_t *table, uint32_t id, uint32_t metric,
                                  uint32_t latency_ms, uint16_t loss_permille, uint32_t mtu);

/* A message got through, and took this long. */
fzn_link_err_t fzn_link_observe_ack(fzn_link_table_t *table, uint32_t id, uint32_t rtt_ms,
                                     uint64_t now);

/* A message did not get through. */
fzn_link_err_t fzn_link_observe_loss(fzn_link_table_t *table, uint32_t id, uint64_t now);

/* Mark a link up or down. A consumer knows this -- an interface went away, a
 * radio was switched off -- and no measurement can tell it. */
fzn_link_err_t fzn_link_set_usable(fzn_link_table_t *table, uint32_t id, int usable);

/* The current estimate for one link. */
const fzn_link_entry_t *fzn_link_get(const fzn_link_table_t *table, uint32_t id);

/* Fill an array `sched/` can choose from. Returns how many were written,
 * never more than `out_cap`. */
size_t fzn_link_snapshot(const fzn_link_table_t *table, fzn_link_t *out, size_t out_cap);

/* A short name for `fzn_link_err_t`. Never NULL. */
const char *fzn_link_err_str(fzn_link_err_t err);

#endif /* FZN_LINK_H */
