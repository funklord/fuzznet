/* Which link should this message take?
 *
 * Absorbed from fuzzypickles' `sched.c` (project.md sec 5), which is one of
 * the four files their measurement found standalone. What came across is the
 * decision; what did not is any idea of what a link *is*. This module never
 * opens anything, never sends anything, and does not know whether a link is
 * wifi, Bluetooth or a tunnel. A consumer describes its candidates as numbers
 * it measured and gets back one of them, or nothing.
 *
 * sec 2 keeps transport out of this library and that still holds: choosing
 * among links a consumer supplied is not choosing a transport, any more than
 * comparing two capability identifiers is deciding what a capability means.
 *
 * IMPORTANCE IS NOT A PRIORITY SCALAR, and this is the part that is easy to
 * lose. fuzzypickles' own header is emphatic about it: "a max-importance
 * message wants the link most likely to arrive, which may be the slowest. A
 * fire-and-forget voice frame wants the fastest link and is happily dropped.
 * Do not collapse these into one number."
 *
 * So a class weights the COMPONENTS -- declared metric, measured latency,
 * measured loss -- rather than reweighting a blended total. A single "link
 * quality" number is the right answer to "how is this link doing" and the
 * wrong answer to "which link should this message take", because the two
 * questions disagree about what good means. **The test that matters is two
 * links and two classes giving opposite answers**, and it is in
 * `sched/test/sched_test.c` for that reason.
 *
 * HARD CONSTRAINTS COME FIRST AND CAN EXCLUDE EVERYTHING. A voice frame that
 * will arrive after it is due is worth nothing, so a link too slow for it is
 * not a worse choice -- it is not a choice. When nothing survives,
 * `FZN_SCHED_ERR_NONE` is the answer and the caller drops. Falling back to
 * the least-bad survivor would be the wrong kind of helpful, and it is the
 * mistake a scoring function makes when it has no notion of a floor.
 *
 * WHAT THE CONSUMER MEASURES, THIS MODULE ONLY READS. Latency and loss are
 * observations a consumer takes; energy, if it matters to a consumer, is
 * reported to it rather than modelled here, for the reason fuzzypickles gives:
 * a battery drains because of the screen and forty other processes, so a
 * library computing its own consumption would produce a number with no
 * relationship to how much is actually left.
 */

#ifndef FZN_SCHED_H
#define FZN_SCHED_H

#include <stddef.h>
#include <stdint.h>

typedef enum fzn_sched_err {
	FZN_SCHED_OK = 0,
	FZN_SCHED_ERR_MALFORMED = -1,
	/* Nothing satisfied the class's hard constraints. A real answer, and
	 * the caller drops rather than sending over something that cannot
	 * carry the message in time. */
	FZN_SCHED_ERR_NONE = -2,
} fzn_sched_err_t;

/* One candidate, described by the consumer.
 *
 * `id` is the consumer's own handle and is never interpreted -- an index, a
 * file descriptor, a pointer's low bits. The scale of `metric` is the
 * consumer's too; it is only ever compared against other links' metrics
 * through the same weights. */
typedef struct fzn_link {
	uint32_t id;
	uint32_t metric;
	uint32_t latency_ms;
	uint16_t loss_permille; /* parts per thousand, so 25 is 2.5% */
	uint32_t mtu;
	int usable; /* the consumer says this link is up */
} fzn_link_t;

/* What a class of traffic requires, and what it cares about.
 *
 * A constraint of zero means "no constraint", except `min_mtu` where zero
 * likewise means unconstrained. The weights need no particular scale: they
 * are relative to each other and a weight of zero means the component is
 * ignored, which is how a class says "I do not care how lossy it is". */
typedef struct fzn_class {
	uint32_t max_latency_ms;
	uint16_t max_loss_permille;
	uint32_t min_mtu;

	uint32_t weight_metric;
	uint32_t weight_latency;
	uint32_t weight_loss;
} fzn_class_t;

/* Choose a link for this class, or say that none qualifies.
 *
 * `chosen` receives the INDEX into `links`, not the id, so that a caller can
 * reach the whole candidate without searching for it. Ties go to the lowest
 * index, so the same inputs always give the same answer -- a scheduler whose
 * choice wandered between identical candidates would make a network's
 * behaviour unreproducible for no gain. */
fzn_sched_err_t fzn_sched_select(const fzn_link_t *links, size_t link_count,
                                  const fzn_class_t *class, size_t *chosen);

/* Whether one link satisfies a class's hard constraints, exposed because a
 * consumer often wants to say WHY nothing qualified. */
int fzn_sched_admits(const fzn_link_t *link, const fzn_class_t *class);

/* The weighted cost of a link under a class. Lower is better. Exposed for the
 * same reason: a consumer explaining a choice wants the numbers behind it. */
uint64_t fzn_sched_cost(const fzn_link_t *link, const fzn_class_t *class);

/* A short name for `fzn_sched_err_t`. Never NULL. */
const char *fzn_sched_err_str(fzn_sched_err_t err);

#endif /* FZN_SCHED_H */
