/*
 * Planned deletion: taking bytes off this host, deliberately.
 *
 * project.md sec 155. The last of the copyright holder's three -- "the
 * cross host-copy of a catalog and its contents, and planned deletion" --
 * and the counterpart to `catalog/copy.h`, which brings bytes in.
 *
 * WHY IT IS PLANNED AND NOT `unlink`. sec 152 gave every host its own
 * retention, so a node this host has marked DROP is a node whose bytes it
 * would like back. Acting on that one file at a time, as the mark is set,
 * gets three things wrong, and each is a real way to lose data rather than a
 * tidiness argument:
 *
 *   - **A blob may be shared.** Several nodes referencing one blob is the
 *     reason a caller chooses a blob over an inline value at all. Removing
 *     the bytes because one node said DROP takes them from every other node
 *     that still wants them, and the catalogue goes on claiming they are
 *     there.
 *   - **This host may be the last that has them.** Retention is per-host by
 *     design, which means "everybody dropped it" is a state the design
 *     permits and nothing prevents. A deletion that cannot ask how many other
 *     hosts hold the bytes is a deletion that cannot tell tidying up from
 *     losing the only copy.
 *   - **Deleting is not resumable unless it was planned.** A consumer part
 *     way through, interrupted, has no way to know what it had decided --
 *     the marks it was acting on are still there and the bytes it removed are
 *     not, and those two facts do not distinguish "done" from "half done".
 *
 * SO A SWEEP IS THE REFILE'S SHAPE, DELIBERATELY. sec 148 built a job that
 * captures, locks, walks a sorted cursor, and survives a restart; this is the
 * same five calls over a different list, because a consumer that has learned
 * one has learned both and because the properties that made a refile sound
 * are the ones a deletion needs:
 *
 *   1. `fzn_catalog_sweep_capture` -- decide what may go, ONCE, against the
 *      catalogue and the two seams. The catalogue is not yet locked.
 *   2. `fzn_catalog_sweep_begin` -- lock. From here the catalogue answers
 *      FZN_CATALOG_ERR_BUSY to everything but progress and the calls below.
 *   3. `fzn_catalog_sweep_at` gives the node, the blob and its length; the
 *      consumer removes the bytes and calls `fzn_catalog_sweep_advance`.
 *   4. `fzn_catalog_sweep_progress` answers throughout.
 *   5. `fzn_catalog_sweep_end` unlocks, and refuses while work remains.
 *
 * THE DECISION IS TAKEN AT CAPTURE AND NEVER AGAIN, which is what makes the
 * cursor mean something. The lock is why: nothing may change the catalogue
 * or the retention table while the sweep runs, so the list cannot move
 * underneath a count. A sweep that re-asked the seams per step would be a
 * different sweep at every step, and a restart could not resume it.
 *
 * IT REMOVES BYTES AND NEVER ASSERTIONS, and the difference is the same
 * category the retention table is in. Unlinking a node from the catalogue is
 * an assertion that travels -- sec 144 -- and every host sees it. Removing
 * the bytes is this host's own arrangement, exactly as the filing and the
 * retention are, and it says nothing to anybody. A node whose bytes this host
 * swept is still in the catalogue, still named, still fetchable again from a
 * peer that kept it. **A sweep is therefore reversible wherever anybody else
 * kept a copy, and irreversible exactly where it is not** -- which is what
 * the witness seam below exists to let a consumer refuse.
 *
 * REACHABILITY IS NOT CONSULTED HERE AND IS NOT MISSING. A node no longer
 * linked from anywhere is not swept unless retention says to drop it, and
 * that separation is the design rather than a gap: `catalog/reach.h` answers
 * which nodes nothing links, and answering it needs evidence this module has
 * no business collecting -- a frontier saying how far this host has read from
 * every issuer it follows, without which an edge that has not arrived yet
 * makes a live node look orphaned. sec 156.
 *
 * So the composition is three steps and this is the last of them:
 * `fzn_catalog_unreachable` proposes, `fzn_catalog_retain` records the
 * consumer's decision, and the sweep removes bytes with the two guards below
 * intact. Being wrong about reachability therefore costs a re-fetch wherever
 * somebody else kept a copy, rather than being a new way to lose data.
 */

#ifndef FZN_CATALOG_SWEEP_H
#define FZN_CATALOG_SWEEP_H

#include "catalog.h"
#include "copy.h"

#include <stddef.h>
#include <stdint.h>

/*
 * How many OTHER hosts are known to hold these bytes.
 *
 * A consumer answers from the holdings its peers announced --
 * `fzn_catalog_copy_holdings` is what produces one -- and this library never
 * learns how they are kept. It counts HOSTS OTHER THAN THIS ONE: a consumer
 * that counted itself would make every blob it holds look like it had a
 * witness, which is the one answer that must never be free.
 *
 * A SEAM THAT CANNOT ANSWER SAYS ZERO, and here that refuses the deletion
 * rather than allowing it. `catalog/copy.h` takes the same rule in the other
 * direction, and it is one rule rather than two: an unanswerable seam yields
 * the conservative answer, which for a fetch is "ask again" and for a
 * deletion is "keep the bytes".
 */
typedef struct fzn_catalog_witness_ops {
	size_t (*others)(void *ctx, const uint8_t root[FZN_BLOB_HASH_LEN], uint64_t len);
	void *ctx;
} fzn_catalog_witness_ops_t;

/* One blob to remove, and the node that stopped wanting it.
 *
 * THE NODE IS CARRIED THOUGH THE BYTES ARE WHAT GOES, because a consumer
 * removing a file needs to name it, and `fzn_catalog_filed_path` names a
 * node. A blob several nodes shared appears once -- see `sweep_capture` --
 * and the node named is the first that reached it in id order, so the choice
 * is deterministic rather than whichever the table happened to hold first. */
typedef struct fzn_catalog_removal {
	fzn_catalog_id_t node;
	uint8_t root[FZN_BLOB_HASH_LEN];
	uint64_t len;
} fzn_catalog_removal_t;

/*
 * What became of every blob the catalogue references.
 *
 * THE POPULATION IS THE BLOB ENTRIES, and they partition -- each lands in
 * exactly one counter, and the suite asserts the sum:
 *
 *     blob entries = planned + retained + shared + last_copy
 *                  + absent + truncated + duplicates
 *
 * An INLINE value is not in the population at all and is counted nowhere. It
 * lives inside the record that asserted it, so there is nothing on disk to
 * remove that is not the record itself, and removing that is the journal's
 * business rather than the catalogue's.
 *
 * THEY ARE KEPT APART RATHER THAN SUMMED because a consumer that swept
 * nothing needs to say WHY, and the reasons call for different actions:
 * `retained` is this host's own policy working, `shared` and `last_copy` are
 * the two guards refusing, `absent` is nothing to do, and `truncated` is the
 * caller's own sizing. Collapsed into one number, a sweep held back by the
 * last-copy guard would be indistinguishable from a catalogue with nothing to
 * sweep -- and those want opposite responses.
 */
typedef struct fzn_catalog_sweep_plan {
	/* Rows written to the job. */
	size_t planned;
	/* Retained, so not a candidate at all. */
	size_t retained;
	/* Dropped, and a RETAINED node needs the same bytes. The guard that
	 * makes a shared blob safe, and the one a consumer acting mark by mark
	 * cannot have. */
	size_t shared;
	/* Dropped, and too few other hosts are known to hold it. `min_others`
	 * says how few is too few. */
	size_t last_copy;
	/* Dropped, and this host does not have the bytes anyway -- already
	 * swept, or never fetched. Nothing to do rather than a refusal, and
	 * counted apart so an empty sweep is legible. */
	size_t absent;
	/* Dropped and removable, and the job's rows ran out. Loud, because a
	 * sweep that silently held some of them would leave a consumer
	 * believing it had reclaimed what it had not. */
	size_t truncated;
	/* A second reference to a blob already planned. */
	size_t duplicates;
} fzn_catalog_sweep_plan_t;

typedef struct fzn_catalog_sweep {
	fzn_catalog_removal_t *removals;
	size_t capacity;
	size_t used;
	/* How many have been removed. The whole of the resumable state, and
	 * meaningful only because nothing may change the catalogue meanwhile.
	 */
	size_t done;
	int captured;
} fzn_catalog_sweep_t;

/*
 * Decide what may go, into caller-owned rows.
 *
 * A node is a candidate when this host does NOT keep it -- `fzn_catalog_keeps`
 * says, so the catalogue's own default and any override both apply. A
 * candidate is planned when its blob is not needed by a retained node, this
 * host has the bytes, and at least `min_others` other hosts are known to hold
 * them.
 *
 * A CATALOGUE NOBODY HAS SET A RETENTION ON IS A CANDIDATE FOR ALL OF IT, and
 * that follows from sec 152 rather than from anything here: a catalogue keeps
 * nothing until told, so that adopting a stranger's does not start filling a
 * disk. The consequence in this direction is sharper than in that one -- a
 * consumer that never called `fzn_catalog_retain_all` fetches nothing, which
 * is merely quiet, and sweeps everything it happens to hold, which is not.
 *
 * It is coherent rather than dangerous, because the same predicate gates both:
 * a host that kept nothing has nothing of its own to lose. What makes it safe
 * for a host that DID fetch under some earlier policy is the two guards below,
 * and `min_others` in particular -- which is the reason a caller should think
 * about that number before it thinks about this default.
 *
 * `min_others` IS THE CALLER'S AND THIS LIBRARY WILL NOT CHOOSE IT. How many
 * copies are enough is a question about somebody's network, their peers'
 * reliability and what the bytes are worth, and a default here would be a
 * number nobody chose applied to data nobody can get back. Zero means the
 * caller takes responsibility and the witness seam is not consulted at all --
 * which is right for a cache and wrong for the only copy of a photograph, and
 * the caller is the one who knows which it has.
 *
 * `now` IS READ ONCE, HERE, AND NOWHERE ELSE IN THE JOB. sec 157 gave
 * retention deadlines, so "does this host keep it" is a question with a
 * moment in it -- and taking that moment at capture is what keeps sec 155's
 * cursor sound. A sweep that re-read the clock per step would be a different
 * sweep at every step, and a job resumed after a restart would resume into a
 * decision nobody took. A consumer that wants the schedule's later answer
 * captures again.
 *
 * ROWS ARE SORTED BY NODE ID, so the order is the same on every machine and
 * after every restart whatever order the content table happens to be in. That
 * is what lets the cursor be a count.
 *
 * FZN_CATALOG_ERR_BUSY while any job holds the catalogue. A sweep captured
 * mid-refile would be deciding against a filing that is being rearranged.
 *
 * IT TALKS THROUGH THE CATALOGUE'S LOG, set by `fzn_catalog_set_log`, and
 * about two things a plan cannot say for itself. A `min_others` of zero is
 * noted, because the plan it returns is indistinguishable from one that
 * passed the last-copy guard -- `last_copy` is zero whether the seam refused
 * nothing or was never asked. A truncated job is warned about, because a
 * consumer running it to the end reclaims less than the catalogue offered.
 * Neither is an error and neither has anywhere else to be said.
 */
fzn_catalog_err_t fzn_catalog_sweep_capture(const fzn_catalog_t *catalog,
                                            const fzn_catalog_holdings_ops_t *holdings,
                                            const fzn_catalog_witness_ops_t *witness,
                                            size_t min_others, uint64_t now,
                                            fzn_catalog_sweep_t *job,
                                            fzn_catalog_removal_t *removals, size_t capacity,
                                            fzn_catalog_sweep_plan_t *plan);

/* Take the catalogue. Idempotent, because a restart calls it again on a job
 * it has loaded from disk -- the refile's argument exactly. Refuses
 * FZN_CATALOG_ERR_BUSY when another kind of job holds it. */
fzn_catalog_err_t fzn_catalog_sweep_begin(fzn_catalog_t *catalog, fzn_catalog_sweep_t *job);

/* The step the cursor is on: which node, and which bytes to remove.
 *
 * FZN_CATALOG_ERR_ABSENT when the cursor is past the last removal, which is
 * how a caller knows the work is finished. */
fzn_catalog_err_t fzn_catalog_sweep_at(const fzn_catalog_sweep_t *job,
                                       fzn_catalog_removal_t *out);

/* One removal done. Called AFTER the bytes are gone, so a crash between the
 * two repeats a removal rather than skipping one -- the direction that loses
 * nothing, since removing what is already removed is an error a consumer can
 * ignore. The refile makes the same choice for the same reason. */
fzn_catalog_err_t fzn_catalog_sweep_advance(fzn_catalog_sweep_t *job);

/* What to draw. Answers while a sweep is under way, which is the one thing
 * the holder asked stay possible of a job that holds the catalogue. */
fzn_catalog_err_t fzn_catalog_sweep_progress(const fzn_catalog_sweep_t *job, size_t *done_out,
                                             size_t *total_out);

/* Give the catalogue back. Refuses while work remains, so a consumer cannot
 * end a sweep it abandoned and leave the catalogue unlocked while its own
 * record of what it meant to remove is discarded. */
fzn_catalog_err_t fzn_catalog_sweep_end(fzn_catalog_t *catalog, fzn_catalog_sweep_t *job);

#endif /* FZN_CATALOG_SWEEP_H */
