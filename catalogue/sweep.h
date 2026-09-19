/* THE SWEEP PLANNER over the new model. project.md sec 317 step 2, and sec
 * 321.
 *
 * IT IS A PLANNER AND NOT A DELETER, which is the old catalog/sweep.h's
 * property and is kept deliberately. It decides what MAY go and writes rows
 * into caller-owned storage; the bytes are removed outside this library, by
 * whoever owns the filestore. Nothing here opens, writes or unlinks anything.
 * C17: a removal is an explicit gesture, never a consequence of a query.
 *
 * WHAT CHANGED FROM catalog/sweep.h IS THE DATA SOURCE, NOT THE GUARD CHAIN.
 * The old planner walked an edge DAG and asked two callback seams -- a
 * holdings op for "does this host have the bytes" and a witness op for "how
 * many others do". Both are gone: the guards now read the assertion set the
 * caller already holds. The chain itself, its order, its counters and its
 * cursor are the tested ones, because they were right and re-deriving them
 * from scratch would have risked re-introducing what they already fixed.
 *
 *     old                              new
 *     fzn_catalog_keeps                fzn_catalogue_keeps        (step 3)
 *     a_retained_node_needs            fzn_catalogue_referenced   (step 1)
 *     holdings->holds callback         this host among the holders
 *     witness->others callback         the holder count, less this host
 *
 * THE TWO SEAMS DISAPPEARING IS THE POINT OF THE NEW MODEL. Each was a
 * callback a consumer had to supply and could supply wrongly, and an absent
 * one answered conservatively because there was nothing better to do. Both
 * questions are now derived from records that had to be signed by a host that
 * actually holds the bytes (C5e/C8a), so a consumer cannot answer them at all,
 * let alone wrongly.
 *
 * THERE IS NO LOCK HERE, AND THAT IS A CONSEQUENCE RATHER THAN AN OMISSION.
 * The old planner refused to capture while another job held `catalog->busy_with`,
 * because that module owned a container to hold the flag. The new model owns
 * none -- every query takes the caller's assertion set -- so there is nothing
 * to lock and nobody to lock it against. What the flag protected still has to
 * hold: the set and the retention table must not change between capture and
 * the last removal, or the cursor is a count into something that has moved.
 * That is now the caller's to guarantee, and it is stated here rather than
 * enforced, because an unstated precondition and an absent one look identical
 * from outside.
 */

#ifndef FZN_CATALOGUE_SWEEP_H
#define FZN_CATALOGUE_SWEEP_H

#include <stddef.h>
#include <stdint.h>

#include "catalogue.h"
#include "retention.h"

/* Declared, not included. sec 209 -- the same shape catalog/catalog.h uses,
 * and the only difference is where the handle lives. That module kept it in
 * the container it owned; this model owns none, so it comes in on the call.
 * NULL is silence. */
struct flog_t;

/* One planned removal.
 *
 * THE ENTITY IS THE WHOLE ROW, where catalog/'s carried a node id, a blob root
 * and a length. C1 collapses the first two: an entity IS the content hash the
 * filestore knows the file by, so there is no node that points at bytes and no
 * two entities can name the same bytes. The length is gone because nothing in
 * this model carries it -- a consumer holding a content hash asks its own
 * filestore how big it is, and a field this planner cannot source would be one
 * it invented. */
typedef struct fzn_catalogue_removal {
	uint8_t entity[FZN_CATALOGUE_ENTITY_LEN];
} fzn_catalogue_removal_t;

/*
 * What became of every entity the set names.
 *
 * THE POPULATION IS THE DISTINCT ENTITIES, and they partition -- each lands in
 * exactly one counter, and the suite asserts the sum:
 *
 *     distinct entities = planned + retained + referenced + last_copy
 *                       + absent + incomplete + truncated
 *
 * An entity NO assertion names is not in the population, and that is C9: it
 * may still sit on disk, and removing it is the explicit C17 gesture rather
 * than something a planner arrives at. An entity this host holds is always in
 * the population, because holding it means having issued a HOLDER assertion
 * that names it.
 *
 * THEY ARE KEPT APART RATHER THAN SUMMED because a consumer that swept nothing
 * needs to say WHY, and the reasons call for different actions: `retained` is
 * this host's own policy working, `referenced` and `last_copy` are the two
 * guards refusing, `absent` is nothing to do, `incomplete` is partial data,
 * and `truncated` is the caller's own sizing. Collapsed into one number, a
 * sweep held back by the last-copy guard would be indistinguishable from a set
 * with nothing to sweep -- and those want opposite responses.
 */
typedef struct fzn_catalogue_sweep_plan {
	/* Rows written to the job. */
	size_t planned;
	/* This host keeps it, so not a candidate at all. */
	size_t retained;
	/* A live CURATED assertion still names it. A holder assertion is not
	 * one -- see fzn_catalogue_referenced, and sec 321 for what counting it
	 * did. */
	size_t referenced;
	/* Too few OTHER hosts are known to hold it; `min_others` says how few
	 * is too few. */
	size_t last_copy;
	/* This host does not have the bytes anyway -- already swept, or never
	 * fetched. Nothing to do rather than a refusal, and counted apart so an
	 * empty sweep is legible. */
	size_t absent;
	/* THE HOLDERS COULD NOT BE DETERMINED, so nothing was decided. sec
	 * 316's asymmetry: on partial data, never delete. Counted apart from
	 * `last_copy` because they call for opposite responses -- a last copy
	 * means go and replicate it, an incomplete answer means go and catch
	 * up with a source before sweeping again. */
	size_t incomplete;
	/* Removable, and the job's rows ran out. Loud, because a sweep that
	 * silently held some of them would leave a consumer believing it had
	 * reclaimed what it had not. */
	size_t truncated;
} fzn_catalogue_sweep_plan_t;

typedef struct fzn_catalogue_sweep {
	fzn_catalogue_removal_t *removals;
	size_t capacity;
	size_t used;
	/* How many have been removed. The whole of the resumable state, and
	 * meaningful only because nothing may change the set meanwhile. */
	size_t done;
	int captured;
} fzn_catalogue_sweep_t;

/*
 * Decide what may go, into caller-owned rows.
 *
 * An entity is a candidate when this host does NOT keep it -- `holds` says, so
 * both the catalogue-wide bit and any override apply, and a NULL table keeps
 * nothing and makes everything a candidate. A candidate is planned when no
 * live curated assertion names it, this host is among its holders, and at
 * least `min_others` OTHER hosts are too.
 *
 * `self` is this host's key, and it is what turns the holder set into the two
 * questions the old callbacks answered: whether this host has the bytes, and
 * how many others do.
 *
 * `min_others` OF ZERO SWITCHES THE LAST-COPY GUARD OFF, which is a legitimate
 * answer for a cache and the wrong one for the only copy of a photograph. It
 * is the caller's to give, and a capture that plans anything with it off says
 * so through the log, because the plan that comes back looks exactly like one
 * that passed the guard.
 *
 * `now` is a parameter rather than state, as everywhere else in this tree.
 *
 * `log` IS WHERE THIS SAYS WHAT IT DID, or NULL for silence. Three conditions
 * are reported there and nowhere a caller is forced to look: the last-copy
 * guard being switched off, a job that did not fit its rows, and entities left
 * undecided on partial data. Each is legible in the counters as well -- but a
 * plan with the guard off looks exactly like one that passed it, since
 * `last_copy` is zero either way, so a reader who did not already suspect it
 * has nothing to notice.
 */
fzn_catalogue_err_t fzn_catalogue_sweep_capture(const fzn_catalogue_assertion_t *set,
                                                size_t count,
                                                const fzn_catalogue_holds_t *holds,
                                                const uint8_t *self, size_t self_len,
                                                size_t min_others, uint64_t now,
                                                struct flog_t *log,
                                                fzn_catalogue_sweep_t *job,
                                                fzn_catalogue_removal_t *removals,
                                                size_t capacity,
                                                fzn_catalogue_sweep_plan_t *plan);

/* The row the cursor is on. FZN_CATALOGUE_ERR_RANGE when the job is done. */
fzn_catalogue_err_t fzn_catalogue_sweep_at(const fzn_catalogue_sweep_t *job,
                                           fzn_catalogue_removal_t *out);

/* Step past the row the cursor is on, once its bytes are gone. Idempotence is
 * NOT offered: a consumer that advances twice has skipped a removal, and this
 * cannot tell that from a retry. */
fzn_catalogue_err_t fzn_catalogue_sweep_advance(fzn_catalogue_sweep_t *job);

/* How far through. Both outputs are required, because a caller that wanted
 * only one of them would be computing a fraction from a number it did not
 * ask for. */
fzn_catalogue_err_t fzn_catalogue_sweep_progress(const fzn_catalogue_sweep_t *job,
                                                 size_t *done_out, size_t *total_out);

#endif /* FZN_CATALOGUE_SWEEP_H */
