/* See sweep.h. */

#include "sweep.h"

/* Diagnostics through flog, vendored and possibly absent. The old planner
 * spoke through the catalogue's own log, because a sweep is a thing that
 * happens TO a catalogue and a consumer that has already said where that
 * catalogue talks should not have to say it again per job. The new model owns
 * no container, so the handle comes in on the capture call instead -- see
 * sweep.h. NULL is silence, and silence is the default a caller gets by not
 * asking. */
#ifdef FZN_FLOG_ON
#include "flog.h"
#define SWEEP_LOG(log, sub, sev, ...)                                              \
	do {                                                                       \
		if (log)                                                           \
			flog_printf(log, sub, sev, FLOG_MSG_NONE, __VA_ARGS__);    \
	} while (0)
#else
#define SWEEP_LOG(log, sub, sev, ...) ((void)(log))
#endif

#include <string.h>

/* HOW MANY HOLDERS FIT BEFORE THE ANSWER STOPS BEING CERTAIN.
 *
 * `fzn_catalog_holders` writes a list and reports how many did not fit, so
 * the TOTAL is always knowable -- written plus dropped -- and it is only
 * whether THIS host is among them that a short buffer can hide. Sized for a
 * stack frame in a library that allocates nothing; an entity with more holders
 * than this is reported `incomplete` rather than guessed at, which is sec
 * 316's asymmetry and the safe direction, since the unsafe one is planning a
 * removal. */
#define HOLDER_SCRATCH 16u

static int bytes_eq(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen)
{
	if (alen != blen)
		return 0;
	if (alen == 0)
		return 1;
	return memcmp(a, b, alen) == 0;
}

/* Has this entity already been decided in this capture?
 *
 * THE POPULATION IS THE DISTINCT ENTITIES, so an entity named by five
 * assertions is one member of it and not five. The old planner counted repeats
 * in a `duplicates` bucket because several catalogue nodes could point at one
 * blob; C1 removes that case -- an entity IS the content hash -- so a repeat
 * here is the same entity named again and is skipped before any counter sees
 * it, rather than being counted as an outcome. */
static int already_seen(const fzn_catalog_assertion_t *set, size_t upto,
                        const uint8_t *entity, size_t entity_len)
{
	size_t i;

	for (i = 0; i < upto; i++)
		if (bytes_eq(set[i].entity, set[i].entity_len, entity, entity_len))
			return 1;
	return 0;
}

/* Insert in entity order.
 *
 * SORTED SO THE CURSOR MEANS THE SAME THING EVERYWHERE. The set's order is
 * whatever arrival happened to produce, and a count into an arrival-ordered
 * list resumes somewhere else on another machine. The old planner sorted for
 * exactly this reason and the note is repeated rather than cross-referenced,
 * because the next person to add a job will be reading whichever file they are
 * in. */
static void insert_sorted(fzn_catalog_removal_t *rows, size_t *used,
                          const fzn_catalog_removal_t *row)
{
	size_t at = *used;

	while (at > 0 && memcmp(rows[at - 1].entity, row->entity,
	                        FZN_CATALOG_ENTITY_LEN) > 0) {
		rows[at] = rows[at - 1];
		at--;
	}
	rows[at] = *row;
	(*used)++;
}

/* The two questions the old callback seams answered, from the records.
 *
 * Returns 0 when the holders could not be determined, and writes nothing. */
static int holder_facts(const fzn_catalog_assertion_t *set, size_t count,
                        const uint8_t *entity, size_t entity_len,
                        const uint8_t *self, size_t self_len,
                        int *self_holds, size_t *others)
{
	fzn_catalog_source_t who[HOLDER_SCRATCH];
	size_t written = 0, dropped = 0, i;
	int mine = 0;

	if (fzn_catalog_holders(set, count, entity, entity_len, who, HOLDER_SCRATCH,
	                          &written, &dropped) != FZN_CATALOG_OK)
		return 0;

	for (i = 0; i < written; i++)
		if (bytes_eq(who[i].issuer, who[i].issuer_len, self, self_len))
			mine = 1;

	/* THE TOTAL SURVIVES A SHORT BUFFER; THE MEMBERSHIP DOES NOT. Written
	 * plus dropped is the true holder count whatever fitted, so the
	 * last-copy arithmetic is sound. But a `self` that did not fit is
	 * indistinguishable from a `self` that is not a holder, and those lead
	 * to opposite outcomes -- planning a removal, or recording that there
	 * is nothing here to remove. Refuse to answer rather than pick. */
	if (!mine && dropped > 0)
		return 0;

	*self_holds = mine;
	*others = written + dropped - (mine ? 1u : 0u);
	return 1;
}

fzn_catalog_err_t fzn_catalog_sweep_capture(const fzn_catalog_assertion_t *set,
                                                size_t count,
                                                const fzn_catalog_holds_t *holds,
                                                const uint8_t *self, size_t self_len,
                                                size_t min_others, uint64_t now,
                                                struct flog_t *log,
                                                fzn_catalog_sweep_t *job,
                                                fzn_catalog_removal_t *removals,
                                                size_t capacity,
                                                fzn_catalog_sweep_plan_t *plan)
{
	size_t i;

	if (!plan)
		return FZN_CATALOG_ERR_MALFORMED;
	memset(plan, 0, sizeof(*plan));
	if ((count != 0 && !set) || !self || self_len == 0 || !job || !removals ||
	    capacity == 0)
		return FZN_CATALOG_ERR_MALFORMED;

	memset(job, 0, sizeof(*job));
	job->removals = removals;
	job->capacity = capacity;

	for (i = 0; i < count; i++) {
		const fzn_catalog_assertion_t *a = &set[i];
		fzn_catalog_removal_t row;
		int self_holds = 0;
		size_t others = 0;

		/* An entity this planner cannot key a row on. The retention
		 * table refuses the same lengths for the same reason, so a
		 * shorter or longer entity could not have been kept or dropped
		 * either; it is not in the population. */
		if (a->entity_len != FZN_CATALOG_ENTITY_LEN)
			continue;
		if (already_seen(set, i, a->entity, a->entity_len))
			continue;

		if (fzn_catalog_keeps(holds, a->entity, a->entity_len, now)) {
			plan->retained++;
			continue;
		}
		/* STILL WANTED BY SOMETHING. A holder assertion is not a want
		 * -- see fzn_catalog_referenced and sec 321. */
		if (fzn_catalog_referenced(set, count, a->entity, a->entity_len)) {
			plan->referenced++;
			continue;
		}
		if (!holder_facts(set, count, a->entity, a->entity_len, self, self_len,
		                  &self_holds, &others)) {
			plan->incomplete++;
			continue;
		}
		if (!self_holds) {
			plan->absent++;
			continue;
		}
		/* THE LAST-COPY GUARD, and `min_others` of zero switches it off
		 * entirely rather than asking a question whose answer would not
		 * be used. A caller that says zero has said it takes
		 * responsibility. */
		if (min_others > 0 && others < min_others) {
			plan->last_copy++;
			continue;
		}

		if (job->used >= job->capacity) {
			plan->truncated++;
			continue;
		}

		memcpy(row.entity, a->entity, FZN_CATALOG_ENTITY_LEN);
		insert_sorted(job->removals, &job->used, &row);
	}

	plan->planned = job->used;
	job->captured = 1;

	/*
	 * THE GUARD BEING OFF IS NOT AN ERROR AND MUST NOT BE SILENT.
	 *
	 * `min_others` of zero is the caller's to give, and what it does is
	 * switch off the one check standing between a plan and losing bytes
	 * nobody else has. The plan that comes back looks exactly like one that
	 * passed the guard: `last_copy` is zero either way, because the
	 * question was never asked. So this is a note and not a warning --
	 * nothing is wrong; something irreversible is about to happen with a
	 * check disabled, which is precisely what a note is for.
	 *
	 * Silent when it planned nothing, because a capture that would remove
	 * nothing has not disabled anything that mattered.
	 */
	if (min_others == 0u && plan->planned > 0u)
		SWEEP_LOG(log, "catalog/sweep", FLOG_NOTE,
		          "planning to remove %zu entities with the last-copy guard "
		          "off: min_others is 0, so no holder count was required",
		          plan->planned);

	/* AND A JOB THAT DID NOT FIT SAYS SO. A consumer that runs this job to
	 * completion and frees nothing more has reclaimed less than it asked
	 * for, and nothing else in the run says which. */
	if (plan->truncated > 0u)
		SWEEP_LOG(log, "catalog/sweep", FLOG_WARN,
		          "%zu removable entities did not fit in this job's %zu rows, "
		          "so running it to the end reclaims less than the set offered",
		          plan->truncated, job->capacity);

	/* AND PARTIAL DATA IS THE ONE A CONSUMER MUST NOT READ AS "NOTHING TO
	 * DO". An incomplete holder answer means a source has not been caught
	 * up with, and sweeping again before it is will reach the same wall. */
	if (plan->incomplete > 0u)
		SWEEP_LOG(log, "catalog/sweep", FLOG_NOTE,
		          "%zu entities were left undecided because their holders could "
		          "not be determined; catch up with the sources before sweeping "
		          "again rather than reading this as nothing to do",
		          plan->incomplete);

	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_sweep_at(const fzn_catalog_sweep_t *job,
                                           fzn_catalog_removal_t *out)
{
	if (!job || !job->captured || !out)
		return FZN_CATALOG_ERR_MALFORMED;
	if (job->done >= job->used)
		return FZN_CATALOG_ERR_RANGE;

	*out = job->removals[job->done];
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_sweep_advance(fzn_catalog_sweep_t *job)
{
	if (!job || !job->captured)
		return FZN_CATALOG_ERR_MALFORMED;
	if (job->done >= job->used)
		return FZN_CATALOG_ERR_RANGE;

	job->done++;
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_sweep_progress(const fzn_catalog_sweep_t *job,
                                                 size_t *done_out, size_t *total_out)
{
	if (!job || !job->captured || !done_out || !total_out)
		return FZN_CATALOG_ERR_MALFORMED;

	*done_out = job->done;
	*total_out = job->used;
	return FZN_CATALOG_OK;
}
