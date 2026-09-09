/* See sweep.h. */

#include "sweep.h"

/* Diagnostics through flog, vendored and possibly absent. sec 209.
 *
 * THROUGH THE CATALOGUE'S LOG rather than one of the job's own. A sweep is a
 * thing that happens TO a catalogue, and a consumer that has already said
 * where that catalogue talks should not have to say it again for each job --
 * the sublog name it chose is what puts these lines under the same heading as
 * everything else the catalogue said. */
#ifdef FZN_FLOG_ON
#include "flog.h"
#define SWEEP_LOG(c, sub, sev, ...)                                                        	do {                                                                               		if ((c) && (c)->log)                                                       			flog_printf((c)->log, sub, sev, FLOG_MSG_NONE, __VA_ARGS__);        	} while (0)
#else
#define SWEEP_LOG(c, sub, sev, ...) ((void)0)
#endif

#include <string.h>

/* Whether any RETAINED node needs these bytes.
 *
 * THE GUARD A CONSUMER ACTING MARK BY MARK CANNOT HAVE, and the reason a
 * deletion is planned rather than immediate. Several nodes sharing one blob
 * is the whole reason to choose a blob over an inline value, so one node
 * saying DROP says nothing about the bytes until every node that reaches them
 * has said it. */
static int a_retained_node_needs(const fzn_catalog_t *catalog,
                                 const uint8_t root[FZN_BLOB_HASH_LEN], uint64_t now)
{
	size_t i;

	for (i = 0; i < catalog->entry_used; i++) {
		const fzn_catalog_entry_t *entry = &catalog->entries[i];

		if (entry->kind != FZN_CATALOG_CONTENT_BLOB)
			continue;
		if (memcmp(entry->root, root, FZN_BLOB_HASH_LEN) != 0)
			continue;
		if (fzn_catalog_keeps(catalog, &entry->id, now))
			return 1;
	}

	return 0;
}

static int this_host_holds(const fzn_catalog_holdings_ops_t *holdings,
                           const uint8_t root[FZN_BLOB_HASH_LEN], uint64_t len)
{
	if (!holdings || !holdings->holds)
		return 0;

	return holdings->holds(holdings->ctx, root, len) != 0;
}

/* How many other hosts are known to have them.
 *
 * AN ABSENT SEAM ANSWERS ZERO, which refuses the deletion whenever
 * `min_others` is above zero. sweep.h argues it: one rule, the conservative
 * answer, which for a fetch is "ask again" and for a deletion is "keep the
 * bytes". */
static size_t others_holding(const fzn_catalog_witness_ops_t *witness,
                             const uint8_t root[FZN_BLOB_HASH_LEN], uint64_t len)
{
	if (!witness || !witness->others)
		return 0;

	return witness->others(witness->ctx, root, len);
}

static int already_planned(const fzn_catalog_removal_t *rows, size_t used,
                           const uint8_t root[FZN_BLOB_HASH_LEN])
{
	size_t i;

	for (i = 0; i < used; i++) {
		if (memcmp(rows[i].root, root, FZN_BLOB_HASH_LEN) == 0)
			return 1;
	}

	return 0;
}

/* Insert in node-id order.
 *
 * SORTED SO THE CURSOR MEANS THE SAME THING EVERYWHERE. The content table's
 * order is whatever arrival happened to produce, and a count into an
 * arrival-ordered list resumes somewhere else on another machine. The refile
 * sorts for exactly this reason and the note is worth repeating here rather
 * than cross-referenced, because the next person to add a job will be reading
 * whichever file they are in. */
static void insert_sorted(fzn_catalog_removal_t *rows, size_t *used,
                          const fzn_catalog_removal_t *row)
{
	size_t at = *used;

	while (at > 0 && memcmp(rows[at - 1].node.b, row->node.b, FZN_CATALOG_ID_LEN) > 0) {
		rows[at] = rows[at - 1];
		at--;
	}
	rows[at] = *row;
	(*used)++;
}

fzn_catalog_err_t fzn_catalog_sweep_capture(const fzn_catalog_t *catalog,
                                            const fzn_catalog_holdings_ops_t *holdings,
                                            const fzn_catalog_witness_ops_t *witness,
                                            size_t min_others, uint64_t now,
                                            fzn_catalog_sweep_t *job,
                                            fzn_catalog_removal_t *removals, size_t capacity,
                                            fzn_catalog_sweep_plan_t *plan)
{
	size_t i;

	if (!plan)
		return FZN_CATALOG_ERR_MALFORMED;
	memset(plan, 0, sizeof(*plan));
	/* `edges` is what `fzn_catalog_init` sets, so this is "has this
	 * catalogue been initialised" -- checked here because the other four
	 * entry points check it and a capture that did not would be the one
	 * door into the job left open. */
	if (!catalog || !catalog->edges || !job || !removals || capacity == 0)
		return FZN_CATALOG_ERR_MALFORMED;
	/* A sweep captured while a refile runs would be deciding against a
	 * filing that is being rearranged. sec 149. */
	if (catalog->busy_with != FZN_CATALOG_JOB_NONE)
		return FZN_CATALOG_ERR_BUSY;

	memset(job, 0, sizeof(*job));
	job->removals = removals;
	job->capacity = capacity;

	for (i = 0; i < catalog->entry_used; i++) {
		const fzn_catalog_entry_t *entry = &catalog->entries[i];
		fzn_catalog_removal_t row;

		if (entry->kind != FZN_CATALOG_CONTENT_BLOB)
			continue;
		/* AN INLINE VALUE IS NOT SWEPT AND CANNOT BE. It lives inside
		 * the record that asserted it, so there is nothing on disk to
		 * remove that is not the record itself -- and removing that is
		 * the journal's business rather than the catalogue's. */

		if (fzn_catalog_keeps(catalog, &entry->id, now)) {
			plan->retained++;
			continue;
		}
		if (a_retained_node_needs(catalog, entry->root, now)) {
			plan->shared++;
			continue;
		}
		if (!this_host_holds(holdings, entry->root, entry->blob_len)) {
			plan->absent++;
			continue;
		}
		/* THE LAST-COPY GUARD, and `min_others` of zero switches it off
		 * entirely rather than asking a seam whose answer would not be
		 * used. A caller that says zero has said it takes
		 * responsibility. */
		if (min_others > 0 &&
		    others_holding(witness, entry->root, entry->blob_len) < min_others) {
			plan->last_copy++;
			continue;
		}

		if (already_planned(job->removals, job->used, entry->root)) {
			plan->duplicates++;
			continue;
		}
		if (job->used >= job->capacity) {
			plan->truncated++;
			continue;
		}

		row.node = entry->id;
		memcpy(row.root, entry->root, FZN_BLOB_HASH_LEN);
		row.len = entry->blob_len;
		insert_sorted(job->removals, &job->used, &row);
	}

	plan->planned = job->used;
	job->captured = 1;

	/*
	 * THE GUARD BEING OFF IS NOT AN ERROR AND MUST NOT BE SILENT.
	 *
	 * `min_others` of zero is a legitimate answer -- right for a cache,
	 * this header says, and wrong for the only copy of a photograph -- and
	 * it is the caller's to give. What it does is switch off the one check
	 * standing between a plan and losing bytes nobody else has, and the
	 * plan that comes back looks exactly like one that passed the guard:
	 * `last_copy` is zero either way, because the seam was never asked.
	 *
	 * So this is FLOG_NOTE and not a warning. Nothing is wrong; something
	 * irreversible is about to happen with a check disabled, which is
	 * precisely what a note is for.
	 *
	 * SILENT WHEN IT PLANNED NOTHING, because a capture that would remove
	 * nothing has not disabled anything that mattered.
	 */
	if (min_others == 0u && plan->planned > 0u)
		SWEEP_LOG(catalog, "catalog/sweep", FLOG_NOTE,
		          "planning to remove %zu blobs with the last-copy guard off: "
		          "min_others is 0, so no witness was asked whether anybody else "
		          "holds them",
		          plan->planned);

	/*
	 * AND A JOB THAT DID NOT FIT SAYS SO. sweep.h calls `truncated` loud --
	 * "a sweep that silently held some of them would leave a consumer
	 * believing it had reclaimed what it had not" -- and until now the
	 * only voice it had was a counter beside six others. A consumer that
	 * runs this job to completion and frees nothing more has reclaimed
	 * less than it asked for, and nothing else in the run says which.
	 */
	if (plan->truncated > 0u)
		SWEEP_LOG(catalog, "catalog/sweep", FLOG_WARN,
		          "%zu removable blobs did not fit in this job's %zu rows, so "
		          "running it to the end reclaims less than the catalogue offered",
		          plan->truncated, job->capacity);

	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_sweep_begin(fzn_catalog_t *catalog, fzn_catalog_sweep_t *job)
{
	if (!catalog || !catalog->edges || !job || !job->captured)
		return FZN_CATALOG_ERR_MALFORMED;
	/* Another kind of job's lock is not this one's to take. sec 155. */
	if (catalog->busy_with != FZN_CATALOG_JOB_NONE &&
	    catalog->busy_with != FZN_CATALOG_JOB_SWEEP)
		return FZN_CATALOG_ERR_BUSY;

	/* IDEMPOTENT, BECAUSE A RESTART CALLS IT AGAIN, exactly as a refile's
	 * does: a consumer that crashed mid-sweep reloads the job and begins
	 * the same one. */
	catalog->busy_with = FZN_CATALOG_JOB_SWEEP;
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_sweep_at(const fzn_catalog_sweep_t *job,
                                       fzn_catalog_removal_t *out)
{
	if (!job || !job->captured || !out)
		return FZN_CATALOG_ERR_MALFORMED;
	if (job->done >= job->used)
		return FZN_CATALOG_ERR_ABSENT;

	*out = job->removals[job->done];
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_sweep_advance(fzn_catalog_sweep_t *job)
{
	if (!job || !job->captured)
		return FZN_CATALOG_ERR_MALFORMED;
	if (job->done >= job->used)
		return FZN_CATALOG_ERR_ABSENT;

	job->done++;
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_sweep_progress(const fzn_catalog_sweep_t *job, size_t *done_out,
                                             size_t *total_out)
{
	if (!job || !job->captured || !done_out || !total_out)
		return FZN_CATALOG_ERR_MALFORMED;

	*done_out = job->done;
	*total_out = job->used;
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_sweep_end(fzn_catalog_t *catalog, fzn_catalog_sweep_t *job)
{
	if (!catalog || !catalog->edges || !job || !job->captured)
		return FZN_CATALOG_ERR_MALFORMED;
	/* Refused while work remains, so a consumer cannot end a sweep it
	 * abandoned and discard its own record of what it meant to remove. */
	if (job->done < job->used)
		return FZN_CATALOG_ERR_BUSY;
	/* And a job is ended by the job that started it. */
	if (catalog->busy_with != FZN_CATALOG_JOB_NONE &&
	    catalog->busy_with != FZN_CATALOG_JOB_SWEEP)
		return FZN_CATALOG_ERR_BUSY;

	catalog->busy_with = FZN_CATALOG_JOB_NONE;
	return FZN_CATALOG_OK;
}
