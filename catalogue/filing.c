/* See filing.h. */

#include "filing.h"

#include <string.h>

static int bytes_eq(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen)
{
	if (alen != blen)
		return 0;
	if (alen == 0)
		return 1;
	return memcmp(a, b, alen) == 0;
}

/* Is this (entity, name, value) a link the records actually assert?
 *
 * LIVE AND CURATED, both. Liveness is C5c: a retracted link is not a place an
 * entity belongs. Curated is C9 and sec 321: a HOLDER-capability assertion
 * says where bytes ARE, not where they BELONG, so filing on the strength of
 * one would let the fact that a host holds something decide where it files it
 * -- which is the fixpoint that section describes, wearing different clothes. */
static int link_asserted(const fzn_catalogue_assertion_t *set, size_t count,
                         const uint8_t *entity, size_t entity_len, const uint8_t *name,
                         size_t name_len, const uint8_t *path, size_t path_len)
{
	size_t i;

	for (i = 0; i < count; i++) {
		const fzn_catalogue_assertion_t *a = &set[i];

		/* C5c: a retracted link is not a place an entity belongs. */
		if (!a->live)
			continue;
		/* C9 and sec 321: a HOLDER assertion says where the bytes ARE,
		 * not where they BELONG. Filing on one would let the fact that
		 * a host holds something decide where it files it. */
		if (a->capability == FZN_CATALOGUE_CAP_HOLDER)
			continue;
		if (!bytes_eq(a->entity, a->entity_len, entity, entity_len))
			continue;
		if (!bytes_eq(a->name, a->name_len, name, name_len))
			continue;
		if (bytes_eq(a->value, a->value_len, path, path_len))
			return 1;
	}

	return 0;
}

static fzn_catalogue_filing_t *find(const fzn_catalogue_filings_t *filings,
                                    const uint8_t *entity)
{
	size_t i;

	for (i = 0; i < filings->used; i++)
		if (memcmp(filings->rows[i].entity, entity, FZN_CATALOGUE_ENTITY_LEN) == 0)
			return &filings->rows[i];
	return NULL;
}

static int usable(const fzn_catalogue_filings_t *filings, const uint8_t *entity,
                  size_t entity_len)
{
	if (!filings || !entity)
		return 0;
	if (entity_len != FZN_CATALOGUE_ENTITY_LEN)
		return 0;
	return filings->capacity == 0 || filings->rows != NULL;
}

/* Does the set still assert this row's link? */
static int row_backed(const fzn_catalogue_filing_t *row,
                      const fzn_catalogue_assertion_t *set, size_t count)
{
	return link_asserted(set, count, row->entity, FZN_CATALOGUE_ENTITY_LEN, row->name,
	                     row->name_len, row->path, row->path_len);
}

fzn_catalogue_err_t fzn_catalogue_filings_init(fzn_catalogue_filings_t *filings,
                                               fzn_catalogue_filing_t *rows,
                                               size_t capacity)
{
	if (!filings)
		return FZN_CATALOGUE_ERR_MALFORMED;
	if (capacity > 0 && !rows)
		return FZN_CATALOGUE_ERR_MALFORMED;

	memset(filings, 0, sizeof(*filings));
	filings->rows = rows;
	filings->capacity = capacity;
	return FZN_CATALOGUE_OK;
}

fzn_catalogue_err_t fzn_catalogue_file_under(fzn_catalogue_filings_t *filings,
                                             const fzn_catalogue_assertion_t *set,
                                             size_t count, const uint8_t *entity,
                                             size_t entity_len, const uint8_t *name,
                                             size_t name_len, const uint8_t *path,
                                             size_t path_len)
{
	fzn_catalogue_filing_t *row;

	if (!usable(filings, entity, entity_len))
		return FZN_CATALOGUE_ERR_MALFORMED;
	if ((count != 0 && !set) || (name_len != 0 && !name) || (path_len != 0 && !path))
		return FZN_CATALOGUE_ERR_MALFORMED;
	/* REFUSED RATHER THAN TRUNCATED. A truncated path names a different
	 * place, and moving a file there is not a smaller error than refusing
	 * to move it at all. */
	if (name_len > FZN_CATALOGUE_FILING_NAME_MAX ||
	    path_len > FZN_CATALOGUE_FILING_PATH_MAX)
		return FZN_CATALOGUE_ERR_RANGE;
	/* A FILING IS A SUBSET OF WHAT THE RECORDS ASSERT. */
	if (!link_asserted(set, count, entity, entity_len, name, name_len, path, path_len))
		return FZN_CATALOGUE_ERR_ABSENT;

	row = find(filings, entity);
	if (!row) {
		if (filings->used >= filings->capacity)
			return FZN_CATALOGUE_ERR_RANGE;
		row = &filings->rows[filings->used];
		memcpy(row->entity, entity, FZN_CATALOGUE_ENTITY_LEN);
		filings->used++;
	}

	/* EXACTLY ONCE, STRUCTURALLY: this overwrites whatever was here, so a
	 * second place is not expressible rather than being detected. */
	memset(row->name, 0, sizeof(row->name));
	memset(row->path, 0, sizeof(row->path));
	if (name_len)
		memcpy(row->name, name, name_len);
	if (path_len)
		memcpy(row->path, path, path_len);
	row->name_len = name_len;
	row->path_len = path_len;
	return FZN_CATALOGUE_OK;
}

fzn_catalogue_err_t fzn_catalogue_unfile(fzn_catalogue_filings_t *filings,
                                         const uint8_t *entity, size_t entity_len)
{
	fzn_catalogue_filing_t *row;

	if (!usable(filings, entity, entity_len))
		return FZN_CATALOGUE_ERR_MALFORMED;

	row = find(filings, entity);
	if (!row)
		return FZN_CATALOGUE_OK;

	*row = filings->rows[filings->used - 1u];
	filings->used--;
	return FZN_CATALOGUE_OK;
}

const fzn_catalogue_filing_t *fzn_catalogue_filed_under(
        const fzn_catalogue_filings_t *filings, const fzn_catalogue_assertion_t *set,
        size_t count, const uint8_t *entity, size_t entity_len)
{
	const fzn_catalogue_filing_t *row;

	if (!usable(filings, entity, entity_len))
		return NULL;
	if (count != 0 && !set)
		return NULL;

	row = find(filings, entity);
	if (!row)
		return NULL;
	/* THE RE-CHECK. See filing.h: there is no unlink to hook, so a filing
	 * whose link has been retracted is refused here rather than cleared
	 * when it stopped being true. A path computed from a membership nobody
	 * asserts is worse than no path. */
	if (!row_backed(row, set, count))
		return NULL;
	return row;
}

size_t fzn_catalogue_filing_prune(fzn_catalogue_filings_t *filings,
                                  const fzn_catalogue_assertion_t *set, size_t count)
{
	size_t i = 0;
	size_t dropped = 0;

	if (!filings || !filings->rows || (count != 0 && !set))
		return 0;

	while (i < filings->used) {
		if (row_backed(&filings->rows[i], set, count)) {
			i++;
			continue;
		}
		/* Swap with the last and re-examine this slot, which now holds
		 * a row that has not been looked at. */
		filings->rows[i] = filings->rows[filings->used - 1u];
		filings->used--;
		dropped++;
	}

	return dropped;
}

size_t fzn_catalogue_filing_count(const fzn_catalogue_filings_t *filings)
{
	return filings ? filings->used : 0;
}

/* Insert in entity order, so the cursor means the same thing everywhere. The
 * table's order is whatever filing happened to produce, and a count into it
 * resumes somewhere else after a restart that rebuilt it. */
static void insert_sorted(fzn_catalogue_move_t *moves, size_t *used,
                          const fzn_catalogue_move_t *move)
{
	size_t at = *used;

	while (at > 0 && memcmp(moves[at - 1].entity, move->entity,
	                        FZN_CATALOGUE_ENTITY_LEN) > 0) {
		moves[at] = moves[at - 1];
		at--;
	}
	moves[at] = *move;
	(*used)++;
}

fzn_catalogue_err_t fzn_catalogue_refile_capture(const fzn_catalogue_filings_t *filings,
                                                 fzn_catalogue_refile_t *job,
                                                 fzn_catalogue_move_t *moves,
                                                 size_t capacity)
{
	size_t i;

	if (!job)
		return FZN_CATALOGUE_ERR_MALFORMED;
	/* ZEROED BEFORE ANYTHING IS CHECKED, so a refused capture cannot leave
	 * a job that reads as usable -- `captured` is what every call below
	 * trusts, and a caller whose capture failed must not be able to walk a
	 * cursor over whatever was on the stack. The plan structs in
	 * catalogue/sweep.h and catalogue/copy.h are zeroed first for the same
	 * reason; found by the test asserting it. */
	memset(job, 0, sizeof(*job));
	if (!filings || (!moves && capacity > 0))
		return FZN_CATALOGUE_ERR_MALFORMED;
	if (filings->capacity > 0 && !filings->rows)
		return FZN_CATALOGUE_ERR_MALFORMED;
	/* LOUDLY, because a capture that silently held some of them would move
	 * some of the files and leave the rest where a stale path says they
	 * are -- and nothing afterwards would say which. */
	if (filings->used > capacity)
		return FZN_CATALOGUE_ERR_RANGE;

	job->moves = moves;
	job->capacity = capacity;

	for (i = 0; i < filings->used; i++) {
		const fzn_catalogue_filing_t *row = &filings->rows[i];
		fzn_catalogue_move_t move;

		memset(&move, 0, sizeof(move));
		memcpy(move.entity, row->entity, FZN_CATALOGUE_ENTITY_LEN);
		memcpy(move.was_name, row->name, sizeof(move.was_name));
		memcpy(move.was_path, row->path, sizeof(move.was_path));
		move.was_name_len = row->name_len;
		move.was_path_len = row->path_len;
		insert_sorted(job->moves, &job->used, &move);
	}

	job->captured = 1;
	return FZN_CATALOGUE_OK;
}

fzn_catalogue_err_t fzn_catalogue_refile_at(const fzn_catalogue_refile_t *job,
                                            const fzn_catalogue_filings_t *filings,
                                            const fzn_catalogue_assertion_t *set,
                                            size_t count,
                                            const fzn_catalogue_move_t **from,
                                            const fzn_catalogue_filing_t **to)
{
	const fzn_catalogue_move_t *move;

	if (!job || !job->captured || !filings || !from || !to)
		return FZN_CATALOGUE_ERR_MALFORMED;
	if (job->done >= job->used)
		return FZN_CATALOGUE_ERR_RANGE;

	move = &job->moves[job->done];
	*from = move;
	/* NULL IS A REAL ANSWER. The consumer may have unfiled it, or its link
	 * may have been retracted since -- and what to do with a file whose
	 * entity has no home is the consumer's decision, not this library's. */
	*to = fzn_catalogue_filed_under(filings, set, count, move->entity,
	                                FZN_CATALOGUE_ENTITY_LEN);
	return FZN_CATALOGUE_OK;
}

fzn_catalogue_err_t fzn_catalogue_refile_advance(fzn_catalogue_refile_t *job)
{
	if (!job || !job->captured)
		return FZN_CATALOGUE_ERR_MALFORMED;
	if (job->done >= job->used)
		return FZN_CATALOGUE_ERR_RANGE;

	job->done++;
	return FZN_CATALOGUE_OK;
}

fzn_catalogue_err_t fzn_catalogue_refile_progress(const fzn_catalogue_refile_t *job,
                                                  size_t *done_out, size_t *total_out)
{
	if (!job || !job->captured || !done_out || !total_out)
		return FZN_CATALOGUE_ERR_MALFORMED;

	*done_out = job->done;
	*total_out = job->used;
	return FZN_CATALOGUE_OK;
}
