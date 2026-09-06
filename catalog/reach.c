/* See reach.h. */

#include "reach.h"

#include <string.h>

static int same_id(const fzn_catalog_id_t *a, const fzn_catalog_id_t *b)
{
	return memcmp(a->b, b->b, FZN_CATALOG_ID_LEN) == 0;
}

/*
 * ONE DEFINITION OF "A NODE", READ THREE WAYS.
 *
 * Sizing, collecting and membership all need to agree about what counts as a
 * node, and three loops that each decided for themselves would be three
 * things to keep in step -- with the failure being that a caller sizes an
 * array by one rule and the walk overflows it under another. So there is a
 * single enumeration of candidate slots and everything reads it.
 *
 * A slot may yield nothing: an ABSENT edge is a tombstone -- sec 144 keeps
 * the row so a stale link cannot resurrect the membership -- and neither end
 * of one is a node. Were it otherwise, unlinking something would turn it into
 * permanent garbage this module kept proposing for deletion.
 */
static size_t candidate_count(const fzn_catalog_t *catalog)
{
	return catalog->used * 2u + catalog->entry_used + catalog->name_used;
}

static int candidate(const fzn_catalog_t *catalog, size_t k, fzn_catalog_id_t *out)
{
	size_t edge_slots = catalog->used * 2u;

	if (k < edge_slots) {
		const fzn_catalog_edge_t *edge = &catalog->edges[k / 2u];

		if (!edge->present)
			return 0;
		*out = (k % 2u) ? edge->child : edge->parent;
		return 1;
	}
	k -= edge_slots;
	if (k < catalog->entry_used) {
		*out = catalog->entries[k].id;
		return 1;
	}
	k -= catalog->entry_used;
	if (k < catalog->name_used) {
		*out = catalog->names[k].id;
		return 1;
	}

	return 0;
}

static int known(const fzn_catalog_t *catalog, const fzn_catalog_id_t *id)
{
	fzn_catalog_id_t at;
	size_t k;

	for (k = 0; k < candidate_count(catalog); k++) {
		if (candidate(catalog, k, &at) && same_id(&at, id))
			return 1;
	}

	return 0;
}

size_t fzn_catalog_nodes(const fzn_catalog_t *catalog)
{
	/* COUNTED WITHOUT A BUFFER, by asking whether each candidate appeared
	 * at an earlier slot. Quadratic, and the alternatives are an allocation
	 * this library does not make or a caller-owned array for the one
	 * function whose whole purpose is telling a caller how big an array to
	 * make. */
	fzn_catalog_id_t at;
	fzn_catalog_id_t earlier;
	size_t count = 0;
	size_t k;
	size_t j;

	if (!catalog || !catalog->edges)
		return 0;

	for (k = 0; k < candidate_count(catalog); k++) {
		int first = 1;

		if (!candidate(catalog, k, &at))
			continue;
		for (j = 0; j < k; j++) {
			if (candidate(catalog, j, &earlier) && same_id(&earlier, &at)) {
				first = 0;
				break;
			}
		}
		if (first)
			count++;
	}

	return count;
}

/* Append if absent. Zero means there was no room, and the two callers below
 * treat that differently on purpose. */
static int add_unique(fzn_catalog_id_t *list, size_t *used, size_t cap,
                      const fzn_catalog_id_t *id)
{
	size_t i;

	for (i = 0; i < *used; i++) {
		if (same_id(&list[i], id))
			return 1;
	}
	if (*used >= cap)
		return 0;

	list[*used] = *id;
	(*used)++;
	return 1;
}

/* The issuer and sequence of the k-th ROW, over the same three tables.
 *
 * A separate enumeration from the node one because the populations differ: a
 * present edge is one row and two nodes, and an absent edge is a row that
 * still had an issuer -- somebody asserted the unlink, and this host applied
 * it, so the frontier must account for them. Counting rows through the node
 * enumeration would silently drop every tombstone's author. */
static int row_source(const fzn_catalog_t *catalog, size_t k, const uint8_t **issuer,
                      uint64_t *seq)
{
	if (k < catalog->used) {
		*issuer = catalog->edges[k].issuer;
		*seq = catalog->edges[k].seq;
		return 1;
	}
	k -= catalog->used;
	if (k < catalog->entry_used) {
		*issuer = catalog->entries[k].issuer;
		*seq = catalog->entries[k].seq;
		return 1;
	}
	k -= catalog->entry_used;
	if (k < catalog->name_used) {
		*issuer = catalog->names[k].issuer;
		*seq = catalog->names[k].seq;
		return 1;
	}

	return 0;
}

static size_t row_count(const fzn_catalog_t *catalog)
{
	return catalog->used + catalog->entry_used + catalog->name_used;
}

size_t fzn_catalog_sources(const fzn_catalog_t *catalog, fzn_catalog_source_t *out,
                           size_t out_cap, size_t *dropped)
{
	size_t used = 0;
	size_t k;

	/* `dropped` IS REQUIRED. `fzn_sync_digest`'s rule and its reason: the
	 * scan runs in table order, so a host that overflows drops the same
	 * issuers every time and never learns it depends on them. */
	if (!dropped)
		return 0;
	*dropped = 0;
	if (!catalog || !catalog->edges || (!out && out_cap > 0))
		return 0;

	for (k = 0; k < row_count(catalog); k++) {
		const uint8_t *issuer;
		uint64_t seq;
		size_t i;
		int found = 0;

		if (!row_source(catalog, k, &issuer, &seq))
			continue;
		for (i = 0; i < used; i++) {
			if (memcmp(out[i].issuer, issuer, FZN_PUBKEY_LEN) != 0)
				continue;
			found = 1;
			out[i].rows++;
			/* The HIGHEST applied, since rows are in table order
			 * and not in sequence order. */
			if (seq > out[i].seq)
				out[i].seq = seq;
			break;
		}
		if (found)
			continue;
		if (used >= out_cap) {
			/* DISTINCT ISSUERS, NOT ROWS. Reaching here means this
			 * issuer is not in `out`, so an earlier row naming it
			 * was dropped too and has already been counted -- and
			 * without this scan an issuer with four rows would
			 * report four drops, which is a count of the wrong
			 * thing wearing the right name. `fzn_sync_digest`'s
			 * `dropped` means issuers and so does this. */
			size_t j;
			int counted = 0;

			for (j = 0; j < k; j++) {
				const uint8_t *before;
				uint64_t ignored;

				if (!row_source(catalog, j, &before, &ignored))
					continue;
				if (memcmp(before, issuer, FZN_PUBKEY_LEN) == 0) {
					counted = 1;
					break;
				}
			}
			if (!counted)
				(*dropped)++;
			continue;
		}
		memcpy(out[used].issuer, issuer, FZN_PUBKEY_LEN);
		out[used].seq = seq;
		out[used].rows = 1;
		used++;
	}

	return used;
}

/* Whether the caller has accounted for every issuer this catalogue depends
 * on, and has not claimed to be behind its own catalogue.
 *
 * Checked against the ROWS rather than against a materialised source list, so
 * this needs no buffer and cannot disagree with `fzn_catalog_sources` about
 * who counts -- both read `row_source`. */
static fzn_catalog_err_t vouched_for(const fzn_catalog_t *catalog,
                                     const fzn_catalog_frontier_t *frontier,
                                     size_t frontier_count, fzn_catalog_reach_t *plan)
{
	size_t k;

	for (k = 0; k < row_count(catalog); k++) {
		const uint8_t *issuer;
		uint64_t seq;
		size_t i;

		if (!row_source(catalog, k, &issuer, &seq))
			continue;
		for (i = 0; i < frontier_count; i++) {
			if (memcmp(frontier[i].issuer, issuer, FZN_PUBKEY_LEN) != 0)
				continue;
			/* A FRONTIER BEHIND THIS CATALOGUE'S OWN APPLIED
			 * SEQUENCE IS INCOHERENT: the caller has applied a
			 * record it says it has not read, so whatever produced
			 * the frontier is not describing this catalogue. */
			if (frontier[i].received < seq)
				i = frontier_count;
			break;
		}
		if (i >= frontier_count) {
			memcpy(plan->unvouched, issuer, FZN_PUBKEY_LEN);
			plan->unvouched_set = 1;
			return FZN_CATALOG_ERR_INCOMPLETE;
		}
	}

	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_unreachable(const fzn_catalog_t *catalog,
                                          const fzn_catalog_id_t *roots, size_t root_count,
                                          const fzn_catalog_frontier_t *frontier,
                                          size_t frontier_count, fzn_catalog_id_t *scratch,
                                          size_t scratch_cap, fzn_catalog_id_t *out,
                                          size_t out_cap, fzn_catalog_reach_t *plan)
{
	fzn_catalog_err_t err;
	size_t seen = 0;
	size_t head;
	size_t i;
	size_t k;

	if (!plan)
		return FZN_CATALOG_ERR_MALFORMED;
	memset(plan, 0, sizeof(*plan));
	if (!catalog || !catalog->edges || !roots || !scratch || (!out && out_cap > 0))
		return FZN_CATALOG_ERR_MALFORMED;
	/* ZERO ROOTS WOULD REPORT THE WHOLE CATALOGUE AS GARBAGE, and this is
	 * the one module whose answer gets acted on by deleting. */
	if (root_count == 0 || scratch_cap == 0)
		return FZN_CATALOG_ERR_MALFORMED;
	if (!frontier && frontier_count > 0)
		return FZN_CATALOG_ERR_MALFORMED;
	if (catalog->busy_with != FZN_CATALOG_JOB_NONE)
		return FZN_CATALOG_ERR_BUSY;

	/* A ROOT THE CATALOGUE DOES NOT KNOW, for the same reason: a typo
	 * would otherwise propose everything. Checked before the frontier
	 * because it is the cheaper mistake to make and the cheaper to find. */
	for (i = 0; i < root_count; i++) {
		if (!known(catalog, &roots[i]))
			return FZN_CATALOG_ERR_ABSENT;
	}

	err = vouched_for(catalog, frontier, frontier_count, plan);
	if (err != FZN_CATALOG_OK)
		return err;

	/* THE WALK. `scratch` is both the visited set and the queue: `head` is
	 * how far the queue has been consumed and `seen` is where the next
	 * append lands, so a node is enqueued exactly when it is first seen. */
	for (i = 0; i < root_count; i++) {
		if (!add_unique(scratch, &seen, scratch_cap, &roots[i]))
			return FZN_CATALOG_ERR_FULL;
	}
	plan->roots = root_count;

	for (head = 0; head < seen; head++) {
		fzn_catalog_id_t node = scratch[head];

		for (i = 0; i < catalog->used; i++) {
			const fzn_catalog_edge_t *edge = &catalog->edges[i];

			if (!edge->present || !same_id(&edge->parent, &node))
				continue;
			/* FULL RATHER THAN A COUNTER, and the asymmetry with
			 * `out` below is the point. A scratch that ran out
			 * leaves reachable nodes unvisited, so they come back
			 * as UNREACHABLE -- a proposal to delete live data. A
			 * short `out` only proposes less. */
			if (!add_unique(scratch, &seen, scratch_cap, &edge->child))
				return FZN_CATALOG_ERR_FULL;
		}
	}
	plan->reachable = seen;

	/* WHAT THE WALK DID NOT REACH. Enumerated over the node definition
	 * rather than over the scratch, so a node with rows and no edges --
	 * content nobody linked -- is reported, which is exactly the case
	 * worth reporting. */
	for (k = 0; k < candidate_count(catalog); k++) {
		fzn_catalog_id_t at;
		int seen_before = 0;
		size_t j;

		if (!candidate(catalog, k, &at))
			continue;
		/* Each distinct node once: skip a candidate that appeared at an
		 * earlier slot. */
		for (j = 0; j < k; j++) {
			fzn_catalog_id_t earlier;

			if (candidate(catalog, j, &earlier) && same_id(&earlier, &at)) {
				seen_before = 1;
				break;
			}
		}
		if (seen_before)
			continue;

		for (j = 0; j < seen; j++) {
			if (same_id(&scratch[j], &at))
				break;
		}
		if (j < seen)
			continue;

		plan->unreachable++;
		if (plan->unreachable > out_cap) {
			plan->truncated++;
			plan->unreachable--;
			continue;
		}
		out[plan->unreachable - 1u] = at;
	}

	/* `reachable` counts what the walk visited, which includes roots that
	 * the catalogue knows; every one of those is a node, so the two
	 * populations agree and the suite asserts they sum to the node count.
	 */
	return FZN_CATALOG_OK;
}
