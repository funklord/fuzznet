/* See copy.h. */

#include "copy.h"

#include <string.h>

/* Whether a blob is already in the list being built.
 *
 * QUADRATIC IN THE OUTPUT, DELIBERATELY. The scan is over what has been
 * written rather than over the catalogue, so it is bounded by the caller's
 * own `out_cap` and not by how large a catalogue can grow. The trade is a
 * 32-byte comparison against a duplicate FETCH, which is the whole blob --
 * several nodes sharing one blob is the reason a caller chooses a blob over
 * an inline value in the first place, so the duplicate is the expected case
 * rather than the odd one. */
static int already_listed(const fzn_catalog_blob_t *out, size_t written,
                          const uint8_t root[FZN_BLOB_HASH_LEN])
{
	size_t i;

	for (i = 0; i < written; i++) {
		if (memcmp(out[i].root, root, FZN_BLOB_HASH_LEN) == 0)
			return 1;
	}

	return 0;
}

/* Ask the seam, treating an absent one as "this host holds nothing".
 *
 * A NULL `holdings` is the state a host adopting a catalogue is in, so it is
 * the easy case rather than a stub every consumer has to write. A seam
 * present but with no callback is the same answer: a partially filled ops
 * struct must not be read as a held blob, since that direction makes a host
 * advertise bytes it cannot serve. */
static int host_holds(const fzn_catalog_holdings_ops_t *holdings,
                      const uint8_t root[FZN_BLOB_HASH_LEN], uint64_t len)
{
	if (!holdings || !holdings->holds)
		return 0;

	return holdings->holds(holdings->ctx, root, len) != 0;
}

/* Append, or count the truncation. Nothing is written past `out_cap`, and a
 * truncated walk keeps walking so the counters describe the whole catalogue
 * rather than the prefix that fitted -- a caller sizing its array needs the
 * total, and `truncated` is the number to add. */
static void emit(fzn_catalog_blob_t *out, size_t out_cap, fzn_catalog_copy_t *plan,
                 const uint8_t root[FZN_BLOB_HASH_LEN], uint64_t len)
{
	if (already_listed(out, plan->written, root)) {
		plan->duplicates++;
		return;
	}
	if (plan->written >= out_cap) {
		plan->truncated++;
		return;
	}

	memcpy(out[plan->written].root, root, FZN_BLOB_HASH_LEN);
	out[plan->written].len = len;
	plan->written++;
}

/* Both walks over the content table share everything but one question, so
 * they share the walk. `retained_only` is that question: a want list asks
 * what this host has chosen to keep, and a holdings announcement asks nothing
 * about policy at all -- see copy.h, where the difference between an
 * intention and a fact is argued. */
static fzn_catalog_err_t walk(const fzn_catalog_t *catalog,
                              const fzn_catalog_holdings_ops_t *holdings, int retained_only,
                              uint64_t now, int want_missing, fzn_catalog_blob_t *out,
                              size_t out_cap, fzn_catalog_copy_t *plan)
{
	size_t i;

	if (!plan)
		return FZN_CATALOG_ERR_MALFORMED;
	memset(plan, 0, sizeof(*plan));
	if (!catalog || (!out && out_cap > 0))
		return FZN_CATALOG_ERR_MALFORMED;
	/* sec 149: while a refile holds the catalogue, progress is the only
	 * question it answers. */
	if (catalog->busy_with)
		return FZN_CATALOG_ERR_BUSY;

	for (i = 0; i < catalog->entry_used; i++) {
		const fzn_catalog_entry_t *entry = &catalog->entries[i];
		int held;

		if (retained_only && !fzn_catalog_keeps(catalog, &entry->id, now)) {
			plan->not_retained++;
			continue;
		}
		if (entry->kind == FZN_CATALOG_CONTENT_INLINE) {
			plan->inline_ready++;
			continue;
		}
		if (entry->kind != FZN_CATALOG_CONTENT_BLOB) {
			plan->no_content++;
			continue;
		}

		/* CLASSIFY FIRST, EMIT SECOND, and both walks classify
		 * identically. Counting only the class a walk emits would
		 * leave each walk's counters describing a different
		 * population, and the two sums copy.h states could not both
		 * be checked. */
		held = host_holds(holdings, entry->root, entry->blob_len);
		if (held)
			plan->already_held++;
		else
			plan->missing++;

		/* A want list emits what is missing; a holdings announcement
		 * emits what is here. */
		if (want_missing) {
			if (!held)
				emit(out, out_cap, plan, entry->root,
				     entry->blob_len);
		} else if (held) {
			emit(out, out_cap, plan, entry->root, entry->blob_len);
		}
	}

	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_copy_want(const fzn_catalog_t *catalog,
                                        const fzn_catalog_holdings_ops_t *holdings,
                                        uint64_t now, fzn_catalog_blob_t *out, size_t out_cap,
                                        fzn_catalog_copy_t *plan)
{
	return walk(catalog, holdings, 1, now, 1, out, out_cap, plan);
}

fzn_catalog_err_t fzn_catalog_copy_holdings(const fzn_catalog_t *catalog,
                                            const fzn_catalog_holdings_ops_t *holdings,
                                            fzn_catalog_blob_t *out, size_t out_cap,
                                            fzn_catalog_copy_t *plan)
{
	return walk(catalog, holdings, 0, 0, 0, out, out_cap, plan);
}

/* What this catalogue says about a root, or NULL when it says nothing.
 *
 * The linear scan is what bounds an offer to the catalogue. A caller with a
 * catalogue large enough for that to matter has an index; this module does
 * not build one, because a second copy of the content table is a second thing
 * to keep in step and the answer would be the same. */
static const fzn_catalog_entry_t *entry_for_root(const fzn_catalog_t *catalog,
                                                 const uint8_t root[FZN_BLOB_HASH_LEN])
{
	size_t i;

	for (i = 0; i < catalog->entry_used; i++) {
		const fzn_catalog_entry_t *entry = &catalog->entries[i];

		if (entry->kind != FZN_CATALOG_CONTENT_BLOB)
			continue;
		if (memcmp(entry->root, root, FZN_BLOB_HASH_LEN) == 0)
			return entry;
	}

	return NULL;
}

fzn_catalog_err_t fzn_catalog_copy_offer(const fzn_catalog_t *catalog,
                                         const fzn_catalog_holdings_ops_t *holdings,
                                         const fzn_catalog_blob_t *wants, size_t want_count,
                                         fzn_catalog_blob_t *out, size_t out_cap,
                                         fzn_catalog_copy_t *plan)
{
	size_t i;

	if (!plan)
		return FZN_CATALOG_ERR_MALFORMED;
	memset(plan, 0, sizeof(*plan));
	if (!catalog || (!out && out_cap > 0) || (!wants && want_count > 0))
		return FZN_CATALOG_ERR_MALFORMED;
	if (catalog->busy_with)
		return FZN_CATALOG_ERR_BUSY;

	for (i = 0; i < want_count; i++) {
		const fzn_catalog_entry_t *entry = entry_for_root(catalog, wants[i].root);

		/* THE SCOPE CHECK, and copy.h says why it is the point rather
		 * than a detail: without it a want list is a request for any
		 * blob whose hash a peer can name. */
		if (!entry) {
			plan->unknown++;
			continue;
		}
		if (!host_holds(holdings, entry->root, entry->blob_len)) {
			/* Known here and not held. Not an error and not a
			 * refusal: the peer asks again next round, which is
			 * `record/sync.h`'s pull shape. Counted so an offer's
			 * arithmetic closes the same way a walk's does. */
			plan->missing++;
			continue;
		}
		plan->already_held++;

		/* THE CATALOGUE'S LENGTH, NOT THE PEER'S. */
		emit(out, out_cap, plan, entry->root, entry->blob_len);
	}

	return FZN_CATALOG_OK;
}
