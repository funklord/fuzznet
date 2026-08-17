/* Planning the cut. See split.h. */

#include "split.h"

fzn_split_err_t fzn_split_plan(size_t total, size_t max_payload, fzn_split_t *out)
{
	size_t count;

	if (!out || max_payload == 0)
		return FZN_SPLIT_ERR_MALFORMED;

	/* Checked before the arithmetic rather than after, because a plan is
	 * not something to build and then reject: every field below would be
	 * consistent, correct, and unsendable. */
	if (max_payload > FZN_SPLIT_MAX_PAYLOAD)
		return FZN_SPLIT_ERR_PAYLOAD_TOO_LARGE;

	/* Refused rather than treated as zero pieces. Reassembly rejects an
	 * empty piece, so a plan for nothing would describe something the
	 * other half will not accept -- and the two halves disagreeing about
	 * an edge is exactly what this module exists to prevent. */
	if (total == 0)
		return FZN_SPLIT_ERR_MALFORMED;

	/* Ceiling division written so it cannot overflow: total + max - 1
	 * would, for a total near SIZE_MAX, and a wrapped count is a plan
	 * that looks small. */
	count = total / max_payload;
	if (total % max_payload != 0)
		count++;

	if (count > FZN_REASM_MAX_CHUNKS)
		return FZN_SPLIT_ERR_TOO_LARGE;

	out->total = total;
	out->chunks = (uint16_t)count;
	/* A single-piece message has a stride of its own length rather than
	 * of max_payload, so that `buffer_needed` is what the message
	 * actually costs and matches what reassembly computes for chunks == 1.
	 * The two halves agree on this edge or the round trip fails. */
	out->chunk_size = (count == 1) ? total : max_payload;
	out->buffer_needed = out->chunk_size * count;

	return FZN_SPLIT_OK;
}

fzn_split_err_t fzn_split_at(const fzn_split_t *plan, uint16_t index, size_t *offset,
                              size_t *len)
{
	size_t start;

	if (!plan || !offset || !len || plan->chunks == 0 || plan->chunk_size == 0)
		return FZN_SPLIT_ERR_MALFORMED;
	if (index >= plan->chunks)
		return FZN_SPLIT_ERR_MALFORMED;

	start = (size_t)index * plan->chunk_size;

	*offset = start;
	/* Only the last piece is short, and it is short by exactly what the
	 * stride overshot. */
	*len = (index + 1u == plan->chunks) ? plan->total - start : plan->chunk_size;

	return FZN_SPLIT_OK;
}
