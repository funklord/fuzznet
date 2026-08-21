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

	/* THE PLAN'S FIELDS MUST AGREE WITH ONE ANOTHER, and until this was
	 * added they were not required to. Two of the three were already
	 * validated above, which is the tell: this function had decided the
	 * plan was untrusted and then read `total` as though it were not.
	 *
	 * The last piece's length is `total - start`. A plan claiming ten
	 * bytes in pieces of a hundred gives start 300 for piece 3 and a
	 * length of 2^64 - 290, returned with FZN_SPLIT_OK -- and a caller
	 * does not copy the plan's bytes itself, it copies what this function
	 * hands back, so the overread lands at the call site.
	 *
	 * Division rather than multiplication for the same reason as
	 * `chunk/reassembly.c`'s sizing: `index * chunk_size` is itself
	 * capable of wrapping when the fields disagree, so the bound has to be
	 * established before the offset is computed rather than after.
	 * `(total - 1) / chunk_size` is the largest index whose piece starts
	 * inside the message, and `total >= 1` holds because `chunk_size` is
	 * non-zero and no larger than it. */
	if (plan->chunk_size > plan->total)
		return FZN_SPLIT_ERR_MALFORMED;
	if ((size_t)index > (plan->total - 1u) / plan->chunk_size)
		return FZN_SPLIT_ERR_MALFORMED;

	start = (size_t)index * plan->chunk_size;

	*offset = start;
	/* Only the last piece is short, and it is short by exactly what the
	 * stride overshot. */
	*len = (index + 1u == plan->chunks) ? plan->total - start : plan->chunk_size;

	return FZN_SPLIT_OK;
}

/* See split.h.
 *
 * NO `default:` LABEL, and that is the mechanism rather than an oversight.
 * `-Wswitch` -- which `-Wall` turns on -- warns about an enumerated switch
 * that omits a case only when there is no default, so leaving it out is what
 * makes the compiler notice a code added to fzn_split_err_t and not rendered here. A
 * default would silence exactly the warning worth having and turn a new code
 * into a silent "unknown" in somebody's log.
 *
 * The fallback then lives after the switch, where it catches a value that is
 * not an enumerator at all -- which no amount of compiler help can rule out,
 * since the argument may have come from a cast or from the wire. */
const char *fzn_split_err_str(fzn_split_err_t err)
{
	switch (err) {
	case FZN_SPLIT_OK:
		return "ok";
	case FZN_SPLIT_ERR_MALFORMED:
		return "malformed argument";
	case FZN_SPLIT_ERR_TOO_LARGE:
		return "message needs more chunks than a receiver tracks";
	case FZN_SPLIT_ERR_PAYLOAD_TOO_LARGE:
		return "max_payload exceeds what a frame carries";
	}

	return "unknown";
}
