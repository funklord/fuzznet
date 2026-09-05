/* Assignment and congestion for a multi-peer transfer. The reasoning is in
 * transfer.h. */

#include "transfer.h"

#include <string.h>

/* One more than the widest window, so that with every slot live there is
 * still a candidate left to hand back.
 *
 * THAT HOLDS WHILE A CALLER KEEPS ONE GRANULARITY, and is stated rather than
 * assumed: assignments are made from planner output, so with a constant
 * `max_per_range` the candidates and the pending ranges fall on the same
 * boundaries and each live slot rules out exactly one candidate. A caller
 * that changes granularity mid-transfer can have one pending range straddle
 * two candidates, and the search can then answer NONE while a free range
 * exists further on. That is a spurious wait rather than a lost range -- the
 * next call with the original granularity finds it -- and it is why this is
 * documented as a window rather than a search. */
#define CANDIDATES (FZN_TRANSFER_MAX_SLOTS + 1u)

const char *fzn_transfer_err_str(fzn_transfer_err_t err)
{
	switch (err) {
	case FZN_TRANSFER_OK:
		return "ok";
	case FZN_TRANSFER_ERR_MALFORMED:
		return "malformed";
	case FZN_TRANSFER_NONE:
		return "nothing to ask for";
	case FZN_TRANSFER_FULL:
		return "window full";
	case FZN_TRANSFER_ERR_UNKNOWN:
		return "no such assignment";
	}
	return "unknown";
}

/* Half-open intervals, so touching ranges do not count as overlapping.
 * Written without adding on both sides at once because `first + count` is
 * bounded by the blob's leaf count and cannot wrap, which is established at
 * assignment time rather than assumed here. */
static int overlaps(uint64_t a_first, uint64_t a_count, uint64_t b_first, uint64_t b_count)
{
	return a_first < b_first + b_count && b_first < a_first + a_count;
}

static int is_pending(const fzn_transfer_t *transfer, uint64_t first, uint64_t count)
{
	size_t at;

	for (at = 0; at < transfer->cap; at++) {
		const fzn_transfer_assign_t *slot = &transfer->slots[at];

		if (slot->live && overlaps(first, count, slot->first, slot->count))
			return 1;
	}
	return 0;
}

/* The one live slot matching a peer and an exact range, or `cap` for none.
 * Exact rather than overlapping: an answer names the range it was asked
 * for, and a partial match is a different question this module does not
 * answer. */
static size_t find_slot(const fzn_transfer_t *transfer, uint32_t peer, uint64_t first,
                        uint64_t count)
{
	size_t at;

	for (at = 0; at < transfer->cap; at++) {
		const fzn_transfer_assign_t *slot = &transfer->slots[at];

		if (slot->live && slot->peer == peer && slot->first == first &&
		    slot->count == count)
			return at;
	}
	return transfer->cap;
}

static void on_success(fzn_transfer_t *transfer)
{
	transfer->successes++;
	if (transfer->successes < transfer->window)
		return;
	transfer->successes = 0u;
	if ((size_t)transfer->window < transfer->cap)
		transfer->window++;
}

static void on_loss(fzn_transfer_t *transfer)
{
	transfer->window /= 2u;
	if (transfer->window == 0u)
		transfer->window = 1u;
	transfer->successes = 0u;
}

fzn_transfer_err_t fzn_transfer_open(fzn_transfer_t *transfer, fzn_spool_t *spool,
                                     fzn_transfer_assign_t *slots, size_t cap)
{
	if (!transfer || !spool || !slots)
		return FZN_TRANSFER_ERR_MALFORMED;
	if (cap == 0u || cap > FZN_TRANSFER_MAX_SLOTS)
		return FZN_TRANSFER_ERR_MALFORMED;
	/* A spool that was never opened has no leaves and nothing to plan
	 * over, and would otherwise present as a permanently complete
	 * transfer. */
	if (spool->leaves == 0u || !spool->present)
		return FZN_TRANSFER_ERR_MALFORMED;

	memset(slots, 0, cap * sizeof(*slots));
	transfer->spool = spool;
	transfer->slots = slots;
	transfer->cap = cap;
	transfer->in_flight = 0u;
	transfer->window = 1u;
	transfer->successes = 0u;
	return FZN_TRANSFER_OK;
}

fzn_transfer_err_t fzn_transfer_next_want(fzn_transfer_t *transfer, uint32_t peer,
                                          uint64_t from, uint64_t max_per_range,
                                          uint64_t deadline, fzn_spool_range_t *out)
{
	fzn_spool_range_t candidates[CANDIDATES];
	size_t found = 0u, at, free_slot;

	if (!transfer || !transfer->spool || !transfer->slots || !out)
		return FZN_TRANSFER_ERR_MALFORMED;
	if (max_per_range == 0u)
		return FZN_TRANSFER_ERR_MALFORMED;
	/* THE WINDOW IS CHECKED BEFORE THE PLAN, so a closed window costs a
	 * comparison rather than a walk of the bitmap. */
	if (transfer->in_flight >= (size_t)transfer->window)
		return FZN_TRANSFER_FULL;

	if (fzn_spool_plan_want(transfer->spool, from, max_per_range, candidates, CANDIDATES,
	                        &found) != FZN_SPOOL_OK)
		return FZN_TRANSFER_ERR_MALFORMED;
	if (found == 0u)
		return FZN_TRANSFER_NONE;

	for (at = 0; at < found; at++) {
		if (!is_pending(transfer, candidates[at].first, candidates[at].count))
			break;
	}
	if (at == found)
		return FZN_TRANSFER_NONE;

	for (free_slot = 0; free_slot < transfer->cap; free_slot++) {
		if (!transfer->slots[free_slot].live)
			break;
	}
	/* Unreachable while `in_flight` and the live slots agree, which they
	 * do because both change together below. Refused rather than
	 * asserted, because the alternative is writing past the array. */
	if (free_slot == transfer->cap)
		return FZN_TRANSFER_FULL;

	/* THE RECORD GOES IN BEFORE THE RANGE GOES OUT. Everything above may
	 * be reordered freely; this may not be moved after the return, and
	 * transfer.h says why. */
	transfer->slots[free_slot].first = candidates[at].first;
	transfer->slots[free_slot].count = candidates[at].count;
	transfer->slots[free_slot].deadline = deadline;
	transfer->slots[free_slot].peer = peer;
	transfer->slots[free_slot].live = 1u;
	transfer->in_flight++;

	out->first = candidates[at].first;
	out->count = candidates[at].count;
	return FZN_TRANSFER_OK;
}

fzn_transfer_err_t fzn_transfer_delivered(fzn_transfer_t *transfer, uint32_t peer,
                                          uint64_t first, uint64_t count)
{
	size_t slot;
	uint64_t i;

	if (!transfer || !transfer->spool || !transfer->slots)
		return FZN_TRANSFER_ERR_MALFORMED;

	slot = find_slot(transfer, peer, first, count);
	if (slot == transfer->cap)
		return FZN_TRANSFER_ERR_UNKNOWN;

	/* Asked of the store rather than taken from the caller. A claim of
	 * delivery over leaves the bitmap does not hold would otherwise open
	 * the window on work that never happened. */
	for (i = 0; i < count; i++) {
		if (!fzn_spool_has(transfer->spool, first + i))
			return FZN_TRANSFER_ERR_UNKNOWN;
	}

	transfer->slots[slot].live = 0u;
	transfer->in_flight--;
	on_success(transfer);
	return FZN_TRANSFER_OK;
}

fzn_transfer_err_t fzn_transfer_failed(fzn_transfer_t *transfer, uint32_t peer, uint64_t first,
                                       uint64_t count)
{
	size_t slot;

	if (!transfer || !transfer->slots)
		return FZN_TRANSFER_ERR_MALFORMED;

	slot = find_slot(transfer, peer, first, count);
	if (slot == transfer->cap)
		return FZN_TRANSFER_ERR_UNKNOWN;

	transfer->slots[slot].live = 0u;
	transfer->in_flight--;
	on_loss(transfer);
	return FZN_TRANSFER_OK;
}

size_t fzn_transfer_expire(fzn_transfer_t *transfer, uint64_t now)
{
	size_t at, dropped = 0u;

	if (!transfer || !transfer->slots)
		return 0u;

	for (at = 0; at < transfer->cap; at++) {
		fzn_transfer_assign_t *slot = &transfer->slots[at];

		if (!slot->live || slot->deadline > now)
			continue;
		slot->live = 0u;
		transfer->in_flight--;
		dropped++;
	}
	/* One halving for the event, however many slots it took with it. */
	if (dropped > 0u)
		on_loss(transfer);
	return dropped;
}

unsigned fzn_transfer_window(const fzn_transfer_t *transfer)
{
	return transfer ? transfer->window : 0u;
}

size_t fzn_transfer_in_flight(const fzn_transfer_t *transfer)
{
	return transfer ? transfer->in_flight : 0u;
}
