/* See link.h. */

#include "link.h"

#include <string.h>

static int usable_table(const fzn_link_table_t *table)
{
	return table && table->entries && table->used <= table->capacity;
}

static fzn_link_entry_t *find(const fzn_link_table_t *table, uint32_t id)
{
	fzn_link_entry_t *hit = NULL;

	for (size_t i = 0; i < table->used; i++) {
		if (table->entries[i].id == id)
			hit = &table->entries[i];
	}

	return hit;
}

fzn_link_err_t fzn_link_table_init(fzn_link_table_t *table, fzn_link_entry_t *entries,
                                    size_t capacity)
{
	if (!table || !entries || capacity == 0)
		return FZN_LINK_ERR_MALFORMED;

	memset(entries, 0, capacity * sizeof(*entries));
	table->entries = entries;
	table->capacity = capacity;
	table->used = 0;

	return FZN_LINK_OK;
}

fzn_link_err_t fzn_link_register(fzn_link_table_t *table, uint32_t id, uint32_t metric,
                                  uint32_t latency_ms, uint16_t loss_permille, uint32_t mtu)
{
	fzn_link_entry_t *e;

	if (!usable_table(table))
		return FZN_LINK_ERR_MALFORMED;
	if (loss_permille > 1000u)
		return FZN_LINK_ERR_MALFORMED;
	if (find(table, id))
		return FZN_LINK_ERR_DUPLICATE;

	if (table->used >= table->capacity)
		return FZN_LINK_ERR_FULL;

	e = &table->entries[table->used++];
	e->id = id;
	e->metric = metric;
	/* THE PRIOR IS THE STARTING ESTIMATE, not a separate field consulted
	 * until some threshold. See link.h: the alternative has a cliff in it
	 * and has to invent a latency for a link nobody has used. */
	e->latency_ms = latency_ms;
	e->loss_permille = loss_permille;
	e->mtu = mtu;
	e->observations = 0;
	e->last_seen = 0;
	e->usable = 1;

	return FZN_LINK_OK;
}

/* One step of the exponentially weighted average, in integers.
 *
 * `(old * (2^k - 1) + sample) >> k`, widened to 64 bits before multiplying:
 * a latency near UINT32_MAX times seven overflows 32 bits, and a wrapped
 * average would report a terrible link as excellent -- consistently, which
 * would look deliberate.
 *
 * THE SHIFT DISCARDS A REMAINDER, AND DISCARDING IT ALWAYS ROUNDS DOWN --
 * which is not a rounding preference here, because "down" is always toward
 * the flattering answer. Lower latency and lower loss both make a link look
 * better, so a bias that only ever subtracts is a bias that only ever
 * overstates a link's quality. Measured on the plain truncating version:
 *
 *   - 100000 consecutive losses estimated 993 permille, not 1000. The
 *     estimator has a fixed point wherever `1000 - x < 8`, so it stalls as
 *     soon as it gets within a remainder of the target and a link dropping
 *     EVERY message could never report worse than 99.3% loss. A hard
 *     constraint in `sched/` set anywhere above that admits a dead link.
 *   - 100000 samples of a 500 ms link estimated 493 ms, a standing 1.4%
 *     understatement that no amount of evidence corrects.
 *
 * ROUNDING TOWARD THE SAMPLE fixes both directions at once, and is cheaper
 * than carrying more precision in the entry. Away from the sample the
 * truncation is already toward it, so only the upward case needs the
 * correction: repeated identical samples then actually reach their value
 * instead of stalling a remainder short of it. */
static uint32_t smooth(uint32_t old, uint32_t sample)
{
	uint64_t weighted = (uint64_t)old * ((1u << FZN_LINK_SMOOTH_SHIFT) - 1u);
	uint64_t total = weighted + (uint64_t)sample;
	uint32_t result = (uint32_t)(total >> FZN_LINK_SMOOTH_SHIFT);

	if (sample > old && (total & (((uint64_t)1u << FZN_LINK_SMOOTH_SHIFT) - 1u)) != 0u)
		result++;

	return result;
}

fzn_link_err_t fzn_link_observe_ack(fzn_link_table_t *table, uint32_t id, uint32_t rtt_ms,
                                     uint64_t now)
{
	fzn_link_entry_t *e;

	if (!usable_table(table))
		return FZN_LINK_ERR_MALFORMED;

	e = find(table, id);
	if (!e)
		return FZN_LINK_ERR_ABSENT;

	e->latency_ms = smooth(e->latency_ms, rtt_ms);
	/* A success is a sample of zero loss on the same scale as a failure's
	 * thousand, so the two observations use one estimator rather than a
	 * counter that would need a window and a decision about its length. */
	e->loss_permille = (uint16_t)smooth(e->loss_permille, 0u);
	e->observations++;
	e->last_seen = now;

	return FZN_LINK_OK;
}

fzn_link_err_t fzn_link_observe_loss(fzn_link_table_t *table, uint32_t id, uint64_t now)
{
	fzn_link_entry_t *e;

	if (!usable_table(table))
		return FZN_LINK_ERR_MALFORMED;

	e = find(table, id);
	if (!e)
		return FZN_LINK_ERR_ABSENT;

	/* Latency is deliberately NOT updated. A lost message has no round trip
	 * to report, and counting it as some large number would blend a loss
	 * signal into a latency one -- which is exactly the collapsing into a
	 * single number that `sched/` exists to avoid. */
	e->loss_permille = (uint16_t)smooth(e->loss_permille, 1000u);
	e->observations++;
	e->last_seen = now;

	return FZN_LINK_OK;
}

fzn_link_err_t fzn_link_set_usable(fzn_link_table_t *table, uint32_t id, int usable)
{
	fzn_link_entry_t *e;

	if (!usable_table(table))
		return FZN_LINK_ERR_MALFORMED;

	e = find(table, id);
	if (!e)
		return FZN_LINK_ERR_ABSENT;

	e->usable = usable ? 1 : 0;

	return FZN_LINK_OK;
}

const fzn_link_entry_t *fzn_link_get(const fzn_link_table_t *table, uint32_t id)
{
	if (!usable_table(table))
		return NULL;

	return find(table, id);
}

size_t fzn_link_snapshot(const fzn_link_table_t *table, fzn_sched_candidate_t *out, size_t out_cap,
                         size_t *dropped)
{
	size_t n = 0;

	/* Required, for the reason `fzn_sync_digest` takes one: an
	 * out-parameter a caller may omit is one every caller omits. */
	if (!dropped)
		return 0;

	*dropped = 0;

	if (!usable_table(table) || !out)
		return 0;

	/* COUNTS PAST THE BOUND RATHER THAN STOPPING AT IT, and the entries
	 * past it are always the same ones.
	 *
	 * `link/` has no unregister and no compaction: `fzn_link_register`
	 * appends at `entries[used]` and every observation mutates in place, so
	 * table order IS registration order, permanently. Truncation therefore
	 * drops the most RECENTLY registered links -- the interface that just
	 * came up, the relay address just discovered, the radio switched back
	 * on. Exactly the links a consumer most needs to hear about.
	 *
	 * Measured with three links and an `out_cap` of two, the first two
	 * marked unusable: `fzn_sched_select` answered "no link satisfies this
	 * class" and the consumer concluded the network was down while a
	 * healthy link sat one index past the bound. Every round, identically,
	 * for as long as the table lives.
	 *
	 * And it compounds. `sched/` only ever sees the snapshot, so nothing is
	 * ever sent on that link, so `fzn_link_observe_ack` and `_loss` are
	 * never called for it either -- its estimate stays frozen at the
	 * declared prior for ever. link.h's thesis that "the declared metric is
	 * a prior; measurement is evidence" is unreachable for anything past
	 * `out_cap`. */
	for (size_t i = 0; i < table->used; i++) {
		const fzn_link_entry_t *e = &table->entries[i];

		if (n >= out_cap) {
			(*dropped)++;
			continue;
		}

		out[n].id = e->id;
		out[n].metric = e->metric;
		out[n].latency_ms = e->latency_ms;
		out[n].loss_permille = e->loss_permille;
		out[n].mtu = e->mtu;
		out[n].usable = e->usable;
		n++;
	}

	return n;
}

const char *fzn_link_err_str(fzn_link_err_t err)
{
	switch (err) {
	case FZN_LINK_OK:
		return "ok";
	case FZN_LINK_ERR_MALFORMED:
		return "malformed argument";
	case FZN_LINK_ERR_FULL:
		return "no room for another link";
	case FZN_LINK_ERR_DUPLICATE:
		return "this link is registered already";
	case FZN_LINK_ERR_ABSENT:
		return "no such link";
	}

	return "unknown";
}
