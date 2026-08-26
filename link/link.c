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
		if (table->entries[i].live && table->entries[i].id == id)
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
	e->live = 1;

	return FZN_LINK_OK;
}

/* One step of the exponentially weighted average, in integers.
 *
 * `(old * (2^k - 1) + sample) >> k`, widened to 64 bits before multiplying:
 * a latency near UINT32_MAX times seven overflows 32 bits, and a wrapped
 * average would report a terrible link as excellent -- consistently, which
 * would look deliberate. */
static uint32_t smooth(uint32_t old, uint32_t sample)
{
	uint64_t weighted = (uint64_t)old * ((1u << FZN_LINK_SMOOTH_SHIFT) - 1u);

	return (uint32_t)((weighted + (uint64_t)sample) >> FZN_LINK_SMOOTH_SHIFT);
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

size_t fzn_link_snapshot(const fzn_link_table_t *table, fzn_link_t *out, size_t out_cap)
{
	size_t n = 0;

	if (!usable_table(table) || !out)
		return 0;

	for (size_t i = 0; i < table->used && n < out_cap; i++) {
		const fzn_link_entry_t *e = &table->entries[i];

		if (!e->live)
			continue;
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
