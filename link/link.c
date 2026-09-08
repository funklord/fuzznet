/* See link.h. */

#include "link.h"

/*
 * DIAGNOSTICS GO THROUGH flog, WHICH IS VENDORED AND MAY BE ABSENT. sec 209.
 *
 * The macro rather than an `if` at each site so that a build without flog has
 * no reference to it at all -- not a call guarded at runtime. With it absent
 * the arguments are discarded by the preprocessor, so `FLOG_WARN` need not
 * exist for the file to compile.
 *
 * `FLOG_MSG_NONE` throughout: flog's message ids are an X-macro table in its
 * own header, and extending it from here would be editing a vendored
 * dependency. The subsystem and the text carry the meaning instead.
 */
#ifdef FZN_FLOG_ON
/*
 * A VENDORED HEADER IS NOT EXEMPT FROM OUR WARNING SET, and that is worth
 * knowing before the next one is included. A vendored SOURCE is compiled with
 * GEN_CFLAGS and never sees `-Wpedantic`; a vendored HEADER is read by OUR
 * compiler under OUR flags, so a fault in it lands in our build and the
 * consumer cannot fix it from outside.
 *
 * This one did: `flog.h` spelled the current function `__FUNCTION__`, a GNU
 * extension where C11 has `__func__`. Reported rather than patched -- a
 * dependency's fault is signalled -- and fixed upstream in flog ba3007f,
 * which is the pin here. flog's own build never saw it, its default flags
 * being `-W -Wall -Os`; only a pedantic consumer does.
 *
 * A `#pragma GCC diagnostic ignored` around this include DOES NOT WORK, and
 * that is recorded because it compiles, it reads as correct, and it changes
 * nothing. `flog_printf` is a macro, so the offending token is expanded at
 * the CALL SITE below and merely REPORTED against a line in flog.h; the
 * pragma suppresses at the point of expansion, which is outside any region
 * wrapped around an include. It survived one round of checking because the
 * second `make` had nothing to rebuild and printed nothing -- **a no-op that
 * produces silence is indistinguishable from a fix that produces silence.**
 */
#include "flog.h"
#define LINK_LOG(table, sub, sev, ...)                                                     \
	do {                                                                               \
		if ((table) && (table)->log)                                               \
			flog_printf((table)->log, sub, sev, FLOG_MSG_NONE, __VA_ARGS__);   \
	} while (0)
#else
#define LINK_LOG(table, sub, sev, ...) ((void)0)
#endif

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
	/* Quiet unless somebody asks. A table on a caller's stack would
	 * otherwise carry whatever was there. */
	table->log = NULL;

	return FZN_LINK_OK;
}

void fzn_link_set_log(fzn_link_table_t *table, struct flog_t *log)
{
	if (!table)
		return;

	table->log = log;
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

	/*
	 * THE ONE THING THIS TABLE KNOWS THAT NO RETURN VALUE CARRIES.
	 *
	 * `dropped` is reported, and a caller that reads it learns a number.
	 * What the header above says and the number does not is that these are
	 * the SAME links every call -- this table never reorders, so truncation
	 * always drops the most recently registered -- and that being dropped
	 * is self-sustaining: sched never sees them, so nothing is sent on
	 * them, so they are never measured, so their estimates stay frozen at a
	 * declared prior for ever.
	 *
	 * A consumer can therefore be told the network is down while a healthy
	 * link sits one index past the bound. That is exactly the failure a
	 * log is the first line of troubleshooting for, and until sec 209 this
	 * library had no way to mention it.
	 */
	if (*dropped)
		LINK_LOG(table, "link/snapshot", FLOG_WARN,
		         "%zu of %zu links did not fit and are invisible to selection; "
		         "the same links every call, so they are never sent on and never "
		         "measured",
		         *dropped, table->used);

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
