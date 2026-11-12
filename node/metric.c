/* The metric layer's table: project.md sec 1034 and 1055, and the header. */
#include "metric.h"

#include <string.h>

void fzn_metrics_init(fzn_metrics_t *m)
{
	if (!m)
		return;
	memset(m, 0, sizeof(*m));
	m->rows = m->own;
	m->cap = FZN_METRIC_OWN;
}

int fzn_metrics_use(fzn_metrics_t *m, fzn_metric_t *rows, size_t cap)
{
	if (!m || !m->rows || !rows || cap < m->n)
		return 0;
	if (rows != m->rows) {
		memset(rows, 0, cap * sizeof(*rows));
		memcpy(rows, m->rows, m->n * sizeof(*rows));
	}
	m->rows = rows;
	m->cap = cap;
	return 1;
}

static int name_ok(const char *name, size_t *len)
{
	size_t i, n = name ? strlen(name) : 0u;

	if (n == 0u || n > FZN_METRIC_NAME_MAX)
		return 0;
	for (i = 0; i < n; i++)
		if (name[i] <= ' ' || name[i] > '~' || name[i] == ',')
			return 0;
	*len = n;
	return 1;
}

static fzn_metric_t *find(const fzn_metrics_t *m, const char *name)
{
	size_t i;

	for (i = 0; m && m->rows && i < m->n; i++)
		if (strcmp(m->rows[i].name, name) == 0)
			return &m->rows[i];
	return NULL;
}

fzn_metric_t *fzn_metrics_open(fzn_metrics_t *m, const char *name, uint64_t prior)
{
	fzn_metric_t *r;
	size_t len = 0;

	if (!m || !m->rows || !name_ok(name, &len))
		return NULL;
	if ((r = find(m, name)) != NULL)
		return r;
	if (m->n >= m->cap)
		return NULL;
	r = &m->rows[m->n++];
	memset(r, 0, sizeof(*r));
	memcpy(r->name, name, len + 1u);
	r->estimate = r->prior = prior;
	r->used = 1;
	return r;
}

fzn_metric_t *fzn_metrics_open_within(fzn_metrics_t *m, const char *name, uint64_t prior,
                                      const char *within, size_t max, uint64_t *evicted)
{
	fzn_metric_t *r, *oldest = NULL;
	size_t i, n = 0, wlen = within ? strlen(within) : 0u, len = 0;

	if (evicted)
		*evicted = 0;
	if (!m || !m->rows || !max || !name_ok(name, &len))
		return NULL;
	if ((r = find(m, name)) != NULL)
		return r;
	for (i = 0; i < m->n; i++) {
		if (strncmp(m->rows[i].name, within, wlen) != 0)
			continue;
		n++;
		if (!oldest || m->rows[i].last_ms < oldest->last_ms)
			oldest = &m->rows[i];
	}
	if (n < max || !oldest)
		return fzn_metrics_open(m, name, prior);
	/* ITS PLACE GIVEN, its total said. */
	if (evicted)
		*evicted = oldest->total;
	memset(oldest, 0, sizeof(*oldest));
	memcpy(oldest->name, name, len + 1u);
	oldest->estimate = oldest->prior = prior;
	oldest->used = 1;
	return oldest;
}

const fzn_metric_t *fzn_metrics_get(const fzn_metrics_t *m, const char *name)
{
	return name ? find(m, name) : NULL;
}

/* `link/`'S ESTIMATOR, sec 202, to the bit: seven parts the old and one the
 * sample, rounded up when the sample is above, so a steady sample is reached
 * rather than approached for ever from below. Past what the product holds, the
 * same step taken as a difference. */
static uint64_t smooth(uint64_t old, uint64_t sample)
{
	const uint64_t parts = (uint64_t)1u << FZN_METRIC_SMOOTH_SHIFT;
	uint64_t total;

	if (old > UINT64_MAX / parts || sample > UINT64_MAX / parts)
		return sample >= old ? old + ((sample - old) >> FZN_METRIC_SMOOTH_SHIFT)
		                     : old - ((old - sample) >> FZN_METRIC_SMOOTH_SHIFT);
	total = old * (parts - 1u) + sample;
	return (total >> FZN_METRIC_SMOOTH_SHIFT) + (sample > old && (total & (parts - 1u)) != 0u);
}

int fzn_metrics_observe(fzn_metrics_t *m, const char *name, uint64_t sample, uint64_t now_ms)
{
	fzn_metric_t *r = name ? find(m, name) : NULL;

	if (!r)
		return 0;
	r->estimate = smooth(r->estimate, sample);
	if (!r->observations)
		r->first_ms = now_ms;
	r->observations++;
	r->last_ms = now_ms;
	return 1;
}

int fzn_metrics_count(fzn_metrics_t *m, const char *name, uint64_t amount, uint64_t now_ms)
{
	fzn_metric_t *r = name ? find(m, name) : NULL;

	if (!r)
		return 0;
	if (!r->observations)
		r->window_start_ms = r->first_ms = now_ms;
	/* THE WINDOW ENDED: its sum a second over how long it ran, as the meter's
	 * rows close theirs. A clock set back starts a window afresh. */
	if (now_ms < r->window_start_ms)
		r->window_start_ms = now_ms;
	else if (now_ms >= r->window_start_ms + FZN_METRIC_WINDOW_MS) {
		uint64_t span_ms = now_ms - r->window_start_ms;

		r->rate = r->window_sum * 1000u / span_ms;
		r->window_start_ms = now_ms;
		r->window_sum = 0;
	}
	r->total += amount;
	r->window_sum += amount;
	r->observations++;
	r->last_ms = now_ms;
	return 1;
}

size_t fzn_metrics_page(const fzn_metrics_t *m, const char *prefix, size_t from, size_t max,
                        void (*row)(void *ctx, const fzn_metric_t *r), void *ctx, size_t *next)
{
	size_t i, seen = 0, handed = 0, plen = prefix ? strlen(prefix) : 0u;

	if (next)
		*next = from;
	if (!m || !m->rows)
		return 0;
	for (i = 0; i < m->n; i++) {
		if (plen && strncmp(m->rows[i].name, prefix, plen) != 0)
			continue;
		if (seen++ < from)
			continue;
		if (handed == max)
			return handed;
		if (row)
			row(ctx, &m->rows[i]);
		handed++;
		if (next)
			*next = seen;
	}
	if (next)
		*next = seen;
	return handed;
}
