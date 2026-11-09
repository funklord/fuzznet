#include "sync_load.h"

#include <stdio.h>
#include <string.h>

const char *fzn_sync_queue_name(fzn_sync_queue_t q)
{
	switch (q) {
	case FZN_SYNC_QUEUE_FILES:
		return "files";
	case FZN_SYNC_QUEUE_FILE_BYTES:
		return "file-bytes";
	case FZN_SYNC_QUEUE_ASKS:
		return "asks";
	case FZN_SYNC_QUEUE_ROUND_MS:
		return "round-ms";
	default:
		return "?";
	}
}

const char *fzn_sync_verdict_name(fzn_sync_verdict_t v)
{
	switch (v) {
	case FZN_SYNC_LOAD_OK:
		return "ok";
	case FZN_SYNC_LOAD_BUSY:
		return "busy";
	case FZN_SYNC_LOAD_GROWING:
		return "growing";
	default:
		return "?";
	}
}

void fzn_sync_load_sample(fzn_sync_load_t *s, const uint64_t values[FZN_SYNC_QUEUES],
                          uint64_t period_ms)
{
	size_t q;
	uint64_t load;

	if (!s || !values)
		return;
	for (q = 0; q < FZN_SYNC_QUEUES; q++)
		s->samples[q][s->at] = values[q];
	load = period_ms ? values[FZN_SYNC_QUEUE_ROUND_MS] * 100u / period_ms : 0u;
	s->load[s->at] = load > UINT32_MAX ? UINT32_MAX : (uint32_t)load;
	s->at = (s->at + 1u) % FZN_SYNC_LOAD_SAMPLES;
	if (s->n < FZN_SYNC_LOAD_SAMPLES)
		s->n++;
}

/* The `i`th sample held of row `row`, oldest first. */
static uint64_t sample_at(const fzn_sync_load_t *s, const uint64_t *row, size_t i)
{
	size_t first = s->n < FZN_SYNC_LOAD_SAMPLES ? 0u : s->at;

	return row[(first + i) % FZN_SYNC_LOAD_SAMPLES];
}

fzn_sync_stat_t fzn_sync_load_stat(const fzn_sync_load_t *s, fzn_sync_queue_t q)
{
	fzn_sync_stat_t st;
	uint64_t sum = 0, prev = 0;
	size_t i, rises = 0;

	memset(&st, 0, sizeof(st));
	if (!s || !s->n || q >= FZN_SYNC_QUEUES)
		return st;
	/* GROWING: the window full, the last above the first, rising at
	 * half its steps or more, and no fall of more than a quarter on the
	 * way -- a queue a round drains in part and then refills is not one
	 * the rounds keep up with either, but a deep fall is one they did,
	 * and a queue at rest that ends one up has not grown. */
	st.growing = s->n == FZN_SYNC_LOAD_SAMPLES;
	for (i = 0; i < s->n; i++) {
		uint64_t v = sample_at(s, s->samples[q], i);

		sum += v;
		if (v > st.peak)
			st.peak = v;
		if (i && v < prev - prev / 4u)
			st.growing = 0;
		rises += i && v > prev;
		prev = v;
	}
	st.now = prev;
	st.mean = sum / s->n;
	if (st.growing && (st.now <= sample_at(s, s->samples[q], 0) || rises < s->n / 2u))
		st.growing = 0;
	return st;
}

uint32_t fzn_sync_load_now(const fzn_sync_load_t *s)
{
	if (!s || !s->n)
		return 0;
	return s->load[(s->at + FZN_SYNC_LOAD_SAMPLES - 1u) % FZN_SYNC_LOAD_SAMPLES];
}

fzn_sync_verdict_t fzn_sync_load_verdict(const fzn_sync_load_t *s, fzn_sync_queue_t *why)
{
	size_t q, i;

	if (!s || s->n < FZN_SYNC_LOAD_SAMPLES)
		return FZN_SYNC_LOAD_OK;
	/* THE ROUND'S OWN LENGTH is the load, not a queue: a round that
	 * grows in length is said as busy once it fills its period. */
	for (q = 0; q < FZN_SYNC_QUEUES; q++)
		if (q != FZN_SYNC_QUEUE_ROUND_MS && fzn_sync_load_stat(s, (fzn_sync_queue_t)q).growing) {
			if (why)
				*why = (fzn_sync_queue_t)q;
			return FZN_SYNC_LOAD_GROWING;
		}
	for (i = 0; i < FZN_SYNC_LOAD_SAMPLES && s->load[i] >= 100u; i++)
		;
	if (i < FZN_SYNC_LOAD_SAMPLES)
		return FZN_SYNC_LOAD_OK;
	if (why)
		*why = FZN_SYNC_QUEUE_ROUND_MS;
	return FZN_SYNC_LOAD_BUSY;
}

size_t fzn_sync_load_say(const fzn_sync_load_t *s, char *out, size_t cap)
{
	size_t at, q;
	int n;

	if (!s || !out || !cap)
		return 0;
	n = snprintf(out, cap, "ok %u %s", (unsigned)fzn_sync_load_now(s),
	             fzn_sync_verdict_name(fzn_sync_load_verdict(s, NULL)));
	if (n < 0 || (size_t)n >= cap)
		return 0;
	at = (size_t)n;
	for (q = 0; q < FZN_SYNC_QUEUES; q++) {
		fzn_sync_stat_t st = fzn_sync_load_stat(s, (fzn_sync_queue_t)q);

		n = snprintf(out + at, cap - at, " %s,%llu,%llu,%llu,%s",
		             fzn_sync_queue_name((fzn_sync_queue_t)q), (unsigned long long)st.now,
		             (unsigned long long)st.peak, (unsigned long long)st.mean,
		             st.growing ? "growing" : "steady");
		if (n < 0 || (size_t)n >= cap - at)
			return 0;
		at += (size_t)n;
	}
	if (at + 2u > cap)
		return 0;
	out[at++] = '\n';
	out[at] = '\0';
	return at;
}
