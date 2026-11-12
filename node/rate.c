/* How often a value is stored or carried. node/rate.h says what and why. */
#include "rate.h"

#include <string.h>

void fzn_rate_init(fzn_rate_t *r, fzn_rate_slot_t *slots, size_t cap)
{
	if (!r)
		return;
	memset(r, 0, sizeof(*r));
	r->rows = slots;
	r->cap = slots ? cap : 0u;
	if (slots && cap)
		memset(slots, 0, cap * sizeof(*slots));
}

/* ONE OF THE BURST'S, at `now_ms`: 1 when one was left. */
static int burst_take(fzn_rate_t *r, uint64_t now_ms)
{
	if (now_ms < r->burst_from_ms || now_ms - r->burst_from_ms >= FZN_RATE_BURST_MS) {
		r->burst_from_ms = now_ms;
		r->burst_used = 0;
	}
	if (r->burst_used >= FZN_RATE_BURST)
		return 0;
	r->burst_used++;
	return 1;
}

static fzn_rate_slot_t *slot_of(fzn_rate_t *r, const uint8_t *key, size_t key_len)
{
	fzn_rate_slot_t *free_one = NULL, *oldest = NULL;
	size_t i;

	for (i = 0; i < r->cap; i++) {
		fzn_rate_slot_t *s = &r->rows[i];

		if (s->used && s->key_len == key_len && memcmp(s->key, key, key_len) == 0)
			return s;
		if (!s->used && !free_one)
			free_one = s;
		/* A FULL TABLE gives way the least recently offered with nothing held. */
		if (s->used && !s->pending && (!oldest || s->offered_ms < oldest->offered_ms))
			oldest = s;
	}
	if (!free_one && oldest) {
		memset(oldest, 0, sizeof(*oldest));
		free_one = oldest;
	}
	return free_one;
}

fzn_rate_verdict_t fzn_rate_offer(fzn_rate_t *r, const uint8_t *key, size_t key_len,
                                  const uint8_t *value, size_t value_len, uint64_t every_ms,
                                  uint64_t now_ms, int *first)
{
	fzn_rate_slot_t *s;

	if (first)
		*first = 0;
	if (!r || !r->rows || !key || !key_len || key_len > FZN_RATE_KEY_MAX
	    || value_len > FZN_RATE_VALUE_MAX || (value_len && !value)
	    || !(s = slot_of(r, key, key_len)))
		return FZN_RATE_REFUSED;
	if (!s->used) {
		s->used = 1;
		memcpy(s->key, key, key_len);
		s->key_len = key_len;
	}
	s->window_ms = every_ms < FZN_RATE_FLOOR_MS ? FZN_RATE_FLOOR_MS : every_ms;
	s->offered_ms = now_ms;
	/* FREE: never passed, or its window has gone by, nothing held, and the
	 * burst not spent. */
	if (!s->pending && (!s->passed_ms || now_ms - s->passed_ms >= s->window_ms)
	    && burst_take(r, now_ms)) {
		s->passed_ms = now_ms ? now_ms : 1u;
		s->held = 0;
		s->said = 0;
		return FZN_RATE_NOW;
	}
	if (!s->said) {
		s->said = 1;
		if (first)
			*first = 1;
	}
	memcpy(s->value, value, value_len);
	s->value_len = value_len;
	s->pending = 1;
	s->held++;
	return FZN_RATE_HELD;
}

size_t fzn_rate_due(fzn_rate_t *r, uint64_t now_ms,
                    void (*due)(void *ctx, const uint8_t *key, size_t key_len,
                                const uint8_t *value, size_t value_len, unsigned long held),
                    void *ctx)
{
	size_t i, n = 0;

	for (i = 0; r && r->rows && i < r->cap; i++) {
		fzn_rate_slot_t *s = &r->rows[i];
		unsigned long held;

		if (!s->used || !s->pending || now_ms - s->passed_ms < s->window_ms
		    || !burst_take(r, now_ms))
			continue;
		held = s->held;
		s->pending = 0;
		s->passed_ms = now_ms ? now_ms : 1u;
		s->held = 0;
		if (due)
			due(ctx, s->key, s->key_len, s->value, s->value_len, held);
		n++;
	}
	return n;
}
