/* A guard against hammering: project.md sec 1074, and the header. */
#include "guard.h"

#include <string.h>

void fzn_guard_init(fzn_guard_t *g, fzn_guard_slot_t *rows, size_t cap)
{
	if (!g)
		return;
	memset(g, 0, sizeof(*g));
	if (rows && cap) {
		memset(rows, 0, cap * sizeof(*rows));
		g->rows = rows;
		g->cap = cap;
	}
}

int fzn_guard_full(const fzn_guard_t *g)
{
	return g && g->used >= g->cap;
}

int fzn_guard_rows(fzn_guard_t *g, fzn_guard_slot_t *rows, size_t cap)
{
	if (!g || !rows || cap < g->cap)
		return 0;
	memset(rows + g->cap, 0, (cap - g->cap) * sizeof(*rows));
	g->rows = rows;
	g->cap = cap;
	return 1;
}

static fzn_guard_slot_t *slot_of(fzn_guard_t *g, const uint8_t *key, uint64_t now_ms,
                                 uint32_t burst)
{
	fzn_guard_slot_t *s = NULL, *old = NULL;
	size_t i;

	for (i = 0; i < g->cap; i++) {
		fzn_guard_slot_t *r = &g->rows[i];

		if (r->used && memcmp(r->key, key, FZN_GUARD_KEY_LEN) == 0)
			return r;
		if (!r->used && !s)
			s = r;
		/* NEVER A BLOCKED KEY'S PLACE: that would set it free. */
		if (r->used && r->blocked_until_ms <= now_ms && (!old || r->seen_ms < old->seen_ms))
			old = r;
	}
	if (!s) {
		s = old;
		if (!s)
			return NULL;
	} else {
		g->used++;
	}
	memset(s, 0, sizeof(*s));
	memcpy(s->key, key, FZN_GUARD_KEY_LEN);
	s->tokens = burst;
	s->tokens_at_ms = now_ms;
	s->used = 1;
	return s;
}

fzn_guard_verdict_t fzn_guard_ask(fzn_guard_t *g, const uint8_t key[FZN_GUARD_KEY_LEN],
                                  uint64_t now_ms, uint32_t burst, uint64_t refill_ms,
                                  uint64_t block_max_ms, int *first)
{
	fzn_guard_slot_t *s;
	uint64_t period;

	if (first)
		*first = 0;
	/* WITH NO ROOM TO REMEMBER, admitted: a guard that cannot count is no
	 * reason to refuse a caller. */
	if (!g || !g->rows || !key || !burst || !refill_ms || !(s = slot_of(g, key, now_ms, burst)))
		return FZN_GUARD_ADMIT;
	/* QUIET A WHOLE BLOCK'S LENGTH: clean again. */
	if (s->offences && now_ms >= s->seen_ms + block_max_ms) {
		s->offences = 0;
		s->refused = 0;
	}
	s->seen_ms = now_ms;
	if (now_ms < s->blocked_until_ms) {
		g->refused_total++;
		return FZN_GUARD_BLOCKED;
	}
	/* TOKENS EARNED since they were last counted, one a refill, to the burst. */
	if (now_ms > s->tokens_at_ms) {
		uint64_t earned = (now_ms - s->tokens_at_ms) / refill_ms;

		if (earned) {
			s->tokens = s->tokens + earned >= burst ? burst : s->tokens + (uint32_t)earned;
			s->tokens_at_ms += earned * refill_ms;
		}
	} else {
		s->tokens_at_ms = now_ms;
	}
	/* A BURST LOWERED takes hold at once: tokens held past it are not kept. */
	if (s->tokens > burst)
		s->tokens = burst;
	if (s->tokens) {
		s->tokens--;
		s->refused = 0;
		return FZN_GUARD_ADMIT;
	}
	g->refused_total++;
	if (!s->refused) {
		/* THE FIRST REFUSAL: said once, and a token's wait the only cost. */
		s->refused = 1;
		if (first)
			*first = 1;
		return FZN_GUARD_REFUSED;
	}
	/* REFUSED AGAIN WHILE REFUSED: blocked, the period doubling an offence. */
	period = refill_ms;
	if (s->offences < 63u)
		period = refill_ms << s->offences;
	if (period > block_max_ms || period < refill_ms)
		period = block_max_ms;
	if (s->offences < 63u)
		s->offences++;
	s->blocked_until_ms = now_ms + period;
	return FZN_GUARD_BLOCKED;
}
