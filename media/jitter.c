/* A call's frames put back in order: media/jitter.h, fuzznet sec 1234. */
#include "jitter.h"

#include <string.h>

/* `a` before `b`, serially. */
static int before(uint32_t a, uint32_t b)
{
	return (int32_t)(a - b) < 0;
}

void fzn_jitter_init(fzn_jitter_t *j)
{
	if (j)
		memset(j, 0, sizeof(*j));
}

size_t fzn_jitter_held(const fzn_jitter_t *j)
{
	size_t i, n = 0;

	for (i = 0; j && i < FZN_JITTER_SLOTS; i++)
		n += j->entries[i].used != 0u;
	return n;
}

uint64_t fzn_jitter_lost(const fzn_jitter_t *j)
{
	return j ? j->lost : 0u;
}

/* THE OLDEST HELD, serially; 0 with none. */
static int oldest(const fzn_jitter_t *j, uint32_t *seq)
{
	size_t i;
	int any = 0;

	for (i = 0; i < FZN_JITTER_SLOTS; i++)
		if (j->entries[i].used && (!any || before(j->entries[i].seq, *seq))) {
			*seq = j->entries[i].seq;
			any = 1;
		}
	return any;
}

/* PAST FZN_JITTER_CATCH_UP HELD, the newest FZN_JITTER_START kept and play
 * moved to the first of them, everything skipped counted lost. */
static void catch_up(fzn_jitter_t *j)
{
	uint32_t keep_from = 0;
	size_t i, k;

	if (fzn_jitter_held(j) <= FZN_JITTER_CATCH_UP)
		return;
	/* The FZN_JITTER_START-th newest: the held seq with exactly START - 1
	 * held after it. */
	for (i = 0; i < FZN_JITTER_SLOTS; i++) {
		size_t newer = 0;

		if (!j->entries[i].used)
			continue;
		for (k = 0; k < FZN_JITTER_SLOTS; k++)
			if (j->entries[k].used && before(j->entries[i].seq, j->entries[k].seq))
				newer++;
		if (newer == FZN_JITTER_START - 1u) {
			keep_from = j->entries[i].seq;
			break;
		}
	}
	j->lost += (uint64_t)(uint32_t)(keep_from - j->next);
	for (i = 0; i < FZN_JITTER_SLOTS; i++)
		if (j->entries[i].used && before(j->entries[i].seq, keep_from))
			j->entries[i].used = 0;
	j->next = keep_from;
}

int fzn_jitter_take(fzn_jitter_t *j, uint32_t seq, const uint8_t *frame, size_t len)
{
	fzn_jitter_slot_t *s;

	if (!j || (len && !frame) || len > FZN_JITTER_FRAME_MAX)
		return 0;
	/* LATE IS LOST: one already played past is not taken. */
	if (j->playing && before(seq, j->next))
		return 0;
	/* FAR AHEAD of what plays next, past what the slots hold: every frame
	 * between is gone, and play moves to this one. */
	if (j->playing && (uint32_t)(seq - j->next) >= FZN_JITTER_SLOTS) {
		size_t i;

		j->lost += (uint64_t)(uint32_t)(seq - j->next);
		for (i = 0; i < FZN_JITTER_SLOTS; i++)
			j->entries[i].used = 0;
		j->next = seq;
	}
	s = &j->entries[seq % FZN_JITTER_SLOTS];
	/* A SLOT HOLDING ANOTHER FRAME keeps the newer of the two. */
	if (s->used && s->seq != seq && before(seq, s->seq))
		return 0;
	s->seq = seq;
	s->len = (uint16_t)len;
	if (len)
		memcpy(s->frame, frame, len);
	s->used = 1;
	if (j->playing)
		catch_up(j);
	return 1;
}

int fzn_jitter_pull(fzn_jitter_t *j, uint8_t *frame, size_t cap, size_t *len)
{
	fzn_jitter_slot_t *s;
	size_t i;

	if (!j || !len)
		return 0;
	*len = 0;
	if (!j->playing) {
		if (fzn_jitter_held(j) < FZN_JITTER_START || !oldest(j, &j->next))
			return 0;
		j->playing = 1;
	}
	s = &j->entries[j->next % FZN_JITTER_SLOTS];
	if (s->used && s->seq == j->next && s->len <= cap) {
		if (s->len && frame)
			memcpy(frame, s->frame, s->len);
		*len = s->len;
		s->used = 0;
	} else {
		j->lost++;
	}
	/* ANYTHING OLDER THAN WHAT PLAYS NEXT IS GONE. */
	for (i = 0; i < FZN_JITTER_SLOTS; i++)
		if (j->entries[i].used && !before(j->next, j->entries[i].seq))
			j->entries[i].used = 0;
	j->next++;
	return 1;
}
