/* See reasm_print.h. */

#include "reasm_print.h"

#include <string.h>

#define DIGITS_MAX 21u

struct sink {
	char *out;
	size_t used;
};

static void put(struct sink *s, const char *bytes, size_t len)
{
	if (s->out)
		memcpy(s->out + s->used, bytes, len);
	s->used += len;
}

static void put_str(struct sink *s, const char *text)
{
	put(s, text, strlen(text));
}

static void put_size(struct sink *s, size_t value)
{
	char digits[DIGITS_MAX];
	size_t at = sizeof(digits);

	do {
		digits[--at] = (char)('0' + (value % 10u));
		value /= 10u;
	} while (value);

	put(s, digits + at, sizeof(digits) - at);
}

/* What the table is holding, counted without touching it. */
struct census {
	size_t live;
	size_t handed;
	size_t sweepable;
	size_t capacity;
	/* Distinct senders holding `per_sender_max` slots. Counted at each
	 * sender's FIRST live slot, so a sender with three slots is one
	 * sender rather than three. */
	size_t capped;
	size_t quota;
};

/* Whether slot `at` is the first LIVE slot its sender holds, so that a sender
 * is counted once however many slots it has. Live-only on both sides: a free
 * slot keeps whatever sender it last held, and matching against one would
 * silence a real sender by declaring it already seen. */
static int first_slot_for(const fzn_reasm_t *table, size_t at)
{
	size_t i;

	for (i = 0; i < at; i++) {
		const fzn_partial_t *earlier = &table->partials[i];

		if (earlier->live
		    && memcmp(earlier->sender, table->partials[at].sender, FZN_SENDER_LEN) == 0)
			return 0;
	}
	return 1;
}

static void take_census(const fzn_reasm_t *table, uint64_t now, struct census *c)
{
	size_t i;

	c->live = 0;
	c->handed = 0;
	c->sweepable = 0;
	c->capacity = table->capacity;
	c->capped = 0;
	c->quota = table->per_sender_max;

	for (i = 0; i < table->capacity; i++) {
		const fzn_partial_t *slot = &table->partials[i];

		if (!slot->live)
			continue;
		c->live++;

		/* THE QUOTA COUNT USES THE MODULE'S OWN DEFINITION, which is
		 * why it is a call and not a comparison written here. A count
		 * that skipped handed slots would be smaller than the one
		 * `fzn_reasm_accept` refuses on, and this line would report
		 * room for a sender already being told QUOTA. */
		if (first_slot_for(table, i) && table->per_sender_max
		    && fzn_reasm_held_by(table, slot->sender) >= table->per_sender_max)
			c->capped++;

		if (slot->handed) {
			c->handed++;
			continue;
		}
		/* THE SAME CONDITION `fzn_reasm_expire` SWEEPS ON, including
		 * the `!handed` above it: expiry must not take a slot the
		 * caller is still reading, so a count that ignored `handed`
		 * would promise back slots no sweep will return. */
		if (slot->expires_at <= now)
			c->sweepable++;
	}
}

static void render(struct sink *s, fzn_reasm_line_t state, const struct census *c)
{
	/*
	 * THE VERDICT LEADS, and here it leads because the three FULL lines
	 * differ in WHO has to act -- the consumer, the sweep, or whoever sizes
	 * the table. A line opening with counts would put that behind them.
	 *
	 * ALL SIX NAMED, NO `default:`.
	 */
	switch (state) {
	case FZN_REASM_LINE_NONE:
		put_str(s, "cannot say -- there is no reassembly table to read\n");
		return;
	case FZN_REASM_LINE_EMPTY:
		put_str(s, "nothing half-finished, ");
		put_size(s, c->capacity);
		put_str(s, " slots free\n");
		return;
	case FZN_REASM_LINE_HOLDING:
		put_str(s, "holding ");
		put_size(s, c->live);
		put_str(s, " of ");
		put_size(s, c->capacity);
		put_str(s, ", ");
		put_size(s, c->sweepable);
		put_str(s, " ready to sweep\n");
		return;
	case FZN_REASM_LINE_FULL_HANDED:
		/* THE FIX IS THE CONSUMER'S, and it is a leak. reassembly.h
		 * chose exhaustion as the honest symptom of a caller that never
		 * releases, so saying "full" without saying this sends somebody
		 * to enlarge a table that will fill again. */
		put_str(s, "FULL -- ");
		put_size(s, c->handed);
		put_str(s, " of ");
		put_size(s, c->capacity);
		put_str(s, " slots are finished messages nobody released\n");
		return;
	case FZN_REASM_LINE_FULL_UNSWEPT:
		put_str(s, "FULL -- ");
		put_size(s, c->sweepable);
		put_str(s, " of ");
		put_size(s, c->capacity);
		put_str(s, " slots are past their deadline, so nothing is calling expire\n");
		return;
	case FZN_REASM_LINE_QUOTA:
		/* THE VERDICT IS THAT SOMETHING IS BEING REFUSED, and the free
		 * slots are the evidence rather than the reassurance. Naming
		 * both numbers is what says which bound to raise: the capacity
		 * is not the one that is binding. */
		put_str(s, "REFUSING -- ");
		put_size(s, c->capped);
		put_str(s, " senders hold their quota of ");
		put_size(s, c->quota);
		put_str(s, " while ");
		put_size(s, c->capacity - c->live);
		put_str(s, " of ");
		put_size(s, c->capacity);
		put_str(s, " slots stand free, so per_sender_max is the bound that binds\n");
		return;
	case FZN_REASM_LINE_FULL_LIVE:
		/* NEITHER TIME NOR RELEASING HELPS. The header warns that a
		 * consumer will read a full table as the first of those, so
		 * this line has to rule both out rather than merely report a
		 * number. */
		put_str(s, "FULL -- ");
		put_size(s, c->capacity);
		put_str(s, " slots all live and unexpired, so waiting and releasing will not "
		           "help and the bounds are too small\n");
		return;
	}
}

fzn_reasm_err_t fzn_reasm_print(const fzn_reasm_t *table, uint64_t now, char *out, size_t cap,
                                size_t *len_out, fzn_reasm_line_t *state_out)
{
	struct sink measure;
	struct sink write;
	struct census c;
	fzn_reasm_line_t said = FZN_REASM_LINE_NONE;

	if (len_out)
		*len_out = 0;
	if (state_out)
		*state_out = FZN_REASM_LINE_NONE;

	if (!out || !len_out || !state_out)
		return FZN_REASM_ERR_MALFORMED;

	c.live = 0;
	c.handed = 0;
	c.sweepable = 0;
	c.capacity = 0;
	c.capped = 0;
	c.quota = 0;

	if (table && table->partials && table->capacity) {
		take_census(table, now, &c);

		if (c.live == 0u)
			said = FZN_REASM_LINE_EMPTY;
		/* A TABLE WITH ROOM STILL HAS A SECOND WAY TO REFUSE. Asked
		 * here rather than after the FULL arms because a full table
		 * refuses everybody and the per-sender bound is moot in it. */
		else if (c.live < c.capacity)
			said = c.capped ? FZN_REASM_LINE_QUOTA : FZN_REASM_LINE_HOLDING;
		/* MOST ACTIONABLE FIRST. A leak never self-corrects, a missed
		 * sweep is one call, and a sizing problem is a restart. */
		else if (c.handed)
			said = FZN_REASM_LINE_FULL_HANDED;
		else if (c.sweepable)
			said = FZN_REASM_LINE_FULL_UNSWEPT;
		else
			said = FZN_REASM_LINE_FULL_LIVE;
	}

	measure.out = NULL;
	measure.used = 0;
	render(&measure, said, &c);

	if (measure.used + 1u > cap) {
		*len_out = measure.used + 1u;
		return FZN_REASM_ERR_MALFORMED;
	}

	write.out = out;
	write.used = 0;
	render(&write, said, &c);
	out[write.used] = '\0';
	*len_out = write.used;
	*state_out = said;

	return FZN_REASM_OK;
}
