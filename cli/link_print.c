#include "link_print.h"

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

static void put_u64(struct sink *s, uint64_t value)
{
	char digits[DIGITS_MAX];
	size_t at = sizeof(digits);

	do {
		digits[--at] = (char)('0' + (value % 10u));
		value /= 10u;
	} while (value);

	put(s, digits + at, sizeof(digits) - at);
}

/* Parts per thousand as a percentage with one decimal, since that is how
 * `fzn_sched_candidate_t` documents the unit and a reader should not have to
 * convert a permille in their head to know whether a path is losing. */
static void put_permille(struct sink *s, uint16_t permille)
{
	put_u64(s, permille / 10u);
	put_str(s, ".");
	put_u64(s, permille % 10u);
	put_str(s, "%");
}

/* What the table holds, counted once so the line and the out-parameters
 * cannot disagree about it. */
struct tally {
	size_t links;
	size_t usable;
	size_t unmeasured;              /* usable, and never observed */
	const fzn_link_entry_t *best;   /* the usable link with the lowest estimate */
};

static void count(const fzn_link_table_t *table, struct tally *t)
{
	size_t i;

	memset(t, 0, sizeof(*t));

	if (!table || !table->entries)
		return;

	t->links = table->used;
	for (i = 0u; i < table->used; i++) {
		const fzn_link_entry_t *e = &table->entries[i];

		if (!e->usable)
			continue;

		t->usable++;
		if (!e->observations)
			t->unmeasured++;

		/* LOWEST ESTIMATE WINS, AND TIES GO TO THE FIRST, which is the
		 * earliest registered. This is NOT `fzn_sched_select` and does
		 * not try to be -- sched weighs metric, loss and MTU against a
		 * traffic class this printer knows nothing about. Naming it
		 * "best" here would invite a reader to expect the two to agree;
		 * the line says "lowest" for that reason. */
		if (!t->best || e->latency_ms < t->best->latency_ms)
			t->best = e;
	}
}

static fzn_link_line_t classify(const struct tally *t)
{
	if (!t->links)
		return FZN_LINK_LINE_NONE;
	if (!t->usable)
		return FZN_LINK_LINE_ALL_DOWN;
	/* MEASURED MEANS EVIDENCE ON A LINK THAT CAN BE CHOSEN. An observed
	 * link that has since been marked unusable leaves nothing choosable
	 * with evidence behind it, so the state falls back to UNMEASURED
	 * rather than staying at MEASURED on the strength of a path nothing
	 * will select. */
	if (t->unmeasured == t->usable)
		return FZN_LINK_LINE_UNMEASURED;
	return FZN_LINK_LINE_MEASURED;
}

static void render(struct sink *s, const struct tally *t, fzn_link_line_t state)
{
	if (state == FZN_LINK_LINE_NONE) {
		put_str(s, "no links -- nothing has been registered, so there is "
		           "no path to try");
		return;
	}

	put_u64(s, t->links);
	put_str(s, t->links == 1u ? " link, " : " links, ");

	if (state == FZN_LINK_LINE_ALL_DOWN) {
		/* SWITCHED OFF, NOT MISSING. The count is repeated as "all"
		 * rather than as a zero, because a zero beside a link count is
		 * the reading this sentence exists to prevent. */
		put_str(s, "all marked unusable -- this host has paths and is "
		           "not permitted to use them");
		return;
	}

	put_u64(s, t->usable);
	put_str(s, " usable");

	if (state == FZN_LINK_LINE_UNMEASURED) {
		/* ONE SENTENCE FOR THE WHOLE TABLE, because in this state every
		 * usable link is on a prior and there is nothing to qualify
		 * link by link. An earlier draft marked the lowest number
		 * DECLARED and then added "2 usable links are still on a
		 * declared metric", which says the same thing twice and reads
		 * as two findings. */
		put_str(s, ", none measured; lowest declared ");
		put_u64(s, t->best->latency_ms);
		put_str(s, " ms -- every number here is the far end's claim");
		return;
	}

	put_str(s, "; lowest ");
	put_u64(s, t->best->latency_ms);
	put_str(s, " ms");

	if (!t->best->observations) {
		/* THE MARKER GOES ON THE NUMBER IT QUALIFIES. A trailing note
		 * would be read as being about the table, and the number a
		 * person acts on is this one. The state is MEASURED here -- some
		 * OTHER usable link has evidence -- so the lowest estimate being
		 * a claim is exactly the case `link.h` warns about: an unused
		 * link asserted to be fast outranking a measured one. */
		put_str(s, " DECLARED (never measured)");
	} else {
		put_str(s, " over ");
		put_u64(s, t->best->observations);
		put_str(s, t->best->observations == 1u ? " sample" : " samples");
		put_str(s, ", losing ");
		put_permille(s, t->best->loss_permille);
	}

	if (t->unmeasured) {
		put_str(s, "; ");
		put_u64(s, t->unmeasured);
		put_str(s, t->unmeasured == 1u ? " usable link is" : " usable links are");
		put_str(s, " still on a declared metric");
	}
}

fzn_link_err_t fzn_link_print(const fzn_link_table_t *table, char *out, size_t cap,
                              size_t *len_out, fzn_link_line_t *state_out,
                              size_t *unmeasured_out)
{
	struct sink measure = { NULL, 0u };
	struct sink write;
	struct tally t;
	fzn_link_line_t state;

	/* The conservative values first, so a refusal below leaves a caller
	 * reading "no path" rather than whatever it passed in. */
	if (state_out)
		*state_out = FZN_LINK_LINE_NONE;
	if (unmeasured_out)
		*unmeasured_out = 0u;
	if (len_out)
		*len_out = 0u;

	if (!out || !len_out || !state_out || !unmeasured_out)
		return FZN_LINK_ERR_MALFORMED;

	count(table, &t);
	state = classify(&t);

	render(&measure, &t, state);
	if (measure.used + 1u > cap) {
		*len_out = measure.used + 1u;
		return FZN_LINK_ERR_MALFORMED;
	}

	write.out = out;
	write.used = 0u;
	render(&write, &t, state);
	out[write.used] = '\0';

	*len_out = write.used;
	*state_out = state;
	*unmeasured_out = t.unmeasured;
	return FZN_LINK_OK;
}
