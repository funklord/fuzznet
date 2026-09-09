/* See sched_print.h. */

#include "sched_print.h"

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

/* What the table looked like to this class, counted without deciding
 * anything. */
struct census {
	size_t links;
	size_t admitted;
	size_t down;
	size_t slow;
	size_t lossy;
	size_t small;
	/* The id and cost of the chosen link, when there is one. */
	uint32_t id;
	uint64_t cost;
};

static void take_census(const fzn_sched_candidate_t *links, size_t count,
                        const fzn_class_t *wanted, struct census *c)
{
	size_t i;

	memset(c, 0, sizeof(*c));
	c->links = count;

	for (i = 0; i < count; i++) {
		/* ASKED OF THE MODULE, so a report cannot disagree with what
		 * `fzn_sched_select` skipped. Re-deriving the three
		 * comparisons here would be a second definition of a hard
		 * constraint, which is what `fzn_sched_excluded_by` exists to
		 * prevent. */
		switch (fzn_sched_excluded_by(&links[i], wanted)) {
		case FZN_SCHED_ADMITTED:
			c->admitted++;
			break;
		case FZN_SCHED_EXCLUDED_UNUSABLE:
			c->down++;
			break;
		case FZN_SCHED_EXCLUDED_LATENCY:
			c->slow++;
			break;
		case FZN_SCHED_EXCLUDED_LOSS:
			c->lossy++;
			break;
		case FZN_SCHED_EXCLUDED_MTU:
			c->small++;
			break;
		case FZN_SCHED_EXCLUDED_MALFORMED:
			/* A null link inside a non-null array, which the caller
			 * cannot produce with this signature -- counted nowhere
			 * rather than folded into a reason it is not. */
			break;
		}
	}
}

/* Which of the four exclusion states the census describes, when nothing was
 * admitted. Separate from `render` because it is a judgement and rendering is
 * not. */
static fzn_sched_line_t nothing_qualified(const struct census *c)
{
	size_t kinds = 0;

	if (c->slow)
		kinds++;
	if (c->lossy)
		kinds++;
	if (c->small)
		kinds++;

	/* EVERY LINK DOWN OUTRANKS THE CONSTRAINTS, because it is not about
	 * this class at all: a table of dead links excludes every class there
	 * is, and telling somebody to raise a latency bound would send them to
	 * change the one thing that cannot help. */
	if (kinds == 0u)
		return FZN_SCHED_LINE_NOTHING_UP;
	/* Some links down and the rest excluded for ONE reason still has that
	 * one fix, so the down ones are reported as a count rather than
	 * changing the verdict. */
	if (kinds > 1u)
		return FZN_SCHED_LINE_NO_SINGLE_FIX;
	if (c->slow)
		return FZN_SCHED_LINE_TOO_SLOW;
	if (c->lossy)
		return FZN_SCHED_LINE_TOO_LOSSY;
	return FZN_SCHED_LINE_TOO_SMALL;
}

static void render(struct sink *s, fzn_sched_line_t state, const struct census *c)
{
	/*
	 * THE VERDICT LEADS. sec 207: a terminal clips from the right, and
	 * every line below opens with what happened rather than with the
	 * counts that explain it.
	 *
	 * ALL SEVEN NAMED, NO `default:`, so a state added later will not
	 * compile until it has a line.
	 */
	switch (state) {
	case FZN_SCHED_LINE_NONE:
		put_str(s, "cannot say -- there is no selection to report\n");
		return;
	case FZN_SCHED_LINE_CHOSEN:
		put_str(s, "link ");
		put_u64(s, c->id);
		put_str(s, " carries this class, at cost ");
		put_u64(s, c->cost);
		put_str(s, " of ");
		put_u64(s, c->admitted);
		put_str(s, " that qualified\n");
		return;
	case FZN_SCHED_LINE_NOTHING_UP:
		/* NOT A CLASS PROBLEM, and the line has to say so or somebody
		 * spends the afternoon loosening constraints. */
		put_str(s, "DROPPING -- none of ");
		put_u64(s, c->links);
		put_str(s, " links is up, so no class can be carried and this one is not "
		           "the reason\n");
		return;
	case FZN_SCHED_LINE_TOO_SLOW:
		put_str(s, "DROPPING -- ");
		put_u64(s, c->slow);
		put_str(s, " of ");
		put_u64(s, c->links);
		put_str(s, " links are slower than this class allows, so max_latency_ms is "
		           "the bound to raise\n");
		return;
	case FZN_SCHED_LINE_TOO_LOSSY:
		put_str(s, "DROPPING -- ");
		put_u64(s, c->lossy);
		put_str(s, " of ");
		put_u64(s, c->links);
		put_str(s, " links lose more than this class allows, so max_loss_permille "
		           "is the bound to raise\n");
		return;
	case FZN_SCHED_LINE_TOO_SMALL:
		put_str(s, "DROPPING -- ");
		put_u64(s, c->small);
		put_str(s, " of ");
		put_u64(s, c->links);
		put_str(s, " links carry less than this class needs, so min_mtu is the "
		           "bound to lower\n");
		return;
	case FZN_SCHED_LINE_NO_SINGLE_FIX:
		/* THE ONE WITH NO FIX TO NAME. Every other line points at a
		 * field; this one exists to say that pointing at any of them
		 * would be wrong. */
		put_str(s, "DROPPING -- no single change helps: ");
		put_u64(s, c->slow);
		put_str(s, " too slow, ");
		put_u64(s, c->lossy);
		put_str(s, " too lossy, ");
		put_u64(s, c->small);
		put_str(s, " too small, ");
		put_u64(s, c->down);
		put_str(s, " down\n");
		return;
	}
}

fzn_sched_err_t fzn_sched_print(const fzn_sched_candidate_t *links, size_t link_count,
                                const fzn_class_t *wanted, fzn_sched_err_t err, size_t chosen,
                                char *out, size_t cap, size_t *len_out,
                                fzn_sched_line_t *state_out)
{
	struct sink measure;
	struct sink write;
	struct census c;
	fzn_sched_line_t said = FZN_SCHED_LINE_NONE;

	if (len_out)
		*len_out = 0;
	if (state_out)
		*state_out = FZN_SCHED_LINE_NONE;

	if (!out || !len_out || !state_out)
		return FZN_SCHED_ERR_MALFORMED;

	memset(&c, 0, sizeof(c));

	if (links && link_count && wanted) {
		take_census(links, link_count, wanted, &c);

		if (err == FZN_SCHED_OK && chosen < link_count
		    && fzn_sched_admits(&links[chosen], wanted)) {
			said = FZN_SCHED_LINE_CHOSEN;
			c.id = links[chosen].id;
			c.cost = fzn_sched_cost(&links[chosen], wanted);
		} else if (err == FZN_SCHED_ERR_NONE) {
			said = nothing_qualified(&c);
		}
		/* AN `err` OF OK NAMING A LINK THAT DOES NOT QUALIFY IS NOT
		 * REPORTED AS A CHOICE. It is either a caller pairing an answer
		 * with the wrong table or a selection this module would not
		 * have made, and describing it as a choice would put this
		 * printer's name behind it. */
	}

	measure.out = NULL;
	measure.used = 0;
	render(&measure, said, &c);

	if (measure.used + 1u > cap) {
		*len_out = measure.used + 1u;
		return FZN_SCHED_ERR_MALFORMED;
	}

	write.out = out;
	write.used = 0;
	render(&write, said, &c);
	out[write.used] = '\0';
	*len_out = write.used;
	*state_out = said;

	return FZN_SCHED_OK;
}
