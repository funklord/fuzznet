/* See claim_print.h. */

#include "claim_print.h"

#include <string.h>

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

static void render(struct sink *s, fzn_claim_line_t state)
{
	/*
	 * THE VERDICT LEADS, and here there is nothing but verdict: no counts,
	 * because a claim is one bit and the interesting content is entirely
	 * in which of the four things happened.
	 *
	 * ALL FIVE NAMED, NO `default:`.
	 */
	switch (state) {
	case FZN_CLAIM_LINE_NONE:
		put_str(s, "cannot say -- there is no claim to report on\n");
		return;
	case FZN_CLAIM_LINE_OWNED:
		put_str(s, "this process owns the identity's mutable state\n");
		return;
	case FZN_CLAIM_LINE_ELSEWHERE:
		/* THE WORKING CASE, AND IT MUST NOT READ AS A FAULT. Every
		 * process but one gets this, and a consumer that shows it as an
		 * error has alarmed a user about a host that is fine. */
		put_str(s, "another process of this identity owns its mutable state, which "
		           "is the normal arrangement -- this one reads the shared store "
		           "and submits through the owner\n");
		return;
	case FZN_CLAIM_LINE_UNARBITRATED:
		/* THE ONE THAT NEEDS SOMEBODY. */
		put_str(s, "PROBLEM -- this host cannot arbitrate ownership at all, so the "
		           "store is unusable rather than busy: the lock backend could not "
		           "answer\n");
		return;
	case FZN_CLAIM_LINE_RELEASED:
		/* NOT "SOMEBODY ELSE HAS IT". This process let go; whether
		 * anybody has picked it up is a question nobody asked. */
		put_str(s, "this process no longer owns the identity's mutable state, and "
		           "another may take it\n");
		return;
	case FZN_CLAIM_LINE_MISUSE:
		put_str(s, "PROBLEM -- this program asked for something its own state "
		           "contradicts, which is a bug in it rather than a condition of "
		           "the host\n");
		return;
	}
}

fzn_claim_err_t fzn_claim_print(const fzn_claim_t *claim, fzn_claim_err_t err, char *out,
                                size_t cap, size_t *len_out, fzn_claim_line_t *state_out)
{
	struct sink measure;
	struct sink write;
	fzn_claim_line_t said = FZN_CLAIM_LINE_NONE;

	if (len_out)
		*len_out = 0;
	if (state_out)
		*state_out = FZN_CLAIM_LINE_NONE;

	if (!out || !len_out || !state_out)
		return FZN_CLAIM_ERR_MALFORMED;

	if (claim) {
		switch (err) {
		case FZN_CLAIM_OK:
			/* ASKED RATHER THAN ASSUMED. A take and a release both
			 * answer OK and leave the claim in opposite states. */
			said = fzn_claim_held(claim) ? FZN_CLAIM_LINE_OWNED
			                             : FZN_CLAIM_LINE_RELEASED;
			break;
		case FZN_CLAIM_ERR_HELD:
			said = FZN_CLAIM_LINE_ELSEWHERE;
			break;
		case FZN_CLAIM_ERR_BACKEND:
			said = FZN_CLAIM_LINE_UNARBITRATED;
			break;
		case FZN_CLAIM_ERR_MALFORMED:
		case FZN_CLAIM_ERR_STATE:
			said = FZN_CLAIM_LINE_MISUSE;
			break;
		}
		/* NO `default:` ABOVE, so a code added to claim.h fails to
		 * compile here rather than rendering as "cannot say". */
	}

	measure.out = NULL;
	measure.used = 0;
	render(&measure, said);

	if (measure.used + 1u > cap) {
		*len_out = measure.used + 1u;
		return FZN_CLAIM_ERR_MALFORMED;
	}

	write.out = out;
	write.used = 0;
	render(&write, said);
	out[write.used] = '\0';
	*len_out = write.used;
	*state_out = said;

	return FZN_CLAIM_OK;
}
