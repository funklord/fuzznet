#include "authz_print.h"

#include "../trust/trust.h"

#include <string.h>

/* The three origins a request can arrive over, with the words a person reads.
 * FZN_ORIGIN_NONE is not among them: it is the unset value, reaches nothing
 * by construction, and a column saying so would be about a mistake rather
 * than about a transport. */
struct origin_row {
	fzn_origin_t origin;
	const char *label;
};

static const struct origin_row ORIGINS[] = {
	{ FZN_ORIGIN_SAME_USER, "same user" },
	{ FZN_ORIGIN_LOCAL, "local" },
	{ FZN_ORIGIN_REMOTE, "remote" },
};

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

static void render(struct sink *s, const fzn_authz_policy_t *policy, fzn_authz_line_t state)
{
	char print[FZN_TRUST_FINGERPRINT_LEN];
	int first = 1;
	size_t i;

	if (state == FZN_AUTHZ_LINE_UNSPELLED) {
		/* NOBODY HAS SAID. Not "denied", which is what it does -- what
		 * it IS, is unconfigured, and the two want different actions
		 * from whoever is reading. */
		put_str(s, "no policy has been spelled; reachable from nothing\n");
		return;
	}

	/*
	 * REACHABILITY FIRST, THEN THE CAPABILITY, and it was the other way
	 * round until 2026-09-08. sec 207.
	 *
	 * A capability spells to 64 hex characters, and a terminal clips a
	 * line from the RIGHT -- so with the capability first, `reachable
	 * from` began at column 93 and the whole answer fell off an
	 * 80-column terminal. What an operator saw was an identifier and
	 * nothing about who may use it, which is the question this line
	 * exists to answer.
	 */
	put_str(s, "reachable from ");

	for (i = 0; i < sizeof(ORIGINS) / sizeof(ORIGINS[0]); i++) {
		/* THE LIBRARY'S ANSWER, not a test of the bitmask. */
		if (!fzn_authz_origin_permitted(*policy, ORIGINS[i].origin))
			continue;
		if (!first)
			put_str(s, ", ");
		put_str(s, ORIGINS[i].label);
		first = 0;
	}

	if (first)
		put_str(s, "nothing");

	put_str(s, "; ");

	if (state == FZN_AUTHZ_LINE_UNGUARDED)
		/* ITS OWN WORDS, because a policy that has drifted to
		 * unguarded is what somebody is looking for when they read
		 * this. */
		put_str(s, "no capability -- UNGUARDED");
	else {
		put_str(s, "capability ");
		if (fzn_trust_fingerprint(policy->capability.b, print, sizeof(print)) ==
		    FZN_TRUST_OK)
			put_str(s, print);
		else
			put_str(s, "this line could not format");
	}

	put_str(s, "\n");
}

fzn_chain_err_t fzn_authz_print(const fzn_authz_policy_t *policy, char *out, size_t cap,
                                size_t *len_out, fzn_authz_line_t *state_out)
{
	struct sink measure;
	struct sink write;
	fzn_authz_line_t said = FZN_AUTHZ_LINE_UNSPELLED;

	if (len_out)
		*len_out = 0;
	if (state_out)
		*state_out = FZN_AUTHZ_LINE_UNSPELLED;

	if (!out || !len_out || !state_out)
		return FZN_CHAIN_ERR_MALFORMED;

	if (policy && policy->spelled)
		said = policy->guarded ? FZN_AUTHZ_LINE_GUARDED : FZN_AUTHZ_LINE_UNGUARDED;

	measure.out = NULL;
	measure.used = 0;
	render(&measure, policy, said);

	if (measure.used + 1u > cap) {
		*len_out = measure.used + 1u;
		return FZN_CHAIN_ERR_MALFORMED;
	}

	write.out = out;
	write.used = 0;
	render(&write, policy, said);
	out[write.used] = '\0';
	*len_out = write.used;
	*state_out = said;

	return FZN_CHAIN_OK;
}
