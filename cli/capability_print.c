#include "capability_print.h"

#include "../trust/trust.h"

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

static void render(struct sink *s, const fzn_chain_t *chain, fzn_capability_state_t state)
{
	char print[FZN_TRUST_FINGERPRINT_LEN];

	if (state == FZN_CAPABILITY_NONE) {
		put_str(s, "no capability held\n");
		return;
	}

	/*
	 * THE VERDICT COMES BEFORE THE BYTES, and it did not until 2026-09-08.
	 *
	 * A capability spells to 64 hex characters and a terminal clips a line
	 * from the RIGHT, so with the bytes first the widget showing this line
	 * needed more than 80 columns and the word `expired` was the part that
	 * fell off. Measured through qtty at 80x24: the screen showed the
	 * capability and `expires at 1000`, and nowhere on it did it say the
	 * capability had expired. A person reading that sees an identifier and
	 * a date and no answer.
	 *
	 * So the answer goes left of the evidence. What is lost to a narrow
	 * terminal is then 32 opaque bytes nobody compares by eye anyway, and
	 * losing those is visibly a truncation rather than silently a
	 * different meaning.
	 */
	switch (state) {
	case FZN_CAPABILITY_REVOKED:
		/* ITS OWN WORDS. Renewing this would be exactly wrong. */
		put_str(s, "REVOKED by the issuer");
		break;
	case FZN_CAPABILITY_EXPIRED:
		put_str(s, "expired");
		break;
	default:
		/* "usable", not "allowed" -- finding a chain is not
		 * authorisation. */
		put_str(s, "usable");
		break;
	}

	put_str(s, ": ");

	/* THE SAME SPELLING OF THIRTY-TWO BYTES THE ANCHOR USES. A fingerprint
	 * compared against a differently formatted copy of itself cannot be
	 * compared at all. */
	if (fzn_trust_fingerprint(chain->capability.b, print, sizeof(print)) == FZN_TRUST_OK)
		put_str(s, print);
	else
		put_str(s, "a capability this line could not format");

	if (chain->expires_at == FZN_NO_EXPIRY) {
		/* THE SENTINEL IS NOT AN INSTANT. It is 0, so printing it as a
		 * number would put the oldest possible date beside the chain
		 * that outlives every other. */
		put_str(s, "; does not expire");
	} else {
		put_str(s, "; expires at ");
		put_u64(s, chain->expires_at);
	}

	put_str(s, "\n");
}

fzn_chain_err_t fzn_capability_print(const fzn_chain_t *chain,
                                     const fzn_revocation_store_t *revocations, uint64_t now,
                                     char *out, size_t cap, size_t *len_out,
                                     fzn_capability_state_t *state_out)
{
	struct sink measure;
	struct sink write;
	fzn_capability_state_t said = FZN_CAPABILITY_NONE;

	if (len_out)
		*len_out = 0;
	if (state_out)
		*state_out = FZN_CAPABILITY_NONE;

	if (!out || !len_out || !state_out)
		return FZN_CHAIN_ERR_MALFORMED;

	if (chain) {
		/* REVOCATION FIRST, BECAUSE IT WINS. `covers` and not `known`:
		 * the authorization question, not the replication one. */
		if (fzn_revocation_covers(revocations, chain->root, &chain->capability,
		                          chain->grantee))
			said = FZN_CAPABILITY_REVOKED;
		else if (fzn_chain_expired_at(chain, now))
			said = FZN_CAPABILITY_EXPIRED;
		else
			said = FZN_CAPABILITY_USABLE;
	}

	measure.out = NULL;
	measure.used = 0;
	render(&measure, chain, said);

	if (measure.used + 1u > cap) {
		*len_out = measure.used + 1u;
		return FZN_CHAIN_ERR_MALFORMED;
	}

	write.out = out;
	write.used = 0;
	render(&write, chain, said);
	out[write.used] = '\0';
	*len_out = write.used;
	*state_out = said;

	return FZN_CHAIN_OK;
}
