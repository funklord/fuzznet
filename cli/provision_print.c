#include "provision_print.h"

#include "../trust/trust.h"

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

static void render(struct sink *s, fzn_provision_line_t state,
                   const fzn_provision_card_t *card, const char *code)
{
	char print[FZN_TRUST_FINGERPRINT_LEN];

	switch (state) {
	case FZN_PROVISION_LINE_NOTHING:
		put_str(s, "no card\n");
		return;
	case FZN_PROVISION_LINE_REFUSED:
		put_str(s, "REFUSED -- the signature does not verify");
		break;
	case FZN_PROVISION_LINE_UNCHECKED:
		put_str(s, "not checked -- no verifier was given");
		break;
	case FZN_PROVISION_LINE_EXPIRED:
		put_str(s, "expired");
		break;
	case FZN_PROVISION_LINE_UNDATED:
		put_str(s, "verified -- no clock, so the expiry was not looked at");
		break;
	default:
		put_str(s, "verified, and in date");
		break;
	}

	/* THE FINGERPRINT WAITS FOR A VERDICT, AND A LOGGED ONE WAITS HARDER.
	 * A root printed for a card that did not verify outlives the moment
	 * and is read later by somebody who was not there. */
	if (state >= FZN_PROVISION_LINE_UNDATED) {
		put_str(s, "; root ");
		if (fzn_trust_fingerprint(card->root, print, sizeof(print)) == FZN_TRUST_OK)
			put_str(s, print);
		else
			put_str(s, "this line could not format");
	} else {
		put_str(s, "; root not shown until the card verifies");
	}

	if (code) {
		/* A CARD IS PUBLIC BY CONSTRUCTION -- it exists to be
		 * photographed -- so the text is printed whatever the verdict.
		 * It is the fingerprint that waits, not the code. */
		put_str(s, "\ncode ");
		put_str(s, code);
	}

	put_str(s, "\n");
}

fzn_provision_err_t fzn_provision_print(const uint8_t *bytes, size_t len,
                                        const fzn_sign_ops_t *verifier, uint64_t now,
                                        char *out, size_t cap, size_t *len_out,
                                        fzn_provision_line_t *state_out)
{
	char text[FZN_PROVISION_TEXT_LEN];
	fzn_provision_card_t card;
	struct sink measure;
	struct sink write;
	fzn_provision_line_t said = FZN_PROVISION_LINE_NOTHING;
	const char *code = NULL;

	if (len_out)
		*len_out = 0;
	if (state_out)
		*state_out = FZN_PROVISION_LINE_NOTHING;

	if (!out || !len_out || !state_out)
		return FZN_PROVISION_ERR_MALFORMED;

	memset(&card, 0, sizeof(card));

	if (bytes && len > 0u) {
		/* SHAPE FIRST AND SEPARATELY, on provision.h's argument that a
		 * reader which cannot tell "these bytes are not a card" from
		 * "this card is not signed by who it says" can report neither
		 * usefully. */
		if (fzn_provision_open(bytes, len, &card) != FZN_PROVISION_OK) {
			said = FZN_PROVISION_LINE_REFUSED;
		} else {
			if (fzn_provision_text(bytes, len, text, sizeof(text)) ==
			    FZN_PROVISION_OK)
				code = text;

			if (!verifier) {
				said = FZN_PROVISION_LINE_UNCHECKED;
			} else {
				switch (fzn_provision_verify(card, verifier, now)) {
				case FZN_PROVISION_OK:
					said = now ? FZN_PROVISION_LINE_USABLE
					           : FZN_PROVISION_LINE_UNDATED;
					break;
				case FZN_PROVISION_ERR_EXPIRED:
					said = FZN_PROVISION_LINE_EXPIRED;
					break;
				default:
					said = FZN_PROVISION_LINE_REFUSED;
					break;
				}
			}
		}
	}

	measure.out = NULL;
	measure.used = 0;
	render(&measure, said, &card, code);

	if (measure.used + 1u > cap) {
		*len_out = measure.used + 1u;
		return FZN_PROVISION_ERR_MALFORMED;
	}

	write.out = out;
	write.used = 0;
	render(&write, said, &card, code);
	out[write.used] = '\0';
	*len_out = write.used;
	*state_out = said;

	return FZN_PROVISION_OK;
}
