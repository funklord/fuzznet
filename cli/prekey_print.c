/* See prekey_print.h. */

#include "prekey_print.h"

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

static void render(struct sink *s, fzn_prekey_line_t state)
{
	/*
	 * THE VERDICT LEADS, on sec 207's rule, and the three that need
	 * somebody open with a word that says so.
	 *
	 * ALL NINE NAMED, NO `default:`, so a code added to prekey.h fails to
	 * compile here rather than rendering as "cannot say".
	 */
	switch (state) {
	case FZN_PREKEY_LINE_NONE:
		put_str(s, "cannot say -- there is no offer to report on\n");
		return;
	case FZN_PREKEY_LINE_LEARNED:
		put_str(s, "this host now holds a prekey for a peer it had none for\n");
		return;
	case FZN_PREKEY_LINE_ROTATED:
		/* WORTH SHOWING AND NOT ALARMING. Rotation is what the design
		 * is for; a person seeing it often is seeing the protocol work,
		 * and a person seeing it constantly is seeing something else. */
		put_str(s, "this peer rotated its prekey and the newer one is now held\n");
		return;
	case FZN_PREKEY_LINE_UNCHANGED:
		/* NOT AN EVENT, in prekey.h's own words, so the line must not
		 * read as one. */
		put_str(s, "the same prekey arrived again and nothing moved, which is an "
		           "ordinary re-delivery rather than an event\n");
		return;
	case FZN_PREKEY_LINE_ROLLBACK:
		/* THE ONE AN OPERATOR HAS TO SEE. */
		put_str(s, "ATTENTION -- an older prekey for this peer was replayed and "
		           "refused: the record is real and correctly signed, so if that "
		           "key has since leaked this is an attempt to use it\n");
		return;
	case FZN_PREKEY_LINE_WRONG_HOST:
		put_str(s, "ATTENTION -- a record naming a different host arrived for this "
		           "peer and was refused, which is a different peer in this slot "
		           "rather than this one rotating a key\n");
		return;
	case FZN_PREKEY_LINE_UNVERIFIED:
		put_str(s, "refused -- this record does not verify under the host key it "
		           "names, so it was forged or damaged in transit\n");
		return;
	case FZN_PREKEY_LINE_FOREIGN:
		/* USUALLY SKEW. Saying so is the difference between somebody
		 * checking versions and somebody suspecting a peer. */
		put_str(s, "refused -- these bytes are not this protocol's prekey shape, "
		           "which is usually a version difference rather than an attack\n");
		return;
	case FZN_PREKEY_LINE_LOCAL:
		/* THIS SIDE'S FAULT, and the line has to say so or a peer gets
		 * blamed for a verifier this host never configured. */
		put_str(s, "PROBLEM -- this host could not check the record: its own "
		           "verifier was absent or refused, so nothing here is a statement "
		           "about the peer\n");
		return;
	}
}

/* Whether anything about the stored prekey moved. `fzn_prekey_pin` answers OK
 * for a first pin, a rotation and a re-delivery, and only the peer says which:
 * a re-delivery leaves the record byte-identical. */
static int prekey_moved(const fzn_prekey_peer_t *before, const fzn_prekey_peer_t *after)
{
	if (before->created_at != after->created_at)
		return 1;
	return memcmp(before->prekey, after->prekey, FZN_PREKEY_LEN) != 0;
}

fzn_prekey_err_t fzn_prekey_print(const fzn_prekey_peer_t *before,
                                  const fzn_prekey_peer_t *after, fzn_prekey_err_t err,
                                  char *out, size_t cap, size_t *len_out,
                                  fzn_prekey_line_t *state_out)
{
	struct sink measure;
	struct sink write;
	fzn_prekey_line_t said = FZN_PREKEY_LINE_NONE;

	if (len_out)
		*len_out = 0;
	if (state_out)
		*state_out = FZN_PREKEY_LINE_NONE;

	if (!out || !len_out || !state_out)
		return FZN_PREKEY_ERR_MALFORMED;

	if (before && after) {
		switch (err) {
		case FZN_PREKEY_OK:
			/* THREE EVENTS UNDER ONE CODE, told apart by what the
			 * peer held. A peer with no anchor before this call had
			 * nothing to rotate. */
			if (fzn_trust_source_of(&before->trust) == FZN_TRUST_NONE)
				said = FZN_PREKEY_LINE_LEARNED;
			else if (prekey_moved(before, after))
				said = FZN_PREKEY_LINE_ROTATED;
			else
				said = FZN_PREKEY_LINE_UNCHANGED;
			break;
		case FZN_PREKEY_ERR_ROLLBACK:
			said = FZN_PREKEY_LINE_ROLLBACK;
			break;
		case FZN_PREKEY_ERR_WRONG_HOST:
			said = FZN_PREKEY_LINE_WRONG_HOST;
			break;
		case FZN_PREKEY_ERR_SIGNATURE:
			said = FZN_PREKEY_LINE_UNVERIFIED;
			break;
		case FZN_PREKEY_ERR_SHAPE:
			said = FZN_PREKEY_LINE_FOREIGN;
			break;
		case FZN_PREKEY_ERR_SIGNER:
		case FZN_PREKEY_ERR_MALFORMED:
			said = FZN_PREKEY_LINE_LOCAL;
			break;
		}
		/* NO `default:` ABOVE. */
	}

	measure.out = NULL;
	measure.used = 0;
	render(&measure, said);

	if (measure.used + 1u > cap) {
		*len_out = measure.used + 1u;
		return FZN_PREKEY_ERR_MALFORMED;
	}

	write.out = out;
	write.used = 0;
	render(&write, said);
	out[write.used] = '\0';
	*len_out = write.used;
	*state_out = said;

	return FZN_PREKEY_OK;
}
