/* See persist_print.h. */

#include "persist_print.h"

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

/* What this slot is, in a person's words rather than an enumerator's.
 *
 * NOT A PUBLIC RENDERER. `persist.h` has no `fzn_persist_slot_str` and this
 * does not add one: the strings here are written for a sentence a person
 * reads, and a consumer that wants the name alone wants a different string
 * from the one that fits "this host's ... could not be read". Adding a
 * public renderer is a decision about the module's surface rather than
 * something a printer should take on its way past.
 *
 * ALL FIVE NAMED, NO `default:`, so a slot added to persist.h fails to
 * compile here rather than being described as "state". */
static const char *slot_words(fzn_persist_slot_t slot, int *known)
{
	*known = 1;
	switch (slot) {
	case FZN_PERSIST_TRUST:
		return "this host's trust anchor";
	case FZN_PERSIST_OWN_PREKEY:
		return "this host's own prekey secret";
	case FZN_PERSIST_PEER:
		return "a pinned peer";
	case FZN_PERSIST_SEND_CHAIN:
		return "a ratchet chain for sending to a peer";
	case FZN_PERSIST_RECV_CHAIN:
		return "a ratchet chain for receiving from a peer";
	}
	*known = 0;
	return "an unknown slot";
}

static void render(struct sink *s, fzn_persist_line_t state, const char *what)
{
	/*
	 * THE VERDICT LEADS, sec 207, except that every line here has to name
	 * WHICH state was being read -- losing a trust anchor and losing one
	 * peer's chain are not the same event -- so the slot comes second and
	 * the verdict still comes first.
	 *
	 * ALL SEVEN NAMED, NO `default:`.
	 */
	switch (state) {
	case FZN_PERSIST_LINE_NONE:
		put_str(s, "cannot say -- there is no stored state to report on\n");
		return;
	case FZN_PERSIST_LINE_LOADED:
		put_str(s, "read back: ");
		put_str(s, what);
		put_str(s, "\n");
		return;
	case FZN_PERSIST_LINE_FRESH:
		/* THE ORDINARY FIRST RUN, and it must not read as a loss. */
		put_str(s, "nothing stored yet for ");
		put_str(s, what);
		put_str(s, ", which is the ordinary state on a first run\n");
		return;
	case FZN_PERSIST_LINE_LOST:
		/* THE SAME CODE, THE OPPOSITE EVENT. Nobody else reports this:
		 * the store answers the same way it does on a first run. */
		put_str(s, "ATTENTION -- ");
		put_str(s, what);
		put_str(s, " is gone, and this host has stored it before, so something "
		           "removed it rather than this being a first run\n");
		return;
	case FZN_PERSIST_LINE_CORRUPT:
		/* NOT AN ATTACK, in persist.h's own words, and refused rather
		 * than repaired -- so the file is still there. */
		put_str(s, "PROBLEM -- ");
		put_str(s, what);
		put_str(s, " is stored in a shape this version does not read: a corrupt or "
		           "foreign file rather than an attack, left alone rather than "
		           "repaired\n");
		return;
	case FZN_PERSIST_LINE_UNAVAILABLE:
		put_str(s, "PROBLEM -- ");
		put_str(s, what);
		put_str(s, " could not be read at all: the store refused or was absent, "
		           "which is this host's disk rather than its contents\n");
		return;
	case FZN_PERSIST_LINE_LOCAL:
		put_str(s, "PROBLEM -- this program asked for something impossible while "
		           "reading ");
		put_str(s, what);
		put_str(s, ", which is a bug in it rather than a condition of the host\n");
		return;
	}
}

fzn_persist_err_t fzn_persist_print(fzn_persist_slot_t slot, fzn_persist_err_t err,
                                    int had_stored, char *out, size_t cap, size_t *len_out,
                                    fzn_persist_line_t *state_out)
{
	struct sink measure;
	struct sink write;
	fzn_persist_line_t said = FZN_PERSIST_LINE_NONE;
	const char *what;
	int known = 0;

	if (len_out)
		*len_out = 0;
	if (state_out)
		*state_out = FZN_PERSIST_LINE_NONE;

	if (!out || !len_out || !state_out)
		return FZN_PERSIST_ERR_MALFORMED;

	what = slot_words(slot, &known);

	if (known) {
		switch (err) {
		case FZN_PERSIST_OK:
			said = FZN_PERSIST_LINE_LOADED;
			break;
		case FZN_PERSIST_ERR_ABSENT:
			/* THE ONE PLACE `had_stored` IS READ. */
			said = had_stored ? FZN_PERSIST_LINE_LOST : FZN_PERSIST_LINE_FRESH;
			break;
		case FZN_PERSIST_ERR_SHAPE:
			said = FZN_PERSIST_LINE_CORRUPT;
			break;
		case FZN_PERSIST_ERR_BACKEND:
			said = FZN_PERSIST_LINE_UNAVAILABLE;
			break;
		case FZN_PERSIST_ERR_MALFORMED:
			said = FZN_PERSIST_LINE_LOCAL;
			break;
		}
		/* NO `default:` ABOVE. */
	}

	measure.out = NULL;
	measure.used = 0;
	render(&measure, said, what);

	if (measure.used + 1u > cap) {
		*len_out = measure.used + 1u;
		return FZN_PERSIST_ERR_MALFORMED;
	}

	write.out = out;
	write.used = 0;
	render(&write, said, what);
	out[write.used] = '\0';
	*len_out = write.used;
	*state_out = said;

	return FZN_PERSIST_OK;
}
