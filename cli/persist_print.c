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
 * ALL TEN NAMED, NO `default:`, so a slot added to persist.h is refused by
 * -Wswitch here rather than being described as "state". A warning and not a
 * failure, since the build has no -Werror: the sixth went unhandled for four
 * days, sec 373. */
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
	case FZN_PERSIST_NODE_PEER:
		return "a peer this node serves";
	case FZN_PERSIST_OWN_IDENTITY:
		return "this host's own identity";
	case FZN_PERSIST_PAIRED_NODE:
		return "a node this host is paired to";
	case FZN_PERSIST_ISSUED_REVOCATION:
		return "a revocation this host issued";
	case FZN_PERSIST_VOTE:
		return "a revocation vote this host learned from a peer";
	case FZN_PERSIST_ROOT_CHANGE:
		return "a change to the estate's roots";
	case FZN_PERSIST_OWN_ROOT:
		return "this host's own root key";
	case FZN_PERSIST_ADMIN_CONFIRM:
		return "a confirmation of an admin's grant";
	case FZN_PERSIST_OWN_ADMIN:
		return "this host's own admin chain";
	case FZN_PERSIST_NOTE:
		return "a writer's record of a note";
	case FZN_PERSIST_NOTE_PURGE:
		return "a note's purge awaiting its hosts' consent";
	case FZN_PERSIST_NOTE_PARTNER:
		return "a node that pulls notes from this one";
	case FZN_PERSIST_CONTACT:
		return "a contact this host knows by name";
	case FZN_PERSIST_NOTE_SHARE:
		return "a subtree of notes shared with a contact";
	case FZN_PERSIST_SHARED_NOTE:
		return "a note a contact shared with this host";
	case FZN_PERSIST_RECEIVED_SHARE:
		return "a share this host accepted, and where it is pulled from";
	case FZN_PERSIST_CONTACT_GROUP:
		return "a group of contacts a subtree can be shared with";
	case FZN_PERSIST_LOG_RULE:
		return "a retention rule for this host's logs";
	case FZN_PERSIST_ADMIN_RETENTION:
		return "an estate retention rule an admin set, with its chain";
	case FZN_PERSIST_ROSTER:
		return "a contact added or removed by a member, with its chain";
	case FZN_PERSIST_FILE_SHARE:
		return "a file shared with a contact, a group or every contact";
	case FZN_PERSIST_SUCCESSION:
		return "a key succeeded by another, with its issuer's chain";
	case FZN_PERSIST_NOTE_PURGED:
		return "a note purged, whose records are never filed again";
	case FZN_PERSIST_NOTE_WRAP:
		return "the key a note's content keys are wrapped under";
	case FZN_PERSIST_OP_BYTES:
		return "bytes an operation-journal entry saved";
	case FZN_PERSIST_CONVERSATION_KEY:
		return "the key a conversation's lines of one month are sealed under";
	case FZN_PERSIST_MESSAGE_STATE:
		return "a conversation line's latest mark";
	case FZN_PERSIST_MESSAGE_INDEX:
		return "a conversation's index, read position, or how far a stream was taken in";
	case FZN_PERSIST_MESSAGE_LINE:
		return "a conversation line as the store keeps it";
	case FZN_PERSIST_SETTING:
		return "a setting of the estate's configuration, at one rank";
	case FZN_PERSIST_GRANT:
		return "a grant the journal carried, kept so chains outlive it";
	case FZN_PERSIST_JOURNAL_SPINE:
		return "the ids of estate acts cut from the journal, so their standing is judged";
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
