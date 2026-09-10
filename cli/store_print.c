/* See store_print.h. */

#include "store_print.h"

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

static void render(struct sink *s, fzn_record_store_line_t state)
{
	/*
	 * THE VERDICT LEADS, sec 207. There is nothing else here: a store
	 * answer is one fact, and which of the five it is carries all of it.
	 *
	 * ALL SEVEN NAMED, NO `default:`.
	 */
	switch (state) {
	case FZN_RECORD_STORE_LINE_NONE:
		put_str(s, "cannot say -- that is not an answer this knows\n");
		return;
	case FZN_RECORD_STORE_LINE_HELD:
		put_str(s, "held: the record came back\n");
		return;
	case FZN_RECORD_STORE_LINE_NOT_HELD:
		/* MOST OF WHAT A BUSY READER ASKS. A line that alarmed here
		 * would alarm continuously on a working host. */
		put_str(s, "not held: this store does not have that record, which is the "
		           "ordinary answer for anything the owner has not fetched yet\n");
		return;
	case FZN_RECORD_STORE_LINE_UNREADABLE:
		/* THE ONE WITH A CONCRETE HARM BEHIND IT. */
		put_str(s, "PROBLEM -- this store could not answer at all, which is not an "
		           "empty store: a reader that treats it as one will ask the "
		           "network for everything it already has\n");
		return;
	case FZN_RECORD_STORE_LINE_DAMAGED:
		put_str(s, "PROBLEM -- what came back is not a record: a truncated write or "
		           "a file somebody edited, which is this record rather than the "
		           "store\n");
		return;
	case FZN_RECORD_STORE_LINE_MISPLACED:
		/* THE ONE NOBODY EXPECTS. Not a failure to find: a wrong find. */
		put_str(s, "ATTENTION -- what came back IS a record and is not the one that "
		           "was asked for, so this store's index disagrees with its "
		           "contents\n");
		return;
	case FZN_RECORD_STORE_LINE_LOCAL:
		put_str(s, "PROBLEM -- this program asked for something impossible, which "
		           "is a bug in it rather than a condition of the store\n");
		return;
	}
}

int fzn_record_store_print(fzn_record_store_err_t err, char *out, size_t cap,
                           size_t *len_out, fzn_record_store_line_t *state_out)
{
	struct sink measure;
	struct sink write;
	fzn_record_store_line_t said = FZN_RECORD_STORE_LINE_NONE;

	if (len_out)
		*len_out = 0;
	if (state_out)
		*state_out = FZN_RECORD_STORE_LINE_NONE;

	if (!out || !len_out || !state_out)
		return 0;

	switch (err) {
	case FZN_RECORD_STORE_OK:
		said = FZN_RECORD_STORE_LINE_HELD;
		break;
	case FZN_RECORD_STORE_ERR_ABSENT:
		said = FZN_RECORD_STORE_LINE_NOT_HELD;
		break;
	case FZN_RECORD_STORE_ERR_BACKEND:
		said = FZN_RECORD_STORE_LINE_UNREADABLE;
		break;
	case FZN_RECORD_STORE_ERR_SHAPE:
		said = FZN_RECORD_STORE_LINE_DAMAGED;
		break;
	case FZN_RECORD_STORE_ERR_MISPLACED:
		said = FZN_RECORD_STORE_LINE_MISPLACED;
		break;
	case FZN_RECORD_STORE_ERR_MALFORMED:
		said = FZN_RECORD_STORE_LINE_LOCAL;
		break;
	}
	/* NO `default:` ABOVE, so a code added to store.h fails to compile
	 * here rather than rendering as "cannot say". */

	measure.out = NULL;
	measure.used = 0;
	render(&measure, said);

	if (measure.used + 1u > cap) {
		*len_out = measure.used + 1u;
		return 0;
	}

	write.out = out;
	write.used = 0;
	render(&write, said);
	out[write.used] = '\0';
	*len_out = write.used;
	*state_out = said;

	return 1;
}
