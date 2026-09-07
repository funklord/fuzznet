#include "journal_print.h"

#include "../constant_time/constant_time.h"

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

static void render(struct sink *s, fzn_journal_stream_state_t stream_state,
                   fzn_journal_table_state_t table_state, uint64_t received, uint64_t pending,
                   size_t used, size_t capacity)
{
	switch (stream_state) {
	case FZN_JOURNAL_STREAM_UNREADABLE:
		put_str(s, "the journal cannot be read");
		break;
	case FZN_JOURNAL_STREAM_UNTRACKED:
		/* NOT "wants 1". `fzn_journal_next` would say that, and it says
		 * the same for a stream this host follows and has heard nothing
		 * from. sec 186. */
		put_str(s, "not followed");
		break;
	case FZN_JOURNAL_STREAM_FRESH:
		put_str(s, "followed, nothing received");
		break;
	case FZN_JOURNAL_STREAM_EXHAUSTED:
		put_str(s, "exhausted, no next sequence");
		break;
	default:
		put_str(s, "received to ");
		put_u64(s, received);
		if (pending > 0u) {
			put_str(s, ", ");
			put_u64(s, pending);
			put_str(s, " not yet applied");
		}
		break;
	}

	if (stream_state != FZN_JOURNAL_STREAM_UNREADABLE) {
		put_str(s, "; table ");
		put_u64(s, (uint64_t)used);
		put_str(s, "/");
		put_u64(s, (uint64_t)capacity);
		if (table_state == FZN_JOURNAL_TABLE_FULL)
			/* THE LINE A PERSON NEEDS EVEN THOUGH THEY ASKED ABOUT
			 * ONE STREAM. Every row still looks healthy. */
			put_str(s, " FULL, refusing peers it has not met");
	}

	put_str(s, "\n");
}

fzn_journal_err_t fzn_journal_print(const fzn_journal_t *journal,
                                    const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream,
                                    char *out, size_t cap, size_t *len_out,
                                    fzn_journal_stream_state_t *stream_out,
                                    fzn_journal_table_state_t *table_out)
{
	struct sink measure;
	struct sink write;
	fzn_journal_stream_state_t said = FZN_JOURNAL_STREAM_UNTRACKED;
	fzn_journal_table_state_t table = FZN_JOURNAL_TABLE_FULL;
	const fzn_journal_entry_t *row = NULL;
	uint64_t received = 0;
	uint64_t pending = 0;
	size_t used = 0;
	size_t capacity = 0;
	size_t i;

	if (len_out)
		*len_out = 0;
	/* CONSERVATIVE BEFORE ANY REFUSAL. Both zero values ask for
	 * attention. sec 191. */
	if (stream_out)
		*stream_out = FZN_JOURNAL_STREAM_UNTRACKED;
	if (table_out)
		*table_out = FZN_JOURNAL_TABLE_FULL;

	if (!journal || !issuer || !out || !len_out || !stream_out || !table_out)
		return FZN_JOURNAL_ERR_MALFORMED;

	if (journal->used > journal->capacity ||
	    (journal->used > 0u && !journal->entries)) {
		said = FZN_JOURNAL_STREAM_UNREADABLE;
		table = FZN_JOURNAL_TABLE_UNREADABLE;
	} else {
		used = journal->used;
		capacity = journal->capacity;
		table = used >= capacity ? FZN_JOURNAL_TABLE_FULL : FZN_JOURNAL_TABLE_ROOM;

		for (i = 0; i < journal->used; i++) {
			if (journal->entries[i].stream != stream)
				continue;
			if (!fzn_ct_memeq(journal->entries[i].issuer, issuer, FZN_PUBKEY_LEN))
				continue;
			row = &journal->entries[i];
			break;
		}

		if (!row) {
			said = FZN_JOURNAL_STREAM_UNTRACKED;
		} else {
			uint64_t next = fzn_journal_next(journal, issuer, stream);

			pending = fzn_journal_pending(journal, issuer, stream);
			if (next == UINT64_MAX)
				said = FZN_JOURNAL_STREAM_EXHAUSTED;
			else if (next <= 1u)
				said = FZN_JOURNAL_STREAM_FRESH;
			else {
				said = FZN_JOURNAL_STREAM_TRACKING;
				received = next - 1u;
			}
		}
	}

	measure.out = NULL;
	measure.used = 0;
	render(&measure, said, table, received, pending, used, capacity);

	if (measure.used + 1u > cap) {
		*len_out = measure.used + 1u;
		return FZN_JOURNAL_ERR_MALFORMED;
	}

	write.out = out;
	write.used = 0;
	render(&write, said, table, received, pending, used, capacity);
	out[write.used] = '\0';
	*len_out = write.used;
	*stream_out = said;
	*table_out = table;

	return FZN_JOURNAL_OK;
}
