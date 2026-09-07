#include "log_print.h"

#include <string.h>

/* Enough for any uint64 in decimal, and a NUL. */
#define DIGITS_MAX 21u

/*
 * A destination that can also be no destination.
 *
 * THE RENDERING RUNS TWICE, once to measure and once to write, and that is
 * what buys the header's promise that nothing is written unless the whole
 * thing fits. The alternative -- writing while it fits and giving up
 * part-way -- leaves a caller holding half a loss report, which is the one
 * thing this file exists to prevent. A body's length is not knowable without
 * rendering it, so measuring means rendering; a viewer is not a hot path and
 * this is the cheap side of the trade.
 *
 * `out` is NULL on the measuring pass. `used` counts what the result needs
 * either way, so the two passes agree by construction rather than by two
 * pieces of arithmetic being kept in step.
 */
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

	/* Written backwards from the end, so zero still produces one digit. */
	do {
		digits[--at] = (char)('0' + (value % 10u));
		value /= 10u;
	} while (value);

	put(s, digits + at, sizeof(digits) - at);
}

/*
 * THE SUMMARY, AND IT GOES FIRST.
 *
 * `next` is the sequence this host wants, so everything below it was
 * received. Anything received and not held has been evicted -- GONE in
 * `fzn_log_get`'s vocabulary -- and a viewer showing only what it holds would
 * present a shorter history as a complete one. That is the whole reason this
 * function is handed a journal.
 *
 * The words match `gui/log_view.cpp` deliberately, so a consumer offering
 * both does not appear to disagree with itself. Nothing checks that they
 * still match; project.md sec 167 records it as a gap rather than a promise.
 */
static void summary(struct sink *s, uint64_t first, uint64_t last, uint64_t next,
                    size_t got, int more_held)
{
	/* EMPTINESS IS THE LOG'S RANGE, NOT WHAT WAS ASKED FOR. Deciding it
	 * from `got` would make `rows = 0` -- the summary-only call this
	 * header offers a health check -- report "nothing held" about a log
	 * that is full. The two questions have separate answers and only one
	 * of them is about the log. */
	if (last == 0u) {
		put_str(s, "nothing held");
		if (next > 1u) {
			put_str(s, "; ");
			put_u64(s, next - 1u);
			put_str(s, " received and evicted");
		}
		put_str(s, "\n");
		return;
	}

	put_u64(s, first);
	put_str(s, " to ");
	put_u64(s, last);

	if (first > 1u) {
		put_str(s, "; ");
		put_u64(s, first - 1u);
		put_str(s, " earlier evicted");
	} else {
		/* "complete" rather than "none evicted", so the word EVICTED
		 * appears only when something was. A reader scanning for loss
		 * should not have to read a negation. */
		put_str(s, "; complete");
	}

	/* A WINDOW IS SAID, NOT TAKEN SILENTLY. `rows` is the caller's screen,
	 * not the log's contents, and a tail presented without saying it is a
	 * tail is the same fault as an unmarked eviction one layer up. */
	if (more_held && got > 0) {
		put_str(s, "; showing ");
		put_u64(s, (uint64_t)got);
		put_str(s, " newest");
	} else if (more_held) {
		put_str(s, "; showing none");
	}

	put_str(s, "\n");
}

/* Which halves a render is producing. `fzn_log_print` asks for both, and asks
 * for them in one pass, so the composed form IS the two halves rather than a
 * third rendering that has to agree with them. */
#define PART_SUMMARY 1u
#define PART_ENTRIES 2u

static void render(struct sink *s, unsigned parts, uint64_t first, uint64_t last,
                   uint64_t next, const fzn_log_entry_t **window, size_t got,
                   int more_held)
{
	size_t i;

	if (parts & PART_SUMMARY)
		summary(s, first, last, next, got, more_held);

	if (!(parts & PART_ENTRIES))
		return;

	for (i = 0; i < got; i++) {
		char text[FZN_LOG_TEXT_MAX];

		put_u64(s, window[i]->seq);
		put_str(s, "  ");

		/* THE ONLY PATH BODY BYTES TAKE. `fzn_log_body_text` escapes
		 * everything outside printable ASCII, which is what stops a
		 * body drawing a second entry with a newline and what stops one
		 * driving the terminal with an escape byte. There is
		 * deliberately no branch here that writes `window[i]->body`. */
		if (fzn_log_body_text(window[i]->body, window[i]->body_len, text,
		                      sizeof(text)) != FZN_LOG_OK) {
			/* SAID, NOT SKIPPED. A row missing from a list is
			 * indistinguishable from a record never appended. */
			put_str(s, "(unrenderable body)");
		} else {
			put_str(s, text);
		}
		put_str(s, "\n");
	}
}

static fzn_log_err_t emit(unsigned parts, const fzn_log_t *log, const fzn_journal_t *journal,
                          const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream,
                          size_t rows, char *out, size_t cap, size_t *len_out)
{
	/* The caller's window, bounded by what it asked for. FZN_LOG_PRINT_MAX
	 * is sized from the same number, so a caller that used it fits. */
	const fzn_log_entry_t *window[FZN_LOG_PRINT_WINDOW_MAX];
	struct sink measure;
	struct sink write;
	uint64_t first = 0;
	uint64_t last = 0;
	uint64_t next;
	size_t got = 0;
	int more_held = 0;

	if (len_out)
		*len_out = 0;
	if (!log || !journal || !issuer || !out || !len_out)
		return FZN_LOG_ERR_MALFORMED;
	if (rows > FZN_LOG_PRINT_WINDOW_MAX)
		return FZN_LOG_ERR_MALFORMED;

	fzn_log_range(log, issuer, stream, &first, &last);

	/* THE TAIL, NOT THE HEAD. `fzn_log_read_since` fills from the oldest
	 * entry after `since`, so asking it for `rows` entries from zero
	 * returns the OLDEST rows -- the opposite of what a viewer wants and,
	 * worse, of what the summary would then call them. Start `since` a
	 * window back from the newest sequence the log holds. */
	if (rows > 0u) {
		uint64_t since = last > (uint64_t)rows ? last - (uint64_t)rows : 0u;

		got = fzn_log_read_since(log, issuer, stream, since, window, rows);
	}

	/* WHETHER THE WINDOW HID ANYTHING, asked of the log's own range rather
	 * than inferred from `got == rows`. A window exactly the size of the
	 * stream fills completely and hides nothing, and guessing from the
	 * count alone would report that as a tail. */
	if (got > 0u && window[0]->seq > first)
		more_held = 1;
	if (rows == 0u && last > 0u)
		more_held = 1;

	next = fzn_journal_next(journal, issuer, stream);

	measure.out = NULL;
	measure.used = 0;
	render(&measure, parts, first, last, next, window, got, more_held);

	if (measure.used + 1u > cap) {
		*len_out = measure.used + 1u;
		return FZN_LOG_ERR_MALFORMED;
	}

	write.out = out;
	write.used = 0;
	render(&write, parts, first, last, next, window, got, more_held);
	out[write.used] = '\0';
	*len_out = write.used;

	return FZN_LOG_OK;
}

fzn_log_err_t fzn_log_print(const fzn_log_t *log, const fzn_journal_t *journal,
                            const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream,
                            size_t rows, char *out, size_t cap, size_t *len_out)
{
	return emit(PART_SUMMARY | PART_ENTRIES, log, journal, issuer, stream, rows, out, cap,
	            len_out);
}

fzn_log_err_t fzn_log_summary(const fzn_log_t *log, const fzn_journal_t *journal,
                              const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream,
                              size_t rows, char *out, size_t cap, size_t *len_out)
{
	return emit(PART_SUMMARY, log, journal, issuer, stream, rows, out, cap, len_out);
}

fzn_log_err_t fzn_log_entries(const fzn_log_t *log, const fzn_journal_t *journal,
                              const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream,
                              size_t rows, char *out, size_t cap, size_t *len_out)
{
	return emit(PART_ENTRIES, log, journal, issuer, stream, rows, out, cap, len_out);
}
