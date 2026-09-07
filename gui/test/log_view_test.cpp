/* Tests for gui/log_view.cpp, headless.
 *
 * THE CASE THIS FILE EXISTS FOR is the one a log viewer gets wrong by
 * omission: a log that has evicted must SAY so, because a reader given a
 * shorter history presented as a complete one draws conclusions from records
 * that are not there. project.md sec 141.
 *
 * The other is the injection case. A body is opaque bytes, so one carrying a
 * newline and a plausible sequence number must not draw a second entry that
 * no issuer ever signed -- and a suite that only fed it printable text would
 * pass whatever the renderer did.
 *
 * Headless under an offscreen platform, for the reason gui/test/
 * trust_view_test.cpp gives: that is also the arrangement qtty relies on.
 */

extern "C" {
#include "../../log/log.h"
#include "../../record/journal.h"
#include "../../record/record.h"
}

#include "../log_view.h"

extern "C" {
#include "../../cli/log_print.h"
}

#include <QApplication>
#include <QString>

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (ok)
		return;

	failures++;
	fprintf(stderr, "  FAIL log_view_test.cpp:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

/* LINES, NOT NEWLINES. The two differ by whether the last line is
 * terminated, and since sec 168 this widget's text is not -- a trailing
 * newline in a QPlainTextEdit is a blank row of the reader's screen. Counting
 * newlines made the assertion depend on that, which is a property of the
 * text area rather than of what was rendered. */
static int lines_of(const QString &text)
{
	return text.isEmpty() ? 0 : (int)text.split(QLatin1Char('\n')).size();
}

/* ---- a signer, so the fixtures are real records ------------------------ */

static void tag(uint8_t out[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	uint64_t h = 1469598103934665603u;
	size_t i;

	for (i = 0; i < msg_len; i++) {
		h ^= msg[i];
		h *= 1099511628211u;
	}
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h ^= (uint64_t)i;
		h *= 1099511628211u;
		out[i] = (uint8_t)(h >> 32);
	}
}

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	(void)ctx;
	tag(sig, msg, msg_len);
	return 1;
}

static uint8_t ISSUER[FZN_PUBKEY_LEN];
static uint8_t SUBJECT[FZN_SUBJECT_LEN];
static uint8_t SLOTS[8][FZN_RECORD_MAX_LEN];

/* Build a record with the body given, into slot `which`. */
static int make(fzn_record_t *r, size_t which, uint64_t seq, const uint8_t *body,
                size_t body_len)
{
	fzn_sign_ops_t ops;
	size_t wrote = 0;

	memset(&ops, 0, sizeof(ops));
	ops.sign = stub_sign;
	if (fzn_record_sign(ISSUER, SUBJECT, 5u, 3u, seq, 1u, body, body_len, &ops,
	                    SLOTS[which], FZN_RECORD_MAX_LEN, &wrote) != FZN_RECORD_OK)
		return 0;
	return fzn_record_open(SLOTS[which], wrote, r) == FZN_RECORD_OK;
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");

	QApplication app(argc, argv);
	fzn_log_view view;
	fzn_log_entry_t rows[4];
	fzn_journal_entry_t positions[2];
	fzn_log_t log;
	fzn_journal_t journal;
	fzn_record_t rec;
	QString empty_summary, full_summary, evicted_summary;
	uint64_t seq;

	memset(ISSUER, 0xa1, sizeof(ISSUER));
	memset(SUBJECT, 0x51, sizeof(SUBJECT));

	/* A VIEW WITH NO LOG SAYS SO, rather than showing an empty list that
	 * looks like a stream with nothing in it. Those are different facts. */
	CHECK(!view.summary_text().isEmpty(), "a view with no log says nothing at all");
	CHECK(view.entries_text().isEmpty(), "a view with no log listed entries");
	empty_summary = view.summary_text();

	CHECK(fzn_log_init(&log, rows, 4) == FZN_LOG_OK, "the log would not init");
	CHECK(fzn_journal_init(&journal, positions, 2) == FZN_JOURNAL_OK,
	      "the journal would not init");
	CHECK(fzn_journal_anchor(&journal, ISSUER, 5u, 0u) == FZN_JOURNAL_OK,
	      "the stream could not be followed");

	/* An empty log is NOT the same as no log. */
	view.show_stream(&log, &journal, ISSUER, 5u);
	CHECK(view.summary_text() != empty_summary,
	      "an empty log and an absent one read the same");
	CHECK(view.entries_text().isEmpty(), "an empty log listed entries");

	/* Three entries, printable, held in full. */
	for (seq = 1u; seq <= 3u; seq++) {
		const uint8_t body[3] = { 'a', (uint8_t)('0' + seq), 'z' };

		CHECK(make(&rec, (size_t)seq, seq, body, sizeof(body)),
		      "the fixture could not build a record");
		CHECK(fzn_log_append(&log, &rec) == FZN_LOG_OK, "append refused");
		CHECK(fzn_journal_admit(&journal, ISSUER, 5u, seq) == FZN_JOURNAL_OK,
		      "the journal refused the record");
	}
	view.show_stream(&log, &journal, ISSUER, 5u);
	full_summary = view.summary_text();
	CHECK(lines_of(view.entries_text()) == 3,
	      "three entries did not produce three lines");
	CHECK(view.entries_text().contains(QStringLiteral("a1z")), "the first entry is missing");
	CHECK(view.entries_text().contains(QStringLiteral("a3z")), "the last entry is missing");
	/* Oldest first, as fzn_log_read_since returns them. */
	CHECK(view.entries_text().indexOf(QStringLiteral("a1z"))
	              < view.entries_text().indexOf(QStringLiteral("a3z")),
	      "the entries are not oldest first");
	CHECK(!full_summary.isEmpty(), "a full log says nothing");

	/*
	 * THE CASE THIS FILE EXISTS FOR. The log holds four; appending a fifth
	 * evicts the first. The view must say that something is gone rather
	 * than showing three entries as though they were the whole history.
	 */
	for (seq = 4u; seq <= 6u; seq++) {
		const uint8_t body[3] = { 'b', (uint8_t)('0' + seq), 'z' };

		CHECK(make(&rec, (size_t)seq, seq, body, sizeof(body)),
		      "the fixture could not build a later record");
		CHECK(fzn_log_append(&log, &rec) == FZN_LOG_OK, "a later append refused");
		CHECK(fzn_journal_admit(&journal, ISSUER, 5u, seq) == FZN_JOURNAL_OK,
		      "the journal refused a later record");
	}
	view.show_stream(&log, &journal, ISSUER, 5u);
	evicted_summary = view.summary_text();
	CHECK(fzn_log_dropped(&log) > 0, "the fixture evicted nothing, so the case is empty");
	CHECK(!view.entries_text().contains(QStringLiteral("a1z")),
	      "the evicted entry is still listed, so the fixture proves nothing");
	/* THE SUMMARY MUST SAY LOSS HAPPENED, not merely read differently. The
	 * first version of this asserted only that the two summaries differ --
	 * which they do because the range moved, so deleting the branch that
	 * names the eviction left it passing. The sabotage harness reported it
	 * SURVIVED, which is how the weak assertion was found. */
	CHECK(evicted_summary.contains(QStringLiteral("evicted")),
	      "a log that has evicted does not say so");
	CHECK(!full_summary.contains(QStringLiteral("evicted")),
	      "a complete log claims something was evicted, so the word proves nothing");
	CHECK(evicted_summary != full_summary,
	      "a log that has evicted reads exactly like one that has not");

	/*
	 * THE INJECTION CASE. A body carrying a newline and a plausible
	 * sequence must not draw a second entry nobody signed.
	 */
	{
		fzn_log_entry_t solo_rows[2];
		fzn_journal_entry_t solo_positions[1];
		fzn_log_t solo;
		fzn_journal_t solo_journal;
		const uint8_t nasty[] = { 'x', '\n', '9', '9', ' ', 'f', 'a', 'k', 'e' };

		CHECK(fzn_log_init(&solo, solo_rows, 2) == FZN_LOG_OK, "the solo log failed");
		CHECK(fzn_journal_init(&solo_journal, solo_positions, 1) == FZN_JOURNAL_OK,
		      "the solo journal failed");
		CHECK(fzn_journal_anchor(&solo_journal, ISSUER, 5u, 0u) == FZN_JOURNAL_OK,
		      "the solo stream could not be followed");
		CHECK(make(&rec, 0u, 1u, nasty, sizeof(nasty)),
		      "the fixture could not build the nasty record");
		CHECK(fzn_log_append(&solo, &rec) == FZN_LOG_OK, "the nasty append refused");
		CHECK(fzn_journal_admit(&solo_journal, ISSUER, 5u, 1u) == FZN_JOURNAL_OK,
		      "the journal refused the nasty record");

		view.show_stream(&solo, &solo_journal, ISSUER, 5u);
		CHECK(lines_of(view.entries_text()) == 1,
		      "a body with a newline drew a second entry that nobody signed");
		CHECK(view.entries_text().contains(QStringLiteral("\\x0a")),
		      "the newline was not escaped");
		/* THE PROPERTY IS THAT NO LINE BEGINS WITH THE FORGED SEQUENCE,
		 * not that the text vanished. Escaping neutralises the break;
		 * it does not delete content, and it must not -- a viewer that
		 * dropped bytes it distrusted would show something other than
		 * what was signed. The first assertion of this pair was written
		 * as "the text survived intact" and was wrong about which
		 * property matters. */
		CHECK(!view.entries_text().contains(QStringLiteral("\n99 ")),
		      "a line begins with the forged sequence, so the body drew an entry");
		CHECK(view.entries_text().contains(QStringLiteral("99 fake")),
		      "the body's own bytes were dropped rather than escaped");
	}

	/* THE CASE sec 168 EXISTS FOR. The widget must not have its own
	 * wording -- it must be showing `cli/log_print`'s. Asserting the
	 * strings it displays EQUAL what the library renders is a
	 * relationship rather than a table: it stays true when the wording
	 * changes, and it goes red the moment somebody composes a summary
	 * here again. Asserting the words themselves would be a second copy
	 * of them, which is the thing being removed. */
	{
		static char want[FZN_LOG_PRINT_MAX(8)];
		size_t len = 0;
		QString rendered;

		view.show_stream(&log, &journal, ISSUER, 5u);

		CHECK(fzn_log_summary(&log, &journal, ISSUER, 5u, 256u, want, sizeof(want),
		                      &len) == FZN_LOG_OK,
		      "the library would not render the summary");
		rendered = QString::fromLatin1(want);
		while (rendered.endsWith(QLatin1Char('\n')))
			rendered.chop(1);
		CHECK(view.summary_text() == rendered,
		      "the widget's summary is not the library's, so there are two "
		      "wordings for one screen again");

		CHECK(fzn_log_entries(&log, &journal, ISSUER, 5u, 256u, want, sizeof(want),
		                      &len) == FZN_LOG_OK,
		      "the library would not render the entries");
		rendered = QString::fromLatin1(want);
		while (rendered.endsWith(QLatin1Char('\n')))
			rendered.chop(1);
		CHECK(view.entries_text() == rendered,
		      "the widget's entries are not the library's");
	}

	/* THE WINDOW ADAPTS TO THE BUFFER, and says the number it settled on.
	 * A widget budget of 64 KiB cannot hold 40 entries whose bodies escape
	 * to four characters a byte, so the render halves its window until it
	 * fits -- and the whole safety of doing that rests on the summary
	 * declaring what is on the screen. Without this case the halving loop
	 * never runs: every other log here holds four entries. */
	{
		static uint8_t big_slots[40][FZN_RECORD_MAX_LEN];
		static fzn_log_entry_t big_rows[40];
		static fzn_journal_entry_t big_positions[2];
		static uint8_t body[FZN_RECORD_BODY_MAX];
		fzn_log_t big;
		fzn_journal_t big_journal;
		size_t i;
		int built = 1;

		/* High bytes, so every one escapes to four characters and the
		 * worst case is the real case. */
		memset(body, 0xfe, sizeof(body));

		CHECK(fzn_log_init(&big, big_rows, 40) == FZN_LOG_OK, "the big log would not init");
		CHECK(fzn_journal_init(&big_journal, big_positions, 2) == FZN_JOURNAL_OK,
		      "the big journal would not init");
		CHECK(fzn_journal_anchor(&big_journal, ISSUER, 5u, 0u) == FZN_JOURNAL_OK,
		      "the big stream could not be followed");

		for (i = 1u; i <= 40u; i++) {
			fzn_sign_ops_t ops;
			fzn_record_t r;
			size_t wrote = 0;

			memset(&ops, 0, sizeof(ops));
			ops.sign = stub_sign;
			if (fzn_record_sign(ISSUER, SUBJECT, 5u, 3u, (uint64_t)i, 1u, body,
			                    sizeof(body), &ops, big_slots[i - 1u],
			                    FZN_RECORD_MAX_LEN, &wrote) != FZN_RECORD_OK ||
			    fzn_record_open(big_slots[i - 1u], wrote, &r) != FZN_RECORD_OK ||
			    fzn_log_append(&big, &r) != FZN_LOG_OK ||
			    fzn_journal_admit(&big_journal, ISSUER, 5u, (uint64_t)i) !=
			            FZN_JOURNAL_OK)
				built = 0;
		}
		CHECK(built, "the fixture could not fill a log past the widget's budget");

		view.show_stream(&big, &big_journal, ISSUER, 5u);
		CHECK(view.summary_text().contains(QStringLiteral("showing")),
		      "a window the budget shortened was not declared, so a reader is "
		      "shown a tail presented as the whole log");
		CHECK(lines_of(view.entries_text()) > 0,
		      "the shortened window showed nothing at all");
		CHECK(lines_of(view.entries_text()) < 40,
		      "the budget did not shorten the window, so this case proves nothing");
		CHECK(view.entries_text().contains(QStringLiteral("40  ")),
		      "the shortened window is not the newest entries");
	}

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	printf("log_view_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
