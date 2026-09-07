#include "log_view.h"

extern "C" {
#include "../cli/log_print.h"
}

#include <QFont>
#include <QLabel>
#include <QPlainTextEdit>
#include <QVBoxLayout>

/* Enough to ask for a screenful and know whether more was held. A viewer is
 * not a synchroniser: it shows the tail and says so, rather than pulling a
 * whole log into a widget because it could. */
#define FZN_LOG_VIEW_ROWS 256u

/*
 * WHAT THIS WIDGET WILL SPEND ON ONE RENDER, and why it is a budget rather
 * than a worst case.
 *
 * FZN_LOG_PRINT_MAX(256) is 530561 bytes, because every one of 512 body bytes
 * can escape to four characters. That is the honest bound and it is nothing
 * like the real one; sizing a widget's buffer to it would spend half a
 * megabyte to display a screenful of short lines.
 *
 * So the window ADAPTS instead. `cli/log_print` refuses a buffer it cannot
 * fill and says how much it wanted, which is exactly what makes this
 * possible: ask for 256 rows, and on refusal halve and ask again. The
 * summary declares the window it settled on, so a reader is told they are
 * seeing fewer -- nothing is hidden by the shrinking, which is the whole
 * reason the declaration exists.
 */
#define FZN_LOG_VIEW_BUDGET 65536u

fzn_log_view::fzn_log_view(QWidget *parent)
        : QWidget(parent), summary_(new QLabel(this)), entries_(new QPlainTextEdit(this))
{
	QVBoxLayout *layout = new QVBoxLayout(this);
	QFont mono = entries_->font();

	/* Monospace, so a sequence column lines up and an escaped byte is four
	 * columns wherever it falls. On a character-cell backend every font
	 * already is, and the style hint costs nothing there. */
	mono.setStyleHint(QFont::Monospace);
	mono.setFamily(mono.defaultFamily());
	entries_->setFont(mono);

	/* READ-ONLY AND SELECTABLE. A log a reader cannot copy out of is one
	 * they will retype into a bug report, and a log they can EDIT is one
	 * whose screen stops being evidence of what was signed. */
	entries_->setReadOnly(true);
	entries_->setLineWrapMode(QPlainTextEdit::NoWrap);

	/* NO FRAME. project.md sec 159.
	 *
	 * Rendered through qtty this editor's frame came out as a left edge and
	 * nothing else: box-drawing characters down one column, no top run and
	 * no right side. A border that draws one of its four sides is worse
	 * than no border, and it costs a cell of width and a row top and bottom
	 * on a 24-row terminal to do it.
	 *
	 * IT COST DECORATION AND NOT CONTENT, WHICH THIS COMMENT FIRST GOT
	 * WRONG. The first version said the frame put a blank row between every
	 * log line. That is real and it is not this widget: it needs a
	 * PROPORTIONAL font, and the monospace hint above -- set since sec 141
	 * so a sequence column lines up -- is what prevents it. Measured one
	 * setting at a time; `readOnly` and `NoWrap` make no difference and the
	 * font makes all of it. So the entries were always on consecutive rows
	 * here, and the claim that they were not came from a synthetic
	 * reproduction that had defaulted its font.
	 *
	 * SO THE REASON THAT STANDS IS THE SECOND ONE, and it does not depend
	 * on qtty at all: a GENERIC WIDGET SHOULD NOT IMPOSE CHROME. This is
	 * the object every consumer embeds -- sec 141 -- and a border around it
	 * is the consumer's decision, reachable with a QGroupBox around the
	 * whole thing. That survives whatever qtty's side does next. */
	entries_->setFrameShape(QFrame::NoFrame);

	layout->addWidget(summary_);
	layout->addWidget(entries_);

	show_stream(nullptr, nullptr, nullptr, 0);
}

/* One line off the end. `cli/log_print` terminates both halves with a
 * newline because a stream needs one; a label and a text area do not, and a
 * trailing blank row in a QPlainTextEdit is a row of the reader's screen. */
static QString trimmed(const char *text)
{
	QString s = QString::fromLatin1(text);

	while (s.endsWith(QLatin1Char('\n')))
		s.chop(1);
	return s;
}

void fzn_log_view::show_stream(const fzn_log_t *log, const fzn_journal_t *journal,
                               const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream)
{
	static char text[FZN_LOG_VIEW_BUDGET];
	size_t rows = FZN_LOG_VIEW_ROWS;
	size_t len = 0;

	/* NOT A SECOND RENDERER. project.md sec 168. This widget used to
	 * compose both strings itself, in wording that matched
	 * `cli/log_print.c`'s by hand -- two implementations of one screen,
	 * with nothing checking they still agreed and no reason either author
	 * would look. The words are that file's now, and this asks for them.
	 *
	 * IT ASKS FOR THE HALVES RATHER THAN SPLITTING THE WHOLE. Taking
	 * `fzn_log_print` and cutting at the first newline would make this
	 * widget a parser of a format, which is a new thing to get wrong
	 * rather than one thing fewer. */
	if (!log || !journal || !issuer) {
		/* A VIEW WITH NO LOG SAYS SO, rather than showing an empty list
		 * that looks like a stream with nothing in it. Those are
		 * different facts, and a reader deciding whether a host is
		 * quiet or unconfigured needs to tell them apart. */
		summary_->setText(QStringLiteral("no log"));
		entries_->setPlainText(QString());
		return;
	}

	/* AS MANY ROWS AS FIT, HALVING UNTIL THEY DO. Terminates because the
	 * window strictly decreases and zero rows renders no entry lines at
	 * all, which fits in any buffer that holds the summary. */
	while (rows > 0u &&
	       fzn_log_entries(log, journal, issuer, stream, rows, text, sizeof(text),
	                       &len) != FZN_LOG_OK)
		rows /= 2u;

	/* THE SUMMARY IS ASKED FOR THE WINDOW THAT WAS SETTLED ON, not the one
	 * that was wanted, or it would declare a number of rows that are not
	 * on the screen. */
	if (fzn_log_summary(log, journal, issuer, stream, rows, text, sizeof(text), &len) !=
	    FZN_LOG_OK) {
		summary_->setText(QStringLiteral("no log"));
		entries_->setPlainText(QString());
		return;
	}
	summary_->setText(trimmed(text));

	if (fzn_log_entries(log, journal, issuer, stream, rows, text, sizeof(text), &len) !=
	    FZN_LOG_OK) {
		/* THE SUMMARY STAYS. It was rendered and it is the half that
		 * says what has been lost; blanking it because the entries
		 * would not fit would throw away the more important of the
		 * two. Reached only if a zero-row render refuses, which the
		 * loop above has already ruled out for every buffer that held
		 * the summary. */
		entries_->setPlainText(QStringLiteral("(entries could not be rendered)"));
		return;
	}
	entries_->setPlainText(trimmed(text));
}

QString fzn_log_view::summary_text() const
{
	return summary_->text();
}

QString fzn_log_view::entries_text() const
{
	return entries_->toPlainText();
}
