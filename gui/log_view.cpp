#include "log_view.h"

#include <QFont>
#include <QLabel>
#include <QPlainTextEdit>
#include <QVBoxLayout>

/* Enough to ask for a screenful and know whether more was held. A viewer is
 * not a synchroniser: it shows the tail and says so, rather than pulling a
 * whole log into a widget because it could. */
static const size_t FZN_LOG_VIEW_ROWS = 256u;

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

	layout->addWidget(summary_);
	layout->addWidget(entries_);

	show_stream(nullptr, nullptr, nullptr, 0);
}

void fzn_log_view::show_stream(const fzn_log_t *log, const fzn_journal_t *journal,
                               const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream)
{
	const fzn_log_entry_t *rows[FZN_LOG_VIEW_ROWS];
	char text[FZN_LOG_TEXT_MAX];
	QString body;
	uint64_t first = 0;
	uint64_t last = 0;
	uint64_t next;
	size_t got;
	size_t i;

	if (!log || !journal || !issuer) {
		summary_->setText(QStringLiteral("no log"));
		entries_->setPlainText(QString());
		return;
	}

	fzn_log_range(log, issuer, stream, &first, &last);
	next = fzn_journal_next(journal, issuer, stream);
	got = fzn_log_read_since(log, issuer, stream, 0, rows, FZN_LOG_VIEW_ROWS);

	for (i = 0; i < got; i++) {
		if (fzn_log_body_text(rows[i]->body, rows[i]->body_len, text, sizeof(text))
		    != FZN_LOG_OK) {
			/* A BODY THAT WILL NOT RENDER IS SAID SO, not skipped.
			 * A row missing from a list is indistinguishable from a
			 * record that was never appended. */
			body += QStringLiteral("%1  (unrenderable body)\n")
			                .arg((qulonglong)rows[i]->seq);
			continue;
		}
		body += QStringLiteral("%1  %2\n")
		                .arg((qulonglong)rows[i]->seq)
		                .arg(QString::fromLatin1(text));
	}
	entries_->setPlainText(body);

	/*
	 * THE SUMMARY IS WHERE THE MISSING ENTRIES ARE NAMED, and it is the
	 * reason this widget takes a journal.
	 *
	 * `next` is the sequence this host wants, so everything below it was
	 * received. Anything received and not held has been evicted -- GONE in
	 * `fzn_log_get`'s vocabulary -- and a viewer that showed only what it
	 * holds would present a shorter history as a complete one.
	 */
	if (got == 0) {
		summary_->setText(next > 1u
		                          ? QStringLiteral("nothing held; %1 received and evicted")
		                                    .arg((qulonglong)(next - 1u))
		                          : QStringLiteral("nothing held"));
		return;
	}

	if (first > 1u) {
		summary_->setText(QStringLiteral("%1 to %2; %3 earlier evicted")
		                          .arg((qulonglong)first)
		                          .arg((qulonglong)last)
		                          .arg((qulonglong)(first - 1u)));
		return;
	}

	/* "complete" rather than "none evicted", so the word EVICTED appears
	 * only when something was. A reader scanning for loss should not have
	 * to read a negation, and a test asserting on the word should not be
	 * satisfied by the line that says the opposite. */
	summary_->setText(QStringLiteral("%1 to %2; complete")
	                          .arg((qulonglong)first)
	                          .arg((qulonglong)last));
}

QString fzn_log_view::summary_text() const
{
	return summary_->text();
}

QString fzn_log_view::entries_text() const
{
	return entries_->toPlainText();
}
