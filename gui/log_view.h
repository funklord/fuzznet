/*
 * A widget showing a log, including what it no longer holds.
 *
 * project.md sec 141. `log/log.h` evicts by design -- "losing its oldest
 * entries is its normal condition rather than a failure" -- and it counts
 * what it dropped, and it distinguishes an entry retention ate from one that
 * has yet to arrive. **A viewer that lists what it holds and stops has
 * silently thrown away the most important thing the module knows.** A reader
 * of a log with an unmarked hole in it draws conclusions from a record that
 * is not there.
 *
 * SO THIS TAKES A JOURNAL, exactly as `fzn_log_get` does and for the reason
 * that header gives: the position "is a parameter rather than a second call
 * the caller is trusted to remember". A viewer cannot tell GONE from ABSENT
 * without it, and one that could be constructed without it would be one
 * somebody constructs without it.
 *
 * A BODY IS OPAQUE BYTES and is rendered by `fzn_log_body_text`, which
 * escapes everything outside printable ASCII. That is not tidiness: a body
 * carrying a newline and a plausible sequence number would otherwise draw a
 * SECOND entry that no issuer ever signed, and one carrying an escape byte
 * would drive the terminal the view is drawn on.
 *
 * QT WIDGETS AND NO Q_OBJECT, for the reasons `gui/trust_view.h` gives at
 * length: qtty renders unmodified Widgets on a character-cell terminal, and
 * a view that emits nothing needs no meta-object.
 */
#ifndef FZN_GUI_LOG_VIEW_H
#define FZN_GUI_LOG_VIEW_H

extern "C" {
#include "../log/log.h"
}

#include <QWidget>

class QLabel;
class QPlainTextEdit;

class fzn_log_view : public QWidget {
public:
	explicit fzn_log_view(QWidget *parent = nullptr);

	/*
	 * Show one issuer's stream out of `log`, judged against `journal`.
	 *
	 * Either pointer being null shows an empty view that says it is empty,
	 * rather than an empty view that looks like a stream with nothing in
	 * it. Those are different facts and a reader deciding whether a host is
	 * quiet or unconfigured needs to tell them apart.
	 */
	void show_stream(const fzn_log_t *log, const fzn_journal_t *journal,
	                 const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream);

	/* What is on screen, so a test can read it back without one. The
	 * summary is where the missing entries are named; the entries are one
	 * per line, oldest first, as `fzn_log_read_since` returns them. */
	QString summary_text() const;
	QString entries_text() const;

private:
	QLabel *summary_;
	QPlainTextEdit *entries_;
};

#endif
