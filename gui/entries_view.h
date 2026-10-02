/*
 * A host's log, as a person reads it. sec 468: sec 428's viewer, on a
 * widget, over sec 463's gathering.
 *
 * WHERE THE LINES COME FROM IS A CALLBACK, the gather family's `ask`: the
 * query this widget builds goes to it and pages come back. So one widget
 * reads this machine's log directory -- `fzn_entries_view_dir_ask`, which
 * answers from the files with no network, as a host would -- or another
 * host's over the remote hop, which is the host application's to hand in.
 *
 * WHAT IT SHOWS: a program's lines, from a span back from now, those
 * holding a substring when one is given -- an instance field gives an entry
 * and everything it caused -- in full, or shortened as `log/view.h` does,
 * hiding what repeats from line to line. Shortening is display only; the
 * lines are kept whole.
 *
 * A HOST THAT DOES NOT ANSWER SAYS SO, as the notes widget learned from
 * fuzzypickles: "no lines" and "the host did not answer" are different
 * words.
 *
 * NO Q_OBJECT AND THEREFORE NO moc, as every widget here: buttons connect to
 * lambdas. Built with the GUI and FZN_LOG_FILE, which gathering needs.
 */

#ifndef FZN_GUI_ENTRIES_VIEW_H
#define FZN_GUI_ENTRIES_VIEW_H

extern "C" {
#include "../log/gather.h"
}

#include <QString>
#include <QStringList>
#include <QWidget>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;

/* An `ask` answering from the log directory `ctx` (a `const char *`) on
 * this machine, through `fzn_gather_answer`. */
int fzn_entries_view_dir_ask(void *ctx, const uint8_t *request, size_t request_len,
                             uint8_t *reply, size_t reply_cap, size_t *reply_len);

class fzn_entries_view : public QWidget {
public:
	fzn_entries_view(fzn_gather_ask_t ask, void *ask_ctx, QWidget *parent = nullptr);

	/* WHAT IS ASKED FOR, public because a headless test cannot type. */
	void set_program(const QString &program);
	void set_match(const QString &match);
	/* Seconds back from now; 0 for everything. */
	void set_since(unsigned long seconds);
	void set_short(bool on);

	/* Ask, and show what came back. Whether the host answered. */
	bool refresh();

	/* WHAT IS ON SCREEN. */
	QString text() const;
	QString status() const;
	/* The lines as they came, whole, oldest first. */
	const QStringList &lines() const { return m_lines; }

private:
	void show_lines();

	fzn_gather_ask_t m_ask;
	void *m_ask_ctx;
	QStringList m_lines;
	unsigned long m_since = 0;

	QLineEdit *m_program;
	QLineEdit *m_match;
	QComboBox *m_span;
	QCheckBox *m_short;
	QPushButton *m_refresh;
	QPlainTextEdit *m_text;
	QLabel *m_status;
};

#endif /* FZN_GUI_ENTRIES_VIEW_H */
