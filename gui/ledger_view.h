/*
 * Who has acknowledged this subject, and whether the answer can be believed.
 *
 * project.md sec 228. `cli/ledger_print` answers this for ONE peer and is what
 * each row here shows; the aggregate is this widget's own. It is the same
 * division `gui/manifest_view` makes, pointed the other way: that one is what
 * this host is missing, this one is what everybody else has received.
 *
 * ONE SUBJECT, MANY PEERS, which is the shape the question actually has. A
 * consumer asking "has this gone out" holds one document and a list of hosts,
 * so that is the call: a subject, the version this host holds, and the peers
 * to ask about.
 *
 * UNREADABLE OUTRANKS EVERY OTHER ROW, however many are current.
 * `record/ledger.h`'s accessors all answer an unscannable table in the voice
 * of a readable one -- a version of zero, a count of zero, "behind" -- so a
 * screen of green rows drawn from one is a screen of nothing. That is not a
 * majority to be outvoted; it is the whole display being void.
 *
 * BEHIND AND NEVER-CONFIRMED ARE COLLAPSED IN THE SUMMARY AND KEPT APART IN
 * THE ROWS, and the division is deliberate. The action is identical -- send it
 * -- so an aggregate that split them would offer a distinction nobody acts on;
 * the row still says which, because a peer that acknowledged version three and
 * one that has never spoken are different things to look into.
 *
 * THE CONSUMER SUPPLIES THE PEERS AND THEIR LABELS, and this library has no
 * way to enumerate either. `record/ledger.h` says it in as many words: "The
 * recipient set. Who is owed a copy is policy, and policy is not this
 * library's."
 *
 * NO KEY IS DRAWN. A row is a label and a verdict, for `gui/manifest_view`'s
 * reason: thirty-two bytes spell to 64 characters and a truncation of one is
 * the prefix comparison `trust/trust.h` refuses to invite.
 *
 * NO Q_OBJECT AND THEREFORE NO moc, on sec 140's rule. It displays.
 */

#ifndef FZN_GUI_LEDGER_VIEW_H
#define FZN_GUI_LEDGER_VIEW_H

extern "C" {
#include "../cli/ledger_print.h"
#include "../record/ledger.h"
}

#include <QString>
#include <QWidget>

class QLabel;

/* One row's worth: a peer this host sends to and the consumer's word for it. */
struct fzn_ledger_view_row {
	const uint8_t *peer;
	QString label;
};

/* As many rows as this widget will draw. Beyond it the rows understate what
 * the summary counted, and `rows_truncated` says so. */
#define FZN_LEDGER_VIEW_ROWS_MAX 32

class fzn_ledger_view : public QWidget {
public:
	explicit fzn_ledger_view(QWidget *parent = nullptr);

	/*
	 * What this widget says about the peers it was given.
	 *
	 * NOTHING is no ledger, or no peer to ask about. UNREADABLE is a
	 * ledger whose own fields disagree, and it outranks the rest. CURRENT
	 * is every peer acknowledged at the version this host holds or better.
	 * BEHIND is at least one that has not.
	 */
	enum state { NOTHING, UNREADABLE, CURRENT, BEHIND };

	/* Show what each of `rows` has confirmed about `subject` at `kind`,
	 * against `current`, the version this host holds. `ledger` may be
	 * NULL, which is NOTHING however many rows are passed. */
	void show_peers(const fzn_ledger_t *ledger, const uint8_t subject[FZN_SUBJECT_LEN],
	                uint32_t kind, uint64_t current, const fzn_ledger_view_row *rows,
	                size_t count);

	/* What is on the screen. */
	state shown_state() const;

	/* The aggregate. The widget's own words, because no single call to the
	 * printer can say how many peers there are. */
	QString summary_text() const;

	/* One line per peer, column-aligned, each carrying the printer's
	 * verdict for that peer. */
	QString rows_text() const;

	/* How many of the peers asked about are not yet at `current` --
	 * behind and never-confirmed together, because the summary counts them
	 * together and a caller alarming on it should not parse a sentence.
	 * Zero when the ledger is unreadable, which is not a claim that
	 * everybody is current: `shown_state` is what says whether the number
	 * means anything. */
	size_t outstanding() const;

	/* Whether there were more peers than FZN_LEDGER_VIEW_ROWS_MAX, so the
	 * rows understate what the summary counted. */
	bool rows_truncated() const;

private:
	state state_;
	size_t outstanding_;
	bool rows_truncated_;
	QLabel *summary_;
	QLabel *rows_;
};

#endif /* FZN_GUI_LEDGER_VIEW_H */
