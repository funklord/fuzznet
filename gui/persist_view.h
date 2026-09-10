/*
 * What this host recovered of its own stored state, as a screen.
 *
 * project.md sec 254. It SHOWS `cli/persist_print`'s line per slot, per sec
 * 193, and adds the one thing that printer cannot: **all five slots at
 * once**, and which of them is the worst.
 *
 * THAT IS THE WHOLE REASON THIS WIDGET EXISTS. `fzn_persist_print` answers
 * about one slot, because that is what a caller asks about one call at a
 * time. A person starting a program wants the other question -- did my
 * identity come back -- and the answer is a fact about the SET: four slots
 * read and the anchor missing is a different morning from four slots read
 * and one peer's chain missing, and no per-slot line can say which of them
 * happened.
 *
 * THE WORST ROW DECIDES THE SUMMARY, as `gui/manifest_view` and
 * `gui/ledger_view` do. A screen of green rows with one loss in it is a
 * screen whose summary must say loss: a person scanning five lines will read
 * the first sentence and stop, so the first sentence has to be the one that
 * matters.
 *
 * THE ORDER IS THE ENUM'S, NOT THE SEVERITY'S. Rows stay in slot order --
 * anchor, own prekey, peer, send chain, receive chain -- so two readings of
 * one host can be compared line by line, and so a person learns where to
 * look. Sorting by badness would move the rows under them.
 *
 * NO MOC. Nothing here declares a signal or a slot, so a refresh is the
 * consumer calling `show_slots` again.
 */

#ifndef FZN_GUI_PERSIST_VIEW_H
#define FZN_GUI_PERSIST_VIEW_H

extern "C" {
#include "../cli/persist_print.h"
#include "../persist/persist.h"
}

#include <QString>
#include <QWidget>

class QLabel;

/* One slot's outcome, as the consumer saw it. `had_stored` is that
 * consumer's own record of whether this host has written that slot before --
 * `cli/persist_print.h` says what it costs to get wrong, and a widget cannot
 * check it either. */
struct fzn_persist_view_row {
	fzn_persist_slot_t slot;
	fzn_persist_err_t err;
	int had_stored;
};

class fzn_persist_view : public QWidget {
public:
	explicit fzn_persist_view(QWidget *parent = nullptr);

	/*
	 * What this widget says about the set it was given.
	 *
	 * NOTHING is no rows. RECOVERED is every slot read back. FRESH is a
	 * host with nothing stored anywhere and nothing lost -- a first run.
	 * INCOMPLETE is at least one slot absent on a host that had stored,
	 * corrupt, unreadable, or asked for wrongly.
	 *
	 * FRESH AND INCOMPLETE ARE NOT DEGREES OF ONE THING. A first run has
	 * nothing to worry about and a partial recovery has, and collapsing
	 * them would make the most common startup indistinguishable from the
	 * one that needs somebody.
	 */
	enum state { NOTHING, RECOVERED, FRESH, INCOMPLETE };

	/* Show what each of `rows` reported. `rows` may be NULL, which is
	 * NOTHING however many are claimed. */
	void show_slots(const fzn_persist_view_row *rows, size_t count);

	/* What is on the screen. */
	state shown_state() const;

	/* The widget's own aggregate, because no single call to the printer
	 * can say how many slots there were. */
	QString summary_text() const;

	/* One line per slot, each carrying the printer's verdict for it. */
	QString rows_text() const;

	/* How many slots did not come back -- absent-after-storing, corrupt,
	 * unreadable or refused. Zero on a first run, which is not a claim
	 * that everything was recovered: `shown_state` is what says whether
	 * the number means anything. */
	size_t missing() const;

private:
	state state_;
	size_t missing_;
	QLabel *summary_;
	QLabel *rows_;
};

#endif /* FZN_GUI_PERSIST_VIEW_H */
