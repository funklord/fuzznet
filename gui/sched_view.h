/*
 * Which link a class got and, per link, why the others did not.
 *
 * project.md sec 248. It SHOWS `cli/sched_print`'s line rather than composing
 * its own, per sec 193, and adds only what sec 194 permits a medium to add:
 * the printer counts how many links were excluded and for what, and a screen
 * has room to say WHICH.
 *
 * THAT IS THE WHOLE REASON THIS WIDGET EXISTS. `fzn_sched_print` can say "3
 * of 5 links are slower than this class allows" -- true, and an operator
 * deciding whether to take a path out of service, or which one to fix, needs
 * the row. On the NO_SINGLE_FIX line it matters most: that line deliberately
 * names no bound to change, so without the rows a reader is told there is no
 * single fix and nothing about where the several are.
 *
 * IT IS NOT `gui/link_view`. That one's subject is which of a link's numbers
 * are MEASUREMENTS and which are the far end's word, and its header says so
 * is the whole reason it exists. This one's subject is one CLASS against the
 * same table. Two questions over one set of rows, and a widget answering both
 * would be a screen whose columns disagree about what they are for.
 *
 * THE CLASS COMES FROM THE CONSUMER, and so does the answer: `show_choice`
 * takes what `fzn_sched_select` returned rather than selecting again, for
 * `cli/sched_print`'s reason -- a second selection could differ, and a screen
 * describing a choice nobody made is worse than a blank one.
 *
 * NO MOC. Nothing here declares a signal or a slot, so this stays a plain
 * compile and link, and a refresh is the consumer calling `show_choice`
 * again. A widget that decided when to re-read a link table would be deciding
 * when to observe the network.
 *
 * THE ROWS ARE MONOSPACED AND COLUMN-ALIGNED IN THE TEXT, on sec 158's
 * argument: the alignment is in the string, so it is the same at every width
 * and a reading can be compared against a CLI's.
 */

#ifndef FZN_GUI_SCHED_VIEW_H
#define FZN_GUI_SCHED_VIEW_H

extern "C" {
#include "../cli/sched_print.h"
#include "../sched/sched.h"
}

#include <QString>
#include <QWidget>

class QLabel;

/* As many rows as this widget will draw. Beyond it the rows understate what
 * the summary counted, and `rows_truncated` says so. */
#define FZN_SCHED_VIEW_ROWS_MAX 32

class fzn_sched_view : public QWidget {
public:
	explicit fzn_sched_view(QWidget *parent = nullptr);

	/*
	 * What this widget says about the table it was given.
	 *
	 * NOTHING is no links or no class. CARRIED is a chosen link. DROPPED
	 * is every other answer -- the four reasons are in the printer's line
	 * and in the rows, and a caller alarming on "is this class moving"
	 * should not have to know which of them applied.
	 */
	enum state { NOTHING, CARRIED, DROPPED };

	/* Show the selection `err` and `chosen` describe, over `links` under
	 * `wanted`. `links` may be NULL, which is NOTHING however many are
	 * claimed. */
	void show_choice(const fzn_sched_candidate_t *links, size_t link_count,
	                 const fzn_class_t *wanted, fzn_sched_err_t err, size_t chosen);

	/* What is on the screen. */
	state shown_state() const;

	/* The printer's line, unaltered. */
	QString summary_text() const;

	/* One row per link: its id, its cost under this class, and either that
	 * it was chosen or why it was excluded. */
	QString rows_text() const;

	/* How many links this class cannot use, chosen or not. Zero when
	 * `shown_state` is NOTHING, which is not a claim that every link is
	 * usable -- there was no table to count. */
	size_t unusable() const;

	/* Whether there were more links than FZN_SCHED_VIEW_ROWS_MAX. */
	bool rows_truncated() const;

private:
	state state_;
	size_t unusable_;
	bool rows_truncated_;
	QLabel *summary_;
	QLabel *rows_;
};

#endif /* FZN_GUI_SCHED_VIEW_H */
