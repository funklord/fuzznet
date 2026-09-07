/*
 * A planned deletion: what is about to be taken off this host, how far it has
 * got, and -- when nothing is going, WHY nothing is going.
 *
 * project.md sec 181. `catalog/sweep.h` is the model, and this widget's whole
 * design is a sentence already in that header:
 *
 *   "THEY ARE KEPT APART RATHER THAN SUMMED because a consumer that swept
 *    nothing needs to say WHY ... Collapsed into one number, a sweep held
 *    back by the last-copy guard would be indistinguishable from a catalogue
 *    with nothing to sweep -- and those want opposite responses."
 *
 * The library went to trouble to keep seven counters apart. A screen that
 * showed "0 planned" would undo that in one line, so this does not.
 *
 * FOUR REASONS NOTHING IS PLANNED, AND THEY CALL FOR DIFFERENT ACTIONS.
 * `retained` is this host's own policy working -- change the policy if the
 * space is wanted. `shared` and `last_copy` are the two guards REFUSING, and
 * a guard refusing is the system working rather than a fault: last_copy in
 * particular means too few other hosts are known to hold it, so the answer is
 * more replicas and not more sweeping. `absent` is nothing to do. A person
 * looking at a full disk needs to know which of those they are in.
 *
 * `truncated` IS SAID LOUDLY WHATEVER ELSE IS TRUE, on sweep.h's own
 * argument: the rows ran out, so "a sweep that silently held some of them
 * would leave a consumer believing it had reclaimed what it had not". It is
 * the caller's own sizing rather than a refusal, and it is the one counter
 * that means the number beside it is short.
 *
 * IT RENDERS THE LIBRARY'S ANSWERS AND COMPUTES NONE, sec 165's rule.
 * Progress is `fzn_catalog_sweep_progress`, whose comment says in as many
 * words that it is "what to draw" and that it answers while a sweep is under
 * way -- so this widget uses the accessor the library provides for it rather
 * than reading `done` and `used` out of the struct.
 *
 * IT MUST NOT RUN THE SWEEP, and that is sec 179's rule arriving at a more
 * dangerous module. `fzn_catalog_sweep_begin`, `_advance` and `_end` all
 * mutate, and `_advance` is called AFTER bytes are gone -- so a view that
 * advanced a cursor would record a deletion that never happened, and the
 * bytes would be lost from the record while still on disk. Nothing here is
 * anything but a read.
 *
 * NO Q_OBJECT AND THEREFORE NO moc, on sec 140's rule. It displays.
 */

#ifndef FZN_GUI_SWEEP_VIEW_H
#define FZN_GUI_SWEEP_VIEW_H

extern "C" {
#include "../catalog/sweep.h"
}

#include <QString>
#include <QWidget>

class QLabel;
class QProgressBar;

class fzn_sweep_view : public QWidget {
public:
	explicit fzn_sweep_view(QWidget *parent = nullptr);

	/*
	 * What this widget says about the sweep it was given.
	 *
	 * EMPTY and HELD_BACK are the pair the library asked for by keeping
	 * its counters apart. Both plan nothing. EMPTY means there was nothing
	 * to plan; HELD_BACK means there was, and something refused -- a
	 * retention policy, a shared blob, or too few other holders.
	 */
	enum state { NOTHING, EMPTY, HELD_BACK, READY, RUNNING, DONE };

	/*
	 * Show one plan, and optionally the job carrying it out.
	 *
	 * `plan` may be NULL, which is the nothing-captured state -- a
	 * consumer that has not run `fzn_catalog_sweep_capture` yet has no
	 * plan rather than an empty one, and those are different.
	 *
	 * `job` may be NULL: a plan is worth showing before anybody begins.
	 */
	void show_sweep(const fzn_catalog_sweep_plan_t *plan, const fzn_catalog_sweep_t *job);

	/* What is on the screen. */
	state shown_state() const;
	QString state_text() const;
	QString reasons_text() const;
	QString progress_text() const;

	/* Whether the plan ran out of rows, which means every other number
	 * here is short. */
	bool truncated() const;

private:
	state state_;
	bool truncated_;
	QLabel *state_label_;
	QLabel *reasons_;
	QProgressBar *progress_;
};

#endif /* FZN_GUI_SWEEP_VIEW_H */
