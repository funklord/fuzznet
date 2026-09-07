/*
 * One blob being assembled: how much is here, what is outstanding, and
 * whether anything is still happening.
 *
 * project.md sec 179. Beyond sec 139's named list, which is complete -- this
 * is the state every consuming software has to show a user and had no object
 * for. "Is this transfer moving, and how far has it got" is the question a
 * person asks of a file, and `spool/` plus `spool/transfer.h` hold the whole
 * answer between them.
 *
 * IT RENDERS THE LIBRARY'S ANSWERS AND COMPUTES NONE, sec 165's rule.
 * Completion is `fzn_spool_complete`'s answer and not `have == leaves`,
 * because a bitmap and a counter agreeing is the library's invariant to keep
 * rather than this widget's to assume.
 *
 * IT MUST NOT CALL `fzn_transfer_expire`, AND THAT IS THE SHARPEST RULE
 * HERE. That call reclaims assignments whose deadline has passed and returns
 * how many it took -- it MUTATES. A view that refreshed itself by calling it
 * would reclaim a peer's outstanding ranges as a side effect of somebody
 * LOOKING at the screen, and the transfer would behave differently depending
 * on whether a window was open. Everything on this screen is read-only, and
 * the suite asserts that showing twice changes nothing.
 *
 * FOUR STATES, AND THREE OF THEM LOOK THE SAME FROM `in_flight`. Nothing
 * outstanding is not one condition:
 *
 *   IDLE      nothing held, nothing asked for -- it has not started
 *   WORKING   something is outstanding
 *   STALLED   incomplete, and nothing is outstanding: every peer has gone
 *             quiet or every assignment has been reclaimed
 *   COMPLETE  the library says so
 *
 * A screen that showed `in_flight == 0` would put "not started", "stuck" and
 * "finished" in the same words, and those are the three things a person
 * looking at a stopped transfer needs to tell apart.
 *
 * A PASSED DEADLINE IS NOT A FAILURE. An assignment past its deadline is
 * RECLAIMABLE -- the range returns to the want-list when somebody calls
 * expire, and the bytes are not lost. It is shown as such, because a screen
 * saying "failed" would report a routine consequence of a lossy transport as
 * an error somebody has to act on.
 *
 * THE WINDOW IS CONGESTION, NOT PROGRESS. `fzn_transfer_window` is batches in
 * flight under AIMD; rendering it beside a fraction invites reading it as
 * one, so it is labelled for what it is and given its own row.
 *
 * NO Q_OBJECT AND THEREFORE NO moc, on sec 140's rule. It displays.
 */

#ifndef FZN_GUI_TRANSFER_VIEW_H
#define FZN_GUI_TRANSFER_VIEW_H

extern "C" {
#include "../spool/spool.h"
#include "../spool/transfer.h"
}

#include <QString>
#include <QWidget>

class QLabel;
class QProgressBar;

class fzn_transfer_view : public QWidget {
public:
	explicit fzn_transfer_view(QWidget *parent = nullptr);

	enum state { NOTHING, IDLE, WORKING, STALLED, COMPLETE };

	/*
	 * Show one transfer, as at `now`.
	 *
	 * `transfer` may be NULL, which shows the spool alone -- a blob being
	 * assembled by something other than this scheduler still has a
	 * position worth showing, and a consumer holding only a spool should
	 * not have to invent a transfer to display it.
	 *
	 * Both NULL is the no-transfer state.
	 *
	 * `now` is the caller's clock, as everywhere. It is used ONLY to say
	 * how many outstanding assignments have passed their deadline, and
	 * never to reclaim one.
	 */
	void show_transfer(const fzn_spool_t *spool, const fzn_transfer_t *transfer,
	                   uint64_t now);

	/* What is on the screen. */
	state shown_state() const;
	QString state_text() const;
	QString progress_text() const;
	QString outstanding_text() const;
	QString window_text() const;

	/* Leaves held and leaves wanted, as the widget read them. A consumer
	 * sizing its own bar wants these rather than the string. */
	uint64_t held() const;
	uint64_t total() const;

private:
	state state_;
	uint64_t held_;
	uint64_t total_;
	QLabel *state_label_;
	QProgressBar *progress_;
	QLabel *outstanding_;
	QLabel *window_;
};

#endif /* FZN_GUI_TRANSFER_VIEW_H */
