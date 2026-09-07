#include "sweep_view.h"

#include <QFormLayout>
#include <QLabel>
#include <QProgressBar>
#include <QStringList>

fzn_sweep_view::fzn_sweep_view(QWidget *parent)
        : QWidget(parent), state_(NOTHING), truncated_(false),
          state_label_(new QLabel(this)), reasons_(new QLabel(this)),
          progress_(new QProgressBar(this))
{
	QFormLayout *form = new QFormLayout(this);

	form->addRow(QStringLiteral("State"), state_label_);
	form->addRow(QStringLiteral("Held back"), reasons_);
	form->addRow(QStringLiteral("Progress"), progress_);

	state_label_->setWordWrap(true);
	reasons_->setWordWrap(true);

	show_sweep(nullptr, nullptr);
}

void fzn_sweep_view::show_sweep(const fzn_catalog_sweep_plan_t *plan,
                                const fzn_catalog_sweep_t *job)
{
	QStringList reasons;
	size_t done = 0;
	size_t total = 0;
	int running = 0;

	state_ = NOTHING;
	truncated_ = false;

	if (!plan) {
		/* NOTHING CAPTURED. Not an empty plan: a consumer that has not
		 * run `sweep_capture` has not asked the question yet, and a
		 * catalogue with nothing to remove has answered it. */
		state_label_->setText(QStringLiteral("nothing captured"));
		reasons_->setText(QStringLiteral("--"));
		progress_->setRange(0, 1);
		progress_->setValue(0);
		progress_->setFormat(QStringLiteral("--"));
		return;
	}

	/* EVERY REASON THAT HELD SOMETHING BACK, NAMED. sweep.h keeps these
	 * apart deliberately and each calls for a different action, so they
	 * are listed rather than summed. */
	if (plan->retained > 0u)
		reasons += QStringLiteral("%1 retained by this host's own policy")
		                   .arg((qulonglong)plan->retained);
	if (plan->shared > 0u)
		reasons += QStringLiteral("%1 shared with a node that is retained")
		                   .arg((qulonglong)plan->shared);
	if (plan->last_copy > 0u)
		reasons += QStringLiteral("%1 held as the last known copy -- too few other "
		                          "hosts hold them")
		                   .arg((qulonglong)plan->last_copy);
	if (plan->absent > 0u)
		reasons += QStringLiteral("%1 not held here anyway")
		                   .arg((qulonglong)plan->absent);

	reasons_->setText(reasons.isEmpty() ? QStringLiteral("nothing")
	                                    : reasons.join(QStringLiteral("; ")));

	/* THE ROWS RAN OUT, AND IT IS SAID WHATEVER ELSE IS TRUE. Every other
	 * number on this screen is short when this is set. */
	truncated_ = plan->truncated > 0u;

	if (job && fzn_catalog_sweep_progress(job, &done, &total) == FZN_CATALOG_OK)
		running = 1;

	if (plan->planned == 0u) {
		/* THE PAIR THE LIBRARY ASKED FOR. Both plan nothing and they
		 * want opposite responses: one is a guard doing its job and the
		 * other is an empty catalogue. */
		if (plan->retained > 0u || plan->shared > 0u || plan->last_copy > 0u) {
			state_ = HELD_BACK;
			state_label_->setText(QStringLiteral("nothing will be removed -- "
			                                     "something held it back"));
		} else {
			state_ = EMPTY;
			state_label_->setText(QStringLiteral("nothing to remove"));
		}
	} else if (!running) {
		state_ = READY;
		state_label_->setText(QStringLiteral("%1 to remove, not started")
		                              .arg((qulonglong)plan->planned));
	} else if (done < total) {
		state_ = RUNNING;
		state_label_->setText(QStringLiteral("removing"));
	} else {
		state_ = DONE;
		state_label_->setText(QStringLiteral("removed"));
	}

	if (truncated_)
		state_label_->setText(state_label_->text() +
		                      QStringLiteral(" -- the plan ran out of rows, so "
		                                     "these counts are short"));

	progress_->setRange(0, total > 0u ? (int)total : 1);
	progress_->setValue((int)done);
	progress_->setFormat(running ? QStringLiteral("%1 of %2").arg((qulonglong)done)
	                                       .arg((qulonglong)total)
	                             : QStringLiteral("not started"));
}

fzn_sweep_view::state fzn_sweep_view::shown_state() const
{
	return state_;
}

QString fzn_sweep_view::state_text() const
{
	return state_label_->text();
}

QString fzn_sweep_view::reasons_text() const
{
	return reasons_->text();
}

QString fzn_sweep_view::progress_text() const
{
	return progress_->text();
}

bool fzn_sweep_view::truncated() const
{
	return truncated_;
}
