#include "transfer_view.h"

#include <QFormLayout>
#include <QLabel>
#include <QProgressBar>

fzn_transfer_view::fzn_transfer_view(QWidget *parent)
        : QWidget(parent), state_(NOTHING), held_(0), total_(0),
          state_label_(new QLabel(this)), progress_(new QProgressBar(this)),
          outstanding_(new QLabel(this)), window_(new QLabel(this))
{
	QFormLayout *form = new QFormLayout(this);

	form->addRow(QStringLiteral("State"), state_label_);
	form->addRow(QStringLiteral("Leaves"), progress_);
	form->addRow(QStringLiteral("Outstanding"), outstanding_);
	form->addRow(QStringLiteral("Window"), window_);

	state_label_->setWordWrap(true);
	outstanding_->setWordWrap(true);

	/* NO FRAME, on sec 159's rule: this is an object every consumer embeds
	 * and chrome around it is the consumer's decision. */
	progress_->setTextVisible(true);

	show_transfer(nullptr, nullptr, 0);
}

void fzn_transfer_view::show_transfer(const fzn_spool_t *spool, const fzn_transfer_t *transfer,
                                      uint64_t now)
{
	size_t in_flight = 0;
	size_t overdue = 0;
	int complete = 0;

	state_ = NOTHING;
	held_ = 0;
	total_ = 0;

	if (!spool) {
		state_label_->setText(QStringLiteral("no transfer"));
		progress_->setRange(0, 1);
		progress_->setValue(0);
		progress_->setFormat(QStringLiteral("--"));
		outstanding_->setText(QStringLiteral("--"));
		window_->setText(QStringLiteral("--"));
		return;
	}

	held_ = spool->have;
	total_ = spool->leaves;

	/* THE LIBRARY'S ANSWER. `have == leaves` is the same answer today and
	 * is this widget assuming an invariant that belongs to `spool/`. */
	complete = fzn_spool_complete(spool);

	progress_->setRange(0, total_ > 0u ? (int)total_ : 1);
	progress_->setValue((int)held_);
	progress_->setFormat(QStringLiteral("%1 of %2").arg((qulonglong)held_)
	                             .arg((qulonglong)total_));

	if (transfer) {
		size_t i;

		/* READ, NEVER RECLAIMED. `fzn_transfer_expire` would take these
		 * ranges back and return how many it took; calling it here
		 * would make looking at the screen change the transfer. The
		 * slots are caller-owned memory and reading them is free. */
		in_flight = fzn_transfer_in_flight(transfer);
		for (i = 0; i < transfer->cap; i++)
			if (transfer->slots[i].live && transfer->slots[i].deadline <= now)
				overdue++;
	}

	if (complete) {
		state_ = COMPLETE;
		state_label_->setText(QStringLiteral("complete"));
	} else if (in_flight > 0u) {
		state_ = WORKING;
		state_label_->setText(QStringLiteral("working"));
	} else if (held_ == 0u) {
		/* NOT STARTED. Distinguished from stalled because nothing has
		 * been asked for yet, which is a different thing to tell a
		 * person than "it stopped". */
		state_ = IDLE;
		state_label_->setText(QStringLiteral("not started"));
	} else {
		/* STOPPED SHORT. Every peer has gone quiet or every assignment
		 * has been reclaimed, and nothing is outstanding. */
		state_ = STALLED;
		state_label_->setText(QStringLiteral("stalled -- nothing outstanding"));
	}

	if (!transfer) {
		outstanding_->setText(QStringLiteral("no scheduler"));
		window_->setText(QStringLiteral("no scheduler"));
		return;
	}

	if (overdue > 0u) {
		/* RECLAIMABLE, NOT FAILED. The range returns to the want-list
		 * when somebody calls expire; the bytes are not lost, and a
		 * screen saying "failed" would make a routine consequence of a
		 * lossy transport look like something to act on. */
		outstanding_->setText(QStringLiteral("%1 batch(es), %2 past deadline and "
		                                     "reclaimable")
		                              .arg((qulonglong)in_flight)
		                              .arg((qulonglong)overdue));
	} else {
		outstanding_->setText(QStringLiteral("%1 batch(es)").arg((qulonglong)in_flight));
	}

	/* CONGESTION, NOT PROGRESS, and it gets its own row and its own noun
	 * so nobody reads it as a fraction of anything. */
	window_->setText(QStringLiteral("%1 batch(es) allowed in flight")
	                         .arg(fzn_transfer_window(transfer)));
}

fzn_transfer_view::state fzn_transfer_view::shown_state() const
{
	return state_;
}

QString fzn_transfer_view::state_text() const
{
	return state_label_->text();
}

QString fzn_transfer_view::progress_text() const
{
	return progress_->text();
}

QString fzn_transfer_view::outstanding_text() const
{
	return outstanding_->text();
}

QString fzn_transfer_view::window_text() const
{
	return window_->text();
}

uint64_t fzn_transfer_view::held() const
{
	return held_;
}

uint64_t fzn_transfer_view::total() const
{
	return total_;
}
