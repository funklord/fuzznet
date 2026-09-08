#include "transfer_view.h"

#include <QFormLayout>
#include <QLabel>
#include <QProgressBar>

fzn_transfer_view::fzn_transfer_view(QWidget *parent)
        : QWidget(parent), state_(NOTHING), held_(0), total_(0),
          state_label_(new QLabel(this)), progress_(new QProgressBar(this)),
          window_(new QLabel(this))
{
	QFormLayout *form = new QFormLayout(this);

	form->addRow(QStringLiteral("Transfer"), state_label_);
	form->addRow(QStringLiteral("Leaves"), progress_);
	form->addRow(QStringLiteral("Window"), window_);

	state_label_->setWordWrap(true);
	window_->setWordWrap(true);

	/* NO FRAME, on sec 159's rule: this is an object every consumer embeds
	 * and chrome around it is the consumer's decision. */
	progress_->setTextVisible(true);

	show_transfer(nullptr, nullptr, 0);
}

void fzn_transfer_view::show_transfer(const fzn_spool_t *spool, const fzn_transfer_t *transfer,
                                      uint64_t now)
{
	char line[FZN_TRANSFER_PRINT_MAX];
	fzn_transfer_state_t said = FZN_TRANSFER_NOTHING;
	size_t len = 0;

	state_ = NOTHING;
	held_ = 0;
	total_ = 0;

	/* ONE DECISION AND ONE WORDING, BOTH THE PRINTER'S. sec 193. */
	if (fzn_transfer_print(spool, transfer, now, line, sizeof(line), &len, &said) !=
	    FZN_TRANSFER_OK) {
		state_label_->setText(QStringLiteral("no transfer"));
		return;
	}

	{
		QString text = QString::fromLatin1(line);

		while (text.endsWith(QLatin1Char('\n')))
			text.chop(1);
		state_label_->setText(text);
	}

	switch (said) {
	case FZN_TRANSFER_COMPLETE:
		state_ = COMPLETE;
		break;
	case FZN_TRANSFER_WORKING:
		state_ = WORKING;
		break;
	case FZN_TRANSFER_IDLE:
		state_ = IDLE;
		break;
	case FZN_TRANSFER_STALLED:
		state_ = STALLED;
		break;
	default:
		state_ = NOTHING;
		break;
	}

	if (!spool) {
		progress_->setRange(0, 1);
		progress_->setValue(0);
		progress_->setFormat(QStringLiteral("--"));
		window_->setText(QStringLiteral("--"));
		return;
	}

	/* THE BAR AND THE WINDOW ARE THE WIDGET'S OWN, filled from the
	 * library rather than parsed out of the line. sec 194. */
	held_ = spool->have;
	total_ = spool->leaves;
	progress_->setRange(0, total_ > 0u ? (int)total_ : 1);
	progress_->setValue((int)held_);
	progress_->setFormat(QStringLiteral("%1 of %2").arg((qulonglong)held_)
	                             .arg((qulonglong)total_));

	window_->setText(transfer ? QStringLiteral("%1 batch(es) allowed in flight")
	                                    .arg(fzn_transfer_window(transfer))
	                          : QStringLiteral("no scheduler"));
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
