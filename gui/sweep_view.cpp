#include "sweep_view.h"

#include <QFormLayout>
#include <QLabel>
#include <QProgressBar>

fzn_sweep_view::fzn_sweep_view(QWidget *parent)
        : QWidget(parent), state_(NOTHING), truncated_(false),
          state_label_(new QLabel(this)), progress_(new QProgressBar(this))
{
	QFormLayout *form = new QFormLayout(this);

	form->addRow(QStringLiteral("Sweep"), state_label_);
	form->addRow(QStringLiteral("Progress"), progress_);

	state_label_->setWordWrap(true);

	show_sweep(nullptr, nullptr);
}

void fzn_sweep_view::show_sweep(const fzn_catalog_sweep_plan_t *plan,
                                const fzn_catalog_sweep_t *job)
{
	char line[FZN_SWEEP_PRINT_MAX];
	fzn_sweep_state_t said = FZN_SWEEP_NOTHING_CAPTURED;
	size_t len = 0;
	int truncated = 0;
	size_t done = 0;
	size_t total = 0;

	state_ = NOTHING;
	truncated_ = false;

	/* ONE DECISION AND ONE WORDING, BOTH THE PRINTER'S. sec 193. */
	if (fzn_sweep_print(plan, job, line, sizeof(line), &len, &said, &truncated) !=
	    FZN_CATALOG_OK) {
		state_label_->setText(QStringLiteral("nothing captured"));
		progress_->setRange(0, 1);
		progress_->setValue(0);
		progress_->setFormat(QStringLiteral("--"));
		return;
	}

	{
		QString text = QString::fromLatin1(line);

		while (text.endsWith(QLatin1Char('\n')))
			text.chop(1);
		state_label_->setText(text);
	}
	truncated_ = truncated != 0;

	switch (said) {
	case FZN_SWEEP_EMPTY:
		state_ = EMPTY;
		break;
	case FZN_SWEEP_HELD_BACK:
		state_ = HELD_BACK;
		break;
	case FZN_SWEEP_READY:
		state_ = READY;
		break;
	case FZN_SWEEP_RUNNING:
		state_ = RUNNING;
		break;
	case FZN_SWEEP_DONE:
		state_ = DONE;
		break;
	/* NAMED RATHER THAN DEFAULTED, so a state added to the printer's enum
	 * stops this file compiling instead of arriving here quietly. sec 193
	 * asks that a printer's new state change the widget in the same
	 * commit, and `-Wall`'s `-Wswitch` is what can enforce it -- only
	 * where there is no `default:`. sec 267. */
	case FZN_SWEEP_NOTHING_CAPTURED:
		state_ = NOTHING;
		break;
	}

	/* THE BAR IS THE WIDGET'S OWN, because a progress bar is a thing a
	 * screen has and a line does not -- and it is drawn from the library's
	 * numbers rather than from the printer's sentence. */
	if (job && fzn_catalog_sweep_progress(job, &done, &total) == FZN_CATALOG_OK) {
		progress_->setRange(0, total > 0u ? (int)total : 1);
		progress_->setValue((int)done);
		progress_->setFormat(QStringLiteral("%1 of %2").arg((qulonglong)done)
		                             .arg((qulonglong)total));
	} else {
		progress_->setRange(0, 1);
		progress_->setValue(0);
		progress_->setFormat(QStringLiteral("not started"));
	}
}

fzn_sweep_view::state fzn_sweep_view::shown_state() const
{
	return state_;
}

QString fzn_sweep_view::state_text() const
{
	return state_label_->text();
}

QString fzn_sweep_view::progress_text() const
{
	return progress_->text();
}

bool fzn_sweep_view::truncated() const
{
	return truncated_;
}
