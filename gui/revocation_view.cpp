#include "revocation_view.h"

#include <QFormLayout>
#include <QLabel>

fzn_revocation_view::fzn_revocation_view(QWidget *parent)
        : QWidget(parent), state_(NOTHING), state_label_(new QLabel(this))
{
	QFormLayout *form = new QFormLayout(this);

	form->addRow(QStringLiteral("Revocations"), state_label_);

	state_label_->setWordWrap(true);

	show_store(nullptr);
}

void fzn_revocation_view::show_store(const fzn_revocation_store_t *store)
{
	char line[FZN_REVOCATION_PRINT_MAX];
	fzn_revocations_state_t said = FZN_REVOCATIONS_UNREADABLE;
	size_t len = 0;

	state_ = NOTHING;

	/* ONE DECISION AND ONE WORDING, BOTH THE PRINTER'S. sec 193. */
	if (fzn_revocation_print(store, line, sizeof(line), &len, &said) != FZN_CHAIN_OK) {
		state_label_->setText(QStringLiteral("no store"));
		return;
	}

	{
		QString text = QString::fromLatin1(line);

		while (text.endsWith(QLatin1Char('\n')))
			text.chop(1);
		state_label_->setText(text);
	}

	switch (said) {
	case FZN_REVOCATIONS_HOLDING:
		state_ = HOLDING;
		break;
	case FZN_REVOCATIONS_NONE:
		/* A NULL STORE AND AN EMPTY ONE ARE THE SAME ANSWER TO THE
		 * PRINTER -- both know of no revocations -- and this widget
		 * keeps them apart because a screen can say which. */
		state_ = store ? EMPTY : NOTHING;
		break;
	/* NAMED RATHER THAN DEFAULTED, so a state added to the printer's enum
	 * stops this file compiling instead of arriving here quietly. sec 193
	 * asks that a printer's new state change the widget in the same
	 * commit, and `-Wall`'s `-Wswitch` is what can enforce it -- only
	 * where there is no `default:`. sec 267. */
	case FZN_REVOCATIONS_UNREADABLE:
		state_ = UNREADABLE;
		break;
	}
}

fzn_revocation_view::state fzn_revocation_view::shown_state() const
{
	return state_;
}

QString fzn_revocation_view::state_text() const
{
	return state_label_->text();
}

