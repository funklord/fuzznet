#include "sync_view.h"

#include <QFormLayout>
#include <QLabel>

fzn_sync_view::fzn_sync_view(QWidget *parent)
        : QWidget(parent), state_(NOTHING), state_label_(new QLabel(this))
{
	QFormLayout *form = new QFormLayout(this);

	form->addRow(QStringLiteral("Sync"), state_label_);

	state_label_->setWordWrap(true);

	show_peer(nullptr, nullptr);
}

void fzn_sync_view::show_peer(const fzn_manifest_state_t *st,
                              const uint8_t issuer[FZN_PUBKEY_LEN])
{
	char line[FZN_SYNC_PRINT_MAX];
	fzn_sync_state_t said = FZN_SYNC_UNMEASURED;
	size_t len = 0;

	state_ = NOTHING;

	/* ONE DECISION AND ONE WORDING, BOTH THE PRINTER'S. sec 193: this
	 * widget used to ask `fzn_manifest_overflowed` and
	 * `fzn_manifest_deficit` itself and compose its own sentence, which
	 * made two implementations of one screen -- the thing sec 168 removed
	 * for the log and that a new CLI counterpart re-creates every time
	 * unless the widget is revisited. */
	if (!issuer || fzn_sync_print(st, issuer, line, sizeof(line), &len, &said) !=
	                       FZN_MANIFEST_OK) {
		state_label_->setText(QStringLiteral("no peer named"));
		return;
	}

	{
		QString text = QString::fromLatin1(line);

		while (text.endsWith(QLatin1Char('\n')))
			text.chop(1);
		state_label_->setText(text);
	}

	switch (said) {
	case FZN_SYNC_UP_TO_DATE:
		state_ = IN_SYNC;
		break;
	case FZN_SYNC_BEHIND:
		state_ = BEHIND;
		break;
	/* NAMED RATHER THAN DEFAULTED, so a state added to the printer's enum
	 * stops this file compiling instead of arriving here quietly. sec 193
	 * asks that a printer's new state change the widget in the same
	 * commit, and `-Wall`'s `-Wswitch` is what can enforce it -- only
	 * where there is no `default:`. sec 267. */
	case FZN_SYNC_UNMEASURED:
		state_ = UNMEASURED;
		break;
	}
}

fzn_sync_view::state fzn_sync_view::shown_state() const
{
	return state_;
}

QString fzn_sync_view::state_text() const
{
	return state_label_->text();
}

