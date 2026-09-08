#include "state_view.h"

#include <QFormLayout>
#include <QLabel>

#include <string.h>

fzn_state_view::fzn_state_view(QWidget *parent)
        : QWidget(parent), state_(NOTHING), state_label_(new QLabel(this))
{
	QFormLayout *form = new QFormLayout(this);

	form->addRow(QStringLiteral("Setting"), state_label_);

	state_label_->setWordWrap(true);

	show_cell(nullptr, nullptr, 0);
}

void fzn_state_view::show_cell(const fzn_state_t *st, const uint8_t subject[FZN_SUBJECT_LEN],
                               uint32_t kind)
{
	char line[FZN_STATE_PRINT_MAX];
	fzn_state_cell_t said = FZN_STATE_CELL_UNREADABLE;
	size_t len = 0;

	state_ = NOTHING;

	/* ONE DECISION AND ONE WORDING, BOTH THE PRINTER'S -- including the
	 * decision to look past `fzn_state_get`. sec 193, sec 197. */
	if (fzn_state_print(st, subject, kind, line, sizeof(line), &len, &said) !=
	    FZN_STATE_OK) {
		state_label_->setText(QStringLiteral("no state"));
		return;
	}

	{
		QString text = QString::fromLatin1(line);

		while (text.endsWith(QLatin1Char('\n')))
			text.chop(1);
		state_label_->setText(text);
	}

	switch (said) {
	case FZN_STATE_CELL_SET:
		state_ = SET;
		break;
	case FZN_STATE_CELL_CLEARED:
		state_ = CLEARED;
		break;
	case FZN_STATE_CELL_NEVER_SET:
		state_ = NEVER_SET;
		break;
	default:
		state_ = st ? UNREADABLE : NOTHING;
		break;
	}
}

fzn_state_view::state fzn_state_view::shown_state() const
{
	return state_;
}

QString fzn_state_view::state_text() const
{
	return state_label_->text();
}

