#include "journal_view.h"

#include <QFormLayout>
#include <QLabel>

#include <stdint.h>
#include <string.h>

fzn_journal_view::fzn_journal_view(QWidget *parent)
        : QWidget(parent), state_(NOTHING), full_(false), state_label_(new QLabel(this))
{
	QFormLayout *form = new QFormLayout(this);

	form->addRow(QStringLiteral("Stream"), state_label_);

	state_label_->setWordWrap(true);

	show_stream(nullptr, nullptr, 0);
}

void fzn_journal_view::show_stream(const fzn_journal_t *journal,
                                   const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream)
{
	char line[FZN_JOURNAL_PRINT_MAX];
	fzn_journal_stream_state_t said = FZN_JOURNAL_STREAM_UNTRACKED;
	fzn_journal_table_state_t table = FZN_JOURNAL_TABLE_FULL;
	size_t len = 0;

	state_ = NOTHING;
	full_ = false;

	/* ONE DECISION AND ONE WORDING, BOTH THE PRINTER'S. sec 193. */
	if (fzn_journal_print(journal, issuer, stream, line, sizeof(line), &len, &said,
	                      &table) != FZN_JOURNAL_OK) {
		state_label_->setText(QStringLiteral("no journal"));
		return;
	}

	{
		QString text = QString::fromLatin1(line);

		while (text.endsWith(QLatin1Char('\n')))
			text.chop(1);
		state_label_->setText(text);
	}

	full_ = table == FZN_JOURNAL_TABLE_FULL;

	switch (said) {
	case FZN_JOURNAL_STREAM_UNREADABLE:
		state_ = UNREADABLE;
		break;
	case FZN_JOURNAL_STREAM_FRESH:
		state_ = FRESH;
		break;
	case FZN_JOURNAL_STREAM_TRACKING:
		state_ = TRACKING;
		break;
	case FZN_JOURNAL_STREAM_EXHAUSTED:
		state_ = EXHAUSTED;
		break;
	default:
		state_ = UNTRACKED;
		break;
	}
}

fzn_journal_view::state fzn_journal_view::shown_state() const
{
	return state_;
}

QString fzn_journal_view::state_text() const
{
	return state_label_->text();
}

bool fzn_journal_view::full() const
{
	return full_;
}

