#include "state_view.h"

extern "C" {
#include "../constant_time/constant_time.h"
#include "../trust/trust.h"
}

#include <QFormLayout>
#include <QLabel>

#include <string.h>

fzn_state_view::fzn_state_view(QWidget *parent)
        : QWidget(parent), state_(NOTHING), seq_(0), state_label_(new QLabel(this)),
          issuer_(new QLabel(this))
{
	QFormLayout *form = new QFormLayout(this);

	form->addRow(QStringLiteral("State"), state_label_);
	form->addRow(QStringLiteral("Said by"), issuer_);

	state_label_->setWordWrap(true);
	issuer_->setWordWrap(true);

	show_cell(nullptr, nullptr, 0);
}

void fzn_state_view::show_cell(const fzn_state_t *st, const uint8_t subject[FZN_SUBJECT_LEN],
                               uint32_t kind)
{
	const fzn_state_entry_t *live = NULL;
	const fzn_state_entry_t *found = NULL;
	size_t i;

	state_ = NOTHING;
	seq_ = 0;
	issuer_->setText(QStringLiteral("--"));

	if (!st || !subject) {
		state_label_->setText(QStringLiteral("no state"));
		return;
	}

	if (!fzn_state_sound(st)) {
		/* NOT A CELL TO DRAW. Walking `used` here is the read that goes
		 * off the array, and this is the library's own answer rather
		 * than this widget's arithmetic. sec 184. */
		state_ = UNREADABLE;
		state_label_->setText(QStringLiteral("the state cannot be read -- it counts "
		                                     "more cells than it holds"));
		return;
	}

	/* THE VALUE IS THE LIBRARY'S ANSWER. Everything this widget adds is
	 * about the ABSENCE, so the presence is not second-guessed. */
	live = fzn_state_get(st, subject, kind);

	if (live) {
		char print[FZN_TRUST_FINGERPRINT_LEN];

		state_ = SET;
		seq_ = live->seq;
		state_label_->setText(QStringLiteral("set"));
		if (fzn_trust_fingerprint(live->issuer, print, sizeof(print)) == FZN_TRUST_OK)
			issuer_->setText(QString::fromLatin1(print));
		else
			issuer_->setText(QStringLiteral("an issuer this widget could not "
			                                "format"));
		return;
	}

	/* AND HERE IS WHERE THIS WIDGET LOOKS PAST THE ACCESSOR. `get` answers NULL
	 * for a tombstone and for a subject nobody ever set, deliberately, so
	 * that code taking a decision cannot act differently on the two. A
	 * PERSON must: one is unconfigured and the other is somebody's doing,
	 * and the tombstone still names them. */
	for (i = 0; i < st->used; i++) {
		if (st->entries[i].kind != kind)
			continue;
		if (!fzn_ct_memeq(st->entries[i].subject, subject, FZN_SUBJECT_LEN))
			continue;
		found = &st->entries[i];
		break;
	}

	if (!found) {
		state_ = NEVER_SET;
		state_label_->setText(QStringLiteral("nobody has set this"));
		return;
	}

	state_ = CLEARED;
	seq_ = found->seq;
	state_label_->setText(QStringLiteral("cleared -- it was set, and somebody "
	                                     "took it back"));
	{
		char print[FZN_TRUST_FINGERPRINT_LEN];

		if (fzn_trust_fingerprint(found->issuer, print, sizeof(print)) == FZN_TRUST_OK)
			issuer_->setText(QString::fromLatin1(print));
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

QString fzn_state_view::issuer_text() const
{
	return issuer_->text();
}

uint64_t fzn_state_view::seq() const
{
	return seq_;
}
