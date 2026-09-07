#include "revocation_view.h"

#include <QFormLayout>
#include <QLabel>

fzn_revocation_view::fzn_revocation_view(QWidget *parent)
        : QWidget(parent), state_(NOTHING), in_force_(0), withdrawn_(0),
          state_label_(new QLabel(this)), summary_(new QLabel(this))
{
	QFormLayout *form = new QFormLayout(this);

	form->addRow(QStringLiteral("State"), state_label_);
	form->addRow(QStringLiteral("Held"), summary_);

	state_label_->setWordWrap(true);
	summary_->setWordWrap(true);

	show_store(nullptr);
}

void fzn_revocation_view::show_store(const fzn_revocation_store_t *store)
{
	size_t i;

	state_ = NOTHING;
	in_force_ = 0;
	withdrawn_ = 0;

	if (!store) {
		/* KNOWS OF NO REVOCATIONS, which revocation.h says is the
		 * meaning of a null store rather than a caller's mistake. */
		state_label_->setText(QStringLiteral("no store -- this host knows of no "
		                                     "revocations"));
		summary_->setText(QStringLiteral("--"));
		return;
	}

	if (store->used > store->capacity || (store->used > 0u && !store->entries)) {
		/* NOT A COUNT TO DRAW. This is the library's own definition of a
		 * corrupt store, and walking `used` here is precisely the read
		 * that runs off the array. Neither `covers` nor `known` can be
		 * asked to distinguish it -- both answer 1 either way, failing
		 * closed -- so the check is here until the library grows a
		 * predicate. sec 182. */
		state_ = UNREADABLE;
		state_label_->setText(QStringLiteral("the store cannot be read -- it "
		                                     "counts more entries than it holds"));
		summary_->setText(QStringLiteral("nothing here is trustworthy"));
		return;
	}

	for (i = 0; i < store->used; i++) {
		/* THE ENTRY'S ACTION, NOT ITS PRESENCE. chain.h: a withdrawal
		 * replaces the revocation at its key rather than removing it,
		 * so a reader that counted rows would report every restored
		 * capability as revoked. */
		if (store->entries[i].withdrawn)
			withdrawn_++;
		else
			in_force_++;
	}

	if (store->used == 0u) {
		state_ = EMPTY;
		state_label_->setText(QStringLiteral("nothing withdrawn"));
		summary_->setText(QStringLiteral("no revocation has been heard of"));
		return;
	}

	state_ = HOLDING;
	state_label_->setText(QStringLiteral("%1 in force").arg((qulonglong)in_force_));

	if (withdrawn_ > 0u) {
		/* SAID SEPARATELY AND ALWAYS. A restored capability is the
		 * thing somebody is looking for when a peer says they were cut
		 * off and are not any more, and it is invisible in a total. */
		summary_->setText(QStringLiteral("%1 in force; %2 since withdrawn, so those "
		                                 "capabilities work again")
		                          .arg((qulonglong)in_force_)
		                          .arg((qulonglong)withdrawn_));
	} else {
		summary_->setText(QStringLiteral("%1 in force; none withdrawn")
		                          .arg((qulonglong)in_force_));
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

QString fzn_revocation_view::summary_text() const
{
	return summary_->text();
}

size_t fzn_revocation_view::in_force() const
{
	return in_force_;
}

size_t fzn_revocation_view::withdrawn() const
{
	return withdrawn_;
}
