#include "sync_view.h"

#include <QFormLayout>
#include <QLabel>

/* A screenful of pairs. A viewer is not a fetcher: `fzn_manifest_deficit` is
 * the `from = 0` case and manifest.h says it is "right for a report a human
 * reads", while anything that FETCHES wants the resumable form. This reads. */
#define FZN_SYNC_VIEW_PAIRS 32u

fzn_sync_view::fzn_sync_view(QWidget *parent)
        : QWidget(parent), state_(NOTHING), missing_(0), dropped_(0),
          state_label_(new QLabel(this)), detail_(new QLabel(this))
{
	QFormLayout *form = new QFormLayout(this);

	form->addRow(QStringLiteral("State"), state_label_);
	form->addRow(QStringLiteral("Detail"), detail_);

	state_label_->setWordWrap(true);
	detail_->setWordWrap(true);

	show_peer(nullptr, nullptr);
}

void fzn_sync_view::show_peer(const fzn_manifest_state_t *st,
                              const uint8_t issuer[FZN_PUBKEY_LEN])
{
	fzn_manifest_pair_t pairs[FZN_SYNC_VIEW_PAIRS];
	size_t dropped = 0;

	state_ = NOTHING;
	missing_ = 0;
	dropped_ = 0;

	if (!issuer) {
		state_label_->setText(QStringLiteral("no peer named"));
		detail_->setText(QStringLiteral("--"));
		return;
	}

	/* THE LIBRARY'S ANSWER, ASKED FIRST. A NULL state, disagreeing fields
	 * and an unfollowed issuer are all "cannot say", and manifest.h makes
	 * that the same answer deliberately -- so the pointer is NOT
	 * short-circuited here, or this widget would be deciding a case the
	 * library has already decided. */
	if (fzn_manifest_overflowed(st, issuer)) {
		/* NOT ZERO MISSING. The deficit is unmeasured, and reporting an
		 * unmeasured deficit as sound is the fail-open the module
		 * exists to remove. */
		state_ = UNMEASURED;
		state_label_->setText(QStringLiteral("cannot say -- this host is not in a "
		                                     "position to know what it is missing"));
		detail_->setText(QStringLiteral("the peer is not followed, the state is "
		                                "absent, or a report was dropped for want "
		                                "of room"));
		return;
	}

	missing_ = fzn_manifest_deficit(st, issuer, pairs, FZN_SYNC_VIEW_PAIRS, &dropped);
	dropped_ = dropped;

	if (missing_ == 0u && dropped_ == 0u) {
		/* A GENUINE ZERO. It may still be vacuous -- a followed issuer
		 * that has said nothing is complete because there is nothing to
		 * be behind on -- and that is the truth rather than a caveat. */
		state_ = IN_SYNC;
		state_label_->setText(QStringLiteral("up to date"));
		detail_->setText(QStringLiteral("nothing outstanding from this peer"));
		return;
	}

	state_ = BEHIND;
	state_label_->setText(QStringLiteral("%1 outstanding").arg((qulonglong)missing_));

	if (dropped_ > 0u) {
		/* SAID, ON manifest.h's ARGUMENT that a report which quietly
		 * does not fit is "a range nobody asks for again". The number
		 * beside it is short. */
		detail_->setText(QStringLiteral("%1 listed; %2 more did not fit, so this "
		                                "count is short")
		                         .arg((qulonglong)missing_)
		                         .arg((qulonglong)dropped_));
	} else {
		detail_->setText(QStringLiteral("%1 pair(s) this host has not got")
		                         .arg((qulonglong)missing_));
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

QString fzn_sync_view::detail_text() const
{
	return detail_->text();
}

size_t fzn_sync_view::missing() const
{
	return missing_;
}

size_t fzn_sync_view::dropped() const
{
	return dropped_;
}
