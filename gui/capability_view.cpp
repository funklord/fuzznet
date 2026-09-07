#include "capability_view.h"

extern "C" {
#include "../trust/trust.h"
}

#include <QFormLayout>
#include <QLabel>

#include <string.h>

/* Thirty-two bytes, spelled the way the anchor spells them.
 *
 * `trust_view` exists because a fingerprint compared against a differently
 * formatted copy of itself cannot be compared, and a capability id and a
 * public key are both FZN_PUBKEY_LEN here. `authz_view` reaches for the same
 * function for the same reason. */
static QString spelled(const uint8_t *key)
{
	char text[FZN_TRUST_FINGERPRINT_LEN];

	if (fzn_trust_fingerprint(key, text, sizeof(text)) != FZN_TRUST_OK)
		return QStringLiteral("a value this widget could not format");
	return QString::fromLatin1(text);
}

fzn_capability_view::fzn_capability_view(QWidget *parent)
        : QWidget(parent), state_(HOLDS_NOTHING), capability_(new QLabel(this)),
          grantee_(new QLabel(this)), expiry_(new QLabel(this)),
          state_label_(new QLabel(this))
{
	QFormLayout *form = new QFormLayout(this);

	form->addRow(QStringLiteral("Capability"), capability_);
	form->addRow(QStringLiteral("Authorises"), grantee_);
	form->addRow(QStringLiteral("Expires"), expiry_);
	form->addRow(QStringLiteral("State"), state_label_);

	capability_->setWordWrap(true);
	grantee_->setWordWrap(true);
	expiry_->setWordWrap(true);
	state_label_->setWordWrap(true);

	show_capability(nullptr, nullptr, 0);
}

void fzn_capability_view::show_capability(const fzn_chain_t *chain,
                                          const fzn_revocation_store_t *revocations,
                                          uint64_t now)
{
	if (!chain) {
		/* NOT A DEAD CAPABILITY. There is no capability here at all,
		 * and the two want different things from whoever is reading. */
		state_ = HOLDS_NOTHING;
		capability_->setText(QStringLiteral("none held"));
		grantee_->setText(QStringLiteral("nobody"));
		expiry_->setText(QStringLiteral("--"));
		state_label_->setText(QStringLiteral("no capability is held"));
		return;
	}

	capability_->setText(spelled(chain->capability.b));
	grantee_->setText(spelled(chain->grantee));

	if (chain->expires_at == FZN_NO_EXPIRY) {
		/* THE SENTINEL IS NOT AN INSTANT. FZN_NO_EXPIRY is 0, so
		 * printing it as a number would put "0" on the screen -- the
		 * oldest possible date -- for the chain that outlives every
		 * other. The same zero is what makes `fzn_chain_expired_at`
		 * worth a function. */
		expiry_->setText(QStringLiteral("does not expire"));
	} else {
		/* THE NUMBER, NOT A DATE, and that is deliberate. Nothing in
		 * this library states an epoch: `now` arrives from the caller
		 * in every module that takes one, and no code here reads a
		 * clock. A widget that rendered these as calendar dates would
		 * be choosing an epoch and a timezone on the library's behalf
		 * and would be wrong for any consumer that had chosen
		 * differently. The consumer knows what its own clock counts. */
		expiry_->setText(QString::number(chain->expires_at));
	}

	/* REVOCATION IS ASKED FIRST, because it wins -- see the header. It is
	 * `covers` and not `known`: the authorization question, not the
	 * replication one. */
	if (fzn_revocation_covers(revocations, chain->root, &chain->capability,
	                          chain->grantee)) {
		state_ = REVOKED;
		state_label_->setText(QStringLiteral("revoked by the issuer"));
		return;
	}

	/* THE LIBRARY'S COMPARISON, not this widget's. `expires_at <= now`
	 * here would report every unexpiring chain as expired. */
	if (fzn_chain_expired_at(chain, now)) {
		state_ = EXPIRED;
		state_label_->setText(QStringLiteral("expired"));
		return;
	}

	/* "USABLE", NOT "ALLOWED". Holding a live chain is not authorisation;
	 * the request is still verified and `fzn_authz_decide` is still asked
	 * whether a chain was required. */
	state_ = USABLE;
	state_label_->setText(QStringLiteral("usable"));
}

fzn_capability_view::state fzn_capability_view::shown_state() const
{
	return state_;
}

QString fzn_capability_view::state_text() const
{
	return state_label_->text();
}

QString fzn_capability_view::capability_text() const
{
	return capability_->text();
}

QString fzn_capability_view::grantee_text() const
{
	return grantee_->text();
}

QString fzn_capability_view::expiry_text() const
{
	return expiry_->text();
}
