#include "provision_view.h"
#include "qr_view.h"

extern "C" {
#include "../trust/trust.h"
}

#include <QFormLayout>
#include <QLabel>
#include <QVBoxLayout>

#include <string.h>

fzn_qr_level_t fzn_provision_view::code_level()
{
	/* LEVEL L, BECAUSE IT IS THE ONLY ONE THAT FITS. See the header: 682
	 * characters go into version 15 at L and into no version at all at M,
	 * Q or H. A function rather than a literal at the call site, so the
	 * suite can assert the choice against the encoder rather than against
	 * a copy of it. */
	return FZN_QR_LEVEL_L;
}

fzn_provision_view::fzn_provision_view(QWidget *parent)
        : QWidget(parent), state_(NOTHING), state_label_(new QLabel(this)),
          root_(new QLabel(this)), code_(new fzn_qr_view(this))
{
	QVBoxLayout *outer = new QVBoxLayout(this);
	QFormLayout *form = new QFormLayout;

	form->addRow(QStringLiteral("State"), state_label_);
	form->addRow(QStringLiteral("Root"), root_);
	state_label_->setWordWrap(true);
	root_->setWordWrap(true);

	outer->addLayout(form);
	outer->addWidget(code_);

	show_card(nullptr, 0, nullptr, 0);
}

void fzn_provision_view::show_card(const uint8_t *bytes, size_t len,
                                   const fzn_sign_ops_t *verifier, uint64_t now)
{
	char text[FZN_PROVISION_TEXT_LEN];
	fzn_provision_card_t card;
	fzn_provision_err_t opened;

	state_ = NOTHING;
	code_text_.clear();
	code_->show_text(QString(), code_level());

	if (!bytes || len == 0) {
		state_label_->setText(QStringLiteral("no card"));
		root_->setText(QStringLiteral("--"));
		return;
	}

	/* SHAPE FIRST, AND SEPARATELY. provision.h splits `open` from `verify`
	 * because "a reader that cannot tell 'these bytes are not a card' from
	 * 'this card is not signed by who it says' cannot report either
	 * usefully", and a screen inherits that distinction rather than
	 * flattening it. */
	opened = fzn_provision_open(bytes, len, &card);
	if (opened != FZN_PROVISION_OK) {
		state_ = REFUSED;
		state_label_->setText(QStringLiteral("not a card: ") +
		                      QString::fromLatin1(fzn_provision_err_str(opened)));
		root_->setText(QStringLiteral("--"));
		return;
	}

	/* THE CODE IS DRAWN WHATEVER THE VERDICT. A card is public by
	 * construction -- it exists to be photographed -- and the offering
	 * side has nothing to check its own card against. It is the
	 * FINGERPRINT that waits for a verdict, not the code. */
	if (fzn_provision_text(bytes, len, text, sizeof(text)) == FZN_PROVISION_OK) {
		code_text_ = QString::fromLatin1(text);
		code_->show_text(code_text_, code_level());
	}

	if (!verifier) {
		/* NOBODY CHECKED. Not "probably fine": the signature is what
		 * binds this root to this prekey, and without it the two need
		 * not have come from the same hand. */
		state_ = UNCHECKED;
		state_label_->setText(QStringLiteral("not checked -- no verifier was given"));
		root_->setText(QStringLiteral("not shown until the card verifies"));
		return;
	}

	switch (fzn_provision_verify(card, verifier, now)) {
	case FZN_PROVISION_OK:
		state_ = now ? USABLE : UNDATED;
		break;
	case FZN_PROVISION_ERR_EXPIRED:
		/* ITS OWN STATE, on provision.h's argument: a card that was
		 * valid and is not any more is an ordinary thing to meet and
		 * an unremarkable thing to say to a user, where a malformed
		 * one is a fault somewhere. */
		state_ = EXPIRED;
		break;
	default:
		state_ = REFUSED;
		break;
	}

	if (state_ != USABLE && state_ != UNDATED) {
		state_label_->setText(state_ == EXPIRED
		                              ? QStringLiteral("expired")
		                              : QStringLiteral("the signature does not verify"));
		root_->setText(QStringLiteral("not shown until the card verifies"));
		return;
	}

	/* VERIFIED, SO THE FINGERPRINT IS WORTH COMPARING. The same spelling
	 * of thirty-two bytes `trust_view` uses, for its reason: a fingerprint
	 * compared against a differently formatted copy of itself cannot be
	 * compared at all. */
	{
		char print[FZN_TRUST_FINGERPRINT_LEN];

		if (fzn_trust_fingerprint(card.root, print, sizeof(print)) == FZN_TRUST_OK)
			root_->setText(QString::fromLatin1(print));
		else
			root_->setText(QStringLiteral("a root this widget could not format"));
	}

	state_label_->setText(state_ == USABLE
	                              ? QStringLiteral("verified, and in date")
	                              : QStringLiteral("verified -- no clock, so not dated"));
}

fzn_provision_view::state fzn_provision_view::shown_state() const
{
	return state_;
}

QString fzn_provision_view::state_text() const
{
	return state_label_->text();
}

QString fzn_provision_view::root_text() const
{
	return root_->text();
}

QString fzn_provision_view::code_text() const
{
	return code_text_;
}
