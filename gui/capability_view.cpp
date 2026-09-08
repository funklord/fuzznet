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
        : QWidget(parent), state_(HOLDS_NOTHING), grantee_(new QLabel(this)),
          state_label_(new QLabel(this))
{
	QFormLayout *form = new QFormLayout(this);

	form->addRow(QStringLiteral("Capability"), state_label_);
	form->addRow(QStringLiteral("Authorises"), grantee_);

	state_label_->setWordWrap(true);
	grantee_->setWordWrap(true);

	show_capability(nullptr, nullptr, 0);
}

void fzn_capability_view::show_capability(const fzn_chain_t *chain,
                                          const fzn_revocation_store_t *revocations,
                                          uint64_t now)
{
	char line[FZN_CAPABILITY_PRINT_MAX];
	fzn_capability_state_t said = FZN_CAPABILITY_NONE;
	size_t len = 0;

	state_ = HOLDS_NOTHING;

	/* ONE DECISION AND ONE WORDING, BOTH THE PRINTER'S. sec 193. */
	if (fzn_capability_print(chain, revocations, now, line, sizeof(line), &len, &said) !=
	    FZN_CHAIN_OK) {
		state_label_->setText(QStringLiteral("no capability held"));
		grantee_->setText(QStringLiteral("nobody"));
		return;
	}

	{
		QString text = QString::fromLatin1(line);

		while (text.endsWith(QLatin1Char('\n')))
			text.chop(1);
		state_label_->setText(text);
	}

	switch (said) {
	case FZN_CAPABILITY_REVOKED:
		state_ = REVOKED;
		break;
	case FZN_CAPABILITY_EXPIRED:
		state_ = EXPIRED;
		break;
	case FZN_CAPABILITY_USABLE:
		state_ = USABLE;
		break;
	default:
		state_ = HOLDS_NOTHING;
		break;
	}

	/* THE GRANTEE IS THE WIDGET'S OWN ROW, on sec 194's line: a screen has
	 * room for a second identity and a status line does not. It is the
	 * anchor's spelling, not this widget's. */
	if (!chain) {
		grantee_->setText(QStringLiteral("nobody"));
		return;
	}
	grantee_->setText(spelled(chain->grantee));
}

fzn_capability_view::state fzn_capability_view::shown_state() const
{
	return state_;
}

QString fzn_capability_view::state_text() const
{
	return state_label_->text();
}

QString fzn_capability_view::grantee_text() const
{
	return grantee_->text();
}

