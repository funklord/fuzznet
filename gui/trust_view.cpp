#include "trust_view.h"

#include <QFont>
#include <QLabel>
#include <QVBoxLayout>

fzn_trust_view::fzn_trust_view(QWidget *parent)
        : QWidget(parent), fingerprint_(new QLabel(this)), source_(new QLabel(this))
{
	QVBoxLayout *layout = new QVBoxLayout(this);

	/* MONOSPACE, BECAUSE THE FINGERPRINT IS COMPARED CHARACTER BY
	 * CHARACTER. A proportional font makes two groups of four hex digits
	 * different widths, which is exactly the comparison this exists to
	 * support being made harder. `QFontDatabase::systemFont` is not used:
	 * setting the style hint asks for a monospace family and lets a
	 * character-cell backend, where every font is already monospace, ignore
	 * it entirely. */
	QFont mono = fingerprint_->font();
	mono.setStyleHint(QFont::Monospace);
	mono.setFamily(mono.defaultFamily());
	fingerprint_->setFont(mono);

	/* SELECTABLE, because comparing out of band means copying it somewhere
	 * -- a message, a phone, a piece of paper. A fingerprint a user cannot
	 * copy is one they will retype, and retyping 64 hex digits is how a
	 * comparison quietly stops happening. */
	fingerprint_->setTextInteractionFlags(Qt::TextSelectableByMouse
	                                      | Qt::TextSelectableByKeyboard);
	fingerprint_->setWordWrap(true);

	layout->addWidget(source_);
	layout->addWidget(fingerprint_);

	show_anchor(nullptr);
}

void fzn_trust_view::show_anchor(const fzn_trust_t *trust)
{
	char text[FZN_TRUST_FINGERPRINT_LEN];
	const uint8_t *root = trust ? fzn_trust_root(trust) : nullptr;

	source_->setText(QString::fromUtf8(
	        fzn_trust_source_str(trust ? fzn_trust_source_of(trust) : FZN_TRUST_NONE)));

	/* AN ANCHOR WITH NO ROOT SHOWS NO FINGERPRINT, and says so rather than
	 * showing an empty one -- an empty field reads as a fingerprint of
	 * something, which is the reading that matters least when it is wrong
	 * and most when a user is deciding whether to trust a host. */
	if (!root || fzn_trust_fingerprint(root, text, sizeof(text)) != FZN_TRUST_OK) {
		fingerprint_->setText(QStringLiteral("(none)"));
		return;
	}

	fingerprint_->setText(QString::fromLatin1(text));
}

QString fzn_trust_view::fingerprint_text() const
{
	return fingerprint_->text();
}

QString fzn_trust_view::source_text() const
{
	return source_->text();
}
