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
	static char line[FZN_PROVISION_PRINT_MAX];
	char text[FZN_PROVISION_TEXT_LEN];
	fzn_provision_line_t said = FZN_PROVISION_LINE_NOTHING;
	size_t out_len = 0;

	state_ = NOTHING;
	code_text_.clear();
	code_->show_text(QString(), code_level());

	/* ONE DECISION AND ONE WORDING, BOTH THE PRINTER'S -- including which
	 * states may show a fingerprint. sec 193, sec 200. */
	if (fzn_provision_print(bytes, len, verifier, now, line, sizeof(line), &out_len,
	                        &said) != FZN_PROVISION_OK) {
		state_label_->setText(QStringLiteral("no card"));
		root_->setText(QStringLiteral("--"));
		return;
	}

	switch (said) {
	case FZN_PROVISION_LINE_REFUSED:
		state_ = REFUSED;
		break;
	case FZN_PROVISION_LINE_UNCHECKED:
		state_ = UNCHECKED;
		break;
	case FZN_PROVISION_LINE_EXPIRED:
		state_ = EXPIRED;
		break;
	case FZN_PROVISION_LINE_UNDATED:
		state_ = UNDATED;
		break;
	case FZN_PROVISION_LINE_USABLE:
		state_ = USABLE;
		break;
	default:
		state_ = NOTHING;
		break;
	}

	/* THE LINE CARRIES A CODE ROW OF ITS OWN, which a screen shows as a
	 * picture instead -- so the verdict half goes in the label and the
	 * code half is drawn. */
	{
		QString whole = QString::fromLatin1(line);
		int at = whole.indexOf(QStringLiteral("\ncode "));

		if (at >= 0)
			whole = whole.left(at);
		while (whole.endsWith(QLatin1Char('\n')))
			whole.chop(1);
		state_label_->setText(whole);
		root_->setText(whole.contains(QStringLiteral("root not shown"))
		                       ? QStringLiteral("not shown until the card verifies")
		                       : QStringLiteral("in the line above"));
	}

	/* A CODE ONLY WHERE THERE IS A CARD. `fzn_provision_text` will happily
	 * base32 any bytes of the right length, so rubbish would otherwise be
	 * drawn as a scannable code. The printer makes the same distinction --
	 * it emits a code row only after `open` succeeds -- and this asks the
	 * library the same shape question rather than parsing the answer back
	 * out of the line. Two callers asking one library is not duplication;
	 * two callers DECIDING would be. */
	{
		fzn_provision_card_t parsed;

		if (!bytes || len == 0u ||
		    fzn_provision_open(bytes, len, &parsed) != FZN_PROVISION_OK)
			return;
	}

	if (fzn_provision_text(bytes, len, text, sizeof(text)) == FZN_PROVISION_OK) {
		code_text_ = QString::fromLatin1(text);
		code_->show_text(code_text_, code_level());
	}
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
