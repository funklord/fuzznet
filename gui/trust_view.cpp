#include "trust_view.h"

#include <QFont>
#include <QLabel>
#include <QStringList>
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

	/* EVERY FACT ON THIS SCREEN COMES FROM THE LIBRARY, and sec 201
	 * measured that `cli/trust_print` has none to add: `fzn_trust_root`
	 * returns NULL exactly when the source is FZN_TRUST_NONE, so asking
	 * the printer whether there is an anchor is asking `trust->source` by
	 * a longer route, and `fzn_trust_source_str` already distinguishes all
	 * four sources including SELF. Ten of the eleven views consolidated
	 * onto a printer; this one did not, because there was nothing to
	 * consolidate. */
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

	fingerprint_->setText(wrapped(QString::fromLatin1(text)));
}

/*
 * THE LINE BREAKS ARE IN THE TEXT, NOT IN THE LAYOUT. project.md sec 158.
 *
 * A word-wrapped label breaks where the width happens to fall, so the same
 * fingerprint reads as one line in a wide window and two in a narrow one --
 * and this widget's whole argument is that a user cannot compare a
 * fingerprint against a differently-formatted copy of itself. A format that
 * moves with the window is that problem produced by the thing built to
 * prevent it.
 *
 * MEASURED, AND WORSE THAN UNTIDY. Rendered through qtty at 76 to 80 columns
 * the label neither fitted nor wrapped: it CLIPPED, and 80 columns is the
 * canonical terminal width. The widget held all 79 characters and the screen
 * showed 78, so `fingerprint_text` -- and the test asserting on it -- agreed
 * with the library while the user compared 63 hex digits of 64 and could not
 * tell. A truncated fingerprint that looks whole is the one failure this
 * widget exists to prevent.
 *
 * EIGHT GROUPS A LINE, so a line is 39 characters and two lines carry the
 * whole key.
 *
 * THE FLOOR IS 41 COLUMNS, MEASURED AND NOT ASSUMED. This comment first said
 * 40, reasoning that 39 characters fit 40 cells; the same probe that found
 * the original defect swept 28 to 48 columns and found every width up to 40
 * still losing digits, because the layout's own margin costs two cells. The
 * arithmetic was right about the string and wrong about the widget.
 *
 * Below 41 a line is clipped -- nothing here renders 39 characters in 30
 * columns -- and that limit is stated rather than papered over. qtty's own
 * fixtures render at 46 to 52 columns, so the floor is under anything it
 * exercises; a consumer targeting a narrower terminal wants fewer groups a
 * line and more lines, which is a trade against vertical space rather than a
 * defect in this one.
 */
QString fzn_trust_view::wrapped(const QString &fingerprint)
{
	const int per_line = 8;
	QStringList groups = fingerprint.split(QLatin1Char(' '), Qt::SkipEmptyParts);
	QStringList lines;
	int at;

	for (at = 0; at < groups.size(); at += per_line) {
		lines += QStringList(groups.mid(at, per_line)).join(QLatin1Char(' '));
	}

	return lines.join(QLatin1Char('\n'));
}

QString fzn_trust_view::fingerprint_text() const
{
	return fingerprint_->text();
}

QString fzn_trust_view::source_text() const
{
	return source_->text();
}
