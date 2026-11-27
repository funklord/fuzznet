/* A LABEL THAT SHOWS ITS WORDS AS WORDS, sec 1506: a QLabel left on
 * Qt::AutoText turns to rich text by itself when its text merely looks
 * like markup, so whoever named a file, a contact or a group restyled
 * the line that quoted it -- "<b>RICHMARK</b> a file" made a question
 * bold (fuzzypickles, inbox 20261127T0527Z). Every label in gui/ is made
 * here, plain; `make style` refuses a `new QLabel(` anywhere else. The
 * two forms are QLabel's own, so the call reads as the constructor did.
 *
 * And a tooltip carrying somebody else's words: Qt shows it as rich text
 * on the same guess, so `fzn_plain_tip` escapes one that looks like
 * markup -- it then shows literally, its line breaks kept.
 *
 * Header-only, with no Q_OBJECT, so a host needs no moc for it. */

#ifndef FZN_GUI_PLAIN_LABEL_H
#define FZN_GUI_PLAIN_LABEL_H

#include <QLabel>
#include <QString>
#include <QTextDocument>

static inline QLabel *fzn_plain_label(QWidget *parent = nullptr)
{
	QLabel *l = new QLabel(parent);
	l->setTextFormat(Qt::PlainText);
	return l;
}

static inline QLabel *fzn_plain_label(const QString &text, QWidget *parent = nullptr)
{
	QLabel *l = new QLabel(parent);
	l->setTextFormat(Qt::PlainText);
	l->setText(text);
	return l;
}

static inline QString fzn_plain_tip(const QString &text)
{
	return Qt::mightBeRichText(text)
	               ? QStringLiteral("<p style='white-space:pre-wrap'>") + text.toHtmlEscaped() + QStringLiteral("</p>")
	               : text;
}

#endif
