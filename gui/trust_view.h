/*
 * A widget showing an anchor, so that every consumer shows it the same way.
 *
 * project.md sec 140. `trust/trust.h` says a consumer using `fzn_trust_adopt`
 * "owes its user a way to check the anchor out of band -- a fingerprint to
 * compare, a confirmation step, something", and then leaves every consumer to
 * build one. Four projects building it separately produce four wordings and
 * four fingerprint formats, and a user cannot compare a fingerprint against a
 * differently-formatted copy of itself.
 *
 * QT WIDGETS, AND NOTHING ELSE. `harmonization.md` settles that GUI work is
 * Qt Widgets rather than QML, and the reason it matters here is `qtty`: that
 * project renders an unmodified Qt Widgets application on a character-cell
 * terminal, so a widget written this way gives a headless daemon a
 * configuration view from the same source as a desktop dialog. A QML view
 * would give one of those and not the other.
 *
 * NO Q_OBJECT AND THEREFORE NO moc, DELIBERATELY AND FOR NOW. This widget
 * displays and emits nothing, so it needs no meta-object -- which keeps the
 * first C++ in this tree to a plain compile and link, with no generated
 * sources and no build step that has to find `moc`. THE MOMENT A WIDGET HERE
 * NEEDS A SIGNAL -- a confirm button is the obvious one -- that stops being
 * true, and adding moc is a deliberate change rather than something to slip
 * in beside a feature.
 *
 * IT IS THE ONE VIEW OF THE ELEVEN THAT DOES NOT CONSOLIDATE ONTO A
 * PRINTER, and it does not need FZN_CLI. sec 201 asked whether it should and
 * measured that there was nothing to move.
 *
 * The wording could never have been shared: sec 158 breaks the fingerprint
 * into lines at fixed positions, because a user cannot compare a fingerprint
 * against a differently-formatted copy of itself and a word-wrapped label
 * reformats with the window, while a status line is one line by definition.
 * That much was expected. What was not is that the CLASSIFICATION had
 * nothing to give either: `fzn_trust_root` returns NULL exactly when the
 * source is FZN_TRUST_NONE, so asking `cli/trust_print` whether this host
 * has an anchor is asking `trust->source` by a longer route, and
 * `fzn_trust_source_str` already separates all four sources including SELF.
 *
 * A DEPENDENCY THAT WAS TRIED AND SHOWN INERT. It was written, and the
 * sabotage that should have caught its removal survived -- because the guard
 * it added was a second reading of a fact the widget already had. sec 200's
 * line is that two callers asking one library is not duplication; this is
 * the case that proves the converse costs something, since a printer call
 * nobody needs still has to be kept working. What remains of it is in the
 * TEST, which links both surfaces and asserts they agree.
 *
 * IT READS, AND DOES NOT DECIDE. Nothing here anchors, adopts or confirms
 * anything: it renders what it is given. A confirmation step is a decision
 * with a security meaning, and putting the button in the same object as the
 * display would make it easy to ship one that confirms what it drew rather
 * than what was checked.
 */
#ifndef FZN_GUI_TRUST_VIEW_H
#define FZN_GUI_TRUST_VIEW_H

extern "C" {
#include "../trust/trust.h"
}

#include <QWidget>

class QLabel;

class fzn_trust_view : public QWidget {
public:
	explicit fzn_trust_view(QWidget *parent = nullptr);

	/*
	 * Show this anchor.
	 *
	 * A null pointer, or an anchor with no root, is shown as having none --
	 * NOT as an empty fingerprint, which reads like a fingerprint of
	 * something. `fzn_trust_root` returning NULL is the library's existing
	 * fail-closed path and this follows it rather than inventing a second.
	 */
	void show_anchor(const fzn_trust_t *trust);

	/* What the widget is currently displaying, so a test can read it back
	 * without a screen. These are the strings a user sees; a test asserting
	 * on anything else would be asserting on this class's internals rather
	 * than on what it communicates. */
	QString fingerprint_text() const;
	QString source_text() const;

	/*
	 * The library's fingerprint, broken into display lines. sec 158.
	 *
	 * Public and static so a test can assert the FORMAT without a widget,
	 * a screen or a terminal -- the property that matters is that no line
	 * is wider than a small terminal, and that is a fact about this
	 * function rather than about any rendering of it.
	 */
	static QString wrapped(const QString &fingerprint);

private:
	QLabel *fingerprint_;
	QLabel *source_;
};

#endif
