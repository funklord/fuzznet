/*
 * How many issuers this host follows, and how many of their revocation
 * pictures it cannot vouch for.
 *
 * project.md sec 226. `cli/manifest_print` answers this for ONE issuer and is
 * what each row here shows; the aggregate is this widget's own, and it is the
 * reason the widget is worth having. A consumer that followed five issuers and
 * wanted to know whether any of them is under-reported would otherwise write
 * that loop itself -- and four consumers would write four wordings of the one
 * sentence that matters, which is the argument sec 140 made for the screen in
 * the first place.
 *
 * THE ONE THAT MATTERS IS UNDERSTATED. `chain/manifest.h` calls a dropped pair
 * the one refusal in the library that fails OPEN: the host "looks MORE
 * complete than it is". Four sound issuers and one understated is not "mostly
 * fine" -- the understated one is the only row that can be hiding an authority
 * this host still honours -- so the aggregate reports the WORST row rather
 * than a count of good ones.
 *
 * THE CONSUMER SUPPLIES THE ISSUERS AND THEIR LABELS, and this library
 * deliberately has no way to enumerate either. `manifest.h` says the recipient
 * set "is policy, and policy is not this library's", and a consumer that
 * called `fzn_manifest_follow` necessarily holds the keys it passed. Adding an
 * enumerator so a widget could ask would be the library keeping a second copy
 * of a list its caller owns.
 *
 * NO KEY IS DRAWN. A row is a label and a verdict. Thirty-two bytes of issuer
 * spell to 79 characters and a truncation of one is the prefix comparison
 * `trust/trust.h` refuses to invite; the label is the consumer's word for the
 * key and is what a person actually recognises.
 *
 * IT ASKS `cli/manifest_print` AND SHOWS WHAT IT SAYS, and needs FZN_CLI for
 * it. sec 193's rule, met the other way round for once: the printer landed
 * first because it found a library gap, and this follows it.
 *
 * NO Q_OBJECT AND THEREFORE NO moc, on sec 140's rule. It displays.
 */

#ifndef FZN_GUI_MANIFEST_VIEW_H
#define FZN_GUI_MANIFEST_VIEW_H

extern "C" {
#include "../chain/manifest.h"
#include "../cli/manifest_print.h"
}

#include <QString>
#include <QWidget>

class QLabel;

/* One row's worth: a key this host follows and the consumer's word for it. */
struct fzn_manifest_view_row {
	const uint8_t *issuer;
	QString label;
};

/* As many rows as this widget will draw. Beyond it the rows understate what
 * the summary counted, and `rows_truncated` says so -- `gui/link_view`'s
 * arrangement and for its reason: a screen that silently stops is a screen
 * somebody reads as complete. */
#define FZN_MANIFEST_VIEW_ROWS_MAX 32

class fzn_manifest_view : public QWidget {
public:
	explicit fzn_manifest_view(QWidget *parent = nullptr);

	/*
	 * What this widget says about the issuers it was given.
	 *
	 * NOTHING is no state, or no issuer to ask about. COMPLETE is every
	 * issuer up to date with a count that can be believed. PENDING is
	 * revocations outstanding and every count sound. UNDERSTATED is at
	 * least one issuer whose count is a FLOOR, and it outranks the other
	 * three however many rows are sound.
	 */
	enum state { NOTHING, COMPLETE, PENDING, UNDERSTATED };

	/* Show what this host knows about each of `rows`. `state` may be NULL,
	 * which is NOTHING however many rows are passed -- a caller with no
	 * manifest state is tracking nothing, and saying "up to date" would be
	 * the fail-open this whole path exists to remove. */
	void show_issuers(const fzn_manifest_state_t *state, const fzn_manifest_view_row *rows,
	                  size_t count);

	/* What is on the screen. */
	state shown_state() const;

	/* The aggregate. The widget's own words, because no single call to the
	 * printer can say how many issuers there are. */
	QString summary_text() const;

	/* One line per issuer, column-aligned, each carrying the printer's
	 * verdict for that issuer. */
	QString rows_text() const;

	/* How many of the issuers asked about have a count that cannot be
	 * believed. Its own accessor rather than a word in the summary,
	 * because a caller sorting or alarming on it should not parse a
	 * sentence. */
	size_t understated() const;

	/* Whether there were more issuers than FZN_MANIFEST_VIEW_ROWS_MAX, so
	 * the rows understate what the summary counted. */
	bool rows_truncated() const;

private:
	state state_;
	size_t understated_;
	bool rows_truncated_;
	QLabel *summary_;
	QLabel *rows_;
};

#endif /* FZN_GUI_MANIFEST_VIEW_H */
