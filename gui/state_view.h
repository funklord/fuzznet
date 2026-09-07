/*
 * What this host currently believes about one subject -- and, when it
 * believes nothing, whether that is because nobody ever said or because
 * somebody took it back.
 *
 * project.md sec 184. `state/state.h` is the model: "a value some issuer set,
 * for some subject, of some kind", and it exists to answer "what does it
 * currently say", which its own header calls "the one a consumer asks on
 * every decision".
 *
 * THIS WIDGET LOOKS PAST `fzn_state_get`, DELIBERATELY, AND IT IS THE ONLY
 * ONE OF THESE THAT DOES. That accessor returns NULL for a tombstone and for
 * a subject nothing ever set, and the header says exactly why: "a caller
 * asking what a subject says must not have to know that this file remembers
 * who unset it."
 *
 * That is right for the caller it was written for -- code taking a DECISION
 * cannot act differently on the two, and inviting it to would be inviting a
 * bug. It is wrong for a person. "Nobody has configured this" and "somebody
 * revoked it, and here is who and when" are the two things somebody staring
 * at a host that will not do what they expect most needs told apart, and the
 * tombstone is sitting in the table with the issuer still on it.
 *
 * So the rule every other view here follows -- render the library's answer,
 * compute nothing -- is followed for the VALUE and knowingly stepped past for
 * the ABSENCE. The library is not wrong and neither is this; they have
 * different callers. Said at length because "the widget reads a field the
 * accessor hides" is otherwise indistinguishable from a widget that did not
 * read the header.
 *
 * IT ASKS WHETHER THE STATE CAN BE WALKED. `fzn_state_sound`, added with this
 * widget for the reason sec 183 added its two siblings -- walking `entries`
 * is what the tombstone answer costs, and a state counting more cells than it
 * holds is the read that goes off the end.
 *
 * NO Q_OBJECT AND THEREFORE NO moc, on sec 140's rule. It displays.
 */

#ifndef FZN_GUI_STATE_VIEW_H
#define FZN_GUI_STATE_VIEW_H

extern "C" {
#include "../state/state.h"
}

#include <QString>
#include <QWidget>

class QLabel;

class fzn_state_view : public QWidget {
public:
	explicit fzn_state_view(QWidget *parent = nullptr);

	/*
	 * UNREADABLE is a state whose count exceeds its array. NEVER_SET and
	 * CLEARED are the pair this widget exists for: `fzn_state_get` answers
	 * NULL for both, and they are not the same fact about a host.
	 */
	enum state { NOTHING, UNREADABLE, NEVER_SET, CLEARED, SET };

	/* Show one cell. `st` may be NULL. */
	void show_cell(const fzn_state_t *st, const uint8_t subject[FZN_SUBJECT_LEN],
	               uint32_t kind);

	state shown_state() const;
	QString state_text() const;

	/* Who set or cleared it, as a fingerprint, and empty when nobody has.
	 * A tombstone still names its clearer -- that is the whole reason this
	 * widget walks. */
	QString issuer_text() const;

	/* The sequence the winning record carried, or zero. */
	uint64_t seq() const;

private:
	state state_;
	uint64_t seq_;
	QLabel *state_label_;
	QLabel *issuer_;
};

#endif /* FZN_GUI_STATE_VIEW_H */
