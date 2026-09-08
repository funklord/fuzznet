/*
 * What this host believes has been withdrawn -- and what it believes has been
 * GIVEN BACK, which is the same table and not the same thing.
 *
 * project.md sec 182. `chain/revocation.h` is the model. `gui/capability_view`
 * answers "is this one capability usable"; this answers "what does this host
 * know", which is the question somebody asks when a peer says they were cut
 * off and nobody here can see why.
 *
 * PRESENCE IS NOT REVOCATION, AND THAT IS THE WHOLE OF THIS WIDGET.
 * `chain.h` is explicit: "A withdrawal REPLACES the revocation at this key
 * rather than removing it, so PRESENCE IS NOT THE ANSWER to 'is this revoked'
 * -- every reader must ask this field." The entry stays because removing it
 * would let a re-relayed copy of the withdrawn revocation be re-admitted on
 * every propagation round, "not a one-time resurrection but a loop".
 *
 * So a screen that listed the store's contents as revocations would report
 * every capability that was ever revoked and has since been RESTORED as
 * revoked -- which `revocation.c` calls "the outage the whole withdrawal
 * design exists to end". The two are counted apart here and never summed.
 *
 * THE STORE IS ASKED WHETHER IT CAN BE READ, and the walk stops if it cannot.
 * A corrupt store is one where `used` exceeds the array, so walking `used`
 * entries is exactly the read that goes off the end.
 *
 * `fzn_revocation_covers` and `fzn_revocation_known` both answer 1 for such a
 * store -- failing closed, which is right -- and neither can therefore be
 * used to IDENTIFY one. sec 182 open-coded the test here for want of anything
 * to ask; sec 183 added `fzn_revocation_store_sound` on the holder's
 * instruction, and this asks it now.
 *
 * The pointer is checked first, because a NULL store is SOUND: it holds
 * nothing, which is an answer, and `sound` is not a null check.
 *
 * IT ASKS `cli/revocation_print` AND SHOWS WHAT IT SAYS, and needs FZN_CLI
 * for it. sec 198, under sec 193's rule: printer and widget in one commit.
 *
 * NO Q_OBJECT AND THEREFORE NO moc, on sec 140's rule. It displays.
 */

#ifndef FZN_GUI_REVOCATION_VIEW_H
#define FZN_GUI_REVOCATION_VIEW_H

extern "C" {
#include "../chain/revocation.h"
#include "../cli/revocation_print.h"
}

#include <QString>
#include <QWidget>

class QLabel;

class fzn_revocation_view : public QWidget {
public:
	explicit fzn_revocation_view(QWidget *parent = nullptr);

	/*
	 * NOTHING is no store at all. EMPTY is a store that holds nothing --
	 * a host that has heard of no revocation. UNREADABLE is a store whose
	 * count exceeds its array, which is not a number to draw.
	 */
	enum state { NOTHING, UNREADABLE, EMPTY, HOLDING };

	/* Show what a store holds. `store` may be NULL, which a caller with no
	 * store legitimately has -- `fzn_revocation_covers` documents NULL as
	 * "knows of no revocations" rather than as a mistake. */
	void show_store(const fzn_revocation_store_t *store);

	/* `state_text` is `fzn_revocation_print`'s line, which carries both
	 * counts. There is deliberately no accessor for a total, here or in
	 * the printer: a sum of in-force and withdrawn is the number that
	 * reports restored capabilities as cut off. */
	state shown_state() const;
	QString state_text() const;

private:
	state state_;
	QLabel *state_label_;
};

#endif /* FZN_GUI_REVOCATION_VIEW_H */
