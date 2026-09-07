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
 * THE WALK IS BOUNDED BY `capacity`, NOT BY `used`, and that needs saying
 * because it looks like belt and braces and is not. A corrupt store is one
 * where `used` exceeds the array -- that is the definition the library's own
 * predicates use -- so walking `used` entries is exactly the read that goes
 * off the end. `fzn_revocation_covers` answers 1 for such a store and
 * `fzn_revocation_known` answers 1 as well, both failing closed, but NEITHER
 * IS A SOUNDNESS PREDICATE a consumer can ask: there is no public way to
 * separate "this store is corrupt" from "this triple is revoked".
 *
 * sec 166 found the same gap on `fzn_chain_store_t` and recorded it. This
 * widget does what a consumer must do meanwhile -- bound its own walk and SAY
 * the store is unreadable rather than draw a number from it. Adding the
 * predicate is a library change and the holder's.
 *
 * NO Q_OBJECT AND THEREFORE NO moc, on sec 140's rule. It displays.
 */

#ifndef FZN_GUI_REVOCATION_VIEW_H
#define FZN_GUI_REVOCATION_VIEW_H

extern "C" {
#include "../chain/revocation.h"
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

	state shown_state() const;
	QString state_text() const;
	QString summary_text() const;

	/* Entries in force, and entries whose revocation has been withdrawn.
	 * Counted apart, and a consumer wanting a total must add them itself
	 * -- there is no accessor for the sum, deliberately. */
	size_t in_force() const;
	size_t withdrawn() const;

private:
	state state_;
	size_t in_force_;
	size_t withdrawn_;
	QLabel *state_label_;
	QLabel *summary_;
};

#endif /* FZN_GUI_REVOCATION_VIEW_H */
