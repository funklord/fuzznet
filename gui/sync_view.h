/*
 * Whether this host is up to date with one peer -- and, crucially, whether it
 * is in a position to say.
 *
 * project.md sec 185. `chain/manifest.h` is the model. A manifest is a key's
 * signed statement of what it holds; this host admits one and the difference
 * against its own holdings is the DEFICIT, which is what it must ask for.
 *
 * "IN SYNC" AND "CANNOT SAY" BOTH REPORT A DEFICIT OF ZERO, AND THAT IS THE
 * WHOLE OF THIS WIDGET. manifest.h is explicit that the second exists and why
 * it answers the way it does:
 *
 *   `fzn_manifest_overflowed` answers 1 "when a pair from that issuer was
 *   dropped for want of room, and ALSO for a NULL state, a state whose own
 *   fields disagree, and an issuer that is not followed -- all of which are
 *   the same fact in different clothes: this host cannot say what it is
 *   missing from that key."
 *
 * And it says what is at stake: it answers the opposite way round from
 * `fzn_revocation_covers`, because "an absent state means the deficit is
 * entirely unmeasured, and reporting an unmeasured deficit as sound is the
 * fail-open this module exists to remove."
 *
 * A screen that drew "0 missing" without asking `overflowed` would put that
 * fail-open back at the last possible moment -- after the library had spent a
 * whole module removing it. So this asks, and an unmeasured deficit is its own
 * state with its own words.
 *
 * A FRESH JOINER IS COMPLETE BY VACUITY, and that is not a bug to paper over.
 * manifest.h: "no manifest is an empty union is a zero deficit, so a fresh
 * joiner is COMPLETE by vacuity. A number's absence is distinguishable from
 * zero; a set's is not." Following an issuer and admitting nothing is a
 * genuine zero, and it means only that nobody has said anything yet.
 *
 * A SHORT REPORT IS SAID. `fzn_manifest_deficit`'s `dropped` count is
 * required rather than optional, on the argument that "a deficit report that
 * quietly does not fit is a range nobody asks for again". A view that showed
 * the pairs it received and not the ones that would not fit would be the same
 * silence one layer up.
 *
 * IT ASKS `cli/sync_print` AND SHOWS WHAT IT SAYS, and needs FZN_CLI for it.
 * sec 193. This widget and that printer were written days apart and each
 * decided the state from `fzn_manifest_overflowed` and `fzn_manifest_deficit`
 * itself -- two implementations of one decision, which is exactly what sec 168
 * removed between `gui/log_view` and `cli/log_print` and exactly what writing
 * a CLI counterpart for an existing widget re-creates unless the widget is
 * revisited.
 *
 * NO Q_OBJECT AND THEREFORE NO moc, on sec 140's rule. It displays.
 */

#ifndef FZN_GUI_SYNC_VIEW_H
#define FZN_GUI_SYNC_VIEW_H

extern "C" {
#include "../chain/manifest.h"
#include "../cli/sync_print.h"
}

#include <QString>
#include <QWidget>

class QLabel;

class fzn_sync_view : public QWidget {
public:
	explicit fzn_sync_view(QWidget *parent = nullptr);

	/*
	 * UNMEASURED is the state this widget exists for: the deficit is zero
	 * and that number means nothing, because the host cannot say. It is
	 * NOT a flavour of IN_SYNC and the two never share words.
	 */
	enum state { NOTHING, UNMEASURED, IN_SYNC, BEHIND };

	/* Show what this host can say about `issuer`. Either pointer may be
	 * NULL, which `fzn_manifest_overflowed` already treats as "cannot
	 * say" -- so it is passed through rather than short-circuited, and the
	 * library's answer is the one on the screen. */
	void show_peer(const fzn_manifest_state_t *st, const uint8_t issuer[FZN_PUBKEY_LEN]);

	state shown_state() const;

	/* The line `fzn_sync_print` produced, which is the whole of what is on
	 * the screen. There is deliberately no second accessor for the counts:
	 * a consumer wanting numbers asks `fzn_manifest_deficit`, which is the
	 * library rather than a widget's reading of it. */
	QString state_text() const;

private:
	state state_;
	QLabel *state_label_;
};

#endif /* FZN_GUI_SYNC_VIEW_H */
