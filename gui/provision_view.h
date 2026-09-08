/*
 * A provisioning card: the code to photograph, and who it says you are
 * pairing with.
 *
 * project.md sec 171. sec 160 encodes QR modules, sec 161 paints them and sec
 * 163 prints them to a terminal -- and until this widget nothing in the tree
 * produced anything to put in one. `provision/provision.h` is the payload
 * those three were built for, which its own header says in as many words: its
 * card is uppercase base32 "because QR alphanumeric mode covers 0-9, A-Z and
 * a handful of symbols including `:`".
 *
 * IT RENDERS THE LIBRARY'S ANSWERS AND COMPUTES NONE, sec 165's rule. Whether
 * a card is genuine is `fzn_provision_verify`'s answer; the string the code
 * carries is `fzn_provision_text`'s; the fingerprint is
 * `fzn_trust_fingerprint`'s.
 *
 * A FINGERPRINT IS NOT SHOWN FOR A CARD THAT DID NOT VERIFY, and that is the
 * security decision this widget exists to get right rather than a display
 * preference.
 *
 * A card names a root, a hop and a prekey, and the envelope signature is what
 * says those three were assembled by the key the device is about to pin --
 * provision.h: "The parts may each be genuine and not belong together." So a
 * card carrying a GENUINE root beside an ATTACKER'S prekey is a real object
 * an attacker can build, and it is the case `provision/test` calls the
 * recombined card. A user pairing by comparing a fingerprint out of band will
 * compare the root, find it correct, and accept -- because the screen offered
 * them the one field that matches. Showing that fingerprint before the
 * signature has been checked is therefore not a small optimism; it is handing
 * the user the attacker's own evidence.
 *
 * SO WHEN THERE IS NO VERDICT THERE IS NO FINGERPRINT. The code itself is
 * still shown, because a card is public by construction -- it is made to be
 * photographed -- and the offering side has nothing to check its own card
 * against.
 *
 * "NOT DATED" IS A STATE OF ITS OWN. `fzn_provision_verify` takes `now` and
 * treats zero as "skip the expiry check", which provision.h justifies: a
 * device being provisioned may not have talked to anything yet and may have
 * no clock. A widget that passed zero and then said "usable" would be
 * reporting a check it did not make.
 *
 * IT ASKS `cli/provision_print` AND SHOWS WHAT IT SAYS, and needs FZN_CLI for
 * it. sec 200, under sec 193's rule. It keeps its own QR widget on sec 194's
 * line: a code is a thing a screen has and a line does not, and the string it
 * carries comes from the same `fzn_provision_text` the printer uses.
 *
 * NO Q_OBJECT AND THEREFORE NO moc, on sec 140's rule. It displays.
 */

#ifndef FZN_GUI_PROVISION_VIEW_H
#define FZN_GUI_PROVISION_VIEW_H

extern "C" {
#include "../chain/chain.h"
#include "../cli/provision_print.h"
#include "../provision/provision.h"
#include "../qr/qr.h"
}

#include <QString>
#include <QWidget>

class QLabel;
class fzn_qr_view;

class fzn_provision_view : public QWidget {
public:
	explicit fzn_provision_view(QWidget *parent = nullptr);

	/*
	 * What this widget says about the card it was given.
	 *
	 * NOTHING and REFUSED are kept apart for `capability_view`'s reason:
	 * a consumer holding no card and one holding bytes that are not a card
	 * have different things wrong with them.
	 *
	 * UNCHECKED and UNDATED are both short of USABLE and are not the same
	 * shortfall. UNCHECKED had no verifier at all, so nothing binds this
	 * root to this prekey. UNDATED had one and passed it, but no clock --
	 * so the signature holds and the expiry, which is what stops an old
	 * card being replayed at a device, was never looked at. Collapsing
	 * them would tell a user that a card nobody checked and a card that
	 * checked out are the same thing.
	 */
	enum state { NOTHING, REFUSED, UNCHECKED, UNDATED, EXPIRED, USABLE };

	/*
	 * Show one card.
	 *
	 * `bytes`/`len` are a packed card. `verifier` may be NULL, which is
	 * the offering side showing its own card: there is nothing to check it
	 * against, so the code is drawn and no fingerprint is offered.
	 *
	 * `now` is the caller's clock, zero meaning it has none -- passed
	 * through to `fzn_provision_verify` rather than substituted for, so
	 * that the library decides what zero means.
	 */
	void show_card(const uint8_t *bytes, size_t len, const fzn_sign_ops_t *verifier,
	               uint64_t now);

	/* `state_text` is `fzn_provision_print`'s line, carrying the verdict
	 * and -- only when the card verified and is in date -- the root's
	 * fingerprint. */
	state shown_state() const;
	QString state_text() const;

	/* The root's fingerprint, or the reason there is not one. A test reads
	 * this; so does a consumer building a pairing prompt.
	 *
	 * There is deliberately no `shows_fingerprint()` beside it. Such a
	 * predicate would have to recognise its own refusal wording, and a
	 * security property tested by matching a message prefix is one a
	 * reworded message quietly switches off. The suite compares this
	 * against what `fzn_trust_fingerprint` produces instead, which is a
	 * relationship and cannot be satisfied by a change of words. */
	QString root_text() const;

	/* The string the code carries, empty when no code is shown. */
	QString code_text() const;

	/*
	 * THE ERROR CORRECTION LEVEL A CARD IS ENCODED AT, and it is not a
	 * preference. Measured: a card's text is 682 characters, which fits
	 * version 15 at level L and NO version at M, Q or H. The suite pins
	 * that, so a later change to the card's layout that pushes it past
	 * what a code can hold fails here rather than in somebody's camera.
	 */
	static fzn_qr_level_t code_level();

private:
	state state_;
	QLabel *state_label_;
	QLabel *root_;
	fzn_qr_view *code_;
	QString code_text_;
};

#endif /* FZN_GUI_PROVISION_VIEW_H */
