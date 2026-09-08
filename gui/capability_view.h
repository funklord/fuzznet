/*
 * One capability a host holds, and what state it is in, so every consuming
 * software says the same thing about it.
 *
 * project.md sec 166. sec 139 asked for the objects every consumer needs and
 * named capabilities among them; `chain/chain.h` is the model, and this is a
 * way of looking at one verified chain.
 *
 * IT RENDERS THE LIBRARY'S ANSWERS AND COMPUTES NONE, which is the rule
 * `gui/authz_view.h` states and the one that decided this widget's shape
 * twice over. Expiry is `fzn_chain_expired_at`'s answer and revocation is
 * `fzn_revocation_covers`'s. Neither test is written here.
 *
 * HELD IS NOT AUTHORISED, and no word on this screen says otherwise.
 * `fzn_chain_store_lookup` shouts the same thing at its own callers: finding
 * a chain is not permission, because the request still has to be verified
 * and `fzn_authz_decide` still has to be asked whether a chain was required
 * at all. So the live state is spelled "usable" rather than "allowed", and
 * `gui/authz_view` is the widget that answers the other half.
 *
 * REVOKED IS ASKED WITH `fzn_revocation_covers`, NEVER `fzn_revocation_
 * known`. revocation.h keeps three predicates apart and says they must not
 * be confused: `covers` answers authorization, `known` answers "must I still
 * fetch this". They differ on exactly one state -- an entry whose revocation
 * has since been WITHDRAWN, where `known` is 1 and `covers` is 0 -- and a
 * widget asking the replication question would report a restored capability
 * as revoked, which revocation.c calls "the outage the whole withdrawal
 * design exists to end". One word apart in the source and invisible on
 * every store that has never seen a withdrawal.
 *
 * EXPIRED AND REVOKED GET DIFFERENT WORDS, though both mean unusable. The
 * distinction is the same one `authz_view` draws between unspelled and
 * denying: expiry is a schedule running out, revocation is somebody's
 * decision about this key, and a person looking at a capability that stopped
 * working needs to know which happened. A screen that said "unusable" for
 * both would be accurate and useless.
 *
 * REVOCATION WINS WHEN BOTH ARE TRUE. An expired chain that was also revoked
 * shows as revoked, because expiry is passive and reversible by reissue
 * while a revocation is a decision somebody took about this grantee -- the
 * one of the two that somebody may need to act on, and the one that stays
 * true after the dates stop mattering.
 *
 * IT ASKS `cli/capability_print` AND SHOWS WHAT IT SAYS, and needs FZN_CLI
 * for it. sec 196, under sec 193's rule: printer and widget in one commit.
 *
 * NO Q_OBJECT AND THEREFORE NO moc, on sec 140's rule. It displays.
 */

#ifndef FZN_GUI_CAPABILITY_VIEW_H
#define FZN_GUI_CAPABILITY_VIEW_H

extern "C" {
#include "../chain/chain.h"
#include "../chain/revocation.h"
#include "../cli/capability_print.h"
}

#include <QString>
#include <QWidget>

class QLabel;

class fzn_capability_view : public QWidget {
public:
	explicit fzn_capability_view(QWidget *parent = nullptr);

	/*
	 * What this widget says about the chain it was given.
	 *
	 * HOLDS_NOTHING is its own state rather than a flavour of unusable,
	 * for `authz_view`'s reason: a consumer that was handed no chain and
	 * one that was handed a dead chain have different things wrong with
	 * them, and only the second is about a capability at all.
	 */
	enum state { HOLDS_NOTHING, USABLE, EXPIRED, REVOKED };

	/*
	 * Show one verified chain, as at `now`, against what this host knows
	 * to be revoked.
	 *
	 * `chain` may be NULL, which shows the held-nothing state.
	 *
	 * `revocations` may be NULL, and that is not a caller's mistake --
	 * `fzn_revocation_covers` documents NULL as the answer a host with no
	 * store gives, meaning it knows of no revocations. It is passed
	 * straight through rather than being checked here, so that a corrupt
	 * store reaches the library and gets the library's fail-closed answer.
	 *
	 * `now` is the caller's clock, as it is in the seven library modules
	 * that take one. This widget does not read a clock; a view that
	 * fetched its own would answer a different question from the code that
	 * gates the request.
	 */
	void show_capability(const fzn_chain_t *chain,
	                     const fzn_revocation_store_t *revocations, uint64_t now);

	/* What is on the screen. A test reads these; a consumer auditing what
	 * it holds wants the first. */
	state shown_state() const;
	QString state_text() const;
	QString capability_text() const;
	QString grantee_text() const;
	QString expiry_text() const;

private:
	state state_;
	QLabel *grantee_;
	QLabel *state_label_;
};

#endif /* FZN_GUI_CAPABILITY_VIEW_H */
