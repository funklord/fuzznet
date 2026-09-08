/*
 * Who is on the other end of a local socket, what they asked for, and the
 * answer -- as a screen.
 *
 * project.md sec 204. It SHOWS `cli/peer_print`'s line rather than composing
 * one, per sec 193, and needs FZN_CLI for it.
 *
 * A TICK IS TWO-VALUED AND THE ANSWER IS THREE-VALUED, which is this widget's
 * whole hazard and the reason it does not use a QCheckBox for the verdict.
 * `peer.h` built a tri-state deliberately -- "the enum has no boolean
 * reading" -- because flattening "could not tell" into "no" is safe only
 * while both deny, and flattening it the other way "turns a read that failed
 * into an allow". Every natural affordance a toolkit offers for membership is
 * a checkbox, a tick or a coloured dot, and all of them are two-valued: the
 * moment one is used, UNKNOWN has to become one of the other two on screen
 * and the distinction the library spent a module defending is gone at the
 * last inch. So the verdict is three words that share no prefix, and the test
 * asserts they are pairwise distinct rather than trusting anyone to keep
 * them so.
 *
 * WHAT IT ADDS OVER THE LINE is the group list. The printer summarises it as
 * a count because a line cannot carry sixty-four gids, and an operator asking
 * "why was I denied" wants to see them. That is sec 194's boundary: the
 * medium affords a list, so the widget shows one and restates nothing else.
 *
 * AND AN EMPTY LIST IS NOT AN UNREADABLE ONE, which is the same hazard again
 * in the place a screen makes it easiest. peer.h: "a `Groups:` line with no
 * entries is a REAL empty membership ... A missing `Groups:` line is not:
 * that is could not tell". Both draw as an empty widget unless something is
 * put there on purpose, so the unreadable case says so in words and the empty
 * case says it is empty.
 *
 * `group_count` IS NOT READ WHEN THE LIST IS UNKNOWN. peer.h documents it as
 * meaningless then, and a widget that displayed it would be showing a number
 * the library says means nothing -- in the one place a reader has no way to
 * know that.
 *
 * NO MOC, LIKE THE REST OF gui/, and it reads without deciding: nothing here
 * admits, denies or reads a socket. A button that granted from the same
 * object that draws the verdict would be granting on the strength of what it
 * drew.
 */

#ifndef FZN_GUI_PEER_VIEW_H
#define FZN_GUI_PEER_VIEW_H

extern "C" {
#include "../cli/peer_print.h"
}

#include <QString>
#include <QWidget>

class QLabel;

class fzn_peer_view : public QWidget {
public:
	explicit fzn_peer_view(QWidget *parent = nullptr);

	/*
	 * Show one admission decision.
	 *
	 * `peer` may be NULL, which is the nothing-is-known case, and `verb`
	 * may be NULL. Both deny.
	 */
	void show_peer(const fzn_peer_t *peer, const uint8_t *verb, size_t verb_len,
	               const fzn_verb_rule_t *rules, size_t rule_count);

	/* The verdict on screen -- the library's own enum, not a second one. */
	fzn_peer_verdict_t shown_verdict() const;

	/* Whether the table names the verb at all. Kept separate from the
	 * verdict because it is orthogonal to it: a verb can be named and the
	 * verdict still UNKNOWN, and the two denials differ only in this. */
	bool named() const;

	/* The line `fzn_peer_print` produced. */
	QString summary_text() const;

	/* The three words. Never a tick, never a colour alone, and never a
	 * blank -- see the header. */
	QString verdict_text() const;

	/* The peer's groups, or a sentence saying they could not be read.
	 * Never empty for a peer, because an empty widget is what an
	 * unreadable list and a genuinely empty one would both look like. */
	QString groups_text() const;

private:
	fzn_peer_verdict_t verdict_;
	bool named_;
	QLabel *summary_;
	QLabel *verdict_label_;
	QLabel *groups_;
};

#endif /* FZN_GUI_PEER_VIEW_H */
