/*
 * What this host has received from one peer's stream, what it has applied,
 * and whether it is tracking that peer at all.
 *
 * project.md sec 186. `record/journal.h` is the model: per (issuer, stream),
 * "have I got it, and have I applied it".
 *
 * `fzn_journal_next` ANSWERS 1 FOR TWO DIFFERENT HOSTS, and that is the pair
 * this widget exists for. Its header says it "Returns 1 for an issuer never
 * seen" -- and 1 is also the honest answer for a stream this host FOLLOWS
 * which has said nothing yet. Both want sequence 1 next. Only one of them is
 * listening.
 *
 * "Why am I getting nothing from Bob" has two answers and they are opposite:
 * Bob has sent nothing, or this host never followed Bob. A screen that showed
 * the number alone would answer neither.
 *
 * AN EXHAUSTED STREAM IS NOT A VERY LARGE WANT. `next` answers UINT64_MAX for
 * a stream that has run out, and `fzn_journal_admit` refuses that value as a
 * duplicate. Rendered as a number it reads as a request for record
 * eighteen quintillion; it means there will never be another.
 *
 * A FULL JOURNAL IS REFUSING NEW PEERS, AND NOTHING ELSE SAYS SO. journal.h:
 * a full table is "REFUSED RATHER THAN EVICTED, for the reason
 * `frame/freshness.h` refuses a full replay window: dropping an issuer to
 * make room forgets what was seen from it, and the next record from that
 * issuer is then accepted at any sequence -- which readmits everything it
 * ever sent. A visible refusal a consumer can alarm on is the smaller harm."
 *
 * That refusal is only visible if somebody shows it. A host at capacity looks
 * exactly like a healthy one from any single stream's row, and every new peer
 * is being turned away -- so the table's own state is on this screen beside
 * the stream's.
 *
 * IT ASKS `cli/journal_print` AND SHOWS WHAT IT SAYS, and needs FZN_CLI for
 * it. sec 193: this widget and that printer each classified the stream and
 * the table themselves, which is two implementations of one screen -- the
 * duplication sec 168 removed for the log, re-created because a CLI
 * counterpart written for an existing widget always does unless the widget is
 * revisited.
 *
 * THE WALK AND ITS BOUND LIVE IN THE PRINTER NOW, WHICH IS A LIBRARY GAP AND
 * THE FOURTH OF ITS KIND. Telling untracked from fresh means finding the row, and
 * `record/journal.c` keeps its scannability rule private as `usable()` --
 * after `chain_store`, `revocation` and `state`. sec 183 made two of those
 * public on the holder's instruction and sec 184 took a third as a judgement.
 * This one is REPORTED rather than taken: a second unilateral extension is a
 * habit rather than a judgement, and four private copies of one rule is a
 * question about the library's shape rather than four defects. The widget is
 * worse for the gap, visibly, which is the argument.
 *
 * NO Q_OBJECT AND THEREFORE NO moc, on sec 140's rule. It displays.
 */

#ifndef FZN_GUI_JOURNAL_VIEW_H
#define FZN_GUI_JOURNAL_VIEW_H

extern "C" {
#include "../cli/journal_print.h"
#include "../record/journal.h"
}

#include <QString>
#include <QWidget>

class QLabel;

class fzn_journal_view : public QWidget {
public:
	explicit fzn_journal_view(QWidget *parent = nullptr);

	/*
	 * UNTRACKED and FRESH both want sequence 1. UNTRACKED is not
	 * listening; FRESH is, and has heard nothing.
	 */
	enum state { NOTHING, UNREADABLE, UNTRACKED, FRESH, TRACKING, EXHAUSTED };

	void show_stream(const fzn_journal_t *journal, const uint8_t issuer[FZN_PUBKEY_LEN],
	                 uint32_t stream);

	state shown_state() const;

	/* The line `fzn_journal_print` produced, carrying both the stream's
	 * position and the table's condition. */
	QString state_text() const;

	/* Whether the table has no room for another peer -- the printer's
	 * answer. Independent of the stream shown: a full journal refuses
	 * issuers it has never met and every row on it still looks healthy,
	 * which is why it is a separate accessor rather than something a
	 * caller is expected to read out of the line. */
	bool full() const;

private:
	state state_;
	bool full_;
	QLabel *state_label_;
};

#endif /* FZN_GUI_JOURNAL_VIEW_H */
