/*
 * The paths this host has, as a screen: one summary sentence, and a row per
 * link saying which of them are measurements.
 *
 * project.md sec 202. It SHOWS `cli/link_print`'s line rather than composing
 * its own, per sec 193, and needs FZN_CLI for it. What it adds is what sec
 * 194 permits a medium to add and nothing more: the printer can qualify only
 * the one number it names, and a screen has room to say per link which rows
 * are evidence and which are the far end's word.
 *
 * THAT IS THE WHOLE REASON THIS WIDGET EXISTS. `link.h` seeds a new link's
 * estimate with the declared metric, so a table renders identically whether
 * its numbers were measured or asserted, and `fzn_link_print` can only say
 * "the lowest one is a claim" or "N usable links are still on a declared
 * metric" -- true, and it does not say WHICH. An operator deciding whether to
 * take a path out of service needs the row.
 *
 * NO MOC, LIKE THE REST OF gui/. Nothing here declares a signal or a slot, so
 * this stays a plain compile and link. A refresh is the consumer calling
 * `show_links` again; there is no timer and no polling, because a widget that
 * decided when to re-read a table would be deciding when to observe the
 * network.
 *
 * THE ROWS ARE MONOSPACED AND COLUMN-ALIGNED IN THE TEXT, on sec 158's
 * argument for the fingerprint: a layout that arranges columns rearranges
 * them when the window changes, and two readings of one table that do not
 * line up cannot be compared against each other or against a CLI. The
 * alignment is in the string, so it is the same at every width.
 *
 * IT READS AND DOES NOT DECIDE. Nothing here registers, observes or marks a
 * link usable. `fzn_link_set_usable` is a consumer's statement about its own
 * interfaces, and a button that called it from the same object that draws the
 * table would be one that acted on what it drew rather than on what is.
 */

#ifndef FZN_GUI_LINK_VIEW_H
#define FZN_GUI_LINK_VIEW_H

extern "C" {
#include "../cli/link_print.h"
}

#include <QString>
#include <QWidget>

class QLabel;

/* How many rows are drawn. A caller owns its own table and may size it as it
 * likes, and a widget that rendered ten thousand rows into one label would be
 * unusable rather than informative. Truncation is reported rather than
 * silent, per `fzn_link_snapshot`'s own rule: the links past a bound are
 * always the same ones, so a quiet cut hides the same links for ever. */
#define FZN_LINK_VIEW_ROWS_MAX 32u

class fzn_link_view : public QWidget {
public:
	explicit fzn_link_view(QWidget *parent = nullptr);

	/*
	 * What this widget says about the table it was given.
	 *
	 * NONE and ALL_DOWN are the pair worth keeping apart: no link
	 * registered is a host nobody has configured, every link unusable is a
	 * host whose interfaces are down. UNMEASURED and MEASURED are the
	 * other: whether anything on screen is evidence.
	 */
	enum state { NONE, ALL_DOWN, UNMEASURED, MEASURED };

	/*
	 * Show one link table.
	 *
	 * `table` may be NULL, which is the no-path state.
	 */
	void show_links(const fzn_link_table_t *table);

	/* What is on the screen. */
	state shown_state() const;

	/* The line `fzn_link_print` produced. */
	QString summary_text() const;

	/* One line per link, column-aligned, with a header row. The widget's
	 * own, because a printer's single line cannot carry a row per link --
	 * and it is the reason this widget is worth having. */
	QString rows_text() const;

	/* How many usable links are still showing their declared metric. The
	 * printer's answer, kept as its own accessor because it is orthogonal
	 * to the state: a table is MEASURED as soon as one usable link has
	 * evidence, while others sched may choose are still on a prior. */
	size_t unmeasured() const;

	/* Whether there were more links than FZN_LINK_VIEW_ROWS_MAX, so the
	 * rows understate what the summary counted. */
	bool rows_truncated() const;

private:
	state state_;
	size_t unmeasured_;
	bool rows_truncated_;
	QLabel *summary_;
	QLabel *rows_;
};

#endif /* FZN_GUI_LINK_VIEW_H */
