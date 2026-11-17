/*
 * This host's legs, as a widget: fuzznet sec 1210.
 *
 * A LEG is this host to one address (sec 906, sec 1075) -- what fuzznetd
 * measures, as `list leg` lists it. A row a leg: its address, the link it
 * goes over, its latency, how much of what was asked came back and how many
 * silences in a row, what an answer costs, and its budget. The rest is a
 * row's tooltip, being a sentence that matters only for a leg in trouble:
 * when it was last asked and last answered, an ask out and unanswered, and
 * a leg no peer is reached at now.
 *
 * fuzzypickles' Connection page drew this table from its own link layer
 * (inbox 20261117T0122Z); the node keeps every figure since sec 1210, and
 * NOTHING IS DERIVED HERE -- the cost rule, the budget's window and the
 * ages are the node's, off a clock this process does not share.
 *
 * A PHONE'S WIDTH: under 400 pixels only the address and what came back
 * stay, as `reach_view` does (sec 1196): the question there is which peer
 * cannot be reached, and a cost with no address beside it answers nothing.
 *
 * Through the typed client on the host's ask callback (`rpc_ask.h`), so in
 * binary on a host's socket. NO Q_OBJECT AND THEREFORE NO moc.
 */
#ifndef FZN_GUI_LEG_VIEW_H
#define FZN_GUI_LEG_VIEW_H

#include "notebook_view.h"

#include <QString>
#include <QStringList>
#include <QWidget>

class QLabel;
class QResizeEvent;
class QTableWidget;
struct fzn_gui_rpc;

class fzn_leg_view : public QWidget {
public:
	fzn_leg_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent = nullptr);
	~fzn_leg_view() override;

	/* Ask for the legs and show them. Whether the node answered; a silent
	 * one is said so. */
	bool refresh();

	/* WHAT IS ON SCREEN, public because a headless test cannot look: the
	 * summary line, each row's cells joined by " | ", and row `i`'s
	 * tooltip. */
	QString summary() const;
	QStringList rows() const;
	QString detail(int row) const;

	/* The phone's layout, chosen by width; public so a test can ask. */
	void narrow(bool yes);

protected:
	void resizeEvent(QResizeEvent *event) override;

private:
	struct fzn_gui_rpc *m_rpc;
	QLabel *m_summary;
	QTableWidget *m_table;
};

#endif /* FZN_GUI_LEG_VIEW_H */
