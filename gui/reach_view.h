/*
 * How this host is reached, as a widget: fuzznet sec 1134.
 *
 * Three things fuzzypickles' Connection page drew by hand: where other
 * hosts see this one from outside, and how many of them agree (one
 * report alone is a guess, sec 1125); which hosts answered on this
 * network; and whether this host relays for others, at what quota, and
 * for whom. A person asks again for each of the first two. And whether
 * this host keeps up with what it syncs (sec 1135): the share of each round
 * its sync takes, and fuzznet's own advice when it does not keep up.
 *
 * EVERY REPORT, NOT THE FIRST, sec 1196: fuzzypickles listed what it lacked
 * here before its page could go (inbox 20261117T0122Z). Each host's report
 * of where it sees this one -- the address, who said it, when -- is a row,
 * and the one selected can be advertised: written as this host's
 * `net/address`, what a card and a peer asking for this host's records
 * carry. Each host found on this network says when it was seen; the relay
 * says, per peer, what it used and how often it was turned away. And the
 * node's own recent activity, newest first, each line's message where a
 * narrow column keeps it. Under 400 pixels the columns a phone can do
 * without are hidden.
 *
 * Through the typed client on the host's ask callback (`rpc_ask.h`).
 * NO Q_OBJECT AND THEREFORE NO moc.
 */
#ifndef FZN_GUI_REACH_VIEW_H
#define FZN_GUI_REACH_VIEW_H

#include "notebook_view.h"

#include <QString>
#include <QStringList>
#include <QWidget>

class QLabel;
class QPushButton;
class QResizeEvent;
class QTreeWidget;
struct fzn_gui_rpc;

class fzn_reach_view : public QWidget {
public:
	fzn_reach_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent = nullptr);
	~fzn_reach_view() override;

	/* Ask all three and show them. Whether the node answered. */
	bool refresh();

	/* WHAT A PERSON DOES, public because a headless test cannot click. */
	bool ask_outside();
	bool look_here();
	/* The report in row `row` of `seen_by()` advertised as this host's
	 * address; whether the node took it. */
	bool advertise(int row);

	/* WHAT IS ON SCREEN: the outside line, each report as "ADDRESS -- WHO
	 * -- WHEN", the hosts found here as "ADDRESS -- KEY -- WHEN", the
	 * relay line and each peer as "PEER -- USED -- REFUSED", the status
	 * line. */
	QString outside() const;
	QStringList seen_by() const;
	QStringList found() const;
	QString relay() const;
	QStringList relayed() const;
	QStringList activity() const;
	QString keeping_up() const;
	QString status() const;

protected:
	void resizeEvent(QResizeEvent *event) override;

private:
	void narrow(bool yes);

	struct fzn_gui_rpc *m_rpc;

	QLabel *m_outside;
	QTreeWidget *m_seen_by;
	QPushButton *m_ask_outside;
	QPushButton *m_advertise;
	QTreeWidget *m_found;
	QPushButton *m_look_here;
	QLabel *m_relay;
	QTreeWidget *m_relayed;
	QTreeWidget *m_activity;
	QLabel *m_load;
	QPushButton *m_refresh;
	QLabel *m_status;
};

#endif /* FZN_GUI_REACH_VIEW_H */
