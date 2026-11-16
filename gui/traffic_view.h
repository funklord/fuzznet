/*
 * What this node has moved, by family and by host: project.md sec 1182,
 * the register's "a hostable transfer view" (sec 1070). fuzzypickles drew
 * this as its Transfers tab over `fzn_rpc_transfer_list`; by the register's
 * rule it is fuzznet's, and this is it, hosted as the other views are.
 *
 * NAMED `traffic`, not `transfer`, because `transfer_view` is already the
 * one blob being assembled (sec 179), a different question: that view says
 * how far one file has come, this one what every family and every peer is
 * moving now. The daemon calls its meter `traffic` (node/daemon.c).
 *
 * A DISPLAY OF THE DAEMON'S NUMBERS, not its own accounting: the daemon is
 * the only party that sees bytes cross a socket and the only one with a
 * clock, so it counts and samples, and this asks and draws. A view that kept
 * totals of its own would disagree with the daemon's the moment either
 * started again.
 *
 * TWO TREES, one by family and one by host, each parent from the daemon's
 * own sums -- a family's bytes with its evicted rows' in, a host's from every
 * row -- and the rows that fitted beneath it, "3 of 40" where fewer arrived
 * than it holds. A parent built by adding up its children would report one
 * frame of a table as the whole and drop a host whose rows were all cut.
 *
 * WHAT WAS OPEN STAYS OPEN across a refresh, by key, since a host refreshes
 * this on a timer and a tree that collapsed each second could not be read.
 *
 * A FILE IS NAMED from the library (`fzn_rpc_library_list`), where this user
 * named it; a file nobody here named -- serving somebody else's fetch -- is
 * its root, abbreviated, which is the honest label.
 *
 * NO MOC, like the rest of gui/: `refresh` is the host's to call.
 */
#ifndef FZN_GUI_TRAFFIC_VIEW_H
#define FZN_GUI_TRAFFIC_VIEW_H

#include "notebook_view.h"

#include <QString>
#include <QWidget>

class QLabel;
class QTreeWidget;
struct fzn_gui_rpc;

class fzn_traffic_view : public QWidget {
public:
	fzn_traffic_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent = nullptr);
	~fzn_traffic_view() override;

	/* Ask the node and draw; whether it answered. A node that did not is
	 * said so on the summary line, and the trees keep what they last held. */
	bool refresh();

	/* What is on the screen. */
	QString summary() const;
	QTreeWidget *by_family() const { return by_family_; }
	QTreeWidget *by_host() const { return by_host_; }

private:
	fzn_gui_rpc *rpc_;
	QLabel *summary_;
	QTreeWidget *by_family_;
	QTreeWidget *by_host_;
};

#endif /* FZN_GUI_TRAFFIC_VIEW_H */
