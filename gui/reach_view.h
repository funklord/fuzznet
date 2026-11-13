/*
 * How this host is reached, as a widget: fuzznet sec 1134.
 *
 * Three things fuzzypickles' Connection page drew by hand: where other
 * hosts see this one from outside, and how many of them agree (one
 * report alone is a guess, sec 1125); which hosts answered on this
 * network; and whether this host relays for others, at what quota, and
 * for whom. A person asks again for each of the first two.
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
class QListWidget;
class QPushButton;
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

	/* WHAT IS ON SCREEN: the outside line, the hosts found here, the relay
	 * line, the status line. */
	QString outside() const;
	QStringList found() const;
	QString relay() const;
	QString status() const;

private:
	struct fzn_gui_rpc *m_rpc;

	QLabel *m_outside;
	QPushButton *m_ask_outside;
	QListWidget *m_found;
	QPushButton *m_look_here;
	QLabel *m_relay;
	QPushButton *m_refresh;
	QLabel *m_status;
};

#endif /* FZN_GUI_REACH_VIEW_H */
