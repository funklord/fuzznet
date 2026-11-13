/*
 * This user's other hosts, as a widget: fuzznet sec 1124.
 *
 * Each of the user's hosts this one knows -- its name, its key's first
 * bytes, where it is reached, and whether either holds a pairing to the
 * other, as the node judged it when it listed them. A person sets where one
 * is reached, by HOST:PORT.
 *
 * NOT HERE, ON PURPOSE: removing a host. A person who has lost a phone and
 * finds a Remove button beside it will take it for the end of that phone's
 * access, and it is not -- a lost device's grant ends by k votes to revoke
 * it, which the governance view asks for. The view says where that is.
 *
 * Through the typed client on the host's ask callback (`rpc_ask.h`), as the
 * contacts and devices views are. NO Q_OBJECT AND THEREFORE NO moc.
 */
#ifndef FZN_GUI_HOSTS_VIEW_H
#define FZN_GUI_HOSTS_VIEW_H

#include "notebook_view.h"

#include <QString>
#include <QStringList>
#include <QWidget>

class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;
struct fzn_gui_rpc;

class fzn_hosts_view : public QWidget {
public:
	fzn_hosts_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent = nullptr);
	~fzn_hosts_view() override;

	/* Ask for this user's hosts and show them. Whether the node answered. */
	bool refresh();

	/* WHAT A PERSON DOES, public because a headless test cannot click. */
	void select(int row);
	void set_address_text(const QString &address);
	bool set_address();

	/* WHAT IS ON SCREEN: each host as its cells joined by " | ", the
	 * address line, and the status line. */
	QStringList rows() const;
	QString address_text() const;
	QString status() const;

private:
	struct fzn_gui_rpc *m_rpc;

	QTableWidget *m_table;
	QLineEdit *m_address;
	QPushButton *m_set;
	QPushButton *m_refresh;
	QLabel *m_status;
};

#endif /* FZN_GUI_HOSTS_VIEW_H */
