/*
 * This user's other hosts, as a widget: fuzznet sec 1124.
 *
 * Each of the user's hosts this one knows -- its name, its key's first
 * bytes, where it is reached, and whether either holds a pairing to the
 * other, as the node judged it when it listed them. A person sets where one
 * is reached, by HOST:PORT.
 *
 * AND A BACKUP OF THIS HOST, sec 1133: its keys and state copied by the node
 * into an empty directory of this user's, with the warning that matters
 * said first -- whoever holds the copy can act as this host.
 *
 * ADMIN, sec 1157 (fuzzypickles' hosts page, inbox 20261114T0128Z): a chosen
 * host made an admin -- the node grants it and answers the chain, shown for
 * the person to carry to that host -- and a chain given to THIS host
 * applied, after which its node starts again in place to act with it
 * (`set admin`, fuzznet sec 658); and whom this host has granted admin,
 * named as its hosts, standing or revoked.
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
	bool back_up(const QString &dir);
	bool make_admin();
	void set_chain_text(const QString &chain);
	bool apply_chain();

	/* WHAT IS ON SCREEN: each host as its cells joined by " | ", the
	 * address line, and the status line. */
	QStringList rows() const;
	QString address_text() const;
	QString status() const;
	/* The chain a grant answered, to carry to its host; and whom this host
	 * has granted admin, as said. */
	QString granted_chain() const;
	QStringList granted() const;

private:
	struct fzn_gui_rpc *m_rpc;

	QTableWidget *m_table;
	QLineEdit *m_address;
	QPushButton *m_set;
	QPushButton *m_refresh;
	QLineEdit *m_backup_dir;
	QPushButton *m_back_up;
	QPushButton *m_make_admin;
	QLineEdit *m_given;   /* the chain a grant answered, read-only */
	QLineEdit *m_chain;   /* a chain given to this host */
	QPushButton *m_apply;
	QLabel *m_granted;
	QStringList m_granted_said;
	QLabel *m_status;
};

#endif /* FZN_GUI_HOSTS_VIEW_H */
