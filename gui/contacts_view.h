/*
 * A user's contacts and the requests waiting to become contacts, as a widget
 * other software hosts, sec 1107 -- the register's "a contacts view" (sec
 * 1070), which every consumer showing who it talks to was writing alone.
 *
 * TWO LISTS: the contacts, each a name and the first bytes of its user's key;
 * and the pairing requests waiting here, each the name the requester PROPOSES
 * beside its host's key. A request is unauthenticated until it is approved,
 * so its proposed name is never shown without the key the decision rests on
 * (the client refuses a name carrying a control character, rpc_limits.h).
 *
 * WHAT A PERSON DOES: approve a request under a name of their own -- the
 * proposed one offered -- or reject it; rename a contact, which is how two
 * holding one name come apart (sec 893); remove one. A contact in a state
 * (sec 1118) is listed with it; one removed on another host, or held by none
 * whose record stands, may be added back -- the same `add contact NAME KEY`
 * a rename asks, so the button says which it does. One removed for good is
 * not renamed or added back here.
 *
 * Through the typed client on the host's ask callback (`rpc_ask.h`), as the
 * objects and settings views are; the node's refusals in its words, and a
 * node that does not answer said to be so. NO Q_OBJECT AND THEREFORE NO moc.
 */

#ifndef FZN_GUI_CONTACTS_VIEW_H
#define FZN_GUI_CONTACTS_VIEW_H

#include "notebook_view.h"

#include <QString>
#include <QStringList>
#include <QWidget>

struct fzn_gui_rpc;
class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;

class fzn_contacts_view : public QWidget {
public:
	fzn_contacts_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent = nullptr);
	~fzn_contacts_view() override;

	/* Ask for the contacts and the requests and show both. Whether the node
	 * answered. */
	bool refresh();

	/* WHAT A PERSON DOES, public because a headless test cannot click. The
	 * name is the line typed: a request's local name, a contact's new one. */
	void select_contact(int row);
	void select_request(int row);
	void set_name(const QString &name);
	bool approve();
	bool reject();
	bool rename();
	bool remove();

	/* WHAT IS ON SCREEN: each contact as NAME KEY16, each request as
	 * PROPOSED KEY16, the name line, and the status line. */
	QStringList contacts() const;
	QStringList requests() const;
	QString name() const;
	QString status() const;

private:
	struct fzn_gui_rpc *m_rpc;
	struct keys;
	keys *m_keys; /* each row's full key, contacts' and requests' */

	QTableWidget *m_contacts;
	QTableWidget *m_requests;
	QLineEdit *m_name;
	QPushButton *m_approve;
	QPushButton *m_reject;
	QPushButton *m_rename;
	QPushButton *m_remove;
	QPushButton *m_refresh;
	QLabel *m_status;
};

#endif /* FZN_GUI_CONTACTS_VIEW_H */
