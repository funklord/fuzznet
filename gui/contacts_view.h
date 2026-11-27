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
#include "press_again.h"

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
	/* MAKING A CONTACT, sec 1484: this host's card as text -- `FZC1:...`,
	 * what the other side adds -- or empty where the node gave none; and
	 * the other side's card added, asking them to be a contact under
	 * `name` (the name their card offers where empty). The buttons copy the
	 * one and ask for the other. */
	QString my_card();
	/* WHERE THIS HOST IS REACHED, CHOSEN, sec 1539: a card is refused
	 * while this host has no address, and the addresses its peers report
	 * seeing it at are then offered on a row of their own. What is
	 * offered, and the one at `row` written as this host's address -- the
	 * card shown after. */
	QStringList card_addresses() const;
	bool use_card_address(int row);
	bool add_contact(const QString &card, const QString &name);

	/* WHAT IS ON SCREEN: each contact as NAME KEY16, each request as
	 * PROPOSED KEY16, the name line, and the status line. */
	QStringList contacts() const;
	QStringList requests() const;
	QString name() const;
	QString status() const;
	/* WHAT THE CHOSEN CONTACT MAY FETCH from this host, sec 1504: its
	 * files by name, read as it is chosen (`get file shared NAME`). */
	QString shared() const;

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
	QPushButton *m_my_card;
	QPushButton *m_add;
	QWidget *m_card_row;
	QWidget *m_address_row = nullptr;
	class QComboBox *m_card_address = nullptr;
	/* The refusal and its offer, when the card has no address. */
	bool offer_card_addresses(const QString &refused);
	QString m_name_for; /* the row the name box was filled for */
	fzn_press_again m_again; /* Reject and Remove asked again, sec 1515 */
	QLineEdit *m_card;
	QLabel *m_status;
	QLabel *m_shared;
	void read_shared(const QString &name);
};

#endif /* FZN_GUI_CONTACTS_VIEW_H */
