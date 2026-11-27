/*
 * A new group with its members, as a widget: fuzznet sec 1508, from
 * fuzzypickles' form (its sec 210, asked by the holder 2026-10-08), which it
 * keeps until this has what it does (inbox 20261127T0627Z).
 *
 * Three steps, each on the widget in turn:
 *   1. THE NAME, and Create: the group exists from then, this user its
 *      only member.
 *   2. THE MEMBERS: this user's contacts, ticked and added in one go, or
 *      skipped. Only an active contact with a verified identity can be
 *      ticked: one added from a bare prekey has no root key, and a group
 *      names its members by root key, so it is shown but cannot be ticked,
 *      saying why (sec 1502).
 *   3. READY: who is in it, who could not be added and why, and Open the
 *      group, which tells the host `@NAME` as the conversations list does.
 *
 * NOT MODAL, and nothing here stops a host having several open at once --
 * a window each on a desktop, a page each on a phone. `title` says which
 * one this is, for a host listing those in progress.
 *
 * Through the typed client on the host's ask callback (`rpc_ask.h`).
 * NO Q_OBJECT AND THEREFORE NO moc.
 */
#ifndef FZN_GUI_NEW_GROUP_VIEW_H
#define FZN_GUI_NEW_GROUP_VIEW_H

#include "notebook_view.h"

#include <QString>
#include <QStringList>
#include <QWidget>

#include <functional>

class QLabel;
class QLineEdit;
class QListWidget;
class QPushButton;
class QStackedLayout;
struct fzn_gui_rpc;

class fzn_new_group_view : public QWidget {
public:
	fzn_new_group_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent = nullptr);
	~fzn_new_group_view() override;

	/* WHICH STEP IS SHOWN: 1 the name, 2 the members, 3 ready. */
	int step() const;
	/* What a host lists this one by: "New group" until it is made, then
	 * its name. */
	QString title() const;

	/* WHAT A PERSON DOES, public because a headless test cannot click. */
	bool create(const QString &name);
	/* The contacts offered, as shown; which can be ticked; ticking one. */
	QStringList contacts() const;
	bool tickable(const QString &contact) const;
	bool tick(const QString &contact, bool on);
	/* Every ticked contact added, or none: then ready. */
	bool add_ticked();
	void skip();
	/* READY: what is said of the group, and opening it. */
	QString summary() const;
	bool open();

	/* The host opens a conversation by `@NAME`, as on the list. */
	void on_open(std::function<void(const QString &to)> open) { m_open = open; }
	/* Every line said, for a host's log or notice. */
	void on_notice(std::function<void(const QString &line)> told) { m_notice_told = told; }
	QString status() const;

private:
	void say(const QString &line);
	void read_contacts();
	struct fzn_gui_rpc *m_rpc;
	QString m_name;
	QStringList m_added, m_failed;
	std::function<void(const QString &)> m_open, m_notice_told;
	QStackedLayout *m_steps;
	QLineEdit *m_name_edit;
	QListWidget *m_contacts;
	QLabel *m_summary;
	QLabel *m_status;
};

#endif /* FZN_GUI_NEW_GROUP_VIEW_H */
