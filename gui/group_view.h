/*
 * One group's members, as a widget: fuzznet sec 1143.
 *
 * The group half of fuzzypickles' conversation row menu (inbox 1553Z, item
 * 3): who is in the group and who of them is an admin, this user marked
 * "you"; for an admin, adding one of this user's contacts, removing a
 * member, and making a member an admin or no longer one -- a PROPOSAL until
 * a majority of the admins asks the same (secs 627, 1012), said with how
 * many have; whether a member added later gets the earlier lines (sec 625);
 * and leaving the group, which forgets it here.
 *
 * A member who is no contact of this user is named by what the roster can
 * say of it and cannot be acted on by name, since every verb names a
 * contact. Through the typed client on the host's ask callback
 * (`rpc_ask.h`). NO Q_OBJECT AND THEREFORE NO moc.
 */
#ifndef FZN_GUI_GROUP_VIEW_H
#define FZN_GUI_GROUP_VIEW_H

#include "notebook_view.h"

#include <QString>
#include <QStringList>
#include <QWidget>

class QCheckBox;
class QComboBox;
class QLabel;
class QListWidget;
class QPushButton;
struct fzn_gui_rpc;

class fzn_group_view : public QWidget {
public:
	fzn_group_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent = nullptr);
	~fzn_group_view() override;

	/* Which group, by its name; refresh() then shows it. */
	void set_group(const QString &name);

	/* Ask for its members, the contacts not in it, and its earlier-lines
	 * setting. Whether the node answered. */
	bool refresh();

	/* WHAT A PERSON DOES, public because a headless test cannot click.
	 * A row is a member, counted from 0 as shown. */
	bool add_member(const QString &contact);
	bool remove_member(int row);
	bool set_admin(int row, bool make);
	bool set_earlier(bool on);
	bool leave();

	/* WHAT IS ON SCREEN: each member as said, the contacts offered to add,
	 * whether this user may change who is in it, and the status line. */
	QStringList members() const;
	QStringList addable() const;
	bool may_change() const;
	bool earlier() const;
	QString status() const;

private:
	QString member_name(int row) const;
	void enable();

	struct fzn_gui_rpc *m_rpc;
	QString m_group;
	bool m_admin;

	QLabel *m_title;
	QListWidget *m_members;
	QComboBox *m_contacts;
	QPushButton *m_add;
	QPushButton *m_remove;
	QPushButton *m_make_admin;
	QPushButton *m_unmake_admin;
	QCheckBox *m_earlier;
	QPushButton *m_leave;
	QLabel *m_status;
};

#endif /* FZN_GUI_GROUP_VIEW_H */
