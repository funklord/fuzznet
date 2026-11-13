/*
 * Every conversation, as a list, as a widget: fuzznet sec 1138.
 *
 * What a messenger opens on (fuzzypickles inbox 1553Z, item 3): contacts
 * and groups under two headings, newest first, each with its newest line
 * and when it came ("you: see you at 8", "a file: photo.jpg", "a sticker:
 * waving") and how many lines are unread. Two requests a refresh, whatever
 * the user holds: `list message newest` (sec 1136) and `list message unread`
 * (sec 1084), with the names from the contact and group listings.
 *
 * Choosing a conversation tells the host, which opens it -- a contact by
 * its name, a group as `@NAME`, as `conversation_view` takes them.
 *
 * Lines and names are other people's words, in caret form (sec 1126).
 *
 * EACH ROW'S MENU (sec 1144, fuzzypickles 1553Z item 3): a contact's
 * offers sending a file, a call, a video call, and sharing this user's
 * location with it or no longer; a group's offers sending a file, calling
 * everyone in it, and its members and admins. Sharing is done here; the
 * rest is the host's, told what and to whom -- a contact's name, `@NAME`
 * for a group, and for calling a group its members' names joined by
 * commas, as `fzn_call_view::call` takes them.
 * Through the typed client on the host's ask callback (`rpc_ask.h`).
 * NO Q_OBJECT AND THEREFORE NO moc.
 */
#ifndef FZN_GUI_CONVERSATIONS_VIEW_H
#define FZN_GUI_CONVERSATIONS_VIEW_H

#include "notebook_view.h"

#include <QString>
#include <QStringList>
#include <QWidget>

#include <functional>
#include <stdint.h>

class QLabel;
class QPushButton;
class QTreeWidget;
class QTreeWidgetItem;
struct fzn_gui_rpc;

class fzn_conversations_view : public QWidget {
public:
	fzn_conversations_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent = nullptr);
	~fzn_conversations_view() override;

	/* Ask for every conversation and show them. Whether the node answered. */
	bool refresh();

	/* WHAT TO DO WHEN ONE IS CHOSEN: given the contact's name, or `@NAME`. */
	void on_open(std::function<void(const QString &)> open);

	/* WHAT A PERSON DOES, public because a headless test cannot click:
	 * choose the `row`th conversation under contacts (`group` 0) or groups
	 * (1), counted from 0 as shown. */
	bool open(int group, int row);

	/* WHAT TO DO WITH A ROW'S MENU CHOICE the host carries out: `what` is
	 * file, call, video or members, `to` as above. */
	void on_action(std::function<void(const QString &what, const QString &to)> act);

	/* A row's menu as offered, and choosing from it -- public because a
	 * headless test cannot open a menu. */
	QStringList actions(int group, int row);
	bool act(int group, int row, const QString &action);

	/* The clock, seconds since 1970; 0 reads the system's. */
	void set_now(uint32_t utc_s);

	/* WHAT IS ON SCREEN: each heading, then each conversation beneath it
	 * indented, as shown; the status line. */
	QStringList shown() const;
	QString status() const;

private:
	QTreeWidgetItem *row_item(int group, int row) const;
	int sharing(const QString &contact);

	struct fzn_gui_rpc *m_rpc;
	std::function<void(const QString &)> m_open;
	std::function<void(const QString &, const QString &)> m_act;
	uint32_t m_now;

	QTreeWidget *m_tree;
	QPushButton *m_refresh;
	QLabel *m_status;
};

#endif /* FZN_GUI_CONVERSATIONS_VIEW_H */
