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

#include <QHash>
#include <QColor>
#include <QString>
#include <QStringList>
#include <QVector>
#include <QWidget>

#include <functional>
#include <stdint.h>

class QLabel;
class QPushButton;
class QResizeEvent;
class QTreeWidget;
class QTreeWidgetItem;
struct fzn_gui_rpc;

/* How long a deletion asked for once waits to be chosen again. */
#define FZN_CONVERSATIONS_CONFIRM_S 10

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
	/* A CONTACT'S BADGE beside its name, sec 1232, from whatever the host
	 * keeps -- a location view's `badge_for`, say: the text for a name,
	 * empty for none, and `*stale` set where it should be dimmed. Read at
	 * each refresh. */
	void set_badge(std::function<QString(const QString &name, bool *stale)> badge);
	/* WHY A ROW'S ACTION CANNOT BE TAKEN, where it is offered disabled --
	 * empty where it can. As `actions` last offered it. */
	QString refused(const QString &action) const;

	/* A CONTACT'S PICTURE WHERE THERE IS NONE, sec 1264, fuzzypickles' walk
	 * against LINE: the name's initial in a circle of a colour the name
	 * picks, the same everywhere for one name, dark enough that its white
	 * initial clears 4.5:1 (WCAG). The circle is the initial's own ground,
	 * so it needs nothing of the desktop's. Shown on a phone's flat list. */
	static QColor initial_colour(const QString &name);
	/* ONE LIST ON A PHONE, sec 1245: whether the rows are shown flat --
	 * contacts and groups together, newest first, a group marked -- not
	 * under two headings. `open` and `act` count a kind's rows either way. */
	bool flat() const;

	/* WHAT IS ON SCREEN: each heading, then each conversation beneath it
	 * indented, as shown; the status line. */
	QStringList shown() const;
	QString status() const;

protected:
	/* UNDER 400 PIXELS, one list; wider, two headings (sec 1245). */
	void resizeEvent(QResizeEvent *event) override;

private:
	void lay_out();
	void members_menu(const QString &group, QStringList *out);
	bool member_act(const QString &group, const QString &action);
	/* A deletion asked for once, by group, and when: chosen again in time,
	 * it is done (sec 1246). */
	QString m_armed;
	qint64 m_armed_at = 0;
	/* A ROW AS READ, kept to lay out again at another width. */
	struct row {
		QString name, text, when, open;
		size_t unread;
		int kind;
	};
	QVector<row> m_rows;
	bool m_flat = false;
	QTreeWidgetItem *row_item(int group, int row) const;
	int sharing(const QString &contact);
	/* A GROUP'S MEMBERS THIS USER CAN NAME, this user not among them; 0
	 * when the node could not say. */
	bool callable(const QString &group, QStringList *who);
	std::function<QString(const QString &, bool *)> m_badge;
	/* Each action `actions` offered disabled, with why. */
	QHash<QString, QString> m_refused;

	struct fzn_gui_rpc *m_rpc;
	std::function<void(const QString &)> m_open;
	std::function<void(const QString &, const QString &)> m_act;
	uint32_t m_now;

	QTreeWidget *m_tree;
	QPushButton *m_refresh;
	QLabel *m_status;
};

#endif /* FZN_GUI_CONVERSATIONS_VIEW_H */
