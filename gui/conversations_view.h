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
#include <QFontMetrics>
#include <QString>
#include <QStringList>
#include <QVector>
#include <QWidget>

#include <functional>
#include <stdint.h>

class QLabel;
class QLineEdit;
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
	/* A NEW GROUP named `name`, this user its only member until members are
	 * added from its menu (sec 1483): whether the node made it, said either
	 * way. The New group button asks the name and calls this. */
	bool create_group(const QString &name);
	/* THE NAME ASKED INLINE, sec 1496: New group shows a line under the
	 * list for the name, no dialog; `ask_group_name` is that button. */
	void ask_group_name();

	/* WHAT TO DO WHEN ONE IS CHOSEN: given the contact's name, or `@NAME`.
	 * One click or tap opens it (sec 1496), as a messenger's list does. */
	void on_open(std::function<void(const QString &)> open);
	/* THE OPEN ONE, sec 1496: on a desktop it stays chosen in the list,
	 * across refreshes, and the host may set it -- a contact by name, a
	 * group by its name with `is_group`. Whether it is listed. */
	bool select(const QString &name, bool is_group);
	QString chosen() const;
	/* TOLD WHEN THE CHOICE CHANGES: what is chosen now (empty for none),
	 * and whether a person chose it or a refresh lost it. */
	void on_chosen(std::function<void(const QString &to, bool by_person)> told) { m_chosen_told = told; }
	/* THE CHOSEN ONE'S MENU, for a phone's More button: its actions, and
	 * the menu shown under `at` (global). Empty, and nothing shown, with
	 * none chosen. */
	QStringList chosen_actions();
	bool act_chosen(const QString &action);
	void show_chosen_menu(const QPoint &at);
	/* COUNTS FOR A HOST'S STATUS STRIP AND TASKBAR, sec 1496: contacts and
	 * groups listed, and the unread lines across them all; changed at once
	 * by `mark_read`, which a host calls as it marks one read. */
	int contacts_count() const;
	int groups_count() const;
	size_t unread_total() const;
	void mark_read(const QString &to);
	/* THE HOST'S CONTROLS (sec 1496): the Refresh and New group buttons
	 * and the status line hidden where the host has its own; the layout
	 * pinned flat (1) or under headings (0), or by width (-1). */
	void set_controls_shown(bool shown);
	/* EVERY ACT'S RESULT OR REFUSAL, said on the status line and told here
	 * (sec 1508), for a host whose own controls hide that line. */
	void on_notice(std::function<void(const QString &line)> told) { m_notice_told = told; }
	/* A GROUP'S MEMBERS OR ADMINS CHANGED from its menu: the group named,
	 * so a roster the host shows follows at once (sec 1508). */
	void on_members_changed(std::function<void(const QString &group)> told) { m_members_told = told; }
	/* NEW GROUP HANDED TO THE HOST, which opens a `fzn_new_group_view`
	 * of its own -- several at once if it likes (sec 1508); unset, the
	 * name is asked on a line under the list. */
	void on_new_group(std::function<void()> told) { m_new_group_told = told; }
	/* LOCATION SHARED OR NO LONGER, from a contact's menu, once the node
	 * took it (sec 1513): the contact and which, so the host says what is
	 * true of this device -- location off here, a permission to ask. */
	void on_location_shared(std::function<void(const QString &contact, bool on)> told) { m_location_told = told; }
	void set_layout(int flat);
	/* WHETHER THE OPEN ONE STAYS CHOSEN (sec 1512): 1 as on a desktop, 0 as
	 * on a phone, where opening leaves the list; -1, the default, by the
	 * flat layout -- a host whose phone keeps headings says 0. */
	void set_keep_chosen(int keep);

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
	/* BY KEY, sec 1496: two contacts sharing a name look different. */
	static QColor key_colour(const QByteArray &key);
	/* WHAT A ROW SHOWS IN `width` px, sec 1517: the name whole, and only
	 * the rest after it cut -- the name itself cut only when it alone does
	 * not fit. */
	static QString row_shown(const QFontMetrics &fm, const QString &name, const QString &rest, int width);
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
		QByteArray key; /* the contact's key or the group's id, sec 1274 */
		size_t unread;
		uint64_t stime_ms; /* the newest line's, for the view's own order */
		QString standing; /* why a contact no longer active cannot be sent to, sec 1499 */
		QString waiting; /* how long its oldest line has waited undelivered, sec 1501 */
		int kind;
		int name_len = 0; /* how much of text is the name, sec 1517 */
	};
	/* READ MARKS FOR ONE CONVERSATION, sec 1274: "Read marks: ..." entries,
	 * the one standing marked; and choosing one. */
	void read_marks_menu(const QByteArray &key, QStringList *out);
	bool read_marks_act(const QByteArray &key, const QString &name, const QString &action);
	QVector<row> m_rows;
	/* How many conversations the last refresh had room for. */
	size_t m_room = 0;
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
	QPushButton *m_new_group;
	QLabel *m_status;
	QLineEdit *m_group_name;
	QPushButton *m_make_group;
	QWidget *m_group_row;
	QString m_chosen, m_last_open, m_restored;
	qint64 m_last_open_at = 0;
	int m_layout_pin = -1, m_keep_chosen = -1;
	std::function<void(const QString &, bool)> m_chosen_told;
	std::function<void(const QString &)> m_notice_told, m_members_told;
	std::function<void()> m_new_group_told;
	std::function<void(const QString &, bool)> m_location_told;
	void say(const QString &line);
	void opened(const QString &to);
	void show_menu(QTreeWidgetItem *item, const QPoint &at);
};

#endif /* FZN_GUI_CONVERSATIONS_VIEW_H */
