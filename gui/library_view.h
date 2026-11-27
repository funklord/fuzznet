/*
 * The files this user's hosts and contacts have catalogued, as a widget:
 * fuzznet sec 1131.
 *
 * Each file the catalogue names -- its name, kind, size and length, and
 * where it is: here, on how many other hosts, or nowhere this host can see.
 * "Here" is this host's own bytes, never its published claim (the client's
 * rule since 2026-11-10: a claim is a claim). A person asks for a file not
 * held here; it arrives in the background from whoever holds it.
 *
 * WHAT A PERSON DOES ON A FILE HERE (sec 1156, fuzzypickles' library page,
 * inbox 20261114T0128Z): play it, through the host's player (`on_play`, the
 * root and its name -- snurra's, which plays a file still arriving); share
 * it with every contact, a contact or a group, and see and take back whom it
 * is shared with; save it to a file; verify its pieces, a broken one
 * dropped to be fetched again; and remove this device's copy.
 *
 * Names and kinds are other hosts' words, shown in caret form (sec 1126).
 *
 * Through the typed client on the host's ask callback (`rpc_ask.h`).
 * NO Q_OBJECT AND THEREFORE NO moc.
 */
#ifndef FZN_GUI_LIBRARY_VIEW_H
#define FZN_GUI_LIBRARY_VIEW_H

#include "notebook_view.h"

#include <QString>
#include <QStringList>
#include <QWidget>

#include <functional>

class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QResizeEvent;
class QTableWidget;
struct fzn_gui_rpc;

class fzn_library_view : public QWidget {
public:
	fzn_library_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent = nullptr);
	~fzn_library_view() override;

	/* Ask for the library and show it. Whether the node answered. */
	bool refresh();

	/* THE HOST'S PLAYER, given the file's root and name. Play on a file held
	 * nowhere here asks for it first and hands it on at once: the host's
	 * player plays a file still arriving (sec 1493). */
	void on_play(std::function<void(const QByteArray &root, const QString &name)> play);
	/* EVERY LINE THE VIEW SAYS, for a host's log or notice (sec 1493). */
	void on_notice(std::function<void(const QString &line)> told) { m_notice_told = told; }

	/* WHAT A PERSON DOES, public because a headless test cannot click. */
	void select(int row);
	bool fetch();
	bool play();
	/* `to` a contact's name, `@NAME` a group, or empty for every contact. */
	bool share(const QString &to);
	bool unshare(const QString &to);
	/* SAVED, written private (0600): a file whole here through the node,
	 * and the playable part of one still arriving, or any file to a
	 * `content://` target a phone's picker gives, read slice by slice
	 * through the view (sec 1493). */
	bool save_to(const QString &path);
	bool verify();
	bool remove();
	/* CONFIRMED INLINE before they act (sec 1493): the question and its
	 * button on a line under the list, no dialog. `offered` is the
	 * question shown, `confirm` its button. */
	void ask_remove();
	void ask_share(const QString &to);
	QString offered() const;
	bool confirm();
	/* FILES ADDED to the library from this machine (sec 1485): each put in
	 * this host's store, private, and catalogued by its name and its kind
	 * as the system names it, which has the node read its tags and hear a
	 * tune. How many were added; the Add button asks which. */
	int add_files(const QStringList &paths);
	/* THE CHOSEN FILE'S DETAIL (secs 1493, 1497): which hosts hold it, by
	 * this user's names for them, and how much of it plays here and
	 * whether it is whole. */
	QString detail() const;
	/* NARROW, for a phone (sec 1493): Kind, Size and Length dropped. Set
	 * by the view's width unless the host pins its layout. */
	void set_narrow(bool narrow);
	bool narrow() const { return m_narrow; }

	/* FINDING A FILE, sec 1207: the files whose name or kind holds `text`,
	 * any case, and of the kind chosen -- empty for every kind. Both kept
	 * across a refresh; a kind no file has any more goes back to every
	 * kind. */
	void set_find(const QString &text);
	void set_kind(const QString &kind);
	/* The kinds offered, as the files say them, in order -- after "every
	 * audio kind" and its like, "audio/" and a star, for each family a file has. */
	QStringList kinds() const;

	/* Whom the chosen file is shared with, as said: "every contact", a
	 * contact's name, `@NAME`. */
	QStringList shares() const;

	/* WHAT IS ON SCREEN: each file shown as its cells joined by " | ", and
	 * the status line. */
	QStringList rows() const;
	QString status() const;

protected:
	void resizeEvent(QResizeEvent *event) override;

private:
	void say(const QString &line);
	bool save_slices(const QByteArray &root, const QString &path);
	void read_detail();
	QByteArray chosen_root() const;
	QString chosen_name() const;
	void read_shares();
	void apply_filter();

	struct fzn_gui_rpc *m_rpc;
	std::function<void(const QByteArray &, const QString &)> m_play;
	QStringList m_shares;

	QLineEdit *m_find;
	QComboBox *m_kind;
	QString m_filter_said;
	QTableWidget *m_table;
	QPushButton *m_play_button;
	QPushButton *m_share;
	QPushButton *m_save;
	QPushButton *m_add;
	QPushButton *m_verify;
	QPushButton *m_remove;
	QPushButton *m_fetch;
	QPushButton *m_refresh;
	QLabel *m_status;
	QLabel *m_detail;
	class fzn_notice_line *m_confirm;
	std::function<void(const QString &)> m_notice_told;
	bool m_narrow = false;
};

#endif /* FZN_GUI_LIBRARY_VIEW_H */
