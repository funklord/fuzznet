/*
 * The notes surface as a widget other software hosts. sec 439, phase 5 of
 * the notes move.
 *
 * fuzzypickles' `notes_widget` spoke its own control protocol to its own
 * daemon; this one speaks fuzznet's local grammar -- the note, share and
 * received verbs of `node/notes.h` and `node/admin.h` -- one request line at
 * a time. What it needs from its host is exactly two things, as theirs did: a
 * way to ask the node, handed in, and somewhere to say what happened.
 *
 * THE WAY TO ASK IS A CALLBACK, not a socket: `fzn_notebook_view_socket_ask`
 * is the one a host uses, over `local/client`, and a test hands in one that
 * answers through `node/notes.c` in the same process. So the widget is tested
 * against the real verbs and no daemon.
 *
 * WHAT IT CARRIES FROM fuzzypickles, as sec 422 listed:
 *
 *   - THE UN-SHARE WARNING, before anybody shares: what a contact has
 *     fetched stays with them, and unsharing stops only what comes next.
 *     Said beside the controls rather than in a dialog, so it is read before
 *     the click and not after.
 *   - A NODE THAT DOES NOT ANSWER SAYS SO. Their sec 112 found the widget
 *     showing an empty notebook and saying nothing when the daemon was
 *     unreachable; a hosted widget has no status line of the window's to
 *     lean on, so it owes its host the state itself. "Nothing here yet" and
 *     "the node did not answer" are different words.
 *   - A REFRESH KEEPS THE READER'S PLACE. Their b32b2c7: restoring the open
 *     note's selection scrolled the list back to it on every poll.
 *
 * A SHARED TREE IS READ-ONLY HERE as it is at the node: picking a contact's
 * tree turns the editing controls off, and every read goes through `list
 * shared` and `get shared`.
 *
 * TEXT TRAVELS THROUGH FILES. A request line is 512 bytes and a note's text
 * may be 256 KiB with newlines in it, so saving writes a temporary file and
 * asks `set note ID file PATH`, and opening asks `get note ID file PATH` --
 * which opens a blob as readily as an inline text. The node reads and writes
 * them as itself, which is why the verbs need the node's own user.
 *
 * NO Q_OBJECT AND THEREFORE NO moc, on sec 140's rule: buttons connect to
 * lambdas, and the log is a callback rather than a signal.
 */

#ifndef FZN_GUI_NOTEBOOK_VIEW_H
#define FZN_GUI_NOTEBOOK_VIEW_H

#include <QByteArray>
#include <QList>
#include <QString>
#include <QStringList>
#include <QWidget>

#include <cstddef>
#include <functional>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QListWidget;
class QPlainTextEdit;
class QPushButton;

/* Send one request line, without its newline, and write the reply line into
 * `reply`; the reply's length, or 0 when the node did not answer. */
typedef size_t (*fzn_notebook_view_ask_t)(void *ctx, const char *line, char *reply,
                                         size_t reply_cap);

/* The host's: `ctx` is the node's socket path, a `const char *`. */
size_t fzn_notebook_view_socket_ask(void *ctx, const char *line, char *reply, size_t reply_cap);

class fzn_notebook_view : public QWidget {
public:
	fzn_notebook_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent = nullptr);

	/* One line for the host's log: what was done, or why it was not. */
	void set_log(std::function<void(const QString &)> log) { m_log = std::move(log); }

	/* Re-read the trees, the open folder and the open note. The host calls
	 * it when the surface is shown and on its own timer; nothing here polls. */
	void refresh();

	/* THE ACTIONS, public because a headless test cannot drive the input
	 * dialogs and double-clicks that reach them. Each says what happened
	 * through the log, and returns whether the node took it. */
	bool open_tree(const QString &contact); /* empty for this user's own */
	bool descend(const QString &id, const QString &title);
	bool ascend();
	bool open_note(const QString &id);
	bool new_note(const QString &title);
	bool new_folder(const QString &title);
	/* CHECKLISTS, sec 442: a list's items are lines `[ ] text` and
	 * `[x] text` in the body, which is read-only for a list; they change
	 * one at a time through these. */
	bool new_list(const QString &title);
	bool add_item(const QString &text);
	bool toggle_item(int index);
	/* sec 453: the item at `index` goes, and the ones after move up. */
	bool remove_item(int index);
	/* MOVING, sec 453: cut the open note, open the folder it goes to, and
	 * move it there. The node refuses a folder under its own descendant. */
	bool cut();
	bool move_here();
	bool save();
	bool trash();
	bool restore();
	bool empty_trash();
	bool share_with(const QString &contact);
	bool unshare_with(const QString &contact);
	void show_trash(bool on);
	/* PINNED AND ARCHIVED, sec 444: a pinned note is marked and listed
	 * first; archived notes are a view of their own, as the trash is. */
	void show_archived(bool on);
	bool pin(bool on);
	bool archive(bool on);
	/* A KNotes .ics, a Keep .json or a Takeout directory into the folder
	 * open, sec 440; the Import button reaches it behind a file dialog. */
	bool import_file(const QString &path);

	/* WHAT IS ON SCREEN, for a host and a test. */
	QListWidget *list() const { return m_list; }
	QString status() const;
	QString location() const;
	QString title_text() const;
	QString body_text() const;
	QString shared_with() const;
	QString warning() const;
	bool editable() const;
	QString open_id() const { return m_open; }
	/* The note cut and waiting to be moved; empty when none is. */
	QString cut_id() const { return m_cut; }
	/* The ids listed, in order, as the list shows them. */
	QStringList listed_ids() const;

private:
	/* One request; the reply's detail past the status word into `detail`,
	 * and its status: 1 ok, 0 refused (detail says why), -1 no answer. */
	int ask(const QString &line, QString *detail);
	void say(const QString &line);
	void refresh_trees();
	void refresh_list();
	void refresh_note();
	void refresh_shares();
	void set_status(const QString &text);
	bool shared() const { return !m_tree.isEmpty(); }
	QString parent_id() const;

	fzn_notebook_view_ask_t m_ask;
	void *m_ask_ctx;
	std::function<void(const QString &)> m_log;

	/* Whose tree: empty is this user's own, else a contact's name. */
	QString m_tree;
	/* The folders open, from the top, and their titles for the location. */
	QStringList m_path;
	QStringList m_path_titles;
	/* The note in the editor, as hex; empty composing nothing. */
	QString m_open;
	/* The note cut for a move, and its title for saying so. */
	QString m_cut;
	QString m_cut_title;
	bool m_trash = false;
	/* Whether the open note is a checklist, and its items' ticks. */
	bool m_is_list = false;
	bool m_archived = false;
	/* The open note's flags, as `get note` gave them. */
	unsigned m_flags = 0;
	QList<bool> m_ticks;
	/* Set while a refresh rewrites the tree chooser, so its change is not
	 * taken for somebody picking a tree. */
	bool m_updating = false;
	/* Whether the last request was answered, and what the list held. */
	bool m_answered = true;

	QComboBox *m_trees;
	QLabel *m_location;
	QLabel *m_status;
	QPushButton *m_up;
	QListWidget *m_list;
	QCheckBox *m_show_trash;
	QCheckBox *m_show_archived;
	QPushButton *m_pin;
	QPushButton *m_archive;
	QLineEdit *m_title;
	QPlainTextEdit *m_body;
	QPushButton *m_new_note;
	QPushButton *m_new_folder;
	QPushButton *m_save;
	QPushButton *m_trash_button;
	QPushButton *m_restore;
	QPushButton *m_empty;
	QPushButton *m_import;
	QPushButton *m_new_list;
	QLineEdit *m_item_text;
	QPushButton *m_add_item;
	QPushButton *m_toggle;
	QPushButton *m_remove_item;
	QPushButton *m_cut_button;
	QPushButton *m_move_here;
	QComboBox *m_share_to;
	QPushButton *m_share;
	QPushButton *m_unshare;
	QLabel *m_shared_with;
	QLabel *m_warning;
};

#endif /* FZN_GUI_NOTEBOOK_VIEW_H */
