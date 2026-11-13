/*
 * A conversation with one contact, as a widget: fuzznet sec 1126.
 *
 * The lines between this user and a contact, oldest at the top, each with
 * who wrote it and when; a line to write and Send; and the read position,
 * which the node holds and syncs between this user's devices (sec 528), set
 * at the newest line that came in each time the conversation is shown, so
 * reading it here reads it everywhere.
 *
 * A LINE IS UNTRUSTED TEXT, written by somebody else. It is shown in caret
 * form (`fzn_rpc_tty_escape`), since the same widget is drawn on a terminal
 * by qtty, where a raw escape in a line would act on the terminal.
 *
 * A GROUP is opened as `@NAME`: its lines in the order the node gives them
 * (sec 728), each member named by this user's contact for them, or their
 * key's first bytes where they are no contact; its read position is kept
 * by the group's id, which no rename moves (sec 1084).
 *
 * Through the typed client on the host's ask callback (`rpc_ask.h`), as the
 * contacts and devices views are. NO Q_OBJECT AND THEREFORE NO moc.
 */
#ifndef FZN_GUI_CONVERSATION_VIEW_H
#define FZN_GUI_CONVERSATION_VIEW_H

#include "notebook_view.h"

#include <QString>
#include <QStringList>
#include <QWidget>

#include <stdint.h>

class QLabel;
class QLineEdit;
class QListWidget;
class QPushButton;
struct fzn_gui_rpc;

class fzn_conversation_view : public QWidget {
public:
	fzn_conversation_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent = nullptr);
	~fzn_conversation_view() override;

	/* The contact whose conversation this shows, by its name, or a group
	 * as `@NAME`, and then `refresh`. Whether the node answered. */
	bool open(const QString &contact);
	bool refresh();

	/* WHAT A PERSON DOES, public because a headless test cannot click. */
	void set_text(const QString &text);
	bool send();
	/* A FILE A LINE NAMES (sec 1130): choose the line (counted from 0, oldest
	 * first), ask for the file -- it arrives in the background, from
	 * whoever holds it -- and save it once whole. Saving with no path asks
	 * where, offering the sender's name for it. */
	void select_line(int row);
	bool fetch();
	bool save_to(const QString &path);
	/* OLDER LINES, a page more each time (sec 1140), and A FILE SENT: stored
	 * here, private, and sent as a line, which grants it to the
	 * conversation. `send_file` with no path asks which. */
	bool show_older();
	bool send_file(const QString &path);

	/* The clock, seconds since 1970, for the times shown; 0 reads the
	 * system's. */
	void set_now(uint32_t utc_s);

	/* WHAT IS ON SCREEN: each line as shown, oldest first; the line being
	 * written; the status line. */
	QStringList lines() const;
	QString text() const;
	QString status() const;

private:
	struct fzn_gui_rpc *m_rpc;
	QString m_contact;
	uint32_t m_now;

	QLabel *m_title;
	QListWidget *m_lines;
	QLineEdit *m_text;
	QPushButton *m_send;
	QPushButton *m_fetch;
	QPushButton *m_save;
	QPushButton *m_older;
	QPushButton *m_send_file;
	size_t m_max; /* the most lines shown, a page more for each "older" */
	QLabel *m_status;
};

#endif /* FZN_GUI_CONVERSATION_VIEW_H */
