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
 * A STICKER LINE IS DRAWN (sec 1145) from the thumbnail the node renders
 * of a pack it holds, wherever Qt reads the format, as the sticker picker
 * draws one; it is said in words until its pack has arrived, and always
 * for Lottie, which wants thorvg. A sticker that came in offers "Keep
 * this sticker pack", which keeps the pack in this user's collection.
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
class QRect;
class QResizeEvent;
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
	/* A LINE OPENED WHERE IT IS, sec 1242 -- tapped, or activated: a file
	 * fetched if it is not here whole, saved if it is (where `save_path`
	 * says, or where the person chooses). Whether anything was done. */
	bool open_line(int row, const QString &save_path = QString());
	/* THE STICKER PICKER IN THE CONVERSATION, sec 1243: shown below the
	 * line being written by the button beside Send, and a sticker chosen
	 * there sent as a line -- the words being written kept. */
	void show_stickers(bool on);
	bool stickers_shown() const;
	bool send_sticker(const QString &ref);
	/* A STICKER THAT CAME IN, on the chosen line: its pack kept. */
	bool keep_pack();
	/* STICKERS FOR THE LINE BEING TYPED, sec 1272: a row above it of the
	 * kept stickers that fit what is typed so far, asked a quarter second
	 * after the typing stops, hidden when none fits. One chosen is sent in
	 * place of the words, as LINE does. `suggest_now` asks at once;
	 * `suggested` is each one's description, best first. */
	void suggest_now();
	QStringList suggested() const;
	bool send_suggested(int i);
	/* A REPLY, sec 1282: the line with id `id` (16 bytes) answered by the
	 * next line sent, as "Reply" on a chosen line does; an empty id, or a
	 * line sent, ends it. `replying` says to which line, empty for none. */
	void reply_to(const QByteArray &id);
	QByteArray replying() const;
	/* A REACTION, sec 1282: `reaction` on the line with id `id`, sent as
	 * a line the other end folds under it; an empty one takes this user's
	 * back. What "React" on a chosen line sends, one of `reactions()`. */
	bool react(const QByteArray &id, const QString &reaction);
	/* THIS USER'S LINE `id` TAKEN BACK, sec 1284, as "Unsend" on a chosen
	 * line of its own does: the node holds the hour and the setting. */
	bool unsend(const QByteArray &id);
	static QStringList reactions();

	/* The clock, seconds since 1970, for the times shown; 0 reads the
	 * system's. */
	void set_now(uint32_t utc_s);
	/* WHAT A LINE'S STATE IS SAID AS, after it: " (delivered)", " (read)",
	 * a group's " (read by 3)" (sec 1273) -- nothing for one that came in.
	 * `state` an fzn_rpc_line_state_t. */
	static QString state_said(bool outgoing, unsigned state, unsigned read_by);

	/* WHAT IS ON SCREEN: each line as shown, oldest first; the line being
	 * written; the status line. */
	QStringList lines() const;
	/* Whether line `row` is drawn as a picture. */
	bool drawn(int row) const;
	/* BUBBLES ON A PHONE, sec 1241: whether the lines are drawn so, and
	 * where line `row`'s bubble is, in the list's own coordinates --
	 * this user's at the right, everyone else's at the left. */
	bool bubbles() const;
	QRect bubble_rect(int row) const;
	QString text() const;
	QString status() const;
	/* THE NOTICE'S ONE ACTION, sec 1253: its words, empty for none, and
	 * taking it as the button does. A line chosen offers what fits it --
	 * a file got or saved, a sticker's pack kept. */
	QString offered() const;
	bool take_offer();

protected:
	/* UNDER 400 PIXELS, bubbles; wider, the log (sec 1241). */
	void resizeEvent(QResizeEvent *event) override;

private:
	void draw_stickers();
	bool send_line(const QByteArray &text);
	bool refresh_lines();
	void merge_calls(bool full, uint32_t now);
	void offer_for(class QListWidgetItem *item);
	/* THE LINE CHOSEN, by its text, kept across a refresh (sec 1253). */
	QString m_chosen;
	/* THE LINE THE NEXT ONE SENT ANSWERS, by its id, sec 1282. */
	QByteArray m_reply_to;
	bool m_refreshing = false;
	class bubble_delegate *m_bubbles;
	class fzn_sticker_picker_view *m_picker;
	QPushButton *m_stickers;
	class QListWidget *m_suggest;
	class QTimer *m_suggest_soon;

	struct fzn_gui_rpc *m_rpc;
	struct art;
	art *m_art; /* each sticker drawn, for the view's life */
	QString m_contact;
	uint32_t m_now;

	QLabel *m_title;
	QListWidget *m_lines;
	QLineEdit *m_text;
	QPushButton *m_send;
	QPushButton *m_older;
	QPushButton *m_send_file;
	QPushButton *m_react;
	size_t m_max; /* the most lines shown, a page more for each "older" */
	class fzn_notice_line *m_notice;
};

#endif /* FZN_GUI_CONVERSATION_VIEW_H */
