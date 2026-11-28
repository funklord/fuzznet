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

#include <QByteArray>
#include <QHash>
#include <QString>
#include <QStringList>
#include <QWidget>

#include <stdint.h>

#include <functional>

class QListWidgetItem;
class QTimer;

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
	/* LINE `id` SHOWN AND CHOSEN, sec 1528 -- a search hit's: paged back a
	 * page at a time while older lines remain, as far as
	 * FZN_SHOW_LINE_PAGES pages; centred, and the place kept there. False,
	 * and said, when it is not in the conversation. */
	bool show_line(const QByteArray &id);
	bool send_file(const QString &path);
	/* THE CALLS A HOST'S WINDOW MAKES, sec 1529 (fuzzypickles' Files page
	 * and share-in): a line or a file sent to any conversation, NAME or
	 * @GROUP, open here or not -- in reply only to the open one's reply;
	 * a file the view did not draw, by its whole reference, saved to
	 * `where` now or when it lands; and which conversation is open. */
	bool send_text_to(const QString &conversation, const QString &text);
	bool send_file_to(const QString &conversation, const QString &path);
	bool save_file(const QByteArray &ref, const QString &where);
	QString current_conversation() const;
	bool current_is_group() const;
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
	/* WHAT THE REPLY BAR SAYS, sec 1527: "Replying to WHO: words", empty
	 * and hidden when no reply is under way; its Cancel lets the reply go. */
	QString reply_bar() const;
	/* A REACTION, sec 1282: `reaction` on the line with id `id`, sent as
	 * a line the other end folds under it; an empty one takes this user's
	 * back. What "React" on a chosen line sends, one of `reactions()`. */
	bool react(const QByteArray &id, const QString &reaction);
	/* THIS USER'S LINE `id` TAKEN BACK, sec 1284, as "Unsend" on a chosen
	 * line of its own does: the node holds the hour and the setting. */
	bool unsend(const QByteArray &id);
	static QStringList reactions();
	/* ONE MENU FOR A LINE, sec 1530, opened by a right-click or a long
	 * press through the host's hook (sec 1511): everything that line
	 * allows -- its file saved or got, its sticker's pack kept, a reply,
	 * each reaction, a reaction taken back, and this user's own recent
	 * line taken back. What row `row` offers, and one of them done. */
	QStringList line_actions(int row);
	bool line_act(int row, const QString &action);

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
	/* Whether the chosen line's sticker is playing (sec 1300). */
	bool playing() const;
	/* Whether a pop-up sticker is shown across the log (sec 1302). */
	bool popped() const;
	/* Whether an effect sticker plays behind the log's lines (sec 1315). */
	bool effected() const;

	/* THE HOST'S PLAYER FOR A STICKER'S SOUND (sec 1301), given the file it
	 * was written to; unset, no sound is fetched. */
	void on_sound(std::function<void(const QString &path)> play);
	/* EVERY ACT'S OUTCOME, as its notice says it, told the host for its
	 * log (sec 1533): a send refused, a file saved, a reply ended. */
	void on_log(std::function<void(const QString &line)> log);
	/* WHETHER THE LINES SHOWN MAY BE MARKED READ NOW, sec 1518: asked at
	 * each refresh, so a host marks read only what a person can see -- its
	 * window in front, this view showing. Unset, every refresh marks. */
	void mark_read_when(std::function<bool()> may);
	/* NEW LINES SHOWN AS THEY ARRIVE, sec 1522: while the view is shown it
	 * asks the node for the open conversation's newest line every `ms`
	 * (2000 unless set; 0 stops it) and refreshes when that line, or its
	 * state, changed -- so a host that never polls still shows them, and a
	 * reader at the end sees them without scrolling (sec 1518). A host
	 * subscribed to fuzznetd's events calls `message_event` with an event's
	 * NAME, and the view looks at once. */
	void set_watch_ms(int ms);
	void message_event(const QString &name);
	/* Look now: whether the newest line changed, and the view was
	 * refreshed for it. */
	bool watch_now();
	/* A FILE ASKED FOR BY OPENING IT, written where it was asked when it
	 * lands, sec 1526: looked at on the watch's tick, shown or not. How
	 * many are waiting, and a look now: how many were written. */
	int pending_saves() const;
	int land_pending();
	/* A STICKER WHOSE PACK HAS NOT COME, drawn when it lands (sec 1534):
	 * looked for again on the watch's tick while shown, as many as
	 * FZN_ART_TRIES times a sticker, then left as its words. How many
	 * were drawn by this look. */
	int redraw_waiting();
	/* TOUCH, BY THE HOST'S WORD, sec 1535: 1 finger-sized targets and
	 * bubbles, 0 neither, -1 (the default) by the view's width -- as the
	 * conversations list's set_layout. A tablet a host knows is touched
	 * is wide, and a desktop window narrow is clicked. */
	void set_touch(int on);
	/* THE PICKER'S "ADD STICKER PACKS" HANDED TO THE HOST, through this
	 * view (sec 1541): its picker is its own. */
	void on_add_packs(std::function<void()> add);
	/* A LINE'S MENU, opened at `at` in the lines' viewport -- a right-click
	 * or a held press (sec 1541). Whether one opened. */
	bool open_line_menu(const QPoint &at);
	/* A STICKER'S WORDS WRITTEN IN THE COMPOSER, sec 1536: what the
	 * picker hands over for a sticker that takes words. The line being
	 * written becomes its words, held to `limit`, with a bar saying so and
	 * a Cancel; Send sends the sticker with them, in reply where one is
	 * under way. Whether a sticker is waiting for its words. */
	void ask_sticker_words(const QByteArray &pack, quint64 id, int limit, const QString &what);
	bool sticker_waits_for_words() const;
	/* SEAMS A HOST'S SUITE ASKS, sec 1537: whether row `row`, this user's
	 * own, may still be taken back; and how many stickers are still
	 * waiting for their pack's art. */
	bool can_unsend_row(int row);
	int waiting_for_packs() const;
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
	int sticker_box(const QByteArray &pack, qulonglong id, struct fzn_sticker_entry *out);
	void play(QListWidgetItem *item);
	void rest();
	void play_frame();
	void sound(QListWidgetItem *item);
	void pop(QListWidgetItem *item);
	void unpop();
	void pop_frame();
	bool eventFilter(QObject *watched, QEvent *event) override;
	class QLabel *m_popup = nullptr;
	QTimer *m_pop = nullptr;
	std::function<void(const QString &)> m_sound;
	std::function<bool()> m_may_mark;
	QTimer *m_watch = nullptr;
	class QWidget *m_reply_row = nullptr;
	QLabel *m_reply_said = nullptr;
	class QPushButton *m_reply_cancel = nullptr;
	/* `text` as the reply when one is under way (sec 1527): one send for
	 * typed words, a sticker and a suggestion alike. */
	bool send_as_reply(const QByteArray &text);
	bool send_line_to(const QString &conversation, const QByteArray &text);
	/* Whether `item`, this user's own, may still be taken back here. */
	bool may_unsend(const QListWidgetItem *item);
	struct pending_save {
		QByteArray ref;
		QString where;
	};
	QVector<pending_save> m_pending;
	bool save_ref(const QByteArray &ref, const QString &where);
	/* The open conversation's newest line, as last shown: its id and
	 * state, and for a group who read it. Empty until a refresh. */
	QByteArray m_newest_seen;
	/* Looks for each undrawn sticker's art, by sticker and words. */
	QHash<QByteArray, int> m_art_tries;
	int m_touch_pin = -1;
	/* A PRESS HELD ON A LINE, sec 1541: its timer and where it began. */
	QTimer *m_hold = nullptr;
	QPoint m_hold_at;
	/* The sticker waiting for its words, empty pack for none. */
	QByteArray m_words_pack;
	quint64 m_words_id = 0;
	class QWidget *m_words_row = nullptr;
	QLabel *m_words_said = nullptr;
	void end_sticker_words();
	void apply_touch();
	QByteArray newest_now();
	/* Whose lines the list holds, so a newly opened one starts at its end. */
	QString m_place_for;
	/* FOLLOWING THE END until the reader scrolls away from it; the moves a
	 * refill makes itself are not the reader's. */
	bool m_follow = true, m_filling = false;
	bool fill_lines();
	QTimer *m_play = nullptr;
	QListWidgetItem *m_playing = nullptr;
	QByteArray m_playing_key;
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
