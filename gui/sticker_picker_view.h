/*
 * Choosing a sticker to send, and keeping packs, as a widget: fuzznet sec
 * 1141.
 *
 * What the focused app keeps of fuzzypickles' sticker pages (inbox 1553Z,
 * item 1): the packs this user keeps as tabs, each pack's stickers drawn
 * as the node renders them, and one tap choosing one -- the host is told the
 * reference a line carries (`fzn:sticker/...`), which it sends as any line.
 * And keeping packs from files, several at once, saying "Kept N of M" and
 * why each other was not.
 *
 * A STICKER IS DRAWN where Qt reads its rendition -- PNG, APNG's first
 * frame, WebP -- and named by its description otherwise: a Lottie sticker
 * wants thorvg, which fuzzypickles vendors and fuzznet does not (sec 1127's
 * question to it).
 *
 * Through the typed client on the host's ask callback (`rpc_ask.h`).
 * NO Q_OBJECT AND THEREFORE NO moc.
 */
#ifndef FZN_GUI_STICKER_PICKER_VIEW_H
#define FZN_GUI_STICKER_PICKER_VIEW_H

#include "notebook_view.h"

#include <QString>
#include <QStringList>
#include <QWidget>

#include <functional>

class QLabel;
class QLineEdit;
class QListWidget;
class QListWidgetItem;
class QPushButton;
class QTabWidget;
struct fzn_gui_rpc;

class fzn_sticker_picker_view : public QWidget {
public:
	fzn_sticker_picker_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent = nullptr);
	~fzn_sticker_picker_view() override;

	/* Ask for the packs and their stickers and show them. Whether the node
	 * answered. */
	bool refresh();

	/* WHAT TO DO WHEN ONE IS CHOSEN: given the reference a line carries. */
	void on_pick(std::function<void(const QString &)> pick);

	/* HOW A MESSAGE OR NAME STICKER'S WORDS ARE ASKED (sec 1296): given its
	 * description and the characters its box holds, the words into
	 * `*words`, false for a choice called off. Unset, a dialog asks. */
	void on_words(std::function<bool(const QString &description, int limit, QString *words)> ask);

	/* HOW A STICKER'S SOUND IS PLAYED (sec 1314): given the file it was
	 * written to, when a person touches a sticker whose pack gives it one --
	 * heard before it is sent, as the log plays it once received (sec 1301).
	 * Unset, no sound is fetched. */
	void on_sound(std::function<void(const QString &path)> play);
	/* "ADD STICKER PACKS" HANDED TO THE HOST, sec 1533 -- its own import,
	 * on a phone the platform's picker -- in place of the picker's file
	 * dialog. Unset, the dialog as before. */
	void on_add_packs(std::function<void()> add);
	/* ONE CLICK SENDS, by the host's word (sec 1544): a click plays a
	 * sticker and sends it at once, as fuzzypickles' picker does. Off by
	 * default -- a click is a person touching it, and choosing it to send
	 * is activation (sec 1322). */
	void set_click_sends(bool on);
	/* A STICKER THAT TAKES WORDS HANDED TO THE HOST AS CHOSEN, sec 1536:
	 * its pack, id, word limit and what it is, so the host asks for the
	 * words in its own time -- the conversation view in its composer --
	 * where `on_words` must answer before the pick returns. Set, it wins
	 * over `on_words` and the picker's own row. */
	/* A PACK'S ART DRAWN WHEN ITS TAB IS SHOWN (sec 1547), not every
	 * pack's at each refresh. How many stickers were drawn by this look. */
	int draw_shown();
	void on_pick_words(std::function<void(const QByteArray &pack, quint64 id, int limit, const QString &what)> pick);

	/* WHAT A PERSON DOES, public because a headless test cannot click:
	 * choose sticker `row` of pack `pack` (both from 0, as shown); keep
	 * packs from files, asking which when `paths` is empty. */
	bool pick(int pack, int row);
	/* TOUCH sticker `row` of pack `pack`, as a click does: its sound played
	 * where it has one. Whether one was handed to the player. */
	bool touch(int pack, int row);
	/* Whether a touched sticker that moves is playing (sec 1322): a
	 * Lottie, an APNG or an animated WebP plays for three loops when
	 * touched, then rests on its still. */
	bool playing() const;
	bool keep_files(const QStringList &paths);
	/* LET PACK `pack` GO (from 0, as shown), sec 1298: without asking, the
	 * button asking first. */
	bool forget(int pack);

	/* FINDING A STICKER, sec 1298: the kept stickers that fit `text`, best
	 * first, shown in place of the tabs; empty shows the tabs again. FOUND
	 * is what is shown, by description; PICK_FOUND chooses one of them. */
	void set_find(const QString &text);
	QStringList found() const;
	bool pick_found(int row);

	/* WHAT IS ON SCREEN: each pack's name, then its stickers indented, each
	 * as its description and whether it is drawn; the status line. RECENT
	 * the Recent tab's stickers by description, newest first (sec 1317),
	 * empty where it is not shown; `pick_recent` chooses one. Pack numbers
	 * elsewhere count packs alone, the Recent tab not among them. */
	QStringList shown() const;
	QStringList recent() const;
	bool pick_recent(int row);
	QString status() const;

private:
	struct fzn_gui_rpc *m_rpc;
	std::function<void(const QString &)> m_pick;
	std::function<bool(const QString &, int, QString *)> m_words;

	bool pick_item(QListWidgetItem *item);
	class QListWidget *pack_list(int pack) const;
	int pack_of_tab(int tab) const;
	void show_recent();
	bool sound(QListWidgetItem *item);
	void play(QListWidgetItem *item);
	void play_frame();
	void rest();

	std::function<void(const QString &)> m_sound;
	std::function<void()> m_add_packs;
	bool m_click_sends = false;
	/* A CLICK: its sound and play, and the pick when the host asks. */
	void clicked(QListWidgetItem *item);
	std::function<void(const QByteArray &, quint64, int, const QString &)> m_pick_words;
	/* EACH STICKER'S SOUND, written once into a directory the view owns
	 * and removes with it. */
	struct sounds;
	sounds *m_sounds;
	class QTimer *m_play = nullptr;
	QListWidgetItem *m_playing = nullptr;

	QTabWidget *m_tabs;
	QPushButton *m_keep;
	QPushButton *m_refresh;
	QPushButton *m_forget;
	int m_forget_armed = -1;
	qint64 m_forget_armed_at = 0;
	/* THE WORDS ASKED ON A ROW OF THE PICKER (sec 1515), where a dialog
	 * was a second window: shown, waited for in a loop of its own, as a
	 * host's sheet does, and gone. */
	bool ask_words(int limit, QString *words);
	class QWidget *m_words_row = nullptr;
	class QLineEdit *m_words_edit = nullptr;
	class QLabel *m_words_said = nullptr;
	class QPushButton *m_words_send = nullptr, *m_words_cancel = nullptr;
	QLineEdit *m_find;
	QListWidget *m_found;
	QLabel *m_status;
};

#endif /* FZN_GUI_STICKER_PICKER_VIEW_H */
