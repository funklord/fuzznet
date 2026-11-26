/*
 * The music this user's hosts hold, as a widget: fuzznet sec 1449.
 *
 * Every file the catalogue says is music, by album: the album, the artist
 * it is by -- its album artist where one is said, else the track's artist
 * -- and its year, then its tracks in disc and track order, each with its
 * title (the file's name where it says none), its artist where that differs
 * from the album's, its length and where it is. What the files say of
 * themselves is read where their bytes are (sec 1447); a library from
 * before is read on asking ("Read the tags").
 *
 * WHAT IT SOUNDS LIKE, sec 1458: each track's tempo and key as the host
 * holding it heard them (sec 1457), shown beside its length; the music
 * ordered by album, by tempo (a group a whole BPM, slowest first), by key
 * (round the Camelot wheel, so neighbours that mix stand together) or by
 * artist; found by its key or tempo as by its words; and a library heard
 * on asking ("Hear the music"), the host hearing it a tune at a time.
 *
 * WHAT A PERSON DOES: play a track through the host's player (`on_play`,
 * the root and its title), or a whole album in its order (`on_play_all`);
 * get a track not held here; find music by a word of its title, artist,
 * album or genre.
 *
 * Words are other hosts' and other people's, shown in caret form (sec 1126).
 *
 * Through the typed client on the host's ask callback (`rpc_ask.h`).
 * NO Q_OBJECT AND THEREFORE NO moc.
 */
#ifndef FZN_GUI_MUSIC_VIEW_H
#define FZN_GUI_MUSIC_VIEW_H

#include "notebook_view.h"

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>
#include <QStringList>
#include <QWidget>

#include <functional>

#include <stddef.h>
#include <stdint.h>

class QLabel;
class QLineEdit;
class QPushButton;
class QTreeWidget;
class QTreeWidgetItem;
struct fzn_gui_rpc;

class fzn_music_view : public QWidget {
public:
	fzn_music_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent = nullptr);
	~fzn_music_view() override;

	/* A SCRIPTED NODE'S BINARY ANSWERS, for a test; null takes it back. */
	void answer_binary(int (*answer)(void *ctx, const uint8_t *msg, size_t len, uint8_t *reply,
	                                 size_t reply_cap, size_t *reply_len),
	                   void *ctx);

	/* Ask for the music and show it. Whether the node answered. */
	bool refresh();

	/* THE HOST'S PLAYER: one track, its root and title; or an album, its
	 * tracks in order. */
	void on_play(std::function<void(const QByteArray &root, const QString &title)> play);
	void on_play_all(std::function<void(const QList<QPair<QByteArray, QString>> &tracks)> play);

	/* WHAT A PERSON DOES, public because a headless test cannot click: the
	 * Nth row shown, an album's or a track's. */
	void select(int row);
	bool play();
	bool fetch();
	/* A library from before, read for its tags a page at a time; how many
	 * names it learned. */
	int read_tags();
	/* The held tunes queued to be heard, a page at a time: how many wait to
	 * be heard, or -1 where the host refused. */
	int hear();
	void set_find(const QString &text);
	/* THE ORDER: by album, by tempo, by key, by artist. */
	enum order { BY_ALBUM, BY_TEMPO, BY_KEY, BY_ARTIST };
	void set_order(order o);

	/* WHAT IS ON SCREEN: each row shown, a group -- an album as "ALBUM |
	 * ARTIST | YEAR | | |", else "TEMPO", "KEY" or "ARTIST" -- and its tracks
	 * beneath as "  N. TITLE | ARTIST | LENGTH | BPM | KEY | WHERE", and the
	 * status line. */
	QStringList rows() const;
	QString status() const;

private:
	QTreeWidgetItem *chosen() const;
	QList<QTreeWidgetItem *> shown() const;
	void apply_filter();
	void rebuild();

	struct fzn_gui_rpc *m_rpc;
	std::function<void(const QByteArray &, const QString &)> m_play;
	std::function<void(const QList<QPair<QByteArray, QString>> &)> m_play_all;

	QLineEdit *m_find;
	QTreeWidget *m_tree;
	QPushButton *m_play_button;
	QPushButton *m_fetch;
	QPushButton *m_read;
	QPushButton *m_hear;
	QPushButton *m_refresh;
	class fzn_combo_box *m_order;
	QList<struct fzn_rpc_music_entry> m_music; /* as last listed */
	QLabel *m_status;
	QString m_filter_said;
};

#endif /* FZN_GUI_MUSIC_VIEW_H */
