/*
 * The photographs this user's hosts hold, as a widget: fuzznet sec 1450.
 *
 * Every file the catalogue says is a photograph (sec 1449), by the month
 * it was taken, newest first, then by time; each with when, the camera,
 * its size and where it was taken, and where its bytes are. Those taken at
 * no time said come last, under "When unknown". What a photograph says of
 * itself is read where its bytes are (sec 1447).
 *
 * THUMBNAILS, sec 1455: each photograph held here shows the camera's own
 * thumbnail (EXIF's), read from its first 64 KiB through the play slices,
 * a few at a time on a timer, so opening a library of thousands waits for
 * none of them; one without a thumbnail shows none.
 *
 * THE ONE CHOSEN IS SHOWN: its bytes read through the library's play
 * slices -- from this host, or arriving from another -- decoded at the
 * preview's size, and turned as the camera's orientation says. Only the
 * chosen one is read, so opening a library of thousands reads none.
 *
 * Words are other hosts' and other people's, shown in caret form (sec 1126).
 *
 * Through the typed client on the host's ask callback (`rpc_ask.h`).
 * NO Q_OBJECT AND THEREFORE NO moc.
 */
#ifndef FZN_GUI_PHOTO_VIEW_H
#define FZN_GUI_PHOTO_VIEW_H

#include "notebook_view.h"

#include <QByteArray>
#include <QImage>
#include <QString>
#include <QStringList>
#include <QWidget>

#include <stddef.h>
#include <stdint.h>

class QLabel;
class QLineEdit;
class QPushButton;
class QTreeWidget;
class QTreeWidgetItem;
struct fzn_gui_rpc;

class fzn_photo_view : public QWidget {
public:
	fzn_photo_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent = nullptr);
	~fzn_photo_view() override;

	/* A SCRIPTED NODE'S BINARY ANSWERS, for a test; null takes it back. */
	void answer_binary(int (*answer)(void *ctx, const uint8_t *msg, size_t len, uint8_t *reply,
	                                 size_t reply_cap, size_t *reply_len),
	                   void *ctx);

	/* Ask for the photographs and show them. Whether the node answered. */
	bool refresh();

	/* WHAT A PERSON DOES, public because a headless test cannot click: the
	 * Nth row shown, a month's or a photograph's. Choosing a photograph
	 * shows it where its bytes can be read. */
	void select(int row);
	bool fetch();
	void set_find(const QString &text);
	/* THUMBNAILS still to read, up to `n` of them now: how many were read.
	 * The timer calls it; a test does. Whether row `row` shows one. */
	int read_thumbnails(int n);
	bool has_thumbnail(int row) const;

	/* WHAT IS ON SCREEN: each row shown, a month as "MONTH YEAR | N" and its
	 * photographs beneath as "  TIME | CAMERA | SIZE | PLACE | WHERE"; the
	 * picture shown, null for none; and the status line. */
	QStringList rows() const;
	QImage shown_picture() const;
	QString status() const;

private:
	QTreeWidgetItem *chosen() const;
	QList<QTreeWidgetItem *> shown() const;
	void apply_filter();
	void show_chosen();

	struct fzn_gui_rpc *m_rpc;

	QLineEdit *m_find;
	QTreeWidget *m_tree;
	QLabel *m_picture;
	QImage m_shown;
	QList<QByteArray> m_thumbs_wanted; /* roots, in the order shown */
	class QTimer *m_thumb_timer;
	QPushButton *m_fetch;
	QPushButton *m_refresh;
	QLabel *m_status;
	QString m_filter_said;
};

#endif /* FZN_GUI_PHOTO_VIEW_H */
