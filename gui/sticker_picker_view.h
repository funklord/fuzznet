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

	/* WHAT A PERSON DOES, public because a headless test cannot click:
	 * choose sticker `row` of pack `pack` (both from 0, as shown); keep
	 * packs from files, asking which when `paths` is empty. */
	bool pick(int pack, int row);
	bool keep_files(const QStringList &paths);

	/* WHAT IS ON SCREEN: each pack's name, then its stickers indented, each
	 * as its description and whether it is drawn; the status line. */
	QStringList shown() const;
	QString status() const;

private:
	struct fzn_gui_rpc *m_rpc;
	std::function<void(const QString &)> m_pick;

	QTabWidget *m_tabs;
	QPushButton *m_keep;
	QPushButton *m_refresh;
	QLabel *m_status;
};

#endif /* FZN_GUI_STICKER_PICKER_VIEW_H */
