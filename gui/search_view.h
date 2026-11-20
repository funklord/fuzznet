/*
 * The one search, as a widget: fuzznet sec 1293, over secs 1287-1292.
 *
 * A box for words and a chooser of whom with -- this user's own hosts, or
 * one contact, whose hosts alone are then asked and who is told the words
 * (sec 1292) -- and the hits of every store in the one order: what was
 * found (its words), where (lines, notes, stickers, contacts) and when.
 * The page fills as hosts answer; the status line says how many answered,
 * and a page is never called whole before every host asked has answered
 * or been given up on. "More" asks for the page after the last hit.
 *
 * Found words are other people's, shown in caret form (sec 1126).
 *
 * Through the typed client on the host's ask callback (`rpc_ask.h`).
 * NO Q_OBJECT AND THEREFORE NO moc.
 */
#ifndef FZN_GUI_SEARCH_VIEW_H
#define FZN_GUI_SEARCH_VIEW_H

#include "notebook_view.h"

#include <QByteArray>
#include <QString>
#include <QStringList>
#include <QWidget>

#include <functional>

class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;
class QTimer;
struct fzn_gui_rpc;
struct fzn_rpc_search_page;

class fzn_search_view : public QWidget {
public:
	fzn_search_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent = nullptr);
	~fzn_search_view() override;

	/* The contacts offered in the chooser, read again. Whether the node
	 * answered. */
	bool refresh();

	/* WHAT TO DO WITH A HIT CHOSEN: its store's name and its key there. */
	void on_open(std::function<void(const QString &store, const QByteArray &key)> open);

	/* WHAT A PERSON DOES, public because a headless test cannot click.
	 * SEARCH asks for `words`, with the contact named `with` or nobody
	 * (empty): whether the node took it. POLL reads the page as far as it
	 * is answered, once; whether it read. MORE asks for the page after the
	 * last hit shown. OPEN hands the chosen hit to `on_open`. */
	bool search(const QString &words, const QString &with = QString());
	bool poll();
	bool more();
	void select(int row);
	bool open();

	/* Whether every host asked has answered, or been given up on. */
	bool settled() const;

	/* WHAT IS ON SCREEN: each hit as its cells joined by " | ", and the
	 * status line. */
	QStringList rows() const;
	QString status() const;

private:
	void show_page();
	bool ask_page(bool next);

	struct fzn_gui_rpc *m_rpc;
	struct fzn_rpc_search_page *m_page;
	std::function<void(const QString &, const QByteArray &)> m_open;
	QString m_words, m_with;
	int m_polls;
	bool m_asked;

	QLineEdit *m_find;
	QComboBox *m_who;
	QTableWidget *m_table;
	QPushButton *m_go;
	QPushButton *m_more;
	QPushButton *m_open_button;
	QLabel *m_status;
	QTimer *m_timer;
};

#endif /* FZN_GUI_SEARCH_VIEW_H */
