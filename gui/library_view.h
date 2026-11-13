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

class QLabel;
class QPushButton;
class QTableWidget;
struct fzn_gui_rpc;

class fzn_library_view : public QWidget {
public:
	fzn_library_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent = nullptr);
	~fzn_library_view() override;

	/* Ask for the library and show it. Whether the node answered. */
	bool refresh();

	/* WHAT A PERSON DOES, public because a headless test cannot click. */
	void select(int row);
	bool fetch();

	/* WHAT IS ON SCREEN: each file as its cells joined by " | ", and the
	 * status line. */
	QStringList rows() const;
	QString status() const;

private:
	struct fzn_gui_rpc *m_rpc;

	QTableWidget *m_table;
	QPushButton *m_fetch;
	QPushButton *m_refresh;
	QLabel *m_status;
};

#endif /* FZN_GUI_LIBRARY_VIEW_H */
