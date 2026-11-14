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
 * WHAT A PERSON DOES ON A FILE HERE (sec 1156, fuzzypickles' library page,
 * inbox 20261114T0128Z): play it, through the host's player (`on_play`, the
 * root and its name -- snurra's, which plays a file still arriving); share
 * it with every contact, a contact or a group, and see and take back whom it
 * is shared with; save it to a file; verify its pieces, a broken one
 * dropped to be fetched again; and remove this device's copy.
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

#include <functional>

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

	/* THE HOST'S PLAYER, given the file's root and name. */
	void on_play(std::function<void(const QByteArray &root, const QString &name)> play);

	/* WHAT A PERSON DOES, public because a headless test cannot click. */
	void select(int row);
	bool fetch();
	bool play();
	/* `to` a contact's name, `@NAME` a group, or empty for every contact. */
	bool share(const QString &to);
	bool unshare(const QString &to);
	bool save_to(const QString &path);
	bool verify();
	bool remove();

	/* Whom the chosen file is shared with, as said: "every contact", a
	 * contact's name, `@NAME`. */
	QStringList shares() const;

	/* WHAT IS ON SCREEN: each file as its cells joined by " | ", and the
	 * status line. */
	QStringList rows() const;
	QString status() const;

private:
	QByteArray chosen_root() const;
	QString chosen_name() const;
	void read_shares();

	struct fzn_gui_rpc *m_rpc;
	std::function<void(const QByteArray &, const QString &)> m_play;
	QStringList m_shares;

	QTableWidget *m_table;
	QPushButton *m_play_button;
	QPushButton *m_share;
	QPushButton *m_save;
	QPushButton *m_verify;
	QPushButton *m_remove;
	QPushButton *m_fetch;
	QPushButton *m_refresh;
	QLabel *m_status;
};

#endif /* FZN_GUI_LIBRARY_VIEW_H */
