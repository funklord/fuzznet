/*
 * What this user's hosts decided apart, and settling it, as a widget:
 * fuzznet sec 1127.
 *
 * When two of a user's hosts change one thing while they cannot reach each
 * other -- a contact's name, an estate setting -- each decision stands as a
 * side, and the node lists the subjects with more than one (sec 895). Here
 * each subject is shown in words (a contact's name as "the name of X"), its
 * sides beneath it with the value each host chose and when, and a person
 * keeps one: the change made again, which is what closes the fork on every
 * host.
 *
 * A side's value is shown in caret form, as every text another host wrote
 * is (sec 1126), and settled with exactly the bytes the node listed.
 *
 * Through the typed client on the host's ask callback (`rpc_ask.h`).
 * NO Q_OBJECT AND THEREFORE NO moc.
 */
#ifndef FZN_GUI_FORKS_VIEW_H
#define FZN_GUI_FORKS_VIEW_H

#include "notebook_view.h"

#include <QString>
#include <QStringList>
#include <QWidget>

#include <stdint.h>

class QLabel;
class QPushButton;
class QTreeWidget;
struct fzn_gui_rpc;

class fzn_forks_view : public QWidget {
public:
	fzn_forks_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent = nullptr);
	~fzn_forks_view() override;

	/* Ask what was decided apart and show it. Whether the node answered. */
	bool refresh();

	/* WHAT A PERSON DOES, public because a headless test cannot click:
	 * choose side `side` of subject `subject` (both counted from 0, in the
	 * order shown; side -1 the subject's own row, which is not kept), and
	 * keep it. */
	void select(int subject, int side);
	bool keep();

	/* WHAT IS ON SCREEN: each subject as its words, each side indented
	 * beneath as "  VALUE -- HOST16, DATE", and the status line. */
	QStringList shown() const;
	QString status() const;

private:
	struct fzn_gui_rpc *m_rpc;

	QTreeWidget *m_tree;
	QPushButton *m_keep;
	QPushButton *m_refresh;
	QLabel *m_status;
};

#endif /* FZN_GUI_FORKS_VIEW_H */
