/*
 * Where the people sharing a position with this user are, as a widget other
 * software hosts, sec 1109 -- the register's "a location view" (sec 1070),
 * the Nearby screen every consumer showing positions was writing alone.
 *
 * THIS HOST FIRST: whether it samples its own position, from where and how
 * often, or why it stopped -- the comparison the node keeps for exactly this.
 * THEN EACH CONTACT'S NEWEST FIX: where, how sure (the accuracy, a coarse fix
 * said so), how old, and from this host's own newest fix how far and which
 * way -- a bearing only where the two fixes' accuracy leaves it meaning
 * something (location/geo.h decides).
 *
 * WHAT A PERSON DOES: ask a contact for its position now, and grant or take
 * back this user's own position to them. Through the typed client on the
 * host's ask callback (`rpc_ask.h`), as the other views are. The clock is the
 * host's to set, so a test fixes "now". NO Q_OBJECT AND THEREFORE NO moc.
 */

#ifndef FZN_GUI_LOCATION_VIEW_H
#define FZN_GUI_LOCATION_VIEW_H

#include "notebook_view.h"

#include <QString>
#include <QStringList>
#include <QWidget>

#include <stdint.h>

struct fzn_gui_rpc;
class QComboBox;
class QLabel;
class QPushButton;
class QTableWidget;

class fzn_location_view : public QWidget {
public:
	fzn_location_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent = nullptr);
	~fzn_location_view() override;

	/* Ask for this host's sampling, its own newest fix and every contact's,
	 * and show them. Whether the node answered. */
	bool refresh();

	/* WHAT A PERSON DOES, public because a headless test cannot click. */
	void select(int row);
	bool fetch();
	bool share(bool on);
	/* THE PRECISION a grant gives (a fzn_rpc_location_precision_t): chosen
	 * before sharing, and read back from what this host grants the contact
	 * chosen, sec 1119. */
	void set_precision(int precision);
	int precision() const;

	/* The clock, seconds since 1970; 0 reads the system's. */
	void set_now(uint32_t utc_s);

	/* WHAT IS ON SCREEN: this host's line, each row as its cells joined by
	 * " | ", and the status line. */
	QString own() const;
	QStringList rows() const;
	QString status() const;

private:
	struct fzn_gui_rpc *m_rpc;
	uint32_t m_now;

	QLabel *m_own;
	QTableWidget *m_table;
	QPushButton *m_fetch;
	QPushButton *m_share;
	QPushButton *m_unshare;
	QComboBox *m_precision;
	QPushButton *m_refresh;
	QLabel *m_status;
};

#endif /* FZN_GUI_LOCATION_VIEW_H */
