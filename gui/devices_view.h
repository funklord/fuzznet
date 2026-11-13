/*
 * Adding a device to this user's hosts, as a widget: fuzznet sec 1122.
 *
 * THE INVITING SIDE of sec 896's one-code join. A person makes a code here
 * -- FZI1: text, shown as text and as a QR to photograph, good for ten
 * minutes -- and the new device takes it. Whether this host's person is
 * asked before a device joins is the host setting invite/confirm, shown and
 * changed here; with it on, each device that holds a code waits, listed by
 * its key, until it is let in or turned away. With it off, whoever holds the
 * code is let in, which the view says beside the switch.
 *
 * AND THE JOINING SIDE, sec 1123: a code from another of this user's hosts
 * typed or pasted here is handed to this node, which goes on asking that
 * host for five minutes. The view asks once a second whether this host now
 * serves under that user (`fzn_rpc_device_joined`), never waiting on the
 * node in between, and says when it has or when five minutes have passed.
 *
 * Through the typed client on the host's ask callback (`rpc_ask.h`), as the
 * contacts and location views are. NO Q_OBJECT AND THEREFORE NO moc.
 */
#ifndef FZN_GUI_DEVICES_VIEW_H
#define FZN_GUI_DEVICES_VIEW_H

#include "notebook_view.h"

#include <QString>
#include <QStringList>
#include <QWidget>

class QCheckBox;
class QLabel;
class QLineEdit;
class QListWidget;
class QPushButton;
class QTimer;
class fzn_qr_view;
struct fzn_gui_rpc;

class fzn_devices_view : public QWidget {
public:
	fzn_devices_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent = nullptr);
	~fzn_devices_view() override;

	/* Ask whether joining is confirmed and which devices wait, and show
	 * both. Whether the node answered. */
	bool refresh();

	/* WHAT A PERSON DOES, public because a headless test cannot click. */
	bool invite();
	bool set_confirm(bool on);
	void select_waiting(int row);
	bool answer(bool let_in);
	/* JOIN with a code, and the once-a-second look a timer makes, public so
	 * a test can make it without a clock: 1 joined, 0 still asking. */
	bool join(const QString &code);
	int poll_join();

	/* WHAT IS ON SCREEN: the code made, whether a QR of it is drawn, the
	 * switch, each waiting device's key (16 hex), and the status line. */
	QString code() const;
	bool code_drawn() const;
	bool confirm() const;
	QStringList waiting() const;
	QString status() const;

private:
	struct fzn_gui_rpc *m_rpc;
	struct keys;
	keys *m_keys; /* each waiting device's full key */

	QLabel *m_code;
	fzn_qr_view *m_qr;
	QPushButton *m_invite;
	QCheckBox *m_confirm;
	QLabel *m_confirm_note;
	QListWidget *m_waiting;
	QPushButton *m_let_in;
	QPushButton *m_turn_away;
	QPushButton *m_refresh;
	QLineEdit *m_join_code;
	QPushButton *m_join;
	QTimer *m_join_timer;
	int m_join_looks; /* looks left before the node's five minutes are up */
	QLabel *m_status;
};

#endif /* FZN_GUI_DEVICES_VIEW_H */
