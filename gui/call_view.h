/*
 * Calls, as a widget: fuzznet sec 1142.
 *
 * What fuzzypickles' call bar does, kept by the focused app (inbox 1553Z,
 * item 3): each live call said as a person reads it -- "bob is calling
 * (audio and video)", "Calling bob...", "In a call with bob" -- with Answer
 * and Decline for one ringing here and Hang up for the others; a call
 * begun to a contact, audio or video; and a call that has ended said with
 * why, a missed one as missed (sec 1082, 1090).
 *
 * THE MEDIA IS NOT HERE: capture, codecs, playback, mute and the camera are
 * the host's, over the call's media channel (sec 1113). This is the call's
 * state and the person's say in it.
 *
 * The host refreshes it when the node says a call changed (`event call`),
 * or on a timer. Through the typed client on the host's ask callback
 * (`rpc_ask.h`). NO Q_OBJECT AND THEREFORE NO moc.
 */
#ifndef FZN_GUI_CALL_VIEW_H
#define FZN_GUI_CALL_VIEW_H

#include "notebook_view.h"

#include <QString>
#include <QStringList>
#include <QWidget>

class QLabel;
class QListWidget;
class QPushButton;
struct fzn_gui_rpc;

class fzn_call_view : public QWidget {
public:
	fzn_call_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent = nullptr);
	~fzn_call_view() override;

	/* Ask which calls live, and say why any seen before has ended. Whether
	 * the node answered the list. */
	bool refresh();

	/* WHAT A PERSON DOES, public because a headless test cannot click. */
	bool call(const QString &contact, bool video);
	void select(int row);
	bool answer();
	bool decline();
	bool hang_up();

	/* WHAT IS ON SCREEN: each live call as said, and the status line. */
	QStringList calls() const;
	QString status() const;

private:
	bool respond(const char *what, int state);

	struct fzn_gui_rpc *m_rpc;
	struct seen;
	seen *m_seen; /* the calls listed last time, to tell an ending */

	QListWidget *m_list;
	QPushButton *m_answer;
	QPushButton *m_decline;
	QPushButton *m_hang_up;
	QLabel *m_status;
};

#endif /* FZN_GUI_CALL_VIEW_H */
