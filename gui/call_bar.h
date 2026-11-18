/*
 * One line for the call that matters, over every page: fuzznet sec 1238.
 *
 * fuzzypickles' 1900Z item 6 and 2000Z item 5 (secs 1224, 1230): a call
 * rings while a person is anywhere in the app, and a list with buttons is
 * a page nobody goes to find. So this is a bar a host puts above every
 * page -- hidden while there is no call -- saying the call that matters
 * most: one ringing here, then one up, then one ringing out. Ringing here
 * it offers Answer and Decline; up, how long it has run, Mute, the camera
 * for a video call, and Hang up; ringing out, Hang up.
 *
 * AND IT CARRIES THE CALL: once one is up, its sound (`call_audio`) and,
 * given the node's socket, its picture (`call_video`) -- so a host no
 * longer opens the media itself (sec 1234). A call that ends is said as a
 * person would for a few seconds -- "Call with bob ended, 0:42.", "Missed
 * call from bob." -- and the bar goes.
 *
 * The host refreshes it when the node says a call changed (`event call`)
 * or on a timer. Through the typed client on the host's ask callback.
 * NO Q_OBJECT AND THEREFORE NO moc.
 */
#ifndef FZN_GUI_CALL_BAR_H
#define FZN_GUI_CALL_BAR_H

#include "notebook_view.h"

#include <QHash>
#include <QString>
#include <QStringList>
#include <QWidget>

#include <functional>

#include <stdint.h>

class QLabel;
class QPushButton;
class fzn_call_audio;
class fzn_call_video;
struct fzn_gui_rpc;

/* How long a call's ending stays said before the bar goes. */
#define FZN_CALL_BAR_ENDED_S 5u

class fzn_call_bar : public QWidget {
public:
	/* `node_socket`, where the node answers, opens a call's picture; empty
	 * carries its sound alone. */
	fzn_call_bar(fzn_notebook_view_ask_t ask, void *ask_ctx, const QString &node_socket = QString(),
	             QWidget *parent = nullptr);
	~fzn_call_bar() override;

	/* Ask which calls live, show the one that matters, carry its media
	 * once up, and say an ending. Whether the node answered. */
	bool refresh();

	/* WHAT A PERSON DOES, public because a headless test cannot click. */
	bool answer();
	bool decline();
	bool hang_up();
	void set_muted(bool muted);
	void set_camera(bool on);

	/* WHAT IS SHOWN: the line, and the buttons offered, by their words. */
	QString said() const;
	QStringList buttons() const;
	/* The call shown, by id, or empty. */
	QString shown_id() const { return m_id; }

	/* The media it carries, for a host drawing the picture and for tests. */
	fzn_call_audio *audio() { return m_audio; }
	fzn_call_video *video() { return m_video; }

	/* The clock, seconds since 1970; 0 reads the system's. */
	void set_now(uint32_t utc_s) { m_now = utc_s; }

	/* A CALL RINGING HERE AS A SCREEN, sec 1247, fuzzypickles' walk: a thin
	 * bar is easy to miss. Allowed, the bar grows while a call rings here
	 * -- the caller large, Answer and Decline large beneath -- and the host
	 * is told as ringing starts and stops, to raise the bar over the page
	 * and let it go. */
	void set_screen(bool allowed);
	bool screen() const { return m_screen_on; }
	void on_ringing(std::function<void(bool ringing)> told) { m_ringing_told = told; }

private:
	uint32_t now() const;
	bool respond(const char *what, int state);
	void carry(const QString &id, bool up);

	struct fzn_gui_rpc *m_rpc;
	fzn_call_audio *m_audio;
	fzn_call_video *m_video;
	uint32_t m_now = 0;
	QString m_id, m_who;
	int m_state = 0;
	/* Each call seen, by id: who, its state and when it came up. */
	struct seen {
		QString who;
		int state;
		uint32_t up_at;
	};
	QHash<QString, seen> m_seen;
	QString m_ended;
	uint32_t m_ended_at = 0;
	QLabel *m_said;
	QPushButton *m_answer, *m_decline, *m_mute, *m_camera, *m_hang_up;
	class QBoxLayout *m_row;
	bool m_screen_allowed = false, m_screen_on = false, m_ringing = false;
	std::function<void(bool)> m_ringing_told;
	void as_screen(bool on);
};

#endif /* FZN_GUI_CALL_BAR_H */
