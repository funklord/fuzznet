/*
 * gui/press_again.h -- an act confirmed by asking for it again, sec 1515.
 *
 * A dialog is a second top-level window, which Qt's Android plugin aborts an
 * app for making under TalkBack (combo.h, menu_exec.h), so a view confirms a
 * one-way act -- removing a contact, leaving a group -- by its button pressed
 * again within FZN_PRESS_AGAIN_S, the first press saying what the second
 * will do. The conversations list's deletions (sec 1246) and the sticker
 * picker's Let go do the same by hand.
 *
 * Header-only, with no Q_OBJECT.
 */
#ifndef FZN_GUI_PRESS_AGAIN_H
#define FZN_GUI_PRESS_AGAIN_H

#include <QDateTime>
#include <QString>

#define FZN_PRESS_AGAIN_S 10

struct fzn_press_again {
	QString armed;
	qint64 at = 0;

	/* WHETHER `what` WAS ASKED FOR JUST NOW: false on the first press,
	 * which arms it; true on a second for the same `what` in time. */
	bool confirmed(const QString &what)
	{
		const qint64 now = QDateTime::currentSecsSinceEpoch();
		if (armed != what || now > at + FZN_PRESS_AGAIN_S) {
			armed = what;
			at = now;
			return false;
		}
		armed.clear();
		return true;
	}
};

#endif
