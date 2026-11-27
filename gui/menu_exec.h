/*
 * gui/menu_exec.h -- every view's menu opened through one hook, sec 1511.
 *
 * On Android a QMenu is a Qt::Popup, a second top-level window, and Qt
 * 6.12's Android plugin aborts a Widgets app that makes one while an
 * accessibility service runs -- TalkBack among them (`combo.h` records the
 * finding). fuzzypickles hosts the library view since its 3028a301, so its
 * Share menu aborted the app for a TalkBack user (inbox 20261127T0735Z).
 *
 * So a view opens a menu with `fzn_menu_exec`, never `exec` or `popup`, and
 * a host may set one hook for all of them -- fuzzypickles' runs the menu as
 * a sheet inside its window, with a nested loop, keeping exec's shape: it
 * returns the action chosen, or null. With no hook set it is `exec(at)`.
 * `make style` refuses a menu's own `exec(` or `popup(` in gui/ elsewhere.
 *
 * Header-only, so a view's test links nothing more. The hook lives in an
 * inline function's static, which is one object across every translation
 * unit -- a `static` free function would give each its own, and a hook set
 * in one would not be seen by another.
 */
#ifndef FZN_GUI_MENU_EXEC_H
#define FZN_GUI_MENU_EXEC_H

#include <QAction>
#include <QMenu>
#include <QPoint>

#include <functional>

/* Handed the menu, the widget it is for, and where Qt would have shown it:
 * the action chosen, or null for none. */
using fzn_menu_exec_fn = std::function<QAction *(QMenu *menu, QWidget *context, const QPoint &at)>;

inline fzn_menu_exec_fn &fzn_menu_exec_hook()
{
	static fzn_menu_exec_fn hook;
	return hook;
}

/* ONE HOOK FOR EVERY VIEW'S MENUS, set before or after they are made: read
 * at each opening. An empty function clears it. */
inline void fzn_menu_set_exec(fzn_menu_exec_fn hook) { fzn_menu_exec_hook() = std::move(hook); }

inline QAction *fzn_menu_exec(QMenu *menu, QWidget *context, const QPoint &at)
{
	if (fzn_menu_exec_hook())
		return fzn_menu_exec_hook()(menu, context, at);
	return menu->exec(at); /* menu-exec-allow: the one place */
}

#endif
