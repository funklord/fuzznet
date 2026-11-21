/*
 * gui/combo.h -- the chooser every view here makes, sec 1357.
 *
 * On Android a QComboBox's list is a Qt::Popup, a second top-level window,
 * and Qt 6.12's Android plugin aborts a Widgets app that makes one while an
 * accessibility service runs -- TalkBack among them, so the person who needs
 * the screen read to them loses the app on opening a chooser (fuzzypickles'
 * finding, measured in hydra for a QMenu, a Qt::Popup and a QDialog). A host
 * that shows its choosers inside its own window -- fuzzypickles lists the rows
 * in a sheet -- could not reach these views' combos from outside: TalkBack
 * opens a combo through its accessibility action, which calls `showPopup()`
 * itself.
 *
 * So every view makes an `fzn_combo_box`, and a host may set one hook for all
 * of them: handed the combo, it shows the choice its own way and answers
 * true, or answers false for the ordinary list. With no hook set it is a
 * QComboBox. Header-only, so a view's test links nothing more.
 */
#ifndef FZN_GUI_COMBO_H
#define FZN_GUI_COMBO_H

#include <QComboBox>

#include <functional>

class fzn_combo_box : public QComboBox {
public:
	/* True when the host showed the choice itself; false for Qt's list. */
	using popup_fn = std::function<bool(QComboBox *)>;

	explicit fzn_combo_box(QWidget *parent = nullptr) : QComboBox(parent) {}

	/* ONE HOOK FOR EVERY VIEW's combos, set before or after they are made:
	 * read at each opening. An empty function clears it. */
	static void set_popup(popup_fn hook) { popup_hook() = std::move(hook); }

	void showPopup() override
	{
		if (popup_hook() && popup_hook()(this))
			return;
		QComboBox::showPopup();
	}

private:
	static popup_fn &popup_hook()
	{
		static popup_fn hook;
		return hook;
	}
};

#endif
