/*
 * The node's declared settings as a widget other software hosts, sec 1103:
 * secs 686's schema -- every setting the node declares, its type, where it
 * may stand and what it means -- put in front of a person.
 *
 * A ROW A SETTING, its key and summary. Chosen, it shows its value and
 * WHERE IT STANDS: set on this host, set above it (its group or the estate),
 * or following the default. Every setting offers "Default (VALUE)" beside a
 * value of the person's own, so following the default is a choice they make
 * and the node stores as one -- a clear, not today's default written down
 * (a config file records choices, not values).
 *
 * IT DOES NOT VALIDATE. THE NODE DOES, as the configuration form leaves it to
 * the CLI's parser (sec 164): a flag offers `on` and `off`, every other type
 * takes words, and a value the node refuses is said in its words. What the
 * schema says beside a value is shown: its unit and bounds, that it waits for
 * a restart, that peers can see it, and a sensitive one's value is never
 * shown, only whether one is set.
 *
 * ADVANCED SETTINGS WAIT until "Show advanced" is ticked, so the first list a
 * person sees is the handful they change; and "Has it reached my other
 * devices?" says, for a setting the estate shares, this host's version and
 * each other host's (fuzzypickles' page's two other uses, sec 1106).
 *
 * Through the typed client on the host's ask callback (`rpc_ask.h`), as the
 * objects view is. NO Q_OBJECT AND THEREFORE NO moc.
 */

#ifndef FZN_GUI_SETTINGS_VIEW_H
#define FZN_GUI_SETTINGS_VIEW_H

#include "notebook_view.h"

#include <QString>
#include <QStringList>
#include <QWidget>

struct fzn_gui_rpc;
class QCheckBox;
class QComboBox;
class QLabel;
class QListWidget;
class QPushButton;

class fzn_settings_view : public QWidget {
public:
	fzn_settings_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent = nullptr);
	~fzn_settings_view() override;

	/* Ask for the schema and list it. Whether the node answered. */
	bool refresh();

	/* WHAT A PERSON DOES, public because a headless test cannot click:
	 * choose a setting, choose "Default (...)" or a value (or type one), and
	 * apply. Whether the node took it. */
	bool select(int row);
	void choose(const QString &value);
	bool apply();
	/* List the advanced settings too, or hide them again. */
	void show_advanced(bool on);
	/* Ask where the chosen setting has reached. Whether the node answered. */
	bool reach();

	/* WHAT IS ON SCREEN: the keys listed, the choices the chosen one offers
	 * (the first is always the default), the one chosen, where its value
	 * stands, the notes the schema adds, and the status line. */
	QStringList keys() const;
	QStringList offered() const;
	QString chosen() const;
	QString where() const;
	QString notes() const;
	QString status() const;
	QString reached() const;

private:
	struct fzn_gui_rpc *m_rpc;
	struct entry;
	entry *m_entries;
	int m_count;
	int *m_shown; /* the listed rows' entries, advanced ones left out unless asked */
	int m_shown_count;
	bool fill();
	int chosen_entry() const;

	QListWidget *m_list;
	QComboBox *m_value;
	QLabel *m_where;
	QLabel *m_notes;
	QPushButton *m_apply;
	QPushButton *m_refresh;
	QCheckBox *m_advanced;
	QPushButton *m_reach;
	QLabel *m_reached;
	QLabel *m_status;
};

#endif /* FZN_GUI_SETTINGS_VIEW_H */
