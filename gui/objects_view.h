/*
 * The estate's named objects as a widget other software hosts, sec 1102:
 * secs 948's on/off lamp and its kin -- `living_room_lamp = on`, set on one
 * host and read on every other -- put in front of a person.
 *
 * A ROW AN OBJECT: its name, its value, who set it and the words it allows.
 * A value is chosen from those words when the object names them, typed when
 * it takes any; Set sends it. A set the node holds for a moment (`ok held`,
 * sec 1037) says so, rather than reading back the old value and seeming lost.
 *
 * THROUGH THE TYPED CLIENT, sec 1098: the widget calls fzn_rpc_object_list
 * and _set, and the client's requests go to the node by the ask callback a
 * host hands in -- `fzn_notebook_view_socket_ask`, or a test's node -- so the
 * grammar is read in one place, the client, and not again here.
 *
 * AN OBJECT IS ADDED by its name and the words it allows -- `on off`, or
 * nothing for any word -- and the chosen one REMOVED, fuzzypickles' Objects
 * page's two other uses (sec 1104), so a consumer hosts this in its place.
 * refresh() is one `list object`, cheap enough for a host to call on every
 * `object` event the node publishes.
 *
 * WHAT THE NODE REFUSES IS SAID IN ITS WORDS, and a node that does not answer
 * says so: "no objects" and "the node did not answer" are different words.
 * NO Q_OBJECT AND THEREFORE NO moc: buttons connect to lambdas.
 */

#ifndef FZN_GUI_OBJECTS_VIEW_H
#define FZN_GUI_OBJECTS_VIEW_H

#include "notebook_view.h"

#include <QString>
#include <QStringList>
#include <QWidget>

struct fzn_gui_rpc;
class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;

class fzn_objects_view : public QWidget {
public:
	fzn_objects_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent = nullptr);
	~fzn_objects_view() override;

	/* Ask for every object and show them. Whether the node answered. */
	bool refresh();

	/* WHAT A PERSON DOES, public because a headless test cannot click:
	 * choose a row, choose or type a value, set it. Whether the node took it. */
	void select(int row);
	void choose(const QString &value);
	bool set();
	/* A new object's name and its allowed words, space separated, empty for
	 * any word; then add it. And remove the chosen row. */
	void name_new(const QString &name, const QString &words);
	bool add();
	bool remove();

	/* WHAT IS ON SCREEN: each row as NAME=VALUE, the words the chosen row
	 * offers, and the status line. */
	QStringList rows() const;
	QStringList offered() const;
	QString status() const;

private:
	struct fzn_gui_rpc *m_rpc; /* the typed client on the host's callback */

	QTableWidget *m_table;
	QComboBox *m_value;
	QPushButton *m_set;
	QPushButton *m_refresh;
	QLineEdit *m_new_name;
	QLineEdit *m_new_words;
	QPushButton *m_add;
	QPushButton *m_remove;
	QLabel *m_status;
	QStringList m_allowed; /* each row's allowed words, `*` for any */
};

#endif /* FZN_GUI_OBJECTS_VIEW_H */
