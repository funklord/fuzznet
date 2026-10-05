/*
 * The retention rules as a widget other software hosts. sec 485: secs 475
 * to 483's rules, which the node's socket has carried as verbs, put in front
 * of a person.
 *
 * TWO SETS, SIDE BY SIDE, because they are two decisions with two owners:
 * THIS NODE'S rules (`list retention`), set by its own user and applied to
 * its own log, and THE ESTATE'S (`list estate-retention`), set by a root or
 * an estate admin and applied on every host they reach. The estate's carry
 * a note saying so, read before the click.
 *
 * A RULE IS TYPED AS A LINE, the syntax `log/retain.h` gives -- `prune *
 * level=D age 7d` -- and shown in its canonical spelling as the node lists
 * it, so what is listed is what the node holds.
 *
 * WHAT THE NODE REFUSES IS SAID IN ITS WORDS: a rule that is not one, one
 * held already, a node that stands as neither a root nor an admin. A node
 * that does not answer says so, as the notebook does (sec 439): "no rules"
 * and "the node did not answer" are different words.
 *
 * THE WAY TO ASK is the notebook's callback, so a host hands in
 * `fzn_notebook_view_socket_ask` and a test a node of its own. NO Q_OBJECT
 * AND THEREFORE NO moc: buttons connect to lambdas.
 */

#ifndef FZN_GUI_RETENTION_VIEW_H
#define FZN_GUI_RETENTION_VIEW_H

#include "notebook_view.h"

#include <QString>
#include <QStringList>
#include <QWidget>

class QLabel;
class QLineEdit;
class QListWidget;
class QPushButton;

class fzn_retention_view : public QWidget {
public:
	fzn_retention_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent = nullptr);

	/* Ask for both sets and show them. Whether the node answered. */
	bool refresh();

	/* WHAT A PERSON DOES, public because a headless test cannot click. The
	 * rule is the line typed, or for a removal with nothing typed, the row
	 * selected. Whether the node took it. */
	void set_rule(const QString &rule);
	bool add(bool estate);
	bool remove(bool estate);
	void select(bool estate, int row);

	/* WHAT IS ON SCREEN. */
	QStringList node_rules() const;
	QStringList estate_rules() const;
	QString status() const;
	QString estate_status() const;

private:
	int ask(const QString &line, QString *detail);
	bool fill(bool estate);

	fzn_notebook_view_ask_t m_ask;
	void *m_ask_ctx;

	QLineEdit *m_rule;
	QListWidget *m_node;
	QListWidget *m_estate;
	QPushButton *m_add_node;
	QPushButton *m_remove_node;
	QPushButton *m_add_estate;
	QPushButton *m_remove_estate;
	QPushButton *m_refresh;
	QLabel *m_status;
	QLabel *m_estate_status;
	QLabel *m_estate_note;
};

#endif /* FZN_GUI_RETENTION_VIEW_H */
