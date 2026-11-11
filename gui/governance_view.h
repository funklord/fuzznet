/*
 * The estate's governance as a widget other software hosts. sec 1023, asked
 * by fuzzypickles (inbox 20261111T0403Z): the node answered its roots, its
 * k, its votes, its successions, its staged changes and its profile, and no
 * client showed any of it.
 *
 * FIVE PARTS, a tab each, each read by its own verb and each saying for
 * itself when the node refused or did not answer -- a tab's title carries
 * its count, so what waits is seen without opening it:
 *
 *   - THE ROOTS AND k (`list root`, sec 1023): who the roots are, which one
 *     this host acts as, and how many votes it takes to revoke; `add root`,
 *     `remove root` and `set quorum` change them, a root's to do.
 *   - THE VOTES HELD (`list vote`, sec 1023): every vote to revoke this host
 *     holds, by the key it is against, as N of k. Adding this host's own vote
 *     is `revoke peer KEY`, asked first in a row of its own, since a vote that
 *     reaches k takes the device's grant with it. Below them the votes on a
 *     host's setting (sec 909), read from `list record under vote/` -- each
 *     voter's newest -- as a value on a host with N of k for it; joining one
 *     is `add vote setting HOST KEY VALUE` with what the listing showed
 *     (sec 1029).
 *   - THE SUCCESSIONS (`list succession`, sec 499): each re-key, counting or
 *     waiting for confirmations; confirming one is `add succession OLD`.
 *   - THE STAGED CHANGES (`list staged`, sec 873): each change that reverts
 *     at its deadline unless confirmed; confirming is `add confirm TOKEN`.
 *   - THE PROFILE (`get preset`, `list preset choices`, sec 1023): the one in
 *     force and those this build lets its user switch to; `set preset NAME`.
 *
 * A KEY IS SHOWN BY ITS FIRST 16 HEX DIGITS, the whole of it in the row's
 * tooltip and kept as the row's data, so an action on a row uses the key the
 * node named and not its shortening.
 *
 * WHAT THE NODE REFUSES IS SAID IN ITS WORDS, and a node that does not answer
 * says so, as the notebook does (sec 439).
 *
 * THE WAY TO ASK is the notebook's callback, so a host hands in
 * `fzn_notebook_view_socket_ask` and a test a node of its own. NO Q_OBJECT
 * AND THEREFORE NO moc: buttons connect to lambdas.
 */

#ifndef FZN_GUI_GOVERNANCE_VIEW_H
#define FZN_GUI_GOVERNANCE_VIEW_H

#include "notebook_view.h"

#include <QString>
#include <QStringList>
#include <QWidget>

class QComboBox;
class QLabel;
class QLineEdit;
class QListWidget;
class QPushButton;
class QSpinBox;
class QTabWidget;
class QWidget;

class fzn_governance_view : public QWidget {
public:
	fzn_governance_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent = nullptr);

	/* Read every part. Whether the node answered all of them. */
	bool refresh();

	/* WHAT A PERSON DOES, public because a headless test cannot click. A key
	 * is the one typed, or with nothing typed, the row selected. Each says
	 * what happened in its part's status, and returns whether the node took
	 * it. */
	void set_key(const QString &key);
	void select(QListWidget *list, int row);
	bool add_root();
	bool remove_root();
	bool set_k(int k);
	/* Two steps: the first shows the question, the second votes. */
	void ask_vote();
	bool vote();
	void cancel_vote();
	bool vote_setting();
	bool confirm_succession();
	bool confirm_staged();
	bool choose_preset(const QString &name);

	/* WHAT IS ON SCREEN: each row's text, and the full key or token it acts
	 * on. */
	QListWidget *roots_list() const { return m_roots; }
	QListWidget *votes_list() const { return m_votes; }
	QListWidget *setting_votes_list() const { return m_setting_votes; }
	QListWidget *successions_list() const { return m_successions; }
	QListWidget *staged_list() const { return m_staged; }
	QStringList rows(QListWidget *list) const;
	QStringList tab_titles() const;
	int k() const { return m_k_held; }
	QString preset() const;
	QStringList preset_choices() const;
	bool vote_asked() const;
	QString roots_status() const;
	QString votes_status() const;
	QString successions_status() const;
	QString staged_status() const;
	QString preset_status() const;

private:
	int ask(const QString &line, QString *detail);
	bool fill_roots();
	bool fill_votes();
	bool fill_setting_votes();
	bool fill_successions();
	bool fill_staged();
	bool fill_preset();
	QString key_for(QListWidget *list) const;
	bool act(const QString &line, QLabel *status, const QString &done);

	fzn_notebook_view_ask_t m_ask;
	void *m_ask_ctx;
	int m_k_held;

	QLineEdit *m_key;
	QTabWidget *m_tabs;
	QListWidget *m_roots;
	QSpinBox *m_k;
	QPushButton *m_add_root;
	QPushButton *m_remove_root;
	QPushButton *m_set_k;
	QLabel *m_roots_status;

	QListWidget *m_votes;
	QPushButton *m_vote;
	QWidget *m_vote_bar;
	QLabel *m_vote_question;
	QLabel *m_votes_status;
	QListWidget *m_setting_votes;
	QPushButton *m_vote_setting;

	QListWidget *m_successions;
	QPushButton *m_confirm_succession;
	QLabel *m_successions_status;

	QListWidget *m_staged;
	QPushButton *m_confirm_staged;
	QLabel *m_staged_status;

	QComboBox *m_presets;
	QPushButton *m_choose_preset;
	QLabel *m_preset_status;

	QPushButton *m_refresh;
};

#endif /* FZN_GUI_GOVERNANCE_VIEW_H */
