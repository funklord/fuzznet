/* See retention_view.h. */

#include "retention_view.h"
#include "plain_label.h"
#include "keep_place.h"
#include "rpc_ask.h"

#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPushButton>
#include <QVBoxLayout>

#include <cstring>

fzn_retention_view::fzn_retention_view(fzn_notebook_view_ask_t ask, void *ask_ctx,
                                       QWidget *parent)
        : QWidget(parent), m_rpc(new fzn_gui_rpc)
{
	fzn_gui_rpc_init(m_rpc, ask, ask_ctx);
	auto *outer = new QVBoxLayout(this);
	/* ONE ABOVE THE OTHER, sec 1120: side by side they made the view 360 px,
	 * past a folding phone's 320 px cover screen. */
	auto *lists = new QVBoxLayout();
	auto *node_col = new QVBoxLayout();
	auto *estate_col = new QVBoxLayout();
	auto *node_buttons = new QHBoxLayout();
	auto *estate_buttons = new QHBoxLayout();

	m_rule = new QLineEdit(this);
	m_rule->setPlaceholderText(QStringLiteral("prune|keep PROGRAM|* [copy] [level=CEWNIVDT] "
	                                          "[subsystem=PATH] [text=MATCH] age|size|count N"));
	m_node = new QListWidget(this);
	m_estate = new QListWidget(this);
	m_add_node = new QPushButton(QStringLiteral("Add"), this);
	m_remove_node = new QPushButton(QStringLiteral("Remove"), this);
	m_add_estate = new QPushButton(QStringLiteral("Add"), this);
	m_remove_estate = new QPushButton(QStringLiteral("Remove"), this);
	m_refresh = new QPushButton(QStringLiteral("Refresh"), this);
	/* SPOKEN NAMES, sec 1120: the two Adds and the two Removes say which
	 * list they act on, and the rule line and lists are named. */
	m_rule->setAccessibleName(QStringLiteral("A retention rule"));
	m_node->setAccessibleName(QStringLiteral("This node's rules"));
	m_estate->setAccessibleName(QStringLiteral("The estate's rules"));
	m_add_node->setAccessibleName(QStringLiteral("Add to this node's rules"));
	m_remove_node->setAccessibleName(QStringLiteral("Remove from this node's rules"));
	m_add_estate->setAccessibleName(QStringLiteral("Add to the estate's rules"));
	m_remove_estate->setAccessibleName(QStringLiteral("Remove from the estate's rules"));
	m_status = fzn_plain_label(this);
	m_status->setWordWrap(true);
	m_estate_status = fzn_plain_label(this);
	m_estate_status->setWordWrap(true);
	/* SAID BEFORE THE CLICK: an estate rule is not this host's alone. */
	m_estate_note = fzn_plain_label(QStringLiteral("An estate rule applies on every host it reaches; "
	                                          "setting one needs a root or an admin."),
	                           this);
	m_estate_note->setWordWrap(true);

	node_col->addWidget(fzn_plain_label(QStringLiteral("This node's rules"), this));
	node_col->addWidget(m_node, 1);
	node_buttons->addWidget(m_add_node);
	node_buttons->addWidget(m_remove_node);
	node_col->addLayout(node_buttons);
	node_col->addWidget(m_status);
	estate_col->addWidget(fzn_plain_label(QStringLiteral("The estate's rules"), this));
	estate_col->addWidget(m_estate, 1);
	estate_buttons->addWidget(m_add_estate);
	estate_buttons->addWidget(m_remove_estate);
	estate_col->addLayout(estate_buttons);
	estate_col->addWidget(m_estate_status);
	lists->addLayout(node_col, 1);
	lists->addLayout(estate_col, 1);
	outer->addWidget(m_rule);
	outer->addLayout(lists, 1);
	/* FULL WIDTH, so it is read whole at any width. */
	outer->addWidget(m_estate_note);
	outer->addWidget(m_refresh);

	connect(m_add_node, &QPushButton::clicked, this, [this]() { add(false); });
	connect(m_remove_node, &QPushButton::clicked, this, [this]() { remove(false); });
	connect(m_add_estate, &QPushButton::clicked, this, [this]() { add(true); });
	connect(m_remove_estate, &QPushButton::clicked, this, [this]() { remove(true); });
	connect(m_refresh, &QPushButton::clicked, this, [this]() { refresh(); });
	refresh();
}

fzn_retention_view::~fzn_retention_view() { delete m_rpc; }

/* One set into its list, through the typed client (sec 1258). */
bool fzn_retention_view::fill(bool estate)
{
	QListWidget *list = estate ? m_estate : m_node;
	QLabel *status = estate ? m_estate_status : m_status;
	auto *rules = new fzn_rpc_rules_t;
	size_t i;

	fzn_keep_place kept(list);

	list->clear();
	if (fzn_rpc_rules(&m_rpc->c, estate ? 1 : 0, rules) != FZN_RPC_OK) {
		const QString why = QString::fromUtf8(fzn_gui_rpc_silent(m_rpc));
		const bool silent = !m_rpc->c.answered;

		delete rules;
		status->setText(why.isEmpty() ? QStringLiteral("The node refused the listing.") : why);
		return !silent;
	}
	for (i = 0; i < rules->count; i++)
		list->addItem(QString::fromUtf8(rules->rule[i]));
	status->setText(rules->overflow ? QStringLiteral("%1 rule(s), and more than this lists.").arg(list->count())
	                : list->count() ? QStringLiteral("%1 rule(s).").arg(list->count())
	                                : QStringLiteral("No rules."));
	delete rules;
	return true;
}

bool fzn_retention_view::refresh()
{
	bool here = fill(false), estate = fill(true);

	return here && estate;
}

void fzn_retention_view::set_rule(const QString &rule)
{
	m_rule->setText(rule);
}

void fzn_retention_view::select(bool estate, int row)
{
	(estate ? m_estate : m_node)->setCurrentRow(row);
}

/* A RULE ADDED OR REMOVED, the node's refusal in its words. */
bool fzn_retention_view::change(bool estate, bool add, const QString &rule)
{
	QLabel *status = estate ? m_estate_status : m_status;
	const QByteArray bytes = rule.toUtf8();

	if (fzn_rpc_rule_change(&m_rpc->c, estate ? 1 : 0, add ? 1 : 0, bytes.constData(), (size_t)bytes.size())
	    != FZN_RPC_OK) {
		const QString why = QString::fromUtf8(fzn_gui_rpc_silent(m_rpc));

		status->setText(why.isEmpty() ? (add ? QStringLiteral("The node refused the rule.")
		                                     : QStringLiteral("The node refused."))
		                              : why);
		return false;
	}
	m_rule->clear();
	fill(estate);
	return true;
}

bool fzn_retention_view::add(bool estate)
{
	const QString rule = m_rule->text().trimmed();

	if (rule.isEmpty()) {
		(estate ? m_estate_status : m_status)->setText(QStringLiteral("Type a rule first."));
		return false;
	}
	return change(estate, true, rule);
}

bool fzn_retention_view::remove(bool estate)
{
	QListWidget *list = estate ? m_estate : m_node;
	QString rule = m_rule->text().trimmed();

	/* THE ROW SELECTED, when nothing is typed: a listed rule is removed by
	 * the spelling the node listed it in. */
	if (rule.isEmpty() && list->currentItem())
		rule = list->currentItem()->text();
	if (rule.isEmpty()) {
		(estate ? m_estate_status : m_status)->setText(QStringLiteral("Type or select a rule first."));
		return false;
	}
	return change(estate, false, rule);
}

QStringList fzn_retention_view::node_rules() const
{
	QStringList out;
	int i;

	for (i = 0; i < m_node->count(); i++)
		out << m_node->item(i)->text();
	return out;
}

QStringList fzn_retention_view::estate_rules() const
{
	QStringList out;
	int i;

	for (i = 0; i < m_estate->count(); i++)
		out << m_estate->item(i)->text();
	return out;
}

QString fzn_retention_view::status() const
{
	return m_status->text();
}

QString fzn_retention_view::estate_status() const
{
	return m_estate_status->text();
}
