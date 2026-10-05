/* See retention_view.h. */

#include "retention_view.h"

extern "C" {
#include "../local/vocabulary.h"
}

#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPushButton>
#include <QVBoxLayout>

#include <cstring>

/* A reply line at its longest. */
static const size_t REPLY_CAP = FZN_REPLY_MAX + 2u;

/* `%XX` back to the byte, as `node/admin.c` escapes a rule into one word. */
static QString unescape(const QString &word)
{
	QByteArray in = word.toUtf8(), out;
	int i;

	for (i = 0; i < in.size(); i++) {
		bool ok = false;

		if (in[i] == '%' && i + 2 < in.size()) {
			int v = in.mid(i + 1, 2).toInt(&ok, 16);

			if (ok) {
				out.append((char)v);
				i += 2;
				continue;
			}
		}
		out.append(in[i]);
	}
	return QString::fromUtf8(out);
}

fzn_retention_view::fzn_retention_view(fzn_notebook_view_ask_t ask, void *ask_ctx,
                                       QWidget *parent)
        : QWidget(parent), m_ask(ask), m_ask_ctx(ask_ctx)
{
	auto *outer = new QVBoxLayout(this);
	auto *lists = new QHBoxLayout();
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
	m_status = new QLabel(this);
	m_status->setWordWrap(true);
	m_estate_status = new QLabel(this);
	m_estate_status->setWordWrap(true);
	/* SAID BEFORE THE CLICK: an estate rule is not this host's alone. */
	m_estate_note = new QLabel(QStringLiteral("An estate rule applies on every host it reaches; "
	                                          "setting one needs a root or an admin."),
	                           this);
	m_estate_note->setWordWrap(true);

	node_col->addWidget(new QLabel(QStringLiteral("This node's rules"), this));
	node_col->addWidget(m_node, 1);
	node_buttons->addWidget(m_add_node);
	node_buttons->addWidget(m_remove_node);
	node_col->addLayout(node_buttons);
	node_col->addWidget(m_status);
	estate_col->addWidget(new QLabel(QStringLiteral("The estate's rules"), this));
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

/* 1 ok, 0 refused with `detail` the node's words, -1 no answer. */
int fzn_retention_view::ask(const QString &line, QString *detail)
{
	char reply[REPLY_CAP];
	const uint8_t *d = nullptr;
	size_t len, d_len = 0;
	QByteArray bytes = line.toUtf8();
	fzn_reply_t kind;

	if (detail)
		detail->clear();
	if (!m_ask || bytes.size() >= (int)FZN_REQUEST_MAX || bytes.contains('\n'))
		return 0;
	len = m_ask(m_ask_ctx, bytes.constData(), reply, sizeof(reply));
	if (len == 0u || len >= sizeof(reply))
		return -1;
	while (len && (reply[len - 1u] == '\n' || reply[len - 1u] == '\r'))
		len--;
	kind = fzn_reply_of((const uint8_t *)reply, len, &d, &d_len);
	if (detail && d)
		*detail = QString::fromUtf8((const char *)d, (int)d_len);
	return kind == FZN_REPLY_OK ? 1 : 0;
}

/* One set, `ok COUNT RULE ...`, into its list. */
bool fzn_retention_view::fill(bool estate)
{
	QListWidget *list = estate ? m_estate : m_node;
	QLabel *status = estate ? m_estate_status : m_status;
	QString detail;
	int r = ask(estate ? QStringLiteral("list estate-retention") : QStringLiteral("list retention"),
	            &detail);
	QStringList words;
	int i;

	list->clear();
	if (r < 0) {
		status->setText(QStringLiteral("The node did not answer."));
		return false;
	}
	if (r == 0) {
		status->setText(detail.isEmpty() ? QStringLiteral("The node refused the listing.")
		                                 : detail);
		return true;
	}
	words = detail.split(QLatin1Char(' '), Qt::SkipEmptyParts);
	/* AS MANY AS THE COUNT SAYS, and no more: a word past them is not a
	 * rule, whatever else the reply carries. */
	{
		bool ok = false;
		int count = words.isEmpty() ? 0 : words[0].toInt(&ok);

		if (!ok || count < 0 || count > words.size() - 1) {
			status->setText(QStringLiteral("The node's listing did not read."));
			return true;
		}
		for (i = 1; i <= count; i++)
			list->addItem(unescape(words[i]));
	}
	status->setText(list->count() ? QStringLiteral("%1 rule(s).").arg(list->count())
	                              : QStringLiteral("No rules."));
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

bool fzn_retention_view::add(bool estate)
{
	QLabel *status = estate ? m_estate_status : m_status;
	QString rule = m_rule->text().trimmed(), detail;
	int r;

	if (rule.isEmpty()) {
		status->setText(QStringLiteral("Type a rule first."));
		return false;
	}
	r = ask((estate ? QStringLiteral("add estate-retention ") : QStringLiteral("add retention "))
	                + rule,
	        &detail);
	if (r < 0) {
		status->setText(QStringLiteral("The node did not answer."));
		return false;
	}
	if (r == 0) {
		status->setText(detail.isEmpty() ? QStringLiteral("The node refused the rule.") : detail);
		return false;
	}
	m_rule->clear();
	fill(estate);
	return true;
}

bool fzn_retention_view::remove(bool estate)
{
	QListWidget *list = estate ? m_estate : m_node;
	QLabel *status = estate ? m_estate_status : m_status;
	QString rule = m_rule->text().trimmed(), detail;
	int r;

	/* THE ROW SELECTED, when nothing is typed: a listed rule is removed by
	 * the spelling the node listed it in. */
	if (rule.isEmpty() && list->currentItem())
		rule = list->currentItem()->text();
	if (rule.isEmpty()) {
		status->setText(QStringLiteral("Type or select a rule first."));
		return false;
	}
	r = ask((estate ? QStringLiteral("remove estate-retention ")
	                : QStringLiteral("remove retention "))
	                + rule,
	        &detail);
	if (r < 0) {
		status->setText(QStringLiteral("The node did not answer."));
		return false;
	}
	if (r == 0) {
		status->setText(detail.isEmpty() ? QStringLiteral("The node refused.") : detail);
		return false;
	}
	m_rule->clear();
	fill(estate);
	return true;
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
