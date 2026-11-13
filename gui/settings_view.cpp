/* The node's settings as a widget: gui/settings_view.h, sec 1103. */
#include "settings_view.h"

#include "rpc_ask.h"

#include <QCheckBox>
#include <QComboBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QHeaderView>
#include <QTreeWidget>
#include <QPushButton>
#include <QVBoxLayout>

#include <stdlib.h>
#include <string.h>

struct fzn_settings_view::entry {
	fzn_rpc_config_schema_entry_t schema;
	unsigned set_at; /* as last read */
};

fzn_settings_view::fzn_settings_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent)
    : QWidget(parent), m_rpc(new fzn_gui_rpc), m_entries(nullptr), m_count(0), m_shown(nullptr),
      m_shown_count(0), m_items(nullptr), m_keep(nullptr), m_keep_ctx(nullptr)
{
	fzn_gui_rpc_init(m_rpc, ask, ask_ctx);

	m_list = new QTreeWidget(this);
	m_list->setHeaderHidden(true);
	m_list->setColumnCount(1);
	m_value = new QComboBox(this);
	/* NAMED FOR A SCREEN READER, sec 1120. */
	m_list->setAccessibleName(tr("Settings"));
	m_value->setAccessibleName(tr("The chosen setting's value"));
	m_where = new QLabel(this);
	m_notes = new QLabel(this);
	m_notes->setWordWrap(true);
	m_apply = new QPushButton(tr("Apply"), this);
	m_refresh = new QPushButton(tr("Refresh"), this);
	m_status = new QLabel(this);
	m_status->setWordWrap(true);
	m_advanced = new QCheckBox(tr("Show advanced"), this);
	m_reach = new QPushButton(tr("Has it reached my other devices?"), this);
	m_reached = new QLabel(this);
	m_reached->setWordWrap(true);

	auto *row = new QHBoxLayout;
	row->addWidget(m_value, 1);
	row->addWidget(m_apply);
	row->addWidget(m_refresh);
	auto *col = new QVBoxLayout(this);
	col->addWidget(m_advanced);
	col->addWidget(m_list, 1);
	col->addWidget(m_where);
	col->addLayout(row);
	col->addWidget(m_notes);
	col->addWidget(m_reach);
	col->addWidget(m_reached);
	col->addWidget(m_status);

	/* A GROUP'S OWN ROW CHOOSES NOTHING: only a setting's does. */
	connect(m_list, &QTreeWidget::currentItemChanged,
	        [this](QTreeWidgetItem *, QTreeWidgetItem *) {
		        int r = current_row();
		        if (r >= 0)
			        select(r);
	        });
	connect(m_apply, &QPushButton::clicked, [this]() { apply(); });
	connect(m_refresh, &QPushButton::clicked, [this]() { refresh(); });
	connect(m_advanced, &QCheckBox::toggled, [this](bool on) { show_advanced(on); });
	connect(m_reach, &QPushButton::clicked, [this]() { reach(); });
	m_value->setEnabled(false);
	m_apply->setEnabled(false);
	m_reach->setEnabled(false);
}

fzn_settings_view::~fzn_settings_view()
{
	delete[] m_entries;
	delete[] m_shown;
	delete[] m_items;
	delete m_rpc;
}

static QString failed_words(const fzn_gui_rpc *r)
{
	return QString::fromUtf8(fzn_gui_rpc_silent(r));
}

bool fzn_settings_view::refresh()
{
	/* A PAGE OF THE SCHEMA IS LARGE, so it lives on the heap for the read. */
	auto *schema = new fzn_rpc_config_schema_resp_t;
	if (fzn_rpc_config_schema(&m_rpc->c, "", 0, schema) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		delete schema;
		return m_rpc->c.answered;
	}
	delete[] m_entries;
	delete[] m_shown;
	m_count = (int)schema->count;
	m_entries = new entry[schema->count ? schema->count : 1];
	m_shown = new int[schema->count ? schema->count : 1];
	delete[] m_items;
	m_items = new QTreeWidgetItem *[schema->count ? schema->count : 1];
	for (size_t i = 0; i < schema->count; i++) {
		m_entries[i].schema = schema->entries[i];
		m_entries[i].set_at = 0;
	}
	m_status->setText(schema->truncated ? tr("More settings than one page shows.")
	                  : schema->count ? QString()
	                                  : tr("The node declares no settings."));
	delete schema;
	return fill();
}

/* THE LISTED ROWS: every setting, an advanced one only when asked for. */
bool fzn_settings_view::fill()
{
	m_list->blockSignals(true);
	m_list->clear();
	m_shown_count = 0;
	/* GROUP BY THE FIRST PART, each group where its first key falls, and the
	 * rows numbered in the order they are drawn. */
	QStringList order;
	for (int i = 0; i < m_count; i++) {
		QString key = QString::fromUtf8(m_entries[i].schema.key);
		QString group = key.section(QLatin1Char('.'), 0, 0);
		if (!order.contains(group))
			order << group;
	}
	for (const QString &group : order) {
		QTreeWidgetItem *head = nullptr;
		for (int i = 0; i < m_count; i++) {
			const fzn_rpc_config_schema_entry_t *e = &m_entries[i].schema;
			QString key = QString::fromUtf8(e->key);
			if (key.section(QLatin1Char('.'), 0, 0) != group)
				continue;
			if ((e->flags & FZN_SCHEMA_ADVANCED) && !m_advanced->isChecked())
				continue;
			/* THE HOST'S OWN RULE, said by its filter. */
			if (m_keep && !m_keep(m_keep_ctx, e->key))
				continue;
			/* NEVER PAST THE ARRAYS, which hold one row a setting. */
			if (m_shown_count >= m_count)
				break;
			if (!head) {
				head = new QTreeWidgetItem(m_list, { group });
				head->setFlags(Qt::ItemIsEnabled);
				head->setExpanded(true);
			}
			auto *item = new QTreeWidgetItem(head, { key + QStringLiteral(" -- ")
			                                         + QString::fromUtf8(e->summary) });
			m_items[m_shown_count] = item;
			m_shown[m_shown_count++] = i;
		}
	}
	m_list->expandAll();
	m_list->blockSignals(false);
	m_value->clear();
	m_value->setEnabled(false);
	m_apply->setEnabled(false);
	m_reach->setEnabled(false);
	m_where->clear();
	m_notes->clear();
	m_reached->clear();
	return true;
}

void fzn_settings_view::show_advanced(bool on)
{
	if (m_advanced->isChecked() != on) {
		m_advanced->setChecked(on); /* toggled() calls back here */
		return;
	}
	fill();
}

int fzn_settings_view::current_row() const
{
	QTreeWidgetItem *at = m_list->currentItem();
	for (int i = 0; at && i < m_shown_count; i++)
		if (m_items[i] == at)
			return i;
	return -1;
}

int fzn_settings_view::chosen_entry() const
{
	int row = current_row();
	return row >= 0 ? m_shown[row] : -1;
}

void fzn_settings_view::set_filter(keep_fn keep, void *ctx)
{
	m_keep = keep;
	m_keep_ctx = ctx;
	fill();
}

QStringList fzn_settings_view::groups() const
{
	QStringList out;
	for (int i = 0; i < m_list->topLevelItemCount(); i++)
		out << m_list->topLevelItem(i)->text(0);
	return out;
}

bool fzn_settings_view::reach()
{
	int at = chosen_entry();
	if (at < 0)
		return false;
	const fzn_rpc_config_schema_entry_t *e = &m_entries[at].schema;
	/* A HOST'S OWN SETTING never leaves it, which the schema says already. */
	if (!(e->scopes & FZN_SCHEMA_ESTATE)) {
		m_reached->setText(tr("This setting is this host's own; other devices do not hold it."));
		return true;
	}
	auto *got = new fzn_rpc_config_status_resp_t;
	if (fzn_rpc_config_status(&m_rpc->c, e->key, e->key_len, nullptr, 0, got) != FZN_RPC_OK) {
		/* A HOST'S OWN SETTING IS SAID SO in the node's words. */
		m_reached->setText(failed_words(m_rpc));
		delete got;
		return m_rpc->c.answered;
	}
	QStringList said;
	said << tr("This host is at version %1.").arg(got->local_seq);
	for (size_t i = 0; i < got->count; i++) {
		const fzn_rpc_config_status_row_t *r = &got->rows[i];
		QString who = QString::fromUtf8(r->name, (int)r->name_len);
		said << (r->acked >= got->local_seq ? tr("%1 has it.").arg(who)
		         : r->acked                 ? tr("%1 is behind, at %2.").arg(who).arg(r->acked)
		                                    : tr("%1 has not heard yet.").arg(who));
	}
	if (!got->count)
		said << tr("No other device holds it.");
	m_reached->setText(said.join(QLatin1Char(' ')));
	delete got;
	return true;
}

bool fzn_settings_view::select(int row)
{
	if (row < 0 || row >= m_shown_count)
		return false;
	if (current_row() != row) {
		m_list->blockSignals(true);
		m_list->setCurrentItem(m_items[row]);
		m_list->blockSignals(false);
	}
	entry *en = &m_entries[m_shown[row]];
	const fzn_rpc_config_schema_entry_t *e = &en->schema;
	fzn_rpc_config_get_resp_t got;
	if (fzn_rpc_config_get(&m_rpc->c, e->key, e->key_len, &got) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	en->set_at = got.set_at;
	const bool sensitive = e->flags & FZN_SCHEMA_SENSITIVE;
	const QString def = QString::fromUtf8(e->default_value);

	/* THE DEFAULT IS A CHOICE, FIRST, AND SAYS WHAT IT IS NOW. */
	m_value->clear();
	m_value->addItem(sensitive || def.isEmpty() ? tr("Default") : tr("Default (%1)").arg(def));
	m_value->setEditable(e->type != FZN_SCHEMA_FLAG);
	if (e->type == FZN_SCHEMA_FLAG)
		m_value->addItems({ QStringLiteral("on"), QStringLiteral("off") });
	if (!got.set_at)
		m_value->setCurrentIndex(0);
	else if (e->type == FZN_SCHEMA_FLAG)
		m_value->setCurrentIndex(m_value->findText(QString::fromUtf8(got.value)));
	else
		/* A SENSITIVE ONE ARRIVES EMPTY: the client withholds it (rpc.c). */
		m_value->setEditText(QString::fromUtf8(got.value));
	m_value->setEnabled(true);
	m_apply->setEnabled(true);
	m_reach->setEnabled(true);
	m_reached->clear();

	m_where->setText(got.set_at == FZN_SCHEMA_HOST     ? tr("Set on this host.")
	                 : got.set_at == FZN_SCHEMA_ESTATE ? tr("Set above this host, for its group or "
	                                                        "the whole estate.")
	                                                   : tr("Following the default."));

	QStringList notes;
	const QString unit = QString::fromUtf8(e->unit);
	if (e->type == FZN_SCHEMA_COUNT && e->max)
		notes << tr("%1 to %2 %3").arg(e->min).arg(e->max).arg(unit).trimmed();
	else if (e->type == FZN_SCHEMA_DURATION && e->max)
		notes << tr("A duration, %1 s to %2 s.").arg(e->min).arg(e->max);
	if (e->flags & FZN_SCHEMA_RESTART)
		notes << tr("Takes effect after a restart.");
	if (e->flags & FZN_SCHEMA_ADVERTISED)
		notes << tr("Peers can see this value.");
	if (sensitive)
		notes << (got.configured ? tr("A value is set; it is not shown.") : tr("No value is set."));
	m_notes->setText(notes.join(QLatin1Char(' ')));
	m_status->clear();
	return true;
}

void fzn_settings_view::choose(const QString &value)
{
	int at = m_value->findText(value);
	if (at >= 0)
		m_value->setCurrentIndex(at);
	else if (m_value->isEditable())
		m_value->setEditText(value);
}

bool fzn_settings_view::apply()
{
	int row = current_row();
	int at = chosen_entry();
	if (at < 0)
		return false;
	const fzn_rpc_config_schema_entry_t *e = &m_entries[at].schema;
	const bool follow = m_value->currentText() == m_value->itemText(0);
	int rc;
	int restart = 0;

	if (follow) {
		rc = fzn_rpc_config_clear(&m_rpc->c, e->key, e->key_len);
	} else {
		QByteArray v = m_value->currentText().toUtf8();
		if (v.isEmpty()) {
			m_status->setText(tr("Type a value, or choose the default."));
			return false;
		}
		rc = fzn_rpc_config_set(&m_rpc->c, e->key, e->key_len, v.constData(), (size_t)v.size(),
		                        nullptr, 0, &restart);
	}
	if (rc != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	const bool held = m_rpc->c.held;
	select(row);
	m_status->setText(held ? tr("Taken; it is being written.")
	                  : follow ? tr("Following the default.")
	                           : tr("Set."));
	return true;
}

QStringList fzn_settings_view::keys() const
{
	QStringList out;
	for (int i = 0; i < m_shown_count; i++)
		out << QString::fromUtf8(m_entries[m_shown[i]].schema.key);
	return out;
}

QStringList fzn_settings_view::offered() const
{
	QStringList out;
	for (int i = 0; i < m_value->count(); i++)
		out << m_value->itemText(i);
	return out;
}

QString fzn_settings_view::chosen() const { return m_value->currentText(); }
QString fzn_settings_view::where() const { return m_where->text(); }
QString fzn_settings_view::notes() const { return m_notes->text(); }
QString fzn_settings_view::status() const { return m_status->text(); }
QString fzn_settings_view::reached() const { return m_reached->text(); }
