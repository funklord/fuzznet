/* The named objects as a widget: gui/objects_view.h, sec 1102. */
#include "objects_view.h"

#include "rpc_ask.h"

#include <QComboBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

#include <stdlib.h>
#include <string.h>

fzn_objects_view::fzn_objects_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent)
    : QWidget(parent), m_rpc(new fzn_gui_rpc)
{
	fzn_gui_rpc_init(m_rpc, ask, ask_ctx);

	m_table = new QTableWidget(0, 4, this);
	m_table->setHorizontalHeaderLabels({ tr("Object"), tr("Value"), tr("Set by"), tr("Allows") });
	m_table->horizontalHeader()->setStretchLastSection(true);
	m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_table->setSelectionMode(QAbstractItemView::SingleSelection);
	m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
	m_value = new QComboBox(this);
	m_set = new QPushButton(tr("Set"), this);
	m_refresh = new QPushButton(tr("Refresh"), this);
	m_status = new QLabel(this);
	m_status->setWordWrap(true);

	auto *row = new QHBoxLayout;
	row->addWidget(m_value, 1);
	row->addWidget(m_set);
	row->addWidget(m_refresh);
	auto *col = new QVBoxLayout(this);
	col->addWidget(m_table, 1);
	col->addLayout(row);
	col->addWidget(m_status);

	connect(m_table, &QTableWidget::currentCellChanged,
	        [this](int r, int, int, int) { select(r); });
	connect(m_set, &QPushButton::clicked, [this]() { set(); });
	connect(m_refresh, &QPushButton::clicked, [this]() { refresh(); });
	select(-1);
}

fzn_objects_view::~fzn_objects_view() { delete m_rpc; }

bool fzn_objects_view::refresh()
{
	fzn_rpc_object_list_resp_t list;

	memset(&list, 0, sizeof list);
	int rc = fzn_rpc_object_list(&m_rpc->c, &list);
	if (rc != FZN_RPC_OK) {
		free(list.entries);
		m_status->setText(m_rpc->c.answered ? QString::fromUtf8(m_rpc->c.error)
		                                    : tr("The node did not answer."));
		return m_rpc->c.answered;
	}
	m_table->setRowCount((int)list.count);
	m_allowed.clear();
	for (size_t i = 0; i < list.count; i++) {
		const fzn_rpc_object_t *o = &list.entries[i];
		/* A SETTER'S KEY, shortened: the full one is the node's to show. */
		QString by = QString::fromUtf8(o->by).left(16);

		m_table->setItem((int)i, 0, new QTableWidgetItem(QString::fromUtf8(o->name)));
		m_table->setItem((int)i, 1, new QTableWidgetItem(o->value[0] ? QString::fromUtf8(o->value)
		                                                             : tr("(not set)")));
		m_table->setItem((int)i, 2, new QTableWidgetItem(by));
		m_table->setItem((int)i, 3, new QTableWidgetItem(QString::fromUtf8(o->allowed)));
		m_allowed.append(QString::fromUtf8(o->allowed));
	}
	free(list.entries);
	m_status->setText(list.count ? QString() : tr("No objects."));
	select(m_table->currentRow());
	return true;
}

void fzn_objects_view::select(int row)
{
	m_value->clear();
	bool chosen = row >= 0 && row < m_allowed.size();
	if (chosen) {
		/* `on|off` NAMES THE WORDS; `*` or nothing takes any, typed. */
		const QString &allowed = m_allowed.at(row);
		bool any = allowed.isEmpty() || allowed == QStringLiteral("*");
		m_value->setEditable(any);
		if (!any)
			m_value->addItems(allowed.split(QLatin1Char('|'), Qt::SkipEmptyParts));
		if (m_table->currentRow() != row)
			m_table->setCurrentCell(row, 0);
	}
	m_value->setEnabled(chosen);
	m_set->setEnabled(chosen);
}

void fzn_objects_view::choose(const QString &value)
{
	int at = m_value->findText(value);
	if (at >= 0)
		m_value->setCurrentIndex(at);
	else if (m_value->isEditable())
		m_value->setEditText(value);
}

bool fzn_objects_view::set()
{
	int row = m_table->currentRow();
	if (row < 0 || !m_table->item(row, 0))
		return false;
	QByteArray name = m_table->item(row, 0)->text().toUtf8();
	QByteArray value = m_value->currentText().toUtf8();
	if (value.isEmpty()) {
		m_status->setText(tr("Choose a value first."));
		return false;
	}
	if (fzn_rpc_object_set(&m_rpc->c, name.constData(), value.constData()) != FZN_RPC_OK) {
		m_status->setText(m_rpc->c.answered ? QString::fromUtf8(m_rpc->c.error)
		                                    : tr("The node did not answer."));
		return false;
	}
	/* HELD, sec 1037: written about a second from now, so the table would
	 * still read the old value -- said, and the row shown as chosen. */
	bool held = m_rpc->c.held;
	refresh();
	if (held) {
		m_table->setItem(row, 1, new QTableWidgetItem(QString::fromUtf8(value)));
		m_status->setText(tr("%1 is being set to %2.").arg(QString::fromUtf8(name),
		                                                     QString::fromUtf8(value)));
	} else {
		m_status->setText(tr("%1 set to %2.").arg(QString::fromUtf8(name),
		                                          QString::fromUtf8(value)));
	}
	return true;
}

QStringList fzn_objects_view::rows() const
{
	QStringList out;
	for (int i = 0; i < m_table->rowCount(); i++)
		out.append(m_table->item(i, 0)->text() + QLatin1Char('=') + m_table->item(i, 1)->text());
	return out;
}

QStringList fzn_objects_view::offered() const
{
	QStringList out;
	for (int i = 0; i < m_value->count(); i++)
		out.append(m_value->itemText(i));
	return out;
}

QString fzn_objects_view::status() const { return m_status->text(); }
