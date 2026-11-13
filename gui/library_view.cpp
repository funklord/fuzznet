/* The files the catalogue names, as a widget: gui/library_view.h, sec 1131. */
#include "library_view.h"

#include "rpc_ask.h"

extern "C" {
#include "../local/rpc_encoding.h"
}

#include <QByteArray>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

#include <string.h>

/* A ROW'S ITEM carries the file's root, to ask for it by. */
#define ROLE_ROOT (Qt::UserRole)
#define ROLE_HERE (Qt::UserRole + 1)
#define ROLE_ARRIVING (Qt::UserRole + 2)

static QString failed_words(const fzn_gui_rpc *r)
{
	return QString::fromUtf8(fzn_gui_rpc_silent(r));
}

/* A SIZE as a person reads it. */
static QString size_words(uint64_t bytes)
{
	if (bytes < 1024u)
		return QObject::tr("%1 bytes").arg(bytes);
	if (bytes < 1024u * 1024u)
		return QObject::tr("%1 KB").arg((double)bytes / 1024.0, 0, 'f', 1);
	if (bytes < 1024u * 1024u * 1024u)
		return QObject::tr("%1 MB").arg((double)bytes / (1024.0 * 1024.0), 0, 'f', 1);
	return QObject::tr("%1 GB").arg((double)bytes / (1024.0 * 1024.0 * 1024.0), 0, 'f', 1);
}

/* A LENGTH, for a file that plays: minutes and seconds; nothing otherwise. */
static QString length_words(uint64_t ms)
{
	if (!ms)
		return QString();
	uint64_t s = ms / 1000u;
	return QStringLiteral("%1:%2").arg(s / 60u).arg(s % 60u, 2, 10, QLatin1Char('0'));
}

static QString words(const char *text, size_t len)
{
	char shown[4u * 256u + 1u];
	fzn_rpc_tty_escape(text, len, shown, sizeof shown);
	return QString::fromUtf8(shown);
}

fzn_library_view::fzn_library_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent)
    : QWidget(parent), m_rpc(new fzn_gui_rpc)
{
	fzn_gui_rpc_init(m_rpc, ask, ask_ctx);

	m_table = new QTableWidget(0, 5, this);
	m_table->setHorizontalHeaderLabels(
	        { tr("File"), tr("Kind"), tr("Size"), tr("Length"), tr("Where") });
	m_table->horizontalHeader()->setStretchLastSection(true);
	m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_table->setSelectionMode(QAbstractItemView::SingleSelection);
	m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
	m_table->setAccessibleName(tr("The library's files"));
	m_fetch = new QPushButton(tr("Get the file"), this);
	m_refresh = new QPushButton(tr("Refresh"), this);
	m_status = new QLabel(this);
	m_status->setWordWrap(true);

	auto *row = new QHBoxLayout;
	row->addWidget(m_fetch);
	row->addWidget(m_refresh);
	row->addStretch(1);
	auto *col = new QVBoxLayout(this);
	col->addWidget(m_table, 1);
	col->addLayout(row);
	col->addWidget(m_status);

	connect(m_table, &QTableWidget::currentCellChanged,
	        [this](int r, int, int, int) { select(r); });
	connect(m_fetch, &QPushButton::clicked, [this]() { fetch(); });
	connect(m_refresh, &QPushButton::clicked, [this]() { refresh(); });
	select(-1);
}

fzn_library_view::~fzn_library_view() { delete m_rpc; }

bool fzn_library_view::refresh()
{
	fzn_rpc_library_list_all_t all;
	size_t i;

	memset(&all, 0, sizeof all);
	if (fzn_rpc_library_list(&m_rpc->c, &all) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		fzn_rpc_library_list_release(&all);
		return m_rpc->c.answered;
	}
	m_table->setRowCount((int)all.count);
	for (i = 0; i < all.count; i++) {
		const fzn_rpc_library_list_entry_t *e = &all.entries[i];
		/* HERE IS THE BYTES ON THIS HOST; the others are claims. */
		const unsigned others = e->holders - (e->held_here && e->holders ? 1u : 0u);
		QString where = e->arriving_permille
		                        ? tr("arriving, %1%").arg(e->arriving_permille / 10u)
		                : e->held_here ? (others ? tr("here, and on %1 other host(s)").arg(others)
		                                       : tr("here"))
		                             : others ? tr("on %1 host(s)").arg(others)
		                                      : tr("nowhere seen");
		if (e->arriving_permille && others)
			where += tr(", from %1 host(s)").arg(others);
		m_table->setItem((int)i, 0, new QTableWidgetItem(words(e->name, e->name_len)));
		m_table->setItem((int)i, 1, new QTableWidgetItem(words(e->kind, e->kind_len)));
		/* A SIZE ONLY WHERE ONE IS KNOWN: the catalogue names none, and a
		 * file not held here has no bytes here to measure. */
		m_table->setItem((int)i, 2, new QTableWidgetItem(e->size ? size_words(e->size) : QString()));
		m_table->setItem((int)i, 3, new QTableWidgetItem(length_words(e->duration_ms)));
		m_table->setItem((int)i, 4, new QTableWidgetItem(where));
		m_table->item((int)i, 0)->setData(ROLE_ROOT, QByteArray((const char *)e->root, 32));
		m_table->item((int)i, 0)->setData(ROLE_HERE, (bool)e->held_here);
		m_table->item((int)i, 0)->setData(ROLE_ARRIVING, e->arriving_permille != 0);
	}
	m_status->setText(all.count ? QString() : tr("The library is empty."));
	fzn_rpc_library_list_release(&all);
	select(-1);
	return true;
}

void fzn_library_view::select(int row)
{
	bool chosen = row >= 0 && row < m_table->rowCount();
	if (chosen && m_table->currentRow() != row)
		m_table->setCurrentCell(row, 0);
	/* A FILE ALREADY HERE is not asked for again. */
	/* A FILE ALREADY HERE, or on its way, is not asked for again. */
	m_fetch->setEnabled(chosen && !m_table->item(row, 0)->data(ROLE_HERE).toBool()
	                    && !m_table->item(row, 0)->data(ROLE_ARRIVING).toBool());
}

bool fzn_library_view::fetch()
{
	int row = m_table->currentRow();
	if (row < 0 || row >= m_table->rowCount() || m_table->item(row, 0)->data(ROLE_HERE).toBool()
	    || m_table->item(row, 0)->data(ROLE_ARRIVING).toBool())
		return false;
	QByteArray root = m_table->item(row, 0)->data(ROLE_ROOT).toByteArray();
	fzn_rpc_blob_fetch_resp_t out;
	if (fzn_rpc_blob_fetch(&m_rpc->c, (const uint8_t *)root.constData(), &out) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	m_status->setText(tr("Asked for %1. It arrives in the background.").arg(m_table->item(row, 0)->text()));
	return true;
}

QStringList fzn_library_view::rows() const
{
	QStringList out;
	for (int i = 0; i < m_table->rowCount(); i++) {
		QStringList cells;
		for (int k = 0; k < m_table->columnCount(); k++)
			cells << m_table->item(i, k)->text();
		out << cells.join(QStringLiteral(" | "));
	}
	return out;
}

QString fzn_library_view::status() const { return m_status->text(); }
