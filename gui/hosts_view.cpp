/* This user's other hosts, as a widget: gui/hosts_view.h, sec 1124. */
#include "hosts_view.h"

#include "rpc_ask.h"

#include <QByteArray>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

static QString failed_words(const fzn_gui_rpc *r)
{
	return QString::fromUtf8(fzn_gui_rpc_silent(r));
}

fzn_hosts_view::fzn_hosts_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent)
    : QWidget(parent), m_rpc(new fzn_gui_rpc)
{
	fzn_gui_rpc_init(m_rpc, ask, ask_ctx);

	m_table = new QTableWidget(0, 4, this);
	m_table->setHorizontalHeaderLabels({ tr("Host"), tr("Key"), tr("Reached at"), tr("Paired") });
	m_table->horizontalHeader()->setStretchLastSection(true);
	m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_table->setSelectionMode(QAbstractItemView::SingleSelection);
	m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
	m_table->setAccessibleName(tr("Your other hosts"));
	m_address = new QLineEdit(this);
	m_address->setPlaceholderText(QStringLiteral("HOST:PORT"));
	m_address->setAccessibleName(tr("Where the chosen host is reached"));
	m_set = new QPushButton(tr("Set address"), this);
	m_refresh = new QPushButton(tr("Refresh"), this);
	m_backup_dir = new QLineEdit(this);
	m_backup_dir->setPlaceholderText(tr("An empty directory"));
	m_backup_dir->setAccessibleName(tr("Where to back this host up"));
	m_back_up = new QPushButton(tr("Back up this host"), this);
	m_status = new QLabel(this);
	m_status->setWordWrap(true);
	/* WHERE A LOST DEVICE IS DEALT WITH, said before anyone looks for it here. */
	auto *lost = new QLabel(tr("Lost a device? Vote to revoke it under Governance; "
	                           "nothing here ends its access."),
	                        this);
	lost->setWordWrap(true);

	auto *where = new QHBoxLayout;
	where->addWidget(m_address, 1);
	where->addWidget(m_set);
	auto *again = new QHBoxLayout;
	again->addWidget(m_refresh);
	again->addStretch(1);
	auto *col = new QVBoxLayout(this);
	col->addWidget(m_table, 1);
	col->addLayout(where);
	col->addLayout(again);
	col->addWidget(lost);
	/* THE WARNING BEFORE THE BUTTON: a backup is this host, to whoever
	 * holds it. */
	auto *backup_note = new QLabel(tr("A backup holds this host's keys: whoever has it can act "
	                                  "as this host. Keep it as safe as the device."),
	                               this);
	backup_note->setWordWrap(true);
	col->addWidget(backup_note);
	auto *backup = new QHBoxLayout;
	backup->addWidget(m_backup_dir, 1);
	backup->addWidget(m_back_up);
	col->addLayout(backup);
	col->addWidget(m_status);

	connect(m_table, &QTableWidget::currentCellChanged,
	        [this](int r, int, int, int) { select(r); });
	connect(m_set, &QPushButton::clicked, [this]() { set_address(); });
	connect(m_refresh, &QPushButton::clicked, [this]() { refresh(); });
	connect(m_back_up, &QPushButton::clicked, [this]() { back_up(m_backup_dir->text()); });
	select(-1);
}

fzn_hosts_view::~fzn_hosts_view() { delete m_rpc; }

bool fzn_hosts_view::refresh()
{
	auto *hosts = new fzn_rpc_sibling_list_resp_t;
	size_t i;

	if (fzn_rpc_sibling_list(&m_rpc->c, hosts) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		delete hosts;
		return m_rpc->c.answered;
	}
	m_table->setRowCount((int)hosts->count);
	for (i = 0; i < hosts->count; i++) {
		const fzn_rpc_sibling_entry_t *h = &hosts->entries[i];
		m_table->setItem((int)i, 0, new QTableWidgetItem(QString::fromUtf8(h->name, (int)h->name_len)));
		m_table->setItem((int)i, 1, new QTableWidgetItem(QString::fromLatin1(
		                                    QByteArray((const char *)h->host_pubkey, 8).toHex())));
		m_table->setItem((int)i, 2, new QTableWidgetItem(h->address_len ? QString::fromUtf8(h->address,
		                                                                                     (int)h->address_len)
		                                                                : tr("not known")));
		/* AS THE NODE JUDGED IT at this listing: a pairing either way. */
		m_table->setItem((int)i, 3, new QTableWidgetItem(h->valid ? tr("yes") : tr("no")));
	}
	m_status->setText(hosts->count ? QString() : tr("This user has no other host yet."));
	delete hosts;
	select(-1);
	return true;
}

void fzn_hosts_view::select(int row)
{
	bool chosen = row >= 0 && row < m_table->rowCount();
	if (chosen && m_table->currentRow() != row)
		m_table->setCurrentCell(row, 0);
	if (chosen) {
		QString at = m_table->item(row, 2)->text();
		m_address->setText(at == tr("not known") ? QString() : at);
	}
	m_set->setEnabled(chosen);
}

void fzn_hosts_view::set_address_text(const QString &address) { m_address->setText(address); }

bool fzn_hosts_view::set_address()
{
	int row = m_table->currentRow();
	if (row < 0 || row >= m_table->rowCount())
		return false;
	QByteArray name = m_table->item(row, 0)->text().toUtf8();
	QByteArray at = m_address->text().trimmed().toUtf8();
	if (fzn_rpc_sibling_set_address(&m_rpc->c, name.constData(), (size_t)name.size(), at.constData(),
	                                (size_t)at.size())
	    != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	refresh();
	m_status->setText(tr("%1 is reached at %2 now.").arg(QString::fromUtf8(name), QString::fromUtf8(at)));
	return true;
}

bool fzn_hosts_view::back_up(const QString &dir)
{
	QByteArray at = dir.trimmed().toUtf8();
	fzn_rpc_identity_backup_resp_t out;

	if (at.isEmpty()) {
		m_status->setText(tr("Say which empty directory to back up into."));
		return false;
	}
	if (fzn_rpc_identity_backup(&m_rpc->c, at.constData(), (size_t)at.size(), &out) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	m_status->setText(tr("Backed up: %1 file(s), %2 byte(s), in %3.")
	                          .arg(out.files)
	                          .arg(out.bytes)
	                          .arg(QString::fromUtf8(at)));
	return true;
}

QStringList fzn_hosts_view::rows() const
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

QString fzn_hosts_view::address_text() const { return m_address->text(); }

QString fzn_hosts_view::status() const { return m_status->text(); }
