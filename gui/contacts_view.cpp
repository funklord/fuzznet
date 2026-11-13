/* Contacts and pairing requests as a widget: gui/contacts_view.h, sec 1107. */
#include "contacts_view.h"

#include "rpc_ask.h"

#include <QByteArray>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QVector>

#include <stdlib.h>
#include <string.h>

struct fzn_contacts_view::keys {
	QVector<QByteArray> contact; /* each contact's user key, 32 bytes */
	QVector<uint8_t> state;      /* each contact's fzn_rpc_contact_state_t */
	QVector<QByteArray> request; /* each request's host key, 32 bytes */
};

/* A KEY'S FIRST 8 BYTES IN HEX, as the node names a host it has no name for. */
static QString short_key(const uint8_t *key)
{
	return QString::fromLatin1(QByteArray((const char *)key, 8).toHex());
}

/* WHERE A CONTACT STANDS, in words, sec 1118: nothing for an ordinary one. */
static QString state_words(uint8_t state)
{
	switch (state) {
	case FZN_RPC_CONTACT_SUSPENDED:
		return QObject::tr("Removed on another of your hosts");
	case FZN_RPC_CONTACT_RETIRED:
		return QObject::tr("Removed for good");
	case FZN_RPC_CONTACT_ABSENT:
		return QObject::tr("No longer held by your hosts");
	case FZN_RPC_CONTACT_ACTIVE:
		break;
	}
	return QString();
}

static QTableWidget *table(QWidget *parent, const QStringList &heads)
{
	auto *t = new QTableWidget(0, heads.size(), parent);
	t->setHorizontalHeaderLabels(heads);
	t->horizontalHeader()->setStretchLastSection(true);
	t->setSelectionBehavior(QAbstractItemView::SelectRows);
	t->setSelectionMode(QAbstractItemView::SingleSelection);
	t->setEditTriggers(QAbstractItemView::NoEditTriggers);
	return t;
}

fzn_contacts_view::fzn_contacts_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent)
    : QWidget(parent), m_rpc(new fzn_gui_rpc), m_keys(new keys)
{
	fzn_gui_rpc_init(m_rpc, ask, ask_ctx);

	m_contacts = table(this, { tr("Contact"), tr("Key"), tr("State") });
	m_requests = table(this, { tr("Asks to be called"), tr("Their host's key"), tr("From") });
	m_name = new QLineEdit(this);
	m_name->setPlaceholderText(tr("Name"));
	m_approve = new QPushButton(tr("Approve"), this);
	m_reject = new QPushButton(tr("Reject"), this);
	m_rename = new QPushButton(tr("Rename"), this);
	m_remove = new QPushButton(tr("Remove"), this);
	m_refresh = new QPushButton(tr("Refresh"), this);
	m_status = new QLabel(this);
	m_status->setWordWrap(true);

	/* NAMED FOR A SCREEN READER, and in three rows rather than one, sec
	 * 1120: the name line and five buttons side by side made the view 492
	 * px, past a folding phone's 320 px cover screen. */
	m_requests->setAccessibleName(tr("Waiting to become contacts"));
	m_contacts->setAccessibleName(tr("Contacts"));
	m_name->setAccessibleName(tr("Name"));
	auto *answer = new QHBoxLayout;
	answer->addWidget(m_approve);
	answer->addWidget(m_reject);
	answer->addStretch(1);
	auto *change = new QHBoxLayout;
	change->addWidget(m_rename);
	change->addWidget(m_remove);
	change->addWidget(m_refresh);
	change->addStretch(1);
	auto *col = new QVBoxLayout(this);
	col->addWidget(new QLabel(tr("Waiting to become contacts"), this));
	col->addWidget(m_requests, 1);
	col->addLayout(answer);
	col->addWidget(new QLabel(tr("Contacts"), this));
	col->addWidget(m_contacts, 2);
	col->addWidget(m_name);
	col->addLayout(change);
	col->addWidget(m_status);

	connect(m_contacts, &QTableWidget::currentCellChanged,
	        [this](int r, int, int, int) { select_contact(r); });
	connect(m_requests, &QTableWidget::currentCellChanged,
	        [this](int r, int, int, int) { select_request(r); });
	connect(m_approve, &QPushButton::clicked, [this]() { approve(); });
	connect(m_reject, &QPushButton::clicked, [this]() { reject(); });
	connect(m_rename, &QPushButton::clicked, [this]() { rename(); });
	connect(m_remove, &QPushButton::clicked, [this]() { remove(); });
	connect(m_refresh, &QPushButton::clicked, [this]() { refresh(); });
	select_contact(-1);
}

fzn_contacts_view::~fzn_contacts_view()
{
	delete m_keys;
	delete m_rpc;
}

static QString failed_words(const fzn_gui_rpc *r)
{
	return QString::fromUtf8(fzn_gui_rpc_silent(r));
}

bool fzn_contacts_view::refresh()
{
	fzn_rpc_peer_list_resp_t list;
	auto *pending = new fzn_rpc_peer_request_list_resp_t;

	memset(&list, 0, sizeof list);
	if (fzn_rpc_peer_list(&m_rpc->c, &list) != FZN_RPC_OK
	    || fzn_rpc_peer_request_list(&m_rpc->c, pending) != FZN_RPC_OK) {
		free(list.entries);
		delete pending;
		m_status->setText(failed_words(m_rpc));
		return m_rpc->c.answered;
	}
	m_contacts->setRowCount((int)list.count);
	m_keys->contact.clear();
	m_keys->state.clear();
	for (size_t i = 0; i < list.count; i++) {
		const fzn_rpc_peer_list_entry_t *p = &list.entries[i];
		m_contacts->setItem((int)i, 0, new QTableWidgetItem(QString::fromUtf8(p->name, (int)p->name_len)));
		m_contacts->setItem((int)i, 1, new QTableWidgetItem(short_key(p->root_pubkey)));
		m_contacts->setItem((int)i, 2, new QTableWidgetItem(state_words(p->state)));
		m_keys->contact.append(QByteArray((const char *)p->root_pubkey, 32));
		m_keys->state.append(p->state);
	}
	m_requests->setRowCount((int)pending->count);
	m_keys->request.clear();
	for (size_t i = 0; i < pending->count; i++) {
		const fzn_rpc_pending_request_entry_t *r = &pending->entries[i];
		QString proposed = r->proposed_display_name_len
		                           ? QString::fromUtf8(r->proposed_display_name,
		                                               (int)r->proposed_display_name_len)
		                           : tr("(no name given)");
		m_requests->setItem((int)i, 0, new QTableWidgetItem(proposed));
		m_requests->setItem((int)i, 1, new QTableWidgetItem(short_key(r->requester_host_pubkey)));
		m_requests->setItem((int)i, 2,
		                    new QTableWidgetItem(QString::fromUtf8(r->address, (int)r->address_len)));
		m_keys->request.append(QByteArray((const char *)r->requester_host_pubkey, 32));
	}
	free(list.entries);
	m_status->setText(list.count || pending->count ? QString() : tr("No contacts yet."));
	delete pending;
	select_contact(-1);
	return true;
}

void fzn_contacts_view::select_contact(int row)
{
	bool chosen = row >= 0 && row < m_keys->contact.size();
	if (chosen) {
		m_requests->clearSelection();
		m_requests->setCurrentCell(-1, -1);
		if (m_contacts->currentRow() != row)
			m_contacts->setCurrentCell(row, 0);
		m_name->setText(m_contacts->item(row, 0)->text());
	}
	/* A RENAME ADDS BACK a contact in a state (sec 576): the button says so,
	 * and a contact removed for good is not offered either. */
	uint8_t state = chosen ? m_keys->state.at(row) : (uint8_t)FZN_RPC_CONTACT_ACTIVE;
	m_rename->setText(state == FZN_RPC_CONTACT_SUSPENDED || state == FZN_RPC_CONTACT_ABSENT
	                          ? tr("Add back")
	                          : tr("Rename"));
	m_rename->setEnabled(chosen && state != FZN_RPC_CONTACT_RETIRED);
	m_remove->setEnabled(chosen);
	m_approve->setEnabled(false);
	m_reject->setEnabled(false);
}

void fzn_contacts_view::select_request(int row)
{
	bool chosen = row >= 0 && row < m_keys->request.size();
	if (chosen) {
		m_contacts->clearSelection();
		m_contacts->setCurrentCell(-1, -1);
		if (m_requests->currentRow() != row)
			m_requests->setCurrentCell(row, 0);
		/* THE PROPOSED NAME OFFERED, the person's to keep or change. */
		QString proposed = m_requests->item(row, 0)->text();
		m_name->setText(proposed == tr("(no name given)") ? QString() : proposed);
	}
	m_approve->setEnabled(chosen);
	m_reject->setEnabled(chosen);
	m_rename->setText(tr("Rename"));
	m_rename->setEnabled(false);
	m_remove->setEnabled(false);
}

void fzn_contacts_view::set_name(const QString &name) { m_name->setText(name); }

bool fzn_contacts_view::approve()
{
	int row = m_requests->currentRow();
	if (row < 0 || row >= m_keys->request.size())
		return false;
	QByteArray name = m_name->text().trimmed().toUtf8();
	if (name.isEmpty()) {
		m_status->setText(tr("Give the new contact a name first."));
		return false;
	}
	fzn_rpc_peer_request_approve_resp_t out;
	if (fzn_rpc_peer_request_approve(&m_rpc->c, (const uint8_t *)m_keys->request.at(row).constData(),
	                                 name.constData(), (size_t)name.size(), &out)
	    != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	refresh();
	m_status->setText(tr("%1 is a contact now.").arg(QString::fromUtf8(name)));
	return true;
}

bool fzn_contacts_view::reject()
{
	int row = m_requests->currentRow();
	if (row < 0 || row >= m_keys->request.size())
		return false;
	if (fzn_rpc_peer_request_reject(&m_rpc->c, (const uint8_t *)m_keys->request.at(row).constData())
	    != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	refresh();
	m_status->setText(tr("The request was turned away."));
	return true;
}

bool fzn_contacts_view::rename()
{
	int row = m_contacts->currentRow();
	if (row < 0 || row >= m_keys->contact.size())
		return false;
	uint8_t state = m_keys->state.at(row);
	if (state == FZN_RPC_CONTACT_RETIRED) {
		m_status->setText(tr("Your hosts removed this contact for good; it is not added back here."));
		return false;
	}
	QByteArray name = m_name->text().trimmed().toUtf8();
	if (name.isEmpty()) {
		m_status->setText(tr("Type the new name first."));
		return false;
	}
	/* BY KEY, so a name two contacts share is no obstacle (sec 893). For a
	 * contact in a state the same ask adds it back. */
	if (fzn_rpc_peer_rename(&m_rpc->c, (const uint8_t *)m_keys->contact.at(row).constData(),
	                        name.constData(), (size_t)name.size())
	    != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	refresh();
	m_status->setText(state == FZN_RPC_CONTACT_ACTIVE
	                          ? tr("Renamed %1.").arg(QString::fromUtf8(name))
	                          : tr("%1 is a contact again.").arg(QString::fromUtf8(name)));
	return true;
}

bool fzn_contacts_view::remove()
{
	int row = m_contacts->currentRow();
	if (row < 0 || row >= m_keys->contact.size())
		return false;
	QByteArray name = m_contacts->item(row, 0)->text().toUtf8();
	if (fzn_rpc_peer_remove(&m_rpc->c, name.constData(), (size_t)name.size()) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	refresh();
	m_status->setText(tr("%1 removed.").arg(QString::fromUtf8(name)));
	return true;
}

QStringList fzn_contacts_view::contacts() const
{
	QStringList out;
	for (int i = 0; i < m_contacts->rowCount(); i++) {
		QString row = m_contacts->item(i, 0)->text() + QLatin1Char(' ') + m_contacts->item(i, 1)->text();
		if (!m_contacts->item(i, 2)->text().isEmpty())
			row += QLatin1String(" (") + m_contacts->item(i, 2)->text() + QLatin1Char(')');
		out << row;
	}
	return out;
}

QStringList fzn_contacts_view::requests() const
{
	QStringList out;
	for (int i = 0; i < m_requests->rowCount(); i++)
		out << m_requests->item(i, 0)->text() + QLatin1Char(' ') + m_requests->item(i, 1)->text();
	return out;
}

QString fzn_contacts_view::name() const { return m_name->text(); }
QString fzn_contacts_view::status() const { return m_status->text(); }
