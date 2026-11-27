/* Contacts and pairing requests as a widget: gui/contacts_view.h, sec 1107. */
#include "contacts_view.h"
#include "combo.h"
#include "plain_label.h"
#include "choose_accessible.h"
#include "keep_place.h"

#include "rpc_ask.h"

#include <QByteArray>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QClipboard>
#include <QComboBox>
#include <QGuiApplication>
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
	m_my_card = new QPushButton(tr("Copy my card"), this);
	m_my_card->setToolTip(tr("Copy this host's card, to send to whom you want as a contact"));
	m_add = new QPushButton(tr("Add from a card"), this);
	m_add->setToolTip(tr("Ask to be a contact of whoever sent you their card"));
	m_shared = fzn_plain_label(this);
	m_shared->setWordWrap(true);
	m_shared->setAccessibleName(tr("What the chosen contact may fetch"));
	m_status = fzn_plain_label(this);
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
	auto *cards = new QHBoxLayout;
	cards->addWidget(m_my_card);
	cards->addWidget(m_add);
	cards->addStretch(1);
	/* THEIR CARD ASKED INLINE (sec 1515): a line under the list, where a
	 * dialog was a second window, the abort under TalkBack. */
	m_card_row = new QWidget(this);
	m_card = new QLineEdit(m_card_row);
	m_card->setPlaceholderText(tr("Their card, as they sent it (FZC1:...)"));
	m_card->setAccessibleName(tr("Their card"));
	auto *ask_card = new QPushButton(tr("Ask"), m_card_row);
	auto *cancel_card = new QPushButton(tr("Cancel"), m_card_row);
	{
		auto *row = new QHBoxLayout(m_card_row);
		row->addWidget(m_card, 1);
		row->addWidget(ask_card);
		row->addWidget(cancel_card);
	}
	m_card_row->hide();
	connect(ask_card, &QPushButton::clicked, [this]() {
		if (add_contact(m_card->text(), m_name->text())) {
			m_card->clear();
			m_card_row->hide();
		}
	});
	connect(m_card, &QLineEdit::returnPressed, [ask_card]() { ask_card->click(); });
	connect(cancel_card, &QPushButton::clicked, [this]() {
		m_card->clear();
		m_card_row->hide();
	});
	auto *col = new QVBoxLayout(this);
	col->addWidget(fzn_plain_label(tr("Waiting to become contacts"), this));
	col->addWidget(m_requests, 1);
	col->addLayout(answer);
	col->addWidget(fzn_plain_label(tr("Contacts"), this));
	col->addWidget(m_contacts, 2);
	col->addWidget(m_name);
	col->addLayout(change);
	col->addLayout(cards);
	col->addWidget(m_card_row);
	/* WHERE THIS HOST IS REACHED, offered when the card is refused for
	 * want of it (sec 1539): one row, a choice and a button. */
	m_address_row = new QWidget(this);
	m_card_address = new fzn_combo_box(m_address_row);
	m_card_address->setAccessibleName(tr("Where this host is reached"));
	{
		auto *use = new QPushButton(tr("Use for my card"), m_address_row);
		auto *row = new QHBoxLayout(m_address_row);
		row->addWidget(m_card_address, 1);
		row->addWidget(use);
		connect(use, &QPushButton::clicked, [this]() { (void)use_card_address(m_card_address->currentIndex()); });
	}
	m_address_row->hide();
	col->addWidget(m_address_row);
	col->addWidget(m_shared);
	col->addWidget(m_status);

	connect(m_contacts, &QTableWidget::currentCellChanged,
	        [this](int r, int, int, int) { select_contact(r); });
	connect(m_requests, &QTableWidget::currentCellChanged,
	        [this](int r, int, int, int) { select_request(r); });
	/* A SCREEN READER CHOOSES TOO, sec 1423: its double tap only selects. */
	fzn_choose_on_accessible_select(m_contacts, nullptr);
	fzn_choose_on_accessible_select(m_requests, nullptr);
	connect(m_approve, &QPushButton::clicked, [this]() { approve(); });
	/* ONE-WAY ACTS ASKED BY PRESSING AGAIN (sec 1515). */
	connect(m_reject, &QPushButton::clicked, [this]() {
		const QString who = m_name->text();
		if (m_again.confirmed(QStringLiteral("reject ") + who))
			reject();
		else
			m_status->setText(tr("Press Reject again to turn away %1's request.").arg(who));
	});
	connect(m_rename, &QPushButton::clicked, [this]() { rename(); });
	connect(m_remove, &QPushButton::clicked, [this]() {
		const QString who = m_name->text();
		if (m_again.confirmed(QStringLiteral("remove ") + who))
			remove();
		else
			m_status->setText(tr("Press Remove again to remove %1 as a contact; they are not told.").arg(who));
	});
	connect(m_refresh, &QPushButton::clicked, [this]() { refresh(); });
	connect(m_my_card, &QPushButton::clicked, [this]() {
		const QString card = my_card();
		if (!card.isEmpty()) {
			QGuiApplication::clipboard()->setText(card);
			m_status->setText(tr("Your card is copied: send it to whom you want as a contact."));
		}
	});
	connect(m_add, &QPushButton::clicked, [this]() {
		m_card_row->show();
		m_card->setFocus();
	});
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

QString fzn_contacts_view::my_card()
{
	fzn_rpc_card_show_resp_t out;

	if (fzn_rpc_card_show(&m_rpc->c, nullptr, 0u, &out) != FZN_RPC_OK) {
		const QString refused = QString::fromUtf8(fzn_gui_rpc_silent(m_rpc));
		if (!offer_card_addresses(refused))
			m_status->setText(refused);
		return QString();
	}
	m_address_row->hide();
	return QString::fromUtf8((const char *)out.card_blob, (int)out.card_blob_len);
}

/* A CARD REFUSED FOR WANT OF AN ADDRESS (the node's "no card: this host
 * has no address"): the addresses peers report, offered. None reported,
 * the refusal stands as it was. */
bool fzn_contacts_view::offer_card_addresses(const QString &refused)
{
	fzn_rpc_addr_observe_resp_t seen;

	if (!refused.contains(QStringLiteral("no address")))
		return false;
	memset(&seen, 0, sizeof seen);
	m_card_address->clear();
	if (fzn_rpc_addr_observe(&m_rpc->c, 0, &seen) == FZN_RPC_OK)
		for (size_t i = 0; i < seen.count; i++) {
			const QString at = QString::fromUtf8(seen.entries[i].address, (int)seen.entries[i].address_len);
			if (!at.isEmpty() && m_card_address->findText(at) < 0)
				m_card_address->addItem(at);
		}
	if (!m_card_address->count())
		return false;
	m_address_row->show();
	m_status->setText(tr("Your card needs where this host is reached. Choose one your contacts see it at."));
	return true;
}

QStringList fzn_contacts_view::card_addresses() const
{
	QStringList out;
	for (int i = 0; m_address_row && !m_address_row->isHidden() && i < m_card_address->count(); i++)
		out << m_card_address->itemText(i);
	return out;
}

bool fzn_contacts_view::use_card_address(int row)
{
	const QString address = row >= 0 && row < m_card_address->count() ? m_card_address->itemText(row) : QString();
	const int colon = address.lastIndexOf(QLatin1Char(':'));

	if (colon <= 0 || colon + 1 >= address.size())
		return false;
	/* WRITTEN AS THE REACH VIEW ADVERTISES ONE (sec 1196): `HOST PORT`. */
	const QByteArray value = (address.left(colon) + QLatin1Char(' ') + address.mid(colon + 1)).toUtf8();
	if (fzn_rpc_config_set(&m_rpc->c, "net.address", 11u, value.constData(), (size_t)value.size(), nullptr, 0,
	                       nullptr)
	    != FZN_RPC_OK) {
		m_status->setText(tr("%1 was refused: %2").arg(address, failed_words(m_rpc)));
		return false;
	}
	const QString card = my_card();
	if (card.isEmpty())
		return false;
	QGuiApplication::clipboard()->setText(card);
	m_status->setText(tr("Your card carries %1 and is copied: send it to whom you want as a contact.").arg(address));
	return true;
}

bool fzn_contacts_view::add_contact(const QString &card, const QString &name)
{
	const QByteArray text = card.simplified().remove(QLatin1Char(' ')).toUtf8();
	char offered[FZN_RPC_PEER_NAME_MAX + 1], where[FZN_RPC_PEER_ADDRESS_MAX + 1];
	fzn_rpc_peer_request_send_resp_t out;

	/* READ FIRST, for the name it offers: a card's shape checked here,
	 * its signature by the node when it is added. */
	if (fzn_rpc_node_card_read(text.constData(), (size_t)text.size(), offered, sizeof(offered), where,
	                           sizeof(where))
	    != FZN_RPC_OK) {
		m_status->setText(tr("That is not a fuzznet card: it begins FZC1:."));
		return false;
	}
	const QByteArray local = (name.trimmed().isEmpty() ? QString::fromUtf8(offered) : name.trimmed()).toUtf8();
	if (local.isEmpty()) {
		m_status->setText(tr("Name the contact: their card offers no name."));
		return false;
	}
	if (fzn_rpc_peer_request_send(&m_rpc->c, (const uint8_t *)text.constData(), (size_t)text.size(),
	                              local.constData(), (size_t)local.size(), nullptr, 0u, &out)
	    != FZN_RPC_OK) {
		m_status->setText(QString::fromUtf8(fzn_gui_rpc_silent(m_rpc)));
		return false;
	}
	refresh();
	m_status->setText(tr("Asked %1 to be a contact; they answer from their requests.").arg(QString::fromUtf8(local)));
	return true;
}

bool fzn_contacts_view::refresh()
{
	fzn_rpc_peer_list_resp_t list;
	auto *pending = new fzn_rpc_peer_request_list_resp_t;
	fzn_keep_answer answer(m_status);

	memset(&list, 0, sizeof list);
	if (fzn_rpc_peer_list(&m_rpc->c, &list) != FZN_RPC_OK
	    || fzn_rpc_peer_request_list(&m_rpc->c, pending) != FZN_RPC_OK) {
		free(list.entries);
		delete pending;
		m_status->setText(failed_words(m_rpc));
		fzn_keep_answer::said(m_status);
		return m_rpc->c.answered;
	}
	/* THE PERSON'S PLACE AND THEIR LAST ANSWER, kept across the refill
	 * (sec 1225). */
	fzn_keep_place contact_place(m_contacts, 1), request_place(m_requests, 1);
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
	/* One table's row is chosen at a time; whichever was, is again. */
	const int contact = contact_place.restore(), request = request_place.restore();
	if (request >= 0)
		select_request(request);
	else
		select_contact(contact);
	answer.restore();
	return true;
}

void fzn_contacts_view::select_contact(int row)
{
	bool chosen = row >= 0 && row < m_keys->contact.size();
	/* NOTHING CHOSEN CLEARS THE ROW TOO: an act reads the current row, and a
	 * refresh no longer clears it (sec 1225). */
	if (!chosen && m_contacts->currentRow() >= 0) {
		m_contacts->clearSelection();
		m_contacts->setCurrentCell(-1, -1);
	}
	if (chosen) {
		m_requests->clearSelection();
		m_requests->setCurrentCell(-1, -1);
		if (m_contacts->currentRow() != row)
			m_contacts->setCurrentCell(row, 0);
		const QString key = QStringLiteral("c") + m_keys->contact.at(row).toHex();
		if (key != m_name_for)
			m_name->setText(m_contacts->item(row, 0)->text());
		m_name_for = key;
	}
	/* A RENAME ADDS BACK a contact in a state (sec 576): the button says so,
	 * and a contact removed for good is not offered either. */
	uint8_t state = chosen ? m_keys->state.at(row) : (uint8_t)FZN_RPC_CONTACT_ACTIVE;
	m_rename->setText(state == FZN_RPC_CONTACT_SUSPENDED || state == FZN_RPC_CONTACT_ABSENT
	                          ? tr("Add back")
	                          : tr("Rename"));
	m_rename->setEnabled(chosen && state != FZN_RPC_CONTACT_RETIRED);
	m_shared->clear();
	if (chosen && state == FZN_RPC_CONTACT_ACTIVE)
		read_shared(m_contacts->item(row, 0)->text());
	m_remove->setEnabled(chosen);
	m_approve->setEnabled(false);
	m_reject->setEnabled(false);
}

void fzn_contacts_view::select_request(int row)
{
	bool chosen = row >= 0 && row < m_keys->request.size();
	if (!chosen && m_requests->currentRow() >= 0) {
		m_requests->clearSelection();
		m_requests->setCurrentCell(-1, -1);
	}
	if (chosen) {
		m_contacts->clearSelection();
		m_contacts->setCurrentCell(-1, -1);
		if (m_requests->currentRow() != row)
			m_requests->setCurrentCell(row, 0);
		/* THE PROPOSED NAME OFFERED, the person's to keep or change. */
		QString proposed = m_requests->item(row, 0)->text();
		/* FILLED WHEN THE CHOICE CHANGES (sec 1515), not at every poll's
		 * restore, which wiped a half-typed name. */
		const QString key = QStringLiteral("r") + m_keys->request.at(row).toHex();
		if (key != m_name_for)
			m_name->setText(proposed == tr("(no name given)") ? QString() : proposed);
		m_name_for = key;
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

QString fzn_contacts_view::shared() const { return m_shared->text(); }

/* WHAT `name` MAY FETCH, by file name -- the first five, named from the
 * library; the rest counted. A node that cannot say leaves the line
 * empty. */
void fzn_contacts_view::read_shared(const QString &name)
{
	const QByteArray who = name.toUtf8();
	fzn_rpc_root_t *roots = nullptr;
	size_t room = 0, n = 0;
	QStringList files;

	if (fzn_rpc_file_shared_with(&m_rpc->c, who.constData(), &roots, &room, &n) != FZN_RPC_OK) {
		free(roots);
		return;
	}
	auto *shown = new fzn_rpc_library_show_resp_t;
	for (size_t i = 0; i < n && i < 5u; i++)
		files << (fzn_rpc_library_show(&m_rpc->c, roots[i], shown) == FZN_RPC_OK && shown->name_len
		                  ? QString::fromUtf8(shown->name, (int)shown->name_len)
		                  : QString::fromLatin1(QByteArray((const char *)roots[i], 4).toHex()));
	delete shown;
	free(roots);
	if (n > 5u)
		files << tr("%n more", nullptr, (int)(n - 5u));
	m_shared->setText(n ? tr("%1 may fetch %n file(s) from this host: %2.", nullptr, (int)n)
	                              .arg(name, files.join(QStringLiteral(", ")))
	                    : tr("%1 may fetch none of this host's files.").arg(name));
}
