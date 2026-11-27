/* This user's other hosts, as a widget: gui/hosts_view.h, sec 1124. */
#include "hosts_view.h"
#include "choose_accessible.h"
#include "keep_place.h"

#include "rpc_ask.h"

#include <QByteArray>
#include <QDateTime>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

#include <string.h>

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
	/* RESET, sec 1215: the button stays off until this host's name is
	 * typed in full, so no slip of a finger reaches it. */
	m_reset_note = new QLabel(this);
	m_reset_note->setWordWrap(true);
	m_reset_typed = new QLineEdit(this);
	m_reset_typed->setAccessibleName(tr("This host's name, typed to reset it"));
	m_reset = new QPushButton(tr("Reset this host"), this);
	m_reset->setEnabled(false);
	m_make_admin = new QPushButton(tr("Make admin"), this);
	m_given = new QLineEdit(this);
	m_given->setReadOnly(true);
	m_given->setAccessibleName(tr("The chain to carry to that host"));
	m_given->setPlaceholderText(tr("A grant's chain shows here"));
	m_chain = new QLineEdit(this);
	m_chain->setAccessibleName(tr("A chain given to this host"));
	m_chain->setPlaceholderText(tr("h1 ... a chain given to this host"));
	m_apply = new QPushButton(tr("Apply"), this);
	m_held = new QLabel(this);
	m_held->setWordWrap(true);
	m_held->setAccessibleName(tr("What this host holds"));
	m_granted = new QLabel(this);
	m_granted->setWordWrap(true);
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
	col->addWidget(m_reset_note);
	auto *reset = new QHBoxLayout;
	reset->addWidget(m_reset_typed, 1);
	reset->addWidget(m_reset);
	col->addLayout(reset);
	auto *grant = new QHBoxLayout;
	grant->addWidget(m_make_admin);
	grant->addWidget(m_given, 1);
	col->addLayout(grant);
	auto *apply = new QHBoxLayout;
	apply->addWidget(m_chain, 1);
	apply->addWidget(m_apply);
	col->addLayout(apply);
	col->addWidget(m_held);
	col->addWidget(m_granted);
	col->addWidget(m_status);

	connect(m_table, &QTableWidget::currentCellChanged,
	        [this](int r, int, int, int) { select(r); });
	/* A SCREEN READER CHOOSES TOO, sec 1423: its double tap only selects. */
	fzn_choose_on_accessible_select(m_table, nullptr);
	connect(m_set, &QPushButton::clicked, [this]() { set_address(); });
	connect(m_refresh, &QPushButton::clicked, [this]() { refresh(); });
	connect(m_make_admin, &QPushButton::clicked, [this]() { make_admin(); });
	connect(m_apply, &QPushButton::clicked, [this]() { apply_chain(); });
	connect(m_back_up, &QPushButton::clicked, [this]() { back_up(m_backup_dir->text()); });
	connect(m_reset_typed, &QLineEdit::textChanged, [this](const QString &t) {
		m_reset->setEnabled(!m_reset_phrase.isEmpty() && t == m_reset_phrase);
	});
	connect(m_reset, &QPushButton::clicked, [this]() { reset_host(); });
	select(-1);
}

/* WHO THIS HOST IS, for its reset: the user's key, and the phrase to type
 * -- the host's own name, or its key's first 16 hex where it has none. */
void fzn_hosts_view::read_self()
{
	fzn_rpc_status_resp_t self;

	m_user_known = false;
	m_reset_phrase.clear();
	if (fzn_rpc_status(&m_rpc->c, &self) == FZN_RPC_OK && self.host_name_len) {
		memcpy(m_user, self.user_pubkey, sizeof(m_user));
		m_user_known = true;
		m_reset_phrase = QString::fromUtf8(self.host_name, (int)self.host_name_len);
	}
	m_reset_note->setText(
	        m_user_known
	                ? tr("Resetting wipes this host's keys and everything it holds, and stops it. It cannot "
	                     "be undone: back it up first. To reset it, type its name, %1, here.")
	                          .arg(m_reset_phrase)
	                : tr("Resetting this host is not offered while the node does not say who it is."));
	m_reset->setEnabled(m_user_known && m_reset_typed->text() == m_reset_phrase);
	/* WHAT IT HOLDS, sec 1505: held is not authorised -- "usable" is the
	 * word, as capability_view's -- and one that does not verify is said
	 * apart from one that was revoked where the node tells them apart. */
	{
		fzn_rpc_cap_list_resp_t caps;
		QStringList said;

		m_held->clear();
		if (fzn_rpc_cap_list(&m_rpc->c, &caps) != FZN_RPC_OK)
			return;
		for (size_t i = 0; i < caps.count; i++) {
			const fzn_rpc_cap_list_entry_t *e = &caps.entries[i];
			QString line = QString::fromUtf8(fzn_rpc_capability_type_name((uint8_t)e->type));
			line += e->revoked ? tr(" (revoked)") : e->valid ? tr(" (usable)") : tr(" (does not verify)");
			if (e->expires_at)
				line += tr(" until %1").arg(QDateTime::fromSecsSinceEpoch((qint64)e->expires_at)
				                                    .toString(QStringLiteral("yyyy-MM-dd")));
			said << line;
		}
		m_held->setText(said.isEmpty() ? tr("This host holds no capability.")
		                               : tr("This host holds: %1.").arg(said.join(QStringLiteral(", "))));
	}
}

QString fzn_hosts_view::held() const { return m_held->text(); }

void fzn_hosts_view::set_reset_text(const QString &typed) { m_reset_typed->setText(typed); }

QString fzn_hosts_view::reset_phrase() const { return m_reset_phrase; }

bool fzn_hosts_view::reset_host()
{
	fzn_rpc_identity_reset_resp_t out;

	if (!m_user_known || m_reset_typed->text() != m_reset_phrase) {
		m_status->setText(m_user_known ? tr("Type this host's name, %1, to reset it.").arg(m_reset_phrase)
		                               : tr("The node did not say who this host is."));
		return false;
	}
	if (fzn_rpc_identity_reset(&m_rpc->c, m_user, &out) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	m_reset_typed->clear();
	m_status->setText(tr("This host was reset: %1 file(s) wiped, and its node has stopped.").arg(out.files));
	return true;
}

fzn_hosts_view::~fzn_hosts_view() { delete m_rpc; }

bool fzn_hosts_view::refresh()
{
	auto *hosts = new fzn_rpc_sibling_list_resp_t;
	size_t i;
	fzn_keep_answer answer(m_status);

	if (fzn_rpc_sibling_list(&m_rpc->c, hosts) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		fzn_keep_answer::said(m_status);
		delete hosts;
		return m_rpc->c.answered;
	}
	/* THE PERSON'S PLACE AND THEIR LAST ANSWER, kept across the refill
	 * (sec 1225). */
	fzn_keep_place place(m_table, 1);
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
	/* WHOM THIS HOST HAS GRANTED ADMIN, named as its hosts. */
	{
		auto *issued = new fzn_rpc_cap_granted_resp_t;
		size_t g, k;

		m_granted_said.clear();
		if (fzn_rpc_cap_granted(&m_rpc->c, issued) == FZN_RPC_OK)
			for (g = 0; g < issued->count; g++) {
				const fzn_rpc_cap_granted_entry_t *e = &issued->entries[g];
				QString who = QString::fromLatin1(QByteArray((const char *)e->grantee_pubkey, 8).toHex());

				if (e->type != FZN_RPC_CAP_ADMIN)
					continue;
				for (k = 0; k < hosts->count; k++)
					if (!memcmp(hosts->entries[k].host_pubkey, e->grantee_pubkey, 32))
						who = QString::fromUtf8(hosts->entries[k].name, (int)hosts->entries[k].name_len);
				m_granted_said << (e->revoked ? tr("%1 (revoked)").arg(who) : who);
			}
		delete issued;
		m_granted->setText(m_granted_said.isEmpty() ? tr("This host has made no host an admin.")
		                                            : tr("Admin granted to: %1.").arg(m_granted_said.join(QStringLiteral(", "))));
	}
	delete hosts;
	read_self();
	select(place.restore());
	answer.restore();
	return true;
}

void fzn_hosts_view::select(int row)
{
	bool chosen = row >= 0 && row < m_table->rowCount();
	if (chosen && m_table->currentRow() != row)
		m_table->setCurrentCell(row, 0);
	/* NOTHING CHOSEN CLEARS THE ROW TOO: an act reads the current row, and a
	 * refresh no longer clears it (sec 1225). */
	if (!chosen && m_table->currentRow() >= 0)
		m_table->setCurrentCell(-1, -1);
	if (chosen) {
		QString at = m_table->item(row, 2)->text();
		m_address->setText(at == tr("not known") ? QString() : at);
	}
	m_set->setEnabled(chosen);
	m_make_admin->setEnabled(chosen);
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

void fzn_hosts_view::set_chain_text(const QString &chain) { m_chain->setText(chain); }

QString fzn_hosts_view::granted_chain() const { return m_given->text(); }

QStringList fzn_hosts_view::granted() const { return m_granted_said; }

/* THE CHOSEN HOST MADE AN ADMIN: the node grants it and answers the chain,
 * which the person carries to that host and applies there. */
bool fzn_hosts_view::make_admin()
{
	const int row = m_table->currentRow();
	auto *hosts = new fzn_rpc_sibling_list_resp_t;
	fzn_rpc_cap_grant_resp_t out;
	const QString name = row >= 0 && row < m_table->rowCount() ? m_table->item(row, 0)->text() : QString();
	size_t i;
	const uint8_t *key = nullptr;

	if (name.isEmpty() || fzn_rpc_sibling_list(&m_rpc->c, hosts) != FZN_RPC_OK) {
		if (!name.isEmpty())
			m_status->setText(failed_words(m_rpc));
		delete hosts;
		return false;
	}
	for (i = 0; i < hosts->count && !key; i++)
		if (QString::fromUtf8(hosts->entries[i].name, (int)hosts->entries[i].name_len) == name)
			key = hosts->entries[i].host_pubkey;
	if (!key || fzn_rpc_cap_grant(&m_rpc->c, FZN_RPC_CAP_ADMIN, key, 0, &out) != FZN_RPC_OK) {
		m_status->setText(key ? failed_words(m_rpc) : tr("%1 is no longer one of this user's hosts.").arg(name));
		delete hosts;
		return false;
	}
	delete hosts;
	refresh();
	m_given->setText(QString::fromUtf8((const char *)out.chain_blob, (int)out.chain_blob_len));
	m_status->setText(tr("%1 is granted admin. Carry the chain above to it and apply it there.").arg(name));
	return true;
}

/* A CHAIN GIVEN TO THIS HOST, kept: its node starts again in place to act
 * with it. */
bool fzn_hosts_view::apply_chain()
{
	const QByteArray chain = m_chain->text().trimmed().toUtf8();

	if (chain.isEmpty()) {
		m_status->setText(tr("Paste the chain another host gave this one."));
		return false;
	}
	if (fzn_rpc_cap_install(&m_rpc->c, FZN_RPC_CAP_ADMIN, (const uint8_t *)chain.constData(), (size_t)chain.size())
	    != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	m_chain->clear();
	m_status->setText(tr("Applied: this host is an admin now, and its node has started again with it."));
	return true;
}

