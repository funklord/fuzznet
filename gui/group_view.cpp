/* One group's members, as a widget: gui/group_view.h, sec 1143. */
#include "group_view.h"

#include "rpc_ask.h"

#include <QByteArray>
#include <QCheckBox>
#include <QComboBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QPushButton>
#include <QSet>
#include <QVBoxLayout>

#include <stdlib.h>
#include <string.h>

/* A member's contact name, empty for one acted on by no name. */
#define ROLE_NAME (Qt::UserRole)
#define ROLE_ADMIN (Qt::UserRole + 1)

static QString failed_words(const fzn_gui_rpc *r)
{
	return QString::fromUtf8(fzn_gui_rpc_silent(r));
}

fzn_group_view::fzn_group_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent)
    : QWidget(parent), m_rpc(new fzn_gui_rpc), m_admin(false)
{
	fzn_gui_rpc_init(m_rpc, ask, ask_ctx);

	m_title = new QLabel(this);
	m_members = new QListWidget(this);
	m_members->setAccessibleName(tr("Members"));
	m_contacts = new QComboBox(this);
	m_contacts->setAccessibleName(tr("Contact to add"));
	m_add = new QPushButton(tr("Add"), this);
	m_remove = new QPushButton(tr("Remove"), this);
	m_make_admin = new QPushButton(tr("Make admin"), this);
	m_unmake_admin = new QPushButton(tr("No longer admin"), this);
	m_earlier = new QCheckBox(tr("Members added later get the earlier lines"), this);
	m_leave = new QPushButton(tr("Leave group"), this);
	m_status = new QLabel(this);
	m_status->setWordWrap(true);

	auto *add_row = new QHBoxLayout;
	add_row->addWidget(m_contacts, 1);
	add_row->addWidget(m_add);
	auto *member_row = new QHBoxLayout;
	member_row->addWidget(m_remove);
	member_row->addWidget(m_make_admin);
	member_row->addWidget(m_unmake_admin);
	member_row->addStretch(1);
	auto *col = new QVBoxLayout(this);
	col->addWidget(m_title);
	col->addWidget(m_members, 1);
	col->addLayout(member_row);
	col->addLayout(add_row);
	col->addWidget(m_earlier);
	col->addWidget(m_leave);
	col->addWidget(m_status);

	connect(m_add, &QPushButton::clicked, [this]() { add_member(m_contacts->currentText()); });
	connect(m_remove, &QPushButton::clicked, [this]() { remove_member(m_members->currentRow()); });
	connect(m_make_admin, &QPushButton::clicked, [this]() { set_admin(m_members->currentRow(), true); });
	connect(m_unmake_admin, &QPushButton::clicked, [this]() { set_admin(m_members->currentRow(), false); });
	connect(m_earlier, &QCheckBox::clicked, [this](bool on) { set_earlier(on); });
	connect(m_leave, &QPushButton::clicked, [this]() { leave(); });
	connect(m_members, &QListWidget::currentRowChanged, [this](int) { enable(); });
	m_status->setText(tr("No group chosen."));
	enable();
}

fzn_group_view::~fzn_group_view() { delete m_rpc; }

void fzn_group_view::set_group(const QString &name)
{
	m_group = name;
	m_title->setText(name);
}

bool fzn_group_view::refresh()
{
	fzn_rpc_group_show_resp_t show;
	fzn_rpc_peer_list_resp_t peers;
	QByteArray group = m_group.toUtf8();
	int earlier = 0;
	size_t i;

	memset(&show, 0, sizeof show);
	memset(&peers, 0, sizeof peers);
	if (group.isEmpty())
		return false;
	if (fzn_rpc_group_show(&m_rpc->c, group.constData(), (size_t)group.size(), &show) != FZN_RPC_OK
	    || fzn_rpc_peer_list(&m_rpc->c, &peers) != FZN_RPC_OK
	    || fzn_rpc_group_earlier_get(&m_rpc->c, group.constData(), (size_t)group.size(), &earlier)
	               != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		free(show.members);
		free(peers.entries);
		m_admin = false;
		enable();
		return false;
	}
	m_members->clear();
	QSet<QString> in;
	for (i = 0; i < show.member_count; i++) {
		const fzn_rpc_group_member_entry_t *m = &show.members[i];
		QString name = QString::fromUtf8(m->name, (int)m->name_len);
		const bool you = !memcmp(m->root_pubkey, show.self_root, 32);
		QString said = you ? tr("you") : !name.isEmpty() ? name : QString::fromUtf8(fzn_rpc_group_nameless_label(&show, i));
		if (m->admin)
			said += tr(" (admin)");
		auto *item = new QListWidgetItem(said, m_members);
		item->setData(ROLE_NAME, you ? QString() : name);
		item->setData(ROLE_ADMIN, (bool)m->admin);
		if (!name.isEmpty())
			in.insert(name);
	}
	m_contacts->clear();
	for (i = 0; i < peers.count; i++) {
		QString name = QString::fromUtf8(peers.entries[i].name, (int)peers.entries[i].name_len);
		/* ONLY AN ACTIVE CONTACT JOINS: a suspended or retired one is
		 * listed with its state (sec 1118), and the node would refuse it. */
		if (peers.entries[i].state == FZN_RPC_CONTACT_ACTIVE && !in.contains(name))
			m_contacts->addItem(name);
	}
	m_admin = show.is_admin;
	m_earlier->setChecked(earlier);
	m_status->setText(m_admin ? QString() : tr("Only the group's admins change who is in it."));
	free(show.members);
	free(peers.entries);
	enable();
	return true;
}

QString fzn_group_view::member_name(int row) const
{
	QListWidgetItem *item = row >= 0 ? m_members->item(row) : nullptr;
	return item ? item->data(ROLE_NAME).toString() : QString();
}

void fzn_group_view::enable()
{
	QListWidgetItem *item = m_members->currentItem();
	const bool named = item && !item->data(ROLE_NAME).toString().isEmpty();
	const bool admin = item && item->data(ROLE_ADMIN).toBool();
	/* WHO MAY CHANGE THE GROUP: an admin, of a member it can name. */
	m_add->setEnabled(m_admin && m_contacts->count());
	m_contacts->setEnabled(m_admin);
	m_remove->setEnabled(m_admin && named);
	m_make_admin->setEnabled(m_admin && named && !admin);
	m_unmake_admin->setEnabled(m_admin && named && admin);
	m_earlier->setEnabled(m_admin);
	m_leave->setEnabled(!m_group.isEmpty());
}

bool fzn_group_view::add_member(const QString &contact)
{
	QByteArray group = m_group.toUtf8(), who = contact.toUtf8();
	if (!m_admin || who.isEmpty())
		return false;
	if (fzn_rpc_group_add_member(&m_rpc->c, group.constData(), (size_t)group.size(), who.constData(),
	                             (size_t)who.size())
	    != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	refresh();
	m_status->setText(tr("Added %1.").arg(contact));
	return true;
}

bool fzn_group_view::remove_member(int row)
{
	QString name = member_name(row);
	QByteArray group = m_group.toUtf8(), who = name.toUtf8();
	if (!m_admin || name.isEmpty())
		return false;
	if (fzn_rpc_group_remove_member(&m_rpc->c, group.constData(), (size_t)group.size(), who.constData(),
	                                (size_t)who.size())
	    != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	refresh();
	m_status->setText(tr("Removed %1.").arg(name));
	return true;
}

bool fzn_group_view::set_admin(int row, bool make)
{
	QString name = member_name(row);
	QByteArray group = m_group.toUtf8(), who = name.toUtf8();
	size_t approvals = 0, needed = 0;
	if (!m_admin || name.isEmpty() || m_members->item(row)->data(ROLE_ADMIN).toBool() == make)
		return false;
	if (fzn_rpc_group_admin(&m_rpc->c, group.constData(), (size_t)group.size(), who.constData(),
	                        (size_t)who.size(), make ? 1 : 0, &approvals, &needed)
	    != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	refresh();
	/* A PROPOSAL until a majority of the admins asks the same. */
	m_status->setText(needed ? tr("Asked: %1 of the %2 admins needed have asked so far.").arg(approvals).arg(needed)
	                  : make ? tr("%1 is an admin.").arg(name)
	                         : tr("%1 is no longer an admin.").arg(name));
	return true;
}

bool fzn_group_view::set_earlier(bool on)
{
	QByteArray group = m_group.toUtf8();
	if (!m_admin) {
		m_earlier->setChecked(!on);
		return false;
	}
	if (fzn_rpc_group_earlier(&m_rpc->c, group.constData(), (size_t)group.size(), on ? 1 : 0) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		m_earlier->setChecked(!on);
		return false;
	}
	m_earlier->setChecked(on);
	m_status->setText(on ? tr("Members added later get the earlier lines.")
	                     : tr("Members added later get only what is said after."));
	return true;
}

bool fzn_group_view::leave()
{
	QByteArray group = m_group.toUtf8();
	if (group.isEmpty())
		return false;
	if (fzn_rpc_group_delete(&m_rpc->c, group.constData(), (size_t)group.size()) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	m_status->setText(tr("You left %1; it is forgotten here.").arg(m_group));
	m_group.clear();
	m_admin = false;
	m_members->clear();
	m_contacts->clear();
	enable();
	return true;
}

QStringList fzn_group_view::members() const
{
	QStringList out;
	for (int i = 0; i < m_members->count(); i++)
		out << m_members->item(i)->text();
	return out;
}

QStringList fzn_group_view::addable() const
{
	QStringList out;
	for (int i = 0; i < m_contacts->count(); i++)
		out << m_contacts->itemText(i);
	return out;
}

bool fzn_group_view::may_change() const { return m_admin; }

bool fzn_group_view::earlier() const { return m_earlier->isChecked(); }

QString fzn_group_view::status() const { return m_status->text(); }
