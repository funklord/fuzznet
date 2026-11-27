/* A new group with its members: new_group_view.h, fuzznet sec 1508. */
#include "new_group_view.h"
#include "plain_label.h"
#include "rpc_ask.h"

#include <QByteArray>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QListWidget>
#include <QPushButton>
#include <QStackedLayout>
#include <QVBoxLayout>

#include <stdlib.h>
#include <string.h>

/* Why a contact cannot be ticked, kept on its row. */
#define ROLE_WHY (Qt::UserRole)

fzn_new_group_view::fzn_new_group_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent)
    : QWidget(parent), m_rpc(new fzn_gui_rpc)
{
	fzn_gui_rpc_init(m_rpc, ask, ask_ctx);
	setAccessibleName(tr("A new group"));

	/* 1. THE NAME. */
	auto *naming = new QWidget(this);
	{
		auto *col = new QVBoxLayout(naming);
		m_name_edit = new QLineEdit(naming);
		m_name_edit->setPlaceholderText(tr("The group's name"));
		m_name_edit->setAccessibleName(tr("The group's name"));
		auto *create_button = new QPushButton(tr("Create"), naming);
		QLabel *say_name = fzn_plain_label(tr("Name the group. It is made when you create it."), naming);
		say_name->setWordWrap(true);
		col->addWidget(say_name);
		col->addWidget(m_name_edit);
		col->addWidget(create_button);
		col->addStretch(1);
		connect(create_button, &QPushButton::clicked, [this]() { create(m_name_edit->text()); });
		connect(m_name_edit, &QLineEdit::returnPressed, [this]() { create(m_name_edit->text()); });
	}
	/* 2. THE MEMBERS. */
	auto *members = new QWidget(this);
	{
		auto *col = new QVBoxLayout(members);
		m_contacts = new QListWidget(members);
		m_contacts->setAccessibleName(tr("Contacts to add"));
		auto *add = new QPushButton(tr("Add the ones ticked"), members);
		auto *skip_button = new QPushButton(tr("Skip"), members);
		auto *row = new QHBoxLayout;
		row->addWidget(add);
		row->addWidget(skip_button);
		row->addStretch(1);
		QLabel *say_tick = fzn_plain_label(tr("Tick who is in it. You can add more later from its menu."), members);
		say_tick->setWordWrap(true);
		col->addWidget(say_tick);
		col->addWidget(m_contacts, 1);
		col->addLayout(row);
		connect(add, &QPushButton::clicked, [this]() { add_ticked(); });
		connect(skip_button, &QPushButton::clicked, [this]() { skip(); });
	}
	/* 3. READY. */
	auto *ready = new QWidget(this);
	{
		auto *col = new QVBoxLayout(ready);
		m_summary = fzn_plain_label(ready);
		m_summary->setWordWrap(true);
		m_summary->setAccessibleName(tr("The new group"));
		auto *open_button = new QPushButton(tr("Open the group"), ready);
		col->addWidget(m_summary);
		col->addWidget(open_button);
		col->addStretch(1);
		connect(open_button, &QPushButton::clicked, [this]() { open(); });
	}
	m_status = fzn_plain_label(this);
	m_status->setWordWrap(true);
	auto *col = new QVBoxLayout(this);
	m_steps = new QStackedLayout;
	m_steps->addWidget(naming);
	m_steps->addWidget(members);
	m_steps->addWidget(ready);
	col->addLayout(m_steps, 1);
	col->addWidget(m_status);
}

fzn_new_group_view::~fzn_new_group_view() { delete m_rpc; }

int fzn_new_group_view::step() const { return m_steps->currentIndex() + 1; }

QString fzn_new_group_view::title() const { return m_name.isEmpty() ? tr("New group") : m_name; }

QString fzn_new_group_view::status() const { return m_status->text(); }

void fzn_new_group_view::say(const QString &line)
{
	m_status->setText(line);
	if (m_notice_told && !line.isEmpty())
		m_notice_told(line);
}

bool fzn_new_group_view::create(const QString &name)
{
	const QByteArray n = name.trimmed().toUtf8();
	fzn_rpc_group_create_resp_t out;

	if (step() != 1)
		return false;
	if (n.isEmpty()) {
		say(tr("Name the group."));
		return false;
	}
	if (fzn_rpc_group_create(&m_rpc->c, n.constData(), (size_t)n.size(), &out) != FZN_RPC_OK) {
		say(QString::fromUtf8(fzn_gui_rpc_silent(m_rpc)));
		return false;
	}
	m_name = name.trimmed();
	read_contacts();
	m_steps->setCurrentIndex(1);
	say(tr("Made the group %1.").arg(m_name));
	return true;
}

/* THE CONTACTS OFFERED: active ones; one with no root key -- added from a
 * bare prekey -- shown and not tickable, saying why. */
void fzn_new_group_view::read_contacts()
{
	static const uint8_t no_root[32] = { 0 };
	fzn_rpc_peer_list_resp_t peers;

	m_contacts->clear();
	memset(&peers, 0, sizeof(peers));
	if (fzn_rpc_peer_list(&m_rpc->c, &peers) != FZN_RPC_OK) {
		free(peers.entries);
		return;
	}
	for (size_t i = 0; i < peers.count; i++) {
		const QString who = QString::fromUtf8(peers.entries[i].name, (int)peers.entries[i].name_len);
		if (peers.entries[i].state != FZN_RPC_CONTACT_ACTIVE)
			continue;
		auto *row = new QListWidgetItem(who, m_contacts);
		if (!memcmp(peers.entries[i].root_pubkey, no_root, 32)) {
			const QString why = tr("added from a prekey; no verified identity");
			row->setText(tr("%1 (%2)").arg(who, why));
			row->setData(ROLE_WHY, why);
			row->setFlags(row->flags() & ~(Qt::ItemIsUserCheckable | Qt::ItemIsEnabled));
		} else {
			row->setFlags(row->flags() | Qt::ItemIsUserCheckable);
			row->setCheckState(Qt::Unchecked);
		}
		row->setData(Qt::AccessibleTextRole, row->text());
		row->setData(Qt::UserRole + 1, who);
	}
	free(peers.entries);
}

QStringList fzn_new_group_view::contacts() const
{
	QStringList out;
	for (int i = 0; i < m_contacts->count(); i++)
		out << m_contacts->item(i)->data(Qt::UserRole + 1).toString();
	return out;
}

bool fzn_new_group_view::tickable(const QString &contact) const
{
	for (int i = 0; i < m_contacts->count(); i++)
		if (m_contacts->item(i)->data(Qt::UserRole + 1).toString() == contact)
			return m_contacts->item(i)->data(ROLE_WHY).toString().isEmpty();
	return false;
}

bool fzn_new_group_view::tick(const QString &contact, bool on)
{
	for (int i = 0; i < m_contacts->count(); i++) {
		QListWidgetItem *row = m_contacts->item(i);
		if (row->data(Qt::UserRole + 1).toString() != contact)
			continue;
		if (!row->data(ROLE_WHY).toString().isEmpty()) {
			say(tr("%1 cannot be added: %2.").arg(contact, row->data(ROLE_WHY).toString()));
			return false;
		}
		row->setCheckState(on ? Qt::Checked : Qt::Unchecked);
		return true;
	}
	return false;
}

bool fzn_new_group_view::add_ticked()
{
	const QByteArray group = m_name.toUtf8();

	if (step() != 2)
		return false;
	m_added.clear();
	m_failed.clear();
	for (int i = 0; i < m_contacts->count(); i++) {
		QListWidgetItem *row = m_contacts->item(i);
		const QString who = row->data(Qt::UserRole + 1).toString();
		const QByteArray w = who.toUtf8();
		if (row->checkState() != Qt::Checked)
			continue;
		if (fzn_rpc_group_add_member(&m_rpc->c, group.constData(), (size_t)group.size(), w.constData(),
		                             (size_t)w.size())
		    == FZN_RPC_OK)
			m_added << who;
		else
			m_failed << tr("%1 -- %2").arg(who, QString::fromUtf8(fzn_gui_rpc_silent(m_rpc)));
	}
	skip();
	return m_failed.isEmpty();
}

/* READY: said as who is in it, and who is not and why. */
void fzn_new_group_view::skip()
{
	QString line = m_added.isEmpty() ? tr("%1 is made, with you alone in it for now.").arg(m_name)
	                                 : tr("%1 is made, with you, %2.").arg(m_name, m_added.join(QStringLiteral(", ")));
	if (!m_failed.isEmpty())
		line += QLatin1Char(' ') + tr("Not added: %1.").arg(m_failed.join(QStringLiteral("; ")));
	m_summary->setText(line);
	m_steps->setCurrentIndex(2);
	say(line);
}

QString fzn_new_group_view::summary() const { return m_summary->text(); }

bool fzn_new_group_view::open()
{
	if (step() != 3 || !m_open)
		return false;
	m_open(QStringLiteral("@") + m_name);
	return true;
}
