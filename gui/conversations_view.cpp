/* Every conversation, as a list: gui/conversations_view.h, sec 1138. */
#include "conversations_view.h"

#include "rpc_ask.h"

extern "C" {
#include "../local/rpc_encoding.h"
}

#include <QByteArray>
#include <QDateTime>
#include <QHBoxLayout>
#include <QHash>
#include <QLabel>
#include <QPushButton>
#include <QTreeWidget>
#include <QVBoxLayout>

#include <stdlib.h>
#include <string.h>
#include <time.h>

/* The most conversations shown: past it the listing is cut and said so. */
#define CONVERSATIONS_MAX 8192u

/* A ROW'S ITEM carries what to open it by. */
#define ROLE_OPEN (Qt::UserRole)

static QString failed_words(const fzn_gui_rpc *r)
{
	return QString::fromUtf8(fzn_gui_rpc_silent(r));
}

static QString said(const char *text, size_t len)
{
	char shown[4u * FZN_RPC_NEWEST_TEXT_MAX + 1u];
	fzn_rpc_tty_escape(text, len, shown, sizeof shown);
	return QString::fromUtf8(shown);
}

/* WHEN, in the reader's own time: the time today, the date before. */
static QString when_words(uint32_t now, uint64_t ms)
{
	QDateTime at = QDateTime::fromMSecsSinceEpoch((qint64)ms);
	QDateTime today = QDateTime::fromSecsSinceEpoch((qint64)now);
	return at.date() == today.date() ? at.toString(QStringLiteral("HH:mm"))
	                                 : at.toString(QStringLiteral("yyyy-MM-dd"));
}

/* WHAT THE NEWEST LINE SAYS, with who wrote it where that is not plain. */
static QString line_words(const fzn_rpc_newest_entry_t *e)
{
	QString what;
	switch ((fzn_rpc_newest_kind_t)e->kind) {
	case FZN_RPC_NEWEST_FILE:
		what = QObject::tr("a file: %1").arg(said(e->text, e->text_len));
		break;
	case FZN_RPC_NEWEST_STICKER:
		what = e->text_len ? QObject::tr("a sticker: %1").arg(said(e->text, e->text_len))
		                   : QObject::tr("a sticker");
		break;
	case FZN_RPC_NEWEST_SHELL:
		what = QObject::tr("a line that can no longer be read");
		break;
	case FZN_RPC_NEWEST_TEXT:
		what = said(e->text, e->text_len);
		break;
	case FZN_RPC_NEWEST_NONE:
		return QObject::tr("nothing said yet");
	}
	if (e->outgoing)
		return QObject::tr("you: %1").arg(what);
	if (e->sender_len)
		return QStringLiteral("%1: %2").arg(said(e->sender, e->sender_len), what);
	return what;
}

fzn_conversations_view::fzn_conversations_view(fzn_notebook_view_ask_t ask, void *ask_ctx,
                                               QWidget *parent)
    : QWidget(parent), m_rpc(new fzn_gui_rpc), m_now(0)
{
	fzn_gui_rpc_init(m_rpc, ask, ask_ctx);

	m_tree = new QTreeWidget(this);
	m_tree->setHeaderHidden(true);
	m_tree->setColumnCount(1);
	m_tree->setWordWrap(true);
	m_tree->setAccessibleName(tr("Conversations"));
	m_refresh = new QPushButton(tr("Refresh"), this);
	m_status = new QLabel(this);
	m_status->setWordWrap(true);

	auto *row = new QHBoxLayout;
	row->addWidget(m_refresh);
	row->addStretch(1);
	auto *col = new QVBoxLayout(this);
	col->addWidget(m_tree, 1);
	col->addLayout(row);
	col->addWidget(m_status);

	connect(m_tree, &QTreeWidget::itemActivated, [this](QTreeWidgetItem *item, int) {
		const QString to = item ? item->data(0, ROLE_OPEN).toString() : QString();
		if (!to.isEmpty() && m_open)
			m_open(to);
	});
	connect(m_refresh, &QPushButton::clicked, [this]() { refresh(); });
	m_status->setText(tr("No conversations yet."));
}

fzn_conversations_view::~fzn_conversations_view() { delete m_rpc; }

void fzn_conversations_view::on_open(std::function<void(const QString &)> open) { m_open = open; }

void fzn_conversations_view::set_now(uint32_t utc_s) { m_now = utc_s; }

bool fzn_conversations_view::refresh()
{
	const uint32_t now = m_now ? m_now : (uint32_t)time(NULL);
	auto *newest = (fzn_rpc_newest_entry_t *)calloc(CONVERSATIONS_MAX, sizeof(fzn_rpc_newest_entry_t));
	auto *unread = (fzn_rpc_unread_entry_t *)calloc(CONVERSATIONS_MAX, sizeof(fzn_rpc_unread_entry_t));
	fzn_rpc_peer_list_resp_t peers;
	fzn_rpc_group_list_resp_t groups;
	size_t n = 0, total = 0, n_unread = 0, unread_total = 0, i;

	memset(&peers, 0, sizeof peers);
	memset(&groups, 0, sizeof groups);
	if (!newest || !unread
	    || fzn_rpc_newest_all(&m_rpc->c, newest, CONVERSATIONS_MAX, &n, &total) != FZN_RPC_OK
	    || fzn_rpc_unread_all(&m_rpc->c, unread, CONVERSATIONS_MAX, &n_unread, &unread_total) != FZN_RPC_OK
	    || fzn_rpc_peer_list(&m_rpc->c, &peers) != FZN_RPC_OK
	    || fzn_rpc_group_list(&m_rpc->c, &groups) != FZN_RPC_OK) {
		m_status->setText(newest && unread ? failed_words(m_rpc) : tr("No room to list them."));
		const bool answered = m_rpc->c.answered;
		free(newest);
		free(unread);
		free(peers.entries);
		free(groups.entries);
		return answered;
	}
	/* NAMES AND COUNTS BY KEY: a contact's root key, a group's id. */
	QHash<QByteArray, QString> contact_name, group_name;
	QHash<QByteArray, size_t> counts;
	for (i = 0; i < peers.count; i++)
		contact_name.insert(QByteArray((const char *)peers.entries[i].root_pubkey, 32),
		                    QString::fromUtf8(peers.entries[i].name, (int)peers.entries[i].name_len));
	for (i = 0; i < groups.count; i++)
		group_name.insert(QByteArray((const char *)groups.entries[i].chat_id, 32),
		                  QString::fromUtf8(groups.entries[i].name, (int)groups.entries[i].name_len));
	for (i = 0; i < n_unread; i++)
		counts.insert(QByteArray((const char *)unread[i].key, 32), unread[i].count);

	m_tree->clear();
	auto *contacts = new QTreeWidgetItem(m_tree, { tr("Contacts") });
	auto *group_head = new QTreeWidgetItem(m_tree, { tr("Groups") });
	for (i = 0; i < n; i++) {
		const fzn_rpc_newest_entry_t *e = &newest[i];
		QByteArray key((const char *)e->key, 32);
		const bool is_group = group_name.contains(key);
		/* A CONVERSATION WITH NOBODY NAMED FOR IT -- a contact since removed
		 * -- is shown and opened by its key. */
		QString name = is_group ? group_name.value(key)
		               : contact_name.value(key, QString::fromLatin1(key.toHex()));
		QString text = QStringLiteral("%1 -- %2").arg(said(name.toUtf8().constData(),
		                                                  (size_t)name.toUtf8().size()),
		                                             line_words(e));
		if (e->stime_ms)
			text += QStringLiteral(" -- ") + when_words(now, e->stime_ms);
		const size_t count = counts.value(key, 0);
		if (count)
			text += tr(" (%1 unread)").arg(count);
		auto *item = new QTreeWidgetItem(is_group ? group_head : contacts, { text });
		item->setData(0, ROLE_OPEN, is_group ? QStringLiteral("@") + name : name);
	}
	contacts->setExpanded(true);
	group_head->setExpanded(true);
	m_status->setText(!n ? tr("No conversations yet.")
	                  : total > n ? tr("%1 of %2 conversations shown.").arg(n).arg(total)
	                              : QString());
	free(newest);
	free(unread);
	free(peers.entries);
	free(groups.entries);
	return true;
}

bool fzn_conversations_view::open(int group, int row)
{
	QTreeWidgetItem *head = m_tree->topLevelItem(group);
	QTreeWidgetItem *item = head ? head->child(row) : nullptr;
	const QString to = item ? item->data(0, ROLE_OPEN).toString() : QString();
	if (to.isEmpty() || !m_open)
		return false;
	m_tree->setCurrentItem(item);
	m_open(to);
	return true;
}

QStringList fzn_conversations_view::shown() const
{
	QStringList out;
	for (int i = 0; i < m_tree->topLevelItemCount(); i++) {
		QTreeWidgetItem *h = m_tree->topLevelItem(i);
		out << h->text(0);
		for (int k = 0; k < h->childCount(); k++)
			out << QStringLiteral("  ") + h->child(k)->text(0);
	}
	return out;
}

QString fzn_conversations_view::status() const { return m_status->text(); }
