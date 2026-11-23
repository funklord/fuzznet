/* Every conversation, as a list: gui/conversations_view.h, sec 1138. */
#include "conversations_view.h"
#include "choose_accessible.h"
#include "phone_layout.h"
#include "keep_place.h"

#include "rpc_ask.h"

extern "C" {
#include "../messages/reply.h"
#include "../local/rpc_encoding.h"
}

#include <QAction>
#include <QByteArray>
#include <QColor>
#include <QDateTime>
#include <QFont>
#include <QHBoxLayout>
#include <QHash>
#include <QHeaderView>
#include <QIcon>
#include <QLabel>
#include <QMenu>
#include <QPainter>
#include <QPixmap>
#include <QPushButton>
#include <QResizeEvent>
#include <QSet>
#include <QTreeWidget>

#include <cmath>
#include <QVBoxLayout>

#include <stdlib.h>
#include <string.h>
#include <time.h>

/* The most conversations shown: past it the listing is cut and said so. */
#define CONVERSATIONS_MAX 8192u

/* A ROW'S ITEM carries what to open it by, and what kind of row it is. */
#define ROLE_OPEN (Qt::UserRole)
#define ROLE_KIND (Qt::UserRole + 1)
#define ROLE_KEY (Qt::UserRole + 2)
enum { ROW_CONTACT = 1, ROW_GROUP = 2, ROW_UNNAMED = 3 };

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
	case FZN_RPC_NEWEST_UNSENT:
		what = QObject::tr("a line taken back");
		break;
	case FZN_RPC_NEWEST_TEXT: {
		/* A REPLY BY ITS OWN WORDS, A REACTION AS ONE, sec 1282: never the
		 * reference either rides in. */
		uint8_t id[FZN_MESSAGE_ID_LEN];
		size_t at = 0, n = 0;

		if (fzn_message_reply_parse(e->text, e->text_len, id, &at))
			what = said(e->text + at, e->text_len - at);
		else if (fzn_message_reaction_parse(e->text, e->text_len, id, &at, &n))
			what = n ? QObject::tr("reacted %1").arg(said(e->text + at, n)) : QObject::tr("took back a reaction");
		else
			what = said(e->text, e->text_len);
		break;
	}
	case FZN_RPC_NEWEST_NONE:
		return QObject::tr("nothing said yet");
	case FZN_RPC_NEWEST_CALL: {
		/* A CALL NEWER THAN ANY LINE, sec 1270, as a list says one. */
		const bool video = (e->call_kinds & 2u) != 0;
		const uint32_t sec = e->call_seconds;

		switch (e->call_outcome) {
		case FZN_RPC_CALL_ANSWERED:
			return (video ? QObject::tr("Video call, %1") : QObject::tr("Voice call, %1"))
			        .arg(sec >= 3600u ? QStringLiteral("%1:%2:%3")
			                                    .arg(sec / 3600u)
			                                    .arg(sec / 60u % 60u, 2, 10, QLatin1Char('0'))
			                                    .arg(sec % 60u, 2, 10, QLatin1Char('0'))
			                          : QStringLiteral("%1:%2").arg(sec / 60u).arg(sec % 60u, 2, 10, QLatin1Char('0')));
		case FZN_RPC_CALL_MISSED:
			return video ? QObject::tr("Missed video call") : QObject::tr("Missed call");
		case FZN_RPC_CALL_DECLINED:
			return QObject::tr("Declined call");
		case FZN_RPC_CALL_BUSY:
		case FZN_RPC_CALL_NO_ANSWER:
			return QObject::tr("Call, no answer");
		case FZN_RPC_CALL_ELSEWHERE:
			return QObject::tr("Call taken on another device");
		default:
			return QObject::tr("Call did not connect");
		}
	}
	}
	if (e->outgoing)
		return QObject::tr("you: %1").arg(what);
	if (e->sender_len)
		return QStringLiteral("%1: %2").arg(said(e->sender, e->sender_len), what);
	return what;
}

/* WHICH ROW AN ITEM IS, as `open` and `act` count them, in either layout. */
static bool place_of(const QTreeWidget *tree, QTreeWidgetItem *item, bool flat, int *group, int *row)
{
	if (!item)
		return false;
	if (!flat) {
		QTreeWidgetItem *head = item->parent();
		if (!head)
			return false;
		*group = tree->indexOfTopLevelItem(head);
		*row = head->indexOfChild(item);
		return true;
	}
	const bool is_group = item->data(0, ROLE_KIND).toInt() == ROW_GROUP;
	*group = is_group ? 1 : 0;
	*row = 0;
	for (int i = 0; i < tree->indexOfTopLevelItem(item); i++)
		*row += (tree->topLevelItem(i)->data(0, ROLE_KIND).toInt() == ROW_GROUP) == is_group;
	return true;
}

fzn_conversations_view::fzn_conversations_view(fzn_notebook_view_ask_t ask, void *ask_ctx,
                                               QWidget *parent)
    : QWidget(parent), m_rpc(new fzn_gui_rpc), m_now(0)
{
	fzn_gui_rpc_init(m_rpc, ask, ask_ctx);

	m_tree = new QTreeWidget(this);
	m_tree->setHeaderHidden(true);
	/* THE ROW AS A MESSENGER LAYS IT OUT, sec 1232: who and the newest
	 * line; a badge the host hands in; when, on the right; and the unread
	 * count as its own mark, where a narrow row cut it first inside the
	 * text. */
	m_tree->setColumnCount(4);
	m_tree->header()->setStretchLastSection(false);
	m_tree->header()->setSectionResizeMode(0, QHeaderView::Stretch);
	for (int c = 1; c < 4; c++)
		m_tree->header()->setSectionResizeMode(c, QHeaderView::ResizeToContents);
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

	/* A SCREEN READER OPENS ONE TOO, sec 1423: its double tap only selects,
	 * so the row is opened as activation opens it. */
	fzn_select_rows_through_cells(m_tree);
	fzn_choose_on_accessible_select(m_tree, [this](const QModelIndex &) {
		QTreeWidgetItem *item = m_tree->currentItem();
		const QString to = item ? item->data(0, ROLE_OPEN).toString() : QString();

		if (!to.isEmpty() && m_open) {
			m_open(to);
			m_tree->clearSelection();
			m_tree->setCurrentItem(nullptr);
		}
	});
	connect(m_tree, &QTreeWidget::itemActivated, [this](QTreeWidgetItem *item, int) {
		const QString to = item ? item->data(0, ROLE_OPEN).toString() : QString();
		if (!to.isEmpty() && m_open) {
			m_open(to);
			/* NOTHING LEFT HIGHLIGHTED once it is open, sec 1232. */
			m_tree->clearSelection();
			m_tree->setCurrentItem(nullptr);
		}
	});
	connect(m_refresh, &QPushButton::clicked, [this]() { refresh(); });
	m_tree->setContextMenuPolicy(Qt::CustomContextMenu);
	connect(m_tree, &QTreeWidget::customContextMenuRequested, [this](const QPoint &at) {
		int group = 0, row = 0;
		if (!place_of(m_tree, m_tree->itemAt(at), m_flat, &group, &row))
			return;
		QMenu menu(this);
		QHash<QString, QMenu *> under;
		for (const QString &a : actions(group, row)) {
			/* "WHAT: WHO" UNDER A SUBMENU OF WHAT (sec 1246), and the act
			 * named in full however it was reached. */
			const int colon = a.indexOf(QStringLiteral(": "));
			QMenu *in = &menu;
			if (colon > 0) {
				const QString what = a.left(colon);
				if (!under.contains(what))
					under.insert(what, menu.addMenu(what));
				in = under.value(what);
			}
			QAction *offered = in->addAction(colon > 0 ? a.mid(colon + 2) : a);
			offered->setData(a);
			/* OFFERED DISABLED, SAYING WHY, rather than refused when chosen. */
			if (!refused(a).isEmpty()) {
				offered->setEnabled(false);
				offered->setText(tr("%1 -- %2").arg(a, refused(a)));
			}
		}
		QAction *chosen = menu.exec(m_tree->viewport()->mapToGlobal(at));
		if (chosen)
			act(group, row, chosen->data().toString());
	});
	m_status->setText(tr("No conversations yet."));
}

fzn_conversations_view::~fzn_conversations_view() { delete m_rpc; }

void fzn_conversations_view::on_open(std::function<void(const QString &)> open) { m_open = open; }

void fzn_conversations_view::on_action(std::function<void(const QString &, const QString &)> act)
{
	m_act = act;
}

void fzn_conversations_view::set_now(uint32_t utc_s) { m_now = utc_s; }

void fzn_conversations_view::set_badge(std::function<QString(const QString &, bool *)> badge)
{
	m_badge = badge;
}

QString fzn_conversations_view::refused(const QString &action) const { return m_refused.value(action); }

/* A GROUP'S MARK in the one list a phone shows, sec 1245: two heads, in
 * the text's own colour. */
/* WCAG's relative luminance, of one sRGB colour. */
static double luminance(const QColor &c)
{
	auto lin = [](double v) { return v <= 0.03928 ? v / 12.92 : std::pow((v + 0.055) / 1.055, 2.4); };

	return 0.2126 * lin(c.redF()) + 0.7152 * lin(c.greenF()) + 0.0722 * lin(c.blueF());
}

QColor fzn_conversations_view::initial_colour(const QString &name)
{
	/* A HUE FROM THE NAME by FNV-1a, stable across runs where qHash is
	 * seeded per process; then darkened until white on it clears 4.5:1. */
	uint32_t h = 2166136261u;
	for (const QChar ch : name.toCaseFolded())
		h = (h ^ ch.unicode()) * 16777619u;
	QColor c = QColor::fromHsl((int)(h % 360u), 150, 100);
	while (1.05 / (luminance(c) + 0.05) < 4.5 && c.lightness() > 20)
		c = QColor::fromHsl(c.hslHue(), c.hslSaturation(), c.lightness() - 8);
	return c;
}

static QIcon initial_icon(const QString &name)
{
	const int px = 32;
	QPixmap pm(px, px);
	QPainter p;
	QFont f;

	pm.fill(Qt::transparent);
	p.begin(&pm);
	p.setRenderHint(QPainter::Antialiasing);
	p.setPen(Qt::NoPen);
	p.setBrush(fzn_conversations_view::initial_colour(name));
	p.drawEllipse(0, 0, px, px);
	f.setBold(true);
	f.setPixelSize(px / 2);
	p.setFont(f);
	p.setPen(Qt::white);
	p.drawText(QRect(0, 0, px, px), Qt::AlignCenter, name.left(1).toUpper());
	p.end();
	return QIcon(pm);
}

static QIcon group_icon(const QPalette &pal)
{
	QPixmap pm(16, 16);
	pm.fill(Qt::transparent);
	QPainter p(&pm);
	p.setRenderHint(QPainter::Antialiasing, true);
	p.setPen(Qt::NoPen);
	p.setBrush(pal.color(QPalette::Text));
	p.drawEllipse(QRectF(1, 2, 6, 6));
	p.drawEllipse(QRectF(9, 2, 6, 6));
	p.drawRoundedRect(QRectF(0, 9, 8, 6), 2, 2);
	p.drawRoundedRect(QRectF(8, 9, 8, 6), 2, 2);
	return QIcon(pm);
}

void fzn_conversations_view::lay_out()
{
	/* THE ROW CHOSEN, by what it opens, and the scroll, kept across the
	 * refill (sec 1225): a host refreshing on its clock does not move the
	 * person off the conversation they were about to open. */
	fzn_keep_place place(m_tree, 0, ROLE_OPEN);
	m_tree->clear();
	QTreeWidgetItem *contacts = nullptr, *group_head = nullptr;
	if (!m_flat) {
		contacts = new QTreeWidgetItem(m_tree, { tr("Contacts") });
		group_head = new QTreeWidgetItem(m_tree, { tr("Groups") });
	}
	for (const row &r : m_rows) {
		const bool is_group = r.kind == ROW_GROUP;
		/* ONE LIST ON A PHONE, NEWEST FIRST, contacts and groups together,
		 * a group marked (fuzzypickles' 2000Z item 6). */
		QTreeWidgetItem *item = m_flat ? new QTreeWidgetItem(m_tree, { r.text, QString(), r.when,
		                                                                 r.unread ? QString::number(r.unread) : QString() })
		                               : new QTreeWidgetItem(is_group ? group_head : contacts,
		                                                     { r.text, QString(), r.when,
		                                                       r.unread ? QString::number(r.unread) : QString() });
		item->setTextAlignment(2, Qt::AlignRight | Qt::AlignVCenter);
		if (m_flat && is_group) {
			item->setIcon(0, group_icon(palette()));
			item->setData(0, Qt::AccessibleDescriptionRole, tr("a group"));
		} else if (m_flat) {
			/* A PICTURE FOR A CONTACT, its initial (sec 1264). */
			item->setIcon(0, initial_icon(r.name));
		}
		/* THE UNREAD COUNT AS A MARK, bold in the highlight's colour, and
		 * said in words to a screen reader. */
		if (r.unread) {
			QFont bold = item->font(3);
			bold.setBold(true);
			item->setFont(3, bold);
			item->setForeground(3, palette().brush(QPalette::Highlight));
			item->setData(3, Qt::AccessibleTextRole, tr("%n unread", nullptr, (int)r.unread));
		}
		/* AND THE HOST'S BADGE for a contact, dimmed when stale. */
		if (r.kind == ROW_CONTACT && m_badge) {
			bool stale = false;
			const QString badge = m_badge(r.name, &stale);
			item->setText(1, badge);
			if (stale)
				item->setForeground(1, palette().brush(QPalette::Disabled, QPalette::Text));
		}
		item->setData(0, ROLE_OPEN, r.open);
		item->setData(0, ROLE_KIND, r.kind);
		item->setData(0, ROLE_KEY, r.key);
	}
	if (contacts) {
		contacts->setExpanded(true);
		group_head->setExpanded(true);
	}
	place.restore();
}

void fzn_conversations_view::resizeEvent(QResizeEvent *event)
{
	QWidget::resizeEvent(event);
	const bool flat = fzn_phone_layout(event->size().width());
	if (flat != m_flat) {
		m_flat = flat;
		lay_out();
	}
}

bool fzn_conversations_view::flat() const { return m_flat; }

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

	/* THE ROWS AS READ, laid out for the width they are shown at (sec
	 * 1245): under headings on a desktop, one list on a phone. */
	m_rows.clear();
	for (i = 0; i < n; i++) {
		const fzn_rpc_newest_entry_t *e = &newest[i];
		QByteArray key((const char *)e->key, 32);
		const bool is_group = group_name.contains(key);
		/* A CONVERSATION WITH NOBODY NAMED FOR IT -- a contact since removed
		 * -- is shown and opened by its key. */
		QString name = is_group ? group_name.value(key)
		               : contact_name.value(key, QString::fromLatin1(key.toHex()));
		row r;
		r.name = name;
		r.text = QStringLiteral("%1 -- %2").arg(said(name.toUtf8().constData(), (size_t)name.toUtf8().size()),
		                                        line_words(e));
		r.when = e->stime_ms ? when_words(now, e->stime_ms) : QString();
		r.unread = counts.value(key, 0);
		r.open = is_group ? QStringLiteral("@") + name : name;
		r.key = key;
		r.kind = is_group ? ROW_GROUP : contact_name.contains(key) ? ROW_CONTACT : ROW_UNNAMED;
		m_rows.append(r);
	}
	lay_out();
	/* THE STATUS IS THE REFRESH'S, not the layout's: laid out again at
	 * another width, the list keeps whatever was last said of it. */
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
	QTreeWidgetItem *item = row_item(group, row);
	const QString to = item ? item->data(0, ROLE_OPEN).toString() : QString();
	if (to.isEmpty() || !m_open)
		return false;
	m_tree->setCurrentItem(item);
	m_open(to);
	/* NOTHING LEFT HIGHLIGHTED once it is open, sec 1232. */
	m_tree->clearSelection();
	m_tree->setCurrentItem(nullptr);
	return true;
}

QStringList fzn_conversations_view::shown() const
{
	/* THE ROW AS READ ALOUD, its columns in order: who and the line, the
	 * badge, when, and how many are unread -- and, flat, a group said so. */
	auto said_row = [this](const QTreeWidgetItem *r) {
		QString line = QStringLiteral("  ") + r->text(0);
		if (m_flat && r->data(0, ROLE_KIND).toInt() == ROW_GROUP)
			line += tr(" (group)");
		if (!r->text(1).isEmpty())
			line += QStringLiteral(" [") + r->text(1) + QLatin1Char(']');
		if (!r->text(2).isEmpty())
			line += QStringLiteral(" -- ") + r->text(2);
		if (!r->text(3).isEmpty())
			line += tr(" (%1 unread)").arg(r->text(3));
		return line;
	};
	QStringList out;
	for (int i = 0; i < m_tree->topLevelItemCount(); i++) {
		QTreeWidgetItem *h = m_tree->topLevelItem(i);
		if (m_flat) {
			out << said_row(h);
			continue;
		}
		out << h->text(0);
		for (int k = 0; k < h->childCount(); k++)
			out << said_row(h->child(k));
	}
	return out;
}

QString fzn_conversations_view::status() const { return m_status->text(); }

QTreeWidgetItem *fzn_conversations_view::row_item(int group, int row) const
{
	if (row < 0)
		return nullptr;
	/* FLAT, the `row`th of its kind as shown: contacts (0) or groups (1). */
	if (m_flat) {
		for (int i = 0, k = 0; i < m_tree->topLevelItemCount(); i++) {
			QTreeWidgetItem *item = m_tree->topLevelItem(i);
			if ((item->data(0, ROLE_KIND).toInt() == ROW_GROUP) == (group == 1) && k++ == row)
				return item;
		}
		return nullptr;
	}
	QTreeWidgetItem *head = m_tree->topLevelItem(group);
	return head ? head->child(row) : nullptr;
}

/* WHETHER THIS USER'S LOCATION IS SHARED WITH A CONTACT: asked when its
 * menu opens rather than with every refresh, since it costs a listing of
 * who holds the stream. 1, 0, or -1 when the node could not say. */
int fzn_conversations_view::sharing(const QString &contact)
{
	fzn_rpc_peer_list_resp_t peers;
	int on = -1;
	memset(&peers, 0, sizeof peers);
	if (fzn_rpc_peer_list(&m_rpc->c, &peers) == FZN_RPC_OK) {
		fzn_rpc_peer_shares(&m_rpc->c, &peers);
		for (size_t i = 0; i < peers.count; i++)
			if (QString::fromUtf8(peers.entries[i].name, (int)peers.entries[i].name_len) == contact)
				on = peers.entries[i].share_location ? 1 : 0;
	} else {
		m_status->setText(failed_words(m_rpc));
	}
	free(peers.entries);
	return on;
}

bool fzn_conversations_view::callable(const QString &group, QStringList *who)
{
	fzn_rpc_group_show_resp_t members;
	QByteArray name = group.toUtf8();
	memset(&members, 0, sizeof members);
	who->clear();
	if (fzn_rpc_group_members(&m_rpc->c, name.constData(), (size_t)name.size(), &members) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		free(members.members);
		return false;
	}
	for (size_t i = 0; i < members.member_count; i++)
		if (members.members[i].name_len)
			*who << QString::fromUtf8(members.members[i].name, (int)members.members[i].name_len);
	free(members.members);
	return true;
}

QStringList fzn_conversations_view::actions(int group, int row)
{
	QTreeWidgetItem *item = row_item(group, row);
	const int kind = item ? item->data(0, ROLE_KIND).toInt() : 0;
	m_refused.clear();
	if (kind == ROW_GROUP) {
		/* CALL EVERYONE OFFERED DISABLED, SAYING WHY, sec 1232: nobody to
		 * call yet, or more than are rung at once -- not offered and then
		 * refused. */
		QStringList who;
		if (callable(item->data(0, ROLE_OPEN).toString().mid(1), &who)) {
			if (who.isEmpty())
				m_refused.insert(tr("Call everyone"), tr("nobody else to call yet"));
			else if (who.size() > FZN_RPC_RING_WHO_MAX)
				m_refused.insert(tr("Call everyone"),
				                 tr("too many to ring at once, %1 at most").arg(FZN_RPC_RING_WHO_MAX));
		}
		QStringList out({ tr("Send a file..."), tr("Call everyone"), tr("Members and admins...") });
		members_menu(item->data(0, ROLE_OPEN).toString().mid(1), &out);
		read_marks_menu(item->data(0, ROLE_KEY).toByteArray(), &out);
		return out;
	}
	if (kind != ROW_CONTACT)
		return {}; /* nobody to name: a contact since removed */
	QStringList out({ tr("Send a file..."), tr("Call"), tr("Video call") });
	const int on = sharing(item->data(0, ROLE_OPEN).toString());
	if (on == 0)
		out << tr("Share my location");
	else if (on == 1)
		out << tr("Stop sharing my location");
	read_marks_menu(item->data(0, ROLE_KEY).toByteArray(), &out);
	return out;
}

/* A GROUP'S MEMBERS FROM ITS ROW'S MENU, sec 1246, fuzzypickles' 1900Z item
 * 3: each act its own entry, "WHAT: WHO", which the menu shows as a
 * submenu of WHAT -- a contact added, a member made an admin or stopped
 * being one, a member removed -- and this device's copy deleted. Offered to
 * an admin; to anybody else offered disabled, saying why. */
void fzn_conversations_view::members_menu(const QString &group, QStringList *out)
{
	fzn_rpc_group_show_resp_t show;
	fzn_rpc_peer_list_resp_t peers;
	QByteArray name = group.toUtf8();
	QSet<QString> in;

	memset(&show, 0, sizeof show);
	memset(&peers, 0, sizeof peers);
	if (fzn_rpc_group_show(&m_rpc->c, name.constData(), (size_t)name.size(), &show) != FZN_RPC_OK) {
		free(show.members);
		*out << tr("Delete this device's copy");
		return;
	}
	if (!show.is_admin) {
		const QString why = tr("only the group's admins change who is in it");
		*out << tr("Add a member") << tr("Remove a member");
		m_refused.insert(tr("Add a member"), why);
		m_refused.insert(tr("Remove a member"), why);
	} else {
		for (size_t i = 0; i < show.member_count; i++) {
			const fzn_rpc_group_member_entry_t *m = &show.members[i];
			const QString who = QString::fromUtf8(m->name, (int)m->name_len);
			/* A NAMELESS MEMBER is this user or no contact: nothing to
			 * name it by in a menu. */
			if (who.isEmpty() || !memcmp(m->root_pubkey, show.self_root, 32))
				continue;
			in.insert(who);
			*out << (m->admin ? tr("Stop being an admin: %1").arg(who) : tr("Make an admin: %1").arg(who))
			     << tr("Remove: %1").arg(who);
		}
		/* ONLY A CONTACT WHO STANDS JOINS, as group_view offers (sec 1118). */
		if (fzn_rpc_peer_list(&m_rpc->c, &peers) == FZN_RPC_OK)
			for (size_t i = 0; i < peers.count; i++) {
				const QString who = QString::fromUtf8(peers.entries[i].name, (int)peers.entries[i].name_len);
				if (peers.entries[i].state == FZN_RPC_CONTACT_ACTIVE && !in.contains(who))
					*out << tr("Add a member: %1").arg(who);
			}
	}
	*out << tr("Delete this device's copy");
	free(show.members);
	free(peers.entries);
}

/* ONE MEMBER ACT from the menu, sec 1246, said as done -- or, for an admin's
 * change other admins must agree to, how many more must ask. */
bool fzn_conversations_view::member_act(const QString &group, const QString &action)
{
	const QByteArray name = group.toUtf8();
	const int colon = action.indexOf(QStringLiteral(": "));
	const QString what = colon > 0 ? action.left(colon) : action, who = colon > 0 ? action.mid(colon + 2) : QString();
	const QByteArray peer = who.toUtf8();
	size_t approvals = 0, needed = 0;
	int rc;

	if (what == tr("Delete this device's copy")) {
		/* CONFIRMED BY CHOOSING IT AGAIN, not by a dialog over the list:
		 * the first choice says what it does, the second within
		 * FZN_CONVERSATIONS_CONFIRM_S does it. */
		const qint64 now = QDateTime::currentSecsSinceEpoch();
		if (m_armed != group || now > m_armed_at + FZN_CONVERSATIONS_CONFIRM_S) {
			m_armed = group;
			m_armed_at = now;
			m_status->setText(tr("Choose \"Delete this device's copy\" again to delete %1 here; the other members keep it.")
			                          .arg(group));
			return true;
		}
		m_armed.clear();
		if (fzn_rpc_group_delete(&m_rpc->c, name.constData(), (size_t)name.size()) != FZN_RPC_OK) {
			m_status->setText(failed_words(m_rpc));
			return false;
		}
		/* THE LIST WITHOUT IT, and then said: a refresh says its own. */
		refresh();
		m_status->setText(tr("Deleted %1 from this device.").arg(group));
		return true;
	}
	if (who.isEmpty())
		return false;
	if (what == tr("Add a member"))
		rc = fzn_rpc_group_add_member(&m_rpc->c, name.constData(), (size_t)name.size(), peer.constData(),
		                              (size_t)peer.size());
	else if (what == tr("Remove"))
		rc = fzn_rpc_group_remove_member(&m_rpc->c, name.constData(), (size_t)name.size(), peer.constData(),
		                                 (size_t)peer.size());
	else if (what == tr("Make an admin") || what == tr("Stop being an admin"))
		rc = fzn_rpc_group_admin(&m_rpc->c, name.constData(), (size_t)name.size(), peer.constData(),
		                         (size_t)peer.size(), what == tr("Make an admin") ? 1 : 0, &approvals, &needed);
	else
		return false;
	if (rc != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	/* THE K OF N SAID, sec 1012: a change waiting on other admins is not done. */
	if (needed > approvals)
		m_status->setText(tr("Asked. It takes effect when %n more admin(s) ask.", nullptr, (int)(needed - approvals)));
	else if (what == tr("Add a member"))
		m_status->setText(tr("%1 is in %2 now.").arg(who, group));
	else if (what == tr("Remove"))
		m_status->setText(tr("%1 is no longer in %2.").arg(who, group));
	else
		m_status->setText(what == tr("Make an admin") ? tr("%1 is an admin of %2 now.").arg(who, group)
		                                              : tr("%1 is no longer an admin of %2.").arg(who, group));
	return true;
}

/* THE SETTING FOR ONE CONVERSATION, sec 1269: `message.read.HEX`, HEX its
 * key's first 24 bytes, as the client names the node's `message/read/HEX`. */
static QByteArray read_key(const QByteArray &key)
{
	return QByteArray("message.read.") + key.left(24).toHex();
}

/* THREE WAYS, as working-practice's settings rule asks: follow the choice
 * for every conversation -- saying what that is now -- or tell, or not. */
void fzn_conversations_view::read_marks_menu(const QByteArray &key, QStringList *out)
{
	fzn_rpc_config_get_resp_t own, all;
	const QByteArray k = read_key(key);
	bool everywhere = false;
	int chosen = -1; /* -1 follows */

	if (key.size() != 32)
		return;
	memset(&own, 0, sizeof own);
	memset(&all, 0, sizeof all);
	if (fzn_rpc_config_get(&m_rpc->c, "message.read-marks", 18, &all) == FZN_RPC_OK)
		everywhere = all.value_len == 2 && !memcmp(all.value, "on", 2);
	if (fzn_rpc_config_get(&m_rpc->c, k.constData(), (size_t)k.size(), &own) == FZN_RPC_OK && own.set_at)
		chosen = own.value_len == 2 && !memcmp(own.value, "on", 2) ? 1 : 0;
	const QString mark = QStringLiteral(" *");
	*out << tr("Read marks: As everywhere (%1)").arg(everywhere ? tr("on") : tr("off")) + (chosen < 0 ? mark : QString())
	     << tr("Read marks: Tell them when I read") + (chosen == 1 ? mark : QString())
	     << tr("Read marks: Don't tell them") + (chosen == 0 ? mark : QString());
}

bool fzn_conversations_view::read_marks_act(const QByteArray &key, const QString &name, const QString &action)
{
	const QByteArray k = read_key(key);
	QString what = action;
	int rc;

	if (key.size() != 32)
		return false;
	if (what.endsWith(QStringLiteral(" *")))
		what.chop(2);
	if (what.startsWith(tr("Read marks: As everywhere")))
		rc = fzn_rpc_config_clear(&m_rpc->c, k.constData(), (size_t)k.size());
	else if (what == tr("Read marks: Tell them when I read") || what == tr("Read marks: Don't tell them"))
		rc = fzn_rpc_config_set(&m_rpc->c, k.constData(), (size_t)k.size(),
		                        what == tr("Read marks: Don't tell them") ? "off" : "on",
		                        what == tr("Read marks: Don't tell them") ? 3u : 2u, nullptr, 0, nullptr);
	else
		return false;
	if (rc != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	m_status->setText(what.startsWith(tr("Read marks: As everywhere"))
	                          ? tr("%1 follows your choice for every conversation.").arg(name)
	                  : what == tr("Read marks: Don't tell them") ? tr("%1 is not told when you read.").arg(name)
	                                                             : tr("%1 is told when you read.").arg(name));
	return true;
}

bool fzn_conversations_view::act(int group, int row, const QString &action)
{
	QTreeWidgetItem *item = row_item(group, row);
	const int kind = item ? item->data(0, ROLE_KIND).toInt() : 0;
	const QString to = item ? item->data(0, ROLE_OPEN).toString() : QString();
	if (kind != ROW_CONTACT && kind != ROW_GROUP)
		return false;
	/* REFUSED TO ONE WHO IS NOT AN ADMIN, saying why, as offered. */
	if (kind == ROW_GROUP && (action == tr("Add a member") || action == tr("Remove a member"))) {
		if (!m_refused.value(action).isEmpty())
			m_status->setText(m_refused.value(action));
		return false;
	}
	if (kind == ROW_GROUP
	    && (action.startsWith(tr("Add a member: ")) || action.startsWith(tr("Remove: "))
	        || action.startsWith(tr("Make an admin: ")) || action.startsWith(tr("Stop being an admin: "))
	        || action == tr("Delete this device's copy")))
		return member_act(to.mid(1), action);
	if (action.startsWith(tr("Read marks: ")))
		return read_marks_act(item->data(0, ROLE_KEY).toByteArray(), to, action);
	if (kind == ROW_CONTACT && (action == tr("Share my location") || action == tr("Stop sharing my location"))) {
		/* SHARED AS THE LOCATION VIEW'S DEFAULT HAS IT, exactly; a coarser
		 * share is chosen there (sec 1119). */
		const bool on = action == tr("Share my location");
		QByteArray who = to.toUtf8();
		int siblings = 0;
		if (fzn_rpc_location_share(&m_rpc->c, who.constData(), (size_t)who.size(), on ? 1 : 0, 0, &siblings)
		    != FZN_RPC_OK) {
			m_status->setText(failed_words(m_rpc));
			return false;
		}
		m_status->setText(on ? tr("%1 can see your position now.").arg(to)
		                     : tr("%1 no longer sees your position.").arg(to));
		return true;
	}
	if (!m_act)
		return false;
	if (action == tr("Send a file...")) {
		m_act(QStringLiteral("file"), to);
		return true;
	}
	if (kind == ROW_CONTACT && (action == tr("Call") || action == tr("Video call"))) {
		m_act(action == tr("Call") ? QStringLiteral("call") : QStringLiteral("video"), to);
		return true;
	}
	if (kind == ROW_GROUP && action == tr("Members and admins...")) {
		m_act(QStringLiteral("members"), to.mid(1));
		return true;
	}
	if (kind == ROW_GROUP && action == tr("Call everyone")) {
		/* EVERY MEMBER THIS USER CAN NAME, this user not among them. */
		QStringList who;
		if (!callable(to.mid(1), &who))
			return false;
		if (who.isEmpty()) {
			m_status->setText(tr("Nobody else in %1 to call.").arg(to.mid(1)));
			return false;
		}
		if (who.size() > FZN_RPC_RING_WHO_MAX) {
			m_status->setText(tr("Too many in %1 to ring at once, %2 at most.").arg(to.mid(1)).arg(FZN_RPC_RING_WHO_MAX));
			return false;
		}
		m_act(QStringLiteral("call"), who.join(QLatin1Char(',')));
		return true;
	}
	return false;
}
