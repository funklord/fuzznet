/* A conversation with one contact, as a widget: gui/conversation_view.h, sec 1126. */
#include "conversation_view.h"

#include "rpc_ask.h"

extern "C" {
#include "../local/rpc_encoding.h"
}

#include <QByteArray>
#include <QDateTime>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPushButton>
#include <QVBoxLayout>

#include <stdlib.h>
#include <string.h>
#include <time.h>

/* The most lines shown: the newest, as many as a conversation's screen
 * holds and a few pages more. */
#define LINES_MAX 200u

static QString failed_words(const fzn_gui_rpc *r)
{
	return QString::fromUtf8(fzn_gui_rpc_silent(r));
}

fzn_conversation_view::fzn_conversation_view(fzn_notebook_view_ask_t ask, void *ask_ctx,
                                             QWidget *parent)
    : QWidget(parent), m_rpc(new fzn_gui_rpc), m_now(0)
{
	fzn_gui_rpc_init(m_rpc, ask, ask_ctx);

	m_title = new QLabel(this);
	m_title->setWordWrap(true);
	m_lines = new QListWidget(this);
	m_lines->setWordWrap(true);
	m_lines->setAccessibleName(tr("The conversation's lines"));
	m_text = new QLineEdit(this);
	m_text->setPlaceholderText(tr("Write a line"));
	m_text->setAccessibleName(tr("A line to send"));
	m_send = new QPushButton(tr("Send"), this);
	m_status = new QLabel(this);
	m_status->setWordWrap(true);

	auto *write = new QHBoxLayout;
	write->addWidget(m_text, 1);
	write->addWidget(m_send);
	auto *col = new QVBoxLayout(this);
	col->addWidget(m_title);
	col->addWidget(m_lines, 1);
	col->addLayout(write);
	col->addWidget(m_status);

	connect(m_send, &QPushButton::clicked, [this]() { send(); });
	connect(m_text, &QLineEdit::returnPressed, [this]() { send(); });
	m_title->setText(tr("No conversation is open."));
	m_send->setEnabled(false);
}

fzn_conversation_view::~fzn_conversation_view() { delete m_rpc; }

void fzn_conversation_view::set_now(uint32_t utc_s) { m_now = utc_s; }

bool fzn_conversation_view::open(const QString &contact)
{
	m_contact = contact;
	m_title->setText(tr("With %1").arg(contact));
	m_send->setEnabled(!contact.isEmpty());
	return refresh();
}

/* WHEN, as a person reads it, in their own time: the time today, the date
 * before. */
static QString when_words(uint32_t now, uint64_t then)
{
	QDateTime at = QDateTime::fromSecsSinceEpoch((qint64)then);
	QDateTime today = QDateTime::fromSecsSinceEpoch((qint64)now);
	return at.date() == today.date() ? at.toString(QStringLiteral("HH:mm"))
	                                 : at.toString(QStringLiteral("yyyy-MM-dd HH:mm"));
}

/* A GROUP'S LINES, newest first as a contact's are, each with who wrote it;
 * the read position at the newest that came in, kept by the group's id. */
static bool group_lines(fzn_gui_rpc *rpc, const QString &group, QListWidget *list, QLabel *status,
                        uint32_t now, bool *answered)
{
	QByteArray name = group.mid(1).toUtf8();
	auto *lines = (fzn_rpc_group_line_t *)calloc(LINES_MAX, sizeof(fzn_rpc_group_line_t));
	size_t count = 0, i;
	const fzn_rpc_inbox_entry_t *newest_in = nullptr;

	*answered = true;
	if (!lines)
		return false;
	if (fzn_rpc_group_lines(&rpc->c, name.constData(), (size_t)name.size(), lines, LINES_MAX, &count)
	    != FZN_RPC_OK) {
		status->setText(failed_words(rpc));
		*answered = rpc->c.answered;
		free(lines);
		return false;
	}
	list->clear();
	for (i = count; i-- > 0;) {
		const fzn_rpc_inbox_entry_t *l = &lines[i].line;
		char shown[4u * FZN_RPC_PEER_TEXT_MAX + 1u];
		char who[4u * FZN_RPC_PEER_NAME_MAX + 1u];

		fzn_rpc_tty_escape(l->text, l->text_len, shown, sizeof shown);
		fzn_rpc_tty_escape(l->sender_name, l->sender_name_len, who, sizeof who);
		list->addItem(QStringLiteral("%1 %2: %3")
		                      .arg(when_words(now, l->stime),
		                           l->outgoing ? QObject::tr("You") : QString::fromUtf8(who),
		                           QString::fromUtf8(shown)));
	}
	for (i = 0; i < count && !newest_in; i++)
		if (!lines[i].line.outgoing)
			newest_in = &lines[i].line;
	status->setText(count ? QString() : QObject::tr("Nothing said yet."));
	if (newest_in) {
		static fzn_rpc_group_list_resp_t groups;
		QByteArray by_id;
		if (fzn_rpc_group_list(&rpc->c, &groups) == FZN_RPC_OK)
			for (i = 0; i < groups.count && by_id.isEmpty(); i++)
				if (groups.entries[i].name_len == (size_t)name.size()
				    && !memcmp(groups.entries[i].name, name.constData(), (size_t)name.size()))
					by_id = "@" + QByteArray((const char *)groups.entries[i].chat_id, 32).toHex();
		if (by_id.isEmpty()
		    || fzn_rpc_message_read(&rpc->c, by_id.constData(), (size_t)by_id.size(),
		                            newest_in->commitment)
		               != FZN_RPC_OK)
			status->setText(QObject::tr("Shown, but not marked read: %1").arg(failed_words(rpc)));
	}
	free(lines);
	if (count)
		list->scrollToBottom();
	return true;
}

bool fzn_conversation_view::refresh()
{
	if (m_contact.isEmpty())
		return false;
	if (m_contact.startsWith(QLatin1Char('@'))) {
		bool answered = true;
		const uint32_t at = m_now ? m_now : (uint32_t)time(NULL);
		return group_lines(m_rpc, m_contact, m_lines, m_status, at, &answered) ? true : answered;
	}
	const uint32_t now = m_now ? m_now : (uint32_t)time(NULL);
	QByteArray who = m_contact.toUtf8();
	auto *lines = (fzn_rpc_inbox_entry_t *)calloc(LINES_MAX, sizeof(fzn_rpc_inbox_entry_t));
	size_t count = 0, i;
	const fzn_rpc_inbox_entry_t *newest_in = nullptr;

	if (!lines)
		return false;
	if (fzn_rpc_inbox_lines(&m_rpc->c, who.constData(), (size_t)who.size(), lines, LINES_MAX, &count)
	    != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		free(lines);
		return m_rpc->c.answered;
	}
	m_lines->clear();
	/* NEWEST FIRST from the node; shown oldest at the top. */
	for (i = count; i-- > 0;) {
		const fzn_rpc_inbox_entry_t *l = &lines[i];
		char shown[4u * FZN_RPC_PEER_TEXT_MAX + 1u];

		fzn_rpc_tty_escape(l->text, l->text_len, shown, sizeof shown);
		m_lines->addItem(QStringLiteral("%1 %2: %3")
		                         .arg(when_words(now, l->stime),
		                              l->outgoing ? tr("You") : m_contact,
		                              QString::fromUtf8(shown)));
	}
	for (i = 0; i < count && !newest_in; i++)
		if (!lines[i].outgoing)
			newest_in = &lines[i];
	/* READ HERE IS READ EVERYWHERE: the node keeps the position and syncs
	 * it to this user's other devices (sec 528). Said, not failed, when the
	 * node will not take it -- the lines are shown either way. */
	if (newest_in
	    && fzn_rpc_message_read(&m_rpc->c, who.constData(), (size_t)who.size(), newest_in->commitment)
	               != FZN_RPC_OK) {
		m_status->setText(tr("Shown, but not marked read: %1").arg(failed_words(m_rpc)));
		free(lines);
		return true;
	}
	m_status->setText(count ? QString() : tr("Nothing said yet."));
	free(lines);
	if (count)
		m_lines->scrollToBottom();
	return true;
}

void fzn_conversation_view::set_text(const QString &text) { m_text->setText(text); }

bool fzn_conversation_view::send()
{
	QByteArray who = m_contact.toUtf8();
	QByteArray text = m_text->text().toUtf8();

	if (m_contact.isEmpty() || text.trimmed().isEmpty())
		return false;
	const bool group = m_contact.startsWith(QLatin1Char('@'));
	if ((group ? fzn_rpc_group_send(&m_rpc->c, who.constData() + 1, (size_t)who.size() - 1,
	                                text.constData(), (size_t)text.size())
	           : fzn_rpc_message_send(&m_rpc->c, who.constData(), (size_t)who.size(), text.constData(),
	                                  (size_t)text.size()))
	    != FZN_RPC_OK) {
		/* THE LINE KEPT, so nothing typed is lost to a refusal. */
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	m_text->clear();
	refresh();
	return true;
}

QStringList fzn_conversation_view::lines() const
{
	QStringList out;
	for (int i = 0; i < m_lines->count(); i++)
		out << m_lines->item(i)->text();
	return out;
}

QString fzn_conversation_view::text() const { return m_text->text(); }

QString fzn_conversation_view::status() const { return m_status->text(); }
