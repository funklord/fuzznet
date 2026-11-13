/* A conversation with one contact, as a widget: gui/conversation_view.h, sec 1126. */
#include "conversation_view.h"

#include "rpc_ask.h"

extern "C" {
#include "../local/rpc_encoding.h"
#include "../messages/attachment.h"
#include "../sticker/pack.h"
}

#include <QByteArray>
#include <QDateTime>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QHash>
#include <QIcon>
#include <QImage>
#include <QPixmap>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPushButton>
#include <QVBoxLayout>

#include <stdlib.h>
#include <string.h>
#include <time.h>

/* A FILE LINE'S ITEM carries the reference it names, to fetch and save by. */
#define ROLE_FILE (Qt::UserRole)
/* A sticker line's pack word (144 hex) and id, "PACK ID"; and whether
 * the line came in. */
#define ROLE_STICKER (Qt::UserRole + 1)
#define ROLE_IN (Qt::UserRole + 2)
/* The most bytes of a sticker's thumbnail read, as the picker reads. */
#define ART_MAX (256u * 1024u)

struct fzn_conversation_view::art {
	QHash<QByteArray, QIcon> drawn;
};

/* A sticker line's pack and id, "PACK ID"; empty for any other line, and
 * for a fuzzypickles reference, which names no pack a node can read. */
static QByteArray sticker_of(const char *text, size_t len)
{
	static fzn_sticker_ref_t ref;
	char word[145];

	if (!fzn_sticker_ref_parse(text, len, &ref) || !ref.length)
		return QByteArray();
	fzn_rpc_sticker_pack_word(&ref, ref.length, word);
	return QByteArray(word, 144) + ' ' + QByteArray::number((qulonglong)ref.id);
}

/* The reference a line's text names, as the bytes an item keeps: root, key,
 * the size in eight bytes, then the name; empty for a line naming none. */
static QByteArray file_of(const char *text, size_t len)
{
	static fzn_attachment_t f;
	QByteArray out;

	if (!fzn_attachment_parse(text, len, &f))
		return out;
	out.append((const char *)f.root, 32);
	out.append((const char *)f.key, 32);
	for (int i = 7; i >= 0; i--)
		out.append((char)(uint8_t)(f.size >> (8 * i)));
	out.append(f.name, (int)f.name_len);
	return out;
}

static uint64_t file_size(const QByteArray &ref)
{
	uint64_t v = 0;
	for (int i = 0; i < 8; i++)
		v = (v << 8) | (uint8_t)ref.at(64 + i);
	return v;
}

/* LINES ASKED FOR, a page at a time: the newest first, older on demand. */
#define LINES_PAGE 200u

/* The most lines shown: the newest, as many as a conversation's screen
 * holds and a few pages more. */
#define LINES_MAX 200u

/* WHERE THIS USER'S OWN LINE HAS GOT TO, said after it (sec 1128); nothing
 * for a line that came in, or one nothing is known of yet. */
static QString state_words(const fzn_rpc_inbox_entry_t *l)
{
	if (!l->outgoing)
		return QString();
	switch ((fzn_rpc_line_state_t)l->state) {
	case FZN_RPC_LINE_DELIVERED:
	case FZN_RPC_LINE_SETTLED:
		return QObject::tr(" (delivered)");
	case FZN_RPC_LINE_HANDED_OVER:
		return QObject::tr(" (with a relay)");
	case FZN_RPC_LINE_NOT_DELIVERED:
		return QObject::tr(" (not delivered)");
	case FZN_RPC_LINE_NONE:
		break;
	}
	return QString();
}

/* A SIZE as a person reads it: the sender's claim, said whole. */
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

/* WHAT A LINE SAYS, sec 1129: a file or a sticker said as one, by the
 * library's own readers (`fzn_attachment_parse`, `fzn_sticker_ref_parse`),
 * rather than as the reference it rides in; anything else as its text. All
 * of it someone else's, so all of it in caret form. */
static QString content_words(const char *text, size_t len)
{
	static fzn_attachment_t file;
	static fzn_sticker_ref_t sticker;
	char shown[4u * FZN_RPC_PEER_TEXT_MAX + 1u];

	if (fzn_attachment_parse(text, len, &file)) {
		fzn_rpc_tty_escape(file.name, file.name_len, shown, sizeof shown);
		return QObject::tr("a file: %1, %2").arg(QString::fromUtf8(shown), size_words(file.size));
	}
	if (fzn_sticker_ref_parse(text, len, &sticker)) {
		const char *said = sticker.text_len ? sticker.text : sticker.description;
		size_t said_len = sticker.text_len ? sticker.text_len : sticker.description_len;
		fzn_rpc_tty_escape(said, said_len, shown, sizeof shown);
		return said_len ? QObject::tr("a sticker: %1").arg(QString::fromUtf8(shown))
		                : QObject::tr("a sticker");
	}
	fzn_rpc_tty_escape(text, len, shown, sizeof shown);
	return QString::fromUtf8(shown);
}

static QString failed_words(const fzn_gui_rpc *r)
{
	return QString::fromUtf8(fzn_gui_rpc_silent(r));
}

fzn_conversation_view::fzn_conversation_view(fzn_notebook_view_ask_t ask, void *ask_ctx,
                                             QWidget *parent)
    : QWidget(parent), m_rpc(new fzn_gui_rpc), m_art(new art), m_now(0), m_max(LINES_PAGE)
{
	fzn_gui_rpc_init(m_rpc, ask, ask_ctx);

	m_title = new QLabel(this);
	m_title->setWordWrap(true);
	m_lines = new QListWidget(this);
	m_lines->setWordWrap(true);
	m_lines->setIconSize(QSize(64, 64));
	m_lines->setAccessibleName(tr("The conversation's lines"));
	m_text = new QLineEdit(this);
	m_text->setPlaceholderText(tr("Write a line"));
	m_text->setAccessibleName(tr("A line to send"));
	m_send = new QPushButton(tr("Send"), this);
	m_fetch = new QPushButton(tr("Get the file"), this);
	m_save = new QPushButton(tr("Save the file"), this);
	m_older = new QPushButton(tr("Older lines"), this);
	m_send_file = new QPushButton(tr("Send a file"), this);
	m_keep = new QPushButton(tr("Keep this sticker pack"), this);
	m_status = new QLabel(this);
	m_status->setWordWrap(true);

	auto *write = new QHBoxLayout;
	write->addWidget(m_text, 1);
	write->addWidget(m_send);
	auto *col = new QVBoxLayout(this);
	col->addWidget(m_title);
	col->addWidget(m_lines, 1);
	auto *older = new QHBoxLayout;
	older->addWidget(m_older);
	older->addStretch(1);
	/* ABOVE THE LINES, where the older ones go. */
	col->insertLayout(1, older);
	auto *files = new QHBoxLayout;
	files->addWidget(m_fetch);
	files->addWidget(m_save);
	files->addStretch(1);
	auto *sending = new QHBoxLayout;
	sending->addWidget(m_send_file);
	/* NOT BESIDE THE FILE'S TWO: three there pass a 320 px cover screen. */
	sending->addWidget(m_keep);
	sending->addStretch(1);
	col->addLayout(files);
	col->addLayout(write);
	col->addLayout(sending);
	col->addWidget(m_status);

	connect(m_send, &QPushButton::clicked, [this]() { send(); });
	connect(m_text, &QLineEdit::returnPressed, [this]() { send(); });
	connect(m_lines, &QListWidget::currentRowChanged, [this](int r) { select_line(r); });
	connect(m_fetch, &QPushButton::clicked, [this]() { fetch(); });
	connect(m_save, &QPushButton::clicked, [this]() { save_to(QString()); });
	connect(m_older, &QPushButton::clicked, [this]() { show_older(); });
	connect(m_send_file, &QPushButton::clicked, [this]() { send_file(QString()); });
	connect(m_keep, &QPushButton::clicked, [this]() { keep_pack(); });
	select_line(-1);
	m_title->setText(tr("No conversation is open."));
	m_send->setEnabled(false);
	m_older->setEnabled(false);
	m_send_file->setEnabled(false);
}

fzn_conversation_view::~fzn_conversation_view()
{
	delete m_art;
	delete m_rpc;
}

void fzn_conversation_view::set_now(uint32_t utc_s) { m_now = utc_s; }

bool fzn_conversation_view::open(const QString &contact)
{
	m_contact = contact;
	m_title->setText(tr("With %1").arg(contact));
	m_send->setEnabled(!contact.isEmpty());
	m_send_file->setEnabled(!contact.isEmpty());
	m_max = LINES_PAGE;
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
                        uint32_t now, size_t max, bool *answered)
{
	QByteArray name = group.mid(1).toUtf8();
	auto *lines = (fzn_rpc_group_line_t *)calloc(max, sizeof(fzn_rpc_group_line_t));
	size_t count = 0, i;
	const fzn_rpc_inbox_entry_t *newest_in = nullptr;

	*answered = true;
	if (!lines)
		return false;
	if (fzn_rpc_group_lines(&rpc->c, name.constData(), (size_t)name.size(), lines, max, &count)
	    != FZN_RPC_OK) {
		status->setText(failed_words(rpc));
		*answered = rpc->c.answered;
		free(lines);
		return false;
	}
	list->clear();
	for (i = count; i-- > 0;) {
		const fzn_rpc_inbox_entry_t *l = &lines[i].line;
		char who[4u * FZN_RPC_PEER_NAME_MAX + 1u];

		fzn_rpc_tty_escape(l->sender_name, l->sender_name_len, who, sizeof who);
		auto *item = new QListWidgetItem(QStringLiteral("%1 %2: %3")
		                      .arg(when_words(now, l->stime),
		                           l->outgoing ? QObject::tr("You") : QString::fromUtf8(who),
		                           content_words(l->text, l->text_len))
		                       + state_words(l));
		item->setData(ROLE_FILE, file_of(l->text, l->text_len));
		item->setData(ROLE_STICKER, sticker_of(l->text, l->text_len));
		item->setData(ROLE_IN, !l->outgoing);
		list->addItem(item);
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
		if (!group_lines(m_rpc, m_contact, m_lines, m_status, at, m_max, &answered))
			return answered;
		m_older->setEnabled((size_t)m_lines->count() >= m_max);
		draw_stickers();
		return true;
	}
	const uint32_t now = m_now ? m_now : (uint32_t)time(NULL);
	QByteArray who = m_contact.toUtf8();
	auto *lines = (fzn_rpc_inbox_entry_t *)calloc(m_max, sizeof(fzn_rpc_inbox_entry_t));
	size_t count = 0, i;
	const fzn_rpc_inbox_entry_t *newest_in = nullptr;

	if (!lines)
		return false;
	if (fzn_rpc_inbox_lines(&m_rpc->c, who.constData(), (size_t)who.size(), lines, m_max, &count)
	    != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		free(lines);
		return m_rpc->c.answered;
	}
	m_lines->clear();
	/* NEWEST FIRST from the node; shown oldest at the top. */
	for (i = count; i-- > 0;) {
		const fzn_rpc_inbox_entry_t *l = &lines[i];

		auto *item = new QListWidgetItem(QStringLiteral("%1 %2: %3")
		                         .arg(when_words(now, l->stime),
		                              l->outgoing ? tr("You") : m_contact,
		                              content_words(l->text, l->text_len))
		                 + state_words(l));
		item->setData(ROLE_FILE, file_of(l->text, l->text_len));
		item->setData(ROLE_STICKER, sticker_of(l->text, l->text_len));
		item->setData(ROLE_IN, !l->outgoing);
		m_lines->addItem(item);
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
		draw_stickers();
		return true;
	}
	m_status->setText(count ? QString() : tr("Nothing said yet."));
	/* A FULL PAGE MAY HAVE MORE BEHIND IT. */
	m_older->setEnabled(count >= m_max);
	free(lines);
	draw_stickers();
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

void fzn_conversation_view::select_line(int row)
{
	QListWidgetItem *item = row >= 0 ? m_lines->item(row) : nullptr;
	if (item && m_lines->currentRow() != row)
		m_lines->setCurrentRow(row);
	const bool file = item && !item->data(ROLE_FILE).toByteArray().isEmpty();
	m_fetch->setEnabled(file);
	m_save->setEnabled(file);
	m_keep->setEnabled(item && item->data(ROLE_IN).toBool()
	                   && !item->data(ROLE_STICKER).toByteArray().isEmpty());
}

bool fzn_conversation_view::fetch()
{
	QListWidgetItem *item = m_lines->currentItem();
	QByteArray ref = item ? item->data(ROLE_FILE).toByteArray() : QByteArray();
	fzn_rpc_blob_fetch_resp_t out;

	if (ref.isEmpty())
		return false;
	if (fzn_rpc_blob_fetch_ref(&m_rpc->c, (const uint8_t *)ref.constData(),
	                           (const uint8_t *)ref.constData() + 32, file_size(ref), &out)
	    != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	/* THE SIZE IS THE SENDER'S CLAIM, said as one; the fetch checks the
	 * file's own tree, so a lie fails there (sec 794). */
	m_status->setText(tr("Asked for the file, said to be %1. It arrives in the background.")
	                          .arg(size_words(file_size(ref))));
	return true;
}

bool fzn_conversation_view::save_to(const QString &path)
{
	QListWidgetItem *item = m_lines->currentItem();
	QByteArray ref = item ? item->data(ROLE_FILE).toByteArray() : QByteArray();
	fzn_rpc_blob_export_resp_t out;

	if (ref.isEmpty())
		return false;
	QString where = path;
	if (where.isEmpty())
		where = QFileDialog::getSaveFileName(this, tr("Save the file"),
		                                     QString::fromUtf8(ref.mid(72)));
	if (where.isEmpty())
		return false;
	QByteArray at = where.toUtf8();
	if (fzn_rpc_blob_export(&m_rpc->c, (const uint8_t *)ref.constData(),
	                        (const uint8_t *)ref.constData() + 32, at.constData(), (size_t)at.size(),
	                        &out)
	    != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	m_status->setText(tr("Saved %1 to %2.").arg(size_words(out.byte_len), where));
	return true;
}

bool fzn_conversation_view::show_older()
{
	if (m_contact.isEmpty())
		return false;
	m_max += LINES_PAGE;
	return refresh();
}

bool fzn_conversation_view::send_file(const QString &path)
{
	QString from = path.isEmpty() ? QFileDialog::getOpenFileName(this, tr("Send a file")) : path;
	if (from.isEmpty() || m_contact.isEmpty())
		return false;
	QByteArray at = from.toUtf8();
	/* THE NAME SENT is the file's own, which the reference refuses if it
	 * could be taken for a path (sec 794). */
	QByteArray name = from.section(QLatin1Char('/'), -1).toUtf8();
	const bool group = m_contact.startsWith(QLatin1Char('@'));
	QByteArray to = (group ? m_contact.mid(1) : m_contact).toUtf8();
	fzn_rpc_blob_add_resp_t stored;
	if (fzn_rpc_blob_add(&m_rpc->c, at.constData(), (size_t)at.size(), FZN_RPC_BLOB_TIER_PRIVATE, &stored)
	            != FZN_RPC_OK
	    || fzn_rpc_message_attach(&m_rpc->c, to.constData(), (size_t)to.size(), group ? 1 : 0,
	                              stored.root, name.constData(), (size_t)name.size())
	               != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	refresh();
	m_status->setText(tr("Sent %1, %2.").arg(QString::fromUtf8(name), size_words(stored.byte_len)));
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

/* EACH STICKER LINE DRAWN, as the picker draws one: the thumbnail the
 * node renders, where Qt reads it. What the node drew is kept for the
 * view's life -- a null icon for Lottie or art Qt cannot read, said in
 * words -- and one the node could not draw is asked again at the next
 * refresh, since its pack may still be arriving. */
void fzn_conversation_view::draw_stickers()
{
	for (int i = 0; i < m_lines->count(); i++) {
		QListWidgetItem *item = m_lines->item(i);
		const QByteArray sticker = item->data(ROLE_STICKER).toByteArray();
		if (sticker.size() <= 145)
			continue;
		auto held = m_art->drawn.constFind(sticker);
		if (held != m_art->drawn.constEnd()) {
			if (!held.value().isNull())
				item->setIcon(held.value());
			continue;
		}
		uint8_t *bytes = nullptr;
		size_t len = 0;
		uint8_t format = 0;
		QImage image;
		if (fzn_rpc_sticker_art(&m_rpc->c, sticker.constData(), 144, sticker.mid(145).toULongLong(),
		                        FZN_STICKER_THUMB, ART_MAX, &bytes, &len, &format)
		    == FZN_RPC_OK) {
			QIcon icon;
			if (format != FZN_STICKER_LOTTIE && image.loadFromData(bytes, (int)len))
				icon = QIcon(QPixmap::fromImage(image));
			m_art->drawn.insert(sticker, icon);
			if (!icon.isNull())
				item->setIcon(icon);
		}
		free(bytes);
	}
}

bool fzn_conversation_view::keep_pack()
{
	QListWidgetItem *item = m_lines->currentItem();
	const QByteArray sticker = item ? item->data(ROLE_STICKER).toByteArray() : QByteArray();
	uint8_t root[32];
	int host_only = 0;

	if (sticker.size() <= 145 || !item->data(ROLE_IN).toBool())
		return false;
	if (fzn_rpc_sticker_keep(&m_rpc->c, sticker.constData(), 144, root, &host_only) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	/* KEPT FOR THIS HOST ALONE where it may not set the estate's settings,
	 * as put answers. */
	m_status->setText(host_only ? tr("Kept the pack, on this device only.")
	                            : tr("Kept the pack with your stickers."));
	return true;
}

bool fzn_conversation_view::drawn(int row) const
{
	QListWidgetItem *item = row >= 0 ? m_lines->item(row) : nullptr;
	return item && !item->icon().isNull();
}

