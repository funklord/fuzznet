/* A conversation with one contact, as a widget: gui/conversation_view.h, sec 1126. */
#include "conversation_view.h"
#include "notice_line.h"
#include "size_words.h"
#include "sticker_picker_view.h"

#include "rpc_ask.h"
#include "sticker_render.h"

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
#include <QPainter>
#include <QPushButton>
#include <QResizeEvent>
#include <QStyledItemDelegate>
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
/* A LINE'S PARTS FOR A BUBBLE, sec 1241: what it says -- with who said it,
 * for a group member's -- and when, with where this user's has got to. */
#define ROLE_BODY (Qt::UserRole + 3)
#define ROLE_META (Qt::UserRole + 4)
/* WHEN IT HAPPENED, seconds since 1970, to place a call among the lines by
 * (sec 1255); and whether the row is a call rather than a line. */
#define ROLE_AT (Qt::UserRole + 5)
#define ROLE_CALL (Qt::UserRole + 6)

/* A LINE AS A BUBBLE ON A PHONE, sec 1241, fuzzypickles' 1700Z item 2: this
 * user's at the right, everyone else's at the left, each wrapped within
 * three quarters of the width, a sticker drawn inside it, the time and the
 * delivery word small beneath. A desktop keeps the log, one line a row: a
 * QListWidget of caret-form lines read as a log on both. */
class bubble_delegate : public QStyledItemDelegate {
public:
	explicit bubble_delegate(QObject *parent) : QStyledItemDelegate(parent) {}
	bool narrow = false;
	int width = 0;

	QRect bubble(const QStyleOptionViewItem &option, const QModelIndex &index) const
	{
		const int across = width > 0 ? width : option.rect.width();
		const int most = across * 3 / 4 - 2 * PAD;
		const QFontMetrics fm(option.font);
		const QFontMetrics fs(small(option.font));
		const QString body = index.data(ROLE_BODY).toString(), meta = index.data(ROLE_META).toString();
		const QRect text = fm.boundingRect(QRect(0, 0, most > 40 ? most : 40, 100000), Qt::TextWordWrap, body);
		const bool icon = !index.data(Qt::DecorationRole).isNull();
		int w = text.width() > fs.horizontalAdvance(meta) ? text.width() : fs.horizontalAdvance(meta);

		if (icon && w < 64)
			w = 64;
		w += 2 * PAD;
		const int h = (icon ? 64 + GAP : 0) + text.height() + GAP + fs.height() + 2 * PAD;
		const int x = index.data(ROLE_IN).toBool() ? option.rect.left() + PAD : option.rect.left() + across - PAD - w;
		return QRect(x, option.rect.top() + GAP / 2, w, h);
	}

	void paint(QPainter *p, const QStyleOptionViewItem &option, const QModelIndex &index) const override
	{
		if (!narrow) {
			QStyledItemDelegate::paint(p, option, index);
			return;
		}
		const QRect b = bubble(option, index);
		const bool in = index.data(ROLE_IN).toBool();
		const QPalette &pal = option.palette;
		QColor fill = in ? pal.color(QPalette::AlternateBase) : pal.color(QPalette::Highlight).lighter(170);

		p->save();
		p->setRenderHint(QPainter::Antialiasing, true);
		p->setPen((option.state & QStyle::State_Selected) ? QPen(pal.color(QPalette::Highlight), 2) : Qt::NoPen);
		p->setBrush(fill);
		p->drawRoundedRect(b, 8, 8);
		QRect at = b.adjusted(PAD, PAD, -PAD, -PAD);
		const QIcon icon = qvariant_cast<QIcon>(index.data(Qt::DecorationRole));
		if (!icon.isNull()) {
			icon.paint(p, QRect(at.left(), at.top(), 64, 64), Qt::AlignLeft | Qt::AlignTop);
			at.setTop(at.top() + 64 + GAP);
		}
		p->setPen(pal.color(QPalette::Text));
		p->drawText(at, Qt::TextWordWrap | Qt::AlignLeft | Qt::AlignTop, index.data(ROLE_BODY).toString());
		p->setFont(small(option.font));
		p->setPen(pal.color(QPalette::Disabled, QPalette::Text));
		p->drawText(at, Qt::AlignRight | Qt::AlignBottom, index.data(ROLE_META).toString());
		p->restore();
	}

	QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const override
	{
		if (!narrow)
			return QStyledItemDelegate::sizeHint(option, index);
		return QSize(width > 0 ? width : option.rect.width(), bubble(option, index).height() + GAP);
	}

private:
	static constexpr int PAD = 6, GAP = 4;
	static QFont small(QFont f)
	{
		f.setPointSizeF(f.pointSizeF() > 0 ? f.pointSizeF() * 0.85 : 8.0);
		return f;
	}
};
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
 * for a line that came in. ONE NOTHING IS KNOWN OF YET IS SENDING, sec 1241:
 * said as nothing, a line on its way could not be told from one stuck
 * (fuzzypickles' 1700Z item 1). */
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
		return QObject::tr(" (sending)");
	}
	return QString();
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
		return QObject::tr("a file: %1, %2").arg(QString::fromUtf8(shown), fzn_size_words(file.size));
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
	m_bubbles = new bubble_delegate(m_lines);
	m_lines->setItemDelegate(m_bubbles);
	/* EACH ROW ITS OWN HEIGHT, a bubble's being its text's. */
	m_lines->setUniformItemSizes(false);
	m_text = new QLineEdit(this);
	m_text->setPlaceholderText(tr("Write a line"));
	m_text->setAccessibleName(tr("A line to send"));
	m_send = new QPushButton(tr("Send"), this);
	m_older = new QPushButton(tr("Older lines"), this);
	m_send_file = new QPushButton(tr("Send a file"), this);
	m_send_file->setAccessibleName(tr("Send a file"));
	/* ONE NOTICE, ITS ONE ACTION (sec 1253): what an act came to, or the
	 * one thing the chosen line offers -- where three buttons stood, most
	 * of them disabled, beside a status line. */
	m_notice = new fzn_notice_line(this);

	auto *write = new QHBoxLayout;
	write->addWidget(m_text, 1);
	/* A STICKER BY SEND, not a page of its own (fuzzypickles' 1700Z item 3,
	 * sec 1243): the picker opens below the line being written. */
	m_stickers = new QPushButton(tr("Sticker"), this);
	m_stickers->setCheckable(true);
	m_stickers->setAccessibleName(tr("Choose a sticker to send"));
	write->addWidget(m_stickers);
	write->addWidget(m_send_file);
	write->addWidget(m_send);
	m_picker = new fzn_sticker_picker_view(ask, ask_ctx, this);
	m_picker->hide();
	m_picker->on_pick([this](const QString &ref) { (void)send_sticker(ref); });
	auto *col = new QVBoxLayout(this);
	col->addWidget(m_title);
	col->addWidget(m_lines, 1);
	auto *older = new QHBoxLayout;
	older->addWidget(m_older);
	older->addStretch(1);
	/* ABOVE THE LINES, where the older ones go. */
	col->insertLayout(1, older);
	/* THE LINE BEING WRITTEN LAST, sec 1253: on a phone the window ends at
	 * the keyboard, so what is last sits right above it -- the notice and
	 * the picker above the line, never under it. */
	col->addWidget(m_notice);
	col->addWidget(m_picker);
	col->addLayout(write);

	connect(m_send, &QPushButton::clicked, [this]() { send(); });
	connect(m_stickers, &QPushButton::toggled, [this](bool on) { show_stickers(on); });
	connect(m_text, &QLineEdit::returnPressed, [this]() { send(); });
	connect(m_lines, &QListWidget::currentRowChanged, [this](int r) { select_line(r); });
	connect(m_lines, &QListWidget::itemActivated,
	        [this](QListWidgetItem *item) { (void)open_line(m_lines->row(item)); });
	connect(m_older, &QPushButton::clicked, [this]() { show_older(); });
	connect(m_send_file, &QPushButton::clicked, [this]() { send_file(QString()); });
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

/* WHAT A REFRESH SAYS WHEN ALL WENT WELL -- nothing, or that nothing has
 * been said -- put over a notice only where the last refresh put it, or
 * where there is none: the answer to the person's last act, or what the
 * chosen line offers, outlives the next poll (sec 1253, sec 1224's fault). */
static void refresh_quiet(fzn_notice_line *notice, const QString &text)
{
	if (notice->text().isEmpty() || notice->from_refresh())
		notice->say(text, true);
}

/* A GROUP'S LINES, newest first as a contact's are, each with who wrote it;
 * the read position at the newest that came in, kept by the group's id. */
static bool group_lines(fzn_gui_rpc *rpc, const QString &group, QListWidget *list, fzn_notice_line *status,
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
		status->say(failed_words(rpc), true);
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
		item->setData(ROLE_BODY, l->outgoing ? content_words(l->text, l->text_len)
		                                     : QStringLiteral("%1\n%2").arg(QString::fromUtf8(who),
		                                                                  content_words(l->text, l->text_len)));
		item->setData(ROLE_META, when_words(now, l->stime) + state_words(l));
		list->addItem(item);
	}
	for (i = 0; i < count && !newest_in; i++)
		if (!lines[i].line.outgoing)
			newest_in = &lines[i].line;
	refresh_quiet(status, count ? QString() : QObject::tr("Nothing said yet."));
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
			status->say(QObject::tr("Shown, but not marked read: %1").arg(failed_words(rpc)), true);
	}
	free(lines);
	if (count)
		list->scrollToBottom();
	return true;
}

/* THE LINES AGAIN, the line chosen kept by its text -- not its scroll,
 * which follows the newest line -- and with it what the notice offers
 * (sec 1253). A line no longer there takes its offer with it. */
bool fzn_conversation_view::refresh()
{
	m_refreshing = true;
	const bool r = refresh_lines();
	m_refreshing = false;
	int at = -1;
	for (int i = 0; !m_chosen.isEmpty() && i < m_lines->count() && at < 0; i++)
		if (m_lines->item(i)->text() == m_chosen)
			at = i;
	if (at >= 0) {
		m_lines->setCurrentRow(at);
	} else if (!m_chosen.isEmpty()) {
		m_chosen.clear();
		if (m_notice->offering())
			m_notice->clear();
	}
	return r;
}

/* A PAST CALL IN A PERSON'S WORDS, from this user's side (sec 1255). */
static QString call_words(const fzn_rpc_call_past_t &p, const QString &who)
{
	const QString video = (p.kinds & 2u) ? QObject::tr(" (video)") : QString();

	switch (p.outcome) {
	case FZN_RPC_CALL_ANSWERED: {
		const QString lasted = p.seconds >= 3600u ? QStringLiteral("%1:%2:%3")
		                                                    .arg(p.seconds / 3600u)
		                                                    .arg(p.seconds / 60u % 60u, 2, 10, QLatin1Char('0'))
		                                                    .arg(p.seconds % 60u, 2, 10, QLatin1Char('0'))
		                                          : QStringLiteral("%1:%2")
		                                                    .arg(p.seconds / 60u)
		                                                    .arg(p.seconds % 60u, 2, 10, QLatin1Char('0'));
		return (p.out ? QObject::tr("You called %1, %2").arg(who, lasted)
		              : QObject::tr("%1 called you, %2").arg(who, lasted))
		       + video;
	}
	case FZN_RPC_CALL_MISSED:
		return QObject::tr("Missed call from %1").arg(who) + video;
	case FZN_RPC_CALL_DECLINED:
		return (p.out ? QObject::tr("%1 declined your call").arg(who) : QObject::tr("You declined %1's call").arg(who))
		       + video;
	case FZN_RPC_CALL_BUSY:
		return QObject::tr("You called %1, busy").arg(who) + video;
	case FZN_RPC_CALL_NO_ANSWER:
		return QObject::tr("You called %1, no answer").arg(who) + video;
	case FZN_RPC_CALL_ELSEWHERE:
		return QObject::tr("%1 called you, taken on another device").arg(who) + video;
	default:
		return (p.out ? QObject::tr("You called %1, it did not connect").arg(who)
		              : QObject::tr("%1's call did not connect").arg(who))
		       + video;
	}
}

/* THE CALLS AMONG THE LINES, sec 1255: each placed by when it was rung,
 * after the lines before it; past the oldest line shown only where the
 * page holds every line. Never a line: not read, not marked, not
 * offered anything. A node that keeps no history adds none. */
void fzn_conversation_view::merge_calls(bool full, uint32_t now)
{
	fzn_rpc_call_past_t past[FZN_RPC_CALL_HISTORY_MAX];
	const QByteArray who = m_contact.toUtf8();
	size_t n = 0, i;

	if (fzn_rpc_call_history(&m_rpc->c, who.constData(), (size_t)who.size(), past, FZN_RPC_CALL_HISTORY_MAX, &n)
	    != FZN_RPC_OK)
		return;
	const qulonglong oldest = full && m_lines->count() ? m_lines->item(0)->data(ROLE_AT).toULongLong() : 0u;
	for (i = 0; i < n; i++) {
		int at = m_lines->count();

		if (past[i].started < oldest)
			continue;
		while (at > 0 && m_lines->item(at - 1)->data(ROLE_AT).toULongLong() > past[i].started)
			at--;
		const QString said = call_words(past[i], m_contact);
		auto *item = new QListWidgetItem(QStringLiteral("%1 %2").arg(when_words(now, past[i].started), said));
		item->setData(ROLE_AT, (qulonglong)past[i].started);
		item->setData(ROLE_CALL, true);
		item->setData(ROLE_IN, !past[i].out);
		item->setData(ROLE_BODY, said);
		item->setData(ROLE_META, when_words(now, past[i].started));
		m_lines->insertItem(at, item);
	}
}

bool fzn_conversation_view::refresh_lines()
{
	if (m_contact.isEmpty())
		return false;
	if (m_contact.startsWith(QLatin1Char('@'))) {
		bool answered = true;
		const uint32_t at = m_now ? m_now : (uint32_t)time(NULL);
		if (!group_lines(m_rpc, m_contact, m_lines, m_notice, at, m_max, &answered))
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
		m_notice->say(failed_words(m_rpc), true);
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
		item->setData(ROLE_BODY, content_words(l->text, l->text_len));
		item->setData(ROLE_META, when_words(now, l->stime) + state_words(l));
		item->setData(ROLE_AT, (qulonglong)l->stime);
		m_lines->addItem(item);
	}
	merge_calls(count >= m_max, now);
	for (i = 0; i < count && !newest_in; i++)
		if (!lines[i].outgoing)
			newest_in = &lines[i];
	/* READ HERE IS READ EVERYWHERE: the node keeps the position and syncs
	 * it to this user's other devices (sec 528). Said, not failed, when the
	 * node will not take it -- the lines are shown either way. */
	if (newest_in
	    && fzn_rpc_message_read(&m_rpc->c, who.constData(), (size_t)who.size(), newest_in->commitment)
	               != FZN_RPC_OK) {
		m_notice->say(tr("Shown, but not marked read: %1").arg(failed_words(m_rpc)), true);
		free(lines);
		draw_stickers();
		return true;
	}
	refresh_quiet(m_notice, count ? QString() : tr("Nothing said yet."));
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
	if (!send_line(m_text->text().toUtf8()))
		return false;
	m_text->clear();
	refresh();
	return true;
}

void fzn_conversation_view::show_stickers(bool on)
{
	if (on)
		(void)m_picker->refresh();
	m_picker->setVisible(on);
	if (m_stickers->isChecked() != on)
		m_stickers->setChecked(on);
}

bool fzn_conversation_view::stickers_shown() const { return !m_picker->isHidden(); }

bool fzn_conversation_view::send_sticker(const QString &ref)
{
	if (!send_line(ref.toUtf8()))
		return false;
	show_stickers(false);
	refresh();
	return true;
}

/* ONE LINE SENT to the conversation open: 1, or the refusal said. */
bool fzn_conversation_view::send_line(const QByteArray &text)
{
	QByteArray who = m_contact.toUtf8();

	if (m_contact.isEmpty() || text.trimmed().isEmpty())
		return false;
	const bool group = m_contact.startsWith(QLatin1Char('@'));
	if ((group ? fzn_rpc_group_send(&m_rpc->c, who.constData() + 1, (size_t)who.size() - 1,
	                                text.constData(), (size_t)text.size())
	           : fzn_rpc_message_send(&m_rpc->c, who.constData(), (size_t)who.size(), text.constData(),
	                                  (size_t)text.size()))
	    != FZN_RPC_OK) {
		/* THE LINE KEPT, so nothing typed is lost to a refusal. */
		m_notice->say(failed_words(m_rpc));
		return false;
	}
	return true;
}

void fzn_conversation_view::select_line(int row)
{
	QListWidgetItem *item = row >= 0 ? m_lines->item(row) : nullptr;
	if (item && m_lines->currentRow() != row)
		m_lines->setCurrentRow(row);
	/* A REFRESH PUTS THE CHOICE BACK ITSELF, and the same line chosen again
	 * offers nothing new: its notice stands, an act's answer included. */
	const QString key = item ? item->text() : QString();
	if (m_refreshing || key == m_chosen)
		return;
	m_chosen = key;
	offer_for(item);
}

/* WHAT THE CHOSEN LINE OFFERS, sec 1253: a file, saved if it is here whole
 * and got if not; a sticker that came in, its pack kept. Any other line
 * takes back an offer standing, and leaves a said answer be. */
void fzn_conversation_view::offer_for(QListWidgetItem *item)
{
	const QByteArray ref = item ? item->data(ROLE_FILE).toByteArray() : QByteArray();
	const QByteArray sticker = item ? item->data(ROLE_STICKER).toByteArray() : QByteArray();

	if (!ref.isEmpty()) {
		fzn_rpc_blob_status_resp_t st;
		const QString name = QString::fromUtf8(ref.mid(72));

		memset(&st, 0, sizeof st);
		if (fzn_rpc_blob_status(&m_rpc->c, (const uint8_t *)ref.constData(), &st) == FZN_RPC_OK && st.known
		    && st.complete)
			m_notice->offer(tr("%1, %2, is here.").arg(name, fzn_size_words(file_size(ref))), tr("Save the file"),
			                [this]() { (void)save_to(QString()); });
		else
			m_notice->offer(tr("%1, said to be %2.").arg(name, fzn_size_words(file_size(ref))), tr("Get the file"),
			                [this]() { (void)fetch(); });
		return;
	}
	if (sticker.size() > 145 && item->data(ROLE_IN).toBool()) {
		m_notice->offer(tr("A sticker from a pack you can keep."), tr("Keep this sticker pack"),
		                [this]() { (void)keep_pack(); });
		return;
	}
	if (m_notice->offering())
		m_notice->clear();
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
		m_notice->say(failed_words(m_rpc));
		return false;
	}
	/* THE SIZE IS THE SENDER'S CLAIM, said as one; the fetch checks the
	 * file's own tree, so a lie fails there (sec 794). */
	m_notice->say(tr("Asked for the file, said to be %1. It arrives in the background.")
	                      .arg(fzn_size_words(file_size(ref))));
	return true;
}

bool fzn_conversation_view::open_line(int row, const QString &save_path)
{
	QListWidgetItem *item = row >= 0 ? m_lines->item(row) : nullptr;
	const QByteArray ref = item ? item->data(ROLE_FILE).toByteArray() : QByteArray();
	fzn_rpc_blob_status_resp_t st;

	if (ref.isEmpty())
		return false;
	select_line(row);
	/* HERE WHOLE, SAVED; otherwise asked for, and a second tap once it has
	 * come saves it -- one action where there were a choice and two
	 * buttons (fuzzypickles' 1700Z item 4). */
	memset(&st, 0, sizeof st);
	if (fzn_rpc_blob_status(&m_rpc->c, (const uint8_t *)ref.constData(), &st) == FZN_RPC_OK && st.known
	    && st.complete)
		return save_to(save_path);
	return fetch();
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
		m_notice->say(failed_words(m_rpc));
		return false;
	}
	m_notice->say(tr("Saved %1 to %2.").arg(fzn_size_words(out.byte_len), where));
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
		m_notice->say(failed_words(m_rpc));
		return false;
	}
	refresh();
	m_notice->say(tr("Sent %1, %2.").arg(QString::fromUtf8(name), fzn_size_words(stored.byte_len)));
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

QString fzn_conversation_view::status() const { return m_notice->text(); }

QString fzn_conversation_view::offered() const { return m_notice->action(); }

bool fzn_conversation_view::take_offer() { return m_notice->act(); }

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
		if (fzn_rpc_sticker_art(&m_rpc->c, sticker.constData(), 144, sticker.mid(145).toULongLong(),
		                        FZN_STICKER_THUMB, ART_MAX, &bytes, &len, &format)
		    == FZN_RPC_OK) {
			QIcon icon;
			/* LOTTIE TOO where thorvg is built in, sec 1151. */
			const fzn_sticker_render_result r = fzn_sticker_render_art(bytes, len, format, QSize(64, 64));
			if (!r.pixmap.isNull())
				icon = QIcon(r.pixmap);
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
		m_notice->say(failed_words(m_rpc));
		return false;
	}
	/* KEPT FOR THIS HOST ALONE where it may not set the estate's settings,
	 * as put answers. */
	m_notice->say(host_only ? tr("Kept the pack, on this device only.") : tr("Kept the pack with your stickers."));
	return true;
}

bool fzn_conversation_view::drawn(int row) const
{
	QListWidgetItem *item = row >= 0 ? m_lines->item(row) : nullptr;
	return item && !item->icon().isNull();
}

void fzn_conversation_view::resizeEvent(QResizeEvent *event)
{
	QWidget::resizeEvent(event);
	m_bubbles->narrow = event->size().width() < 400;
	m_bubbles->width = m_lines->viewport()->width();
	/* A FINGER'S TARGETS ON A PHONE, sec 1253: every button and the line
	 * being written at least FZN_NOTICE_LINE_TOUCH_PX tall. */
	for (QWidget *w : { (QWidget *)m_send, (QWidget *)m_send_file, (QWidget *)m_stickers, (QWidget *)m_older,
	                    (QWidget *)m_text })
		w->setMinimumHeight(m_bubbles->narrow ? FZN_NOTICE_LINE_TOUCH_PX : 0);
	m_notice->set_touch(m_bubbles->narrow);
	m_send_file->setText(m_bubbles->narrow ? tr("File") : tr("Send a file"));
	m_lines->doItemsLayout();
}

bool fzn_conversation_view::bubbles() const { return m_bubbles->narrow; }

QRect fzn_conversation_view::bubble_rect(int row) const
{
	QListWidgetItem *item = m_lines->item(row);
	if (!item || !m_bubbles->narrow)
		return QRect();
	QStyleOptionViewItem option;
	option.initFrom(m_lines->viewport());
	option.rect = m_lines->visualItemRect(item);
	option.font = m_lines->font();
	return m_bubbles->bubble(option, m_lines->model()->index(row, 0));
}
