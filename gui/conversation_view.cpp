/* A conversation with one contact, as a widget: gui/conversation_view.h, sec 1126. */
#include "conversation_view.h"
#include "plain_label.h"
#include "menu_exec.h"
#include "choose_accessible.h"
#include "phone_layout.h"
#include "notice_line.h"
#include "size_words.h"
#include "sticker_picker_view.h"

#include "rpc_ask.h"
#include "sticker_render.h"

extern "C" {
#include "../local/rpc_encoding.h"
#include "../messages/attachment.h"
#include "../messages/reply.h"
#include "../hex/hex.h"
#include "../sticker/pack.h"
}

#include <QByteArray>
#include <QDateTime>
#include <QElapsedTimer>
#include <QTemporaryDir>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QHash>
#include <QMenu>
#include <QMap>
#include <QVector>
#include <QIcon>
#include <QImage>
#include <QPixmap>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPainter>
#include <QPushButton>
#include <QScrollBar>
#include <QResizeEvent>
#include <QStyledItemDelegate>
#include <QTimer>
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
/* THE LINE'S ID, what a reply or a reaction names it by (sec 1282). */
#define ROLE_ID (Qt::UserRole + 7)
/* TAKEN BACK BY ITS SENDER, sec 1284. */
#define ROLE_UNSENT (Qt::UserRole + 8)
/* A STICKER'S WORDS, the sender's, for a message or name sticker (sec 1295). */
#define ROLE_STICKER_TEXT (Qt::UserRole + 9)

/* A STICKER IN THE LOG, sec 1295: its main rendition at this many pixels
 * across, where the 64 px thumbnail read as an icon beside a line. */
#define STICKER_PX 128

/* A STICKER PLAYED, sec 1300: one loop in this long, a frame every so
 * often, and so many loops before it rests on its still -- the chosen
 * line's alone, by one timer for the view (sec 1151's "one frame, not a
 * player": a timer per sticker in a scrolling log burns a core). */
#define PLAY_LOOP_MS 2000
#define PLAY_FRAME_MS 40
#define PLAY_LOOPS 3

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

		if (icon && w < STICKER_PX)
			w = STICKER_PX;
		w += 2 * PAD;
		const int h = (icon ? STICKER_PX + GAP : 0) + text.height() + GAP + fs.height() + 2 * PAD;
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
			icon.paint(p, QRect(at.left(), at.top(), STICKER_PX, STICKER_PX), Qt::AlignLeft | Qt::AlignTop);
			at.setTop(at.top() + STICKER_PX + GAP);
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
	/* EACH STICKER'S SOUND, written once into a directory the view owns and
	 * removes with it, by sticker (sec 1301). */
	QTemporaryDir sounds;
	QHash<QByteArray, QString> sound_at;
	/* A POP-UP STICKER'S POP-UP ART and its format, by sticker (sec 1302). */
	QHash<QByteArray, QByteArray> popup_art;
	QHash<QByteArray, int> popup_format;
	QByteArray popping;
	/* AN EFFECT STICKER plays behind the lines rather than over them (sec
	 * 1315): its frame painted on the viewport before the lines are. */
	bool behind = false;
	QPixmap behind_frame;
	QElapsedTimer popped_for;
	/* A LOTTIE STICKER'S ART, by the same key, kept to play it (sec 1300). */
	QHash<QByteArray, QByteArray> lottie;
	/* ITS FORMAT: a Lottie, or a raster one of more than one frame -- an
	 * APNG or animated WebP (sec 1322), played as a Lottie is. */
	QHash<QByteArray, int> moving_format;
	QElapsedTimer playing_for;
	/* EACH PACK'S STICKERS, read once a pack for their boxes (sec 1295):
	 * by the pack's word, each sticker by its id. */
	QHash<QByteArray, QHash<qulonglong, fzn_rpc_node_sticker_item_t>> boxes;
};

/* A sticker line's words, the sender's: empty for any other line. */
static QString sticker_text_of(const char *text, size_t len)
{
	static fzn_sticker_ref_t ref;

	if (!fzn_sticker_ref_parse(text, len, &ref) || !ref.length || !ref.text_len)
		return QString();
	return QString::fromUtf8(ref.text, (int)ref.text_len);
}

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
static QString state_words(const fzn_rpc_inbox_entry_t *l, unsigned read_by = 0)
{
	return fzn_conversation_view::state_said(l->outgoing != 0, l->state, read_by);
}

QString fzn_conversation_view::state_said(bool outgoing, unsigned state, unsigned read_by)
{
	if (!outgoing || state == FZN_RPC_LINE_UNSENT)
		return QString();
	/* A GROUP'S LINE, HOW MANY READ IT, sec 1273, as LINE's "Read 3". */
	if (read_by)
		return QObject::tr(" (read by %n)", nullptr, (int)read_by);
	switch ((fzn_rpc_line_state_t)state) {
	case FZN_RPC_LINE_DELIVERED:
	case FZN_RPC_LINE_SETTLED:
		return QObject::tr(" (delivered)");
	case FZN_RPC_LINE_HANDED_OVER:
		return QObject::tr(" (with a relay)");
	case FZN_RPC_LINE_NOT_DELIVERED:
		return QObject::tr(" (not delivered)");
	case FZN_RPC_LINE_READ:
		return QObject::tr(" (read)");
	case FZN_RPC_LINE_NONE:
		return QObject::tr(" (sending)");
	case FZN_RPC_LINE_UNSENT:
		break;
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

/* LINES ABOUT OTHER LINES, sec 1282: each line's words by its id, for a
 * reply to quote, and each reaction folded under the line it names, each
 * sender's newest standing and none taking theirs back. Gathered over the
 * lines shown, oldest first: a reply to a line older than the page says
 * so rather than quoting it. */
struct about_lines {
	QHash<QByteArray, QString> words;
	QHash<QByteArray, QHash<QByteArray, QByteArray>> reactions;
};

static QByteArray id_of(const fzn_rpc_inbox_entry_t *l)
{
	return QByteArray((const char *)l->commitment, (int)sizeof l->commitment);
}

static bool reaction_of(const fzn_rpc_inbox_entry_t *l, QByteArray *to, QByteArray *reaction)
{
	uint8_t id[FZN_MESSAGE_ID_LEN];
	size_t at = 0, n = 0;

	if (!fzn_message_reaction_parse(l->text, l->text_len, id, &at, &n))
		return false;
	*to = QByteArray((const char *)id, (int)sizeof id);
	*reaction = QByteArray(l->text + at, (int)n);
	return true;
}

static void gather(const QVector<const fzn_rpc_inbox_entry_t *> &oldest_first, about_lines *a)
{
	for (const fzn_rpc_inbox_entry_t *l : oldest_first) {
		QByteArray to, reaction;

		if (reaction_of(l, &to, &reaction)) {
			/* WHO REACTED: this user, or the sender by key and name -- a
			 * group's members share the group's host key. */
			const QByteArray who = l->outgoing ? QByteArray("\001")
			                                   : QByteArray((const char *)l->sender_host_pubkey, 32)
			                                             + QByteArray(l->sender_name, (int)l->sender_name_len);
			if (reaction.isEmpty())
				a->reactions[to].remove(who);
			else
				a->reactions[to][who] = reaction;
			continue;
		}
		a->words.insert(id_of(l), l->state == FZN_RPC_LINE_UNSENT ? QObject::tr("This line was taken back.")
		                                                          : content_words(l->text, l->text_len));
	}
}

/* A LINE'S WORDS, a reply's with the start of the line it answers, and the
 * reactions to it after, each with how many gave it. */
static QString shown_words(const fzn_rpc_inbox_entry_t *l, const about_lines &a)
{
	uint8_t id[FZN_MESSAGE_ID_LEN];
	size_t at = 0;
	QString said;

	/* TAKEN BACK BY ITS SENDER, sec 1284: its text gone, said so. */
	if (l->state == FZN_RPC_LINE_UNSENT)
		said = QObject::tr("This line was taken back.");
	else if (fzn_message_reply_parse(l->text, l->text_len, id, &at)) {
		const QString to = a.words.value(QByteArray((const char *)id, (int)sizeof id));
		const QString body = content_words(l->text + at, l->text_len - at);
		said = to.isEmpty() ? QObject::tr("(in reply to a line not shown) %1").arg(body)
		                    : QObject::tr("(in reply to \"%1\") %2")
		                              .arg(to.size() > 40 ? to.left(39) + QChar(0x2026) : to, body);
	} else {
		said = content_words(l->text, l->text_len);
	}
	const auto r = a.reactions.find(id_of(l));
	if (r != a.reactions.end() && !r->isEmpty()) {
		QMap<QByteArray, int> counts;
		QStringList parts;
		char shown[4u * FZN_MESSAGE_REACTION_MAX + 1u];

		for (const QByteArray &one : *r)
			counts[one]++;
		for (auto c = counts.constBegin(); c != counts.constEnd(); ++c) {
			fzn_rpc_tty_escape(c.key().constData(), (size_t)c.key().size(), shown, sizeof shown);
			parts << QStringLiteral("%1 %2").arg(QString::fromUtf8(shown)).arg(c.value());
		}
		said += QStringLiteral(" [%1]").arg(parts.join(QStringLiteral(", ")));
	}
	return said;
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

	m_title = fzn_plain_label(this);
	m_title->setWordWrap(true);
	m_lines = new QListWidget(this);
	{
		QScrollBar *bar = m_lines->verticalScrollBar();
		connect(bar, &QScrollBar::valueChanged, [this, bar](int v) {
			if (!m_filling)
				m_follow = v >= bar->maximum();
		});
		/* A WINDOW GROWN, or lines laid out late, keeps a reader at the end
		 * there. */
		connect(bar, &QScrollBar::rangeChanged, [this, bar](int, int max) {
			if (m_follow && !m_filling)
				bar->setValue(max);
		});
	}
	m_lines->setWordWrap(true);
	m_lines->setIconSize(QSize(STICKER_PX, STICKER_PX));
	m_play = new QTimer(this);
	m_play->setInterval(PLAY_FRAME_MS);
	connect(m_play, &QTimer::timeout, [this]() { play_frame(); });
	/* A POP-UP STICKER, over the log and not in it (sec 1302): clicks go
	 * through to the lines beneath. */
	m_popup = fzn_plain_label(m_lines->viewport());
	m_popup->setAlignment(Qt::AlignCenter);
	m_popup->setAttribute(Qt::WA_TransparentForMouseEvents);
	m_popup->hide();
	m_lines->viewport()->installEventFilter(this);
	m_pop = new QTimer(this);
	m_pop->setInterval(PLAY_FRAME_MS);
	connect(m_pop, &QTimer::timeout, [this]() { pop_frame(); });
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
	/* A REACTION TO THE CHOSEN LINE, sec 1282: a few, as LINE and Signal
	 * offer, from a menu -- the notice holds one action, a reply. */
	m_react = new QPushButton(tr("React"), this);
	m_react->setAccessibleName(tr("React to the chosen line"));
	/* OPENED THROUGH THE HOST'S HOOK (sec 1515): a button's own menu pops
	 * itself, past fzn_menu_exec, the abort under TalkBack that
	 * menu_exec.h exists for (fuzzypickles, inbox 20261127T0950Z). */
	connect(m_react, &QPushButton::clicked, [this]() {
		QMenu menu(m_react);
		for (const QString &r : reactions())
			menu.addAction(r)->setData(r);
		QAction *chosen = fzn_menu_exec(&menu, m_react, m_react->mapToGlobal(QPoint(0, m_react->height())));
		QListWidgetItem *item = m_lines->currentItem();
		if (chosen)
			(void)react(item ? item->data(ROLE_ID).toByteArray() : QByteArray(), chosen->data().toString());
	});
	m_react->setEnabled(false);
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
	/* STICKERS FOR WHAT IS TYPED, sec 1272: one row, above the line. */
	m_suggest = new QListWidget(this);
	m_suggest->setViewMode(QListView::IconMode);
	m_suggest->setFlow(QListView::LeftToRight);
	m_suggest->setWrapping(false);
	m_suggest->setIconSize(QSize(56, 56));
	/* ONE ROW TALL: the icon and a line of words, from the font, so a
	 * character cell sizes it as well as a screen does (qtty sec 7). */
	m_suggest->setMaximumHeight(56 + 2 * m_suggest->fontMetrics().height());
	m_suggest->setAccessibleName(tr("Stickers for what you are writing"));
	m_suggest->hide();
	/* THE WATCH, sec 1522: asks only while the view is shown. */
	m_watch = new QTimer(this);
	m_watch->setInterval(2000);
	connect(m_watch, &QTimer::timeout, [this]() {
		if (isVisible())
			(void)watch_now();
	});
	m_watch->start();
	m_suggest_soon = new QTimer(this);
	m_suggest_soon->setSingleShot(true);
	m_suggest_soon->setInterval(250);
	connect(m_suggest_soon, &QTimer::timeout, [this]() { suggest_now(); });
	connect(m_text, &QLineEdit::textEdited, [this](const QString &) { m_suggest_soon->start(); });
	connect(m_suggest, &QListWidget::itemActivated,
	        [this](QListWidgetItem *item) { (void)send_suggested(m_suggest->row(item)); });
	/* A SCREEN READER CHOOSES TOO, sec 1423: its double tap only selects. */
	fzn_choose_on_accessible_select(m_suggest, [this](const QModelIndex &at) { (void)send_suggested(at.row()); });
	auto *col = new QVBoxLayout(this);
	col->addWidget(m_title);
	col->addWidget(m_lines, 1);
	auto *older = new QHBoxLayout;
	older->addWidget(m_older);
	older->addStretch(1);
	/* REACT BESIDE THE LINES, not the line being written: it acts on the
	 * chosen line, and the row it would join holds a phone's 320 px only
	 * as it is (qtty_render_test). */
	older->addWidget(m_react);
	/* ABOVE THE LINES, where the older ones go. */
	col->insertLayout(1, older);
	/* THE LINE BEING WRITTEN LAST, sec 1253: on a phone the window ends at
	 * the keyboard, so what is last sits right above it -- the notice and
	 * the picker above the line, never under it. */
	col->addWidget(m_notice);
	col->addWidget(m_picker);
	col->addWidget(m_suggest);
	col->addLayout(write);

	connect(m_send, &QPushButton::clicked, [this]() { send(); });
	connect(m_stickers, &QPushButton::toggled, [this](bool on) { show_stickers(on); });
	connect(m_text, &QLineEdit::returnPressed, [this]() { send(); });
	connect(m_lines, &QListWidget::currentRowChanged, [this](int r) { select_line(r); });
	fzn_choose_on_accessible_select(m_lines, nullptr);
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
	reply_to(QByteArray());
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
                        uint32_t now, size_t max, bool *answered, bool mark)
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
	QVector<const fzn_rpc_inbox_entry_t *> oldest_first;
	about_lines about;
	for (i = count; i-- > 0;)
		oldest_first << &lines[i].line;
	gather(oldest_first, &about);
	for (i = count; i-- > 0;) {
		const fzn_rpc_inbox_entry_t *l = &lines[i].line;
		char who[4u * FZN_RPC_PEER_NAME_MAX + 1u];
		QByteArray to, reaction;

		/* A REACTION IS SHOWN ON ITS LINE, never as one (sec 1282). */
		if (reaction_of(l, &to, &reaction))
			continue;
		fzn_rpc_tty_escape(l->sender_name, l->sender_name_len, who, sizeof who);
		const QString said = shown_words(l, about);
		auto *item = new QListWidgetItem(QStringLiteral("%1 %2: %3")
		                      .arg(when_words(now, l->stime),
		                           l->outgoing ? QObject::tr("You") : QString::fromUtf8(who), said)
		                       + state_words(l, lines[i].read_by));
		item->setData(ROLE_ID, id_of(l));
		item->setData(ROLE_AT, (qulonglong)l->stime);
		item->setData(ROLE_UNSENT, l->state == FZN_RPC_LINE_UNSENT);
		item->setData(ROLE_FILE, file_of(l->text, l->text_len));
		item->setData(ROLE_STICKER, sticker_of(l->text, l->text_len));
		item->setData(ROLE_STICKER_TEXT, sticker_text_of(l->text, l->text_len));
		item->setData(ROLE_IN, !l->outgoing);
		item->setData(ROLE_BODY, l->outgoing ? said
		                                     : QStringLiteral("%1\n%2").arg(QString::fromUtf8(who), said));
		item->setData(ROLE_META, when_words(now, l->stime) + state_words(l, lines[i].read_by));
		list->addItem(item);
	}
	for (i = 0; i < count && !newest_in; i++)
		if (!lines[i].line.outgoing)
			newest_in = &lines[i].line;
	/* EMPTY, SAID KINDLY, as fuzzypickles' does (its sec 286): a blank
	 * page read as one still loading. */
	refresh_quiet(status, count ? QString() : QObject::tr("No messages in %1 yet.").arg(group.mid(1)));
	if (newest_in && mark) {
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

void fzn_conversation_view::mark_read_when(std::function<bool()> may) { m_may_mark = std::move(may); }

void fzn_conversation_view::set_watch_ms(int ms)
{
	if (ms <= 0) {
		m_watch->stop();
		return;
	}
	m_watch->start(ms);
}

void fzn_conversation_view::message_event(const QString &name)
{
	(void)name;
	(void)watch_now();
}

/* THE NEWEST LINE'S MARK: one line asked, newest first -- its id and
 * state, and who read it in a group. Empty when the node did not answer,
 * so a silent node refreshes nothing. */
QByteArray fzn_conversation_view::newest_now()
{
	QByteArray mark;

	if (m_contact.isEmpty())
		return mark;
	if (m_contact.startsWith(QLatin1Char('@'))) {
		fzn_rpc_group_line_t newest;
		size_t count = 0;
		const QByteArray name = m_contact.mid(1).toUtf8();

		if (fzn_rpc_group_lines(&m_rpc->c, name.constData(), (size_t)name.size(), &newest, 1, &count)
		    != FZN_RPC_OK)
			return mark;
		mark = "g";
		if (count)
			mark += QByteArray((const char *)newest.line.commitment, 16) + (char)newest.line.state
			        + QByteArray::number(newest.read_by);
		return mark;
	}
	fzn_rpc_inbox_entry_t newest;
	size_t count = 0;
	const QByteArray who = m_contact.toUtf8();

	if (fzn_rpc_inbox_lines(&m_rpc->c, who.constData(), (size_t)who.size(), &newest, 1, &count) != FZN_RPC_OK)
		return mark;
	mark = "c";
	if (count)
		mark += QByteArray((const char *)newest.commitment, 16) + (char)newest.state;
	return mark;
}

bool fzn_conversation_view::watch_now()
{
	const QByteArray now = newest_now();

	if (now.isEmpty() || now == m_newest_seen)
		return false;
	(void)refresh();
	return true;
}

/* THE READER'S PLACE KEPT across a refill, sec 1518: at the end, the end
 * again, as new lines arrive; scrolled up into the history, the line at
 * the top stays at the top. Every poll pulled a reader down to the newest
 * line (fuzzypickles' 0950Z item 1). A conversation newly opened starts
 * at its end. */
bool fzn_conversation_view::refresh_lines()
{
	QScrollBar *bar = m_lines->verticalScrollBar();
	const int was = bar->value();
	QByteArray top_id;
	QString top_text;

	if (m_place_for != m_contact || m_lines->count() == 0)
		m_follow = true;
	const bool at_end = m_follow;
	if (!at_end) {
		if (QListWidgetItem *top = m_lines->itemAt(4, 4)) {
			top_id = top->data(ROLE_ID).toByteArray();
			top_text = top->text();
		}
	}
	m_filling = true;
	const bool r = fill_lines();
	m_place_for = m_contact;
	m_newest_seen = r ? newest_now() : QByteArray();
	if (at_end) {
		m_lines->scrollToBottom();
	} else {
		int at = -1;
		for (int i = 0; i < m_lines->count() && at < 0; i++) {
			QListWidgetItem *it = m_lines->item(i);
			if (top_id.isEmpty() ? it->text() == top_text : it->data(ROLE_ID).toByteArray() == top_id)
				at = i;
		}
		/* THE TOP LINE GONE -- unsent, or past the page -- the scroll as
		 * it was. */
		if (at >= 0)
			m_lines->scrollToItem(m_lines->item(at), QAbstractItemView::PositionAtTop);
		else
			bar->setValue(was);
	}
	m_filling = false;
	return r;
}

bool fzn_conversation_view::fill_lines()
{
	const bool mark = !m_may_mark || m_may_mark();

	if (m_contact.isEmpty())
		return false;
	if (m_contact.startsWith(QLatin1Char('@'))) {
		bool answered = true;
		const uint32_t at = m_now ? m_now : (uint32_t)time(NULL);
		if (!group_lines(m_rpc, m_contact, m_lines, m_notice, at, m_max, &answered, mark))
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
	QVector<const fzn_rpc_inbox_entry_t *> oldest_first;
	about_lines about;
	for (i = count; i-- > 0;)
		oldest_first << &lines[i];
	gather(oldest_first, &about);
	/* NEWEST FIRST from the node; shown oldest at the top. */
	for (i = count; i-- > 0;) {
		const fzn_rpc_inbox_entry_t *l = &lines[i];
		QByteArray to, reaction;

		/* A REACTION IS SHOWN ON ITS LINE, never as one (sec 1282). */
		if (reaction_of(l, &to, &reaction))
			continue;
		const QString said = shown_words(l, about);
		auto *item = new QListWidgetItem(QStringLiteral("%1 %2: %3")
		                         .arg(when_words(now, l->stime), l->outgoing ? tr("You") : m_contact, said)
		                 + state_words(l));
		item->setData(ROLE_ID, id_of(l));
		item->setData(ROLE_FILE, file_of(l->text, l->text_len));
		item->setData(ROLE_STICKER, sticker_of(l->text, l->text_len));
		item->setData(ROLE_STICKER_TEXT, sticker_text_of(l->text, l->text_len));
		item->setData(ROLE_IN, !l->outgoing);
		item->setData(ROLE_BODY, said);
		item->setData(ROLE_META, when_words(now, l->stime) + state_words(l));
		item->setData(ROLE_AT, (qulonglong)l->stime);
		item->setData(ROLE_UNSENT, l->state == FZN_RPC_LINE_UNSENT);
		m_lines->addItem(item);
	}
	merge_calls(count >= m_max, now);
	for (i = 0; i < count && !newest_in; i++)
		if (!lines[i].outgoing)
			newest_in = &lines[i];
	/* READ HERE IS READ EVERYWHERE: the node keeps the position and syncs
	 * it to this user's other devices (sec 528). Said, not failed, when the
	 * node will not take it -- the lines are shown either way. */
	if (newest_in && mark
	    && fzn_rpc_message_read(&m_rpc->c, who.constData(), (size_t)who.size(), newest_in->commitment)
	               != FZN_RPC_OK) {
		m_notice->say(tr("Shown, but not marked read: %1").arg(failed_words(m_rpc)), true);
		free(lines);
		draw_stickers();
		return true;
	}
	refresh_quiet(m_notice, count ? QString() : tr("No messages with %1 yet. Say hello!").arg(m_contact));
	/* A FULL PAGE MAY HAVE MORE BEHIND IT. */
	m_older->setEnabled(count >= m_max);
	free(lines);
	draw_stickers();
	return true;
}

void fzn_conversation_view::set_text(const QString &text) { m_text->setText(text); }

bool fzn_conversation_view::send()
{
	QByteArray text = m_text->text().toUtf8();

	/* IN REPLY, sec 1282: the words after the line they answer's id. */
	if (m_reply_to.size() == (int)FZN_MESSAGE_ID_LEN && !text.trimmed().isEmpty()) {
		char wrapped[FZN_MESSAGE_TEXT_MAX + 1u];
		const size_t n = fzn_message_reply_write((const uint8_t *)m_reply_to.constData(), text.constData(),
		                                 (size_t)text.size(), wrapped, sizeof wrapped);
		if (!n) {
			m_notice->say(tr("That is too long to send as a reply."));
			return false;
		}
		text = QByteArray(wrapped, (int)n);
	}
	if (!send_line(text))
		return false;
	reply_to(QByteArray());
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

#define ROLE_SUGGEST_PACK (Qt::UserRole + 40)
#define ROLE_SUGGEST_ID (Qt::UserRole + 41)
#define SUGGEST_SHOWN 8

void fzn_conversation_view::suggest_now()
{
	/* EACH STICKER DRAWN ONCE, by its pack and id, for the view's life:
	 * the row is asked again at every pause in the typing. */
	static QHash<QString, QPixmap> drawn_once;
	auto *found = new fzn_rpc_sticker_match_resp_t;
	const QByteArray typed = m_text->text().toUtf8();
	QByteArray answered;

	/* A REPLY'S LINE IS ITS CONTEXT, sec 1321: stickers that fit the line
	 * answered are offered before a word is typed. */
	for (int i = 0; !m_reply_to.isEmpty() && i < m_lines->count() && answered.isEmpty(); i++)
		if (m_lines->item(i)->data(ROLE_ID).toByteArray() == m_reply_to)
			answered = m_lines->item(i)->data(ROLE_BODY).toString().toUtf8();
	m_suggest->clear();
	if (m_contact.isEmpty() || (typed.trimmed().isEmpty() && answered.trimmed().isEmpty())
	    || (answered.isEmpty() ? fzn_rpc_sticker_match(&m_rpc->c, typed.constData(), (size_t)typed.size(), found)
	                           : fzn_rpc_sticker_answer(&m_rpc->c, answered.constData(), (size_t)answered.size(),
	                                                    typed.constData(), (size_t)typed.size(), found))
	               != FZN_RPC_OK) {
		m_suggest->hide();
		delete found;
		return;
	}
	for (size_t i = 0; i < found->count && i < SUGGEST_SHOWN; i++) {
		const fzn_rpc_sticker_match_entry_t *e = &found->entries[i];
		char hex[65];
		fzn_hex_encode(e->root, 32, hex);
		const QByteArray pack(hex, 64);
		const QString key = QString::fromLatin1(pack) + QLatin1Char('/') + QString::number(e->id);
		const QString words = QString::fromUtf8(e->description, (int)e->description_len);
		auto *item = new QListWidgetItem(m_suggest);

		if (!drawn_once.contains(key)) {
			uint8_t *art = nullptr;
			size_t art_len = 0;
			uint8_t format = 0;
			QPixmap pic;
			if (fzn_rpc_sticker_art(&m_rpc->c, pack.constData(), 64, e->id, FZN_STICKER_THUMB, ART_MAX, &art,
			                        &art_len, &format)
			    == FZN_RPC_OK)
				pic = fzn_sticker_render_art(art, art_len, format, QSize(56, 56)).pixmap;
			free(art);
			drawn_once.insert(key, pic);
		}
		const QPixmap pic = drawn_once.value(key);
		if (!pic.isNull())
			item->setIcon(QIcon(pic));
		else
			item->setText(words.isEmpty() ? tr("a sticker") : words);
		item->setToolTip(fzn_plain_tip(words));
		item->setData(Qt::AccessibleTextRole, words.isEmpty() ? tr("a sticker") : words);
		item->setData(ROLE_SUGGEST_PACK, pack);
		item->setData(ROLE_SUGGEST_ID, (qulonglong)e->id);
	}
	m_suggest->setVisible(m_suggest->count() > 0);
	delete found;
}

QStringList fzn_conversation_view::suggested() const
{
	QStringList out;
	for (int i = 0; i < m_suggest->count(); i++)
		out << m_suggest->item(i)->data(Qt::AccessibleTextRole).toString();
	return out;
}

/* ONE CHOSEN SENT, IN PLACE OF THE WORDS, as LINE does: the line cleared
 * once the sticker went, and kept if it did not. */
bool fzn_conversation_view::send_suggested(int i)
{
	QListWidgetItem *item = i >= 0 ? m_suggest->item(i) : nullptr;
	char ref[FZN_STICKER_REF_SENT_MAX + 1];
	size_t ref_len = 0;

	if (!item)
		return false;
	const QByteArray pack = item->data(ROLE_SUGGEST_PACK).toByteArray();
	if (fzn_rpc_sticker_reference(&m_rpc->c, pack.constData(), (size_t)pack.size(),
	                              (uint64_t)item->data(ROLE_SUGGEST_ID).toULongLong(), ref, sizeof ref, &ref_len)
	    != FZN_RPC_OK) {
		m_notice->say(failed_words(m_rpc));
		return false;
	}
	/* A REFUSED SEND SAYS SO ITSELF, and the words stay. */
	if (!send_line(QByteArray(ref, (int)ref_len)))
		return false;
	m_text->clear();
	m_suggest->clear();
	m_suggest->hide();
	refresh();
	return true;
}

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

void fzn_conversation_view::reply_to(const QByteArray &id)
{
	QString quoted;

	m_reply_to = id.size() == (int)FZN_MESSAGE_ID_LEN ? id : QByteArray();
	for (int i = 0; !m_reply_to.isEmpty() && i < m_lines->count() && quoted.isEmpty(); i++)
		if (m_lines->item(i)->data(ROLE_ID).toByteArray() == m_reply_to)
			quoted = m_lines->item(i)->data(ROLE_BODY).toString();
	if (quoted.size() > 40)
		quoted = quoted.left(39) + QChar(0x2026);
	m_text->setPlaceholderText(m_reply_to.isEmpty() ? tr("Write a line")
	                                                : tr("Your reply to \"%1\"").arg(quoted));
	if (!m_reply_to.isEmpty())
		m_text->setFocus();
	suggest_now();
}

QByteArray fzn_conversation_view::replying() const { return m_reply_to; }

bool fzn_conversation_view::unsend(const QByteArray &id)
{
	QByteArray who = m_contact.toUtf8();

	if (id.size() != (int)FZN_MESSAGE_ID_LEN || m_contact.isEmpty())
		return false;
	if (fzn_rpc_message_unsend(&m_rpc->c, who.constData(), (size_t)who.size(), (const uint8_t *)id.constData())
	    != FZN_RPC_OK) {
		m_notice->say(failed_words(m_rpc));
		return false;
	}
	m_notice->say(tr("Taken back."));
	refresh();
	return true;
}

QStringList fzn_conversation_view::reactions()
{
	return { QString::fromUtf8("\xf0\x9f\x91\x8d"), QString::fromUtf8("\xe2\x9d\xa4\xef\xb8\x8f"),
	         QString::fromUtf8("\xf0\x9f\x98\x82"), QString::fromUtf8("\xf0\x9f\x98\xae"),
	         QString::fromUtf8("\xf0\x9f\x98\xa2"), QString::fromUtf8("\xf0\x9f\x99\x8f") };
}

bool fzn_conversation_view::react(const QByteArray &id, const QString &reaction)
{
	const QByteArray r = reaction.toUtf8();
	char text[FZN_MESSAGE_TEXT_MAX + 1u];
	size_t n;

	if (id.size() != (int)FZN_MESSAGE_ID_LEN
	    || !(n = fzn_message_reaction_write((const uint8_t *)id.constData(), r.constData(), (size_t)r.size(),
	                                        text, sizeof text)))
		return false;
	if (!send_line(QByteArray(text, (int)n)))
		return false;
	refresh();
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
	if (!m_refreshing)
		play(item);
	if (m_refreshing || key == m_chosen)
		return;
	m_chosen = key;
	/* A NEW CHOICE ONLY: its sound once, not again at a refresh; and a
	 * pop-up sticker across the log (sec 1302). */
	if (item)
		sound(item);
	pop(item);
	m_react->setEnabled(item && item->data(ROLE_ID).toByteArray().size() == (int)FZN_MESSAGE_ID_LEN);
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
	/* ANY OTHER LINE CAN BE ANSWERED, sec 1282; a past call cannot. */
	const QByteArray id = item ? item->data(ROLE_ID).toByteArray() : QByteArray();
	/* THIS USER'S OWN LINE, under an hour old, taken back instead, sec
	 * 1284 -- offered only where this user has unsend on. */
	if (id.size() == (int)FZN_MESSAGE_ID_LEN && !item->data(ROLE_IN).toBool()
	    && !item->data(ROLE_UNSENT).toBool()) {
		const qulonglong now = m_now ? m_now : (qulonglong)time(NULL), sent = item->data(ROLE_AT).toULongLong();
		fzn_rpc_config_get_resp_t on;

		memset(&on, 0, sizeof on);
		if (sent && now >= sent && now - sent < FZN_MESSAGE_UNSEND_WINDOW_MS / 1000u
		    && fzn_rpc_config_get(&m_rpc->c, "message.unsend", 14, &on) == FZN_RPC_OK && on.value_len == 2
		    && !memcmp(on.value, "on", 2)) {
			m_notice->offer(tr("Take this line back, here and from them, within an hour of sending it."),
			                tr("Unsend"), [this, id]() { (void)unsend(id); });
			return;
		}
	}
	if (id.size() == (int)FZN_MESSAGE_ID_LEN && !item->data(ROLE_UNSENT).toBool()) {
		m_notice->offer(tr("Answer this line with the next one you send."), tr("Reply"),
		                [this, id]() { reply_to(id); });
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
	/* SENT IN REPLY while a reply is under way (sec 1510), as a line is:
	 * the node writes the reply mark before the reference (sec 1395). */
	const bool replying = m_reply_to.size() == (int)FZN_MESSAGE_ID_LEN;
	if (fzn_rpc_blob_add(&m_rpc->c, at.constData(), (size_t)at.size(), FZN_RPC_BLOB_TIER_PRIVATE, &stored)
	            != FZN_RPC_OK
	    || (replying ? fzn_rpc_message_attach_reply(&m_rpc->c, to.constData(), (size_t)to.size(), group ? 1 : 0,
	                                                stored.root, name.constData(), (size_t)name.size(),
	                                                (const uint8_t *)m_reply_to.constData())
	                 : fzn_rpc_message_attach(&m_rpc->c, to.constData(), (size_t)to.size(), group ? 1 : 0,
	                                          stored.root, name.constData(), (size_t)name.size()))
	               != FZN_RPC_OK) {
		m_notice->say(failed_words(m_rpc));
		return false;
	}
	if (replying)
		reply_to(QByteArray());
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
/* THE CHOSEN LINE'S STICKER PLAYED, sec 1300, where its art is a Lottie
 * one this build draws; any other line chosen, or none, stops it on its
 * still. */
void fzn_conversation_view::play(QListWidgetItem *item)
{
	const QByteArray key = item ? item->data(ROLE_STICKER).toByteArray() + '\n'
	                                      + item->data(ROLE_STICKER_TEXT).toString().toUtf8()
	                            : QByteArray();

	if (m_playing && m_playing != item)
		rest();
	if (!item || !m_art->lottie.contains(key) || m_playing == item)
		return;
	m_playing = item;
	m_playing_key = key;
	m_art->playing_for.start();
	m_play->start();
}

/* THE PLAYED STICKER BACK ON ITS STILL, the timer stopped. */
void fzn_conversation_view::rest()
{
	m_play->stop();
	if (m_playing) {
		auto still = m_art->drawn.constFind(m_playing_key);
		if (still != m_art->drawn.constEnd() && !still.value().isNull())
			m_playing->setIcon(still.value());
	}
	m_playing = nullptr;
}

/* ONE FRAME OF THE STICKER PLAYING, its words drawn into it as on its still. */
void fzn_conversation_view::play_frame()
{
	const qint64 ms = m_art->playing_for.elapsed();
	auto art = m_art->lottie.constFind(m_playing_key);

	if (!m_playing || art == m_art->lottie.constEnd() || ms >= PLAY_LOOP_MS * PLAY_LOOPS) {
		rest();
		return;
	}
	const float progress = (float)(ms % PLAY_LOOP_MS) / (float)PLAY_LOOP_MS;
	const fzn_sticker_render_result r = fzn_sticker_render_art((const uint8_t *)art.value().constData(),
	                                                           (size_t)art.value().size(),
	                                                           (uint8_t)m_art->moving_format.value(m_playing_key,
	                                                                                               FZN_STICKER_LOTTIE),
	                                                           QSize(STICKER_PX, STICKER_PX), progress);
	if (r.pixmap.isNull())
		return;
	QPixmap shown = r.pixmap;
	const QString words = m_playing->data(ROLE_STICKER_TEXT).toString();
	const QByteArray sticker = m_playing->data(ROLE_STICKER).toByteArray();
	if (!words.isEmpty()) {
		fzn_sticker_entry_t *box = new fzn_sticker_entry_t;
		if (sticker_box(sticker.left(144), sticker.mid(145).toULongLong(), box))
			shown = fzn_sticker_with_text(shown, box, words);
		delete box;
	}
	m_playing->setIcon(QIcon(shown));
}

bool fzn_conversation_view::playing() const { return m_playing != nullptr; }

/* A POP-UP STICKER CHOSEN, sec 1302: its pop-up art across the log for one
 * loop -- played where it is a Lottie one this build draws, still
 * otherwise -- then gone; any other line chosen, or none, takes it away.
 * AN EFFECT STICKER (sec 1315) the same, but behind the lines: painted on
 * the log's background, the words over it. */
void fzn_conversation_view::pop(QListWidgetItem *item)
{
	const QByteArray sticker = item ? item->data(ROLE_STICKER).toByteArray() : QByteArray();
	fzn_sticker_entry_t *box;

	unpop();
	if (sticker.size() <= 145)
		return;
	box = new fzn_sticker_entry_t;
	const qulonglong id = sticker.mid(145).toULongLong();
	const bool known = sticker_box(sticker.left(144), id, box);
	const bool popup = known && box->type == FZN_STICKER_POPUP, effect = known && box->type == FZN_STICKER_EFFECT;
	delete box;
	if (!popup && !effect)
		return;
	if (!m_art->popup_art.contains(sticker)) {
		uint8_t *bytes = nullptr, format = 0;
		size_t len = 0;

		if (fzn_rpc_sticker_art(&m_rpc->c, sticker.constData(), 144, id, FZN_STICKER_POPUP_ART, ART_MAX, &bytes,
		                        &len, &format)
		    != FZN_RPC_OK) {
			free(bytes);
			return;
		}
		m_art->popup_art.insert(sticker, QByteArray((const char *)bytes, (int)len));
		m_art->popup_format.insert(sticker, format);
		free(bytes);
	}
	m_art->popping = sticker;
	m_art->behind = effect;
	m_art->popped_for.start();
	if (!effect) {
		m_popup->setGeometry(m_lines->viewport()->rect());
		m_popup->show();
		m_popup->raise();
	}
	pop_frame();
	if (!m_art->popping.isEmpty())
		m_pop->start();
}

void fzn_conversation_view::unpop()
{
	m_pop->stop();
	m_popup->hide();
	m_art->popping.clear();
	if (m_art->behind) {
		m_art->behind = false;
		m_art->behind_frame = QPixmap();
		m_lines->viewport()->update();
	}
}

/* THE EFFECT'S FRAME, under the lines: the viewport's background is filled
 * before its paint event reaches this filter, and the lines are painted
 * after it, so the frame lies between the two. */
bool fzn_conversation_view::eventFilter(QObject *watched, QEvent *event)
{
	if (event->type() == QEvent::Paint && watched == m_lines->viewport() && m_art->behind
	    && !m_art->behind_frame.isNull()) {
		QPainter p(m_lines->viewport());
		const QRect room = m_lines->viewport()->rect();
		const QSize at = m_art->behind_frame.size() / m_art->behind_frame.devicePixelRatio();

		p.drawPixmap(room.center().x() - at.width() / 2, room.center().y() - at.height() / 2, m_art->behind_frame);
	}
	return QWidget::eventFilter(watched, event);
}

void fzn_conversation_view::pop_frame()
{
	const qint64 ms = m_art->popped_for.elapsed();
	auto art = m_art->popup_art.constFind(m_art->popping);

	if (art == m_art->popup_art.constEnd() || ms >= PLAY_LOOP_MS) {
		unpop();
		return;
	}
	const QSize room = m_lines->viewport()->size();
	const int side = qMax(STICKER_PX, qMin(room.width(), room.height()));
	const fzn_sticker_render_result r = fzn_sticker_render_art(
	        (const uint8_t *)art.value().constData(), (size_t)art.value().size(),
	        (uint8_t)m_art->popup_format.value(m_art->popping), QSize(side, side), (float)ms / (float)PLAY_LOOP_MS);
	if (r.pixmap.isNull()) {
		unpop();
		return;
	}
	if (m_art->behind) {
		m_art->behind_frame = r.pixmap;
		m_lines->viewport()->update();
		return;
	}
	m_popup->setPixmap(r.pixmap);
}

bool fzn_conversation_view::popped() const { return !m_art->popping.isEmpty() && !m_art->behind; }

bool fzn_conversation_view::effected() const { return !m_art->popping.isEmpty() && m_art->behind; }

void fzn_conversation_view::on_sound(std::function<void(const QString &)> play) { m_sound = std::move(play); }

/* THE CHOSEN STICKER'S SOUND, sec 1301, where its pack says it has one and
 * the host plays sounds: written once, then handed to the host's player
 * each time the sticker is chosen. */
void fzn_conversation_view::sound(QListWidgetItem *item)
{
	const QByteArray sticker = item->data(ROLE_STICKER).toByteArray();
	fzn_sticker_entry_t *box;

	if (!m_sound || sticker.size() <= 145)
		return;
	auto at = m_art->sound_at.constFind(sticker);
	if (at != m_art->sound_at.constEnd()) {
		m_sound(at.value());
		return;
	}
	box = new fzn_sticker_entry_t;
	const qulonglong id = sticker.mid(145).toULongLong();
	const bool has = sticker_box(sticker.left(144), id, box) && (box->flags & FZN_STICKER_FLAG_SOUND);
	delete box;
	if (!has || !m_art->sounds.isValid())
		return;
	const QString path = m_art->sounds.filePath(QStringLiteral("%1-%2").arg(QString::fromLatin1(sticker.left(16))).arg(id));
	const QByteArray p = path.toUtf8();
	uint64_t bytes = 0;
	if (fzn_rpc_sticker_sound(&m_rpc->c, sticker.constData(), 144, id, p.constData(), (size_t)p.size(), &bytes)
	    != FZN_RPC_OK)
		return;
	m_art->sound_at.insert(sticker, path);
	m_sound(path);
}

/* A STICKER'S BOX, sec 1295: its pack's stickers read once, and this one
 * as the overlay reads an entry -- the box, its paint and the main
 * rendition's size it is measured in. 0 where the pack will not list or
 * holds no such sticker. */
int fzn_conversation_view::sticker_box(const QByteArray &pack, qulonglong id, fzn_sticker_entry_t *out)
{
	auto held = m_art->boxes.constFind(pack);

	if (held == m_art->boxes.constEnd()) {
		auto *items = new fzn_rpc_node_sticker_items_resp_t;
		QHash<qulonglong, fzn_rpc_node_sticker_item_t> by_id;

		memset(items, 0, sizeof *items);
		if (fzn_rpc_sticker_items(&m_rpc->c, pack.constData(), (size_t)pack.size(), items) == FZN_RPC_OK)
			for (size_t i = 0; i < items->count; i++)
				by_id.insert((qulonglong)items->entries[i].id, items->entries[i]);
		delete items;
		held = m_art->boxes.insert(pack, by_id);
	}
	auto one = held.value().constFind(id);
	if (one == held.value().constEnd())
		return 0;
	memset(out, 0, sizeof *out);
	out->id = one->id;
	out->type = one->type;
	out->flags = one->flags;
	out->text_limit = one->text_limit;
	out->text_x = one->text_x;
	out->text_y = one->text_y;
	out->text_w = one->text_w;
	out->text_h = one->text_h;
	out->text_fill = one->text_fill;
	out->text_ink = one->text_ink;
	out->text_turn = one->text_turn;
	out->renditions[0].role = FZN_STICKER_MAIN;
	out->renditions[0].width = one->main_w;
	out->renditions[0].height = one->main_h;
	out->rendition_count = one->main_w && one->main_h ? 1u : 0u;
	return 1;
}

void fzn_conversation_view::draw_stickers()
{
	for (int i = 0; i < m_lines->count(); i++) {
		QListWidgetItem *item = m_lines->item(i);
		const QByteArray sticker = item->data(ROLE_STICKER).toByteArray();
		const QString words = item->data(ROLE_STICKER_TEXT).toString();
		if (sticker.size() <= 145)
			continue;
		/* ONE DRAWING A STICKER AND ITS WORDS: the same sticker sent with
		 * other words is another drawing. */
		const QByteArray key = sticker + '\n' + words.toUtf8();
		auto held = m_art->drawn.constFind(key);
		if (held != m_art->drawn.constEnd()) {
			if (!held.value().isNull())
				item->setIcon(held.value());
			continue;
		}
		uint8_t *bytes = nullptr;
		size_t len = 0;
		uint8_t format = 0;
		const qulonglong id = sticker.mid(145).toULongLong();
		/* THE MAIN RENDITION, at STICKER_PX (sec 1295); the thumbnail where
		 * the pack carries no main one. */
		int got = fzn_rpc_sticker_art(&m_rpc->c, sticker.constData(), 144, id, FZN_STICKER_MAIN, ART_MAX, &bytes,
		                              &len, &format)
		          == FZN_RPC_OK;
		if (!got) {
			free(bytes);
			bytes = nullptr;
			got = fzn_rpc_sticker_art(&m_rpc->c, sticker.constData(), 144, id, FZN_STICKER_THUMB, ART_MAX, &bytes,
			                          &len, &format)
			      == FZN_RPC_OK;
		}
		if (got) {
			QIcon icon;
			/* WHAT MOVES IS KEPT TO PLAY, sec 1300 and 1322: a Lottie, and a
			 * raster sticker of more than one frame. */
			if (format == FZN_STICKER_LOTTIE || fzn_sticker_render_frames(bytes, len, format) > 1) {
				m_art->lottie.insert(key, QByteArray((const char *)bytes, (int)len));
				m_art->moving_format.insert(key, format);
			}
			/* LOTTIE TOO where thorvg is built in, sec 1151. */
			const fzn_sticker_render_result r =
			        fzn_sticker_render_art(bytes, len, format, QSize(STICKER_PX, STICKER_PX));
			if (!r.pixmap.isNull()) {
				QPixmap shown = r.pixmap;
				fzn_sticker_entry_t *box = new fzn_sticker_entry_t;

				/* A MESSAGE OR NAME STICKER CARRIES THE SENDER'S WORDS, drawn
				 * into its box as sent (sec 1295). */
				if (!words.isEmpty() && sticker_box(sticker.left(144), id, box))
					shown = fzn_sticker_with_text(shown, box, words);
				delete box;
				icon = QIcon(shown);
			}
			m_art->drawn.insert(key, icon);
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
	m_bubbles->narrow = fzn_phone_layout(event->size().width());
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
