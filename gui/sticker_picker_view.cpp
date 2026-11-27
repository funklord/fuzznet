/* Choosing a sticker, and keeping packs: gui/sticker_picker_view.h, sec 1141. */
#include "sticker_picker_view.h"
#include "staged_file.h"
#include "plain_label.h"
#include "choose_accessible.h"

#include "rpc_ask.h"
#include "sticker_render.h"

extern "C" {
#include "../hex/hex.h"
#include "../local/rpc_encoding.h"
#include "../sticker/pack.h"
}

#include <QBoxLayout>
#include <QByteArray>
#include <QDateTime>
#include <QEventLoop>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QIcon>
#include <QLineEdit>
#include <QImage>
#include <QLabel>
#include <QListWidget>
#include <QPixmap>
#include <QPushButton>
#include <QHash>
#include <QTabWidget>
#include <QElapsedTimer>
#include <QTemporaryDir>
#include <QTimer>
#include <QVBoxLayout>

#include <stdlib.h>
#include <string.h>

/* The most of a rendition read to draw: a thumbnail is a few KB. */
#define ART_MAX (256u * 1024u)

/* A STICKER'S ITEM carries its pack and id, to ask its reference by. */
#define ROLE_PACK (Qt::UserRole)
#define ROLE_ID (Qt::UserRole + 1)
#define ROLE_DRAWN (Qt::UserRole + 2)
/* THE CHARACTERS ITS WORDS MAY RUN TO, 0 for a sticker with no box (sec 1296). */
#define ROLE_LIMIT (Qt::UserRole + 3)
#define ROLE_DESCRIPTION (Qt::UserRole + 4)
#define ROLE_FLAGS (Qt::UserRole + 5)
/* WHAT MOVES, sec 1322: its art and format, kept to play when touched. */
#define ROLE_MOVING (Qt::UserRole + 6)
#define ROLE_MOVING_FORMAT (Qt::UserRole + 7)

/* A LOOP AND HOW MANY, and a frame's time: as the log plays (sec 1300). */
#define PLAY_LOOP_MS 2000
#define PLAY_LOOPS 3
#define PLAY_FRAME_MS 40

struct fzn_sticker_picker_view::sounds {
	QElapsedTimer playing_for;
	QIcon still;
	QTemporaryDir dir;
	QHash<QString, QString> at; /* "PACK/ID" to the file written */
};

static QString failed_words(const fzn_gui_rpc *r)
{
	return QString::fromUtf8(fzn_gui_rpc_silent(r));
}

static QString said(const char *text, size_t len)
{
	char shown[4u * 129u + 1u];
	fzn_rpc_tty_escape(text, len, shown, sizeof shown);
	return QString::fromUtf8(shown);
}

fzn_sticker_picker_view::fzn_sticker_picker_view(fzn_notebook_view_ask_t ask, void *ask_ctx,
                                                 QWidget *parent)
    : QWidget(parent), m_rpc(new fzn_gui_rpc), m_sounds(new sounds)
{
	fzn_gui_rpc_init(m_rpc, ask, ask_ctx);

	m_tabs = new QTabWidget(this);
	m_tabs->setAccessibleName(tr("Sticker packs"));
	/* FINDING A STICKER, sec 1298: by the words its pack gives it, every
	 * kept pack at once, as the suggestion row matches a line being typed
	 * (sec 1272). The stickers found stand in place of the tabs. */
	m_find = new QLineEdit(this);
	m_find->setPlaceholderText(tr("Find a sticker"));
	m_find->setAccessibleName(tr("Find a sticker by its words"));
	m_find->setClearButtonEnabled(true);
	fzn_name_clear_button(m_find);
	m_found = new QListWidget(this);
	m_found->setViewMode(QListView::IconMode);
	m_found->setIconSize(QSize(64, 64));
	m_found->setResizeMode(QListView::Adjust);
	m_found->setWordWrap(true);
	m_found->setAccessibleName(tr("Stickers found"));
	m_found->hide();
	m_keep = new QPushButton(tr("Add sticker packs"), this);
	m_keep->setAccessibleName(tr("Keep sticker packs from files"));
	m_refresh = new QPushButton(tr("Refresh"), this);
	/* LETTING A PACK GO, sec 1298: the pack on show, from every host of
	 * this user; kept again from any line that carries one of its stickers. */
	m_forget = new QPushButton(tr("Let go"), this);
	m_forget->setAccessibleName(tr("Let the sticker pack on show go"));
	m_status = fzn_plain_label(this);
	m_status->setWordWrap(true);

	auto *row = new QHBoxLayout;
	row->addWidget(m_keep);
	row->addWidget(m_forget);
	row->addWidget(m_refresh);
	row->addStretch(1);
	auto *col = new QVBoxLayout(this);
	col->addWidget(m_find);
	col->addWidget(m_tabs, 1);
	col->addWidget(m_found, 1);
	col->addLayout(row);
	col->addWidget(m_status);

	connect(m_keep, &QPushButton::clicked, [this]() {
		if (m_add_packs)
			m_add_packs();
		else
			keep_files(QStringList());
	});
	connect(m_refresh, &QPushButton::clicked, [this]() { refresh(); });
	connect(m_find, &QLineEdit::textChanged, [this](const QString &text) { set_find(text); });
	connect(m_found, &QListWidget::itemActivated, [this](QListWidgetItem *item) { pick_item(item); });
	/* A SCREEN READER PICKS TOO, sec 1423: its double tap only selects, and
	 * is the one gesture it has, so it sends as activation does. */
	fzn_choose_on_accessible_select(m_found, [this](const QModelIndex &at) { pick_item(m_found->item(at.row())); });
	connect(m_found, &QListWidget::itemClicked, [this](QListWidgetItem *item) {
		play(item);
		sound(item);
	});
	connect(m_forget, &QPushButton::clicked, [this]() {
		const int at = pack_of_tab(m_tabs->currentIndex());

		if (at < 0)
			return;
		/* ASKED BY PRESSING AGAIN (sec 1515), within ten seconds, as the
		 * conversations list's deletions are: a message box was a second
		 * window, the abort under TalkBack. */
		const qint64 now = QDateTime::currentSecsSinceEpoch();
		if (m_forget_armed != at || now > m_forget_armed_at + 10) {
			m_forget_armed = at;
			m_forget_armed_at = now;
			m_status->setText(tr("Press Let go again to let %1 go from your stickers. You can keep it again "
			                     "from any message that carries one of its stickers.")
			                          .arg(m_tabs->tabText(m_tabs->indexOf(pack_list(at)))));
			return;
		}
		m_forget_armed = -1;
		forget(at);
	});
	m_status->setText(tr("No sticker packs kept yet."));
	m_play = new QTimer(this);
	m_play->setInterval(PLAY_FRAME_MS);
	connect(m_play, &QTimer::timeout, [this]() { play_frame(); });
}

fzn_sticker_picker_view::~fzn_sticker_picker_view()
{
	delete m_sounds;
	delete m_rpc;
}

void fzn_sticker_picker_view::on_sound(std::function<void(const QString &)> play) { m_sound = std::move(play); }

void fzn_sticker_picker_view::on_add_packs(std::function<void()> add) { m_add_packs = std::move(add); }

void fzn_sticker_picker_view::on_words(std::function<bool(const QString &, int, QString *)> ask)
{
	m_words = std::move(ask);
}

void fzn_sticker_picker_view::on_pick(std::function<void(const QString &)> pick) { m_pick = pick; }

bool fzn_sticker_picker_view::refresh()
{
	fzn_rpc_sticker_packs_t packs;
	auto *items = new fzn_rpc_node_sticker_items_resp_t;
	size_t p, i;

	if (fzn_rpc_sticker_list(&m_rpc->c, &packs) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		fzn_rpc_sticker_packs_release(&packs);
		delete items;
		return m_rpc->c.answered;
	}
	rest(); /* the items are about to go */
	while (m_tabs->count()) {
		QWidget *w = m_tabs->widget(0);
		m_tabs->removeTab(0);
		delete w;
	}
	for (p = 0; p < packs.count; p++) {
		char hex[65];
		fzn_hex_encode(packs.entries[p].root, 32, hex);
		const QByteArray pack(hex, 64);
		auto *list = new QListWidget;
		list->setViewMode(QListView::IconMode);
		list->setIconSize(QSize(64, 64));
		list->setResizeMode(QListView::Adjust);
		list->setWordWrap(true);
		list->setAccessibleName(tr("Stickers in %1").arg(said(packs.entries[p].name,
		                                                   packs.entries[p].name_len)));
		if (fzn_rpc_sticker_items(&m_rpc->c, pack.constData(), 64, items) == FZN_RPC_OK) {
			for (i = 0; i < items->count; i++) {
				const fzn_rpc_node_sticker_item_t *s = &items->entries[i];
				auto *item = new QListWidgetItem(said(s->description, s->description_len), list);
				uint8_t *art = nullptr;
				size_t art_len = 0;
				uint8_t format = 0;
				bool drawn = false;
				/* DRAWN BY THE RENDERER, Lottie included where thorvg is
				 * built in (sec 1151), named otherwise. */
				if (fzn_rpc_sticker_art(&m_rpc->c, pack.constData(), 64, s->id, FZN_STICKER_THUMB,
				                        ART_MAX, &art, &art_len, &format)
				    == FZN_RPC_OK) {
					const fzn_sticker_render_result r =
					        fzn_sticker_render_art(art, art_len, format, QSize(64, 64));
					if (!r.pixmap.isNull()) {
						item->setIcon(QIcon(r.pixmap));
						drawn = true;
						if (fzn_sticker_render_frames(art, art_len, format) > 1) {
							item->setData(ROLE_MOVING, QByteArray((const char *)art, (int)art_len));
							item->setData(ROLE_MOVING_FORMAT, (int)format);
						}
					}
				}
				free(art);
				item->setData(ROLE_PACK, pack);
				item->setData(ROLE_ID, (qulonglong)s->id);
				item->setData(ROLE_DRAWN, drawn);
				item->setData(ROLE_LIMIT, (int)s->text_limit);
				item->setData(ROLE_DESCRIPTION, said(s->description, s->description_len));
				item->setData(ROLE_FLAGS, (int)s->flags);
			}
		}
		connect(list, &QListWidget::itemActivated, [this](QListWidgetItem *item) {
			QListWidget *l = item ? item->listWidget() : nullptr;
			if (l)
				pick_item(item);
		});
		fzn_choose_on_accessible_select(list, [this, list](const QModelIndex &at) { pick_item(list->item(at.row())); });
		/* A CLICK is a person touching it: its sound, where it has one;
		 * choosing it to send stays activation. */
		connect(list, &QListWidget::itemClicked, [this](QListWidgetItem *item) {
			play(item);
			sound(item);
		});
		list->setProperty("pack", pack);
		m_tabs->addTab(list, said(packs.entries[p].name, packs.entries[p].name_len));
	}
	m_status->setText(packs.count ? QString() : tr("No sticker packs kept yet."));
	fzn_rpc_sticker_packs_release(&packs);
	delete items;
	show_recent();
	return true;
}

/* THE RECENT TAB, sec 1317: the stickers this user sent lately, from any
 * of their hosts, newest first -- each as its pack's tab shows it, so it
 * asks the node for no art; one whose pack is not kept here is left out.
 * First among the tabs, and not shown when it would be empty or the node
 * cannot say. */
void fzn_sticker_picker_view::show_recent()
{
	auto *sent = new fzn_rpc_sticker_match_resp_t;
	auto *list = new QListWidget;

	memset(sent, 0, sizeof *sent);
	if (fzn_rpc_sticker_recent(&m_rpc->c, sent) == FZN_RPC_OK)
		for (size_t i = 0; i < sent->count; i++) {
			char hex[65];

			fzn_hex_encode(sent->entries[i].root, 32, hex);
			const QByteArray pack(hex, 64);
			for (int t = 0; t < m_tabs->count(); t++) {
				auto *l = qobject_cast<QListWidget *>(m_tabs->widget(t));
				if (!l || l->property("pack").toByteArray() != pack)
					continue;
				for (int r = 0; r < l->count(); r++)
					if (l->item(r)->data(ROLE_ID).toULongLong() == (qulonglong)sent->entries[i].id)
						list->addItem(l->item(r)->clone());
			}
		}
	delete sent;
	if (!list->count()) {
		delete list;
		return;
	}
	list->setViewMode(QListView::IconMode);
	list->setIconSize(QSize(64, 64));
	list->setResizeMode(QListView::Adjust);
	list->setWordWrap(true);
	list->setAccessibleName(tr("Stickers you sent lately"));
	list->setProperty("recent", true);
	connect(list, &QListWidget::itemActivated, [this](QListWidgetItem *item) { pick_item(item); });
	fzn_choose_on_accessible_select(list, [this, list](const QModelIndex &at) { pick_item(list->item(at.row())); });
	connect(list, &QListWidget::itemClicked, [this](QListWidgetItem *item) {
		play(item);
		sound(item);
	});
	m_tabs->insertTab(0, list, tr("Recent"));
	m_tabs->setCurrentIndex(0);
}

/* PACK `pack`'S LIST, counting packs alone (the Recent tab is none). */
QListWidget *fzn_sticker_picker_view::pack_list(int pack) const
{
	for (int t = 0; t < m_tabs->count(); t++) {
		auto *l = qobject_cast<QListWidget *>(m_tabs->widget(t));
		if (!l || l->property("recent").toBool())
			continue;
		if (pack-- == 0)
			return l;
	}
	return nullptr;
}

int fzn_sticker_picker_view::pack_of_tab(int tab) const
{
	QWidget *w = m_tabs->widget(tab);
	int pack = 0;

	if (!w || w->property("recent").toBool())
		return -1;
	for (int t = 0; t < tab; t++)
		if (!m_tabs->widget(t)->property("recent").toBool())
			pack++;
	return pack;
}

QStringList fzn_sticker_picker_view::recent() const
{
	QStringList out;
	auto *l = m_tabs->count() ? qobject_cast<QListWidget *>(m_tabs->widget(0)) : nullptr;

	for (int r = 0; l && l->property("recent").toBool() && r < l->count(); r++)
		out << l->item(r)->text();
	return out;
}

bool fzn_sticker_picker_view::pick_recent(int row)
{
	auto *l = m_tabs->count() ? qobject_cast<QListWidget *>(m_tabs->widget(0)) : nullptr;

	return l && l->property("recent").toBool() && pick_item(l->item(row));
}

bool fzn_sticker_picker_view::pick(int pack, int row)
{
	QListWidget *list = pack_list(pack);

	return pick_item(list ? list->item(row) : nullptr);
}

bool fzn_sticker_picker_view::touch(int pack, int row)
{
	QListWidget *list = pack_list(pack);
	QListWidgetItem *item = list ? list->item(row) : nullptr;

	play(item);
	return sound(item);
}

/* A TOUCHED STICKER THAT MOVES PLAYS, sec 1322: one at a time, for three
 * loops, then back on its still; one that does not, nothing. */
void fzn_sticker_picker_view::play(QListWidgetItem *item)
{
	if (m_playing && m_playing != item)
		rest();
	if (!item || item->data(ROLE_MOVING).toByteArray().isEmpty() || m_playing == item)
		return;
	m_playing = item;
	m_sounds->still = item->icon();
	m_sounds->playing_for.start();
	m_play->start();
}

void fzn_sticker_picker_view::play_frame()
{
	const qint64 ms = m_sounds->playing_for.elapsed();

	if (!m_playing || ms >= PLAY_LOOP_MS * PLAY_LOOPS) {
		rest();
		return;
	}
	const QByteArray art = m_playing->data(ROLE_MOVING).toByteArray();
	const fzn_sticker_render_result r =
	        fzn_sticker_render_art((const uint8_t *)art.constData(), (size_t)art.size(),
	                               (uint8_t)m_playing->data(ROLE_MOVING_FORMAT).toInt(), QSize(64, 64),
	                               (float)(ms % PLAY_LOOP_MS) / (float)PLAY_LOOP_MS);
	if (!r.pixmap.isNull())
		m_playing->setIcon(QIcon(r.pixmap));
}

void fzn_sticker_picker_view::rest()
{
	m_play->stop();
	if (m_playing && !m_sounds->still.isNull())
		m_playing->setIcon(m_sounds->still);
	m_playing = nullptr;
}

bool fzn_sticker_picker_view::playing() const { return m_playing != nullptr; }

/* A STICKER'S SOUND, sec 1314: written once from the node, as the log
 * writes it (sec 1301), then handed to the host's player on each touch. */
bool fzn_sticker_picker_view::sound(QListWidgetItem *item)
{
	if (!item || !m_sound || !(item->data(ROLE_FLAGS).toInt() & FZN_STICKER_FLAG_SOUND))
		return false;
	const QByteArray pack = item->data(ROLE_PACK).toByteArray();
	const uint64_t id = (uint64_t)item->data(ROLE_ID).toULongLong();
	const QString key = QString::fromLatin1(pack) + QLatin1Char('/') + QString::number((qulonglong)id);
	auto at = m_sounds->at.constFind(key);
	if (at != m_sounds->at.constEnd()) {
		m_sound(at.value());
		return true;
	}
	if (!m_sounds->dir.isValid())
		return false;
	const QString path =
	        m_sounds->dir.filePath(QStringLiteral("%1-%2").arg(QString::fromLatin1(pack.left(16))).arg((qulonglong)id));
	const QByteArray p = path.toUtf8();
	uint64_t bytes = 0;
	if (fzn_rpc_sticker_sound(&m_rpc->c, pack.constData(), (size_t)pack.size(), id, p.constData(), (size_t)p.size(),
	                          &bytes)
	    != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	m_sounds->at.insert(key, path);
	m_sound(path);
	return true;
}

bool fzn_sticker_picker_view::pick_found(int row)
{
	return pick_item(m_found->item(row));
}

void fzn_sticker_picker_view::set_find(const QString &text)
{
	const QByteArray typed = text.trimmed().toUtf8();
	auto *matched = new fzn_rpc_sticker_match_resp_t;
	size_t i;

	if (m_playing && m_playing->listWidget() == m_found)
		rest();
	m_found->clear();
	if (typed.isEmpty()) {
		m_found->hide();
		m_tabs->show();
		delete matched;
		return;
	}
	m_tabs->hide();
	m_found->show();
	memset(matched, 0, sizeof *matched);
	if (fzn_rpc_sticker_match(&m_rpc->c, typed.constData(), (size_t)typed.size(), matched) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		delete matched;
		return;
	}
	/* EACH FOUND AS ITS PACK'S TAB SHOWS IT -- drawn, its box -- so a
	 * search asks the node for no art; one in a pack not listed here yet is
	 * left until a refresh lists it. */
	for (i = 0; i < matched->count; i++) {
		char hex[65];

		fzn_hex_encode(matched->entries[i].root, 32, hex);
		const QByteArray pack(hex, 64);
		for (int t = 0; t < m_tabs->count(); t++) {
			auto *list = qobject_cast<QListWidget *>(m_tabs->widget(t));
			if (!list || list->property("pack").toByteArray() != pack)
				continue;
			for (int r = 0; r < list->count(); r++)
				if (list->item(r)->data(ROLE_ID).toULongLong() == (qulonglong)matched->entries[i].id)
					m_found->addItem(list->item(r)->clone());
		}
	}
	m_status->setText(m_found->count() ? QString() : tr("No sticker kept here fits that."));
	delete matched;
}

QStringList fzn_sticker_picker_view::found() const
{
	QStringList out;

	for (int r = 0; r < m_found->count(); r++)
		out << m_found->item(r)->text();
	return out;
}

bool fzn_sticker_picker_view::ask_words(int limit, QString *words)
{
	if (!m_words_row) {
		m_words_row = new QWidget(this);
		m_words_said = fzn_plain_label(m_words_row);
		m_words_said->setWordWrap(true);
		m_words_edit = new QLineEdit(m_words_row);
		m_words_edit->setAccessibleName(tr("What the sticker says"));
		m_words_send = new QPushButton(tr("Send"), m_words_row);
		m_words_cancel = new QPushButton(tr("Cancel"), m_words_row);
		auto *col = new QVBoxLayout(m_words_row);
		auto *row = new QHBoxLayout;
		row->addWidget(m_words_edit, 1);
		row->addWidget(m_words_send);
		row->addWidget(m_words_cancel);
		col->addWidget(m_words_said);
		col->addLayout(row);
		if (auto *box = qobject_cast<QBoxLayout *>(layout()))
			box->addWidget(m_words_row);
	}
	m_words_said->setText(tr("What it says, up to %n character(s)", nullptr, limit));
	m_words_edit->setMaxLength(limit);
	m_words_edit->clear();
	m_words_row->show();
	m_words_edit->setFocus();
	QEventLoop wait;
	int answer = 0;
	const QMetaObject::Connection sent = connect(m_words_send, &QPushButton::clicked, [&]() {
		answer = 1;
		wait.quit();
	});
	const QMetaObject::Connection entered = connect(m_words_edit, &QLineEdit::returnPressed, [&]() {
		answer = 1;
		wait.quit();
	});
	const QMetaObject::Connection cancelled = connect(m_words_cancel, &QPushButton::clicked, [&]() {
		answer = 0;
		wait.quit();
	});
	wait.exec();
	disconnect(sent);
	disconnect(entered);
	disconnect(cancelled);
	m_words_row->hide();
	if (answer)
		*words = m_words_edit->text();
	return answer != 0;
}

bool fzn_sticker_picker_view::pick_item(QListWidgetItem *item)
{
	char ref[FZN_STICKER_REF_SENT_MAX + 1];
	size_t ref_len = 0;

	if (!item || !m_pick)
		return false;
	QByteArray p = item->data(ROLE_PACK).toByteArray();
	const uint64_t id = (uint64_t)item->data(ROLE_ID).toULongLong();
	const int limit = item->data(ROLE_LIMIT).toInt();
	QString words;

	/* A MESSAGE OR NAME STICKER ASKS FOR ITS WORDS, sec 1296: the box holds
	 * what the sender writes, so a choice with none to ask is half a
	 * sticker. Cancelled, nothing is sent; left empty, it goes as drawn. */
	if (limit > 0) {
		bool ok = false;

		if (m_words)
			ok = m_words(item->data(ROLE_DESCRIPTION).toString(), limit, &words);
		else
			ok = ask_words(limit, &words);
		if (!ok)
			return false;
		words = words.trimmed().left(limit);
	}
	const QByteArray w = words.toUtf8();
	if ((w.isEmpty() ? fzn_rpc_sticker_reference(&m_rpc->c, p.constData(), (size_t)p.size(), id, ref, sizeof ref,
	                                             &ref_len)
	                 : fzn_rpc_sticker_reference_words(&m_rpc->c, p.constData(), (size_t)p.size(), id,
	                                                   w.constData(), (size_t)w.size(), ref, sizeof ref,
	                                                   &ref_len))
	    != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	m_pick(QString::fromUtf8(ref, (int)ref_len));
	return true;
}

bool fzn_sticker_picker_view::forget(int pack)
{
	QWidget *tab = pack_list(pack);
	const QByteArray hex = tab ? tab->property("pack").toByteArray() : QByteArray();
	const QString name = tab ? m_tabs->tabText(m_tabs->indexOf(tab)) : QString();
	uint8_t root[32];

	if (hex.size() != 64 || fzn_hex_decode(hex.constData(), root, sizeof root) != 0)
		return false;
	if (fzn_rpc_sticker_forget(&m_rpc->c, root) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	refresh();
	m_status->setText(tr("Let %1 go.").arg(name));
	return true;
}

bool fzn_sticker_picker_view::keep_files(const QStringList &paths)
{
	QStringList files = paths.isEmpty()
	                            ? QFileDialog::getOpenFileNames(this, tr("Add sticker packs"), QString(),
	                                                            tr("Sticker packs and their specs (*.fzs *.spec)"))
	                            : paths;
	QStringList why;
	int kept = 0;

	if (files.isEmpty())
		return false;
	for (const QString &f : files) {
		/* A PHONE'S PICKED PACK, staged for the node (sec 1532). */
		QTemporaryFile staged(fzn_staged_template("pack"));
		const QByteArray at = fzn_stage_in(f, staged).toUtf8();
		uint8_t root[32];
		int host_only = 0;
		if (at.isEmpty())
			why << tr("%1: it could not be read").arg(fzn_picked_name(f));
		else if (fzn_rpc_sticker_file_keep(&m_rpc->c, at.constData(), (size_t)at.size(), root, &host_only)
		         == FZN_RPC_OK)
			kept++;
		else
			why << QStringLiteral("%1: %2").arg(fzn_picked_name(f), failed_words(m_rpc));
	}
	refresh();
	QString words = tr("Kept %1 of %2.").arg(kept).arg(files.size());
	if (!why.isEmpty())
		words += QLatin1Char(' ') + why.join(QStringLiteral("; ")) + QLatin1Char('.');
	m_status->setText(words);
	return kept == files.size();
}

QStringList fzn_sticker_picker_view::shown() const
{
	QStringList out;
	for (int t = 0; t < m_tabs->count(); t++) {
		auto *list = qobject_cast<QListWidget *>(m_tabs->widget(t));
		if (list && list->property("recent").toBool())
			continue;
		out << m_tabs->tabText(t);
		for (int i = 0; list && i < list->count(); i++)
			out << QStringLiteral("  %1%2").arg(list->item(i)->text(),
			                                    list->item(i)->data(ROLE_DRAWN).toBool()
			                                            ? QStringLiteral(" [drawn]")
			                                            : QString());
	}
	return out;
}

QString fzn_sticker_picker_view::status() const { return m_status->text(); }
