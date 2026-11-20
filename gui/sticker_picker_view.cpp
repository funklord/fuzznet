/* Choosing a sticker, and keeping packs: gui/sticker_picker_view.h, sec 1141. */
#include "sticker_picker_view.h"

#include "rpc_ask.h"
#include "sticker_render.h"

extern "C" {
#include "../hex/hex.h"
#include "../local/rpc_encoding.h"
#include "../sticker/pack.h"
}

#include <QByteArray>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QIcon>
#include <QInputDialog>
#include <QLineEdit>
#include <QMessageBox>
#include <QImage>
#include <QLabel>
#include <QListWidget>
#include <QPixmap>
#include <QPushButton>
#include <QTabWidget>
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
    : QWidget(parent), m_rpc(new fzn_gui_rpc)
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
	m_status = new QLabel(this);
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

	connect(m_keep, &QPushButton::clicked, [this]() { keep_files(QStringList()); });
	connect(m_refresh, &QPushButton::clicked, [this]() { refresh(); });
	connect(m_find, &QLineEdit::textChanged, [this](const QString &text) { set_find(text); });
	connect(m_found, &QListWidget::itemActivated, [this](QListWidgetItem *item) { pick_item(item); });
	connect(m_forget, &QPushButton::clicked, [this]() {
		const int at = m_tabs->currentIndex();

		if (at < 0)
			return;
		if (QMessageBox::question(this, tr("Let the pack go"),
		                          tr("Let %1 go from your stickers? You can keep it again from any message "
		                             "that carries one of its stickers.")
		                                  .arg(m_tabs->tabText(at)))
		    == QMessageBox::Yes)
			forget(at);
	});
	m_status->setText(tr("No sticker packs kept yet."));
}

fzn_sticker_picker_view::~fzn_sticker_picker_view() { delete m_rpc; }

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
					}
				}
				free(art);
				item->setData(ROLE_PACK, pack);
				item->setData(ROLE_ID, (qulonglong)s->id);
				item->setData(ROLE_DRAWN, drawn);
				item->setData(ROLE_LIMIT, (int)s->text_limit);
				item->setData(ROLE_DESCRIPTION, said(s->description, s->description_len));
			}
		}
		connect(list, &QListWidget::itemActivated, [this](QListWidgetItem *item) {
			QListWidget *l = item ? item->listWidget() : nullptr;
			if (l)
				pick(m_tabs->indexOf(l), l->row(item));
		});
		list->setProperty("pack", pack);
		m_tabs->addTab(list, said(packs.entries[p].name, packs.entries[p].name_len));
	}
	m_status->setText(packs.count ? QString() : tr("No sticker packs kept yet."));
	fzn_rpc_sticker_packs_release(&packs);
	delete items;
	return true;
}

bool fzn_sticker_picker_view::pick(int pack, int row)
{
	auto *list = qobject_cast<QListWidget *>(m_tabs->widget(pack));

	return pick_item(list ? list->item(row) : nullptr);
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
			words = QInputDialog::getText(this, tr("Words for the sticker"),
			                              tr("What it says, up to %n character(s)", nullptr, limit),
			                              QLineEdit::Normal, QString(), &ok);
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
	QWidget *tab = m_tabs->widget(pack);
	const QByteArray hex = tab ? tab->property("pack").toByteArray() : QByteArray();
	const QString name = tab ? m_tabs->tabText(pack) : QString();
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
	                                                            tr("Sticker packs (*.fzs)"))
	                            : paths;
	QStringList why;
	int kept = 0;

	if (files.isEmpty())
		return false;
	for (const QString &f : files) {
		QByteArray at = f.toUtf8();
		uint8_t root[32];
		int host_only = 0;
		if (fzn_rpc_sticker_file_keep(&m_rpc->c, at.constData(), (size_t)at.size(), root, &host_only)
		    == FZN_RPC_OK)
			kept++;
		else
			why << QStringLiteral("%1: %2").arg(f.section(QLatin1Char('/'), -1), failed_words(m_rpc));
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
		out << m_tabs->tabText(t);
		auto *list = qobject_cast<QListWidget *>(m_tabs->widget(t));
		for (int i = 0; list && i < list->count(); i++)
			out << QStringLiteral("  %1%2").arg(list->item(i)->text(),
			                                    list->item(i)->data(ROLE_DRAWN).toBool()
			                                            ? QStringLiteral(" [drawn]")
			                                            : QString());
	}
	return out;
}

QString fzn_sticker_picker_view::status() const { return m_status->text(); }
