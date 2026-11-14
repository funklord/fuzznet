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
	m_keep = new QPushButton(tr("Add sticker packs"), this);
	m_keep->setAccessibleName(tr("Keep sticker packs from files"));
	m_refresh = new QPushButton(tr("Refresh"), this);
	m_status = new QLabel(this);
	m_status->setWordWrap(true);

	auto *row = new QHBoxLayout;
	row->addWidget(m_keep);
	row->addWidget(m_refresh);
	row->addStretch(1);
	auto *col = new QVBoxLayout(this);
	col->addWidget(m_tabs, 1);
	col->addLayout(row);
	col->addWidget(m_status);

	connect(m_keep, &QPushButton::clicked, [this]() { keep_files(QStringList()); });
	connect(m_refresh, &QPushButton::clicked, [this]() { refresh(); });
	m_status->setText(tr("No sticker packs kept yet."));
}

fzn_sticker_picker_view::~fzn_sticker_picker_view() { delete m_rpc; }

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
			}
		}
		connect(list, &QListWidget::itemActivated, [this](QListWidgetItem *item) {
			QListWidget *l = item ? item->listWidget() : nullptr;
			if (l)
				pick(m_tabs->indexOf(l), l->row(item));
		});
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
	QListWidgetItem *item = list ? list->item(row) : nullptr;
	char ref[FZN_STICKER_REF_SENT_MAX + 1];
	size_t ref_len = 0;

	if (!item || !m_pick)
		return false;
	QByteArray p = item->data(ROLE_PACK).toByteArray();
	if (fzn_rpc_sticker_reference(&m_rpc->c, p.constData(), (size_t)p.size(),
	                              (uint64_t)item->data(ROLE_ID).toULongLong(), ref, sizeof ref, &ref_len)
	    != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	m_pick(QString::fromUtf8(ref, (int)ref_len));
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
