/* The music this user's hosts hold, as a widget: gui/music_view.h, sec 1449. */
#include "music_view.h"
#include "choose_accessible.h"
#include "keep_place.h"

#include "rpc_ask.h"

extern "C" {
#include "../local/rpc_encoding.h"
}

#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMap>
#include <QPushButton>
#include <QTreeWidget>
#include <QVBoxLayout>

#include <algorithm>

#include <stdlib.h>
#include <string.h>

/* A TRACK'S ITEM carries its root, whether its bytes are here, and the words
 * a search reads; an album's carries none of them. */
#define ROLE_ROOT (Qt::UserRole)
#define ROLE_HERE (Qt::UserRole + 1)
#define ROLE_FIND (Qt::UserRole + 2)

static QString failed_words(const fzn_gui_rpc *r)
{
	return QString::fromUtf8(fzn_gui_rpc_silent(r));
}

static QString words(const char *text)
{
	char shown[4u * 256u + 1u];
	fzn_rpc_tty_escape(text, strlen(text), shown, sizeof shown);
	return QString::fromUtf8(shown);
}

static QString length_words(uint64_t ms)
{
	if (!ms)
		return QString();
	uint64_t s = ms / 1000u;
	return QStringLiteral("%1:%2").arg(s / 60u).arg(s % 60u, 2, 10, QLatin1Char('0'));
}

fzn_music_view::fzn_music_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent)
    : QWidget(parent), m_rpc(new fzn_gui_rpc)
{
	fzn_gui_rpc_init(m_rpc, ask, ask_ctx);

	m_find = new QLineEdit(this);
	m_find->setPlaceholderText(tr("Find music"));
	m_find->setAccessibleName(tr("Find music by a word of its title, artist, album or genre"));
	m_find->setClearButtonEnabled(true);
	fzn_name_clear_button(m_find);
	m_tree = new QTreeWidget(this);
	m_tree->setColumnCount(4);
	m_tree->setHeaderLabels({ tr("Title"), tr("Artist"), tr("Length"), tr("Where") });
	m_tree->header()->setStretchLastSection(true);
	m_tree->setSelectionMode(QAbstractItemView::SingleSelection);
	m_tree->setAccessibleName(tr("The music, by album"));
	m_play_button = new QPushButton(tr("Play"), this);
	m_fetch = new QPushButton(tr("Get it"), this);
	m_read = new QPushButton(tr("Read the tags"), this);
	m_read->setToolTip(tr("Read the title, artist and album each file says of itself"));
	m_refresh = new QPushButton(tr("Refresh"), this);
	m_status = new QLabel(this);
	m_status->setWordWrap(true);

	auto *row = new QHBoxLayout;
	row->addWidget(m_play_button);
	row->addWidget(m_fetch);
	row->addStretch(1);
	auto *more = new QHBoxLayout;
	more->addWidget(m_read);
	more->addWidget(m_refresh);
	more->addStretch(1);
	auto *col = new QVBoxLayout(this);
	col->addWidget(m_find);
	col->addWidget(m_tree, 1);
	col->addLayout(row);
	col->addLayout(more);
	col->addWidget(m_status);

	connect(m_tree, &QTreeWidget::currentItemChanged, [this](QTreeWidgetItem *, QTreeWidgetItem *) {
		QTreeWidgetItem *it = chosen();
		const bool track = it && it->parent();
		m_fetch->setEnabled(track && !it->data(0, ROLE_HERE).toBool());
		m_play_button->setEnabled(it && (track ? (bool)m_play : (bool)m_play_all));
	});
	/* A SCREEN READER CHOOSES TOO, sec 1423: its double tap only selects. */
	fzn_choose_on_accessible_select(m_tree, nullptr);
	connect(m_tree, &QTreeWidget::itemActivated, [this](QTreeWidgetItem *, int) { play(); });
	connect(m_play_button, &QPushButton::clicked, [this]() { play(); });
	connect(m_fetch, &QPushButton::clicked, [this]() { fetch(); });
	connect(m_read, &QPushButton::clicked, [this]() { read_tags(); });
	connect(m_refresh, &QPushButton::clicked, [this]() { refresh(); });
	connect(m_find, &QLineEdit::textChanged, [this](const QString &) { apply_filter(); });
	m_play_button->setEnabled(false);
	m_fetch->setEnabled(false);
}

fzn_music_view::~fzn_music_view() { delete m_rpc; }

void fzn_music_view::answer_binary(int (*answer)(void *ctx, const uint8_t *msg, size_t len, uint8_t *reply,
                                                 size_t reply_cap, size_t *reply_len),
                                   void *ctx)
{
	m_rpc->c.binary_answer = answer;
	m_rpc->c.binary_ctx = ctx;
}

void fzn_music_view::on_play(std::function<void(const QByteArray &, const QString &)> play)
{
	m_play = std::move(play);
}

void fzn_music_view::on_play_all(std::function<void(const QList<QPair<QByteArray, QString>> &)> play)
{
	m_play_all = std::move(play);
}

/* AN ALBUM'S KEY: its title and whom it is by, so two albums of one name by
 * two artists stay two. */
struct album_key {
	QString album, by;
	bool operator<(const album_key &o) const
	{
		const int a = QString::compare(by, o.by, Qt::CaseInsensitive);
		return a ? a < 0 : QString::compare(album, o.album, Qt::CaseInsensitive) < 0;
	}
};

bool fzn_music_view::refresh()
{
	fzn_rpc_music_list_t all;
	fzn_keep_answer answer(m_status);

	memset(&all, 0, sizeof all);
	if (fzn_rpc_music_list(&m_rpc->c, &all) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		fzn_keep_answer::said(m_status);
		fzn_rpc_music_list_release(&all);
		return m_rpc->c.answered;
	}
	/* BY ALBUM, then by disc and track, then by title. */
	QMap<album_key, QList<const fzn_rpc_music_entry_t *>> albums;
	QMap<album_key, uint16_t> years;
	for (size_t i = 0; i < all.count; i++) {
		const fzn_rpc_music_entry_t *e = &all.entries[i];
		const album_key k = { words(e->album), words(e->album_artist[0] ? e->album_artist : e->artist) };
		albums[k].append(e);
		if (e->year && (!years.value(k) || e->year < years.value(k)))
			years[k] = e->year;
	}
	const QByteArray kept = chosen() && chosen()->parent() ? chosen()->data(0, ROLE_ROOT).toByteArray() : QByteArray();
	m_tree->clear();
	QTreeWidgetItem *again = nullptr;
	for (auto a = albums.begin(); a != albums.end(); ++a) {
		QList<const fzn_rpc_music_entry_t *> &tracks = a.value();
		std::sort(tracks.begin(), tracks.end(), [](const fzn_rpc_music_entry_t *x, const fzn_rpc_music_entry_t *y) {
			if (x->disc != y->disc)
				return x->disc < y->disc;
			if (x->track != y->track)
				return x->track < y->track;
			return strcmp(x->title[0] ? x->title : x->name, y->title[0] ? y->title : y->name) < 0;
		});
		auto *album = new QTreeWidgetItem(m_tree);
		album->setText(0, a.key().album.isEmpty() ? tr("No album") : a.key().album);
		album->setText(1, a.key().by.isEmpty() ? tr("Unknown artist") : a.key().by);
		album->setText(2, years.value(a.key()) ? QString::number(years.value(a.key())) : QString());
		for (const fzn_rpc_music_entry_t *e : tracks) {
			auto *t = new QTreeWidgetItem(album);
			const QString title = words(e->title[0] ? e->title : e->name);
			const QString artist = words(e->artist);
			const unsigned others = e->holders - (e->held_here && e->holders ? 1u : 0u);
			t->setText(0, e->track ? QStringLiteral("%1. %2").arg(e->track).arg(title) : title);
			/* THE ARTIST WHERE IT IS NOT THE ALBUM'S: a compilation's tracks
			 * say whose each is, an album by one artist does not repeat it. */
			t->setText(1, artist == a.key().by ? QString() : artist);
			t->setText(2, length_words(e->duration_ms));
			t->setText(3, e->held_here ? (others ? tr("here, and on %1 other host(s)").arg(others) : tr("here"))
			              : others   ? tr("on %1 host(s)").arg(others)
			                         : tr("nowhere seen"));
			t->setData(0, ROLE_ROOT, QByteArray((const char *)e->root, 32));
			t->setData(0, ROLE_HERE, (bool)e->held_here);
			t->setData(0, ROLE_FIND, QStringList({ title, artist, a.key().album, a.key().by, words(e->genre) })
			                                 .join(QLatin1Char('\n')));
			t->setData(0, Qt::AccessibleTextRole, tr("%1, by %2").arg(title, artist.isEmpty() ? a.key().by : artist));
			if (!kept.isEmpty() && t->data(0, ROLE_ROOT).toByteArray() == kept)
				again = t;
		}
	}
	m_tree->expandAll();
	m_status->setText(all.count ? tr("%n piece(s) of music.", nullptr, (int)all.count)
	                            : tr("No music is catalogued yet. \"Read the tags\" reads what files say of "
	                                 "themselves."));
	fzn_rpc_music_list_release(&all);
	m_filter_said.clear();
	if (again)
		m_tree->setCurrentItem(again);
	apply_filter();
	answer.restore();
	return true;
}

/* EACH TRACK SHOWN OR HIDDEN by a word it holds, and each album with the
 * tracks it shows; and said. */
void fzn_music_view::apply_filter()
{
	const QString text = m_find->text().trimmed();
	int shown_tracks = 0, every = 0;

	for (int a = 0; a < m_tree->topLevelItemCount(); a++) {
		QTreeWidgetItem *album = m_tree->topLevelItem(a);
		int left = 0;

		for (int t = 0; t < album->childCount(); t++) {
			QTreeWidgetItem *track = album->child(t);
			const bool show = text.isEmpty() || track->data(0, ROLE_FIND).toString().contains(text, Qt::CaseInsensitive);

			track->setHidden(!show);
			left += show;
			every++;
		}
		album->setHidden(!left);
		shown_tracks += left;
	}
	/* A TRACK CHOSEN AND NOW HIDDEN is not acted on unseen. */
	if (chosen() && chosen()->isHidden())
		m_tree->setCurrentItem(nullptr);
	if (text.isEmpty()) {
		if (!m_filter_said.isEmpty() && m_status->text() == m_filter_said)
			m_status->clear();
		m_filter_said.clear();
		return;
	}
	m_filter_said = shown_tracks ? tr("%1 of %2 shown.").arg(shown_tracks).arg(every) : tr("No music matches.");
	m_status->setText(m_filter_said);
}

void fzn_music_view::set_find(const QString &text) { m_find->setText(text); }

QTreeWidgetItem *fzn_music_view::chosen() const { return m_tree->currentItem(); }

QList<QTreeWidgetItem *> fzn_music_view::shown() const
{
	QList<QTreeWidgetItem *> out;
	for (int a = 0; a < m_tree->topLevelItemCount(); a++) {
		QTreeWidgetItem *album = m_tree->topLevelItem(a);
		if (album->isHidden())
			continue;
		out << album;
		for (int t = 0; t < album->childCount(); t++)
			if (!album->child(t)->isHidden())
				out << album->child(t);
	}
	return out;
}

void fzn_music_view::select(int row)
{
	const QList<QTreeWidgetItem *> rows = shown();
	m_tree->setCurrentItem(row >= 0 && row < rows.size() ? rows[row] : nullptr);
}

bool fzn_music_view::play()
{
	QTreeWidgetItem *it = chosen();
	if (!it || it->isHidden())
		return false;
	if (it->parent()) {
		if (!m_play)
			return false;
		m_play(it->data(0, ROLE_ROOT).toByteArray(), it->data(0, Qt::AccessibleTextRole).toString());
		return true;
	}
	/* AN ALBUM, its tracks shown in their order. */
	if (!m_play_all)
		return false;
	QList<QPair<QByteArray, QString>> tracks;
	for (int t = 0; t < it->childCount(); t++)
		if (!it->child(t)->isHidden())
			tracks.append({ it->child(t)->data(0, ROLE_ROOT).toByteArray(),
			                it->child(t)->data(0, Qt::AccessibleTextRole).toString() });
	if (tracks.isEmpty())
		return false;
	m_play_all(tracks);
	return true;
}

bool fzn_music_view::fetch()
{
	QTreeWidgetItem *it = chosen();
	if (!it || !it->parent() || it->isHidden() || it->data(0, ROLE_HERE).toBool())
		return false;
	const QByteArray root = it->data(0, ROLE_ROOT).toByteArray();
	fzn_rpc_blob_fetch_resp_t out;
	if (fzn_rpc_blob_fetch(&m_rpc->c, (const uint8_t *)root.constData(), &out) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	m_status->setText(tr("Getting it from another host."));
	return true;
}

int fzn_music_view::read_tags()
{
	uint32_t from = 0, next = 0, total = 0, asserted = 0, learned = 0;
	int pages = 0;

	/* A PAGE AT A TIME until the last, bounded in case a node keeps saying
	 * there is more without moving. */
	do {
		if (fzn_rpc_library_read_tags(&m_rpc->c, from, &next, &total, &asserted) != FZN_RPC_OK) {
			m_status->setText(failed_words(m_rpc));
			return -1;
		}
		learned += asserted;
		if (next <= from)
			break;
		from = next;
	} while (from < total && ++pages < 100000);
	refresh();
	m_status->setText(learned ? tr("Read %1 file(s); %2 name(s) learned.").arg(total).arg(learned)
	                          : tr("Read %1 file(s); nothing new.").arg(total));
	return (int)learned;
}

QStringList fzn_music_view::rows() const
{
	QStringList out;
	for (QTreeWidgetItem *it : shown())
		out << (it->parent() ? QStringLiteral("  ") : QString())
		                + QStringList({ it->text(0), it->text(1), it->text(2), it->text(3) }).join(QStringLiteral(" | "));
	return out;
}

QString fzn_music_view::status() const { return m_status->text(); }
