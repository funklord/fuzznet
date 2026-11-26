/* The music this user's hosts hold, as a widget: gui/music_view.h, secs 1449, 1458. */
#include "music_view.h"
#include "choose_accessible.h"
#include "combo.h"
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
#include <QRegularExpression>
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
#define ROLE_BPM (Qt::UserRole + 3)   /* the tempo heard, 0 for none */
#define ROLE_PLACE (Qt::UserRole + 4) /* the key's place on the wheel, "8A", or empty */
#define ROLE_VIDEO (Qt::UserRole + 5) /* its music video's root, sec 1472, or empty */

/* WHAT A PERSON TYPES TO FIND MUSIC, sec 1467: words, each of which a
 * track must hold -- a word of its title, artist, album or genre, its key
 * or its rounded tempo -- and two that are not words. A TEMPO, "128 bpm"
 * or "120-130 bpm" (the unit glued on or not, the bounds either way
 * round), holds a track heard at it, rounded as the column shows it; a
 * KEY'S PLACE on the Camelot wheel, "8A", holds a track in that key alone,
 * not one whose title merely contains the letters. */
struct music_term {
	enum { WORD, TEMPO, PLACE } kind;
	QString word;
	double lo, hi;
};

static bool tempo_of(const QString &t, double *lo, double *hi)
{
	const QStringList ends = t.split(QLatin1Char('-'));
	bool a = false, b = false;

	if (ends.size() == 1) {
		*lo = *hi = ends[0].toDouble(&a);
		return a && *lo > 0;
	}
	if (ends.size() != 2)
		return false;
	*lo = ends[0].toDouble(&a);
	*hi = ends[1].toDouble(&b);
	if (*lo > *hi)
		std::swap(*lo, *hi);
	return a && b && *lo > 0;
}

static QList<music_term> music_terms(const QString &text)
{
	static const QRegularExpression place(QStringLiteral("^(1[0-2]|[1-9])[AB]$"),
	                                      QRegularExpression::CaseInsensitiveOption);
	const QStringList w = text.split(QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);
	QList<music_term> out;

	for (int i = 0; i < w.size(); i++) {
		music_term t{ music_term::WORD, w[i], 0, 0 };
		const bool glued = w[i].size() > 3 && w[i].endsWith(QLatin1String("bpm"), Qt::CaseInsensitive);
		const bool apart = i + 1 < w.size() && !w[i + 1].compare(QLatin1String("bpm"), Qt::CaseInsensitive);

		if ((glued || apart) && tempo_of(glued ? w[i].chopped(3) : w[i], &t.lo, &t.hi)) {
			t.kind = music_term::TEMPO;
			i += apart && !glued;
		} else if (place.match(w[i]).hasMatch()) {
			t.kind = music_term::PLACE;
			t.word = w[i].toUpper();
		}
		out.append(t);
	}
	return out;
}

static bool holds(const QTreeWidgetItem *track, const QList<music_term> &terms)
{
	for (const music_term &t : terms) {
		const double bpm = track->data(0, ROLE_BPM).toDouble();

		switch (t.kind) {
		case music_term::TEMPO:
			if (!(bpm > 0 && bpm >= t.lo - 0.5 && bpm < t.hi + 0.5))
				return false;
			break;
		case music_term::PLACE:
			if (track->data(0, ROLE_PLACE).toString() != t.word)
				return false;
			break;
		case music_term::WORD:
			if (!track->data(0, ROLE_FIND).toString().contains(t.word, Qt::CaseInsensitive))
				return false;
			break;
		}
	}
	return true;
}

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

/* A KEY'S PLACE ON THE WHEEL, from its name as the host asserts it ("8A
 * Am"): its Camelot number, A before B; none last. */
static int key_order(const char *key)
{
	int number = 0, i = 0;

	while (i < 2 && key[i] >= '0' && key[i] <= '9')
		number = number * 10 + (key[i++] - '0');
	if (!i || number < 1 || number > 12 || (key[i] != 'A' && key[i] != 'B'))
		return 1000;
	return number * 2 + (key[i] == 'B');
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
	m_find->setAccessibleName(tr("Find music by words of its title, artist, album or genre, a tempo such as 120-130 bpm, or a key "
	                             "such as 8A"));
	m_find->setClearButtonEnabled(true);
	fzn_name_clear_button(m_find);
	m_order = new fzn_combo_box(this);
	m_order->setAccessibleName(tr("Order the music"));
	m_order->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
	m_order->setMinimumContentsLength(8);
	m_order->addItem(tr("By album"));
	m_order->addItem(tr("By tempo"));
	m_order->addItem(tr("By key"));
	m_order->addItem(tr("By artist"));
	m_tree = new QTreeWidget(this);
	m_tree->setColumnCount(7);
	m_tree->setHeaderLabels(
	        { tr("Title"), tr("Artist"), tr("Length"), tr("BPM"), tr("Key"), tr("Where"), tr("With") });
	m_tree->header()->setStretchLastSection(true);
	m_tree->setSelectionMode(QAbstractItemView::SingleSelection);
	m_tree->setAccessibleName(tr("The music, by album"));
	m_play_button = new QPushButton(tr("Play"), this);
	m_fetch = new QPushButton(tr("Get it"), this);
	/* ITS MUSIC VIDEO, sec 1472: a file of its own, played as a track is,
	 * by the host's player -- fetched or streamed by root like any. */
	m_video = new QPushButton(tr("Video"), this);
	m_video->setToolTip(tr("Play the music video that goes with this track"));
	m_read = new QPushButton(tr("Read the tags"), this);
	m_read->setToolTip(tr("Read the title, artist and album each file says of itself"));
	m_hear = new QPushButton(tr("Hear the music"), this);
	m_hear->setToolTip(tr("Have each host hear the tunes it holds for their tempo and key"));
	m_refresh = new QPushButton(tr("Refresh"), this);
	m_status = new QLabel(this);
	m_status->setWordWrap(true);

	auto *row = new QHBoxLayout;
	row->addWidget(m_play_button);
	row->addWidget(m_fetch);
	row->addWidget(m_video);
	row->addStretch(1);
	auto *more = new QHBoxLayout;
	more->addWidget(m_read);
	more->addWidget(m_hear);
	more->addWidget(m_refresh);
	more->addStretch(1);
	auto *top = new QHBoxLayout;
	top->addWidget(m_find, 1);
	top->addWidget(m_order);
	auto *col = new QVBoxLayout(this);
	col->addLayout(top);
	col->addWidget(m_tree, 1);
	col->addLayout(row);
	col->addLayout(more);
	col->addWidget(m_status);

	connect(m_tree, &QTreeWidget::currentItemChanged, [this](QTreeWidgetItem *, QTreeWidgetItem *) {
		QTreeWidgetItem *it = chosen();
		const bool track = it && it->parent();
		m_fetch->setEnabled(track && !it->data(0, ROLE_HERE).toBool());
		m_play_button->setEnabled(it && (track ? (bool)m_play : (bool)m_play_all));
		m_video->setEnabled(track && m_play && !it->data(0, ROLE_VIDEO).toByteArray().isEmpty());
	});
	/* A SCREEN READER CHOOSES TOO, sec 1423: its double tap only selects. */
	fzn_choose_on_accessible_select(m_tree, nullptr);
	connect(m_tree, &QTreeWidget::itemActivated, [this](QTreeWidgetItem *, int) { play(); });
	connect(m_play_button, &QPushButton::clicked, [this]() { play(); });
	connect(m_fetch, &QPushButton::clicked, [this]() { fetch(); });
	connect(m_video, &QPushButton::clicked, [this]() { play_video(); });
	connect(m_read, &QPushButton::clicked, [this]() { read_tags(); });
	connect(m_hear, &QPushButton::clicked, [this]() { hear(); });
	connect(m_order, QOverload<int>::of(&QComboBox::currentIndexChanged), [this](int) { rebuild(); });
	connect(m_refresh, &QPushButton::clicked, [this]() { refresh(); });
	connect(m_find, &QLineEdit::textChanged, [this](const QString &) { apply_filter(); });
	m_play_button->setEnabled(false);
	m_fetch->setEnabled(false);
	m_video->setEnabled(false);
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
	m_music.clear();
	for (size_t i = 0; i < all.count; i++)
		m_music.append(all.entries[i]);
	fzn_rpc_music_list_release(&all);
	rebuild();
	answer.restore();
	return true;
}

void fzn_music_view::set_order(order o) { m_order->setCurrentIndex((int)o); }

/* THE TREE FROM THE MUSIC LAST LISTED, in the order chosen: groups, each
 * with its tracks. An album's tracks by disc and track; a tempo's slowest
 * first; a key's and an artist's by album, then disc and track. */
void fzn_music_view::rebuild()
{
	const order o = (order)m_order->currentIndex();
	/* A GROUP'S KEY: what it sorts by, then what it shows -- two albums of
	 * one name by two artists stay two. */
	struct group {
		int rank;
		QString title, by;
		bool operator<(const group &g) const
		{
			if (rank != g.rank)
				return rank < g.rank;
			const int a = QString::compare(by, g.by, Qt::CaseInsensitive);
			return a ? a < 0 : QString::compare(title, g.title, Qt::CaseInsensitive) < 0;
		}
	};
	QMap<group, QList<const fzn_rpc_music_entry_t *>> groups;
	QMap<group, uint16_t> years;
	for (const fzn_rpc_music_entry_t &m : m_music) {
		const fzn_rpc_music_entry_t *e = &m;
		const QString by = words(e->album_artist[0] ? e->album_artist : e->artist);
		group g = { 0, words(e->album), by };
		if (o == BY_TEMPO) {
			const int bpm = (int)(atof(e->bpm) + 0.5);
			g = { bpm > 0 ? bpm : 100000, bpm > 0 ? tr("%1 BPM").arg(bpm) : tr("Tempo not heard"), QString() };
		} else if (o == BY_KEY) {
			g = { key_order(e->key), e->key[0] ? words(e->key) : tr("Key not heard"), QString() };
		} else if (o == BY_ARTIST) {
			g = { e->artist[0] ? 0 : 1, e->artist[0] ? words(e->artist) : tr("Unknown artist"), QString() };
		}
		groups[g].append(e);
		if (o == BY_ALBUM && e->year && (!years.value(g) || e->year < years.value(g)))
			years[g] = e->year;
	}
	const QByteArray kept = chosen() && chosen()->parent() ? chosen()->data(0, ROLE_ROOT).toByteArray() : QByteArray();
	/* A CHOSEN GROUP KEPT TOO, by what it says -- an album and whom it is
	 * by, or a tempo, key or artist -- as a track is kept by its root: a
	 * host refreshing every two seconds took an album's Play away before
	 * the tap arrived (fuzzypickles, inbox 20261126T2117Z, sec 1487). */
	const QString kept_group = chosen() && !chosen()->parent()
	                                   ? chosen()->text(0) + QLatin1Char('\x1f') + chosen()->text(1)
	                                   : QString();
	m_tree->clear();
	QTreeWidgetItem *again = nullptr;
	for (auto a = groups.begin(); a != groups.end(); ++a) {
		QList<const fzn_rpc_music_entry_t *> &tracks = a.value();
		std::sort(tracks.begin(), tracks.end(), [o](const fzn_rpc_music_entry_t *x, const fzn_rpc_music_entry_t *y) {
			if (o == BY_TEMPO && atof(x->bpm) != atof(y->bpm))
				return atof(x->bpm) < atof(y->bpm);
			if (o != BY_ALBUM) {
				const int c = strcmp(x->album, y->album);
				if (c)
					return c < 0;
			}
			if (x->disc != y->disc)
				return x->disc < y->disc;
			if (x->track != y->track)
				return x->track < y->track;
			return strcmp(x->title[0] ? x->title : x->name, y->title[0] ? y->title : y->name) < 0;
		});
		auto *head = new QTreeWidgetItem(m_tree);
		if (o == BY_ALBUM) {
			head->setText(0, a.key().title.isEmpty() ? tr("No album") : a.key().title);
			head->setText(1, a.key().by.isEmpty() ? tr("Unknown artist") : a.key().by);
			head->setText(2, years.value(a.key()) ? QString::number(years.value(a.key())) : QString());
		} else {
			head->setText(0, a.key().title);
		}
		if (!kept_group.isEmpty() && !again && head->text(0) + QLatin1Char('\x1f') + head->text(1) == kept_group)
			again = head;
		for (const fzn_rpc_music_entry_t *e : tracks) {
			auto *t = new QTreeWidgetItem(head);
			const QString title = words(e->title[0] ? e->title : e->name);
			const QString artist = words(e->artist);
			const QString by = words(e->album_artist[0] ? e->album_artist : e->artist);
			const unsigned others = e->holders - (e->held_here && e->holders ? 1u : 0u);
			const double bpm = atof(e->bpm);
			t->setText(0, e->track && o == BY_ALBUM ? QStringLiteral("%1. %2").arg(e->track).arg(title) : title);
			/* THE ARTIST WHERE THE GROUP DOES NOT SAY IT: a compilation's
			 * tracks say whose each is, an album by one artist does not
			 * repeat it, and an artist's group says it once. */
			t->setText(1, (o == BY_ALBUM && artist == by) || o == BY_ARTIST ? QString() : artist);
			t->setText(2, length_words(e->duration_ms));
			t->setText(3, bpm > 0 ? QString::number(bpm, 'f', bpm == (int)bpm ? 0 : 1) : QString());
			t->setText(4, words(e->key));
			t->setText(5, e->held_here ? (others ? tr("here, and on %1 other host(s)").arg(others) : tr("here"))
			              : others   ? tr("on %1 host(s)").arg(others)
			                         : tr("nowhere seen"));
			t->setData(0, ROLE_ROOT, QByteArray((const char *)e->root, 32));
			t->setData(0, ROLE_HERE, (bool)e->held_here);
			t->setData(0, ROLE_FIND, QStringList({ title, artist, words(e->album), by, words(e->genre), words(e->key),
			                                       bpm > 0 ? QString::number((int)(bpm + 0.5)) : QString() })
			                                 .join(QLatin1Char('\n')));
			/* WHAT GOES WITH IT, sec 1472: each a file of its own. */
			{
				QStringList with;
				if (e->has_video)
					with << tr("video");
				if (e->has_lyrics)
					with << tr("lyrics");
				if (e->has_tracklist)
					with << tr("tracklist");
				if (e->has_beatmap)
					with << tr("beatmap");
				t->setText(6, with.join(QStringLiteral(", ")));
				if (e->has_video)
					t->setData(0, ROLE_VIDEO, QByteArray((const char *)e->video, 32));
			}
			t->setData(0, ROLE_BPM, bpm);
			t->setData(0, ROLE_PLACE, words(e->key).section(QLatin1Char(' '), 0, 0).toUpper());
			t->setData(0, Qt::AccessibleTextRole, tr("%1, by %2").arg(title, artist.isEmpty() ? by : artist));
			if (!kept.isEmpty() && t->data(0, ROLE_ROOT).toByteArray() == kept)
				again = t;
		}
	}
	m_tree->expandAll();
	m_status->setText(m_music.size() ? tr("%n piece(s) of music.", nullptr, (int)m_music.size())
	                                 : tr("No music is catalogued yet. \"Read the tags\" reads what files say of "
	                                      "themselves."));
	m_filter_said.clear();
	if (again)
		m_tree->setCurrentItem(again);
	apply_filter();
}

/* EACH TRACK SHOWN OR HIDDEN by a word it holds, and each album with the
 * tracks it shows; and said. */
void fzn_music_view::apply_filter()
{
	const QString text = m_find->text().trimmed();
	const QList<music_term> terms = music_terms(text);
	int shown_tracks = 0, every = 0;

	for (int a = 0; a < m_tree->topLevelItemCount(); a++) {
		QTreeWidgetItem *album = m_tree->topLevelItem(a);
		int left = 0;

		for (int t = 0; t < album->childCount(); t++) {
			QTreeWidgetItem *track = album->child(t);
			const bool show = holds(track, terms);

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

bool fzn_music_view::play_video()
{
	QTreeWidgetItem *it = chosen();
	const QByteArray video = it && it->parent() && !it->isHidden() ? it->data(0, ROLE_VIDEO).toByteArray() : QByteArray();
	if (video.isEmpty() || !m_play)
		return false;
	m_play(video, tr("%1 (video)").arg(it->data(0, Qt::AccessibleTextRole).toString()));
	return true;
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

int fzn_music_view::hear()
{
	uint32_t from = 0, next = 0, total = 0, queued = 0, waiting = 0;
	int pages = 0;

	/* A PAGE AT A TIME until the last, bounded as read_tags is. */
	do {
		if (fzn_rpc_library_hear(&m_rpc->c, from, &next, &total, &queued, &waiting) != FZN_RPC_OK) {
			m_status->setText(failed_words(m_rpc));
			return -1;
		}
		if (next <= from)
			break;
		from = next;
	} while (from < total && ++pages < 100000);
	m_status->setText(waiting ? tr("%1 tune(s) to be heard; their tempo and key show as each is.").arg(waiting)
	                          : tr("Every tune held here has been heard."));
	return (int)waiting;
}

QStringList fzn_music_view::rows() const
{
	QStringList out;
	for (QTreeWidgetItem *it : shown()) {
		QStringList cells;
		for (int c = 0; c < 6; c++)
			cells << it->text(c);
		if (!it->text(6).isEmpty())
			cells << it->text(6);
		out << (it->parent() ? QStringLiteral("  ") : QString()) + cells.join(QStringLiteral(" | "));
	}
	return out;
}

QString fzn_music_view::status() const { return m_status->text(); }
