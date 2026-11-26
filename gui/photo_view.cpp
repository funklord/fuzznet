/* The photographs this user's hosts hold, as a widget: gui/photo_view.h,
 * secs 1450, 1460. */
#include "photo_view.h"
#include "choose_accessible.h"
#include "keep_place.h"
#include "size_words.h"

#include "rpc_ask.h"

extern "C" {
#include "../media/tags.h"
}

extern "C" {
#include "../local/rpc_encoding.h"
}

#include <QBuffer>
#include <QDate>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QIcon>
#include <QImageReader>
#include <QLabel>
#include <QLineEdit>
#include <QLocale>
#include <QMap>
#include <QPixmap>
#include <QPushButton>
#include <QTimer>
#include <QTransform>
#include <QTreeWidget>
#include <QVBoxLayout>

#include <algorithm>

#include <stdlib.h>
#include <string.h>

#define ROLE_ROOT (Qt::UserRole)
#define ROLE_HERE (Qt::UserRole + 1)
#define ROLE_FIND (Qt::UserRole + 2)
#define ROLE_TURN (Qt::UserRole + 3)
#define ROLE_VIDEO (Qt::UserRole + 4)

/* A THUMBNAIL is read from this much of a photograph's start: EXIF's APP1,
 * which holds it, is at most 64 KiB. */
#define THUMB_HEAD (64u * 1024u)
#define THUMB_SIDE 48

/* THE MOST A PHOTOGRAPH SHOWN MAY BE: its bytes read whole, a camera's
 * largest raw JPEG well within it; and its canvas as its header says it,
 * so a small file naming an enormous one is not decoded (sec 1446's lesson). */
#define PHOTO_BYTES_MAX (64u * 1024u * 1024u)
#define PHOTO_SIDE_MAX 20000
/* The preview's side. */
#define PREVIEW_SIDE 300

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

/* A PLACE as people read one: "33.8650 degrees S, 20.2250 degrees E", the
 * hemisphere a letter in place of a sign. */
static QString place_words(int32_t lat_e7, int32_t lon_e7)
{
	const double lat = lat_e7 / 1e7, lon = lon_e7 / 1e7;
	return QStringLiteral("%1° %2, %3° %4")
	        .arg(qAbs(lat), 0, 'f', 4)
	        .arg(lat < 0 ? QLatin1Char('S') : QLatin1Char('N'))
	        .arg(qAbs(lon), 0, 'f', 4)
	        .arg(lon < 0 ? QLatin1Char('W') : QLatin1Char('E'));
}

fzn_photo_view::fzn_photo_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent)
    : QWidget(parent), m_rpc(new fzn_gui_rpc)
{
	fzn_gui_rpc_init(m_rpc, ask, ask_ctx);

	m_find = new QLineEdit(this);
	m_find->setPlaceholderText(tr("Find a photograph"));
	m_find->setAccessibleName(tr("Find a photograph by its camera, its time or its name"));
	m_find->setClearButtonEnabled(true);
	fzn_name_clear_button(m_find);
	m_tree = new QTreeWidget(this);
	m_tree->setColumnCount(5);
	m_tree->setHeaderLabels({ tr("Taken"), tr("Camera"), tr("Size"), tr("Place"), tr("Where") });
	m_tree->header()->setStretchLastSection(true);
	m_tree->setSelectionMode(QAbstractItemView::SingleSelection);
	m_tree->setAccessibleName(tr("The photographs, by month taken"));
	m_picture = new QLabel(this);
	m_picture->setAlignment(Qt::AlignCenter);
	m_picture->setMinimumHeight(120);
	m_picture->setAccessibleName(tr("The photograph chosen"));
	m_fetch = new QPushButton(tr("Get it"), this);
	m_play_button = new QPushButton(tr("Play"), this);
	m_play_button->setToolTip(tr("Play the video chosen"));
	m_refresh = new QPushButton(tr("Refresh"), this);
	m_status = new QLabel(this);
	m_status->setWordWrap(true);

	auto *row = new QHBoxLayout;
	row->addWidget(m_play_button);
	row->addWidget(m_fetch);
	row->addWidget(m_refresh);
	row->addStretch(1);
	auto *col = new QVBoxLayout(this);
	col->addWidget(m_find);
	col->addWidget(m_tree, 2);
	col->addWidget(m_picture, 1);
	col->addLayout(row);
	col->addWidget(m_status);

	connect(m_tree, &QTreeWidget::currentItemChanged,
	        [this](QTreeWidgetItem *, QTreeWidgetItem *) { show_chosen(); });
	fzn_choose_on_accessible_select(m_tree, nullptr);
	connect(m_fetch, &QPushButton::clicked, [this]() { fetch(); });
	connect(m_play_button, &QPushButton::clicked, [this]() { play(); });
	connect(m_tree, &QTreeWidget::itemActivated, [this](QTreeWidgetItem *, int) { play(); });
	connect(m_refresh, &QPushButton::clicked, [this]() { refresh(); });
	connect(m_find, &QLineEdit::textChanged, [this](const QString &) { apply_filter(); });
	m_fetch->setEnabled(false);
	m_play_button->setEnabled(false);
	m_tree->setIconSize(QSize(THUMB_SIDE, THUMB_SIDE));
	m_thumb_timer = new QTimer(this);
	m_thumb_timer->setInterval(30);
	connect(m_thumb_timer, &QTimer::timeout, [this]() {
		if (!read_thumbnails(1))
			m_thumb_timer->stop();
	});
}

fzn_photo_view::~fzn_photo_view() { delete m_rpc; }

void fzn_photo_view::on_play(std::function<void(const QByteArray &, const QString &)> play)
{
	m_play = std::move(play);
}

/* A VIDEO'S LENGTH as a clock reads it. */
static QString length_words(uint64_t ms)
{
	const uint64_t s = ms / 1000u;
	return QStringLiteral("%1:%2").arg(s / 60u).arg(s % 60u, 2, 10, QLatin1Char('0'));
}

void fzn_photo_view::answer_binary(int (*answer)(void *ctx, const uint8_t *msg, size_t len, uint8_t *reply,
                                                 size_t reply_cap, size_t *reply_len),
                                   void *ctx)
{
	m_rpc->c.binary_answer = answer;
	m_rpc->c.binary_ctx = ctx;
}

bool fzn_photo_view::refresh()
{
	fzn_rpc_photo_list_t all;
	fzn_keep_answer answer(m_status);

	memset(&all, 0, sizeof all);
	if (fzn_rpc_photo_list(&m_rpc->c, &all) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		fzn_keep_answer::said(m_status);
		fzn_rpc_photo_list_release(&all);
		return m_rpc->c.answered;
	}
	/* BY MONTH, newest first; the photographs of no time said last. */
	QList<const fzn_rpc_photo_entry_t *> order;
	for (size_t i = 0; i < all.count; i++)
		order << &all.entries[i];
	std::sort(order.begin(), order.end(), [](const fzn_rpc_photo_entry_t *a, const fzn_rpc_photo_entry_t *b) {
		if (!a->taken[0] != !b->taken[0])
			return a->taken[0] != 0;
		const int c = strcmp(a->taken, b->taken);
		return c ? c > 0 : memcmp(a->root, b->root, 32) < 0;
	});
	const QByteArray kept = chosen() && chosen()->parent() ? chosen()->data(0, ROLE_ROOT).toByteArray() : QByteArray();
	m_tree->clear();
	m_thumbs_wanted.clear();
	QTreeWidgetItem *month = nullptr, *again = nullptr;
	QString month_key;
	size_t videos = 0;
	for (const fzn_rpc_photo_entry_t *e : order) {
		const QString taken = QString::fromLatin1(e->taken);
		const QString key = taken.left(7);
		if (!month || key != month_key) {
			month = new QTreeWidgetItem(m_tree);
			month_key = key;
			const QDate d = QDate::fromString(key + QStringLiteral("-01"), QStringLiteral("yyyy-MM-dd"));
			month->setText(0, d.isValid() ? QLocale().toString(d, QStringLiteral("MMMM yyyy")) : tr("When unknown"));
		}
		auto *p = new QTreeWidgetItem(month);
		const unsigned others = e->holders - (e->held_here && e->holders ? 1u : 0u);
		/* "2023-07-14T21:45:30" said as "2023-07-14 21:45". */
		p->setText(0, taken.isEmpty() ? words(e->name) : taken.left(10) + QLatin1Char(' ') + taken.mid(11, 5));
		p->setText(1, words(e->camera));
		const QString size = e->width && e->height ? QStringLiteral("%1 × %2").arg(e->width).arg(e->height) : QString();
		if (e->video) {
			const QString length = e->duration_ms ? length_words(e->duration_ms) : QString();
			const QString both = size.isEmpty() || length.isEmpty() ? size + length : size + QStringLiteral(", ") + length;
			p->setText(2, both.isEmpty() ? tr("video") : tr("%1 video").arg(both));
		} else {
			p->setText(2, size);
		}
		p->setText(3, e->place ? place_words(e->latitude_e7, e->longitude_e7) : QString());
		p->setText(4, e->held_here ? (others ? tr("here, and on %1 other host(s)").arg(others) : tr("here"))
		              : others   ? tr("on %1 host(s)").arg(others)
		                         : tr("nowhere seen"));
		p->setData(0, ROLE_ROOT, QByteArray((const char *)e->root, 32));
		p->setData(0, ROLE_HERE, (bool)e->held_here);
		p->setData(0, ROLE_TURN, (int)e->orientation);
		p->setData(0, ROLE_VIDEO, (bool)e->video);
		videos += e->video ? 1u : 0u;
		/* A VIDEO HAS NO CAMERA'S THUMBNAIL: EXIF's is a photograph's. */
		if (e->held_here && !e->video)
			m_thumbs_wanted << p->data(0, ROLE_ROOT).toByteArray();
		p->setData(0, ROLE_FIND, QStringList({ p->text(0), p->text(1), words(e->name), month->text(0) }).join(QLatin1Char('\n')));
		p->setData(0, Qt::AccessibleTextRole, (e->video ? tr("A video, %1") : tr("A photograph, %1"))
		                                              .arg(taken.isEmpty() ? words(e->name) : p->text(0)));
		if (!kept.isEmpty() && p->data(0, ROLE_ROOT).toByteArray() == kept)
			again = p;
	}
	for (int m = 0; m < m_tree->topLevelItemCount(); m++)
		m_tree->topLevelItem(m)->setText(1, QString::number(m_tree->topLevelItem(m)->childCount()));
	m_tree->expandAll();
	if (!m_thumbs_wanted.isEmpty())
		m_thumb_timer->start();
	m_status->setText(!all.count ? tr("No photograph is catalogued yet.")
	                  : videos   ? tr("%1 photograph(s) and %2 video(s).").arg(all.count - videos).arg(videos)
	                             : tr("%n photograph(s).", nullptr, (int)all.count));
	fzn_rpc_photo_list_release(&all);
	m_filter_said.clear();
	if (again)
		m_tree->setCurrentItem(again);
	apply_filter();
	answer.restore();
	return true;
}

void fzn_photo_view::apply_filter()
{
	const QString text = m_find->text().trimmed();
	int left_all = 0, every = 0;

	for (int m = 0; m < m_tree->topLevelItemCount(); m++) {
		QTreeWidgetItem *month = m_tree->topLevelItem(m);
		int left = 0;

		for (int i = 0; i < month->childCount(); i++) {
			QTreeWidgetItem *p = month->child(i);
			const bool show = text.isEmpty() || p->data(0, ROLE_FIND).toString().contains(text, Qt::CaseInsensitive);

			p->setHidden(!show);
			left += show;
			every++;
		}
		month->setHidden(!left);
		left_all += left;
	}
	if (chosen() && chosen()->isHidden())
		m_tree->setCurrentItem(nullptr);
	if (text.isEmpty()) {
		if (!m_filter_said.isEmpty() && m_status->text() == m_filter_said)
			m_status->clear();
		m_filter_said.clear();
		return;
	}
	m_filter_said = left_all ? tr("%1 of %2 shown.").arg(left_all).arg(every) : tr("No photograph matches.");
	m_status->setText(m_filter_said);
}

/* THE CHOSEN PHOTOGRAPH READ AND SHOWN: its bytes through the play slices,
 * its size from its header before it is decoded, decoded at the preview's
 * size and turned as it says. */
void fzn_photo_view::show_chosen()
{
	QTreeWidgetItem *it = chosen();
	const bool photo = it && it->parent();

	m_shown = QImage();
	m_picture->clear();
	m_fetch->setEnabled(photo && !it->data(0, ROLE_HERE).toBool());
	m_play_button->setEnabled(photo && it->data(0, ROLE_VIDEO).toBool() && (bool)m_play);
	if (!photo)
		return;
	/* A VIDEO is played, not decoded here. */
	if (it->data(0, ROLE_VIDEO).toBool()) {
		m_status->setText(tr("A video: \"Play\" plays it."));
		return;
	}
	const QByteArray root = it->data(0, ROLE_ROOT).toByteArray();
	QByteArray bytes;
	fzn_rpc_library_play_resp_t *slice = (fzn_rpc_library_play_resp_t *)malloc(sizeof(*slice));
	if (!slice)
		return;
	uint64_t at = 0;
	for (;;) {
		if (fzn_rpc_library_play(&m_rpc->c, (const uint8_t *)root.constData(), at, FZN_RPC_LIBRARY_PLAY_MAX_SLICE,
		                         slice)
		    != FZN_RPC_OK) {
			m_status->setText(it->data(0, ROLE_HERE).toBool() ? failed_words(m_rpc)
			                                                  : tr("Not here yet: \"Get it\" asks another host."));
			free(slice);
			return;
		}
		if (slice->size > PHOTO_BYTES_MAX) {
			m_status->setText(tr("This photograph is too large to show."));
			free(slice);
			return;
		}
		if (slice->underrun) {
			m_status->setText(tr("Still arriving."));
			free(slice);
			return;
		}
		if (!slice->data_len)
			break;
		bytes.append((const char *)slice->data, (int)slice->data_len);
		at += slice->data_len;
		if (at >= slice->size)
			break;
	}
	free(slice);
	QBuffer buf(&bytes);
	buf.open(QIODevice::ReadOnly);
	QImageReader reader(&buf);
	reader.setAutoTransform(true);
	const QSize size = reader.size();
	if (!size.isValid() || size.width() > PHOTO_SIDE_MAX || size.height() > PHOTO_SIDE_MAX) {
		m_status->setText(tr("This photograph could not be shown."));
		return;
	}
	reader.setScaledSize(size.scaled(PREVIEW_SIDE, PREVIEW_SIDE, Qt::KeepAspectRatio));
	if (!reader.read(&m_shown)) {
		m_status->setText(tr("This photograph could not be shown."));
		return;
	}
	m_picture->setPixmap(QPixmap::fromImage(m_shown));
}

/* A PICTURE TURNED AS EXIF'S ORIENTATION SAYS: 1 as it is; 2 and 4 mirrored;
 * 3 a half turn; 6 a quarter clockwise, 8 anticlockwise; 5 and 7 those,
 * mirrored. */
static QImage turned(const QImage &img, int orientation)
{
	QTransform t;
	bool mirror = orientation == 2 || orientation == 4 || orientation == 5 || orientation == 7;

	if (orientation == 3 || orientation == 4)
		t.rotate(180);
	else if (orientation == 6 || orientation == 5)
		t.rotate(90);
	else if (orientation == 8 || orientation == 7)
		t.rotate(270);
	QImage out = t.isIdentity() ? img : img.transformed(t);
	return mirror ? out.mirrored(true, false) : out;
}

int fzn_photo_view::read_thumbnails(int n)
{
	int read = 0;
	fzn_rpc_library_play_resp_t *slice = (fzn_rpc_library_play_resp_t *)malloc(sizeof(*slice));

	if (!slice)
		return 0;
	while (read < n && !m_thumbs_wanted.isEmpty()) {
		const QByteArray root = m_thumbs_wanted.takeFirst();
		QByteArray head;
		uint64_t at = 0;

		/* THE FIRST 64 KiB, or the file where it is shorter. */
		while (head.size() < (int)THUMB_HEAD) {
			if (fzn_rpc_library_play(&m_rpc->c, (const uint8_t *)root.constData(), at,
			                         FZN_RPC_LIBRARY_PLAY_MAX_SLICE, slice)
			            != FZN_RPC_OK
			    || slice->underrun || !slice->data_len)
				break;
			head.append((const char *)slice->data, (int)slice->data_len);
			at += slice->data_len;
			if (at >= slice->size)
				break;
		}
		read++;
		size_t off = 0, len = 0;
		QImage img;
		if (!fzn_media_exif_thumbnail((const uint8_t *)head.constData(), (size_t)head.size(), &off, &len)
		    || !img.loadFromData((const uchar *)head.constData() + off, (int)len, "JPG"))
			continue;
		for (int m = 0; m < m_tree->topLevelItemCount(); m++)
			for (int i = 0; i < m_tree->topLevelItem(m)->childCount(); i++) {
				QTreeWidgetItem *p = m_tree->topLevelItem(m)->child(i);
				if (p->data(0, ROLE_ROOT).toByteArray() == root)
					p->setIcon(0, QIcon(QPixmap::fromImage(
					                      turned(img, p->data(0, ROLE_TURN).toInt())
					                              .scaled(THUMB_SIDE, THUMB_SIDE, Qt::KeepAspectRatio,
					                                      Qt::SmoothTransformation))));
			}
	}
	free(slice);
	return read;
}

bool fzn_photo_view::has_thumbnail(int row) const
{
	const QList<QTreeWidgetItem *> rows = shown();
	return row >= 0 && row < rows.size() && !rows[row]->icon(0).isNull();
}

void fzn_photo_view::set_find(const QString &text) { m_find->setText(text); }

QTreeWidgetItem *fzn_photo_view::chosen() const { return m_tree->currentItem(); }

QList<QTreeWidgetItem *> fzn_photo_view::shown() const
{
	QList<QTreeWidgetItem *> out;
	for (int m = 0; m < m_tree->topLevelItemCount(); m++) {
		QTreeWidgetItem *month = m_tree->topLevelItem(m);
		if (month->isHidden())
			continue;
		out << month;
		for (int i = 0; i < month->childCount(); i++)
			if (!month->child(i)->isHidden())
				out << month->child(i);
	}
	return out;
}

void fzn_photo_view::select(int row)
{
	const QList<QTreeWidgetItem *> rows = shown();
	m_tree->setCurrentItem(row >= 0 && row < rows.size() ? rows[row] : nullptr);
}

bool fzn_photo_view::fetch()
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

QStringList fzn_photo_view::rows() const
{
	QStringList out;
	for (QTreeWidgetItem *it : shown()) {
		QStringList cells;
		const int n = it->parent() ? 5 : 2;
		for (int c = 0; c < n; c++)
			cells << it->text(c);
		out << (it->parent() ? QStringLiteral("  ") : QString()) + cells.join(QStringLiteral(" | "));
	}
	return out;
}

QImage fzn_photo_view::shown_picture() const { return m_shown; }

bool fzn_photo_view::play()
{
	QTreeWidgetItem *it = chosen();
	if (!it || !it->parent() || it->isHidden() || !it->data(0, ROLE_VIDEO).toBool() || !m_play)
		return false;
	m_play(it->data(0, ROLE_ROOT).toByteArray(), it->data(0, Qt::AccessibleTextRole).toString());
	return true;
}

QString fzn_photo_view::status() const { return m_status->text(); }
