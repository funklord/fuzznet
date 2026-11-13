/* Positions shared with this user, as a widget: gui/location_view.h, sec 1109. */
#include "location_view.h"

#include "rpc_ask.h"

extern "C" {
#include "../location/geo.h"
}

#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

#include <stdlib.h>
#include <string.h>
#include <time.h>

fzn_location_view::fzn_location_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent)
    : QWidget(parent), m_rpc(new fzn_gui_rpc), m_now(0)
{
	fzn_gui_rpc_init(m_rpc, ask, ask_ctx);

	m_own = new QLabel(this);
	m_own->setWordWrap(true);
	m_table = new QTableWidget(0, 5, this);
	m_table->setHorizontalHeaderLabels(
	        { tr("Contact"), tr("Where"), tr("How sure"), tr("When"), tr("From here") });
	m_table->horizontalHeader()->setStretchLastSection(true);
	m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_table->setSelectionMode(QAbstractItemView::SingleSelection);
	m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
	m_fetch = new QPushButton(tr("Ask where they are"), this);
	m_share = new QPushButton(tr("Share mine with them"), this);
	m_unshare = new QPushButton(tr("Stop sharing mine"), this);
	m_refresh = new QPushButton(tr("Refresh"), this);
	m_status = new QLabel(this);
	m_status->setWordWrap(true);

	auto *row = new QHBoxLayout;
	row->addWidget(m_fetch);
	row->addWidget(m_share);
	row->addWidget(m_unshare);
	row->addWidget(m_refresh);
	auto *col = new QVBoxLayout(this);
	col->addWidget(m_own);
	col->addWidget(m_table, 1);
	col->addLayout(row);
	col->addWidget(m_status);

	connect(m_table, &QTableWidget::currentCellChanged,
	        [this](int r, int, int, int) { select(r); });
	connect(m_fetch, &QPushButton::clicked, [this]() { fetch(); });
	connect(m_share, &QPushButton::clicked, [this]() { share(true); });
	connect(m_unshare, &QPushButton::clicked, [this]() { share(false); });
	connect(m_refresh, &QPushButton::clicked, [this]() { refresh(); });
	select(-1);
}

fzn_location_view::~fzn_location_view() { delete m_rpc; }

void fzn_location_view::set_now(uint32_t utc_s) { m_now = utc_s; }

static QString failed_words(const fzn_gui_rpc *r) { return QString::fromUtf8(fzn_gui_rpc_silent(r)); }

/* HOW OLD, in the words a person reads: seconds, minutes, hours, days. */
static QString age_words(uint32_t now, uint32_t then)
{
	if (!then)
		return QObject::tr("unknown");
	if (then >= now)
		return QObject::tr("just now");
	uint32_t s = now - then;
	if (s < 60)
		return QObject::tr("%1 s ago").arg(s);
	if (s < 3600)
		return QObject::tr("%1 min ago").arg(s / 60);
	if (s < 86400)
		return QObject::tr("%1 h ago").arg(s / 3600);
	return QObject::tr("%1 days ago").arg(s / 86400);
}

static QString where_words(const fzn_rpc_location_show_entry_t *f)
{
	return QStringLiteral("%1, %2").arg(f->lat_e7 / 1e7, 0, 'f', 5).arg(f->lon_e7 / 1e7, 0, 'f', 5);
}

/* THE ACCURACY, the larger of east and north; a coarse fix said so. */
static QString sure_words(const fzn_rpc_location_show_entry_t *f)
{
	uint32_t m = f->acc_e_m > f->acc_n_m ? f->acc_e_m : f->acc_n_m;
	QString s = m ? QObject::tr("within %1 m").arg(m) : QObject::tr("unknown");
	return f->is_coarse ? QObject::tr("%1, coarse").arg(s) : s;
}

bool fzn_location_view::refresh()
{
	const uint32_t now = m_now ? m_now : (uint32_t)time(NULL);
	fzn_rpc_location_status_resp_t st;

	if (fzn_rpc_location_status(&m_rpc->c, &st) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return m_rpc->c.answered;
	}
	QString own = !st.configured ? tr("This host does not share its own position.")
	              : st.sampling  ? tr("This host samples its position every %1 s from %2.")
	                                      .arg(st.interval_s)
	                                      .arg(QString::fromUtf8(st.source, (int)st.source_len))
	              : st.stopped_reason == FZN_RPC_LOCATION_STOPPED_UNREACHABLE
	                      ? tr("This host cannot reach its position source.")
	                      : tr("This host's position source has stopped.");

	/* THIS HOST'S OWN NEWEST FIX, which every distance is measured from. */
	auto *mine = new fzn_rpc_location_show_resp_t;
	const fzn_rpc_location_show_entry_t *from = nullptr;
	if (fzn_rpc_location_show(&m_rpc->c, "", 0, mine) == FZN_RPC_OK && mine->count)
		from = &mine->entries[0];
	if (from)
		own += QLatin1Char(' ') + tr("Its own position: %1, %2.").arg(where_words(from),
		                                                              age_words(now, from->utc_s));

	fzn_rpc_location_latest_t *latest = nullptr;
	size_t room = 0, count = 0;
	if (fzn_rpc_location_latest(&m_rpc->c, &latest, &room, &count) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		free(latest);
		delete mine;
		return m_rpc->c.answered;
	}
	m_own->setText(own);
	m_table->setRowCount((int)count);
	for (size_t i = 0; i < count; i++) {
		const fzn_rpc_location_show_entry_t *f = &latest[i].fix;
		QString here = tr("--");
		if (from) {
			double d = fzn_geo_distance_m(from->lat_e7, from->lon_e7, f->lat_e7, f->lon_e7);
			char text[32];
			fzn_geo_format_distance(text, sizeof text, d);
			here = QString::fromUtf8(text);
			/* A DIRECTION ONLY WHERE THE FIXES' ACCURACY LEAVES IT ONE. */
			double sure = (double)(from->acc_e_m > from->acc_n_m ? from->acc_e_m : from->acc_n_m)
			              + (double)(f->acc_e_m > f->acc_n_m ? f->acc_e_m : f->acc_n_m);
			if (fzn_geo_bearing_is_meaningful(d, sure))
				here += QLatin1Char(' ')
				        + QString::fromUtf8(fzn_geo_compass_point(fzn_geo_bearing_deg(
				                from->lat_e7, from->lon_e7, f->lat_e7, f->lon_e7)));
		}
		m_table->setItem((int)i, 0, new QTableWidgetItem(QString::fromUtf8(latest[i].name)));
		m_table->setItem((int)i, 1, new QTableWidgetItem(where_words(f)));
		m_table->setItem((int)i, 2, new QTableWidgetItem(sure_words(f)));
		m_table->setItem((int)i, 3, new QTableWidgetItem(age_words(now, f->utc_s)));
		m_table->setItem((int)i, 4, new QTableWidgetItem(here));
	}
	free(latest);
	delete mine;
	m_status->setText(count ? QString() : tr("Nobody shares a position with you yet."));
	select(-1);
	return true;
}

void fzn_location_view::select(int row)
{
	bool chosen = row >= 0 && row < m_table->rowCount();
	if (chosen && m_table->currentRow() != row)
		m_table->setCurrentCell(row, 0);
	m_fetch->setEnabled(chosen);
	m_share->setEnabled(chosen);
	m_unshare->setEnabled(chosen);
}

bool fzn_location_view::fetch()
{
	int row = m_table->currentRow();
	if (row < 0 || !m_table->item(row, 0))
		return false;
	QByteArray who = m_table->item(row, 0)->text().toUtf8();
	if (fzn_rpc_location_fetch(&m_rpc->c, who.constData(), (size_t)who.size()) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	m_status->setText(tr("Asked %1 where they are.").arg(QString::fromUtf8(who)));
	return true;
}

bool fzn_location_view::share(bool on)
{
	int row = m_table->currentRow();
	if (row < 0 || !m_table->item(row, 0))
		return false;
	QByteArray who = m_table->item(row, 0)->text().toUtf8();
	int siblings = 0;
	if (fzn_rpc_location_share(&m_rpc->c, who.constData(), (size_t)who.size(), on ? 1 : 0,
	                           FZN_RPC_LOCATION_PRECISION_EXACT, &siblings)
	    != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	m_status->setText(on ? tr("%1 can see your position now.").arg(QString::fromUtf8(who))
	                     : tr("%1 no longer sees your position.").arg(QString::fromUtf8(who)));
	return true;
}

QString fzn_location_view::own() const { return m_own->text(); }

QStringList fzn_location_view::rows() const
{
	QStringList out;
	for (int i = 0; i < m_table->rowCount(); i++) {
		QStringList cells;
		for (int k = 0; k < m_table->columnCount(); k++)
			cells << m_table->item(i, k)->text();
		out << cells.join(QStringLiteral(" | "));
	}
	return out;
}

QString fzn_location_view::status() const { return m_status->text(); }
