/* This host's legs, as a widget: leg_view.h, sec 1210. */
#include "leg_view.h"
#include "size_words.h"
#include "rpc_ask.h"

#include <QHeaderView>
#include <QLabel>
#include <QResizeEvent>
#include <QTableWidget>
#include <QVBoxLayout>

#define NARROW_PX 400

enum { COL_ADDRESS, COL_OVER, COL_LATENCY, COL_ANSWERED, COL_COST, COL_BUDGET, COLS };

/* AN AGE, as a person says it: seconds, minutes or hours. */
static QString ago(uint64_t ms)
{
	const uint64_t s = ms / 1000u;

	if (s < 120u)
		return QObject::tr("%1 s").arg(s);
	if (s < 7200u)
		return QObject::tr("%1 min").arg(s / 60u);
	return QObject::tr("%1 h").arg(s / 3600u);
}

fzn_leg_view::fzn_leg_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent)
    : QWidget(parent), m_rpc(new fzn_gui_rpc)
{
	fzn_gui_rpc_init(m_rpc, ask, ask_ctx);
	m_summary = new QLabel(this);
	m_summary->setWordWrap(true);
	m_table = new QTableWidget(0, COLS, this);
	m_table->setHorizontalHeaderLabels(
	        { tr("Address"), tr("Over"), tr("Latency"), tr("Answered"), tr("Cost"), tr("Budget") });
	m_table->horizontalHeader()->setStretchLastSection(true);
	m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
	m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_table->setAccessibleName(tr("This host's legs"));
	auto *col = new QVBoxLayout(this);
	col->addWidget(m_summary);
	col->addWidget(m_table, 1);
}

fzn_leg_view::~fzn_leg_view() { delete m_rpc; }

bool fzn_leg_view::refresh()
{
	auto *legs = new fzn_rpc_leg_list_resp_t;
	size_t answering = 0, i;

	if (fzn_rpc_leg_list(&m_rpc->c, legs) != FZN_RPC_OK) {
		m_summary->setText(QString::fromUtf8(fzn_gui_rpc_silent(m_rpc)));
		m_table->setRowCount(0);
		delete legs;
		return m_rpc->c.answered;
	}
	m_table->setRowCount((int)legs->count);
	for (i = 0; i < legs->count; i++) {
		const fzn_rpc_leg_entry_t *l = &legs->entries[i];
		char over[24];
		QStringList why;

		answering += l->replied > 0;
		/* THE PREDICATE, NOT THE VALUE: a leg measured at 0 ms is a fast one,
		 * and one never answered has no latency and no cost at all. */
		QString answered = tr("%1 of %2").arg(l->replied).arg(l->sent);
		if (l->consecutive_failures)
			answered += tr(", %1 lost in a row").arg(l->consecutive_failures);
		/* UNLIMITED is every leg's state until `net/budget` is set, so it is
		 * said, rather than drawn as a budget of nothing fully spent. */
		const QString budget = l->budget_limit
		                               ? tr("%1 of %2").arg(fzn_size_words(l->budget_spent), fzn_size_words(l->budget_limit))
		                               : tr("unlimited");
		const QString cells[COLS] = {
			QString::fromUtf8(l->address, (int)l->address_len),
			QString::fromLatin1(fzn_rpc_transport_name(l->transport, over, sizeof over)),
			l->replied ? tr("%1 ms").arg(l->rtt_ms) : tr("unmeasured"),
			answered,
			l->replied && l->cost ? tr("%1 ms").arg(l->cost) : QStringLiteral("-"),
			budget,
		};
		for (int k = 0; k < COLS; k++)
			m_table->setItem((int)i, k, new QTableWidgetItem(cells[k]));
		if (l->sent)
			why << tr("last asked %1 ago").arg(ago(l->since_attempt_ms))
			    << (l->replied ? tr("last answered %1 ago").arg(ago(l->since_success_ms))
			                   : tr("never answered"));
		if (l->outstanding)
			why << tr("an ask is out and unanswered");
		if (!l->in_use)
			why << tr("no peer is reached at this address now");
		if (l->budget_limit && l->budget_spent >= l->budget_limit)
			why << tr("its budget is spent: no file is fetched over it until the window ends");
		for (int k = 0; k < COLS; k++)
			m_table->item((int)i, k)->setToolTip(why.join(QLatin1Char('\n')));
	}
	m_summary->setText(legs->count ? tr("%1 leg(s), %2 answering").arg(legs->count).arg(answering)
	                               : tr("No legs yet: nothing has been asked of a peer."));
	delete legs;
	narrow(width() < NARROW_PX);
	return true;
}

QString fzn_leg_view::summary() const { return m_summary->text(); }

QStringList fzn_leg_view::rows() const
{
	QStringList out;

	for (int r = 0; r < m_table->rowCount(); r++) {
		QStringList cells;
		for (int k = 0; k < COLS; k++)
			if (!m_table->isColumnHidden(k))
				cells << m_table->item(r, k)->text();
		out << cells.join(QStringLiteral(" | "));
	}
	return out;
}

QString fzn_leg_view::detail(int row) const
{
	return row >= 0 && row < m_table->rowCount() ? m_table->item(row, 0)->toolTip() : QString();
}

void fzn_leg_view::narrow(bool yes)
{
	for (int k : { COL_OVER, COL_LATENCY, COL_COST, COL_BUDGET })
		m_table->setColumnHidden(k, yes);
}

void fzn_leg_view::resizeEvent(QResizeEvent *event)
{
	QWidget::resizeEvent(event);
	narrow(event->size().width() < NARROW_PX);
}
