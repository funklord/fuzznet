/* How this host is reached, as a widget: gui/reach_view.h, sec 1134. */
#include "reach_view.h"

#include "rpc_ask.h"

extern "C" {
#include "../local/rpc_encoding.h"
}

#include <QByteArray>
#include <QDateTime>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QResizeEvent>
#include <QTreeWidget>
#include <QVBoxLayout>

/* Narrower than this, the columns a phone can do without are hidden. */
#define NARROW_PX 400

static QString failed_words(const fzn_gui_rpc *r)
{
	return QString::fromUtf8(fzn_gui_rpc_silent(r));
}

/* Another host's words, in caret form (sec 1126). */
static QString said(const char *text, size_t len)
{
	char shown[4u * (FZN_RPC_PEER_ADDRESS_MAX + 1u)];
	fzn_rpc_tty_escape(text, len, shown, sizeof shown);
	return QString::fromUtf8(shown);
}

/* A time on the node's clock, in seconds, as a person reads it here: the
 * time alone today, the day as well otherwise. */
static QString when(uint64_t s)
{
	if (!s)
		return QObject::tr("never");
	const QDateTime t = QDateTime::fromSecsSinceEpoch((qint64)s);
	return t.date() == QDate::currentDate() ? t.toString(QStringLiteral("HH:mm:ss"))
	                                        : t.toString(QStringLiteral("yyyy-MM-dd HH:mm"));
}

static QTreeWidget *table(QWidget *parent, const QStringList &heads, const QString &spoken)
{
	auto *t = new QTreeWidget(parent);

	t->setColumnCount(heads.size());
	t->setHeaderLabels(heads);
	t->setRootIsDecorated(false);
	t->setAccessibleName(spoken);
	t->header()->setStretchLastSection(true);
	return t;
}

/* A table's rows as "A -- B -- C", for a headless reader. */
static QStringList rows_of(const QTreeWidget *t)
{
	QStringList out;

	for (int i = 0; i < t->topLevelItemCount(); i++) {
		QStringList cells;

		for (int k = 0; k < t->columnCount(); k++)
			cells << t->topLevelItem(i)->text(k);
		out << cells.join(QStringLiteral(" -- "));
	}
	return out;
}

fzn_reach_view::fzn_reach_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent)
    : QWidget(parent), m_rpc(new fzn_gui_rpc)
{
	fzn_gui_rpc_init(m_rpc, ask, ask_ctx);

	m_outside = new QLabel(this);
	m_outside->setWordWrap(true);
	m_seen_by = table(this, { tr("Address"), tr("Reported by"), tr("When") },
	                  tr("Where other hosts see this one"));
	m_seen_by->setObjectName(QStringLiteral("reach_seen_by"));
	m_ask_outside = new QPushButton(tr("Ask again"), this);
	m_ask_outside->setAccessibleName(tr("Ask other hosts again where they see this one"));
	m_advertise = new QPushButton(tr("Advertise the selected address"), this);
	m_advertise->setAccessibleName(tr("Advertise the selected address as this host's"));
	m_advertise->setEnabled(false);
	m_found = table(this, { tr("Address"), tr("Host"), tr("Seen") }, tr("Hosts that answered on this network"));
	m_found->setObjectName(QStringLiteral("reach_found"));
	m_look_here = new QPushButton(tr("Look on this network"), this);
	m_relay = new QLabel(this);
	m_relay->setWordWrap(true);
	m_relayed = table(this, { tr("Peer"), tr("Used"), tr("Refused") }, tr("What each peer used of the relay"));
	m_relayed->setObjectName(QStringLiteral("reach_relayed"));
	m_activity = table(this, { tr("#"), tr("What the node did") }, tr("What this node did lately"));
	m_activity->setObjectName(QStringLiteral("reach_activity"));
	m_load = new QLabel(this);
	m_load->setWordWrap(true);
	m_refresh = new QPushButton(tr("Refresh"), this);
	m_status = new QLabel(this);
	m_status->setWordWrap(true);

	auto *outside_row = new QHBoxLayout;
	outside_row->addWidget(m_ask_outside);
	outside_row->addWidget(m_advertise);
	outside_row->addStretch(1);
	auto *here_row = new QHBoxLayout;
	here_row->addWidget(m_look_here);
	here_row->addWidget(m_refresh);
	here_row->addStretch(1);
	auto *col = new QVBoxLayout(this);
	col->addWidget(m_outside);
	col->addWidget(m_seen_by, 1);
	col->addLayout(outside_row);
	auto *found_label = new QLabel(tr("On this network"), this);
	col->addWidget(found_label);
	col->addWidget(m_found, 1);
	col->addLayout(here_row);
	col->addWidget(m_relay);
	col->addWidget(m_relayed, 1);
	col->addWidget(m_load);
	col->addWidget(new QLabel(tr("Lately"), this));
	col->addWidget(m_activity, 1);
	col->addWidget(m_status);

	connect(m_ask_outside, &QPushButton::clicked, [this]() { ask_outside(); });
	connect(m_advertise, &QPushButton::clicked,
	        [this]() { advertise(m_seen_by->indexOfTopLevelItem(m_seen_by->currentItem())); });
	connect(m_seen_by, &QTreeWidget::itemSelectionChanged,
	        [this]() { m_advertise->setEnabled(!m_seen_by->selectedItems().isEmpty()); });
	connect(m_look_here, &QPushButton::clicked, [this]() { look_here(); });
	connect(m_refresh, &QPushButton::clicked, [this]() { refresh(); });
	m_outside->setText(tr("Where others see this host is not known yet."));
}

fzn_reach_view::~fzn_reach_view() { delete m_rpc; }

bool fzn_reach_view::refresh()
{
	fzn_rpc_addr_observe_resp_t seen;
	auto *lan = new fzn_rpc_lan_discover_resp_t;
	auto *relay = new fzn_rpc_relay_status_resp_t;
	size_t i;
	bool ok = false;

	if (fzn_rpc_addr_observe(&m_rpc->c, 0, &seen) != FZN_RPC_OK
	    || fzn_rpc_lan_discover(&m_rpc->c, 0, lan) != FZN_RPC_OK
	    || fzn_rpc_relay_status(&m_rpc->c, relay) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		ok = m_rpc->c.answered;
		delete lan;
		delete relay;
		return ok;
	}
	/* OUTSIDE: the first report's address, with how many agree on it --
	 * the node's own count (sec 1125). One report alone is a guess. */
	if (!seen.count)
		m_outside->setText(tr("No host has said where it sees this one from."));
	else if (seen.agree > 1)
		m_outside->setText(tr("Others see this host at %1 (%2 of %3 agree).")
		                           .arg(said(seen.entries[0].address, seen.entries[0].address_len))
		                           .arg(seen.agree)
		                           .arg(seen.count));
	else
		m_outside->setText(tr("One host sees this one at %1; nothing confirms it yet.")
		                           .arg(said(seen.entries[0].address, seen.entries[0].address_len)));
	/* EVERY REPORT, sec 1196, each a row a person can pick to advertise. */
	m_seen_by->clear();
	for (i = 0; i < seen.count; i++) {
		const fzn_rpc_addr_observed_entry_t &e = seen.entries[i];
		auto *row = new QTreeWidgetItem(m_seen_by, { said(e.address, e.address_len),
		                                             said(e.reporter, e.reporter_len), when(e.observed_at) });

		row->setData(0, Qt::UserRole, QString::fromUtf8(e.address, (int)e.address_len));
	}
	m_advertise->setEnabled(!m_seen_by->selectedItems().isEmpty());
	m_found->clear();
	for (i = 0; i < lan->count; i++)
		new QTreeWidgetItem(m_found,
		                    { said(lan->entries[i].address, lan->entries[i].address_len),
		                      QString::fromLatin1(QByteArray((const char *)lan->entries[i].host_pubkey, 8).toHex()),
		                      when(lan->entries[i].seen_at) });
	/* THE RELAY: off, or on with its quota -- 0 is no limit, not none. */
	m_relay->setText(!relay->enabled ? tr("This host does not relay for others.")
	                 : tr("This host relays for others: %1 per %2 s each; %3 using it now.")
	                           .arg(relay->quota_bytes ? tr("%1 bytes").arg(relay->quota_bytes)
	                                                   : tr("no limit"))
	                           .arg(relay->window_s)
	                           .arg(relay->count));
	/* AND FOR WHOM, sec 1196: each peer's bytes this window and the times
	 * it was turned away, which the quota alone does not say. */
	m_relayed->clear();
	for (i = 0; i < relay->count; i++)
		new QTreeWidgetItem(m_relayed, { said(relay->entries[i].peer, relay->entries[i].peer_len),
		                                 tr("%1 bytes").arg(relay->entries[i].bytes_used),
		                                 QString::number(relay->entries[i].refused) });
	m_relayed->setVisible(relay->count > 0);
	/* KEEPING UP, sec 1135: the share of each round sync takes, and
	 * fuzznet's own advice when it does not keep up. A node too old to
	 * say leaves the line empty rather than the view failed. */
	fzn_rpc_sync_load_t load;
	if (fzn_rpc_sync_load(&m_rpc->c, &load) == FZN_RPC_OK) {
		const char *advice = fzn_rpc_sync_load_advice(&load);
		m_load->setText(advice ? tr("Not keeping up (%1% of each round): %2.")
		                                 .arg(load.load_pct)
		                                 .arg(QString::fromUtf8(advice))
		                       : tr("Keeping up: syncing takes %1% of each round.").arg(load.load_pct));
	} else {
		m_load->clear();
	}
	/* LATELY, sec 1196: the node's own log, newest first. THE MESSAGE, NOT
	 * THE PREAMBLE -- a stored line opens "[time file:line|function
	 * category] ", so a column narrower than the line would cut exactly
	 * the part somebody came to read; the number keeps its own column so a
	 * row matches the node's log. A node keeping none hides the table
	 * rather than failing the view. */
	auto *log = new fzn_rpc_log_show_resp_t;
	m_activity->clear();
	if (fzn_rpc_log_show(&m_rpc->c, log) == FZN_RPC_OK) {
		for (i = 0; i < log->count; i++) {
			QString line = QString::fromUtf8(log->entries[i].text, (int)log->entries[i].text_len);
			const int close = line.startsWith(QLatin1Char('[')) ? line.indexOf(QStringLiteral("] ")) : -1;
			if (close > 0)
				line = line.mid(close + 2);
			new QTreeWidgetItem(m_activity, { QString::number(log->entries[i].seq), line });
		}
	}
	m_activity->setVisible(m_activity->topLevelItemCount() > 0);
	delete log;
	m_status->setText(QString());
	delete lan;
	delete relay;
	return true;
}

bool fzn_reach_view::ask_outside()
{
	fzn_rpc_addr_observe_resp_t seen;
	if (fzn_rpc_addr_observe(&m_rpc->c, 1, &seen) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	/* NOBODY ASKED is not "asked, no answer yet" (the client's own rule). */
	m_status->setText(seen.probes_sent ? tr("Asked %1 host(s); their answers come in a round.")
	                                           .arg(seen.probes_sent)
	                                   : tr("There is no host to ask yet."));
	return seen.probes_sent > 0;
}

/* ADVERTISED AS `net/address`, HOST PORT, sec 1196: the setting a card and
 * a peer asking for this host's records carry (sec 579), written where the
 * node keeps it -- as fuzzypickles' Connection page did. The port is after
 * the last colon, so a bare IPv6 host keeps its own. */
bool fzn_reach_view::advertise(int row)
{
	QTreeWidgetItem *item = m_seen_by->topLevelItem(row);
	if (!item) {
		m_status->setText(tr("Select an address first -- one a host reported."));
		return false;
	}
	const QString address = item->data(0, Qt::UserRole).toString();
	const int colon = address.lastIndexOf(QLatin1Char(':'));
	if (colon <= 0 || colon + 1 >= address.size()) {
		m_status->setText(tr("%1 is not an address with a port.").arg(address));
		return false;
	}
	const QByteArray value = (address.left(colon) + QLatin1Char(' ') + address.mid(colon + 1)).toUtf8();
	if (fzn_rpc_config_set(&m_rpc->c, "net.address", 11u, value.constData(), (size_t)value.size(), nullptr, 0,
	                       nullptr)
	    != FZN_RPC_OK) {
		m_status->setText(tr("%1 was refused: %2").arg(address, failed_words(m_rpc)));
		return false;
	}
	m_status->setText(tr("Advertising %1 -- hosts asking for this one's records see it.").arg(address));
	return true;
}

bool fzn_reach_view::look_here()
{
	auto *lan = new fzn_rpc_lan_discover_resp_t;
	if (fzn_rpc_lan_discover(&m_rpc->c, 1, lan) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		delete lan;
		return false;
	}
	const bool probed = lan->probed;
	m_status->setText(probed ? tr("Asked on this network; hosts that answer are listed above.")
	                         : tr("Nothing could be asked on this network."));
	delete lan;
	return probed;
}

/* A PHONE'S WIDTH, sec 1196: who reported an address, when a host was seen
 * and how often a peer was refused go; what each row is stays. */
void fzn_reach_view::narrow(bool yes)
{
	m_seen_by->setColumnHidden(1, yes);
	m_found->setColumnHidden(2, yes);
	m_relayed->setColumnHidden(2, yes);
}

void fzn_reach_view::resizeEvent(QResizeEvent *event)
{
	QWidget::resizeEvent(event);
	narrow(event->size().width() < NARROW_PX);
}

QString fzn_reach_view::outside() const { return m_outside->text(); }

QStringList fzn_reach_view::seen_by() const { return rows_of(m_seen_by); }

QStringList fzn_reach_view::found() const { return rows_of(m_found); }

QString fzn_reach_view::relay() const { return m_relay->text(); }

QStringList fzn_reach_view::relayed() const { return rows_of(m_relayed); }

QStringList fzn_reach_view::activity() const { return rows_of(m_activity); }

QString fzn_reach_view::keeping_up() const { return m_load->text(); }

QString fzn_reach_view::status() const { return m_status->text(); }
