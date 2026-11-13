/* How this host is reached, as a widget: gui/reach_view.h, sec 1134. */
#include "reach_view.h"

#include "rpc_ask.h"

extern "C" {
#include "../local/rpc_encoding.h"
}

#include <QByteArray>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QPushButton>
#include <QVBoxLayout>

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

fzn_reach_view::fzn_reach_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent)
    : QWidget(parent), m_rpc(new fzn_gui_rpc)
{
	fzn_gui_rpc_init(m_rpc, ask, ask_ctx);

	m_outside = new QLabel(this);
	m_outside->setWordWrap(true);
	m_ask_outside = new QPushButton(tr("Ask again"), this);
	m_ask_outside->setAccessibleName(tr("Ask other hosts again where they see this one"));
	m_found = new QListWidget(this);
	m_found->setAccessibleName(tr("Hosts that answered on this network"));
	m_look_here = new QPushButton(tr("Look on this network"), this);
	m_relay = new QLabel(this);
	m_relay->setWordWrap(true);
	m_load = new QLabel(this);
	m_load->setWordWrap(true);
	m_refresh = new QPushButton(tr("Refresh"), this);
	m_status = new QLabel(this);
	m_status->setWordWrap(true);

	auto *outside_row = new QHBoxLayout;
	outside_row->addWidget(m_ask_outside);
	outside_row->addStretch(1);
	auto *here_row = new QHBoxLayout;
	here_row->addWidget(m_look_here);
	here_row->addWidget(m_refresh);
	here_row->addStretch(1);
	auto *col = new QVBoxLayout(this);
	col->addWidget(m_outside);
	col->addLayout(outside_row);
	auto *found_label = new QLabel(tr("On this network"), this);
	col->addWidget(found_label);
	col->addWidget(m_found, 1);
	col->addLayout(here_row);
	col->addWidget(m_relay);
	col->addWidget(m_load);
	col->addWidget(m_status);

	connect(m_ask_outside, &QPushButton::clicked, [this]() { ask_outside(); });
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
	m_found->clear();
	for (i = 0; i < lan->count; i++)
		m_found->addItem(QStringLiteral("%1 -- %2").arg(
		        said(lan->entries[i].address, lan->entries[i].address_len),
		        QString::fromLatin1(QByteArray((const char *)lan->entries[i].host_pubkey, 8).toHex())));
	/* THE RELAY: off, or on with its quota -- 0 is no limit, not none. */
	m_relay->setText(!relay->enabled ? tr("This host does not relay for others.")
	                 : tr("This host relays for others: %1 per %2 s each; %3 using it now.")
	                           .arg(relay->quota_bytes ? tr("%1 bytes").arg(relay->quota_bytes)
	                                                   : tr("no limit"))
	                           .arg(relay->window_s)
	                           .arg(relay->count));
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

QString fzn_reach_view::outside() const { return m_outside->text(); }

QStringList fzn_reach_view::found() const
{
	QStringList out;
	for (int i = 0; i < m_found->count(); i++)
		out << m_found->item(i)->text();
	return out;
}

QString fzn_reach_view::relay() const { return m_relay->text(); }

QString fzn_reach_view::keeping_up() const { return m_load->text(); }

QString fzn_reach_view::status() const { return m_status->text(); }
