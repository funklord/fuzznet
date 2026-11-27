/* What a person is told of clocks that disagree: clock_notice.h, sec 1507. */
#include "clock_notice.h"
#include "rpc_ask.h"

#include <QCoreApplication>
#include <QStringList>

#include <stdlib.h>
#include <string.h>

static QString tr_(const char *s) { return QCoreApplication::translate("clock_notice", s); }

/* A span in the unit a person reads it in: seconds under two minutes,
 * minutes under two hours, then hours. */
static QString span(quint64 seconds)
{
	if (seconds < 120)
		return tr_("%1 seconds").arg(seconds);
	if (seconds < 2 * 3600)
		return tr_("%1 minutes").arg(seconds / 60);
	return tr_("%1 hours").arg(seconds / 3600);
}

QString fzn_clock_notice_text(const fzn_rpc_clock_estate_t &estate, const fzn_rpc_clock_list_t &rows,
                              const QHash<QByteArray, QString> &names)
{
	if (estate.state == FZN_RPC_CLOCK_WRONG) {
		/* To the nearest second: 899994 ms is fifteen minutes, not fourteen. */
		const quint64 off = (quint64(estate.offset_ms < 0 ? -estate.offset_ms : estate.offset_ms) + 500) / 1000;
		QString text = (estate.offset_ms > 0
		                        ? tr_("This device's clock is %1 behind your other devices' (%2 measured), "
		                              "so nothing it sends them gets through. Set this device's date and time.")
		                        : tr_("This device's clock is %1 ahead of your other devices' (%2 measured), "
		                              "so nothing it sends them gets through. Set this device's date and time."))
		                       .arg(span(off))
		                       .arg(estate.devices);
		if (rows.count > 0)
			text += QLatin1Char(' ') + tr_("Clocks disagree with %1 device(s) because of it.").arg(rows.count);
		return text;
	}
	if (rows.count == 0)
		return QString();
	size_t newest = 0;
	for (size_t i = 1; i < rows.count; i++)
		if (rows.rows[i].at > rows.rows[newest].at)
			newest = i;
	const fzn_rpc_clock_row_t &r = rows.rows[newest];
	const QByteArray key(reinterpret_cast<const char *>(r.key), 32);
	QString who = names.value(key);
	if (who.isEmpty())
		who = tr_("a device (%1)").arg(QString::fromLatin1(key.left(4).toHex()));
	const QString which = r.ahead ? tr_("%1's clock runs ahead of this device's, or this one's behind")
	                              : tr_("%1's clock runs behind this device's, or this one's ahead");
	const QString check = estate.state == FZN_RPC_CLOCK_RIGHT
	                              ? tr_("This device's clock agrees with your other devices', so it is %1's "
	                                    "date and time to set.")
	                                        .arg(who)
	                              : tr_("Check that this device's date and time are right.");
	QString text = tr_("This device's clock and %1's are more than %2 apart, so nothing gets "
	                   "through between them (%3). %4")
	                       .arg(who, span(r.seconds), which.arg(who), check);
	if (rows.count > 1)
		text += QLatin1Char(' ') + tr_("Clocks disagree with %1 other device(s) too.").arg(rows.count - 1);
	return text;
}

QString fzn_clock_notice_signature(const fzn_rpc_clock_estate_t &estate, const fzn_rpc_clock_list_t &rows)
{
	QStringList parts;
	for (size_t i = 0; i < rows.count; i++)
		parts << QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(rows.rows[i].key), 32).toHex())
		                 + (rows.rows[i].ahead ? QStringLiteral("+") : QStringLiteral("-"));
	parts.sort();
	parts.prepend(QString::number(int(estate.state)));
	return parts.join(QLatin1Char(','));
}

bool fzn_clock_notice_read(fzn_notebook_view_ask_t ask, void *ask_ctx, QString *text, QString *signature)
{
	fzn_gui_rpc rpc;
	fzn_rpc_clock_estate_t estate;
	fzn_rpc_clock_list_t rows;
	fzn_rpc_peer_list_resp_t peers;
	QHash<QByteArray, QString> names;
	size_t i;

	text->clear();
	signature->clear();
	fzn_gui_rpc_init(&rpc, ask, ask_ctx);
	memset(&estate, 0, sizeof(estate));
	memset(&rows, 0, sizeof(rows));
	memset(&peers, 0, sizeof(peers));
	if (fzn_rpc_clock_get(&rpc.c, &estate) != FZN_RPC_OK || fzn_rpc_clock_list(&rpc.c, &rows) != FZN_RPC_OK) {
		fzn_rpc_clock_list_release(&rows);
		return rpc.c.answered;
	}
	/* WHO EACH KEY IS: a contact by its host's key, a sibling by its own. */
	if (fzn_rpc_peer_list(&rpc.c, &peers) == FZN_RPC_OK)
		for (i = 0; i < peers.count; i++) {
			const QString name = QString::fromUtf8(peers.entries[i].name, (int)peers.entries[i].name_len);
			names.insert(QByteArray((const char *)peers.entries[i].host_pubkey, 32), name);
			names.insert(QByteArray((const char *)peers.entries[i].root_pubkey, 32), name);
		}
	free(peers.entries);
	{
		auto *siblings = new fzn_rpc_sibling_list_resp_t;
		memset(siblings, 0, sizeof(*siblings));
		if (fzn_rpc_sibling_list(&rpc.c, siblings) == FZN_RPC_OK)
			for (i = 0; i < siblings->count; i++)
				names.insert(QByteArray((const char *)siblings->entries[i].host_pubkey, 32),
				             QString::fromUtf8(siblings->entries[i].name, (int)siblings->entries[i].name_len));
		delete siblings;
	}
	*text = fzn_clock_notice_text(estate, rows, names);
	*signature = text->isEmpty() ? QString() : fzn_clock_notice_signature(estate, rows);
	fzn_rpc_clock_list_release(&rows);
	return true;
}
