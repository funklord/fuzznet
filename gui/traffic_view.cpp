/* What this node has moved, by family and by host: traffic_view.h, sec 1182. */
#include "traffic_view.h"
#include "plain_label.h"
#include "keep_place.h"

#include "rpc_ask.h"

#include <QHash>
#include <QLabel>
#include <QMap>
#include <QSet>
#include <QSplitter>
#include <QStringList>
#include <QTreeWidget>
#include <QVBoxLayout>

#include <stdlib.h>
#include <string.h>

/* A SIZE as a person reads it. */
static QString size_words(uint64_t bytes)
{
	if (bytes < 1024u)
		return QObject::tr("%1 B").arg(bytes);
	if (bytes < 1024u * 1024u)
		return QObject::tr("%1 KB").arg((double)bytes / 1024.0, 0, 'f', 1);
	if (bytes < 1024u * 1024u * 1024u)
		return QObject::tr("%1 MB").arg((double)bytes / (1024.0 * 1024.0), 0, 'f', 1);
	return QObject::tr("%1 GB").arg((double)bytes / (1024.0 * 1024.0 * 1024.0), 0, 'f', 1);
}

static QString rate_words(uint64_t down, uint64_t up)
{
	return (down || up) ? QObject::tr("%1/s down, %2/s up").arg(size_words(down), size_words(up))
	                    : QObject::tr("idle");
}

static QString hex_of(const uint8_t *p, size_t n)
{
	return QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(p), (int)n).toHex());
}

/* WHAT A ROW MOVES: a file by the name the library gives it, else its root;
 * otherwise the peer, who for chat is the whole answer. */
static QString row_label(const fzn_rpc_transfer_entry_t *e, const QHash<QString, QString> &names)
{
	if (e->key_kind == FZN_RPC_METER_KEY_BLOB && e->key_len) {
		const QString root = hex_of(e->key, e->key_len);
		return names.value(root, root.left(12) + QStringLiteral("..."));
	}
	return QString::fromUtf8(e->peer_address, (int)e->peer_address_len);
}

fzn_traffic_view::fzn_traffic_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent)
        : QWidget(parent), rpc_(new fzn_gui_rpc)
{
	QVBoxLayout *layout = new QVBoxLayout(this);
	QSplitter *split = new QSplitter(Qt::Vertical, this);

	fzn_gui_rpc_init(rpc_, ask, ask_ctx);
	summary_ = fzn_plain_label(tr("nothing moving"), this);
	summary_->setObjectName(QStringLiteral("traffic_summary"));
	summary_->setWordWrap(true);
	layout->addWidget(summary_);
	auto make_tree = [&](const char *name, const QString &first, const QString &spoken) {
		QTreeWidget *tree = new QTreeWidget(split);

		tree->setObjectName(QString::fromLatin1(name));
		/* NAMED FOR A SCREEN READER, sec 1120: two trees alike in shape
		 * are told apart by what they group by. */
		tree->setAccessibleName(spoken);
		tree->setColumnCount(5);
		tree->setHeaderLabels({ first, tr("rows"), tr("down"), tr("up"), tr("rate") });
		tree->setRootIsDecorated(true);
		split->addWidget(tree);
		return tree;
	};
	by_family_ = make_tree("traffic_by_family", tr("family"), tr("Traffic by family"));
	by_host_ = make_tree("traffic_by_host", tr("host"), tr("Traffic by host"));
	layout->addWidget(split, 1);
}

fzn_traffic_view::~fzn_traffic_view() { delete rpc_; }

QString fzn_traffic_view::summary() const { return summary_->text(); }

namespace {
struct bucket {
	uint64_t down = 0, up = 0, rate_down = 0, rate_up = 0, rows = 0;
	QList<const fzn_rpc_transfer_entry_t *> shown;
};
}

/* ONE TREE from one listing: a parent per family or host from the daemon's
 * sums, the rows that fitted beneath it, and what was open kept open. */
static void fill(QTreeWidget *tree, bool by_host, const fzn_rpc_transfer_list_resp_t *v,
                 const QHash<QString, QString> &names)
{
	QSet<QString> was_open;
	QMap<QString, bucket> groups;
	size_t i;

	for (int k = 0; k < tree->topLevelItemCount(); k++)
		if (tree->topLevelItem(k)->isExpanded())
			was_open.insert(tree->topLevelItem(k)->data(0, Qt::UserRole).toString());
	if (by_host)
		for (i = 0; i < v->host_count; i++) {
			const fzn_rpc_transfer_host_t &h = v->hosts[i];
			bucket &b = groups[QString::fromUtf8(h.peer_address, (int)h.peer_address_len)];

			b.down = h.bytes_down;
			b.up = h.bytes_up;
			b.rate_down = h.rate_down;
			b.rate_up = h.rate_up;
			b.rows = h.rows;
		}
	else
		for (i = 0; i < v->subsystem_count; i++) {
			const fzn_rpc_transfer_subsystem_t &t = v->subsystems[i];
			bucket &b = groups[QString::fromUtf8(t.family)];

			/* EVICTED BYTES IN A FAMILY'S TOTAL: they were counted, only
			 * their peer was lost, which is why the host tree cannot show
			 * them and the two need not agree. */
			b.down = t.bytes_down + t.evicted_down;
			b.up = t.bytes_up + t.evicted_up;
			b.rate_down = t.rate_down;
			b.rate_up = t.rate_up;
			b.rows = t.rows;
		}
	for (i = 0; i < v->count; i++) {
		const fzn_rpc_transfer_entry_t *e = &v->entries[i];

		groups[by_host ? QString::fromUtf8(e->peer_address, (int)e->peer_address_len)
		               : QString::fromUtf8(e->family)]
		        .shown.append(e);
	}
	/* THE READER'S PLACE KEPT across the refill (sec 1515, as sec 1225's
	 * views): a poll threw them to the top. */
	fzn_keep_place kept(tree);
	tree->clear();
	for (auto it = groups.constBegin(); it != groups.constEnd(); ++it) {
		const bucket &b = it.value();
		const QString rows = (uint64_t)b.shown.size() < b.rows
		                             ? QObject::tr("%1 of %2").arg(b.shown.size()).arg(b.rows)
		                             : QString::number(b.rows > (uint64_t)b.shown.size() ? b.rows
		                                                                                 : (uint64_t)b.shown.size());
		QTreeWidgetItem *parent = new QTreeWidgetItem(
		        tree, QStringList{ it.key(), rows, size_words(b.down), size_words(b.up),
		                           rate_words(b.rate_down, b.rate_up) });

		parent->setData(0, Qt::UserRole, it.key());
		for (const fzn_rpc_transfer_entry_t *e : b.shown) {
			/* UNDER A HOST, which family and which of its things; under a
			 * family, what it moves. */
			const QString other = by_host ? QObject::tr("%1: %2").arg(QString::fromUtf8(e->family), row_label(e, names))
			                              : row_label(e, names);

			new QTreeWidgetItem(parent, QStringList{ other, QString(), size_words(e->bytes_down),
			                                         size_words(e->bytes_up),
			                                         rate_words(e->rate_down, e->rate_up) });
		}
		parent->setExpanded(was_open.contains(it.key()));
	}
}

bool fzn_traffic_view::refresh()
{
	static fzn_rpc_transfer_list_resp_t v;
	fzn_rpc_library_list_all_t library = { nullptr, 0, 0 };
	QHash<QString, QString> names;
	uint64_t down = 0, up = 0, rate_down = 0, rate_up = 0;
	size_t i;

	if (fzn_rpc_transfer_list(&rpc_->c, &v) != FZN_RPC_OK) {
		summary_->setText(tr("Traffic could not be read: %1").arg(QString::fromUtf8(fzn_gui_rpc_silent(rpc_))));
		return false;
	}
	/* THE LIBRARY'S NAMES, where it lists any: a node with no catalogue
	 * names nothing, and each file is then its root. */
	if (fzn_rpc_library_list(&rpc_->c, &library) == FZN_RPC_OK)
		for (i = 0; i < library.count; i++)
			if (library.entries[i].name_len)
				names.insert(hex_of(library.entries[i].root, 32u),
				             QString::fromUtf8(library.entries[i].name, (int)library.entries[i].name_len));
	fzn_rpc_library_list_release(&library);
	/* ONE LISTING, BOTH TREES: two asks could disagree by a second. */
	fill(by_family_, false, &v, names);
	fill(by_host_, true, &v, names);
	for (i = 0; i < v.subsystem_count; i++) {
		down += v.subsystems[i].bytes_down + v.subsystems[i].evicted_down;
		up += v.subsystems[i].bytes_up + v.subsystems[i].evicted_up;
		rate_down += v.subsystems[i].rate_down;
		rate_up += v.subsystems[i].rate_up;
	}
	if (!v.rows_total) {
		summary_->setText(tr("nothing moving"));
		return true;
	}
	QString said = tr("%1 row(s) across %2 host(s) -- %3 in, %4 out -- now %5/s in, %6/s out")
	                       .arg(v.rows_total)
	                       .arg(v.hosts_total)
	                       .arg(size_words(down), size_words(up), size_words(rate_down), size_words(rate_up));
	/* SAID RATHER THAN SHOWN SILENTLY: the trees hold what fitted, and a
	 * reader counting rows would otherwise take it for everything. */
	if (v.rows_total > v.count)
		said += tr(" -- listing %1 of %2 rows").arg(v.count).arg(v.rows_total);
	summary_->setText(said);
	return true;
}
