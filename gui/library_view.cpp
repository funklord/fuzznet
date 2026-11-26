/* The files the catalogue names, as a widget: gui/library_view.h, sec 1131. */
#include "library_view.h"
#include "clock_words.h"
#include "choose_accessible.h"
#include "combo.h"
#include "size_words.h"
#include "keep_place.h"

#include "rpc_ask.h"

extern "C" {
#include "../local/rpc_encoding.h"
}

#include <QByteArray>
#include <QComboBox>
#include <QLineEdit>
#include <QFileDialog>
#include <QMenu>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QFileInfo>
#include <QLabel>
#include <QMimeDatabase>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

#include <stdlib.h>
#include <string.h>

/* A ROW'S ITEM carries the file's root, to ask for it by. */
#define ROLE_ROOT (Qt::UserRole)
#define ROLE_HERE (Qt::UserRole + 1)
#define ROLE_ARRIVING (Qt::UserRole + 2)

static QString failed_words(const fzn_gui_rpc *r)
{
	return QString::fromUtf8(fzn_gui_rpc_silent(r));
}

/* A LENGTH, for a file that plays: minutes and seconds; nothing otherwise. */
static QString length_words(uint64_t ms)
{
	if (!ms)
		return QString();
	return fzn_clock_words(ms / 1000u);
}

static QString words(const char *text, size_t len)
{
	char shown[4u * 256u + 1u];
	fzn_rpc_tty_escape(text, len, shown, sizeof shown);
	return QString::fromUtf8(shown);
}

fzn_library_view::fzn_library_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent)
    : QWidget(parent), m_rpc(new fzn_gui_rpc)
{
	fzn_gui_rpc_init(m_rpc, ask, ask_ctx);

	m_table = new QTableWidget(0, 5, this);
	m_table->setHorizontalHeaderLabels(
	        { tr("File"), tr("Kind"), tr("Size"), tr("Length"), tr("Where") });
	m_table->horizontalHeader()->setStretchLastSection(true);
	m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_table->setSelectionMode(QAbstractItemView::SingleSelection);
	m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
	m_table->setAccessibleName(tr("The library's files"));
	/* FINDING A FILE, sec 1207: by a word of its name or kind, and by kind.
	 * The chooser no wider than eight letters, so the row fits 320 px. */
	m_find = new QLineEdit(this);
	m_find->setPlaceholderText(tr("Find a file"));
	m_find->setAccessibleName(tr("Find a file by its name or kind"));
	m_find->setClearButtonEnabled(true);
	fzn_name_clear_button(m_find);
	m_kind = new fzn_combo_box(this);
	m_kind->setAccessibleName(tr("Show one kind of file"));
	m_kind->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
	m_kind->setMinimumContentsLength(8);
	m_kind->addItem(tr("Every kind"), QString());
	m_fetch = new QPushButton(tr("Get the file"), this);
	m_play_button = new QPushButton(tr("Play"), this);
	m_share = new QPushButton(tr("Share..."), this);
	m_save = new QPushButton(tr("Save..."), this);
	m_add = new QPushButton(tr("Add..."), this);
	m_add->setToolTip(tr("Add files from this machine to the library"));
	m_verify = new QPushButton(tr("Verify"), this);
	m_remove = new QPushButton(tr("Remove"), this);
	m_refresh = new QPushButton(tr("Refresh"), this);
	m_status = new QLabel(this);
	m_status->setWordWrap(true);

	auto *row = new QHBoxLayout;
	row->addWidget(m_play_button);
	row->addWidget(m_fetch);
	row->addWidget(m_refresh);
	row->addStretch(1);
	/* TWO ROWS MORE, two buttons each: four in one row made the view 360 px,
	 * past a 320 px cover screen. */
	auto *more = new QHBoxLayout;
	more->addWidget(m_add);
	more->addWidget(m_share);
	more->addWidget(m_save);
	more->addStretch(1);
	auto *care = new QHBoxLayout;
	care->addWidget(m_verify);
	care->addWidget(m_remove);
	care->addStretch(1);
	auto *find = new QHBoxLayout;
	find->addWidget(m_find, 1);
	find->addWidget(m_kind);
	auto *col = new QVBoxLayout(this);
	col->addLayout(find);
	col->addWidget(m_table, 1);
	col->addLayout(row);
	col->addLayout(more);
	col->addLayout(care);
	col->addWidget(m_status);

	connect(m_table, &QTableWidget::currentCellChanged,
	        [this](int r, int, int, int) { select(r); });
	/* A SCREEN READER CHOOSES TOO, sec 1423: its double tap only selects. */
	fzn_choose_on_accessible_select(m_table, nullptr);
	connect(m_fetch, &QPushButton::clicked, [this]() { fetch(); });
	connect(m_play_button, &QPushButton::clicked, [this]() { play(); });
	connect(m_verify, &QPushButton::clicked, [this]() { verify(); });
	connect(m_remove, &QPushButton::clicked, [this]() { remove(); });
	connect(m_add, &QPushButton::clicked, [this]() {
		const QStringList paths = QFileDialog::getOpenFileNames(this, tr("Add to the library"));
		if (!paths.isEmpty())
			add_files(paths);
	});
	connect(m_save, &QPushButton::clicked, [this]() {
		const QString path = QFileDialog::getSaveFileName(this, tr("Save the file"), chosen_name());
		if (!path.isEmpty())
			save_to(path);
	});
	/* SHARE: every contact, each contact and group by name, and each share
	 * there is to take back. */
	connect(m_share, &QPushButton::clicked, [this]() {
		fzn_rpc_peer_list_resp_t peers;
		fzn_rpc_group_list_resp_t groups;
		QMenu menu(this);
		size_t i;

		memset(&peers, 0, sizeof peers);
		memset(&groups, 0, sizeof groups);
		menu.addAction(tr("With every contact"))->setData(QString());
		if (fzn_rpc_peer_list(&m_rpc->c, &peers) == FZN_RPC_OK)
			for (i = 0; i < peers.count; i++)
				if (peers.entries[i].state == FZN_RPC_CONTACT_ACTIVE)
					menu.addAction(tr("With %1").arg(QString::fromUtf8(peers.entries[i].name)))
					        ->setData(QString::fromUtf8(peers.entries[i].name));
		if (fzn_rpc_group_list(&m_rpc->c, &groups) == FZN_RPC_OK)
			for (i = 0; i < groups.count; i++) {
				const QString g = QStringLiteral("@") + QString::fromUtf8(groups.entries[i].name,
				                                                          (int)groups.entries[i].name_len);
				menu.addAction(tr("With %1").arg(g))->setData(g);
			}
		free(peers.entries);
		free(groups.entries);
		if (!m_shares.isEmpty()) {
			menu.addSeparator();
			for (const QString &s : m_shares)
				menu.addAction(tr("No longer with %1").arg(s))->setData(QStringLiteral("-") + s);
		}
		QAction *a = menu.exec(m_share->mapToGlobal(QPoint(0, m_share->height())));
		if (!a)
			return;
		const QString to = a->data().toString();
		if (to.startsWith(QLatin1Char('-')))
			unshare(to.mid(1) == tr("every contact") ? QString() : to.mid(1));
		else
			share(to);
	});
	connect(m_refresh, &QPushButton::clicked, [this]() { refresh(); });
	connect(m_find, &QLineEdit::textChanged, [this](const QString &) { apply_filter(); });
	connect(m_kind, QOverload<int>::of(&QComboBox::currentIndexChanged), [this](int) { apply_filter(); });
	select(-1);
}

fzn_library_view::~fzn_library_view() { delete m_rpc; }

int fzn_library_view::add_files(const QStringList &paths)
{
	QMimeDatabase kinds;
	int added = 0;

	for (const QString &path : paths) {
		const QByteArray at = path.toUtf8();
		const QByteArray name = QFileInfo(path).fileName().toUtf8();
		const QString kind = kinds.mimeTypeForFile(path).name();
		fzn_rpc_blob_add_resp_t stored;
		fzn_rpc_library_add_req_t entry;

		if (fzn_rpc_blob_add(&m_rpc->c, at.constData(), (size_t)at.size(), FZN_RPC_BLOB_TIER_PRIVATE, &stored)
		    != FZN_RPC_OK) {
			m_status->setText(tr("%1 was not added: %2")
			                          .arg(QString::fromUtf8(name), QString::fromUtf8(fzn_gui_rpc_silent(m_rpc))));
			break;
		}
		memset(&entry, 0, sizeof(entry));
		memcpy(entry.root, stored.root, sizeof(entry.root));
		memcpy(entry.content_key, stored.key, sizeof(entry.content_key));
		entry.size = stored.byte_len;
		entry.name_len = (size_t)qMin(name.size(), (int)sizeof(entry.name) - 1);
		memcpy(entry.name, name.constData(), entry.name_len);
		/* THE SYSTEM'S NAME FOR ITS KIND, where it has one past "a run of
		 * bytes": the music and photo catalogues sort by it. */
		if (kind != QStringLiteral("application/octet-stream") && kind.size() < (int)sizeof(entry.kind)) {
			entry.kind_len = (size_t)kind.toLatin1().size();
			memcpy(entry.kind, kind.toLatin1().constData(), entry.kind_len);
		}
		if (fzn_rpc_library_add(&m_rpc->c, &entry) != FZN_RPC_OK) {
			m_status->setText(tr("%1 was stored and not catalogued: %2")
			                          .arg(QString::fromUtf8(name), QString::fromUtf8(fzn_gui_rpc_silent(m_rpc))));
			break;
		}
		added++;
	}
	if (added) {
		const QString said = m_status->text();
		refresh();
		m_status->setText(added == paths.size() ? tr("Added %n file(s) to the library.", nullptr, added) : said);
	}
	return added;
}

bool fzn_library_view::refresh()
{
	fzn_rpc_library_list_all_t all;
	size_t i;
	fzn_keep_answer answer(m_status);

	memset(&all, 0, sizeof all);
	if (fzn_rpc_library_list(&m_rpc->c, &all) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		fzn_keep_answer::said(m_status);
		fzn_rpc_library_list_release(&all);
		return m_rpc->c.answered;
	}
	/* THE PERSON'S PLACE AND THEIR LAST ANSWER, kept across the refill
	 * (sec 1225). */
	fzn_keep_place place(m_table, 0, ROLE_ROOT);
	m_table->setRowCount((int)all.count);
	for (i = 0; i < all.count; i++) {
		const fzn_rpc_library_list_entry_t *e = &all.entries[i];
		/* HERE IS THE BYTES ON THIS HOST; the others are claims. */
		const unsigned others = e->holders - (e->held_here && e->holders ? 1u : 0u);
		QString where = e->arriving_permille
		                        ? tr("arriving, %1%").arg(e->arriving_permille / 10u)
		                : e->held_here ? (others ? tr("here, and on %1 other host(s)").arg(others)
		                                       : tr("here"))
		                             : others ? tr("on %1 host(s)").arg(others)
		                                      : tr("nowhere seen");
		if (e->arriving_permille && others)
			where += tr(", from %1 host(s)").arg(others);
		m_table->setItem((int)i, 0, new QTableWidgetItem(words(e->name, e->name_len)));
		m_table->setItem((int)i, 1, new QTableWidgetItem(words(e->kind, e->kind_len)));
		/* A SIZE ONLY WHERE ONE IS KNOWN: the catalogue names none, and a
		 * file not held here has no bytes here to measure. */
		m_table->setItem((int)i, 2, new QTableWidgetItem(e->size ? fzn_size_words(e->size) : QString()));
		m_table->setItem((int)i, 3, new QTableWidgetItem(length_words(e->duration_ms)));
		m_table->setItem((int)i, 4, new QTableWidgetItem(where));
		m_table->item((int)i, 0)->setData(ROLE_ROOT, QByteArray((const char *)e->root, 32));
		m_table->item((int)i, 0)->setData(ROLE_HERE, (bool)e->held_here);
		m_table->item((int)i, 0)->setData(ROLE_ARRIVING, e->arriving_permille != 0);
	}
	m_status->setText(all.count ? QString() : tr("The library is empty."));
	m_filter_said.clear();
	fzn_rpc_library_list_release(&all);
	/* THE KINDS THE FILES HAVE NOW, the one chosen kept while a file has it. */
	{
		const QString chosen = m_kind->currentData().toString();
		QStringList found;

		for (int r = 0; r < m_table->rowCount(); r++) {
			const QString k = m_table->item(r, 1)->text();
			if (!k.isEmpty() && !found.contains(k))
				found << k;
		}
		found.sort();
		m_kind->blockSignals(true);
		m_kind->clear();
		m_kind->addItem(tr("Every kind"), QString());
		for (const QString &k : found)
			m_kind->addItem(k, k);
		m_kind->setCurrentIndex(qMax(0, m_kind->findData(chosen)));
		m_kind->blockSignals(false);
	}
	select(place.restore());
	apply_filter();
	answer.restore();
	return true;
}

/* EACH FILE SHOWN OR HIDDEN by what is being found, and said: how many of
 * how many, or that none matches. */
void fzn_library_view::apply_filter()
{
	const QString text = m_find->text().trimmed();
	const QString kind = m_kind->currentData().toString();
	int shown = 0, r;

	for (r = 0; r < m_table->rowCount(); r++) {
		const QString name = m_table->item(r, 0)->text();
		const QString k = m_table->item(r, 1)->text();
		const bool show = (text.isEmpty() || name.contains(text, Qt::CaseInsensitive)
		                   || k.contains(text, Qt::CaseInsensitive))
		                  && (kind.isEmpty() || k == kind);

		m_table->setRowHidden(r, !show);
		shown += show ? 1 : 0;
	}
	/* A FILE CHOSEN AND NOW HIDDEN is not acted on unseen. */
	r = m_table->currentRow();
	if (r >= 0 && m_table->isRowHidden(r)) {
		m_table->setCurrentCell(-1, -1);
		select(-1);
	}
	if (text.isEmpty() && kind.isEmpty()) {
		if (!m_filter_said.isEmpty() && m_status->text() == m_filter_said)
			m_status->clear();
		m_filter_said.clear();
		return;
	}
	if (!m_table->rowCount())
		return;
	m_filter_said = shown ? tr("%1 of %2 files shown.").arg(shown).arg(m_table->rowCount())
	                      : tr("No file matches.");
	m_status->setText(m_filter_said);
}

void fzn_library_view::set_find(const QString &text) { m_find->setText(text); }

void fzn_library_view::set_kind(const QString &kind)
{
	m_kind->setCurrentIndex(qMax(0, m_kind->findData(kind.isEmpty() ? QString() : kind)));
}

QStringList fzn_library_view::kinds() const
{
	QStringList out;
	for (int i = 1; i < m_kind->count(); i++)
		out << m_kind->itemText(i);
	return out;
}

void fzn_library_view::select(int row)
{
	bool chosen = row >= 0 && row < m_table->rowCount() && !m_table->isRowHidden(row);
	if (chosen && m_table->currentRow() != row)
		m_table->setCurrentCell(row, 0);
	/* NOTHING CHOSEN CLEARS THE ROW TOO: an act reads the current row, and a
	 * refresh no longer clears it (sec 1225). */
	if (!chosen && m_table->currentRow() >= 0)
		m_table->setCurrentCell(-1, -1);
	/* A FILE ALREADY HERE is not asked for again. */
	/* A FILE ALREADY HERE, or on its way, is not asked for again. */
	m_fetch->setEnabled(chosen && !m_table->item(row, 0)->data(ROLE_HERE).toBool()
	                    && !m_table->item(row, 0)->data(ROLE_ARRIVING).toBool());
	/* WHAT A FILE HERE OFFERS: played while it arrives too; the rest want
	 * its bytes on this host. */
	const bool here = chosen && m_table->item(row, 0)->data(ROLE_HERE).toBool();
	const bool arriving = chosen && m_table->item(row, 0)->data(ROLE_ARRIVING).toBool();
	m_play_button->setEnabled((here || arriving) && m_play);
	m_share->setEnabled(here);
	m_save->setEnabled(here);
	m_verify->setEnabled(here);
	m_remove->setEnabled(here);
	read_shares();
}

bool fzn_library_view::fetch()
{
	int row = m_table->currentRow();
	if (row < 0 || row >= m_table->rowCount() || m_table->item(row, 0)->data(ROLE_HERE).toBool()
	    || m_table->item(row, 0)->data(ROLE_ARRIVING).toBool())
		return false;
	QByteArray root = m_table->item(row, 0)->data(ROLE_ROOT).toByteArray();
	fzn_rpc_blob_fetch_resp_t out;
	if (fzn_rpc_blob_fetch(&m_rpc->c, (const uint8_t *)root.constData(), &out) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	m_status->setText(tr("Asked for %1. It arrives in the background.").arg(m_table->item(row, 0)->text()));
	return true;
}

QStringList fzn_library_view::rows() const
{
	QStringList out;
	for (int i = 0; i < m_table->rowCount(); i++) {
		QStringList cells;
		if (m_table->isRowHidden(i))
			continue;
		for (int k = 0; k < m_table->columnCount(); k++)
			cells << m_table->item(i, k)->text();
		out << cells.join(QStringLiteral(" | "));
	}
	return out;
}

QString fzn_library_view::status() const { return m_status->text(); }

void fzn_library_view::on_play(std::function<void(const QByteArray &, const QString &)> play)
{
	m_play = play;
	select(m_table->currentRow());
}

QByteArray fzn_library_view::chosen_root() const
{
	const int row = m_table->currentRow();
	return row >= 0 && row < m_table->rowCount() ? m_table->item(row, 0)->data(ROLE_ROOT).toByteArray()
	                                             : QByteArray();
}

QString fzn_library_view::chosen_name() const
{
	const int row = m_table->currentRow();
	return row >= 0 && row < m_table->rowCount() ? m_table->item(row, 0)->text() : QString();
}

static bool chosen_here(const QTableWidget *t)
{
	const int row = t->currentRow();
	return row >= 0 && row < t->rowCount() && t->item(row, 0)->data(ROLE_HERE).toBool();
}

/* WHOM THE CHOSEN FILE IS SHARED WITH, read when it is chosen. */
void fzn_library_view::read_shares()
{
	fzn_rpc_file_share_t *s = nullptr;
	size_t room = 0, n = 0, i;
	const QByteArray root = chosen_root();

	m_shares.clear();
	if (root.size() != 32 || !chosen_here(m_table)
	    || fzn_rpc_file_shares(&m_rpc->c, (const uint8_t *)root.constData(), &s, &room, &n) != FZN_RPC_OK) {
		free(s);
		return;
	}
	for (i = 0; i < n; i++)
		m_shares << (s[i].kind == FZN_RPC_FILE_SHARE_EVERYONE ? tr("every contact")
		             : s[i].kind == FZN_RPC_FILE_SHARE_GROUP  ? QStringLiteral("@") + QString::fromUtf8(s[i].name)
		                                                      : QString::fromUtf8(s[i].name));
	free(s);
	if (!m_shares.isEmpty())
		m_status->setText(tr("Shared with %1.").arg(m_shares.join(QStringLiteral(", "))));
}

QStringList fzn_library_view::shares() const { return m_shares; }

bool fzn_library_view::play()
{
	const int row = m_table->currentRow();
	const QByteArray root = chosen_root();
	if (root.size() != 32 || !m_play
	    || !(m_table->item(row, 0)->data(ROLE_HERE).toBool() || m_table->item(row, 0)->data(ROLE_ARRIVING).toBool()))
		return false;
	m_play(root, chosen_name());
	return true;
}

bool fzn_library_view::share(const QString &to)
{
	const QByteArray root = chosen_root(), who = to.toUtf8();
	if (root.size() != 32 || !chosen_here(m_table))
		return false;
	if (fzn_rpc_file_share(&m_rpc->c, (const uint8_t *)root.constData(), to.isEmpty() ? nullptr : who.constData(), 1)
	    != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	read_shares();
	m_status->setText(to.isEmpty() ? tr("%1 is shared with every contact.").arg(chosen_name())
	                               : tr("%1 is shared with %2.").arg(chosen_name(), to));
	return true;
}

bool fzn_library_view::unshare(const QString &to)
{
	const QByteArray root = chosen_root(), who = to.toUtf8();
	if (root.size() != 32 || !chosen_here(m_table))
		return false;
	if (fzn_rpc_file_share(&m_rpc->c, (const uint8_t *)root.constData(), to.isEmpty() ? nullptr : who.constData(), 0)
	    != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	read_shares();
	m_status->setText(to.isEmpty() ? tr("%1 is no longer shared with every contact.").arg(chosen_name())
	                               : tr("%1 is no longer shared with %2.").arg(chosen_name(), to));
	return true;
}

bool fzn_library_view::save_to(const QString &path)
{
	const QByteArray root = chosen_root(), where = path.toUtf8();
	fzn_rpc_blob_export_resp_t out;
	if (root.size() != 32 || path.isEmpty() || !chosen_here(m_table))
		return false;
	if (fzn_rpc_blob_export(&m_rpc->c, (const uint8_t *)root.constData(), nullptr, where.constData(),
	                        (size_t)where.size(), &out)
	    != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	m_status->setText(tr("Saved %1 to %2.").arg(fzn_size_words(out.byte_len), path));
	return true;
}

bool fzn_library_view::verify()
{
	const QByteArray root = chosen_root();
	fzn_rpc_blob_scrub_resp_t out;
	uint64_t from = 0, checked = 0, dropped = 0;
	if (root.size() != 32 || !chosen_here(m_table))
		return false;
	/* EVERY SLICE, sec 1490: the client answers a slice and where to go
	 * on. fuzznetd checks a whole file in one, but "every one whole" is
	 * said only once the answer says done -- never of a file's start. */
	for (;;) {
		if (fzn_rpc_blob_scrub(&m_rpc->c, (const uint8_t *)root.constData(), from, &out) != FZN_RPC_OK) {
			m_status->setText(failed_words(m_rpc));
			return false;
		}
		checked += out.checked;
		dropped += out.dropped;
		if (out.done)
			break;
		if (out.next_index <= from) {
			m_status->setText(tr("The check stopped at piece %1 of %2.").arg(from).arg(out.leaf_count));
			return false;
		}
		from = out.next_index;
	}
	/* A BROKEN PIECE IS DROPPED, to be fetched again: said so. */
	m_status->setText(dropped ? tr("%1 pieces checked; %2 broken, dropped to be fetched again.")
	                                    .arg(checked)
	                                    .arg(dropped)
	                          : tr("%1 pieces checked, every one whole.").arg(checked));
	return true;
}

bool fzn_library_view::remove()
{
	const QByteArray root = chosen_root();
	const QString name = chosen_name();
	if (root.size() != 32 || !chosen_here(m_table))
		return false;
	if (fzn_rpc_file_remove(&m_rpc->c, (const uint8_t *)root.constData()) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	refresh();
	/* OTHER DEVICES' COPIES STAY, so it can be fetched again from one. */
	m_status->setText(tr("%1 is removed from this device.").arg(name));
	return true;
}

