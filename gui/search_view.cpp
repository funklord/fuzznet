/* The one search, as a widget: gui/search_view.h, sec 1293. */
#include "search_view.h"
#include "combo.h"

#include "rpc_ask.h"

extern "C" {
#include "../local/rpc_encoding.h"
}

#include <QComboBox>
#include <QDateTime>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QTimer>
#include <QVBoxLayout>

#include <stdlib.h>
#include <string.h>

/* A ROW'S ITEM carries the hit's store and key. */
#define ROLE_STORE (Qt::UserRole)
#define ROLE_KEY (Qt::UserRole + 1)

/* HOW LONG A PAGE IS READ AGAIN while hosts are still answering: every
 * quarter second, as long as a remote asker's own wait (3 s, sec 1287)
 * and a little more, after which the page is what came. */
#define POLL_MS 250
#define POLLS_MAX 16

static QString words(const char *text, size_t len)
{
	char shown[4u * 128u + 1u];
	fzn_rpc_tty_escape(text, len, shown, sizeof shown);
	return QString::fromUtf8(shown);
}

/* WHERE A HIT WAS FOUND, in a person's words. */
static QString where_words(const char *store)
{
	if (!strcmp(store, "lines"))
		return QObject::tr("a conversation");
	if (!strcmp(store, "notes"))
		return QObject::tr("a note");
	if (!strcmp(store, "stickers"))
		return QObject::tr("a sticker");
	if (!strcmp(store, "contacts"))
		return QObject::tr("a contact");
	return QString::fromUtf8(store);
}

fzn_search_view::fzn_search_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent)
    : QWidget(parent), m_rpc(new fzn_gui_rpc), m_page(new fzn_rpc_search_page_t), m_polls(0), m_asked(false)
{
	fzn_gui_rpc_init(m_rpc, ask, ask_ctx);
	memset(m_page, 0, sizeof *m_page);

	m_find = new QLineEdit(this);
	m_find->setPlaceholderText(tr("Search everything"));
	m_find->setAccessibleName(tr("Words to search for"));
	m_find->setClearButtonEnabled(true);
	/* WHOM WITH: this user's own hosts, or one contact -- who is then told
	 * the words, and nobody else is (sec 1292). No wider than eight
	 * letters, so the row fits 320 px. */
	m_who = new fzn_combo_box(this);
	m_who->setAccessibleName(tr("Search what you share with a contact, or everything of yours"));
	m_who->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
	m_who->setMinimumContentsLength(8);
	m_who->addItem(tr("Mine"), QString());
	m_go = new QPushButton(tr("Search"), this);
	m_table = new QTableWidget(0, 3, this);
	m_table->setHorizontalHeaderLabels({ tr("Found"), tr("In"), tr("When") });
	m_table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
	m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_table->setSelectionMode(QAbstractItemView::SingleSelection);
	m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
	m_table->setAccessibleName(tr("What the search found"));
	m_more = new QPushButton(tr("More"), this);
	m_open_button = new QPushButton(tr("Open"), this);
	m_status = new QLabel(this);
	m_status->setWordWrap(true);
	/* WHAT IS SEARCHED, said before anything is (sec 1126's rule: no blank
	 * list). */
	m_status->setText(tr("Search your conversations, notes, stickers and contacts."));
	m_timer = new QTimer(this);
	m_timer->setInterval(POLL_MS);

	auto *top = new QHBoxLayout;
	top->addWidget(m_find, 1);
	top->addWidget(m_who);
	top->addWidget(m_go);
	auto *row = new QHBoxLayout;
	row->addWidget(m_open_button);
	row->addWidget(m_more);
	row->addStretch(1);
	auto *col = new QVBoxLayout(this);
	col->addLayout(top);
	col->addWidget(m_table, 1);
	col->addLayout(row);
	col->addWidget(m_status);

	connect(m_go, &QPushButton::clicked, [this]() { search(m_find->text(), m_who->currentData().toString()); });
	connect(m_find, &QLineEdit::returnPressed,
	        [this]() { search(m_find->text(), m_who->currentData().toString()); });
	connect(m_more, &QPushButton::clicked, [this]() { more(); });
	connect(m_open_button, &QPushButton::clicked, [this]() { open(); });
	connect(m_table, &QTableWidget::currentCellChanged, [this](int r, int, int, int) { select(r); });
	connect(m_table, &QTableWidget::cellActivated, [this](int r, int) {
		select(r);
		open();
	});
	connect(m_timer, &QTimer::timeout, [this]() {
		if (!poll() || settled() || ++m_polls >= POLLS_MAX)
			m_timer->stop();
	});
	m_more->setEnabled(false);
	select(-1);
}

fzn_search_view::~fzn_search_view()
{
	delete m_page;
	delete m_rpc;
}

void fzn_search_view::on_open(std::function<void(const QString &, const QByteArray &)> open)
{
	m_open = std::move(open);
}

bool fzn_search_view::refresh()
{
	fzn_rpc_peer_list_resp_t peers;
	const QString chosen = m_who->currentData().toString();
	size_t i;

	memset(&peers, 0, sizeof peers);
	if (fzn_rpc_peer_list(&m_rpc->c, &peers) != FZN_RPC_OK) {
		m_status->setText(QString::fromUtf8(fzn_gui_rpc_silent(m_rpc)));
		free(peers.entries);
		return m_rpc->c.answered;
	}
	m_who->blockSignals(true);
	m_who->clear();
	m_who->addItem(tr("Mine"), QString());
	for (i = 0; i < peers.count; i++)
		if (peers.entries[i].state == FZN_RPC_CONTACT_ACTIVE) {
			const QString name = QString::fromUtf8(peers.entries[i].name);
			m_who->addItem(tr("With %1").arg(name), name);
		}
	m_who->setCurrentIndex(qMax(0, m_who->findData(chosen)));
	m_who->blockSignals(false);
	free(peers.entries);
	return true;
}

/* ASK FOR A PAGE: the first, or the one after the last hit shown. */
bool fzn_search_view::ask_page(bool next)
{
	const QByteArray w = m_words.toUtf8(), with = m_with.toUtf8();
	fzn_rpc_search_hit_t after;
	size_t asked = 0;

	if (next) {
		if (!m_page->count)
			return false;
		after = m_page->hits[m_page->count - 1u];
	}
	m_timer->stop();
	if (fzn_rpc_search_fetch(&m_rpc->c, with.isEmpty() ? nullptr : with.constData(), w.constData(),
	                         next ? &after : nullptr, &asked)
	    != FZN_RPC_OK) {
		m_status->setText(QString::fromUtf8(fzn_gui_rpc_silent(m_rpc)));
		return false;
	}
	m_asked = true;
	m_polls = 0;
	if (!poll())
		return false;
	if (!settled())
		m_timer->start();
	return true;
}

bool fzn_search_view::search(const QString &text, const QString &with)
{
	m_words = text.trimmed();
	m_with = with;
	if (m_words.isEmpty()) {
		m_status->setText(tr("Say what to search for."));
		return false;
	}
	m_find->setText(m_words);
	m_who->setCurrentIndex(qMax(0, m_who->findData(with)));
	return ask_page(false);
}

bool fzn_search_view::more()
{
	return m_page->more && ask_page(true);
}

bool fzn_search_view::poll()
{
	if (!m_asked)
		return false;
	if (fzn_rpc_search_get(&m_rpc->c, m_page) != FZN_RPC_OK) {
		m_status->setText(QString::fromUtf8(fzn_gui_rpc_silent(m_rpc)));
		return false;
	}
	show_page();
	return true;
}

bool fzn_search_view::settled() const
{
	return m_asked && m_page->answered + m_page->late >= m_page->asked;
}

void fzn_search_view::show_page()
{
	size_t i;

	m_table->setRowCount((int)m_page->count);
	for (i = 0; i < m_page->count; i++) {
		const fzn_rpc_search_hit_t *h = &m_page->hits[i];
		const QString when = h->time_ms ? QDateTime::fromMSecsSinceEpoch((qint64)h->time_ms)
		                                          .toString(QStringLiteral("yyyy-MM-dd hh:mm"))
		                                : QString();

		m_table->setItem((int)i, 0, new QTableWidgetItem(words(h->snippet, h->snippet_len)));
		m_table->setItem((int)i, 1, new QTableWidgetItem(where_words(h->store)));
		m_table->setItem((int)i, 2, new QTableWidgetItem(when));
		m_table->item((int)i, 0)->setData(ROLE_STORE, QString::fromUtf8(h->store));
		m_table->item((int)i, 0)->setData(ROLE_KEY, QByteArray((const char *)h->key, (int)h->key_len));
	}
	/* HOW FAR ANSWERED: a page is not called whole while a host asked has
	 * not answered (sec 1287's fourth rule). */
	QString said = m_page->count ? tr("%n found", nullptr, (int)m_page->count) : tr("Nothing found");
	if (m_page->asked) {
		if (m_page->answered + m_page->late < m_page->asked)
			said += tr("; %1 of %2 host(s) answered so far").arg(m_page->answered).arg(m_page->asked);
		else if (m_page->late)
			said += tr("; %1 of %2 host(s) did not answer").arg(m_page->late).arg(m_page->asked);
	}
	/* NOT EVERYTHING SEARCHED, sec 1328: a page is never called whole when
	 * a store stopped short of what it holds. */
	if (m_page->partial)
		said += tr("; only the newest were searched");
	m_status->setText(said + QStringLiteral("."));
	m_more->setEnabled(m_page->more != 0);
	select(m_table->currentRow());
}

void fzn_search_view::select(int row)
{
	/* THE ROW CHOSEN ON THE TABLE TOO, sec 1356: `open` reads the table's
	 * current row, so a host calling `select(2); open()` as the header has
	 * it opened whatever row was current, or nothing (fuzzypickles' window
	 * suite). Set only where it moves, so the table's own signal, which
	 * comes here, does not come round again. */
	if (row >= 0 && row < m_table->rowCount() && row != m_table->currentRow())
		m_table->setCurrentCell(row, 0);
	m_open_button->setEnabled(row >= 0 && row < m_table->rowCount() && m_open);
}

bool fzn_search_view::open()
{
	const int r = m_table->currentRow();

	if (r < 0 || r >= m_table->rowCount() || !m_open)
		return false;
	m_open(m_table->item(r, 0)->data(ROLE_STORE).toString(), m_table->item(r, 0)->data(ROLE_KEY).toByteArray());
	return true;
}

QStringList fzn_search_view::rows() const
{
	QStringList out;

	for (int r = 0; r < m_table->rowCount(); r++)
		out << m_table->item(r, 0)->text() + QStringLiteral(" | ") + m_table->item(r, 1)->text()
		               + QStringLiteral(" | ") + m_table->item(r, 2)->text();
	return out;
}

QString fzn_search_view::status() const
{
	return m_status->text();
}
