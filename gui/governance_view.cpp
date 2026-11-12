/* See governance_view.h. */

#include "governance_view.h"

extern "C" {
#include "../local/vocabulary.h"
}

#include <QComboBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPushButton>
#include <QSpinBox>
#include <QTabWidget>
#include <QVBoxLayout>

/* A reply line at its longest. */
static const size_t REPLY_CAP = FZN_REPLY_MAX + 2u;

/* Pages of `list succession` read before giving up on a node that keeps
 * answering more: a page that adds nothing ends it sooner. */
static const int SUCCESSION_PAGES = 64;

static QString short_key(const QString &key)
{
	return key.size() > 16 ? key.left(16) + QStringLiteral("...") : key;
}

/* A row showing `text`, acting on `full`. */
static void add_row(QListWidget *list, const QString &text, const QString &full)
{
	auto *item = new QListWidgetItem(text, list);

	item->setData(Qt::UserRole, full);
	item->setToolTip(full);
}

/* A PART IS A TAB, so each fits a terminal's 24 rows and a small window: five
 * lists one above the other did not (qtty_render_test). */
static QVBoxLayout *part(QTabWidget *tabs, const QString &title)
{
	auto *page = new QWidget(tabs);
	auto *col = new QVBoxLayout(page);

	tabs->addTab(page, title);
	return col;
}

/* THE TAB'S TITLE WITH ITS COUNT, when there is one to wait on. */
static void titled(QTabWidget *tabs, int tab, const char *title, int count)
{
	tabs->setTabText(tab, count > 0 ? QStringLiteral("%1 (%2)").arg(QLatin1String(title)).arg(count)
	                                : QLatin1String(title));
}

/* SAID BEFORE THE CLICK, wrapped so it is read whole at any width. */
static QLabel *note_label(QWidget *owner, const QString &text)
{
	auto *l = new QLabel(text, owner);

	l->setWordWrap(true);
	return l;
}

static QLabel *status_label(QWidget *owner)
{
	auto *l = new QLabel(owner);

	l->setWordWrap(true);
	return l;
}

fzn_governance_view::fzn_governance_view(fzn_notebook_view_ask_t ask, void *ask_ctx,
                                         QWidget *parent)
        : QWidget(parent), m_ask(ask), m_ask_ctx(ask_ctx), m_k_held(0)
{
	auto *outer = new QVBoxLayout(this);
	QVBoxLayout *col;
	QHBoxLayout *row;

	m_key = new QLineEdit(this);
	m_key->setPlaceholderText(QStringLiteral("a key, 64 hex digits -- or select a row"));
	outer->addWidget(m_key);
	m_tabs = new QTabWidget(this);
	outer->addWidget(m_tabs, 1);

	/* THE ROOTS AND k. */
	col = part(m_tabs, QStringLiteral("Roots"));
	m_roots = new QListWidget(this);
	m_k = new QSpinBox(this);
	m_k->setRange(1, 255);
	m_k->setPrefix(QStringLiteral("k = "));
	m_add_root = new QPushButton(QStringLiteral("Add root"), this);
	m_remove_root = new QPushButton(QStringLiteral("Remove root"), this);
	m_set_k = new QPushButton(QStringLiteral("Set k"), this);
	m_roots_status = status_label(this);
	col->addWidget(m_roots, 1);
	/* TWO ROWS, sec 1041: the roots' buttons, then k -- on one, the view was 60
	 * px wider than a folding phone's 320 px cover screen. */
	row = new QHBoxLayout();
	row->addWidget(m_add_root);
	row->addWidget(m_remove_root);
	row->addStretch(1);
	col->addLayout(row);
	row = new QHBoxLayout();
	row->addWidget(m_k);
	row->addWidget(m_set_k);
	row->addStretch(1);
	col->addLayout(row);
	/* SAID BEFORE THE CLICK. */
	col->addWidget(note_label(this, QStringLiteral("k votes revoke a device. Changing roots or k "
	                                               "needs a root.")));
	col->addWidget(m_roots_status);

	/* THE VOTES HELD. */
	col = part(m_tabs, QStringLiteral("Votes"));
	m_votes = new QListWidget(this);
	m_vote = new QPushButton(QStringLiteral("Add this host's vote..."), this);
	m_vote_bar = new QWidget(this);
	{
		auto *bar = new QHBoxLayout(m_vote_bar);
		auto *yes = new QPushButton(QStringLiteral("Vote"), m_vote_bar);
		auto *no = new QPushButton(QStringLiteral("Cancel"), m_vote_bar);

		m_vote_question = new QLabel(m_vote_bar);
		m_vote_question->setWordWrap(true);
		bar->addWidget(m_vote_question, 1);
		bar->addWidget(yes);
		bar->addWidget(no);
		connect(yes, &QPushButton::clicked, this, [this]() { vote(); });
		connect(no, &QPushButton::clicked, this, [this]() { cancel_vote(); });
	}
	m_vote_bar->hide();
	m_votes_status = status_label(this);
	m_setting_votes = new QListWidget(this);
	m_vote_setting = new QPushButton(QStringLiteral("Vote for this value too"), this);
	col->addWidget(m_votes, 1);
	col->addWidget(m_vote);
	col->addWidget(m_vote_bar);
	col->addWidget(m_setting_votes, 1);
	col->addWidget(m_vote_setting);
	col->addWidget(m_votes_status);

	/* THE SUCCESSIONS. */
	col = part(m_tabs, QStringLiteral("Re-keys"));
	m_successions = new QListWidget(this);
	m_confirm_succession = new QPushButton(QStringLiteral("Confirm re-key"), this);
	m_successions_status = status_label(this);
	col->addWidget(m_successions, 1);
	col->addWidget(m_confirm_succession);
	col->addWidget(m_successions_status);

	/* THE STAGED CHANGES. */
	col = part(m_tabs, QStringLiteral("Staged"));
	m_staged = new QListWidget(this);
	m_confirm_staged = new QPushButton(QStringLiteral("Confirm change"), this);
	m_staged_status = status_label(this);
	col->addWidget(m_staged, 1);
	col->addWidget(note_label(this, QStringLiteral("Each reverts on every host at its deadline "
	                                               "unless confirmed.")));
	col->addWidget(m_confirm_staged);
	col->addWidget(m_staged_status);

	/* THE PROFILE. */
	col = part(m_tabs, QStringLiteral("Profile"));
	m_presets = new QComboBox(this);
	m_choose_preset = new QPushButton(QStringLiteral("Use profile"), this);
	m_preset_status = status_label(this);
	/* THE CHOOSER ABOVE ITS BUTTON, sec 1041, for the same screen. */
	col->addWidget(m_presets);
	row = new QHBoxLayout();
	row->addWidget(m_choose_preset);
	row->addStretch(1);
	col->addLayout(row);
	col->addWidget(m_preset_status);

	m_refresh = new QPushButton(QStringLiteral("Refresh"), this);
	outer->addWidget(m_refresh);

	/* EVERY INPUT NAMED for a screen reader, sec 1044: a placeholder and a
	 * spin box's prefix are not read as a name, and the page that decides who
	 * governs an estate met a screen reader with two unnamed boxes. */
	m_key->setAccessibleName(QStringLiteral("Key"));
	m_k->setAccessibleName(QStringLiteral("k, root signatures a revocation needs"));
	m_roots->setAccessibleName(QStringLiteral("Roots"));
	m_votes->setAccessibleName(QStringLiteral("Votes against a key"));
	m_setting_votes->setAccessibleName(QStringLiteral("Votes for a setting's value"));
	m_successions->setAccessibleName(QStringLiteral("Re-keys"));
	m_staged->setAccessibleName(QStringLiteral("Staged changes"));
	m_presets->setAccessibleName(QStringLiteral("Profile"));

	connect(m_add_root, &QPushButton::clicked, this, [this]() { add_root(); });
	connect(m_remove_root, &QPushButton::clicked, this, [this]() { remove_root(); });
	connect(m_set_k, &QPushButton::clicked, this, [this]() { set_k(m_k->value()); });
	connect(m_vote, &QPushButton::clicked, this, [this]() { ask_vote(); });
	connect(m_vote_setting, &QPushButton::clicked, this, [this]() { vote_setting(); });
	connect(m_confirm_succession, &QPushButton::clicked, this,
	        [this]() { confirm_succession(); });
	connect(m_confirm_staged, &QPushButton::clicked, this, [this]() { confirm_staged(); });
	connect(m_choose_preset, &QPushButton::clicked, this,
	        [this]() { choose_preset(m_presets->currentText()); });
	connect(m_refresh, &QPushButton::clicked, this, [this]() { refresh(); });
	refresh();
}

/* 1 ok, 0 refused with `detail` the node's words, -1 no answer. */
int fzn_governance_view::ask(const QString &line, QString *detail)
{
	char reply[REPLY_CAP];
	const uint8_t *d = nullptr;
	size_t len, d_len = 0;
	QByteArray bytes = line.toUtf8();
	fzn_reply_t kind;

	if (detail)
		detail->clear();
	if (!m_ask || bytes.size() >= (int)FZN_REQUEST_MAX || bytes.contains('\n'))
		return 0;
	len = m_ask(m_ask_ctx, bytes.constData(), reply, sizeof(reply));
	if (len == 0u || len >= sizeof(reply))
		return -1;
	while (len && (reply[len - 1u] == '\n' || reply[len - 1u] == '\r'))
		len--;
	kind = fzn_reply_of((const uint8_t *)reply, len, &d, &d_len);
	if (detail && d)
		*detail = QString::fromUtf8((const char *)d, (int)d_len);
	return kind == FZN_REPLY_OK ? 1 : 0;
}

/* `r` from ask() said in `status`: false when there is nothing to list. */
static bool said(int r, const QString &detail, QLabel *status)
{
	if (r < 0) {
		status->setText(QStringLiteral("The node did not answer."));
		return false;
	}
	if (r == 0) {
		status->setText(detail.isEmpty() ? QStringLiteral("The node refused.") : detail);
		return false;
	}
	return true;
}

/* `ok K N ITEM ...`: K and N read, and the items, as many as N says and
 * no more. False when it does not read. */
static bool counted(const QString &detail, int *k, QStringList *items)
{
	QStringList w = detail.split(QLatin1Char(' '), Qt::SkipEmptyParts);
	bool ok_k = false, ok_n = false;
	int n;

	if (w.size() < 2)
		return false;
	*k = w[0].toInt(&ok_k);
	n = w[1].toInt(&ok_n);
	if (!ok_k || !ok_n || n < 0)
		return false;
	*items = w.mid(2, n);
	return true;
}

bool fzn_governance_view::fill_roots()
{
	QString detail;
	QStringList items;
	int r = ask(QStringLiteral("list root"), &detail), k = 0;

	m_roots->clear();
	if (!said(r, detail, m_roots_status))
		return r >= 0;
	if (!counted(detail, &k, &items)) {
		m_roots_status->setText(QStringLiteral("The node's listing did not read."));
		return true;
	}
	for (const QString &item : items) {
		QString key = item.section(QLatin1Char(','), 0, 0);
		bool acting = item.section(QLatin1Char(','), 1, 1) == QLatin1String("acting");

		add_row(m_roots, acting ? short_key(key) + QStringLiteral("  (this host acts as it)")
		                        : short_key(key),
		        key);
	}
	titled(m_tabs, 0, "Roots", m_roots->count());
	m_k_held = k;
	m_k->setValue(k);
	m_roots_status->setText(QStringLiteral("%1 root(s); k is %2.").arg(m_roots->count()).arg(k));
	return true;
}

bool fzn_governance_view::fill_votes()
{
	QString detail;
	QStringList items;
	QStringList against;
	int r = ask(QStringLiteral("list vote"), &detail), k = 0;

	m_votes->clear();
	if (!said(r, detail, m_votes_status))
		return r >= 0;
	if (!counted(detail, &k, &items)) {
		m_votes_status->setText(QStringLiteral("The node's listing did not read."));
		return true;
	}
	/* ONE ROW PER KEY VOTED AGAINST, saying how near k it is: the standing
	 * votes counted, a withdrawn one named but not counted. */
	for (const QString &item : items) {
		QString key = item.section(QLatin1Char(','), 0, 0);

		if (!against.contains(key))
			against << key;
	}
	for (const QString &key : against) {
		int standing = 0, withdrawn = 0;

		for (const QString &item : items)
			if (item.section(QLatin1Char(','), 0, 0) == key) {
				if (item.section(QLatin1Char(','), 2, 2) == QLatin1String("withdrawn"))
					withdrawn++;
				else
					standing++;
			}
		add_row(m_votes,
		        QStringLiteral("%1  %2 of %3%4")
		                .arg(short_key(key))
		                .arg(standing)
		                .arg(k)
		                .arg(withdrawn ? QStringLiteral(", %1 withdrawn").arg(withdrawn)
		                               : QString()),
		        key);
	}
	titled(m_tabs, 1, "Votes", m_votes->count());
	m_votes_status->setText(m_votes->count() ? QStringLiteral("%1 key(s) voted against.")
	                                                   .arg(m_votes->count())
	                                         : QStringLiteral("No votes held."));
	return true;
}

/* THE VOTES ON A HOST'S SETTING, sec 909: records `vote/HOST/KEY` = VALUE, read
 * from `list record under vote/ FROM` (`ok FROM SHOWN MORE HOST,KEY,VERSION,VALUE
 * ...`), paged. A voter's newest record for a cell is its vote; the rows are
 * each value voted for, with how many voters stand for it. */
bool fzn_governance_view::fill_setting_votes()
{
	struct vote {
		QString voter, cell, value;
		qulonglong version;
	};
	QList<vote> newest;
	QStringList order;
	QString detail;
	int page, from = 0, i;

	m_setting_votes->clear();
	for (page = 0; page < SUCCESSION_PAGES; page++) {
		QStringList w;
		int r = ask(QStringLiteral("list record under vote/ %1").arg(from), &detail);
		bool ok_shown = false;
		int shown;

		if (r <= 0)
			return r == 0;
		w = detail.split(QLatin1Char(' '), Qt::SkipEmptyParts);
		shown = w.size() >= 3 ? w[1].toInt(&ok_shown) : -1;
		if (!ok_shown || shown != w.size() - 3)
			return true;
		for (i = 3; i < w.size(); i++) {
			vote v;
			int j;

			v.voter = w[i].section(QLatin1Char(','), 0, 0);
			v.cell = w[i].section(QLatin1Char(','), 1, 1);
			v.version = w[i].section(QLatin1Char(','), 2, 2).toULongLong();
			v.value = w[i].section(QLatin1Char(','), 3);
			for (j = 0; j < newest.size(); j++)
				if (newest[j].voter == v.voter && newest[j].cell == v.cell)
					break;
			if (j == newest.size())
				newest << v;
			else if (v.version >= newest[j].version)
				newest[j] = v;
		}
		from += shown;
		if (w[2] != QLatin1String("1") || shown == 0)
			break;
	}
	for (const vote &v : newest) {
		QString key = v.cell + QLatin1Char(' ') + v.value;

		if (!order.contains(key))
			order << key;
	}
	for (const QString &key : order) {
		QString cell = key.section(QLatin1Char(' '), 0, 0), value = key.section(QLatin1Char(' '), 1);
		/* `vote/HOST/KEY`: the host by its 16 hex, then the setting's key. */
		QString host = cell.section(QLatin1Char('/'), 1, 1);
		QString setting = cell.section(QLatin1Char('/'), 2);
		int voters = 0;

		for (const vote &v : newest)
			voters += v.cell == cell && v.value == value;
		add_row(m_setting_votes,
		        QStringLiteral("%1 = %2  on %3  %4 of %5")
		                .arg(setting, value, short_key(host))
		                .arg(voters)
		                .arg(m_k_held),
		        host + QLatin1Char(' ') + setting + QLatin1Char(' ') + value);
	}
	titled(m_tabs, 1, "Votes", m_votes->count() + m_setting_votes->count());
	return true;
}

bool fzn_governance_view::fill_successions()
{
	int page, from = 0, total = 0;
	QString detail;

	m_successions->clear();
	/* `ok TOTAL FROM OLD>NEW,STATE ...`, paged. */
	for (page = 0; page < SUCCESSION_PAGES; page++) {
		QStringList w;
		bool ok_total = false;
		int r = ask(QStringLiteral("list succession %1").arg(from), &detail), i, added = 0;

		if (!said(r, detail, m_successions_status))
			return r >= 0;
		w = detail.split(QLatin1Char(' '), Qt::SkipEmptyParts);
		if (w.size() < 2 || (total = w[0].toInt(&ok_total), !ok_total)) {
			m_successions_status->setText(QStringLiteral("The node's listing did not read."));
			return true;
		}
		for (i = 2; i < w.size(); i++) {
			QString pair = w[i].section(QLatin1Char(','), 0, 0);
			QString state = w[i].section(QLatin1Char(','), 1, 1);
			QString old_key = pair.section(QLatin1Char('>'), 0, 0);
			QString new_key = pair.section(QLatin1Char('>'), 1, 1);

			add_row(m_successions,
			        QStringLiteral("%1 -> %2  %3")
			                .arg(short_key(old_key), short_key(new_key), state),
			        old_key);
			added++;
		}
		from += added;
		if (added == 0 || from >= total)
			break;
	}
	titled(m_tabs, 2, "Re-keys", m_successions->count());
	m_successions_status->setText(m_successions->count()
	                                      ? QStringLiteral("%1 re-key(s).").arg(m_successions->count())
	                                      : QStringLiteral("No devices re-keyed."));
	return true;
}

bool fzn_governance_view::fill_staged()
{
	QString detail;
	QStringList w;
	bool ok = false;
	int r = ask(QStringLiteral("list staged"), &detail), n, i;

	m_staged->clear();
	if (!said(r, detail, m_staged_status))
		return r >= 0;
	/* `ok N TOKEN,DEADLINE,KEY ...`. */
	w = detail.split(QLatin1Char(' '), Qt::SkipEmptyParts);
	n = w.isEmpty() ? -1 : w[0].toInt(&ok);
	if (!ok || n < 0 || n > w.size() - 1) {
		m_staged_status->setText(QStringLiteral("The node's listing did not read."));
		return true;
	}
	for (i = 1; i <= n; i++) {
		QString token = w[i].section(QLatin1Char(','), 0, 0);
		QString deadline = w[i].section(QLatin1Char(','), 1, 1);
		QString key = w[i].section(QLatin1Char(','), 2);

		add_row(m_staged, QStringLiteral("%1  reverts at %2").arg(key, deadline), token);
	}
	titled(m_tabs, 3, "Staged", m_staged->count());
	m_staged_status->setText(m_staged->count() ? QStringLiteral("%1 change(s) waiting.")
	                                                     .arg(m_staged->count())
	                                           : QStringLiteral("No changes waiting."));
	return true;
}

bool fzn_governance_view::fill_preset()
{
	QString detail, current;
	QStringList items;
	int r = ask(QStringLiteral("get preset"), &detail);

	m_presets->clear();
	if (!said(r, detail, m_preset_status))
		return r >= 0;
	current = detail.trimmed();
	r = ask(QStringLiteral("list preset choices"), &detail);
	if (r > 0) {
		QStringList w = detail.split(QLatin1Char(' '), Qt::SkipEmptyParts);
		bool ok = false;
		int n = w.isEmpty() ? -1 : w[0].toInt(&ok);

		if (ok && n >= 0 && n <= w.size() - 1)
			items = w.mid(1, n);
	}
	m_presets->addItems(items);
	if (items.contains(current))
		m_presets->setCurrentText(current);
	m_choose_preset->setEnabled(!items.isEmpty());
	m_preset_status->setText(
	        items.isEmpty()
	                ? QStringLiteral("In force: %1. This build offers no other.").arg(current)
	                : QStringLiteral("In force: %1.").arg(current));
	return true;
}

bool fzn_governance_view::refresh()
{
	bool a = fill_roots(), b = fill_votes() && fill_setting_votes(), c = fill_successions(),
	     d = fill_staged(), e = fill_preset();

	return a && b && c && d && e;
}

void fzn_governance_view::set_key(const QString &key)
{
	m_key->setText(key);
}

void fzn_governance_view::select(QListWidget *list, int row)
{
	list->setCurrentRow(row);
}

/* The key typed, or the selected row's. */
QString fzn_governance_view::key_for(QListWidget *list) const
{
	QString key = m_key->text().trimmed();

	if (key.isEmpty() && list && list->currentItem())
		key = list->currentItem()->data(Qt::UserRole).toString();
	return key;
}

/* Ask `line`; on ok say `done` and read every part again. */
bool fzn_governance_view::act(const QString &line, QLabel *status, const QString &done)
{
	QString detail;
	int r = ask(line, &detail);

	if (!said(r, detail, status))
		return false;
	m_key->clear();
	refresh();
	status->setText(done);
	return true;
}

bool fzn_governance_view::add_root()
{
	QString key = m_key->text().trimmed();

	if (key.isEmpty()) {
		m_roots_status->setText(QStringLiteral("Type the new root's key first."));
		return false;
	}
	return act(QStringLiteral("add root ") + key, m_roots_status,
	           QStringLiteral("%1 is a root.").arg(short_key(key)));
}

bool fzn_governance_view::remove_root()
{
	QString key = key_for(m_roots);

	if (key.isEmpty()) {
		m_roots_status->setText(QStringLiteral("Type or select a root first."));
		return false;
	}
	return act(QStringLiteral("remove root ") + key, m_roots_status,
	           QStringLiteral("%1 is a root no more.").arg(short_key(key)));
}

bool fzn_governance_view::set_k(int k)
{
	return act(QStringLiteral("set quorum %1").arg(k), m_roots_status,
	           QStringLiteral("k is %1.").arg(k));
}

void fzn_governance_view::ask_vote()
{
	QString key = key_for(m_votes);

	if (key.isEmpty()) {
		m_votes_status->setText(QStringLiteral("Type or select the key to vote against first."));
		return;
	}
	m_vote_bar->setProperty("key", key);
	m_vote_question->setText(QStringLiteral("Vote to revoke %1? When k votes stand, its grant "
	                                        "falls on every host.")
	                                 .arg(short_key(key)));
	m_vote_bar->show();
}

bool fzn_governance_view::vote()
{
	QString key = m_vote_bar->property("key").toString();

	m_vote_bar->hide();
	if (key.isEmpty())
		return false;
	return act(QStringLiteral("revoke peer ") + key, m_votes_status,
	           QStringLiteral("This host voted against %1.").arg(short_key(key)));
}

void fzn_governance_view::cancel_vote()
{
	m_vote_bar->setProperty("key", QString());
	m_vote_bar->hide();
}

bool fzn_governance_view::vote_setting()
{
	QString line = m_setting_votes->currentItem()
	                       ? m_setting_votes->currentItem()->data(Qt::UserRole).toString()
	                       : QString();

	if (line.isEmpty()) {
		m_votes_status->setText(QStringLiteral("Select a value voted for first."));
		return false;
	}
	return act(QStringLiteral("add vote setting ") + line, m_votes_status,
	           QStringLiteral("This host voted for it too."));
}

bool fzn_governance_view::confirm_succession()
{
	QString key = key_for(m_successions);

	if (key.isEmpty()) {
		m_successions_status->setText(QStringLiteral("Select a re-key first."));
		return false;
	}
	return act(QStringLiteral("add succession ") + key, m_successions_status,
	           QStringLiteral("This host confirmed %1's re-key.").arg(short_key(key)));
}

bool fzn_governance_view::confirm_staged()
{
	QString token = m_staged->currentItem() ? m_staged->currentItem()->data(Qt::UserRole).toString()
	                                        : QString();

	if (token.isEmpty()) {
		m_staged_status->setText(QStringLiteral("Select a change first."));
		return false;
	}
	return act(QStringLiteral("add confirm ") + token, m_staged_status,
	           QStringLiteral("Confirmed; it will not revert."));
}

bool fzn_governance_view::choose_preset(const QString &name)
{
	if (name.isEmpty()) {
		m_preset_status->setText(QStringLiteral("Choose a profile first."));
		return false;
	}
	return act(QStringLiteral("set preset ") + name, m_preset_status,
	           QStringLiteral("Profile %1 chosen.").arg(name));
}

QStringList fzn_governance_view::rows(QListWidget *list) const
{
	QStringList out;
	int i;

	for (i = 0; i < list->count(); i++)
		out << list->item(i)->text();
	return out;
}

QStringList fzn_governance_view::tab_titles() const
{
	QStringList out;
	int i;

	for (i = 0; i < m_tabs->count(); i++)
		out << m_tabs->tabText(i);
	return out;
}

QString fzn_governance_view::preset() const
{
	return m_presets->currentText();
}

QStringList fzn_governance_view::preset_choices() const
{
	QStringList out;
	int i;

	for (i = 0; i < m_presets->count(); i++)
		out << m_presets->itemText(i);
	return out;
}

bool fzn_governance_view::vote_asked() const
{
	return !m_vote_bar->isHidden();
}

QString fzn_governance_view::roots_status() const { return m_roots_status->text(); }
QString fzn_governance_view::votes_status() const { return m_votes_status->text(); }
QString fzn_governance_view::successions_status() const { return m_successions_status->text(); }
QString fzn_governance_view::staged_status() const { return m_staged_status->text(); }
QString fzn_governance_view::preset_status() const { return m_preset_status->text(); }
