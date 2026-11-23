/* What another program shares, sent to a conversation: share_view.h,
 * fuzznet sec 1257. */
#include "share_view.h"
#include "choose_accessible.h"
#include "notice_line.h"
#include "rpc_ask.h"
#include "size_words.h"

#include <QByteArray>
#include <QFileInfo>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPushButton>
#include <QVBoxLayout>

#include <utility>

#include <string.h>

static QString failed_words(const fzn_gui_rpc *r) { return QString::fromUtf8(fzn_gui_rpc_silent(r)); }

fzn_share_view::fzn_share_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent)
    : QWidget(parent), m_rpc(new fzn_gui_rpc)
{
	fzn_gui_rpc_init(m_rpc, ask, ask_ctx);
	m_what = new QLabel(this);
	m_what->setWordWrap(true);
	m_text = new QLineEdit(this);
	m_text->setAccessibleName(tr("The words to send"));
	m_filter = new QLineEdit(this);
	m_filter->setPlaceholderText(tr("Find a person or a group"));
	m_filter->setAccessibleName(tr("Find a conversation"));
	m_list = new QListWidget(this);
	m_list->setAccessibleName(tr("Send to"));
	m_send = new QPushButton(tr("Send"), this);
	m_notice = new fzn_notice_line(this);

	auto *col = new QVBoxLayout(this);
	col->addWidget(m_what);
	col->addWidget(m_text);
	col->addWidget(m_filter);
	col->addWidget(m_list, 1);
	col->addWidget(m_notice);
	col->addWidget(m_send);
	connect(m_filter, &QLineEdit::textChanged, [this](const QString &w) { set_filter(w); });
	connect(m_list, &QListWidget::currentRowChanged, [this](int r) { choose(r); });
	/* A SCREEN READER CHOOSES TOO, sec 1423: its double tap only selects. */
	fzn_choose_on_accessible_select(m_list, nullptr);
	connect(m_list, &QListWidget::itemActivated, [this](QListWidgetItem *) { (void)send(); });
	connect(m_send, &QPushButton::clicked, [this]() { (void)send(); });
	m_text->hide();
	m_send->setEnabled(false);
	m_what->setText(tr("Nothing has been shared."));
}

fzn_share_view::~fzn_share_view() { delete m_rpc; }

bool fzn_share_view::set_file(const QString &path)
{
	const QFileInfo f(path);

	m_file.clear();
	m_text->clear();
	m_text->hide();
	if (path.isEmpty() || !f.isFile()) {
		m_what->setText(tr("Nothing has been shared."));
		m_notice->say(path.isEmpty() ? QString() : tr("%1 is not a file this can send.").arg(path));
		choose(m_list->currentRow());
		return false;
	}
	m_file = path;
	m_what->setText(tr("Send %1, %2, to:").arg(f.fileName(), fzn_size_words((uint64_t)f.size())));
	m_notice->clear();
	choose(m_list->currentRow());
	return true;
}

bool fzn_share_view::set_text(const QString &text)
{
	m_file.clear();
	m_text->setText(text);
	m_text->setVisible(true);
	m_what->setText(text.trimmed().isEmpty() ? tr("Nothing has been shared.") : tr("Send these words to:"));
	m_notice->clear();
	choose(m_list->currentRow());
	return !text.trimmed().isEmpty();
}

/* EVERY CONVERSATION THIS USER HAS: contacts by their names, then groups
 * as `@NAME`, each list as the node gives it. */
bool fzn_share_view::refresh()
{
	auto *peers = new fzn_rpc_peer_list_resp_t;
	auto *groups = new fzn_rpc_group_list_resp_t;
	bool ok = true;

	memset(peers, 0, sizeof(*peers));
	memset(groups, 0, sizeof(*groups));
	m_all.clear();
	if (fzn_rpc_peer_list(&m_rpc->c, peers) == FZN_RPC_OK) {
		for (size_t i = 0; i < peers->count; i++)
			m_all << QString::fromUtf8(peers->entries[i].name, (int)peers->entries[i].name_len);
	} else {
		m_notice->say(failed_words(m_rpc));
		ok = false;
	}
	/* A NODE KEEPING NO GROUPS still has its contacts. */
	if (ok && fzn_rpc_group_list(&m_rpc->c, groups) == FZN_RPC_OK)
		for (size_t i = 0; i < groups->count; i++)
			m_all << QLatin1Char('@') + QString::fromUtf8(groups->entries[i].name, (int)groups->entries[i].name_len);
	fzn_rpc_peer_list_release(peers);
	fzn_rpc_group_list_release(groups);
	delete peers;
	delete groups;
	fill();
	return ok;
}

/* THE LIST AGAIN, narrowed by the filter, the conversation chosen kept. */
void fzn_share_view::fill()
{
	const QString was = chosen(), words = m_filter->text().trimmed();

	m_list->clear();
	for (const QString &name : m_all)
		if (words.isEmpty() || name.contains(words, Qt::CaseInsensitive))
			m_list->addItem(name);
	for (int i = 0; i < m_list->count(); i++)
		if (m_list->item(i)->text() == was)
			m_list->setCurrentRow(i);
	choose(m_list->currentRow());
}

void fzn_share_view::set_filter(const QString &words)
{
	if (m_filter->text() != words)
		m_filter->setText(words); /* textChanged comes back here */
	else
		fill();
}

void fzn_share_view::choose(int row)
{
	if (row >= 0 && m_list->currentRow() != row && row < m_list->count())
		m_list->setCurrentRow(row);
	m_send->setEnabled(!chosen().isEmpty() && (!m_file.isEmpty() || !m_text->text().trimmed().isEmpty()));
}

bool fzn_share_view::send()
{
	const QString to = chosen();
	const bool group = to.startsWith(QLatin1Char('@'));
	const QByteArray name = (group ? to.mid(1) : to).toUtf8();

	if (to.isEmpty() || (m_file.isEmpty() && m_text->text().trimmed().isEmpty()))
		return false;
	if (!m_file.isEmpty()) {
		/* STORED HERE, PRIVATE, and sent as a line, which grants it to the
		 * conversation -- the conversation's own Send a file. */
		const QByteArray at = m_file.toUtf8(), base = QFileInfo(m_file).fileName().toUtf8();
		fzn_rpc_blob_add_resp_t stored;

		if (fzn_rpc_blob_add(&m_rpc->c, at.constData(), (size_t)at.size(), FZN_RPC_BLOB_TIER_PRIVATE, &stored)
		            != FZN_RPC_OK
		    || fzn_rpc_message_attach(&m_rpc->c, name.constData(), (size_t)name.size(), group ? 1 : 0, stored.root,
		                              base.constData(), (size_t)base.size())
		               != FZN_RPC_OK) {
			m_notice->say(failed_words(m_rpc));
			return false;
		}
		m_notice->say(tr("Sent %1 to %2.").arg(QString::fromUtf8(base), to));
	} else {
		const QByteArray text = m_text->text().toUtf8();

		if ((group ? fzn_rpc_group_send(&m_rpc->c, name.constData(), (size_t)name.size(), text.constData(),
		                                (size_t)text.size())
		           : fzn_rpc_message_send(&m_rpc->c, name.constData(), (size_t)name.size(), text.constData(),
		                                  (size_t)text.size()))
		    != FZN_RPC_OK) {
			/* THE WORDS KEPT, so nothing is lost to a refusal. */
			m_notice->say(failed_words(m_rpc));
			return false;
		}
		m_notice->say(tr("Sent to %1.").arg(to));
	}
	if (m_sent)
		m_sent(to);
	return true;
}

void fzn_share_view::on_sent(std::function<void(const QString &to)> told) { m_sent = std::move(told); }

QString fzn_share_view::shared() const
{
	return m_file.isEmpty() ? m_text->text() : m_what->text();
}

QStringList fzn_share_view::listed() const
{
	QStringList out;
	for (int i = 0; i < m_list->count(); i++)
		out << m_list->item(i)->text();
	return out;
}

QString fzn_share_view::chosen() const
{
	return m_list->currentItem() ? m_list->currentItem()->text() : QString();
}

QString fzn_share_view::status() const { return m_notice->text(); }
