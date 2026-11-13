/* What this user's hosts decided apart, as a widget: gui/forks_view.h, sec 1127. */
#include "forks_view.h"

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
#include <QTreeWidget>
#include <QVBoxLayout>

#include <stdlib.h>

/* The most sides listed: a fork has two or three, and a person settles a
 * few at a time. */
#define SIDES_MAX 128u

/* A SIDE'S ITEM carries its subject and its value as the node listed them,
 * to settle with exactly those bytes. */
#define ROLE_SUBJECT (Qt::UserRole)
#define ROLE_VALUE (Qt::UserRole + 1)

static QString failed_words(const fzn_gui_rpc *r)
{
	return QString::fromUtf8(fzn_gui_rpc_silent(r));
}

fzn_forks_view::fzn_forks_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent)
    : QWidget(parent), m_rpc(new fzn_gui_rpc)
{
	fzn_gui_rpc_init(m_rpc, ask, ask_ctx);

	auto *intro = new QLabel(tr("Your hosts decided these apart. Keep one side of each, "
	                            "and every host takes it."),
	                         this);
	intro->setWordWrap(true);
	m_tree = new QTreeWidget(this);
	m_tree->setHeaderHidden(true);
	m_tree->setColumnCount(1);
	m_tree->setAccessibleName(tr("What was decided apart"));
	m_keep = new QPushButton(tr("Keep this"), this);
	m_keep->setAccessibleName(tr("Keep the chosen side"));
	m_refresh = new QPushButton(tr("Refresh"), this);
	m_status = new QLabel(this);
	m_status->setWordWrap(true);

	auto *row = new QHBoxLayout;
	row->addWidget(m_keep);
	row->addWidget(m_refresh);
	row->addStretch(1);
	auto *col = new QVBoxLayout(this);
	col->addWidget(intro);
	col->addWidget(m_tree, 1);
	col->addLayout(row);
	col->addWidget(m_status);

	connect(m_tree, &QTreeWidget::currentItemChanged, [this](QTreeWidgetItem *now, QTreeWidgetItem *) {
		m_keep->setEnabled(now && now->parent());
	});
	connect(m_keep, &QPushButton::clicked, [this]() { keep(); });
	connect(m_refresh, &QPushButton::clicked, [this]() { refresh(); });
	m_keep->setEnabled(false);
}

fzn_forks_view::~fzn_forks_view() { delete m_rpc; }

bool fzn_forks_view::refresh()
{
	auto *sides = (fzn_rpc_fork_side_t *)calloc(SIDES_MAX, sizeof(fzn_rpc_fork_side_t));
	size_t count = 0, i;
	QTreeWidgetItem *subject = nullptr;

	if (!sides)
		return false;
	if (fzn_rpc_fork_list(&m_rpc->c, sides, SIDES_MAX, &count) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		free(sides);
		return m_rpc->c.answered;
	}
	m_tree->clear();
	/* A SUBJECT'S ROWS TOGETHER, as the node lists them. */
	for (i = 0; i < count; i++) {
		const fzn_rpc_fork_side_t *s = &sides[i];
		char label[2u * FZN_RPC_FORK_SUBJECT_MAX + 64u];
		char shown[4u * FZN_RPC_FORK_VALUE_MAX + 1u];

		if (!subject || subject->data(0, ROLE_SUBJECT).toByteArray() != QByteArray(s->subject)) {
			fzn_rpc_fork_subject_label(&m_rpc->c, s->subject, label, sizeof label);
			subject = new QTreeWidgetItem(m_tree, { QString::fromUtf8(label) });
			subject->setData(0, ROLE_SUBJECT, QByteArray(s->subject));
			subject->setExpanded(true);
		}
		fzn_rpc_tty_escape(s->value, strlen(s->value), shown, sizeof shown);
		auto *side = new QTreeWidgetItem(
		        subject, { QStringLiteral("%1 -- %2, %3")
		                           .arg(QString::fromUtf8(shown),
		                                QString::fromLatin1(QByteArray((const char *)s->host, 8).toHex()),
		                                QDateTime::fromMSecsSinceEpoch((qint64)s->at)
		                                        .toString(QStringLiteral("yyyy-MM-dd HH:mm"))) });
		side->setData(0, ROLE_SUBJECT, QByteArray(s->subject));
		side->setData(0, ROLE_VALUE, QByteArray(s->value));
	}
	free(sides);
	m_status->setText(count ? QString() : tr("Your hosts agree on everything."));
	m_keep->setEnabled(false);
	return true;
}

void fzn_forks_view::select(int subject, int side)
{
	QTreeWidgetItem *s = m_tree->topLevelItem(subject);
	QTreeWidgetItem *chosen = s && side >= 0 ? s->child(side) : s;
	m_tree->setCurrentItem(chosen);
	m_keep->setEnabled(chosen && chosen->parent());
}

bool fzn_forks_view::keep()
{
	QTreeWidgetItem *side = m_tree->currentItem();
	if (!side || !side->parent())
		return false;
	QByteArray subject = side->data(0, ROLE_SUBJECT).toByteArray();
	QByteArray value = side->data(0, ROLE_VALUE).toByteArray();
	QString words = side->parent()->text(0);
	if (fzn_rpc_fork_settle(&m_rpc->c, subject.constData(), value.constData()) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	refresh();
	m_status->setText(tr("Kept for %1; every host takes it.").arg(words));
	return true;
}

QStringList fzn_forks_view::shown() const
{
	QStringList out;
	for (int i = 0; i < m_tree->topLevelItemCount(); i++) {
		QTreeWidgetItem *s = m_tree->topLevelItem(i);
		out << s->text(0);
		for (int k = 0; k < s->childCount(); k++)
			out << QStringLiteral("  ") + s->child(k)->text(0);
	}
	return out;
}

QString fzn_forks_view::status() const { return m_status->text(); }
