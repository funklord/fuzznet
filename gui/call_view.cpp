/* Calls, as a widget: gui/call_view.h, sec 1142. */
#include "call_view.h"

#include "rpc_ask.h"

#include <QByteArray>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QPushButton>
#include <QVBoxLayout>
#include <QVector>

#include <string.h>

#define ROLE_ID (Qt::UserRole)
#define ROLE_STATE (Qt::UserRole + 1)

struct fzn_call_view::seen {
	QVector<QByteArray> ids;   /* each call's 16 hex */
	QVector<QString> who;      /* the other end, as said */
	QVector<uint8_t> state;    /* its state when last listed */
};

static QString failed_words(const fzn_gui_rpc *r)
{
	return QString::fromUtf8(fzn_gui_rpc_silent(r));
}

static QString kinds_words(uint8_t kinds)
{
	return kinds == (FZN_RPC_AUDIO | FZN_RPC_VIDEO) ? QObject::tr("audio and video")
	       : kinds == FZN_RPC_VIDEO                 ? QObject::tr("video")
	                                                : QObject::tr("audio");
}

fzn_call_view::fzn_call_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent)
    : QWidget(parent), m_rpc(new fzn_gui_rpc), m_seen(new seen)
{
	fzn_gui_rpc_init(m_rpc, ask, ask_ctx);

	m_list = new QListWidget(this);
	m_list->setAccessibleName(tr("Calls"));
	m_answer = new QPushButton(tr("Answer"), this);
	m_decline = new QPushButton(tr("Decline"), this);
	m_hang_up = new QPushButton(tr("Hang up"), this);
	m_status = new QLabel(this);
	m_status->setWordWrap(true);

	auto *row = new QHBoxLayout;
	row->addWidget(m_answer);
	row->addWidget(m_decline);
	row->addWidget(m_hang_up);
	row->addStretch(1);
	auto *col = new QVBoxLayout(this);
	col->addWidget(m_list, 1);
	col->addLayout(row);
	col->addWidget(m_status);

	connect(m_list, &QListWidget::currentRowChanged, [this](int r) { select(r); });
	connect(m_answer, &QPushButton::clicked, [this]() { answer(); });
	connect(m_decline, &QPushButton::clicked, [this]() { decline(); });
	connect(m_hang_up, &QPushButton::clicked, [this]() { hang_up(); });
	m_status->setText(tr("No call."));
	select(-1);
}

fzn_call_view::~fzn_call_view()
{
	delete m_seen;
	delete m_rpc;
}

bool fzn_call_view::refresh()
{
	fzn_rpc_entry_t live[FZN_RPC_CALLS_MAX];
	size_t n = 0, i;
	int k;
	seen now;

	if (fzn_rpc_calls(&m_rpc->c, live, FZN_RPC_CALLS_MAX, &n) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	m_list->clear();
	for (i = 0; i < n; i++) {
		const fzn_rpc_entry_t *e = &live[i];
		char name[FZN_RPC_PEER_NAME_MAX + 1];
		QString who = e->has_user && fzn_rpc_user_name(&m_rpc->c, e->user, name, sizeof name)
		                      ? QString::fromUtf8(name)
		                      : tr("someone");
		QString said = e->state == FZN_RPC_RINGING_IN
		                       ? tr("%1 is calling (%2)").arg(who, kinds_words(e->kinds))
		               : e->state == FZN_RPC_RINGING_OUT ? tr("Calling %1...").arg(who)
		                                                 : tr("In a call with %1").arg(who);
		auto *item = new QListWidgetItem(said, m_list);
		item->setData(ROLE_ID, QByteArray(e->id, FZN_RPC_ID_HEX));
		item->setData(ROLE_STATE, (int)e->state);
		now.ids.append(QByteArray(e->id, FZN_RPC_ID_HEX));
		now.who.append(who);
		now.state.append(e->state);
	}
	/* A CALL GONE FROM THE LIST HAS ENDED: said with why, sec 1082, and a
	 * missed one as missed, sec 1090. */
	QString ended;
	for (k = 0; k < m_seen->ids.size(); k++) {
		if (now.ids.contains(m_seen->ids.at(k)))
			continue;
		char reason[FZN_RPC_REASON_MAX + 1] = "";
		if (fzn_rpc_ended(&m_rpc->c, m_seen->ids.at(k).constData(), reason, sizeof reason) != FZN_RPC_OK
		    || !reason[0])
			continue; /* forgotten past its 30 s, or live again */
		ended = m_seen->state.at(k) == FZN_RPC_RINGING_IN && fzn_rpc_missed(reason)
		                ? tr("Missed call from %1.").arg(m_seen->who.at(k))
		                : tr("The call with %1 ended: %2.")
		                          .arg(m_seen->who.at(k), QString::fromUtf8(fzn_rpc_ended_words(reason)));
	}
	*m_seen = now;
	m_status->setText(!ended.isEmpty() ? ended : n ? QString() : tr("No call."));
	select(n ? 0 : -1);
	return true;
}

bool fzn_call_view::call(const QString &contact, bool video)
{
	QByteArray who = contact.toUtf8();
	char id[FZN_RPC_ID_HEX + 1];
	if (fzn_rpc_ring(&m_rpc->c, who.constData(), (size_t)who.size(),
	                 video ? (uint8_t)(FZN_RPC_AUDIO | FZN_RPC_VIDEO) : (uint8_t)FZN_RPC_AUDIO, id)
	    != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	refresh();
	return true;
}

void fzn_call_view::select(int row)
{
	QListWidgetItem *item = row >= 0 ? m_list->item(row) : nullptr;
	if (item && m_list->currentRow() != row)
		m_list->setCurrentRow(row);
	const int state = item ? item->data(ROLE_STATE).toInt() : 0;
	/* WHAT EACH STATE ALLOWS: a call ringing here is answered or declined;
	 * one ringing out or up is hung up. */
	m_answer->setEnabled(state == FZN_RPC_RINGING_IN);
	m_decline->setEnabled(state == FZN_RPC_RINGING_IN);
	m_hang_up->setEnabled(state == FZN_RPC_RINGING_OUT || state == FZN_RPC_UP);
}

bool fzn_call_view::respond(const char *what, int state)
{
	QListWidgetItem *item = m_list->currentItem();
	if (!item || item->data(ROLE_STATE).toInt() != state)
		return false;
	QByteArray id = item->data(ROLE_ID).toByteArray();
	if (fzn_rpc_respond(&m_rpc->c, id.constData(), what) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	refresh();
	return true;
}

bool fzn_call_view::answer() { return respond("answer", FZN_RPC_RINGING_IN); }

bool fzn_call_view::decline() { return respond("decline", FZN_RPC_RINGING_IN); }

bool fzn_call_view::hang_up()
{
	QListWidgetItem *item = m_list->currentItem();
	const int state = item ? item->data(ROLE_STATE).toInt() : 0;
	return respond("hangup", state == FZN_RPC_UP ? FZN_RPC_UP : FZN_RPC_RINGING_OUT);
}

QStringList fzn_call_view::calls() const
{
	QStringList out;
	for (int i = 0; i < m_list->count(); i++)
		out << m_list->item(i)->text();
	return out;
}

QString fzn_call_view::status() const { return m_status->text(); }
