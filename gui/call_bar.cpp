/* One line for the call that matters: call_bar.h, fuzznet sec 1238. */
#include "call_bar.h"
#include "call_audio.h"
#include "call_video.h"
#include "rpc_ask.h"

#include <QByteArray>
#include <QBoxLayout>
#include <QFontMetrics>
#include <QLabel>
#include <QPushButton>

#include <time.h>

static QString elapsed_words(uint32_t s)
{
	return s >= 3600u ? QStringLiteral("%1:%2:%3")
	                            .arg(s / 3600u)
	                            .arg(s / 60u % 60u, 2, 10, QLatin1Char('0'))
	                            .arg(s % 60u, 2, 10, QLatin1Char('0'))
	                  : QStringLiteral("%1:%2").arg(s / 60u).arg(s % 60u, 2, 10, QLatin1Char('0'));
}

fzn_call_bar::fzn_call_bar(fzn_notebook_view_ask_t ask, void *ask_ctx, const QString &node_socket, QWidget *parent)
    : QWidget(parent), m_rpc(new fzn_gui_rpc), m_audio(new fzn_call_audio(ask, ask_ctx)),
      m_video(node_socket.isEmpty() ? nullptr : new fzn_call_video(node_socket, this))
{
	fzn_gui_rpc_init(m_rpc, ask, ask_ctx);
	m_said = new QLabel(this);
	m_said->setWordWrap(true);
	m_said->setAccessibleName(tr("The call"));
	m_answer = new QPushButton(tr("Answer"), this);
	m_decline = new QPushButton(tr("Decline"), this);
	m_mute = new QPushButton(tr("Mute"), this);
	m_mute->setCheckable(true);
	m_camera = new QPushButton(tr("Camera"), this);
	m_camera->setCheckable(true);
	m_hang_up = new QPushButton(tr("Hang up"), this);
	m_row = new QBoxLayout(QBoxLayout::LeftToRight, this);
	m_row->addWidget(m_said, 1);
	for (QPushButton *b : { m_answer, m_decline, m_mute, m_camera, m_hang_up })
		m_row->addWidget(b);
	connect(m_answer, &QPushButton::clicked, [this]() { answer(); });
	connect(m_decline, &QPushButton::clicked, [this]() { decline(); });
	connect(m_hang_up, &QPushButton::clicked, [this]() { hang_up(); });
	connect(m_mute, &QPushButton::toggled, [this](bool on) { set_muted(on); });
	connect(m_camera, &QPushButton::toggled, [this](bool on) { set_camera(on); });
	refresh();
}

fzn_call_bar::~fzn_call_bar()
{
	delete m_audio;
	delete m_rpc;
}

uint32_t fzn_call_bar::now() const { return m_now ? m_now : (uint32_t)time(nullptr); }

/* THE CALL'S MEDIA, carried while it is up and only then. */
void fzn_call_bar::carry(const QString &id, bool up)
{
	if (!up) {
		m_audio->stop();
		if (m_video)
			m_video->stop();
		return;
	}
	if (m_audio->id() != id || !m_audio->running())
		(void)m_audio->start(id);
	if (m_video && !m_video->running())
		(void)m_video->start(id);
}

bool fzn_call_bar::refresh()
{
	fzn_rpc_entry_t live[FZN_RPC_CALLS_MAX];
	size_t n = 0, i;
	const uint32_t t = now();
	QHash<QString, seen> was = m_seen;

	if (fzn_rpc_calls(&m_rpc->c, live, FZN_RPC_CALLS_MAX, &n) != FZN_RPC_OK)
		return false;
	/* THE ONE THAT MATTERS: ringing here, then up, then ringing out. */
	const fzn_rpc_entry_t *chosen = nullptr;
	m_seen.clear();
	for (i = 0; i < n; i++) {
		const fzn_rpc_entry_t *e = &live[i];
		const QString id = QString::fromLatin1(e->id);
		char name[FZN_RPC_PEER_NAME_MAX + 1];
		const QString who = e->has_user && fzn_rpc_user_name(&m_rpc->c, e->user, name, sizeof name)
		                            ? QString::fromUtf8(name)
		                            : tr("someone");
		const auto before = was.constFind(id);
		const uint32_t up_at = e->state == FZN_RPC_UP
		                               ? (before != was.constEnd() && before->state == FZN_RPC_UP ? before->up_at : t)
		                               : 0u;

		m_seen.insert(id, { who, e->state, up_at });
		auto rank = [](int state) {
			return state == FZN_RPC_RINGING_IN ? 3 : state == FZN_RPC_UP ? 2 : 1;
		};
		if (!chosen || rank(e->state) > rank(chosen->state))
			chosen = e;
	}
	/* A CALL GONE FROM THE LIST HAS ENDED: said as a person would (sec
	 * 1082, 1090), for a few seconds. */
	for (auto it = was.constBegin(); it != was.constEnd(); ++it) {
		char reason[FZN_RPC_REASON_MAX + 1] = "";
		const QByteArray id = it.key().toLatin1();

		if (m_seen.contains(it.key())
		    || fzn_rpc_ended(&m_rpc->c, id.constData(), reason, sizeof reason) != FZN_RPC_OK || !reason[0])
			continue;
		const QString why = QString::fromUtf8(reason);
		if (it->state == FZN_RPC_UP)
			m_ended = tr("Call with %1 ended, %2.").arg(it->who, elapsed_words(t - it->up_at));
		else if (it->state == FZN_RPC_RINGING_IN && fzn_rpc_missed(reason))
			m_ended = tr("Missed call from %1.").arg(it->who);
		else if (it->state == FZN_RPC_RINGING_OUT && why == QLatin1String("declined"))
			m_ended = tr("%1 declined.").arg(it->who);
		else if (it->state == FZN_RPC_RINGING_OUT && why == QLatin1String("busy"))
			m_ended = tr("%1 is busy.").arg(it->who);
		else if (it->state == FZN_RPC_RINGING_OUT && why == QLatin1String("no-answer"))
			m_ended = tr("%1 did not answer.").arg(it->who);
		else
			m_ended = tr("The call with %1: %2.").arg(it->who, QString::fromUtf8(fzn_rpc_ended_words(reason)));
		m_ended_at = t;
	}
	m_id = chosen ? QString::fromLatin1(chosen->id) : QString();
	m_state = chosen ? chosen->state : 0;
	m_who = chosen ? m_seen.value(m_id).who : QString();
	carry(m_id, m_state == FZN_RPC_UP);
	if (chosen) {
		const QString kinds = (chosen->kinds & FZN_RPC_VIDEO) ? tr("video call") : tr("call");
		m_said->setText(m_state == FZN_RPC_RINGING_IN ? tr("%1 is calling you (%2)").arg(m_who, kinds)
		                : m_state == FZN_RPC_UP
		                        ? tr("In a call with %1, %2").arg(m_who, elapsed_words(t - m_seen.value(m_id).up_at))
		                        : tr("Calling %1...").arg(m_who));
		m_ended.clear();
	} else if (!m_ended.isEmpty() && t - m_ended_at < FZN_CALL_BAR_ENDED_S) {
		m_said->setText(m_ended);
	} else {
		m_ended.clear();
		m_said->clear();
	}
	/* WHAT EACH STATE OFFERS. */
	m_answer->setVisible(m_state == FZN_RPC_RINGING_IN);
	m_decline->setVisible(m_state == FZN_RPC_RINGING_IN);
	m_mute->setVisible(m_state == FZN_RPC_UP);
	m_camera->setVisible(m_state == FZN_RPC_UP && m_video && chosen && (chosen->kinds & FZN_RPC_VIDEO));
	m_hang_up->setVisible(m_state == FZN_RPC_UP || m_state == FZN_RPC_RINGING_OUT);
	/* RINGING HERE: the host told as it starts and stops, and the bar a
	 * screen while it rings, where allowed (sec 1247). */
	const bool ringing = m_state == FZN_RPC_RINGING_IN;
	as_screen(ringing && m_screen_allowed);
	if (ringing != m_ringing) {
		m_ringing = ringing;
		if (m_ringing_told)
			m_ringing_told(ringing);
	}
	/* HIDDEN WHILE THERE IS NOTHING TO SAY. */
	setVisible(!m_said->text().isEmpty());
	return true;
}

void fzn_call_bar::set_screen(bool allowed)
{
	m_screen_allowed = allowed;
	as_screen(allowed && m_state == FZN_RPC_RINGING_IN);
}

/* THE BAR AS A SCREEN: stacked, the caller in a large face, Answer and
 * Decline tall enough to be found without looking for them. */
void fzn_call_bar::as_screen(bool on)
{
	if (on == m_screen_on)
		return;
	m_screen_on = on;
	m_row->setDirection(on ? QBoxLayout::TopToBottom : QBoxLayout::LeftToRight);
	QFont big = font();
	if (on)
		big.setPointSizeF(big.pointSizeF() > 0 ? big.pointSizeF() * 1.8 : 18.0);
	m_said->setFont(big);
	m_said->setAlignment(on ? Qt::AlignCenter : Qt::AlignLeft | Qt::AlignVCenter);
	for (QPushButton *b : { m_answer, m_decline }) {
		b->setFont(big);
		b->setMinimumHeight(on ? 4 * QFontMetrics(big).height() : 0);
	}
}

bool fzn_call_bar::respond(const char *what, int state)
{
	const QByteArray id = m_id.toLatin1();

	if (m_id.isEmpty() || m_state != state || fzn_rpc_respond(&m_rpc->c, id.constData(), what) != FZN_RPC_OK)
		return false;
	refresh();
	return true;
}

bool fzn_call_bar::answer() { return respond("answer", FZN_RPC_RINGING_IN); }

bool fzn_call_bar::decline() { return respond("decline", FZN_RPC_RINGING_IN); }

bool fzn_call_bar::hang_up()
{
	return respond("hangup", m_state == FZN_RPC_UP ? FZN_RPC_UP : FZN_RPC_RINGING_OUT);
}

void fzn_call_bar::set_muted(bool muted)
{
	m_audio->set_muted(muted);
	if (m_mute->isChecked() != muted)
		m_mute->setChecked(muted);
}

void fzn_call_bar::set_camera(bool on)
{
	if (m_video)
		m_video->set_camera(on);
}

QString fzn_call_bar::said() const { return m_said->text(); }

QStringList fzn_call_bar::buttons() const
{
	QStringList out;
	for (const QPushButton *b : { m_answer, m_decline, m_mute, m_camera, m_hang_up })
		if (!b->isHidden())
			out << b->text();
	return out;
}
