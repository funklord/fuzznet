/* One line for the call that matters: call_bar.h, fuzznet sec 1238. */
#include "call_bar.h"
#include "plain_label.h"
#include "call_audio.h"
#include "clock_words.h"
#include "call_video.h"
#include "rpc_ask.h"

#include <QByteArray>
#include <QBoxLayout>
#include <QFontMetrics>
#include <QLabel>
#include <QPainter>
#include <QPixmap>
#include <QPushButton>
#include <QTimer>

#include <time.h>

static QString elapsed_words(uint32_t s) { return fzn_clock_words(s); }

/* WHAT A CALL CARRIES, in the words of every line about it (sec 1491). */
static QString carries(int kinds)
{
	return (kinds & 3) == 3 ? QObject::tr("audio and video") : (kinds & 2) ? QObject::tr("video") : QObject::tr("audio");
}

/* A FONT SCALED, set in points or in pixels: on Android pointSizeF() is -1
 * and the font is in pixels, so scaling the points left the caller's name
 * at the line's own size (fuzzypickles 8de7f48e). */
static QFont scaled(QFont f, double by)
{
	if (f.pointSizeF() > 0)
		f.setPointSizeF(f.pointSizeF() * by);
	else if (f.pixelSize() > 0)
		f.setPixelSize((int)(f.pixelSize() * by + 0.5));
	else
		f.setPointSizeF(18.0);
	return f;
}

fzn_call_bar::fzn_call_bar(fzn_notebook_view_ask_t ask, void *ask_ctx, const QString &node_socket, QWidget *parent)
    : QWidget(parent), m_rpc(new fzn_gui_rpc), m_audio(new fzn_call_audio(ask, ask_ctx)),
      m_video(node_socket.isEmpty() ? nullptr : new fzn_call_video(node_socket, this))
{
	fzn_gui_rpc_init(m_rpc, ask, ask_ctx);
	/* NAMED, so a host or a test finds each widget (sec 1491). */
	setObjectName(QStringLiteral("call_bar"));
	m_said = fzn_plain_label(this);
	m_said->setObjectName(QStringLiteral("call_bar_text"));
	m_said->setWordWrap(true);
	m_said->setAccessibleName(tr("The call"));
	m_answer = new QPushButton(tr("Answer"), this);
	m_decline = new QPushButton(tr("Decline"), this);
	m_mute = new QPushButton(tr("Mute"), this);
	m_mute->setCheckable(true);
	m_camera = new QPushButton(tr("Camera"), this);
	m_camera->setCheckable(true);
	m_hang_up = new QPushButton(tr("Hang up"), this);
	m_answer->setObjectName(QStringLiteral("call_bar_answer"));
	m_decline->setObjectName(QStringLiteral("call_bar_decline"));
	m_mute->setObjectName(QStringLiteral("call_bar_mute"));
	m_camera->setObjectName(QStringLiteral("call_bar_camera"));
	m_hang_up->setObjectName(QStringLiteral("call_bar_hangup"));
	/* THE OTHER END'S PICTURE above the line, while a video call is up and
	 * one has come (sec 1262). */
	m_picture = fzn_plain_label(this);
	m_picture->setAlignment(Qt::AlignCenter);
	m_picture->setObjectName(QStringLiteral("call_bar_picture"));
	m_picture->setAccessibleName(tr("The other end's picture"));
	m_picture->hide();
	auto *col = new QBoxLayout(QBoxLayout::TopToBottom, this);
	col->addWidget(m_picture);
	m_row = new QBoxLayout(QBoxLayout::LeftToRight);
	col->addLayout(m_row);
	m_row->addWidget(m_said, 1);
	/* DECLINE ON THE LEFT, ANSWER ON THE RIGHT, as a phone's own dialer
	 * has them -- side by side in the bar and on the screen alike. */
	auto *choose = new QHBoxLayout;
	choose->addWidget(m_decline);
	choose->addWidget(m_answer);
	m_row->addLayout(choose);
	for (QPushButton *b : { m_mute, m_camera, m_hang_up })
		m_row->addWidget(b);
	connect(m_answer, &QPushButton::clicked, [this]() { answer(); });
	connect(m_decline, &QPushButton::clicked, [this]() { decline(); });
	connect(m_hang_up, &QPushButton::clicked, [this]() { hang_up(); });
	connect(m_mute, &QPushButton::toggled, [this](bool on) { set_muted(on); });
	connect(m_camera, &QPushButton::toggled, [this](bool on) { set_camera(on); });
	if (m_video) {
		m_video->on_picture([this](const QImage &image) {
			m_remote = image;
			show_pictures();
		});
		m_video->on_own_picture([this](const QImage &image) {
			m_own = image;
			show_pictures();
		});
	}
	/* EACH SECOND WHILE UP, the time said again, nothing asked. */
	m_ticker = new QTimer(this);
	m_ticker->setInterval(1000);
	QObject::connect(m_ticker, &QTimer::timeout, [this]() { tick(); });
	/* NOTHING OFFERED until a call is read (sec 1513): a node that cannot
	 * list calls left every button showing over an empty window. */
	for (QPushButton *b : { m_answer, m_decline, m_mute, m_camera, m_hang_up })
		b->hide();
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
		/* WHOM THIS WINDOW RANG, where the node names no user (sec 1491). */
		const QString who = e->has_user && fzn_rpc_user_name(&m_rpc->c, e->user, name, sizeof name)
		                            ? QString::fromUtf8(name)
		                            : m_rung.value(id, tr("someone"));
		const auto before = was.constFind(id);
		const uint32_t up_at = e->state == FZN_RPC_UP
		                               ? (before != was.constEnd() && before->state == FZN_RPC_UP ? before->up_at : t)
		                               : 0u;

		m_seen.insert(id, { who, e->state, up_at, e->kinds });
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
		const QString words = QString::fromUtf8(fzn_rpc_ended_words(reason));
		/* THE REASON TO THE LOG, every ending (sec 1491): the bar says it
		 * as a person would, the log keeps why. */
		if (it->state == FZN_RPC_UP)
			log(tr("The call with %1 ended: %2 (%3).").arg(it->who, words, elapsed_words(t - it->up_at)));
		else if (it->state == FZN_RPC_RINGING_IN && fzn_rpc_missed(reason))
			log(tr("Missed call from %1: %2.").arg(it->who, words));
		else
			log(tr("The call with %1 ended: %2.").arg(it->who, words));
		if (it->state == FZN_RPC_UP)
			m_ended = tr("Call with %1 ended, %2.").arg(it->who, elapsed_words(t - it->up_at));
		else if (it->state == FZN_RPC_RINGING_IN && fzn_rpc_missed(reason)) {
			m_ended = tr("Missed call from %1.").arg(it->who);
			/* TOLD ONCE, for the host's notice (sec 1262). */
			if (m_missed_told)
				m_missed_told(it->who, (it->kinds & 2) != 0);
		}
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
	m_kinds = chosen ? chosen->kinds : 0;
	carry(m_id, m_state == FZN_RPC_UP);
	/* A VIDEO CALL STARTS WITH THE CAMERA ON, once: turned off, it stays
	 * off for the rest of the call (sec 1491). No call up, it goes off. */
	if (m_video && m_state == FZN_RPC_UP && is_video() && !m_camera_begun.contains(m_id)) {
		m_camera_begun.insert(m_id, true);
		set_camera(true);
	} else if (m_video && m_state != FZN_RPC_UP && m_camera->isChecked())
		set_camera(false);
	if (m_state == FZN_RPC_UP)
		m_ticker->start();
	else
		m_ticker->stop();
	show_pictures();
	if (chosen) {
		say_shown();
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
	m_camera->setVisible(m_state == FZN_RPC_UP && m_video);
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

/* THE LINE FOR THE CALL SHOWN, at the time now. */
void fzn_call_bar::say_shown()
{
	const QString what = carries(m_kinds);

	if (m_state == FZN_RPC_RINGING_IN)
		m_said->setText(tr("%1 is calling you (%2)").arg(m_who, what));
	else if (m_state == FZN_RPC_RINGING_OUT)
		m_said->setText(tr("Calling %1 (%2)...").arg(m_who, what));
	else {
		/* UP: how long, and how this end is heard and what is wrong, where
		 * the sound has said (sec 1491). */
		const QString trouble = !m_audio->trouble().isEmpty() ? m_audio->trouble()
		                        : m_video                     ? m_video->trouble()
		                                                      : QString();
		QString line = tr("In a call with %1 (%2), %3.")
		                       .arg(m_who, what, elapsed_words(now() - m_seen.value(m_id).up_at));
		if (!m_audio->quality().isEmpty())
			line += QStringLiteral(" (%1)").arg(m_audio->quality());
		if (!trouble.isEmpty())
			line += QLatin1Char(' ') + trouble;
		m_said->setText(line);
	}
}

void fzn_call_bar::tick()
{
	if (m_state == FZN_RPC_UP && !m_id.isEmpty()) {
		say_shown();
		show_pictures();
	}
}

bool fzn_call_bar::picture_shown() const { return !m_picture->isHidden() && !m_remote.isNull(); }

bool fzn_call_bar::own_picture_shown() const { return !m_picture->isHidden() && !m_own.isNull(); }

/* THE PICTURES: the other end's while fresh, on any call up -- a call rung
 * as sound may still carry one -- and this end's in the bottom right,
 * a quarter of the width, while the camera sends. */
void fzn_call_bar::show_pictures()
{
	const qint64 age = m_video ? m_video->picture_age_ms() : -1;

	/* NO CALL UP, NO PICTURE: the channel stopped has no age, so the
	 * other end's is blanked below, and the camera stopped this end's. */
	if (!m_video)
		return;
	if (!m_remote.isNull() && (age < 0 || age > FZN_CALL_BAR_STILL_MS))
		m_remote = QImage();
	if (m_video && !m_video->camera_on())
		m_own = QImage();
	if (m_remote.isNull() && m_own.isNull()) {
		m_picture->clear();
		m_picture->hide();
		return;
	}
	QImage canvas(320, 240, QImage::Format_RGB32);
	canvas.fill(Qt::black);
	QPainter p(&canvas);
	p.setRenderHint(QPainter::SmoothPixmapTransform);
	if (!m_remote.isNull()) {
		const QSize at = m_remote.size().scaled(canvas.size(), Qt::KeepAspectRatio);
		p.drawImage(QRect((canvas.width() - at.width()) / 2, (canvas.height() - at.height()) / 2, at.width(),
		                  at.height()),
		            m_remote);
	} else {
		p.setPen(Qt::white);
		p.drawText(canvas.rect(), Qt::AlignCenter, tr("No picture from them"));
	}
	if (!m_own.isNull()) {
		const QSize at = m_own.size().scaled(canvas.width() / 4, canvas.width() / 4, Qt::KeepAspectRatio);
		const QRect r(canvas.width() - at.width() - 6, canvas.height() - at.height() - 6, at.width(),
		              at.height());
		p.drawImage(r, m_own);
		p.setPen(Qt::white);
		p.drawRect(r.adjusted(0, 0, -1, -1));
	}
	p.end();
	m_picture->setPixmap(QPixmap::fromImage(canvas));
	m_picture->show();
}

void fzn_call_bar::log(const QString &line)
{
	if (m_log_told)
		m_log_told(line);
}

bool fzn_call_bar::ring(const QString &who, unsigned kinds)
{
	const QByteArray w = who.toUtf8();
	char id[FZN_RPC_ID_HEX + 1];

	if (who.isEmpty()
	    || fzn_rpc_ring(&m_rpc->c, w.constData(), (size_t)w.size(), (uint8_t)kinds, id) != FZN_RPC_OK) {
		log(tr("%1 was not called: %2").arg(who, QString::fromUtf8(m_rpc->c.error[0] ? m_rpc->c.error : "no answer")));
		return false;
	}
	m_rung.insert(QString::fromLatin1(id), who);
	log(tr("Calling %1").arg(who));
	refresh();
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
	const QFont big = on ? scaled(font(), 1.8) : font();
	m_said->setFont(big);
	m_said->setAlignment(on ? Qt::AlignCenter : Qt::AlignLeft | Qt::AlignVCenter);
	for (QPushButton *b : { m_answer, m_decline }) {
		b->setFont(big);
		b->setMinimumHeight(on ? 4 * QFontMetrics(big).height() : 0);
	}
	/* RED AND GREEN on the screen, whatever the scheme, as every phone's
	 * are: the colours are the buttons' meaning before their words. */
	m_decline->setStyleSheet(on ? QStringLiteral("QPushButton { background: #d93025; color: white; }") : QString());
	m_answer->setStyleSheet(on ? QStringLiteral("QPushButton { background: #1e8e3e; color: white; }") : QString());
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

/* THE BUTTONS SAY WHAT THEY WILL DO NEXT (sec 1491): Unmute, Stop camera. */
void fzn_call_bar::set_muted(bool muted)
{
	m_audio->set_muted(muted);
	m_mute->blockSignals(true);
	m_mute->setChecked(muted);
	m_mute->blockSignals(false);
	m_mute->setText(muted ? tr("Unmute") : tr("Mute"));
}

void fzn_call_bar::set_camera(bool on)
{
	if (m_video)
		m_video->set_camera(on);
	m_camera->blockSignals(true);
	m_camera->setChecked(on);
	m_camera->blockSignals(false);
	m_camera->setText(on ? tr("Stop camera") : tr("Camera"));
	show_pictures();
}

QString fzn_call_bar::said() const { return m_said->text(); }

QStringList fzn_call_bar::buttons() const
{
	QStringList out;
	for (const QPushButton *b : { m_decline, m_answer, m_mute, m_camera, m_hang_up })
		if (!b->isHidden())
			out << b->text();
	return out;
}
