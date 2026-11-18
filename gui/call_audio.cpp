/* A call's sound on this device: call_audio.h, fuzznet sec 1236. */
#include "call_audio.h"
#include "call_opus.h"
#include "rpc_ask.h"

extern "C" {
#include "../local/call_sound.h"
}

#include <QDateTime>
#include <QIODevice>
#include <QObject>
#include <QTimer>
#include <QVector>

#ifdef FZN_CAMERA_ON
#include <QAudioDevice>
#include <QAudioFormat>
#include <QAudioSink>
#include <QAudioSource>
#include <QCoreApplication>
#include <QMediaDevices>
#if QT_VERSION >= QT_VERSION_CHECK(6, 5, 0)
#include <QPermissions>
#endif
#endif

fzn_call_audio::fzn_call_audio(fzn_notebook_view_ask_t ask, void *ask_ctx)
    : m_rpc(new fzn_gui_rpc), m_sound(new fzn_call_sound)
{
	fzn_gui_rpc_init(m_rpc, ask, ask_ctx);
	fzn_call_sound_start(m_sound, "0000000000000000", 0);
}

fzn_call_audio::~fzn_call_audio()
{
	stop();
	fzn_call_opus_close(m_opus);
	delete m_sound;
	delete m_rpc;
}

bool fzn_call_audio::start(const QString &id)
{
	if (id == m_id && running())
		return true;
	stop();
	const QByteArray hex = id.toLatin1();
	if (fzn_call_sound_start(m_sound, hex.constData(), (uint64_t)QDateTime::currentMSecsSinceEpoch()) != 0) {
		m_trouble = QObject::tr("That is not a call.");
		return false;
	}
	m_id = id;
	m_trouble.clear();
	m_quality.clear();
	m_ticks = 0;
	/* OPUS WHERE THE BUILD HAS IT, opened fresh for this call; the devices
	 * may still send it back to mu-law. A test asks for it by its rate. */
	fzn_call_opus_close(m_opus);
	m_opus = fzn_call_opus_open(nullptr);
	const bool test = m_test_source || m_test_sink;
	if (m_opus && (!test || m_test_rate == (int)FZN_CALL_OPUS_RATE))
		(void)fzn_call_sound_codec(m_sound, fzn_call_opus_codec(m_opus));
	if (!test)
		open_devices();
	m_timer = new QTimer;
	m_timer->setInterval(20);
	QObject::connect(m_timer, &QTimer::timeout,
	                 [this]() { tick((uint64_t)QDateTime::currentMSecsSinceEpoch()); });
	m_timer->start();
	return true;
}

void fzn_call_audio::stop()
{
	delete m_timer;
	m_timer = nullptr;
	close_devices();
	m_id.clear();
}

void fzn_call_audio::set_muted(bool muted) { m_sound->muted = muted ? 1 : 0; }

bool fzn_call_audio::muted() const { return m_sound->muted != 0; }

uint32_t fzn_call_audio::frames_sent() const { return m_sound->seq; }

void fzn_call_audio::set_test_io(source_fn source, sink_fn sink, int rate)
{
	m_test_source = source;
	m_test_sink = sink;
	m_test_rate = rate;
}

QString fzn_call_audio::codec() const
{
	return m_sound->codec ? QStringLiteral("Opus") : QStringLiteral("mu-law");
}

#ifdef FZN_CAMERA_ON
/* THE FORMAT A DEVICE TAKES, 16-bit at `rate` or a whole multiple of it:
 * the multiple, or 0 where it takes neither. */
static int factor_for(const QAudioDevice &dev, QAudioFormat *f, int rate)
{
	f->setSampleFormat(QAudioFormat::Int16);
	f->setChannelCount(1);
	f->setSampleRate(rate);
	if (dev.isFormatSupported(*f))
		return 1;
	QAudioFormat pref = dev.preferredFormat();
	pref.setSampleFormat(QAudioFormat::Int16);
	if (pref.sampleRate() % rate || !dev.isFormatSupported(pref))
		return 0;
	*f = pref;
	return pref.sampleRate() / rate;
}
#endif

void fzn_call_audio::open_devices()
{
#ifdef FZN_CAMERA_ON
	/* REFUSED THE MICROPHONE, only the speaker opens: they are still heard. */
	bool may_record = true;
#if QT_VERSION >= QT_VERSION_CHECK(6, 5, 0)
	if (qApp)
		may_record = qApp->checkPermission(QMicrophonePermission{}) == Qt::PermissionStatus::Granted;
#endif
	const QAudioDevice in = may_record ? QMediaDevices::defaultAudioInput() : QAudioDevice();
	const QAudioDevice out = QMediaDevices::defaultAudioOutput();
	QAudioFormat fin, fout;

	int rate = (int)fzn_call_sound_rate(m_sound);
	m_in_factor = in.isNull() ? 0 : factor_for(in, &fin, rate);
	m_out_factor = out.isNull() ? 0 : factor_for(out, &fout, rate);
	/* OPUS ONLY WHERE BOTH DEVICES TAKE ITS RATE, as fuzzypickles' call:
	 * mu-law at 8 kHz otherwise. */
	if (rate != (int)FZN_ULAW_RATE && ((!in.isNull() && !m_in_factor) || !m_out_factor)) {
		(void)fzn_call_sound_codec(m_sound, nullptr);
		rate = (int)FZN_ULAW_RATE;
		m_in_factor = in.isNull() ? 0 : factor_for(in, &fin, rate);
		m_out_factor = out.isNull() ? 0 : factor_for(out, &fout, rate);
	}
	if (!m_in_factor && may_record) {
		m_trouble = QObject::tr("No microphone this call can use.");
	} else if (m_in_factor) {
		auto *source = new QAudioSource(in, fin);
		m_in_channels = fin.channelCount();
		m_source_device = source;
		m_in = source->start();
	}
	if (!m_out_factor) {
		m_trouble = QObject::tr("No speaker this call can use.");
	} else {
		auto *sink = new QAudioSink(out, fout);
		m_out_channels = fout.channelCount();
		m_sink_device = sink;
		m_out = sink->start();
	}
#else
	m_trouble = QObject::tr("This build has no sound: it was made without Qt Multimedia.");
#endif
}

void fzn_call_audio::close_devices()
{
#ifdef FZN_CAMERA_ON
	if (m_source_device)
		static_cast<QAudioSource *>(m_source_device)->stop();
	if (m_sink_device)
		static_cast<QAudioSink *>(m_sink_device)->stop();
#endif
	delete m_source_device;
	delete m_sink_device;
	m_source_device = m_sink_device = nullptr;
	m_in = m_out = nullptr;
}

void fzn_call_audio::tick(uint64_t now_ms)
{
	int16_t played[FZN_CALL_SOUND_FRAME_MAX];
	QVector<int16_t> captured;
	const size_t frame = fzn_call_sound_frame(m_sound);

	if (!running())
		return;
	/* OUT: what was captured, at the call's rate, mono. */
	if (m_test_source) {
		int16_t buf[FZN_CALL_SOUND_FRAME_MAX * 2];
		const size_t n = m_test_source(buf, sizeof(buf) / sizeof(buf[0]));
		for (size_t i = 0; i < n; i++)
			captured.append(buf[i]);
	} else if (m_in) {
		const QByteArray raw = m_in->readAll();
		const auto *s = reinterpret_cast<const int16_t *>(raw.constData());
		const int per = m_in_factor * m_in_channels;
		/* AVERAGED DOWN, and the channels folded to one. */
		for (int i = 0; per > 0 && i + per <= (int)(raw.size() / 2); i += per) {
			int sum = 0;
			for (int k = 0; k < per; k++)
				sum += s[i + k];
			captured.append((int16_t)(sum / per));
		}
	}
	if (fzn_call_sound_send(m_sound, &m_rpc->c, captured.constData(), (size_t)captured.size(), now_ms) < 0)
		return; /* the call went: whatever ends it stops this */
	/* IN: whatever arrived, into the jitter buffer. */
	(void)fzn_call_sound_receive(m_sound, &m_rpc->c);
	/* HOW IT IS HEARD, once a second (sec 1026). */
	if (++m_ticks % 50u == 0u && fzn_call_sound_quality(m_sound, &m_rpc->c, now_ms) == 1)
		m_quality = m_sound->trip_ms >= 0 ? QObject::tr("they lose %1%, %2 ms round trip")
		                                            .arg(m_sound->loss_pct)
		                                            .arg(m_sound->trip_ms)
		                                  : QObject::tr("they lose %1%").arg(m_sound->loss_pct);
	/* PLAY: a frame a tick, so the buffer drains as fast as it fills. */
	if (!fzn_call_sound_play(m_sound, played))
		return;
	if (m_test_sink) {
		m_test_sink(played, frame);
	} else if (m_out && m_out_factor > 0) {
		/* REPEATED UP to the device's rate and channels. */
		const int repeat = m_out_factor * m_out_channels;
		QVector<int16_t> wide;
		wide.reserve((int)frame * repeat);
		for (size_t i = 0; i < frame; i++)
			for (int k = 0; k < repeat; k++)
				wide.append(played[i]);
		m_out->write(reinterpret_cast<const char *>(wide.constData()), (qint64)wide.size() * 2);
	}
}
