/*
 * A call's sound on this device's microphone and speaker: fuzznet sec 1236,
 * step 3 of taking a call's media into fuzznet (secs 1234, 1235), moved
 * from fuzzypickles' call_audio.
 *
 * Every 20 ms, while a call is carried, what the microphone gave goes out
 * and what arrived is played -- through `local/call_sound.h`, which does
 * everything but the devices. 8 kHz mono mu-law; a device that cannot run
 * at 8 kHz is run at its own rate when that is a whole multiple, averaged
 * down and repeated up, and stereo is folded to mono. With the microphone
 * refused (a phone's permission) only the speaker opens: the other end is
 * still heard.
 *
 * Through Qt 6 Multimedia, built only where it is (FZN_CAMERA_ON, which
 * says the build has it); elsewhere `trouble` says why there is no sound.
 * TEST SEAM: `set_test_io` replaces both devices with functions, in any
 * build, so a test with no sound card drives the whole path through the
 * node; `tick` is public for it.
 *
 * Through the typed client on the host's ask callback (`rpc_ask.h`).
 * NO Q_OBJECT AND THEREFORE NO moc.
 */
#ifndef FZN_GUI_CALL_AUDIO_H
#define FZN_GUI_CALL_AUDIO_H

#include "notebook_view.h"

#include <QString>

#include <functional>
#include <stddef.h>
#include <stdint.h>

class QIODevice;
class QObject;
class QTimer;
struct fzn_gui_rpc;
struct fzn_call_sound;

class fzn_call_audio {
public:
	fzn_call_audio(fzn_notebook_view_ask_t ask, void *ask_ctx);
	~fzn_call_audio();
	fzn_call_audio(const fzn_call_audio &) = delete;
	fzn_call_audio &operator=(const fzn_call_audio &) = delete;

	/* Carry the sound of call `id` (16 hex); stop. Running for it already
	 * is a no-op. Whether it started. */
	bool start(const QString &id);
	void stop();
	bool running() const { return !m_id.isEmpty(); }
	QString id() const { return m_id; }
	/* Why there is no sound, or empty. */
	QString trouble() const { return m_trouble; }

	/* Muted, silence goes out in place of the microphone: the frames go
	 * on, so the other end's reports and the round trip do too. */
	void set_muted(bool muted);
	bool muted() const;
	/* How this end is heard, as the other end last reported it; empty
	 * until it has. */
	QString quality() const { return m_quality; }
	uint32_t frames_sent() const;

	using source_fn = std::function<size_t(int16_t *pcm, size_t cap)>;
	using sink_fn = std::function<void(const int16_t *pcm, size_t n)>;
	/* 8 kHz mono both ways, in place of the devices. */
	void set_test_io(source_fn source, sink_fn sink);
	/* One 20 ms turn, at `now_ms`: the timer's, public for a test. */
	void tick(uint64_t now_ms);

private:
	void open_devices();
	void close_devices();

	struct fzn_gui_rpc *m_rpc;
	struct fzn_call_sound *m_sound;
	QString m_id, m_trouble, m_quality;
	QTimer *m_timer = nullptr;
	source_fn m_test_source;
	sink_fn m_test_sink;
	uint64_t m_ticks = 0;
	/* The devices, where the build has them, each at a whole multiple of
	 * 8 kHz and its own channel count. */
	QObject *m_source_device = nullptr, *m_sink_device = nullptr;
	QIODevice *m_in = nullptr, *m_out = nullptr;
	int m_in_factor = 0, m_in_channels = 1, m_out_factor = 0, m_out_channels = 1;
};

#endif /* FZN_GUI_CALL_AUDIO_H */
