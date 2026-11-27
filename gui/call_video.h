/*
 * A call's picture: fuzznet sec 1237, step 4 of taking a call's media into
 * fuzznet (secs 1234-1236), moved from fuzzypickles' call_video.
 *
 * On the held media channel (sec 1113, `local/rpc_media.h`): whole frames,
 * video on stream 2, read as they arrive. THE CODEC IS JPEG, a frame at a
 * time: each stands alone, so a frame lost is a picture skipped rather
 * than a smear until the next key frame -- what a call over a relay abroad
 * most needs -- and it is QImage's own on every target. At most 320x240,
 * at the best quality that fits one whole frame. An inter-frame codec
 * would cost a fifth of the bandwidth, and needs an encoder a build may
 * not have.
 *
 * The channel is opened whether or not this end sends, so the other end's
 * picture is seen on a call this end took as sound only. The camera is
 * `camera_feed`'s, thinned to eight frames a second.
 *
 * TEST SEAM: `attach` takes a connection the host -- or a test's
 * socketpair -- made, and `send_picture` sends as the camera would.
 * NO Q_OBJECT AND THEREFORE NO moc.
 */
#ifndef FZN_GUI_CALL_VIDEO_H
#define FZN_GUI_CALL_VIDEO_H

#include <QByteArray>
#include <QtGlobal>
#include <QImage>
#include <QString>

#include <functional>
#include <stddef.h>
#include <stdint.h>

class QObject;
class QSocketNotifier;
class fzn_camera_feed;
struct fzn_rpc_media;

/* The largest picture sent; the rate is the camera feed's, eight a second. */
#define FZN_CALL_VIDEO_WIDTH 320
#define FZN_CALL_VIDEO_HEIGHT 240

/* A PICTURE MADE A FRAME: scaled to fit 320x240, JPEG at the best quality
 * that fits `max` bytes; empty when none does. */
QByteArray fzn_video_encode(const QImage &image, size_t max);
/* A FRAME MADE A PICTURE AGAIN; null when it is not one. */
QImage fzn_video_decode(const uint8_t *media, size_t len);

class fzn_call_video {
public:
	/* `node_socket`: where the node answers, for `start` to open the
	 * channel; `owner` parents what Qt makes. */
	fzn_call_video(const QString &node_socket, QObject *owner = nullptr);
	~fzn_call_video();
	fzn_call_video(const fzn_call_video &) = delete;
	fzn_call_video &operator=(const fzn_call_video &) = delete;

	/* Carry the picture of call `id` (16 hex) on a channel of its own;
	 * stop. Whether it opened. */
	bool start(const QString &id);
	/* THE SAME on a connection the caller made (a host's own, a test's). */
	bool attach(int fd, const QString &id);
	void stop();
	bool running() const;
	QString trouble() const { return m_trouble; }

	/* Each picture from the other end, as it arrives. */
	void on_picture(std::function<void(const QImage &)> told) { m_told = told; }
	/* EACH PICTURE THIS END SENDS, as its person sees it -- mirrored for a
	 * front camera, as a mirror is; what is sent is as the camera saw it
	 * (sec 1491, fuzzypickles' call_video). */
	void on_own_picture(std::function<void(const QImage &)> told) { m_own_told = told; }
	/* HOW LONG SINCE THE OTHER END'S LAST PICTURE, in ms, or -1 for none
	 * on this channel: a picture that stopped is not left standing. */
	qint64 picture_age_ms() const;
	/* A CHANNEL THE NODE CLOSED for a call is not opened again for it
	 * (sec 1491): `start` refuses that call until another is started. */
	QString closed_id() const { return m_closed_id; }
	/* The camera: asked for (a permission on a phone), and said in
	 * `trouble` when it cannot be had. Wanted, it comes back with the
	 * next channel opened, as `stop` closes it with the channel. */
	void set_camera(bool on);
	bool camera_on() const;
	/* Send a picture now, as the camera would. False with no channel open
	 * or a picture that will not fit. */
	bool send_picture(const QImage &image);
	/* Read whatever has arrived: the channel's notifier does, and a test. */
	void poll();
	uint32_t frames_sent() const { return m_sent; }
	uint32_t frames_received() const { return m_received; }

private:
	bool opened(const QString &id);

	QString m_node_socket, m_trouble, m_id;
	QObject *m_owner;
	struct fzn_rpc_media *m_media;
	bool m_open = false;
	QSocketNotifier *m_notifier = nullptr;
	fzn_camera_feed *m_camera = nullptr;
	std::function<void(const QImage &)> m_told, m_own_told;
	QString m_closed_id;
	bool m_camera_wanted = false;
	qint64 m_picture_at_ms = -1;
	uint32_t m_sent = 0, m_received = 0;
	qint64 m_started_ms = 0;
};

#endif /* FZN_GUI_CALL_VIDEO_H */
