/* A call's picture: call_video.h, fuzznet sec 1237. */
#include "call_video.h"
#include "camera_feed.h"

extern "C" {
#include "../local/rpc.h"
#include "../local/rpc_err.h"
#include "../local/rpc_media.h"
}

#include <QBuffer>
#include <QDateTime>
#include <QObject>
#include <QSocketNotifier>

#include <string.h>

QByteArray fzn_video_encode(const QImage &image, size_t max)
{
	if (image.isNull())
		return QByteArray();
	const QImage small =
	        image.width() > FZN_CALL_VIDEO_WIDTH || image.height() > FZN_CALL_VIDEO_HEIGHT
	                ? image.scaled(FZN_CALL_VIDEO_WIDTH, FZN_CALL_VIDEO_HEIGHT, Qt::KeepAspectRatio, Qt::SmoothTransformation)
	                : image;
	/* THE BEST QUALITY THAT FITS, stepping down: a face reads at 40. */
	for (int quality = 80; quality >= 10; quality -= 10) {
		QByteArray out;
		QBuffer buf(&out);

		buf.open(QIODevice::WriteOnly);
		if (small.save(&buf, "JPG", quality) && (size_t)out.size() <= max)
			return out;
	}
	return QByteArray();
}

QImage fzn_video_decode(const uint8_t *media, size_t len)
{
	if (!media || !len)
		return QImage();
	return QImage::fromData(media, (int)len, "JPG");
}

fzn_call_video::fzn_call_video(const QString &node_socket, QObject *owner)
    : m_node_socket(node_socket), m_owner(owner), m_media(new fzn_rpc_media)
{
	memset(m_media, 0, sizeof(*m_media));
	m_media->fd = -1;
}

fzn_call_video::~fzn_call_video()
{
	stop();
	delete m_camera;
	delete m_media;
}

bool fzn_call_video::running() const { return m_open; }

bool fzn_call_video::start(const QString &id)
{
	fzn_rpc_t c;
	const QByteArray hex = id.toLatin1(), path = m_node_socket.toUtf8();

	stop();
	if (!m_closed_id.isEmpty() && id == m_closed_id)
		return false;
	m_closed_id.clear();
	fzn_rpc_init(&c);
	if ((size_t)path.size() >= sizeof(c.node_socket)) {
		m_trouble = QObject::tr("The node's socket path is too long.");
		return false;
	}
	memcpy(c.node_socket, path.constData(), (size_t)path.size());
	c.node_socket[path.size()] = '\0';
	if (fzn_rpc_media_open(&c, hex.constData(), m_media) != FZN_RPC_OK) {
		m_trouble = QString::fromUtf8(c.error[0] ? c.error : "the node would not open the call's picture");
		/* SAID ONCE, not tried at every refresh: a node from before sec
		 * 1113 has no channel, and the call is sound only. */
		m_closed_id = id;
		return false;
	}
	return opened(id);
}

bool fzn_call_video::attach(int fd, const QString &id)
{
	uint8_t call[8];
	const QByteArray hex = QByteArray::fromHex(id.toLatin1());

	stop();
	if (hex.size() != 8) {
		m_trouble = QObject::tr("That is not a call.");
		return false;
	}
	memcpy(call, hex.constData(), 8);
	if (fzn_rpc_media_attach(nullptr, m_media, fd, call) != FZN_RPC_OK) {
		m_trouble = QObject::tr("The node would not open the call's picture.");
		return false;
	}
	return opened(id);
}

bool fzn_call_video::opened(const QString &id)
{
	m_id = id;
	m_open = true;
	m_picture_at_ms = -1;
	/* A CHANNEL OPEN FOR IT, by `start` or `attach`: no longer closed. */
	m_closed_id.clear();
	m_trouble.clear();
	m_sent = m_received = 0;
	m_started_ms = QDateTime::currentMSecsSinceEpoch();
	/* READ AS IT ARRIVES: a frame late is worth nothing, and the node closes
	 * a channel nobody reads rather than keeping it (sec 1113). */
	m_notifier = new QSocketNotifier(fzn_rpc_media_fd(m_media), QSocketNotifier::Read, m_owner);
	QObject::connect(m_notifier, &QSocketNotifier::activated, [this]() { poll(); });
	if (m_camera_wanted)
		set_camera(true);
	return true;
}

void fzn_call_video::stop()
{
	if (m_camera)
		m_camera->stop();
	delete m_notifier;
	m_notifier = nullptr;
	if (m_open)
		fzn_rpc_media_close(m_media);
	m_open = false;
	m_picture_at_ms = -1;
}

void fzn_call_video::poll()
{
	fzn_rpc_media_frame_t f;
	int r;

	while (m_open && (r = fzn_rpc_media_recv(m_media, &f)) != 0) {
		if (r < 0) {
			/* THE CHANNEL CLOSED: the call ended, or the node let it go --
			 * not opened again for this call (sec 1491). */
			m_trouble = QObject::tr("The call's picture stopped.");
			m_closed_id = m_id;
			stop();
			return;
		}
		if (f.stream != 2u)
			continue;
		const QImage picture = fzn_video_decode(f.media, f.media_len);
		if (picture.isNull())
			continue;
		m_received++;
		m_picture_at_ms = QDateTime::currentMSecsSinceEpoch();
		if (m_told)
			m_told(picture);
	}
}

bool fzn_call_video::send_picture(const QImage &image)
{
	if (!m_open)
		return false;
	const QByteArray frame = fzn_video_encode(image, FZN_RPC_MEDIA_MAX);
	if (frame.isEmpty())
		return false;
	const uint32_t at = (uint32_t)(QDateTime::currentMSecsSinceEpoch() - m_started_ms);
	if (fzn_rpc_media_send(m_media, 2, m_sent, at, reinterpret_cast<const uint8_t *>(frame.constData()),
	                       (size_t)frame.size())
	    != FZN_RPC_OK)
		return false;
	m_sent++;
	return true;
}

qint64 fzn_call_video::picture_age_ms() const
{
	return m_picture_at_ms < 0 ? -1 : QDateTime::currentMSecsSinceEpoch() - m_picture_at_ms;
}

void fzn_call_video::set_camera(bool on)
{
	m_camera_wanted = on;
	if (!on) {
		if (m_camera)
			m_camera->stop();
		return;
	}
	/* EACH FRAME SENT, and shown to its own person as a mirror shows. */
	auto each = [this](const QImage &frame) {
		(void)send_picture(frame);
		if (m_own_told)
			m_own_told(m_camera->front() ? frame.mirrored(true, false) : frame);
	};
	if (!m_camera)
		m_camera = new fzn_camera_feed(m_owner, each, [this]() { m_trouble = m_camera->why(); });
	/* NO CHANNEL YET: started with the next one (`opened`). */
	if (!m_open)
		return;
	if (!m_camera->start())
		m_trouble = m_camera->why();
}

bool fzn_call_video::camera_on() const { return m_camera && m_camera->running(); }
