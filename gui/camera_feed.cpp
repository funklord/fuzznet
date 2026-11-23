/* The device's camera as a stream of pictures: gui/camera_feed.h, sec 1158. */
#include "camera_feed.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QImage>
#include <QObject>
#include <QTimer>

#include <memory>
#include <mutex>

#ifdef FZN_CAMERA_ON
#include <QCamera>
#include <QCameraDevice>
#include <QMediaCaptureSession>
#include <QMediaDevices>
#include <QVideoFrame>
#include <QVideoSink>
#if QT_CONFIG(permissions)
#include <QPermissions>
#endif
#endif

/* ONE FRAME IN EIGHT of a camera's thirty, and none wider than a code
 * needs: the header says why. */
#define FRAME_EVERY_MS 125
#define FRAME_WIDTH_MAX 960

#ifdef FZN_CAMERA_ON
/* THE NEWEST FRAME, and nothing more, sec 1409: written on the camera's
 * thread, taken on the GUI thread. Shared, so a frame arriving while the
 * feed stops finds this still there. */
struct newest_frame {
	std::mutex lock;
	QVideoFrame frame;
	bool live = false;
};
#endif

struct fzn_camera_feed::impl {
	QObject *owner;
	each_t each;
	stopped_t stopped;
	QElapsedTimer since;
	QString why;
	bool asking; /* the person is being asked for the camera */
	bool gray;   /* the luma plane is enough */
#ifdef FZN_CAMERA_ON
	QCamera *camera;
	QMediaCaptureSession *session;
	QVideoSink *sink;
	QTimer *tick;
	std::shared_ptr<newest_frame> newest;
#endif
};

fzn_camera_feed::fzn_camera_feed(QObject *owner, each_t each, stopped_t stopped) : m(new impl)
{
	m->owner = owner;
	m->each = std::move(each);
	m->stopped = std::move(stopped);
	m->asking = false;
	m->gray = false;
#ifdef FZN_CAMERA_ON
	m->camera = nullptr;
	m->session = nullptr;
	m->sink = nullptr;
	m->tick = nullptr;
#endif
}

void fzn_camera_feed::set_gray(bool gray) { m->gray = gray; }

fzn_camera_feed::~fzn_camera_feed()
{
	stop();
	delete m;
}

bool fzn_camera_feed::built()
{
#ifdef FZN_CAMERA_ON
	return true;
#else
	return false;
#endif
}

#ifdef FZN_CAMERA_ON
/* A FRAME AS A PICTURE: the luma plane copied as it lies where grey is
 * enough and the frame is one of the planar or semi-planar YUV formats a
 * phone's camera gives, whose first plane IS luma; otherwise Qt's own
 * conversion, a readback and a colour transform. */
QImage fzn_camera_feed::picture(const QVideoFrame &shown, bool gray)
{
	QVideoFrame frame(shown);
	const QVideoFrameFormat::PixelFormat f = frame.pixelFormat();

	if (gray
	    && (f == QVideoFrameFormat::Format_NV12 || f == QVideoFrameFormat::Format_NV21
	        || f == QVideoFrameFormat::Format_YUV420P || f == QVideoFrameFormat::Format_YV12)
	    && frame.map(QVideoFrame::ReadOnly)) {
		const QImage luma(frame.bits(0), frame.width(), frame.height(), frame.bytesPerLine(0),
		                  QImage::Format_Grayscale8);
		QImage copy = luma.copy();

		frame.unmap();
		return copy;
	}
	return frame.toImage();
}

/* THE CAMERA ITSELF, once the person has let it be used.
 *
 * NOTHING IS CONVERTED ON ARRIVAL, sec 1409. A frame arrives on the
 * camera's thread thirty times a second; it was queued to the GUI thread
 * and converted there, each one, before `frame` thinned to one in eight --
 * conversion slower than arrival, so the queue grew until Android called
 * the program not responding (fuzzypickles, fuzznet inbox 20261123T1250Z).
 * Now the camera's thread only keeps the newest frame, and a timer on the
 * GUI thread converts that one, every FRAME_EVERY_MS. */
bool fzn_camera_feed::open()
{
	fzn_camera_feed *feed = this;

	QCameraDevice device = QMediaDevices::defaultVideoInput();

	if (device.isNull()) {
		m->why = QObject::tr("No camera was found on this device.");
		return false;
	}
	m->camera = new QCamera(device, m->owner);
	m->session = new QMediaCaptureSession(m->owner);
	m->sink = new QVideoSink(m->owner);
	m->session->setCamera(m->camera);
	m->session->setVideoSink(m->sink);
	m->newest = std::make_shared<newest_frame>();
	m->newest->live = true;
	{
		std::shared_ptr<newest_frame> newest = m->newest;

		QObject::connect(
		        m->sink, &QVideoSink::videoFrameChanged, m->sink,
		        [newest](const QVideoFrame &f) {
			        std::lock_guard<std::mutex> hold(newest->lock);

			        if (newest->live)
				        newest->frame = f;
		        },
		        Qt::DirectConnection);
	}
	m->tick = new QTimer(m->owner);
	m->tick->setInterval(FRAME_EVERY_MS);
	QObject::connect(m->tick, &QTimer::timeout, m->owner, [feed, this]() {
		QVideoFrame f;

		if (!m->newest)
			return;
		{
			std::lock_guard<std::mutex> hold(m->newest->lock);

			f = m->newest->frame;
			m->newest->frame = QVideoFrame();
		}
		if (f.isValid())
			feed->frame(picture(f, m->gray));
	});
	m->tick->start();
	QObject::connect(m->camera, &QCamera::errorOccurred, m->owner,
	                 [feed, this](QCamera::Error, const QString &words) {
		                 m->why = words.isEmpty() ? QObject::tr("The camera stopped.") : words;
		                 feed->stop();
		                 if (m->stopped)
			                 m->stopped();
	                 });
	m->since.invalidate();
	m->camera->start();
	return true;
}
#endif

bool fzn_camera_feed::start()
{
	m->why.clear();
	if (running())
		return true;
#ifndef FZN_CAMERA_ON
	m->why = QObject::tr("This build has no camera. Choose a picture instead.");
	return false;
#else
#if QT_CONFIG(permissions)
	/* ASKED, where the platform asks the person (Android): the camera
	 * opens when they say yes. */
	QCameraPermission permission;
	switch (qApp->checkPermission(permission)) {
	case Qt::PermissionStatus::Undetermined:
		m->asking = true;
		qApp->requestPermission(permission, m->owner, [this](const QPermission &p) {
			m->asking = false;
			if (p.status() == Qt::PermissionStatus::Granted)
				(void)open();
			else
				m->why = QObject::tr("The camera was not allowed.");
		});
		return true;
	case Qt::PermissionStatus::Denied:
		m->why = QObject::tr("The camera is not allowed for this program. Allow it in the system's settings.");
		return false;
	case Qt::PermissionStatus::Granted:
		break;
	}
#endif
	return open();
#endif
}

void fzn_camera_feed::stop()
{
	m->asking = false;
#ifdef FZN_CAMERA_ON
	/* CUT OFF AT ONCE, so no frame arrives for a feed that has stopped, and
	 * deleted LATER: stop() is also called from the camera's own error
	 * signal, and an object deleted inside its signal is used after. */
	if (m->newest) {
		std::lock_guard<std::mutex> hold(m->newest->lock);

		m->newest->live = false;
		m->newest->frame = QVideoFrame();
	}
	m->newest.reset();
	if (m->tick) {
		m->tick->stop();
		m->tick->deleteLater();
	}
	m->tick = nullptr;
	if (m->camera) {
		QObject::disconnect(m->camera, nullptr, m->owner, nullptr);
		QObject::disconnect(m->sink, nullptr, nullptr, nullptr);
		m->camera->stop();
		m->session->deleteLater();
		m->sink->deleteLater();
		m->camera->deleteLater();
	}
	m->session = nullptr;
	m->sink = nullptr;
	m->camera = nullptr;
#endif
}

bool fzn_camera_feed::running() const
{
#ifdef FZN_CAMERA_ON
	return m->asking || m->camera;
#else
	return false;
#endif
}

QString fzn_camera_feed::why() const { return m->why; }

void fzn_camera_feed::frame(const QImage &picture)
{
	if (picture.isNull() || !m->each)
		return;
	if (m->since.isValid() && m->since.elapsed() < FRAME_EVERY_MS)
		return;
	m->since.start();
	if (picture.width() > FRAME_WIDTH_MAX)
		m->each(picture.scaledToWidth(FRAME_WIDTH_MAX, Qt::FastTransformation));
	else
		m->each(picture);
}
