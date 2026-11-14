/* The device's camera as a stream of pictures: gui/camera_feed.h, sec 1158. */
#include "camera_feed.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QImage>
#include <QObject>

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

struct fzn_camera_feed::impl {
	QObject *owner;
	each_t each;
	stopped_t stopped;
	QElapsedTimer since;
	QString why;
	bool asking; /* the person is being asked for the camera */
#ifdef FZN_CAMERA_ON
	QCamera *camera;
	QMediaCaptureSession *session;
	QVideoSink *sink;
#endif
};

fzn_camera_feed::fzn_camera_feed(QObject *owner, each_t each, stopped_t stopped) : m(new impl)
{
	m->owner = owner;
	m->each = std::move(each);
	m->stopped = std::move(stopped);
	m->asking = false;
#ifdef FZN_CAMERA_ON
	m->camera = nullptr;
	m->session = nullptr;
	m->sink = nullptr;
#endif
}

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
/* THE CAMERA ITSELF, once the person has let it be used. */
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
	QObject::connect(m->sink, &QVideoSink::videoFrameChanged, m->owner,
	                 [feed](const QVideoFrame &f) { feed->frame(f.toImage()); });
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
	if (m->camera) {
		QObject::disconnect(m->camera, nullptr, m->owner, nullptr);
		QObject::disconnect(m->sink, nullptr, m->owner, nullptr);
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
