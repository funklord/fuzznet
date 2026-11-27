/*
 * The device's camera as a stream of pictures: fuzznet sec 1158.
 *
 * Camera capture is fuzznet's (the holder, sec 1069), and the first thing
 * that wants it is scanning a code: the devices view joins with the code a
 * camera reads off another host's screen (sec 1158), and a contact card is
 * the same act. So this is no view of its own -- a widget starts it, is
 * handed each frame as a QImage, and stops it once it has what it wanted.
 *
 * Through Qt 6 Multimedia, which is a camera on Linux, Android and the rest
 * from one API; fuzzypickles' V4L2 module reaches only the first. Built only
 * where Qt 6 Multimedia is (FZN_CAMERA_ON); elsewhere `start` says why not
 * and returns false, and a picture from a file is the way left.
 *
 * FRAMES ARE THINNED AND SHRUNK before they are handed on: a camera gives
 * thirty a second at its own size, and a code read from the eighth frame of
 * a second is read as soon as a person can tell. One every 125 ms, no wider
 * than 960 pixels, which a code filling a third of the picture survives.
 *
 * NO Q_OBJECT AND THEREFORE NO moc: signals are taken with lambdas.
 */
#ifndef FZN_GUI_CAMERA_FEED_H
#define FZN_GUI_CAMERA_FEED_H

#include <QString>

#include <functional>

class QImage;
class QObject;
class QVideoFrame;

class fzn_camera_feed {
public:
	typedef std::function<void(const QImage &frame)> each_t;
	typedef std::function<void()> stopped_t;

	/* `owner` parents what Qt makes, so it goes with the widget.
	 * `stopped`, when given, is told a camera that failed after it opened,
	 * the words in `why()`; a stop asked for is not told. */
	fzn_camera_feed(QObject *owner, each_t each, stopped_t stopped = stopped_t());
	~fzn_camera_feed();

	/* Whether this build has a camera at all. */
	static bool built();

	/* START the default camera: true once asked, and false with the words
	 * why in `why` -- not built, no camera, or not allowed. On a platform
	 * that asks the person first (Android), true may come before the
	 * answer, and a refusal then arrives as `why()`. */
	bool start();
	void stop();
	bool running() const;
	QString why() const;
	/* WHETHER IT FACES THE PERSON, as of the last start: a front camera's
	 * picture is shown to its own person mirrored, as a mirror is (sec
	 * 1491). False where none opened or the platform does not say. */
	bool front() const;

	/* GREY IS ENOUGH -- a code to read, not a face to show: a phone camera's
	 * frame is then handed on as its luma plane, copied, rather than
	 * converted to colour (sec 1409). Off unless asked. */
	void set_gray(bool gray);
	/* A FRAME AS A PICTURE, as the feed makes one: the luma plane copied
	 * where `gray` and the frame is NV12, NV21, YUV420P or YV12, else Qt's
	 * conversion. Public so a test can hand it a frame it made. Defined
	 * only where the build has a camera. */
	static QImage picture(const QVideoFrame &frame, bool gray);
	/* A FRAME AS THE CAMERA WOULD HAND IT, thinned and shrunk as one from
	 * the camera is: public so a test without a camera can drive it. */
	void frame(const QImage &picture);

private:
	struct impl;
	impl *m;
	bool open();
};

#endif /* FZN_GUI_CAMERA_FEED_H */
