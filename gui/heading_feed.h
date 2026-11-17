/*
 * The way this device faces, from its compass: fuzznet sec 1211.
 *
 * Qt Sensors' QCompass, where the build has Qt Sensors (FZN_SENSORS_ON, as
 * the camera is where Qt Multimedia is, sec 1158); elsewhere `active` is
 * false and nothing is fed, and a view draws north-up and says so. The
 * azimuth is told as it changes, degrees clockwise from north. A reading
 * the sensor calls uncalibrated below one third is not told: a needle
 * pointing confidently the wrong way is worse than none.
 */
#ifndef FZN_GUI_HEADING_FEED_H
#define FZN_GUI_HEADING_FEED_H

#include <functional>

class QObject;

class fzn_heading_feed {
public:
	explicit fzn_heading_feed(std::function<void(double deg)> told);
	~fzn_heading_feed();
	fzn_heading_feed(const fzn_heading_feed &) = delete;
	fzn_heading_feed &operator=(const fzn_heading_feed &) = delete;

	/* Whether a compass is giving readings. */
	bool active() const;
	/* READ ONLY WHILE WANTED, sec 1233: a compass read tens of times a
	 * second costs a phone's battery whether anybody looks or not, so a
	 * host stops it while its view is hidden and starts it again on show.
	 * Neither does anything without a compass. */
	void start();
	void stop();
	bool running() const;

private:
	QObject *m_compass;
	std::function<void(double)> m_told;
};

#endif /* FZN_GUI_HEADING_FEED_H */
