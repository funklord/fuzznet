/* The way this device faces, from its compass: heading_feed.h, sec 1211. */
#include "heading_feed.h"

#include <QObject>

#ifdef FZN_SENSORS_ON
#include <QCompass>
#include <QCompassReading>
#endif

fzn_heading_feed::fzn_heading_feed(std::function<void(double)> told) : m_compass(nullptr), m_told(told)
{
#ifdef FZN_SENSORS_ON
	auto *compass = new QCompass;

	m_compass = compass;
	QObject::connect(compass, &QCompass::readingChanged, compass, [this, compass]() {
		const QCompassReading *r = compass->reading();
		if (r && r->calibrationLevel() >= 1.0 / 3.0 && m_told)
			m_told(r->azimuth());
	});
	if (!compass->start()) {
		delete compass;
		m_compass = nullptr;
	}
#endif
}

fzn_heading_feed::~fzn_heading_feed() { delete m_compass; }

bool fzn_heading_feed::active() const { return m_compass != nullptr; }
