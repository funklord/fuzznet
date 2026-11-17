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

void fzn_heading_feed::start()
{
#ifdef FZN_SENSORS_ON
	if (m_compass && !static_cast<QCompass *>(m_compass)->isActive())
		(void)static_cast<QCompass *>(m_compass)->start();
#endif
}

void fzn_heading_feed::stop()
{
#ifdef FZN_SENSORS_ON
	if (m_compass)
		static_cast<QCompass *>(m_compass)->stop();
#endif
}

bool fzn_heading_feed::running() const
{
#ifdef FZN_SENSORS_ON
	return m_compass && static_cast<QCompass *>(m_compass)->isActive();
#else
	return false;
#endif
}

bool fzn_heading_feed::active() const { return m_compass != nullptr; }
