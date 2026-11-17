/* A compass rose that points at a contact: compass_rose.h, sec 1211. */
#include "compass_rose.h"

#include <QPainter>
#include <QPainterPath>
#include <QPalette>

#include <math.h>

/* An angle into [0, 360). */
static double wrapped(double deg)
{
	double a = fmod(deg, 360.0);
	return a < 0.0 ? a + 360.0 : a;
}

fzn_compass_rose::fzn_compass_rose(QWidget *parent) : QWidget(parent)
{
	setAccessibleName(tr("Which way"));
	said_changed();
}

void fzn_compass_rose::set_heading(double deg)
{
	m_heading = wrapped(deg);
	m_have_heading = true;
	said_changed();
}

void fzn_compass_rose::clear_heading()
{
	m_have_heading = false;
	said_changed();
}

void fzn_compass_rose::set_target(const QString &who, double bearing_deg)
{
	m_who = who;
	m_bearing = wrapped(bearing_deg);
	m_have_target = true;
	said_changed();
}

void fzn_compass_rose::clear_target()
{
	m_have_target = false;
	m_who.clear();
	said_changed();
}

double fzn_compass_rose::needle_deg() const
{
	if (!m_have_target)
		return -1.0;
	return wrapped(m_bearing - (m_have_heading ? m_heading : 0.0));
}

QString fzn_compass_rose::said() const
{
	if (!m_have_target)
		return tr("No one to point at.");
	const int bearing = (int)lround(m_bearing) % 360;
	if (!m_have_heading)
		return tr("%1 is at %2 degrees from north; this device's heading is not known, so north is up.")
		        .arg(m_who)
		        .arg(bearing);
	/* RELATIVE, in (-180, 180]: right is positive. */
	double r = needle_deg();
	if (r > 180.0)
		r -= 360.0;
	const int a = (int)lround(fabs(r));
	if (a <= 15)
		return tr("%1 is straight ahead.").arg(m_who);
	if (a >= 165)
		return tr("%1 is behind you.").arg(m_who);
	return r > 0.0 ? tr("%1 is %2 degrees to your right.").arg(m_who).arg(a)
	               : tr("%1 is %2 degrees to your left.").arg(m_who).arg(a);
}

void fzn_compass_rose::said_changed()
{
	setAccessibleDescription(said());
	setToolTip(said());
	update();
}

void fzn_compass_rose::paintEvent(QPaintEvent *)
{
	QPainter p(this);
	const QPalette &pal = palette();
	const double side = qMin(width(), height());
	const double r = side / 2.0 - 4.0;
	static const char *const cardinal[4] = { "N", "E", "S", "W" };

	p.setRenderHint(QPainter::Antialiasing);
	p.translate(width() / 2.0, height() / 2.0);
	p.setPen(QPen(pal.color(QPalette::WindowText), 1.5));
	p.setBrush(pal.color(QPalette::Base));
	p.drawEllipse(QPointF(0, 0), r, r);
	/* THE CARDS, turned so N is where north is: against the heading. */
	p.save();
	p.rotate(m_have_heading ? -m_heading : 0.0);
	for (int i = 0; i < 4; i++) {
		const QRectF box(-12, -r + 2, 24, 18);
		p.setPen(i == 0 ? pal.color(QPalette::Highlight) : pal.color(QPalette::WindowText));
		p.drawText(box, Qt::AlignCenter, QString::fromLatin1(cardinal[i]));
		p.rotate(90.0);
	}
	p.restore();
	if (!m_have_target)
		return;
	/* THE NEEDLE, from the middle toward the contact. */
	p.rotate(needle_deg());
	QPainterPath needle;
	needle.moveTo(0, -r + 22);
	needle.lineTo(7, 0);
	needle.lineTo(-7, 0);
	needle.closeSubpath();
	p.setPen(Qt::NoPen);
	p.setBrush(pal.color(QPalette::Highlight));
	p.drawPath(needle);
}
