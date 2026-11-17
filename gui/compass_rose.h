/*
 * A compass rose that points at a contact: fuzznet sec 1211, the Nearby
 * page's last item (fuzzypickles' inbox 20261117T0122Z, the holder's word in
 * sec 1208 -- both phones tested have a heading sensor).
 *
 * THE NEEDLE IS THE BEARING LESS THE HEADING: with the phone's heading
 * known, the rose turns so its N is where north is, and the needle points
 * where the contact is, as the phone is held. With no heading the rose is
 * north-up, the needle the bearing from north, and it says so -- a needle
 * that does not move with the phone must not look as though it did.
 *
 * WHAT IS SAID, for a reader who cannot see it and for a test: "alice is
 * straight ahead", "40 degrees to your right", "behind you", or with no
 * heading "at 120 degrees from north". Within 15 degrees is ahead and past
 * 165 behind, as a person points rather than as an instrument reads.
 *
 * It draws and decides nothing else: the heading comes from whoever has
 * it (`heading_feed` where Qt Sensors is, or the host), the bearing from
 * `location_view`, which knows when one means something. NO Q_OBJECT.
 */
#ifndef FZN_GUI_COMPASS_ROSE_H
#define FZN_GUI_COMPASS_ROSE_H

#include <QString>
#include <QWidget>

class fzn_compass_rose : public QWidget {
public:
	explicit fzn_compass_rose(QWidget *parent = nullptr);

	/* The way the phone faces, degrees clockwise from north; cleared, the
	 * rose is north-up. */
	void set_heading(double deg);
	void clear_heading();
	bool has_heading() const { return m_have_heading; }

	/* Who the needle points at and their bearing from here, degrees from
	 * north; cleared, there is no needle. */
	void set_target(const QString &who, double bearing_deg);
	void clear_target();

	/* THE NEEDLE ON SCREEN, degrees clockwise from straight up, in
	 * [0, 360); -1 with no target. And what is said of it. */
	double needle_deg() const;
	QString said() const;

	QSize sizeHint() const override { return QSize(160, 160); }
	QSize minimumSizeHint() const override { return QSize(96, 96); }

protected:
	void paintEvent(QPaintEvent *event) override;

private:
	void said_changed();

	bool m_have_heading = false, m_have_target = false;
	double m_heading = 0.0, m_bearing = 0.0;
	QString m_who;
};

#endif /* FZN_GUI_COMPASS_ROSE_H */
