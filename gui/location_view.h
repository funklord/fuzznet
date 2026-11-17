/*
 * Where the people sharing a position with this user are, as a widget other
 * software hosts, sec 1109 -- the register's "a location view" (sec 1070),
 * the Nearby screen every consumer showing positions was writing alone.
 *
 * THIS HOST FIRST: whether it samples its own position, from where and how
 * often, or why it stopped -- the comparison the node keeps for exactly this.
 * THEN EACH CONTACT'S NEWEST FIX: where, how sure (the accuracy, a coarse fix
 * said so), how old, and from this host's own newest fix how far and which
 * way -- a bearing only where the two fixes' accuracy leaves it meaning
 * something (location/geo.h decides).
 *
 * WHAT A PERSON DOES: ask a contact for its position now, and grant or take
 * back this user's own position to them. Through the typed client on the
 * host's ask callback (`rpc_ask.h`), as the other views are. The clock is the
 * host's to set, so a test fixes "now". NO Q_OBJECT AND THEREFORE NO moc.
 *
 * WHAT A HOST'S OTHER WIDGETS DRAW, sec 1197, from fuzzypickles' list of
 * what its Nearby page did and this did not (inbox 20261117T0122Z): a
 * contact's badge -- an arrow and a distance while the fix is fresh, its
 * age once it is not, so a stale distance is never shown as current -- and
 * whether it is stale, for a list to dim it. A contact's place as a map
 * link, the bearing in degrees beside its compass word, asking again too
 * soon said with when it was last asked, and a host with no fix of its own
 * told why no distance shows and that the map works without one.
 */

#ifndef FZN_GUI_LOCATION_VIEW_H
#define FZN_GUI_LOCATION_VIEW_H

#include "notebook_view.h"

#include <QHash>
#include <QString>
#include <QStringList>
#include <QUrl>
#include <QWidget>

#include <functional>

#include <stdint.h>

struct fzn_gui_rpc;
class QComboBox;
class fzn_compass_rose;
class fzn_heading_feed;
class QHideEvent;
class QLabel;
class QPushButton;
class QResizeEvent;
class QShowEvent;
class QTableWidget;

/* A FIX THIS OLD IS SHOWN BY ITS AGE, not its distance: five minutes, as
 * fuzzypickles' badge had it. */
#define FZN_LOCATION_VIEW_FRESH_S 300u
/* ASKING A CONTACT AGAIN within this is said, with when it was asked. */
#define FZN_LOCATION_VIEW_ASK_GAP_S 5u

class fzn_location_view : public QWidget {
public:
	fzn_location_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent = nullptr);
	~fzn_location_view() override;

	/* Ask for this host's sampling, its own newest fix and every contact's,
	 * and show them. Whether the node answered. */
	bool refresh();

	/* WHAT A PERSON DOES, public because a headless test cannot click. */
	void select(int row);
	bool fetch();
	bool share(bool on);
	/* THE PRECISION a grant gives (a fzn_rpc_location_precision_t): chosen
	 * before sharing, and read back from what this host grants the contact
	 * chosen, sec 1119. */
	void set_precision(int precision);
	int precision() const;

	/* The clock, seconds since 1970; 0 reads the system's. */
	void set_now(uint32_t utc_s);

	/* A CONTACT'S BADGE, by name, for another widget beside the name: an
	 * arrow and the distance while the fix is fresh (FZN_LOCATION_VIEW_FRESH_S),
	 * "here" within its accuracy, the age once it is stale or this host has
	 * no fix of its own; empty for a contact whose position does not reach
	 * this host. As of the last refresh. */
	QString badge_for(const QString &name) const;
	/* Whether that badge is an age rather than a distance; never for an
	 * empty one, which has nothing to dim. */
	bool badge_is_stale(const QString &name) const;
	/* Where a contact is, as a map opens it: geo: on Android, OpenStreetMap
	 * elsewhere. Empty for no fix. */
	QUrl map_url(const QString &name) const;
	bool show_on_map();
	/* WHAT OPENS A MAP, sec 1233: QDesktopServices by default; a host or a
	 * test may give its own, which says whether it opened one. */
	void set_map_opener(std::function<bool(const QUrl &)> open);

	/* THE CONTACT CHOSEN, by name, or empty, sec 1233 -- and told when it
	 * changes, not on every refresh, for a host driving something beside
	 * the view (fuzzypickles' rose, 1135Z). */
	QString chosen() const;
	void on_chosen(std::function<void(const QString &name)> told);
	/* THE BEARING TO `name` from this host's fix, degrees from north, and
	 * the distance in metres when `metres` is given: 1 where a bearing
	 * means something -- both fresh, and farther apart than they are
	 * unsure -- else 0. */
	bool bearing_to(const QString &name, double *deg, double *metres = nullptr) const;
	/* Whether the compass is being read now: while shown, with the
	 * application active, and only where there is one. */
	bool heading_running() const;

	/* WHICH WAY THE DEVICE FACES, sec 1211: degrees clockwise from north,
	 * from its compass where the build has Qt Sensors and else from the
	 * host. The compass rose turns with it and points at the contact
	 * chosen, and the badges' arrows point as the device is held.
	 * Cleared, both are north-up. */
	void set_heading(double deg);
	void clear_heading();
	const fzn_compass_rose *rose() const { return m_rose; }

	/* WHAT IS ON SCREEN: this host's line, each row as its cells joined by
	 * " | ", and the status line. */
	QString own() const;
	QStringList rows() const;
	QString status() const;

protected:
	/* A PHONE'S WIDTH, sec 1197: under 400 pixels the place in degrees and
	 * how sure it is are hidden; who, when and how far stay. */
	void resizeEvent(QResizeEvent *event) override;
	/* THE COMPASS READ ONLY WHILE ON SCREEN, sec 1233. */
	void showEvent(QShowEvent *event) override;
	void hideEvent(QHideEvent *event) override;

private:
	struct fzn_gui_rpc *m_rpc;
	uint32_t m_now;
	/* As of the last refresh: each contact's newest fix by name, and this
	 * host's own, if it has one. */
	struct fix {
		int32_t lat_e7, lon_e7;
		uint32_t utc_s, sure_m;
	};
	QHash<QString, fix> m_fixes;
	fix m_mine;
	bool m_have_mine;
	/* When each contact was last asked, for "too soon" (FZN_LOCATION_VIEW_ASK_GAP_S). */
	QHash<QString, uint32_t> m_asked;
	uint32_t now() const;
	QPushButton *m_map;
	fzn_compass_rose *m_rose;
	fzn_heading_feed *m_feed;
	bool m_have_heading = false;
	double m_heading = 0.0;
	void feed_track();
	std::function<bool(const QUrl &)> m_open_map;
	std::function<void(const QString &)> m_on_chosen;
	QString m_chosen_told;

	QLabel *m_own;
	QTableWidget *m_table;
	QPushButton *m_fetch;
	QPushButton *m_share;
	QPushButton *m_unshare;
	QComboBox *m_precision;
	QPushButton *m_refresh;
	QLabel *m_status;
};

#endif /* FZN_GUI_LOCATION_VIEW_H */
