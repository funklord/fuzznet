#ifndef FZN_LOCATION_GEO_H
#define FZN_LOCATION_GEO_H

#include <stddef.h>
#include <stdint.h>

/*
 * Distance and bearing between two position fixes: the "find your friends"
 * indicator, taken from fuzzypickles' client/geo.c (fuzznet sec 1093).
 *
 * WHY HERE, AND NOT IN A FRONTEND
 *   "How far away and in which direction" is arithmetic, not drawing. A Qt
 *   window renders it as a rotating arrow on a map; a terminal renders the
 *   same two numbers as text and a compass point. Sharing the maths and
 *   duplicating only the presentation is the seam: every consumer of
 *   fuzznet's location stream gets the same answer.
 *
 * WHY IT NEEDS THE MATHS LIBRARY
 *   It is trigonometry -- haversine and atan2 -- where the rest of location/
 *   is integer work on fixes; a program that calls it links -lm.
 *
 * WHAT IS NOT HERE, DELIBERATELY
 *   Device orientation. Pointing an arrow at someone needs to know which
 *   way the DEVICE is facing, which is a magnetometer/accelerometer
 *   reading, not a position. That is a separate source from GNSS: different
 *   hardware, a much higher update rate, and -- most importantly -- it is
 *   never stored and never transmitted. Your compass heading is a now-only
 *   local value used to rotate a widget, as presence is now-only. Only
 *   positions travel between hosts; keeping it out of this header is what
 *   stops it drifting into the stored record.
 */

/* Mean Earth radius, metres (IUGG). Haversine on a sphere is ~0.5% off an
 * ellipsoid, which is metres over a kilometre -- far inside GNSS error, so
 * a full Vincenty solution would be false precision here. */
#define FZN_GEO_EARTH_RADIUS_M 6371008.8

/*
 * Great-circle distance in metres between two fixes given as 1e-7 degrees
 * (fzn_location_fix_t's own units, so callers never convert by hand).
 */
double fzn_geo_distance_m(int32_t lat1_e7, int32_t lon1_e7, int32_t lat2_e7, int32_t lon2_e7);

/*
 * Initial bearing from point 1 to point 2, in degrees clockwise from TRUE
 * north, normalised to [0, 360).
 *
 * TRUE north, not magnetic -- this is derived from coordinates, so it has
 * no magnetic component at all. A device compass reads MAGNETIC north, and
 * the difference (declination) reaches ~20 degrees in populated areas and
 * far more at high latitudes. Twenty degrees at 500 m is 170 m of error, so
 * a frontend that rotates an arrow by a raw magnetometer reading against
 * this bearing will point confidently at the wrong place. Correcting it
 * needs a world magnetic model, or a platform API that already applies one
 * (Android's does; a bare Linux magnetometer does not). Flagged here
 * because it is invisible in testing and wrong in the field.
 */
double fzn_geo_bearing_deg(int32_t lat1_e7, int32_t lon1_e7, int32_t lat2_e7, int32_t lon2_e7);

/*
 * Whether a bearing is worth showing as a direction at all.
 *
 * Two fixes each with tens of metres of error say very little about
 * direction when the targets are close together: the angular uncertainty is
 * roughly atan(combined_accuracy / distance), so 30 m of combined error at
 * 50 m apart is about 31 degrees -- an arrow that is confidently meaningless.
 * The same error at 1 km is under 2 degrees and perfectly usable.
 *
 * Returns 1 when distance exceeds FZN_GEO_BEARING_MIN_RATIO times the
 * combined accuracy (about 11 degrees of uncertainty), 0 otherwise. A
 * frontend should fall back to "somewhere within N m" rather than draw an
 * arrow when this returns 0.
 */
#define FZN_GEO_BEARING_MIN_RATIO 5.0
int fzn_geo_bearing_is_meaningful(double distance_m, double combined_accuracy_m);

/*
 * Formats a distance for display: metres below 1 km, kilometres above, with
 * precision that does not outrun the measurement (no "1.4837 km" from fixes
 * good to 20 m). Returns 0 on success, -1 if out_cap is too small.
 */
int fzn_geo_format_distance(char *out, size_t out_cap, double metres);

/*
 * Elevation angle from one fix to another, in degrees: positive when the
 * target is above the observer, negative below, zero level.
 *
 * THE MISSING-ALTITUDE RULE
 *   Altitude is optional in a fix, and either end may lack it. When either
 *   does, this returns 0 and reports elevation_known = 0: the arrow lies
 *   flat against the earth rather than disappearing. A direction is still
 *   worth showing when the height is unknown -- "that way, level" is the
 *   honest rendering of what is known, and a frontend drawing in 3D keeps
 *   drawing in 3D.
 *
 *   The distinction matters to the caller: an arrow that is level because
 *   both ends are at the same height and one that is level because nobody
 *   knows is the same picture and a different claim. elevation_known is
 *   what lets a frontend say so.
 *
 * ON WHETHER TO SHOW IT AT ALL
 *   GNSS vertical error runs 1.5-3x the horizontal (fuzzypickles'
 *   geolocation notes are blunt about it), so at ordinary separations an
 *   elevation angle is mostly noise -- worth having for a hillside or a
 *   tall building, not worth
 *   asserting by default. elevation_is_meaningful() applies the same ratio
 *   test the bearing uses, against the VERTICAL accuracies, so a frontend
 *   can draw the tilt only when the numbers support it.
 */
typedef struct fzn_geo_arrow {
	double distance_m;      /* great-circle, over the ground */
	double bearing_deg;     /* clockwise from TRUE north */
	double elevation_deg;   /* + above, - below, 0 level or unknown */
	int bearing_meaningful;  /* 0 -> show a radius, not a direction */
	int elevation_known;     /* 0 -> level because altitude is missing */
	int elevation_meaningful; /* 0 -> draw it flat; the tilt is noise */
} fzn_geo_arrow_t;

/*
 * Elevation angle for a known height difference over a known ground
 * distance. Straightforward atan2, exposed separately because a caller with
 * altitudes from somewhere other than a fix still wants the same answer.
 *
 * A zero ground distance is directly above or below: reported as +/-90, not
 * as a division by zero.
 */
double fzn_geo_elevation_deg(double distance_m, double alt_diff_m);

/*
 * Whether an elevation angle is worth drawing as a tilt, by the same ratio
 * test the bearing uses -- but against the height difference and the
 * combined VERTICAL accuracy, which is the pair that decides whether a slope
 * is real or is the receiver guessing.
 */
int fzn_geo_elevation_is_meaningful(double alt_diff_m, double combined_v_accuracy_m);

/*
 * Everything a frontend needs to point at someone, in one call.
 *
 * has_alt1/has_alt2 carry the fix's own altitude-presence flags; when either
 * is 0 the result is level and elevation_known is 0, per the rule above.
 * Accuracies are metres; pass the worse axis for the horizontal pair, since
 * an arrow is only as good as the axis it is worst on.
 */
void fzn_geo_arrow_between(int32_t lat1_e7, int32_t lon1_e7, int has_alt1, double alt1_m,
         double h_acc1_m, double v_acc1_m, int32_t lat2_e7, int32_t lon2_e7,
         int has_alt2, double alt2_m, double h_acc2_m, double v_acc2_m,
         fzn_geo_arrow_t *out);

/*
 * Where to draw the arrow on a screen that turns with the device.
 *
 * THE POINT OF SPLITTING THIS OUT
 *   A position fix arrives every few seconds at best; a magnetometer reports
 *   fifty to a hundred times a second, and an arrow that "follows the
 *   movement of the device" is redrawn at that rate. Running haversine and
 *   two atan2s per frame to compute a bearing that has not changed would be
 *   wasteful and, worse, would tie the smoothness of the arrow to the
 *   accuracy of the geodesy. So fzn_geo_arrow_between() is the slow half,
 *   called when a fix changes, and this is the fast half: one subtraction
 *   per frame against a cached bearing.
 *
 * heading_known == 0 means there is no orientation source -- an ordinary
 * desktop has no magnetometer -- and the answer is the true bearing itself,
 * which a frontend draws north-up. That is a presentation fallback, not a
 * loss of information: the direction is equally correct, the user just has
 * to hold the map the right way round: degrading by dropping presentation
 * rather than capability, as fuzzypickles' geolocation notes put it.
 *
 * device_heading_deg is where the DEVICE points, clockwise from true north.
 * A magnetometer reports magnetic north; converting to true north is the
 * caller's job, because the declination correction needs a position and a
 * model this layer has no business carrying.
 */
double fzn_geo_screen_angle_deg(double bearing_deg, int heading_known, double device_heading_deg);

/*
 * 16-point compass abbreviation ("N", "NNE", ... "NNW") for a bearing in
 * degrees. Never NULL, and wraps input outside [0, 360).
 *
 * This is the form the ncurses client can carry: it cannot draw a map or
 * rotate an arrow live, but "1.2 km NNE" is the same information and is
 * genuinely useful over ssh.
 */
const char *fzn_geo_compass_point(double bearing_deg);

#endif /* FZN_LOCATION_GEO_H */
