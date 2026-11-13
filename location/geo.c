#include "geo.h"

#include <math.h>
#include <stdio.h>

#define DEG_PER_E7 1e-7
#define PI 3.14159265358979323846

static double e7_to_rad(int32_t e7) { return (double)e7 * DEG_PER_E7 * PI / 180.0; }

double fzn_geo_distance_m(int32_t lat1_e7, int32_t lon1_e7, int32_t lat2_e7, int32_t lon2_e7) {
	double p1 = e7_to_rad(lat1_e7);
	double p2 = e7_to_rad(lat2_e7);
	double dp = p2 - p1;
	double dl = e7_to_rad(lon2_e7) - e7_to_rad(lon1_e7);

	/* Haversine rather than the spherical law of cosines: the latter loses
	 * precision catastrophically at small separations, which is exactly the
	 * case this feature cares about most (two people in the same street). */
	double sdp = sin(dp / 2.0);
	double sdl = sin(dl / 2.0);
	double a = sdp * sdp + cos(p1) * cos(p2) * sdl * sdl;
	if (a < 0.0) a = 0.0;
	if (a > 1.0) a = 1.0;
	return 2.0 * FZN_GEO_EARTH_RADIUS_M * atan2(sqrt(a), sqrt(1.0 - a));
}

double fzn_geo_bearing_deg(int32_t lat1_e7, int32_t lon1_e7, int32_t lat2_e7, int32_t lon2_e7) {
	double p1 = e7_to_rad(lat1_e7);
	double p2 = e7_to_rad(lat2_e7);
	double dl = e7_to_rad(lon2_e7) - e7_to_rad(lon1_e7);

	double y = sin(dl) * cos(p2);
	double x = cos(p1) * sin(p2) - sin(p1) * cos(p2) * cos(dl);
	double deg = atan2(y, x) * 180.0 / PI;

	/* atan2 returns (-180, 180]; compass bearings are [0, 360). fmod alone
	 * would leave negatives negative. */
	deg = fmod(deg + 360.0, 360.0);
	if (deg < 0.0) deg += 360.0;
	return deg;
}

int fzn_geo_bearing_is_meaningful(double distance_m, double combined_accuracy_m) {
	if (!(distance_m > 0.0)) return 0;              /* same place, or NaN */
	if (!(combined_accuracy_m > 0.0)) return 1;     /* no error estimate to fail against */
	return distance_m > FZN_GEO_BEARING_MIN_RATIO * combined_accuracy_m;
}

int fzn_geo_format_distance(char *out, size_t out_cap, double metres) {
	if (out == NULL || out_cap < 8) return -1;
	if (!(metres >= 0.0)) return -1; /* also catches NaN */

	int n;
	if (metres < 1000.0) {
		/* Whole metres: a fix good to several metres has no business
		 * displaying centimetres. */
		n = snprintf(out, out_cap, "%.0f m", metres);
	} else if (metres < 10000.0) {
		n = snprintf(out, out_cap, "%.1f km", metres / 1000.0);
	} else {
		/* Past 10 km a tenth of a kilometre is below anything a user acts
		 * on, so it is noise on the display. */
		n = snprintf(out, out_cap, "%.0f km", metres / 1000.0);
	}
	return (n < 0 || (size_t)n >= out_cap) ? -1 : 0;
}

const char *fzn_geo_compass_point(double bearing_deg) {
	static const char *points[16] = {"N",  "NNE", "NE", "ENE", "E",  "ESE", "SE", "SSE",
		                                "S",  "SSW", "SW", "WSW", "W",  "WNW", "NW", "NNW"};
	if (!(bearing_deg == bearing_deg)) return "N"; /* NaN */
	double d = fmod(bearing_deg, 360.0);
	if (d < 0.0) d += 360.0;
	/* +11.25 so each name is centred on its compass point rather than
	 * starting at it -- without it, due north would read as NNE. */
	int idx = (int)((d + 11.25) / 22.5) % 16;
	return points[idx];
}

double fzn_geo_elevation_deg(double distance_m, double alt_diff_m) {
	if (!(distance_m == distance_m) || !(alt_diff_m == alt_diff_m)) return 0.0; /* NaN */
	/* Directly overhead or underfoot. atan2 handles a zero denominator, but
	 * saying so explicitly is clearer than relying on it, and a zero ground
	 * distance with zero height difference is level rather than undefined. */
	if (distance_m <= 0.0) {
		if (alt_diff_m > 0.0) return 90.0;
		if (alt_diff_m < 0.0) return -90.0;
		return 0.0;
	}
	return atan2(alt_diff_m, distance_m) * 180.0 / PI;
}

int fzn_geo_elevation_is_meaningful(double alt_diff_m, double combined_v_accuracy_m) {
	if (!(alt_diff_m == alt_diff_m)) return 0;
	if (!(combined_v_accuracy_m > 0.0)) return 1; /* nothing to fail against */
	double rise = alt_diff_m < 0.0 ? -alt_diff_m : alt_diff_m;
	/* Same ratio the bearing uses, applied to the pair that decides whether a
	 * slope is real: a 10 m height difference with 8 m of vertical error is
	 * a guess, and drawing it as a tilt would dress that guess up as a fact. */
	return rise > FZN_GEO_BEARING_MIN_RATIO * combined_v_accuracy_m;
}

void fzn_geo_arrow_between(int32_t lat1_e7, int32_t lon1_e7, int has_alt1, double alt1_m,
         double h_acc1_m, double v_acc1_m, int32_t lat2_e7, int32_t lon2_e7,
         int has_alt2, double alt2_m, double h_acc2_m, double v_acc2_m,
         fzn_geo_arrow_t *out) {
	if (!out) return;
	out->distance_m = fzn_geo_distance_m(lat1_e7, lon1_e7, lat2_e7, lon2_e7);
	out->bearing_deg = fzn_geo_bearing_deg(lat1_e7, lon1_e7, lat2_e7, lon2_e7);

	/* Errors add in quadrature rather than linearly: two independent 5 m
	 * estimates make about 7 m of combined uncertainty, not 10. */
	double h_combined = sqrt(h_acc1_m * h_acc1_m + h_acc2_m * h_acc2_m);
	out->bearing_meaningful = fzn_geo_bearing_is_meaningful(out->distance_m, h_combined);

	if (!has_alt1 || !has_alt2) {
		/*
		 * Either end without an altitude means the arrow lies flat: level is
		 * the honest rendering of an unknown height, and it keeps the arrow
		 * pointing rather than vanishing over a field the sender may simply
		 * not have had. elevation_known says which kind of level this is.
		 */
		out->elevation_deg = 0.0;
		out->elevation_known = 0;
		out->elevation_meaningful = 0;
		return;
	}

	double rise = alt2_m - alt1_m;
	out->elevation_deg = fzn_geo_elevation_deg(out->distance_m, rise);
	out->elevation_known = 1;
	double v_combined = sqrt(v_acc1_m * v_acc1_m + v_acc2_m * v_acc2_m);
	out->elevation_meaningful = fzn_geo_elevation_is_meaningful(rise, v_combined);
}

double fzn_geo_screen_angle_deg(double bearing_deg, int heading_known, double device_heading_deg) {
	if (!(bearing_deg == bearing_deg)) return 0.0; /* NaN */
	double a = bearing_deg;
	if (heading_known && device_heading_deg == device_heading_deg) a -= device_heading_deg;
	a = fmod(a, 360.0);
	if (a < 0.0) a += 360.0;
	return a;
}
