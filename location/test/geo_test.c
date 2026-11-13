#include "../geo.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

/*
 * Tests client/geo.c.
 *
 * Reference distances are computed against known city-pair great-circle
 * values; tolerances are generous because the point is not sub-metre
 * agreement with an ellipsoid solution (haversine is ~0.5% off, which is
 * far inside GNSS error) but that the maths is not wrong by kilometres or
 * pointing the wrong way.
 *
 * Bearing tests care most about the cases that are easy to get subtly
 * wrong and invisible when they are: crossing the antimeridian, the
 * southern hemisphere, and the wrap from atan2's (-180, 180] to a compass
 * [0, 360).
 */

static int failures = 0;

#define CHECK(cond)                                                   \
  do {                                                                \
    if (!(cond)) {                                                    \
      fprintf(stderr, "FAIL geo_test.c:%d: %s\n", __LINE__, #cond);    \
      failures++;                                                     \
    }                                                                 \
  } while (0)

#define E7(deg) ((int32_t)((deg) * 1e7))

static int near(double a, double b, double tol) { return fabs(a - b) <= tol; }

/* Angular closeness, respecting wrap: 359.9 and 0.1 are 0.2 apart. */
static int near_deg(double a, double b, double tol) {
	double d = fabs(fmod(a - b + 540.0, 360.0) - 180.0);
	return d <= tol;
}

static void test_distance_known_pairs(void) {
	/* Stockholm -> Oslo, ~416 km. */
	double d = fzn_geo_distance_m(E7(59.3293), E7(18.0686), E7(59.9139), E7(10.7522));
	CHECK(near(d, 416000.0, 5000.0));

	/* London -> New York, ~5570 km: a long, high-latitude great circle. */
	d = fzn_geo_distance_m(E7(51.5074), E7(-0.1278), E7(40.7128), E7(-74.0060));
	CHECK(near(d, 5570000.0, 30000.0));

	/* One degree of latitude at any longitude is ~111.2 km. */
	d = fzn_geo_distance_m(E7(0.0), E7(0.0), E7(1.0), E7(0.0));
	CHECK(near(d, 111195.0, 500.0));

	/* Identical points are exactly zero, not a small rounding artefact --
	 * this is the case a "distance to yourself" display hits constantly. */
	CHECK(fzn_geo_distance_m(E7(59.3293), E7(18.0686), E7(59.3293), E7(18.0686)) == 0.0);
}

/* Short separations are the case this feature cares about most, and the
 * one where a spherical-law-of-cosines implementation would lose all
 * precision. */
static void test_distance_short_range(void) {
	/* 0.0001 degrees of latitude is ~11.1 m. */
	double d = fzn_geo_distance_m(E7(59.3293), E7(18.0686), E7(59.3294), E7(18.0686));
	CHECK(near(d, 11.1, 0.5));

	/* ~1 m, well inside GNSS noise but must still be finite and positive. */
	d = fzn_geo_distance_m(E7(59.3293), E7(18.0686), E7(59.32930900), E7(18.0686));
	CHECK(d > 0.5 && d < 2.0);
}

/* The antimeridian is where a naive longitude subtraction goes 40000 km
 * wrong, and it is invisible unless tested deliberately. */
static void test_distance_across_antimeridian(void) {
	double d = fzn_geo_distance_m(E7(0.0), E7(179.9), E7(0.0), E7(-179.9));
	CHECK(near(d, 22239.0, 200.0)); /* 0.2 degrees at the equator, NOT 359.8 */

	double b = fzn_geo_bearing_deg(E7(0.0), E7(179.9), E7(0.0), E7(-179.9));
	CHECK(near_deg(b, 90.0, 1.0)); /* still due east */
}

static void test_bearing_cardinals(void) {
	/* Due north, south, east, west from the equator/prime meridian. */
	CHECK(near_deg(fzn_geo_bearing_deg(E7(0.0), E7(0.0), E7(1.0), E7(0.0)), 0.0, 0.5));
	CHECK(near_deg(fzn_geo_bearing_deg(E7(0.0), E7(0.0), E7(0.0), E7(1.0)), 90.0, 0.5));
	CHECK(near_deg(fzn_geo_bearing_deg(E7(0.0), E7(0.0), E7(-1.0), E7(0.0)), 180.0, 0.5));
	/* Due west must come back as 270, not -90 -- the atan2 wrap. */
	double w = fzn_geo_bearing_deg(E7(0.0), E7(0.0), E7(0.0), E7(-1.0));
	CHECK(near_deg(w, 270.0, 0.5));
	CHECK(w >= 0.0 && w < 360.0);
}

/* Every bearing must land in [0, 360) regardless of hemisphere or
 * direction -- a negative would index a compass table out of bounds. */
static void test_bearing_always_normalised(void) {
	const int32_t lats[] = {E7(-85.0), E7(-33.8688), E7(0.0), E7(51.5), E7(85.0)};
	const int32_t lons[] = {E7(-179.0), E7(-74.0), E7(0.0), E7(151.2), E7(179.0)};
	for (size_t i = 0; i < 5; i++) {
		for (size_t j = 0; j < 5; j++) {
			for (size_t k = 0; k < 5; k++) {
				double b = fzn_geo_bearing_deg(lats[i], lons[j], lats[k], lons[(j + 2) % 5]);
				CHECK(b >= 0.0 && b < 360.0);
			}
		}
	}
}

/* Southern hemisphere: Sydney -> Melbourne is roughly southwest. */
static void test_bearing_southern_hemisphere(void) {
	double b = fzn_geo_bearing_deg(E7(-33.8688), E7(151.2093), E7(-37.8136), E7(144.9631));
	CHECK(b > 200.0 && b < 260.0);
	const char *pt = fzn_geo_compass_point(b);
	CHECK(strcmp(pt, "SW") == 0 || strcmp(pt, "WSW") == 0 || strcmp(pt, "SSW") == 0);
}

/* An arrow drawn from two fuzzy fixes that are close together points
 * confidently nowhere -- the gate exists so a frontend shows a radius
 * instead. */
static void test_bearing_meaningfulness_gate(void) {
	CHECK(fzn_geo_bearing_is_meaningful(50.0, 30.0) == 0);   /* ~31 deg of slop */
	CHECK(fzn_geo_bearing_is_meaningful(1000.0, 30.0) == 1); /* under 2 deg */
	CHECK(fzn_geo_bearing_is_meaningful(150.0, 30.0) == 0);  /* exactly at the ratio */
	CHECK(fzn_geo_bearing_is_meaningful(151.0, 30.0) == 1);

	/* Degenerate inputs must not claim a usable bearing. */
	CHECK(fzn_geo_bearing_is_meaningful(0.0, 10.0) == 0);
	/* No accuracy estimate: nothing to fail against, so allow it. */
	CHECK(fzn_geo_bearing_is_meaningful(100.0, 0.0) == 1);
}

static void test_format_distance(void) {
	char buf[32];
	CHECK(fzn_geo_format_distance(buf, sizeof(buf), 0.0) == 0);
	CHECK(strcmp(buf, "0 m") == 0);
	CHECK(fzn_geo_format_distance(buf, sizeof(buf), 47.4) == 0);
	CHECK(strcmp(buf, "47 m") == 0);
	CHECK(fzn_geo_format_distance(buf, sizeof(buf), 999.0) == 0);
	CHECK(strcmp(buf, "999 m") == 0);
	CHECK(fzn_geo_format_distance(buf, sizeof(buf), 1200.0) == 0);
	CHECK(strcmp(buf, "1.2 km") == 0);
	CHECK(fzn_geo_format_distance(buf, sizeof(buf), 416000.0) == 0);
	CHECK(strcmp(buf, "416 km") == 0);

	/* Too small a buffer is refused, never truncated into a wrong number. */
	char tiny[4];
	CHECK(fzn_geo_format_distance(tiny, sizeof(tiny), 1200.0) == -1);
	CHECK(fzn_geo_format_distance(buf, sizeof(buf), -1.0) == -1);
}

/* Each name must be centred on its compass point, not start at it --
 * otherwise due north reads as NNE. */
static void test_compass_points(void) {
	CHECK(strcmp(fzn_geo_compass_point(0.0), "N") == 0);
	CHECK(strcmp(fzn_geo_compass_point(11.0), "N") == 0);
	CHECK(strcmp(fzn_geo_compass_point(359.0), "N") == 0);
	CHECK(strcmp(fzn_geo_compass_point(90.0), "E") == 0);
	CHECK(strcmp(fzn_geo_compass_point(180.0), "S") == 0);
	CHECK(strcmp(fzn_geo_compass_point(270.0), "W") == 0);
	CHECK(strcmp(fzn_geo_compass_point(45.0), "NE") == 0);
	CHECK(strcmp(fzn_geo_compass_point(22.5), "NNE") == 0);
	CHECK(strcmp(fzn_geo_compass_point(337.5), "NNW") == 0);

	/* Out-of-range input wraps rather than indexing off the table. */
	CHECK(strcmp(fzn_geo_compass_point(720.0), "N") == 0);
	CHECK(strcmp(fzn_geo_compass_point(-90.0), "W") == 0);
}


/* ---- elevation and the device-relative arrow ---- */

static void test_elevation_angle(void) {
	/* A 100 m rise over 100 m of ground is 45 degrees, the one case anyone
	 * can check by inspection. */
	CHECK(fabs(fzn_geo_elevation_deg(100.0, 100.0) - 45.0) < 1e-9);
	CHECK(fabs(fzn_geo_elevation_deg(100.0, -100.0) + 45.0) < 1e-9);
	CHECK(fabs(fzn_geo_elevation_deg(1000.0, 0.0)) < 1e-9);

	/* Directly overhead: reported as a right angle rather than a division by
	 * zero, and level when there is no height difference either. */
	CHECK(fabs(fzn_geo_elevation_deg(0.0, 50.0) - 90.0) < 1e-9);
	CHECK(fabs(fzn_geo_elevation_deg(0.0, -50.0) + 90.0) < 1e-9);
	CHECK(fabs(fzn_geo_elevation_deg(0.0, 0.0)) < 1e-9);
}

static void test_elevation_meaningfulness(void) {
	/* GNSS vertical error runs 1.5-3x the horizontal, so a small height
	 * difference is the receiver guessing. Drawing that as a tilt would
	 * dress the guess up as a fact. */
	CHECK(fzn_geo_elevation_is_meaningful(10.0, 8.0) == 0);
	CHECK(fzn_geo_elevation_is_meaningful(100.0, 8.0) == 1);
	CHECK(fzn_geo_elevation_is_meaningful(-100.0, 8.0) == 1); /* downhill counts */
	CHECK(fzn_geo_elevation_is_meaningful(1.0, 0.0) == 1);    /* nothing to fail against */
}

static void test_arrow_is_flat_when_altitude_is_missing(void) {
	/*
	 * The rule: if either end lacks an altitude the arrow lies flat against
	 * the earth rather than disappearing. A direction is still worth showing
	 * when the height is unknown, and elevation_known is what lets a frontend
	 * say "level because nobody knows" rather than "level because it is".
	 */
	fzn_geo_arrow_t a;
	/* Gothenburg-ish, a few hundred metres apart, one end without altitude. */
	fzn_geo_arrow_between(577089000, 119746000, 1, 55.0, 5.0, 8.0,
	                       577189000, 119946000, 0, 0.0, 5.0, 8.0, &a);
	CHECK(a.elevation_known == 0);
	CHECK(a.elevation_deg == 0.0);
	CHECK(a.elevation_meaningful == 0);
	/* ...and it is still a usable arrow. */
	CHECK(a.distance_m > 0.0);
	CHECK(a.bearing_deg >= 0.0 && a.bearing_deg < 360.0);
	CHECK(a.bearing_meaningful == 1);

	/* Neither end has one: same rule. */
	fzn_geo_arrow_between(577089000, 119746000, 0, 0.0, 5.0, 8.0,
	                       577189000, 119946000, 0, 0.0, 5.0, 8.0, &a);
	CHECK(a.elevation_known == 0);
	CHECK(a.elevation_deg == 0.0);
}

static void test_arrow_tilts_when_both_ends_know_their_height(void) {
	fzn_geo_arrow_t a;
	/* 65 m of climb over a few hundred metres: a real hillside, and well
	 * clear of the vertical error. */
	fzn_geo_arrow_between(577089000, 119746000, 1, 55.0, 5.0, 3.0,
	                       577189000, 119946000, 1, 120.0, 5.0, 3.0, &a);
	CHECK(a.elevation_known == 1);
	CHECK(a.elevation_deg > 0.0); /* they are above us */
	CHECK(a.elevation_meaningful == 1);

	/* Reverse the pair and the tilt reverses with it. */
	fzn_geo_arrow_t b;
	fzn_geo_arrow_between(577189000, 119946000, 1, 120.0, 5.0, 3.0,
	                       577089000, 119746000, 1, 55.0, 5.0, 3.0, &b);
	CHECK(b.elevation_deg < 0.0);
	CHECK(fabs(a.elevation_deg + b.elevation_deg) < 1e-6);
}

static void test_arrow_hides_a_tilt_it_cannot_support(void) {
	fzn_geo_arrow_t a;
	/* Two metres apart vertically, with eight metres of vertical error each:
	 * a known altitude, and a slope nobody should draw. */
	fzn_geo_arrow_between(577089000, 119746000, 1, 55.0, 5.0, 8.0,
	                       577189000, 119946000, 1, 57.0, 5.0, 8.0, &a);
	CHECK(a.elevation_known == 1);        /* both ends reported a height */
	CHECK(a.elevation_meaningful == 0);   /* ...and it means nothing */
}

static void test_screen_angle_follows_the_device(void) {
	/*
	 * The per-frame half. Facing north, an arrow due east is drawn at 90
	 * degrees; turn the device to face east and the same target is straight
	 * ahead. This is one subtraction precisely so it can run at magnetometer
	 * rate without recomputing any geodesy.
	 */
	CHECK(fabs(fzn_geo_screen_angle_deg(90.0, 1, 0.0) - 90.0) < 1e-9);
	CHECK(fabs(fzn_geo_screen_angle_deg(90.0, 1, 90.0)) < 1e-9);
	CHECK(fabs(fzn_geo_screen_angle_deg(90.0, 1, 180.0) - 270.0) < 1e-9);

	/* Wrapping in both directions, since a heading crosses north constantly
	 * and an arrow that jumps there would be visible at every turn. */
	CHECK(fabs(fzn_geo_screen_angle_deg(10.0, 1, 350.0) - 20.0) < 1e-9);
	CHECK(fabs(fzn_geo_screen_angle_deg(350.0, 1, 10.0) - 340.0) < 1e-9);

	/* No orientation source -- an ordinary desktop -- is north-up, which is
	 * the true bearing unchanged. */
	CHECK(fabs(fzn_geo_screen_angle_deg(123.0, 0, 45.0) - 123.0) < 1e-9);
}

int main(void) {
	test_distance_known_pairs();
	test_distance_short_range();
	test_distance_across_antimeridian();
	test_bearing_cardinals();
	test_bearing_always_normalised();
	test_bearing_southern_hemisphere();
	test_bearing_meaningfulness_gate();
	test_format_distance();
	test_compass_points();

	test_elevation_angle();
	test_elevation_meaningfulness();
	test_arrow_is_flat_when_altitude_is_missing();
	test_arrow_tilts_when_both_ends_know_their_height();
	test_arrow_hides_a_tilt_it_cannot_support();
	test_screen_angle_follows_the_device();

	if (failures) {
		fprintf(stderr, "geo_test: %d failure(s)\n", failures);
		return 1;
	}
	printf("geo_test: all passed\n");
	return 0;
}
