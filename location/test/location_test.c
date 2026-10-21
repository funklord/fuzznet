/* location/location.h, sec 676: the fix's bytes at their offsets, a round
 * trip, absent fields as zero, the ranges refused both ways, the accuracy
 * and bearing scales, and the grid each level degrades to -- the numbers
 * fuzzypickles' own tests held, carried over. */
#include "../location.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL location_test.c:%d: %s\n", line, what);
	}
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static fzn_location_fix_t sample(void)
{
	fzn_location_fix_t f;

	memset(&f, 0, sizeof(f));
	f.lat_e7 = 593293230;	/* 59.329323 N */
	f.lon_e7 = 180685810;	/* 18.068581 E */
	f.utc_s = 1792600000u;
	f.alt_m = -12;
	f.has_alt = 1;
	f.bearing = fzn_location_bearing_encode(90);
	f.has_bearing = 1;
	f.acc_e = fzn_location_acc_encode(5);
	f.acc_n = fzn_location_acc_encode(9);
	f.acc_v = fzn_location_acc_encode(20);
	return f;
}

static void test_the_bytes(void)
{
	fzn_location_fix_t f = sample(), back;
	uint8_t b[FZN_LOCATION_FIX_LEN + 1u];

	CHECK(fzn_location_fix_encode(&f, b, FZN_LOCATION_FIX_LEN - 1u) == 0,
	      "a fix was encoded into a short buffer");
	CHECK(fzn_location_fix_encode(&f, b, sizeof(b)) == 1, "the sample did not encode");
	/* BIG-ENDIAN, at the schema's offsets. */
	CHECK(b[0] == 0x23 && b[1] == 0x5c && b[2] == 0xef && b[3] == 0xae,
	      "latitude is not big-endian at 0");
	CHECK(b[12] == 0xff && b[13] == 0xf4, "a negative altitude is not big-endian at 12");
	CHECK(b[18] == (FZN_LOCATION_FLAG_ALT | FZN_LOCATION_FLAG_BEARING), "the flags are wrong");
	CHECK(fzn_location_fix_decode(b, FZN_LOCATION_FIX_LEN, &back) == 1
	              && back.lat_e7 == f.lat_e7 && back.lon_e7 == f.lon_e7
	              && back.utc_s == f.utc_s && back.alt_m == -12 && back.has_alt
	              && back.has_bearing && back.bearing == f.bearing && back.acc_e == f.acc_e
	              && back.acc_n == f.acc_n && back.acc_v == f.acc_v && !back.is_coarse,
	      "the sample did not round-trip");
	CHECK(fzn_location_fix_decode(b, FZN_LOCATION_FIX_LEN + 1u, &back) == 0
	              && fzn_location_fix_decode(b, FZN_LOCATION_FIX_LEN - 1u, &back) == 0,
	      "a length not a fix's was decoded");
	/* ABSENT IS ZERO: no altitude, no bearing, and their bytes are 0
	 * whatever the fields held. */
	f.has_alt = 0;
	f.has_bearing = 0;
	CHECK(fzn_location_fix_encode(&f, b, sizeof(b)) == 1 && b[12] == 0 && b[13] == 0
	              && b[14] == 0 && b[17] == 0 && b[18] == 0,
	      "an absent field left bytes behind");
	/* A FLAG NOBODY DEFINED is not a fix. */
	b[18] = 0x08;
	CHECK(fzn_location_fix_decode(b, FZN_LOCATION_FIX_LEN, &back) == 0,
	      "a fix with an undefined flag was decoded");
}

static void test_the_ranges(void)
{
	fzn_location_fix_t f = sample(), back;
	uint8_t b[FZN_LOCATION_FIX_LEN];

	f.lat_e7 = FZN_LOCATION_LAT_E7_MAX;
	f.lon_e7 = -FZN_LOCATION_LON_E7_MAX;
	CHECK(fzn_location_fix_encode(&f, b, sizeof(b)) == 1
	              && fzn_location_fix_decode(b, sizeof(b), &back) == 1,
	      "a pole on the antimeridian was refused");
	f.lat_e7 = FZN_LOCATION_LAT_E7_MAX + 1;
	CHECK(fzn_location_fix_encode(&f, b, sizeof(b)) == 0, "latitude past 90 was encoded");
	f.lat_e7 = 0;
	f.lon_e7 = FZN_LOCATION_LON_E7_MAX + 1;
	CHECK(fzn_location_fix_encode(&f, b, sizeof(b)) == 0, "longitude past 180 was encoded");
	/* AND DECODED: bytes a writer could not have made. */
	f.lon_e7 = 0;
	CHECK(fzn_location_fix_encode(&f, b, sizeof(b)) == 1, "fixture: a fix at 0 0");
	b[0] = 0x40;	/* latitude 107 degrees */
	CHECK(fzn_location_fix_decode(b, sizeof(b), &back) == 0,
	      "a latitude out of range was decoded");
}

static void test_the_scales(void)
{
	fzn_location_fix_t f = sample();
	uint32_t m;

	CHECK(fzn_location_acc_encode(0) == 0 && fzn_location_acc_encode(1) == 0
	              && fzn_location_acc_decode(0) == 1,
	      "a metre or better is not code 0");
	CHECK(fzn_location_acc_encode(0xffffffffu) == 254u,
	      "the largest accuracy did not saturate at 254");
	CHECK(fzn_location_acc_decode(FZN_LOCATION_ACC_UNKNOWN) == 0,
	      "unknown accuracy decoded to a measurement");
	/* WITHIN 7% BELOW SATURATION, which is 254's 61440 m: past it every
	 * accuracy is 61440, so "about 7%" holds only up to there. */
	for (m = 2; m <= 61440u; m++) {
		uint32_t back = fzn_location_acc_decode(fzn_location_acc_encode(m));

		if (back > m || back * 100u < m * 93u) {
			CHECK(0, "an accuracy below saturation came back more than 7% off");
			break;
		}
	}
	CHECK(fzn_location_acc_decode(254u) == 61440u
	              && fzn_location_acc_decode(fzn_location_acc_encode(100000u)) == 61440u,
	      "saturation is not 61440 m");
	CHECK(fzn_location_worst_h_acc_m(&f) == fzn_location_acc_decode(f.acc_n),
	      "the worse axis is not the north-south one");
	f.acc_e = FZN_LOCATION_ACC_UNKNOWN;
	CHECK(fzn_location_worst_h_acc_m(&f) == 0xffffffffu,
	      "an unknown axis did not count as the worst");
	CHECK(fzn_location_bearing_encode(0) == 0 && fzn_location_bearing_encode(360) == 0
	              && fzn_location_bearing_decode(fzn_location_bearing_encode(90)) == 90
	              && fzn_location_bearing_decode(fzn_location_bearing_encode(359)) >= 358,
	      "a bearing did not round-trip to a degree");
}

static void test_the_grids(void)
{
	fzn_location_fix_t f = sample(), g;

	g = f;
	fzn_location_degrade(&g, FZN_LOCATION_EXACT);
	CHECK(memcmp(&g, &f, sizeof(f)) == 0, "the exact level changed the fix");
	g = f;
	fzn_location_degrade(&g, FZN_LOCATION_COARSE);
	CHECK(g.lat_e7 == 593300000 && g.lon_e7 == 180700000 && g.is_coarse,
	      "the coarse grid is not 0.01 degree");
	g = f;
	fzn_location_degrade(&g, FZN_LOCATION_REGION);
	CHECK(g.lat_e7 == 593000000 && g.lon_e7 == 181000000 && g.is_coarse,
	      "the region grid is not 0.1 degree");
	/* HALF AWAY FROM ZERO, south and west too. */
	g = f;
	g.lat_e7 = -593350000;
	g.lon_e7 = -50000;
	fzn_location_degrade(&g, FZN_LOCATION_COARSE);
	CHECK(g.lat_e7 == -593400000 && g.lon_e7 == -100000,
	      "a half step south or west did not round away from zero");
	/* CLAMPED: rounding at the antimeridian stays a longitude. */
	g = f;
	g.lon_e7 = FZN_LOCATION_LON_E7_MAX - 1;
	fzn_location_degrade(&g, FZN_LOCATION_REGION);
	CHECK(g.lon_e7 == FZN_LOCATION_LON_E7_MAX, "the antimeridian was rounded past");
}

static int parses(const char *text, int32_t limit, int32_t want)
{
	int32_t got = 12345;

	return fzn_location_degrees_parse(text, strlen(text), limit, &got) == 1 && got == want;
}

static int refuses(const char *text, int32_t limit)
{
	int32_t got = 12345;

	return fzn_location_degrees_parse(text, strlen(text), limit, &got) == 0 && got == 12345;
}

static void test_degrees_as_text(void)
{
	const int32_t LAT = FZN_LOCATION_LAT_E7_MAX, LON = FZN_LOCATION_LON_E7_MAX;
	char text[FZN_LOCATION_DEGREES_TEXT_MAX];

	CHECK(parses("59.3293230", LAT, 593293230) && parses("59.329323", LAT, 593293230)
	              && parses("-18", LON, -180000000) && parses("0", LAT, 0)
	              && parses("-0.0000001", LAT, -1) && parses("180.0000000", LON, LON)
	              && parses("-90", LAT, -LAT),
	      "a coordinate in degrees did not parse exactly");
	CHECK(refuses("", LAT) && refuses("-", LAT) && refuses(".5", LAT) && refuses("5.", LAT)
	              && refuses("-.5", LAT) && refuses("1.2.3", LAT) && refuses("1e5", LAT)
	              && refuses("+5", LAT) && refuses("1.00000001", LAT) && refuses(" 5", LAT),
	      "text that is no coordinate was parsed");
	CHECK(refuses("90.0000001", LAT) && refuses("-180.0000001", LON) && refuses("91", LAT)
	              && refuses("99999999999", LON) && refuses("0000000000000001", LAT),
	      "a coordinate past its limit, or too many digits, was parsed");
	CHECK(fzn_location_degrees_text(593293230, text) == 10u && strcmp(text, "59.3293230") == 0,
	      "59.3293230 did not print as itself");
	CHECK(fzn_location_degrees_text(-1, text) && strcmp(text, "-0.0000001") == 0
	              && fzn_location_degrees_text(-LON, text) && strcmp(text, "-180.0000000") == 0
	              && fzn_location_degrees_text(0, text) && strcmp(text, "0.0000000") == 0,
	      "a small negative, the antimeridian or zero printed wrong");
	CHECK(fzn_location_degrees_text(-LON, text) + 1u <= FZN_LOCATION_DEGREES_TEXT_MAX,
	      "the longest text does not fit its bound");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	CHECK(0, "deliberate");
	CHECK(failures == before + 1, "a failing check did not count");
	failures = before;
	checks -= 1;
}

int main(void)
{
	test_the_bytes();
	test_the_ranges();
	test_the_scales();
	test_the_grids();
	test_degrees_as_text();
	test_the_suite_can_tell_pass_from_fail();

	printf("location_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
