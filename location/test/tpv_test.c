/* location/tpv.h, sec 678: gpsd's reports as gpsd sends them -- a 3D fix,
 * a 2D one, one still acquiring, the other classes -- read to the fixes
 * they carry, with rounding, the accuracy axes' fallbacks, and the lines
 * that are refused. */
#include "../tpv.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL tpv_test.c:%d: %s\n", line, what);
	}
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static int parse(const char *line, fzn_location_fix_t *f)
{
	memset(f, 0x5a, sizeof(*f));
	return fzn_location_tpv_parse(line, strlen(line), f);
}

/* A 3D FIX AS gpsd 3.22 REPORTS ONE. */
static const char FIX_3D[] =
        "{\"class\":\"TPV\",\"device\":\"/dev/ttyACM0\",\"mode\":3,"
        "\"time\":\"2026-10-21T12:00:05.000Z\",\"ept\":0.005,\"lat\":59.329323456,"
        "\"lon\":-18.068581549,\"altHAE\":31.6,\"altMSL\":7.2,\"alt\":7.2,\"epx\":4.2,"
        "\"epy\":8.6,\"epv\":19.4,\"track\":271.4,\"speed\":1.2,\"eph\":9.1}";

static void test_a_3d_fix(void)
{
	fzn_location_fix_t f;

	CHECK(parse(FIX_3D, &f) == 1, "a 3D fix was not read");
	/* ROUNDED at the eighth place: .3293234|56 up, .0685815|49 down. */
	CHECK(f.lat_e7 == 593293235 && f.lon_e7 == -180685815,
	      "the coordinates were not rounded half away from zero");
	CHECK(f.utc_s == 1792584005u, "the time was not read as UTC");
	/* altHAE, rounded: 31.6 is 32, and preferred over the older `alt`. */
	CHECK(f.has_alt && f.alt_m == 32, "altHAE was not taken, rounded");
	CHECK(f.has_bearing && fzn_location_bearing_decode(f.bearing) == 271,
	      "the track was not the bearing");
	CHECK(f.acc_e == fzn_location_acc_encode(4) && f.acc_n == fzn_location_acc_encode(9)
	              && f.acc_v == fzn_location_acc_encode(19),
	      "epx, epy and epv were not the three accuracies");
}

static void test_the_axes_fall_back(void)
{
	fzn_location_fix_t f;

	CHECK(parse("{\"class\":\"TPV\",\"mode\":2,\"lat\":1.5,\"lon\":2.5,\"eph\":12}", &f) == 1
	              && f.acc_e == fzn_location_acc_encode(12)
	              && f.acc_n == fzn_location_acc_encode(12),
	      "eph alone was not both axes");
	CHECK(parse("{\"class\":\"TPV\",\"mode\":2,\"lat\":1.5,\"lon\":2.5,\"epy\":7}", &f) == 1
	              && f.acc_e == fzn_location_acc_encode(7)
	              && f.acc_n == fzn_location_acc_encode(7),
	      "one axis alone was not claimed in both");
	CHECK(parse("{\"class\":\"TPV\",\"mode\":2,\"lat\":1.5,\"lon\":2.5}", &f) == 1
	              && f.acc_e == FZN_LOCATION_ACC_UNKNOWN && f.acc_n == FZN_LOCATION_ACC_UNKNOWN,
	      "no accuracy was not unknown");
}

static void test_a_2d_fix_has_no_altitude(void)
{
	fzn_location_fix_t f;

	CHECK(parse("{\"class\":\"TPV\",\"mode\":2,\"lat\":-33.8688,\"lon\":151.2093,"
	            "\"alt\":40.0,\"epv\":3}", &f) == 1
	              && !f.has_alt && f.alt_m == 0 && f.acc_v == 0 && !f.has_bearing
	              && f.lat_e7 == -338688000 && f.lon_e7 == 1512093000 && f.utc_s == 0,
	      "a 2D fix claimed an altitude, or a time it was not given");
}

static void test_what_carries_nothing(void)
{
	fzn_location_fix_t f;

	CHECK(parse("{\"class\":\"TPV\",\"device\":\"/dev/ttyACM0\",\"mode\":1}", &f) == 0,
	      "a TPV still acquiring gave a fix");
	CHECK(parse("{\"class\":\"SKY\",\"satellites\":[]}", &f) == 0
	              && parse("{\"class\":\"VERSION\",\"release\":\"3.22\"}", &f) == 0,
	      "another class gave a fix");
	CHECK(parse("{\"class\":\"TPV\",\"mode\":3,\"lat\":1.0}", &f) == 0,
	      "a TPV with no longitude gave a fix");
}

static void test_what_is_refused(void)
{
	fzn_location_fix_t f;

	CHECK(parse("{\"mode\":3,\"lat\":1.0,\"lon\":2.0}", &f) == -1, "a line with no class was read");
	CHECK(parse("{\"class\":\"TPV\",\"mode\":3,\"lat\":91.0,\"lon\":2.0}", &f) == -1
	              && parse("{\"class\":\"TPV\",\"mode\":3,\"lat\":1.0,\"lon\":-180.0000001}", &f)
	                         == -1,
	      "a coordinate out of range was read");
	CHECK(parse("{\"class\":\"TPV\",\"mode\":3,\"lat\":1e1,\"lon\":2.0}", &f) == 0,
	      "an exponent was read as a number");
	CHECK(parse("{\"class\":\"TPV\",\"mode\":3,\"lat\":1.,\"lon\":2.0}", &f) == 0,
	      "a point with no digit after it was read as a number");
	CHECK(parse("{\"class\":\"TPV\",\"mode\":3,\"time\":\"2026-13-01T00:00:00Z\","
	            "\"lat\":1.0,\"lon\":2.0}", &f) == 1 && f.utc_s == 0,
	      "a thirteenth month was read as a time");
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
	test_a_3d_fix();
	test_the_axes_fall_back();
	test_a_2d_fix_has_no_altitude();
	test_what_carries_nothing();
	test_what_is_refused();
	test_the_suite_can_tell_pass_from_fail();

	printf("tpv_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
