#include "tpv.h"

#include <string.h>

#include "../wire/generated/json.h"
#include "../wire/json_walk.h"

/* THE KEYS READ, each the first member of its name in the object:
 * gpsd's TPV is one flat object, walked once through situ's JSON (sec
 * 1470); a key nested in another member's value is not one of these. */
enum { K_CLASS, K_MODE, K_LAT, K_LON, K_TIME, K_ALT_HAE, K_ALT, K_TRACK, K_EPH, K_EPX, K_EPY, K_EPV, K_COUNT };
static const char *const key_names[K_COUNT] = { "class", "mode", "lat", "lon", "time", "altHAE",
	                                        "alt", "track", "eph", "epx", "epy", "epv" };

struct tpv_values {
	situ_view_t at[K_COUNT];
	int have[K_COUNT];
};

static int take(const char *key, size_t len, const situ_view_t *held, void *ctx)
{
	struct tpv_values *t = ctx;
	int k;

	for (k = 0; k < K_COUNT; k++)
		if (!t->have[k] && fzn_json_walk_key_is(key, len, key_names[k])) {
			t->at[k] = *held;
			t->have[k] = 1;
			break;
		}
	return 1;
}

/* A NUMBER, to `places` decimals in `*out`, rounded half away from zero at
 * the first digit past them: 1, or 0 for no number there. An exponent, or
 * a magnitude past 10^12 at that scale, is no number gpsd sends. */
static int scaled(const struct tpv_values *t, int key, unsigned places, int64_t *out)
{
	const char *v, *end;
	size_t len;
	int64_t whole = 0;
	unsigned taken = 0;
	int negative = 0, digits = 0, round_up = 0;

	if (!t->have[key] || !fzn_json_walk_number(&t->at[key], &v, &len))
		return 0;
	end = v + len;
	if (v < end && *v == '-') {
		negative = 1;
		v++;
	}
	for (; v < end && *v >= '0' && *v <= '9'; v++, digits++) {
		if (digits == 12)
			return 0;
		whole = whole * 10 + (*v - '0');
	}
	if (!digits)
		return 0;
	if (v < end && *v == '.') {
		v++;
		if (v >= end || *v < '0' || *v > '9')
			return 0;
		for (; v < end && *v >= '0' && *v <= '9'; v++) {
			if (taken < places) {
				whole = whole * 10 + (*v - '0');
				taken++;
			} else if (taken == places) {
				round_up = *v >= '5';
				taken++;
			}
		}
	}
	/* The whole number read, or it was none -- an exponent among what
	 * is left. */
	if (v != end)
		return 0;
	if (taken > places)
		taken = places;
	for (; taken < places; taken++)
		whole *= 10;
	whole += round_up;
	*out = negative ? -whole : whole;
	return 1;
}

/* A SHORT STRING's characters, unescaped -- gpsd's class and time hold no
 * escapes -- into `out`, NUL ended: 1, or 0 for none, one holding an
 * escape, or one longer than `cap`. */
static int string_of(const struct tpv_values *t, int key, char *out, size_t cap)
{
	const char *v;
	size_t len;

	if (!t->have[key] || !fzn_json_walk_string(&t->at[key], &v, &len) || len + 1u > cap || memchr(v, '\\', len))
		return 0;
	memcpy(out, v, len);
	out[len] = '\0';
	return 1;
}

/* `YYYY-MM-DDTHH:MM:SS[.fff]Z` as seconds since the epoch: 1, or 0. */
static int iso_utc(const char *t, uint32_t *out)
{
	static const unsigned at[6] = { 0, 5, 8, 11, 14, 17 }, width[6] = { 4, 2, 2, 2, 2, 2 };
	static const char after[6] = { '-', '-', 'T', ':', ':', '\0' };
	long v[6];
	long long days, secs;
	int yy, era;
	unsigned yoe, doy, doe, k, i;

	for (k = 0; k < 6u; k++) {
		v[k] = 0;
		for (i = 0; i < width[k]; i++) {
			char c = t[at[k] + i];

			if (c < '0' || c > '9')
				return 0;
			v[k] = v[k] * 10 + (c - '0');
		}
		if (after[k] && t[at[k] + width[k]] != after[k])
			return 0;
	}
	if (v[1] < 1 || v[1] > 12 || v[2] < 1 || v[2] > 31 || v[3] > 23 || v[4] > 59 || v[5] > 60)
		return 0;
	/* DAYS FROM 1970-01-01, Howard Hinnant's civil algorithm. */
	yy = (int)v[0] - (v[1] <= 2);
	era = (yy >= 0 ? yy : yy - 399) / 400;
	yoe = (unsigned)(yy - era * 400);
	doy = (unsigned)((153 * (v[1] + (v[1] > 2 ? -3 : 9)) + 2) / 5 + v[2] - 1);
	doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
	days = (long long)era * 146097 + (long long)doe - 719468;
	secs = days * 86400 + v[3] * 3600 + v[4] * 60 + v[5];
	if (secs < 0 || secs > 0xffffffffLL)
		return 0;
	*out = (uint32_t)secs;
	return 1;
}

int fzn_location_tpv_parse(const char *line, size_t len, fzn_location_fix_t *out)
{
	char class_name[16], when[40];
	int64_t mode, lat, lon, alt, track, eph, epx, epy, epv;
	int have_eph, have_x, have_y;
	struct tpv_values t;
	situ_msg_t msg;
	situ_view_t line_value;

	memset(&t, 0, sizeof(t));
	/* ONE JSON OBJECT, framed and validated: a line that is none -- cut,
	 * mangled, `1.` for a number -- is no line gpsd would send. */
	if (!line || !out || !len || !fzn_json_walk_frame(line, len, &msg, &line_value)
	    || !fzn_json_walk_members(&line_value, take, &t))
		return -1;
	if (!string_of(&t, K_CLASS, class_name, sizeof(class_name)))
		return -1;
	if (strcmp(class_name, "TPV") != 0)
		return 0;
	if (!scaled(&t, K_MODE, 0, &mode) || mode < 2)
		return 0;
	if (!scaled(&t, K_LAT, 7, &lat) || !scaled(&t, K_LON, 7, &lon))
		return 0;
	if (lat > FZN_LOCATION_LAT_E7_MAX || lat < -FZN_LOCATION_LAT_E7_MAX
	    || lon > FZN_LOCATION_LON_E7_MAX || lon < -FZN_LOCATION_LON_E7_MAX)
		return -1;
	memset(out, 0, sizeof(*out));
	out->lat_e7 = (int32_t)lat;
	out->lon_e7 = (int32_t)lon;
	if (!string_of(&t, K_TIME, when, sizeof(when)) || !iso_utc(when, &out->utc_s))
		out->utc_s = 0;
	if (mode >= 3 && (scaled(&t, K_ALT_HAE, 0, &alt) || scaled(&t, K_ALT, 0, &alt))
	    && alt > -32768 && alt < 32767) {
		out->alt_m = (int16_t)alt;
		out->has_alt = 1;
	}
	/* A HEADING ONLY WHILE MOVING: gpsd leaves `track` out otherwise. */
	if (scaled(&t, K_TRACK, 0, &track) && track >= 0 && track < 360) {
		out->bearing = fzn_location_bearing_encode((uint16_t)track);
		out->has_bearing = 1;
	}
	/* TWO AXES WHERE GIVEN, one claimed in both where only one is, and
	 * unknown where none is -- never a figure made up. */
	have_eph = scaled(&t, K_EPH, 0, &eph) && eph >= 0;
	have_x = scaled(&t, K_EPX, 0, &epx) && epx >= 0;
	have_y = scaled(&t, K_EPY, 0, &epy) && epy >= 0;
	if (!(have_x && have_y)) {
		if (have_eph) {
			epx = epy = eph;
		} else if (have_x) {
			epy = epx;
		} else if (have_y) {
			epx = epy;
		} else {
			epx = epy = -1;
		}
	}
	out->acc_e = epx < 0 ? (uint8_t)FZN_LOCATION_ACC_UNKNOWN
	                     : fzn_location_acc_encode(epx > 0xffffffffLL ? 0xffffffffu : (uint32_t)epx);
	out->acc_n = epy < 0 ? (uint8_t)FZN_LOCATION_ACC_UNKNOWN
	                     : fzn_location_acc_encode(epy > 0xffffffffLL ? 0xffffffffu : (uint32_t)epy);
	if (out->has_alt)
		out->acc_v = scaled(&t, K_EPV, 0, &epv) && epv >= 0
		             ? fzn_location_acc_encode(epv > 0xffffffffLL ? 0xffffffffu : (uint32_t)epv)
		             : (uint8_t)FZN_LOCATION_ACC_UNKNOWN;
	return 1;
}
