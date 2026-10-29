#include "location.h"

#include "../wire/bytes.h"

#include <stdio.h>
#include <string.h>

_Static_assert(FZN_LOCATION_OFF_FLAGS + 1u == FZN_LOCATION_FIX_LEN,
               "location layout: the fix is not nineteen bytes");

/* ---- accuracy, log-scaled ------------------------------------------------
 *
 * code = 16 * log2(metres), by an integer octave-and-fraction walk rather
 * than log2(), so the library needs neither libm nor floating point. */
uint8_t fzn_location_acc_encode(uint32_t metres)
{
	uint32_t octave = 0, v = metres, base, frac, code;

	if (metres <= 1u)
		return 0;
	while (v >= 2u) {
		v >>= 1;
		octave++;
	}
	base = 1u << octave;
	frac = (uint32_t)(((uint64_t)(metres - base) * 16u) / base);
	code = octave * 16u + frac;
	/* 254, not 255: the top code is "unknown". */
	return code > 254u ? 254u : (uint8_t)code;
}

uint32_t fzn_location_acc_decode(uint8_t code)
{
	uint32_t octave = (uint32_t)code / 16u, frac = (uint32_t)code % 16u, base;

	if (code == FZN_LOCATION_ACC_UNKNOWN)
		return 0;
	if (code == 0u)
		return 1;
	if (octave >= 32u)
		return 0xffffffffu;
	base = 1u << octave;
	return base + (base * frac) / 16u;
}

uint32_t fzn_location_worst_h_acc_m(const fzn_location_fix_t *fix)
{
	uint32_t e, n;

	if (!fix || fix->acc_e == FZN_LOCATION_ACC_UNKNOWN || fix->acc_n == FZN_LOCATION_ACC_UNKNOWN)
		return 0xffffffffu;
	e = fzn_location_acc_decode(fix->acc_e);
	n = fzn_location_acc_decode(fix->acc_n);
	return e > n ? e : n;
}

/* ---- bearing ---------------------------------------------------------- */

uint8_t fzn_location_bearing_encode(uint16_t degrees)
{
	uint32_t d = degrees % 360u;

	return (uint8_t)((d * 255u + 180u) / 360u);
}

uint16_t fzn_location_bearing_decode(uint8_t code)
{
	return (uint16_t)(((uint32_t)code * 360u + 127u) / 255u);
}

/* ---- the fix ---------------------------------------------------------- */

static int in_range(int32_t lat, int32_t lon)
{
	return lat <= FZN_LOCATION_LAT_E7_MAX && lat >= -FZN_LOCATION_LAT_E7_MAX
	       && lon <= FZN_LOCATION_LON_E7_MAX && lon >= -FZN_LOCATION_LON_E7_MAX;
}

/* Two's complement both ways without an implementation-defined cast. */
static uint32_t from_i32(int32_t v)
{
	return (uint32_t)v;
}

static int32_t to_i32(uint32_t u)
{
	return u <= 0x7fffffffu ? (int32_t)u : (int32_t)(u - 0x80000000u) + (-0x7fffffff - 1);
}

static int16_t to_i16(uint16_t u)
{
	return u <= 0x7fffu ? (int16_t)u : (int16_t)((int32_t)u - 0x10000);
}

int fzn_location_fix_encode(const fzn_location_fix_t *fix, uint8_t *out, size_t out_cap)
{
	uint8_t flags = 0;

	if (!fix || !out || out_cap < FZN_LOCATION_FIX_LEN || !in_range(fix->lat_e7, fix->lon_e7))
		return 0;
	if (fix->has_alt)
		flags |= FZN_LOCATION_FLAG_ALT;
	if (fix->has_bearing)
		flags |= FZN_LOCATION_FLAG_BEARING;
	if (fix->is_coarse)
		flags |= FZN_LOCATION_FLAG_COARSE;
	fzn_put_be32(out + FZN_LOCATION_OFF_LAT, from_i32(fix->lat_e7));
	fzn_put_be32(out + FZN_LOCATION_OFF_LON, from_i32(fix->lon_e7));
	fzn_put_be32(out + FZN_LOCATION_OFF_UTC, fix->utc_s);
	/* ABSENT IS ZERO, so a fix has one encoding. */
	fzn_put_be16(out + FZN_LOCATION_OFF_ALT, fix->has_alt ? (uint16_t)fix->alt_m : 0u);
	out[FZN_LOCATION_OFF_BEARING] = fix->has_bearing ? fix->bearing : 0u;
	out[FZN_LOCATION_OFF_ACC_E] = fix->acc_e;
	out[FZN_LOCATION_OFF_ACC_N] = fix->acc_n;
	out[FZN_LOCATION_OFF_ACC_V] = fix->has_alt ? fix->acc_v : 0u;
	out[FZN_LOCATION_OFF_FLAGS] = flags;
	return 1;
}

int fzn_location_fix_decode(const uint8_t *in, size_t len, fzn_location_fix_t *out)
{
	uint8_t flags;

	if (!in || !out || len != FZN_LOCATION_FIX_LEN)
		return 0;
	memset(out, 0, sizeof(*out));
	flags = in[FZN_LOCATION_OFF_FLAGS];
	/* A FLAG NOT DEFINED IS NOT A FIX: the schema bounds the byte at 7. */
	if (flags & ~(FZN_LOCATION_FLAG_ALT | FZN_LOCATION_FLAG_BEARING | FZN_LOCATION_FLAG_COARSE))
		return 0;
	out->lat_e7 = to_i32(fzn_get_be32(in + FZN_LOCATION_OFF_LAT));
	out->lon_e7 = to_i32(fzn_get_be32(in + FZN_LOCATION_OFF_LON));
	if (!in_range(out->lat_e7, out->lon_e7))
		return 0;
	out->utc_s = fzn_get_be32(in + FZN_LOCATION_OFF_UTC);
	out->has_alt = (flags & FZN_LOCATION_FLAG_ALT) ? 1u : 0u;
	out->has_bearing = (flags & FZN_LOCATION_FLAG_BEARING) ? 1u : 0u;
	/* ABSENT IS ZERO HERE TOO, sec 770: the encoder writes an absent field
	 * as zero, and a decoder that passed over whatever stood there let one
	 * fix be any of 2^40 strings -- location_fuzz's first run. Bytes that
	 * are no encoder's are no fix. */
	if ((!out->has_alt
	     && (fzn_get_be16(in + FZN_LOCATION_OFF_ALT) || in[FZN_LOCATION_OFF_ACC_V]))
	    || (!out->has_bearing && in[FZN_LOCATION_OFF_BEARING]))
		return 0;
	out->is_coarse = (flags & FZN_LOCATION_FLAG_COARSE) ? 1u : 0u;
	out->alt_m = out->has_alt ? to_i16(fzn_get_be16(in + FZN_LOCATION_OFF_ALT)) : 0;
	out->bearing = out->has_bearing ? in[FZN_LOCATION_OFF_BEARING] : 0u;
	out->acc_e = in[FZN_LOCATION_OFF_ACC_E];
	out->acc_n = in[FZN_LOCATION_OFF_ACC_N];
	out->acc_v = out->has_alt ? in[FZN_LOCATION_OFF_ACC_V] : 0u;
	return 1;
}

/* ---- degrees as text ------------------------------------------------- */

int fzn_location_degrees_parse(const char *text, size_t len, int32_t limit_e7, int32_t *out)
{
	size_t i = 0, digits = 0, places = 0;
	int negative = 0, point = 0;
	int64_t v = 0;

	if (!text || !out || !len)
		return 0;
	if (text[0] == '-') {
		negative = 1;
		i = 1;
	}
	for (; i < len; i++) {
		char c = text[i];

		if (c == '.' && !point) {
			point = 1;
			continue;
		}
		/* TEN DIGITS AT MOST, 180.0000000's: more cannot be a
		 * coordinate, and would overflow being scaled. */
		if (c < '0' || c > '9' || (point && places == 7u) || digits == 10u)
			return 0;
		v = v * 10 + (c - '0');
		digits++;
		if (point)
			places++;
	}
	/* A DIGIT EACH SIDE OF THE POINT, or no point. */
	if (!digits || (point && (!places || text[len - 1u] == '.' || text[negative] == '.')))
		return 0;
	for (; places < 7u; places++)
		v *= 10;
	if (v > limit_e7)
		return 0;
	*out = negative ? -(int32_t)v : (int32_t)v;
	return 1;
}

size_t fzn_location_degrees_text(int32_t e7, char *out)
{
	int64_t v = e7;
	uint32_t whole, frac;
	int n;

	if (!out)
		return 0;
	if (v < 0)
		v = -v;
	whole = (uint32_t)(v / 10000000);
	frac = (uint32_t)(v % 10000000);
	n = snprintf(out, FZN_LOCATION_DEGREES_TEXT_MAX, "%s%u.%07u", e7 < 0 ? "-" : "",
	             (unsigned)whole, (unsigned)frac);
	return n > 0 ? (size_t)n : 0u;
}

/* ---- degrading -------------------------------------------------------- */

/* `v`, 1e-7 degrees, to the nearest multiple of `step`, half away from
 * zero; in 64 bits, where v + step / 2 always fits. */
static int32_t to_grid(int32_t v, int32_t step)
{
	int64_t g = step, x = v;
	int64_t r = x >= 0 ? ((x + g / 2) / g) * g : -(((-x) + g / 2) / g) * g;

	return (int32_t)r;
}

void fzn_location_degrade(fzn_location_fix_t *fix, fzn_location_level_t level)
{
	int32_t step;

	if (!fix)
		return;
	/* DEGREES, NOT METRES: a cell is square in degrees and narrows toward
	 * the poles, which a privacy floor, whose job is only to stop being
	 * exact, can afford. */
	switch (level) {
	case FZN_LOCATION_COARSE:
		step = 100000;
		break;
	case FZN_LOCATION_REGION:
		step = 1000000;
		break;
	case FZN_LOCATION_EXACT:
	default:
		return;
	}
	fix->lat_e7 = to_grid(fix->lat_e7, step);
	fix->lon_e7 = to_grid(fix->lon_e7, step);
	if (fix->lat_e7 > FZN_LOCATION_LAT_E7_MAX)
		fix->lat_e7 = FZN_LOCATION_LAT_E7_MAX;
	else if (fix->lat_e7 < -FZN_LOCATION_LAT_E7_MAX)
		fix->lat_e7 = -FZN_LOCATION_LAT_E7_MAX;
	if (fix->lon_e7 > FZN_LOCATION_LON_E7_MAX)
		fix->lon_e7 = FZN_LOCATION_LON_E7_MAX;
	else if (fix->lon_e7 < -FZN_LOCATION_LON_E7_MAX)
		fix->lon_e7 = -FZN_LOCATION_LON_E7_MAX;
	fix->is_coarse = 1;
}
