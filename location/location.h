/*
 * A POSITION FIX, encoded, and what can be done to one without a network,
 * sec 676: fuzzypickles' location codec moved into fuzznet, as the holder
 * decided on 2026-10-21 (sec 672) -- the fields, the scales and the
 * degrading theirs (`core/src/location_internal.h` and `location.c`, read
 * at their d02897b), the byte order this tree's.
 *
 * NINETEEN BYTES, BIG-ENDIAN, `location/fix.situ`:
 *
 *    0  lat_e7   i32  latitude in 1e-7 degrees, -90 to 90
 *    4  lon_e7   i32  longitude in 1e-7 degrees, -180 to 180
 *    8  utc_s    u32  seconds since the epoch
 *   12  alt_m    i16  metres, a measurement only with FLAG_ALT
 *   14  bearing  u8   360/255 degrees a step, only with FLAG_BEARING
 *   15  acc_e    u8   east-west accuracy, log-scaled
 *   16  acc_n    u8   north-south accuracy, log-scaled
 *   17  acc_v    u8   vertical accuracy, only with FLAG_ALT
 *   18  flags    u8   FLAG_ALT, FLAG_BEARING, FLAG_COARSE
 *
 * TWO HORIZONTAL AXES, NOT ONE RADIUS: a receiver's error is rarely
 * circular, and gpsd reports east-west and north-south apart. Equal axes
 * are the circle. An absent field is written as zero, so two fixes that
 * mean the same are the same bytes.
 *
 * A COORDINATE OUT OF RANGE IS REFUSED, encoding and decoding, rather than
 * clamped: it can come only from a caller's fault, a corrupt store or a
 * hostile peer, and quietly moving somebody is worse than saying so.
 */
#ifndef FZN_LOCATION_H
#define FZN_LOCATION_H

#include <stddef.h>
#include <stdint.h>

#define FZN_LOCATION_FIX_LEN 19u

#define FZN_LOCATION_OFF_LAT 0u
#define FZN_LOCATION_OFF_LON 4u
#define FZN_LOCATION_OFF_UTC 8u
#define FZN_LOCATION_OFF_ALT 12u
#define FZN_LOCATION_OFF_BEARING 14u
#define FZN_LOCATION_OFF_ACC_E 15u
#define FZN_LOCATION_OFF_ACC_N 16u
#define FZN_LOCATION_OFF_ACC_V 17u
#define FZN_LOCATION_OFF_FLAGS 18u

#define FZN_LOCATION_FLAG_ALT 0x01u
#define FZN_LOCATION_FLAG_BEARING 0x02u
#define FZN_LOCATION_FLAG_COARSE 0x04u

#define FZN_LOCATION_LAT_E7_MAX 900000000
#define FZN_LOCATION_LON_E7_MAX 1800000000

/* THE ACCURACY THE RECEIVER DID NOT GIVE: distinct from every real one, so
 * an unknown estimate is neither a metre nor a measurement. */
#define FZN_LOCATION_ACC_UNKNOWN 255u

/* THE LEVELS A FIX IS DEGRADED TO, sec 632's renditions in this order: the
 * exact fix, a grid of 0.01 degree (about a kilometre), and one of 0.1
 * degree (about eleven). */
typedef enum fzn_location_level {
	FZN_LOCATION_EXACT = 0,
	FZN_LOCATION_COARSE = 1,
	FZN_LOCATION_REGION = 2
} fzn_location_level_t;
#define FZN_LOCATION_LEVELS 3u

/* A fix, decoded. The flags byte is no field: presence is the booleans,
 * so the two cannot disagree. */
typedef struct fzn_location_fix {
	int32_t lat_e7;
	int32_t lon_e7;
	uint32_t utc_s;
	int16_t alt_m;
	uint8_t bearing;
	uint8_t acc_e;
	uint8_t acc_n;
	uint8_t acc_v;
	uint8_t has_alt;
	uint8_t has_bearing;
	uint8_t is_coarse;
} fzn_location_fix_t;

/* Metres to the log scale, 16 codes an octave, 0 for a metre or better,
 * saturating at 254, which is 61440 m: below that, back within 7% of the
 * input, never above it; past it, 61440 m whatever the input. And back;
 * 0 for FZN_LOCATION_ACC_UNKNOWN, which no real accuracy decodes to. */
uint8_t fzn_location_acc_encode(uint32_t metres);
uint32_t fzn_location_acc_decode(uint8_t code);

/* THE WORSE HORIZONTAL AXIS, metres: the conservative one number for a
 * gate. An unknown axis is the worst there is, so a fix of unknown
 * accuracy never passes one. */
uint32_t fzn_location_worst_h_acc_m(const fzn_location_fix_t *fix);

/* Degrees, 0 to 359, to the byte and back, each rounded to nearest so a
 * track carries no bias. */
uint8_t fzn_location_bearing_encode(uint16_t degrees);
uint16_t fzn_location_bearing_decode(uint8_t code);

/* ENCODE into exactly FZN_LOCATION_FIX_LEN bytes of `out`: 1, or 0 for a
 * short `out` or a coordinate out of range. DECODE `len` bytes: 1, or 0
 * for a length that is not a fix's, or a coordinate out of range. */
int fzn_location_fix_encode(const fzn_location_fix_t *fix, uint8_t *out, size_t out_cap);
int fzn_location_fix_decode(const uint8_t *in, size_t len, fzn_location_fix_t *out);

/* DEGRADE `fix` in place to `level`: its position rounded to that level's
 * grid, half away from zero, clamped to the poles and the antimeridian, and
 * marked coarse. EXACT, or a level not listed, leaves it untouched. */
void fzn_location_degrade(fzn_location_fix_t *fix, fzn_location_level_t level);

#endif /* FZN_LOCATION_H */
