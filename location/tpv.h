/*
 * GPSD'S POSITION REPORT, read, sec 678: one line of gpsd's JSON -- a TPV
 * object -- to a fix (`location/location.h`), with no socket and no
 * floating point, so the part most likely to be wrong is the part a suite
 * can hold without a receiver. Carried over from fuzzypickles'
 * `daemon/gpsd_source.c` (at their d02897b) in what it reads and refuses;
 * its numbers are read as decimals and rounded half away from zero, where
 * theirs went through strtod.
 *
 * A FLAT KEY SCANNER, NOT A JSON PARSER: gpsd's TPV is one flat object of
 * numbers and short strings, and its keys do not recur in its values.
 *
 * What a line gives:
 *   - nothing, for another class (SKY, VERSION, WATCH ...) or a TPV with
 *     no fix (mode 0 or 1), which gpsd sends all the while it acquires;
 *   - a fix: lat and lon to 1e-7 degrees; time from `time`, ISO 8601 UTC,
 *     or 0 for the caller to supply; altitude, `altHAE` or the older `alt`,
 *     only for a 3D fix (mode 3), since a 2D fix's altitude is no
 *     measurement; bearing from `track`; the two horizontal axes from
 *     `epx` and `epy`, or both from `eph`, or one from the other, or
 *     unknown; vertical accuracy from `epv`, beside an altitude.
 */
#ifndef FZN_LOCATION_TPV_H
#define FZN_LOCATION_TPV_H

#include <stddef.h>
#include <stdint.h>

#include "location.h"

/* `len` bytes of one line: 1 with the fix in `out`; 0 for a line that
 * carries none; -1 for a line that is no TPV gpsd would send -- no class,
 * a coordinate out of range or not a number. A fix with no `time` has
 * `utc_s` 0. */
int fzn_location_tpv_parse(const char *line, size_t len, fzn_location_fix_t *out);

#endif /* FZN_LOCATION_TPV_H */
