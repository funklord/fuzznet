/*
 * A fuzz harness for journey 5's wire inputs, sec 689's location: what a
 * host that shares its position, or asks for another's, is handed by
 * somebody else -- sec 770.
 *
 *   - A STREAM QUERY (`node/streams.h`): a contact's or a member's host
 *     asks a stream by name, past the last seq it holds.
 *   - THE ANSWER, a stream's records (`fzn_streams_take`): the asked host
 *     answers its own records, and this host keeps them as that host's.
 *   - A FIX (`location/location.h`): the bytes of one rendition, which a
 *     contact's host wrote and this host decodes to list.
 *   - A TPV LINE (`location/tpv.h`): one line of gpsd's JSON, read from a
 *     socket this host connects to -- a local daemon's, and still bytes
 *     this host did not write.
 *
 * THE PEER LIES BY MUTATION: each input is made whole, then with even odds
 * bent -- bits flipped, cut short, grown, a slice repeated or two bytes
 * swapped -- and a TPV line besides has a digit, a sign or a quote moved.
 *
 * THE PROPERTIES:
 *   1. A QUERY round-trips, and a bent one that decodes encodes back as
 *      exactly its bytes, a name a stream may have: one encoding a query.
 *   2. A WHOLE ANSWER is taken whole: every record kept as put. A BENT ONE
 *      takes at most what it claims, and each record kept is one the bytes
 *      hold, at levels and lengths a record may have, put back as bytes
 *      found in the answer -- nothing kept that was not said.
 *   3. A FIX round-trips; a bent one that decodes is in range and encodes
 *      back as exactly its bytes, so two strings never name one fix; and
 *      degraded to any level it stays in range, marked coarse below exact,
 *      and degrading it again moves nothing.
 *   4. A TPV LINE, bent, is read to a fix only in range, and that fix
 *      encodes.
 *
 * FLOORS: a run in which no bent query decoded, no bent answer kept a
 * record or none was refused, no bent fix decoded, or no bent TPV line
 * was read and none refused, has not tested what it claims.
 */

#include "../streams.h"
#include "../../location/location.h"
#include "../../location/tpv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 3000u
#define FUZZ_MIN_CASES 1000u

static int failures;

static void fail(const char *what, unsigned long c)
{
	failures++;
	if (failures <= 10)
		fprintf(stderr, "  FAIL location_fuzz.c: case %lu: %s\n", c, what);
}

/* ---- a generator, seeded ---------------------------------------------- */

static uint64_t state = 0x9e3779b97f4a7c15ull;

static uint64_t next(void)
{
	state ^= state << 13;
	state ^= state >> 7;
	state ^= state << 17;
	return state;
}

/* ---- the lie ----------------------------------------------------------- */

static size_t bend(uint8_t *p, size_t len, size_t cap)
{
	size_t i, n, a, b;
	uint8_t t;

	if (!len)
		return len;
	switch (next() % 5u) {
	case 0: /* bits flipped */
		n = 1u + (size_t)(next() % 6u);
		for (i = 0; i < n; i++)
			p[next() % len] ^= (uint8_t)(1u << (next() % 8u));
		return len;
	case 1: /* cut short */
		return (size_t)(next() % len);
	case 2: /* grown */
		n = 1u + (size_t)(next() % 32u);
		if (len + n > cap)
			n = cap - len;
		for (i = 0; i < n; i++)
			p[len + i] = (uint8_t)next();
		return len + n;
	case 3: /* a slice repeated */
		a = (size_t)(next() % len);
		n = 1u + (size_t)(next() % 16u);
		if (a + n > len)
			n = len - a;
		if (len + n > cap)
			return len;
		memmove(p + a + n, p + a, len - a);
		return len + n;
	default: /* two bytes swapped */
		a = (size_t)(next() % len);
		b = (size_t)(next() % len);
		t = p[a];
		p[a] = p[b];
		p[b] = t;
		return len;
	}
}

/* A TPV LINE'S OWN LIES: a character from the ones its numbers and
 * strings are made of, put where another was. */
static void bend_text(uint8_t *p, size_t len)
{
	static const char CHARS[] = "0123456789-+.eE\":,{} ";

	if (len)
		p[next() % len] = (uint8_t)CHARS[next() % (sizeof(CHARS) - 1u)];
}

/* ---- a store in memory, of every slot ----------------------------------- */

static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	(void)ctx;
	for (i = 0; i < in_len; i++)
		h = (h ^ in[i]) * 0x100000001b3ull;
	for (i = 0; i < out_len; i++) {
		h = (h ^ (uint64_t)i) * 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 56);
	}
	return 1;
}

static const fzn_hash_ops_t HASH = { stub_hash, NULL };

#define ROWS 64u
#define ROW_MAX 512u

static struct {
	int used;
	fzn_persist_slot_t slot;
	uint8_t subject[32];
	uint8_t bytes[ROW_MAX];
	size_t len;
} rows[ROWS];

static int find(fzn_persist_slot_t slot, const uint8_t *subject)
{
	int i;

	for (i = 0; i < (int)ROWS; i++)
		if (rows[i].used && rows[i].slot == slot && memcmp(rows[i].subject, subject, 32u) == 0)
			return i;
	return -1;
}

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	int i = find(slot, subject);

	(void)ctx;
	if (i < 0 || rows[i].len > cap)
		return 0;
	memcpy(out, rows[i].bytes, rows[i].len);
	*len = rows[i].len;
	return 1;
}

static int mem_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                    const uint8_t *bytes, size_t len)
{
	int i = find(slot, subject), k;

	(void)ctx;
	if (len > ROW_MAX)
		return 0;
	for (k = 0; i < 0 && k < (int)ROWS; k++)
		if (!rows[k].used)
			i = k;
	if (i < 0)
		return 0;
	rows[i].used = 1;
	rows[i].slot = slot;
	memcpy(rows[i].subject, subject, 32u);
	memcpy(rows[i].bytes, bytes, len);
	rows[i].len = len;
	return 1;
}

static int mem_list(void *ctx, fzn_persist_slot_t slot, uint8_t *out, size_t max, size_t *count)
{
	size_t i, n = 0;

	(void)ctx;
	for (i = 0; i < ROWS; i++)
		if (rows[i].used && rows[i].slot == slot) {
			if (n == max)
				return 0;
			memcpy(out + 32u * n++, rows[i].subject, 32u);
		}
	*count = n;
	return 1;
}

static int mem_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	int i = find(slot, subject);

	(void)ctx;
	if (i >= 0)
		rows[i].used = 0;
	return 1;
}

static const fzn_persist_ops_t STORE = { mem_load, mem_save, mem_list, mem_remove, NULL, NULL };
static const fzn_streams_t S = { &STORE, &HASH };

/* ---- the inputs, made whole -------------------------------------------- */

static size_t a_name(char *name)
{
	static const char CHARS[] = "abcdefghijklmnopqrstuvwxyz0123456789_";
	size_t n = 1u + (size_t)(next() % FZN_STREAM_NAME_MAX), i;

	for (i = 0; i < n; i++)
		name[i] = CHARS[next() % (sizeof(CHARS) - 1u)];
	return n;
}

static void a_record(fzn_stream_record_t *r, uint64_t seq)
{
	size_t k, i;

	memset(r, 0, sizeof(*r));
	r->seq = seq;
	r->at = next();
	r->levels = 1u + (size_t)(next() % FZN_STREAM_LEVELS_MAX);
	for (k = 0; k < r->levels; k++) {
		r->rendition_len[k] = (size_t)(next() % (FZN_STREAM_RENDITION_MAX + 1u));
		for (i = 0; i < r->rendition_len[k]; i++)
			r->rendition[k][i] = (uint8_t)next();
	}
}

static int same_record(const fzn_stream_record_t *a, const fzn_stream_record_t *b)
{
	size_t k;

	if (a->seq != b->seq || a->at != b->at || a->levels != b->levels)
		return 0;
	for (k = 0; k < a->levels; k++)
		if (a->rendition_len[k] != b->rendition_len[k]
		    || memcmp(a->rendition[k], b->rendition[k], a->rendition_len[k]) != 0)
			return 0;
	return 1;
}

static void a_fix(fzn_location_fix_t *f)
{
	memset(f, 0, sizeof(*f));
	f->lat_e7 = (int32_t)(next() % (2u * FZN_LOCATION_LAT_E7_MAX + 1u)) - FZN_LOCATION_LAT_E7_MAX;
	f->lon_e7 = (int32_t)((int64_t)(next() % (2ull * FZN_LOCATION_LON_E7_MAX + 1u))
	                      - FZN_LOCATION_LON_E7_MAX);
	f->utc_s = (uint32_t)next();
	f->has_alt = (uint8_t)(next() & 1u);
	if (f->has_alt) {
		f->alt_m = (int16_t)next();
		f->acc_v = (uint8_t)next();
	}
	f->has_bearing = (uint8_t)(next() & 1u);
	if (f->has_bearing)
		f->bearing = (uint8_t)next();
	f->acc_e = (uint8_t)next();
	f->acc_n = (uint8_t)next();
}

static int same_fix(const fzn_location_fix_t *a, const fzn_location_fix_t *b)
{
	return a->lat_e7 == b->lat_e7 && a->lon_e7 == b->lon_e7 && a->utc_s == b->utc_s
	       && a->alt_m == b->alt_m && a->bearing == b->bearing && a->acc_e == b->acc_e
	       && a->acc_n == b->acc_n && a->acc_v == b->acc_v && a->has_alt == b->has_alt
	       && a->has_bearing == b->has_bearing && a->is_coarse == b->is_coarse;
}

static int in_range(const fzn_location_fix_t *f)
{
	return f->lat_e7 >= -FZN_LOCATION_LAT_E7_MAX && f->lat_e7 <= FZN_LOCATION_LAT_E7_MAX
	       && f->lon_e7 >= -FZN_LOCATION_LON_E7_MAX && f->lon_e7 <= FZN_LOCATION_LON_E7_MAX;
}

static const char TPV[] =
        "{\"class\":\"TPV\",\"device\":\"/dev/ttyACM0\",\"mode\":3,"
        "\"time\":\"2026-10-21T12:00:05.000Z\",\"ept\":0.005,\"lat\":59.329323456,"
        "\"lon\":-18.068581549,\"altHAE\":31.6,\"altMSL\":7.2,\"alt\":7.2,\"epx\":4.2,"
        "\"epy\":8.6,\"epv\":19.4,\"track\":271.4,\"speed\":1.2,\"eph\":9.1}";

int main(int argc, char **argv)
{
	static const uint8_t host[32] = { 0x5a, 0x01 };
	unsigned long cases = FUZZ_DEFAULT_CASES, c;
	unsigned long query_bent = 0, kept_bent = 0, refused_bent = 0, fix_bent = 0;
	unsigned long tpv_read = 0, tpv_refused = 0;

	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases < FUZZ_MIN_CASES)
			cases = FUZZ_MIN_CASES;
	}
	if (argc > 2)
		state = strtoull(argv[2], NULL, 0) | 1u;

	for (c = 0; c < cases; c++) {
		/* 1: A QUERY. */
		{
			char name[FZN_STREAM_NAME_MAX];
			uint8_t q[FZN_STREAM_QUERY_MAX + 64u], again[FZN_STREAM_QUERY_MAX];
			size_t name_len = a_name(name), n, got_len = 0;
			uint64_t since = next(), got_since = 0;
			const char *got = NULL;

			n = fzn_streams_query_encode(name, name_len, since, q, sizeof(q));
			if (!n || !fzn_streams_query_decode(q, n, &got, &got_len, &got_since)
			    || got_len != name_len || memcmp(got, name, name_len) != 0 || got_since != since)
				fail("a whole query did not round-trip", c);
			n = bend(q, n, sizeof(q));
			if (fzn_streams_query_decode(q, n, &got, &got_len, &got_since)) {
				query_bent++;
				if (!fzn_stream_name_ok(got, got_len)
				    || fzn_streams_query_encode(got, got_len, got_since, again, sizeof(again)) != n
				    || memcmp(again, q, n) != 0)
					fail("a bent query decoded to other than its own bytes", c);
			}
		}

		/* 2: THE ANSWER. */
		{
			static fzn_stream_record_t made[8], held;
			static uint8_t answer[8u * (17u + FZN_STREAM_LEVELS_MAX * 65u) + 64u];
			size_t count = 1u + (size_t)(next() % 8u), k, at = 0, len, taken = 0;
			uint64_t seq = 1u + next() % 1000u, stopped, s, last;
			fzn_streams_err_t err;

			memset(rows, 0, sizeof(rows));
			for (k = 0; k < count; k++) {
				a_record(&made[k], seq + k);
				at = fzn_streams_record_put(&made[k], answer, at, sizeof(answer));
			}
			err = fzn_streams_take(&S, "location", 8u, host, answer, at, count, &taken,
			                       &stopped);
			if (err != FZN_STREAMS_OK || taken != count)
				fail("a whole answer was not taken whole", c);
			for (k = 0; k < count; k++)
				if (fzn_streams_get(&S, "location", 8u, host, made[k].seq, &held)
				        != FZN_STREAMS_OK
				    || !same_record(&held, &made[k]))
					fail("a record of a whole answer was not kept as put", c);

			memset(rows, 0, sizeof(rows));
			len = bend(answer, at, sizeof(answer));
			err = fzn_streams_take(&S, "location", 8u, host, answer, len, count, &taken,
			                       &stopped);
			if (taken > count)
				fail("a bent answer took more records than it claimed", c);
			if (err == FZN_STREAMS_ERR_MALFORMED)
				refused_bent++;
			last = fzn_streams_last(&S, "location", 8u, host);
			for (s = last > 64u ? last - 63u : 1u; last && s <= last; s++) {
				uint8_t put[17u + FZN_STREAM_LEVELS_MAX * 65u];
				size_t n, i;
				int found = 0;

				if (fzn_streams_get(&S, "location", 8u, host, s, &held) != FZN_STREAMS_OK)
					continue;
				kept_bent++;
				n = fzn_streams_record_put(&held, put, 0, sizeof(put));
				if (!n || held.levels == 0u || held.levels > FZN_STREAM_LEVELS_MAX)
					fail("a record kept from a bent answer is no record", c);
				for (i = 0; n && i + n <= len && !found; i++)
					found = memcmp(answer + i, put, n) == 0;
				if (!found)
					fail("a record kept from a bent answer is not in its bytes", c);
			}
		}

		/* 3: A FIX. */
		{
			fzn_location_fix_t f, got, deg, twice;
			uint8_t bytes[FZN_LOCATION_FIX_LEN + 64u], again[FZN_LOCATION_FIX_LEN];
			size_t n;
			unsigned level;

			a_fix(&f);
			if (!fzn_location_fix_encode(&f, bytes, sizeof(bytes))
			    || !fzn_location_fix_decode(bytes, FZN_LOCATION_FIX_LEN, &got)
			    || !same_fix(&got, &f))
				fail("a whole fix did not round-trip", c);
			n = bend(bytes, FZN_LOCATION_FIX_LEN, sizeof(bytes));
			if (fzn_location_fix_decode(bytes, n, &got)) {
				fix_bent++;
				if (!in_range(&got) || !fzn_location_fix_encode(&got, again, sizeof(again))
				    || n != FZN_LOCATION_FIX_LEN || memcmp(again, bytes, n) != 0)
					fail("a bent fix decoded to other than its own bytes", c);
				for (level = 0; level < FZN_LOCATION_LEVELS; level++) {
					deg = got;
					fzn_location_degrade(&deg, (fzn_location_level_t)level);
					twice = deg;
					fzn_location_degrade(&twice, (fzn_location_level_t)level);
					if (!in_range(&deg) || (level && !deg.is_coarse)
					    || !same_fix(&deg, &twice)
					    || !fzn_location_fix_encode(&deg, again, sizeof(again)))
						fail("a degraded fix left its range, was not marked, or moved again",
						     c);
				}
			}
		}

		/* 4: A TPV LINE. */
		{
			uint8_t line[sizeof(TPV) + 64u], out[FZN_LOCATION_FIX_LEN];
			fzn_location_fix_t f;
			size_t n = sizeof(TPV) - 1u, k;
			int r;

			memcpy(line, TPV, n);
			for (k = next() % 4u; k; k--)
				bend_text(line, n);
			if (next() & 1u)
				n = bend(line, n, sizeof(line) - 1u);
			r = fzn_location_tpv_parse((const char *)line, n, &f);
			if (r == 1) {
				tpv_read++;
				if (!in_range(&f) || !fzn_location_fix_encode(&f, out, sizeof(out)))
					fail("a bent TPV line was read to a fix out of range", c);
			} else if (r < 0)
				tpv_refused++;
		}
	}

	if (query_bent == 0u)
		fail("no bent query decoded", cases);
	if (kept_bent == 0u || refused_bent == 0u)
		fail("no bent answer kept a record, or none was refused", cases);
	if (fix_bent == 0u)
		fail("no bent fix decoded", cases);
	if (tpv_read == 0u || tpv_refused == 0u)
		fail("no bent TPV line was read, or none was refused", cases);
	printf("location_fuzz: %lu cases, %lu bent query(s) decoded, %lu record(s) kept from bent "
	       "answers, %lu refused, %lu bent fix(es) decoded, %lu TPV line(s) read, %lu refused, "
	       "%d failure(s)\n",
	       cases, query_bent, kept_bent, refused_bent, fix_bent, tpv_read, tpv_refused, failures);
	return failures ? 1 : 0;
}
