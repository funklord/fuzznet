/* THE SETTINGS PARSERS ON SITU'S CODE AGAINST THE ONES THEY REPLACED,
 * project.md sec 1408: state/schema.c's count, duration, flag and address,
 * whose grammar is node/settings_registry.situ's generated parsers, and
 * `state/test/schema_ref.h`, the hand-written parsers they were until
 * then, kept whole as the oracle. Each is given the same seeded strings --
 * digits with and without leading zeros, d h m s, on off 1 0, hosts and
 * ports, and every byte nearby -- under seeded bounds, and every verdict,
 * value and host is compared.
 *
 * NO DIFFERENCE IS ACCEPTED within the bounds fuzznet's tables use. One is
 * known outside them and not drawn: a duration whose count passes 2^32 - 1,
 * which the generated `decimal u32` refuses, possible only where a table's
 * maximum passes 136 years in seconds.
 *
 * Exit 0 when nothing differed; 1 with each kind of difference, how often,
 * and the first string. `make fuzz CASES=N` asks N strings.
 */

#include "../schema.h"
#include "schema_ref.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STEPS 200000u
#define LONGEST 24u

static uint64_t rng = 0x1408u;

static uint32_t next(void)
{
	rng ^= rng << 13;
	rng ^= rng >> 7;
	rng ^= rng << 17;
	return (uint32_t)rng;
}

/* A STRING LIKELY TO SIT NEAR A BOUNDARY: mostly the alphabet the four
 * grammars read, now and then any byte. */
static size_t draw(uint8_t *out)
{
	static const char alphabet[] = "0000123456789dhmsonf .:-aZ_x+";
	const size_t len = next() % LONGEST;
	size_t i;

	for (i = 0; i < len; i++)
		out[i] = next() % 16u ? (uint8_t)alphabet[next() % (sizeof(alphabet) - 1u)] : (uint8_t)next();
	return len;
}

/* A BOUND as a table writes one: small, a power of ten, or wide. */
static uint64_t bound(void)
{
	static const uint64_t usual[] = { 0, 1, 3, 9, 10, 16, 255, 3600, 36500, 65535, 86400, 315360000u };

	return next() % 2u ? usual[next() % (sizeof(usual) / sizeof(usual[0]))] : next() % 100000u;
}

static unsigned differ[4], first_kind = 4u;
static uint8_t first[LONGEST];
static size_t first_len;

static void note(unsigned kind, const uint8_t *v, size_t len)
{
	if (!differ[kind]++ && first_kind == 4u) {
		first_kind = kind;
		memcpy(first, v, len);
		first_len = len;
	}
}

int main(int argc, char **argv)
{
	static const char *const kinds[4] = { "count", "duration", "flag", "address" };
	const unsigned steps = argc > 1 ? (unsigned)strtoul(argv[1], NULL, 10) : STEPS;
	unsigned step, taken[4] = { 0 }, i;
	uint8_t v[LONGEST];

	for (step = 0; step < steps; step++) {
		const size_t len = draw(v);
		uint64_t lo = bound(), hi = bound(), a = 0, b = 0;
		char host_a[300], host_b[300];
		uint16_t pa = 0, pb = 0;
		size_t cap;
		int x, y;

		if (lo > hi) {
			uint64_t t = lo;

			lo = hi;
			hi = t;
		}
		x = fzn_schema_count(v, len, lo, hi, &a);
		y = fzn_schema_ref_count(v, len, lo, hi, &b);
		if (x != y || (x && a != b))
			note(0, v, len);
		taken[0] += x != 0;
		if (hi) {
			a = b = 0;
			x = fzn_schema_duration(v, len, lo, hi, &a);
			y = fzn_schema_ref_duration(v, len, lo, hi, &b);
			if (x != y || (x && a != b))
				note(1, v, len);
			taken[1] += x != 0;
		}
		x = fzn_schema_flag(v, len);
		y = fzn_schema_ref_flag(v, len);
		if (x != y)
			note(2, v, len);
		taken[2] += x >= 0;
		/* A HOST ROOM of none, a tight one, or a wide one. */
		cap = next() % 3u == 0u ? 0u : next() % 2u ? 1u + next() % 8u : sizeof(host_a);
		memset(host_a, 0, sizeof(host_a));
		memset(host_b, 0, sizeof(host_b));
		x = fzn_schema_address(v, len, cap ? host_a : NULL, cap, &pa);
		y = fzn_schema_ref_address(v, len, cap ? host_b : NULL, cap, &pb);
		if (x != y || (x && (pa != pb || strcmp(host_a, host_b) != 0)))
			note(3, v, len);
		taken[3] += x != 0;
	}
	printf("schema_agree_fuzz: %u strings; taken by both: %u counts, %u durations, %u flags, %u addresses; "
	       "%u difference(s)\n",
	       steps, taken[0], taken[1], taken[2], taken[3], differ[0] + differ[1] + differ[2] + differ[3]);
	for (i = 0; i < 4u; i++)
		if (differ[i])
			printf("  %s: %u\n", kinds[i], differ[i]);
	if (first_kind < 4u)
		printf("  first, a %s: \"%.*s\"\n", kinds[first_kind], (int)first_len, (const char *)first);
	return differ[0] + differ[1] + differ[2] + differ[3] ? 1 : 0;
}
