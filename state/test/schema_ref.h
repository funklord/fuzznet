/* THE SETTINGS PARSERS state/schema.c WROTE BY HAND, project.md sec 1408:
 * a count, a duration, a flag and an address, kept whole as the oracle the
 * parsers on situ's generated code are held to (`schema_agree_fuzz`).
 * Header-only, so nothing links it and no suite counts it as a test of its
 * own. Not to be called from anything but that fuzzer.
 */
#ifndef FZN_STATE_TEST_SCHEMA_REF_H
#define FZN_STATE_TEST_SCHEMA_REF_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static inline int fzn_schema_ref_flag(const uint8_t *value, size_t len)
{
	if (!value)
		return -1;
	if ((len == 2u && memcmp(value, "on", 2u) == 0) || (len == 1u && value[0] == '1'))
		return 1;
	if ((len == 3u && memcmp(value, "off", 3u) == 0) || (len == 1u && value[0] == '0'))
		return 0;
	return -1;
}

static inline int fzn_schema_ref_count(const uint8_t *value, size_t len, uint64_t min, uint64_t max, uint64_t *out)
{
	uint64_t n = 0, m;
	size_t i, digits = 0;

	for (m = max; m; m /= 10u)
		digits++;
	if (!value || len == 0u || len > (digits ? digits : 1u))
		return 0;
	for (i = 0; i < len; i++) {
		if (value[i] < '0' || value[i] > '9')
			return 0;
		n = (n * 10u) + (uint64_t)(value[i] - '0');
	}
	if (n < min || n > max)
		return 0;
	if (out)
		*out = n;
	return 1;
}

static inline int fzn_schema_ref_duration(const uint8_t *value, size_t len, uint64_t min, uint64_t max,
                        uint64_t *seconds)
{
	uint64_t unit, n = 0;

	if (!value || len < 2u)
		return 0;
	switch (value[len - 1u]) {
	case 'd':
		unit = 86400u;
		break;
	case 'h':
		unit = 3600u;
		break;
	case 'm':
		unit = 60u;
		break;
	case 's':
		unit = 1u;
		break;
	default:
		return 0;
	}
	/* AT MOST `max` IN WHICHEVER UNIT, so the product cannot overflow. */
	if (!fzn_schema_ref_count(value, len - 1u, 1u, max / unit, &n) || n * unit < min)
		return 0;
	if (seconds)
		*seconds = n * unit;
	return 1;
}

static inline int fzn_schema_ref_address(const uint8_t *value, size_t len, char *host, size_t host_cap,
                       uint16_t *port)
{
	size_t space, i;
	uint64_t p = 0;

	if (!value)
		return 0;
	for (space = 0; space < len && value[space] != ' '; space++)
		;
	if (space == 0u || space == len || (host_cap && space >= host_cap) || (host && !host_cap))
		return 0;
	for (i = 0; i < space; i++) {
		uint8_t c = value[i];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		      || c == '.' || c == '-' || c == ':'))
			return 0;
	}
	if (!fzn_schema_ref_count(value + space + 1u, len - space - 1u, 1u, 65535u, &p))
		return 0;
	if (host) {
		memcpy(host, value, space);
		host[space] = '\0';
	}
	if (port)
		*port = (uint16_t)p;
	return 1;
}

#endif
