#include "schema.h"

#include <string.h>

static size_t key_len_of(const char *key)
{
	return key ? strlen(key) : 0u;
}

const fzn_schema_entry_t *fzn_schema_find(const fzn_schema_entry_t *table, size_t n,
                                          const uint8_t *key, size_t len)
{
	size_t i, j;

	if (!table || !key || !len)
		return NULL;
	for (i = 0; i < n; i++) {
		size_t k = key_len_of(table[i].key);

		if (!k)
			continue;
		if (table[i].key[k - 1u] != '/') {
			if (k == len && memcmp(table[i].key, key, len) == 0)
				return &table[i];
			continue;
		}
		/* A FAMILY: the key, then one word. */
		if (len <= k || memcmp(table[i].key, key, k) != 0)
			continue;
		for (j = k; j < len; j++)
			if (!((key[j] >= 'a' && key[j] <= 'z') || (key[j] >= '0' && key[j] <= '9')))
				break;
		if (j == len)
			return &table[i];
	}
	return NULL;
}

int fzn_schema_overlap(const char *a, const char *b)
{
	size_t la = key_len_of(a), lb = key_len_of(b);

	if (!la || !lb)
		return 0;
	if (la == lb)
		return memcmp(a, b, la) == 0;
	/* THE SHORTER A FAMILY the longer is inside. */
	if (la < lb)
		return a[la - 1u] == '/' && memcmp(a, b, la) == 0;
	return b[lb - 1u] == '/' && memcmp(a, b, lb) == 0;
}

int fzn_schema_flag(const uint8_t *value, size_t len)
{
	if (!value)
		return -1;
	if ((len == 2u && memcmp(value, "on", 2u) == 0) || (len == 1u && value[0] == '1'))
		return 1;
	if ((len == 3u && memcmp(value, "off", 3u) == 0) || (len == 1u && value[0] == '0'))
		return 0;
	return -1;
}

int fzn_schema_count(const uint8_t *value, size_t len, uint64_t min, uint64_t max, uint64_t *out)
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

int fzn_schema_duration(const uint8_t *value, size_t len, uint64_t min, uint64_t max,
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
	if (!fzn_schema_count(value, len - 1u, 1u, max / unit, &n) || n * unit < min)
		return 0;
	if (seconds)
		*seconds = n * unit;
	return 1;
}

int fzn_schema_address(const uint8_t *value, size_t len, char *host, size_t host_cap,
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
	if (!fzn_schema_count(value + space + 1u, len - space - 1u, 1u, 65535u, &p))
		return 0;
	if (host) {
		memcpy(host, value, space);
		host[space] = '\0';
	}
	if (port)
		*port = (uint16_t)p;
	return 1;
}

const char *fzn_schema_type_name(fzn_schema_type_t type)
{
	switch (type) {
	case FZN_SCHEMA_FLAG:
		return "flag";
	case FZN_SCHEMA_COUNT:
		return "count";
	case FZN_SCHEMA_DURATION:
		return "duration";
	case FZN_SCHEMA_ADDRESS:
		return "address";
	case FZN_SCHEMA_TEXT:
		return "text";
	}
	return "text";
}

const char *fzn_schema_check(const fzn_schema_entry_t *e, const uint8_t *value, size_t len)
{
	size_t i;

	if (!e)
		return NULL;
	if (!value && len)
		return "no value";
	switch (e->type) {
	case FZN_SCHEMA_FLAG:
		return fzn_schema_flag(value, len) < 0 ? "a flag is on or off" : NULL;
	case FZN_SCHEMA_COUNT:
		return fzn_schema_count(value, len, e->min, e->max, NULL) ? NULL
		                                                         : "not a count in its range";
	case FZN_SCHEMA_DURATION:
		return fzn_schema_duration(value, len, e->min, e->max, NULL)
		               ? NULL
		               : "not a duration in its range, a count and one of d h m s";
	case FZN_SCHEMA_ADDRESS:
		return fzn_schema_address(value, len, NULL, e->max ? (size_t)e->max + 1u : 0u, NULL)
		               ? NULL
		               : "not HOST PORT";
	case FZN_SCHEMA_TEXT:
		if (len < e->min || (e->max && len > e->max))
			return "text of the wrong length";
		for (i = 0; i < len; i++)
			if (value[i] < 0x20u || value[i] > 0x7eu)
				return "text that does not print";
		return e->check ? e->check(value, len) : NULL;
	}
	return "an entry of no type";
}
