#include "schema.h"

#include "../wire/generated/settings_registry.h"

#include <stdint.h>
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

/* THE FOUR CELL TYPES ON SITU'S GENERATED PARSERS, sec 1408: the grammar
 * of a count, a duration, a flag and an address is
 * node/settings_registry.situ's, and these keep only what the hand
 * parsers decided beyond it -- the caller's bounds, and a count no longer
 * than its maximum's digits, so "0007" stays refused where 255 is the
 * most. state/test/schema_ref.h keeps the hand parsers, and
 * schema_agree_fuzz holds the two to one verdict. */

/* `value` as a message for a generated parser, or 0 when it cannot be. */
static int wrap(situ_msg_t *m, const uint8_t *value, size_t len)
{
	if (!value || len > UINT32_MAX)
		return 0;
	situ_msg_init(m, (uint8_t *)(uintptr_t)value, (uint32_t)len);
	return 1;
}

static size_t digits_of(uint64_t max)
{
	size_t digits = 1;

	while (max /= 10u)
		digits++;
	return digits;
}

int fzn_schema_flag(const uint8_t *value, size_t len)
{
	situ_msg_t m;
	situ_view_t v;

	if (!wrap(&m, value, len) || fzn_settings_registry_flag_view(&m, 0u, (uint32_t)len, &v) != SITU_OK
	    || fzn_settings_registry_flag_validate(v) != SITU_OK)
		return -1;
	return fzn_settings_registry_flag_value_get(v) ? 1 : 0;
}

int fzn_schema_count(const uint8_t *value, size_t len, uint64_t min, uint64_t max, uint64_t *out)
{
	situ_msg_t m;
	situ_view_t v;
	uint64_t n = 0;

	if (len > digits_of(max) || !wrap(&m, value, len)
	    || fzn_settings_registry_count_view(&m, 0u, (uint32_t)len, &v) != SITU_OK
	    || fzn_settings_registry_count_validate(v) != SITU_OK
	    || fzn_settings_registry_count_value_get(v, &n) != SITU_OK || n < min || n > max)
		return 0;
	if (out)
		*out = n;
	return 1;
}

int fzn_schema_duration(const uint8_t *value, size_t len, uint64_t min, uint64_t max,
                        uint64_t *seconds)
{
	situ_msg_t m;
	situ_view_t v;
	uint32_t n = 0;
	uint64_t unit;

	if (len < 2u || !wrap(&m, value, len)
	    || fzn_settings_registry_duration_view(&m, 0u, (uint32_t)len, &v) != SITU_OK
	    || fzn_settings_registry_duration_validate(v) != SITU_OK
	    || fzn_settings_registry_duration_count_get(v, &n) != SITU_OK || n == 0u)
		return 0;
	unit = fzn_settings_registry_duration_value_get(v) / n;
	/* AT MOST `max` IN WHICHEVER UNIT, so the product cannot overflow. */
	if (len - 1u > digits_of(max / unit) || n > max / unit || n * unit < min)
		return 0;
	if (seconds)
		*seconds = n * unit;
	return 1;
}

int fzn_schema_address(const uint8_t *value, size_t len, char *host, size_t host_cap,
                       uint16_t *port)
{
	situ_msg_t m;
	situ_view_t v;
	uint16_t p = 0;
	size_t space;

	if ((host && !host_cap) || !wrap(&m, value, len)
	    || fzn_settings_registry_address_view(&m, 0u, (uint32_t)len, &v) != SITU_OK
	    || fzn_settings_registry_address_validate(v) != SITU_OK
	    || fzn_settings_registry_address_port_get(v, &p) != SITU_OK)
		return 0;
	space = 1u + fzn_settings_registry_address_host_len(v);
	/* THE PORT IN AT MOST FIVE DIGITS, as the hand parser counted them. */
	if (len - space - 1u > 5u || (host_cap && space >= host_cap))
		return 0;
	if (host) {
		memcpy(host, value, space);
		host[space] = '\0';
	}
	if (port)
		*port = p;
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

/* A FLAG OR A COUNT AS A NUMBER to order by: 1 with `*n`, or 0. */
static int ordinal(const fzn_schema_entry_t *e, const uint8_t *v, size_t len, uint64_t *n)
{
	size_t i;

	if (fzn_schema_check(e, v, len))
		return 0;
	if (e->type == FZN_SCHEMA_FLAG) {
		*n = (len == 2u && memcmp(v, "on", 2u) == 0) || (len == 1u && v[0] == '1');
		return 1;
	}
	if (e->type != FZN_SCHEMA_COUNT || !len)
		return 0;
	for (*n = 0, i = 0; i < len; i++)
		*n = *n * 10u + (uint64_t)(v[i] - '0');
	return 1;
}

int fzn_schema_safer(const fzn_schema_entry_t *e, const uint8_t *a, size_t a_len,
                     const uint8_t *b, size_t b_len)
{
	uint64_t x, y;

	if (!e || !a || !b || !(e->flags & (FZN_SCHEMA_SAFE_LOWER | FZN_SCHEMA_SAFE_HIGHER))
	    || !ordinal(e, a, a_len, &x) || !ordinal(e, b, b_len, &y))
		return 0;
	return (e->flags & FZN_SCHEMA_SAFE_LOWER) ? y < x : y > x;
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
