/* JSON walked through situ's views: wire/json_walk.h, sec 1469. */
#include "json_walk.h"
#include "generated/json.h"

#include <string.h>

int fzn_json_walk_frame(const char *text, size_t len, struct situ_msg *msg, struct situ_view *out)
{
	uint32_t need = 0;

	if (!text || !msg || !out || len > UINT32_MAX
	    || fzn_json_value_required((const uint8_t *)text, (uint32_t)len, &need) != SITU_OK || need > len)
		return 0;
	situ_msg_init(msg, (uint8_t *)(uintptr_t)text, need);
	return fzn_json_value_view(msg, 0, need, out) == SITU_OK && fzn_json_value_validate(*out) == SITU_OK;
}

int fzn_json_walk_members(const struct situ_view *value_at,
                          int (*each)(const char *key, size_t key_len, const struct situ_view *held, void *ctx),
                          void *ctx)
{
	situ_view_t object, members, member, held;
	situ_cursor_t cursor = { 0u, 0u };

	if (!value_at || !each || fzn_json_value_body_as_object_view(*value_at, &object) != SITU_OK)
		return 0;
	if (fzn_json_object_next_get(object) == '}')
		return 1;
	if (fzn_json_object_body_as_members_view(object, &members) != SITU_OK)
		return 0;
	/* THE RUN ONCE, by situ's cursor (situ d7e3ce5b): each member after
	 * the last, not counted again from the first. */
	while (fzn_json_members_entries_next(members, &cursor, &member) == SITU_OK)
		if (fzn_json_member_held_view(member, &held) != SITU_OK
		    || !each((const char *)fzn_json_member_key_ptr(member), fzn_json_member_key_len(member), &held, ctx))
			return 0;
	return 1;
}

int fzn_json_walk_elements(const struct situ_view *value_at, int (*each)(const struct situ_view *held, void *ctx),
                           void *ctx)
{
	situ_view_t array, elements, element, held;
	situ_cursor_t cursor = { 0u, 0u };

	if (!value_at || !each || fzn_json_value_body_as_array_view(*value_at, &array) != SITU_OK)
		return 0;
	if (fzn_json_array_next_get(array) == ']')
		return 1;
	if (fzn_json_array_body_as_elements_view(array, &elements) != SITU_OK)
		return 0;
	while (fzn_json_elements_entries_next(elements, &cursor, &element) == SITU_OK)
		if (fzn_json_element_held_view(element, &held) != SITU_OK || !each(&held, ctx))
			return 0;
	return 1;
}

int fzn_json_walk_string(const struct situ_view *value, const char **chars, size_t *len)
{
	situ_view_t t;

	if (!value || !chars || !len || fzn_json_value_body_as_string_view(*value, &t) != SITU_OK)
		return 0;
	*chars = (const char *)fzn_json_text_chars_ptr(t);
	*len = fzn_json_text_chars_len(t);
	return 1;
}

int fzn_json_walk_number(const struct situ_view *value, const char **text, size_t *len)
{
	situ_view_t v;
	const char *at;
	uint32_t n;

	if (!value || !text || !len || fzn_json_value_body_as_number_view(*value, &v) != SITU_OK || !(n = fzn_json_number_extent(v))
	    || n > v.limit)
		return 0;
	at = (const char *)situ_base(v);
	while (n && (at[n - 1u] == ' ' || at[n - 1u] == '\t' || at[n - 1u] == '\r' || at[n - 1u] == '\n'))
		n--;
	*text = at;
	*len = n;
	return n != 0;
}

int fzn_json_walk_key_is(const char *key, size_t len, const char *want)
{
	return key && want && len == strlen(want) && !memcmp(key, want, len);
}
