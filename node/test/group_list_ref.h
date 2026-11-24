/* THE GROUP LIST'S HAND CHECK, `member_check` as node/schema.c had it, kept
 * whole as the oracle for the one read through situ's code (project.md sec
 * 1441), with `fzn_scope_group_id`'s rule beside it. node/test/
 * permit_agree_fuzz holds the two to the same verdict and the same words. */

#ifndef FZN_NODE_TEST_GROUP_LIST_REF_H
#define FZN_NODE_TEST_GROUP_LIST_REF_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define REF_GROUP_ID_LEN 32u

static inline int ref_group_char(uint8_t c)
{
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
}

static inline int ref_group_id(const uint8_t *name, size_t len, uint8_t id[REF_GROUP_ID_LEN])
{
	size_t i;

	if (!name || !id || len == 0u || len > REF_GROUP_ID_LEN)
		return 0;
	for (i = 0; i < len; i++)
		if (!ref_group_char(name[i]))
			return 0;
	memset(id, 0, REF_GROUP_ID_LEN);
	memcpy(id, name, len);
	return 1;
}

/* `group/member`, sec 868: group names apart by single spaces, each one
 * `fzn_scope_group_id` takes, none twice. */
static inline const char *ref_group_list_check(const uint8_t *value, size_t len)
{
	static const char WHY[] = "group names of a-z, 0-9 and ._-, 1 to 32 bytes, apart by "
	                          "single spaces, none twice";
	uint8_t id[REF_GROUP_ID_LEN], seen[16][REF_GROUP_ID_LEN];
	size_t at = 0, n_seen = 0, i;

	while (at < len) {
		size_t start = at;

		while (at < len && value[at] != ' ')
			at++;
		if (!ref_group_id(value + start, at - start, id) || n_seen == 16u)
			return WHY;
		for (i = 0; i < n_seen; i++)
			if (memcmp(seen[i], id, sizeof(id)) == 0)
				return WHY;
		memcpy(seen[n_seen++], id, sizeof(id));
		if (at < len && ++at == len)
			return WHY;	/* a trailing space */
	}
	return n_seen ? NULL : WHY;
}

#endif
