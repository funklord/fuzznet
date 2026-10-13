/* A GROUP AS A FIXTURE, sec 626: filed as its log would leave it and named
 * here, with no acts behind it -- what a test of a grant to a group needs,
 * which is the membership and nothing about how it came to be. Static, for
 * the tests that include it. */
#ifndef FZN_TEST_GROUP_FIXTURE_H
#define FZN_TEST_GROUP_FIXTURE_H

#include <string.h>

#include "../groups.h"

/* A GROUP NAMED `name` with id all `id_byte`, and no members. */
static inline int group_make(const fzn_persist_ops_t *ops, const char *name, uint8_t id_byte,
                             fzn_group_t *g)
{
	memset(g, 0, sizeof(*g));
	memset(g->id, id_byte, sizeof(g->id));
	g->seq = 1u;
	g->epoch = 1u;
	g->backfill = 1u;
	return fzn_group_log_put(ops, g) == FZN_GROUP_LOG_OK
	       && fzn_node_group_rename(ops, g->id, name, strlen(name)) == FZN_CONTACT_OK;
}

static inline int group_join(const fzn_persist_ops_t *ops, fzn_group_t *g, const uint8_t *key)
{
	if (g->n_members == FZN_GROUP_MEMBERS_MAX)
		return 0;
	memcpy(g->members[g->n_members++], key, FZN_PUBKEY_LEN);
	return fzn_group_log_put(ops, g) == FZN_GROUP_LOG_OK;
}

static inline int group_leave(const fzn_persist_ops_t *ops, fzn_group_t *g, const uint8_t *key)
{
	size_t i;

	for (i = 0; i < g->n_members; i++)
		if (memcmp(g->members[i], key, FZN_PUBKEY_LEN) == 0) {
			memmove(g->members[i], g->members[i + 1u],
			        (g->n_members - i - 1u) * FZN_PUBKEY_LEN);
			g->n_members--;
			return fzn_group_log_put(ops, g) == FZN_GROUP_LOG_OK;
		}
	return 0;
}

/* THE GROUP GONE from this host, its name with it. */
static inline int group_drop(const fzn_persist_ops_t *ops, const fzn_group_t *g)
{
	return ops->remove && ops->remove(ops->ctx, FZN_PERSIST_GROUP, g->id)
	       && ops->remove(ops->ctx, FZN_PERSIST_GROUP_LABEL, g->id);
}

#endif /* FZN_TEST_GROUP_FIXTURE_H */
