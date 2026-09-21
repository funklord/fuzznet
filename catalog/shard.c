/* See shard.h. */

#include "shard.h"

#include <string.h>

fzn_catalog_err_t fzn_catalog_shard_plan(const fzn_catalog_shard_key_t *keys,
                                         size_t count, size_t min_entries,
                                         fzn_catalog_shard_t *out, size_t out_cap,
                                         size_t *out_count)
{
	size_t shards, i, at;

	if (!out_count)
		return FZN_CATALOG_ERR_MALFORMED;
	*out_count = 0;
	if ((count != 0 && !keys) || (!out && out_cap > 0))
		return FZN_CATALOG_ERR_MALFORMED;
	if (min_entries == 0)
		return FZN_CATALOG_ERR_MALFORMED;

	/* SORTED, CHECKED RATHER THAN ASSUMED. A shard is a key RANGE, so
	 * cutting an unsorted list produces overlapping ranges and an index
	 * that cannot say which blob holds a key. One pass over data already in
	 * hand, against a failure that is otherwise silent. */
	for (i = 1; i < count; i++)
		if (memcmp(keys[i - 1u].b, keys[i].b, FZN_CATALOG_SHARD_KEY_LEN) > 0)
			return FZN_CATALOG_ERR_MALFORMED;

	if (count == 0)
		return FZN_CATALOG_OK;

	/* A REGISTER SMALLER THAN ONE SHARD IS ONE SHARD. The whole register is
	 * then the anonymity set, which is the best available. */
	shards = count / min_entries;
	if (shards == 0)
		shards = 1;

	if (shards > out_cap)
		return FZN_CATALOG_ERR_RANGE;

	at = 0;
	for (i = 0; i < shards; i++) {
		out[i].first = keys[at];
		/* THE REMAINDER GOES INTO THE LAST SHARD. Giving the tail its own
		 * shard would make the last range smaller than every other, so
		 * the end of the key space would have a weaker anonymity set
		 * than the rest and a fetch landing there would reveal more. */
		if (i + 1u == shards)
			out[i].entries = count - at;
		else
			out[i].entries = min_entries;
		at += out[i].entries;
	}

	*out_count = shards;
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_shard_of(const fzn_catalog_shard_t *plan, size_t count,
                                       const fzn_catalog_shard_key_t *key,
                                       size_t *index_out)
{
	size_t i, found = 0;

	if (!index_out)
		return FZN_CATALOG_ERR_MALFORMED;
	*index_out = 0;
	if (!plan || !key)
		return FZN_CATALOG_ERR_MALFORMED;
	if (count == 0)
		return FZN_CATALOG_ERR_ABSENT;

	/* THE RANGES COVER THE WHOLE KEY SPACE, so a key below the first
	 * shard's start belongs to the first shard rather than to nothing: the
	 * plan's first key is the lowest key the register HAD, not the lowest
	 * that could exist. */
	for (i = 0; i < count; i++)
		if (memcmp(key->b, plan[i].first.b, FZN_CATALOG_SHARD_KEY_LEN) >= 0)
			found = i;

	*index_out = found;
	return FZN_CATALOG_OK;
}
