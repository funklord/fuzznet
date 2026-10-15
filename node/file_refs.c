/* The references of this estate's files: project.md sec 634, and the
 * header. */
#include "file_refs.h"

#include <string.h>

_Static_assert(FZN_BLOB_HASH_LEN == 32u, "a root is filed as a subject");

int fzn_node_file_ref_get(const fzn_persist_ops_t *store, const uint8_t root[FZN_BLOB_HASH_LEN],
                          uint8_t ref[FZN_NODE_FILE_REF_LEN])
{
	size_t n = 0;

	/* FILED UNDER ITS ROOT, which is a subject's length. */
	if (!store || !store->load || !root || !ref)
		return 0;
	return store->load(store->ctx, FZN_PERSIST_FILE_REF, root, ref, FZN_NODE_FILE_REF_LEN, &n)
	       && n == FZN_NODE_FILE_REF_LEN && memcmp(ref, root, FZN_BLOB_HASH_LEN) == 0;
}

int fzn_node_file_ref_keep(const fzn_persist_ops_t *store, const uint8_t ref[FZN_NODE_FILE_REF_LEN])
{
	uint8_t held[FZN_NODE_FILE_REF_LEN];

	if (!store || !store->save || !ref)
		return 0;
	/* THE FIRST STANDS: a second key under one root is somebody's error or
	 * somebody's attempt, and either way not this file's. */
	if (fzn_node_file_ref_get(store, ref, held))
		return memcmp(held, ref, FZN_NODE_FILE_REF_LEN) == 0;
	return store->save(store->ctx, FZN_PERSIST_FILE_REF, ref, ref, FZN_NODE_FILE_REF_LEN);
}
