/*
 * THE REFERENCES OF THIS ESTATE'S FILES, project.md sec 634: a file's root,
 * content key and length (`node/files.h`'s 72 bytes), kept by every host of
 * the estate holding or listing the file -- the holder's decision of
 * 2026-10-15 that all estate members should normally be able to open the
 * files they have; storage blind to a file's content is a later feature.
 *
 * KEPT WHEN SEEN: a `put file` answers one, and a verb naming one -- a
 * fetch, an export -- hands one over. CARRIED BETWEEN THE ESTATE'S HOSTS on
 * request, as message keys are (sec 527), never in the journal: a host
 * lacking the reference of a file it holds or its catalogue lists asks its
 * siblings for it.
 *
 * Persist slot FZN_PERSIST_FILE_REF, keyed by root, CORE: a reference lost
 * is a file this host can no longer open.
 */
#ifndef FZN_NODE_FILE_REFS_H
#define FZN_NODE_FILE_REFS_H

#include <stddef.h>
#include <stdint.h>

#include "files.h"

/* KEEP `ref`, a file's reference, under its root: one held already is
 * replaced only by the same bytes -- a different key under one root is
 * refused, the first standing. 1 when kept or already held. */
int fzn_node_file_ref_keep(const fzn_persist_ops_t *store, const uint8_t ref[FZN_NODE_FILE_REF_LEN]);

/* The reference of `root`, held here: 1 when it is. */
int fzn_node_file_ref_get(const fzn_persist_ops_t *store, const uint8_t root[FZN_BLOB_HASH_LEN],
                          uint8_t ref[FZN_NODE_FILE_REF_LEN]);

#endif /* FZN_NODE_FILE_REFS_H */
