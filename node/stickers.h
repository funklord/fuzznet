/*
 * A USER'S STICKERS ON THE NODE, sec 681: sec 679's step b. A pack
 * (`sticker/pack.h`) is a file of the node's (`node/files.h`), sealed and
 * fetched as any file is; a pack SAVED is the user's, kept as a setting so
 * every host of theirs has the collection:
 *
 *   estate cell `sticker/` + 56 hex of the pack's root
 *       `REF NAME`: the file's reference, 144 hex (root, key, length), and
 *       the pack's name. A host that may not set the estate's settings
 *       keeps it in its own host cell, and says so (`ok host`), as sec
 *       660's stream grants do.
 *
 * SAVING IS NOT HOLDING, and forgetting is not deleting: fuzzypickles kept
 * the two apart (their sec 15) and so does this. A pack a message names is
 * fetched to be shown whether saved or not (step c); forgetting one leaves
 * its bytes for every message that names it. Nothing here removes a file.
 *
 * THE VERBS, this node's own user's:
 *
 *   put sticker SPEC        a pack built from the spec at the absolute
 *                           path SPEC and the files it names beside it,
 *                           put, and saved. `ok ROOT`.
 *   list sticker            the saved packs: `ok N ROOT,LENGTH,NAME,HELD,
 *                           SCOPE ...`, NAME escaped (`local/escape.h`),
 *                           HELD 1 when the pack is whole here, SCOPE
 *                           `estate` or `host`.
 *   list sticker PACK       a pack's stickers: `ok N ID,TYPE,FLAGS,DESC
 *                           ...`, DESC escaped. PACK a saved pack's ROOT,
 *                           or the 144 hex of any held pack's reference.
 *   get sticker PACK ID     `ok fzn:sticker/...`, the reference a message
 *                           carries.
 *   get sticker PACK ID ROLE PATH
 *                           that sticker's rendition of ROLE (thumb,
 *                           inline, main, popup), or the nearest it has,
 *                           written to the new file at the absolute PATH:
 *                           `ok FORMAT WIDTH HEIGHT`.
 *   remove sticker ROOT     the pack forgotten; its bytes stay.
 */
#ifndef FZN_NODE_STICKERS_H
#define FZN_NODE_STICKERS_H

#include <stddef.h>
#include <stdint.h>

#include "files.h"
#include "settings.h"
#include "../local/vocabulary.h"
#include "../chain/authz.h"

typedef struct fzn_node_stickers {
	fzn_node_files_t *files;
	const fzn_node_settings_t *settings;	/* `estate` set */
	const uint8_t *host;	/* this host's key, for its own cell */
} fzn_node_stickers_t;

/* The verbs above; 0 for a request that is not one. */
size_t fzn_node_stickers_local(void *ctx, fzn_origin_t origin, const fzn_request_t *request,
                               char *reply, size_t cap);

/* THE SAVED PACK `root` names: 1 with its reference, or 0. */
int fzn_node_stickers_saved(const fzn_node_stickers_t *st, const uint8_t root[FZN_BLOB_HASH_LEN],
                            fzn_node_file_ref_t *ref);

#endif /* FZN_NODE_STICKERS_H */
