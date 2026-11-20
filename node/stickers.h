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
 *   list sticker [FROM]     the saved packs: `ok TOTAL FROM ROOT,LENGTH,
 *                           NAME,HELD,SCOPE ...`, as many as fit one reply
 *                           from the FROMth (sec 684), NAME escaped
 *                           (`local/escape.h`), HELD 1 when the pack is
 *                           whole here, SCOPE `estate` or `host`.
 *   list sticker PACK [FROM]
 *                           a pack's stickers, paged as above: `ok TOTAL
 *                           FROM ID,TYPE,FLAGS,DESC,LIMIT,X,Y,W,H,FILL,INK,
 *                           TURN,MAIN_W,MAIN_H ...`, DESC escaped; the box
 *                           (sec 841, 864) in the main rendition's pixels,
 *                           FILL and INK 8 hex, all 0 for no box.
 *                           PACK a saved pack's ROOT, or the 144 hex of any
 *                           held pack's reference.
 *   list sticker answer CONTEXT [TEXT]
 *                           as `match`, answering a line: CONTEXT its
 *                           words, escaped, one word, counting half what
 *                           TEXT does (sec 1321).
 *   list sticker recent     the stickers this user sent lately, newest
 *                           first, each once (sec 1317): `ok COUNT 0
 *                           ROOT,ID,DESC ...`, at most 20, DESC escaped --
 *                           as sent, whether or not its pack is kept here.
 *   get sticker PACK        `ok ID`, the pack's own id from its art in
 *                           decimal (sec 859), 0 for a pack before it.
 *   get sticker PACK ID     `ok fzn:sticker/...`, the reference a message
 *                           carries.
 *   get sticker PACK ID ROLE PATH
 *   get sticker PACK ID sound PATH   its sound's bytes into PATH, answered
 *                                    `ok BYTES`; refused for a sticker with
 *                                    none (sec 1301)
 *                           that sticker's rendition of ROLE (thumb,
 *                           inline, main, popup), or the nearest it has,
 *                           written to the new file at the absolute PATH:
 *                           `ok FORMAT WIDTH HEIGHT`.
 *   add sticker REF         a pack held here, by the 144 hex of its
 *                           reference -- one a message named, fetched by the
 *                           sweep -- saved, its name read from the pack:
 *                           answered as `put sticker` is. Receiving never
 *                           saves; this is the user's keep (sec 683).
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
#include "../session/commitment.h"
#include "../search/search.h"

struct fzn_sticker_ref; /* sticker/pack.h */
typedef struct fzn_node_stickers {
	fzn_node_files_t *files;
	const fzn_node_settings_t *settings;	/* `estate` set */
	const uint8_t *host;	/* this host's key, for its own cell */
	/* BLAKE2b, for the ids a spec leaves out (`fzn_sticker_derive_ids`,
	 * sec 702); NULL refuses such a spec. */
	const fzn_hash_ops_t *hash;
	/* THE STICKERS THIS USER SENT LATELY, newest first, at most MAX into
	 * OUT: the count (sec 1317). Kept by whoever keeps the lines --
	 * fuzznetd's `fzn_node_messages_stickers_sent` -- so this module
	 * links none of them; NULL refuses `list sticker recent`. */
	size_t (*recent)(void *ctx, struct fzn_sticker_ref *out, size_t max);
	void *recent_ctx;
} fzn_node_stickers_t;

/* The most stickers `list sticker recent` says. */
#define FZN_NODE_STICKERS_RECENT_MAX 20u

/* The verbs above; 0 for a request that is not one. */
size_t fzn_node_stickers_local(void *ctx, fzn_origin_t origin, const fzn_request_t *request,
                               char *reply, size_t cap);

/* THE SAVED PACK `root` names: 1 with its reference, or 0. */
int fzn_node_stickers_saved(const fzn_node_stickers_t *st, const uint8_t root[FZN_BLOB_HASH_LEN],
                            fzn_node_file_ref_t *ref);

/* EVERY PACK THIS USER KEEPS, as `list sticker` lists them, sec 1172: ROOT
 * and LENGTH the pack file's, NAME raw, HELD whether the file is whole
 * here, ESTATE whether it is saved for every host or this one alone. ROOT
 * is good only during the call. 1 once each was handed over, 0 when the
 * settings did not list. */
typedef struct fzn_node_sticker_pack {
	const uint8_t *root;
	uint64_t length;
	char name[256];	/* FZN_STICKER_NAME_MAX and its NUL */
	size_t name_len;
	int held;
	int estate;
} fzn_node_sticker_pack_t;
int fzn_node_stickers_each(const fzn_node_stickers_t *st,
                           void (*each)(void *ctx, const fzn_node_sticker_pack_t *pack), void *ctx);

/* THE STICKERS THAT FIT THE LINE BEING TYPED, sec 1272: of every kept
 * pack held whole here, scored by fzn_sticker_match, the best first and
 * at most 20, each handed over -- its pack's root, its id, its score and
 * its description, good for the call. Each pack's words are read once and
 * held by its root, so a search at every key costs no file read; a pack
 * no longer kept is let go. 1, or 0 when the packs would not list. */
typedef struct fzn_node_sticker_match {
	const uint8_t *root;
	uint64_t id;
	unsigned score;
	const char *description;
	size_t description_len;
} fzn_node_sticker_match_t;
int fzn_node_stickers_match(const fzn_node_stickers_t *st, const char *typed, size_t typed_len,
                            void (*each)(void *ctx, const fzn_node_sticker_match_t *hit), void *ctx);
/* THE SAME, ANSWERING A LINE (sec 1321): CONTEXT the words of the line
 * being replied to, which count half what TYPED does, so stickers that fit
 * the line answered are offered before anything is typed and a typed word
 * still leads. Either may be empty. */
int fzn_node_stickers_answer(const fzn_node_stickers_t *st, const char *context, size_t context_len,
                             const char *typed, size_t typed_len,
                             void (*each)(void *ctx, const fzn_node_sticker_match_t *hit), void *ctx);

/* ONE SAVED PACK'S STICKERS, as `list sticker PACK` lists them, sec 1248:
 * each entry handed over with its main rendition's size, the entry good
 * only during the call. 1 once each was, 0 for no such pack saved, -1 for
 * one not here whole or no pack. */
struct fzn_sticker_entry;
int fzn_node_stickers_items(const fzn_node_stickers_t *st, const uint8_t root[FZN_BLOB_HASH_LEN],
                            void (*each)(void *ctx, const struct fzn_sticker_entry *e, unsigned main_w,
                                         unsigned main_h),
                            void *ctx);

/* THE KEPT STICKERS AS A STORE OF THE ONE SEARCH, sec 1287: `ctx` the
 * stickers, each hit a sticker keyed by its pack's root and its id (big
 * endian), scored by `fzn_node_stickers_match`. */
int fzn_node_stickers_search(void *ctx, const fzn_search_query_t *q, const uint8_t *asker, fzn_search_emit_t emit,
                             void *emit_ctx);

#endif /* FZN_NODE_STICKERS_H */
