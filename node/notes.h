/* A node's notes, as verbs on its local socket. sec 431, phase 4 of the notes
 * move.
 *
 * `notes/` is the model -- store, view, author, purge, import -- and this is
 * the node holding one: its store over the node's own `persist/`, its author
 * signing as the node, and the verbs a client uses. fuzzypickles' widget spoke
 * its own control protocol to its daemon; sec 422 has fuzznet's widget speak
 * fuzznet's local grammar instead, and these are that grammar's notes words.
 *
 *     add note PARENT TITLE        a note under PARENT, titled; answers its id
 *     add folder PARENT TITLE      a folder
 *     set note ID title TEXT       rename
 *     set note ID text TEXT        replace the text, inline
 *     set note ID file PATH        replace the text from a file, sealed into
 *                                  a blob when it does not fit inline
 *     set note ID parent PARENT    move
 *     set note ID FLAG             pin, unpin, trash, untrash, archive,
 *                                  unarchive
 *     list note PARENT [FROM]      children, a page at a time
 *     get note ID                  one note's fields
 *     get note ID text [FROM]      its inline text, a page at a time
 *     get note ID file PATH        its whole text into a file, opened from its
 *                                  blob when it is one
 *     remove note trash            empty the trash
 *
 * PARENT is a note's id in hex, or `top` for the top level. A listing of
 * `top` is the top level as `notes/view.h` defines it: the root's children,
 * then every note the root cannot reach.
 *
 * ALL OF THEM NEED THE NODE'S OWN USER. Notes are a user's private data, and
 * the reads are as private as the writes; a path names a file the node opens
 * as itself.
 *
 * TEXT IN A REPLY IS ESCAPED, so a reply stays one line and an item one
 * field: a byte below 0x21, `%`, `,` and 0x7f become `%XX`. Other bytes pass,
 * UTF-8 included, so a title stays readable and greppable.
 *
 * WHO MAY WRITE. The admitted set is this node and the nodes it is paired to
 * -- the peers it pulls from, which are the peers notes will sync with. A
 * record from anyone else is refused at the store, a locally written one
 * included, so a node outside its own set cannot write a note either.
 *
 * EMPTYING THE TRASH asks the same paired nodes to consent (`notes/purge.h`).
 * The purge conversation between nodes is not built yet, so on a node with
 * paired nodes an emptied note waits, pending; on one with none it goes at
 * once. The reply says which.
 */

#ifndef FZN_NODE_NOTES_H
#define FZN_NODE_NOTES_H

#include <stddef.h>
#include <stdint.h>

#include "../chain/authz.h"
#include "../local/vocabulary.h"
#include "../notes/import.h"
#include "../notes/purge.h"
#include "../notes/sync.h"

/* The nodes a notes store admits besides this one: its paired nodes. */
#define FZN_NODE_NOTES_WRITERS 16u

/* Open a sealed text back -- the node's shelf, in practice. Nonzero on
 * success, with `*out_len` the text's length. */
typedef int (*fzn_node_notes_open_fn)(void *ctx, const fzn_note_blob_ref_t *ref, uint8_t *out,
                                      size_t cap, size_t *out_len);

typedef struct fzn_node_notes {
	fzn_notes_store_t store;
	fzn_notes_author_t author;
	fzn_notes_writer_t admitted[FZN_NODE_NOTES_WRITERS + 1u];
	size_t admitted_count;
	/* Long texts: both NULL and a text too long for inline is refused. */
	fzn_notes_seal_fn seal;
	fzn_node_notes_open_fn open;
	void *text_ctx;
	/* The wall clock, in milliseconds. */
	uint64_t (*now_ms)(void);
} fzn_node_notes_t;

/*
 * Set up over the node's store, signing as `self` with `sign`, ids from
 * `rng`, and admitting `self` and the `peer_count` keys in `peers`.
 * MALFORMED past FZN_NODE_NOTES_WRITERS peers: a short set would refuse a
 * paired node's notes with nothing saying why.
 */
fzn_notes_err_t fzn_node_notes_init(fzn_node_notes_t *notes, const fzn_persist_ops_t *store,
                                    const fzn_hash_ops_t *hash, const fzn_sign_ops_t *sign,
                                    const fzn_random_ops_t *rng,
                                    const uint8_t self[FZN_PUBKEY_LEN],
                                    const uint8_t (*peers)[FZN_PUBKEY_LEN], size_t peer_count,
                                    uint64_t (*now_ms)(void));

/* A peer's notes sync message (`notes/sync.h`), for `node/admin.h`'s remote
 * hook: answered from this node's store. 0 for what is not one. sec 432. */
size_t fzn_node_notes_remote(void *ctx, const uint8_t *request, size_t request_len,
                             uint8_t *reply, size_t reply_cap);

/* The verbs above, for `node/admin.h`'s hook. 0 when `request` is not one. */
size_t fzn_node_notes_local(void *ctx, fzn_origin_t origin, const fzn_request_t *request,
                            char *reply, size_t reply_cap);

#endif /* FZN_NODE_NOTES_H */
