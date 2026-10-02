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
 *     list note PARENT [FROM]      children, a page at a time; a note
 *                                  pending purge is left out
 *     get note ID                  one note's fields
 *     get note ID text [FROM]      its inline text, a page at a time
 *     get note ID file PATH        its whole text into a file, opened from its
 *                                  blob when it is one
 *     remove note trash            empty the trash
 *     add share SUBTREE NAME       share SUBTREE with the contact NAME (sec 436)
 *     remove share SUBTREE NAME    stop
 *     list share [FROM]            what is shared, with whom
 *     list shared NAME PARENT [FROM]
 *                                  the tree the contact NAME shared with this
 *                                  node (sec 437); `top` is the roots of what
 *                                  was shared, the notes whose parent this
 *                                  node does not hold
 *     get shared NAME ID ...       as `get note`, in that tree
 *
 *     remove text unused           remove every long text no note names,
 *                                  this node's own or a sharer's (sec 443);
 *                                  answers REMOVED KEPT
 *     add list PARENT TITLE        a checklist (sec 442)
 *     get note ID items [FROM]     its items, `FLAGS,TEXT`, a page at a time
 *     add item ID TEXT             an item at the end
 *     set note ID item N check     tick item N (from 0), or uncheck it
 *     set note ID item N text TEXT reword it
 *     remove item ID N             remove it
 *     add import PARENT PATH       a KNotes .ics, a Keep .json or a Takeout
 *                                  directory into PARENT (sec 440); answers
 *                                  IMPORTED ALREADY UNDATED REFUSED and the
 *                                  refused notes' titles
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
 * WHO MAY WRITE. The admitted set is this node and the nodes paired to it:
 * those it pulls from and those it serves. A record from anyone else is
 * refused at the store, a locally written one included, so a node outside
 * its own set cannot write a note either.
 *
 * EMPTYING THE TRASH asks for consent from every node that holds copies: the
 * nodes this one pulls from, and its partners, the nodes that have pulled
 * from it (`notes/sync.h`) within FZN_NODE_NOTES_PARTNER_AGE_MS. The conversation is driven by whichever side
 * pulls, so a purge completes as each of them next pulls or is pulled from.
 * On a node with none it goes at once. The reply says how many wait.
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

/* A partner that has not pulled for this long is not pinned by a new purge:
 * thirty days. It has not been holding the user's latest notes, and a purge
 * pinning a node that is gone would wait for ever. Whether it still holds
 * an old copy of what is emptied is the cost accepted. sec 434. */
#define FZN_NODE_NOTES_PARTNER_AGE_MS (30ull * 24u * 3600u * 1000u)

/* The nodes a notes store admits besides this one: the nodes paired to it
 * and the nodes it pulls from -- `node/peer_persist.h`'s 64 and room for the
 * pulls besides. */
#define FZN_NODE_NOTES_WRITERS 80u

/* What `add import` reads at once: a Keep note's file, 1 MiB, and a KNotes
 * calendar, 16 MiB. A file past either is refused and named, not cut. */
#define FZN_NODE_NOTES_IMPORT_FILE_MAX (1024u * 1024u)
#define FZN_NODE_NOTES_IMPORT_ICS_MAX (16u * 1024u * 1024u)

/* Remove the texts `keep` does not keep -- the node's shelf, in practice
 * (`fzn_node_shelf_collect`); `keep` is handed `keep_ctx`. Nonzero on
 * success, with the counts. sec 443. */
typedef int (*fzn_node_notes_collect_fn)(void *ctx,
                                         int (*keep)(void *keep_ctx, const uint8_t *root),
                                         void *keep_ctx, size_t *kept, size_t *removed);

/* PUSHING A TEXT, sec 448. `place` takes one span (`data`, a spool DATA
 * message) of the text `root` at `length` -- or, with `data` NULL, only says
 * whether it is whole -- setting `*complete`; nonzero when the span was
 * taken or the question answered. `span` writes the span from leaf `first`
 * this node would push, `*count` leaves; nonzero on success. Both are the
 * node's shelf, in practice. */
typedef int (*fzn_node_notes_place_fn)(void *ctx, const uint8_t *root, uint64_t length,
                                       const uint8_t *data, size_t data_len, int *complete);
typedef int (*fzn_node_notes_span_fn)(void *ctx, const uint8_t *root, uint64_t first,
                                      uint8_t *out, size_t cap, size_t *out_len,
                                      uint64_t *count);

/* Open a sealed text back -- the node's shelf, in practice. Nonzero on
 * success, with `*out_len` the text's length. */
typedef int (*fzn_node_notes_open_fn)(void *ctx, const fzn_note_blob_ref_t *ref, uint8_t *out,
                                      size_t cap, size_t *out_len);

typedef struct fzn_node_notes {
	fzn_notes_store_t store;
	fzn_notes_author_t author;
	fzn_notes_writer_t admitted[FZN_NODE_NOTES_WRITERS + 1u];
	size_t admitted_count;
	/* How many of `admitted` the node was opened with -- itself, its
	 * peers and its pulls -- before any member proved by a chain. sec 445. */
	size_t base_count;
	/* The nodes this one pulls from, which a purge always asks. */
	fzn_notes_writer_t pulls[FZN_NODE_NOTES_WRITERS];
	size_t pull_count;
	/* Long texts: both NULL and a text too long for inline is refused. */
	fzn_notes_seal_fn seal;
	fzn_node_notes_open_fn open;
	/* Collecting texts no note names, or NULL: then `remove text unused`
	 * says this node keeps none. sec 443. */
	fzn_node_notes_collect_fn collect;
	/* Taking and giving a pushed text's spans, or NULL. sec 448. */
	fzn_node_notes_place_fn place;
	fzn_node_notes_span_fn span;
	void *text_ctx;
	/* The wall clock, in milliseconds. */
	uint64_t (*now_ms)(void);
	/* Set when a write takes -- a note, a share, an import -- or emptying
	 * the trash leaves purges waiting, for a caller that converses on a
	 * timer to do so now instead; the caller clears it. sec 449. */
	int fresh;
} fzn_node_notes_t;

/*
 * Set up over the node's store, signing as `self` with `sign`, ids from
 * `rng`, admitting `self` and the `peer_count` keys in `peers`, and pulling
 * from the `pull_count` keys in `pulls`, which should be among `peers`.
 * MALFORMED past FZN_NODE_NOTES_WRITERS of either: a short set would refuse a
 * paired node's notes with nothing saying why.
 */
fzn_notes_err_t fzn_node_notes_init(fzn_node_notes_t *notes, const fzn_persist_ops_t *store,
                                    const fzn_hash_ops_t *hash, const fzn_sign_ops_t *sign,
                                    const fzn_random_ops_t *rng,
                                    const uint8_t self[FZN_PUBKEY_LEN],
                                    const uint8_t (*peers)[FZN_PUBKEY_LEN], size_t peer_count,
                                    const uint8_t (*pulls)[FZN_PUBKEY_LEN], size_t pull_count,
                                    uint64_t (*now_ms)(void));

/* ADMIT THE ESTATE'S MEMBERS, proved by their chains (`node/members.h`):
 * the set becomes the one the node was opened with and these, each once, as
 * far as room allows. Replaces the members admitted before, so one revoked
 * since drops out. How many were added. sec 445. */
size_t fzn_node_notes_admit_members(fzn_node_notes_t *notes, const uint8_t (*keys)[FZN_PUBKEY_LEN],
                                    size_t count);

/* A peer's notes sync message (`notes/sync.h`), for `node/admin.h`'s remote
 * hook: answered from this node's store. 0 for what is not one. sec 432.
 * `shared` is a contact's request (sec 436), answered with only the notes
 * the subtrees shared with `sender` reach. */
size_t fzn_node_notes_remote(void *ctx, const uint8_t *sender, int shared,
                             const uint8_t *request, size_t request_len, uint8_t *reply,
                             size_t reply_cap);

/* Whether a note the subtrees shared with `sender` reach has its text in the
 * blob `root`: the texts a contact may fetch from this node's shelf, sec 438.
 * Asked per request, so unsharing or moving a note out stops its text being
 * served at once. */
int fzn_node_notes_shares_blob(fzn_node_notes_t *n, const uint8_t *sender,
                               const uint8_t root[FZN_BLOB_HASH_LEN]);

/* Whether a note this node holds -- in its own tree or any sharer's -- has
 * its text in the blob `root`: what collecting the shelf keeps. sec 443. */
int fzn_node_notes_names_blob(fzn_node_notes_t *n, const uint8_t root[FZN_BLOB_HASH_LEN]);

/* What one push of texts did. */
typedef struct fzn_node_notes_text_tally {
	size_t offered; /* texts this node's notes name and it holds whole */
	size_t pushed;  /* of those, sent because the peer wanted them */
	size_t spans;
	size_t refused; /* the peer would not take them */
} fzn_node_notes_text_tally_t;

/* PUSH THE TEXTS, sec 448: offer every text a note this node holds names,
 * and send the spans of each the peer wants, until it is whole there. A
 * pushed note whose text stayed on its writer was a note no one else could
 * read; the peer takes a text only for a note it holds, at that note's
 * length, from a sender it admits. */
int fzn_node_notes_push_texts(fzn_node_notes_t *n, fzn_notes_sync_ask_t ask, void *ask_ctx,
                              fzn_node_notes_text_tally_t *tally);

/* The verbs above, for `node/admin.h`'s hook. 0 when `request` is not one. */
size_t fzn_node_notes_local(void *ctx, fzn_origin_t origin, const fzn_request_t *request,
                            char *reply, size_t reply_cap);

#endif /* FZN_NODE_NOTES_H */
