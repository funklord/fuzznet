/* Writing notes: create, edit, move and trash, as signed records. sec 426,
 * phase 3 of the notes move.
 *
 * Ported from fuzzypickles' `notes_service` create and edit at b419405, with
 * a move added. Each operation builds a note body (`notes/note.h`), places it
 * (`tree/tree.h`), signs it as this host at the next sequence and hands it to
 * `fzn_notes_put` -- THE SAME ADMISSION AN ARRIVING RECORD GOES THROUGH. A
 * locally authored note is not privileged: a host outside its own admitted set
 * cannot write one either, and that is the answer rather than a special case.
 *
 * A NOTE ID IS RANDOM, NOT DERIVED FROM THE CONTENT. Content-addressing would
 * make two notes with the same text one node, so writing "milk" twice would
 * silently be one note and editing one would move the other.
 *
 * AN EDIT IS SUPERSESSION, which the store already does: a new record for the
 * same note at a higher sequence. What an edit must NOT change matters as much
 * as what it does:
 *
 *   - the note's parent and its place among siblings, so editing cannot move;
 *   - its content type, so renaming a checklist does not turn it into prose;
 *   - its creation time, which is the note's and not the last edit's;
 *   - every field the edit does not name, and every flag it does not set or
 *     clear -- renaming a note must not discard its text, unpin it, or bring
 *     it back from the trash.
 *
 * IT WRITES THIS HOST'S OWN CLAIM. Where this host has no record of the note
 * and another writer does -- the ordinary state after a sync -- the placement
 * and fields are taken from what is held, and this host's claim joins the
 * others rather than replacing them: `tree/` refuses to resolve competing
 * claims, and an edit is not the place to start.
 *
 * A MOVE is an edit of placement only: a new parent, at the end of its
 * children. It can make a cycle, which `tree/` reports rather than forbids;
 * only a note made its own parent is refused, since that one is never meant.
 *
 * EVERY NOTE'S CONTENT IS A SEALED BLOB, since sec 514 (the design is sec
 * 511): the record carries the meta, and title, text and labels are the
 * payload `seal` puts in a blob. An edit naming a content field opens the
 * held payload through `open`, changes it, and seals a new blob under a new
 * key; an edit of flags or colour, and a move, keep the reference, since the
 * same content under the same key is not a key reused. A note whose blob is
 * not here yet can be pinned, trashed and moved, and its content not edited:
 * PENDING.
 *
 * EVERY RECORD IS CHAINED, since sec 517 (the design is sec 511): `chain`
 * signs the body as the next record of this host's notes stream, naming the
 * one before, and hands the record back -- the node's journal, in practice
 * (`node/journal.h`). The journal is the note's history; the store this
 * writes into after is the index of each claim's latest record, which a view
 * reads. Room in that index and this host's own admission are checked BEFORE
 * the chain is asked, so a write the index would refuse leaves nothing in the
 * history either.
 */

#ifndef FZN_NOTES_AUTHOR_H
#define FZN_NOTES_AUTHOR_H

#include <stddef.h>
#include <stdint.h>

#include "view.h"
#include "../session/random.h"

/* Seal a payload into a blob and fill its reference -- the node's shelf, in
 * practice (`node/shelf.h`). Nonzero on success. */
typedef int (*fzn_notes_seal_fn)(void *ctx, const uint8_t *payload, size_t len,
                                 fzn_note_blob_ref_t *ref);

/* Open a blob back into its payload. Nonzero on success, with `*out_len` the
 * payload's length; zero when it is not here, or will not open. */
typedef int (*fzn_notes_open_fn)(void *ctx, const fzn_note_blob_ref_t *ref, uint8_t *out,
                                 size_t cap, size_t *out_len);

/* Sign `body` as the next record of `issuer`'s notes stream -- `kind` on
 * FZN_NOTE_STREAM, about `subject`, naming the stream's last record -- keep
 * it, and copy it into `record`, `cap` bytes, `*record_len` of them. Nonzero
 * on success. The kind is FZN_NOTE_KIND for a note, FZN_NOTE_PURGE_KIND for
 * a purge (sec 519). */
typedef int (*fzn_notes_chain_fn)(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN],
                                  const fzn_sign_ops_t *sign, uint32_t kind,
                                  const uint8_t subject[FZN_SUBJECT_LEN], const uint8_t *body,
                                  size_t body_len, uint64_t now_ms, uint8_t *record,
                                  size_t cap, size_t *record_len);

/* Everything writing a note needs. All borrowed. `view` is scratch, since an
 * edit of another writer's note and a create's placement both read the tree. */
typedef struct fzn_notes_author {
	const fzn_notes_store_t *store;
	fzn_notes_view_t *view;
	/* This host's key, which `sign` signs as and verifies with. */
	const uint8_t *issuer;
	const fzn_sign_ops_t *sign;
	const fzn_random_ops_t *rng;
	/* The admitted set this host's own records go through. */
	fzn_notes_policy_t policy;
	/* Where content goes and comes from, sec 514: both are required. */
	fzn_notes_seal_fn seal;
	fzn_notes_open_fn open;
	void *text_ctx;
	/* Where records are chained, sec 517: required. */
	fzn_notes_chain_fn chain;
	void *chain_ctx;
} fzn_notes_author_t;

/* A NOTE'S CONTENT, READ: `node`'s meta into `meta`, and its payload, opened
 * through `open` into `buf`, into `out`'s title, text and labels. SHAPE for a
 * node that is no version-2 note; PENDING when the blob does not open, or
 * `open` is NULL -- `meta` is filled either way. */
fzn_notes_err_t fzn_notes_read(fzn_notes_open_fn open, void *ctx, const fzn_tree_node_t *node,
                               fzn_note_meta_t *meta, uint8_t *buf, size_t cap,
                               fzn_note_t *out);

/* The blob reference in `node`'s meta: nonzero for a version-2 note. What
 * every scan for the texts a tree names reads, sec 514. */
int fzn_notes_ref_of(const fzn_tree_node_t *node, fzn_note_blob_ref_t *ref);

/* Which fields an edit replaces. A field not named keeps what it said. */
#define FZN_NOTES_EDIT_TITLE  0x01u
#define FZN_NOTES_EDIT_TEXT   0x02u
#define FZN_NOTES_EDIT_LABELS 0x04u
#define FZN_NOTES_EDIT_COLOUR 0x08u
#define FZN_NOTES_EDIT_FIELDS                                                                 \
	(FZN_NOTES_EDIT_TITLE | FZN_NOTES_EDIT_TEXT | FZN_NOTES_EDIT_LABELS                    \
	 | FZN_NOTES_EDIT_COLOUR)

/* The flags an edit may set or clear: pinned, archived, trashed. */
#define FZN_NOTES_EDIT_FLAGS                                                                  \
	(FZN_NOTE_FLAG_PINNED | FZN_NOTE_FLAG_ARCHIVED | FZN_NOTE_FLAG_TRASHED)

/*
 * A new note under `parent` (all-zero for the top level), at the end of its
 * children. `fields` supplies title, text, labels, colour and flags; its
 * times are ignored and set to `now_ms`. `content_type` must be one this
 * build may write. `id_out` receives the new id.
 */
fzn_notes_err_t fzn_notes_create(const fzn_notes_author_t *author,
                                 const uint8_t parent[FZN_TREE_ID_LEN], uint16_t content_type,
                                 const fzn_note_t *fields, uint64_t now_ms,
                                 uint8_t id_out[FZN_TREE_ID_LEN]);

/* The same, with the note's creation time given rather than now: an import
 * keeps the time its source says the note was made, which is also what a
 * second import recognises it by (`notes/import.h`). 0 means now. */
fzn_notes_err_t fzn_notes_create_dated(const fzn_notes_author_t *author,
                                       const uint8_t parent[FZN_TREE_ID_LEN],
                                       uint16_t content_type, const fzn_note_t *fields,
                                       uint64_t created_at_ms, uint64_t now_ms,
                                       uint8_t id_out[FZN_TREE_ID_LEN]);

/*
 * Rewrite the fields `which` names from `with`, set the flags in `set` and
 * clear those in `clear` (both within FZN_NOTES_EDIT_FLAGS, and not the same
 * flag in both), keeping everything else. ABSENT for a note no writer holds.
 */
fzn_notes_err_t fzn_notes_edit(const fzn_notes_author_t *author,
                               const uint8_t id[FZN_TREE_ID_LEN], unsigned which,
                               const fzn_note_t *with, uint8_t set, uint8_t clear,
                               uint64_t now_ms);

/* Put a note under `parent`, at the end of its children. MALFORMED for a
 * note made its own parent; ABSENT for a note no writer holds. */
fzn_notes_err_t fzn_notes_move(const fzn_notes_author_t *author,
                               const uint8_t id[FZN_TREE_ID_LEN],
                               const uint8_t parent[FZN_TREE_ID_LEN], uint64_t now_ms);

#endif /* FZN_NOTES_AUTHOR_H */
