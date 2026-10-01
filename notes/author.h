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
 * A LONG NOTE'S TEXT is sealed before it gets here (`node/shelf.h`): the text
 * field a caller passes is then the 72-byte reference, with
 * FZN_NOTE_FLAG_TEXT_IS_BLOB set in the note it hands over.
 */

#ifndef FZN_NOTES_AUTHOR_H
#define FZN_NOTES_AUTHOR_H

#include <stddef.h>
#include <stdint.h>

#include "view.h"
#include "../session/random.h"

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
} fzn_notes_author_t;

/* Which fields an edit replaces. A field not named keeps what it said. */
#define FZN_NOTES_EDIT_TITLE  0x01u
#define FZN_NOTES_EDIT_TEXT   0x02u /* and the TEXT_IS_BLOB flag with it */
#define FZN_NOTES_EDIT_LABELS 0x04u
#define FZN_NOTES_EDIT_COLOUR 0x08u
#define FZN_NOTES_EDIT_FIELDS                                                                 \
	(FZN_NOTES_EDIT_TITLE | FZN_NOTES_EDIT_TEXT | FZN_NOTES_EDIT_LABELS                    \
	 | FZN_NOTES_EDIT_COLOUR)

/* The flags an edit may set or clear: pinned, archived, trashed. TEXT_IS_BLOB
 * moves only with the text, since it says what the text field is. */
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
