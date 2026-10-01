/* Importing notes from Google Keep and KNotes exports. sec 429, the last of
 * phase 3 of the notes move.
 *
 * Ported from fuzzypickles' `notes_import` at 1e002a9, keeping its split and
 * its refusal to lose anything, and closing the gaps their copy has:
 *
 *   - THEIRS REFUSES A LONG NOTE because their blob path was never built.
 *     Here it is (secs 423-424): a text past what fits inline is sealed
 *     through the caller's `seal` hook and the note carries its reference.
 *   - THEIR KNOTES PARSER TRUNCATES SILENTLY. A folded line, and an
 *     unescaped value, past 8 KiB were cut with no count and no report --
 *     the data loss the rest of their file exists to refuse. Here nothing is
 *     cut: a value past FZN_NOTE_TEXT_MAX is the note refused and counted.
 *   - THEIR KEEP PARSER REFUSES A NOTE FOR A `\uXXXX` ESCAPE. Takeout escapes
 *     some characters that way; they are decoded to UTF-8 here, surrogate
 *     pairs included, and a lone surrogate is the one that is refused.
 *   - CHECKLISTS AND LABELS. Theirs refused a Keep checklist and dropped
 *     labels. `notes/note.h` has a LIST type and labels, so a checklist
 *     imports as a list, its items and their ticks intact, and Keep's labels
 *     come across.
 *
 * PARSING IS HERE AND THE FILE READ IS THE CALLER'S, as in fuzzypickles: this
 * library has no I/O, and the parsers are testable for it. A Takeout is a
 * directory of one-note files, and walking it is the caller's too.
 *
 * NEITHER SOURCE HAS A HIERARCHY, measured by fuzzypickles: Keep's labels are
 * flat and a note may carry several, so a label cannot be a parent, and
 * KNotes is flat VJOURNAL. So imported notes land flat under one folder the
 * caller names, and the user arranges them afterwards.
 *
 * NOTHING IS TRUNCATED, EVER. Import is one-shot, run when a user has least
 * context, and a silently shortened note is data loss found months later with
 * the export gone. A note that cannot come across whole is refused, counted
 * and named, so the user knows what did not while they still have the file.
 *
 * A SECOND IMPORT RECOGNISES WHAT THE FIRST BROUGHT by the source's creation
 * time and the title together. KNotes carries a UID and Keep carries no id at
 * all, so fuzzypickles' holder settled on the creation time, which survives a
 * user editing the note; the title is added because a time alone is shared by
 * notes made in the same millisecond. A note whose source gives no creation
 * time is imported every time, and counted as undated rather than pretended
 * deduplicated.
 */

#ifndef FZN_NOTES_IMPORT_H
#define FZN_NOTES_IMPORT_H

#include <stddef.h>
#include <stdint.h>

#include "author.h"

/* One note as an export describes it, a VIEW into the parser's scratch that
 * is valid only during the callback it is handed to. For a LIST, `text` is
 * the encoded items, as `notes/note.h` lays them out. */
typedef struct fzn_notes_import_entry {
	uint16_t content_type;
	const uint8_t *title;
	size_t title_len;
	const uint8_t *text;
	size_t text_len;
	const uint8_t *labels; /* NUL-separated, as a note's are */
	size_t labels_len;
	uint8_t flags;           /* PINNED, ARCHIVED, TRASHED */
	uint64_t created_at_ms;  /* 0 when the source did not say */
} fzn_notes_import_entry_t;

/* Called once per note parsed. Nonzero stops the parse. */
typedef int (*fzn_notes_import_fn)(void *ctx, const fzn_notes_import_entry_t *entry);

/* A note an export holds that the parser could not take, and why. Its title
 * is what a user searches their export for, so it is given when known. */
typedef enum fzn_notes_import_refusal {
	FZN_NOTES_IMPORT_UNPARSED = 1, /* malformed, or empty */
	FZN_NOTES_IMPORT_TOO_LONG = 2, /* a field past what any note can hold */
	FZN_NOTES_IMPORT_NO_SEAL = 3,  /* too long for inline, and no seal hook */
	FZN_NOTES_IMPORT_FAILED = 4    /* the store, the seal or the author refused */
} fzn_notes_import_refusal_t;

/* How a refusal reaches the caller, so it can name the note. */
typedef void (*fzn_notes_import_refused_fn)(void *ctx, fzn_notes_import_refusal_t why,
                                            const uint8_t *title, size_t title_len);

/*
 * One Google Keep Takeout note: a single JSON object. NOT A JSON PARSER, as
 * fuzzypickles' was not, and it says so: it reads `title`, `textContent`,
 * `listContent`, `labels`, `isPinned`, `isArchived`, `isTrashed` and
 * `createdTimestampUsec` at the top level only -- depth is tracked, so a key
 * inside `attachments` cannot be taken for the note's own -- and leaves
 * everything else alone. One note per call; `refused` (may be NULL) hears a
 * note that could not be taken.
 */
fzn_notes_err_t fzn_notes_import_keep(const uint8_t *json, size_t len, fzn_notes_import_fn fn,
                                      void *ctx, fzn_notes_import_refused_fn refused,
                                      void *refused_ctx);

/*
 * A KNotes calendar: every VJOURNAL in it. SUMMARY is the title, DESCRIPTION
 * the text, CREATED the creation time. Folded lines are unfolded first, which
 * is not optional: iCalendar wraps at 75 octets, and a parser skipping it
 * would import the first 75 characters of every long note and call it done.
 */
fzn_notes_err_t fzn_notes_import_knotes(const uint8_t *ics, size_t len, fzn_notes_import_fn fn,
                                        void *ctx, fzn_notes_import_refused_fn refused,
                                        void *refused_ctx);

/* Seal a long text and fill its reference -- the node's shelf, in practice
 * (`node/shelf.h`). Nonzero on success. */
typedef int (*fzn_notes_seal_fn)(void *ctx, const uint8_t *text, size_t len,
                                 fzn_note_blob_ref_t *ref);

/*
 * An import in progress: where notes go, how long texts are sealed, and the
 * tally. Hand `fzn_notes_import_take` to a parser with this as its context,
 * and `fzn_notes_import_refuse` as its refusal hook.
 */
typedef struct fzn_notes_import_run {
	const fzn_notes_author_t *author;
	uint8_t folder[FZN_TREE_ID_LEN];
	fzn_notes_seal_fn seal; /* NULL: a text too long for inline is refused */
	void *seal_ctx;
	uint64_t now_ms;
	size_t imported;
	size_t already;  /* recognised from an earlier import, not written again */
	size_t undated;  /* imported with no creation time to recognise them by */
	size_t refused;  /* every refusal, whichever stage it came from */
	/* Where refusals are named, or NULL. */
	fzn_notes_import_refused_fn on_refused;
	void *refused_ctx;
} fzn_notes_import_run_t;

/* The parser callback: create one note under the run's folder, sealing its
 * text when it does not fit inline, unless an earlier import brought it. */
int fzn_notes_import_take(void *run, const fzn_notes_import_entry_t *entry);

/* The parser refusal hook: count it, and pass it to the run's `on_refused`. */
void fzn_notes_import_refuse(void *run, fzn_notes_import_refusal_t why, const uint8_t *title,
                             size_t title_len);

#endif /* FZN_NOTES_IMPORT_H */
