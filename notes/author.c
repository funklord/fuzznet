/* See author.h. */

#include "author.h"

#include <string.h>

/* Where a new last child goes when there are none: room to insert before. */
#define FIRST_ORDER 1000u

/* A note as held, with its variable fields COPIED OUT. A note is a view over
 * the record it was opened from, and the buffers it points into are reused to
 * build its successor, so a preserved field held as a pointer would be read
 * after it had been overwritten. */
typedef struct held {
	uint8_t parent[FZN_TREE_ID_LEN];
	uint64_t order;
	uint16_t content_type;
	fzn_note_t note;
	uint8_t title[FZN_NOTE_CONTENT_MAX];
	uint8_t text[FZN_NOTE_CONTENT_MAX];
	uint8_t labels[FZN_NOTE_CONTENT_MAX];
} held_t;

static int is_root(const uint8_t id[FZN_TREE_ID_LEN])
{
	static const uint8_t zero[FZN_TREE_ID_LEN];

	return memcmp(id, zero, FZN_TREE_ID_LEN) == 0;
}

static int author_ok(const fzn_notes_author_t *a)
{
	return a && a->store && a->view && a->issuer && a->sign && a->sign->sign;
}

/* An order after every child `parent` has, `id` aside -- so a note moved
 * within its own parent goes to the end rather than staying past itself. */
static fzn_notes_err_t order_after(const fzn_notes_view_t *view,
                                   const uint8_t parent[FZN_TREE_ID_LEN], const uint8_t *id,
                                   uint64_t *out)
{
	uint64_t high = 0;
	size_t i;
	int any = 0;
	fzn_tree_err_t err;

	for (i = 0; i < view->count; i++) {
		if (memcmp(view->nodes[i].parent, parent, FZN_TREE_ID_LEN) != 0)
			continue;
		if (id && memcmp(view->nodes[i].id, id, FZN_TREE_ID_LEN) == 0)
			continue;
		if (!any || view->nodes[i].order > high)
			high = view->nodes[i].order;
		any = 1;
	}
	if (!any) {
		*out = FIRST_ORDER;
		return FZN_NOTES_OK;
	}
	/* EXHAUSTED STILL WRITES A KEY, which ties and is ordered by id. */
	err = fzn_tree_order_between(high, UINT64_MAX, out);
	return err == FZN_TREE_OK || err == FZN_TREE_ORDER_EXHAUSTED ? FZN_NOTES_OK
	                                                             : FZN_NOTES_ERR_MALFORMED;
}

static fzn_notes_err_t take(const fzn_tree_node_t *node, held_t *h)
{
	fzn_note_t note;

	memcpy(h->parent, node->parent, FZN_TREE_ID_LEN);
	h->order = node->order;
	h->content_type = node->content_type;
	/* A NOTE THIS BUILD CANNOT READ IS NOT EDITED. Writing its fields back
	 * as empty -- which is what an edit of unreadable content would do --
	 * deletes what a newer host wrote. fuzzypickles' edit took the
	 * placement and carried on; this refuses. */
	if (fzn_note_open(node->content_type, node->content, node->content_len, &note)
	    != FZN_NOTE_OK)
		return FZN_NOTES_ERR_SHAPE;
	h->note = note;
	memcpy(h->title, note.title, note.title_len);
	memcpy(h->text, note.text, note.text_len);
	memcpy(h->labels, note.labels, note.labels_len);
	h->note.title = h->title;
	h->note.text = h->text;
	h->note.labels = h->labels;
	return FZN_NOTES_OK;
}

/* The note `id` as held: this host's own claim first, else any writer's. */
static fzn_notes_err_t held_note(const fzn_notes_author_t *a, const uint8_t id[FZN_TREE_ID_LEN],
                                 held_t *h)
{
	static uint8_t record[FZN_RECORD_MAX_LEN];
	fzn_record_t rec;
	fzn_tree_node_t node;
	size_t len = 0, i;
	fzn_notes_err_t err;

	if (fzn_notes_get(a->store, id, a->issuer, record, sizeof(record), &len) == FZN_NOTES_OK
	    && fzn_record_open(record, len, &rec) == FZN_RECORD_OK
	    && fzn_tree_open(rec, &node) == FZN_TREE_OK)
		return take(&node, h);
	err = fzn_notes_view_load(a->store, a->view);
	if (err != FZN_NOTES_OK)
		return err;
	for (i = 0; i < a->view->count; i++)
		if (memcmp(a->view->nodes[i].id, id, FZN_TREE_ID_LEN) == 0)
			return take(&a->view->nodes[i], h);
	return FZN_NOTES_ERR_ABSENT;
}

/* Build, sign as this host at its next sequence, and put. */
static fzn_notes_err_t write_note(const fzn_notes_author_t *a,
                                  const uint8_t id[FZN_TREE_ID_LEN],
                                  const uint8_t parent[FZN_TREE_ID_LEN], uint64_t order,
                                  uint16_t content_type, const fzn_note_t *note, uint64_t now_ms)
{
	static uint8_t content[FZN_NOTE_CONTENT_MAX + FZN_NOTE_HEADER_LEN];
	static uint8_t body[FZN_RECORD_BODY_MAX];
	static uint8_t record[FZN_RECORD_MAX_LEN];
	size_t content_len = 0, body_len = 0, record_len = 0;
	uint64_t seq = 0;
	fzn_notes_err_t err;

	if (fzn_note_content(note, content, sizeof(content), &content_len) != FZN_NOTE_OK
	    || fzn_tree_body(parent, order, content_type, content, content_len, body, sizeof(body),
	                     &body_len)
	               != FZN_TREE_OK)
		return FZN_NOTES_ERR_MALFORMED;
	/* THE SEQUENCE LAST, after everything that can refuse: a number taken
	 * and not used is a gap nothing minds, but there is no reason to make
	 * one for a note that was never going to be written. */
	err = fzn_notes_next_seq(a->store, a->issuer, &seq);
	if (err != FZN_NOTES_OK)
		return err;
	if (fzn_record_sign(a->issuer, id, FZN_NOTE_STREAM, FZN_NOTE_KIND, seq, now_ms, body,
	                    body_len, a->sign, record, sizeof(record), &record_len)
	    != FZN_RECORD_OK)
		return FZN_NOTES_ERR_MALFORMED;
	return fzn_notes_put(a->store, record, record_len, a->policy, a->sign, NULL, NULL);
}

fzn_notes_err_t fzn_notes_create(const fzn_notes_author_t *author,
                                 const uint8_t parent[FZN_TREE_ID_LEN], uint16_t content_type,
                                 const fzn_note_t *fields, uint64_t now_ms,
                                 uint8_t id_out[FZN_TREE_ID_LEN])
{
	return fzn_notes_create_dated(author, parent, content_type, fields, now_ms, now_ms, id_out);
}

fzn_notes_err_t fzn_notes_create_dated(const fzn_notes_author_t *author,
                                       const uint8_t parent[FZN_TREE_ID_LEN],
                                       uint16_t content_type, const fzn_note_t *fields,
                                       uint64_t created_at_ms, uint64_t now_ms,
                                       uint8_t id_out[FZN_TREE_ID_LEN])
{
	fzn_note_t note;
	uint64_t order = 0;
	fzn_notes_err_t err;

	if (!author_ok(author) || !author->rng || !author->rng->fill || !parent || !fields
	    || !id_out)
		return FZN_NOTES_ERR_MALFORMED;
	if (!fzn_note_type_writable(content_type))
		return FZN_NOTES_ERR_MALFORMED;
	note = *fields;
	note.version = FZN_NOTE_VERSION;
	note.created_at_ms = created_at_ms ? created_at_ms : now_ms;
	note.edited_at_ms = now_ms;
	if (fzn_note_shape_ok(content_type, &note) != FZN_NOTE_OK)
		return FZN_NOTES_ERR_MALFORMED;
	if (!author->rng->fill(author->rng->ctx, id_out, FZN_TREE_ID_LEN))
		return FZN_NOTES_ERR_BACKEND;
	/* THE ALL-ZERO ID IS THE ROOT, which is not a node. */
	if (is_root(id_out))
		id_out[0] = 1u;
	err = fzn_notes_view_load(author->store, author->view);
	if (err != FZN_NOTES_OK)
		return err;
	err = order_after(author->view, parent, NULL, &order);
	if (err != FZN_NOTES_OK)
		return err;
	return write_note(author, id_out, parent, order, content_type, &note, now_ms);
}

fzn_notes_err_t fzn_notes_edit(const fzn_notes_author_t *author,
                               const uint8_t id[FZN_TREE_ID_LEN], unsigned which,
                               const fzn_note_t *with, uint8_t set, uint8_t clear,
                               uint64_t now_ms)
{
	static held_t h;
	fzn_note_t note;
	fzn_notes_err_t err;

	if (!author_ok(author) || !id)
		return FZN_NOTES_ERR_MALFORMED;
	if ((which & ~FZN_NOTES_EDIT_FIELDS) != 0u || (which && !with)
	    || (set & (uint8_t)~FZN_NOTES_EDIT_FLAGS) != 0u
	    || (clear & (uint8_t)~FZN_NOTES_EDIT_FLAGS) != 0u || (set & clear) != 0u
	    || (which == 0u && set == 0u && clear == 0u))
		return FZN_NOTES_ERR_MALFORMED;
	/* The root is not a node and has no record to supersede. */
	if (is_root(id))
		return FZN_NOTES_ERR_ABSENT;
	err = held_note(author, id, &h);
	if (err != FZN_NOTES_OK)
		return err;

	/* WHATEVER THIS EDIT DOES NOT NAME KEEPS WHAT THE NOTE SAID. */
	note = h.note;
	if (which & FZN_NOTES_EDIT_TITLE) {
		note.title = with->title;
		note.title_len = with->title_len;
	}
	if (which & FZN_NOTES_EDIT_TEXT) {
		note.text = with->text;
		note.text_len = with->text_len;
		note.flags = (uint8_t)((note.flags & ~FZN_NOTE_FLAG_TEXT_IS_BLOB)
		                       | (with->flags & FZN_NOTE_FLAG_TEXT_IS_BLOB));
	}
	if (which & FZN_NOTES_EDIT_LABELS) {
		note.labels = with->labels;
		note.labels_len = with->labels_len;
	}
	if (which & FZN_NOTES_EDIT_COLOUR)
		note.colour = with->colour;
	note.flags = (uint8_t)((note.flags | set) & ~clear);
	/* The note's own creation time; only the edit time moves. */
	note.edited_at_ms = now_ms;
	if (fzn_note_shape_ok(h.content_type, &note) != FZN_NOTE_OK)
		return FZN_NOTES_ERR_MALFORMED;
	/* SAME PARENT, SAME ORDER, SAME TYPE: an edit is not a move. */
	return write_note(author, id, h.parent, h.order, h.content_type, &note, now_ms);
}

fzn_notes_err_t fzn_notes_move(const fzn_notes_author_t *author,
                               const uint8_t id[FZN_TREE_ID_LEN],
                               const uint8_t parent[FZN_TREE_ID_LEN], uint64_t now_ms)
{
	static held_t h;
	fzn_note_t note;
	uint64_t order = 0;
	fzn_notes_err_t err;

	if (!author_ok(author) || !id || !parent)
		return FZN_NOTES_ERR_MALFORMED;
	if (memcmp(id, parent, FZN_TREE_ID_LEN) == 0)
		return FZN_NOTES_ERR_MALFORMED;
	if (is_root(id))
		return FZN_NOTES_ERR_ABSENT;
	err = held_note(author, id, &h);
	if (err != FZN_NOTES_OK)
		return err;
	err = fzn_notes_view_load(author->store, author->view);
	if (err != FZN_NOTES_OK)
		return err;
	err = order_after(author->view, parent, id, &order);
	if (err != FZN_NOTES_OK)
		return err;
	note = h.note;
	note.edited_at_ms = now_ms;
	return write_note(author, id, parent, order, h.content_type, &note, now_ms);
}
