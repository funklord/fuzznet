/* See author.h. */

#include "author.h"

#include <string.h>

/* Where a new last child goes when there are none: room to insert before. */
#define FIRST_ORDER 1000u

/* A note as held: its placement and its meta. Its payload is opened only
 * when an edit changes it, into `payload`, and a note view over that buffer
 * is safe while the successor is built in others. */
typedef struct held {
	uint8_t parent[FZN_TREE_ID_LEN];
	uint64_t order;
	uint16_t content_type;
	fzn_note_meta_t meta;
} held_t;

/* The one payload buffer: opening the held note's, then writing the new. */
static uint8_t payload_in[FZN_NOTE_PAYLOAD_MAX];
static uint8_t payload_out[FZN_NOTE_PAYLOAD_MAX];

static int is_root(const uint8_t id[FZN_TREE_ID_LEN])
{
	static const uint8_t zero[FZN_TREE_ID_LEN];

	return memcmp(id, zero, FZN_TREE_ID_LEN) == 0;
}

static int author_ok(const fzn_notes_author_t *a)
{
	return a && a->store && a->view && a->issuer && a->sign && a->sign->sign && a->seal
	       && a->open && a->chain;
}

/* `ref`'s key wrapped, or unwrapped -- one operation -- under `id`'s wrap
 * key in `store`, into `out`. PENDING when the store holds none. sec 520. */
static fzn_notes_err_t wrapped(const fzn_notes_store_t *store, const uint8_t id[FZN_TREE_ID_LEN],
                               const fzn_note_blob_ref_t *ref, fzn_note_blob_ref_t *out)
{
	uint8_t wk[FZN_NOTE_WRAP_KEY_LEN];
	fzn_notes_err_t err = fzn_notes_wrap_get(store, id, wk);

	if (err == FZN_NOTES_ERR_ABSENT)
		return FZN_NOTES_ERR_PENDING;
	if (err != FZN_NOTES_OK)
		return err;
	*out = *ref;
	if (fzn_note_wrap(store->hash, wk, ref->root, ref->key, out->key) != FZN_NOTE_OK)
		err = FZN_NOTES_ERR_MALFORMED;
	memset(wk, 0, sizeof(wk));
	return err;
}

fzn_notes_err_t fzn_notes_read(const fzn_notes_store_t *store, fzn_notes_open_fn open,
                               void *ctx, const fzn_tree_node_t *node, fzn_note_meta_t *meta,
                               uint8_t *buf, size_t cap, fzn_note_t *out)
{
	fzn_note_blob_ref_t plain;
	fzn_notes_err_t err;
	size_t len = 0;
	int opened;

	if (!store || !node || !meta || !buf || !out)
		return FZN_NOTES_ERR_MALFORMED;
	if (fzn_note_meta_open(node->content_type, node->content, node->content_len, meta)
	    != FZN_NOTE_OK)
		return FZN_NOTES_ERR_SHAPE;
	if (!open)
		return FZN_NOTES_ERR_PENDING;
	err = wrapped(store, node->id, &meta->content, &plain);
	if (err != FZN_NOTES_OK)
		return err;
	opened = open(ctx, &plain, buf, cap, &len) && len == meta->content.length;
	memset(plain.key, 0, sizeof(plain.key));
	if (!opened)
		return FZN_NOTES_ERR_PENDING;
	return fzn_note_payload_open(buf, len, out) == FZN_NOTE_OK ? FZN_NOTES_OK
	                                                           : FZN_NOTES_ERR_SHAPE;
}

int fzn_notes_ref_of(const fzn_tree_node_t *node, fzn_note_blob_ref_t *ref)
{
	fzn_note_meta_t meta;

	if (!node || !ref
	    || fzn_note_meta_open(node->content_type, node->content, node->content_len, &meta)
	               != FZN_NOTE_OK)
		return 0;
	*ref = meta.content;
	return 1;
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
	memcpy(h->parent, node->parent, FZN_TREE_ID_LEN);
	h->order = node->order;
	h->content_type = node->content_type;
	/* A NOTE THIS BUILD CANNOT READ IS NOT EDITED. Writing its fields back
	 * as empty -- which is what an edit of unreadable content would do --
	 * deletes what a newer host wrote. fuzzypickles' edit took the
	 * placement and carried on; this refuses. */
	if (fzn_note_meta_open(node->content_type, node->content, node->content_len, &h->meta)
	    != FZN_NOTE_OK)
		return FZN_NOTES_ERR_SHAPE;
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

/* WHETHER THE INDEX WILL TAKE A RECORD of `id` from this host: its key in
 * the admitted set, and room for the claim -- held already, or a place left.
 * Asked before the chain, which cannot take a record back. */
static fzn_notes_err_t index_takes(const fzn_notes_author_t *a, const uint8_t id[FZN_TREE_ID_LEN])
{
	static uint8_t keys[FZN_NOTES_MAX][FZN_PUBKEY_LEN];
	static uint8_t record[FZN_RECORD_MAX_LEN];
	size_t i, count = 0, len = 0;
	int admitted = 0;
	fzn_notes_err_t err;

	for (i = 0; a->policy.spelled && a->policy.admitted && i < a->policy.admitted_count; i++)
		admitted |= memcmp(a->policy.admitted[i].key, a->issuer, FZN_PUBKEY_LEN) == 0;
	if (!admitted)
		return FZN_NOTES_ERR_DENIED;
	if (fzn_notes_get(a->store, id, a->issuer, record, sizeof(record), &len) == FZN_NOTES_OK)
		return FZN_NOTES_OK;
	err = fzn_notes_claims(a->store, keys, FZN_NOTES_MAX, &count);
	if (err != FZN_NOTES_OK)
		return err;
	return count < FZN_NOTES_MAX ? FZN_NOTES_OK : FZN_NOTES_ERR_FULL;
}

/* Build, chain as this host's next note record, and put. */
static fzn_notes_err_t write_note(const fzn_notes_author_t *a,
                                  const uint8_t id[FZN_TREE_ID_LEN],
                                  const uint8_t parent[FZN_TREE_ID_LEN], uint64_t order,
                                  uint16_t content_type, const fzn_note_meta_t *meta,
                                  uint64_t now_ms)
{
	static uint8_t content[FZN_NOTE_META_LEN];
	static uint8_t body[FZN_RECORD_BODY_MAX];
	static uint8_t record[FZN_RECORD_MAX_LEN];
	size_t body_len = 0, record_len = 0;
	int wrote = 0;
	fzn_notes_err_t err;

	if (fzn_note_meta_write(meta, content) != FZN_NOTE_OK
	    || fzn_tree_body(parent, order, content_type, content, sizeof(content), body,
	                     sizeof(body), &body_len)
	               != FZN_TREE_OK)
		return FZN_NOTES_ERR_MALFORMED;
	/* THE CHAIN LAST, after everything that can refuse: a record in the
	 * history cannot be taken back, so one the index would not take is
	 * never made. */
	err = index_takes(a, id);
	if (err != FZN_NOTES_OK)
		return err;
	if (!a->chain(a->chain_ctx, a->issuer, a->sign, FZN_NOTE_KIND, id, body, body_len, now_ms,
	              record, sizeof(record), &record_len))
		return FZN_NOTES_ERR_BACKEND;
	err = fzn_notes_put(a->store, record, record_len, a->policy, a->sign, &wrote, NULL);
	if (err != FZN_NOTES_OK)
		return err;
	/* A RECORD THE INDEX CALLS OLDER than the one it holds from this host
	 * is a store kept before sec 517, whose own records were numbered by a
	 * counter the chain starts below. It is not migrated: said, not
	 * dropped. */
	return wrote ? FZN_NOTES_OK : FZN_NOTES_ERR_SHAPE;
}

/* Seal `fields`' title, text and labels as a new blob, its reference into
 * `ref`, after checking the shape `content_type` requires. */
static fzn_notes_err_t seal_payload(const fzn_notes_author_t *a, uint16_t content_type,
                                    const fzn_note_t *fields, fzn_note_blob_ref_t *ref)
{
	size_t len = 0;
	fzn_note_err_t nerr;

	if (fzn_note_shape_ok(content_type, fields) != FZN_NOTE_OK)
		return FZN_NOTES_ERR_MALFORMED;
	nerr = fzn_note_payload_write(fields, payload_out, sizeof(payload_out), &len);
	if (nerr != FZN_NOTE_OK)
		return FZN_NOTES_ERR_MALFORMED;
	if (!a->seal(a->text_ctx, payload_out, len, ref))
		return FZN_NOTES_ERR_BACKEND;
	return FZN_NOTES_OK;
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
	fzn_note_meta_t meta;
	fzn_note_t content;
	uint64_t order = 0;
	fzn_notes_err_t err;

	if (!author_ok(author) || !author->rng || !author->rng->fill || !parent || !fields
	    || !id_out)
		return FZN_NOTES_ERR_MALFORMED;
	if (!fzn_note_type_writable(content_type))
		return FZN_NOTES_ERR_MALFORMED;
	if (fields->flags & (uint8_t)~FZN_NOTE_META_FLAGS_KNOWN)
		return FZN_NOTES_ERR_MALFORMED;
	/* THE CONTENT ALONE goes into the payload; flags and colour are the
	 * meta's. */
	memset(&content, 0, sizeof(content));
	content.title = fields->title;
	content.title_len = fields->title_len;
	content.text = fields->text;
	content.text_len = fields->text_len;
	content.labels = fields->labels;
	content.labels_len = fields->labels_len;
	memset(&meta, 0, sizeof(meta));
	meta.flags = fields->flags;
	meta.colour = fields->colour;
	meta.created_at_ms = created_at_ms ? created_at_ms : now_ms;
	meta.edited_at_ms = now_ms;
	if (!author->rng->fill(author->rng->ctx, id_out, FZN_TREE_ID_LEN))
		return FZN_NOTES_ERR_BACKEND;
	/* THE ALL-ZERO ID IS THE ROOT, which is not a node. */
	if (is_root(id_out))
		id_out[0] = 1u;
	/* THE WRAP KEY FIRST, sec 520, kept before anything names it: a record
	 * here must never wrap under a key this host does not hold. */
	{
		uint8_t wk[FZN_NOTE_WRAP_KEY_LEN];

		err = author->rng->fill(author->rng->ctx, wk, sizeof(wk))
		              ? fzn_notes_wrap_put(author->store, id_out, wk)
		              : FZN_NOTES_ERR_BACKEND;
		memset(wk, 0, sizeof(wk));
		if (err != FZN_NOTES_OK)
			return err;
	}
	err = seal_payload(author, content_type, &content, &meta.content);
	if (err == FZN_NOTES_OK)
		err = wrapped(author->store, id_out, &meta.content, &meta.content);
	if (err != FZN_NOTES_OK) {
		(void)fzn_notes_wrap_erase(author->store, id_out);
		return err;
	}
	err = fzn_notes_view_load(author->store, author->view);
	if (err != FZN_NOTES_OK)
		return err;
	err = order_after(author->view, parent, NULL, &order);
	if (err == FZN_NOTES_OK)
		err = write_note(author, id_out, parent, order, content_type, &meta, now_ms);
	/* A NOTE NEVER WRITTEN keeps no wrap key behind it. */
	if (err != FZN_NOTES_OK)
		(void)fzn_notes_wrap_erase(author->store, id_out);
	return err;
}

fzn_notes_err_t fzn_notes_edit(const fzn_notes_author_t *author,
                               const uint8_t id[FZN_TREE_ID_LEN], unsigned which,
                               const fzn_note_t *with, uint8_t set, uint8_t clear,
                               uint64_t now_ms)
{
	static held_t h;
	fzn_note_meta_t meta;
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
	meta = h.meta;
	if (which & (FZN_NOTES_EDIT_TITLE | FZN_NOTES_EDIT_TEXT | FZN_NOTES_EDIT_LABELS)) {
		fzn_note_blob_ref_t plain;
		fzn_note_t content;
		size_t len = 0;
		int opened;

		/* THE HELD PAYLOAD, OPENED, so the fields this edit keeps are kept:
		 * a content edit of a note whose blob, or wrap key, is not here
		 * yet would otherwise write those fields back empty. */
		err = wrapped(author->store, id, &h.meta.content, &plain);
		if (err != FZN_NOTES_OK)
			return err;
		opened = author->open(author->text_ctx, &plain, payload_in, sizeof(payload_in), &len);
		memset(plain.key, 0, sizeof(plain.key));
		if (!opened || len != h.meta.content.length)
			return FZN_NOTES_ERR_PENDING;
		if (fzn_note_payload_open(payload_in, len, &content) != FZN_NOTE_OK)
			return FZN_NOTES_ERR_SHAPE;
		if (which & FZN_NOTES_EDIT_TITLE) {
			content.title = with->title;
			content.title_len = with->title_len;
		}
		if (which & FZN_NOTES_EDIT_TEXT) {
			content.text = with->text;
			content.text_len = with->text_len;
		}
		if (which & FZN_NOTES_EDIT_LABELS) {
			content.labels = with->labels;
			content.labels_len = with->labels_len;
		}
		/* A NEW BLOB UNDER A NEW KEY: `blob/` forbids a key reused across
		 * different contents. */
		err = seal_payload(author, h.content_type, &content, &meta.content);
		if (err == FZN_NOTES_OK)
			err = wrapped(author->store, id, &meta.content, &meta.content);
		if (err != FZN_NOTES_OK)
			return err;
	}
	if (which & FZN_NOTES_EDIT_COLOUR)
		meta.colour = with->colour;
	meta.flags = (uint8_t)((meta.flags | set) & ~clear);
	/* The note's own creation time; only the edit time moves. */
	meta.edited_at_ms = now_ms;
	/* SAME PARENT, SAME ORDER, SAME TYPE: an edit is not a move. */
	return write_note(author, id, h.parent, h.order, h.content_type, &meta, now_ms);
}

/* WHETHER `id` IS `at` OR ABOVE IT, by any writer's claim on the way up:
 * moving `id` under `at` would then make a cycle, and the notes in it would
 * leave the tree for the top of the view. Each claim is walked once, so a
 * cycle the view already holds -- concurrent moves on two hosts can make
 * one -- ends the walk. sec 453. */
static int above(const fzn_notes_view_t *view, const uint8_t id[FZN_TREE_ID_LEN],
                 const uint8_t at[FZN_TREE_ID_LEN])
{
	static uint8_t seen[FZN_NOTES_MAX];
	static size_t stack[FZN_NOTES_MAX];
	size_t top = 0, i, k;

	if (memcmp(id, at, FZN_TREE_ID_LEN) == 0)
		return 1;
	memset(seen, 0, sizeof(seen));
	for (i = 0; i < view->count; i++)
		if (memcmp(view->nodes[i].id, at, FZN_TREE_ID_LEN) == 0) {
			seen[i] = 1;
			stack[top++] = i;
		}
	while (top) {
		const uint8_t *up = view->nodes[stack[--top]].parent;

		if (memcmp(up, id, FZN_TREE_ID_LEN) == 0)
			return 1;
		if (is_root(up))
			continue;
		for (k = 0; k < view->count; k++)
			if (!seen[k] && memcmp(view->nodes[k].id, up, FZN_TREE_ID_LEN) == 0) {
				seen[k] = 1;
				stack[top++] = k;
			}
	}
	return 0;
}

fzn_notes_err_t fzn_notes_move(const fzn_notes_author_t *author,
                               const uint8_t id[FZN_TREE_ID_LEN],
                               const uint8_t parent[FZN_TREE_ID_LEN], uint64_t now_ms)
{
	static held_t h;
	fzn_note_meta_t meta;
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
	/* NOT UNDER ITS OWN DESCENDANT, as not under itself. */
	if (above(author->view, id, parent))
		return FZN_NOTES_ERR_MALFORMED;
	err = order_after(author->view, parent, id, &order);
	if (err != FZN_NOTES_OK)
		return err;
	/* THE SAME CONTENT, so the same reference: a move is placement only. */
	meta = h.meta;
	meta.edited_at_ms = now_ms;
	return write_note(author, id, parent, order, h.content_type, &meta, now_ms);
}
