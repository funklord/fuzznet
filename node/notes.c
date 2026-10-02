/* See notes.h. */

#define _POSIX_C_SOURCE 200809L

#include "notes.h"

#include "../contact/contact.h"
#include "../notes/received.h"
#include "../notes/share.h"
#include "../notes/text.h"

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ID_HEX (FZN_TREE_ID_LEN * 2u)

static const char HEX[] = "0123456789abcdef";

/* The tree this node reads back: every claim at full size, so it is static
 * and shared by the verbs, which the node's one loop runs one at a time. */
static fzn_notes_view_t view;

static size_t answer(char *reply, size_t cap, fzn_reply_t kind, const char *detail, size_t len)
{
	size_t out = 0;

	if (fzn_reply_compose((uint8_t *)reply, cap, &out, kind, (const uint8_t *)detail, len)
	    != FZN_COMPOSE_OK)
		return 0;
	return out;
}

static size_t say(char *reply, size_t cap, fzn_reply_t kind, const char *detail)
{
	return answer(reply, cap, kind, detail, detail ? strlen(detail) : 0u);
}

static size_t refuse(char *reply, size_t cap, fzn_notes_err_t err)
{
	return say(reply, cap,
	           err == FZN_NOTES_ERR_MALFORMED ? FZN_REPLY_MALFORMED : FZN_REPLY_ERROR,
	           fzn_notes_err_str(err));
}

/* The next space-separated word, and what follows it. */
static int word(const uint8_t **at, size_t *left, const uint8_t **w, size_t *w_len)
{
	size_t i = 0;

	while (*left && **at == ' ') {
		(*at)++;
		(*left)--;
	}
	if (!*left)
		return 0;
	while (i < *left && (*at)[i] != ' ')
		i++;
	*w = *at;
	*w_len = i;
	*at += i;
	*left -= i;
	if (*left) {
		(*at)++;
		(*left)--;
	}
	return 1;
}

static int is_word(const uint8_t *w, size_t w_len, const char *s)
{
	return w_len == strlen(s) && memcmp(w, s, w_len) == 0;
}

/* A note's id in hex, or `top` for the root. */
static int parse_id(const uint8_t *w, size_t w_len, uint8_t out[FZN_TREE_ID_LEN])
{
	size_t i;

	if (is_word(w, w_len, "top")) {
		memset(out, 0, FZN_TREE_ID_LEN);
		return 1;
	}
	if (w_len != ID_HEX)
		return 0;
	for (i = 0; i < w_len; i++) {
		const char *h = memchr(HEX, w[i], 16u);

		if (!h)
			return 0;
		if (i % 2u == 0u)
			out[i / 2u] = (uint8_t)((h - HEX) << 4);
		else
			out[i / 2u] |= (uint8_t)(h - HEX);
	}
	return 1;
}

static void hex_of(const uint8_t *b, size_t n, char *out)
{
	size_t i;

	for (i = 0; i < n; i++) {
		out[i * 2u] = HEX[b[i] >> 4];
		out[(i * 2u) + 1u] = HEX[b[i] & 15u];
	}
}

/* Escape `n` bytes into `out`, at most `cap`; how many input bytes went in. */
static size_t escape(const uint8_t *b, size_t n, char *out, size_t cap, size_t *written)
{
	size_t i, w = 0;

	for (i = 0; i < n; i++) {
		uint8_t c = b[i];

		if (c <= 0x20u || c == '%' || c == ',' || c == 0x7fu) {
			if (cap - w < 3u)
				break;
			out[w++] = '%';
			out[w++] = HEX[c >> 4];
			out[w++] = HEX[c & 15u];
		} else {
			if (cap - w < 1u)
				break;
			out[w++] = (char)c;
		}
	}
	*written = w;
	return i;
}

static uint64_t now(const fzn_node_notes_t *n)
{
	return n->now_ms ? n->now_ms() : 0u;
}

fzn_notes_err_t fzn_node_notes_init(fzn_node_notes_t *notes, const fzn_persist_ops_t *store,
                                    const fzn_hash_ops_t *hash, const fzn_sign_ops_t *sign,
                                    const fzn_random_ops_t *rng,
                                    const uint8_t self[FZN_PUBKEY_LEN],
                                    const uint8_t (*peers)[FZN_PUBKEY_LEN], size_t peer_count,
                                    const uint8_t (*pulls)[FZN_PUBKEY_LEN], size_t pull_count,
                                    uint64_t (*now_ms)(void))
{
	size_t i;
	fzn_notes_err_t err;

	if (!notes || !sign || !rng || !self || (peer_count && !peers) || (pull_count && !pulls)
	    || peer_count > FZN_NODE_NOTES_WRITERS || pull_count > FZN_NODE_NOTES_WRITERS)
		return FZN_NOTES_ERR_MALFORMED;
	memset(notes, 0, sizeof(*notes));
	err = fzn_notes_store_init(&notes->store, store, hash);
	if (err != FZN_NOTES_OK)
		return err;
	memcpy(notes->admitted[0].key, self, FZN_PUBKEY_LEN);
	for (i = 0; i < peer_count; i++)
		memcpy(notes->admitted[i + 1u].key, peers[i], FZN_PUBKEY_LEN);
	notes->admitted_count = peer_count + 1u;
	for (i = 0; i < pull_count; i++)
		memcpy(notes->pulls[i].key, pulls[i], FZN_PUBKEY_LEN);
	notes->pull_count = pull_count;
	notes->author.store = &notes->store;
	notes->author.view = &view;
	notes->author.issuer = notes->admitted[0].key;
	notes->author.sign = sign;
	notes->author.rng = rng;
	notes->author.policy = fzn_notes_policy_writers(notes->admitted, notes->admitted_count);
	notes->now_ms = now_ms;
	return FZN_NOTES_OK;
}

/* The claim on `id` to show: this node's own, else the first held. */
static const fzn_tree_node_t *find(const fzn_node_notes_t *n, const uint8_t id[FZN_TREE_ID_LEN],
                                   size_t *at)
{
	size_t i, first = view.count;

	for (i = 0; i < view.count; i++) {
		if (memcmp(view.nodes[i].id, id, FZN_TREE_ID_LEN) != 0)
			continue;
		if (memcmp(view.writers[i], n->author.issuer, FZN_PUBKEY_LEN) == 0) {
			*at = i;
			return &view.nodes[i];
		}
		if (first == view.count)
			first = i;
	}
	if (first == view.count)
		return NULL;
	*at = first;
	return &view.nodes[first];
}

/* Checklists, below: `get` and `set` reach them. sec 442. */
static size_t get_items(fzn_node_notes_t *n, const fzn_notes_store_t *store,
                        const uint8_t id[FZN_TREE_ID_LEN], const uint8_t *at, size_t left,
                        char *reply, size_t cap);
static size_t set_item(fzn_node_notes_t *n, const uint8_t id[FZN_TREE_ID_LEN], const uint8_t *at,
                       size_t left, char *reply, size_t cap);

/* ---- add ----------------------------------------------------------------- */

static size_t add(fzn_node_notes_t *n, uint16_t type, const uint8_t *at, size_t left, char *reply,
                  size_t cap)
{
	uint8_t parent[FZN_TREE_ID_LEN], id[FZN_TREE_ID_LEN];
	const uint8_t *w;
	size_t w_len;
	char hex[ID_HEX];
	fzn_note_t note;
	fzn_notes_err_t err;

	if (!word(&at, &left, &w, &w_len) || !parse_id(w, w_len, parent))
		return say(reply, cap, FZN_REPLY_MALFORMED, "add note PARENT TITLE");
	memset(&note, 0, sizeof(note));
	note.title = at;
	note.title_len = left;
	err = fzn_notes_create(&n->author, parent, type, &note, now(n), id);
	if (err != FZN_NOTES_OK)
		return refuse(reply, cap, err);
	hex_of(id, sizeof(id), hex);
	return answer(reply, cap, FZN_REPLY_OK, hex, sizeof(hex));
}

/* ---- set ----------------------------------------------------------------- */

static size_t set_text(fzn_node_notes_t *n, const uint8_t id[FZN_TREE_ID_LEN],
                       const uint8_t *text, size_t len, char *reply, size_t cap)
{
	fzn_note_t with;
	fzn_notes_err_t err;

	memset(&with, 0, sizeof(with));
	with.text = text;
	with.text_len = len;
	err = fzn_notes_edit(&n->author, id, FZN_NOTES_EDIT_TEXT, &with, 0u, 0u, now(n));
	/* TOO LONG FOR INLINE, AND A SEAL TO HAND: the text goes into a blob
	 * and the note carries its reference. Nothing is cut to make it fit. */
	if (err == FZN_NOTES_ERR_MALFORMED && n->seal && len > 0u) {
		fzn_note_blob_ref_t ref;
		uint8_t field[FZN_NOTE_BLOB_REF_LEN];

		if (!n->seal(n->text_ctx, text, len, &ref)
		    || fzn_note_blob_ref_write(&ref, field) != FZN_NOTE_OK)
			return say(reply, cap, FZN_REPLY_ERROR, "the text would not seal");
		with.text = field;
		with.text_len = sizeof(field);
		with.flags = FZN_NOTE_FLAG_TEXT_IS_BLOB;
		err = fzn_notes_edit(&n->author, id, FZN_NOTES_EDIT_TEXT, &with, 0u, 0u, now(n));
	} else if (err == FZN_NOTES_ERR_MALFORMED && len > 0u) {
		/* The request was well formed; the note cannot hold it. */
		return say(reply, cap, FZN_REPLY_ERROR, "too long to hold inline, and no blob store");
	}
	if (err != FZN_NOTES_OK)
		return refuse(reply, cap, err);
	return say(reply, cap, FZN_REPLY_OK, NULL);
}

static size_t read_file(const uint8_t *path, size_t path_len, uint8_t *out, size_t cap,
                        size_t *len)
{
	char name[512];
	FILE *f;

	if (path_len == 0u || path_len >= sizeof(name) || memchr(path, '\0', path_len))
		return 0;
	memcpy(name, path, path_len);
	name[path_len] = '\0';
	f = fopen(name, "rb");
	if (!f)
		return 0;
	*len = fread(out, 1u, cap, f);
	(void)fclose(f);
	return 1;
}

static size_t set(fzn_node_notes_t *n, const uint8_t *at, size_t left, char *reply, size_t cap)
{
	static uint8_t text[FZN_NOTE_TEXT_MAX + 1u];
	static const struct {
		const char *word;
		uint8_t set, clear;
	} FLAGS[] = {
		{ "pin", FZN_NOTE_FLAG_PINNED, 0u },     { "unpin", 0u, FZN_NOTE_FLAG_PINNED },
		{ "trash", FZN_NOTE_FLAG_TRASHED, 0u },  { "untrash", 0u, FZN_NOTE_FLAG_TRASHED },
		{ "archive", FZN_NOTE_FLAG_ARCHIVED, 0u }, { "unarchive", 0u, FZN_NOTE_FLAG_ARCHIVED },
	};
	uint8_t id[FZN_TREE_ID_LEN], parent[FZN_TREE_ID_LEN];
	const uint8_t *w, *field;
	size_t w_len, field_len, i, len = 0;
	fzn_note_t with;
	fzn_notes_err_t err;

	if (!word(&at, &left, &w, &w_len) || !parse_id(w, w_len, id)
	    || !word(&at, &left, &field, &field_len))
		return say(reply, cap, FZN_REPLY_MALFORMED, "set note ID FIELD [VALUE]");
	for (i = 0; i < sizeof(FLAGS) / sizeof(FLAGS[0]); i++)
		if (is_word(field, field_len, FLAGS[i].word)) {
			err = fzn_notes_edit(&n->author, id, 0u, NULL, FLAGS[i].set, FLAGS[i].clear,
			                     now(n));
			return err == FZN_NOTES_OK ? say(reply, cap, FZN_REPLY_OK, NULL)
			                           : refuse(reply, cap, err);
		}
	if (is_word(field, field_len, "title")) {
		memset(&with, 0, sizeof(with));
		with.title = at;
		with.title_len = left;
		err = fzn_notes_edit(&n->author, id, FZN_NOTES_EDIT_TITLE, &with, 0u, 0u, now(n));
		return err == FZN_NOTES_OK ? say(reply, cap, FZN_REPLY_OK, NULL)
		                           : refuse(reply, cap, err);
	}
	/* A CHECKLIST'S TEXT IS ITS ITEMS, so its items change through the
	 * item verbs only. The edit checks a list's shape, and refuses bytes
	 * that are no items as malformed -- which `set_text` reads as too long
	 * for inline and seals into a blob, whose items nothing checks. sec 442. */
	if (is_word(field, field_len, "text") || is_word(field, field_len, "file")) {
		size_t idx = 0;
		const fzn_tree_node_t *node;

		if (fzn_notes_view_load(&n->store, &view) == FZN_NOTES_OK
		    && (node = find(n, id, &idx)) != NULL && node->content_type == FZN_NOTE_TYPE_LIST)
			return say(reply, cap, FZN_REPLY_ERROR,
			           "a checklist's items change through the item verbs");
	}
	if (is_word(field, field_len, "text"))
		return set_text(n, id, at, left, reply, cap);
	if (is_word(field, field_len, "item"))
		return set_item(n, id, at, left, reply, cap);
	if (is_word(field, field_len, "file")) {
		/* ONE BYTE PAST THE BOUND is read, so a file at the bound and one
		 * past it are told apart; the second is refused, not cut. */
		if (!read_file(at, left, text, sizeof(text), &len))
			return say(reply, cap, FZN_REPLY_ERROR, "cannot read that file");
		if (len > FZN_NOTE_TEXT_MAX)
			return say(reply, cap, FZN_REPLY_ERROR, "past 256 KiB");
		return set_text(n, id, text, len, reply, cap);
	}
	if (is_word(field, field_len, "parent")) {
		if (!word(&at, &left, &w, &w_len) || !parse_id(w, w_len, parent))
			return say(reply, cap, FZN_REPLY_MALFORMED, "set note ID parent PARENT");
		err = fzn_notes_move(&n->author, id, parent, now(n));
		return err == FZN_NOTES_OK ? say(reply, cap, FZN_REPLY_OK, NULL)
		                           : refuse(reply, cap, err);
	}
	return say(reply, cap, FZN_REPLY_MALFORMED, "no such field");
}

/* ---- list ---------------------------------------------------------------- */

/* `store` is this node's notes, or a sharer's tree when `shared` is set
 * (sec 437): then the top is the shared subtrees' roots. */
static size_t list(const fzn_notes_store_t *store, int shared, const uint8_t *at, size_t left,
                   char *reply, size_t cap)
{
	static const fzn_tree_node_t *out[FZN_NOTES_MAX];
	static uint8_t contested[FZN_NOTES_MAX][FZN_TREE_ID_LEN];
	static char detail[FZN_REPLY_MAX];
	size_t limit = (cap > 0u && cap - 1u < FZN_REPLY_MAX) ? cap - 1u : FZN_REPLY_MAX;
	uint8_t parent[FZN_TREE_ID_LEN];
	const uint8_t *w;
	size_t w_len, count = 0, from = 0, used, i, j, n_contested;
	int cut = 0, k;
	fzn_notes_err_t err;

	if (!word(&at, &left, &w, &w_len) || !parse_id(w, w_len, parent))
		return say(reply, cap, FZN_REPLY_MALFORMED, "list note PARENT [FROM]");
	if (word(&at, &left, &w, &w_len))
		for (i = 0; i < w_len; i++) {
			if (w[i] < '0' || w[i] > '9' || from > FZN_NOTES_MAX)
				return say(reply, cap, FZN_REPLY_MALFORMED, "not an index");
			from = (from * 10u) + (size_t)(w[i] - '0');
		}
	err = fzn_notes_view_load(store, &view);
	if (err != FZN_NOTES_OK)
		return refuse(reply, cap, err);
	if (fzn_tree_is_root(parent) && shared)
		count = fzn_notes_received_roots(&view, out, FZN_NOTES_MAX);
	else
		err = fzn_tree_is_root(parent)
		              ? fzn_notes_top_level(&view, out, FZN_NOTES_MAX, &count, &cut)
		              : fzn_notes_children(&view, parent, out, FZN_NOTES_MAX, &count, &cut);
	if (err != FZN_NOTES_OK)
		return refuse(reply, cap, err);
	/* A NOTE PENDING PURGE IS LEFT OUT: one a user emptied must not come
	 * back into view because a node that holds it has not answered yet.
	 * sec 434. */
	for (i = 0, j = 0; i < count; i++)
		if (!fzn_notes_purge_pending(store, out[i]->id))
			out[j++] = out[i];
	count = j;
	if (from > count)
		return say(reply, cap, FZN_REPLY_MALFORMED, "past the last note");
	n_contested = fzn_notes_contested(&view, contested, FZN_NOTES_MAX);
	/* The head, TOTAL FROM, then as many items as fit. */
	k = snprintf(detail, sizeof(detail), "%zu %zu", count, from);
	if (k < 0 || (size_t)k >= limit)
		return 0;
	used = (size_t)k;
	for (i = from; i < count; i++) {
		const fzn_tree_node_t *node = out[i];
		size_t idx = (size_t)(node - view.nodes), wrote = 0, took;
		char item[ID_HEX + 32u];
		int is_contested = 0, m;
		fzn_note_t note;
		const uint8_t *title = (const uint8_t *)"";
		size_t title_len = 0;
		uint8_t flags = 0;

		for (j = 0; j < n_contested && j < FZN_NOTES_MAX; j++)
			is_contested |= memcmp(contested[j], node->id, FZN_TREE_ID_LEN) == 0;
		if (fzn_note_open(node->content_type, node->content, node->content_len, &note)
		    == FZN_NOTE_OK) {
			title = note.title;
			title_len = note.title_len;
			flags = note.flags;
		}
		hex_of(node->id, FZN_TREE_ID_LEN, item);
		m = snprintf(item + ID_HEX, sizeof(item) - ID_HEX, ",%u,%u,%d,%d,",
		             (unsigned)node->content_type, (unsigned)flags,
		             fzn_notes_reachable(&view, idx), is_contested);
		if (m < 0 || (size_t)m >= sizeof(item) - ID_HEX)
			return 0;
		/* An item goes in whole or not at all: a page ends where the
		 * next one does not fit, and the caller asks from there. */
		if (limit - used < 1u + ID_HEX + (size_t)m + 1u)
			break;
		detail[used] = ' ';
		memcpy(detail + used + 1u, item, ID_HEX + (size_t)m);
		took = escape(title, title_len, detail + used + 1u + ID_HEX + (size_t)m,
		              limit - used - 1u - ID_HEX - (size_t)m, &wrote);
		if (took < title_len)
			break;
		used += 1u + ID_HEX + (size_t)m + wrote;
	}
	return answer(reply, cap, FZN_REPLY_OK, detail, used);
}

/* ---- get ----------------------------------------------------------------- */

static size_t get(fzn_node_notes_t *n, const fzn_notes_store_t *store, const uint8_t *at,
                  size_t left, char *reply, size_t cap)
{
	static uint8_t text[FZN_NOTE_TEXT_MAX];
	static char detail[FZN_REPLY_MAX];
	size_t limit = (cap > 0u && cap - 1u < FZN_REPLY_MAX) ? cap - 1u : FZN_REPLY_MAX;
	uint8_t id[FZN_TREE_ID_LEN];
	const uint8_t *w, *field;
	size_t w_len, field_len, idx = 0, used, wrote = 0, from = 0, i;
	const fzn_tree_node_t *node;
	fzn_note_t note;
	fzn_notes_err_t err;
	int k;

	if (!word(&at, &left, &w, &w_len) || !parse_id(w, w_len, id) || fzn_tree_is_root(id))
		return say(reply, cap, FZN_REPLY_MALFORMED, "get note ID [text [FROM] | file PATH]");
	err = fzn_notes_view_load(store, &view);
	if (err != FZN_NOTES_OK)
		return refuse(reply, cap, err);
	node = find(n, id, &idx);
	if (!node)
		return refuse(reply, cap, FZN_NOTES_ERR_ABSENT);
	if (fzn_note_open(node->content_type, node->content, node->content_len, &note)
	    != FZN_NOTE_OK)
		return refuse(reply, cap, FZN_NOTES_ERR_SHAPE);

	if (!word(&at, &left, &field, &field_len)) {
		/* THE FIELDS: type, flags, created, edited, parent, the text's
		 * length and whether it is a blob, then the title, escaped. */
		fzn_note_blob_ref_t ref;
		int blob = fzn_note_blob_ref(&note, &ref) == FZN_NOTE_OK;
		char parent[ID_HEX + 1u];

		hex_of(node->parent, FZN_TREE_ID_LEN, parent);
		parent[ID_HEX] = '\0';
		k = snprintf(detail, sizeof(detail), "%u %u %llu %llu %s %s %llu ",
		             (unsigned)node->content_type, (unsigned)note.flags,
		             (unsigned long long)note.created_at_ms,
		             (unsigned long long)note.edited_at_ms, parent, blob ? "blob" : "inline",
		             (unsigned long long)(blob ? ref.length : note.text_len));
		if (k < 0 || (size_t)k >= limit)
			return 0;
		used = (size_t)k;
		if (escape(note.title, note.title_len, detail + used, limit - used, &wrote)
		    < note.title_len)
			return say(reply, cap, FZN_REPLY_ERROR, "the title does not fit a reply");
		return answer(reply, cap, FZN_REPLY_OK, detail, used + wrote);
	}
	if (is_word(field, field_len, "items"))
		return get_items(n, store, id, at, left, reply, cap);
	if (is_word(field, field_len, "text")) {
		if (note.flags & FZN_NOTE_FLAG_TEXT_IS_BLOB)
			return say(reply, cap, FZN_REPLY_ERROR, "a blob: get note ID file PATH");
		if (word(&at, &left, &w, &w_len))
			for (i = 0; i < w_len; i++) {
				if (w[i] < '0' || w[i] > '9' || from > FZN_NOTE_TEXT_MAX)
					return say(reply, cap, FZN_REPLY_MALFORMED, "not an index");
				from = (from * 10u) + (size_t)(w[i] - '0');
			}
		if (from > note.text_len)
			return say(reply, cap, FZN_REPLY_MALFORMED, "past the text");
		k = snprintf(detail, sizeof(detail), "%zu %zu ", note.text_len, from);
		if (k < 0 || (size_t)k >= limit)
			return 0;
		(void)escape(note.text + from, note.text_len - from, detail + k, limit - (size_t)k,
		             &wrote);
		return answer(reply, cap, FZN_REPLY_OK, detail, (size_t)k + wrote);
	}
	if (is_word(field, field_len, "file")) {
		const uint8_t *body = note.text;
		size_t body_len = note.text_len;
		char name[512];
		int fd, ok;

		if (note.flags & FZN_NOTE_FLAG_TEXT_IS_BLOB) {
			fzn_note_blob_ref_t ref;

			if (!n->open || fzn_note_blob_ref(&note, &ref) != FZN_NOTE_OK
			    || !n->open(n->text_ctx, &ref, text, sizeof(text), &body_len))
				return say(reply, cap, FZN_REPLY_ERROR, "the text is not here yet");
			body = text;
		}
		if (left == 0u || left >= sizeof(name) || memchr(at, '\0', left))
			return say(reply, cap, FZN_REPLY_MALFORMED, "get note ID file PATH");
		memcpy(name, at, left);
		name[left] = '\0';
		/* 0600: a note is as private as the store it came from. */
		fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (fd < 0)
			return say(reply, cap, FZN_REPLY_ERROR, "cannot write that file");
		ok = write(fd, body, body_len) == (ssize_t)body_len;
		ok = (close(fd) == 0) && ok;
		if (!ok)
			return say(reply, cap, FZN_REPLY_ERROR, "the file did not write whole");
		k = snprintf(detail, sizeof(detail), "%zu", body_len);
		return answer(reply, cap, FZN_REPLY_OK, detail, k > 0 ? (size_t)k : 0u);
	}
	return say(reply, cap, FZN_REPLY_MALFORMED, "no such field");
}

/* ---- checklists, sec 442 ------------------------------------------------- */

static uint8_t items_buf[FZN_NOTE_TEXT_MAX];
static uint8_t fresh_buf[FZN_NOTE_TEXT_MAX];

/* A checklist's items, wherever they are: inline in the note, or in its blob
 * opened through the node's text hook -- a long list is sealed as a long
 * text is. ABSENT when the blob is not here. */
static fzn_notes_err_t list_items(fzn_node_notes_t *n, const fzn_note_t *note, uint8_t *out,
                                  size_t cap, size_t *len)
{
	fzn_note_blob_ref_t ref;

	*len = 0;
	if (note->flags & FZN_NOTE_FLAG_TEXT_IS_BLOB) {
		if (!n->open || fzn_note_blob_ref(note, &ref) != FZN_NOTE_OK
		    || !n->open(n->text_ctx, &ref, out, cap, len))
			return FZN_NOTES_ERR_ABSENT;
		return FZN_NOTES_OK;
	}
	if (note->text_len > cap)
		return FZN_NOTES_ERR_SHAPE;
	if (note->text_len)
		memcpy(out, note->text, note->text_len);
	*len = note->text_len;
	return FZN_NOTES_OK;
}

/* The next item of `len` bytes of items, as a list note's text holds them. */
static fzn_note_err_t next_item(const uint8_t *bytes, size_t len, size_t *cursor,
                                fzn_note_item_t *item)
{
	fzn_note_t held;

	memset(&held, 0, sizeof(held));
	held.text = bytes;
	held.text_len = len;
	return fzn_note_item_next(&held, cursor, item);
}

/* The checklist `id` in `store`, with its items in `items_buf`. 0 when it
 * opened, else the reply saying why. */
static size_t open_list(fzn_node_notes_t *n, const fzn_notes_store_t *store,
                        const uint8_t id[FZN_TREE_ID_LEN], fzn_note_t *note, size_t *items_len,
                        char *reply, size_t cap)
{
	const fzn_tree_node_t *node;
	size_t idx = 0;
	fzn_notes_err_t err;

	err = fzn_notes_view_load(store, &view);
	if (err != FZN_NOTES_OK)
		return refuse(reply, cap, err);
	node = find(n, id, &idx);
	if (!node)
		return refuse(reply, cap, FZN_NOTES_ERR_ABSENT);
	if (node->content_type != FZN_NOTE_TYPE_LIST
	    || fzn_note_open(node->content_type, node->content, node->content_len, note)
	               != FZN_NOTE_OK)
		return say(reply, cap, FZN_REPLY_ERROR, "not a checklist");
	err = list_items(n, note, items_buf, sizeof(items_buf), items_len);
	if (err == FZN_NOTES_ERR_ABSENT)
		return say(reply, cap, FZN_REPLY_ERROR, "the items are not here yet");
	if (err != FZN_NOTES_OK)
		return refuse(reply, cap, err);
	return 0;
}

/* `get note ID items [FROM]`: `ok TOTAL FROM FLAGS,TEXT ...`, a page at a
 * time, each text escaped so an item stays one field. */
static size_t get_items(fzn_node_notes_t *n, const fzn_notes_store_t *store,
                        const uint8_t id[FZN_TREE_ID_LEN], const uint8_t *at, size_t left,
                        char *reply, size_t cap)
{
	static char detail[FZN_REPLY_MAX];
	size_t limit = (cap > 0u && cap - 1u < FZN_REPLY_MAX) ? cap - 1u : FZN_REPLY_MAX;
	size_t items_len = 0, cursor = 0, total = 0, from = 0, i, used, r;
	const uint8_t *w;
	size_t w_len;
	fzn_note_item_t item;
	fzn_note_t note;
	int k;

	if (word(&at, &left, &w, &w_len))
		for (i = 0; i < w_len; i++) {
			if (w[i] < '0' || w[i] > '9' || from > FZN_NOTE_TEXT_MAX)
				return say(reply, cap, FZN_REPLY_MALFORMED, "not an index");
			from = (from * 10u) + (size_t)(w[i] - '0');
		}
	r = open_list(n, store, id, &note, &items_len, reply, cap);
	if (r)
		return r;
	while (next_item(items_buf, items_len, &cursor, &item) == FZN_NOTE_OK)
		total++;
	if (from > total)
		return say(reply, cap, FZN_REPLY_MALFORMED, "past the last item");
	k = snprintf(detail, sizeof(detail), "%zu %zu", total, from);
	if (k < 0 || (size_t)k >= limit)
		return 0;
	used = (size_t)k;
	cursor = 0;
	for (i = 0; next_item(items_buf, items_len, &cursor, &item) == FZN_NOTE_OK; i++) {
		size_t wrote = 0;
		char head[8];
		int m;

		if (i < from)
			continue;
		m = snprintf(head, sizeof(head), " %u,", (unsigned)item.flags);
		if (m < 0 || limit - used < (size_t)m + 1u)
			break;
		/* AN ITEM WHOLE OR NOT AT ALL: the page ends where the next one
		 * does not fit, and the caller asks from there. */
		if (escape(item.text, item.text_len, detail + used + (size_t)m,
		           limit - used - (size_t)m, &wrote)
		    < item.text_len)
			break;
		memcpy(detail + used, head, (size_t)m);
		used += (size_t)m + wrote;
	}
	return answer(reply, cap, FZN_REPLY_OK, detail, used);
}

/* Rewrite the checklist `id`'s items: every item as it was, except item
 * `which` -- changed to `flags` and `text`, or left out when `drop` -- and
 * a new one at the end when `which` is the count. */
static size_t rewrite_items(fzn_node_notes_t *n, const uint8_t id[FZN_TREE_ID_LEN], size_t which,
                            int drop, int set_flags, uint8_t flags, const uint8_t *text,
                            size_t text_len, char *reply, size_t cap)
{
	size_t items_len = 0, cursor = 0, used = 0, i, r;
	fzn_note_item_t item;
	fzn_note_t note;
	int found = 0;

	r = open_list(n, &n->store, id, &note, &items_len, reply, cap);
	if (r)
		return r;
	for (i = 0; next_item(items_buf, items_len, &cursor, &item) == FZN_NOTE_OK; i++) {
		uint8_t f = item.flags;
		const uint8_t *t = item.text;
		size_t t_len = item.text_len;

		if (i == which) {
			found = 1;
			if (drop)
				continue;
			if (set_flags)
				f = flags;
			if (text) {
				t = text;
				t_len = text_len;
			}
		}
		if (fzn_note_item_put(fresh_buf, sizeof(fresh_buf), &used, f, t, t_len) != FZN_NOTE_OK)
			return say(reply, cap, FZN_REPLY_ERROR, "past what a note can hold");
	}
	if (!found) {
		/* ONE PAST THE LAST IS AN APPEND; anything further is no item. */
		if (which != i || drop || !text)
			return say(reply, cap, FZN_REPLY_ERROR, "no such item");
		if (fzn_note_item_put(fresh_buf, sizeof(fresh_buf), &used, flags, text, text_len)
		    != FZN_NOTE_OK)
			return say(reply, cap, FZN_REPLY_ERROR, "past what a note can hold");
	}
	return set_text(n, id, fresh_buf, used, reply, cap);
}

static int parse_index(const uint8_t *w, size_t w_len, size_t *out)
{
	size_t i, v = 0;

	if (w_len == 0u || w_len > 6u)
		return 0;
	for (i = 0; i < w_len; i++) {
		if (w[i] < '0' || w[i] > '9')
			return 0;
		v = (v * 10u) + (size_t)(w[i] - '0');
	}
	*out = v;
	return 1;
}

/* `set note ID item N check|uncheck|text TEXT`. */
static size_t set_item(fzn_node_notes_t *n, const uint8_t id[FZN_TREE_ID_LEN], const uint8_t *at,
                       size_t left, char *reply, size_t cap)
{
	const uint8_t *w, *how;
	size_t w_len, how_len, which = 0;
	static const char USAGE[] = "set note ID item N check|uncheck|text TEXT";

	if (!word(&at, &left, &w, &w_len) || !parse_index(w, w_len, &which)
	    || !word(&at, &left, &how, &how_len))
		return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
	if (is_word(how, how_len, "check") || is_word(how, how_len, "uncheck"))
		return rewrite_items(n, id, which, 0, 1,
		                     is_word(how, how_len, "check") ? FZN_NOTE_ITEM_FLAG_CHECKED : 0u,
		                     NULL, 0u, reply, cap);
	if (is_word(how, how_len, "text") && left)
		return rewrite_items(n, id, which, 0, 0, 0u, at, left, reply, cap);
	return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
}

/* `add item ID TEXT` appends; `remove item ID N` removes. */
static size_t change_item(fzn_node_notes_t *n, int add, const uint8_t *at, size_t left,
                          char *reply, size_t cap)
{
	uint8_t id[FZN_TREE_ID_LEN];
	const uint8_t *w;
	size_t w_len, which = 0, items_len = 0, cursor = 0, count = 0, r;
	fzn_note_item_t item;
	fzn_note_t note;

	if (!word(&at, &left, &w, &w_len) || !parse_id(w, w_len, id) || fzn_tree_is_root(id))
		return say(reply, cap, FZN_REPLY_MALFORMED,
		           add ? "add item ID TEXT" : "remove item ID N");
	if (!add) {
		if (!word(&at, &left, &w, &w_len) || !parse_index(w, w_len, &which))
			return say(reply, cap, FZN_REPLY_MALFORMED, "remove item ID N");
		return rewrite_items(n, id, which, 1, 0, 0u, NULL, 0u, reply, cap);
	}
	if (!left)
		return say(reply, cap, FZN_REPLY_MALFORMED, "add item ID TEXT");
	r = open_list(n, &n->store, id, &note, &items_len, reply, cap);
	if (r)
		return r;
	while (next_item(items_buf, items_len, &cursor, &item) == FZN_NOTE_OK)
		count++;
	return rewrite_items(n, id, count, 0, 1, 0u, at, left, reply, cap);
}

/* ---- remove note trash --------------------------------------------------- */

static size_t empty_trash(fzn_node_notes_t *n, char *reply, size_t cap)
{
	static uint8_t partners[FZN_NODE_NOTES_WRITERS][FZN_PUBKEY_LEN];
	static fzn_notes_writer_t asked[2u * FZN_NODE_NOTES_WRITERS];
	size_t queued = 0, pending = 0, i, n_partners = 0, n_asked = 0;
	char detail[48];
	fzn_notes_err_t err;
	int k;

	/* EVERY NODE HOLDING COPIES IS ASKED: those this one pulls from, and
	 * its partners, which pulled from it. A store that cannot list its
	 * partners refuses, rather than purging past nodes it forgot. */
	if (fzn_notes_partners(&n->store, partners, FZN_NODE_NOTES_WRITERS, &n_partners)
	    != FZN_NOTES_OK)
		return say(reply, cap, FZN_REPLY_ERROR, "the partners would not list");
	for (i = 0; i < n->pull_count; i++)
		asked[n_asked++] = n->pulls[i];
	for (i = 0; i < n_partners; i++) {
		uint64_t seen = 0;

		/* A PARTNER GONE A MONTH IS NOT PINNED: a purge waiting on a node
		 * that will never pull again would wait for ever. One whose time
		 * will not read is pinned, the side that keeps data. */
		if (fzn_notes_partner_seen_at(&n->store, partners[i], &seen) == FZN_NOTES_OK
		    && now(n) > seen && now(n) - seen > FZN_NODE_NOTES_PARTNER_AGE_MS)
			continue;
		memcpy(asked[n_asked++].key, partners[i], FZN_PUBKEY_LEN);
	}
	err = fzn_notes_purge_trash(&n->store, &view, n->author.issuer,
	                            fzn_notes_asking(asked, n_asked), now(n), &queued);
	if (err != FZN_NOTES_OK)
		return refuse(reply, cap, err);
	/* What is still waiting for consent, so the reply says which: the
	 * view is the one emptying loaded, before anything was erased. */
	for (i = 0; i < view.count; i++)
		if (memcmp(view.writers[i], n->author.issuer, FZN_PUBKEY_LEN) == 0
		    && fzn_notes_purge_pending(&n->store, view.nodes[i].id))
			pending++;
	if (pending)
		n->fresh = 1;
	k = snprintf(detail, sizeof(detail), "%zu %zu", queued, pending);
	return answer(reply, cap, FZN_REPLY_OK, detail, k > 0 ? (size_t)k : 0u);
}

/* `add share SUBTREE NAME` and `remove share SUBTREE NAME`: share the note
 * SUBTREE and everything below it with the contact NAME, or stop. sec 436.
 * The contact fetches through a grant, `grant share`, which is admin's. */
static size_t change_share(fzn_node_notes_t *n, int add, const uint8_t *at, size_t left,
                           char *reply, size_t cap)
{
	uint8_t subtree[FZN_TREE_ID_LEN];
	const uint8_t *w, *name;
	size_t w_len, name_len, i;
	fzn_contact_t contact;
	fzn_contact_err_t cerr;
	fzn_notes_err_t err;
	int found = 0;

	if (!word(&at, &left, &w, &w_len) || !parse_id(w, w_len, subtree)
	    || !word(&at, &left, &name, &name_len))
		return say(reply, cap, FZN_REPLY_MALFORMED,
		           add ? "add share SUBTREE NAME" : "remove share SUBTREE NAME");
	/* NOT THE TOP: sharing the root would be sharing every note this node
	 * will ever hold, which is not a subtree anybody chose. */
	if (fzn_tree_is_root(subtree))
		return say(reply, cap, FZN_REPLY_MALFORMED, "share a note, not the top");
	cerr = fzn_contact_find(n->store.ops, (const char *)name, name_len, &contact);
	if (cerr != FZN_CONTACT_OK)
		return say(reply, cap,
		           cerr == FZN_CONTACT_ERR_NAME ? FZN_REPLY_MALFORMED : FZN_REPLY_ERROR,
		           fzn_contact_err_str(cerr));
	if (!add) {
		err = fzn_notes_share_remove(&n->store, subtree, contact.key);
		return err == FZN_NOTES_OK ? say(reply, cap, FZN_REPLY_OK, NULL) : refuse(reply, cap, err);
	}
	/* A NOTE THIS NODE HOLDS, so a typo is refused rather than shared and
	 * served empty. */
	err = fzn_notes_view_load(&n->store, &view);
	if (err != FZN_NOTES_OK)
		return refuse(reply, cap, err);
	for (i = 0; i < view.count && !found; i++)
		found = memcmp(view.nodes[i].id, subtree, FZN_TREE_ID_LEN) == 0;
	if (!found)
		return refuse(reply, cap, FZN_NOTES_ERR_ABSENT);
	err = fzn_notes_share_add(&n->store, subtree, contact.key, now(n));
	return err == FZN_NOTES_OK ? say(reply, cap, FZN_REPLY_OK, NULL) : refuse(reply, cap, err);
}

/* `list share [FROM]`: `ok TOTAL FROM SUBTREE,NAME ...`, a page at a time; a
 * share whose contact was since forgotten names the contact's key. */
static size_t list_shares(fzn_node_notes_t *n, const uint8_t *at, size_t left, char *reply,
                          size_t cap)
{
	static fzn_notes_share_t all[FZN_NOTES_SHARES_MAX];
	static char detail[FZN_REPLY_MAX];
	size_t limit = (cap > 0u && cap - 1u < FZN_REPLY_MAX) ? cap - 1u : FZN_REPLY_MAX;
	size_t count = 0, from = 0, used, i;
	const uint8_t *w;
	size_t w_len;
	fzn_notes_err_t err;
	int m;

	if (word(&at, &left, &w, &w_len))
		for (i = 0; i < w_len; i++) {
			if (w[i] < '0' || w[i] > '9' || from > FZN_NOTES_SHARES_MAX)
				return say(reply, cap, FZN_REPLY_MALFORMED, "not an index");
			from = (from * 10u) + (size_t)(w[i] - '0');
		}
	err = fzn_notes_share_list(&n->store, all, FZN_NOTES_SHARES_MAX, &count);
	if (err != FZN_NOTES_OK)
		return refuse(reply, cap, err);
	if (from > count)
		return say(reply, cap, FZN_REPLY_MALFORMED, "past the last share");
	m = snprintf(detail, sizeof(detail), "%zu %zu", count, from);
	if (m < 0 || (size_t)m >= limit)
		return 0;
	used = (size_t)m;
	for (i = from; i < count; i++) {
		fzn_contact_t contact;
		char who[FZN_PUBKEY_LEN * 2u];
		size_t who_len;

		if (fzn_contact_get(n->store.ops, all[i].contact, &contact) == FZN_CONTACT_OK) {
			memcpy(who, contact.name, contact.name_len);
			who_len = contact.name_len;
		} else {
			hex_of(all[i].contact, FZN_PUBKEY_LEN, who);
			who_len = sizeof(who);
		}
		if (limit - used < 1u + ID_HEX + 1u + who_len)
			break;
		detail[used++] = ' ';
		hex_of(all[i].subtree, FZN_TREE_ID_LEN, detail + used);
		used += ID_HEX;
		detail[used++] = ',';
		memcpy(detail + used, who, who_len);
		used += who_len;
	}
	return answer(reply, cap, FZN_REPLY_OK, detail, used);
}

/* ---- add import --------------------------------------------------------- */

/* The titles of what an import refused, escaped and space-separated, as far
 * as the reply has room: what a user searches their export for. */
struct refused_names {
	char text[FZN_REPLY_MAX];
	size_t used;
	int cut;
};

static void name_refused(void *ctx, fzn_notes_import_refusal_t why, const uint8_t *title,
                         size_t title_len)
{
	struct refused_names *names = (struct refused_names *)ctx;
	size_t wrote = 0;

	(void)why;
	if (names->cut || sizeof(names->text) - names->used < 2u) {
		names->cut = 1;
		return;
	}
	names->text[names->used] = ' ';
	if (escape(title_len ? title : (const uint8_t *)"(untitled)",
	           title_len ? title_len : 10u, names->text + names->used + 1u,
	           sizeof(names->text) - names->used - 1u, &wrote)
	    < (title_len ? title_len : 10u)) {
		names->cut = 1;
		return;
	}
	names->used += 1u + wrote;
}

/* A whole file into memory, refused past `max` -- one byte more is read so a
 * file at the bound and one past it are told apart. The caller frees. */
static uint8_t *slurp(const char *path, size_t max, size_t *len, int *too_big)
{
	FILE *f = fopen(path, "rb");
	uint8_t *buf;

	*len = 0;
	*too_big = 0;
	if (!f)
		return NULL;
	buf = (uint8_t *)malloc(max + 1u);
	if (buf)
		*len = fread(buf, 1u, max + 1u, f);
	(void)fclose(f);
	if (buf && *len > max) {
		free(buf);
		*too_big = 1;
		return NULL;
	}
	return buf;
}

static int ends_with(const char *name, const char *suffix)
{
	size_t n = strlen(name), k = strlen(suffix);

	return n > k && strcmp(name + n - k, suffix) == 0;
}

/* One Keep note file; a file that will not read, or is past the bound, is a
 * refusal named by the file, since its title is inside what was not read. */
static void import_keep_file(fzn_notes_import_run_t *run, const char *path, const char *name)
{
	size_t len = 0;
	int too_big = 0;
	uint8_t *json = slurp(path, FZN_NODE_NOTES_IMPORT_FILE_MAX, &len, &too_big);

	if (!json) {
		fzn_notes_import_refuse(run, too_big ? FZN_NOTES_IMPORT_TOO_LONG
		                                     : FZN_NOTES_IMPORT_UNPARSED,
		                        (const uint8_t *)name, strlen(name));
		return;
	}
	(void)fzn_notes_import_keep(json, len, fzn_notes_import_take, run, fzn_notes_import_refuse,
	                            run);
	free(json);
}

/* `add import PARENT PATH`: a KNotes `.ics`, a Keep note's `.json`, or a
 * Takeout directory of them, into the folder PARENT. sec 440. The node reads
 * PATH as itself, which is why the verb needs its own user. Answers
 * `IMPORTED ALREADY UNDATED REFUSED` and the refused notes' titles. */
static size_t import(fzn_node_notes_t *n, const uint8_t *at, size_t left, char *reply,
                     size_t cap)
{
	static struct refused_names names;
	static char detail[FZN_REPLY_MAX];
	size_t limit = (cap > 0u && cap - 1u < FZN_REPLY_MAX) ? cap - 1u : FZN_REPLY_MAX;
	fzn_notes_import_run_t run;
	char path[512];
	const uint8_t *w;
	size_t w_len, idx = 0;
	struct stat st;
	int k;

	memset(&run, 0, sizeof(run));
	if (!word(&at, &left, &w, &w_len) || !parse_id(w, w_len, run.folder) || left == 0u
	    || left >= sizeof(path) || memchr(at, '\0', left))
		return say(reply, cap, FZN_REPLY_MALFORMED, "add import PARENT PATH");
	memcpy(path, at, left);
	path[left] = '\0';
	/* INTO A FOLDER THIS NODE HOLDS, or the top: notes under an id nobody
	 * holds would land where no listing reaches them. */
	if (!fzn_tree_is_root(run.folder)) {
		if (fzn_notes_view_load(&n->store, &view) != FZN_NOTES_OK
		    || !find(n, run.folder, &idx))
			return refuse(reply, cap, FZN_NOTES_ERR_ABSENT);
	}
	if (stat(path, &st) != 0)
		return say(reply, cap, FZN_REPLY_ERROR, "cannot read that path");
	run.author = &n->author;
	run.seal = n->seal;
	run.seal_ctx = n->text_ctx;
	run.now_ms = now(n);
	memset(&names, 0, sizeof(names));
	run.on_refused = name_refused;
	run.refused_ctx = &names;

	if (S_ISDIR(st.st_mode)) {
		/* A TAKEOUT: every `.json` in the directory is one note; anything
		 * else in it -- attachments, the HTML twin of each note -- is not
		 * a note and is left alone. */
		DIR *dir = opendir(path);
		struct dirent *e;

		if (!dir)
			return say(reply, cap, FZN_REPLY_ERROR, "cannot read that directory");
		while ((e = readdir(dir)) != NULL) {
			char file[1024];

			if (!ends_with(e->d_name, ".json"))
				continue;
			k = snprintf(file, sizeof(file), "%s/%s", path, e->d_name);
			if (k < 0 || (size_t)k >= sizeof(file)) {
				fzn_notes_import_refuse(&run, FZN_NOTES_IMPORT_UNPARSED,
				                        (const uint8_t *)e->d_name, strlen(e->d_name));
				continue;
			}
			import_keep_file(&run, file, e->d_name);
		}
		(void)closedir(dir);
	} else if (ends_with(path, ".ics")) {
		size_t len = 0;
		int too_big = 0;
		uint8_t *ics = slurp(path, FZN_NODE_NOTES_IMPORT_ICS_MAX, &len, &too_big);

		if (!ics)
			return say(reply, cap, FZN_REPLY_ERROR,
			           too_big ? "past what one import reads" : "cannot read that file");
		(void)fzn_notes_import_knotes(ics, len, fzn_notes_import_take, &run,
		                              fzn_notes_import_refuse, &run);
		free(ics);
	} else if (ends_with(path, ".json")) {
		const char *base = strrchr(path, '/');

		import_keep_file(&run, path, base ? base + 1 : path);
	} else {
		return say(reply, cap, FZN_REPLY_MALFORMED,
		           "a KNotes .ics, a Keep .json, or a Takeout directory");
	}
	k = snprintf(detail, sizeof(detail), "%zu %zu %zu %zu", run.imported, run.already,
	             run.undated, run.refused);
	if (k < 0 || (size_t)k >= limit)
		return 0;
	/* THE NAMES AS FAR AS THERE IS ROOM; the count above is all of them. */
	if (names.used && limit - (size_t)k > names.used) {
		memcpy(detail + k, names.text, names.used);
		k += (int)names.used;
	}
	return answer(reply, cap, FZN_REPLY_OK, detail, (size_t)k);
}

/* `list shared NAME PARENT [FROM]` and `get shared NAME ID ...`: the note
 * verbs' reads, over the tree the contact NAME shared with this node. sec
 * 437. Nothing writes there but pulling. */
static size_t read_shared(fzn_node_notes_t *n, int listing, const uint8_t *at, size_t left,
                          char *reply, size_t cap)
{
	static fzn_notes_received_t seam;
	static fzn_persist_ops_t ops;
	fzn_notes_store_t store;
	fzn_contact_t contact;
	fzn_contact_err_t cerr;
	const uint8_t *name;
	size_t name_len;

	if (!word(&at, &left, &name, &name_len))
		return say(reply, cap, FZN_REPLY_MALFORMED,
		           listing ? "list shared NAME PARENT [FROM]" : "get shared NAME ID ...");
	cerr = fzn_contact_find(n->store.ops, (const char *)name, name_len, &contact);
	if (cerr != FZN_CONTACT_OK)
		return say(reply, cap,
		           cerr == FZN_CONTACT_ERR_NAME ? FZN_REPLY_MALFORMED : FZN_REPLY_ERROR,
		           fzn_contact_err_str(cerr));
	if (fzn_notes_received_ops(&seam, n->store.ops, n->store.hash, contact.key, &ops)
	            != FZN_NOTES_OK
	    || fzn_notes_store_init(&store, &ops, n->store.hash) != FZN_NOTES_OK)
		return say(reply, cap, FZN_REPLY_ERROR, "the shared notes would not open");
	return listing ? list(&store, 1, at, left, reply, cap) : get(n, &store, at, left, reply, cap);
}

size_t fzn_node_notes_local(void *ctx, fzn_origin_t origin, const fzn_request_t *request,
                            char *reply, size_t reply_cap)
{
	fzn_node_notes_t *n = (fzn_node_notes_t *)ctx;
	const uint8_t *at, *subject;
	size_t left, subject_len;

	if (!n || !request || !reply || !request->arg)
		return 0;
	at = request->arg;
	left = request->arg_len;
	if (!word(&at, &left, &subject, &subject_len))
		return 0;
	if (is_word(subject, subject_len, "import")) {
		if (request->parsed != FZN_VERB_ADD)
			return 0;
		if (origin != FZN_ORIGIN_SAME_USER)
			return say(reply, reply_cap, FZN_REPLY_DENIED,
			           "notes need this node's own user");
		return import(n, at, left, reply, reply_cap);
	}
	if (is_word(subject, subject_len, "shared")) {
		if (request->parsed != FZN_VERB_LIST && request->parsed != FZN_VERB_GET)
			return 0;
		if (origin != FZN_ORIGIN_SAME_USER)
			return say(reply, reply_cap, FZN_REPLY_DENIED,
			           "notes need this node's own user");
		return read_shared(n, request->parsed == FZN_VERB_LIST, at, left, reply, reply_cap);
	}
	if (is_word(subject, subject_len, "share")) {
		if (request->parsed != FZN_VERB_ADD && request->parsed != FZN_VERB_REMOVE
		    && request->parsed != FZN_VERB_LIST)
			return 0;
		if (origin != FZN_ORIGIN_SAME_USER)
			return say(reply, reply_cap, FZN_REPLY_DENIED,
			           "shares need this node's own user");
		if (request->parsed == FZN_VERB_LIST)
			return list_shares(n, at, left, reply, reply_cap);
		return change_share(n, request->parsed == FZN_VERB_ADD, at, left, reply, reply_cap);
	}
	if (is_word(subject, subject_len, "item")) {
		if (request->parsed != FZN_VERB_ADD && request->parsed != FZN_VERB_REMOVE)
			return 0;
		if (origin != FZN_ORIGIN_SAME_USER)
			return say(reply, reply_cap, FZN_REPLY_DENIED, "notes need this node's own user");
		return change_item(n, request->parsed == FZN_VERB_ADD, at, left, reply, reply_cap);
	}
	if (!is_word(subject, subject_len, "note") && !is_word(subject, subject_len, "folder")
	    && !is_word(subject, subject_len, "list"))
		return 0;
	if ((is_word(subject, subject_len, "folder") || is_word(subject, subject_len, "list"))
	    && request->parsed != FZN_VERB_ADD)
		return 0;
	if (request->parsed != FZN_VERB_ADD && request->parsed != FZN_VERB_SET
	    && request->parsed != FZN_VERB_LIST && request->parsed != FZN_VERB_GET
	    && request->parsed != FZN_VERB_REMOVE)
		return 0;
	if (origin != FZN_ORIGIN_SAME_USER)
		return say(reply, reply_cap, FZN_REPLY_DENIED, "notes need this node's own user");
	switch (request->parsed) {
	case FZN_VERB_ADD:
		return add(n,
		           is_word(subject, subject_len, "folder") ? FZN_NOTE_TYPE_FOLDER
		           : is_word(subject, subject_len, "list") ? FZN_NOTE_TYPE_LIST
		                                                   : FZN_NOTE_TYPE_NOTE,
		           at, left, reply, reply_cap);
	case FZN_VERB_SET:
		return set(n, at, left, reply, reply_cap);
	case FZN_VERB_LIST:
		return list(&n->store, 0, at, left, reply, reply_cap);
	case FZN_VERB_GET:
		return get(n, &n->store, at, left, reply, reply_cap);
	case FZN_VERB_REMOVE:
		if (is_word(at, left, "trash"))
			return empty_trash(n, reply, reply_cap);
		return say(reply, reply_cap, FZN_REPLY_MALFORMED, "remove note trash");
	default:
		return 0;
	}
}

/* A contact's request, sec 436: answered over the subtrees shared with it
 * and what they reach in this node's view now -- so a note moved out of a
 * shared subtree stops being served, and one moved in starts. */
static uint8_t reach[FZN_NOTES_MAX][FZN_TREE_ID_LEN];

/* What the subtrees shared with `sender` reach in the view now, into
 * `reach`, with `view` loaded. A STORE THAT WILL NOT READ REACHES NOTHING
 * rather than refusing: the contact then sees an empty share. */
static void shared_scope(fzn_node_notes_t *n, const uint8_t *sender,
                         fzn_notes_sync_scope_t *scope)
{
	static uint8_t seeds[FZN_NOTES_SHARES_MAX][FZN_TREE_ID_LEN];
	size_t seed_count = 0;

	scope->ids = (const uint8_t (*)[FZN_TREE_ID_LEN])reach;
	scope->count = 0;
	if (sender
	    && fzn_notes_share_with(&n->store, sender, seeds, FZN_NOTES_SHARES_MAX, &seed_count)
	               == FZN_NOTES_OK
	    && seed_count && fzn_notes_view_load(&n->store, &view) == FZN_NOTES_OK)
		scope->count = fzn_notes_share_reach(&view, (const uint8_t (*)[FZN_TREE_ID_LEN])seeds,
		                                     seed_count, reach, FZN_NOTES_MAX);
}

static size_t answer_shared(fzn_node_notes_t *n, const uint8_t *sender, const uint8_t *request,
                            size_t request_len, uint8_t *reply, size_t reply_cap)
{
	fzn_notes_sync_scope_t scope;

	shared_scope(n, sender, &scope);
	return fzn_notes_sync_answer_scoped(&n->store, &scope, request, request_len, reply,
	                                    reply_cap);
}

int fzn_node_notes_shares_blob(fzn_node_notes_t *n, const uint8_t *sender,
                               const uint8_t root[FZN_BLOB_HASH_LEN])
{
	fzn_notes_sync_scope_t scope;
	size_t i, j;

	if (!n || !sender || !root)
		return 0;
	shared_scope(n, sender, &scope);
	/* EVERY CLAIM ON A NOTE IN SCOPE, whoever wrote it: what is served of a
	 * note is every writer's record of it, so its texts are too. */
	for (i = 0; i < view.count; i++) {
		fzn_note_t note;
		fzn_note_blob_ref_t ref;
		int in = 0;

		for (j = 0; j < scope.count && !in; j++)
			in = memcmp(scope.ids[j], view.nodes[i].id, FZN_TREE_ID_LEN) == 0;
		if (in
		    && fzn_note_open(view.nodes[i].content_type, view.nodes[i].content,
		                     view.nodes[i].content_len, &note)
		               == FZN_NOTE_OK
		    && fzn_note_blob_ref(&note, &ref) == FZN_NOTE_OK
		    && memcmp(ref.root, root, FZN_BLOB_HASH_LEN) == 0)
			return 1;
	}
	return 0;
}

size_t fzn_node_notes_remote(void *ctx, const uint8_t *sender, int shared,
                             const uint8_t *request, size_t request_len, uint8_t *reply,
                             size_t reply_cap)
{
	fzn_node_notes_t *n = (fzn_node_notes_t *)ctx;

	if (!n)
		return 0;
	if (shared)
		return answer_shared(n, sender, request, request_len, reply, reply_cap);
	return fzn_notes_sync_answer(&n->store, n->author.policy, sender, now(n), request,
	                             request_len, reply, reply_cap);
}
