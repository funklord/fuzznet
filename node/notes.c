/* See notes.h. */

#define _POSIX_C_SOURCE 200809L

#include "notes.h"

#include "../notes/text.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
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
                                    uint64_t (*now_ms)(void))
{
	size_t i;
	fzn_notes_err_t err;

	if (!notes || !sign || !rng || !self || (peer_count && !peers)
	    || peer_count > FZN_NODE_NOTES_WRITERS)
		return FZN_NOTES_ERR_MALFORMED;
	memset(notes, 0, sizeof(*notes));
	err = fzn_notes_store_init(&notes->store, store, hash);
	if (err != FZN_NOTES_OK)
		return err;
	memcpy(notes->admitted[0].key, self, FZN_PUBKEY_LEN);
	for (i = 0; i < peer_count; i++)
		memcpy(notes->admitted[i + 1u].key, peers[i], FZN_PUBKEY_LEN);
	notes->admitted_count = peer_count + 1u;
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
	if (is_word(field, field_len, "text"))
		return set_text(n, id, at, left, reply, cap);
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

static size_t list(fzn_node_notes_t *n, const uint8_t *at, size_t left, char *reply, size_t cap)
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
	err = fzn_notes_view_load(&n->store, &view);
	if (err != FZN_NOTES_OK)
		return refuse(reply, cap, err);
	err = fzn_tree_is_root(parent)
	              ? fzn_notes_top_level(&view, out, FZN_NOTES_MAX, &count, &cut)
	              : fzn_notes_children(&view, parent, out, FZN_NOTES_MAX, &count, &cut);
	if (err != FZN_NOTES_OK)
		return refuse(reply, cap, err);
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

static size_t get(fzn_node_notes_t *n, const uint8_t *at, size_t left, char *reply, size_t cap)
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
	err = fzn_notes_view_load(&n->store, &view);
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

/* ---- remove note trash --------------------------------------------------- */

static size_t empty_trash(fzn_node_notes_t *n, char *reply, size_t cap)
{
	size_t queued = 0, pending = 0, i;
	char detail[48];
	fzn_notes_err_t err;
	int k;

	/* THE PAIRED NODES ARE ASKED: the admitted set past this node itself. */
	err = fzn_notes_purge_trash(&n->store, &view, n->author.issuer,
	                            fzn_notes_asking(n->admitted + 1, n->admitted_count - 1u),
	                            now(n), &queued);
	if (err != FZN_NOTES_OK)
		return refuse(reply, cap, err);
	/* What is still waiting for consent, so the reply says which: the
	 * view is the one emptying loaded, before anything was erased. */
	for (i = 0; i < view.count; i++)
		if (memcmp(view.writers[i], n->author.issuer, FZN_PUBKEY_LEN) == 0
		    && fzn_notes_purge_pending(&n->store, view.nodes[i].id))
			pending++;
	k = snprintf(detail, sizeof(detail), "%zu %zu", queued, pending);
	return answer(reply, cap, FZN_REPLY_OK, detail, k > 0 ? (size_t)k : 0u);
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
	if (!is_word(subject, subject_len, "note") && !is_word(subject, subject_len, "folder"))
		return 0;
	if (is_word(subject, subject_len, "folder") && request->parsed != FZN_VERB_ADD)
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
		                                                   : FZN_NOTE_TYPE_NOTE,
		           at, left, reply, reply_cap);
	case FZN_VERB_SET:
		return set(n, at, left, reply, reply_cap);
	case FZN_VERB_LIST:
		return list(n, at, left, reply, reply_cap);
	case FZN_VERB_GET:
		return get(n, at, left, reply, reply_cap);
	case FZN_VERB_REMOVE:
		if (is_word(at, left, "trash"))
			return empty_trash(n, reply, reply_cap);
		return say(reply, reply_cap, FZN_REPLY_MALFORMED, "remove note trash");
	default:
		return 0;
	}
}

size_t fzn_node_notes_remote(void *ctx, const uint8_t *request, size_t request_len,
                             uint8_t *reply, size_t reply_cap)
{
	fzn_node_notes_t *n = (fzn_node_notes_t *)ctx;

	return n ? fzn_notes_sync_answer(&n->store, request, request_len, reply, reply_cap) : 0u;
}
