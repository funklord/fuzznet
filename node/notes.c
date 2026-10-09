/* See notes.h. */

#define _POSIX_C_SOURCE 200809L

#include "notes.h"

#include "../contact/contact.h"
#include "../contact/group.h"
#include "../notes/received.h"
#include "../notes/share.h"
#include "../notes/text.h"
#include "../wire/bytes.h"

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

/* Below: a purge marked here, said in this node's stream. sec 519. */
static void told_purged(void *ctx, const uint8_t id[FZN_SUBJECT_LEN]);

/* Every note's payload, opened (sec 514): one at a time, read and done. */
static uint8_t payload_buf[FZN_NOTE_PAYLOAD_MAX];

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
	notes->store.purged = told_purged;
	notes->store.purged_ctx = notes;
	memcpy(notes->admitted[0].key, self, FZN_PUBKEY_LEN);
	for (i = 0; i < peer_count; i++)
		memcpy(notes->admitted[i + 1u].key, peers[i], FZN_PUBKEY_LEN);
	notes->admitted_count = peer_count + 1u;
	notes->base_count = notes->admitted_count;
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

size_t fzn_node_notes_admit_members(fzn_node_notes_t *notes, const uint8_t (*keys)[FZN_PUBKEY_LEN],
                                    size_t count)
{
	size_t i, j, added = 0;

	if (!notes || (!keys && count))
		return 0;
	notes->admitted_count = notes->base_count;
	for (i = 0; i < count; i++) {
		int have = 0;

		for (j = 0; j < notes->admitted_count && !have; j++)
			have = memcmp(notes->admitted[j].key, keys[i], FZN_PUBKEY_LEN) == 0;
		if (have)
			continue;
		if (notes->admitted_count >= sizeof(notes->admitted) / sizeof(notes->admitted[0]))
			break;
		memcpy(notes->admitted[notes->admitted_count++].key, keys[i], FZN_PUBKEY_LEN);
		added++;
	}
	notes->author.policy = fzn_notes_policy_writers(notes->admitted, notes->admitted_count);
	return added;
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

/* A NOTE MARKED PURGED HERE, sec 519: said in this node's notes stream, so
 * every member following it marks it too -- one joining after the pinned
 * conversation has finished included, who would otherwise file the note
 * again from its writers' streams. Counted when it cannot be said: the mark
 * here stands either way. */
static void told_purged(void *ctx, const uint8_t id[FZN_SUBJECT_LEN])
{
	static uint8_t record[FZN_RECORD_MAX_LEN];
	static const uint8_t body[1] = { 1u };
	fzn_node_notes_t *n = (fzn_node_notes_t *)ctx;
	size_t len = 0;

	n->purged_fresh = 1;
	if (!n->chain
	    || !n->chain(n->chain_ctx, n->author.issuer, n->author.sign, FZN_NOTE_PURGE_KIND, id,
	                 body, sizeof(body), now(n), record, sizeof(record), &len))
		n->purges_untold++;
}

/* The author, with the node's content and chain hooks as they are now:
 * fuzznetd sets them after `fzn_node_notes_init`, so they are read at each
 * write. */
static const fzn_notes_author_t *author_of(fzn_node_notes_t *n)
{
	n->author.seal = n->seal;
	n->author.open = n->open;
	n->author.text_ctx = n->text_ctx;
	n->author.chain = n->chain;
	n->author.chain_ctx = n->chain_ctx;
	return &n->author;
}

/* NOWHERE TO KEEP CONTENT OR HISTORY, and so no note can be written: an
 * error, not a malformed request, since the request was well formed. 0 when
 * there is both. */
static size_t no_content_store(const fzn_node_notes_t *n, char *reply, size_t cap)
{
	if (!n->seal || !n->open)
		return say(reply, cap, FZN_REPLY_ERROR,
		           "this node keeps no blob store, where every note's content goes");
	if (!n->chain)
		return say(reply, cap, FZN_REPLY_ERROR,
		           "this node keeps no journal, where every note's history goes");
	return 0;
}

/* `node`'s meta, and its payload opened into `payload_buf`: its key
 * unwrapped under the wrap key `store` holds, this node's own or a sharer's
 * tree's (sec 520). */
static fzn_notes_err_t read_note(const fzn_node_notes_t *n, const fzn_notes_store_t *store,
                                 const fzn_tree_node_t *node, fzn_note_meta_t *meta,
                                 fzn_note_t *note)
{
	return fzn_notes_read(store, n->open, n->text_ctx, node, meta, payload_buf,
	                      sizeof(payload_buf), note);
}

/* ---- the title cache, sec 522 -------------------------------------------- */

/* WHAT A LISTING SHOWS, by blob root: sec 511 promised clients a listing that
 * answers title and labels without a blob read per note. The content under a
 * root never changes, so an entry never goes stale; it goes when collection
 * drops its root (`fzn_node_notes_names_blob`), which a purge does at once
 * (sec 520). In memory only: never carried, never on disk. */
#define TITLES_MAX FZN_NOTES_MAX

static struct title {
	uint8_t root[FZN_BLOB_HASH_LEN];
	uint64_t used; /* 0 for an empty slot, else when last listed */
	size_t title_len;
	size_t labels_len;
	uint8_t title[FZN_NOTE_TITLE_MAX];
	uint8_t labels[FZN_NOTE_LABELS_MAX];
} titles[TITLES_MAX];
static uint64_t titles_clock;
size_t fzn_node_notes_title_opens;

static struct title *title_at(const uint8_t root[FZN_BLOB_HASH_LEN])
{
	size_t i;

	for (i = 0; i < TITLES_MAX; i++)
		if (titles[i].used && memcmp(titles[i].root, root, FZN_BLOB_HASH_LEN) == 0) {
			titles[i].used = ++titles_clock;
			return &titles[i];
		}
	return NULL;
}

/* An entry for `root` from `note`, over the slot listed longest ago. */
static void title_keep(const uint8_t root[FZN_BLOB_HASH_LEN], const fzn_note_t *note)
{
	size_t i, at = 0;

	if (note->title_len > FZN_NOTE_TITLE_MAX || note->labels_len > FZN_NOTE_LABELS_MAX)
		return;
	for (i = 1; i < TITLES_MAX && titles[at].used; i++)
		if (!titles[i].used || titles[i].used < titles[at].used)
			at = i;
	memcpy(titles[at].root, root, FZN_BLOB_HASH_LEN);
	titles[at].title_len = note->title_len;
	titles[at].labels_len = note->labels_len;
	if (note->title_len)
		memcpy(titles[at].title, note->title, note->title_len);
	if (note->labels_len)
		memcpy(titles[at].labels, note->labels, note->labels_len);
	titles[at].used = ++titles_clock;
}

int fzn_node_notes_title_cached(const uint8_t root[FZN_BLOB_HASH_LEN])
{
	size_t i;

	for (i = 0; root && i < TITLES_MAX; i++)
		if (titles[i].used && memcmp(titles[i].root, root, FZN_BLOB_HASH_LEN) == 0)
			return 1;
	return 0;
}

static void title_drop(const uint8_t root[FZN_BLOB_HASH_LEN])
{
	size_t i;

	for (i = 0; i < TITLES_MAX; i++)
		if (titles[i].used && memcmp(titles[i].root, root, FZN_BLOB_HASH_LEN) == 0)
			memset(&titles[i], 0, sizeof(titles[i]));
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
	size_t r = no_content_store(n, reply, cap);

	if (r)
		return r;
	if (!word(&at, &left, &w, &w_len) || !parse_id(w, w_len, parent))
		return say(reply, cap, FZN_REPLY_MALFORMED, "add note PARENT TITLE");
	memset(&note, 0, sizeof(note));
	note.title = at;
	note.title_len = left;
	err = fzn_notes_create(author_of(n), parent, type, &note, now(n), id);
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
	/* Every text is sealed into the note's blob, since sec 514; nothing is
	 * cut to fit, and a payload past its bound is refused whole. */
	err = fzn_notes_edit(author_of(n), id, FZN_NOTES_EDIT_TEXT, &with, 0u, 0u, now(n));
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
	size_t w_len, field_len, i, len = 0, r = no_content_store(n, reply, cap);
	fzn_note_t with;
	fzn_notes_err_t err;

	if (r)
		return r;

	if (!word(&at, &left, &w, &w_len) || !parse_id(w, w_len, id)
	    || !word(&at, &left, &field, &field_len))
		return say(reply, cap, FZN_REPLY_MALFORMED, "set note ID FIELD [VALUE]");
	for (i = 0; i < sizeof(FLAGS) / sizeof(FLAGS[0]); i++)
		if (is_word(field, field_len, FLAGS[i].word)) {
			err = fzn_notes_edit(author_of(n), id, 0u, NULL, FLAGS[i].set, FLAGS[i].clear,
			                     now(n));
			return err == FZN_NOTES_OK ? say(reply, cap, FZN_REPLY_OK, NULL)
			                           : refuse(reply, cap, err);
		}
	if (is_word(field, field_len, "title")) {
		memset(&with, 0, sizeof(with));
		with.title = at;
		with.title_len = left;
		err = fzn_notes_edit(author_of(n), id, FZN_NOTES_EDIT_TITLE, &with, 0u, 0u, now(n));
		return err == FZN_NOTES_OK ? say(reply, cap, FZN_REPLY_OK, NULL)
		                           : refuse(reply, cap, err);
	}
	/* A CHECKLIST'S TEXT IS ITS ITEMS, so its items change through the
	 * item verbs only. The edit checks a list's shape, and refuses bytes
	 * that are no items as malformed, and this answer is the plainer one.
	 * sec 442. */
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
		err = fzn_notes_move(author_of(n), id, parent, now(n));
		return err == FZN_NOTES_OK ? say(reply, cap, FZN_REPLY_OK, NULL)
		                           : refuse(reply, cap, err);
	}
	return say(reply, cap, FZN_REPLY_MALFORMED, "no such field");
}

/* ---- list ---------------------------------------------------------------- */

/* `store` is this node's notes, or a sharer's tree when `shared` is set
 * (sec 437): then the top is the shared subtrees' roots. */
static size_t list(const fzn_node_notes_t *n, const fzn_notes_store_t *store, int shared, const uint8_t *at, size_t left,
                   char *reply, size_t cap)
{
	static const fzn_tree_node_t *out[FZN_NOTES_MAX];
	static uint8_t contested[FZN_NOTES_MAX][FZN_TREE_ID_LEN];
	static char detail[FZN_REPLY_MAX];
	size_t limit = fzn_reply_ok_room(cap);
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
		fzn_note_meta_t meta;
		const uint8_t *title = (const uint8_t *)"", *labels = title;
		size_t title_len = 0, labels_len = 0, lwrote = 0;
		const struct title *cached = NULL;
		uint8_t flags = 0;

		for (j = 0; j < n_contested && j < FZN_NOTES_MAX; j++)
			is_contested |= memcmp(contested[j], node->id, FZN_TREE_ID_LEN) == 0;
		/* THE TITLE IS IN THE BLOB, so a note whose blob is not here
		 * lists by its meta, marked pending (sec 514). A blob opened
		 * once is listed from the cache after (sec 522). */
		if (fzn_note_meta_open(node->content_type, node->content, node->content_len, &meta)
		    == FZN_NOTE_OK) {
			cached = title_at(meta.content.root);
			if (cached) {
				title = cached->title;
				title_len = cached->title_len;
				labels = cached->labels;
				labels_len = cached->labels_len;
				flags = meta.flags;
			} else {
				switch (read_note(n, store, node, &meta, &note)) {
				case FZN_NOTES_OK:
					fzn_node_notes_title_opens++;
					title_keep(meta.content.root, &note);
					title = note.title;
					title_len = note.title_len;
					labels = note.labels;
					labels_len = note.labels_len;
					flags = meta.flags;
					break;
				case FZN_NOTES_ERR_PENDING:
					flags = (uint8_t)(meta.flags | FZN_NODE_NOTES_LIST_PENDING);
					break;
				default:
					break;
				}
			}
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
		/* AND ITS LABELS, a seventh field, escaped as the title is (the
		 * NUL between two labels too), so a client searches them without
		 * opening a note. sec 522. */
		{
			size_t pos = used + 1u + ID_HEX + (size_t)m + wrote;

			if (limit - pos < 1u)
				break;
			detail[pos] = ',';
			if (escape(labels, labels_len, detail + pos + 1u, limit - pos - 1u, &lwrote)
			    < labels_len)
				break;
		}
		used += 1u + ID_HEX + (size_t)m + wrote + 1u + lwrote;
	}
	return answer(reply, cap, FZN_REPLY_OK, detail, used);
}

/* ---- get ----------------------------------------------------------------- */

static size_t get(fzn_node_notes_t *n, const fzn_notes_store_t *store, const uint8_t *at,
                  size_t left, char *reply, size_t cap)
{
	static char detail[FZN_REPLY_MAX];
	size_t limit = fzn_reply_ok_room(cap);
	uint8_t id[FZN_TREE_ID_LEN];
	const uint8_t *w, *field;
	size_t w_len, field_len, idx = 0, used, wrote = 0, from = 0, i;
	const fzn_tree_node_t *node;
	fzn_note_t note;
	fzn_note_meta_t meta;
	fzn_notes_err_t err;
	int k, pending;

	if (!word(&at, &left, &w, &w_len) || !parse_id(w, w_len, id) || fzn_tree_is_root(id))
		return say(reply, cap, FZN_REPLY_MALFORMED, "get note ID [text [FROM] | file PATH]");
	err = fzn_notes_view_load(store, &view);
	if (err != FZN_NOTES_OK)
		return refuse(reply, cap, err);
	node = find(n, id, &idx);
	if (!node)
		return refuse(reply, cap, FZN_NOTES_ERR_ABSENT);
	err = read_note(n, store, node, &meta, &note);
	if (err != FZN_NOTES_OK && err != FZN_NOTES_ERR_PENDING)
		return refuse(reply, cap, err);
	pending = err == FZN_NOTES_ERR_PENDING;
	if (pending)
		memset(&note, 0, sizeof(note));

	if (!word(&at, &left, &field, &field_len)) {
		/* THE FIELDS: type, flags, created, edited, parent, `blob` and
		 * the text's length -- or `pending` and the sealed payload's,
		 * with no title -- then the title, escaped. sec 514. */
		char parent[ID_HEX + 1u];

		hex_of(node->parent, FZN_TREE_ID_LEN, parent);
		parent[ID_HEX] = '\0';
		k = snprintf(detail, sizeof(detail), "%u %u %llu %llu %s %s %llu ",
		             (unsigned)node->content_type, (unsigned)meta.flags,
		             (unsigned long long)meta.created_at_ms,
		             (unsigned long long)meta.edited_at_ms, parent,
		             pending ? "pending" : "blob",
		             (unsigned long long)(pending ? meta.content.length : note.text_len));
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
	if (pending)
		return say(reply, cap, FZN_REPLY_ERROR, "the text is not here yet");
	if (is_word(field, field_len, "text")) {
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

/* ---- collecting texts, sec 443 ------------------------------------------ */

/* Whether any claim in `view` names the blob `root`. */
static int view_names(const fzn_notes_view_t *v, const uint8_t root[FZN_BLOB_HASH_LEN])
{
	size_t i;

	for (i = 0; i < v->count; i++) {
		fzn_note_blob_ref_t ref;

		if (fzn_notes_ref_of(&v->nodes[i], &ref)
		    && memcmp(ref.root, root, FZN_BLOB_HASH_LEN) == 0)
			return 1;
	}
	return 0;
}

static int names_blob(fzn_node_notes_t *n, const uint8_t root[FZN_BLOB_HASH_LEN]);

int fzn_node_notes_names_blob(fzn_node_notes_t *n, const uint8_t root[FZN_BLOB_HASH_LEN])
{
	int named = names_blob(n, root);

	/* A BLOB NO NOTE NAMES takes its listing with it, sec 522: collection
	 * asks here before it removes one, and a purge collects at once. */
	if (!named && root)
		title_drop(root);
	return named;
}

static int names_blob(fzn_node_notes_t *n, const uint8_t root[FZN_BLOB_HASH_LEN])
{
	static uint8_t sharers[FZN_NOTES_RECEIVED_ROWS][FZN_PUBKEY_LEN];
	size_t count = 0, i;

	if (!n || !root)
		return 1;
	/* A TREE THAT WILL NOT READ KEEPS EVERYTHING: a text removed because
	 * its note could not be looked at is a text lost. */
	if (fzn_notes_view_load(&n->store, &view) != FZN_NOTES_OK || view_names(&view, root))
		return 1;
	if (fzn_notes_received_sharers(n->store.ops, sharers, FZN_NOTES_RECEIVED_ROWS, &count)
	    != FZN_NOTES_OK)
		return 1;
	for (i = 0; i < count; i++) {
		fzn_notes_received_t seam;
		fzn_persist_ops_t ops;
		fzn_notes_store_t tree;

		if (fzn_notes_received_ops(&seam, n->store.ops, n->store.hash, sharers[i], &ops)
		            != FZN_NOTES_OK
		    || fzn_notes_store_init(&tree, &ops, n->store.hash) != FZN_NOTES_OK
		    || fzn_notes_view_load(&tree, &view) != FZN_NOTES_OK || view_names(&view, root))
			return 1;
	}
	return 0;
}

static int keep_named(void *ctx, const uint8_t *root)
{
	return fzn_node_notes_names_blob((fzn_node_notes_t *)ctx, root);
}

/* `remove text unused`: `ok REMOVED KEPT`. */
static size_t collect_texts(fzn_node_notes_t *n, const uint8_t *at, size_t left, char *reply,
                            size_t cap)
{
	char detail[48];
	size_t kept = 0, removed = 0;
	int k;

	if (!is_word(at, left, "unused"))
		return say(reply, cap, FZN_REPLY_MALFORMED, "remove text unused");
	if (!n->collect)
		return say(reply, cap, FZN_REPLY_ERROR, "this node keeps no long texts");
	if (!n->collect(n->text_ctx, keep_named, n, &kept, &removed))
		return say(reply, cap, FZN_REPLY_ERROR, "the texts would not all be looked at");
	k = snprintf(detail, sizeof(detail), "%zu %zu", removed, kept);
	return answer(reply, cap, FZN_REPLY_OK, detail, k > 0 ? (size_t)k : 0u);
}

/* ---- pushing texts, sec 448 ------------------------------------------------ */

#define TEXT_PUSH_HEAD (2u + FZN_BLOB_HASH_LEN + 8u)
/* One span's DATA at most: the shelf's largest is some 18 KiB, and a
 * request fuzznetd reassembles is at most 32 KiB (sec 447). */
#define TEXT_SPAN_MAX (24u * 1024u)
#define TEXT_PUSHED_LEN 3u
#define TEXT_REFUSED 0u
#define TEXT_WANTED 1u
#define TEXT_WHOLE 2u

/* Whether a note in this node's own tree names the blob `root` at `length`:
 * a pushed text is taken only for a note this node holds, at its length. */
static int own_note_names(fzn_node_notes_t *n, const uint8_t *root, uint64_t length)
{
	size_t i;

	if (fzn_notes_view_load(&n->store, &view) != FZN_NOTES_OK)
		return 0;
	for (i = 0; i < view.count; i++) {
		fzn_note_blob_ref_t ref;

		if (fzn_notes_ref_of(&view.nodes[i], &ref)
		    && memcmp(ref.root, root, FZN_BLOB_HASH_LEN) == 0 && ref.length == length)
			return 1;
	}
	return 0;
}

static int sender_admitted(const fzn_node_notes_t *n, const uint8_t *sender)
{
	size_t i;

	for (i = 0; sender && i < n->admitted_count; i++)
		if (memcmp(n->admitted[i].key, sender, FZN_PUBKEY_LEN) == 0)
			return 1;
	return 0;
}

/* THE SERVER OF A PUSHED TEXT: an offer (no data) is answered whole or
 * wanted; a span is placed. Refused unless the sender is admitted, a note
 * here names the text at that length, and this node has somewhere to put it. */
static size_t take_text(fzn_node_notes_t *n, const uint8_t *sender, const uint8_t *request,
                        size_t request_len, uint8_t *reply, size_t reply_cap)
{
	uint8_t outcome = TEXT_REFUSED;
	const uint8_t *root;
	uint64_t length;
	int complete = 0;

	if (request_len < 2u || request[0] != FZN_NOTES_SYNC_VERSION
	    || request[1] != FZN_NOTES_SYNC_TEXT_PUSH || reply_cap < TEXT_PUSHED_LEN)
		return 0;
	if (request_len < TEXT_PUSH_HEAD || !n->place || !sender_admitted(n, sender))
		goto answer;
	root = request + 2;
	length = fzn_get_be64(request + 2 + FZN_BLOB_HASH_LEN);
	if (!own_note_names(n, root, length))
		goto answer;
	if (request_len == TEXT_PUSH_HEAD) {
		if (n->place(n->text_ctx, root, length, NULL, 0u, &complete))
			outcome = complete ? TEXT_WHOLE : TEXT_WANTED;
	} else if (n->place(n->text_ctx, root, length, request + TEXT_PUSH_HEAD,
	                    request_len - TEXT_PUSH_HEAD, &complete)) {
		outcome = complete ? TEXT_WHOLE : TEXT_WANTED;
	}
answer:
	reply[0] = FZN_NOTES_SYNC_VERSION;
	reply[1] = FZN_NOTES_SYNC_TEXT_PUSHED;
	reply[2] = outcome;
	return TEXT_PUSHED_LEN;
}

/* Send one TEXT_PUSH, and read its outcome; 0 on no answer or nonsense. */
static int push_one(fzn_notes_sync_ask_t ask, void *ask_ctx, const uint8_t *request,
                    size_t request_len, uint8_t *outcome)
{
	uint8_t reply[TEXT_PUSHED_LEN + 1u];
	size_t reply_len = 0;

	if (!ask(ask_ctx, request, request_len, reply, sizeof(reply), &reply_len)
	    || reply_len != TEXT_PUSHED_LEN || reply[0] != FZN_NOTES_SYNC_VERSION
	    || reply[1] != FZN_NOTES_SYNC_TEXT_PUSHED || reply[2] > TEXT_WHOLE)
		return 0;
	*outcome = reply[2];
	return 1;
}

int fzn_node_notes_push_texts(fzn_node_notes_t *n, fzn_notes_sync_ask_t ask, void *ask_ctx,
                              fzn_node_notes_text_tally_t *tally)
{
	static uint8_t request[TEXT_PUSH_HEAD + TEXT_SPAN_MAX];
	static uint8_t roots[FZN_NOTES_MAX][FZN_BLOB_HASH_LEN];
	static uint64_t lengths[FZN_NOTES_MAX];
	size_t n_roots = 0, i, j;

	if (!n || !ask || !tally)
		return 0;
	memset(tally, 0, sizeof(*tally));
	if (!n->place || !n->span || fzn_notes_view_load(&n->store, &view) != FZN_NOTES_OK)
		return 1;
	/* EVERY TEXT A NOTE HERE NAMES, each once. */
	for (i = 0; i < view.count && n_roots < FZN_NOTES_MAX; i++) {
		fzn_note_blob_ref_t ref;
		int seen = 0;

		if (!fzn_notes_ref_of(&view.nodes[i], &ref))
			continue;
		for (j = 0; j < n_roots && !seen; j++)
			seen = memcmp(roots[j], ref.root, FZN_BLOB_HASH_LEN) == 0;
		if (seen)
			continue;
		memcpy(roots[n_roots], ref.root, FZN_BLOB_HASH_LEN);
		lengths[n_roots++] = ref.length;
	}
	for (i = 0; i < n_roots; i++) {
		uint64_t first = 0, count = 0;
		uint8_t outcome = TEXT_REFUSED;
		int whole_here = 0;

		/* ONLY A TEXT HELD WHOLE HERE is offered: a part has no proofs. */
		if (!n->place(n->text_ctx, roots[i], lengths[i], NULL, 0u, &whole_here) || !whole_here)
			continue;
		tally->offered++;
		request[0] = FZN_NOTES_SYNC_VERSION;
		request[1] = FZN_NOTES_SYNC_TEXT_PUSH;
		memcpy(request + 2, roots[i], FZN_BLOB_HASH_LEN);
		fzn_put_be64(request + 2 + FZN_BLOB_HASH_LEN, lengths[i]);
		if (!push_one(ask, ask_ctx, request, TEXT_PUSH_HEAD, &outcome))
			return 0;
		if (outcome == TEXT_REFUSED) {
			tally->refused++;
			continue;
		}
		if (outcome == TEXT_WHOLE)
			continue;
		tally->pushed++;
		/* SPAN BY SPAN until the peer has it whole, at most one span a
		 * leaf: every span places at least one leaf or ends it. */
		while (outcome == TEXT_WANTED && first < lengths[i] + 1u) {
			size_t data_len = 0;

			if (!n->span(n->text_ctx, roots[i], first, request + TEXT_PUSH_HEAD,
			             sizeof(request) - TEXT_PUSH_HEAD, &data_len, &count)
			    || count == 0u)
				break;
			if (!push_one(ask, ask_ctx, request, TEXT_PUSH_HEAD + data_len, &outcome))
				return 0;
			tally->spans++;
			if (outcome == TEXT_REFUSED) {
				tally->refused++;
				break;
			}
			first += count;
		}
	}
	return 1;
}

/* ---- checklists, sec 442 ------------------------------------------------- */

static uint8_t items_buf[FZN_NOTE_TEXT_MAX];
static uint8_t fresh_buf[FZN_NOTE_TEXT_MAX];

/* A checklist's items: its payload's text, copied out of `payload_buf` so
 * an item rewritten can be read from while the next payload is built. */
static fzn_notes_err_t list_items(const fzn_note_t *note, uint8_t *out, size_t cap, size_t *len)
{
	*len = 0;
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
	fzn_note_meta_t meta;
	size_t idx = 0;
	fzn_notes_err_t err;

	err = fzn_notes_view_load(store, &view);
	if (err != FZN_NOTES_OK)
		return refuse(reply, cap, err);
	node = find(n, id, &idx);
	if (!node)
		return refuse(reply, cap, FZN_NOTES_ERR_ABSENT);
	if (node->content_type != FZN_NOTE_TYPE_LIST)
		return say(reply, cap, FZN_REPLY_ERROR, "not a checklist");
	err = read_note(n, store, node, &meta, note);
	if (err == FZN_NOTES_ERR_PENDING)
		return say(reply, cap, FZN_REPLY_ERROR, "the items are not here yet");
	if (err == FZN_NOTES_OK)
		err = list_items(note, items_buf, sizeof(items_buf), items_len);
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
	size_t limit = fzn_reply_ok_room(cap);
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

	r = no_content_store(n, reply, cap);
	if (r)
		return r;
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

/* HEARD FROM LATELY: pulled from this node within a month, by its time
 * clamped to the clock (sec 470). A node that never pulled from this one --
 * one this node pulls from -- has answered by now if it answers at all,
 * since this side drives that conversation each round. A time that will
 * not read keeps the pin, the side that keeps data. */
static int partner_heard(void *ctx, const uint8_t host[FZN_PUBKEY_LEN], uint64_t now_ms)
{
	fzn_node_notes_t *n = ctx;
	uint64_t seen = 0;
	fzn_notes_err_t err = fzn_notes_partner_seen_clamped(&n->store, host, now_ms, &seen);

	if (err == FZN_NOTES_ERR_ABSENT)
		return 0;
	if (err != FZN_NOTES_OK)
		return 1;
	return now_ms <= seen || now_ms - seen <= FZN_NODE_NOTES_PARTNER_AGE_MS;
}

int fzn_node_notes_release_purges(fzn_node_notes_t *n, size_t *released, size_t *finished)
{
	if (!n || !released || !finished)
		return 0;
	return fzn_notes_purge_release(&n->store, now(n), FZN_NODE_NOTES_PARTNER_AGE_MS,
	                               partner_heard, n, released, finished)
	       == FZN_NOTES_OK;
}

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
	/* FIRST, WHAT THE SILENT PIN, sec 472: a purge waiting a month on a
	 * node gone as long is finished before the count below is taken. */
	{
		size_t released = 0, finished = 0;

		if (!fzn_node_notes_release_purges(n, &released, &finished))
			return say(reply, cap, FZN_REPLY_ERROR, "the purges would not read");
	}
	for (i = 0; i < n->pull_count; i++)
		asked[n_asked++] = n->pulls[i];
	for (i = 0; i < n_partners; i++) {
		uint64_t seen = 0;

		/* A PARTNER GONE A MONTH IS NOT PINNED: a purge waiting on a node
		 * that will never pull again would wait for ever. One whose time
		 * will not read is pinned, the side that keeps data. */
		/* SEEN "IN THE FUTURE" is re-stamped to now, sec 470, so a gone
		 * partner ages from today rather than from a clock since set back. */
		if (fzn_notes_partner_seen_clamped(&n->store, partners[i], now(n), &seen)
		            == FZN_NOTES_OK
		    && now(n) > seen && now(n) - seen > FZN_NODE_NOTES_PARTNER_AGE_MS)
			continue;
		/* NOR ONE THAT IS NO WRITER NOW, sec 451: a device un-paired, or a
		 * member revoked, will not be asked by this node's policy again,
		 * and a purge pinned to it would wait for ever. */
		if (!sender_admitted(n, partners[i]))
			continue;
		memcpy(asked[n_asked++].key, partners[i], FZN_PUBKEY_LEN);
	}
	err = fzn_notes_purge_trash(&n->store, &view, n->author.issuer,
	                            fzn_notes_asking(asked, n_asked), now(n), &queued);
	/* THE QUEUE OF DELETIONS IS FULL, sec 484: said as what it is. The
	 * store's word for FULL is about notes, and the person asked to delete
	 * some; fuzzypickles met the same misreading (their sec 168). */
	if (err == FZN_NOTES_ERR_FULL)
		return say(reply, cap, FZN_REPLY_ERROR,
		           "this node is already waiting on as many deletions as it will -- let one "
		           "finish");
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
	/* `@NAME` IS A GROUP, sec 471, which no contact name can be: the row
	 * goes under the group's id, found by its name. UNSHARING ALSO TAKES
	 * THE GRANTEE AS 64 HEX, which no name can be and `list share` prints
	 * for a row whose contact or group is gone: a share is taken away by
	 * identity, never by working an id out of a name. sec 516. */
	if (!add && name_len == ID_HEX && parse_id(name, name_len, contact.key)) {
		cerr = FZN_CONTACT_OK;
	} else if (name_len > 1u && name[0] == '@') {
		static fzn_group_t group;

		cerr = fzn_group_find(n->store.ops, (const char *)name + 1, name_len - 1u, &group);
		memcpy(contact.key, group.id, FZN_PUBKEY_LEN);
	} else {
		cerr = fzn_contact_find(n->store.ops, (const char *)name, name_len, &contact);
	}
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
	size_t limit = fzn_reply_ok_room(cap);
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
		static fzn_group_t group;
		fzn_contact_t contact;
		char who[FZN_PUBKEY_LEN * 2u];
		size_t who_len;

		if (fzn_contact_get(n->store.ops, all[i].contact, &contact) == FZN_CONTACT_OK) {
			memcpy(who, contact.name, contact.name_len);
			who_len = contact.name_len;
		} else if (fzn_group_get(n->store.ops, all[i].contact, &group) == FZN_CONTACT_OK) {
			/* A GROUP'S ROW, sec 471, as it was named. */
			who[0] = '@';
			memcpy(who + 1, group.name, group.name_len);
			who_len = 1u + group.name_len;
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
	size_t limit = fzn_reply_ok_room(cap);
	fzn_notes_import_run_t run;
	char path[512];
	const uint8_t *w;
	size_t w_len, idx = 0, r = no_content_store(n, reply, cap);
	struct stat st;
	int k;

	if (r)
		return r;

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
	run.author = author_of(n);
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
	return listing ? list(n, &store, 1, at, left, reply, cap) : get(n, &store, at, left, reply, cap);
}

static size_t local_verbs(fzn_node_notes_t *n, fzn_origin_t origin,
                          const fzn_request_t *request, char *reply, size_t reply_cap);

size_t fzn_node_notes_local(void *ctx, fzn_origin_t origin, const fzn_request_t *request,
                            char *reply, size_t reply_cap)
{
	fzn_node_notes_t *n = (fzn_node_notes_t *)ctx;
	size_t len = local_verbs(n, origin, request, reply, reply_cap);
	const uint8_t *detail = NULL;
	size_t detail_len = 0, line_len = len;

	/* A WRITE THAT TOOK marks the notes fresh, so the daemon pushes it
	 * now rather than at its next round. sec 449. The reply's newline is
	 * no part of its token: a bare "ok\n" does not split as "ok". */
	if (line_len && reply[line_len - 1u] == '\n')
		line_len--;
	if (line_len && n && fzn_verb_mutates(request->parsed)
	    && fzn_reply_of((const uint8_t *)reply, line_len, &detail, &detail_len) == FZN_REPLY_OK)
		n->fresh = 1;
	return len;
}

static size_t local_verbs(fzn_node_notes_t *n, fzn_origin_t origin,
                          const fzn_request_t *request, char *reply, size_t reply_cap)
{
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
	/* `remove text unused`; the shelf's own text verbs fall through. */
	if (is_word(subject, subject_len, "text") && request->parsed == FZN_VERB_REMOVE) {
		if (origin != FZN_ORIGIN_SAME_USER)
			return say(reply, reply_cap, FZN_REPLY_DENIED, "notes need this node's own user");
		return collect_texts(n, at, left, reply, reply_cap);
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
		return list(n, &n->store, 0, at, left, reply, reply_cap);
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
	static uint8_t groups[FZN_GROUPS_MAX][FZN_PUBKEY_LEN];
	size_t seed_count = 0, n_groups = 0, g;

	scope->ids = (const uint8_t (*)[FZN_TREE_ID_LEN])reach;
	scope->count = 0;
	if (!sender
	    || fzn_notes_share_with(&n->store, sender, seeds, FZN_NOTES_SHARES_MAX, &seed_count)
	               != FZN_NOTES_OK)
		return;
	/* AND EVERY GROUP'S IT IS IN, sec 471: a group share is one row under
	 * the group's id, so membership is read now, at the request. */
	if (fzn_group_ids_of(n->store.ops, sender, groups, FZN_GROUPS_MAX, &n_groups)
	    == FZN_CONTACT_OK)
		for (g = 0; g < n_groups && seed_count < FZN_NOTES_SHARES_MAX; g++) {
			size_t more = 0;

			if (fzn_notes_share_with(&n->store, groups[g], seeds + seed_count,
			                         FZN_NOTES_SHARES_MAX - seed_count, &more)
			    == FZN_NOTES_OK)
				seed_count += more;
		}
	if (seed_count && fzn_notes_view_load(&n->store, &view) == FZN_NOTES_OK)
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

/* ---- the index fed from a stream, sec 519 ---------------------------------- */

static int node_admits(const fzn_node_notes_t *n, const uint8_t key[FZN_PUBKEY_LEN])
{
	size_t i;

	for (i = 0; i < n->admitted_count; i++)
		if (memcmp(n->admitted[i].key, key, FZN_PUBKEY_LEN) == 0)
			return 1;
	return 0;
}

fzn_notes_err_t fzn_node_notes_file(fzn_node_notes_t *n, const uint8_t *record, size_t len,
                                    int *wrote)
{
	fzn_record_t rec;

	if (wrote)
		*wrote = 0;
	if (!n || !record || fzn_record_open(record, len, &rec) != FZN_RECORD_OK
	    || fzn_record_stream(rec) != FZN_NOTE_STREAM || fzn_record_kind(rec) != FZN_NOTE_KIND)
		return FZN_NOTES_ERR_MALFORMED;
	return fzn_notes_put(&n->store, record, len, n->author.policy, n->author.sign, wrote, NULL);
}

fzn_notes_err_t fzn_node_notes_index_stream(fzn_node_notes_t *n, fzn_node_notes_read_fn read,
                                            void *ctx, const uint8_t key[FZN_PUBKEY_LEN],
                                            uint64_t *cursor, uint64_t to,
                                            fzn_node_notes_index_tally_t *tally)
{
	static uint8_t record[FZN_RECORD_MAX_LEN];
	uint64_t seq;

	if (!n || !read || !key || !cursor || !tally)
		return FZN_NOTES_ERR_MALFORMED;
	memset(tally, 0, sizeof(*tally));
	for (seq = *cursor + 1u; seq <= to; seq++) {
		fzn_record_t rec;
		size_t len = 0;
		fzn_notes_err_t err;
		int wrote = 0;

		/* A RECORD THE STORE WILL NOT GIVE is not passed over: the cursor
		 * stays, and the next round asks again. */
		if (!read(ctx, key, seq, record, sizeof(record), &len))
			return FZN_NOTES_ERR_BACKEND;
		if (fzn_record_open(record, len, &rec) != FZN_RECORD_OK
		    || memcmp(fzn_record_issuer(rec), key, FZN_PUBKEY_LEN) != 0
		    || fzn_record_seq(rec) != seq || fzn_record_stream(rec) != FZN_NOTE_STREAM) {
			tally->skipped++;
		} else if (fzn_record_kind(rec) == FZN_NOTE_KIND) {
			err = fzn_notes_put(&n->store, record, len, n->author.policy, n->author.sign, &wrote,
			                    NULL);
			if (err == FZN_NOTES_ERR_DENIED) {
				tally->waiting = 1;
				return FZN_NOTES_OK;
			}
			if (err == FZN_NOTES_OK)
				(*(wrote ? &tally->filed : &tally->held))++;
			else if (err == FZN_NOTES_ERR_PURGED)
				tally->purged++;
			else if (err == FZN_NOTES_ERR_FULL || err == FZN_NOTES_ERR_BACKEND)
				return err;
			else
				tally->skipped++;
		} else if (fzn_record_kind(rec) == FZN_NOTE_PURGE_KIND) {
			/* WHO MAY ASK A NOTE TO GO is who may write one, as for a
			 * PURGE message: a writer this node admits. */
			if (!node_admits(n, key)) {
				tally->waiting = 1;
				return FZN_NOTES_OK;
			}
			if (fzn_record_verify(rec, n->author.sign) != FZN_RECORD_OK) {
				tally->skipped++;
			} else {
				err = fzn_notes_erase_note(&n->store, fzn_record_subject(rec), NULL);
				if (err != FZN_NOTES_OK)
					return err;
				tally->purged++;
			}
		} else {
			tally->skipped++;
		}
		*cursor = seq;
	}
	return FZN_NOTES_OK;
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
		fzn_note_blob_ref_t ref;
		int in = 0;

		for (j = 0; j < scope.count && !in; j++)
			in = memcmp(scope.ids[j], view.nodes[i].id, FZN_TREE_ID_LEN) == 0;
		if (in && fzn_notes_ref_of(&view.nodes[i], &ref)
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
	/* A MEMBER'S PUSHED TEXT, sec 448: taken from a sender this node
	 * admits. A contact's requests never reach here. */
	{
		size_t taken = take_text(n, sender, request, request_len, reply, reply_cap);

		if (taken)
			return taken;
	}
	/* ONLY THE PURGE CONVERSATION, sec 519, AND WRAP KEYS, sec 520: a
	 * member's notes come in the journal now, so its INDEX and RECORDS go
	 * unanswered, and PUSH is retired. */
	if (request_len < 2u || request[0] != FZN_NOTES_SYNC_VERSION
	    || (request[1] != FZN_NOTES_SYNC_PURGE && request[1] != FZN_NOTES_SYNC_PURGE_ACK
	        && request[1] != FZN_NOTES_SYNC_PURGES_QUERY
	        && request[1] != FZN_NOTES_SYNC_WRAPS_QUERY
	        && request[1] != FZN_NOTES_SYNC_LACKS_QUERY && request[1] != FZN_NOTES_SYNC_GIVE))
		return 0;
	return fzn_notes_sync_answer(&n->store, n->author.policy, sender, now(n), request,
	                             request_len, reply, reply_cap);
}
