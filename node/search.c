/* This node's stores for the one search, and `list search`: sec 1287 step 1. */
#include "search.h"

#include "messages.h"
#include "groups.h"
#include "../contact/contact.h"
#include "../messages/attachment.h"
#include "../messages/reply.h"
#include "../sticker/pack.h"
#include "../local/escape.h"
#include "../wire/bytes.h"
#include "../hex/hex.h"

#include <stdio.h>
#include <string.h>

/* ---- lines ---------------------------------------------------------------- */

/* WHAT OF A LINE IS SEARCHED: its words -- a reply's own, not the line it
 * names; a file by its name; a sticker by its description -- and nothing of
 * a reaction or a shell. 1 with `*text`, `*len`, or 0. */
static int line_words(const fzn_message_t *p, const char **text, size_t *len)
{
	static fzn_attachment_t file;
	static fzn_sticker_ref_t sticker;
	uint8_t id[FZN_MESSAGE_ID_LEN];
	size_t at = 0, n = 0;

	if (!p->readable || !p->text_len
	    || fzn_message_reaction_parse(p->text, p->text_len, id, &at, &n))
		return 0;
	if (fzn_message_reply_parse(p->text, p->text_len, id, &at)) {
		*text = p->text + at;
		*len = p->text_len - at;
		return 1;
	}
	if (fzn_attachment_parse(p->text, p->text_len, &file)) {
		*text = file.name;
		*len = file.name_len;
		return 1;
	}
	if (fzn_sticker_ref_parse(p->text, p->text_len, &sticker)) {
		*text = sticker.text_len ? sticker.text : sticker.description;
		*len = sticker.text_len ? sticker.text_len : sticker.description_len;
		return *len != 0u;
	}
	*text = p->text;
	*len = p->text_len;
	return 1;
}

/* EVERY LINE HELD, newest first, as far as the store's own walk goes: its
 * budget. */
static int run_lines(void *ctx, const fzn_search_query_t *q, const uint8_t *asker, fzn_search_emit_t emit,
                     void *emit_ctx)
{
	static fzn_message_t page[FZN_MESSAGES_PAGE_MAX];
	fzn_node_messages_t *nm = ctx;
	char group_name[FZN_CONTACT_NAME_MAX + 1u];
	size_t from = 0, got = 0, i, group_len = 0;
	int more = 1;

	(void)asker;
	while (more && from + FZN_MESSAGES_PAGE_MAX <= FZN_MESSAGES_WALK_MAX) {
		if (fzn_messages_page(&nm->m, NULL, from, page, FZN_MESSAGES_PAGE_MAX, &got, &more) != FZN_MESSAGES_OK)
			return 0;
		for (i = 0; i < got; i++) {
			const fzn_message_t *p = &page[i];
			uint8_t shared[FZN_MESSAGE_ID_LEN];
			fzn_search_hit_t h;
			const char *text;
			size_t len;
			unsigned s;

			if (!line_words(p, &text, &len) || !(s = fzn_search_score(&q->words, text, len)))
				continue;
			memset(&h, 0, sizeof(h));
			memcpy(h.store, "lines", 6u);
			memcpy(h.key, p->contact, FZN_PUBKEY_LEN);
			memcpy(h.key + FZN_PUBKEY_LEN,
			       fzn_node_messages_shared_id(nm, p,
			                                   fzn_node_group_name(nm->m.store, p->contact, group_name,
			                                                       &group_len)
			                                           == FZN_CONTACT_OK,
			                                   shared),
			       FZN_MESSAGE_ID_LEN);
			h.key_len = FZN_PUBKEY_LEN + FZN_MESSAGE_ID_LEN;
			h.score = s;
			h.time_ms = p->stime;
			fzn_search_snippet(q, text, len, &h);
			if (!emit(emit_ctx, &h))
				return 1;
		}
		if (!got)
			break;
		from += got;
	}
	return 1;
}

/* ---- stickers ---------------------------------------------------------------- */


/* ---- contacts ---------------------------------------------------------------- */

struct contact_walk {
	fzn_search_emit_t emit;
	void *emit_ctx;
	const fzn_search_query_t *q;
};

static int contact_one(void *ctx, const fzn_contact_t *c)
{
	struct contact_walk *w = ctx;
	fzn_search_hit_t h;
	unsigned s = fzn_search_score(&w->q->words, c->name, c->name_len);

	if (!s)
		return 1;
	memset(&h, 0, sizeof(h));
	memcpy(h.store, "contacts", 9u);
	memcpy(h.key, c->key, FZN_PUBKEY_LEN);
	h.key_len = FZN_PUBKEY_LEN;
	h.score = s;
	h.time_ms = c->added_at_ms;
	fzn_search_snippet(w->q, c->name, c->name_len, &h);
	return w->emit(w->emit_ctx, &h);
}

static int run_contacts(void *ctx, const fzn_search_query_t *q, const uint8_t *asker, fzn_search_emit_t emit,
                        void *emit_ctx)
{
	struct contact_walk w = { emit, emit_ctx, q };

	(void)asker;
	return fzn_contact_each(ctx, contact_one, &w) == FZN_CONTACT_OK;
}

size_t fzn_node_search_stores(fzn_node_search_t *s, fzn_search_store_t out[FZN_NODE_SEARCH_STORES])
{
	size_t n = 0;

	if (!s || !out)
		return 0;
	if (s->messages)
		out[n++] = (fzn_search_store_t){ "lines", run_lines, s->messages };
	/* A SUBSYSTEM'S OWN STORE, as its module gives it: the kept stickers'
	 * is `fzn_node_stickers_search`'s, added by whoever has stickers. */
	if (s->extra.run)
		out[n++] = s->extra;
	if (s->contacts)
		out[n++] = (fzn_search_store_t){ "contacts", run_contacts, (void *)(uintptr_t)s->contacts };
	return n;
}

/* ---- the verb -------------------------------------------------------------- */

static int word(const uint8_t **at, size_t *left, const uint8_t **w, size_t *n)
{
	size_t i = 0;

	while (*left && **at == ' ')
		(*at)++, (*left)--;
	if (!*left)
		return 0;
	while (i < *left && (*at)[i] != ' ')
		i++;
	*w = *at;
	*n = i;
	*at += i;
	*left -= i;
	return 1;
}

static int is(const uint8_t *w, size_t n, const char *s)
{
	return n == strlen(s) && !memcmp(w, s, n);
}

static int unhex(const uint8_t *in, size_t n, uint8_t *out)
{
	size_t i;

	for (i = 0; i < n / 2u; i++) {
		int hi = in[2u * i], lo = in[2u * i + 1u];

		hi = hi >= '0' && hi <= '9' ? hi - '0' : hi >= 'a' && hi <= 'f' ? hi - 'a' + 10 : -1;
		lo = lo >= '0' && lo <= '9' ? lo - '0' : lo >= 'a' && lo <= 'f' ? lo - 'a' + 10 : -1;
		if (hi < 0 || lo < 0)
			return 0;
		out[i] = (uint8_t)(hi << 4 | lo);
	}
	return (n % 2u) == 0u;
}

static int number(const uint8_t *w, size_t n, uint64_t *v)
{
	size_t i;

	if (!n || n > 19u)
		return 0;
	for (*v = 0, i = 0; i < n; i++) {
		if (w[i] < '0' || w[i] > '9')
			return 0;
		*v = *v * 10u + (uint64_t)(w[i] - '0');
	}
	return 1;
}

/* `STORE,KEY,SCORE,TIME`, a cursor as a row writes it: 1 into `h`, or 0. */
static int cursor_of(const uint8_t *w, size_t n, fzn_search_hit_t *h)
{
	const uint8_t *f[4];
	size_t len[4], k = 0, i, start = 0;
	uint64_t v = 0;

	for (i = 0; i <= n && k < 4u; i++)
		if (i == n || w[i] == ',') {
			f[k] = w + start;
			len[k++] = i - start;
			start = i + 1u;
		}
	if (k != 4u || start != n + 1u || !len[0] || len[0] > FZN_SEARCH_STORE_NAME_MAX
	    || len[1] > 2u * FZN_SEARCH_KEY_MAX || !unhex(f[1], len[1], h->key) || !number(f[2], len[2], &v)
	    || v > 0xffffffffu)
		return 0;
	memset(h->store, 0, sizeof(h->store));
	memcpy(h->store, f[0], len[0]);
	h->key_len = len[1] / 2u;
	h->score = (unsigned)v;
	return number(f[3], len[3], &h->time_ms);
}

size_t fzn_node_search_local(void *ctx, fzn_origin_t origin, const fzn_request_t *request, char *reply,
                             size_t cap)
{
	static const char USAGE[] = "malformed list search [in STORE] [after STORE,KEY,SCORE,TIME] WORDS\n";
	static fzn_search_hit_t hits[FZN_SEARCH_K_MAX], after;
	static fzn_search_query_t q;
	fzn_search_store_t stores[FZN_NODE_SEARCH_STORES];
	const char *names[FZN_NODE_SEARCH_STORES];
	char store_names[FZN_NODE_SEARCH_STORES][FZN_SEARCH_STORE_NAME_MAX + 1u];
	const uint8_t *at, *w;
	size_t left, n, n_stores, n_names = 0, count = 0, i, used, k;
	int more = 0, has_after = 0, cut = 0;

	if (!ctx || !request || !reply || request->parsed != FZN_VERB_LIST || !request->arg)
		return 0;
	at = request->arg;
	left = request->arg_len;
	if (!word(&at, &left, &w, &n) || !is(w, n, "search"))
		return 0;
	if (origin != FZN_ORIGIN_SAME_USER)
		return (size_t)snprintf(reply, cap, "denied a search is this node's own user's\n");
	for (;;) {
		const uint8_t *save = at;
		size_t save_left = left;

		if (!word(&at, &left, &w, &n))
			return (size_t)snprintf(reply, cap, USAGE);
		if (is(w, n, "in") && n_names < FZN_NODE_SEARCH_STORES && word(&at, &left, &w, &n)
		    && n <= FZN_SEARCH_STORE_NAME_MAX) {
			memcpy(store_names[n_names], w, n);
			store_names[n_names][n] = '\0';
			names[n_names] = store_names[n_names];
			n_names++;
			continue;
		}
		if (is(w, n, "after") && !has_after && word(&at, &left, &w, &n) && cursor_of(w, n, &after)) {
			has_after = 1;
			continue;
		}
		at = save;
		left = save_left;
		break;
	}
	while (left && *at == ' ')
		at++, left--;
	if (!fzn_search_query_init(&q, (const char *)at, left, 20u))
		return (size_t)snprintf(reply, cap, USAGE);
	q.stores = n_names ? names : NULL;
	q.n_stores = n_names;
	q.after = has_after ? &after : NULL;
	n_stores = fzn_node_search_stores(ctx, stores);
	if (!fzn_search_run(stores, n_stores, &q, NULL, hits, &count, &more) && !count)
		return (size_t)snprintf(reply, cap, "error a store would not read\n");
	/* AS MANY ROWS AS THE REPLY HOLDS, the rest said as more. */
	used = (size_t)snprintf(reply, cap, "ok %zu %d", count, more);
	for (i = 0; i < count && !cut; i++) {
		char row[FZN_SEARCH_STORE_NAME_MAX + 2u * FZN_SEARCH_KEY_MAX + 48u + 3u * FZN_SEARCH_SNIPPET_MAX];
		size_t r = (size_t)snprintf(row, sizeof(row), " %s,", hits[i].store), e = 0;

		for (k = 0; k < hits[i].key_len; k++)
			fzn_hex_byte(hits[i].key[k], row + r + 2u * k);
		r += 2u * hits[i].key_len;
		r += (size_t)snprintf(row + r, sizeof(row) - r, ",%u,%llu,", hits[i].score,
		                      (unsigned long long)hits[i].time_ms);
		(void)fzn_escape((const uint8_t *)hits[i].snippet, hits[i].snippet_len, row + r, sizeof(row) - r - 1u, &e);
		r += e;
		if (used + r + 2u > cap) {
			cut = 1;
			break;
		}
		memcpy(reply + used, row, r);
		used += r;
	}
	if (cut) {
		/* FEWER SHOWN: the count says how many, and more follows them. */
		char head[32];
		size_t h_len = (size_t)snprintf(head, sizeof(head), "ok %zu %d", count, more);
		size_t now_len = (size_t)snprintf(head, sizeof(head), "ok %zu 1", i);

		memmove(reply + now_len, reply + h_len, used - h_len);
		memcpy(reply, head, now_len);
		used = used - h_len + now_len;
	}
	reply[used++] = '\n';
	reply[used] = '\0';
	return used;
}
