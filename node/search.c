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

/* THE MOST A PAGE OF ROWS TAKES, every hit at its longest. */
#define FZND_SEARCH_ROWS_MAX (FZN_SEARCH_K_MAX * (FZN_SEARCH_STORE_NAME_MAX + 2u * FZN_SEARCH_KEY_MAX + 48u + 3u * FZN_SEARCH_SNIPPET_MAX))

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

/* WHAT A CONTACT ASKING MAY BE ANSWERED OF A CONVERSATION, sec 1287 step
 * 4: of its own with this user, everything; of a group's, as a member, the
 * lines from its joining on -- every line where the group backfills (sec
 * 905), as a later member is given the history -- and of any other,
 * nothing. Kept for the conversation last asked about, since a walk meets
 * one conversation's lines together. */
struct reach {
	uint8_t key[FZN_PUBKEY_LEN];
	int known, open;
	uint64_t floor_ms;
};

static void reach_of(fzn_node_messages_t *nm, const uint8_t *asker, const uint8_t *conversation, int is_group,
                     struct reach *r)
{
	static fzn_group_t g;

	if (r->known && memcmp(r->key, conversation, FZN_PUBKEY_LEN) == 0)
		return;
	memcpy(r->key, conversation, FZN_PUBKEY_LEN);
	r->known = 1;
	r->open = 0;
	r->floor_ms = 0;
	if (!is_group) {
		r->open = memcmp(conversation, asker, FZN_PUBKEY_LEN) == 0;
		return;
	}
	/* A LOG THAT WILL NOT READ, or a joining this host cannot see, answers
	 * nothing: withheld, as sec 804 withholds a share. */
	if (!nm->m.hash || fzn_group_log_get(nm->m.store, conversation, &g) != FZN_GROUP_LOG_OK
	    || !fzn_group_is_member(&g, asker))
		return;
	r->floor_ms = g.backfill ? 0u : fzn_node_group_joined_ms(nm->m.store, nm->m.hash, conversation, &g, asker);
	r->open = r->floor_ms != UINT64_MAX;
}

/* EVERY LINE HELD, newest first, as far as the store's own walk goes: its
 * budget. A contact asking (`asker` set) is answered only the lines
 * `reach_of` says it reads. */
static int run_lines(void *ctx, const fzn_search_query_t *q, const uint8_t *asker, fzn_search_emit_t emit,
                     void *emit_ctx)
{
	static fzn_message_t page[FZN_MESSAGES_PAGE_MAX];
	const fzn_node_search_t *ns = ctx;
	fzn_node_messages_t *nm = ns->messages;
	const uint8_t *user = ns->user ? *ns->user : NULL;
	char group_name[FZN_CONTACT_NAME_MAX + 1u];
	size_t from = 0, got = 0, i, group_len = 0;
	struct reach r = { { 0 }, 0, 0, 0 };
	int more = 1;

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

			int is_group;

			if (!line_words(p, &text, &len) || !(s = fzn_search_score(&q->words, text, len)))
				continue;
			is_group = fzn_node_group_name(nm->m.store, p->contact, group_name, &group_len) == FZN_CONTACT_OK;
			if (asker) {
				reach_of(nm, asker, p->contact, is_group, &r);
				if (!r.open || p->stime < r.floor_ms)
					continue;
			}
			memset(&h, 0, sizeof(h));
			memcpy(h.store, "lines", 6u);
			memcpy(h.key, p->contact, FZN_PUBKEY_LEN);
			/* A CONTACT'S CONVERSATION BY BOTH ITS ENDS, sec 1294: each user
			 * keeps it under the other's key, so the line a contact's host
			 * finds was another item here until keyed alike. */
			if (!is_group && user) {
				size_t b;

				for (b = 0; b < FZN_PUBKEY_LEN; b++)
					h.key[b] ^= user[b];
			}
			memcpy(h.key + FZN_PUBKEY_LEN, fzn_node_messages_shared_id(nm, p, is_group, shared),
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
	/* NO TIME: when a contact was added differs host by host, and an
	 * item's place in the one order must not (sec 1287), or a host's copy
	 * comes back on the next page. */
	fzn_search_snippet(w->q, c->name, c->name_len, &h);
	return w->emit(w->emit_ctx, &h);
}

static int run_contacts(void *ctx, const fzn_search_query_t *q, const uint8_t *asker, fzn_search_emit_t emit,
                        void *emit_ctx)
{
	struct contact_walk w = { emit, emit_ctx, q };

	/* THIS USER'S CONTACTS ARE ITS OWN: nobody else is answered them. */
	if (asker)
		return 1;
	return fzn_contact_each(ctx, contact_one, &w) == FZN_CONTACT_OK;
}

size_t fzn_node_search_stores(fzn_node_search_t *s, fzn_search_store_t out[FZN_NODE_SEARCH_STORES])
{
	size_t n = 0, i;

	if (!s || !out)
		return 0;
	if (s->messages)
		out[n++] = (fzn_search_store_t){ "lines", run_lines, s };
	/* A SUBSYSTEM'S OWN STORE, as its module gives it: the kept stickers'
	 * is `fzn_node_stickers_search`'s, added by whoever has stickers. */
	for (i = 0; i < FZN_NODE_SEARCH_EXTRA; i++)
		if (s->extra[i].run)
			out[n++] = s->extra[i];
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

/* THE ROWS AND THEIR SPACE: what a search line takes, `[with NAME] [in
 * STORE]... [after CURSOR] WORDS`, read into `a` with K, and the contact
 * NAME names into `with` (`*has_with` set); 1, or 0 for a line of the wrong
 * shape -- a NAME that is no contact here included. */
static int parse(const fzn_node_search_t *s, const uint8_t *at, size_t left, size_t k, fzn_search_ask_t *a,
                 uint8_t with[FZN_PUBKEY_LEN], int *has_with)
{
	const uint8_t *w;
	size_t n, n_names = 0;
	int has_after = 0;

	memset(a, 0, sizeof(*a));
	*has_with = 0;
	for (;;) {
		const uint8_t *save = at;
		size_t save_left = left;

		if (!word(&at, &left, &w, &n))
			return 0;
		if (is(w, n, "with") && !*has_with && s->contacts && word(&at, &left, &w, &n)) {
			fzn_contact_t c;

			if (fzn_contact_find(s->contacts, (const char *)w, n, &c) != FZN_CONTACT_OK)
				return 0;
			memcpy(with, c.key, FZN_PUBKEY_LEN);
			*has_with = 1;
			continue;
		}
		if (is(w, n, "in") && n_names < FZN_SEARCH_ASK_STORES_MAX && word(&at, &left, &w, &n)
		    && n <= FZN_SEARCH_STORE_NAME_MAX) {
			memcpy(a->names[n_names], w, n);
			a->stores[n_names] = a->names[n_names];
			n_names++;
			continue;
		}
		if (is(w, n, "after") && !has_after && word(&at, &left, &w, &n) && cursor_of(w, n, &a->after)) {
			has_after = 1;
			continue;
		}
		at = save;
		left = save_left;
		break;
	}
	while (left && *at == ' ')
		at++, left--;
	if (left > FZN_SEARCH_TEXT_MAX)
		return 0;
	memcpy(a->words, at, left);
	a->words_len = left;
	if (!fzn_search_query_init(&a->query, a->words, a->words_len, k))
		return 0;
	a->query.stores = n_names ? a->stores : NULL;
	a->query.n_stores = n_names;
	a->query.after = has_after ? &a->after : NULL;
	return 1;
}

/* `ok COUNT MORE` and EXTRA, then as many rows as the reply holds: fewer
 * shown, the count says how many and more follows them. */
static size_t rows(const fzn_search_hit_t *hits, size_t count, int more, const char *extra, char *reply,
                   size_t cap)
{
	static char body[FZND_SEARCH_ROWS_MAX];
	size_t used = 0, i, k, shown = count, head;

	for (i = 0; i < count; i++) {
		char row[FZN_SEARCH_STORE_NAME_MAX + 2u * FZN_SEARCH_KEY_MAX + 48u + 3u * FZN_SEARCH_SNIPPET_MAX];
		size_t r = (size_t)snprintf(row, sizeof(row), " %s,", hits[i].store), e = 0;

		for (k = 0; k < hits[i].key_len; k++)
			fzn_hex_byte(hits[i].key[k], row + r + 2u * k);
		r += 2u * hits[i].key_len;
		r += (size_t)snprintf(row + r, sizeof(row) - r, ",%u,%llu,", hits[i].score,
		                      (unsigned long long)hits[i].time_ms);
		(void)fzn_escape((const uint8_t *)hits[i].snippet, hits[i].snippet_len, row + r, sizeof(row) - r - 1u, &e);
		r += e;
		/* ROOM KEPT for the head, at most 64 bytes, and the line's end. */
		if (used + r + 66u > cap || used + r > sizeof(body)) {
			shown = i;
			more = 1;
			break;
		}
		memcpy(body + used, row, r);
		used += r;
	}
	head = (size_t)snprintf(reply, cap, "ok %zu %d%s", shown, more, extra);
	if (head + used + 2u > cap)
		return (size_t)snprintf(reply, cap, "error the reply would not hold a row\n");
	memcpy(reply + head, body, used);
	used += head;
	reply[used++] = '\n';
	reply[used] = '\0';
	return used;
}

/* THE SEARCH OF THIS USER'S HOSTS IN HAND, sec 1287 step 3: one at a time,
 * a later `fetch search` replacing it; its own hits and every answer's,
 * merged when asked. */
static struct {
	unsigned generation;
	int live;
	fzn_search_ask_t ask;
	/* A SEARCH WITH A CONTACT, sec 1292: its root key, where `has_with`. */
	uint8_t with[FZN_PUBKEY_LEN];
	int has_with;
	fzn_search_hit_t hits[(1u + FZN_NODE_SEARCH_HOSTS_MAX) * FZN_SEARCH_K_MAX];
	size_t n, asked, answered, late;
	int more_held;
} held;

void fzn_node_search_answered(fzn_node_search_t *s, unsigned generation, const uint8_t *answer, size_t len)
{
	static fzn_search_hit_t got[FZN_SEARCH_K_MAX];
	size_t n = 0;
	int more = 0;

	(void)s;
	if (!held.live || generation != held.generation)
		return;
	if (!answer || !fzn_search_answer_read(answer, len, got, FZN_SEARCH_K_MAX, &n, &more)) {
		held.late++;
		return;
	}
	held.answered++;
	held.more_held |= more;
	if (n > sizeof(held.hits) / sizeof(held.hits[0]) - held.n)
		n = sizeof(held.hits) / sizeof(held.hits[0]) - held.n;
	memcpy(held.hits + held.n, got, n * sizeof(got[0]));
	held.n += n;
}

size_t fzn_node_search_remote(fzn_node_search_t *s, const uint8_t *asker, const uint8_t *request, size_t len,
                              uint8_t *reply, size_t cap)
{
	fzn_search_store_t stores[FZN_NODE_SEARCH_STORES];
	const size_t n = s ? fzn_node_search_stores(s, stores) : 0u;

	return n ? fzn_search_answer_ask(stores, n, request, len, asker, reply, cap) : 0u;
}

int fzn_node_search_is_contact(const fzn_node_search_t *s, const uint8_t key[FZN_PUBKEY_LEN])
{
	fzn_contact_t c;

	return s && s->contacts && key && fzn_contact_get(s->contacts, key, &c) == FZN_CONTACT_OK;
}

int fzn_node_search_list(fzn_node_search_t *s, const uint8_t *ask, size_t len, const uint8_t *with,
                         fzn_search_hit_t *hits, size_t *count, int *more)
{
	static fzn_search_ask_t a;
	fzn_search_store_t stores[FZN_NODE_SEARCH_STORES];
	size_t n;

	if (!s || !fzn_search_ask_read(ask, len, &a))
		return 0;
	n = fzn_node_search_stores(s, stores);
	return fzn_search_run(stores, n, &a.query, with, hits, count, more) || *count;
}

int fzn_node_search_fetch(fzn_node_search_t *s, const uint8_t *ask, size_t len, const uint8_t *with,
                          size_t *asked)
{
	fzn_search_store_t stores[FZN_NODE_SEARCH_STORES];
	size_t n;

	held.live = 0;
	held.generation++;
	if (!s || !fzn_search_ask_read(ask, len, &held.ask))
		return 0;
	held.has_with = with != NULL;
	if (with)
		memcpy(held.with, with, FZN_PUBKEY_LEN);
	n = fzn_node_search_stores(s, stores);
	/* WITH A CONTACT, sec 1292: what this user and it share, so this
	 * host's stores run as that contact -- each answering what the
	 * contact reads here -- and its hosts are asked, which run theirs
	 * as this user. */
	if (!fzn_search_run(stores, n, &held.ask.query, with, held.hits, &held.n, &held.more_held) && !held.n)
		return 0;
	held.asked = held.answered = held.late = 0;
	held.live = 1;
	if (s->ask_hosts)
		held.asked = s->ask_hosts(s->ask_hosts_ctx, ask, len, with, held.generation);
	*asked = held.asked;
	return 1;
}

int fzn_node_search_held(fzn_node_search_t *s, fzn_search_hit_t *hits, size_t *count, int *more, size_t *asked,
                         size_t *answered, size_t *late)
{
	if (!s || !held.live)
		return 0;
	(void)fzn_search_merge(&held.ask.query, held.hits, held.n, held.more_held, hits, count, more);
	*asked = held.asked;
	*answered = held.answered;
	*late = held.late;
	return 1;
}

size_t fzn_node_search_local(void *ctx, fzn_origin_t origin, const fzn_request_t *request, char *reply,
                             size_t cap)
{
	static const char USAGE[] =
	        "malformed %s search [with CONTACT] [in STORE] [after STORE,KEY,SCORE,TIME] WORDS\n";
	static fzn_search_hit_t hits[FZN_SEARCH_K_MAX];
	static fzn_search_ask_t a;
	fzn_node_search_t *s = ctx;
	fzn_search_store_t stores[FZN_NODE_SEARCH_STORES];
	const uint8_t *at, *w;
	uint8_t with[FZN_PUBKEY_LEN];
	size_t left, n, n_stores, count = 0;
	int more = 0, has_with = 0;

	if (!s || !request || !reply || !request->arg
	    || (request->parsed != FZN_VERB_LIST && request->parsed != FZN_VERB_FETCH
	        && request->parsed != FZN_VERB_GET))
		return 0;
	at = request->arg;
	left = request->arg_len;
	if (!word(&at, &left, &w, &n) || !is(w, n, "search"))
		return 0;
	if (origin != FZN_ORIGIN_SAME_USER)
		return (size_t)snprintf(reply, cap, "denied a search is this node's own user's\n");
	n_stores = fzn_node_search_stores(s, stores);
	/* THE SEARCH OF THIS USER'S HOSTS, merged: as far as they answered. */
	if (request->parsed == FZN_VERB_GET) {
		char extra[64];
		size_t asked = 0, answered = 0, late = 0;

		if (!fzn_node_search_held(s, hits, &count, &more, &asked, &answered, &late))
			return (size_t)snprintf(reply, cap, "error no search asked\n");
		(void)snprintf(extra, sizeof(extra), " %zu %zu %zu", asked, answered, late);
		return rows(hits, count, more, extra, reply, cap);
	}
	if (request->parsed == FZN_VERB_FETCH) {
		static uint8_t ask[FZN_SEARCH_TEXT_MAX + 512u];
		size_t ask_len;

		size_t asked = 0;

		if (!parse(s, at, left, 20u, &a, with, &has_with)
		    || !(ask_len = fzn_search_ask_write(a.words, a.words_len, &a.query, ask, sizeof(ask))))
			return (size_t)snprintf(reply, cap, USAGE, "fetch");
		if (!fzn_node_search_fetch(s, ask, ask_len, has_with ? with : NULL, &asked))
			return (size_t)snprintf(reply, cap, "error a store would not read\n");
		return (size_t)snprintf(reply, cap, "ok %zu\n", asked);
	}
	if (!parse(s, at, left, 20u, &a, with, &has_with))
		return (size_t)snprintf(reply, cap, USAGE, "list");
	if (!fzn_search_run(stores, n_stores, &a.query, has_with ? with : NULL, hits, &count, &more) && !count)
		return (size_t)snprintf(reply, cap, "error a store would not read\n");
	return rows(hits, count, more, "", reply, cap);
}
