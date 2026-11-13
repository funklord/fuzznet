/* See decisions.h. */

#include "decisions.h"

#include "../local/escape.h"
#include "../state/setting.h"
#include "../hex/hex.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REF_HOST_HEX 8u
#define REF_TEXT_MAX (20u + 1u + REF_HOST_HEX)


/* ONE DECISION AS HELD: what it says, and whether another supersedes it. */
struct held {
	fzn_node_decision_t d;
	char self[REF_TEXT_MAX + 1u];
	char bases[FZN_SETTING_VALUE_MAX + 1u];
	int superseded;
};

struct gathered {
	const uint8_t *subject; /* one, or NULL for all */
	size_t subject_len;
	struct held *at;
	size_t n, cap;
	int failed;
};

static size_t ref_text(uint64_t number, const uint8_t host[FZN_PUBKEY_LEN], char *out)
{
	size_t n = (size_t)sprintf(out, "%llu.", (unsigned long long)number), i;

	for (i = 0; i < REF_HOST_HEX / 2u; i++) {
		fzn_hex_byte(host[i], out + n);
		n += 2u;
	}
	out[n] = '\0';
	return n;
}

static int subject_ok(const uint8_t *subject, size_t len)
{
	uint8_t key[FZN_SETTING_KEY_MAX];

	if (!subject || !len || len > FZN_NODE_DECIDED_SUBJECT_MAX)
		return 0;
	memcpy(key, FZN_NODE_DECIDED_PREFIX, FZN_NODE_DECIDED_PREFIX_LEN);
	memcpy(key + FZN_NODE_DECIDED_PREFIX_LEN, subject, len);
	return fzn_setting_key_ok(key, FZN_NODE_DECIDED_PREFIX_LEN + len);
}

static int grounds_ok(const uint8_t *g, size_t len)
{
	size_t i;

	if (!len || len > FZN_NODE_DECIDED_GROUNDS_MAX)
		return 0;
	for (i = 0; i < len; i++)
		if (g[i] <= ' ' || g[i] >= 0x7fu)
			return 0;
	return 1;
}

/* `word` of `*at`, up to a space, which it passes: 0 when there is none. */
static int field(const uint8_t **at, size_t *left, const uint8_t **w, size_t *w_len)
{
	const uint8_t *space = *left ? memchr(*at, ' ', *left) : NULL;

	if (!space)
		return 0;
	*w = *at;
	*w_len = (size_t)(space - *at);
	*left -= *w_len + 1u;
	*at = space + 1;
	return *w_len != 0u;
}

/* ONE RECORD READ AS A DECISION, or passed over: a host writes what it likes
 * under the prefix, and one that will not read decides nothing. */
static void gather(void *ctx, const fzn_setting_t *s)
{
	struct gathered *g = ctx;
	struct held *h;
	const uint8_t *at = s->value, *self, *bases, *grounds;
	size_t left = s->value_len, self_len, bases_len, grounds_len;
	size_t subject_len = s->key_len - FZN_NODE_DECIDED_PREFIX_LEN;

	if (g->failed || !s->set
	    || (g->subject
	        && (subject_len != g->subject_len
	            || memcmp(s->key + FZN_NODE_DECIDED_PREFIX_LEN, g->subject, subject_len) != 0))
	    || subject_len > FZN_NODE_DECIDED_SUBJECT_MAX || !field(&at, &left, &self, &self_len)
	    || self_len > REF_TEXT_MAX || !field(&at, &left, &bases, &bases_len)
	    || !field(&at, &left, &grounds, &grounds_len) || !grounds_ok(grounds, grounds_len))
		return;
	if (g->n == g->cap) {
		size_t cap = g->cap ? g->cap * 2u : 16u;
		struct held *more = realloc(g->at, cap * sizeof(*more));

		if (!more) {
			g->failed = 1;
			return;
		}
		g->at = more;
		g->cap = cap;
	}
	h = &g->at[g->n++];
	memset(h, 0, sizeof(*h));
	memcpy(h->d.subject, s->key + FZN_NODE_DECIDED_PREFIX_LEN, subject_len);
	h->d.subject_len = subject_len;
	memcpy(h->d.host, s->setter, FZN_PUBKEY_LEN);
	h->d.at = s->version;
	memcpy(h->d.grounds, grounds, grounds_len);
	h->d.grounds_len = grounds_len;
	memcpy(h->d.value, at, left);
	h->d.value_len = left;
	memcpy(h->self, self, self_len);
	memcpy(h->bases, bases, bases_len);
}

static int by_subject_newest(const void *a, const void *b)
{
	const struct held *x = a, *y = b;
	size_t n = x->d.subject_len < y->d.subject_len ? x->d.subject_len : y->d.subject_len;
	int c = memcmp(x->d.subject, y->d.subject, n);

	if (c)
		return c;
	if (x->d.subject_len != y->d.subject_len)
		return x->d.subject_len < y->d.subject_len ? -1 : 1;
	if (x->d.at != y->d.at)
		return x->d.at > y->d.at ? -1 : 1;
	return -memcmp(x->d.host, y->d.host, FZN_PUBKEY_LEN);
}

static int same_subject(const struct held *x, const struct held *y)
{
	return x->d.subject_len == y->d.subject_len
	       && memcmp(x->d.subject, y->d.subject, x->d.subject_len) == 0;
}

/* WHETHER `bases` NAMES `self`, as a whole item of the list. */
static int names(const char *bases, const char *self)
{
	size_t len = strlen(self);
	const char *at = bases;

	while ((at = strstr(at, self)) != NULL) {
		if ((at == bases || at[-1] == ',') && (at[len] == ',' || at[len] == '\0'))
			return 1;
		at++;
	}
	return 0;
}

/* EACH RUN OF ONE SUBJECT: every decision another of it names, marked. */
static void mark_superseded(struct held *all, size_t n)
{
	size_t from = 0, to, i, j;

	for (; from < n; from = to) {
		for (to = from + 1u; to < n && same_subject(&all[from], &all[to]); to++)
			;
		for (i = from; i < to; i++)
			for (j = from; j < to; j++)
				if (i != j && names(all[j].bases, all[i].self))
					all[i].superseded = 1;
	}
}

/* EVERY DECISION HELD, read once. Walking opens every record of every kind,
 * and a host that observes often holds far more of those than it does
 * decisions, so a write must not pay for that walk. */
static struct gathered kept;
static int kept_whole;

void fzn_node_decisions_forget(void)
{
	free(kept.at);
	memset(&kept, 0, sizeof(kept));
	kept_whole = 0;
}

static int gather_all(const fzn_node_records_t *nr, struct gathered *g)
{
	static const uint8_t PREFIX[] = FZN_NODE_DECIDED_PREFIX;
	size_t i;

	if (!kept_whole) {
		fzn_node_decisions_forget();
		if (!fzn_node_records_under(nr, PREFIX, FZN_NODE_DECIDED_PREFIX_LEN, gather, &kept)
		    || kept.failed) {
			fzn_node_decisions_forget();
			return 0;
		}
		kept_whole = 1;
	}
	g->at = kept.n ? malloc(kept.n * sizeof(*g->at)) : NULL;
	if (kept.n && !g->at)
		return 0;
	for (i = 0; i < kept.n; i++)
		if (!g->subject
		    || (kept.at[i].d.subject_len == g->subject_len
		        && memcmp(kept.at[i].d.subject, g->subject, g->subject_len) == 0)) {
			g->at[g->n] = kept.at[i];
			g->at[g->n++].superseded = 0;
		}
	if (g->n)
		qsort(g->at, g->n, sizeof(*g->at), by_subject_newest);
	mark_superseded(g->at, g->n);
	return 1;
}

long fzn_node_decisions_heads(const fzn_node_records_t *nr, const uint8_t *subject,
                              size_t subject_len,
                              void (*each)(void *ctx, const fzn_node_decision_t *d), void *ctx)
{
	struct gathered g;
	size_t i;
	long heads = 0;

	if (!nr || !subject_ok(subject, subject_len))
		return -1;
	memset(&g, 0, sizeof(g));
	g.subject = subject;
	g.subject_len = subject_len;
	if (!gather_all(nr, &g))
		return -1;
	for (i = 0; i < g.n; i++)
		if (!g.at[i].superseded) {
			heads++;
			if (each)
				each(ctx, &g.at[i].d);
		}
	free(g.at);
	return heads;
}

long fzn_node_decisions_forks(const fzn_node_records_t *nr,
                              void (*each)(void *ctx, const fzn_node_decision_t *d), void *ctx)
{
	struct gathered g;
	size_t from, to, i;
	long forks = 0;

	if (!nr)
		return -1;
	memset(&g, 0, sizeof(g));
	if (!gather_all(nr, &g))
		return -1;
	for (from = 0; from < g.n; from = to) {
		const struct held *first = NULL;
		int differ = 0;

		for (to = from; to < g.n && same_subject(&g.at[from], &g.at[to]); to++) {
			const struct held *h = &g.at[to];

			if (h->superseded)
				continue;
			if (!first)
				first = h;
			else if (h->d.value_len != first->d.value_len
			         || memcmp(h->d.value, first->d.value, h->d.value_len) != 0)
				differ = 1;
		}
		if (!differ)
			continue;
		forks++;
		if (each)
			for (i = from; i < to; i++)
				if (!g.at[i].superseded)
					each(ctx, &g.at[i].d);
	}
	free(g.at);
	return forks;
}

fzn_node_records_err_t fzn_node_decisions_write(const fzn_node_records_t *nr,
                                                const uint8_t *subject, size_t subject_len,
                                                uint64_t self,
                                                const fzn_node_decision_ref_t *seen,
                                                const uint8_t *grounds, size_t grounds_len,
                                                const uint8_t *value, size_t value_len)
{
	uint8_t key[FZN_SETTING_KEY_MAX], text[FZN_SETTING_VALUE_MAX];
	char self_text[REF_TEXT_MAX + 1u], one[REF_TEXT_MAX + 1u];
	char bases[FZN_SETTING_VALUE_MAX + 1u];
	struct gathered g;
	size_t self_len, bases_len = 0, fixed, i, at;
	fzn_node_records_err_t err;

	if (!nr || !nr->id || !nr->now_ms || !subject_ok(subject, subject_len)
	    || (grounds && !grounds_ok(grounds, grounds_len)) || (value_len && !value))
		return FZN_NODE_RECORDS_MALFORMED;
	if (!grounds) {
		grounds = (const uint8_t *)"-";
		grounds_len = 1u;
	}
	self_len = ref_text(self ? self : nr->now_ms(), nr->id->pubkey, self_text);
	fixed = self_len + 1u + 1u + grounds_len + 1u + value_len;
	if (fixed + 1u > FZN_SETTING_VALUE_MAX)
		return FZN_NODE_RECORDS_MALFORMED;
	memset(&g, 0, sizeof(g));
	g.subject = subject;
	g.subject_len = subject_len;
	if (!gather_all(nr, &g))
		return FZN_NODE_RECORDS_BACKEND;
	if (seen) {
		size_t n = ref_text(seen->number, seen->host, one);

		if (fixed - 1u + n <= FZN_SETTING_VALUE_MAX) {
			memcpy(bases, one, n + 1u);
			bases_len = n;
		}
	}
	for (i = 0; i < g.n; i++) {
		size_t n = strlen(g.at[i].self);

		if (g.at[i].superseded || (bases_len && names(bases, g.at[i].self)))
			continue;
		if (fixed + bases_len + 1u + n > FZN_SETTING_VALUE_MAX)
			break;
		if (bases_len)
			bases[bases_len++] = ',';
		memcpy(bases + bases_len, g.at[i].self, n + 1u);
		bases_len += n;
	}
	free(g.at);
	if (!bases_len) {
		bases[0] = '-';
		bases[1] = '\0';
		bases_len = 1u;
	}
	at = 0;
	memcpy(text, self_text, self_len);
	at += self_len;
	text[at++] = ' ';
	memcpy(text + at, bases, bases_len);
	at += bases_len;
	text[at++] = ' ';
	memcpy(text + at, grounds, grounds_len);
	at += grounds_len;
	text[at++] = ' ';
	if (value_len)
		memcpy(text + at, value, value_len);
	at += value_len;
	memcpy(key, FZN_NODE_DECIDED_PREFIX, FZN_NODE_DECIDED_PREFIX_LEN);
	memcpy(key + FZN_NODE_DECIDED_PREFIX_LEN, subject, subject_len);
	err = fzn_node_records_write(nr, key, FZN_NODE_DECIDED_PREFIX_LEN + subject_len, text, at);
	if (err == FZN_NODE_RECORDS_OK) {
		/* KEPT AS IT WENT OUT, so the next write has seen this one. */
		static fzn_setting_t mine;

		memset(&mine, 0, sizeof(mine));
		mine.key = key;
		mine.key_len = FZN_NODE_DECIDED_PREFIX_LEN + subject_len;
		mine.value = text;
		mine.value_len = at;
		mine.setter = nr->id->pubkey;
		mine.version = nr->now_ms();
		mine.set = 1;
		gather(&kept, &mine);
		if (kept.failed)
			fzn_node_decisions_forget();
	}
	return err;
}

/* ---- the verbs --------------------------------------------------------- */

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
	return 1;
}

static int is_word(const uint8_t *w, size_t w_len, const char *s)
{
	return w_len == strlen(s) && memcmp(w, s, w_len) == 0;
}

struct rows {
	int subject;
	size_t from, seen, shown, used, limit;
	int more;
	char *items;
};

static void row(void *ctx, const fzn_node_decision_t *d)
{
	struct rows *r = ctx;
	char line[8u + FZN_NODE_DECIDED_SUBJECT_MAX + 2u * FZN_PUBKEY_LEN + 24u
	          + 3u * (FZN_NODE_DECIDED_GROUNDS_MAX + FZN_SETTING_VALUE_MAX)];
	size_t n = 0, i, wrote = 0;

	if (r->more || r->seen++ < r->from)
		return;
	line[n++] = ' ';
	if (r->subject) {
		memcpy(line + n, d->subject, d->subject_len);
		n += d->subject_len;
		line[n++] = ',';
	}
	for (i = 0; i < FZN_PUBKEY_LEN; i++) {
		fzn_hex_byte(d->host[i], line + n);
		n += 2u;
	}
	n += (size_t)sprintf(line + n, ",%llu,", (unsigned long long)d->at);
	if (fzn_escape(d->grounds, d->grounds_len, line + n, sizeof(line) - n, &wrote)
	    != d->grounds_len)
		return;
	n += wrote;
	line[n++] = ',';
	if (fzn_escape(d->value, d->value_len, line + n, sizeof(line) - n, &wrote) != d->value_len)
		return;
	n += wrote;
	if (r->used + n > r->limit) {
		r->more = 1;
		return;
	}
	memcpy(r->items + r->used, line, n);
	r->used += n;
	r->shown++;
}

static void rows_begin(struct rows *r, char *items, size_t items_cap, size_t cap)
{
	memset(r, 0, sizeof(*r));
	r->items = items;
	r->limit = fzn_reply_ok_room(cap) > 32u ? fzn_reply_ok_room(cap) - 32u : 0u;
	if (r->limit > items_cap)
		r->limit = items_cap;
}

static size_t list_fork(const fzn_node_records_t *nr, const uint8_t *at, size_t left, char *reply,
                        size_t cap)
{
	static char items[FZN_REPLY_MAX], detail[FZN_REPLY_MAX];
	const uint8_t *w;
	size_t w_len, i;
	struct rows r;
	int c;

	rows_begin(&r, items, sizeof(items), cap);
	r.subject = 1;
	if (word(&at, &left, &w, &w_len)) {
		for (i = 0; i < w_len; i++) {
			if (w[i] < '0' || w[i] > '9' || r.from > ((size_t)1 << 30))
				return say(reply, cap, FZN_REPLY_MALFORMED, "list fork [FROM]");
			r.from = (r.from * 10u) + (size_t)(w[i] - '0');
		}
	}
	if (fzn_node_decisions_forks(nr, row, &r) < 0)
		return say(reply, cap, FZN_REPLY_ERROR, "the decisions could not be read");
	c = snprintf(detail, sizeof(detail), "%zu %zu %d", r.from, r.shown, r.more);
	if (c < 0 || (size_t)c + r.used > sizeof(detail))
		return 0;
	memcpy(detail + c, items, r.used);
	return answer(reply, cap, FZN_REPLY_OK, detail, (size_t)c + r.used);
}

static size_t get_decided(const fzn_node_records_t *nr, const uint8_t *at, size_t left,
                          char *reply, size_t cap)
{
	static char items[FZN_REPLY_MAX], detail[FZN_REPLY_MAX];
	const uint8_t *subject;
	size_t subject_len;
	struct rows r;
	long heads;
	int c;

	if (!word(&at, &left, &subject, &subject_len) || !subject_ok(subject, subject_len))
		return say(reply, cap, FZN_REPLY_MALFORMED, "get decided SUBJECT");
	rows_begin(&r, items, sizeof(items), cap);
	heads = fzn_node_decisions_heads(nr, subject, subject_len, row, &r);
	if (heads < 0)
		return say(reply, cap, FZN_REPLY_ERROR, "the decisions could not be read");
	if (!heads)
		return say(reply, cap, FZN_REPLY_OK, "absent");
	c = snprintf(detail, sizeof(detail), "%ld", heads);
	if (c < 0 || (size_t)c + r.used > sizeof(detail))
		return 0;
	memcpy(detail + c, items, r.used);
	return answer(reply, cap, FZN_REPLY_OK, detail, (size_t)c + r.used);
}

static size_t add_decided(const fzn_node_records_t *nr, const uint8_t *at, size_t left,
                          char *reply, size_t cap)
{
	static const char USAGE[] = "add decided SUBJECT [grounds=WORD] VALUE";
	static const char GROUNDS[] = "grounds=";
	uint8_t value[FZN_SETTING_VALUE_MAX];
	const uint8_t *subject, *w, *rest, *grounds = NULL;
	size_t subject_len, w_len, rest_left, value_len = 0, grounds_len = 0;
	fzn_node_records_err_t err;

	if (!word(&at, &left, &subject, &subject_len) || !subject_ok(subject, subject_len))
		return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
	rest = at;
	rest_left = left;
	if (word(&rest, &rest_left, &w, &w_len) && w_len > sizeof(GROUNDS) - 1u
	    && memcmp(w, GROUNDS, sizeof(GROUNDS) - 1u) == 0) {
		grounds = w + sizeof(GROUNDS) - 1u;
		grounds_len = w_len - (sizeof(GROUNDS) - 1u);
		at = rest;
		left = rest_left;
	}
	while (left && *at == ' ') {
		at++;
		left--;
	}
	if (!left || !fzn_unescape(at, left, value, sizeof(value), &value_len))
		return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
	if (!nr->id)
		return say(reply, cap, FZN_REPLY_UNSUPPORTED, "this node writes no records");
	err = fzn_node_decisions_write(nr, subject, subject_len, 0u, NULL, grounds, grounds_len, value,
	                               value_len);
	if (err == FZN_NODE_RECORDS_MALFORMED)
		return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
	if (err != FZN_NODE_RECORDS_OK)
		return say(reply, cap, FZN_REPLY_ERROR, "the decision was not kept");
	return say(reply, cap, FZN_REPLY_OK, NULL);
}

size_t fzn_node_decisions_local(void *ctx, fzn_origin_t origin, const fzn_request_t *request,
                                char *reply, size_t reply_cap)
{
	const fzn_node_records_t *nr = (const fzn_node_records_t *)ctx;
	const uint8_t *at, *subject;
	size_t left, subject_len;
	int fork, decided;

	if (!nr || !request || !reply || !request->arg)
		return 0;
	at = request->arg;
	left = request->arg_len;
	if (!word(&at, &left, &subject, &subject_len))
		return 0;
	fork = is_word(subject, subject_len, "fork") && request->parsed == FZN_VERB_LIST;
	decided = is_word(subject, subject_len, "decided")
	          && (request->parsed == FZN_VERB_GET || request->parsed == FZN_VERB_ADD);
	if (!fork && !decided)
		return 0;
	if (origin != FZN_ORIGIN_SAME_USER)
		return say(reply, reply_cap, FZN_REPLY_DENIED, "decisions need this node's own user");
	if (!nr->b || !nr->verify)
		return say(reply, reply_cap, FZN_REPLY_UNSUPPORTED, "no store for records");
	if (fork)
		return list_fork(nr, at, left, reply, reply_cap);
	if (request->parsed == FZN_VERB_GET)
		return get_decided(nr, at, left, reply, reply_cap);
	return add_decided(nr, at, left, reply, reply_cap);
}
