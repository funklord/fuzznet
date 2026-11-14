/* See objects.h. */

#include "objects.h"
#include "../hex/hex.h"

#include <stdio.h>
#include <string.h>

/* A RATE GATE'S KEY for an object, so one gate may serve several kinds of value. */
#define OBJECT_RATE_PREFIX "object/"


/* A LISTING'S PAGE: rows held while the second list is walked. */
#define PAGE_ROWS 8u

static int name_ok(const uint8_t *w, size_t n)
{
	size_t i;

	if (!w || !n || n > FZN_NODE_OBJECT_NAME_MAX)
		return 0;
	for (i = 0; i < n; i++)
		if (!((w[i] >= 'a' && w[i] <= 'z') || (w[i] >= '0' && w[i] <= '9') || w[i] == '_'))
			return 0;
	return 1;
}

static int value_ok(const uint8_t *w, size_t n)
{
	size_t i;

	if (!w || !n || n > FZN_NODE_OBJECT_VALUE_MAX || (n == 1u && w[0] == '-'))
		return 0;
	for (i = 0; i < n; i++)
		if (!((w[i] >= 'a' && w[i] <= 'z') || (w[i] >= 'A' && w[i] <= 'Z')
		      || (w[i] >= '0' && w[i] <= '9') || w[i] == '_' || w[i] == '.' || w[i] == '-'))
			return 0;
	return 1;
}

/* `*`, or words between `|`. */
static int allowed_ok(const uint8_t *a, size_t n)
{
	size_t from = 0, i;

	if (!a || !n || n > FZN_SETTING_VALUE_MAX)
		return 0;
	if (n == 1u && a[0] == '*')
		return 1;
	for (i = 0; i <= n; i++)
		if (i == n || a[i] == '|') {
			if (!value_ok(a + from, i - from))
				return 0;
			from = i + 1u;
		}
	return 1;
}

static int allows(const uint8_t *allowed, size_t allowed_len, const uint8_t *value, size_t len)
{
	size_t from = 0, i;

	if (allowed_len == 1u && allowed[0] == '*')
		return 1;
	for (i = 0; i <= allowed_len; i++)
		if (i == allowed_len || allowed[i] == '|') {
			if (i - from == len && memcmp(allowed + from, value, len) == 0)
				return 1;
			from = i + 1u;
		}
	return 0;
}

struct one {
	const uint8_t *name;
	size_t name_len;
	int found;
	fzn_node_list_member_t row;
};

static void find_one(void *ctx, const fzn_node_list_member_t *m)
{
	struct one *f = ctx;

	if (m->member_len == f->name_len && memcmp(m->member, f->name, f->name_len) == 0) {
		f->row = *m;
		f->found = 1;
	}
}

static int row_of(const fzn_node_objects_t *o, const char *list, const uint8_t *name,
                  size_t name_len, struct one *f)
{
	memset(f, 0, sizeof(*f));
	f->name = name;
	f->name_len = name_len;
	return fzn_node_records_list_each(o->records, (const uint8_t *)list, strlen(list), find_one, f);
}

static int hex_digit(uint8_t c)
{
	return fzn_hex_digit_lower(c);
}

/* A VALUE'S RECORD INTO `out`: `VALUE`, or `VALUE HEX` when the host that signed
 * spoke for another. */
static void value_into(fzn_node_object_t *out, const fzn_node_list_member_t *m)
{
	const uint8_t *space = memchr(m->value, ' ', m->value_len);
	size_t n = space ? (size_t)(space - m->value) : m->value_len, i;

	if (!m->in || !value_ok(m->value, n))
		return;
	memcpy(out->value, m->value, n);
	out->value[n] = '\0';
	out->value_len = n;
	out->at = m->at;
	memcpy(out->by, m->host, FZN_PUBKEY_LEN);
	if (!space || m->value_len - n - 1u != 2u * FZN_PUBKEY_LEN)
		return;
	for (i = 0; i < FZN_PUBKEY_LEN; i++) {
		int hi = hex_digit(space[1u + 2u * i]), lo = hex_digit(space[2u + 2u * i]);

		if (hi < 0 || lo < 0) {
			memcpy(out->by, m->host, FZN_PUBKEY_LEN);
			return;
		}
		out->by[i] = (uint8_t)((hi << 4) | lo);
	}
}

fzn_node_object_err_t fzn_node_object_get(const fzn_node_objects_t *o, const uint8_t *name,
                                          size_t name_len, fzn_node_object_t *out)
{
	static struct one f;

	if (!o || !o->records || !out || !name_ok(name, name_len))
		return FZN_NODE_OBJECT_MALFORMED;
	if (!row_of(o, FZN_NODE_OBJECT_LIST, name, name_len, &f))
		return FZN_NODE_OBJECT_BACKEND;
	if (!f.found || !f.row.in)
		return FZN_NODE_OBJECT_ABSENT;
	memset(out, 0, sizeof(*out));
	memcpy(out->name, name, name_len);
	out->name_len = name_len;
	memcpy(out->allowed, f.row.value, f.row.value_len);
	out->allowed_len = f.row.value_len;
	if (!row_of(o, FZN_NODE_OBJECT_VALUE_LIST, name, name_len, &f))
		return FZN_NODE_OBJECT_BACKEND;
	if (f.found)
		value_into(out, &f.row);
	return FZN_NODE_OBJECT_OK;
}

static void told(const fzn_node_objects_t *o, const uint8_t *name, size_t name_len)
{
	if (o->changed)
		o->changed(name, name_len);
}

/* THE TIME A CHANGE IS WRITTEN AT: a records writer asks a clock, so one that does
 * not fall behind what is held stands in for it. */
static uint64_t (*change_clock)(void);
static uint64_t change_floor;

static uint64_t change_now(void)
{
	uint64_t now = change_clock();

	return now > change_floor ? now : change_floor;
}

/* `list`'S ROW OF `name` CHANGED, past the newest held, in or out: a record a
 * clear left counts, or a write by a clock behind it would answer ok and lose. */
static fzn_node_object_err_t change(const fzn_node_objects_t *o, const char *list,
                                    const uint8_t *name, size_t name_len, int in,
                                    const uint8_t *value, size_t value_len)
{
	static struct one f;
	fzn_node_records_t past = *o->records;

	if (!row_of(o, list, name, name_len, &f))
		return FZN_NODE_OBJECT_BACKEND;
	change_clock = o->records->now_ms;
	change_floor = f.found ? f.row.at + 1u : 0u;
	past.now_ms = change_now;
	return fzn_node_records_list_change(&past, (const uint8_t *)list, strlen(list), name, name_len,
	                                    in, value, value_len)
	               == FZN_NODE_RECORDS_OK
	           ? FZN_NODE_OBJECT_OK
	           : FZN_NODE_OBJECT_BACKEND;
}

fzn_node_object_err_t fzn_node_object_add(const fzn_node_objects_t *o, const uint8_t *name,
                                          size_t name_len, const uint8_t *allowed,
                                          size_t allowed_len)
{
	static fzn_node_object_t held;
	fzn_node_object_err_t err;

	if (!o || !o->records || !name_ok(name, name_len) || !allowed_ok(allowed, allowed_len))
		return FZN_NODE_OBJECT_MALFORMED;
	err = fzn_node_object_get(o, name, name_len, &held);
	if (err == FZN_NODE_OBJECT_OK)
		return held.allowed_len == allowed_len && memcmp(held.allowed, allowed, allowed_len) == 0
		               ? FZN_NODE_OBJECT_OK
		               : FZN_NODE_OBJECT_EXISTS;
	if (err != FZN_NODE_OBJECT_ABSENT)
		return err;
	err = change(o, FZN_NODE_OBJECT_LIST, name, name_len, 1, allowed, allowed_len);
	if (err == FZN_NODE_OBJECT_OK)
		told(o, name, name_len);
	return err;
}

fzn_node_object_err_t fzn_node_object_set(const fzn_node_objects_t *o, const uint8_t *name,
                                          size_t name_len, const uint8_t *value, size_t value_len,
                                          const uint8_t *by)
{
	static fzn_node_object_t held;
	uint8_t row[FZN_NODE_OBJECT_VALUE_MAX + 1u + 2u * FZN_PUBKEY_LEN];
	size_t n = value_len, i;
	fzn_node_object_err_t err;

	if (!o || !o->records || !value_ok(value, value_len))
		return FZN_NODE_OBJECT_MALFORMED;
	err = fzn_node_object_get(o, name, name_len, &held);
	if (err != FZN_NODE_OBJECT_OK)
		return err;
	if (!allows(held.allowed, held.allowed_len, value, value_len))
		return FZN_NODE_OBJECT_REFUSED;
	memcpy(row, value, value_len);
	if (by) {
		row[n++] = ' ';
		for (i = 0; i < FZN_PUBKEY_LEN; i++) {
			fzn_hex_byte(by[i], (char *)row + n);
			n += 2u;
		}
	}
	/* HELD TO ITS WINDOW, sec 1034, where a rate gate is set. */
	if (o->rate) {
		uint8_t key[FZN_RATE_KEY_MAX];
		int first = 0;

		if (sizeof(OBJECT_RATE_PREFIX) - 1u + name_len > sizeof(key))
			return FZN_NODE_OBJECT_MALFORMED;
		memcpy(key, OBJECT_RATE_PREFIX, sizeof(OBJECT_RATE_PREFIX) - 1u);
		memcpy(key + sizeof(OBJECT_RATE_PREFIX) - 1u, name, name_len);
		if (fzn_rate_offer(o->rate, key, sizeof(OBJECT_RATE_PREFIX) - 1u + name_len, row, n,
		                   FZN_NODE_OBJECT_EVERY_MS,
		                   o->records->now_ms ? o->records->now_ms() : 0u, &first)
		    == FZN_RATE_HELD) {
			if (first && o->held)
				o->held(name, name_len);
			return FZN_NODE_OBJECT_HELD;
		}
	}
	err = change(o, FZN_NODE_OBJECT_VALUE_LIST, name, name_len, 1, row, n);
	if (err == FZN_NODE_OBJECT_OK)
		told(o, name, name_len);
	return err;
}

/* A HELD VALUE WRITTEN, its window passed: the newest set, as it was taken. */
static void write_due(void *ctx, const uint8_t *key, size_t key_len, const uint8_t *value,
                      size_t value_len, unsigned long held)
{
	const fzn_node_objects_t *o = ctx;
	const uint8_t *name = key + sizeof(OBJECT_RATE_PREFIX) - 1u;
	size_t name_len = key_len - (sizeof(OBJECT_RATE_PREFIX) - 1u);

	(void)held;
	if (key_len <= sizeof(OBJECT_RATE_PREFIX) - 1u
	    || memcmp(key, OBJECT_RATE_PREFIX, sizeof(OBJECT_RATE_PREFIX) - 1u) != 0)
		return;
	if (change(o, FZN_NODE_OBJECT_VALUE_LIST, name, name_len, 1, value, value_len)
	    == FZN_NODE_OBJECT_OK)
		told(o, name, name_len);
}

size_t fzn_node_objects_due(const fzn_node_objects_t *o, uint64_t now_ms)
{
	if (!o || !o->rate || !o->records)
		return 0;
	return fzn_rate_due(o->rate, now_ms, (const uint8_t *)OBJECT_RATE_PREFIX,
	                    sizeof(OBJECT_RATE_PREFIX) - 1u, write_due, (void *)o);
}

fzn_node_object_err_t fzn_node_object_remove(const fzn_node_objects_t *o, const uint8_t *name,
                                             size_t name_len)
{
	static fzn_node_object_t held;
	fzn_node_object_err_t err;

	if (!o || !o->records)
		return FZN_NODE_OBJECT_MALFORMED;
	err = fzn_node_object_get(o, name, name_len, &held);
	if (err != FZN_NODE_OBJECT_OK)
		return err;
	/* ITS VALUE GOES TOO, or a later object of this name would begin with it. */
	err = change(o, FZN_NODE_OBJECT_VALUE_LIST, name, name_len, 0, NULL, 0u);
	if (err == FZN_NODE_OBJECT_OK)
		err = change(o, FZN_NODE_OBJECT_LIST, name, name_len, 0, NULL, 0u);
	if (err == FZN_NODE_OBJECT_OK)
		told(o, name, name_len);
	return err;
}

size_t fzn_node_object_of_key(const uint8_t *key, size_t key_len,
                              char name[FZN_NODE_OBJECT_NAME_MAX + 1u])
{
	static const char *const LISTS[] = { FZN_NODE_LIST_PREFIX FZN_NODE_OBJECT_LIST "/",
		                             FZN_NODE_LIST_PREFIX FZN_NODE_OBJECT_VALUE_LIST "/" };
	size_t i;

	for (i = 0; i < 2u; i++) {
		size_t n = strlen(LISTS[i]);

		if (key_len > n && memcmp(key, LISTS[i], n) == 0 && name_ok(key + n, key_len - n)) {
			memcpy(name, key + n, key_len - n);
			name[key_len - n] = '\0';
			return key_len - n;
		}
	}
	return 0;
}

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

static size_t refused(char *reply, size_t cap, fzn_node_object_err_t err)
{
	switch (err) {
	case FZN_NODE_OBJECT_MALFORMED:
		return say(reply, cap, FZN_REPLY_MALFORMED,
		           "a name is a-z 0-9 _ to 32 bytes, a value one word to 64");
	case FZN_NODE_OBJECT_ABSENT:
		return say(reply, cap, FZN_REPLY_ERROR, "no such object");
	case FZN_NODE_OBJECT_REFUSED:
		return say(reply, cap, FZN_REPLY_DENIED, "a value that object may not have");
	case FZN_NODE_OBJECT_EXISTS:
		return say(reply, cap, FZN_REPLY_ERROR, "that object exists, with other values");
	default:
		return say(reply, cap, FZN_REPLY_ERROR, "the object was not kept");
	}
}

/* `NAME,VALUE,AT,BY,ALLOWED`, or `VALUE AT BY ALLOWED` with `sep` ' ' and no name:
 * its length, or 0 for no room. */
static size_t row_text(const fzn_node_object_t *x, char sep, int with_name, char *out, size_t cap)
{
	char by[2u * FZN_PUBKEY_LEN + 1u];
	size_t i;
	int n;

	if (x->value_len) {
		for (i = 0; i < FZN_PUBKEY_LEN; i++) {
			fzn_hex_byte(x->by[i], by + 2u * i);
		}
		by[2u * FZN_PUBKEY_LEN] = '\0';
	} else {
		by[0] = '-';
		by[1] = '\0';
	}
	n = snprintf(out, cap, "%s%s%s%c%llu%c%s%c%.*s", with_name ? x->name : "",
	             with_name ? "," : "", x->value_len ? x->value : "-", sep,
	             (unsigned long long)x->at, sep, by, sep, (int)x->allowed_len,
	             (const char *)x->allowed);
	return n > 0 && (size_t)n < cap ? (size_t)n : 0u;
}

struct page {
	fzn_node_object_t rows[PAGE_ROWS];
	size_t from, seen, n;
	int more;
};

static void page_row(void *ctx, const fzn_node_list_member_t *m)
{
	struct page *p = ctx;
	fzn_node_object_t *x;

	if (!m->in || !name_ok((const uint8_t *)m->member, m->member_len) || p->seen++ < p->from)
		return;
	if (p->n == PAGE_ROWS) {
		p->more = 1;
		return;
	}
	x = &p->rows[p->n++];
	memset(x, 0, sizeof(*x));
	memcpy(x->name, m->member, m->member_len);
	x->name_len = m->member_len;
	memcpy(x->allowed, m->value, m->value_len);
	x->allowed_len = m->value_len;
}

static void page_value(void *ctx, const fzn_node_list_member_t *m)
{
	struct page *p = ctx;
	size_t i;

	for (i = 0; i < p->n; i++)
		if (p->rows[i].name_len == m->member_len
		    && memcmp(p->rows[i].name, m->member, m->member_len) == 0)
			value_into(&p->rows[i], m);
}

static size_t list_objects(const fzn_node_objects_t *o, const uint8_t *at, size_t left, char *reply,
                           size_t cap)
{
	static struct page p;
	static char detail[FZN_REPLY_MAX];
	const uint8_t *w;
	size_t w_len, i, used, shown = 0, room;
	int c;

	memset(&p, 0, sizeof(p));
	if (word(&at, &left, &w, &w_len))
		for (i = 0; i < w_len; i++) {
			if (w[i] < '0' || w[i] > '9' || p.from > ((size_t)1 << 30))
				return say(reply, cap, FZN_REPLY_MALFORMED, "list object [FROM]");
			p.from = (p.from * 10u) + (size_t)(w[i] - '0');
		}
	if (!fzn_node_records_list_each(o->records, (const uint8_t *)FZN_NODE_OBJECT_LIST,
	                                strlen(FZN_NODE_OBJECT_LIST), page_row, &p)
	    || !fzn_node_records_list_each(o->records, (const uint8_t *)FZN_NODE_OBJECT_VALUE_LIST,
	                                   strlen(FZN_NODE_OBJECT_VALUE_LIST), page_value, &p))
		return say(reply, cap, FZN_REPLY_ERROR, "the objects could not be listed");
	/* THE HEAD'S ROOM KEPT BACK, as its numbers are known only after the rows. */
	used = 32u;
	room = fzn_reply_ok_room(cap);
	if (room > sizeof(detail))
		room = sizeof(detail);
	for (i = 0; i < p.n; i++) {
		size_t n;

		if (used + 2u >= room
		    || !(n = row_text(&p.rows[i], ',', 1, detail + used + 1u, room - used - 1u))) {
			p.more = 1;
			break;
		}
		detail[used] = ' ';
		used += n + 1u;
		shown++;
	}
	{
		char head[32];

		c = snprintf(head, sizeof(head), "%zu %zu %d", p.from, shown, p.more);
		if (c <= 0 || (size_t)c >= sizeof(head))
			return 0;
		memmove(detail + c, detail + 32, used - 32u);
		memcpy(detail, head, (size_t)c);
		return answer(reply, cap, FZN_REPLY_OK, detail, (size_t)c + used - 32u);
	}
}

int fzn_node_objects_each(const fzn_node_objects_t *o,
                          void (*each)(void *ctx, const fzn_node_object_t *x), void *ctx)
{
	static struct page p;
	size_t from = 0, i;

	if (!o || !o->records || !each)
		return 0;
	do {
		memset(&p, 0, sizeof(p));
		p.from = from;
		if (!fzn_node_records_list_each(o->records, (const uint8_t *)FZN_NODE_OBJECT_LIST,
		                                strlen(FZN_NODE_OBJECT_LIST), page_row, &p)
		    || !fzn_node_records_list_each(o->records, (const uint8_t *)FZN_NODE_OBJECT_VALUE_LIST,
		                                   strlen(FZN_NODE_OBJECT_VALUE_LIST), page_value, &p))
			return 0;
		for (i = 0; i < p.n; i++)
			each(ctx, &p.rows[i]);
		from += p.n;
	} while (p.more && p.n);
	return 1;
}

size_t fzn_node_objects_local(void *ctx, fzn_origin_t origin, const fzn_request_t *request,
                              char *reply, size_t reply_cap)
{
	static fzn_node_object_t x;
	const fzn_node_objects_t *o = ctx;
	const uint8_t *at, *subject, *name = NULL, *w = NULL;
	uint8_t allowed[FZN_SETTING_VALUE_MAX];
	size_t left, subject_len, name_len = 0, w_len = 0, allowed_len = 0;
	fzn_node_object_err_t err;

	if (!o || !request || !reply || !request->arg)
		return 0;
	at = request->arg;
	left = request->arg_len;
	if (!word(&at, &left, &subject, &subject_len) || !is_word(subject, subject_len, "object"))
		return 0;
	if (request->parsed != FZN_VERB_ADD && request->parsed != FZN_VERB_SET
	    && request->parsed != FZN_VERB_GET && request->parsed != FZN_VERB_LIST
	    && request->parsed != FZN_VERB_REMOVE)
		return 0;
	if (origin != FZN_ORIGIN_SAME_USER)
		return say(reply, reply_cap, FZN_REPLY_DENIED, "objects need this node's own user");
	if (!o->records || !o->records->b || !o->records->verify)
		return say(reply, reply_cap, FZN_REPLY_UNSUPPORTED, "no store for records");
	if (request->parsed == FZN_VERB_LIST)
		return list_objects(o, at, left, reply, reply_cap);
	if (!word(&at, &left, &name, &name_len))
		return say(reply, reply_cap, FZN_REPLY_MALFORMED,
		           "add object NAME [VALUE...], set object NAME VALUE, get object NAME, "
		           "list object [FROM], remove object NAME");
	switch (request->parsed) {
	case FZN_VERB_ADD:
		while (word(&at, &left, &w, &w_len)) {
			if (allowed_len + w_len + 1u > sizeof(allowed))
				return say(reply, reply_cap, FZN_REPLY_MALFORMED, "too many values");
			if (allowed_len)
				allowed[allowed_len++] = '|';
			memcpy(allowed + allowed_len, w, w_len);
			allowed_len += w_len;
		}
		if (!allowed_len)
			allowed[allowed_len++] = '*';
		err = fzn_node_object_add(o, name, name_len, allowed, allowed_len);
		break;
	case FZN_VERB_SET:
		if (!word(&at, &left, &w, &w_len) || word(&at, &left, &subject, &subject_len))
			return say(reply, reply_cap, FZN_REPLY_MALFORMED, "set object NAME VALUE");
		err = fzn_node_object_set(o, name, name_len, w, w_len, NULL);
		/* TAKEN, AND HELD TO ITS WINDOW, sec 1034: written when it passes. */
		if (err == FZN_NODE_OBJECT_HELD)
			return say(reply, reply_cap, FZN_REPLY_OK, "held");
		break;
	case FZN_VERB_REMOVE:
		err = fzn_node_object_remove(o, name, name_len);
		break;
	default: {
		static char line[FZN_REPLY_MAX];
		size_t n;

		err = fzn_node_object_get(o, name, name_len, &x);
		if (err == FZN_NODE_OBJECT_ABSENT)
			return say(reply, reply_cap, FZN_REPLY_OK, "absent");
		if (err != FZN_NODE_OBJECT_OK)
			return refused(reply, reply_cap, err);
		n = row_text(&x, ' ', 0, line, sizeof(line));
		return n ? answer(reply, reply_cap, FZN_REPLY_OK, line, n) : 0u;
	}
	}
	if (err != FZN_NODE_OBJECT_OK)
		return refused(reply, reply_cap, err);
	return say(reply, reply_cap, FZN_REPLY_OK, NULL);
}

size_t fzn_node_object_call(const fzn_node_objects_t *o, const uint8_t *caller,
                            const uint8_t *args, size_t args_len, uint8_t *answer_out, size_t cap)
{
	static fzn_node_object_t x;
	const uint8_t *verb, *name, *value = NULL, *extra;
	size_t verb_len, name_len, value_len = 0, extra_len;

	if (!o || !o->records || !args || !word(&args, &args_len, &verb, &verb_len)
	    || !word(&args, &args_len, &name, &name_len))
		return 0;
	if (is_word(verb, verb_len, "set")) {
		fzn_node_object_err_t err;

		/* HELD TO ITS WINDOW is taken too, sec 1034: the device is answered the
		 * value standing until it is written. */
		if (!word(&args, &args_len, &value, &value_len)
		    || ((err = fzn_node_object_set(o, name, name_len, value, value_len, caller))
		                != FZN_NODE_OBJECT_OK
		        && err != FZN_NODE_OBJECT_HELD))
			return 0;
	} else if (!is_word(verb, verb_len, "get")) {
		return 0;
	}
	if (word(&args, &args_len, &extra, &extra_len)
	    || fzn_node_object_get(o, name, name_len, &x) != FZN_NODE_OBJECT_OK)
		return 0;
	/* NONE SET IS `-`, as a listing says: an empty answer is a failed call. */
	if (!x.value_len) {
		x.value[0] = '-';
		x.value_len = 1u;
	}
	if (x.value_len > cap)
		return 0;
	memcpy(answer_out, x.value, x.value_len);
	return x.value_len;
}
