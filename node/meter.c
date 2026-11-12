#include "meter.h"

#include "types.h"
#include "../log/cause.h"
#include "../spool/message.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *fzn_meter_family_name(fzn_meter_family_t family)
{
	static const char *const NAMES[FZN_METER_FAMILIES] = {
		"verbs",     "notes",  "members", "messages", "contact-devices", "relay",
		"introduce", "groups", "streams", "file-refs", "files",          "journal",
		"reconcile", "logs",   "extension", "other",
	};

	return (unsigned)family < FZN_METER_FAMILIES ? NAMES[family] : "other";
}

/* VERSION 2's TYPES TO THEIR FAMILY, as `node/types.h` allocates them. */
static fzn_meter_family_t shared_family(unsigned type)
{
	if ((type >= 1u && type <= 10u) || (type >= 15u && type <= 22u))
		return FZN_METER_NOTES;
	if (type == 11u || type == 12u)
		return FZN_METER_MEMBERS;
	if ((type >= 23u && type <= 28u) || type == 33u || type == 34u)
		return FZN_METER_MESSAGES;
	if (type >= 29u && type <= 32u)
		return FZN_METER_CONTACT_DEVICES;
	if (type == FZN_TYPE_RELAY)
		return FZN_METER_RELAY;
	/* AND REACHING HOSTS, sec 1081: an address asked, a manifest asked -- verbs
	 * until then. */
	if (type == FZN_TYPE_INTRODUCE || type == FZN_TYPE_NOTIFY || type == FZN_TYPE_ADDRESS_ASK
	    || type == FZN_TYPE_ROUTING_ASK)
		return FZN_METER_INTRODUCE;
	if (type >= FZN_TYPE_GROUP_SYNC && type <= FZN_TYPE_GROUP_LINES)
		return FZN_METER_GROUPS;
	if (type == FZN_TYPE_STREAM_QUERY || type == FZN_TYPE_STREAM_RECORDS)
		return FZN_METER_STREAMS;
	if (type == FZN_TYPE_FILE_REFS_WANT || type == FZN_TYPE_FILE_REFS)
		return FZN_METER_FILE_REFS;
	if (type >= FZN_TYPES_EXTENSION_FIRST && type <= FZN_TYPES_EXTENSION_LAST)
		return FZN_METER_EXTENSION;
	return FZN_METER_OTHER;
}

fzn_meter_family_t fzn_meter_family_of(const uint8_t *payload, size_t len,
                                       uint8_t key[FZN_METER_KEY_MAX], size_t *key_len)
{
	fzn_entry_name_t cause, origin;
	const uint8_t *inner = NULL;
	size_t inner_len = 0;

	if (key_len)
		*key_len = 0;
	if (!payload || !len)
		return FZN_METER_OTHER;
	/* A CAUSE ENVELOPE IS WHAT IS INSIDE IT. */
	if (payload[0] == FZN_TYPES_VERSION_CAUSE
	    && fzn_cause_unwrap(payload, len, &cause, &origin, &inner, &inner_len) == FZN_CAUSE_OK
	    && inner && inner != payload)
		return fzn_meter_family_of(inner, inner_len, key, key_len);
	/* A VERB LINE opens with a letter: no version byte is one. */
	if (payload[0] >= 'a' && payload[0] <= 'z')
		return FZN_METER_VERBS;
	if (len < 2u)
		return FZN_METER_OTHER;
	switch (payload[0]) {
	case FZN_TYPES_VERSION_SPOOL: {
		size_t at = payload[1] == FZN_MSG_HAVE_QUERY || payload[1] == FZN_MSG_HAVE
		            ? FZN_MSG_HAVE_OFF_ROOT
		            : payload[1] == FZN_MSG_WANT ? FZN_MSG_WANT_OFF_ROOT : 0u;

		/* A FILE'S ROOT, where its message names one: the row's key. */
		if (at && key && key_len && len >= at + FZN_METER_KEY_MAX) {
			memcpy(key, payload + at, FZN_METER_KEY_MAX);
			*key_len = FZN_METER_KEY_MAX;
		}
		return FZN_METER_FILES;
	}
	case FZN_TYPES_VERSION_SHARED:
		return shared_family(payload[1]);
	case FZN_TYPES_VERSION_GATHER:
		return FZN_METER_LOGS;
	case FZN_TYPES_VERSION_EXCHANGE:
		return FZN_METER_JOURNAL;
	case FZN_TYPES_VERSION_RECONCILE:
		return FZN_METER_RECONCILE;
	default:
		return FZN_METER_OTHER;
	}
}

static const char HEX[] = "0123456789abcdef";

/* A ROW'S NAME, `meter/FAMILY/DIR/PEER[/KEY]`: 0 when it will not fit. */
static int row_name(fzn_meter_family_t family, const char *dir, const char *peer,
                    const uint8_t *key, size_t key_len, char name[FZN_METRIC_NAME_MAX + 1u])
{
	char clean[FZN_METER_PEER_MAX + 1u], hex[2u * FZN_METER_KEY_MAX + 2u];
	size_t i, n = strlen(peer);
	int k;

	if (n > FZN_METER_PEER_MAX)
		n = FZN_METER_PEER_MAX;
	/* WHAT A NAME MAY NOT HOLD, read as `_`: a listing's separators. */
	for (i = 0; i < n; i++)
		clean[i] = peer[i] <= ' ' || peer[i] > '~' || peer[i] == ',' || peer[i] == '/' ? '_'
		                                                                              : peer[i];
	clean[n] = '\0';
	hex[0] = '\0';
	if (key_len) {
		hex[0] = '/';
		for (i = 0; i < key_len; i++) {
			hex[1u + 2u * i] = HEX[key[i] >> 4];
			hex[2u + 2u * i] = HEX[key[i] & 15u];
		}
		hex[1u + 2u * key_len] = '\0';
	}
	k = snprintf(name, FZN_METRIC_NAME_MAX + 1u, "meter/%s/%s/%s%s",
	             fzn_meter_family_name(family), dir, clean, hex);
	return k > 0 && (size_t)k <= FZN_METRIC_NAME_MAX;
}

/* ROOM FOR TWO MORE, grown. */
static int room(fzn_meter_t *m)
{
	fzn_metric_t *more;
	size_t cap;

	if (!m->metrics.rows)
		fzn_metrics_init(&m->metrics);
	if (m->metrics.n + 2u <= m->metrics.cap)
		return 1;
	cap = m->metrics.cap * 2u;
	if (!(more = calloc(cap, sizeof(*more))) || !fzn_metrics_use(&m->metrics, more, cap)) {
		free(more);
		return 0;
	}
	free(m->room);
	m->room = more;
	m->room_cap = cap;
	return 1;
}

static void count_dir(fzn_meter_t *m, fzn_meter_family_t family, const char *dir,
                      const char *peer, const uint8_t *key, size_t key_len, uint64_t bytes,
                      uint64_t now, uint64_t *evicted)
{
	char name[FZN_METRIC_NAME_MAX + 1u], within[48];
	uint64_t gone = 0;

	if (!row_name(family, dir, peer, key, key_len, name) || !room(m))
		return;
	(void)snprintf(within, sizeof(within), "meter/%s/%s/", fzn_meter_family_name(family), dir);
	if (!fzn_metrics_open_within(&m->metrics, name, 0u, within, FZN_METER_ROWS_MAX, &gone))
		return;
	*evicted += gone;
	(void)fzn_metrics_count(&m->metrics, name, bytes, now * 1000u);
}

void fzn_meter_count(fzn_meter_t *m, fzn_meter_family_t family, const char *peer,
                     const uint8_t *key, size_t key_len, uint64_t up, uint64_t down,
                     uint64_t now)
{
	if (!m || (unsigned)family >= FZN_METER_FAMILIES || !peer)
		return;
	if (key_len > FZN_METER_KEY_MAX || (key_len && !key))
		key_len = 0;
	count_dir(m, family, "up", peer, key, key_len, up, now, &m->evicted_up[family]);
	count_dir(m, family, "down", peer, key, key_len, down, now, &m->evicted_down[family]);
}

/* A ROW, `meter/FAMILY/up|down/REST`, of `family`: its direction, 1 up, 0 down,
 * and REST; -1 when it is not one of that family's. */
static int row_of(const fzn_metric_t *r, fzn_meter_family_t family, const char **rest)
{
	char up[48], down[48];

	(void)snprintf(up, sizeof(up), "meter/%s/up/", fzn_meter_family_name(family));
	(void)snprintf(down, sizeof(down), "meter/%s/down/", fzn_meter_family_name(family));
	if (strncmp(r->name, up, strlen(up)) == 0) {
		*rest = r->name + strlen(up);
		return 1;
	}
	if (strncmp(r->name, down, strlen(down)) == 0) {
		*rest = r->name + strlen(down);
		return 0;
	}
	return -1;
}

/* THE OTHER DIRECTION OF REST, or NULL. */
static const fzn_metric_t *partner(const fzn_meter_t *m, fzn_meter_family_t family, int up,
                                   const char *rest)
{
	char name[FZN_METRIC_NAME_MAX + 1u];
	int k = snprintf(name, sizeof(name), "meter/%s/%s/%s", fzn_meter_family_name(family),
	                 up ? "down" : "up", rest);

	return k > 0 && (size_t)k < sizeof(name) ? fzn_metrics_get(&m->metrics, name) : NULL;
}

void fzn_meter_family_totals(const fzn_meter_t *m, fzn_meter_family_t family, uint64_t *up,
                             uint64_t *down, uint64_t *rate_up, uint64_t *rate_down,
                             size_t *rows)
{
	const char *rest;
	size_t i;
	int dir;

	*up = m ? m->evicted_up[family] : 0u;
	*down = m ? m->evicted_down[family] : 0u;
	*rate_up = *rate_down = 0;
	*rows = 0;
	for (i = 0; m && m->metrics.rows && i < m->metrics.n; i++) {
		const fzn_metric_t *r = &m->metrics.rows[i];

		if ((dir = row_of(r, family, &rest)) < 0)
			continue;
		if (dir) {
			*up += r->total;
			*rate_up += r->rate;
			(*rows)++;
		} else {
			*down += r->total;
			*rate_down += r->rate;
			*rows += !partner(m, family, 0, rest);
		}
	}
}

static int next_word(const uint8_t **at, size_t *left, const uint8_t **w, size_t *n)
{
	while (*left && **at == ' ') {
		(*at)++;
		(*left)--;
	}
	if (!*left)
		return 0;
	*w = *at;
	while (*left && **at != ' ') {
		(*at)++;
		(*left)--;
	}
	*n = (size_t)(*at - *w);
	return 1;
}

static int from_of(const uint8_t *w, size_t n, size_t *from)
{
	size_t i;

	if (!n || n > 10u)
		return 0;
	*from = 0;
	for (i = 0; i < n; i++) {
		if (w[i] < '0' || w[i] > '9')
			return 0;
		*from = *from * 10u + (size_t)(w[i] - '0');
	}
	return 1;
}

#define REPLY(...) ((size_t)snprintf(reply, cap, __VA_ARGS__))

/* A ROW of `family` as `list transfer` writes it, into `out`: the up row `u`
 * and the down row `d`, either of which may be gone. */
static size_t row_text(fzn_meter_family_t family, const char *rest, const fzn_metric_t *u,
                       const fzn_metric_t *d, char *out, size_t cap)
{
	char peer[FZN_METRIC_NAME_MAX + 1u];
	const char *key = "", *slash;
	uint64_t first, last;
	int n;

	(void)snprintf(peer, sizeof(peer), "%s", rest);
	slash = strrchr(peer, '/');
	if (slash && strlen(slash + 1) == 2u * FZN_METER_KEY_MAX) {
		key = slash + 1;
		peer[slash - peer] = '\0';
	}
	first = u && d ? (u->first_ms < d->first_ms ? u->first_ms : d->first_ms)
	               : (u ? u->first_ms : d->first_ms);
	last = u && d ? (u->last_ms > d->last_ms ? u->last_ms : d->last_ms)
	              : (u ? u->last_ms : d->last_ms);
	n = snprintf(out, cap, "%s,%s,%s,%llu,%llu,%llu,%llu,%llu,%llu",
	             fzn_meter_family_name(family), peer, key,
	             (unsigned long long)(u ? u->total : 0u), (unsigned long long)(d ? d->total : 0u),
	             (unsigned long long)(u ? u->rate : 0u), (unsigned long long)(d ? d->rate : 0u),
	             (unsigned long long)(first / 1000u), (unsigned long long)(last / 1000u));
	return n < 0 || (size_t)n >= cap ? 0u : (size_t)n;
}

/* EACH ROW OF `family` once, as `each` sees it: an up row with its partner, and
 * a down row whose up is gone. */
static size_t rows_each(const fzn_meter_t *m, fzn_meter_family_t family,
                        int (*each)(void *ctx, fzn_meter_family_t family, const char *rest,
                                    const fzn_metric_t *u, const fzn_metric_t *d),
                        void *ctx)
{
	const char *rest;
	size_t i, seen = 0;
	int dir;

	for (i = 0; m->metrics.rows && i < m->metrics.n; i++) {
		const fzn_metric_t *r = &m->metrics.rows[i];
		const fzn_metric_t *p;

		if ((dir = row_of(r, family, &rest)) < 0)
			continue;
		p = partner(m, family, dir, rest);
		if (!dir && p)
			continue;
		seen++;
		if (each && !each(ctx, family, rest, dir ? r : p, dir ? p : r))
			break;
	}
	return seen;
}

struct listing {
	char *reply;
	size_t cap, at, index, from;
	int full;
};

static int list_one(void *ctx, fzn_meter_family_t family, const char *rest, const fzn_metric_t *u,
                    const fzn_metric_t *d)
{
	struct listing *l = ctx;
	char row[400];
	size_t n;

	if (l->index++ < l->from)
		return 1;
	n = row_text(family, rest, u, d, row, sizeof(row));
	/* ROOM FOR THE ROW, its space and the newline. */
	if (!n || l->at + 1u + n + 1u >= l->cap) {
		l->full = 1;
		return 0;
	}
	l->reply[l->at++] = ' ';
	memcpy(l->reply + l->at, row, n);
	l->at += n;
	return 1;
}

static size_t list_rows(const fzn_meter_t *m, size_t from, char *reply, size_t cap)
{
	struct listing l;
	size_t total = 0, f;

	for (f = 0; f < FZN_METER_FAMILIES; f++)
		total += rows_each(m, (fzn_meter_family_t)f, NULL, NULL);
	l.reply = reply;
	l.cap = cap;
	l.index = 0;
	l.from = from;
	l.full = 0;
	l.at = (size_t)snprintf(reply, cap, "ok %zu %zu", total, from);
	for (f = 0; f < FZN_METER_FAMILIES && !l.full; f++)
		(void)rows_each(m, (fzn_meter_family_t)f, list_one, &l);
	reply[l.at++] = '\n';
	reply[l.at] = '\0';
	return l.at;
}

static size_t totals(const fzn_meter_t *m, char *reply, size_t cap)
{
	size_t at = (size_t)snprintf(reply, cap, "ok"), f, rows;

	for (f = 0; f < FZN_METER_FAMILIES; f++) {
		uint64_t up, down, rup, rdown;
		int n;

		fzn_meter_family_totals(m, (fzn_meter_family_t)f, &up, &down, &rup, &rdown, &rows);
		if (!up && !down)
			continue;
		n = snprintf(reply + at, cap - at, " %s,%llu,%llu",
		             fzn_meter_family_name((fzn_meter_family_t)f), (unsigned long long)up,
		             (unsigned long long)down);
		if (n < 0 || at + (size_t)n + 1u >= cap)
			break;
		at += (size_t)n;
	}
	reply[at++] = '\n';
	reply[at] = '\0';
	return at;
}

size_t fzn_meter_local(const fzn_meter_t *m, fzn_origin_t origin, const fzn_request_t *request,
                       char *reply, size_t cap)
{
	const uint8_t *at = request ? request->arg : NULL, *w;
	size_t left = request ? request->arg_len : 0u, n, from = 0;

	if (!at || !next_word(&at, &left, &w, &n) || n != 8u || memcmp(w, "transfer", 8u) != 0)
		return 0;
	if (request->parsed != FZN_VERB_GET && request->parsed != FZN_VERB_LIST)
		return 0;
	if (!reply || cap < 2u)
		return 0;
	if (origin != FZN_ORIGIN_SAME_USER)
		return REPLY("denied traffic is this node's own user's\n");
	if (!m)
		return REPLY("error this node meters nothing\n");
	if (request->parsed == FZN_VERB_GET)
		return next_word(&at, &left, &w, &n) ? REPLY("malformed get transfer\n")
		                                     : totals(m, reply, cap);
	if (next_word(&at, &left, &w, &n) && (left || !from_of(w, n, &from)))
		return REPLY("malformed list transfer [FROM]\n");
	return list_rows(m, from, reply, cap);
}
