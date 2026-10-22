#include "meter.h"

#include "types.h"
#include "../log/cause.h"
#include "../spool/message.h"

#include <stdio.h>
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
	if (type == FZN_TYPE_INTRODUCE || type == FZN_TYPE_NOTIFY)
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

static void close_window(fzn_meter_row_t *r, uint64_t now)
{
	uint64_t span = now > r->window_start ? now - r->window_start : 1u;

	r->rate_up = r->window_up / span;
	r->rate_down = r->window_down / span;
	r->window_start = now;
	r->window_up = r->window_down = 0;
}

void fzn_meter_count(fzn_meter_t *m, fzn_meter_family_t family, const char *peer,
                     const uint8_t *key, size_t key_len, uint64_t up, uint64_t down,
                     uint64_t now)
{
	fzn_meter_row_t *rows, *r = NULL;
	size_t i, n, peer_len;

	if (!m || (unsigned)family >= FZN_METER_FAMILIES || !peer)
		return;
	if (key_len > FZN_METER_KEY_MAX || (key_len && !key))
		key_len = 0;
	peer_len = strlen(peer);
	if (peer_len > FZN_METER_PEER_MAX)
		peer_len = FZN_METER_PEER_MAX;
	rows = m->rows[family];
	n = m->n[family];
	for (i = 0; i < n && !r; i++)
		if (strlen(rows[i].peer) == peer_len && memcmp(rows[i].peer, peer, peer_len) == 0
		    && rows[i].key_len == key_len && (!key_len || memcmp(rows[i].key, key, key_len) == 0))
			r = &rows[i];
	if (!r) {
		if (n < FZN_METER_ROWS_MAX) {
			r = &rows[m->n[family]++];
		} else {
			/* THE LEAST RECENTLY ACTIVE GOES, its bytes kept in the
			 * family's evicted totals so a family's sums stay whole. */
			r = &rows[0];
			for (i = 1; i < n; i++)
				if (rows[i].last_seen < r->last_seen)
					r = &rows[i];
			m->evicted_up[family] += r->up;
			m->evicted_down[family] += r->down;
		}
		memset(r, 0, sizeof(*r));
		memcpy(r->peer, peer, peer_len);
		r->peer[peer_len] = '\0';
		if (key_len)
			memcpy(r->key, key, key_len);
		r->key_len = key_len;
		r->first_seen = r->window_start = now;
	}
	if (now >= r->window_start + FZN_METER_WINDOW_S)
		close_window(r, now);
	r->up += up;
	r->down += down;
	r->window_up += up;
	r->window_down += down;
	r->last_seen = now;
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

/* ROW `r` of `family` as `list transfer` writes it, into `out`. */
static size_t row_text(fzn_meter_family_t family, const fzn_meter_row_t *r, char *out, size_t cap)
{
	static const char HEX[] = "0123456789abcdef";
	char key[2u * FZN_METER_KEY_MAX + 1u];
	size_t i;
	int n;

	for (i = 0; i < r->key_len; i++) {
		key[2u * i] = HEX[r->key[i] >> 4];
		key[2u * i + 1u] = HEX[r->key[i] & 15u];
	}
	key[2u * r->key_len] = '\0';
	n = snprintf(out, cap, "%s,%s,%s,%llu,%llu,%llu,%llu,%llu,%llu",
	             fzn_meter_family_name(family), r->peer, key, (unsigned long long)r->up,
	             (unsigned long long)r->down, (unsigned long long)r->rate_up,
	             (unsigned long long)r->rate_down, (unsigned long long)r->first_seen,
	             (unsigned long long)r->last_seen);
	return n < 0 || (size_t)n >= cap ? 0u : (size_t)n;
}

static size_t list_rows(const fzn_meter_t *m, size_t from, char *reply, size_t cap)
{
	size_t total = 0, index = 0, at, f, i;

	for (f = 0; f < FZN_METER_FAMILIES; f++)
		total += m->n[f];
	at = (size_t)snprintf(reply, cap, "ok %zu %zu", total, from);
	for (f = 0; f < FZN_METER_FAMILIES; f++)
		for (i = 0; i < m->n[f]; i++, index++) {
			char row[320];
			size_t n;

			if (index < from)
				continue;
			n = row_text((fzn_meter_family_t)f, &m->rows[f][i], row, sizeof(row));
			/* ROOM FOR THE ROW, its space and the newline. */
			if (!n || at + 1u + n + 1u >= cap)
				goto full;
			reply[at++] = ' ';
			memcpy(reply + at, row, n);
			at += n;
		}
full:
	reply[at++] = '\n';
	reply[at] = '\0';
	return at;
}

static size_t totals(const fzn_meter_t *m, char *reply, size_t cap)
{
	size_t at = (size_t)snprintf(reply, cap, "ok"), f, i;

	for (f = 0; f < FZN_METER_FAMILIES; f++) {
		uint64_t up = m->evicted_up[f], down = m->evicted_down[f];
		int n;

		for (i = 0; i < m->n[f]; i++) {
			up += m->rows[f][i].up;
			down += m->rows[f][i].down;
		}
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
