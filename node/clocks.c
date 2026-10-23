#include "clocks.h"

#include <stdio.h>
#include <string.h>

void fzn_node_clocks_init(fzn_node_clocks_t *c, fzn_node_clock_t *rows, size_t cap)
{
	if (!c)
		return;
	c->rows = rows;
	c->used = 0;
	c->cap = rows ? cap : 0u;
}

int fzn_node_clocks_use(fzn_node_clocks_t *c, fzn_node_clock_t *rows, size_t cap)
{
	if (!c || !rows || cap < c->used)
		return 0;
	if (c->used && rows != c->rows)
		memmove(rows, c->rows, c->used * sizeof(*rows));
	c->rows = rows;
	c->cap = cap;
	return 1;
}

/* ROWS PAST THEIR KEEPING forgotten, the rest kept in order. */
static void forget_old(fzn_node_clocks_t *c, uint64_t now)
{
	size_t i, kept = 0;

	for (i = 0; i < c->used; i++)
		if (c->rows[i].at + FZN_NODE_CLOCKS_KEEP_S > now) {
			if (kept != i)
				c->rows[kept] = c->rows[i];
			kept++;
		}
	c->used = kept;
}

fzn_node_clocks_err_t fzn_node_clocks_note(fzn_node_clocks_t *c,
                                           const uint8_t peer[FZN_PUBKEY_LEN], int ahead,
                                           uint64_t seconds, uint64_t now)
{
	fzn_node_clock_t *r;
	size_t i;

	if (!c || !peer || (!c->rows && c->cap))
		return FZN_NODE_CLOCKS_MALFORMED;
	forget_old(c, now);
	for (i = 0; i < c->used; i++)
		if (memcmp(c->rows[i].peer, peer, FZN_PUBKEY_LEN) == 0) {
			r = &c->rows[i];
			r->seconds = seconds;
			r->at = now;
			if (r->ahead == (ahead != 0))
				return FZN_NODE_CLOCKS_OK;
			r->ahead = ahead != 0;
			return FZN_NODE_CLOCKS_NEW;
		}
	if (c->used == c->cap)
		return FZN_NODE_CLOCKS_ROOM;
	r = &c->rows[c->used++];
	memcpy(r->peer, peer, FZN_PUBKEY_LEN);
	r->ahead = ahead != 0;
	r->seconds = seconds;
	r->at = now;
	return FZN_NODE_CLOCKS_NEW;
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

size_t fzn_node_clocks_local(fzn_node_clocks_t *c, fzn_origin_t origin,
                             const fzn_request_t *request, uint64_t now, char *reply,
                             size_t cap)
{
	static const char HEX[] = "0123456789abcdef";
	const uint8_t *at = request ? request->arg : NULL, *w;
	size_t left = request ? request->arg_len : 0u, n, from = 0, out, i, k;

	if (!at || request->parsed != FZN_VERB_LIST || !next_word(&at, &left, &w, &n) || n != 5u
	    || memcmp(w, "clock", 5u) != 0)
		return 0;
	if (!reply || cap < 2u)
		return 0;
	if (origin != FZN_ORIGIN_SAME_USER)
		return REPLY("denied clocks are this node's own user's\n");
	if (next_word(&at, &left, &w, &n) && (left || !from_of(w, n, &from)))
		return REPLY("malformed list clock [FROM]\n");
	if (!c)
		return REPLY("error this node keeps no clocks\n");
	forget_old(c, now);
	if (from > c->used)
		from = c->used;
	out = (size_t)snprintf(reply, cap, "ok %zu %zu", c->used, from);
	for (i = from; i < c->used; i++) {
		char row[2u * FZN_PUBKEY_LEN + 64u];
		int m;

		for (k = 0; k < FZN_PUBKEY_LEN; k++) {
			row[2u * k] = HEX[c->rows[i].peer[k] >> 4];
			row[2u * k + 1u] = HEX[c->rows[i].peer[k] & 15u];
		}
		m = snprintf(row + 2u * FZN_PUBKEY_LEN, sizeof(row) - 2u * FZN_PUBKEY_LEN,
		             ",%s,%llu,%llu", c->rows[i].ahead ? "ahead" : "behind",
		             (unsigned long long)c->rows[i].seconds,
		             (unsigned long long)c->rows[i].at);
		if (m < 0 || out + 1u + 2u * FZN_PUBKEY_LEN + (size_t)m + 1u >= cap)
			break;
		out += (size_t)snprintf(reply + out, cap - out, " %s", row);
	}
	return out + (size_t)snprintf(reply + out, cap - out, "\n");
}
