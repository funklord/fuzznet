/* See responsible.h. */

#include "responsible.h"

#include "../local/escape.h"
#include "../hex/hex.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char LABEL[] = "fuzznet.responsible";

struct scored {
	uint8_t score[32];
	size_t index;
	const uint8_t *member;
};

/* HIGHEST SCORE FIRST, a tie by the greater member key: a total order. */
static int highest_first(const void *a, const void *b)
{
	const struct scored *x = a, *y = b;
	int c = memcmp(y->score, x->score, 32u);

	return c ? c : memcmp(y->member, x->member, 32u);
}

int fzn_responsible_order(const fzn_hash_ops_t *hash, const uint8_t *key, size_t key_len,
                          const uint8_t (*members)[32], size_t n, size_t *order)
{
	uint8_t in[sizeof(LABEL) - 1u + 2u + FZN_RESPONSIBLE_KEY_MAX + 32u];
	struct scored *s;
	size_t i, at;

	if (!hash || !hash->hash || (key_len && !key) || key_len > FZN_RESPONSIBLE_KEY_MAX
	    || (n && (!members || !order)))
		return 0;
	if (!n)
		return 1;
	s = malloc(n * sizeof(*s));
	if (!s)
		return 0;
	/* THE KEY'S LENGTH BEFORE IT, so no key is a prefix of another's
	 * input. */
	memcpy(in, LABEL, sizeof(LABEL) - 1u);
	at = sizeof(LABEL) - 1u;
	in[at++] = (uint8_t)(key_len >> 8);
	in[at++] = (uint8_t)key_len;
	if (key_len)
		memcpy(in + at, key, key_len);
	at += key_len;
	for (i = 0; i < n; i++) {
		memcpy(in + at, members[i], 32u);
		if (!hash->hash(hash->ctx, s[i].score, 32u, in, at + 32u)) {
			free(s);
			return 0;
		}
		s[i].index = i;
		s[i].member = members[i];
	}
	qsort(s, n, sizeof(*s), highest_first);
	for (i = 0; i < n; i++)
		order[i] = s[i].index;
	free(s);
	return 1;
}

static size_t say(char *reply, size_t cap, fzn_reply_t kind, const char *detail, size_t len)
{
	size_t out = 0;

	if (fzn_reply_compose((uint8_t *)reply, cap, &out, kind, (const uint8_t *)detail, len)
	    != FZN_COMPOSE_OK)
		return 0;
	return out;
}

static size_t said(char *reply, size_t cap, fzn_reply_t kind, const char *detail)
{
	return say(reply, cap, kind, detail, strlen(detail));
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

size_t fzn_node_responsible_local(const fzn_node_responsible_t *nr, fzn_origin_t origin,
                                  const fzn_request_t *request, char *reply, size_t reply_cap)
{
	static const char USAGE[] = "list responsible KEY [FROM]";
	static char items[FZN_REPLY_MAX], detail[FZN_REPLY_MAX];
	uint8_t key[FZN_RESPONSIBLE_KEY_MAX], (*hosts)[32] = NULL;
	const uint8_t *at, *w, *k;
	size_t left, w_len, k_len, key_len = 0, n = 0, cap = 0, from = 0, i, j, used = 0, shown = 0;
	size_t limit, *order = NULL;
	int more = 0, c;

	if (!nr || !request || !reply || !request->arg || request->parsed != FZN_VERB_LIST)
		return 0;
	at = request->arg;
	left = request->arg_len;
	if (!word(&at, &left, &w, &w_len) || w_len != 11u || memcmp(w, "responsible", 11u) != 0)
		return 0;
	if (origin != FZN_ORIGIN_SAME_USER)
		return said(reply, reply_cap, FZN_REPLY_DENIED, "this node's own user only");
	if (!nr->hash || !nr->host_at)
		return said(reply, reply_cap, FZN_REPLY_UNSUPPORTED, "this node lists no hosts");
	if (!word(&at, &left, &k, &k_len)
	    || !fzn_unescape(k, k_len, key, sizeof(key), &key_len) || !key_len)
		return said(reply, reply_cap, FZN_REPLY_MALFORMED, USAGE);
	if (word(&at, &left, &w, &w_len)) {
		for (i = 0; i < w_len; i++) {
			if (w[i] < '0' || w[i] > '9' || from > ((size_t)1 << 30))
				return said(reply, reply_cap, FZN_REPLY_MALFORMED, USAGE);
			from = (from * 10u) + (size_t)(w[i] - '0');
		}
	}
	if (left)
		return said(reply, reply_cap, FZN_REPLY_MALFORMED, USAGE);
	/* THE ESTATE'S HOSTS, grown to fit (sec 704). */
	for (;;) {
		uint8_t host[32];

		if (!nr->host_at(nr->ctx, n, host))
			break;
		if (n == cap) {
			size_t grown = cap ? cap * 2u : 16u;
			uint8_t (*more_hosts)[32] = realloc(hosts, grown * sizeof(*more_hosts));

			if (!more_hosts) {
				free(hosts);
				return said(reply, reply_cap, FZN_REPLY_ERROR, "no memory for the hosts");
			}
			hosts = more_hosts;
			cap = grown;
		}
		memcpy(hosts[n++], host, 32u);
	}
	order = malloc((n ? n : 1u) * sizeof(*order));
	if (!order || !fzn_responsible_order(nr->hash, key, key_len, (const uint8_t (*)[32])hosts, n,
	                                     order)) {
		free(hosts);
		free(order);
		return said(reply, reply_cap, FZN_REPLY_ERROR, "the order could not be made");
	}
	limit = fzn_reply_ok_room(reply_cap) > 48u ? fzn_reply_ok_room(reply_cap) - 48u : 0u;
	if (limit > sizeof(items))
		limit = sizeof(items);
	for (i = from; i < n; i++) {
		if (used + 1u + 64u > limit) {
			more = 1;
			break;
		}
		items[used++] = ' ';
		for (j = 0; j < 32u; j++) {
			fzn_hex_byte(hosts[order[i]][j], items + used);
			used += 2u;
		}
		shown++;
	}
	free(hosts);
	free(order);
	c = snprintf(detail, sizeof(detail), "%zu %zu %zu %d", n, from, shown, more);
	if (c < 0 || (size_t)c + used > sizeof(detail))
		return 0;
	memcpy(detail + c, items, used);
	return say(reply, reply_cap, FZN_REPLY_OK, detail, (size_t)c + used);
}
