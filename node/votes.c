/* See votes.h. */

#include "votes.h"

#include "../state/setting.h"
#include "../hex/hex.h"

#include <stdlib.h>
#include <string.h>


static size_t prefix_of(const uint8_t host[FZN_PUBKEY_LEN], uint8_t *out)
{
	size_t i, n = FZN_NODE_VOTE_PREFIX_LEN;

	memcpy(out, FZN_NODE_VOTE_PREFIX, n);
	for (i = 0; i < FZN_NODE_VOTE_HOST_HEX / 2u; i++) {
		fzn_hex_byte(host[i], (char *)out + n);
		n += 2u;
	}
	out[n++] = '/';
	return n;
}

fzn_node_records_err_t fzn_node_vote(const fzn_node_records_t *nr,
                                     const uint8_t host[FZN_PUBKEY_LEN], const uint8_t *key,
                                     size_t key_len, const uint8_t *value, size_t value_len)
{
	uint8_t record[FZN_SETTING_KEY_MAX];
	size_t n;

	if (!nr || !host || !key || !key_len || key_len > FZN_NODE_VOTE_KEY_MAX)
		return FZN_NODE_RECORDS_MALFORMED;
	n = prefix_of(host, record);
	memcpy(record + n, key, key_len);
	return fzn_node_records_write(nr, record, n + key_len, value, value_len);
}

/* ONE VOTER'S NEWEST VOTE FOR ONE KEY. */
struct vote {
	uint8_t voter[FZN_PUBKEY_LEN];
	uint8_t key[FZN_SETTING_KEY_MAX];
	size_t key_len;
	uint8_t value[FZN_SETTING_VALUE_MAX];
	size_t value_len;
	uint64_t at;
};

struct tally {
	size_t prefix_len;
	struct vote *at;
	size_t n, cap;
	int failed;
};

static void seen(void *ctx, const fzn_setting_t *s)
{
	struct tally *t = ctx;
	size_t key_len = s->key_len - t->prefix_len, i;
	const uint8_t *key = s->key + t->prefix_len;
	struct vote *v = NULL;

	if (t->failed || !key_len || !s->set)
		return;
	for (i = 0; i < t->n && !v; i++)
		if (t->at[i].key_len == key_len && memcmp(t->at[i].key, key, key_len) == 0
		    && memcmp(t->at[i].voter, s->setter, FZN_PUBKEY_LEN) == 0)
			v = &t->at[i];
	if (v && v->at >= s->version)
		return;
	if (!v) {
		if (t->n == t->cap) {
			size_t cap = t->cap ? t->cap * 2u : 16u;
			struct vote *more = realloc(t->at, cap * sizeof(*more));

			if (!more) {
				t->failed = 1;
				return;
			}
			t->at = more;
			t->cap = cap;
		}
		v = &t->at[t->n++];
		memcpy(v->voter, s->setter, FZN_PUBKEY_LEN);
		memcpy(v->key, key, key_len);
		v->key_len = key_len;
	}
	memcpy(v->value, s->value, s->value_len);
	v->value_len = s->value_len;
	v->at = s->version;
}

static int same(const struct vote *a, const struct vote *b)
{
	return a->key_len == b->key_len && memcmp(a->key, b->key, a->key_len) == 0
	       && a->value_len == b->value_len && memcmp(a->value, b->value, a->value_len) == 0;
}

long fzn_node_votes_count(const fzn_node_records_t *nr, const uint8_t host[FZN_PUBKEY_LEN],
                          size_t k, const fzn_node_vote_ops_t *ops)
{
	uint8_t prefix[FZN_SETTING_KEY_MAX];
	struct tally t;
	size_t i, j;
	long carried = 0;

	if (!nr || !host || !ops || !ops->stands || !ops->votable || !ops->carried || !k)
		return -1;
	memset(&t, 0, sizeof(t));
	t.prefix_len = prefix_of(host, prefix);
	if (!fzn_node_records_under(nr, prefix, t.prefix_len, seen, &t) || t.failed) {
		free(t.at);
		return -1;
	}
	for (i = 0; i < t.n; i++) {
		uint64_t in_force = 0;
		size_t count = 0;
		int first = 1;

		for (j = 0; j < i && first; j++)
			if (same(&t.at[j], &t.at[i]))
				first = 0;
		if (!first || !ops->votable(ops->ctx, t.at[i].key, t.at[i].key_len, &in_force))
			continue;
		for (j = i; j < t.n; j++)
			if (same(&t.at[j], &t.at[i]) && t.at[j].at > in_force
			    && ops->stands(ops->ctx, t.at[j].voter))
				count++;
		if (count >= k) {
			ops->carried(ops->ctx, t.at[i].key, t.at[i].key_len, t.at[i].value,
			             t.at[i].value_len);
			carried++;
		}
	}
	free(t.at);
	return carried;
}
