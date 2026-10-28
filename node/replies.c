#include "replies.h"

#include <stdlib.h>
#include <string.h>

int fzn_node_replies_init(fzn_node_replies_t *r, fzn_node_reply_kept_t *kept, size_t cap,
                          size_t bytes_max, uint64_t ttl_s, const fzn_hash_ops_t *hash)
{
	if (!r || !kept || !cap || !bytes_max || !ttl_s || !hash || !hash->hash)
		return 0;
	memset(r, 0, sizeof(*r));
	memset(kept, 0, cap * sizeof(*kept));
	r->kept = kept;
	r->cap = cap;
	r->bytes_max = bytes_max;
	r->ttl_s = ttl_s;
	r->hash = hash;
	return 1;
}

/* The oldest first, kept so: entry 0 is the oldest. */
static void drop_first(fzn_node_replies_t *r)
{
	r->bytes -= r->kept[0].len;
	free(r->kept[0].bytes);
	memmove(r->kept, r->kept + 1, (r->n - 1u) * sizeof(*r->kept));
	r->n--;
	memset(&r->kept[r->n], 0, sizeof(r->kept[r->n]));
}

static void expire(fzn_node_replies_t *r, uint64_t now)
{
	while (r->n && (now < r->kept[0].at || now - r->kept[0].at > r->ttl_s))
		drop_first(r);
}

const uint8_t *fzn_node_replies_find(fzn_node_replies_t *r, const uint8_t sender[32],
                                     uint32_t msg, const uint8_t *request, size_t request_len,
                                     uint64_t now, size_t *len)
{
	uint8_t digest[FZN_NODE_REPLIES_DIGEST_LEN];
	size_t i;

	if (!r || !r->kept || !sender || (!request && request_len) || !len)
		return NULL;
	expire(r, now);
	if (!r->n || !r->hash->hash(r->hash->ctx, digest, sizeof(digest), request, request_len))
		return NULL;
	for (i = r->n; i > 0u; i--) {
		const fzn_node_reply_kept_t *k = &r->kept[i - 1u];

		if (k->msg == msg && memcmp(k->sender, sender, sizeof(k->sender)) == 0
		    && memcmp(k->digest, digest, sizeof(digest)) == 0) {
			*len = k->len;
			return k->bytes;
		}
	}
	return NULL;
}

const uint8_t *fzn_node_replies_find_piece(fzn_node_replies_t *r, const uint8_t sender[32],
                                           uint32_t msg, uint64_t expires_at, uint64_t now,
                                           size_t *len)
{
	size_t i;

	if (!r || !r->kept || !sender || !expires_at || !len)
		return NULL;
	expire(r, now);
	for (i = r->n; i > 0u; i--) {
		const fzn_node_reply_kept_t *k = &r->kept[i - 1u];

		if (k->msg == msg && k->expires_at == expires_at
		    && memcmp(k->sender, sender, sizeof(k->sender)) == 0) {
			*len = k->len;
			return k->bytes;
		}
	}
	return NULL;
}

void fzn_node_replies_keep(fzn_node_replies_t *r, const uint8_t sender[32], uint32_t msg,
                           uint64_t expires_at, const uint8_t *request, size_t request_len,
                           uint64_t now, const uint8_t *reply, size_t reply_len)
{
	fzn_node_reply_kept_t *k;
	uint8_t *copy;

	if (!r || !r->kept || !sender || (!request && request_len) || !reply || !reply_len
	    || reply_len > r->bytes_max)
		return;
	expire(r, now);
	while (r->n && (r->n == r->cap || r->bytes + reply_len > r->bytes_max))
		drop_first(r);
	copy = malloc(reply_len);
	if (!copy)
		return;
	k = &r->kept[r->n];
	if (!r->hash->hash(r->hash->ctx, k->digest, sizeof(k->digest), request, request_len)) {
		free(copy);
		return;
	}
	memcpy(copy, reply, reply_len);
	memcpy(k->sender, sender, sizeof(k->sender));
	k->msg = msg;
	k->expires_at = expires_at;
	k->at = now;
	k->len = reply_len;
	k->bytes = copy;
	r->bytes += reply_len;
	r->n++;
}

void fzn_node_replies_free(fzn_node_replies_t *r)
{
	if (!r || !r->kept)
		return;
	while (r->n)
		drop_first(r);
}
