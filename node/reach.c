/* Where a host is reached. node/reach.h says what and why. */
#include "reach.h"

#include <string.h>

static uint64_t hold_of(fzn_reach_source_t source)
{
	return source == FZN_REACH_HELLO        ? FZN_REACH_HELLO_S
	       : source == FZN_REACH_INTRODUCED ? FZN_REACH_INTRODUCED_S
	       : source == FZN_REACH_SESSION    ? FZN_REACH_SESSION_S
	                                        : 0u;
}

static int same_remote(const fzn_udp_addr_t *a, const fzn_udp_addr_t *b)
{
	return a->len == b->len && memcmp(a->storage, b->storage, a->len) == 0;
}

static int held(const fzn_reach_pair_t *p, uint64_t now)
{
	return p->used && (p->until == 0u || p->until > now);
}

void fzn_reach_init(fzn_reach_t *r, fzn_reach_pair_t *pairs, size_t cap)
{
	if (!r)
		return;
	r->pairs = pairs;
	r->cap = pairs ? cap : 0u;
	if (pairs && cap)
		memset(pairs, 0, cap * sizeof(*pairs));
}

void fzn_reach_learn(fzn_reach_t *r, const uint8_t host[FZN_PUBKEY_LEN], fzn_reach_local_t local,
                     const fzn_udp_addr_t *remote, fzn_reach_source_t source, uint64_t now)
{
	size_t i, pick;
	uint64_t hold = hold_of(source);

	if (!r || !r->pairs || !r->cap || !host || !remote || remote->len > sizeof(remote->storage))
		return;
	pick = r->cap;
	/* THE SAME WAY, else a free or lapsed pair, else the oldest learnt. */
	for (i = 0; i < r->cap && pick == r->cap; i++)
		if (r->pairs[i].used && r->pairs[i].local == local
		    && memcmp(r->pairs[i].host, host, FZN_PUBKEY_LEN) == 0
		    && same_remote(&r->pairs[i].remote, remote))
			pick = i;
	for (i = 0; i < r->cap && pick == r->cap; i++)
		if (!held(&r->pairs[i], now))
			pick = i;
	if (pick == r->cap) {
		pick = 0;
		for (i = 1; i < r->cap; i++)
			if (r->pairs[i].learnt < r->pairs[pick].learnt)
				pick = i;
	}
	/* A SOURCE NEVER DEMOTES ITS WAY while the better one holds: a manifest
	 * repeating an address a hello proved leaves the hello's word standing. */
	if (r->pairs[pick].used && held(&r->pairs[pick], now) && r->pairs[pick].source > source
	    && memcmp(r->pairs[pick].host, host, FZN_PUBKEY_LEN) == 0)
		return;
	memcpy(r->pairs[pick].host, host, FZN_PUBKEY_LEN);
	r->pairs[pick].remote = *remote;
	r->pairs[pick].local = local;
	r->pairs[pick].source = source;
	r->pairs[pick].learnt = now;
	r->pairs[pick].until = hold ? now + hold : 0u;
	r->pairs[pick].used = 1;
}

int fzn_reach_best(const fzn_reach_t *r, const uint8_t host[FZN_PUBKEY_LEN], uint64_t now,
                   fzn_reach_pair_t *out)
{
	const fzn_reach_pair_t *best = NULL;
	size_t i;

	if (!r || !r->pairs || !host)
		return 0;
	for (i = 0; i < r->cap; i++) {
		const fzn_reach_pair_t *p = &r->pairs[i];

		if (!held(p, now) || memcmp(p->host, host, FZN_PUBKEY_LEN) != 0)
			continue;
		if (!best || p->source > best->source
		    || (p->source == best->source && p->learnt > best->learnt))
			best = p;
	}
	if (!best)
		return 0;
	if (out)
		*out = *best;
	return 1;
}
