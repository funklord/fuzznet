/* Relaying's two tables: project.md sec 622, and the header. */
#include "relay.h"

#include <string.h>

void fzn_node_relay_init(fzn_node_relay_t *r)
{
	if (!r)
		return;
	memset(r, 0, sizeof(*r));
	r->routes = r->own_routes;
	r->seen = r->own_seen;
	r->routes_cap = FZN_NODE_RELAY_ROUTES_MAX;
	r->seen_cap = FZN_NODE_RELAY_SEEN_MAX;
}

int fzn_node_relay_use(fzn_node_relay_t *r, fzn_node_relay_route_t *routes, size_t routes_cap,
                       fzn_node_relay_seen_t *seen, size_t seen_cap)
{
	if (!r || !r->routes || !routes || !seen || routes_cap < r->routes_cap
	    || seen_cap < r->seen_cap)
		return 0;
	memset(routes, 0, routes_cap * sizeof(*routes));
	memset(seen, 0, seen_cap * sizeof(*seen));
	memcpy(routes, r->routes, r->routes_cap * sizeof(*routes));
	memcpy(seen, r->seen, r->seen_cap * sizeof(*seen));
	r->routes = routes;
	r->seen = seen;
	r->routes_cap = routes_cap;
	r->seen_cap = seen_cap;
	return 1;
}

void fzn_node_relay_route(fzn_node_relay_t *r, const uint8_t target[FZN_PUBKEY_LEN], uint32_t msg,
                          const fzn_udp_addr_t *back, uint64_t now)
{
	size_t i, pick;

	if (!r || !r->routes || !target || !back)
		return;
	pick = r->routes_cap;
	/* THE SAME PAIR, else an empty or ended route, else the nearest its
	 * end. */
	for (i = 0; i < r->routes_cap && pick == r->routes_cap; i++)
		if (r->routes[i].used && r->routes[i].msg == msg
		    && memcmp(r->routes[i].target, target, FZN_PUBKEY_LEN) == 0)
			pick = i;
	for (i = 0; i < r->routes_cap && pick == r->routes_cap; i++)
		if (!r->routes[i].used || r->routes[i].until <= now)
			pick = i;
	if (pick == r->routes_cap) {
		pick = 0;
		for (i = 1; i < r->routes_cap; i++)
			if (r->routes[i].until < r->routes[pick].until)
				pick = i;
	}
	memcpy(r->routes[pick].target, target, FZN_PUBKEY_LEN);
	r->routes[pick].msg = msg;
	r->routes[pick].back = *back;
	r->routes[pick].until = now + FZN_NODE_RELAY_ROUTE_S;
	r->routes[pick].used = 1;
}

int fzn_node_relay_back(const fzn_node_relay_t *r, const uint8_t sender[FZN_PUBKEY_LEN],
                        uint32_t msg, uint64_t now, fzn_udp_addr_t *back)
{
	size_t i;

	if (!r || !sender || !back)
		return 0;
	for (i = 0; i < r->routes_cap; i++) {
		const fzn_node_relay_route_t *e = &r->routes[i];

		if (e->used && e->until > now && e->msg == msg
		    && memcmp(e->target, sender, FZN_PUBKEY_LEN) == 0) {
			*back = e->back;
			return 1;
		}
	}
	return 0;
}

void fzn_node_relay_saw(fzn_node_relay_t *r, const uint8_t key[FZN_PUBKEY_LEN],
                        const fzn_udp_addr_t *at, uint64_t now)
{
	size_t i, pick;

	if (!r || !r->seen || !key || !at)
		return;
	pick = r->seen_cap;
	/* THE SAME KEY, else an empty slot, else the oldest. */
	for (i = 0; i < r->seen_cap && pick == r->seen_cap; i++)
		if (r->seen[i].used && memcmp(r->seen[i].key, key, FZN_PUBKEY_LEN) == 0)
			pick = i;
	for (i = 0; i < r->seen_cap && pick == r->seen_cap; i++)
		if (!r->seen[i].used)
			pick = i;
	if (pick == r->seen_cap) {
		pick = 0;
		for (i = 1; i < r->seen_cap; i++)
			if (r->seen[i].when < r->seen[pick].when)
				pick = i;
	}
	memcpy(r->seen[pick].key, key, FZN_PUBKEY_LEN);
	r->seen[pick].at = *at;
	r->seen[pick].when = now;
	r->seen[pick].used = 1;
}

int fzn_node_relay_where(const fzn_node_relay_t *r, const uint8_t key[FZN_PUBKEY_LEN],
                         fzn_udp_addr_t *at, uint64_t *when)
{
	size_t i;

	if (!r || !key || !at)
		return 0;
	for (i = 0; i < r->seen_cap; i++)
		if (r->seen[i].used && memcmp(r->seen[i].key, key, FZN_PUBKEY_LEN) == 0) {
			*at = r->seen[i].at;
			if (when)
				*when = r->seen[i].when;
			return 1;
		}
	return 0;
}

/* ---- who may ask, sec 762 ------------------------------------------------- */

const char *fzn_node_relay_refuse_relay(const fzn_node_relay_asker_t *asker, int enabled,
                                        unsigned hops, int own)
{
	if (!enabled)
		return "this host relays nothing";
	if (!asker || (!asker->member && !asker->contact))
		return "relayed only for this estate and its contacts";
	if (hops == 0u)
		return "relayed already: one hop and never two";
	if (!own)
		return "not a frame of the asker's own";
	return NULL;
}

const char *fzn_node_relay_refuse_introduce(const fzn_node_relay_asker_t *asker)
{
	return asker && asker->member ? NULL : "introductions only within this estate";
}

const char *fzn_node_relay_refuse_notify(const fzn_node_relay_asker_t *asker,
                                         const fzn_node_relay_asker_t *about)
{
	if (!asker || !about)
		return "only this estate, or a contact about its own, introduces";
	if (!asker->member) {
		if (!asker->contact || !about->contact
		    || memcmp(asker->owner, about->owner, FZN_PUBKEY_LEN) != 0)
			return "only this estate, or a contact about its own, introduces";
		return NULL;
	}
	return about->member || about->contact ? NULL : "not a host this one knows";
}

const char *fzn_node_relay_refuse_time(const fzn_node_relay_asker_t *asker)
{
	return asker && (asker->member || asker->contact) ? NULL
	                                                  : "clocks only for this estate and its contacts";
}

const char *fzn_node_relay_refuse_local(fzn_origin_t origin)
{
	return origin == FZN_ORIGIN_SAME_USER ? NULL
	                                       : "where this host is reached is its own user's";
}
