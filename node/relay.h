/*
 * RELAYING, project.md sec 622: fuzzypickles' volunteer relay (their sec 7,
 * PEER_RELAY) brought into fuzznet as step 4b of sec 608 -- the two tables
 * a relay keeps. The decision of what to relay is the daemon's.
 *
 * WHAT A RELAY DOES. A peer A asks relay R, in a request on their session,
 * to forward a frame A sealed for T; R sends it, unread, from R's serving
 * socket to where it last saw T. T answers to where the frame came from,
 * which is R, and R must send that answer on to A unread too -- a request
 * here waits for its answer, where fuzzypickles' relayed frames were
 * fire-and-forget. So:
 *
 *   - ROUTES: for a while after forwarding, a frame from T carrying the
 *     forwarded frame's message id goes back to where A asked from. Keyed
 *     by (sender key, message id), both in a frame's plaintext head.
 *   - SEEN: where each peer was last seen -- the address a granted frame
 *     came from -- so R can reach a host behind a NAT that keeps talking
 *     to it. Never who a peer IS (sec 596): only where to send.
 *
 * Both bounded, both kept in memory: a relay stores no frame, and loses
 * nothing worth keeping by restarting.
 */
#ifndef FZN_NODE_RELAY_H
#define FZN_NODE_RELAY_H

#include <stddef.h>
#include <stdint.h>

#include "../chain/chain.h" /* FZN_PUBKEY_LEN */
#include "../net/udp.h"

#define FZN_NODE_RELAY_ROUTES_MAX 64u
#define FZN_NODE_RELAY_SEEN_MAX 64u
/* How long a forwarded frame's answers are routed back, seconds. */
#define FZN_NODE_RELAY_ROUTE_S 10u

typedef struct fzn_node_relay_route {
	uint8_t target[FZN_PUBKEY_LEN];
	uint32_t msg;
	fzn_udp_addr_t back;
	uint64_t until;
	int used;
} fzn_node_relay_route_t;

typedef struct fzn_node_relay_seen {
	uint8_t key[FZN_PUBKEY_LEN];
	fzn_udp_addr_t at;
	uint64_t when;
	int used;
} fzn_node_relay_seen_t;

typedef struct fzn_node_relay {
	fzn_node_relay_route_t routes[FZN_NODE_RELAY_ROUTES_MAX];
	fzn_node_relay_seen_t seen[FZN_NODE_RELAY_SEEN_MAX];
} fzn_node_relay_t;

void fzn_node_relay_init(fzn_node_relay_t *r);

/* ROUTE `target`'s answers to message `msg` back to `back` until `now` +
 * FZN_NODE_RELAY_ROUTE_S: replacing a route for the same pair, else an
 * expired one, else the one nearest its end. */
void fzn_node_relay_route(fzn_node_relay_t *r, const uint8_t target[FZN_PUBKEY_LEN], uint32_t msg,
                          const fzn_udp_addr_t *back, uint64_t now);

/* WHERE A FRAME FROM `sender` FOR `msg` GOES BACK, into `back`: 1 when a
 * route stands at `now`. The route stays until it ends -- an answer may be
 * several frames. */
int fzn_node_relay_back(const fzn_node_relay_t *r, const uint8_t sender[FZN_PUBKEY_LEN],
                        uint32_t msg, uint64_t now, fzn_udp_addr_t *back);

/* `key` WAS SEEN at `at` at `now`: replacing its last, else the oldest. */
void fzn_node_relay_saw(fzn_node_relay_t *r, const uint8_t key[FZN_PUBKEY_LEN],
                        const fzn_udp_addr_t *at, uint64_t now);

/* WHERE `key` WAS LAST SEEN, into `at` and `*when`: 1 when it was. */
int fzn_node_relay_where(const fzn_node_relay_t *r, const uint8_t key[FZN_PUBKEY_LEN],
                         fzn_udp_addr_t *at, uint64_t *when);

#endif /* FZN_NODE_RELAY_H */
