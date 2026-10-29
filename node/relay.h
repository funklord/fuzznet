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

#include "../chain/authz.h" /* fzn_origin_t */
#include "../chain/chain.h" /* FZN_PUBKEY_LEN */
#include "../net/udp.h"

/* THE TABLES' OWN ROOM, until the caller gives more
 * (`fzn_node_relay_use`). Both learn from any sender, so they are bounded
 * and evict past the bound -- but by the room given, not by 64, which a
 * relay serving more devices than that passed every round. sec 704. */
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
	fzn_node_relay_route_t *routes;
	fzn_node_relay_seen_t *seen;
	size_t routes_cap, seen_cap;
	fzn_node_relay_route_t own_routes[FZN_NODE_RELAY_ROUTES_MAX];
	fzn_node_relay_seen_t own_seen[FZN_NODE_RELAY_SEEN_MAX];
} fzn_node_relay_t;

void fzn_node_relay_init(fzn_node_relay_t *r);

/* LARGER TABLES OF THE CALLER'S, sec 704: `routes` of `routes_cap` and
 * `seen` of `seen_cap`, which must outlive `r`, what is held copied over. 0
 * for room smaller than the tables' own. */
int fzn_node_relay_use(fzn_node_relay_t *r, fzn_node_relay_route_t *routes, size_t routes_cap,
                       fzn_node_relay_seen_t *seen, size_t seen_cap);

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

/*
 * WHO MAY ASK, sec 762: journey 4's authorization, judged here so a table
 * test can try each request with each wrong caller -- the handlers that
 * use them sit in fuzznetd, where no test reaches them. An asker is what
 * this host knows of a sender: a member of its estate, or a standing
 * contact's host and whose, or neither -- a removed contact, a host whose
 * frame opened and nothing more. Each judgment is NULL when allowed and
 * otherwise the reason, which the handler says and answers.
 */
typedef struct fzn_node_relay_asker {
	int member;                    /* holds standing in this estate */
	int contact;                   /* a standing contact's host */
	uint8_t owner[FZN_PUBKEY_LEN]; /* that contact's user, when `contact` */
} fzn_node_relay_asker_t;

/* A FRAME RELAYED: this host relaying at all (`relay/enabled`), for its
 * estate and its contacts, one hop and never two (`hops` the request's
 * budget left), and only a frame the asker sealed itself (`own`). */
const char *fzn_node_relay_refuse_relay(const fzn_node_relay_asker_t *asker, int enabled,
                                        unsigned hops, int own);
/* AN INTRODUCTION ASKED: where a host is is its estate's to know. */
const char *fzn_node_relay_refuse_introduce(const fzn_node_relay_asker_t *asker);
/* A NOTIFY, about `about`: from a member, about a host this one knows; or
 * from a standing contact's host about another of that same contact's
 * (sec 698). */
const char *fzn_node_relay_refuse_notify(const fzn_node_relay_asker_t *asker,
                                         const fzn_node_relay_asker_t *about);
/* A TIME ASK, sec 719: a member's or a standing contact's. A removed
 * contact still reaches the hook (sec 701), and was answered. */
const char *fzn_node_relay_refuse_time(const fzn_node_relay_asker_t *asker);

/* THE REACHABILITY VERBS, sec 762 -- `fetch lan`, `get lan`, `get` and
 * `fetch address`, `get routing` -- asked over the local socket: the node's
 * own user's, as `get relay` and `get events` are. Who this host hears on
 * its network, the probes it sends there, where its peers see it and the
 * routes it holds are that user's to know. NULL for its own user. */
const char *fzn_node_relay_refuse_local(fzn_origin_t origin);

#endif /* FZN_NODE_RELAY_H */
