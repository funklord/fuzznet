/*
 * THE PORTS A HOST LISTENS ON, so a router can forward them and a peer can
 * find them, sec 1289 -- the holder's of 2026-11-19: "a specific set of
 * listener ports that can be port forwarded ... both low (root) ports and
 * high (user) ports ... a span of 10 ports each, so we can forward to
 * several different machines (different estates) on a network ... we may
 * need to scan for them externally ... we don't wanna port clash with
 * anything that is normally used."
 *
 *     root  930 - 939    a daemon run as root, below 1024
 *     user  6280 - 6289  a daemon run as a user
 *     6290               join by request's discovery (`node/offer.h`)
 *
 * CHOSEN BY MEASUREMENT, 2026-11-19, against IANA's service registry (its
 * CSV, every assigned port) and Wikipedia's list of ports in use, official
 * and unofficial: both spans sit inside runs IANA leaves unassigned with
 * free ports either side -- 916-952 and 6270-6299 -- and neither list names
 * any use inside them. Decades, so the set is plain to read and to scan:
 * twenty probes reach every host fuzznet would serve at one address, ten
 * machines or estates behind one router each forwarding one port of a span.
 *
 * A SPAN IS A PLACE TO LOOK, not a law: `--udp-port=PORT` still serves
 * anywhere; `--udp-port=span` takes the first free port of the span the
 * daemon's privilege allows.
 */
#ifndef FZN_NET_PORTS_H
#define FZN_NET_PORTS_H

#include <stddef.h>
#include <stdint.h>

#define FZN_PORTS_SPAN 10u
#define FZN_PORTS_ROOT_FIRST 930u
#define FZN_PORTS_USER_FIRST 6280u
#define FZN_PORTS_DISCOVERY 6290u
/* Every port a host may serve at: both spans. */
#define FZN_PORTS_ALL (2u * FZN_PORTS_SPAN)

/* The `i`th port of the root span (`root` 1) or the user span, `i` below
 * FZN_PORTS_SPAN; 0 for any other `i`. */
uint16_t fzn_ports_nth(int root, unsigned i);

/* Whether `port` is one of either span's. */
int fzn_ports_in_span(uint16_t port);

/* EVERY PORT, in the order a peer scanning an address tries them: the user
 * span first, where most hosts serve, then the root span. FZN_PORTS_ALL. */
size_t fzn_ports_scan(uint16_t out[FZN_PORTS_ALL]);

#endif /* FZN_NET_PORTS_H */
