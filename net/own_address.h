#ifndef FZN_NET_OWN_ADDRESS_H
#define FZN_NET_OWN_ADDRESS_H

#include <stddef.h>
#include <stdint.h>

/* The longest HOST:PORT a candidate is, fuzzypickles' address bound. */
#define FZN_OWN_ADDRESS_MAX 64

/*
 * WHERE OTHERS CAN REACH THIS HOST, offered rather than asked for (taken from
 * fuzzypickles' client/own_address.c, fuzznet sec 1094). A contact card and a
 * pairing request both need "your address", and nobody knows their own IP and
 * the daemon's peer port -- least of all on a phone. Every client offers these
 * candidates, so the ranking is here rather than written once a client.
 */

typedef struct fzn_iface_addr {
	char iface[32]; /* the interface name, which decides its rank */
	char ip[16];    /* IPv4, dotted */
} fzn_iface_addr_t;

/* Up, running, non-loopback IPv4 addresses of this machine (getifaddrs), at
 * most `cap`. Returns how many; 0 when none or when they cannot be read. */
size_t fzn_local_ipv4_addresses(fzn_iface_addr_t *out, size_t cap);

/*
 * The candidates, best first, as "ip:port" (or `advertised` as given):
 *   1. `advertised` -- this host's `net/address` setting -- when set;
 *   2. Wi-Fi and Ethernet interfaces;
 *   3. any other;
 *   4. virtual and cellular interfaces (docker, bridges, tunnels, a phone's
 *      mobile data), rarely reachable from another device on the network;
 *   5. a self-assigned link-local address (169.254/16), on any interface.
 * No interface candidate when `port` is 0. Duplicates are dropped. Pure: the
 * caller supplies the interfaces, so the ranking is testable without a
 * network. Returns how many were written, at most `cap`.
 */
size_t fzn_own_address_candidates(const char *advertised, const fzn_iface_addr_t *locals,
                                  size_t n, uint16_t port,
                                  char out[][FZN_OWN_ADDRESS_MAX + 1], size_t cap);

#endif /* FZN_NET_OWN_ADDRESS_H */
