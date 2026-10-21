/*
 * A LOCATION SOURCE IN gpsd, sec 678: a TCP client of the gpsd daemon,
 * which owns the receiver, deals with its device's permissions once for
 * the system, and serves several clients -- so the node stays unprivileged
 * and shares the receiver with anything else that wants it. Carried over
 * from fuzzypickles' `daemon/gpsd_source.c` (at their d02897b).
 *
 * NEVER BLOCKS: the socket is non-blocking and the link a small state
 * machine advanced one step a poll, so a node polls it from its loop. A
 * gpsd that is not there is an ordinary state, reported, not a failure:
 * creating one connects nothing, and a poll reconnects when the link is
 * down.
 *
 * NOT YET EXERCISED AGAINST A RECEIVER, here or in fuzzypickles: what
 * gpsd sends is held by `location/test/tpv_test.c`, and the link by a
 * stand-in gpsd in `tool/live_location.py`.
 *
 * POSIX SOCKETS, as `net/udp.h`'s and `local/socket.h`'s are: core, no
 * backend's define.
 */
#ifndef FZN_LOCATION_GPSD_H
#define FZN_LOCATION_GPSD_H

#include <stddef.h>
#include <stdint.h>

#include "location.h"

/* WHAT THE LINK IS DOING, for a status to say rather than guess: a source
 * that exists has not therefore connected. */
typedef enum fzn_gpsd_link {
	FZN_GPSD_DISCONNECTED = 0,
	FZN_GPSD_CONNECTING = 1,   /* the socket open, WATCH not yet sent */
	FZN_GPSD_WATCHING = 2      /* WATCH sent; reports arriving */
} fzn_gpsd_link_t;

#define FZN_GPSD_HOST_MAX 253u
#define FZN_GPSD_BUF 8192u

typedef struct fzn_gpsd {
	char host[FZN_GPSD_HOST_MAX + 1u];
	uint16_t port;
	int fd;
	fzn_gpsd_link_t link;
	char buf[FZN_GPSD_BUF];
	size_t buf_len;
	fzn_location_fix_t latest;
	int have_latest;
} fzn_gpsd_t;

/* AIM `g` at `host`, `port`, connecting nothing yet: 1, or 0 for a host
 * empty or too long or a port of 0. */
int fzn_gpsd_init(fzn_gpsd_t *g, const char *host, uint16_t port);

/* ONE STEP: connect when down, send WATCH once connected, read whatever
 * reports have come. 1 with the newest fix since the last poll in `out`,
 * 0 for none. Never blocks. */
int fzn_gpsd_poll(fzn_gpsd_t *g, fzn_location_fix_t *out);

/* Where the link is. */
fzn_gpsd_link_t fzn_gpsd_link(const fzn_gpsd_t *g);

/* Close it; `g` may be aimed again. */
void fzn_gpsd_close(fzn_gpsd_t *g);

#endif /* FZN_LOCATION_GPSD_H */
