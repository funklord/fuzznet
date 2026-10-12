/*
 * WHEN THIS NODE LAST HEARD FROM EACH HOST, sec 601: so a keeper of a piece
 * that has gone silent can be told from one that answered a moment ago,
 * across restarts of this node. One row per host in persist slot
 * FZN_PERSIST_HOST_HEARD, keyed by its key, laid out as `node/heard.situ`.
 *
 * Heard means answered a round's exchange; what a host is silent for is
 * the caller's to judge against `archive/gone`.
 */
#ifndef FZN_NODE_HEARD_H
#define FZN_NODE_HEARD_H

#include <stdint.h>

#include "../persist/persist.h"

typedef enum fzn_heard_err {
	FZN_HEARD_OK = 0,
	/* A null argument, or a store without load or save. */
	FZN_HEARD_MALFORMED = -1,
	/* Never heard from, or its row is not one. */
	FZN_HEARD_ABSENT = -2,
	/* The store would not write. */
	FZN_HEARD_BACKEND = -3
} fzn_heard_err_t;

const char *fzn_heard_err_str(fzn_heard_err_t err);

/* HEARD FROM `host` at `at_us`: kept when later than the time kept, so a
 * clock stepped back never makes a host heard earlier than it was. */
fzn_heard_err_t fzn_heard_mark(const fzn_persist_ops_t *store, const uint8_t host[32],
                               uint64_t at_us);

/* WHEN `host` WAS LAST HEARD FROM, into `*at_us`; ABSENT when never. */
fzn_heard_err_t fzn_heard_when(const fzn_persist_ops_t *store, const uint8_t host[32],
                               uint64_t *at_us);

#endif /* FZN_NODE_HEARD_H */
