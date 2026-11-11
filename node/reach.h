/*
 * WHERE A HOST IS REACHED, sec 1036: a host's candidate pairs, and the one
 * rule every sender asks. Seven stores answered the question before this, each
 * read by its own code in its own order, and none modelled the local side --
 * though sec 1031's fault was measured to be the socket an ask left from.
 *
 * A PAIR is a local socket and a remote address, by the remote host's key,
 * with where it was learnt and when, and how long that source holds:
 *
 *     ADVERTISED   the address a host says it is at       held until replaced
 *     MANIFEST     a contact's, as its manifest gave it   held until replaced
 *     INTRODUCED   where an introducer saw it (sec 698)   FZN_REACH_INTRODUCED_S
 *     HELLO        where it said hello from (sec 697)     FZN_REACH_HELLO_S
 *     SESSION      where a session's frame came from      FZN_REACH_SESSION_S
 *
 * THE RULE, sec 1030's -- as direct as possible, a measured way before a told
 * one: of a host's pairs still held, the one whose source proved it most
 * lately, HELLO, then SESSION, then INTRODUCED, then MANIFEST, then ADVERTISED;
 * of two of one source, the newer. A hello is first because it came to this
 * host's serving socket through whatever NAT is in the way, so the way back is
 * open; an advertised address may sit behind a NAT nothing outside reaches.
 *
 * THE TABLE IS THE CALLER'S, of any size, as the node's other tables are (sec
 * 704): a full one gives its oldest pair way, one past its hold first.
 */
#ifndef FZN_NODE_REACH_H
#define FZN_NODE_REACH_H

#include <stddef.h>
#include <stdint.h>

#include "../chain/chain.h"
#include "../net/udp.h"

#define FZN_REACH_HELLO_S 300u
#define FZN_REACH_INTRODUCED_S 600u
#define FZN_REACH_SESSION_S 300u

typedef enum fzn_reach_source {
	FZN_REACH_ADVERTISED = 1,
	FZN_REACH_MANIFEST = 2,
	FZN_REACH_INTRODUCED = 3,
	FZN_REACH_SESSION = 4,
	FZN_REACH_HELLO = 5
} fzn_reach_source_t;

/* WHICH OF THIS HOST'S SOCKETS a pair sends from. */
typedef enum fzn_reach_local {
	FZN_REACH_SERVING = 1, /* the socket this host serves on, which its hellos leave from */
	FZN_REACH_TARGET = 2   /* a round's target's own socket, which an introduction punches for */
} fzn_reach_local_t;

typedef struct fzn_reach_pair {
	uint8_t host[FZN_PUBKEY_LEN];
	fzn_udp_addr_t remote;
	fzn_reach_local_t local;
	fzn_reach_source_t source;
	uint64_t learnt, until; /* seconds; `until` 0 is held until replaced */
	int used;
} fzn_reach_pair_t;

typedef struct fzn_reach {
	fzn_reach_pair_t *pairs;
	size_t cap;
} fzn_reach_t;

/* `pairs`, `cap` of them, cleared: the caller's, outliving `r`. */
void fzn_reach_init(fzn_reach_t *r, fzn_reach_pair_t *pairs, size_t cap);

/* `host` MAY BE REACHED at `remote` from `local`, learnt from `source` at `now`:
 * the same host, local and remote replaced, else a free pair, else the oldest. */
void fzn_reach_learn(fzn_reach_t *r, const uint8_t host[FZN_PUBKEY_LEN], fzn_reach_local_t local,
                     const fzn_udp_addr_t *remote, fzn_reach_source_t source, uint64_t now);

/* THE PAIR TO USE for `host` at `now`, into `out`, by the rule above: 1, or 0
 * when none is held. */
int fzn_reach_best(const fzn_reach_t *r, const uint8_t host[FZN_PUBKEY_LEN], uint64_t now,
                   fzn_reach_pair_t *out);

#endif /* FZN_NODE_REACH_H */
