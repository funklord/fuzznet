/*
 * PEERS WHOSE CLOCKS DISAGREE WITH THIS NODE'S, sec 717: one row a peer,
 * from the frames of its own (they opened under its session) refused for
 * their expiry (`node/serve.h`'s `on_stale`). For a client to show, where
 * the log line of sec 714 was only for a person reading a log: the
 * requirement fuzzypickles stated, inbox 20261023T2309Z.
 *
 *     list clock [FROM]   ->   ok TOTAL FROM KEY,DIR,SECONDS,AT ...
 *
 * KEY the peer's, in full; DIR `behind` when its frames arrive already
 * expired (its clock behind this one's, or this one ahead) and `ahead` when
 * they arrive past this node's horizon; SECONDS how far outside the window
 * the frame landed, as last measured -- for `behind`, how long it had
 * already expired when it came, which is the clocks' disagreement less the
 * request's life; for `ahead`, how far past the horizon, the disagreement
 * less the skew the horizon allows. A lower bound on the disagreement, not
 * the disagreement: the life is the sender's choice, which this node does
 * not know. AT when last seen, in seconds since the epoch by this node's
 * clock. A row not seen for FZN_NODE_CLOCKS_KEEP_S is forgotten, so a
 * client drops its notice when the row is gone. Paged by FROM, as `list
 * contact` is. The node's own user's alone.
 *
 * THE TABLE IS THE CALLER'S, grown by it on ROOM, as the node's other
 * tables are (sec 704): a row a peer, so as many as the peers that have
 * drifted.
 *
 * WHAT THE PEER WHOSE CLOCK IS WRONG LEARNS: nothing from here. Its frames
 * are dropped unanswered by design -- a reply is an oracle to anyone
 * holding a session -- so the notice is this side's to show.
 */
#ifndef FZN_NODE_CLOCKS_H
#define FZN_NODE_CLOCKS_H

#include <stddef.h>
#include <stdint.h>

#include "../chain/authz.h"
#include "../local/vocabulary.h"
#include "../chain/chain.h"

/* Ten minutes: two request lifetimes. A peer still drifting refreshes its
 * row with every request it sends; one quiet this long is taken to have
 * agreed again, or gone. */
#define FZN_NODE_CLOCKS_KEEP_S 600u

typedef struct fzn_node_clock {
	uint8_t peer[FZN_PUBKEY_LEN];
	int ahead;        /* 1: its frames past the horizon; 0: already expired */
	uint64_t seconds; /* how far outside the window, a lower bound on the skew */
	uint64_t at;      /* when last seen, this node's clock, seconds */
} fzn_node_clock_t;

typedef struct fzn_node_clocks {
	fzn_node_clock_t *rows; /* the caller's */
	size_t used, cap;
} fzn_node_clocks_t;

typedef enum fzn_node_clocks_err {
	FZN_NODE_CLOCKS_OK = 0,      /* the row was there and is refreshed */
	FZN_NODE_CLOCKS_NEW = 1,     /* a row new, or its direction changed */
	FZN_NODE_CLOCKS_ROOM = -1,   /* no room for a new row: grow and note again */
	FZN_NODE_CLOCKS_MALFORMED = -2
} fzn_node_clocks_err_t;

/* Point `c` at `rows`, `cap` of them, empty. */
void fzn_node_clocks_init(fzn_node_clocks_t *c, fzn_node_clock_t *rows, size_t cap);

/* Move `c` onto `rows`, `cap` of them, keeping what it holds. 0 when `cap`
 * is smaller than what is held. */
int fzn_node_clocks_use(fzn_node_clocks_t *c, fzn_node_clock_t *rows, size_t cap);

/* Note `peer`'s frame refused for its clock: `ahead`, by `seconds`, at
 * `now`. Rows not seen since `now - FZN_NODE_CLOCKS_KEEP_S` are forgotten
 * first. */
fzn_node_clocks_err_t fzn_node_clocks_note(fzn_node_clocks_t *c,
                                           const uint8_t peer[FZN_PUBKEY_LEN], int ahead,
                                           uint64_t seconds, uint64_t now);

/* The answer to `request` if it is `list clock`, into `reply` (`cap`
 * bytes), its length; 0 for any other request. Rows past their keeping are
 * forgotten first, at `now`. */
size_t fzn_node_clocks_local(fzn_node_clocks_t *c, fzn_origin_t origin,
                             const fzn_request_t *request, uint64_t now, char *reply,
                             size_t cap);

#endif /* FZN_NODE_CLOCKS_H */
