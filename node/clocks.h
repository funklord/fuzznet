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

/* ---- the time probe and offsets per peer, sec 719 stage 1 -------------- */

/* THE PROBE, version 2 (`node/types.h`):
 *     ask     2 | FZN_TYPE_TIME_ASK | nonce[16]
 *     answer  2 | FZN_TYPE_TIME     | nonce[16] | time_ms (u64, big-endian)
 * A node answers an ask whatever its frame's expiry (`node/remote.c`), so
 * that two clocks already too far apart for any other request can still
 * be measured; answering changes nothing, so a replayed ask gains nothing
 * but the answer. The nonce, echoed, ties an answer to its ask. */
#define FZN_NODE_TIME_NONCE_LEN 16u
#define FZN_NODE_TIME_ASK_LEN (2u + FZN_NODE_TIME_NONCE_LEN)
#define FZN_NODE_TIME_ANSWER_LEN (2u + FZN_NODE_TIME_NONCE_LEN + 8u)

/* Whether `payload` is a time ask. */
int fzn_node_time_is_ask(const uint8_t *payload, size_t len);

/* The ask for `nonce` into `out`, its length; 0 when it does not fit. */
size_t fzn_node_time_ask(const uint8_t nonce[FZN_NODE_TIME_NONCE_LEN], uint8_t *out, size_t cap);

/* The answer to `ask` at `now_ms` into `out`, its length; 0 for an ask
 * that is not one or an answer that does not fit. */
size_t fzn_node_time_answer(const uint8_t *ask, size_t ask_len, uint64_t now_ms, uint8_t *out,
                            size_t cap);

/* AN ANSWER TAKEN: 1 when `answer` answers the ask for `nonce`, with the
 * peer's offset -- its clock less this one's, in milliseconds -- from an ask
 * sent at `sent_ms` and answered at `got_ms` by this node's clock, and the
 * round trip; 0 otherwise. The offset is the peer's time less the
 * midpoint of the two, good to half the round trip. */
int fzn_node_time_take(const uint8_t *answer, size_t len,
                       const uint8_t nonce[FZN_NODE_TIME_NONCE_LEN], uint64_t sent_ms,
                       uint64_t got_ms, int64_t *offset_ms, uint64_t *rtt_ms);

/* THE SAMPLES A PEER'S OFFSET IS FILTERED FROM, NTP's clock filter: of the
 * last few, the one with the least round trip, whose error is the least
 * bounded. Few by nature -- a window, not a store. */
#define FZN_NODE_OFFSET_SAMPLES 8u

typedef struct fzn_node_offset {
	uint8_t peer[FZN_PUBKEY_LEN];
	int64_t offset_ms[FZN_NODE_OFFSET_SAMPLES];
	uint64_t rtt_ms[FZN_NODE_OFFSET_SAMPLES];
	size_t n, next;     /* samples held, and where the next goes */
	uint64_t at;        /* when last sampled, this node's clock, seconds */
} fzn_node_offset_t;

typedef struct fzn_node_offsets {
	fzn_node_offset_t *rows; /* the caller's */
	size_t used, cap;
} fzn_node_offsets_t;

void fzn_node_offsets_init(fzn_node_offsets_t *o, fzn_node_offset_t *rows, size_t cap);

/* Move `o` onto `rows`, keeping what it holds; 0 when `cap` is too small. */
int fzn_node_offsets_use(fzn_node_offsets_t *o, fzn_node_offset_t *rows, size_t cap);

/* A SAMPLE of `peer`'s offset at `now` (seconds). Rows not sampled since
 * `now - FZN_NODE_CLOCKS_KEEP_S` are forgotten first. OK, NEW for a peer
 * not held before, ROOM to grow and note again. */
fzn_node_clocks_err_t fzn_node_offsets_note(fzn_node_offsets_t *o,
                                            const uint8_t peer[FZN_PUBKEY_LEN],
                                            int64_t offset_ms, uint64_t rtt_ms, uint64_t now);

/* `peer`'s filtered offset and its round trip: 1 when it has one, 0 when
 * this node holds no sample of it. */
int fzn_node_offsets_of(const fzn_node_offsets_t *o, const uint8_t peer[FZN_PUBKEY_LEN],
                        int64_t *offset_ms, uint64_t *rtt_ms);

/* When `peer` was last sampled, 0 for never. */
uint64_t fzn_node_offsets_at(const fzn_node_offsets_t *o, const uint8_t peer[FZN_PUBKEY_LEN]);

/* `list offset [FROM]` -> `ok TOTAL FROM KEY,OFFSET_MS,RTT_MS,AT ...`: every
 * peer sampled, its filtered offset (its clock less this one's, signed),
 * that sample's round trip, and when last sampled. 0 for another request. */
size_t fzn_node_offsets_local(fzn_node_offsets_t *o, fzn_origin_t origin,
                              const fzn_request_t *request, uint64_t now, char *reply,
                              size_t cap);

#endif /* FZN_NODE_CLOCKS_H */
