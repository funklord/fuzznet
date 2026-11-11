/*
 * A CALL'S WORDS AND ITS TABLE, sec 1019, sec 1017's steps 2 and 3. A call
 * runs client -> its host -> the other host -> its client, each hop a session
 * (secs 932, 935, 1018), every word said once and never resent. These are the
 * words, as bytes, and the calls a host is part of; what a host does with
 * them is the daemon's.
 *
 *     version 2 | FZN_TYPE_LIVE | KIND | CALL 8 | ...
 *
 *     RING     KINDS 1 | WHOM 32        a call asked, of user WHOM: KINDS a
 *                                       mask of FZN_LIVE_AUDIO, _VIDEO
 *     ANSWER                            taken, on one of WHOM's clients
 *     DECLINE                           refused
 *     HANGUP                            ended, by either end
 *     FRAME    STREAM 1 | SEQ 4 | AT 4 | PIECE 2 | PIECES 2 | MEDIA
 *                                       a frame's piece: STREAM the kind,
 *                                       SEQ the frame's number in it, AT its
 *                                       capture time in the sender's ms, the
 *                                       piece of how many
 *
 * MEDIA IS OPAQUE: the codec, the capture and the jitter buffer are the
 * client's (sec 1017). A frame past one word goes in pieces, which the
 * receiving client puts together, a frame missing one being lost.
 *
 * THE TABLE IS THE CALLER'S, grown on ROOM as the node's other tables are
 * (sec 704): a row a call this host is part of -- as the caller's host, or
 * the callee's.
 */
#ifndef FZN_NODE_LIVE_H
#define FZN_NODE_LIVE_H

#include <stddef.h>
#include <stdint.h>

#include "../chain/chain.h"

#define FZN_LIVE_CALL_LEN 8u
#define FZN_LIVE_HEAD_LEN (2u + 1u + FZN_LIVE_CALL_LEN)
#define FZN_LIVE_RING_LEN (FZN_LIVE_HEAD_LEN + 1u + FZN_PUBKEY_LEN)
#define FZN_LIVE_FRAME_HEAD_LEN (FZN_LIVE_HEAD_LEN + 1u + 4u + 4u + 2u + 2u)

#define FZN_LIVE_AUDIO 1u
#define FZN_LIVE_VIDEO 2u

/* HOW LONG A CALL RINGS unanswered, and is kept with no frame either way. */
#define FZN_LIVE_RING_S 45u
#define FZN_LIVE_IDLE_S 30u

typedef enum fzn_live_kind {
	FZN_LIVE_RING = 1,
	FZN_LIVE_ANSWER = 2,
	FZN_LIVE_DECLINE = 3,
	FZN_LIVE_HANGUP = 4,
	FZN_LIVE_FRAME = 5
} fzn_live_kind_t;

/* ONE WORD READ, pointing into the caller's bytes. */
typedef struct fzn_live_word {
	fzn_live_kind_t kind;
	uint8_t call[FZN_LIVE_CALL_LEN];
	/* RING */
	uint8_t kinds;
	const uint8_t *whom;
	/* FRAME */
	uint8_t stream;
	uint32_t seq, at_ms;
	uint16_t piece, pieces;
	const uint8_t *media;
	size_t media_len;
} fzn_live_word_t;

/* WHETHER `bytes` IS A LIVE WORD at all: version and type. */
int fzn_live_is_word(const uint8_t *bytes, size_t len);

/* `bytes` READ: 1, or 0 when it is no live word or its shape is wrong. */
int fzn_live_read(const uint8_t *bytes, size_t len, fzn_live_word_t *out);

/* A WORD WRITTEN into `out`, its length; 0 when `cap` is short or the word is
 * malformed (a frame's piece past its pieces, or none). */
size_t fzn_live_write(const fzn_live_word_t *w, uint8_t *out, size_t cap);

typedef enum fzn_live_state {
	FZN_LIVE_RINGING_OUT = 1, /* this host's client rang, the other host told */
	FZN_LIVE_RINGING_IN = 2,  /* rung from another host, this host's clients told */
	FZN_LIVE_UP = 3
} fzn_live_state_t;

/* A CALL THIS HOST IS PART OF. `client` the client of this host's in it --
 * the caller's, or, once answered, the one that answered; `host` the other
 * host. */
typedef struct fzn_live_call {
	uint8_t call[FZN_LIVE_CALL_LEN];
	fzn_live_state_t state;
	uint8_t client[FZN_PUBKEY_LEN];
	uint8_t host[FZN_PUBKEY_LEN];
	uint8_t kinds;
	uint64_t since_s, heard_s;
	uint8_t used;
} fzn_live_call_t;

typedef struct fzn_live_calls {
	fzn_live_call_t *rows;
	size_t cap, n;
} fzn_live_calls_t;

/* `call`'S ROW, or NULL. */
fzn_live_call_t *fzn_live_find(fzn_live_calls_t *t, const uint8_t call[FZN_LIVE_CALL_LEN]);

/* A ROW FOR `call`, new or the one held, grown as needed; NULL with no memory. */
fzn_live_call_t *fzn_live_open(fzn_live_calls_t *t, const uint8_t call[FZN_LIVE_CALL_LEN]);

/* `c` ENDED, its row free. */
void fzn_live_end(fzn_live_calls_t *t, fzn_live_call_t *c);

/* ROWS PAST THEIR TIME at `now_s` ended -- ringing past FZN_LIVE_RING_S, or up
 * and heard of by neither end for FZN_LIVE_IDLE_S -- each told to `gone`
 * first; how many. */
size_t fzn_live_expire(fzn_live_calls_t *t, uint64_t now_s,
                       void (*gone)(void *ctx, const fzn_live_call_t *c), void *ctx);

void fzn_live_release(fzn_live_calls_t *t);

#endif /* FZN_NODE_LIVE_H */
