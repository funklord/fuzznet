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
 *     FRAME    STREAM 1 | FROM 2 | SEQ 4 | AT 4 | PIECE 2 | PIECES 2 | MEDIA
 *                                       a frame's piece: STREAM the kind,
 *                                       FROM who sent it (below), SEQ the
 *                                       frame's number in its sender's
 *                                       stream, AT its capture time in the
 *                                       sender's ms, the piece of how many
 *     REPORT   STREAM 1 | RECEIVED 4 | LOST 4 | JITTER 2 | LAST 4 | HELD 4
 *                                       what the receiver measured of a
 *                                       stream, sec 1021: pieces received
 *                                       and lost since the call began, and
 *                                       the jitter of their transit in ms;
 *                                       LAST the AT of the newest piece it
 *                                       received and HELD the ms it held
 *                                       that before reporting (sec 1026)
 *     PARTICIPANT   INDEX 2 | WHOM 32         who a call of several numbers INDEX
 *                                       in its frames' FROM, sec 1024
 *
 * FROM, sec 1024: in a call of several the caller's host is the hub (sec
 * 1022) and numbers each participant from 1, in the order it rang them; 0 is the
 * caller. A participant's frame reaches the hub with any FROM, and the hub writes
 * the participant's number before keeping and passing it on, so a receiver can
 * tell two senders' numbering apart, and the hub says each participant's number
 * with a PARTICIPANT word to every other participant who has joined. A call of two is
 * the same with one participant: the callee's frames read as 1 at the caller, the
 * caller's as 0 at the callee.
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
#define FZN_LIVE_FRAME_HEAD_LEN (FZN_LIVE_HEAD_LEN + 1u + 2u + 4u + 4u + 2u + 2u)
#define FZN_LIVE_FRAME_FROM_AT (FZN_LIVE_HEAD_LEN + 1u)
#define FZN_LIVE_PARTICIPANT_LEN (FZN_LIVE_HEAD_LEN + 2u + FZN_PUBKEY_LEN)
/* The participants a call can number: FROM's room, less the caller's 0. */
#define FZN_LIVE_PARTICIPANTS_MAX 65535u
#define FZN_LIVE_REPORT_LEN (FZN_LIVE_HEAD_LEN + 1u + 4u + 4u + 2u + 4u + 4u)

#define FZN_LIVE_AUDIO 1u
#define FZN_LIVE_VIDEO 2u

/* HOW LONG A CALL RINGS unanswered, and is kept with no frame either way.
 * The RECEIVER'S to set, sec 1073: its `call/ring`, FZN_LIVE_RING_MIN_S to
 * FZN_LIVE_RING_MAX_S, FZN_LIVE_RING_S unset; the caller rings on while RINGING
 * comes, up to the most any receiver may set, and is told NO_ANSWER. */
#define FZN_LIVE_RING_S 45u
#define FZN_LIVE_RING_MIN_S 5u
#define FZN_LIVE_RING_MAX_S 600u
#define FZN_LIVE_IDLE_S 30u
/* RINGING IS A STATE BOTH ENDS KEEP CHECKING, sec 1062, the holder's: the caller
 * says RING each second and the callee answers each with RINGING; either end
 * hearing nothing of the other for FZN_LIVE_RING_SILENT_MS drops the call --
 * five rounds, so a lossy path does not drop a good one -- and a caller that has
 * heard no RINGING at all FZN_LIVE_RING_REACH_MS after ringing drops it as
 * unreachable, the time a session takes to stand, through a relay too. */
#define FZN_LIVE_RING_SILENT_MS 5000u
/* 45 s, sec 1080, a default ring's length: hull measured a callee behind a NAT
 * reached 14.6 to 27.4 s after the first ring, through an introduction,
 * and 15 s dropped every such call. */
#define FZN_LIVE_RING_REACH_MS 45000u

typedef enum fzn_live_kind {
	FZN_LIVE_RING = 1,
	FZN_LIVE_ANSWER = 2,
	FZN_LIVE_DECLINE = 3,
	FZN_LIVE_HANGUP = 4,
	FZN_LIVE_FRAME = 5,
	FZN_LIVE_REPORT = 6,
	FZN_LIVE_PARTICIPANT = 7,
	FZN_LIVE_RINGING = 8, /* the callee to each RING, sec 1062: still here, ringing */
	FZN_LIVE_NO_ANSWER = 9, /* the callee's ring time passed, sec 1073 */
	FZN_LIVE_BUSY = 10      /* the callee's guard refused the ring, sec 1074 */
} fzn_live_kind_t;

/* ONE WORD READ, pointing into the caller's bytes. */
typedef struct fzn_live_word {
	fzn_live_kind_t kind;
	uint8_t call[FZN_LIVE_CALL_LEN];
	/* RING; PARTICIPANT's WHOM too */
	uint8_t kinds;
	const uint8_t *whom;
	/* FRAME; PARTICIPANT's INDEX is `from` */
	uint8_t stream;
	uint16_t from;
	uint32_t seq, at_ms;
	uint16_t piece, pieces;
	const uint8_t *media;
	size_t media_len;
	/* REPORT, and STREAM above */
	uint32_t received, lost;
	uint16_t jitter_ms;
	/* THE ROUND TRIP, sec 1026, as RTCP takes it (RFC 3550, 6.4.1, LSR and
	 * DLSR): the sender, reading LAST back in its own clock, has the round
	 * trip as its now less LAST less HELD -- no clock of the receiver's in
	 * it, so no offset between the two is needed. */
	uint32_t last_at_ms, held_ms;
} fzn_live_word_t;

/* WHAT A RECEIVER MEASURES OF ONE STREAM, sec 1021. Pieces counted by number:
 * a gap past the highest seen is lost until a late one fills it. Jitter as RTP
 * keeps it (RFC 3550, 6.4.1): the mean of the change in transit, arrival less
 * capture, a sixteenth at a time -- in the receiver's ms against the sender's,
 * the clocks' offset cancelling in the change. */
typedef struct fzn_live_stats {
	uint32_t received, lost;
	uint32_t highest;
	int64_t last_transit;
	uint32_t jitter16; /* jitter in ms, times 16 */
	/* THE NEWEST PIECE'S AT, and when it arrived here, sec 1026. */
	uint32_t last_at;
	uint64_t last_arrival_ms;
	uint8_t started;
} fzn_live_stats_t;

/* PIECE `seq` of a frame captured at `at_ms`, arrived at `now_ms`, counted. */
void fzn_live_count(fzn_live_stats_t *st, uint32_t seq, uint32_t at_ms, uint64_t now_ms);

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
	/* HOW LONG IT RINGS here, seconds, sec 1073; 0 for FZN_LIVE_RING_S. */
	uint32_t ring_s;
	/* RINGING CHECKED, sec 1062: when the other end was last heard ringing, ms --
	 * a RING at the callee, a RINGING at the caller -- 0 for never; and whether
	 * this call is held to it, a call this host rang or was rung on itself. */
	uint64_t heard_ms, since_ms;
	uint8_t checked;
	uint8_t used;
} fzn_live_call_t;

/* CALLS ENDED that a late word may still name: a ring is said again until it is
 * answered (sec 1039), and one said again past a decline must not open the call a
 * second time. The newest kept, the oldest forgotten. */
#define FZN_LIVE_ENDED 32u

typedef struct fzn_live_calls {
	fzn_live_call_t *rows;
	size_t cap, n;
	uint8_t ended[FZN_LIVE_ENDED][FZN_LIVE_CALL_LEN];
	size_t ended_next;
} fzn_live_calls_t;

/* `call`'S ROW, or NULL. */
fzn_live_call_t *fzn_live_find(fzn_live_calls_t *t, const uint8_t call[FZN_LIVE_CALL_LEN]);

/* A ROW FOR `call`, new or the one held, grown as needed; NULL with no memory,
 * or for a call among the last FZN_LIVE_ENDED ended here. */
fzn_live_call_t *fzn_live_open(fzn_live_calls_t *t, const uint8_t call[FZN_LIVE_CALL_LEN]);

/* `c` ENDED, its row free, its id kept among the ended. */
void fzn_live_end(fzn_live_calls_t *t, fzn_live_call_t *c);

/* ROWS PAST THEIR TIME at `now_s` ended -- ringing past its ring_s, or up
 * and heard of by neither end for FZN_LIVE_IDLE_S -- each told to `gone`
 * first; how many. */
size_t fzn_live_expire(fzn_live_calls_t *t, uint64_t now_s,
                       void (*gone)(void *ctx, const fzn_live_call_t *c), void *ctx);

void fzn_live_release(fzn_live_calls_t *t);

#endif /* FZN_NODE_LIVE_H */
