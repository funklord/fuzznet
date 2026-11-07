/*
 * A BEARER: whatever carries a sealed frame when UDP does not, project.md sec
 * 912. A radio with no IP on it, a serial line, a board's own link. The
 * holder's, 2026-11-06: an embedded host "has communication, possibly not via
 * ethernet at all. Could be LoRa".
 *
 * WHAT ONE IS: a way to send and to hear a UNIT, a run of at most `unit` bytes
 * that arrives whole or not at all. Nothing here says who hears it: a radio
 * has no addresses, so everyone in range does, and a frame that is not theirs
 * does not open. So a bearer needs no keys and trusts nothing it carries,
 * as a relay does not (sec 3).
 *
 * WHAT THIS ADDS is only size. A sealed frame is 144 bytes before its payload
 * (`FZN_SEAL_OVERHEAD`) and a LoRa unit may be 51, so a frame goes as PIECES,
 * each a unit, and comes back whole only when every piece has come. A piece
 * lost loses the frame, and the asker's resend is what recovers it: nothing
 * here keeps or repeats anything.
 *
 *     piece   link id (2, big-endian) | index (1) | count (1) | bytes
 *
 * The link id is the sender's own number for this frame, so that two senders'
 * pieces in the air at once are not joined. Two that collide make a frame that
 * does not open, which costs that frame and nothing else. BOTH ENDS OF A LINK
 * ARE GIVEN ITS UNIT: a piece's place is its index times the unit, and that is
 * a fact of the link rather than of a frame.
 *
 * NO ALLOCATION, NO POSIX, NO CLOCK: this builds for a board. The slots are
 * the caller's, and how many says how many senders may be part way at once. A
 * device, which hears one bridge, wants one; a bridge wants one for each
 * device that may talk over another.
 *
 * ALSO HERE, SLIP (RFC 1055), for a bearer that is a byte stream: a UART, or a
 * pipe in a test. It marks where a unit ends, as a stream does not.
 */
#ifndef FZN_NET_BEARER_H
#define FZN_NET_BEARER_H

#include <stddef.h>
#include <stdint.h>

#define FZN_BEARER_HEAD_LEN 4u
/* A SMALLER UNIT THAN THIS is a bound of a kind no frame could cross: at 8
 * bytes a piece, 255 pieces hold 2040, past the largest frame. */
#define FZN_BEARER_UNIT_MIN (FZN_BEARER_HEAD_LEN + 8u)
#define FZN_BEARER_UNIT_MAX 1200u
/* The largest frame there is, `SITU_FZN_FRAME_SIZE_MAX`, which bearer_test
 * pins. */
#define FZN_BEARER_FRAME_MAX 1168u
/* A SEEN-MAP for the most pieces a frame can be: 1168 over the 8-byte least. */
#define FZN_BEARER_PIECES_MAX 146u

typedef struct fzn_bearer {
	void *ctx;
	size_t unit; /* the most one send carries, FZN_BEARER_UNIT_MIN and up */
	/* A FRAME GOES WHOLE, as a datagram does: no pieces and no head, so a host
	 * on UDP speaks to a host's port with nothing between (sec 935). */
	int whole;
	/* ONE UNIT SENT. 0 when it could not go. */
	int (*send)(void *ctx, const uint8_t *bytes, size_t len);
	/* ONE UNIT HEARD, within `wait_ms`, into `out`: its length, 0 for none. */
	size_t (*recv)(void *ctx, uint8_t *out, size_t cap, unsigned wait_ms);
} fzn_bearer_t;

/* ONE SENDER'S FRAME, part way. */
typedef struct fzn_bearer_slot {
	uint16_t id;
	uint8_t count; /* 0: this slot is free */
	uint8_t got;
	uint32_t age; /* the join's counter when this began */
	size_t len;   /* known once the last piece came */
	uint8_t seen[(FZN_BEARER_PIECES_MAX + 7u) / 8u];
	uint8_t bytes[FZN_BEARER_FRAME_MAX];
} fzn_bearer_slot_t;

typedef struct fzn_bearer_join {
	fzn_bearer_slot_t *held; /* the caller's */
	size_t n_held;
	size_t unit;
	uint32_t age;
} fzn_bearer_join_t;

/* The pieces a frame of `len` goes as over `unit`, 0 for one that cannot go. */
size_t fzn_bearer_pieces(size_t len, size_t unit);

/* `frame` SENT as pieces under `id`. 1, or 0 for one that could not go. */
int fzn_bearer_send(const fzn_bearer_t *b, uint16_t id, const uint8_t *frame, size_t len);

/* ONE UNIT HEARD: 0 while its frame is incomplete, or for a unit that is no
 * piece; the frame's length, with `*frame` at its bytes, when it completes.
 * Those bytes are the slot's, good until the next call. A new frame with no
 * slot free takes the oldest's. Nothing here is trusted: a piece past its
 * frame, or disagreeing with what came before it, is dropped, and a frame
 * joined from strangers' pieces does not open. */
size_t fzn_bearer_take(fzn_bearer_join_t *j, const uint8_t *unit, size_t len,
                       const uint8_t **frame);

/* ---- SLIP ---------------------------------------------------------------- */

#define FZN_SLIP_END 0xc0u
#define FZN_SLIP_ESC 0xdbu
#define FZN_SLIP_ESC_END 0xdcu
#define FZN_SLIP_ESC_ESC 0xddu

/* `in` as one SLIP packet into `out`: its length, 0 when it does not fit.
 * 2 * `len` + 2 always does. */
size_t fzn_slip_encode(const uint8_t *in, size_t len, uint8_t *out, size_t cap);

typedef struct fzn_slip_reader {
	uint8_t *buffer; /* the caller's */
	size_t cap;
	size_t len;
	int escaped;
	int overrun;
} fzn_slip_reader_t;

/* ONE BYTE of the stream: a packet's length when `byte` ended one, with its
 * bytes in `buffer`, and 0 otherwise. One past `cap`, or an escape that is no
 * escape, loses that packet and no other. */
size_t fzn_slip_feed(fzn_slip_reader_t *r, uint8_t byte);

#endif /* FZN_NET_BEARER_H */
