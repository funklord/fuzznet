#ifndef FZN_RPC_MEDIA_H
#define FZN_RPC_MEDIA_H

/*
 * A CALL'S MEDIA ON A HELD CHANNEL, fuzznet sec 1113: the typed client's half.
 *
 * A client opens one channel for a call and keeps it: each frame it sends is
 * a WHOLE frame -- a video frame of a few KB -- which the node splits into the
 * pieces a session carries and the far node joins again, and each frame it
 * receives comes whole the same way. No hex, no request a piece, no polling
 * of `list frame`: what fuzzypickles asked for video calls (inbox 1000Z),
 * where `add frame` cost a small video call about 105 requests a second.
 *
 * Non-blocking once open: `fzn_rpc_media_fd` is the descriptor to poll, and
 * `fzn_rpc_media_recv` hands back what has arrived without waiting. A frame
 * late is worth nothing, so a channel the client stops reading is closed by
 * the node rather than buffered; open another.
 */

#include <stddef.h>
#include <stdint.h>

#include "rpc.h"
#include "vocabulary.h"

/* The most a whole frame carries: node/live.h's FZN_LIVE_MEDIA_MAX. */
#define FZN_RPC_MEDIA_MAX 8160u

typedef struct fzn_rpc_media {
	int fd;
	uint8_t call[8];
	size_t in_len;
	size_t handed; /* the frame handed out last, dropped at the next receive */
	uint8_t in[2u + FZN_LOCAL_BINARY_MAX];
} fzn_rpc_media_t;

/* ONE WHOLE FRAME RECEIVED: `media` points into the channel's buffer and
 * holds until the next receive. `from` is the sender's number in a call of
 * several (sec 1024), 0 for the other end of a call of two. */
typedef struct fzn_rpc_media_frame {
	uint8_t stream; /* 1 audio, 2 video */
	uint16_t from;
	uint32_t seq, at_ms;
	const uint8_t *media;
	size_t media_len;
} fzn_rpc_media_frame_t;

/* OPEN a channel for the call `call_hex` (16 hex, `list call`'s id) on the
 * node `c` names. FZN_RPC_OK, `m` then open; otherwise the failure's code with
 * `c->error` saying why -- the node's words for a call it does not hold. */
int fzn_rpc_media_open(fzn_rpc_t *c, const char *call_hex, fzn_rpc_media_t *m);

/* THE SAME on a connection the caller made: asks for the channel on `fd` and
 * reads the node's answer. For a host with its own way to the socket, and
 * for a test. FZN_RPC_OK, or the failure with `c->error` (c may be NULL). */
int fzn_rpc_media_attach(fzn_rpc_t *c, fzn_rpc_media_t *m, int fd, const uint8_t call[8]);

int fzn_rpc_media_fd(const fzn_rpc_media_t *m);

/* SEND one whole frame on stream 1 (audio) or 2 (video). FZN_RPC_OK, or
 * FZN_RPC_ERR_MALFORMED past FZN_RPC_MEDIA_MAX, FZN_RPC_ERR_SEND_FAILED when
 * the channel is gone or full. */
int fzn_rpc_media_send(fzn_rpc_media_t *m, uint8_t stream, uint32_t seq, uint32_t at_ms,
                       const uint8_t *media, size_t len);

/* RECEIVE without waiting: 1 a whole frame in `*out`, 0 none yet, and
 * FZN_RPC_ERR_SEND_FAILED when the channel closed (the call ended, or the
 * node let it go). */
int fzn_rpc_media_recv(fzn_rpc_media_t *m, fzn_rpc_media_frame_t *out);

void fzn_rpc_media_close(fzn_rpc_media_t *m);

#endif /* FZN_RPC_MEDIA_H */
