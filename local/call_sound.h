/*
 * A CALL'S SOUND, through the node, for any front end: fuzznet sec 1235,
 * step 2 of taking a call's media into fuzznet (sec 1234). What
 * fuzzypickles' call_audio did each 20 ms, without its devices: what the
 * microphone gave goes out as mu-law frames (`add frame`), what arrived is
 * read (`list frame`) into the jitter buffer, a frame is played, and once a
 * second the other end's report of this one's sound is read (`get call ID
 * quality`). A Qt window drives it with QAudioSource and QAudioSink
 * (gui/call_audio.h); a terminal or a phone's own audio API can drive it
 * the same way.
 *
 * 8 kHz mono, 16-bit samples, a frame 160 of them. Stream 0, mu-law --
 * what every build reads, so a call with fuzzypickles' window sounds both
 * ways. Nothing here reads a clock: every call takes `now_ms`.
 */
#ifndef FZN_LOCAL_CALL_SOUND_H
#define FZN_LOCAL_CALL_SOUND_H

#include <stddef.h>
#include <stdint.h>

#include "rpc.h"
#include "rpc_err.h"
#include "../media/jitter.h"
#include "../media/ulaw.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fzn_call_sound {
	char id[FZN_RPC_ID_HEX + 1];
	uint32_t seq;        /* the next frame sent */
	uint64_t from;       /* where the node's frames are read from next */
	uint64_t started_ms; /* a frame's AT counts from here */
	fzn_jitter_t jitter;
	int16_t pending[FZN_ULAW_FRAME_SAMPLES];
	size_t pending_n;
	int muted;
	/* As the other end last reported this one's sound: `have` 0 until it
	 * has. The round trip is -1 where this end's clock cannot say. */
	int have_quality;
	unsigned loss_pct;
	long trip_ms;
} fzn_call_sound_t;

/* Carry call `id` (FZN_RPC_ID_HEX hex digits) from `now_ms`: 0, or -1 for
 * an id of the wrong shape. */
int fzn_call_sound_start(fzn_call_sound_t *s, const char *id, uint64_t now_ms);

/* SAMPLES CAPTURED, 8 kHz mono: every whole frame they make goes out --
 * silence in its place while muted, so the other end's reports go on. The
 * frames sent, or a negative FZN_RPC_ code when the node would not take one
 * (the call gone, as a rule). */
int fzn_call_sound_send(fzn_call_sound_t *s, fzn_rpc_t *c, const int16_t *pcm, size_t n,
                        uint64_t now_ms);

/* WHAT ARRIVED, read into the jitter buffer: a few reads at most. The
 * frames taken, or a negative FZN_RPC_ code. */
int fzn_call_sound_receive(fzn_call_sound_t *s, fzn_rpc_t *c);

/* THE NEXT 20 MS TO PLAY into `out`: 1, silence for a frame that did not
 * come; 0 while buffering, `out` untouched. */
int fzn_call_sound_play(fzn_call_sound_t *s, int16_t out[FZN_ULAW_FRAME_SAMPLES]);

/* HOW THIS END IS HEARD, read from the node: 1 with `have_quality` and the
 * rest set, 0 when the other end has not reported yet, or a negative
 * FZN_RPC_ code. */
int fzn_call_sound_quality(fzn_call_sound_t *s, fzn_rpc_t *c, uint64_t now_ms);

#ifdef __cplusplus
}
#endif

#endif /* FZN_LOCAL_CALL_SOUND_H */
