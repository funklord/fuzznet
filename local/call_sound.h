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
 *
 * A BETTER CODEC WHERE THE FRONT END HAS ONE, sec 1254: given a codec
 * (`fzn_call_sound_codec`) -- Opus through FFmpeg, in gui/call_opus.h --
 * this end sends it on stream 1 at the codec's rate, and plays stream 1
 * while it arrives and stream 0 otherwise, mu-law repeated up to the
 * codec's rate. An end given a codec sends stream 1 alone, as
 * fuzzypickles' did since its 9a50512: two such ends hear each other at
 * 48 kHz; an end with no codec still sends mu-law, which one with a codec
 * plays; an end that reads stream 0 alone -- a build from before -- hears
 * nothing from one sending Opus, the price fuzzypickles took for a call
 * that sounds better than a telephone. The codec is the front end's, so
 * this library links no FFmpeg.
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

/* 20 MS AT 48 kHz, the most samples a frame of any codec holds here. */
#define FZN_CALL_SOUND_FRAME_MAX 960u
#define FZN_CALL_SOUND_ULAW_STREAM 0u
#define FZN_CALL_SOUND_CODED_STREAM 1u

/* A CODEC, the front end's: RATE in Hz, a whole multiple of 8000; FRAME the
 * samples in 20 ms at it, at most FZN_CALL_SOUND_FRAME_MAX. ENCODE takes one
 * frame's samples and writes a packet of at most `cap` -- FZN_RPC_FRAME_MAX,
 * what one `add frame` carries: its length, 0 for none this time, negative
 * for a failure. DECODE takes a packet -- NULL and 0 for one that
 * did not come, which a codec may conceal -- and writes samples: their
 * count, at most `cap`, or negative. */
typedef struct fzn_call_codec {
	void *ctx;
	unsigned rate;
	unsigned frame;
	int (*encode)(void *ctx, const int16_t *pcm, size_t n, uint8_t *packet, size_t cap);
	int (*decode)(void *ctx, const uint8_t *packet, size_t len, int16_t *pcm, size_t cap);
} fzn_call_codec_t;

typedef struct fzn_call_sound {
	char id[FZN_RPC_ID_HEX + 1];
	uint32_t seq;        /* the next frame sent */
	uint64_t from;       /* where the node's frames are read from next */
	uint64_t started_ms; /* a frame's AT counts from here */
	fzn_jitter_t jitter;
	int16_t pending[FZN_CALL_SOUND_FRAME_MAX];
	size_t pending_n;
	/* THE CODEC, NULL for mu-law alone, and what arrived on its stream. */
	const fzn_call_codec_t *codec;
	fzn_jitter_t coded;
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

/* A CODEC FOR THIS CALL, after start and before the first frame: 0, or -1
 * for one whose rate or frame this cannot carry. NULL goes back to mu-law.
 * The codec is not copied: it must outlive the call. */
int fzn_call_sound_codec(fzn_call_sound_t *s, const fzn_call_codec_t *codec);

/* WHAT THE DEVICES RUN AT: the codec's rate and frame, or 8000 and 160. */
unsigned fzn_call_sound_rate(const fzn_call_sound_t *s);
size_t fzn_call_sound_frame(const fzn_call_sound_t *s);

/* SAMPLES CAPTURED, at fzn_call_sound_rate, mono: every whole frame they make goes out --
 * silence in its place while muted, so the other end's reports go on. The
 * frames sent, or a negative FZN_RPC_ code when the node would not take one
 * (the call gone, as a rule). */
int fzn_call_sound_send(fzn_call_sound_t *s, fzn_rpc_t *c, const int16_t *pcm, size_t n,
                        uint64_t now_ms);

/* WHAT ARRIVED, read into the jitter buffer: a few reads at most. The
 * frames taken, or a negative FZN_RPC_ code. */
int fzn_call_sound_receive(fzn_call_sound_t *s, fzn_rpc_t *c);

/* THE NEXT 20 MS TO PLAY into `out`, fzn_call_sound_frame samples at
 * fzn_call_sound_rate -- `out` holds FZN_CALL_SOUND_FRAME_MAX where a codec
 * is given, FZN_ULAW_FRAME_SAMPLES otherwise: 1, silence for a frame that
 * did not come; 0 while buffering, `out` untouched. */
int fzn_call_sound_play(fzn_call_sound_t *s, int16_t *out);

/* HOW THIS END IS HEARD, read from the node: 1 with `have_quality` and the
 * rest set, 0 when the other end has not reported yet, or a negative
 * FZN_RPC_ code. */
int fzn_call_sound_quality(fzn_call_sound_t *s, fzn_rpc_t *c, uint64_t now_ms);

#ifdef __cplusplus
}
#endif

#endif /* FZN_LOCAL_CALL_SOUND_H */
