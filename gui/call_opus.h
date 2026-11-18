/*
 * Opus for a call's sound, through FFmpeg: fuzznet sec 1254, moved from
 * fuzzypickles' call_opus (its 9a50512). 48 kHz mono, 24 kbit/s, a packet
 * each 20 ms -- 60 to 90 bytes, inside one `add frame` and smaller than
 * mu-law's 160 -- handed to `local/call_sound.h` as its codec, so a call
 * sounds better than a telephone.
 *
 * libopus where the build's FFmpeg has it; FFmpeg's own encoder otherwise,
 * which is marked experimental and is what Qt's Android kit carries -- held
 * to one 20 ms frame of delay, where its default of 360 ms was a third of a
 * second of every call's lag in fuzzypickles' measurement.
 *
 * BUILT WHERE FFmpeg IS (FZN_OPUS_ON, libavcodec and libavutil by
 * pkg-config); elsewhere `fzn_call_opus_open` gives NULL and a call carries
 * mu-law, so a host compiles and links this file either way. The interface
 * names nothing of FFmpeg's.
 */
#ifndef FZN_GUI_CALL_OPUS_H
#define FZN_GUI_CALL_OPUS_H

#include "../local/call_sound.h"

/* 48 kHz, and 20 ms of it. */
#define FZN_CALL_OPUS_RATE 48000u
#define FZN_CALL_OPUS_FRAME 960u

struct fzn_call_opus;

/* An encoder and a decoder, opened: `encoder` names FFmpeg's encoder to use,
 * NULL for libopus where there is one and FFmpeg's own otherwise. NULL where
 * the build has no FFmpeg, or neither opens. */
struct fzn_call_opus *fzn_call_opus_open(const char *encoder);
void fzn_call_opus_close(struct fzn_call_opus *o);

/* THE CODEC to give `fzn_call_sound_codec`, living as long as `o`. */
const fzn_call_codec_t *fzn_call_opus_codec(struct fzn_call_opus *o);

/* Which encoder opened, for a log line: `libopus` or `opus`. */
const char *fzn_call_opus_encoder(const struct fzn_call_opus *o);

#endif /* FZN_GUI_CALL_OPUS_H */
