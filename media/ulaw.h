/*
 * G.711 mu-law, as ITU-T G.711 and every telephone have it: a call's sound
 * at 8 kHz, one byte a sample, a 20 ms frame 160 bytes. fuzznet sec 1234,
 * moved from fuzzypickles' gui/src/call_audio.cpp so that every front end
 * carrying a call has it, not only one Qt window.
 *
 * What a call falls back to: a few lines and no library, where Opus needs
 * one. Pure integer arithmetic; links alone.
 */
#ifndef FZN_MEDIA_ULAW_H
#define FZN_MEDIA_ULAW_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A call's rate and frame: 8000 samples a second, 160 a frame (20 ms). */
#define FZN_ULAW_RATE 8000u
#define FZN_ULAW_FRAME_SAMPLES 160u

uint8_t fzn_ulaw_encode(int16_t sample);
int16_t fzn_ulaw_decode(uint8_t byte);

/* `n` samples each way, `out` holding `n`. */
void fzn_ulaw_encode_frame(const int16_t *pcm, size_t n, uint8_t *out);
void fzn_ulaw_decode_frame(const uint8_t *in, size_t n, int16_t *pcm);

#ifdef __cplusplus
}
#endif

#endif /* FZN_MEDIA_ULAW_H */
