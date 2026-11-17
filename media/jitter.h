/*
 * A CALL'S FRAMES PUT BACK IN ORDER: fuzznet sec 1234, moved from
 * fuzzypickles' call_media, so every front end has the same jitter buffer
 * whatever codec it carries -- mu-law, Opus, a picture.
 *
 * Playing starts once FZN_JITTER_START frames are held (60 ms of 20 ms
 * frames); after that each pull is the next frame in sequence, or a gap
 * where it did not come, counted lost rather than waited for: a frame late
 * is a frame lost (sec 1017). Past FZN_JITTER_CATCH_UP held it skips ahead
 * to the newest FZN_JITTER_START, so a stall does not become a lasting
 * delay.
 *
 * SEQUENCE NUMBERS COMPARED SERIALLY, so a call that runs past 2^32 frames
 * keeps its order, where fuzzypickles' ordered map put frame 0 before frame
 * 2^32 - 1. Fixed size, nothing allocated.
 */
#ifndef FZN_MEDIA_JITTER_H
#define FZN_MEDIA_JITTER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FZN_JITTER_SLOTS 16u
#define FZN_JITTER_FRAME_MAX 512u
#define FZN_JITTER_START 3u
#define FZN_JITTER_CATCH_UP 10u

typedef struct fzn_jitter_slot {
	uint32_t seq;
	uint16_t len;
	uint8_t used;
	uint8_t frame[FZN_JITTER_FRAME_MAX];
} fzn_jitter_slot_t;

typedef struct fzn_jitter {
	/* ENTRIES, not `slots`: Qt defines `slots` as a macro, and a Qt front
	 * end includes this (as node/asks.h found). */
	fzn_jitter_slot_t entries[FZN_JITTER_SLOTS];
	uint32_t next;
	int playing;
	uint64_t lost;
} fzn_jitter_t;

void fzn_jitter_init(fzn_jitter_t *j);

/* A FRAME ARRIVED, by its sequence number: 1 kept, 0 not -- one already
 * played past, or longer than FZN_JITTER_FRAME_MAX. */
int fzn_jitter_take(fzn_jitter_t *j, uint32_t seq, const uint8_t *frame, size_t len);

/* THE NEXT FRAME TO PLAY: 0 while buffering; 1 with the frame in `frame`
 * and `*len` its length, or with `*len` 0 for one that did not come. */
int fzn_jitter_pull(fzn_jitter_t *j, uint8_t *frame, size_t cap, size_t *len);

/* Frames held now, and frames counted lost since init. */
size_t fzn_jitter_held(const fzn_jitter_t *j);
uint64_t fzn_jitter_lost(const fzn_jitter_t *j);

#ifdef __cplusplus
}
#endif

#endif /* FZN_MEDIA_JITTER_H */
