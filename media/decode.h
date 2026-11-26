/*
 * A FILE'S SOUND, decoded for media/analysis.h: project.md sec 1457.
 *
 * Through FFmpeg where the build has it (FZN_MEDIA_DECODE_ON, libavformat,
 * libavcodec, libavutil and libswresample by pkg-config), as gui/call_opus
 * takes its codec: every format FFmpeg opens -- MP3, FLAC, Ogg, M4A, a
 * video's sound -- its first audio stream, resampled to stereo float at
 * FZN_MEDIA_ANALYSIS_RATE. Elsewhere every call answers
 * FZN_MEDIA_DECODE_NONE, so a host links this file either way. The
 * interface names nothing of FFmpeg's.
 *
 * The bytes are anybody's: FFmpeg's demuxers and decoders are what reads
 * them, so a host decodes only what its own user stored into its library.
 */
#ifndef FZN_MEDIA_DECODE_H
#define FZN_MEDIA_DECODE_H

#include <stddef.h>

typedef enum fzn_media_decode_result {
	FZN_MEDIA_DECODE_OK = 0,     /* decoded to the end, or as far as it would */
	FZN_MEDIA_DECODE_NONE = 1,   /* this build has no decoder */
	FZN_MEDIA_DECODE_NO_SOUND = 2, /* it would not open, or holds no sound */
	FZN_MEDIA_DECODE_STOPPED = 3 /* `stop` was set, or `frames` returned 0 */
} fzn_media_decode_result_t;

/* `frames` stereo frames, interleaved, handed on: nonzero to go on. */
typedef int (*fzn_media_frames_t)(void *ctx, const float *stereo, size_t frames);

/* The file at `path`, its first audio stream, at most `max_seconds` of it
 * (0 for all), handed to `frames` as it decodes. `stop`, where not NULL, is
 * read between packets. */
fzn_media_decode_result_t fzn_media_decode(const char *path, double max_seconds, fzn_media_frames_t frames,
                                           void *ctx, const volatile int *stop);

/* Whether this build decodes at all. */
int fzn_media_decode_available(void);

#endif
