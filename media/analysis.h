/*
 * WHAT A TUNE SOUNDS LIKE, project.md sec 1457: its tempo and first beat,
 * its key and its loudness, found from its sound -- what no tag says, or
 * says wrongly, and what a catalogue sorts and searches music by (the
 * holder, 2026-11-26: "the music catalog is about finding all these values
 * and storing the metadata for sorting and searching").
 *
 * snurra's own detector (its src/beats.cpp, analysis 5), carried here into
 * C so the host holding a file finds them once for the whole estate:
 *
 * - THE BEAT: onsets as spectral flux -- how much each frequency's log
 *   magnitude rose from one hop of 512 frames to the next -- then the
 *   tempo from their autocorrelation, weighted toward 120 BPM, between 70
 *   and 180; then the period and phase that fit the whole tune best, by
 *   folding every onset at each candidate period; a dotted pulse and a
 *   half tempo told apart by the low end; a long set judged a minute at a
 *   time where its whole is not clear. A tune whose fold shows no clear
 *   peak has no beat.
 * - THE KEY: a chromagram from G2 to C7, each block weighed by its own
 *   loudest note, correlated with Krumhansl and Kessler's profiles at all
 *   24 keys; none where the best fit is weak (noise, a drum loop).
 * - THE LOUDNESS: ITU-R BS.1770-4 integrated as EBU R128 gates it, in
 *   LUFS, and the highest sample.
 *
 * FED AS IT DECODES: stereo float frames at FZN_MEDIA_ANALYSIS_RATE, in
 * any pieces; memory grows by a few bytes a hop (about 400 KiB an hour).
 */
#ifndef FZN_MEDIA_ANALYSIS_H
#define FZN_MEDIA_ANALYSIS_H

#include <stddef.h>

/* The rate the thresholds were measured at, snurra's. */
#define FZN_MEDIA_ANALYSIS_RATE 48000u

typedef struct fzn_media_sound {
	double bpm;        /* beats a minute; 0: no beat found */
	double first;      /* the first beat, in seconds from the start */
	double confidence; /* the fold's peak over its mean: 1 is none, 6 clear */
	int key;           /* 0 to 11 C to B major, 12 to 23 C to B minor, -1 none */
	double key_fit;    /* the profile's correlation */
	int loudness_known;
	double loudness;   /* LUFS, integrated */
	double peak;       /* the highest sample, 0 to 1 or over */
	double seconds;    /* how much sound was heard */
} fzn_media_sound_t;

typedef struct fzn_media_analysis fzn_media_analysis_t;

/* NULL where memory is short. */
fzn_media_analysis_t *fzn_media_analysis_open(void);
/* `frames` stereo frames, left and right interleaved: 0 where memory ran
 * short, and the analysis is then of what came before. */
int fzn_media_analysis_add(fzn_media_analysis_t *a, const float *stereo, size_t frames);
/* What was heard, into `out`; `stop`, where not NULL, read between the
 * passes, and nonzero gives up (0 returned). Frees `a` either way. */
int fzn_media_analysis_finish(fzn_media_analysis_t *a, fzn_media_sound_t *out, const volatile int *stop);
void fzn_media_analysis_free(fzn_media_analysis_t *a);

/* A key as a DJ reads it: its Camelot number and letter, then its name --
 * "8A Am", "2B Gb". The length written, 0 for none (-1, or no room). */
size_t fzn_media_key_name(int key, char *out, size_t cap);
/* Where a key sorts: by its Camelot number, A before B; none last. And a
 * key read back from its name -- "8A Am", or "8A" alone -- -1 for none. */
int fzn_media_key_order(int key);
int fzn_media_key_parse(const char *name, size_t len);

#endif
