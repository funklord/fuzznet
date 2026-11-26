/*
 * WHICH RECORDING A TUNE IS, project.md sec 1459: its acoustic fingerprint,
 * Chromaprint's, which AcoustID and MusicBrainz identify recordings by --
 * through FFmpeg's own chromaprint muxer, as snurra takes it (its
 * src/fingerprint.cpp), so no library is linked that FFmpeg did not bring.
 *
 * FED AS IT DECODES: stereo float frames at FZN_MEDIA_ANALYSIS_RATE, the
 * same pieces media/analysis.h is fed, up to FZN_MEDIA_PRINT_SECONDS of
 * them, as AcoustID's own fpcalc takes; Chromaprint brings them to its own
 * 11025 Hz. Where the build has no FFmpeg, or FFmpeg no Chromaprint,
 * `fzn_media_print_open` gives NULL and nothing is printed.
 *
 * AND ASKED OF ACOUSTID (fzn_media_acoustid_lookup): the fingerprint and the
 * tune's length, and nothing else, with the client key its user registered
 * at acoustid.org -- never without one, so nothing is sent unasked -- over
 * FFmpeg's https, the certificate checked. The answer's best result: the
 * AcoustID and the first MusicBrainz recording it names, with that
 * recording's title and artists (sec 1463), UTF-8 with no control
 * character, cut at a character's edge.
 */
#ifndef FZN_MEDIA_FINGERPRINT_H
#define FZN_MEDIA_FINGERPRINT_H

#include <stddef.h>
#include <stdint.h>

#define FZN_MEDIA_PRINT_SECONDS 120u
#define FZN_MEDIA_ID_MAX 36u /* a UUID's text */
#define FZN_MEDIA_NAME_MAX 255u /* a catalogue value's most */

typedef struct fzn_media_print fzn_media_print_t;

/* NULL where this build cannot print. `raw` 1 for Chromaprint's 32-bit
 * sub-fingerprints (for comparing two here), 0 for the compressed base64
 * AcoustID takes. */
fzn_media_print_t *fzn_media_print_open(int raw);
/* `frames` stereo frames, as media/analysis.h takes them: past
 * FZN_MEDIA_PRINT_SECONDS, taken and not printed. 0 where the muxer failed. */
int fzn_media_print_add(fzn_media_print_t *p, const float *stereo, size_t frames);
/* The fingerprint, into `out` of `cap` bytes: its length, 0 where there is
 * none or it does not fit. Frees `p` either way. */
size_t fzn_media_print_finish(fzn_media_print_t *p, uint8_t *out, size_t cap);
void fzn_media_print_free(fzn_media_print_t *p);

/* How unlike two raw fingerprints are, `a_n` and `b_n` sub-fingerprints: the
 * share of bits that differ, 0 to 1, at the best alignment within `shift`
 * either way over at least `least` overlapping -- two encodings of one
 * recording well under 0.2, unrelated sound near 0.5. 1 where they do not
 * overlap enough to say. snurra's measure. */
double fzn_media_print_distance(const uint32_t *a, size_t a_n, const uint32_t *b, size_t b_n, int shift, int least);

typedef struct fzn_media_identity {
	char acoustid[FZN_MEDIA_ID_MAX + 1u];  /* the AcoustID, empty for none */
	char recording[FZN_MEDIA_ID_MAX + 1u]; /* the MusicBrainz recording, empty for none */
	char title[FZN_MEDIA_NAME_MAX + 1u];   /* its title, empty for none */
	char artist[FZN_MEDIA_NAME_MAX + 1u];  /* its artists' names, joined by ", " */
	double score;                          /* 0 to 1 */
} fzn_media_identity_t;

typedef enum fzn_media_lookup_result {
	FZN_MEDIA_LOOKUP_FOUND = 0,
	FZN_MEDIA_LOOKUP_UNKNOWN = 1,  /* answered, and it knew no recording */
	FZN_MEDIA_LOOKUP_REFUSED = 2,  /* answered with an error: a bad key, say */
	FZN_MEDIA_LOOKUP_NO_ANSWER = 3, /* no answer, or one that did not read */
	FZN_MEDIA_LOOKUP_NONE = 4      /* no key, no fingerprint, or no FFmpeg */
} fzn_media_lookup_result_t;

/* Asks `url` -- AcoustID's v2 lookup, https://api.acoustid.org/v2/lookup --
 * who the base64 `print` of a tune `seconds` long is, as client `key`. */
fzn_media_lookup_result_t fzn_media_acoustid_lookup(const char *url, const char *key, const char *print,
                                                    unsigned seconds, fzn_media_identity_t *out);

/* The best result of an answer's JSON, as the lookup reads it: for a test. */
fzn_media_lookup_result_t fzn_media_acoustid_read(const char *json, size_t len, fzn_media_identity_t *out);

#endif
