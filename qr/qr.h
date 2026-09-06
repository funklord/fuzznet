/*
 * A QR code, as modules a caller draws.
 *
 * project.md sec 160. sec 71 built `provision/`: a signed card and
 * `fzn_provision_text`, "the STRING a code carries", and it stopped there --
 * "no encoder, no decoder, no bitmap, no camera... turning a string into a
 * photograph is a barcode library's job". The copyright holder approved that
 * scoping at the time and has now asked for the generator, which reverses it.
 * The reversal is theirs; this is what it costs and what makes it safe.
 *
 * IT PRODUCES MODULES AND NOT AN IMAGE. A caller gets a square of bytes, one
 * per module, 0 or 1, and draws them however it draws things -- a Qt widget
 * paints rectangles, a terminal prints two half-blocks a row, a printer
 * scales. Deciding what a pixel is belongs to whoever has the screen, and
 * `gui/` and `cli/` disagree about that by construction.
 *
 * NO ALLOCATION, LIKE EVERYTHING HERE. The caller owns the module array and
 * says how big it is; a code that will not fit is refused rather than
 * truncated, since half a QR code scans as nothing at all.
 *
 * WHY IT IS WRITTEN RATHER THAN VENDORED, which is a real question given
 * `harmonization.md` prefers vendoring what you consume. Three reasons, and
 * the first is the weakest:
 *
 *   - This library vendors exactly one thing, and adding a second brings
 *     somebody else's terms into a tree whose licensing the holder has not
 *     settled. `CLAUDE.md` forbids deciding that, so the cheap path is the
 *     one that does not raise it.
 *   - A vendored encoder allocates. Every one worth having calls `malloc`,
 *     and this library's whole shape is caller-owned tables -- so it would be
 *     the only part of fuzznet a consumer could not use from a fixed arena.
 *   - The payload is known and small. `fzn_provision_text` is 682 characters
 *     of base32 and a `FZN1:` prefix, all of which is in QR's ALPHANUMERIC
 *     set, so the versions and modes this needs are a fraction of the
 *     standard.
 *
 * AND THE TABLES BELOW ARE THE RISK, WHICH IS WHY THE CHECK IS WHAT IT IS.
 * A block-count or error-correction figure written from memory is
 * `evidence.md`'s invented value: every run agrees with itself, because the
 * encoder and the test would be one witness. So `make qrcheck` decodes what
 * this produces with QUIRC -- an independent decoder, vendored by
 * fuzzypickles -- across every version and level this supports. A wrong table
 * entry is a decode failure there and nothing in the suite here.
 */

#ifndef FZN_QR_H
#define FZN_QR_H

#include <stddef.h>
#include <stdint.h>

/*
 * The largest version this encodes.
 *
 * FIFTEEN, AND THE CARD NEEDS ALL OF IT. `fzn_provision_text` is 682
 * alphanumeric characters, which is version 15 at level L exactly -- 523 data
 * codewords against the 471 the payload needs, and version 14 does not hold
 * it.
 *
 * THIS COMMENT FIRST SAID ELEVEN, AND THAT WAS A RECALLED FIGURE. It claimed
 * the card fit version 11 at L and 13 at M, and both halves were wrong: the
 * capacity implied by the tables below -- the ones an independent decoder has
 * since agreed with -- gives version 11 at L about 468 alphanumeric
 * characters, not 772. Nothing measured it until the card was encoded.
 *
 * SO LEVEL L IS THE ONLY LEVEL THE CARD FITS, and that is a real limit rather
 * than a preference: at M the largest version here holds 415 data codewords
 * against the card's 471. A consumer that wants the card at M or better needs
 * versions past 15, which is more table and no new code -- and the sweep in
 * `make qrcheck` would adjudicate the additions the same way it adjudicated
 * these. Shorter payloads have every level available.
 */
#define FZN_QR_VERSION_MAX 15u

/* Modules across a version-15 code: 17 + 4 * 15. A caller sizing for the
 * largest needs this squared. */
#define FZN_QR_SIZE_MAX (17u + 4u * FZN_QR_VERSION_MAX)
#define FZN_QR_MODULES_MAX (FZN_QR_SIZE_MAX * FZN_QR_SIZE_MAX)

/*
 * How much of the code is redundancy.
 *
 * NOT DEFAULTED, because the right answer depends on where the code will be
 * read. A card on a screen wants L and every byte of capacity; one printed on
 * a label that will be handled wants Q or H. The library has no way to know
 * which, and a default here would be a guess applied to somebody's
 * provisioning.
 */
typedef enum fzn_qr_level {
	FZN_QR_LEVEL_L = 0,
	FZN_QR_LEVEL_M = 1,
	FZN_QR_LEVEL_Q = 2,
	FZN_QR_LEVEL_H = 3,
} fzn_qr_level_t;

typedef enum fzn_qr_err {
	FZN_QR_OK = 0,
	FZN_QR_ERR_MALFORMED = -1,
	/* The payload does not fit any version up to FZN_QR_VERSION_MAX at the
	 * level asked for. A caller may retry at a weaker level, which is a
	 * decision rather than something to do on its behalf. */
	FZN_QR_ERR_TOO_LONG = -2,
	/* The caller's module array is smaller than the code needs. `size` is
	 * still written, so a caller can size and retry. */
	FZN_QR_ERR_FULL = -3,
} fzn_qr_err_t;

const char *fzn_qr_err_str(fzn_qr_err_t err);

/*
 * Encode `text` into modules.
 *
 * `out` receives `size * size` bytes, each 0 or 1, row-major from the top
 * left. `size_out` receives `size` and is written even when the answer is
 * FZN_QR_ERR_FULL, so a caller can ask how big and then ask again.
 *
 * NO QUIET ZONE IS INCLUDED, and that is the caller's to add. The standard
 * asks for four modules of background on every side; a widget adds it as
 * margin and a terminal as blank cells, and a library that baked it in would
 * make both of them strip it. `FZN_QR_QUIET` is what to add if you have no
 * opinion.
 *
 * THE MODE IS CHOSEN, NOT ASKED FOR. Text that is entirely in QR's
 * alphanumeric set -- digits, capitals, and ` $%*+-./:` -- is packed at 5.5
 * bits a character; anything else goes as bytes at 8. `fzn_provision_text`
 * is base32 and a prefix, so it takes the narrow path and the card fits a
 * smaller code than it looks like it should.
 */
#define FZN_QR_QUIET 4u

fzn_qr_err_t fzn_qr_encode(const char *text, size_t text_len, fzn_qr_level_t level,
                           uint8_t *out, size_t out_cap, size_t *size_out);

/* The smallest version that would hold `text_len` characters at `level`, or
 * zero when none up to FZN_QR_VERSION_MAX would. Exposed so a caller can size
 * a buffer, and because a consumer choosing a level wants to see what each
 * one costs before choosing. */
unsigned fzn_qr_version_for(const char *text, size_t text_len, fzn_qr_level_t level);

#endif /* FZN_QR_H */
