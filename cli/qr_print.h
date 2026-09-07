/*
 * A QR code as terminal text, so a daemon with no screen can still show one.
 *
 * project.md sec 163. sec 160 encodes modules, sec 161 paints them in a
 * widget; this is the third consumer of the same array and the reason
 * `fzn_qr_encode` hands out modules rather than an image.
 *
 * IT WRITES INTO A CALLER'S BUFFER AND PRINTS NOTHING. No allocation and no
 * stdio, as everywhere here -- and a consumer that wants the code in a log
 * line, a file, or a socket gets the same bytes as one that wants it on a
 * terminal.
 *
 * HALF BLOCKS, BECAUSE A CELL IS NOT SQUARE. sec 162 measured what happens
 * when modules are not square: an independent decoder finds no code at all.
 * A cell here is 8 by 16, so one module per cell is stretched two to one --
 * but a HALF block is 8 by 8, which is square. Two module rows to a text row
 * therefore gets the geometry right and halves the height, which is what
 * makes a small code fit an ordinary terminal at all: version 1 with its
 * quiet zone is 29 columns by 15 rows this way, and 58 by 29 with whole
 * blocks.
 *
 * THE FILLED BLOCK IS THE LIGHT MODULE, AND THAT IS NOT A TYPO. A terminal
 * draws glyphs in the foreground colour on the background, and the ordinary
 * arrangement is light on dark -- so a filled glyph is LIGHT. Printing it for
 * a dark module would hand a scanner the photographic negative of the code,
 * which is a thing most decoders refuse. The quiet zone comes out as a solid
 * border of blocks, which is what a QR code on a terminal has always looked
 * like and is the quickest way to see the convention is right.
 *
 * A LIGHT TERMINAL WANTS THE OTHER ONE, and cannot be detected from here, so
 * it is a flag rather than a guess. `harmonization.md` settles how a GUI
 * detects a dark desktop and none of it reaches a pipe.
 */

#ifndef FZN_CLI_QR_PRINT_H
#define FZN_CLI_QR_PRINT_H

#include "../qr/qr.h"

#include <stddef.h>
#include <stdint.h>

/*
 * How to spell a module.
 *
 * HALF is the default worth having: square modules, half the rows. FULL is
 * for a terminal whose font renders half blocks badly -- they exist, and a
 * code that looks like a smear is worse than one that takes twice the height.
 * ASCII is the fallback for a terminal with no Unicode at all, and it comes
 * with a caveat rather than a promise: `#` does not fill its cell, so the
 * contrast a scanner sees is poor and the code may not read. It is there so
 * that something is printable, not because it is expected to scan.
 */
typedef enum fzn_qr_print_style {
	FZN_QR_PRINT_HALF = 0,
	FZN_QR_PRINT_FULL = 1,
	FZN_QR_PRINT_ASCII = 2,
} fzn_qr_print_style_t;

/* Room for the largest code this library encodes, in the widest spelling.
 *
 * A module is at most two cells and a cell at most three bytes of UTF-8, so a
 * row is `(size + 2 * quiet) * 6` plus a newline; there are at most that many
 * rows. Sized from the constants rather than measured, so it cannot drift
 * when FZN_QR_VERSION_MAX moves. */
#define FZN_QR_PRINT_ACROSS_MAX (FZN_QR_SIZE_MAX + 2u * FZN_QR_QUIET)
#define FZN_QR_PRINT_MAX \
	(FZN_QR_PRINT_ACROSS_MAX * (FZN_QR_PRINT_ACROSS_MAX * 6u + 1u) + 1u)

/*
 * Spell `modules` as text.
 *
 * `modules` and `size` are what `fzn_qr_encode` produced. `out` receives a
 * NUL-terminated string of `*len_out` bytes not counting the NUL, and nothing
 * is written unless the whole thing fits -- half a QR code is not a smaller
 * QR code.
 *
 * THE QUIET ZONE IS INCLUDED, on `gui/qr_view.h`'s argument: four modules of
 * background is what a scanner uses to find the code, and a caller that had
 * to remember to add it would be a caller who sometimes did not.
 *
 * `invert` swaps light for dark, for a terminal that is dark on light.
 *
 * FZN_QR_ERR_MALFORMED for a null argument, a size that is not a QR code's,
 * or a style outside the three; FZN_QR_ERR_FULL when `cap` is too small,
 * with `*len_out` set to what was needed so a caller can size and retry.
 */
fzn_qr_err_t fzn_qr_print(const uint8_t *modules, size_t size,
                          fzn_qr_print_style_t style, int invert, char *out, size_t cap,
                          size_t *len_out);

#endif /* FZN_CLI_QR_PRINT_H */
