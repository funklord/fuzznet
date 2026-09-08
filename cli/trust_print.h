/*
 * This host's trust anchor: who it is, and how it came to be trusted.
 *
 * project.md sec 201. `gui/trust_view` is the same facts for a screen and
 * shows this file's line; both changed in one commit on sec 193's rule. It is
 * the last of the eleven pairs.
 *
 * `trust/trust.h` says a consumer using `fzn_trust_adopt` "owes its user a
 * way to check the anchor out of band -- a fingerprint to compare, a
 * confirmation step, something", and then leaves every consumer to build one.
 * sec 140 built the screen so four projects would not produce four wordings
 * and four fingerprint formats; this is the same debt paid for a host with no
 * screen, and it uses the same `fzn_trust_fingerprint`, so a person can
 * compare what a terminal printed against what a dialog showed.
 *
 * AN ABSENT ANCHOR IS NOT AN EMPTY FINGERPRINT. A line of nothing where a
 * fingerprint belongs reads as a fingerprint -- of something -- and somebody
 * comparing would find it matches nothing and conclude the peer is wrong,
 * when the truth is this host has no anchor at all.
 *
 * HOW IT WAS TRUSTED IS ON THE LINE, AND IT IS NOT DECORATION. `PINNED` was
 * configured out of band by somebody who checked; `ADOPTED` was taken on
 * first contact and is, in trust.h's words, "authenticated by nothing". A
 * fingerprint printed without which of those it is invites comparing an
 * adopted anchor as though somebody had already vouched for it.
 *
 * IT READS AND DOES NOT DECIDE, as sec 140 required of the widget: nothing
 * here pins, adopts or confirms. A confirmation step is a decision with a
 * security meaning and does not belong in the thing that draws the evidence.
 *
 * `FZN_TRUST_LINE_NONE` IS ZERO.
 */

#ifndef FZN_CLI_TRUST_PRINT_H
#define FZN_CLI_TRUST_PRINT_H

#include "../trust/trust.h"

#include <stddef.h>
#include <stdint.h>

/*
 * FOUR SOURCES, NOT THREE, AND THE FOURTH IS NOT AN ABSENCE. A first draft
 * had NONE, ADOPTED and PINNED and let `default:` catch the rest -- which
 * mapped FZN_TRUST_SELF onto "no anchor", printing "this host trusts nothing
 * yet" for a node anchored to its own key.
 *
 * trust.h is explicit that this is wrong: a self-anchored node "is a complete
 * estate of one -- it can issue, sign and serve itself -- so this is a working
 * state rather than a placeholder waiting to be filled". And the difference
 * matters operationally, because the same paragraph says an UNANCHORED node
 * "adopts the next root offered, so whoever reaches it first owns it". Telling
 * an operator their self-anchored host has no anchor invites them to fix a
 * state that is correct, in a way that opens the one that is not.
 *
 * A `default:` over an enum is how that happened. The switch names all four
 * now.
 */
typedef enum fzn_trust_line {
	FZN_TRUST_LINE_NONE = 0,
	/* Taken on first contact, authenticated by nothing. */
	FZN_TRUST_LINE_ADOPTED = 1,
	/* Configured out of band by somebody who checked. */
	FZN_TRUST_LINE_PINNED = 2,
	/* Its own root: a complete estate of one, and a working state. */
	FZN_TRUST_LINE_SELF = 3
} fzn_trust_line_t;

/* Room for a fingerprint, a source and an adoption instant. */
#define FZN_TRUST_PRINT_MAX 160u

/*
 * Render one anchor.
 *
 * `trust` may be NULL, which is FZN_TRUST_LINE_NONE and prints no
 * fingerprint at all.
 *
 * `state_out` is REQUIRED.
 */
fzn_trust_err_t fzn_trust_print(const fzn_trust_t *trust, char *out, size_t cap,
                                size_t *len_out, fzn_trust_line_t *state_out);

#endif /* FZN_CLI_TRUST_PRINT_H */
