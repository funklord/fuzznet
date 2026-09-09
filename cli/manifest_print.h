/*
 * What this host is still missing from one issuer, and whether that number
 * can be believed.
 *
 * project.md sec 224. `chain/manifest.h` calls a dropped pair the one refusal
 * in this library that fails OPEN: it "does not make this host report a fault;
 * it makes it report a SMALLER deficit than it has, which is to say it looks
 * MORE complete than it is". A host in that state is not broken and does not
 * say so anywhere a person looks. This is where it says so.
 *
 * THE NUMBER IS THE EASY HALF. `fzn_manifest_pending` answers it and a
 * consumer could print it in one line. What a consumer cannot get right by
 * accident is that the number is sometimes a FLOOR, and that the accessor
 * answering zero means "the absence of a question" rather than "nothing is
 * outstanding" -- both of which manifest.h states and neither of which
 * survives being reduced to an integer on a screen.
 *
 * FOUR STATES, NAMED, NO `default:`. `cli/trust_print.h` records what a
 * `default:` over an enum cost there; the same rule holds here.
 *
 * IT READS AND DOES NOT DECIDE. Nothing here follows an issuer, admits a
 * manifest or satisfies a pair.
 *
 * `FZN_MANIFEST_LINE_NONE` IS ZERO.
 */

#ifndef FZN_CLI_MANIFEST_PRINT_H
#define FZN_CLI_MANIFEST_PRINT_H

#include "../chain/manifest.h"

#include <stddef.h>
#include <stdint.h>

/*
 * NOT FOLLOWED AND UNDERSTATED ARE DIFFERENT SENTENCES, AND THE LIBRARY COULD
 * NOT TELL THEM APART UNTIL THIS FILE ASKED.
 *
 * `fzn_manifest_pending` answers 0 for an issuer that is not followed;
 * `fzn_manifest_overflowed` answers 1 for the same case AND for a real
 * dropped pair. So the pair (0, 1) meant either "this host tracks nothing
 * from that key" or "it tracks that key, its count is a floor, and what it
 * did record has since been satisfied" -- opposite things to tell a person.
 * `fzn_manifest_follows` was added for this and is measured in the test.
 */
typedef enum fzn_manifest_line {
	/* No state to read, or a caller that passed nothing. */
	FZN_MANIFEST_LINE_NONE = 0,
	/* Not followed: nothing this issuer revokes is being tracked. This is
	 * an absence of a question rather than an answer of zero. */
	FZN_MANIFEST_LINE_UNFOLLOWED = 1,
	/* Followed, nothing outstanding, and the count can be believed. */
	FZN_MANIFEST_LINE_COMPLETE = 2,
	/* Followed, some outstanding, and the count can be believed. */
	FZN_MANIFEST_LINE_PENDING = 3,
	/* Followed, and the count is a FLOOR: a pair was dropped for want of
	 * room, so this host is missing more than it can name.
	 *
	 * ONE STATE FOR TWO WORDINGS, deliberately. A floor of three and a
	 * floor of zero read differently to a person and are the same thing to
	 * a caller -- the number cannot be trusted downwards -- so the line
	 * differs and the state does not. sec 201's rule: a state added so
	 * that every wording has one is symmetry rather than merit. */
	FZN_MANIFEST_LINE_UNDERSTATED = 4
} fzn_manifest_line_t;

/* Room for the longest of the five lines. */
#define FZN_MANIFEST_PRINT_MAX 160u

/*
 * Render what this host is missing from `issuer`.
 *
 * `state` may be NULL, which is FZN_MANIFEST_LINE_NONE.
 *
 * `state_out` is REQUIRED, on the same argument `fzn_manifest_deficit` makes
 * for its own: an optional out-parameter is one every caller ignores, and the
 * whole content of this file is the difference between a number and a number
 * that cannot be believed.
 */
fzn_manifest_err_t fzn_manifest_print(const fzn_manifest_state_t *state,
                                      const uint8_t issuer[FZN_PUBKEY_LEN], char *out,
                                      size_t cap, size_t *len_out,
                                      fzn_manifest_line_t *state_out);

#endif /* FZN_CLI_MANIFEST_PRINT_H */
