/*
 * A provisioning card: whether it verifies, who it says you are pairing with,
 * and the text a code would carry.
 *
 * project.md sec 200. `gui/provision_view` is the same facts for a screen and
 * shows this file's line; both changed in one commit on sec 193's rule.
 *
 * NO FINGERPRINT FOR A CARD THAT DID NOT VERIFY, and on this side the reason
 * is sharper than on a screen. sec 171: a card names a root, a hop and a
 * prekey, and the envelope signature is the only thing saying those three
 * came from one hand -- provision.h, "The parts may each be genuine and not
 * belong together". So an attacker can put a GENUINE root beside their own
 * prekey and sign the envelope themselves, and the root field reads
 * correctly.
 *
 * A person comparing a fingerprint out of band compares exactly that field.
 * **A LINE IS WORSE THAN A SCREEN HERE BECAUSE IT IS LOGGED**: a fingerprint
 * printed for an unverified card outlives the moment, gets read later by
 * somebody who was not there, and carries none of the doubt the operator had.
 * So it is not printed at all until the card verifies.
 *
 * `FZN_PROVISION_LINE_NOTHING` IS ZERO, and every state short of USABLE is
 * below it in the enum, so a caller comparing `>= FZN_PROVISION_LINE_USABLE`
 * gets the only safe test and a caller ignoring the field gets the safest
 * answer.
 *
 * THE CARD'S TEXT IS `fzn_provision_text`'s, which is what a QR carries. A
 * terminal cannot show a code but it can show the string, and a phone can be
 * pointed at a screen showing either.
 */

#ifndef FZN_CLI_PROVISION_PRINT_H
#define FZN_CLI_PROVISION_PRINT_H

#include "../chain/chain.h"
#include "../provision/provision.h"

#include <stddef.h>
#include <stdint.h>

/*
 * ORDERED SO THAT THE THRESHOLD MEANS SOMETHING, which took a correction.
 *
 * The first draft ordered these by how bad they sound -- UNDATED then EXPIRED
 * -- and the fingerprint test `state >= UNDATED` then printed a root for an
 * EXPIRED card, which `gui/provision_view` does not do. Two implementations
 * disagreeing, caught before either shipped because they were written in one
 * commit; sec 193's rule earning its place rather than being applied to it.
 *
 * The order is now: the signature verified, and the expiry did not stop it.
 *
 *     >= FZN_PROVISION_LINE_UNDATED   the parts belong together AND are in
 *                                     date, so a fingerprint is worth
 *                                     comparing
 *     == FZN_PROVISION_LINE_USABLE    that, and a clock said so
 *
 * An expired card's signature IS good and its root IS genuinely bound to its
 * prekey -- the recombination attack this guards is a signature failure, not
 * an expiry. Withholding the fingerprint there is the conservative choice
 * sec 171 made and not a consequence of the ordering: showing it invites
 * somebody to compare and accept a card that has run out.
 */
typedef enum fzn_provision_line {
	FZN_PROVISION_LINE_NOTHING = 0,
	FZN_PROVISION_LINE_REFUSED = 1,
	FZN_PROVISION_LINE_UNCHECKED = 2,
	FZN_PROVISION_LINE_EXPIRED = 3,
	FZN_PROVISION_LINE_UNDATED = 4,
	FZN_PROVISION_LINE_USABLE = 5
} fzn_provision_line_t;

/* Room for a verdict, a fingerprint and the card's whole text form. */
#define FZN_PROVISION_PRINT_MAX (FZN_PROVISION_TEXT_LEN + 160u)

/*
 * Render one card as at `now`.
 *
 * `bytes`/`len` are a packed card; NULL is FZN_PROVISION_LINE_NOTHING.
 *
 * `verifier` may be NULL, which is the offering side showing its own card:
 * there is nothing to check it against, so the code text is printed and no
 * fingerprint is offered.
 *
 * `now` of zero means the caller has no clock, which provision.h treats as
 * "skip the expiry check" -- so the result is UNDATED rather than USABLE, and
 * the line says the expiry was not looked at.
 *
 * `state_out` is REQUIRED.
 */
fzn_provision_err_t fzn_provision_print(const uint8_t *bytes, size_t len,
                                        const fzn_sign_ops_t *verifier, uint64_t now,
                                        char *out, size_t cap, size_t *len_out,
                                        fzn_provision_line_t *state_out);

#endif /* FZN_CLI_PROVISION_PRINT_H */
