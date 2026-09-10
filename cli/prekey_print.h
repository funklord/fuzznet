/*
 * What happened when a peer's prekey record was offered, in the terms a
 * person needs.
 *
 * project.md sec 252. `prekey.h` says of one of its codes, in as many words,
 * that it exists for a reader:
 *
 *   THE ROLLBACK CASE, and it has its own code because it is the one an
 *   operator has to see. A stranger who replays a host's older, real,
 *   correctly-signed record is offering a key the host has moved on from --
 *   and if that key has since leaked, accepting it is the whole attack.
 *
 * Nothing showed it. Seven codes reach a consumer and every distinction in
 * them dies in the integer a person reads -- including the one the header
 * says an operator has to see, and the one it says is not an event at all.
 *
 * NINE STATES, AND EACH HAS A DIFFERENT READER:
 *
 *     learned        this host now trusts a prekey for a peer it did not
 *     rotated        the peer moved to a newer key, which is what rotation
 *                    is for and is worth showing
 *     unchanged      a re-delivery of a record already held. `prekey.h`:
 *                    "ordinary and is not an event"
 *     ROLLBACK       an operator: a real, correctly signed, older record
 *                    replayed, and if that key has leaked this is the attack
 *     wrong host     an operator: a different peer arriving in this slot
 *     unverified     the record does not verify under the host key it names
 *     foreign        not this protocol's shape at all, which is usually a
 *                    version skew rather than an attack
 *     local          OUR verifier was absent or refused, or the caller
 *                    passed something impossible -- this host's problem and
 *                    not the peer's
 *
 * THE LAST ONE IS THE DIRECTION THAT GETS CONFUSED. A missing verifier and a
 * forged signature both stop a peer being pinned, and only one of them is
 * about the peer. A consumer that says "this peer could not be verified"
 * when the truth is "this host has no verifier configured" has accused
 * somebody of something the host did.
 *
 * FZN_PREKEY_ERR_SIGNER AND _MALFORMED SHARE THAT LINE, on sec 201's rule:
 * both are this side's fault, the person reading cannot act on either
 * differently, and splitting them would draw a distinction for the code's
 * benefit on a surface the code does not read.
 *
 * IT TAKES THE PEER BEFORE AND AFTER, which is the only way to tell a
 * rotation from a re-delivery: both answer FZN_PREKEY_OK, both leave the
 * record stored, and the difference is whether anything moved. A caller
 * copies the peer -- it is a small value with no allocation behind it --
 * before calling `fzn_prekey_pin`. The alternative was collapsing the two,
 * and the header calls one of them not an event, which is exactly the
 * distinction a surface exists to keep.
 *
 * IT READS AND DOES NOT DECIDE. Nothing here pins anything, and the verdict
 * comes from the caller's own call rather than from a second attempt -- a
 * printer that pinned for itself would be reporting on an attempt the
 * consumer never made.
 *
 * `FZN_PREKEY_LINE_NONE` IS ZERO.
 */

#ifndef FZN_CLI_PREKEY_PRINT_H
#define FZN_CLI_PREKEY_PRINT_H

#include "../prekey/prekey.h"

#include <stddef.h>
#include <stdint.h>

typedef enum fzn_prekey_line {
	/* No peer, or a code this does not understand. */
	FZN_PREKEY_LINE_NONE = 0,
	/* A prekey for a host this peer slot did not hold. */
	FZN_PREKEY_LINE_LEARNED = 1,
	/* The same host, a newer key, and the stored one moved. */
	FZN_PREKEY_LINE_ROTATED = 2,
	/* The same host and the same key: ordinary, and not an event. */
	FZN_PREKEY_LINE_UNCHANGED = 3,
	/* An older key replayed. The one an operator has to see. */
	FZN_PREKEY_LINE_ROLLBACK = 4,
	/* A different host entirely, in this slot. */
	FZN_PREKEY_LINE_WRONG_HOST = 5,
	/* The self-signature does not verify under the key the record names. */
	FZN_PREKEY_LINE_UNVERIFIED = 6,
	/* Not this protocol's shape: a version or an object tag that is not
	 * ours, which is usually skew rather than an attack. */
	FZN_PREKEY_LINE_FOREIGN = 7,
	/* This host's own problem: no verifier, or a caller bug. */
	FZN_PREKEY_LINE_LOCAL = 8
} fzn_prekey_line_t;

/* Room for the longest of the nine lines. */
#define FZN_PREKEY_PRINT_MAX 300u

/*
 * Render what `err` said, given the peer as it was and as it is.
 *
 * `before` is a copy taken before `fzn_prekey_pin` was called and `after` is
 * the peer that call was given. Either being NULL is FZN_PREKEY_LINE_NONE:
 * a report needs both halves to tell a rotation from a re-delivery, and
 * guessing which it was is the one thing this must not do.
 *
 * `state_out` is REQUIRED.
 */
fzn_prekey_err_t fzn_prekey_print(const fzn_prekey_peer_t *before,
                                  const fzn_prekey_peer_t *after, fzn_prekey_err_t err,
                                  char *out, size_t cap, size_t *len_out,
                                  fzn_prekey_line_t *state_out);

#endif /* FZN_CLI_PREKEY_PRINT_H */
