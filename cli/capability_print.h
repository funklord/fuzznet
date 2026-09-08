/*
 * Whether one capability this host holds is usable, and if not, which of the
 * two reasons.
 *
 * project.md sec 196. `gui/capability_view` is the same facts for a screen
 * and shows this file's line; both changed in one commit on sec 193's rule.
 *
 * EXPIRED AND REVOKED CALL FOR OPPOSITE ACTIONS, which is why they are
 * separate states rather than one "unusable". An expiry has run out and wants
 * renewing; a revocation is somebody's decision about this key and renewing
 * it would be exactly wrong. sec 166 made the distinction for a screen, where
 * it saves a person a wrong guess; here it decides what an automated
 * response does.
 *
 * REVOCATION IS ASKED WITH `fzn_revocation_covers`, NEVER `..._known`.
 * revocation.h keeps three predicates apart and says they must not be
 * confused: `covers` answers authorization and `known` answers "must I still
 * fetch this". They differ on exactly one state -- an entry whose revocation
 * has since been WITHDRAWN -- and asking the wrong one reports a RESTORED
 * capability as cut off, which revocation.c calls "the outage the whole
 * withdrawal design exists to end".
 *
 * EXPIRY IS `fzn_chain_expired_at`'s ANSWER. FZN_NO_EXPIRY is 0, so the
 * obvious comparison reports every chain that never expires as the most
 * expired thing a host holds -- sec 170.
 *
 * `FZN_CAPABILITY_NONE` IS ZERO, so a caller that ignores the state, or reads
 * it after a refusal, is told this host holds nothing rather than that all is
 * well.
 *
 * IT SAYS "usable", NOT "allowed". `fzn_chain_store_lookup` shouts the same
 * at its own callers: finding a chain is not authorisation, because the
 * request is still verified and `fzn_authz_decide` is still asked whether a
 * chain was required at all.
 */

#ifndef FZN_CLI_CAPABILITY_PRINT_H
#define FZN_CLI_CAPABILITY_PRINT_H

#include "../chain/chain.h"
#include "../chain/revocation.h"

#include <stddef.h>
#include <stdint.h>

typedef enum fzn_capability_state {
	FZN_CAPABILITY_NONE = 0,
	FZN_CAPABILITY_REVOKED = 1,
	FZN_CAPABILITY_EXPIRED = 2,
	FZN_CAPABILITY_USABLE = 3
} fzn_capability_state_t;

/* Room for the longest line: a fingerprint, a state and an expiry. */
#define FZN_CAPABILITY_PRINT_MAX 192u

/*
 * Render one verified chain's usability as at `now`.
 *
 * `chain` may be NULL, which is FZN_CAPABILITY_NONE.
 *
 * `revocations` may be NULL, and that is not a caller's mistake:
 * `fzn_revocation_covers` documents NULL as the answer a host with no store
 * gives. It is passed straight through rather than checked here, so a store
 * that cannot be scanned reaches the library and gets its fail-closed answer.
 *
 * REVOCATION WINS WHEN BOTH ARE TRUE, on sec 166's argument: expiry is
 * passive and reversible by reissue, while a revocation is a decision
 * somebody took about this grantee and is the half that may need acting on.
 *
 * `state_out` is REQUIRED.
 */
fzn_chain_err_t fzn_capability_print(const fzn_chain_t *chain,
                                     const fzn_revocation_store_t *revocations, uint64_t now,
                                     char *out, size_t cap, size_t *len_out,
                                     fzn_capability_state_t *state_out);

#endif /* FZN_CLI_CAPABILITY_PRINT_H */
