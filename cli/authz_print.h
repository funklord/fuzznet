/*
 * What a kind of request requires, and which origins can reach it.
 *
 * project.md sec 199. `gui/authz_view` is the same facts for a screen and
 * shows this file's line; both changed in one commit on sec 193's rule.
 *
 * AN UNSPELLED POLICY IS NOT A DENYING ONE, and on a host that is refusing
 * requests this is the whole question. `chain/authz.h` calls `spelled` "the
 * field the whole design rests on": it is what makes a zeroed policy
 * distinguishable from a deliberate one. Both deny. Only one of them is a
 * configuration fault somebody has to find, and a line that reported the
 * verdict alone would hide exactly the case worth reporting.
 *
 * GUARDED AND UNGUARDED ARE ALSO DIFFERENT WORDS, for the reason
 * `fzn_authz_verdict_t` keeps GRANTED_BY_CHAIN and GRANTED_UNGUARDED apart: a
 * policy that has drifted to unguarded is a thing somebody has to be able to
 * find, and it cannot be found if the line says "allowed" for both.
 *
 * IT ASKS `fzn_authz_origin_permitted` PER ORIGIN. Testing `policy.origins`
 * against `FZN_ORIGIN_BIT` here would be a second implementation of the rule
 * that actually gates requests -- readable, obvious, and free to drift.
 *
 * `FZN_AUTHZ_LINE_UNSPELLED` IS ZERO, so a caller that ignores the state, or
 * reads it after a refusal, is told nobody has configured this rather than
 * that it is deliberately closed.
 */

#ifndef FZN_CLI_AUTHZ_PRINT_H
#define FZN_CLI_AUTHZ_PRINT_H

#include "../chain/authz.h"
#include "../chain/chain.h"

#include <stddef.h>
#include <stdint.h>

typedef enum fzn_authz_line {
	FZN_AUTHZ_LINE_UNSPELLED = 0,
	FZN_AUTHZ_LINE_UNGUARDED = 1,
	FZN_AUTHZ_LINE_GUARDED = 2
} fzn_authz_line_t;

/* Room for the longest line: a fingerprint and three origin names. */
#define FZN_AUTHZ_PRINT_MAX 192u

/*
 * Render one policy.
 *
 * `policy` may be NULL, which is the unspelled state -- what a zeroed
 * `fzn_authz_policy_t` is, and what a consumer that forgot to spell one has.
 *
 * `state_out` is REQUIRED.
 *
 * IT RETURNS `fzn_chain_err_t` BECAUSE authz HAS NO ERROR ENUM OF ITS OWN --
 * every entry point there answers a verdict or a predicate rather than a
 * status. `cli/capability_print` borrows the same one for the same reason,
 * and inventing a third would be a vocabulary nobody asked for.
 */
fzn_chain_err_t fzn_authz_print(const fzn_authz_policy_t *policy, char *out, size_t cap,
                                size_t *len_out, fzn_authz_line_t *state_out);

#endif /* FZN_CLI_AUTHZ_PRINT_H */
