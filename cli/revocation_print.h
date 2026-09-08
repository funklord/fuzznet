/*
 * What this host believes has been withdrawn -- and what it believes has been
 * given back, which is the same table and not the same thing.
 *
 * project.md sec 198. `gui/revocation_view` is the same facts for a screen
 * and shows this file's line; both changed in one commit on sec 193's rule.
 *
 * PRESENCE IS NOT REVOCATION. `chain.h`: "A withdrawal REPLACES the
 * revocation at this key rather than removing it, so PRESENCE IS NOT THE
 * ANSWER to 'is this revoked' -- every reader must ask this field." The entry
 * stays because removing it would let a re-relayed copy be re-admitted on
 * every propagation round, "not a one-time resurrection but a loop".
 *
 * So a line counting rows would report every capability that was ever revoked
 * and has since been RESTORED as still cut off. The two counts are separate
 * here and there is deliberately no total.
 *
 * `FZN_REVOCATIONS_UNREADABLE` IS ZERO, AND THAT IS THE FAIL-CLOSED CHOICE.
 * A store whose count exceeds its array cannot be walked, and reporting that
 * as "nothing revoked" is the fail-OPEN answer -- it says every capability is
 * fine when the truth is that this host cannot say. `fzn_revocation_covers`
 * makes the same choice internally, answering "revoked" for such a store.
 */

#ifndef FZN_CLI_REVOCATION_PRINT_H
#define FZN_CLI_REVOCATION_PRINT_H

#include "../chain/revocation.h"

#include <stddef.h>
#include <stdint.h>

typedef enum fzn_revocations_state {
	FZN_REVOCATIONS_UNREADABLE = 0,
	FZN_REVOCATIONS_NONE = 1,
	FZN_REVOCATIONS_HOLDING = 2
} fzn_revocations_state_t;

/* Room for the longest line: two counts and the words between them. */
#define FZN_REVOCATION_PRINT_MAX 160u

/*
 * Render what a store holds.
 *
 * `store` may be NULL, which is FZN_REVOCATIONS_NONE rather than unreadable:
 * `fzn_revocation_covers` documents NULL as "this host knows of no
 * revocations", which is a complete answer about a real thing rather than a
 * failure to look. sec 183's predicate makes the same distinction and this
 * follows it.
 *
 * `state_out` is REQUIRED.
 */
fzn_chain_err_t fzn_revocation_print(const fzn_revocation_store_t *store, char *out,
                                     size_t cap, size_t *len_out,
                                     fzn_revocations_state_t *state_out);

#endif /* FZN_CLI_REVOCATION_PRINT_H */
