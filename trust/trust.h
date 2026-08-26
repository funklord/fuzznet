/* Where a pinned root comes from, including trust on first use.
 *
 * sec 4.2 said the root is "pinned rather than adopted" and `chain/chain.h`
 * still says so, with an argument worth keeping: **there is no nullable-root
 * variant on purpose, because one function with an optional pin is a function
 * somebody calls without the pin.** That remains true and is not weakened
 * here.
 *
 * WHAT CHANGED (2026-08-26, at the copyright holder's instruction) is that
 * fuzzypickles needs TOFU and this library is absorbing its host management.
 * A joining host has no anchor and must get one somehow; refusing to have a
 * path meant the path existed anyway, in the consumer, written three times.
 *
 * HOW BOTH HOLD AT ONCE. `fzn_chain_verify` is untouched: it still takes a
 * root and still refuses a chain rooted anywhere else. This file is only
 * about how a host CAME to have that root, and it hands one over through
 * `fzn_trust_root`, which returns NULL when there is none -- so a consumer
 * that has not anchored cannot accidentally verify against nothing. The
 * verification-time property is unchanged; the bootstrap is now named.
 *
 * TRUST ON FIRST USE IS EXACTLY THAT, AND ITS WEAKNESS IS THE FIRST CONTACT.
 * Nothing authenticates the key adopted at that moment -- whoever answers
 * first is trusted, and an attacker in position then is trusted for ever
 * after. What TOFU buys is that every LATER contact is authenticated, so an
 * attacker who arrives afterwards is refused. That is a real property and a
 * narrow one.
 *
 * So a consumer using `fzn_trust_adopt` **owes its user a way to check the
 * anchor out of band** -- a fingerprint to compare, a confirmation step,
 * something. This module records the moment of adoption (`adopted_at`) and
 * how the anchor arrived (`fzn_trust_source`) precisely so that a consumer
 * can show it. A library cannot make first contact safe; it can refuse to
 * hide when it happened.
 *
 * ONCE ANCHORED, A DIFFERENT KEY IS REFUSED. That is the whole security
 * content of "first". Re-anchoring to something else would make it trust on
 * EVERY use, which is no trust at all, so a second key is an error a consumer
 * should treat as an attack rather than as a retry. A caller that genuinely
 * must start again wants a new `fzn_trust_t`, on the same reasoning
 * `record/journal.h` gives for never rewinding an anchor.
 */

#ifndef FZN_TRUST_H
#define FZN_TRUST_H

#include "../chain/chain.h"

#include <stdint.h>

typedef enum fzn_trust_err {
	FZN_TRUST_OK = 0,
	FZN_TRUST_ERR_MALFORMED = -1,
	/* Anchored already, to a DIFFERENT key. The one error here that a
	 * consumer should treat as hostile rather than as a condition. */
	FZN_TRUST_ERR_ANCHORED = -2,
	/* Anchored already, to the SAME key. An echo -- a join repeated, a
	 * bundle delivered twice -- and not a fault. Distinguished from OK so
	 * that a caller can tell a first adoption from a repeat, which is
	 * exactly what it needs to know before telling a user anything. */
	FZN_TRUST_ERR_UNCHANGED = -3,
} fzn_trust_err_t;

/* How the anchor arrived, so a consumer can say so. */
typedef enum fzn_trust_source {
	FZN_TRUST_NONE = 0,
	/* Configured out of band: an operator typed it, a package shipped it.
	 * Authenticated by whatever put it there. */
	FZN_TRUST_PINNED = 1,
	/* Adopted on first contact. Authenticated by nothing; see above. */
	FZN_TRUST_ADOPTED = 2,
} fzn_trust_source_t;

typedef struct fzn_trust {
	uint8_t root[FZN_PUBKEY_LEN];
	uint64_t adopted_at;
	fzn_trust_source_t source;
} fzn_trust_t;

/* An anchor with nothing in it. */
void fzn_trust_init(fzn_trust_t *trust);

/* Anchor to a root that arrived out of band. */
fzn_trust_err_t fzn_trust_pin(fzn_trust_t *trust, const uint8_t root[FZN_PUBKEY_LEN]);

/* Anchor to a root on first contact, recording when.
 *
 * `now` is stored rather than checked: this module has no opinion about
 * clocks, and the timestamp exists so a consumer can tell a user when its
 * trust was established. */
fzn_trust_err_t fzn_trust_adopt(fzn_trust_t *trust, const uint8_t root[FZN_PUBKEY_LEN],
                                 uint64_t now);

/* The root to verify against, or NULL when there is none.
 *
 * NULL rather than a zero key, because `fzn_chain_verify` refuses NULL and
 * would happily verify against a key of zeroes -- and an anchor nobody set
 * must fail closed rather than match whatever an attacker can also produce. */
const uint8_t *fzn_trust_root(const fzn_trust_t *trust);

/* How this anchor arrived. `FZN_TRUST_NONE` when there is none. */
fzn_trust_source_t fzn_trust_source_of(const fzn_trust_t *trust);

/* When it was adopted, or 0 if it was pinned or absent. */
uint64_t fzn_trust_adopted_at(const fzn_trust_t *trust);

/* A short name for `fzn_trust_err_t`. Never NULL. */
const char *fzn_trust_err_str(fzn_trust_err_t err);

#endif /* FZN_TRUST_H */
