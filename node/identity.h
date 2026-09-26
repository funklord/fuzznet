/* A node's own identity: loaded from its store, or generated when it has none.
 *
 * sec 136 settled that a host generates its identity when absent and ships
 * SELF-ROOTED -- anchored to its own key, with FZN_TRUST_SELF saying so, so a
 * node alone is a complete estate of one and joining another is a pin rather
 * than an attack. `node/provision.h` needs exactly that material to pair a
 * device, and until this file every consumer assembled it by hand from four
 * modules; `node/test/provision_test.c` was the only place that did. sec 375.
 *
 * THREE PARTS, ALL OR NOTHING:
 *
 *   FZN_PERSIST_OWN_IDENTITY   the signing seed -- who this node is
 *   FZN_PERSIST_OWN_PREKEY     the agree secret behind its sessions
 *   FZN_PERSIST_TRUST          whose authority it accepts
 *
 * A store holding some and not others is REFUSED, never repaired. The one
 * mixture a repair would reach for is the dangerous one: an identity whose
 * anchor is gone. Self-rooting it again would silently drop a node out of the
 * estate it had joined, and `persist.h` calls losing an anchor "the whole
 * TOFU protection". A missing agree secret has a milder repair, a rotation,
 * and it is refused as well, because a store that lost one part has told us
 * nothing about the others. Which mixture it is, and what to do about it, is
 * an operator's call made with the files in front of them.
 *
 * WHETHER A PART IS PRESENT IS THE CALLER'S TO SAY. `fzn_persist_ops_t::load`
 * answers 0 for a slot that is absent and for one it could not read, and the
 * copyright holder decided on 2026-09-04 not to widen that seam (sec 61). So
 * `fzn_node_identity_boot` takes the answer rather than guessing it: a backend
 * that can tell -- the file backend can, `fzn_persist_file_holds` -- says so,
 * and a caller that cannot uses `load` and `create` directly and owns the
 * first-run decision. Guessing here would make "the disk was briefly
 * unreadable" into "generate a new node", which destroys the old one.
 *
 * NO KEY PARAMETER ON ANY SIGNING PATH, as `chain.h` requires. The seed is
 * read into a local, handed to the seat, and wiped; afterwards the signer the
 * seat armed is the only holder.
 */

#ifndef FZN_NODE_IDENTITY_H
#define FZN_NODE_IDENTITY_H

#include <stdint.h>

#include "provision.h"
#include "../persist/persist.h"
#include "../session/random.h"

/* Declared, not included. sec 209. */
struct flog_t;

/* What booting needs, all caller-owned and outliving the identity it fills.
 * `sign` must be the signer `seat` arms -- two views of one key -- or the
 * identity will report one public key and sign as another. */
typedef struct fzn_node_identity_env {
	const fzn_persist_ops_t *store;
	const fzn_random_ops_t *rng;
	const fzn_sign_seat_t *seat;
	const fzn_sign_ops_t *sign;
	const fzn_hash_ops_t *hash;
	const fzn_agree_ops_t *agree;
	/* Where a creation and every refusal are reported, under
	 * "node/identity". NULL is silent. A node that made itself a new
	 * identity has done the one thing an operator most needs to be able
	 * to find afterwards. */
	struct flog_t *log;
} fzn_node_identity_env_t;

/* What the caller found stored, one answer per part: FZN_PERSIST_OK for
 * present, FZN_PERSIST_ERR_ABSENT for absent, anything else for "could not
 * tell" -- which boot treats as a store failure, never as a first run. */
typedef struct fzn_node_identity_found {
	fzn_persist_err_t seed;
	fzn_persist_err_t prekey;
	fzn_persist_err_t trust;
} fzn_node_identity_found_t;

typedef enum fzn_node_identity_err {
	FZN_NODE_IDENTITY_OK = 0,
	FZN_NODE_IDENTITY_MALFORMED = -1,
	/* The store refused, or could not say whether a part is there. */
	FZN_NODE_IDENTITY_STORE = -2,
	/* Some parts are stored and some are not. See the header. */
	FZN_NODE_IDENTITY_PARTIAL = -3,
	/* A stored part is not a shape this version reads. */
	FZN_NODE_IDENTITY_SHAPE = -4,
	/* The signer could not be seated, the agree secret would not install,
	 * the random source failed, or the prekey would not issue. */
	FZN_NODE_IDENTITY_CRYPTO = -5,
	/* The store's self-root names a key that is not this identity: the
	 * anchor says "I am my own root" about somebody else. */
	FZN_NODE_IDENTITY_MISMATCH = -6
} fzn_node_identity_err_t;

const char *fzn_node_identity_err_str(fzn_node_identity_err_t err);

/* Restore all three parts. `agree_secret` and `trust` are the caller's and
 * `out` points into them; `now` stamps the prekey record `out` carries, which
 * is re-issued rather than stored -- a peer pins the prekey, not the stamp,
 * so a later stamp over the same key is a re-delivery and moves nothing. */
fzn_node_identity_err_t fzn_node_identity_load(const fzn_node_identity_env_t *env,
                                               uint64_t now,
                                               fzn_agree_secret_t *agree_secret,
                                               fzn_trust_t *trust,
                                               fzn_node_identity_t *out);

/* Generate all three, self-rooted, and save them: the seed first and the
 * anchor last. THE CALLER ASSERTS THE STORE HOLDS NONE OF THEM -- this cannot
 * check, and saving over a live identity destroys it. A save that fails part
 * way leaves a partial store, which the next boot refuses by name. */
fzn_node_identity_err_t fzn_node_identity_create(const fzn_node_identity_env_t *env,
                                                 uint64_t now,
                                                 fzn_agree_secret_t *agree_secret,
                                                 fzn_trust_t *trust,
                                                 fzn_node_identity_t *out);

/* All present: load. All absent: create, and set *created. Anything else is
 * refused without touching the store. */
fzn_node_identity_err_t fzn_node_identity_boot(const fzn_node_identity_env_t *env,
                                               const fzn_node_identity_found_t *found,
                                               uint64_t now,
                                               fzn_agree_secret_t *agree_secret,
                                               fzn_trust_t *trust,
                                               fzn_node_identity_t *out, int *created);

#endif /* FZN_NODE_IDENTITY_H */
