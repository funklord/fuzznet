/* A succession: one key succeeded by another. project.md sec 498.
 *
 * WHY. A device whose keys can no longer be trusted is re-keyed (sec 394,
 * the holder's "successor takes over"; sec 496's two outcomes of a device
 * found again). Revoking its old key at a line (sec 496) keeps what it did
 * before the theft and drops what came after. What revoking cannot do is say
 * that the new key is the same device: everything else in an estate that
 * names the old key -- a contact on somebody's roster, a share, a member's
 * row -- would otherwise lose it, and the owner would have to re-add every
 * reference by hand, on every host.
 *
 * So a succession is a signed statement, "OLD is succeeded by NEW, trusted up
 * to CUT", and every place that names OLD reads through to NEW once the
 * succession counts. It does NOT revoke OLD and does NOT grant NEW: those
 * are a revocation vote at the same cut and an ordinary pairing, which the
 * node's verb casts beside it (sec 498). Kept apart so that each act is
 * judged by the rule it already has -- k of n for the revocation, a pairing
 * for the grant -- and the succession by its own, below.
 *
 * WHO MAY ISSUE ONE: a root of the estate, or an admin showing its admin
 * chain. WHEN IT COUNTS: as an admin grant does (sec 414) -- a root's counts
 * alone, while the root set says its record does; an admin's once k - 1
 * other admins who stand, or one root, have confirmed it with the confirmation
 * object sec 414 already defines, naming the succession by its hash. Judged
 * when read, from what is held, so arrival order decides nothing.
 *
 * READING THROUGH. `fzn_succession_resolve` follows counting successions from
 * a key to the newest one. Two counting successions of one key to different
 * keys are a FORK -- a stolen admin key re-keying a device to its own choice
 * while the owner re-keys it to theirs -- and a fork resolves to nothing: no
 * reference moves until one of them stops counting. A cycle resolves to
 * nothing too. Both fail toward the old key's references staying put, where
 * a wrong guess would hand them to a thief.
 *
 * THE LAYOUT. Big-endian, fixed width, as every signed object here.
 *
 *     offset  size  field
 *          0     1  version    (= FZN_SIGNED_VERSION)
 *          1     1  object     (= FZN_OBJECT_SUCCESSION)
 *          2    32  issuer     (the root or admin that signed it)
 *         34    32  old        (the key succeeded)
 *         66    32  new        (its successor)
 *         98    32  cut        (the last entry of OLD's act log trusted)
 *        130    64  signature
 *
 * A record's ID is the hash of its whole 194 bytes, as a revocation's is, and
 * is what a confirmation names.
 */

#ifndef FZN_SUCCESSION_H
#define FZN_SUCCESSION_H

#include <stddef.h>
#include <stdint.h>

#include "chain.h"
#include "revocation.h"
#include "../session/commitment.h"

#define FZN_SUCCESSION_BODY_LEN 130u
#define FZN_SUCCESSION_LEN (FZN_SUCCESSION_BODY_LEN + (size_t)FZN_SIG_LEN)
#define FZN_SUCCESSION_ID_LEN 32u

#define FZN_SUCCESSION_OFF_VERSION 0u
#define FZN_SUCCESSION_OFF_OBJECT 1u
#define FZN_SUCCESSION_OFF_ISSUER 2u
#define FZN_SUCCESSION_OFF_OLD 34u
#define FZN_SUCCESSION_OFF_NEW 66u
#define FZN_SUCCESSION_OFF_CUT 98u
#define FZN_SUCCESSION_OFF_SIGNATURE FZN_SUCCESSION_BODY_LEN

/* The most successions `fzn_succession_resolve` follows from one key: a
 * device re-keyed this many times in a row is past anything an owner does by
 * hand, and the bound is what keeps a long chain from being a cost. */
#define FZN_SUCCESSION_DEPTH_MAX 16u

/* A view over an opened record, as every signed object here is viewed. */
typedef struct fzn_succession_record {
	const uint8_t *base;
} fzn_succession_record_t;

/* Shape only: length, version, object, and OLD differing from NEW. The
 * signature is asked at admission. SHAPE otherwise. */
fzn_chain_err_t fzn_succession_open(const uint8_t *bytes, size_t len,
                                    fzn_succession_record_t *out);

static inline const uint8_t *fzn_succession_issuer(fzn_succession_record_t r)
{
	return r.base + FZN_SUCCESSION_OFF_ISSUER;
}

static inline const uint8_t *fzn_succession_old(fzn_succession_record_t r)
{
	return r.base + FZN_SUCCESSION_OFF_OLD;
}

static inline const uint8_t *fzn_succession_new(fzn_succession_record_t r)
{
	return r.base + FZN_SUCCESSION_OFF_NEW;
}

static inline const uint8_t *fzn_succession_cut(fzn_succession_record_t r)
{
	return r.base + FZN_SUCCESSION_OFF_CUT;
}

/* Sign a succession: `issuer` says `old` is succeeded by `new_key`, trusting
 * OLD's acts up to `cut` (NULL for none). `out` receives FZN_SUCCESSION_LEN
 * bytes. MALFORMED for OLD equal to NEW. As `fzn_revocation_issue`, `issuer`
 * is a public key and whether the signer holds its secret is not asked. */
fzn_chain_err_t fzn_succession_issue(const uint8_t issuer[FZN_PUBKEY_LEN],
                                     const uint8_t old[FZN_PUBKEY_LEN],
                                     const uint8_t new_key[FZN_PUBKEY_LEN],
                                     const uint8_t cut[FZN_SUCCESSION_ID_LEN],
                                     const fzn_sign_ops_t *sign, uint8_t *out);

/* A succession as a set keeps it: the fields the questions read, and its id.
 * Verified once, on admission. */
typedef struct fzn_succession {
	uint8_t issuer[FZN_PUBKEY_LEN];
	uint8_t old[FZN_PUBKEY_LEN];
	uint8_t new_key[FZN_PUBKEY_LEN];
	uint8_t cut[FZN_SUCCESSION_ID_LEN];
	uint8_t id[FZN_SUCCESSION_ID_LEN];
} fzn_succession_t;

/* The successions a host holds. Caller-owned storage; nothing is evicted. */
typedef struct fzn_succession_set {
	fzn_succession_t *entries;
	size_t capacity;
	size_t used;
	const fzn_hash_ops_t *hash;
} fzn_succession_set_t;

fzn_chain_err_t fzn_succession_set_init(fzn_succession_set_t *set, fzn_succession_t *entries,
                                        size_t capacity, const fzn_hash_ops_t *hash);

/* ADMIT A SUCCESSION: its shape, its issuer's signature, and its issuer's
 * standing to issue one -- the pinned `root` or a member of `revocations`'
 * root set with no chain, or an admin showing its admin chain in `hops`,
 * kept in the store's admin table as a vote's chain is. Whether it COUNTS is
 * the reader's question, below. OK when already held.
 *
 * WRONG_ROOT for a chainless issuer that is no root; CHAIN_INVALID for a bad
 * signature or an admin chain that does not hold; STORE_FULL when the set is
 * full. */
fzn_chain_err_t fzn_succession_admit(fzn_succession_set_t *set,
                                     fzn_revocation_store_t *revocations, const uint8_t *bytes,
                                     size_t len, const fzn_chain_hop_t *hops, size_t hop_count,
                                     const uint8_t root[FZN_PUBKEY_LEN],
                                     const fzn_sign_ops_t *sign);

/* Whether entry `i` counts: its issuer a root whose record counts, or an admin
 * who stands with the confirmations an admin grant would need
 * (`fzn_revocation_confirmed`). 0 for a set or index that is not sound. */
int fzn_succession_counts(const fzn_succession_set_t *set, size_t i,
                          const fzn_revocation_store_t *revocations,
                          const uint8_t root[FZN_PUBKEY_LEN]);

/* WHO `key` IS NOW: the newest key reached from it by counting successions,
 * into `out` -- `key` itself when nothing succeeds it. 0, writing nothing,
 * when the way forks, or runs past FZN_SUCCESSION_DEPTH_MAX -- which a cycle
 * always does. */
int fzn_succession_resolve(const fzn_succession_set_t *set,
                           const fzn_revocation_store_t *revocations,
                           const uint8_t root[FZN_PUBKEY_LEN],
                           const uint8_t key[FZN_PUBKEY_LEN], uint8_t out[FZN_PUBKEY_LEN]);

#endif /* FZN_SUCCESSION_H */
