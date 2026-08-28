#ifndef FZN_AGREE_H
#define FZN_AGREE_H

/*
 * Key agreement, as a seam.
 *
 * THE FOURTH VTABLE, AND UNTIL NOW THE MISSING ONE. This library had sign,
 * hash, AEAD and entropy, and no way for two hosts to arrive at a shared
 * secret. `prekey/prekey.h` publishes a 32-byte key described as the one that
 * "agrees" -- and nothing agreed. That gap is why `session/commitment.h`
 * could say "the transcript is the caller's" without anybody noticing the
 * transcript had nothing to put in it.
 *
 * WHAT IT IS FOR. project.md sec 4.5: a session's root is derived from a
 * transcript, and forward secrecy depends entirely on that transcript
 * containing material that can be DELETED. A long-term identity key cannot
 * be deleted -- it is the thing that makes a host itself -- so an agreement
 * over deletable keys is the only way to get such material in. Without this
 * seam every session key is recomputable by anybody who later obtains the
 * identity secret, and no arrangement of the layers above can fix it.
 *
 * X25519-SHAPED, and named for the operation rather than the algorithm. A
 * 32-byte secret, a 32-byte public key, a 32-byte shared output: that is the
 * shape of X25519, of X448 with different lengths, and of nothing this
 * project is likely to want that does not fit it. A post-quantum KEM does
 * NOT fit -- its encapsulation is not symmetric and its ciphertext travels --
 * so if that day comes it gets its own seam rather than this one widened.
 * Said here so the decision is visible rather than discovered.
 *
 * IT RETURNS A STATUS, WHICH X25519 IMPLEMENTATIONS OFTEN DO NOT. A peer can
 * send a public key of low order, for which the shared secret is a fixed
 * value every attacker knows. Monocypher's `crypto_x25519` reports that and
 * this seam propagates it, because a shared secret that is a constant is
 * exactly the case where continuing looks like working.
 */

#include <stdint.h>

#define FZN_AGREE_SECRET_LEN 32u
#define FZN_AGREE_PUBLIC_LEN 32u
#define FZN_AGREE_SHARED_LEN 32u

typedef struct fzn_agree_ops {
	/*
	 * The public key for a secret. Non-zero on success.
	 *
	 * Separate from generation because a caller that persists a secret --
	 * which a rotating prekey must -- needs to recover its public half
	 * after a restart without keeping a second copy that can disagree
	 * with it.
	 */
	int (*public_of)(void *ctx, uint8_t public_out[FZN_AGREE_PUBLIC_LEN],
	                 const uint8_t secret[FZN_AGREE_SECRET_LEN]);
	/*
	 * The shared secret. Non-zero on success.
	 *
	 * MUST RETURN ZERO for a peer public key with no contributory
	 * behaviour -- a low-order point, whose shared secret is a value the
	 * attacker chose. A binding that cannot detect it must say so rather
	 * than return a constant, because the caller's next act is to derive
	 * a session key from it.
	 */
	int (*agree)(void *ctx, uint8_t shared_out[FZN_AGREE_SHARED_LEN],
	             const uint8_t secret[FZN_AGREE_SECRET_LEN],
	             const uint8_t peer_public[FZN_AGREE_PUBLIC_LEN]);
	void *ctx;
} fzn_agree_ops_t;

/*
 * A secret with a rotation discipline.
 *
 * WHY THIS IS A TYPE RATHER THAN A `uint8_t[32]`. Forward secrecy here is
 * bounded by the rotation window and by nothing else: a compromised host
 * discloses everything back to the last rotation, and past that only if the
 * previous secret was GENUINELY DELETED. "Delete the old one" held by a
 * comment lasts until the first caller who keeps a backup for debugging.
 *
 * So rotation is an operation on this type and it wipes as it goes, and
 * there is no accessor that hands the secret out -- the ops above take it by
 * const pointer from inside. A caller that wants a copy has to write the
 * memcpy itself and can be seen doing it.
 *
 * `generation` counts rotations. It is not a clock and it is not on the
 * wire; it is here so that a caller can tell whether the secret it holds is
 * the one a stored public key belongs to, which is the mistake that makes a
 * rotation look like a corruption.
 */
typedef struct fzn_agree_secret {
	uint8_t secret[FZN_AGREE_SECRET_LEN];
	uint8_t public_key[FZN_AGREE_PUBLIC_LEN];
	uint64_t generation;
	/* Zero until a secret is installed. Not a redundant flag: an all-zero
	 * secret is a real 32-byte value a caller can hand over by accident,
	 * and it must not read as "ready". */
	int live;
} fzn_agree_secret_t;

typedef enum fzn_agree_err {
	FZN_AGREE_OK = 0,
	FZN_AGREE_ERR_MALFORMED,
	/* The ops refused or were absent. */
	FZN_AGREE_ERR_OPS,
	/* The peer's public key produced no contributory shared secret. A
	 * peer's bytes, expected, and refused rather than used. */
	FZN_AGREE_ERR_DEGENERATE,
	/* The secret has not been installed, or has been wiped. */
	FZN_AGREE_ERR_ABSENT,
} fzn_agree_err_t;

const char *fzn_agree_err_str(fzn_agree_err_t err);

/*
 * Installs a secret, deriving and keeping its public half.
 *
 * ROTATES IF ONE IS ALREADY THERE: the previous secret is wiped before the
 * new one is written, and `generation` advances. There is no way to install
 * a second secret while keeping the first, which is the discipline this type
 * exists for.
 *
 * The bytes come from the caller rather than from `session/random.h`, so
 * that a host restoring a persisted prekey and a host minting a fresh one
 * use the same path. A caller minting one fills the buffer from
 * `fzn_random_fill` and wipes its own copy.
 */
fzn_agree_err_t fzn_agree_secret_install(fzn_agree_secret_t *sk, const fzn_agree_ops_t *ops,
                                          const uint8_t secret[FZN_AGREE_SECRET_LEN]);

/* The public half, to publish in a prekey record. NULL if none is installed
 * -- the same shape `fzn_trust_root` uses, and for the same reason: an
 * absent key must not read as a key of zeroes. */
const uint8_t *fzn_agree_secret_public(const fzn_agree_secret_t *sk);

uint64_t fzn_agree_secret_generation(const fzn_agree_secret_t *sk);

/* Agrees with a peer's public key. The secret never leaves the struct. */
fzn_agree_err_t fzn_agree_shared(const fzn_agree_secret_t *sk, const fzn_agree_ops_t *ops,
                                  const uint8_t peer_public[FZN_AGREE_PUBLIC_LEN],
                                  uint8_t shared_out[FZN_AGREE_SHARED_LEN]);

/*
 * Forgets the secret.
 *
 * THIS IS THE FUNCTION THAT BUYS THE FORWARD SECRECY, and it is worth saying
 * plainly: everything sealed under a session derived from this secret becomes
 * unrecoverable at this call and not before. A host that rotates without
 * wiping has the property in its documentation and not in its memory.
 */
void fzn_agree_secret_wipe(fzn_agree_secret_t *sk);

#endif /* FZN_AGREE_H */
