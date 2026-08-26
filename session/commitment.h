/* The key schedule that makes the AEAD key-committing.
 *
 * project.md sec 4.4a says key-committing AEAD is "not optional", and
 * XChaCha20-Poly1305 is not key-committing on its own: a ciphertext can be
 * made to open under two different keys, so one frame can mean two things
 * to two recipients and an attacker who controls one of those keys chooses
 * what the other sees.
 *
 * sec 4.5 settles the construction, and it is the one fuzzypickles ships
 * and this family has reviewed: **derive 48 bytes from ONE hash over the
 * key transcript -- 32 for the AEAD key and 16 for a commitment -- and
 * carry the commitment in the frame.** wire/frame.situ now has the field,
 * in the authenticated header so a receiver can check it before spending a
 * decryption.
 *
 * WHY ONE HASH AND NOT TWO. Deriving the key and the commitment from the
 * same invocation over the same input is what BINDS them: the commitment is
 * a function of exactly the material the key is a function of, so producing
 * a second key that matches a given commitment means finding a second
 * preimage. Two separate derivations, however carefully labelled, would
 * leave a gap for an implementation to feed them different inputs -- and
 * that implementation would still pass every test that checked only that
 * the commitment matched.
 *
 * THE TRANSCRIPT IS THE CALLER'S, which is the same boundary chain.h draws
 * for a signed region. What goes into it -- which keys, in what order -- is
 * a protocol decision that depends on the session model, and sec 4.5's
 * prekey half is not settled. This module hashes what it is handed and
 * splits the result. It does not decide what is worth hashing, and the
 * consequence is that two peers who disagree about the transcript derive
 * different keys and fail to talk rather than talking insecurely.
 *
 * NOT the AEAD itself. The extern codec that situ's `sealed()` region calls
 * is still unwritten, because its calling convention is not yet knowable --
 * see sec 4.5. This is the half that does not depend on it.
 */

#ifndef FZN_COMMITMENT_H
#define FZN_COMMITMENT_H

#include <stddef.h>
#include <stdint.h>

#define FZN_AEAD_KEY_LEN 32
#define FZN_COMMITMENT_LEN 16
/* What one derivation produces, and the reason the two constants above are
 * never used to size a hash separately. */
#define FZN_DERIVED_LEN (FZN_AEAD_KEY_LEN + FZN_COMMITMENT_LEN)

typedef enum fzn_commitment_err {
	FZN_COMMITMENT_OK = 0,
	FZN_COMMITMENT_ERR_MALFORMED = -1,
	/* The hash implementation refused or is absent. */
	FZN_COMMITMENT_ERR_HASH = -2,
	/* The commitment in the frame does not match the one derived from the
	 * key material. The frame is for somebody else, or somebody is trying
	 * to make it mean two things. Refuse without decrypting. */
	FZN_COMMITMENT_ERR_MISMATCH = -3,
} fzn_commitment_err_t;

/* The hash seam, matching the signer seam in chain.h and for the same
 * reasons: sec 4.5 vendors Monocypher once and binds it as an extern rather
 * than wrapping it, and a function pointer is what lets every path here be
 * tested before anything is vendored.
 *
 * `hash` must produce `out_len` bytes over `in`, for any `out_len` up to
 * FZN_DERIVED_LEN. BLAKE2b takes an output length directly, which is why
 * the construction is expressible as one call.
 *
 * `hash` RETURNS NONZERO ON SUCCESS AND ZERO ON FAILURE, matching `verify`
 * in chain.h and `fill` in random.h rather than the 0-means-success
 * convention of much of C.
 *
 * Stated because the cost of guessing it wrong falls entirely on this
 * module and is silent. `fzn_commitment_derive` branches on `!hash->hash(...)`
 * and, on the success path, copies FZN_AEAD_KEY_LEN bytes out of a stack
 * buffer it never initialises. An implementation returning 0 for success is
 * therefore read as having failed -- which is the harmless direction -- but
 * one returning 0 for FAILURE is read as success, and the caller is handed
 * whatever was on the stack as an AEAD key. Nothing downstream can tell that
 * from a real key: it encrypts, it commits, and it is guessable.
 *
 * Every other seam in this library says which way round it is. This one did
 * not, and a vendored hash is exactly the code most likely to be written by
 * someone reading only this declaration. */
typedef struct fzn_hash_ops {
	int (*hash)(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len);
	void *ctx;
} fzn_hash_ops_t;

/* Derive the AEAD key and its commitment from one hash over `transcript`.
 *
 * A domain label is prepended, so the same transcript bytes used for
 * anything else in this protocol cannot collide with this derivation. It is
 * prepended here rather than left to the caller because a label the caller
 * supplies is a label the caller can forget, and forgetting it produces
 * something that works perfectly until the day two uses overlap.
 *
 * Both outputs are written or neither is. On any failure the caller's
 * buffers are left alone, so a refused derivation cannot leave half a key
 * somewhere a later line will use. */
fzn_commitment_err_t fzn_commitment_derive(const fzn_hash_ops_t *hash,
                                            const uint8_t *transcript, size_t transcript_len,
                                            uint8_t key_out[FZN_AEAD_KEY_LEN],
                                            uint8_t commitment_out[FZN_COMMITMENT_LEN]);

/* Check a frame's commitment against a derived one, in constant time.
 *
 * Constant time because the received half is an ATTACKER'S and the derived
 * half is a function of the key: a comparison that returned at the first
 * differing byte would turn "how long did that take" into "how many leading
 * bytes of the derived commitment did I guess", which is a key-material
 * oracle offered for free. This is one of the comparisons sec 4.4a means.
 *
 * Returns FZN_COMMITMENT_OK on a match and FZN_COMMITMENT_ERR_MISMATCH
 * otherwise, rather than a bare int, so that a caller writing
 * `if (fzn_commitment_check(...))` gets a compile-time type rather than an
 * inverted test that always passes. */
fzn_commitment_err_t fzn_commitment_check(const uint8_t derived[FZN_COMMITMENT_LEN],
                                           const uint8_t received[FZN_COMMITMENT_LEN]);

/* A short name for `fzn_commitment_err_t`, for a log line or a message to a user.
 *
 * NEVER NULL, including for a value that is not one of the enumerators, so
 * that a caller may pass the result straight to a printf without a check.
 * An unrecognised value renders as "unknown", which is deliberately not any
 * real code's text -- a caller that cannot tell "we do not know" from a
 * genuine answer is the failure this whole library is careful about
 * elsewhere.
 *
 * The strings are lowercase, carry no trailing punctuation and name the
 * condition rather than restating the constant, on the same reasoning as
 * strerror: the caller supplies the sentence, this supplies the noun. */
const char *fzn_commitment_err_str(fzn_commitment_err_t err);

#endif /* FZN_COMMITMENT_H */
