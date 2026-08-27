/* The key schedule that makes the AEAD key-committing -- and that keeps the
 * commitment from naming the pair of peers who produced it.
 *
 * project.md sec 4.4a says key-committing AEAD is "not optional", and
 * XChaCha20-Poly1305 is not key-committing on its own: a ciphertext can be
 * made to open under two different keys, so one frame can mean two things
 * to two recipients and an attacker who controls one of those keys chooses
 * what the other sees.
 *
 * sec 4.5 settles the construction, and it is the one fuzzypickles ships
 * and this family has reviewed: derive the AEAD key and a commitment from
 * ONE hash over the key transcript, and carry the commitment in the frame.
 * wire/frame.situ has the field, in the authenticated header so a receiver
 * can check it before spending a decryption.
 *
 * THE COMMITMENT WAS A CONSTANT PER PAIR, IN THE CLEAR, ON EVERY DATAGRAM,
 * AND THAT IS THE SOCIAL GRAPH. This is the finding the file was rewritten
 * for, and it is worth stating as the failure rather than as a parameter
 * choice. The commitment used to be the 16-byte tail of one hash over the
 * transcript, and nothing else. The transcript is long-lived material --
 * sim/test/network_test.c models what the design intends, "a key and its
 * commitment per (sender, receiver) pair" -- so those 16 bytes were a
 * stable identifier for the pair, sitting in the cleartext head beside
 * `sender[32]`. Anyone on the path, including a relay, which sec 3 makes an
 * unprivileged bridge that handles frames it is not trusted to author,
 * reads the two together and learns who talks to whom, and for how long,
 * without opening anything.
 *
 * That also defeats the reason `capability[32]` was moved INSIDE the seal.
 * sec 13: "in the clear it announces which authority is being exercised, so
 * the frames worth attacking identify themselves." The same argument
 * applies to any per-pair constant in the head, and it had never been made
 * about this one.
 *
 * THE FIX COSTS ZERO WIRE BYTES: derive the key from the transcript, and
 * the commitment from the transcript AND THE NONCE. The nonce is already in
 * the head and already unique per frame, so the commitment becomes
 * unlinkable across frames while staying checkable before decryption --
 * which is the whole of what sec 4.7 step 3 needs from it.
 *
 * SO THERE ARE TWO DERIVATIONS NOW, AND WHERE THE SEAM FALLS IS THE DESIGN:
 *
 *   1. `fzn_commitment_derive_root` -- ONE hash over the transcript
 *      producing 64 bytes, split into the 32-byte AEAD key and a 32-byte
 *      COMMITMENT KEY. Long-lived, per peer, and IT TAKES NO NONCE.
 *   2. `fzn_commitment_for_nonce` -- one hash over the commitment key and
 *      one frame's nonce, producing that frame's 16-byte commitment. Per
 *      frame, per candidate key, and it cannot see the transcript.
 *
 * WHAT STILL BINDS THE KEY. The old comment here argued that one hash over
 * one input is what makes the commitment BIND the key rather than merely
 * accompany it, and that argument survives intact, one level up: the AEAD
 * key and the commitment key are the two halves of a single hash over a
 * single input, so producing a second AEAD key whose frames carry a given
 * commitment still means finding a second preimage of that hash. The nonce
 * is mixed in on top of material that is already bound, and it is public,
 * so it hands an attacker nothing they did not have. The wire budget is 16
 * bytes either way.
 *
 * TWO SHAPES THAT LOOK CHEAPER AND ARE NOT, recorded so they are not
 * proposed again:
 *
 *   - **Commit to the AEAD key directly**, `H(label | key | nonce)`, and
 *     keep no commitment key. That publishes a 16-byte image of the AEAD
 *     key on every datagram, which is an oracle handed to a key-recovery
 *     attacker for the sake of 32 bytes of session state. The commitment
 *     key exists so that the key itself is never an input to anything that
 *     travels.
 *   - **Commit to the transcript directly**, `H(label | transcript |
 *     nonce)`. Correct, and it makes the per-frame cost a hash over the
 *     whole transcript -- up to FZN_TRANSCRIPT_MAX in commitment.c, which
 *     is several BLAKE2b blocks -- multiplied by the number of candidate
 *     keys, on every arriving datagram. It also obliges a receiver to keep
 *     every peer's transcript alive for the life of the session, which is
 *     more secret material with a longer life than the key it derived.
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
/* The second half of the root derivation. Never transmitted, and never an
 * argument to the AEAD: its only use is as the keyed prefix of the
 * per-frame hash below, which is what stops the AEAD key from being the
 * thing every datagram publishes an image of. 32 rather than 16 because it
 * is a hash input rather than a wire field, so nothing is paying for the
 * extra bytes. */
#define FZN_COMMITMENT_KEY_LEN 32
#define FZN_COMMITMENT_LEN 16
/* The AEAD nonce, which the per-frame derivation reads.
 *
 * Stated here rather than included from session/aead.h because aead.h
 * includes THIS header for FZN_AEAD_KEY_LEN, and a cycle between the two
 * would leave whichever was included first using a constant not yet
 * defined. commitment.c asserts at compile time that the two agree, so a
 * future AEAD with a different nonce length breaks the build rather than
 * leaving this reading 24 bytes out of a shorter buffer. */
#define FZN_COMMITMENT_NONCE_LEN 24
/* What the ROOT derivation produces, and the reason the two key constants
 * above are never used to size a hash separately.
 *
 * 64 is also BLAKE2b's largest digest, so the root derivation now sits
 * exactly on the primitive's ceiling: anything further that wanted to come
 * out of it needs a second call with its own label, not a bigger number
 * here. */
#define FZN_DERIVED_LEN (FZN_AEAD_KEY_LEN + FZN_COMMITMENT_KEY_LEN)

typedef enum fzn_commitment_err {
	FZN_COMMITMENT_OK = 0,
	FZN_COMMITMENT_ERR_MALFORMED = -1,
	/* The hash implementation refused or is absent. */
	FZN_COMMITMENT_ERR_HASH = -2,
	/* The commitment in the frame does not match the one derived from the
	 * key material and that frame's nonce. The frame is for somebody else,
	 * or somebody is trying to make it mean two things. Refuse without
	 * decrypting. */
	FZN_COMMITMENT_ERR_MISMATCH = -3,
} fzn_commitment_err_t;

/* The hash seam, matching the signer seam in chain.h and for the same
 * reasons: sec 4.5 vendors Monocypher once and binds it as an extern rather
 * than wrapping it, and a function pointer is what lets every path here be
 * tested before anything is vendored.
 *
 * `hash` must produce `out_len` bytes over `in`, for any `out_len` up to
 * FZN_DERIVED_LEN. BLAKE2b takes an output length directly, which is why
 * each of the two derivations below is one call rather than a construction.
 *
 * `hash` RETURNS NONZERO ON SUCCESS AND ZERO ON FAILURE, matching `verify`
 * in chain.h and `fill` in random.h rather than the 0-means-success
 * convention of much of C.
 *
 * Stated because the cost of guessing it wrong falls entirely on this
 * module and is silent. Each derivation branches on `!hash->hash(...)` and,
 * on the success path, copies bytes out of a stack buffer it never
 * initialises. An implementation returning 0 for success is therefore read
 * as having FAILED, which is the harmless direction -- a good hash is
 * refused. The dangerous one is an implementation that returns NONZERO on
 * failure: `!nonzero` is false, so the refusal is read as success and the
 * caller is handed whatever was on the stack as an AEAD key. Nothing
 * downstream can tell that from a real key: it encrypts, it commits, and it
 * is guessable.
 *
 * Every other seam in this library says which way round it is. This one did
 * not, and a vendored hash is exactly the code most likely to be written by
 * someone reading only this declaration. */
typedef struct fzn_hash_ops {
	int (*hash)(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len);
	void *ctx;
} fzn_hash_ops_t;

/* Derive the AEAD key and the commitment key from one hash over `transcript`.
 *
 * THIS FUNCTION TAKES NO NONCE, AND THAT IS THE POINT RATHER THAN AN
 * OMISSION. Two peers must arrive at the same AEAD key without having seen
 * each other's nonces: a receiver holds the sender's nonce and the sender
 * has never seen the receiver's, and before a session's first frame neither
 * has any nonce at all. A key that varied per frame would be a different
 * design, and it would need the nonce BEFORE the key, which is not an order
 * the receive path can offer -- sec 4.7 selects a key at step 2 in order to
 * decide anything about the frame whose nonce it would need.
 *
 * So the nonce is absent from this signature deliberately, so that the
 * mistake cannot be made without editing the declaration. IF YOU ARE HERE
 * TO ADD ONE, THIS IS THE PARAGRAPH THAT SAYS NOT TO. It belongs in
 * `fzn_commitment_for_nonce`, which is where it already is.
 *
 * A domain label is prepended, so the same transcript bytes used for
 * anything else in this protocol cannot collide with this derivation. It is
 * prepended here rather than left to the caller because a label the caller
 * supplies is a label the caller can forget, and forgetting it produces
 * something that works perfectly until the day two uses overlap.
 *
 * WHAT TO CACHE, because this is the half whose cost is worth avoiding.
 * Both outputs are per peer and stable for the life of the session: derive
 * them ONCE when the session is established and keep both. `key_out` is the
 * AEAD key. `commitment_key_out` is the only thing
 * `fzn_commitment_for_nonce` needs, so a receiver may forget the transcript
 * as soon as this returns -- which is the shorter life for the more
 * dangerous material, and worth taking. Both outputs are secret and both
 * want `fzn_wipe` (constant_time.h) when the session ends.
 *
 * Both outputs are written or neither is. On any failure the caller's
 * buffers are left alone, so a refused derivation cannot leave half a key
 * somewhere a later line will use.
 *
 * THE NAME CHANGED FROM `fzn_commitment_derive` ON PURPOSE. That function's
 * fourth argument was a 16-byte commitment and this one's is a 32-byte
 * commitment key; C would have let every existing caller keep compiling and
 * overrun a 16-byte buffer by 16 bytes, because an array parameter is a
 * pointer and nothing checks the extent. Renaming turns a silent stack
 * overflow into a compile error at every call site, which is the loud
 * failure and the only one available here. */
fzn_commitment_err_t fzn_commitment_derive_root(const fzn_hash_ops_t *hash,
                                                 const uint8_t *transcript, size_t transcript_len,
                                                 uint8_t key_out[FZN_AEAD_KEY_LEN],
                                                 uint8_t commitment_key_out[FZN_COMMITMENT_KEY_LEN]);

/* Derive one frame's commitment from the commitment key and that frame's
 * nonce.
 *
 * PER FRAME, NOT PER PEER, AND THAT IS A CHANGE IN WHEN DERIVATION HAPPENS.
 * A consumer used to derive a commitment once per peer and keep the pair
 * beside the key; there is nothing to keep now, because the answer differs
 * for every datagram. A sender calls this after drawing the nonce and
 * before filling the head -- so a send path that draws its own nonce must
 * either derive the commitment itself or hand the nonce back. A receiver
 * calls it once per candidate key, on the nonce the frame arrived with.
 *
 * THERE IS NO INTERMEDIATE TO CACHE BELOW THE COMMITMENT KEY, and that is
 * arithmetic rather than an assumption: the hashed input is 16 bytes of
 * label, 32 of commitment key and 24 of nonce, which is 72 -- inside
 * BLAKE2b's 128-byte block, so no compression has run before the nonce is
 * absorbed. There is no partial state predating the nonce, and therefore
 * nothing a caller could hold onto even if the seam exposed it. Cache the
 * commitment key; recompute this.
 *
 * IT REMOVES AN ADDRESSING SHORTCUT, AND THAT SHORTCUT WAS THE LEAK.
 * wire/relay.h says "a receiver knows a frame is its own because the key
 * commitment matches a key it derived, which is addressing by decryption."
 * That still holds, but a receiver holding K candidate keys can no longer
 * index a table BY the commitment, because the commitment is no longer a
 * property of the key alone. It computes K commitments for the frame's
 * nonce and compares each. A table keyed by a per-pair constant is exactly
 * the structure whose existence proves the constant is a per-pair
 * identifier: losing it is the same fact seen from the receiver's side, and
 * an observer's table would have been no harder to build than ours.
 *
 * WHAT THAT COSTS, measured rather than guessed, at -Os against Monocypher's
 * BLAKE2b and XChaCha20-Poly1305 on a 3.07 GHz Westmere Xeon:
 *
 *     fzn_commitment_for_nonce                          560 ns
 *     fzn_commitment_check                               47 ns
 *     AEAD open, 64-byte payload, tag rejected         1260 ns
 *     AEAD open, 1024-byte payload, tag rejected       2120 ns
 *     fzn_commitment_derive_root, 240-byte transcript  1270 ns
 *
 * Minimum of fifty 2000-call batches, because the machine carried a load
 * average in the tens and a mean would have been measuring the other
 * tenants. So each figure is an UPPER BOUND on the real cost, which is the
 * safe direction for the argument below.
 *
 * So sec 4.7 step 3 costs about 610 ns per candidate key where it used to
 * cost a table lookup. The saving it was put before the tag for survives,
 * and is smaller than the phrase "far cheaper" suggests: K candidates cost
 * 610K ns here against 2120K ns of AEAD, about 3.5 times, and only about
 * 2 times on a small frame, since the AEAD's cost falls with the payload
 * and this one does not. The ratio is bounded by BLAKE2b over 72 bytes
 * against Poly1305 over the whole datagram, and that is the whole of it --
 * anyone reasoning about a large K should use these numbers rather than an
 * intuition about hashes being free. A receiver with 100 candidate keys
 * spends about 61 microseconds deciding a frame is not for it, against
 * about 212 microseconds if it had to try the AEAD instead.
 *
 * A caller that wants a table back can have one, keyed by `sender` -- which
 * is in the head already and is a per-peer constant this change does not
 * pretend to hide. That reduces K to the keys held for one sender, and it
 * is the consumer's decision rather than this library's, because only the
 * consumer knows whether its peers are identified by host key or by
 * something coarser.
 *
 * Written or not written: on any failure `commitment_out` is left alone. */
fzn_commitment_err_t fzn_commitment_for_nonce(const fzn_hash_ops_t *hash,
                                               const uint8_t commitment_key[FZN_COMMITMENT_KEY_LEN],
                                               const uint8_t nonce[FZN_COMMITMENT_NONCE_LEN],
                                               uint8_t commitment_out[FZN_COMMITMENT_LEN]);

/* Check a frame's commitment against a derived one, in constant time.
 *
 * Constant time because the received half is an ATTACKER'S and the derived
 * half is a function of the key: a comparison that returned at the first
 * differing byte would turn "how long did that take" into "how many leading
 * bytes of the derived commitment did I guess", which is a key-material
 * oracle offered for free. This is one of the comparisons sec 4.4a means.
 *
 * STILL CONSTANT TIME NOW THE COMMITMENT IS PER FRAME, and the reason has
 * narrowed rather than gone away. One frame's commitment is a one-shot
 * target, so guessing it byte by byte buys an attacker that one frame. But
 * the commitment key behind it is long-lived and every frame of the session
 * is another query against it, so a byte-at-a-time oracle taken over enough
 * frames is a search over that key rather than over one commitment.
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
