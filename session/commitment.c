/* See commitment.h. */

#include "commitment.h"

/* For FZN_AEAD_NONCE_LEN, and for nothing else. commitment.h cannot include
 * this -- aead.h includes commitment.h for FZN_AEAD_KEY_LEN, so the cycle
 * would leave whichever came first using a constant not yet defined -- but
 * a .c file may, and the assertion below is worth the include.
 *
 * WHAT IT GUARDS IS AN OUT-OF-BOUNDS READ, not a mismatch. If a future AEAD
 * brought a shorter nonce and only aead.h were updated,
 * `fzn_commitment_for_nonce` would go on copying FZN_COMMITMENT_NONCE_LEN
 * bytes out of a caller's shorter buffer, and the two peers would still
 * agree with each other -- so nothing would fail, and the read past the end
 * would be found by a sanitizer or by nobody. */
#include "aead.h"

#include "../constant_time/constant_time.h"

#include <string.h>

_Static_assert(FZN_COMMITMENT_NONCE_LEN == FZN_AEAD_NONCE_LEN,
               "the commitment's nonce length has drifted from the AEAD's");

/* Domain separation, and there are two labels because there are two
 * derivations.
 *
 * Sixteen bytes each, fixed, and prepended to whatever the derivation
 * hashes so that the same bytes used for any other purpose in this protocol
 * cannot derive the same key.
 *
 * The version digit is in the label deliberately. If a derivation's shape
 * ever changes, changing its label makes old and new peers derive different
 * keys and fail to talk -- which is the correct failure, and much better
 * than two peers agreeing on a key by hashing different things and
 * discovering it later. That is why the root label says v2: it produced 48
 * bytes and now produces 64, and a peer built before this change must not
 * appear to agree with one built after.
 *
 * WHAT STOPS THE TWO DERIVATIONS PRODUCING THE SAME BYTES. Every input to
 * the root derivation begins with FZN_ROOT_LABEL and every input to the
 * per-frame derivation begins with FZN_BIND_LABEL, both at offset zero and
 * both the same length, so no input to one can equal any input to the
 * other. The lengths being equal is what makes that a one-line argument
 * rather than a case analysis, and it is asserted below.
 *
 * IT IS NOT AN ABSTRACT COLLISION. Without the labels the root hashes
 * `transcript` and the per-frame hash hashes `commitment_key | nonce`, 56
 * bytes -- so a peer persuaded to use a 56-byte transcript equal to some
 * pair's commitment key and nonce would derive an AEAD KEY whose first 16
 * bytes are exactly that pair's published commitment. The frame header
 * would be publishing key material. session/test/commitment_test.c builds
 * that transcript and checks the collision does not happen; delete either
 * label and it does. */
static const char FZN_ROOT_LABEL[16] = "fuzznet-kdf-v2\0\0";
static const char FZN_BIND_LABEL[16] = "fuzznet-bind-v1\0";

_Static_assert(sizeof(FZN_ROOT_LABEL) == sizeof(FZN_BIND_LABEL),
               "the two domain labels must be one length, or their inputs can overlap");

/* The largest transcript this will hash in one pass, and therefore the
 * largest stack buffer it needs.
 *
 * Bounded rather than allocated: nothing in this library allocates, and a
 * transcript is key material whose size is a protocol constant rather than
 * something a stranger chooses. 512 is far above the seven public keys
 * fuzzypickles' equivalent hashes and leaves room for a session model that
 * is not settled yet. */
#define FZN_TRANSCRIPT_MAX 512

fzn_commitment_err_t fzn_commitment_derive_root(const fzn_hash_ops_t *hash,
                                                 const uint8_t *transcript, size_t transcript_len,
                                                 uint8_t key_out[FZN_AEAD_KEY_LEN],
                                                 uint8_t commitment_key_out[FZN_COMMITMENT_KEY_LEN])
{
	uint8_t input[sizeof(FZN_ROOT_LABEL) + FZN_TRANSCRIPT_MAX];
	uint8_t derived[FZN_DERIVED_LEN];
	fzn_commitment_err_t err = FZN_COMMITMENT_OK;

	if (!hash || !hash->hash || !transcript || !key_out || !commitment_key_out)
		return FZN_COMMITMENT_ERR_MALFORMED;
	if (transcript_len == 0 || transcript_len > FZN_TRANSCRIPT_MAX)
		return FZN_COMMITMENT_ERR_MALFORMED;

	memcpy(input, FZN_ROOT_LABEL, sizeof(FZN_ROOT_LABEL));
	memcpy(input + sizeof(FZN_ROOT_LABEL), transcript, transcript_len);

	/* NOTHING ELSE GOES INTO THIS INPUT, and a nonce least of all. Both
	 * peers must reach the same key having seen different nonces, or none
	 * yet -- see commitment.h, which says it at length because this is the
	 * line somebody extends. The per-frame material is
	 * `fzn_commitment_for_nonce`'s, below.
	 *
	 * ONE call, producing both halves. Deriving them separately would
	 * leave the commitment merely accompanying the key rather than binding
	 * it: it is the shared input that makes a second key matching a given
	 * commitment a second-preimage problem. */
	if (!hash->hash(hash->ctx, derived, sizeof(derived), input,
	                sizeof(FZN_ROOT_LABEL) + transcript_len)) {
		err = FZN_COMMITMENT_ERR_HASH;
		goto out;
	}

	/* Written only once the hash has succeeded, so a refused derivation
	 * cannot leave half a key in a buffer a later line will use. */
	memcpy(key_out, derived, FZN_AEAD_KEY_LEN);
	memcpy(commitment_key_out, derived + FZN_AEAD_KEY_LEN, FZN_COMMITMENT_KEY_LEN);

out:
	/* The intermediates are key material, erased through the library's own
	 * wipe (constant_time.h) rather than a memset here.
	 *
	 * IT USED TO BE TWO LOOPS IN THIS FUNCTION, each with a `volatile`
	 * pointer, and the comment explained that the qualifier was what
	 * stopped the compiler deleting a write to something never read again.
	 * That was true and was measured: 411 bytes of text with it, 337
	 * without, so 74 bytes of erasure removed at -Os.
	 *
	 * WHAT CHANGED IS THE STRUCTURE, not the reasoning. Behind a call into
	 * another translation unit the compiler cannot see that these buffers
	 * are dead, so it may not remove the stores at all -- measured, the
	 * same function without `volatile` still writes once it is out here.
	 * The hazard the old comment described was a property of the wipe
	 * being INLINE, and moving it out removes the hazard rather than
	 * guarding against it. `fzn_wipe` keeps the qualifier anyway, for
	 * link-time optimisation.
	 *
	 * A consumer needed this function regardless: it derives a key for
	 * them and had no way for them to erase it. See constant_time.h.
	 *
	 * `input` is wiped in full rather than only the `transcript_len` bytes
	 * that were used. Wiping what was written would be enough and would be
	 * a bound to get wrong later; this cannot be. */
	fzn_wipe(derived, sizeof(derived));
	fzn_wipe(input, sizeof(input));

	return err;
}

fzn_commitment_err_t fzn_commitment_for_nonce(const fzn_hash_ops_t *hash,
                                               const uint8_t commitment_key[FZN_COMMITMENT_KEY_LEN],
                                               const uint8_t nonce[FZN_COMMITMENT_NONCE_LEN],
                                               uint8_t commitment_out[FZN_COMMITMENT_LEN])
{
	uint8_t input[sizeof(FZN_BIND_LABEL) + FZN_COMMITMENT_KEY_LEN + FZN_COMMITMENT_NONCE_LEN];
	uint8_t derived[FZN_COMMITMENT_LEN];
	fzn_commitment_err_t err = FZN_COMMITMENT_OK;

	if (!hash || !hash->hash || !commitment_key || !nonce || !commitment_out)
		return FZN_COMMITMENT_ERR_MALFORMED;

	/* THE NONCE IS THE WHOLE OF THIS FUNCTION'S REASON TO EXIST. Without
	 * it the answer would be a constant per pair, which is what
	 * commitment.h's opening paragraphs are about: 16 stable bytes beside
	 * `sender[32]` in a cleartext head, and the social graph readable by
	 * anyone who forwards a datagram.
	 *
	 * There is no length argument because there is no length choice: the
	 * input is exactly label, commitment key and nonce, all fixed. A
	 * variable-length input here would need its own length encoding to
	 * stay unambiguous, and nothing wants one. */
	memcpy(input, FZN_BIND_LABEL, sizeof(FZN_BIND_LABEL));
	memcpy(input + sizeof(FZN_BIND_LABEL), commitment_key, FZN_COMMITMENT_KEY_LEN);
	memcpy(input + sizeof(FZN_BIND_LABEL) + FZN_COMMITMENT_KEY_LEN, nonce,
	       FZN_COMMITMENT_NONCE_LEN);

	/* Into a temporary and copied out on success, for the same reason the
	 * root derivation does it: a hash that refuses part-way must leave the
	 * caller's buffer as it found it, and a caller that ignored the return
	 * value would otherwise put a half-written commitment in a frame
	 * header and never hear from the peer again. */
	if (!hash->hash(hash->ctx, derived, sizeof(derived), input, sizeof(input))) {
		err = FZN_COMMITMENT_ERR_HASH;
		goto out;
	}

	memcpy(commitment_out, derived, FZN_COMMITMENT_LEN);

out:
	/* `input` holds the commitment key and is wiped. `derived` is NOT, and
	 * the asymmetry is deliberate rather than an oversight: the commitment
	 * is about to be written into a cleartext frame header and read by
	 * everyone on the path, so erasing a stack copy of it would be ritual.
	 * constant_time.h makes the same point from the other side about which
	 * comparisons are load-bearing -- reaching for the careful thing
	 * everywhere is how it stops being possible to see which uses matter. */
	fzn_wipe(input, sizeof(input));

	return err;
}

fzn_commitment_err_t fzn_commitment_check(const uint8_t derived[FZN_COMMITMENT_LEN],
                                           const uint8_t received[FZN_COMMITMENT_LEN])
{
	if (!derived || !received)
		return FZN_COMMITMENT_ERR_MALFORMED;

	return fzn_ct_memeq(derived, received, FZN_COMMITMENT_LEN) ? FZN_COMMITMENT_OK
	                                                           : FZN_COMMITMENT_ERR_MISMATCH;
}

/* See commitment.h.
 *
 * NO `default:` LABEL, and that is the mechanism rather than an oversight.
 * `-Wswitch` -- which `-Wall` turns on -- warns about an enumerated switch
 * that omits a case only when there is no default, so leaving it out is what
 * makes the compiler notice a code added to fzn_commitment_err_t and not rendered here. A
 * default would silence exactly the warning worth having and turn a new code
 * into a silent "unknown" in somebody's log.
 *
 * The fallback then lives after the switch, where it catches a value that is
 * not an enumerator at all -- which no amount of compiler help can rule out,
 * since the argument may have come from a cast or from the wire. */
const char *fzn_commitment_err_str(fzn_commitment_err_t err)
{
	switch (err) {
	case FZN_COMMITMENT_OK:
		return "ok";
	case FZN_COMMITMENT_ERR_MALFORMED:
		return "malformed argument";
	case FZN_COMMITMENT_ERR_HASH:
		return "hash refused or absent";
	case FZN_COMMITMENT_ERR_MISMATCH:
		return "key commitment mismatch";
	}

	return "unknown";
}
