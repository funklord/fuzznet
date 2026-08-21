/* See commitment.h. */

#include "commitment.h"

#include "../constant_time/constant_time.h"

#include <string.h>

/* Domain separation. Sixteen bytes, fixed, and prepended to every
 * transcript this module hashes so that the same bytes used for any other
 * purpose in this protocol cannot derive the same key.
 *
 * The version digit is in the label deliberately. If the transcript's shape
 * ever changes, changing this label makes old and new peers derive
 * different keys and fail to talk -- which is the correct failure, and much
 * better than two peers agreeing on a key by hashing different things and
 * discovering it later. */
static const char FZN_KDF_LABEL[16] = "fuzznet-kdf-v1\0\0";

/* The largest transcript this will hash in one pass, and therefore the
 * largest stack buffer it needs.
 *
 * Bounded rather than allocated: nothing in this library allocates, and a
 * transcript is key material whose size is a protocol constant rather than
 * something a stranger chooses. 512 is far above the seven public keys
 * fuzzypickles' equivalent hashes and leaves room for a session model that
 * is not settled yet. */
#define FZN_TRANSCRIPT_MAX 512

fzn_commitment_err_t fzn_commitment_derive(const fzn_hash_ops_t *hash,
                                            const uint8_t *transcript, size_t transcript_len,
                                            uint8_t key_out[FZN_AEAD_KEY_LEN],
                                            uint8_t commitment_out[FZN_COMMITMENT_LEN])
{
	uint8_t input[sizeof(FZN_KDF_LABEL) + FZN_TRANSCRIPT_MAX];
	uint8_t derived[FZN_DERIVED_LEN];
	fzn_commitment_err_t err = FZN_COMMITMENT_OK;

	if (!hash || !hash->hash || !transcript || !key_out || !commitment_out)
		return FZN_COMMITMENT_ERR_MALFORMED;
	if (transcript_len == 0 || transcript_len > FZN_TRANSCRIPT_MAX)
		return FZN_COMMITMENT_ERR_MALFORMED;

	memcpy(input, FZN_KDF_LABEL, sizeof(FZN_KDF_LABEL));
	memcpy(input + sizeof(FZN_KDF_LABEL), transcript, transcript_len);

	/* ONE call, producing both. See commitment.h: deriving them separately
	 * would leave the commitment merely accompanying the key rather than
	 * binding it. */
	if (!hash->hash(hash->ctx, derived, sizeof(derived), input,
	                sizeof(FZN_KDF_LABEL) + transcript_len)) {
		err = FZN_COMMITMENT_ERR_HASH;
		goto out;
	}

	/* Written only once the hash has succeeded, so a refused derivation
	 * cannot leave half a key in a buffer a later line will use. */
	memcpy(key_out, derived, FZN_AEAD_KEY_LEN);
	memcpy(commitment_out, derived + FZN_AEAD_KEY_LEN, FZN_COMMITMENT_LEN);

out:
	/* The intermediates are key material. `volatile` on the pointer is
	 * what stops a compiler deleting a write to something never read
	 * again -- the classic dead-store elimination of a memset that was
	 * the only thing protecting a secret. Monocypher's crypto_wipe would
	 * do it too, but this module must not depend on it: the hash is a
	 * vtable precisely so nothing here needs a crypto library.
	 *
	 * MEASURED, not assumed. Building this file at -Os with and without
	 * the qualifier: 411 bytes of text with it, 337 without. The compiler
	 * deletes 74 bytes of wipe when it is allowed to, which is the whole
	 * of what the paragraph above claims and is worth a number rather
	 * than a belief.
	 *
	 * CHECKED, now, rather than re-measured by whoever remembers. This
	 * comment used to end "re-measure if the wipe is ever rewritten --
	 * the check is one rebuild and a `size`", which is an instruction to
	 * a person who will not be there, about a security property, in the
	 * one place nobody looks twice. `make codegencheck` counts the
	 * zero-immediate stores in this function: two with the qualifier and
	 * none without, so a deleted wipe stops the build. It is a tripwire
	 * rather than a proof and tools/codegen_gate.py says so.
	 *
	 * `input` is wiped in full rather than only the `transcript_len`
	 * bytes that were used. Wiping what was written would be enough and
	 * would be a bound to get wrong later; this cannot be. */
	{
		volatile uint8_t *p = derived;
		for (size_t i = 0; i < sizeof(derived); i++)
			p[i] = 0;
		p = input;
		for (size_t i = 0; i < sizeof(input); i++)
			p[i] = 0;
	}

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
