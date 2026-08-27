/* See trust.h. */

#include "trust.h"

#include "../constant_time/constant_time.h"

#include <string.h>

void fzn_trust_init(fzn_trust_t *trust)
{
	if (!trust)
		return;

	memset(trust, 0, sizeof(*trust));
	trust->source = FZN_TRUST_NONE;
}

/* Both entry points differ only in what they record about provenance, so the
 * anchoring rule lives in one place and cannot come to differ between them. */
static fzn_trust_err_t anchor(fzn_trust_t *trust, const uint8_t root[FZN_PUBKEY_LEN],
                               fzn_trust_source_t source, uint64_t now)
{
	if (!trust || !root)
		return FZN_TRUST_ERR_MALFORMED;
	/* AN ALL-ZERO ROOT IS REFUSED, and the header already argued for this
	 * without the code doing it.
	 *
	 * `trust.h` says `fzn_trust_root` returns NULL rather than a zero key
	 * "because `fzn_chain_verify` refuses NULL and would happily verify
	 * against a key of zeroes -- and an anchor nobody set must fail closed
	 * rather than match whatever an attacker can also produce". That guard
	 * was keyed on `source`, not on the BYTES, so anchoring all zeroes
	 * succeeded and `fzn_trust_root` then handed them to `fzn_chain_verify`
	 * as a real root. Measured: adopt returns ok, and the accessor returns
	 * non-NULL and all zero.
	 *
	 * The way in is not exotic: a caller anchoring from a join message it
	 * parsed only partly, whose root field was never filled, gets a
	 * permanent successful anchor to a key nobody holds -- and it is
	 * permanent, because the next anchor is refused as ANCHORED.
	 *
	 * MALFORMED rather than a new code: an all-zero key is the caller
	 * handing over a buffer it did not fill, which is what MALFORMED means
	 * throughout this library.
	 *
	 * BRANCH-FREE, THOUGH IT NEED NOT BE. The loop accumulates with `|`
	 * over all 32 bytes and never returns early, so it takes the same time
	 * whatever the key holds -- which is the constant-time idiom, arrived
	 * at because it is also the plainest way to ask "is any byte set".
	 *
	 * This comment used to claim the opposite: "not constant time,
	 * deliberately". That was wrong about the code beneath it, and the
	 * reasoning it offered was sound for a decision nobody had made -- the
	 * comparison is against a constant, so an early exit WOULD have been
	 * fine here, and the code does not take one.
	 *
	 * Left as it is rather than made to match the comment. A branch-free
	 * loop over 32 bytes costs nothing worth measuring, and rewriting
	 * correct code to satisfy a description of it is the wrong direction
	 * -- `evidence.md` says to suspect the check before the code, and a
	 * comment is a check a reader runs. */
	{
		uint8_t any = 0;
		size_t i;

		for (i = 0; i < FZN_PUBKEY_LEN; i++)
			any = (uint8_t)(any | root[i]);
		if (any == 0)
			return FZN_TRUST_ERR_MALFORMED;
	}

	if (trust->source != FZN_TRUST_NONE) {
		/* Constant time, because the comparison is against a value an
		 * attacker chooses and repeats: telling them how much of their
		 * guess matched is the one thing this must not do. */
		if (fzn_ct_memeq(trust->root, root, FZN_PUBKEY_LEN))
			return FZN_TRUST_ERR_UNCHANGED;
		return FZN_TRUST_ERR_ANCHORED;
	}

	memcpy(trust->root, root, FZN_PUBKEY_LEN);
	trust->source = source;
	trust->adopted_at = (source == FZN_TRUST_ADOPTED) ? now : 0u;

	return FZN_TRUST_OK;
}

fzn_trust_err_t fzn_trust_pin(fzn_trust_t *trust, const uint8_t root[FZN_PUBKEY_LEN])
{
	return anchor(trust, root, FZN_TRUST_PINNED, 0);
}

fzn_trust_err_t fzn_trust_adopt(fzn_trust_t *trust, const uint8_t root[FZN_PUBKEY_LEN],
                                 uint64_t now)
{
	return anchor(trust, root, FZN_TRUST_ADOPTED, now);
}

const uint8_t *fzn_trust_root(const fzn_trust_t *trust)
{
	if (!trust || trust->source == FZN_TRUST_NONE)
		return NULL;

	return trust->root;
}

fzn_trust_source_t fzn_trust_source_of(const fzn_trust_t *trust)
{
	return trust ? trust->source : FZN_TRUST_NONE;
}

uint64_t fzn_trust_adopted_at(const fzn_trust_t *trust)
{
	return trust ? trust->adopted_at : 0u;
}

const char *fzn_trust_err_str(fzn_trust_err_t err)
{
	switch (err) {
	case FZN_TRUST_OK:
		return "ok";
	case FZN_TRUST_ERR_MALFORMED:
		return "malformed argument";
	case FZN_TRUST_ERR_ANCHORED:
		return "already anchored to a different root";
	case FZN_TRUST_ERR_UNCHANGED:
		return "already anchored to this root";
	}

	return "unknown";
}
