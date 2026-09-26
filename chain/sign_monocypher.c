/* Monocypher behind chain.h's signer seam. See sign_monocypher.h. */

#include "sign_monocypher.h"

#include <monocypher.h>

#include <string.h>

/* Monocypher returns 0 for a good signature and -1 otherwise; the seam is
 * the other way round, nonzero for good, because that is what reads
 * correctly at the call site in chain.c (`if (!sign->verify(...))`).
 * Inverting here rather than there keeps the convention in the one file
 * that knows both. */
static int mono_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	(void)ctx; /* verification needs no key material of our own */

	return crypto_eddsa_check(sig, pubkey, msg, msg_len) == 0;
}

static int mono_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	fzn_sign_monocypher_t *state = (fzn_sign_monocypher_t *)ctx;

	/* A verify-only signer refuses rather than signing with a zeroed key.
	 * Signing with all zeroes would produce a valid signature under the
	 * public key that zero secret happens to derive -- a real key, owned
	 * by nobody, that a verifier would accept. Refusing is the only safe
	 * answer and it is why `can_sign` exists rather than testing the
	 * buffer for zeroes. */
	if (!state || !state->can_sign)
		return 0;

	crypto_eddsa_sign(sig, state->secret_key, msg, msg_len);
	return 1;
}

/* THE SEED IS COPIED BEFORE MONOCYPHER SEES IT, because
 * `crypto_eddsa_key_pair` wipes the seed buffer it is given -- a courtesy for
 * a caller who wants it gone, and a destroyed identity for one who passed the
 * only copy of a stored key. The seat's contract is that the caller's bytes
 * are the caller's, so the wipe lands on a local and the caller wipes its own
 * when it chooses. */
static int mono_install(void *ctx, const uint8_t seed[FZN_SIGN_SEED_LEN],
                        uint8_t pubkey_out[FZN_PUBKEY_LEN])
{
	fzn_sign_monocypher_t *state = (fzn_sign_monocypher_t *)ctx;
	uint8_t scratch[FZN_SIGN_SEED_LEN];

	if (!state || !seed || !pubkey_out)
		return 0;
	memcpy(scratch, seed, sizeof(scratch));
	crypto_eddsa_key_pair(state->secret_key, pubkey_out, scratch);
	crypto_wipe(scratch, sizeof(scratch));
	state->can_sign = 1;
	return 1;
}

void fzn_sign_monocypher_init(fzn_sign_ops_t *ops, fzn_sign_monocypher_t *state)
{
	if (!ops)
		return;

	ops->verify = mono_verify;
	ops->sign = mono_sign;
	ops->ctx = state;
}

void fzn_sign_monocypher_seat_init(fzn_sign_seat_t *seat, fzn_sign_monocypher_t *state)
{
	if (!seat)
		return;

	seat->install = mono_install;
	seat->ctx = state;
}

void fzn_sign_monocypher_wipe(fzn_sign_monocypher_t *state)
{
	if (!state)
		return;

	crypto_wipe(state->secret_key, sizeof(state->secret_key));
	state->can_sign = 0;
}
