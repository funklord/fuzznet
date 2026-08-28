/* See agree.h. */

#include "agree.h"

#include "../constant_time/constant_time.h"

#include <string.h>

fzn_agree_err_t fzn_agree_secret_install(fzn_agree_secret_t *sk, const fzn_agree_ops_t *ops,
                                          const uint8_t secret[FZN_AGREE_SECRET_LEN])
{
	uint8_t public_key[FZN_AGREE_PUBLIC_LEN];
	uint64_t next;

	if (!sk || !secret)
		return FZN_AGREE_ERR_MALFORMED;
	if (!ops || !ops->public_of)
		return FZN_AGREE_ERR_OPS;

	/* DERIVED BEFORE ANYTHING IS DESTROYED. A binding that refuses must
	 * leave the caller holding the secret it had, not a wiped struct and
	 * no replacement -- which would be a host that cannot decrypt its own
	 * queued traffic because a key derivation failed. */
	if (!ops->public_of(ops->ctx, public_key, secret))
		return FZN_AGREE_ERR_OPS;

	next = sk->live ? sk->generation + 1u : 0u;

	/* THE ROTATION. Everything sealed under a session derived from the
	 * previous secret becomes unrecoverable here, and there is no branch
	 * that keeps it.
	 *
	 * WHAT THE WIPE BUYS, MEASURED, BECAUSE A MUTATION SAID IT BOUGHT
	 * NOTHING. Deleting it fails no test -- the `memcpy` below covers
	 * every byte, so that is what destroys the old secret today. The wipe
	 * is what CONTAINS THE DAMAGE if that ever stops being true. Four
	 * builds, {wipe, no wipe} x {full copy, short by one}, asking whether
	 * any byte of the old secret survives:
	 *
	 *     wipe, full copy      gone
	 *     no wipe, full copy   gone      <- why the mutation passed
	 *     wipe, short copy     gone
	 *     no wipe, short copy  SURVIVES  <- the case it is here for
	 *
	 * So it is unreachable-by-test today, and it is the difference between
	 * a partial copy losing a byte and a partial copy leaking one. Kept,
	 * and recorded as conditional rather than load-bearing, so the next
	 * reader neither deletes it as dead nor defends it as the thing that
	 * provides forward secrecy.
	 *
	 * A `_Static_assert` was tried here first and did not work: it
	 * compares the buffer's size against the constant, which stays true
	 * when the CALL's length argument shrinks. A comment claiming an
	 * assertion covers something it does not is worse than no assertion. */
	fzn_wipe(sk->secret, sizeof(sk->secret));

	memcpy(sk->secret, secret, FZN_AGREE_SECRET_LEN);
	memcpy(sk->public_key, public_key, FZN_AGREE_PUBLIC_LEN);
	sk->generation = next;
	sk->live = 1;

	fzn_wipe(public_key, sizeof(public_key));
	return FZN_AGREE_OK;
}

const uint8_t *fzn_agree_secret_public(const fzn_agree_secret_t *sk)
{
	if (!sk || !sk->live)
		return NULL;
	return sk->public_key;
}

uint64_t fzn_agree_secret_generation(const fzn_agree_secret_t *sk)
{
	return (sk && sk->live) ? sk->generation : 0u;
}

fzn_agree_err_t fzn_agree_shared(const fzn_agree_secret_t *sk, const fzn_agree_ops_t *ops,
                                  const uint8_t peer_public[FZN_AGREE_PUBLIC_LEN],
                                  uint8_t shared_out[FZN_AGREE_SHARED_LEN])
{
	if (!sk || !peer_public || !shared_out)
		return FZN_AGREE_ERR_MALFORMED;
	if (!ops || !ops->agree)
		return FZN_AGREE_ERR_OPS;
	/* A WIPED SECRET IS ITS OWN ANSWER. After a rotation the old struct
	 * holds zeroes, and X25519 over a zero scalar is a defined operation
	 * with a useless result -- so without this the caller would derive a
	 * session key from nothing and it would look like it worked. */
	if (!sk->live)
		return FZN_AGREE_ERR_ABSENT;

	/* A LOW-ORDER PEER KEY IS REFUSED RATHER THAN USED. The shared secret
	 * for one is a value the attacker chose, so a session derived from it
	 * is a session the attacker can read. The binding reports it; this
	 * turns the report into a refusal the caller cannot ignore by
	 * forgetting to check a length. */
	if (!ops->agree(ops->ctx, shared_out, sk->secret, peer_public)) {
		fzn_wipe(shared_out, FZN_AGREE_SHARED_LEN);
		return FZN_AGREE_ERR_DEGENERATE;
	}

	return FZN_AGREE_OK;
}

void fzn_agree_secret_wipe(fzn_agree_secret_t *sk)
{
	if (!sk)
		return;
	fzn_wipe(sk->secret, sizeof(sk->secret));
	/* The public half goes too. NOT OBSERVABLE THROUGH THIS API and known
	 * to be so: `live` is what `fzn_agree_secret_public` consults, so a
	 * mutation deleting this line fails nothing. It is kept for the
	 * reader who reaches into the struct directly -- leaving a public key
	 * behind makes a wiped secret look usable to anything that does not
	 * ask `live` -- and it is recorded as construction-guaranteed rather
	 * than tested, so nobody later mistakes an untested line for an
	 * untested property. */
	memset(sk->public_key, 0, sizeof(sk->public_key));
	sk->generation = 0;
	sk->live = 0;
}

/* See agree.h. No `default:`, so -Wswitch names a code added and not
 * rendered here. */
const char *fzn_agree_err_str(fzn_agree_err_t err)
{
	switch (err) {
	case FZN_AGREE_OK:
		return "ok";
	case FZN_AGREE_ERR_MALFORMED:
		return "malformed argument";
	case FZN_AGREE_ERR_OPS:
		return "agreement ops refused or absent";
	case FZN_AGREE_ERR_DEGENERATE:
		return "peer public key yields no contributory secret";
	case FZN_AGREE_ERR_ABSENT:
		return "no secret installed, or it has been wiped";
	}

	return "unknown";
}
