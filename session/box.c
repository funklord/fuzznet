/* A sealed box to a prekey: project.md sec 618, and the header. */
#include "box.h"

#include <string.h>

#include "../constant_time/constant_time.h"

static const char LABEL[] = "fuzznet.box";

const char *fzn_box_err_str(fzn_box_err_t err)
{
	switch (err) {
	case FZN_BOX_OK:
		return "ok";
	case FZN_BOX_ERR_MALFORMED:
		return "malformed";
	case FZN_BOX_ERR_SHAPE:
		return "not a box";
	case FZN_BOX_ERR_OPEN:
		return "not sealed to this key, or altered";
	case FZN_BOX_ERR_OPS:
		return "the randomness or the agreement refused";
	}
	return "unknown";
}

int fzn_box_is(const uint8_t *bytes, size_t len)
{
	return bytes && len >= FZN_BOX_OVERHEAD && bytes[0] == FZN_BOX_MARK
	       && bytes[1] == FZN_BOX_VERSION;
}

/* THE BOX'S KEY: the label, the ephemeral key, the recipient and their
 * agreement -- both public keys bound, so a box cannot be re-addressed. */
static int box_key(const fzn_hash_ops_t *hash, const uint8_t eph[FZN_AGREE_PUBLIC_LEN],
                   const uint8_t recipient[FZN_AGREE_PUBLIC_LEN],
                   const uint8_t shared[FZN_AGREE_SHARED_LEN], uint8_t key[FZN_AEAD_KEY_LEN])
{
	uint8_t in[sizeof(LABEL) + 2u * FZN_AGREE_PUBLIC_LEN + FZN_AGREE_SHARED_LEN];
	size_t at = sizeof(LABEL);
	int ok;

	memcpy(in, LABEL, sizeof(LABEL));
	memcpy(in + at, eph, FZN_AGREE_PUBLIC_LEN);
	at += FZN_AGREE_PUBLIC_LEN;
	memcpy(in + at, recipient, FZN_AGREE_PUBLIC_LEN);
	at += FZN_AGREE_PUBLIC_LEN;
	memcpy(in + at, shared, FZN_AGREE_SHARED_LEN);
	ok = hash->hash(hash->ctx, key, FZN_AEAD_KEY_LEN, in, sizeof(in));
	fzn_wipe(in, sizeof(in));
	return ok;
}

fzn_box_err_t fzn_box_seal(const fzn_agree_ops_t *agree, const fzn_hash_ops_t *hash,
                           const fzn_aead_ops_t *aead, const fzn_random_ops_t *rng,
                           const uint8_t recipient[FZN_AGREE_PUBLIC_LEN], const uint8_t *payload,
                           size_t len, uint8_t *out, size_t cap, size_t *out_len)
{
	static const uint8_t nonce[FZN_AEAD_NONCE_LEN];
	uint8_t seed[FZN_AGREE_SECRET_LEN], shared[FZN_AGREE_SHARED_LEN], key[FZN_AEAD_KEY_LEN];
	fzn_agree_secret_t eph;
	fzn_box_err_t err = FZN_BOX_ERR_OPS;

	if (!agree || !hash || !aead || !rng || !rng->fill || !recipient || (!payload && len)
	    || !out || !out_len || cap < FZN_BOX_OVERHEAD || cap - FZN_BOX_OVERHEAD < len)
		return FZN_BOX_ERR_MALFORMED;
	memset(&eph, 0, sizeof(eph));
	if (!rng->fill(rng->ctx, seed, sizeof(seed))
	    || fzn_agree_secret_install(&eph, agree, seed) != FZN_AGREE_OK
	    || fzn_agree_shared(&eph, agree, recipient, shared) != FZN_AGREE_OK
	    || !box_key(hash, fzn_agree_secret_public(&eph), recipient, shared, key))
		goto done;
	out[0] = FZN_BOX_MARK;
	out[1] = FZN_BOX_VERSION;
	memcpy(out + 2, fzn_agree_secret_public(&eph), FZN_AGREE_PUBLIC_LEN);
	if (len)
		memmove(out + FZN_BOX_HEAD_LEN, payload, len);
	if (!aead->seal(aead->ctx, key, nonce, out, FZN_BOX_HEAD_LEN, out + FZN_BOX_HEAD_LEN, len,
	                out + FZN_BOX_HEAD_LEN + len))
		goto done;
	*out_len = FZN_BOX_OVERHEAD + len;
	err = FZN_BOX_OK;
done:
	fzn_wipe(seed, sizeof(seed));
	fzn_wipe(shared, sizeof(shared));
	fzn_wipe(key, sizeof(key));
	fzn_agree_secret_wipe(&eph);
	return err;
}

fzn_box_err_t fzn_box_open(const fzn_agree_secret_t *secret, const fzn_agree_ops_t *agree,
                           const fzn_hash_ops_t *hash, const fzn_aead_ops_t *aead,
                           const uint8_t *box, size_t len, uint8_t *out, size_t cap,
                           size_t *out_len)
{
	static const uint8_t nonce[FZN_AEAD_NONCE_LEN];
	uint8_t shared[FZN_AGREE_SHARED_LEN], key[FZN_AEAD_KEY_LEN];
	const uint8_t *mine;
	size_t n;
	fzn_box_err_t err = FZN_BOX_ERR_OPEN;

	if (!secret || !agree || !hash || !aead || !box || !out || !out_len)
		return FZN_BOX_ERR_MALFORMED;
	if (!fzn_box_is(box, len))
		return FZN_BOX_ERR_SHAPE;
	n = len - FZN_BOX_OVERHEAD;
	if (cap < n)
		return FZN_BOX_ERR_MALFORMED;
	mine = fzn_agree_secret_public(secret);
	if (!mine || fzn_agree_shared(secret, agree, box + 2, shared) != FZN_AGREE_OK
	    || !box_key(hash, box + 2, mine, shared, key))
		goto done;
	if (n)
		memmove(out, box + FZN_BOX_HEAD_LEN, n);
	if (!aead->open(aead->ctx, key, nonce, box, FZN_BOX_HEAD_LEN, out, n,
	                box + FZN_BOX_HEAD_LEN + n)) {
		fzn_wipe(out, n);
		goto done;
	}
	*out_len = n;
	err = FZN_BOX_OK;
done:
	fzn_wipe(shared, sizeof(shared));
	fzn_wipe(key, sizeof(key));
	return err;
}
