/* See persist.h. */

#include "persist.h"

#include "../constant_time/constant_time.h"
#include "../wire/bytes.h"

#include <string.h>

/*
 * Every blob is `version | slot | payload`, so a blob restored into the wrong
 * slot is refused rather than reinterpreted.
 *
 * THE SLOT BYTE IS NOT REDUNDANT WITH THE FILENAME A BACKEND CHOSE. A backend
 * is free to key however it likes -- a directory, a table index, a database
 * column -- and a caller that asks the wrong slot, or a backend that returns
 * the wrong row, must not have a trust anchor parsed out of a ratchet chain.
 * It is the same argument `wire/bytes.h` makes for the signed-object tag, at
 * a boundary where the bytes are ours on both sides rather than a peer's.
 */
#define OFF_VERSION 0u
#define OFF_TAG 1u
#define OFF_BODY 2u

/*
 * THE BLOB TAG IS NOT THE KEY SLOT, and separating them is what the first
 * draft of this file got wrong.
 *
 * A KEY SLOT is how a backend files something -- send chain and receive
 * chain are different keys because a caller must never confuse them, per the
 * ordering rule in persist.h. A BLOB TAG is what the bytes ARE, and a send
 * chain and a receive chain are the same thing: a key and a sequence number.
 *
 * The first draft reused the key slot as the tag, which forced the chain
 * packer to write `SEND` into every blob and then carry a comment claiming
 * it wrote something neutral. It did not. Two concepts under one byte, and
 * the comment was the part that noticed.
 */
#define BLOB_TRUST 1u
#define BLOB_SECRET 2u
#define BLOB_PEER 3u
#define BLOB_CHAIN 4u

#define TRUST_BODY (FZN_PUBKEY_LEN + 1u + 8u)                 /* root, source, adopted_at */
#define SECRET_BODY (FZN_AGREE_SECRET_LEN + 8u)               /* secret, generation */
#define PEER_BODY (TRUST_BODY + FZN_PREKEY_LEN + 8u)          /* trust, prekey, created_at */
#define CHAIN_BODY (FZN_CHAIN_KEY_LEN + 8u)                   /* key, seq */

_Static_assert(OFF_BODY + PEER_BODY <= FZN_PERSIST_MAX,
               "FZN_PERSIST_MAX is smaller than the largest blob packed here");
_Static_assert(OFF_BODY + TRUST_BODY <= FZN_PERSIST_MAX, "trust blob past the maximum");
_Static_assert(OFF_BODY + SECRET_BODY <= FZN_PERSIST_MAX, "secret blob past the maximum");
_Static_assert(OFF_BODY + CHAIN_BODY <= FZN_PERSIST_MAX, "chain blob past the maximum");

static fzn_persist_err_t head_write(uint8_t *out, size_t cap, size_t body, uint8_t tag)
{
	if (cap < OFF_BODY + body)
		return FZN_PERSIST_ERR_MALFORMED;
	out[OFF_VERSION] = (uint8_t)FZN_PERSIST_VERSION;
	out[OFF_TAG] = tag;
	return FZN_PERSIST_OK;
}

static fzn_persist_err_t head_check(const uint8_t *bytes, size_t len, size_t body,
                                    uint8_t tag)
{
	/* EXACT, not "at least". A trailing byte is a second encoding of one
	 * blob, and this module refuses one for the reason every decoder here
	 * does: "ignore what you do not understand" is how one format becomes
	 * several. */
	if (len != OFF_BODY + body)
		return FZN_PERSIST_ERR_SHAPE;
	if (bytes[OFF_VERSION] != (uint8_t)FZN_PERSIST_VERSION)
		return FZN_PERSIST_ERR_SHAPE;
	if (bytes[OFF_TAG] != tag)
		return FZN_PERSIST_ERR_SHAPE;
	return FZN_PERSIST_OK;
}

/* ---- trust ------------------------------------------------------------ */

fzn_persist_err_t fzn_persist_trust_pack(const fzn_trust_t *trust, uint8_t *out, size_t cap,
                                          size_t *len)
{
	const uint8_t *root;
	fzn_persist_err_t err;

	if (!trust || !out || !len)
		return FZN_PERSIST_ERR_MALFORMED;
	/* AN UNANCHORED TRUST IS NOT PACKED. Storing "no anchor" and
	 * restoring it is indistinguishable from never having stored one, and
	 * a caller that writes an empty anchor over a real one has destroyed
	 * the thing this file exists to keep. */
	root = fzn_trust_root(trust);
	if (!root)
		return FZN_PERSIST_ERR_MALFORMED;

	err = head_write(out, cap, TRUST_BODY, BLOB_TRUST);
	if (err != FZN_PERSIST_OK)
		return err;

	memcpy(out + OFF_BODY, root, FZN_PUBKEY_LEN);
	out[OFF_BODY + FZN_PUBKEY_LEN] = (uint8_t)fzn_trust_source_of(trust);
	fzn_put_be64(out + OFF_BODY + FZN_PUBKEY_LEN + 1u, fzn_trust_adopted_at(trust));
	*len = OFF_BODY + TRUST_BODY;
	return FZN_PERSIST_OK;
}

fzn_persist_err_t fzn_persist_trust_open(const uint8_t *bytes, size_t len, fzn_trust_t *out)
{
	fzn_persist_err_t err;
	fzn_trust_source_t source;
	uint64_t adopted_at;

	if (!bytes || !out)
		return FZN_PERSIST_ERR_MALFORMED;
	err = head_check(bytes, len, TRUST_BODY, BLOB_TRUST);
	if (err != FZN_PERSIST_OK)
		return err;

	source = (fzn_trust_source_t)bytes[OFF_BODY + FZN_PUBKEY_LEN];
	adopted_at = fzn_get_be64(bytes + OFF_BODY + FZN_PUBKEY_LEN + 1u);

	/* THE PROVENANCE IS RESTORED, NOT RE-DECIDED. A host that confirmed a
	 * key out of band and then restarted must not come back saying it
	 * merely adopted one, and one that adopted must not come back
	 * claiming confirmation -- which is the laundering `prekey/` refuses
	 * on rotation, arriving by way of a file. */
	fzn_trust_init(out);
	if (source == FZN_TRUST_PINNED) {
		if (fzn_trust_pin(out, bytes + OFF_BODY) != FZN_TRUST_OK)
			return FZN_PERSIST_ERR_SHAPE;
	} else if (source == FZN_TRUST_ADOPTED) {
		if (fzn_trust_adopt(out, bytes + OFF_BODY, adopted_at) != FZN_TRUST_OK)
			return FZN_PERSIST_ERR_SHAPE;
	} else {
		/* NONE, or a byte that is not a source at all. Refused rather
		 * than defaulted: an anchor whose provenance was corrupted is
		 * one nobody can answer a user about. */
		return FZN_PERSIST_ERR_SHAPE;
	}
	return FZN_PERSIST_OK;
}

/* ---- the host's own prekey secret ------------------------------------- */

fzn_persist_err_t fzn_persist_secret_pack(const fzn_agree_secret_t *secret, uint8_t *out,
                                           size_t cap, size_t *len)
{
	fzn_persist_err_t err;

	if (!secret || !out || !len)
		return FZN_PERSIST_ERR_MALFORMED;
	if (!fzn_agree_secret_public(secret))
		return FZN_PERSIST_ERR_MALFORMED;

	err = head_write(out, cap, SECRET_BODY, BLOB_SECRET);
	if (err != FZN_PERSIST_OK)
		return err;

	/* THE PUBLIC HALF IS NOT STORED. It is derived from the secret on
	 * restore, so there is no second copy to disagree with it -- which is
	 * exactly why `fzn_agree_secret_install` takes the secret and derives
	 * rather than taking both. */
	memcpy(out + OFF_BODY, secret->secret, FZN_AGREE_SECRET_LEN);
	fzn_put_be64(out + OFF_BODY + FZN_AGREE_SECRET_LEN,
	             fzn_agree_secret_generation(secret));
	*len = OFF_BODY + SECRET_BODY;
	return FZN_PERSIST_OK;
}

fzn_persist_err_t fzn_persist_secret_open(const uint8_t *bytes, size_t len,
                                           const fzn_agree_ops_t *agree,
                                           fzn_agree_secret_t *out)
{
	fzn_persist_err_t err;
	uint64_t generation;

	if (!bytes || !out)
		return FZN_PERSIST_ERR_MALFORMED;
	err = head_check(bytes, len, SECRET_BODY, BLOB_SECRET);
	if (err != FZN_PERSIST_OK)
		return err;

	memset(out, 0, sizeof(*out));
	if (fzn_agree_secret_install(out, agree, bytes + OFF_BODY) != FZN_AGREE_OK)
		return FZN_PERSIST_ERR_BACKEND;

	/* THE GENERATION IS RESTORED AFTER INSTALLING, because installing
	 * counts as a rotation and would otherwise reset it to zero -- and a
	 * host that came back at generation 0 would publish a prekey record
	 * that looks older than the one its peers already hold. */
	generation = fzn_get_be64(bytes + OFF_BODY + FZN_AGREE_SECRET_LEN);
	out->generation = generation;
	return FZN_PERSIST_OK;
}

/* ---- a pinned peer ---------------------------------------------------- */

fzn_persist_err_t fzn_persist_peer_pack(const fzn_prekey_peer_t *peer, uint8_t *out, size_t cap,
                                         size_t *len)
{
	fzn_persist_err_t err;
	size_t at;

	if (!peer || !out || !len)
		return FZN_PERSIST_ERR_MALFORMED;

	err = head_write(out, cap, PEER_BODY, BLOB_PEER);
	if (err != FZN_PERSIST_OK)
		return err;

	/* The peer's anchor goes through the TRUST packer and its two-byte
	 * head is dropped, so there is ONE encoding of a trust rather than
	 * two -- a second would drift the first time either moved. */
	{
		uint8_t inner[OFF_BODY + TRUST_BODY];
		size_t inner_len = 0;

		err = fzn_persist_trust_pack(&peer->trust, inner, sizeof(inner), &inner_len);
		if (err != FZN_PERSIST_OK)
			return err;
		memcpy(out + OFF_BODY, inner + OFF_BODY, TRUST_BODY);
	}

	at = OFF_BODY + TRUST_BODY;
	memcpy(out + at, peer->prekey, FZN_PREKEY_LEN);
	at += FZN_PREKEY_LEN;
	fzn_put_be64(out + at, peer->created_at);
	*len = OFF_BODY + PEER_BODY;
	return FZN_PERSIST_OK;
}

fzn_persist_err_t fzn_persist_peer_open(const uint8_t *bytes, size_t len,
                                         fzn_prekey_peer_t *out)
{
	uint8_t trust_blob[OFF_BODY + TRUST_BODY];
	fzn_persist_err_t err;
	size_t at;

	if (!bytes || !out)
		return FZN_PERSIST_ERR_MALFORMED;
	err = head_check(bytes, len, PEER_BODY, BLOB_PEER);
	if (err != FZN_PERSIST_OK)
		return err;

	fzn_prekey_peer_init(out);

	trust_blob[OFF_VERSION] = (uint8_t)FZN_PERSIST_VERSION;
	trust_blob[OFF_TAG] = BLOB_TRUST;
	memcpy(trust_blob + OFF_BODY, bytes + OFF_BODY, TRUST_BODY);
	err = fzn_persist_trust_open(trust_blob, sizeof(trust_blob), &out->trust);
	if (err != FZN_PERSIST_OK)
		return err;

	at = OFF_BODY + TRUST_BODY;
	memcpy(out->prekey, bytes + at, FZN_PREKEY_LEN);
	at += FZN_PREKEY_LEN;
	out->created_at = fzn_get_be64(bytes + at);
	return FZN_PERSIST_OK;
}

/* ---- a ratchet chain -------------------------------------------------- */

fzn_persist_err_t fzn_persist_chain_pack(const fzn_ratchet_chain_t *chain, uint8_t *out,
                                          size_t cap, size_t *len)
{
	fzn_persist_err_t err;

	if (!chain || !out || !len)
		return FZN_PERSIST_ERR_MALFORMED;

	/* TAGGED AS A CHAIN AND NOT AS A DIRECTION. A send chain and a receive
	 * chain are the same bytes; which one this is belongs to the KEY a
	 * caller stores it under, and persist.h's ordering rule is where
	 * getting that wrong costs a skipped key or key reuse. Putting the
	 * direction in the blob as well would let a caller store a send chain
	 * under the receive key and still open it, so the two would disagree
	 * with nothing to notice. */
	err = head_write(out, cap, CHAIN_BODY, BLOB_CHAIN);
	if (err != FZN_PERSIST_OK)
		return err;

	memcpy(out + OFF_BODY, chain->key, FZN_CHAIN_KEY_LEN);
	fzn_put_be64(out + OFF_BODY + FZN_CHAIN_KEY_LEN, chain->seq);
	*len = OFF_BODY + CHAIN_BODY;
	return FZN_PERSIST_OK;
}

fzn_persist_err_t fzn_persist_chain_open(const uint8_t *bytes, size_t len,
                                          fzn_ratchet_chain_t *out)
{
	fzn_persist_err_t err;

	if (!bytes || !out)
		return FZN_PERSIST_ERR_MALFORMED;
	err = head_check(bytes, len, CHAIN_BODY, BLOB_CHAIN);
	if (err != FZN_PERSIST_OK)
		return err;

	fzn_ratchet_init(out, bytes + OFF_BODY, fzn_get_be64(bytes + OFF_BODY + FZN_CHAIN_KEY_LEN));
	return FZN_PERSIST_OK;
}

/* See persist.h. No `default:`, so -Wswitch names a code added and not
 * rendered here. */
const char *fzn_persist_err_str(fzn_persist_err_t err)
{
	switch (err) {
	case FZN_PERSIST_OK:
		return "ok";
	case FZN_PERSIST_ERR_MALFORMED:
		return "malformed argument";
	case FZN_PERSIST_ERR_SHAPE:
		return "stored bytes are not this slot or version";
	case FZN_PERSIST_ERR_BACKEND:
		return "backend refused or absent";
	case FZN_PERSIST_ERR_ABSENT:
		return "nothing stored under that slot";
	}

	return "unknown";
}
