/* See prekey.h. */

#include "prekey.h"

#include "../constant_time/constant_time.h"
#include "../wire/bytes.h"

#include <string.h>

/* THE LAYOUT, ASSERTED FIELD BY FIELD.
 *
 * `record/record.c` has done this since it was written and states the reason
 * beside it: the offsets are checked individually rather than only the total,
 * because a total is the one thing that survives two fields swapping widths.
 * The reasoning was right and it was applied to exactly one module.
 *
 * MEASURED BEFORE BEING WRITTEN, which is why these are here rather than as
 * tidiness: the total length was the ONLY thing asserted here, and
 * exchanging FZN_PREKEY_OFF_HOST and FZN_PREKEY_OFF_PREKEY preserves it
 * exactly -- the swap surviving the check meant to be the guard. prekey.h
 * names the hazard in terms: the two are different keys with different
 * jobs, the long-term identity signs and the prekey agrees, and a future
 * that changes one must not silently change the other. Swapped, a peer
 * pins a ROTATING key as an identity and agrees against a signing key.
 *
 * The numbers are literals. A constant checked against itself checks nothing,
 * and the point is that a peer cannot see this file -- project.md sec 45 makes
 * the same argument for the domain labels in their vectors.
 */
_Static_assert(FZN_PREKEY_OFF_VERSION == 0u, "prekey layout: version moved");
_Static_assert(FZN_PREKEY_OFF_OBJECT == 1u, "prekey layout: object moved");
_Static_assert(FZN_PREKEY_OFF_HOST == 2u, "prekey layout: host moved");
_Static_assert(FZN_PREKEY_OFF_PREKEY == 34u, "prekey layout: the prekey moved");
_Static_assert(FZN_PREKEY_OFF_CREATED_AT == 66u, "prekey layout: created_at moved");
_Static_assert(FZN_PREKEY_OFF_SIGNATURE == 74u, "prekey layout: the signature moved");
_Static_assert(FZN_PREKEY_BODY_LEN == 74u,
               "prekey layout: the signed body is not 74 bytes");
_Static_assert(FZN_PREKEY_LEN_TOTAL == 138u,
               "the record's length has moved; every peer that pins one must agree");

fzn_prekey_err_t fzn_prekey_issue(const uint8_t host[FZN_PUBKEY_LEN],
                                   const uint8_t prekey[FZN_PREKEY_LEN], uint64_t created_at,
                                   const fzn_sign_ops_t *signer,
                                   uint8_t out[FZN_PREKEY_LEN_TOTAL])
{
	if (!host || !prekey || !out)
		return FZN_PREKEY_ERR_MALFORMED;
	if (!signer || !signer->sign)
		return FZN_PREKEY_ERR_SIGNER;

	out[FZN_PREKEY_OFF_VERSION] = (uint8_t)FZN_SIGNED_VERSION;
	out[FZN_PREKEY_OFF_OBJECT] = (uint8_t)FZN_OBJECT_PREKEY;
	memcpy(out + FZN_PREKEY_OFF_HOST, host, FZN_PUBKEY_LEN);
	memcpy(out + FZN_PREKEY_OFF_PREKEY, prekey, FZN_PREKEY_LEN);
	fzn_put_be64(out + FZN_PREKEY_OFF_CREATED_AT, created_at);

	/* THE SIGNATURE IS OVER THE BYTES THAT WILL BE STORED, in place,
	 * rather than over a transcript rebuilt at signing time. That is what
	 * leaves no second implementation of the layout to drift, and it is
	 * why `fzn_prekey_verify` can re-read the range instead of
	 * reconstructing it. */
	if (!signer->sign(signer->ctx, out + FZN_PREKEY_OFF_SIGNATURE, out,
	                  FZN_PREKEY_BODY_LEN))
		return FZN_PREKEY_ERR_SIGNER;

	return FZN_PREKEY_OK;
}

fzn_prekey_err_t fzn_prekey_open(const uint8_t *bytes, size_t len, fzn_prekey_record_t *out)
{
	if (!bytes || !out)
		return FZN_PREKEY_ERR_MALFORMED;
	/* EXACT, not "at least". A trailing byte would be a second encoding
	 * of one record and therefore a second set of signed bytes. */
	if (len != FZN_PREKEY_LEN_TOTAL)
		return FZN_PREKEY_ERR_SHAPE;
	if (bytes[FZN_PREKEY_OFF_VERSION] != (uint8_t)FZN_SIGNED_VERSION)
		return FZN_PREKEY_ERR_SHAPE;
	if (bytes[FZN_PREKEY_OFF_OBJECT] != (uint8_t)FZN_OBJECT_PREKEY)
		return FZN_PREKEY_ERR_SHAPE;

	out->bytes = bytes;
	out->host = bytes + FZN_PREKEY_OFF_HOST;
	out->prekey = bytes + FZN_PREKEY_OFF_PREKEY;
	out->created_at = fzn_get_be64(bytes + FZN_PREKEY_OFF_CREATED_AT);
	return FZN_PREKEY_OK;
}

fzn_prekey_err_t fzn_prekey_verify(fzn_prekey_record_t record, const fzn_sign_ops_t *verifier)
{
	if (!record.bytes || !record.host)
		return FZN_PREKEY_ERR_MALFORMED;
	if (!verifier || !verifier->verify)
		return FZN_PREKEY_ERR_SIGNER;

	/* UNDER THE HOST KEY THE RECORD ITSELF NAMES, which is what makes
	 * this self-signed and is the whole of what it proves: somebody
	 * holding that secret key wrote these bytes. It says nothing about
	 * whether that key belongs to the party the user meant, and
	 * `fzn_prekey_pin` does not pretend otherwise. */
	if (!verifier->verify(verifier->ctx, record.host, record.bytes, FZN_PREKEY_BODY_LEN,
	                      record.bytes + FZN_PREKEY_OFF_SIGNATURE))
		return FZN_PREKEY_ERR_SIGNATURE;

	return FZN_PREKEY_OK;
}

void fzn_prekey_peer_init(fzn_prekey_peer_t *peer)
{
	if (!peer)
		return;
	memset(peer, 0, sizeof(*peer));
	fzn_trust_init(&peer->trust);
}

fzn_prekey_err_t fzn_prekey_pin(fzn_prekey_peer_t *peer, fzn_prekey_record_t record,
                                 const fzn_sign_ops_t *verifier, fzn_trust_source_t source,
                                 uint64_t now)
{
	const uint8_t *anchor;
	fzn_prekey_err_t err;

	if (!peer || !record.bytes || !record.host || !record.prekey)
		return FZN_PREKEY_ERR_MALFORMED;
	if (source != FZN_TRUST_PINNED && source != FZN_TRUST_ADOPTED)
		return FZN_PREKEY_ERR_MALFORMED;

	/* VERIFIED BEFORE ANYTHING IS COMPARED, let alone written. A record
	 * whose signature does not check is not this host's statement at all,
	 * so comparing its prekey against a stored one -- or its timestamp --
	 * would be reasoning about a stranger's bytes as though they were the
	 * peer's. */
	err = fzn_prekey_verify(record, verifier);
	if (err != FZN_PREKEY_OK)
		return err;

	anchor = fzn_trust_root(&peer->trust);
	if (!anchor) {
		/* First use. */
		if (source == FZN_TRUST_PINNED)
			err = (fzn_trust_pin(&peer->trust, record.host) == FZN_TRUST_OK)
			              ? FZN_PREKEY_OK
			              : FZN_PREKEY_ERR_MALFORMED;
		else
			err = (fzn_trust_adopt(&peer->trust, record.host, now) == FZN_TRUST_OK)
			              ? FZN_PREKEY_OK
			              : FZN_PREKEY_ERR_MALFORMED;
		if (err != FZN_PREKEY_OK)
			return err;
		memcpy(peer->prekey, record.prekey, FZN_PREKEY_LEN);
		peer->created_at = record.created_at;
		return FZN_PREKEY_OK;
	}

	/* A DIFFERENT HOST IS A DIFFERENT PEER, not a rotation. Constant
	 * time, because the comparison is against a stored public key and the
	 * habit of comparing keys the careful way is what keeps
	 * constant_time.h's point legible. */
	if (!fzn_ct_memeq(anchor, record.host, FZN_PUBKEY_LEN))
		return FZN_PREKEY_ERR_WRONG_HOST;

	/* A RE-DELIVERY OF WHAT IS ALREADY HELD IS NOT AN EVENT. Checked
	 * before the timestamp comparison, so a record arriving twice -- which
	 * is ordinary -- does not have to satisfy a monotonicity rule it has
	 * no reason to. */
	if (fzn_ct_memeq(peer->prekey, record.prekey, FZN_PREKEY_LEN)
	    && record.created_at == peer->created_at)
		return FZN_PREKEY_OK;

	/* THE ROLLBACK. A different prekey that is not newer is a real,
	 * correctly-signed, older record replayed by anyone who saw it -- and
	 * if that prekey has since leaked, accepting it is the attack.
	 * Nothing about the bytes is wrong, which is exactly why the
	 * signature cannot catch it and this comparison has to.
	 *
	 * The clock is the HOST'S OWN and is used only to order two of that
	 * host's statements against each other. project.md sec 13b settled
	 * that a clock does not gate admission here; this is not admission,
	 * it is a comparison between two things one key said. */
	if (record.created_at <= peer->created_at)
		return FZN_PREKEY_ERR_ROLLBACK;

	memcpy(peer->prekey, record.prekey, FZN_PREKEY_LEN);
	peer->created_at = record.created_at;
	/* `source` IS NOT TOUCHED. A rotation is not a new first use, and
	 * letting one upgrade an ADOPTED anchor to PINNED would let a peer
	 * launder its own provenance -- the consumer would then show a user
	 * "you verified this" about a key nobody checked. */
	return FZN_PREKEY_OK;
}

/* See prekey.h. No `default:`, so -Wswitch names a code added and not
 * rendered here. */
const char *fzn_prekey_err_str(fzn_prekey_err_t err)
{
	switch (err) {
	case FZN_PREKEY_OK:
		return "ok";
	case FZN_PREKEY_ERR_MALFORMED:
		return "malformed argument";
	case FZN_PREKEY_ERR_SHAPE:
		return "not a prekey record";
	case FZN_PREKEY_ERR_SIGNATURE:
		return "self-signature does not verify";
	case FZN_PREKEY_ERR_SIGNER:
		return "signer or verifier refused or absent";
	case FZN_PREKEY_ERR_ROLLBACK:
		return "an older prekey for a host already pinned";
	case FZN_PREKEY_ERR_WRONG_HOST:
		return "a different host than the one pinned";
	}

	return "unknown";
}
