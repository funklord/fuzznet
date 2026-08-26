/* See record.h. */

#include "record.h"

#include <string.h>

/* THE HEADER'S TABLE, CHECKED BY THE COMPILER. record.h states the layout
 * twice -- once as a table a reader consults and once as the running sum the
 * accessors index with -- and this is what stops the two drifting apart. It
 * is the only place the literal 92 appears in the code.
 *
 * The offsets are checked individually rather than only the total, because a
 * total is the one thing that survives two fields swapping widths. */
_Static_assert(FZN_RECORD_OFF_ISSUER == 2u, "record layout: issuer moved");
_Static_assert(FZN_RECORD_OFF_SUBJECT == 34u, "record layout: subject moved");
_Static_assert(FZN_RECORD_OFF_STREAM == 66u, "record layout: stream moved");
_Static_assert(FZN_RECORD_OFF_KIND == 70u, "record layout: kind moved");
_Static_assert(FZN_RECORD_OFF_SEQ == 74u, "record layout: seq moved");
_Static_assert(FZN_RECORD_OFF_ISSUED_AT == 82u, "record layout: issued_at moved");
_Static_assert(FZN_RECORD_OFF_BODY_LEN == 90u, "record layout: body_len moved");
_Static_assert(FZN_RECORD_HEADER_LEN == 92u, "record layout: the header is not 92 bytes");
_Static_assert(FZN_RECORD_MIN_LEN == 156u, "record layout: an empty record is not 156 bytes");
_Static_assert(FZN_RECORD_MAX_LEN == 668u, "record layout: a full record is not 668 bytes");

/* `body_len` is written with fzn_put_be16 and read with fzn_get_be16, so a
 * body bound that did not fit sixteen bits would encode a length nobody could
 * read back. Cheap to state and it is the assertion that would fire if
 * somebody raised the bound for a consumer that wanted more. */
_Static_assert(FZN_RECORD_BODY_MAX <= 0xffffu, "a body length must fit the u16 that carries it");

fzn_record_err_t fzn_record_open(const uint8_t *bytes, size_t len, fzn_record_t *out)
{
	size_t body_len;

	if (!bytes || !out)
		return FZN_RECORD_ERR_MALFORMED;

	/* The floor first, because everything below reads the header. */
	if (len < FZN_RECORD_MIN_LEN)
		return FZN_RECORD_ERR_SHAPE;

	/* THE TWO BYTES THE SIGNATURE COVERS BUT NOTHING ELSE READS. A record
	 * whose object byte says "hop" is a hop, and refusing it here is what
	 * stops one signed object being presented as another -- see
	 * wire/bytes.h, where the sibling project that paid for the collision
	 * is named. */
	if (bytes[FZN_RECORD_OFF_VERSION] != (uint8_t)FZN_SIGNED_VERSION)
		return FZN_RECORD_ERR_SHAPE;
	if (bytes[FZN_RECORD_OFF_OBJECT] != (uint8_t)FZN_OBJECT_RECORD)
		return FZN_RECORD_ERR_SHAPE;

	/* The bound BEFORE the length agreement, so that an oversized body is
	 * reported as the sizing decision it is rather than as a shapeless
	 * buffer. A consumer can act on BODY_TOO_LARGE -- split the statement,
	 * or raise the bound -- and can do nothing at all about SHAPE. */
	body_len = fzn_get_be16(bytes + FZN_RECORD_OFF_BODY_LEN);
	if (body_len > FZN_RECORD_BODY_MAX)
		return FZN_RECORD_ERR_BODY_TOO_LARGE;

	/* THE LENGTH MUST AGREE WITH THE FIELD, EXACTLY. This is the half of
	 * the binding that the signature cannot supply on its own: a record
	 * whose `body_len` says 4 and whose buffer holds 64 body bytes would
	 * have a signature covering one range and a body occupying another, so
	 * the same signed bytes could be read back as two different records.
	 * Refusing anything but the exact length is what makes the encoding
	 * canonical, and canonical is what makes it signable. */
	if (len != (size_t)FZN_RECORD_HEADER_LEN + body_len + FZN_SIG_LEN)
		return FZN_RECORD_ERR_SHAPE;

	/* Zero is not a sequence a legitimate issuer produces: journal.h
	 * reserves it for "nothing seen yet". Refused here rather than in
	 * `fzn_record_verify`, so a record refused for its sequence has not
	 * reached a function that holds a key -- the ordering claim, made
	 * structural. */
	if (fzn_get_be64(bytes + FZN_RECORD_OFF_SEQ) == 0)
		return FZN_RECORD_ERR_SEQ_ZERO;

	out->base = bytes;
	out->len = len;

	return FZN_RECORD_OK;
}

fzn_record_err_t fzn_record_verify(fzn_record_t record, const fzn_sign_ops_t *sign)
{
	const uint8_t *at;
	size_t len;

	if (!sign || !sign->verify)
		return FZN_RECORD_ERR_MALFORMED;
	/* A view `fzn_record_open` did not fill. Its own answer rather than a
	 * read through whatever the caller had, and MALFORMED because it is
	 * the caller skipping a step rather than a bad record. */
	if (!fzn_record_is_open(record))
		return FZN_RECORD_ERR_MALFORMED;

	/* NOTHING IS RE-CHECKED HERE, and that is the design rather than an
	 * omission. Every layout question was answered by `open`, and every
	 * field lives inside the range below, so there is no decoded copy left
	 * to disagree with what is signed. */
	fzn_record_signed_bytes(record, &at, &len);
	if (!sign->verify(sign->ctx, fzn_record_issuer(record), at, len,
	                  fzn_record_signature(record)))
		return FZN_RECORD_ERR_UNSIGNED;

	return FZN_RECORD_OK;
}

fzn_record_err_t fzn_record_sign(const uint8_t issuer[FZN_PUBKEY_LEN],
                                 const uint8_t subject[FZN_SUBJECT_LEN], uint32_t stream,
                                 uint32_t kind, uint64_t seq, uint64_t issued_at,
                                 const uint8_t *body, size_t body_len,
                                 const fzn_sign_ops_t *sign, uint8_t *out, size_t out_cap,
                                 size_t *out_len)
{
	size_t signed_len;

	if (!issuer || !subject || !sign || !sign->sign || !out || !out_len)
		return FZN_RECORD_ERR_MALFORMED;
	/* A body pointer and a length must agree. This is the last place the
	 * pair can disagree at all: past here the length lives in the bytes
	 * beside the body, and no consumer has to test for it again. */
	if (!body && body_len != 0)
		return FZN_RECORD_ERR_MALFORMED;
	if (body_len > FZN_RECORD_BODY_MAX)
		return FZN_RECORD_ERR_BODY_TOO_LARGE;
	/* Refused for the same reason `fzn_record_open` refuses it, and here
	 * as well as there so that this cannot mint what that will not read. */
	if (seq == 0)
		return FZN_RECORD_ERR_SEQ_ZERO;

	signed_len = (size_t)FZN_RECORD_HEADER_LEN + body_len;
	if (out_cap < signed_len + FZN_SIG_LEN)
		return FZN_RECORD_ERR_MALFORMED;

	out[FZN_RECORD_OFF_VERSION] = (uint8_t)FZN_SIGNED_VERSION;
	out[FZN_RECORD_OFF_OBJECT] = (uint8_t)FZN_OBJECT_RECORD;
	memcpy(out + FZN_RECORD_OFF_ISSUER, issuer, FZN_PUBKEY_LEN);
	memcpy(out + FZN_RECORD_OFF_SUBJECT, subject, FZN_SUBJECT_LEN);
	fzn_put_be32(out + FZN_RECORD_OFF_STREAM, stream);
	fzn_put_be32(out + FZN_RECORD_OFF_KIND, kind);
	fzn_put_be64(out + FZN_RECORD_OFF_SEQ, seq);
	fzn_put_be64(out + FZN_RECORD_OFF_ISSUED_AT, issued_at);
	fzn_put_be16(out + FZN_RECORD_OFF_BODY_LEN, (uint16_t)body_len);
	if (body_len != 0)
		memcpy(out + FZN_RECORD_OFF_BODY, body, body_len);

	/* THE SIGNATURE GOES AFTER THE BODY AND COVERS EVERYTHING BEFORE IT,
	 * which is the same range `fzn_record_signed_bytes` hands a verifier.
	 * One expression of the range, used by both directions. */
	if (!sign->sign(sign->ctx, out + signed_len, out, signed_len))
		return FZN_RECORD_ERR_UNSIGNED;

	*out_len = signed_len + FZN_SIG_LEN;

	return FZN_RECORD_OK;
}

/* See record.h. No `default:` label, so -Wswitch notices a code added and not
 * rendered; the fallback sits after the switch for a value that is not an
 * enumerator at all. */
const char *fzn_record_err_str(fzn_record_err_t err)
{
	switch (err) {
	case FZN_RECORD_OK:
		return "ok";
	case FZN_RECORD_ERR_MALFORMED:
		return "malformed argument";
	case FZN_RECORD_ERR_UNSIGNED:
		return "signature does not check out";
	case FZN_RECORD_ERR_BODY_TOO_LARGE:
		return "body exceeds what a record carries";
	case FZN_RECORD_ERR_SEQ_ZERO:
		return "sequence zero is reserved";
	case FZN_RECORD_ERR_SHAPE:
		return "not the shape of a record";
	}

	return "unknown";
}
