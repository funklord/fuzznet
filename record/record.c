/* See record.h. */

#include "record.h"

#include "../constant_time/constant_time.h"

fzn_record_err_t fzn_record_verify(const fzn_record_t *record, const fzn_sign_ops_t *sign)
{
	if (!record || !sign || !sign->verify)
		return FZN_RECORD_ERR_MALFORMED;
	if (!record->signed_region || record->signed_region_len == 0)
		return FZN_RECORD_ERR_MALFORMED;
	/* A body pointer and a length must agree. A null body of non-zero
	 * length is the caller's bug rather than a bad record, and saying so
	 * separately is what stops it being read as a forgery. */
	if (!record->body && record->body_len != 0)
		return FZN_RECORD_ERR_MALFORMED;
	if (record->body_len > FZN_RECORD_BODY_MAX)
		return FZN_RECORD_ERR_BODY_TOO_LARGE;
	/* Refused BEFORE the signature check, cheaply, because zero is not a
	 * sequence a legitimate issuer produces: journal.h reserves it for
	 * "nothing seen yet". A signed record claiming it would be authentic
	 * and still meaningless. */
	if (record->seq == 0)
		return FZN_RECORD_ERR_SEQ_ZERO;

	if (!sign->verify(sign->ctx, record->issuer, record->signed_region,
	                  record->signed_region_len, record->signature))
		return FZN_RECORD_ERR_UNSIGNED;

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
	}

	return "unknown";
}
