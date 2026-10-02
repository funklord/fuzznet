/* See cause.h. */

#include "cause.h"

#include "../wire/bytes.h"

#include <string.h>

const char *fzn_cause_err_str(fzn_cause_err_t err)
{
	switch (err) {
	case FZN_CAUSE_OK:
		return "ok";
	case FZN_CAUSE_NONE:
		return "not an envelope";
	case FZN_CAUSE_ERR_MALFORMED:
		return "malformed";
	case FZN_CAUSE_ERR_ROOM:
		return "the envelope does not fit";
	}
	return "unknown";
}

fzn_cause_err_t fzn_cause_wrap(const fzn_entry_name_t *cause, const fzn_entry_name_t *origin,
                               const uint8_t *inner, size_t inner_len, uint8_t *out, size_t cap,
                               size_t *len)
{
	uint8_t c[FZN_ENTRY_NAME_RECORD_MAX], o[FZN_ENTRY_NAME_RECORD_MAX];
	size_t cl = 0, ol = 0, need;

	if (!cause || !origin || !inner || inner_len == 0u || inner_len > 0xffffu || !out || !len
	    || fzn_entry_name_pack(cause, c, sizeof(c), &cl) != FZN_ENTRY_OK
	    || fzn_entry_name_pack(origin, o, sizeof(o), &ol) != FZN_ENTRY_OK)
		return FZN_CAUSE_ERR_MALFORMED;
	need = 1u + cl + ol + 2u + inner_len;
	if (need > cap)
		return FZN_CAUSE_ERR_ROOM;
	out[0] = FZN_CAUSE_VERSION;
	memcpy(out + 1, c, cl);
	memcpy(out + 1 + cl, o, ol);
	fzn_put_be16(out + 1 + cl + ol, (uint16_t)inner_len);
	/* memmove: a caller may wrap a request already sitting in `out`'s
	 * tail. */
	memmove(out + 3 + cl + ol, inner, inner_len);
	*len = need;
	return FZN_CAUSE_OK;
}

fzn_cause_err_t fzn_cause_unwrap(const uint8_t *payload, size_t len, fzn_entry_name_t *cause,
                                 fzn_entry_name_t *origin, const uint8_t **inner,
                                 size_t *inner_len)
{
	size_t at = 1, used = 0, n;

	if (!payload || !cause || !origin || !inner || !inner_len)
		return FZN_CAUSE_ERR_MALFORMED;
	if (len == 0u || payload[0] != FZN_CAUSE_VERSION)
		return FZN_CAUSE_NONE;
	if (fzn_entry_name_unpack(payload + at, len - at, cause, &used) != FZN_ENTRY_OK)
		return FZN_CAUSE_ERR_MALFORMED;
	at += used;
	if (fzn_entry_name_unpack(payload + at, len - at, origin, &used) != FZN_ENTRY_OK)
		return FZN_CAUSE_ERR_MALFORMED;
	at += used;
	if (len - at < 2u)
		return FZN_CAUSE_ERR_MALFORMED;
	n = fzn_get_be16(payload + at);
	at += 2u;
	/* EVERY BYTE ACCOUNTED FOR: a request's length that disagrees with
	 * the frame is no envelope of ours. */
	if (n == 0u || len - at != n)
		return FZN_CAUSE_ERR_MALFORMED;
	*inner = payload + at;
	*inner_len = n;
	return FZN_CAUSE_OK;
}
