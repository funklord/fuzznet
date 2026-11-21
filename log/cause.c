/* See cause.h. */

#include "cause.h"

#include "../wire/bytes.h"
#include "../wire/generated/cause_wire.h"
#include "../wire/generated/cause_wire_build.h"

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
	size_t cl = 0, ol = 0;
	uint32_t wrote = 0;
	situ_err_t err;

	if (!cause || !origin || !inner || inner_len == 0u || inner_len > 0xffffu || !out || !len
	    || fzn_entry_name_pack(cause, c, sizeof(c), &cl) != FZN_ENTRY_OK
	    || fzn_entry_name_pack(origin, o, sizeof(o), &ol) != FZN_ENTRY_OK)
		return FZN_CAUSE_ERR_MALFORMED;
	if (1u + cl + ol + 2u + inner_len > cap)
		return FZN_CAUSE_ERR_ROOM;
	/* BUILT BY THE CODE situ GENERATES from `log/cause_wire.situ`, sec
	 * 1362. Its copies are memmove's, so a caller may still wrap a request
	 * already sitting in `out`'s tail. */
	err = fzn_cause_wire_fzn_cause_envelope_build(out, cap > UINT32_MAX ? UINT32_MAX : (uint32_t)cap,
	                                              FZN_CMD_CAUSE, c, (uint32_t)cl, o, (uint32_t)ol, inner,
	                                              (uint32_t)inner_len, &wrote);
	if (err == SITU_ERR_BOUNDS)
		return FZN_CAUSE_ERR_ROOM;
	if (err != SITU_OK)
		return FZN_CAUSE_ERR_MALFORMED;
	*len = wrote;
	return FZN_CAUSE_OK;
}

fzn_cause_err_t fzn_cause_unwrap(const uint8_t *payload, size_t len, fzn_entry_name_t *cause,
                                 fzn_entry_name_t *origin, const uint8_t **inner,
                                 size_t *inner_len)
{
	situ_msg_t m;
	situ_view_t v;
	uint32_t need = 0, at;
	size_t used = 0;

	if (!payload || !cause || !origin || !inner || !inner_len)
		return FZN_CAUSE_ERR_MALFORMED;
	if (len == 0u || payload[0] != FZN_CMD_CAUSE)
		return FZN_CAUSE_NONE;
	/* READ AS THE SCHEMA SAYS, sec 1362: EVERY BYTE ACCOUNTED FOR -- a
	 * request's length that disagrees with the frame is no envelope of
	 * ours -- and the names' layouts the generated validate's; the names
	 * themselves the entry codec's, which gives the C strings. */
	if (len > UINT32_MAX || fzn_cause_wire_fzn_cause_envelope_required(payload, (uint32_t)len, &need) != SITU_OK
	    || need != len)
		return FZN_CAUSE_ERR_MALFORMED;
	situ_msg_init(&m, (uint8_t *)(uintptr_t)payload, (uint32_t)len);
	if (fzn_cause_wire_fzn_cause_envelope_view(&m, 0u, (uint32_t)len, &v) != SITU_OK
	    || fzn_cause_wire_fzn_cause_envelope_validate(v) != SITU_OK
	    || fzn_entry_name_unpack(payload + 1, len - 1u, cause, &used) != FZN_ENTRY_OK)
		return FZN_CAUSE_ERR_MALFORMED;
	at = fzn_cause_wire_fzn_cause_envelope_origin_offset(v);
	if (at > len || fzn_entry_name_unpack(payload + at, len - at, origin, &used) != FZN_ENTRY_OK)
		return FZN_CAUSE_ERR_MALFORMED;
	*inner = fzn_cause_wire_fzn_cause_envelope_inner_ptr(v);
	*inner_len = fzn_cause_wire_fzn_cause_envelope_inner_len_get(v);
	return FZN_CAUSE_OK;
}
