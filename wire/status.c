/* A status between hosts: project.md sec 1076, and the header. The bytes are
 * node/status.situ's, read and built by what situc generates from it. */
#include "status.h"

#include <string.h>

#include "generated/status.h"
#include "generated/status_build.h"

/* THE CODES ARE THE SCHEMA'S: a value here unequal to its own there does not
 * compile. */
#define SAME(a, b) typedef char same_##a[(int)(a) == (int)(b) ? 1 : -1]
SAME(FZN_STATUS_OK, FZN_STATUS_CODE_OK);
SAME(FZN_STATUS_DENIED, FZN_STATUS_CODE_DENIED);
SAME(FZN_STATUS_MALFORMED, FZN_STATUS_CODE_MALFORMED);
SAME(FZN_STATUS_ERROR, FZN_STATUS_CODE_ERROR);
SAME(FZN_STATUS_UNSUPPORTED, FZN_STATUS_CODE_UNSUPPORTED);
SAME(FZN_STATUS_SHEDDING, FZN_STATUS_CODE_SHEDDING);
SAME(FZN_STATUS_BUSY, FZN_STATUS_CODE_BUSY);
typedef char same_length_max[FZN_STATUS_LEN_MAX == FZN_STATUS_MESSAGE_SIZE_MAX ? 1 : -1];
#undef SAME

size_t fzn_status_write(uint8_t *out, size_t cap, fzn_status_t code, const char *why)
{
	size_t why_len = why ? strlen(why) : 0u;
	uint32_t wrote = 0;

	if (!out || !fzn_status_code_is_known((fzn_status_code_t)code) || cap > UINT32_MAX)
		return 0;
	if (why_len > FZN_STATUS_WHY_MAX)
		why_len = FZN_STATUS_WHY_MAX;
	if (fzn_status_message_build(out, (uint32_t)cap, FZN_STATUS_VERSION, FZN_STATUS_TYPE, (fzn_status_code_t)code,
	                             (const uint8_t *)why, (uint32_t)why_len, &wrote)
	    != SITU_OK)
		return 0;
	return wrote;
}

int fzn_status_read(const uint8_t *in, size_t len, fzn_status_t *code, const uint8_t **why,
                    size_t *why_len)
{
	situ_msg_t msg;
	situ_view_t v;

	if (!in || len < FZN_STATUS_HEAD_LEN || len > FZN_STATUS_LEN_MAX || in[0] != FZN_STATUS_VERSION
	    || in[1] != FZN_STATUS_TYPE)
		return 0;
	situ_msg_init(&msg, (uint8_t *)(uintptr_t)in, (uint32_t)len);
	if (fzn_status_message_view(&msg, 0u, (uint32_t)len, &v) != SITU_OK
	    || fzn_status_message_validate(v) != SITU_OK
	    || FZN_STATUS_HEAD_LEN + fzn_status_message_why_len(v) != len
	    || !fzn_status_code_is_known(fzn_status_message_code_get(v)))
		return 0;
	if (code)
		*code = (fzn_status_t)fzn_status_message_code_get(v);
	if (why)
		*why = fzn_status_message_why_ptr(v);
	if (why_len)
		*why_len = fzn_status_message_why_len(v);
	return 1;
}

const char *fzn_status_name(fzn_status_t code)
{
	switch (code) {
	case FZN_STATUS_OK:
		return "ok";
	case FZN_STATUS_DENIED:
		return "denied";
	case FZN_STATUS_MALFORMED:
		return "malformed";
	case FZN_STATUS_ERROR:
		return "error";
	case FZN_STATUS_UNSUPPORTED:
		return "unsupported";
	case FZN_STATUS_SHEDDING:
		return "shedding";
	case FZN_STATUS_BUSY:
		return "busy";
	}
	return "unknown";
}
