/* The session frame. wire/session_frame.h says what and why. */

#include "session_frame.h"

#include <string.h>

#include "bytes.h"

#define DOMAIN "fuzznet session frame 1"
#define DOMAIN_LEN (sizeof(DOMAIN) - 1u)
#define HANDLE_AT 1u
#define COUNTER_AT 5u
#define ASK_HANDLE_AT FZN_SESSION_RANDOM_LEN

int fzn_session_end_derive(fzn_session_end_t *end, const fzn_hash_ops_t *hash,
                           const uint8_t root[FZN_AEAD_KEY_LEN],
                           const uint8_t ask[FZN_SESSION_ASK_LEN],
                           const uint8_t grant[FZN_SESSION_GRANT_LEN], int initiator)
{
	uint8_t in[DOMAIN_LEN + FZN_AEAD_KEY_LEN + FZN_SESSION_ASK_LEN + FZN_SESSION_GRANT_LEN];
	uint8_t keys[FZN_AEAD_KEY_LEN * 2u];
	size_t at = 0;
	int ok;

	if (!end || !hash || !hash->hash || !root || !ask || !grant)
		return 0;
	memset(end, 0, sizeof(*end));
	memcpy(in + at, DOMAIN, DOMAIN_LEN);
	at += DOMAIN_LEN;
	memcpy(in + at, root, FZN_AEAD_KEY_LEN);
	at += FZN_AEAD_KEY_LEN;
	memcpy(in + at, ask, FZN_SESSION_ASK_LEN);
	at += FZN_SESSION_ASK_LEN;
	memcpy(in + at, grant, FZN_SESSION_GRANT_LEN);
	at += FZN_SESSION_GRANT_LEN;
	ok = hash->hash(hash->ctx, keys, sizeof(keys), in, at) != 0;
	if (ok) {
		uint32_t ask_handle = fzn_get_be32(ask + ASK_HANDLE_AT);
		uint32_t grant_handle = fzn_get_be32(grant + ASK_HANDLE_AT);

		memcpy(end->send_key, keys + (initiator ? 0u : FZN_AEAD_KEY_LEN), FZN_AEAD_KEY_LEN);
		memcpy(end->recv_key, keys + (initiator ? FZN_AEAD_KEY_LEN : 0u), FZN_AEAD_KEY_LEN);
		end->hears_as = initiator ? ask_handle : grant_handle;
		end->speaks_to = initiator ? grant_handle : ask_handle;
	}
	memset(keys, 0, sizeof(keys));
	memset(in, 0, sizeof(in));
	return ok;
}

int fzn_session_frame_handle(const uint8_t *frame, size_t frame_len, uint32_t *handle)
{
	if (!frame || !handle || frame_len < FZN_SESSION_FRAME_OVERHEAD
	    || frame_len > FZN_SESSION_FRAME_MAX || frame[0] != FZN_SESSION_FRAME_MARK)
		return 0;
	*handle = fzn_get_be32(frame + HANDLE_AT);
	return 1;
}

/* THE NONCE: the counter, and nothing else is needed, as the key is the
 * session's and the direction's alone. */
static void nonce_of(uint32_t counter, uint8_t nonce[FZN_AEAD_NONCE_LEN])
{
	memset(nonce, 0, FZN_AEAD_NONCE_LEN);
	fzn_put_be32(nonce + FZN_AEAD_NONCE_LEN - 4u, counter);
}

fzn_session_frame_err_t fzn_session_frame_seal(fzn_session_end_t *end, uint32_t msg,
                                               uint32_t expires_at, const uint8_t *payload,
                                               size_t payload_len, uint8_t *frame,
                                               size_t frame_cap, size_t *frame_len,
                                               const fzn_aead_ops_t *aead)
{
	uint8_t nonce[FZN_AEAD_NONCE_LEN];
	uint8_t *text;
	size_t text_len, total;
	uint32_t counter;

	if (!end || (!payload && payload_len) || !frame || !frame_len || !aead || !aead->seal
	    || payload_len > FZN_SESSION_FRAME_PAYLOAD_MAX)
		return FZN_SESSION_FRAME_ERR_MALFORMED;
	if (end->sent == UINT32_MAX)
		return FZN_SESSION_FRAME_ERR_SPENT;
	total = FZN_SESSION_FRAME_OVERHEAD + payload_len;
	if (frame_cap < total)
		return FZN_SESSION_FRAME_ERR_CAPACITY;
	counter = ++end->sent;
	frame[0] = FZN_SESSION_FRAME_MARK;
	fzn_put_be32(frame + HANDLE_AT, end->speaks_to);
	fzn_put_be32(frame + COUNTER_AT, counter);
	text = frame + FZN_SESSION_FRAME_HEAD_LEN;
	text_len = FZN_SESSION_FRAME_SEALED_HEAD_LEN + payload_len;
	fzn_put_be32(text, msg);
	fzn_put_be32(text + 4u, expires_at);
	if (payload_len)
		memcpy(text + FZN_SESSION_FRAME_SEALED_HEAD_LEN, payload, payload_len);
	nonce_of(counter, nonce);
	if (!aead->seal(aead->ctx, end->send_key, nonce, frame, FZN_SESSION_FRAME_HEAD_LEN, text,
	                text_len, frame + FZN_SESSION_FRAME_HEAD_LEN + text_len)) {
		/* THE PLAINTEXT WAS COPIED HERE, so it is wiped here (`aead.h`). */
		memset(frame, 0, total);
		return FZN_SESSION_FRAME_ERR_AEAD;
	}
	*frame_len = total;
	return FZN_SESSION_FRAME_OK;
}

/* HEARD ALREADY, or too old to say. */
static int stale(const fzn_session_end_t *end, uint32_t counter)
{
	uint32_t behind;

	if (counter > end->newest)
		return 0;
	behind = end->newest - counter;
	return behind >= FZN_SESSION_WINDOW || ((end->heard >> behind) & 1u);
}

static void mark_heard(fzn_session_end_t *end, uint32_t counter)
{
	if (counter > end->newest) {
		uint32_t ahead = counter - end->newest;

		end->heard = ahead >= FZN_SESSION_WINDOW ? 0u : end->heard << ahead;
		end->heard |= 1u;
		end->newest = counter;
		return;
	}
	end->heard |= (uint64_t)1u << (end->newest - counter);
}

fzn_session_frame_err_t fzn_session_frame_open(fzn_session_end_t *end, uint8_t *frame,
                                               size_t frame_len, const fzn_aead_ops_t *aead,
                                               fzn_session_opened_t *out)
{
	uint8_t nonce[FZN_AEAD_NONCE_LEN];
	uint8_t *text;
	size_t text_len;
	uint32_t handle, counter;

	if (!end || !frame || !aead || !aead->open || !out)
		return FZN_SESSION_FRAME_ERR_MALFORMED;
	if (!fzn_session_frame_handle(frame, frame_len, &handle) || handle != end->hears_as)
		return FZN_SESSION_FRAME_ERR_SHAPE;
	counter = fzn_get_be32(frame + COUNTER_AT);
	/* 0 IS NEVER SEALED: the first counter is 1, so `newest` 0 is none heard. */
	if (counter == 0u || stale(end, counter))
		return FZN_SESSION_FRAME_ERR_REPLAY;
	text = frame + FZN_SESSION_FRAME_HEAD_LEN;
	text_len = frame_len - FZN_SESSION_FRAME_HEAD_LEN - FZN_AEAD_TAG_LEN;
	nonce_of(counter, nonce);
	if (!aead->open(aead->ctx, end->recv_key, nonce, frame, FZN_SESSION_FRAME_HEAD_LEN, text,
	                text_len, frame + FZN_SESSION_FRAME_HEAD_LEN + text_len))
		return FZN_SESSION_FRAME_ERR_TAG;
	mark_heard(end, counter);
	out->msg = fzn_get_be32(text);
	out->expires_at = fzn_get_be32(text + 4u);
	out->counter = counter;
	out->payload = text + FZN_SESSION_FRAME_SEALED_HEAD_LEN;
	out->payload_len = text_len - FZN_SESSION_FRAME_SEALED_HEAD_LEN;
	return FZN_SESSION_FRAME_OK;
}
