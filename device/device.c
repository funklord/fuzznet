/* The smallest host. device/device.h says what and why. */

#include "device.h"

#include <string.h>

#include "../node/types.h"
#include "../wire/bytes.h"

/* A FULL FRAME ASKS FOR A SESSION AND ONE GRANTS IT: version, type and body. */
#define ASK_PAYLOAD_LEN (2u + FZN_SESSION_ASK_LEN)
#define GRANT_PAYLOAD_LEN (2u + FZN_SESSION_GRANT_LEN)
#define HANDLE_AT FZN_SESSION_RANDOM_LEN

/* TRIES HEARD NOTHING BEFORE THE SESSION IS THOUGHT LOST. One lost unit is common
 * on a radio and costs a resend; asking again costs eight units, and a gateway
 * started again says nothing at all, so this is a sender's only way to know. */
#define SILENCE_BEFORE_ASKING 3u

/* A CALL AS `call_remote` READS IT, and the most one frame holds. */
#define CALL_HEAD_LEN 3u
#define PAYLOAD_MAX (FZN_BEARER_FRAME_MAX - FZN_SEAL_OVERHEAD)

const char *fzn_device_err_str(fzn_device_err_t err)
{
	switch (err) {
	case FZN_DEVICE_OK:
		return "ok";
	case FZN_DEVICE_ERR_MALFORMED:
		return "malformed";
	case FZN_DEVICE_ERR_SEAL:
		return "no frame could be sealed";
	case FZN_DEVICE_ERR_SEND:
		return "the bearer would not send";
	case FZN_DEVICE_ERR_SILENT:
		return "no answer";
	case FZN_DEVICE_ERR_ANSWER:
		return "the answer is no answer, or too long";
	}
	return "unknown";
}

void fzn_device_image_text(const fzn_device_image_t *image, char *out)
{
	static const char hex[] = "0123456789abcdef";
	uint8_t bytes[FZN_DEVICE_IMAGE_LEN];
	size_t i, at = 1u;

	bytes[0] = FZN_DEVICE_IMAGE_VERSION;
	memcpy(bytes + at, image->sender, sizeof(image->sender));
	at += sizeof(image->sender);
	memcpy(bytes + at, image->capability, sizeof(image->capability));
	at += sizeof(image->capability);
	memcpy(bytes + at, image->send_key, sizeof(image->send_key));
	at += sizeof(image->send_key);
	memcpy(bytes + at, image->send_ckey, sizeof(image->send_ckey));
	memcpy(out, FZN_DEVICE_IMAGE_PREFIX, FZN_DEVICE_IMAGE_PREFIX_LEN);
	out += FZN_DEVICE_IMAGE_PREFIX_LEN;
	for (i = 0; i < sizeof(bytes); i++) {
		*out++ = hex[bytes[i] >> 4];
		*out++ = hex[bytes[i] & 15u];
	}
	*out = '\0';
}

static int nibble(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return -1;
}

int fzn_device_image_from_text(const char *text, size_t len, fzn_device_image_t *out)
{
	uint8_t bytes[FZN_DEVICE_IMAGE_LEN];
	size_t i, at = 1u;

	if (!text || !out || len != FZN_DEVICE_IMAGE_TEXT_LEN
	    || memcmp(text, FZN_DEVICE_IMAGE_PREFIX, FZN_DEVICE_IMAGE_PREFIX_LEN) != 0)
		return 0;
	text += FZN_DEVICE_IMAGE_PREFIX_LEN;
	for (i = 0; i < sizeof(bytes); i++) {
		int high = nibble(text[i * 2u]), low = nibble(text[i * 2u + 1u]);

		if (high < 0 || low < 0)
			return 0;
		bytes[i] = (uint8_t)((high << 4) | low);
	}
	if (bytes[0] != FZN_DEVICE_IMAGE_VERSION)
		return 0;
	memcpy(out->sender, bytes + at, sizeof(out->sender));
	at += sizeof(out->sender);
	memcpy(out->capability, bytes + at, sizeof(out->capability));
	at += sizeof(out->capability);
	memcpy(out->send_key, bytes + at, sizeof(out->send_key));
	at += sizeof(out->send_key);
	memcpy(out->send_ckey, bytes + at, sizeof(out->send_ckey));
	return 1;
}

static int usable(const fzn_device_t *d)
{
	return d && d->hash && d->aead && d->rng && d->rng->fill && d->bearer && d->bearer->send
	       && d->bearer->recv && d->join && d->uptime_ms && d->tries;
}

static int fill(const fzn_device_t *d, void *out, size_t len)
{
	return d->rng->fill(d->rng->ctx, (uint8_t *)out, len);
}

static uint16_t fresh_link_id(fzn_device_t *d, int *ok)
{
	uint16_t id = 0;

	*ok = fill(d, &id, sizeof(id));
	return id;
}

/* `payload` SEALED AS MESSAGE `msg` IN A FULL FRAME AND SENT, under a fresh nonce:
 * only ever an ask. */
static fzn_device_err_t send_full(fzn_device_t *d, const uint8_t *payload, size_t len, uint32_t msg)
{
	fzn_send_t what;
	size_t frame_len = 0;
	uint16_t link_id;
	int ok;

	memset(&what, 0, sizeof(what));
	what.sender = d->image.sender;
	what.capability = d->image.capability;
	what.payload = payload;
	what.payload_len = len;
	/* ANSWERED WHATEVER ITS EXPIRY: this frame is how it learns the time. */
	what.expires_at = 1u;
	what.msg = msg;
	what.index = 0;
	what.chunks = 1u;
	what.kind = FZN_KIND_UNIT;
	what.hops = 1u;
	link_id = fresh_link_id(d, &ok);
	if (!ok
	    || fzn_seal_build(d->frame, sizeof(d->frame), &frame_len, &what, d->image.send_key,
	                      d->image.send_ckey, d->hash, d->rng, d->aead)
	               != FZN_SEAL_OK)
		return FZN_DEVICE_ERR_SEAL;
	return fzn_bearer_send(d->bearer, link_id, d->frame, frame_len) ? FZN_DEVICE_OK
	                                                                : FZN_DEVICE_ERR_SEND;
}

/* THE ANSWER TO `msg`, within `wait_ms`, in whichever frame it came: 1 with its
 * payload, in `d->frame`. What is not this device's does not open, and on a radio
 * most of what is heard is not. */
static int await(fzn_device_t *d, uint32_t msg, unsigned wait_ms, const uint8_t **payload,
                 size_t *payload_len)
{
	uint8_t unit[FZN_BEARER_UNIT_MAX];
	uint64_t until = d->uptime_ms(d->uptime_ctx) + wait_ms;

	for (;;) {
		uint64_t now = d->uptime_ms(d->uptime_ctx);
		const uint8_t *whole = NULL;
		fzn_session_opened_t got;
		fzn_opened_t opened;
		size_t n, len;

		if (now >= until)
			return 0;
		n = d->bearer->recv(d->bearer->ctx, unit, sizeof(unit), (unsigned)(until - now));
		if (n && d->bearer->whole) {
			whole = unit;
			len = n;
		} else if (!n || !(len = fzn_bearer_take(d->join, unit, n, &whole))) {
			continue;
		}
		if (len > sizeof(d->frame))
			continue;
		memcpy(d->frame, whole, len);
		if (d->frame[0] == FZN_SESSION_FRAME_MARK) {
			if (!d->session_up
			    || fzn_session_frame_open(&d->session, d->frame, len, d->aead, &got)
			               != FZN_SESSION_FRAME_OK)
				continue;
			if (got.msg == 0u) {
				if (d->heard)
					d->heard(d->heard_ctx, got.payload, got.payload_len);
				continue;
			}
			if (got.msg == msg) {
				*payload = got.payload;
				*payload_len = got.payload_len;
				return 1;
			}
			continue;
		}
		if (fzn_seal_open(d->frame, len, d->image.send_key, d->image.send_ckey, d->hash, d->aead,
		                  &opened)
		            == FZN_SEAL_OK
		    && opened.kind != FZN_KIND_NOP && opened.msg == msg && opened.chunks == 1u) {
			*payload = opened.payload;
			*payload_len = opened.payload_len;
			return 1;
		}
	}
}

static uint32_t next_message(fzn_device_t *d)
{
	uint32_t msg;

	/* BEGUN SOMEWHERE OF ITS OWN, sec 910: a device that restarts must not
	 * ask its first question under the number it asked one before. */
	if (d->next_msg == 0u && (!fill(d, &d->next_msg, sizeof(d->next_msg)) || d->next_msg == 0u))
		d->next_msg = 1u;
	msg = d->next_msg++;
	/* NEVER 0, which is a frame nobody answers (sec 935). */
	if (d->next_msg == 0u)
		d->next_msg = 1u;
	return msg;
}

/* ONE TRY AT A SESSION. The same ask until it is answered, so a gateway that heard
 * it twice gives the grant it gave (`node/sessions.h`). */
static fzn_device_err_t ask_once(fzn_device_t *d)
{
	uint8_t ask[ASK_PAYLOAD_LEN];
	const uint8_t *grant;
	size_t grant_len;
	uint64_t sent, got;
	fzn_device_err_t err;

	if (!d->asking) {
		if (!fill(d, d->ask, FZN_SESSION_RANDOM_LEN)
		    || !fill(d, d->ask + HANDLE_AT, sizeof(uint32_t)))
			return FZN_DEVICE_ERR_SEAL;
		d->ask_msg = next_message(d);
		d->asking = 1;
	}
	ask[0] = FZN_CMD_SESSION;
	ask[1] = FZN_SUBCMD_SESSION_ASK;
	memcpy(ask + 2, d->ask, FZN_SESSION_ASK_LEN);
	sent = d->uptime_ms(d->uptime_ctx);
	if ((err = send_full(d, ask, sizeof(ask), d->ask_msg)) != FZN_DEVICE_OK)
		return err;
	if (!await(d, d->ask_msg, d->wait_ms, &grant, &grant_len))
		return FZN_DEVICE_ERR_SILENT;
	if (grant_len != GRANT_PAYLOAD_LEN || grant[0] != FZN_CMD_SESSION
	    || grant[1] != FZN_SUBCMD_SESSION_GRANT)
		return FZN_DEVICE_ERR_ANSWER;
	if (!fzn_session_end_derive(&d->session, d->hash, d->image.send_key, d->ask, grant + 2, 1))
		return FZN_DEVICE_ERR_SEAL;
	got = d->uptime_ms(d->uptime_ctx);
	d->clock_offset_ms = (int64_t)fzn_get_be64(grant + 2u + HANDLE_AT + 4u)
	                     - (int64_t)(sent + (got - sent) / 2u);
	d->session_up = 1;
	d->silent = 0;
	d->asking = 0;
	return FZN_DEVICE_OK;
}

fzn_device_err_t fzn_device_open(fzn_device_t *d)
{
	unsigned t;

	if (!usable(d))
		return FZN_DEVICE_ERR_MALFORMED;
	if (d->session_up)
		return FZN_DEVICE_OK;
	for (t = 0; t < d->tries; t++) {
		fzn_device_err_t err = ask_once(d);

		if (err != FZN_DEVICE_ERR_SILENT)
			return err;
	}
	return FZN_DEVICE_ERR_SILENT;
}

fzn_device_err_t fzn_device_call(fzn_device_t *d, const char *name, const uint8_t *args,
                                 size_t args_len, uint8_t *answer, size_t cap,
                                 size_t *answer_len, unsigned *status)
{
	uint8_t payload[PAYLOAD_MAX];
	const uint8_t *heard;
	size_t name_len, len, heard_len;
	uint32_t msg;
	unsigned t;

	if (!usable(d) || !name || (!args && args_len) || !answer_len || !status)
		return FZN_DEVICE_ERR_MALFORMED;
	name_len = strlen(name);
	len = CALL_HEAD_LEN + name_len + args_len;
	if (!name_len || name_len > FZN_RRPC_NAME_MAX || len > sizeof(payload))
		return FZN_DEVICE_ERR_MALFORMED;
	payload[0] = FZN_CMD_RRPC;
	payload[1] = FZN_SUBCMD_RRPC_ASK;
	payload[2] = (uint8_t)name_len;
	memcpy(payload + CALL_HEAD_LEN, name, name_len);
	if (args_len)
		memcpy(payload + CALL_HEAD_LEN + name_len, args, args_len);
	msg = next_message(d);
	for (t = 0; t < d->tries; t++) {
		fzn_session_frame_err_t sealed;
		size_t frame_len = 0;
		uint16_t link_id;
		int64_t now_ms;
		int ok;

		if (!d->session_up) {
			fzn_device_err_t err = ask_once(d);

			if (err == FZN_DEVICE_ERR_SILENT)
				continue;
			if (err != FZN_DEVICE_OK)
				return err;
		}
		now_ms = (int64_t)d->uptime_ms(d->uptime_ctx) + d->clock_offset_ms;
		sealed = fzn_session_frame_seal(&d->session, msg,
		                                (uint32_t)(now_ms / 1000) + d->life_s, payload, len, d->frame,
		                                sizeof(d->frame), &frame_len, d->aead);
		if (sealed == FZN_SESSION_FRAME_ERR_SPENT) {
			d->session_up = 0;
			continue;
		}
		link_id = fresh_link_id(d, &ok);
		if (sealed != FZN_SESSION_FRAME_OK || !ok)
			return FZN_DEVICE_ERR_SEAL;
		if (!fzn_bearer_send(d->bearer, link_id, d->frame, frame_len))
			return FZN_DEVICE_ERR_SEND;
		if (!await(d, msg, d->wait_ms, &heard, &heard_len)) {
			/* NOTHING TO BE TOLD BY, so the silence is the telling. */
			if (++d->silent >= SILENCE_BEFORE_ASKING)
				d->session_up = 0;
			continue;
		}
		d->silent = 0;
		if (heard_len < CALL_HEAD_LEN || heard[0] != FZN_CMD_RRPC
		    || heard[1] != FZN_SUBCMD_RRPC_RESULT || heard_len - CALL_HEAD_LEN > cap
		    || (!answer && heard_len > CALL_HEAD_LEN))
			return FZN_DEVICE_ERR_ANSWER;
		*status = heard[2];
		*answer_len = heard_len - CALL_HEAD_LEN;
		if (*answer_len)
			memcpy(answer, heard + CALL_HEAD_LEN, *answer_len);
		return FZN_DEVICE_OK;
	}
	return FZN_DEVICE_ERR_SILENT;
}

fzn_device_err_t fzn_device_say(fzn_device_t *d, const uint8_t *bytes, size_t len)
{
	fzn_device_err_t err;
	fzn_session_frame_err_t sealed;
	size_t frame_len = 0;
	uint16_t link_id;
	int64_t now_ms;
	int ok;

	if (!usable(d) || (!bytes && len) || len > FZN_SESSION_FRAME_PAYLOAD_MAX)
		return FZN_DEVICE_ERR_MALFORMED;
	if ((err = fzn_device_open(d)) != FZN_DEVICE_OK)
		return err;
	now_ms = (int64_t)d->uptime_ms(d->uptime_ctx) + d->clock_offset_ms;
	sealed = fzn_session_frame_seal(&d->session, 0u, (uint32_t)(now_ms / 1000) + d->life_s, bytes,
	                                len, d->frame, sizeof(d->frame), &frame_len, d->aead);
	if (sealed == FZN_SESSION_FRAME_ERR_SPENT) {
		d->session_up = 0;
		return FZN_DEVICE_ERR_SILENT;
	}
	link_id = fresh_link_id(d, &ok);
	if (sealed != FZN_SESSION_FRAME_OK || !ok)
		return FZN_DEVICE_ERR_SEAL;
	return fzn_bearer_send(d->bearer, link_id, d->frame, frame_len) ? FZN_DEVICE_OK
	                                                                : FZN_DEVICE_ERR_SEND;
}

void fzn_device_listen(fzn_device_t *d, unsigned wait_ms)
{
	const uint8_t *none;
	size_t none_len;

	if (usable(d))
		(void)await(d, 0u, wait_ms, &none, &none_len);
}
