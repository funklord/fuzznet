/* The smallest host. device/device.h says what and why. */

#include "device.h"

#include <string.h>

#include "../node/types.h"
#include "../wire/bytes.h"

/* THE TIME PROBE, as `node/clocks.h` states it. Not called from there, as
 * that file serves a daemon's `list clock` and needs stdio. */
#define PROBE_NONCE_LEN 16u
#define PROBE_ANSWER_LEN (2u + PROBE_NONCE_LEN + 8u)

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

/* `payload` SEALED AS MESSAGE `msg` AND SENT, under a fresh nonce. */
static fzn_device_err_t send_once(fzn_device_t *d, const uint8_t *payload, size_t len,
                                  uint32_t msg, uint64_t expires_at)
{
	fzn_send_t what;
	size_t frame_len = 0;
	uint16_t link_id = 0;

	memset(&what, 0, sizeof(what));
	what.sender = d->image.sender;
	what.capability = d->image.capability;
	what.payload = payload;
	what.payload_len = len;
	what.expires_at = expires_at;
	what.msg = msg;
	what.index = 0;
	what.chunks = 1u;
	what.kind = FZN_KIND_UNIT;
	what.hops = 1u;
	if (!fill(d, &link_id, sizeof(link_id))
	    || fzn_seal_build(d->frame, sizeof(d->frame), &frame_len, &what, d->image.send_key,
	                      d->image.send_ckey, d->hash, d->rng, d->aead)
	               != FZN_SEAL_OK)
		return FZN_DEVICE_ERR_SEAL;
	return fzn_bearer_send(d->bearer, link_id, d->frame, frame_len) ? FZN_DEVICE_OK
	                                                                : FZN_DEVICE_ERR_SEND;
}

/* THE ANSWER TO `msg`, within `wait_ms`: 1 with `opened`. What is not this
 * device's does not open, and on a radio most of what is heard is not. */
static int await(fzn_device_t *d, uint32_t msg, unsigned wait_ms, fzn_opened_t *opened)
{
	uint8_t unit[FZN_BEARER_UNIT_MAX];
	uint64_t until = d->uptime_ms(d->uptime_ctx) + wait_ms;

	for (;;) {
		uint64_t now = d->uptime_ms(d->uptime_ctx);
		const uint8_t *whole = NULL;
		size_t n, len;

		if (now >= until)
			return 0;
		n = d->bearer->recv(d->bearer->ctx, unit, sizeof(unit), (unsigned)(until - now));
		if (!n || !(len = fzn_bearer_take(d->join, unit, n, &whole)))
			continue;
		memcpy(d->frame, whole, len);
		if (fzn_seal_open(d->frame, len, d->image.send_key, d->image.send_ckey, d->hash, d->aead,
		                  opened)
		            == FZN_SEAL_OK
		    && opened->kind != FZN_KIND_NOP && opened->msg == msg && opened->chunks == 1u)
			return 1;
	}
}

static uint32_t next_message(fzn_device_t *d)
{
	/* BEGUN SOMEWHERE OF ITS OWN, sec 910: a device that restarts must not
	 * ask its first question under the number it asked one before. */
	if (d->next_msg == 0u && (!fill(d, &d->next_msg, sizeof(d->next_msg)) || d->next_msg == 0u))
		d->next_msg = 1u;
	return d->next_msg++;
}

fzn_device_err_t fzn_device_clock(fzn_device_t *d)
{
	uint8_t ask[2u + PROBE_NONCE_LEN];
	fzn_opened_t opened;
	uint32_t msg;
	unsigned t;

	if (!usable(d))
		return FZN_DEVICE_ERR_MALFORMED;
	ask[0] = FZN_TYPES_VERSION_SHARED;
	ask[1] = FZN_TYPE_TIME_ASK;
	if (!fill(d, ask + 2, PROBE_NONCE_LEN))
		return FZN_DEVICE_ERR_SEAL;
	msg = next_message(d);
	for (t = 0; t < d->tries; t++) {
		uint64_t sent = d->uptime_ms(d->uptime_ctx), got;
		fzn_device_err_t err = send_once(d, ask, sizeof(ask), msg, 1u);

		if (err != FZN_DEVICE_OK)
			return err;
		if (!await(d, msg, d->wait_ms, &opened))
			continue;
		if (opened.payload_len != PROBE_ANSWER_LEN
		    || opened.payload[0] != FZN_TYPES_VERSION_SHARED
		    || opened.payload[1] != FZN_TYPE_TIME
		    || memcmp(opened.payload + 2, ask + 2, PROBE_NONCE_LEN) != 0)
			return FZN_DEVICE_ERR_ANSWER;
		got = d->uptime_ms(d->uptime_ctx);
		d->clock_offset_ms = (int64_t)fzn_get_be64(opened.payload + 2u + PROBE_NONCE_LEN)
		                     - (int64_t)(sent + (got - sent) / 2u);
		d->clock_known = 1;
		return FZN_DEVICE_OK;
	}
	return FZN_DEVICE_ERR_SILENT;
}

fzn_device_err_t fzn_device_call(fzn_device_t *d, const char *name, const uint8_t *args,
                                 size_t args_len, uint8_t *answer, size_t cap,
                                 size_t *answer_len, unsigned *status)
{
	uint8_t payload[PAYLOAD_MAX];
	fzn_opened_t opened;
	fzn_device_err_t err;
	size_t name_len, len;
	uint32_t msg;
	unsigned t;

	if (!usable(d) || !name || (!args && args_len) || !answer_len || !status)
		return FZN_DEVICE_ERR_MALFORMED;
	name_len = strlen(name);
	len = CALL_HEAD_LEN + name_len + args_len;
	if (!name_len || name_len > FZN_CALL_NAME_MAX || len > sizeof(payload))
		return FZN_DEVICE_ERR_MALFORMED;
	if (!d->clock_known && (err = fzn_device_clock(d)) != FZN_DEVICE_OK)
		return err;
	payload[0] = FZN_TYPES_VERSION_SHARED;
	payload[1] = FZN_TYPE_CALL;
	payload[2] = (uint8_t)name_len;
	memcpy(payload + CALL_HEAD_LEN, name, name_len);
	if (args_len)
		memcpy(payload + CALL_HEAD_LEN + name_len, args, args_len);
	msg = next_message(d);
	for (t = 0; t < d->tries; t++) {
		int64_t now_ms = (int64_t)d->uptime_ms(d->uptime_ctx) + d->clock_offset_ms;

		err = send_once(d, payload, len, msg, (uint64_t)(now_ms / 1000) + d->life_s);
		if (err != FZN_DEVICE_OK)
			return err;
		if (!await(d, msg, d->wait_ms, &opened))
			continue;
		if (opened.payload_len < CALL_HEAD_LEN || opened.payload[0] != FZN_TYPES_VERSION_SHARED
		    || opened.payload[1] != FZN_TYPE_CALLED
		    || opened.payload_len - CALL_HEAD_LEN > cap || (!answer && opened.payload_len > 3u))
			return FZN_DEVICE_ERR_ANSWER;
		*status = opened.payload[2];
		*answer_len = opened.payload_len - CALL_HEAD_LEN;
		if (*answer_len)
			memcpy(answer, opened.payload + CALL_HEAD_LEN, *answer_len);
		return FZN_DEVICE_OK;
	}
	/* ASKED AGAIN NEXT TIME: its clock may be why nothing answered. */
	d->clock_known = 0;
	return FZN_DEVICE_ERR_SILENT;
}
