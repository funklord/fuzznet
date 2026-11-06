/* The smallest host against a gateway in this process: device/device.h. The
 * bearer here is a queue, its losses chosen. tool/live_device.py is the same
 * against a real daemon, through a bridge. */

#include "../device.h"
#include "../../node/types.h"
#include "../../session/aead_monocypher.h"
#include "../../session/hash_monocypher.h"
#include "../../session/random_system.h"
#include "../../wire/bytes.h"

#include <stdio.h>
#include <string.h>

static int failures, checks;

#define CHECK(c, what)                                                        \
	do {                                                                      \
		checks++;                                                             \
		if (!(c)) {                                                           \
			failures++;                                                       \
			fprintf(stderr, "  FAIL device_test.c:%d: %s\n", __LINE__, what); \
		}                                                                     \
	} while (0)

static fzn_hash_ops_t hash;
static fzn_aead_ops_t aead;
static fzn_random_ops_t rng;
static fzn_device_image_t image;

/* THE CLOCK: moved by hand, so a wait passes when nothing is heard. */
static uint64_t uptime;

static uint64_t tick(void *ctx)
{
	(void)ctx;
	return uptime;
}

/* THE GATEWAY: what it joined, how many frames it saw, what it said back. */
#define GATEWAY_TIME_MS 5000000000ull
static fzn_bearer_slot_t gate_slot;
static fzn_bearer_join_t gate_join;
static fzn_bearer_t back;
static unsigned frames_seen, drop_frames, answers_to_lose, answer_status;
static uint32_t seen_msgs[16];
static uint64_t last_expiry;
static int say_stranger, answer_wrong_nonce, answer_wrong_msg;

/* What the gateway sends, waiting for the device to hear it. */
static uint8_t queue[64][FZN_BEARER_UNIT_MAX];
static size_t queue_len[64], queue_head, queue_tail;

static int to_device(void *ctx, const uint8_t *bytes, size_t len)
{
	(void)ctx;
	memcpy(queue[queue_tail % 64u], bytes, len);
	queue_len[queue_tail++ % 64u] = len;
	return 1;
}

static void gateway_says(const fzn_opened_t *asked, const uint8_t *payload, size_t len,
                         const uint8_t *key, const uint8_t *ckey)
{
	static const uint8_t none[FZN_CAP_ID_LEN];
	uint8_t frame[FZN_BEARER_FRAME_MAX];
	uint8_t sender[FZN_PUBKEY_LEN];
	fzn_send_t what;
	size_t n = 0;

	memset(sender, 0x47, sizeof(sender));
	memset(&what, 0, sizeof(what));
	what.sender = sender;
	what.capability = none;
	what.payload = payload;
	what.payload_len = len;
	what.expires_at = 0;
	what.msg = asked->msg + (answer_wrong_msg ? 1u : 0u);
	what.chunks = 1u;
	what.kind = FZN_KIND_UNIT;
	what.hops = 1u;
	CHECK(fzn_seal_build(frame, sizeof(frame), &n, &what, key, ckey, &hash, &rng, &aead)
	              == FZN_SEAL_OK,
	      "the gateway could not seal");
	CHECK(fzn_bearer_send(&back, 77u, frame, n) == 1, "the gateway could not send");
}

static int from_device(void *ctx, const uint8_t *bytes, size_t len)
{
	static uint8_t frame[FZN_BEARER_FRAME_MAX];
	const uint8_t *whole = NULL;
	fzn_opened_t opened;
	uint8_t reply[64];
	size_t n;

	(void)ctx;
	if (!(n = fzn_bearer_take(&gate_join, bytes, len, &whole)))
		return 1;
	if (drop_frames) {
		drop_frames--;
		return 1;
	}
	memcpy(frame, whole, n);
	if (fzn_seal_open(frame, n, image.send_key, image.send_ckey, &hash, &aead, &opened)
	    != FZN_SEAL_OK) {
		CHECK(0, "a device's frame did not open");
		return 1;
	}
	CHECK(memcmp(opened.sender, image.sender, FZN_PUBKEY_LEN) == 0, "the frame's sender moved");
	CHECK(memcmp(opened.capability, image.capability, FZN_CAP_ID_LEN) == 0,
	      "the frame's capability moved");
	seen_msgs[frames_seen++ % 16u] = opened.msg;
	if (answers_to_lose) {
		answers_to_lose--;
		return 1;
	}
	if (say_stranger) {
		uint8_t wrong_key[FZN_AEAD_KEY_LEN], wrong_ckey[FZN_COMMITMENT_KEY_LEN];

		memset(wrong_key, 0x13, sizeof(wrong_key));
		memset(wrong_ckey, 0x14, sizeof(wrong_ckey));
		reply[0] = FZN_TYPES_VERSION_SHARED;
		reply[1] = FZN_TYPE_CALLED;
		reply[2] = 99u;
		gateway_says(&opened, reply, 3u, wrong_key, wrong_ckey);
	}
	reply[0] = FZN_TYPES_VERSION_SHARED;
	if (opened.payload[1] == FZN_TYPE_TIME_ASK) {
		reply[1] = FZN_TYPE_TIME;
		memcpy(reply + 2, opened.payload + 2, 16u);
		if (answer_wrong_nonce)
			reply[2] ^= 1u;
		fzn_put_be64(reply + 18, GATEWAY_TIME_MS);
		gateway_says(&opened, reply, 26u, image.send_key, image.send_ckey);
		return 1;
	}
	last_expiry = opened.expires_at;
	CHECK(opened.payload[1] == FZN_TYPE_CALL, "a device sent neither ask nor call");
	reply[1] = FZN_TYPE_CALLED;
	reply[2] = (uint8_t)answer_status;
	memcpy(reply + 3, opened.payload + 3, opened.payload[2]);
	gateway_says(&opened, reply, 3u + opened.payload[2], image.send_key, image.send_ckey);
	return 1;
}

static size_t hear(void *ctx, uint8_t *out, size_t cap, unsigned wait_ms)
{
	size_t n;

	(void)ctx;
	if (queue_head == queue_tail) {
		uptime += wait_ms;
		return 0;
	}
	n = queue_len[queue_head % 64u];
	if (n > cap)
		n = cap;
	memcpy(out, queue[queue_head++ % 64u], n);
	return n;
}

static void device_up(fzn_device_t *d, fzn_bearer_t *b, fzn_bearer_join_t *j,
                      fzn_bearer_slot_t *slot, size_t unit)
{
	memset(d, 0, sizeof(*d));
	memset(b, 0, sizeof(*b));
	memset(j, 0, sizeof(*j));
	memset(&gate_slot, 0, sizeof(gate_slot));
	memset(&gate_join, 0, sizeof(gate_join));
	gate_join.held = &gate_slot;
	gate_join.n_held = 1u;
	gate_join.unit = unit;
	back.unit = unit;
	back.send = to_device;
	b->unit = unit;
	b->send = from_device;
	b->recv = hear;
	j->held = slot;
	j->n_held = 1u;
	j->unit = unit;
	d->image = image;
	d->hash = &hash;
	d->aead = &aead;
	d->rng = &rng;
	d->bearer = b;
	d->join = j;
	d->uptime_ms = tick;
	d->wait_ms = 1000u;
	d->tries = 4u;
	d->life_s = 60u;
	queue_head = queue_tail = 0;
	frames_seen = 0;
}

int main(void)
{
	static fzn_device_t d;
	static fzn_bearer_slot_t slot;
	static const size_t units[] = { 51u, 222u, 1200u };
	char text[FZN_DEVICE_IMAGE_TEXT_LEN + 1u];
	fzn_device_image_t again;
	fzn_bearer_t b;
	fzn_bearer_join_t j;
	uint8_t answer[64];
	size_t k, len = 0;
	unsigned status = 9u;

	fzn_hash_monocypher_init(&hash);
	fzn_aead_monocypher_init(&aead);
	fzn_random_system_init(&rng);
	memset(image.sender, 0x31, sizeof(image.sender));
	memset(image.capability, 0x32, sizeof(image.capability));
	memset(image.send_key, 0x33, sizeof(image.send_key));
	memset(image.send_ckey, 0x34, sizeof(image.send_ckey));

	/* THE IMAGE, as text and back. */
	fzn_device_image_text(&image, text);
	CHECK(strlen(text) == FZN_DEVICE_IMAGE_TEXT_LEN, "an image's text is not its length");
	CHECK(fzn_device_image_from_text(text, strlen(text), &again) == 1
	              && memcmp(&again, &image, sizeof(image)) == 0,
	      "an image did not come back");
	CHECK(fzn_device_image_from_text(text, strlen(text) - 1u, &again) == 0, "a short image read");
	text[0] = 'X';
	CHECK(fzn_device_image_from_text(text, strlen(text), &again) == 0, "no prefix read");
	text[0] = 'F';
	text[6] = 'g';
	CHECK(fzn_device_image_from_text(text, strlen(text), &again) == 0, "a bad digit read");
	text[6] = '1';
	text[FZN_DEVICE_IMAGE_PREFIX_LEN + 1u] = '9';
	CHECK(fzn_device_image_from_text(text, strlen(text), &again) == 0, "another version read");

	/* A CALL, ON EACH UNIT: the time asked first, then the call. */
	for (k = 0; k < sizeof(units) / sizeof(units[0]); k++) {
		device_up(&d, &b, &j, &slot, units[k]);
		uptime = 777000u;
		CHECK(fzn_device_call(&d, "press", (const uint8_t *)"x", 1u, answer, sizeof(answer), &len,
		                      &status)
		              == FZN_DEVICE_OK,
		      "a call was not answered");
		CHECK(status == 0u && len == 5u && memcmp(answer, "press", 5u) == 0,
		      "a call's answer did not read");
		CHECK(frames_seen == 2u && d.clock_known, "the time was not asked first");
		/* AN EXPIRY IN THE GATEWAY'S TERMS, though this device has no such clock. */
		CHECK(last_expiry >= GATEWAY_TIME_MS / 1000u + 59u
		              && last_expiry <= GATEWAY_TIME_MS / 1000u + 61u,
		      "an expiry was not by the gateway's clock");
		CHECK(seen_msgs[0] != seen_msgs[1], "the ask and the call shared a message");
	}

	/* A LOST FRAME: sent again, and the clock asked once. */
	device_up(&d, &b, &j, &slot, 51u);
	drop_frames = 2u;
	CHECK(fzn_device_call(&d, "press", NULL, 0u, answer, sizeof(answer), &len, &status)
	              == FZN_DEVICE_OK,
	      "a lost frame was not recovered");

	/* A LOST ANSWER: the same message, so a kept reply can answer it. */
	device_up(&d, &b, &j, &slot, 222u);
	CHECK(fzn_device_clock(&d) == FZN_DEVICE_OK, "the clock was not asked");
	frames_seen = 0;
	answers_to_lose = 1u;
	CHECK(fzn_device_call(&d, "press", NULL, 0u, answer, sizeof(answer), &len, &status)
	              == FZN_DEVICE_OK,
	      "a lost answer was not recovered");
	CHECK(frames_seen == 2u && seen_msgs[0] == seen_msgs[1],
	      "a resend went as a new message, so a press could count twice");

	/* NOBODY THERE: the tries are bounded, and the clock is asked again. */
	device_up(&d, &b, &j, &slot, 222u);
	CHECK(fzn_device_clock(&d) == FZN_DEVICE_OK, "the clock was not asked");
	drop_frames = 1000u;
	CHECK(fzn_device_call(&d, "press", NULL, 0u, answer, sizeof(answer), &len, &status)
	              == FZN_DEVICE_ERR_SILENT,
	      "silence was not said");
	drop_frames = 0;
	CHECK(!d.clock_known, "a silent gateway left the clock believed");

	/* A STRANGER ON THE SAME RADIO: its frame does not open, and is passed over. */
	device_up(&d, &b, &j, &slot, 222u);
	say_stranger = 1;
	status = 9u;
	CHECK(fzn_device_call(&d, "press", NULL, 0u, answer, sizeof(answer), &len, &status)
	              == FZN_DEVICE_OK
	              && status == 0u,
	      "a stranger's frame was believed");
	say_stranger = 0;

	/* ANOTHER QUESTION'S ANSWER is not this one's. */
	device_up(&d, &b, &j, &slot, 222u);
	CHECK(fzn_device_clock(&d) == FZN_DEVICE_OK, "the clock was not asked");
	answer_wrong_msg = 1;
	CHECK(fzn_device_call(&d, "press", NULL, 0u, answer, sizeof(answer), &len, &status)
	              == FZN_DEVICE_ERR_SILENT,
	      "another message's answer was taken");
	answer_wrong_msg = 0;

	/* A TIME FOR ANOTHER ASK sets no clock. */
	device_up(&d, &b, &j, &slot, 222u);
	answer_wrong_nonce = 1;
	CHECK(fzn_device_clock(&d) == FZN_DEVICE_ERR_ANSWER && !d.clock_known,
	      "a time answering another ask was taken");
	answer_wrong_nonce = 0;

	/* NOT CALLS. */
	device_up(&d, &b, &j, &slot, 222u);
	CHECK(fzn_device_call(&d, "", NULL, 0u, answer, sizeof(answer), &len, &status)
	              == FZN_DEVICE_ERR_MALFORMED,
	      "no name was called");
	CHECK(fzn_device_call(&d, "012345678901234567890123456789012", NULL, 0u, answer, sizeof(answer),
	                      &len, &status)
	              == FZN_DEVICE_ERR_MALFORMED,
	      "too long a name was called");
	CHECK(fzn_device_call(&d, "press", NULL, 2000u, answer, sizeof(answer), &len, &status)
	              == FZN_DEVICE_ERR_MALFORMED,
	      "args with no bytes were called");

	/* TOO SMALL A ROOM refuses the answer rather than cutting it. */
	device_up(&d, &b, &j, &slot, 222u);
	CHECK(fzn_device_call(&d, "press", NULL, 0u, answer, 2u, &len, &status) == FZN_DEVICE_ERR_ANSWER,
	      "a cut answer was given");

	printf("device_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
