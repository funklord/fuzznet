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
static int say_stranger, grant_wrong, answer_wrong_msg, answer_in_full;
/* THE GATEWAY'S END OF THE SESSION, and what it granted last. */
static fzn_session_end_t gate_end;
static int gate_up;
static unsigned asks_seen, units_up, units_down;
static uint32_t gate_handle;
/* SAID, sec 935: what the gateway took with no message, and heard from it. */
static unsigned said_seen, heard_seen;
static int say_first;
static uint8_t heard_bytes[16];

static void heard(void *ctx, const uint8_t *bytes, size_t len)
{
	(void)ctx;
	heard_seen++;
	if (len <= sizeof(heard_bytes))
		memcpy(heard_bytes, bytes, len);
}

/* What the gateway sends, waiting for the device to hear it. */
static uint8_t queue[64][FZN_BEARER_UNIT_MAX];
static size_t queue_len[64], queue_head, queue_tail;

static int to_device(void *ctx, const uint8_t *bytes, size_t len)
{
	(void)ctx;
	units_down++;
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
	units_up++;
	if (!(n = fzn_bearer_take(&gate_join, bytes, len, &whole)))
		return 1;
	if (drop_frames) {
		drop_frames--;
		return 1;
	}
	memcpy(frame, whole, n);
	/* A SESSION FRAME: what a gateway started again cannot read, and says
	 * nothing to. */
	if (frame[0] == FZN_SESSION_FRAME_MARK) {
		fzn_session_opened_t got;
		uint8_t out[FZN_SESSION_FRAME_MAX];
		size_t out_len = 0;

		if (!gate_up)
			return 1;
		CHECK(fzn_session_frame_open(&gate_end, frame, n, &aead, &got) == FZN_SESSION_FRAME_OK,
		      "a device's session frame did not open");
		if (got.msg == 0u) {
			said_seen++;
			return 1;
		}
		seen_msgs[frames_seen++ % 16u] = got.msg;
		last_expiry = got.expires_at;
		if (answers_to_lose) {
			answers_to_lose--;
			return 1;
		}
		CHECK(got.payload[1] == FZN_TYPE_CALL, "a session frame held no call");
		reply[0] = FZN_TYPES_VERSION_SHARED;
		reply[1] = FZN_TYPE_CALLED;
		reply[2] = (uint8_t)answer_status;
		memcpy(reply + 3, got.payload + 3, got.payload[2]);
		if (say_first) {
			CHECK(fzn_session_frame_seal(&gate_end, 0u, 0u, (const uint8_t *)"ding", 4u, out,
			                             sizeof(out), &out_len, &aead)
			              == FZN_SESSION_FRAME_OK,
			      "the gateway could not say");
			CHECK(fzn_bearer_send(&back, 79u, out, out_len) == 1, "the gateway could not send");
		}
		if (answer_in_full) {
			memset(&opened, 0, sizeof(opened));
			opened.msg = got.msg;
			gateway_says(&opened, reply, 3u + got.payload[2], image.send_key, image.send_ckey);
			return 1;
		}
		if (say_stranger) {
			static fzn_session_end_t other;
			uint8_t bad[3] = { FZN_TYPES_VERSION_SHARED, FZN_TYPE_CALLED, 99u };

			memset(&other, 0, sizeof(other));
			memset(other.send_key, 0x15, sizeof(other.send_key));
			other.speaks_to = gate_end.speaks_to;
			CHECK(fzn_session_frame_seal(&other, got.msg, 0u, bad, sizeof(bad), out, sizeof(out),
			                             &out_len, &aead)
			              == FZN_SESSION_FRAME_OK,
			      "a stranger could not seal");
			CHECK(fzn_bearer_send(&back, 76u, out, out_len) == 1, "a stranger could not send");
		}
		CHECK(fzn_session_frame_seal(&gate_end, got.msg + (answer_wrong_msg ? 1u : 0u), 0u, reply,
		                             3u + got.payload[2], out, sizeof(out), &out_len, &aead)
		              == FZN_SESSION_FRAME_OK,
		      "the gateway could not seal in the session");
		CHECK(fzn_bearer_send(&back, 78u, out, out_len) == 1, "the gateway could not send");
		return 1;
	}
	if (fzn_seal_open(frame, n, image.send_key, image.send_ckey, &hash, &aead, &opened)
	    != FZN_SEAL_OK) {
		CHECK(0, "a device's frame did not open");
		return 1;
	}
	CHECK(memcmp(opened.sender, image.sender, FZN_PUBKEY_LEN) == 0, "the frame's sender moved");
	CHECK(memcmp(opened.capability, image.capability, FZN_CAP_ID_LEN) == 0,
	      "the frame's capability moved");
	CHECK(opened.payload_len == 2u + FZN_SESSION_ASK_LEN
	              && opened.payload[1] == FZN_TYPE_SESSION_ASK,
	      "a full frame held anything but an ask");
	seen_msgs[frames_seen++ % 16u] = opened.msg;
	asks_seen++;
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
	reply[1] = FZN_TYPE_SESSION_GRANT;
	memset(reply + 2, 0x5A, FZN_SESSION_RANDOM_LEN);
	gate_handle += 0x1001u;
	fzn_put_be32(reply + 2 + FZN_SESSION_RANDOM_LEN, gate_handle);
	fzn_put_be64(reply + 2 + FZN_SESSION_RANDOM_LEN + 4u, GATEWAY_TIME_MS);
	CHECK(fzn_session_end_derive(&gate_end, &hash, image.send_key, opened.payload + 2, reply + 2, 0),
	      "the gateway could not derive");
	gate_up = 1;
	gateway_says(&opened, reply, grant_wrong ? 3u : 2u + FZN_SESSION_GRANT_LEN, image.send_key,
	             image.send_ckey);
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
	asks_seen = 0;
	gate_up = 0;
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

	/* A CALL, ON EACH UNIT: a session asked for first, then the call in it. */
	for (k = 0; k < sizeof(units) / sizeof(units[0]); k++) {
		device_up(&d, &b, &j, &slot, units[k]);
		uptime = 777000u;
		CHECK(fzn_device_call(&d, "press", (const uint8_t *)"x", 1u, answer, sizeof(answer), &len,
		                      &status)
		              == FZN_DEVICE_OK,
		      "a call was not answered");
		CHECK(status == 0u && len == 5u && memcmp(answer, "press", 5u) == 0,
		      "a call's answer did not read");
		CHECK(frames_seen == 2u && d.session_up && asks_seen == 1u, "no session was asked first");
		/* AN EXPIRY IN THE GATEWAY'S TERMS, though this device has no such clock. */
		CHECK(last_expiry >= GATEWAY_TIME_MS / 1000u + 59u
		              && last_expiry <= GATEWAY_TIME_MS / 1000u + 61u,
		      "an expiry was not by the gateway's clock");
		CHECK(seen_msgs[0] != seen_msgs[1], "the ask and the call shared a message");
	}

	/* WHAT IT IS FOR: at 51 bytes the next call is one unit each way, where a
	 * full frame takes four. */
	device_up(&d, &b, &j, &slot, 51u);
	CHECK(fzn_device_open(&d) == FZN_DEVICE_OK, "no session");
	units_up = units_down = 0;
	CHECK(fzn_device_call(&d, "press", NULL, 0u, answer, sizeof(answer), &len, &status)
	              == FZN_DEVICE_OK,
	      "a call in a session was not answered");
	CHECK(units_up == 1u && units_down == 1u, "a call in a session took more than a unit each way");
	CHECK(asks_seen == 1u, "a standing session was asked for again");

	/* AN ANSWER TOO LONG FOR ONE GOES FULL, and a device opens that as well. */
	device_up(&d, &b, &j, &slot, 222u);
	answer_in_full = 1;
	CHECK(fzn_device_call(&d, "press", NULL, 0u, answer, sizeof(answer), &len, &status)
	              == FZN_DEVICE_OK
	              && len == 5u,
	      "a full frame's answer was not taken in a session");
	answer_in_full = 0;

	/* THE GATEWAY STARTED AGAIN: it says nothing, the device gives the session up
	 * and asks, and the press goes again under its own number, so a kept reply
	 * would answer it. */
	device_up(&d, &b, &j, &slot, 51u);
	d.tries = 8u;
	CHECK(fzn_device_open(&d) == FZN_DEVICE_OK, "no session");
	answers_to_lose = 3u;
	frames_seen = 0;
	CHECK(fzn_device_call(&d, "press", NULL, 0u, answer, sizeof(answer), &len, &status)
	              == FZN_DEVICE_OK,
	      "a gateway started again was not asked again");
	CHECK(asks_seen == 2u, "the session was not asked for again");
	CHECK(seen_msgs[0] == seen_msgs[(frames_seen - 1u) % 16u],
	      "a resend under a new session went as a new press");

	/* ONE THAT SAYS NOTHING AT ALL, as a gateway with no such session does. */
	device_up(&d, &b, &j, &slot, 51u);
	d.tries = 8u;
	CHECK(fzn_device_open(&d) == FZN_DEVICE_OK, "no session");
	gate_up = 0;
	CHECK(fzn_device_call(&d, "press", NULL, 0u, answer, sizeof(answer), &len, &status)
	              == FZN_DEVICE_OK
	              && asks_seen == 2u,
	      "silence did not lead to asking again");

	/* SAID, sec 935: no answer asked, and a word heard in the middle of a call is
	 * told, and is not taken for its answer. */
	device_up(&d, &b, &j, &slot, 51u);
	d.heard = heard;
	said_seen = heard_seen = 0;
	units_up = 0;
	CHECK(fzn_device_say(&d, (const uint8_t *)"hi", 2u) == FZN_DEVICE_OK, "a word was not said");
	CHECK(asks_seen == 1u && said_seen == 1u, "a word did not ask a session first, or was not said");
	units_up = 0;
	CHECK(fzn_device_say(&d, (const uint8_t *)"hi", 2u) == FZN_DEVICE_OK && units_up == 1u
	              && said_seen == 2u && asks_seen == 1u,
	      "a word in a session took more than a unit");
	say_first = 1;
	status = 9u;
	CHECK(fzn_device_call(&d, "press", NULL, 0u, answer, sizeof(answer), &len, &status)
	              == FZN_DEVICE_OK
	              && status == 0u && len == 5u,
	      "a word heard in a call was taken for its answer");
	say_first = 0;
	CHECK(heard_seen == 1u && memcmp(heard_bytes, "ding", 4u) == 0, "a word in a call was not told");
	CHECK(fzn_device_say(&d, NULL, 2u) == FZN_DEVICE_ERR_MALFORMED, "no bytes were said");
	/* NOTHING TO HEAR: a listen ends at its wait. */
	uptime = 1000u;
	fzn_device_listen(&d, 500u);
	CHECK(uptime >= 1500u, "a listen ended early");
	/* A MESSAGE NUMBER IS NEVER THE ONE NOBODY ANSWERS. */
	d.next_msg = UINT32_MAX;
	CHECK(fzn_device_call(&d, "press", NULL, 0u, answer, sizeof(answer), &len, &status)
	              == FZN_DEVICE_OK
	              && d.next_msg == 1u,
	      "a message number went round to 0");

	/* A LOST FRAME: sent again. */
	device_up(&d, &b, &j, &slot, 51u);
	drop_frames = 2u;
	CHECK(fzn_device_call(&d, "press", NULL, 0u, answer, sizeof(answer), &len, &status)
	              == FZN_DEVICE_OK,
	      "a lost frame was not recovered");

	/* A LOST ANSWER: the same message, so a kept reply can answer it. */
	device_up(&d, &b, &j, &slot, 222u);
	CHECK(fzn_device_open(&d) == FZN_DEVICE_OK, "no session");
	frames_seen = 0;
	answers_to_lose = 1u;
	CHECK(fzn_device_call(&d, "press", NULL, 0u, answer, sizeof(answer), &len, &status)
	              == FZN_DEVICE_OK,
	      "a lost answer was not recovered");
	CHECK(frames_seen == 2u && seen_msgs[0] == seen_msgs[1],
	      "a resend went as a new message, so a press could count twice");

	/* NOBODY THERE: the tries are bounded, and the session given up. */
	device_up(&d, &b, &j, &slot, 222u);
	CHECK(fzn_device_open(&d) == FZN_DEVICE_OK, "no session");
	drop_frames = 1000u;
	CHECK(fzn_device_call(&d, "press", NULL, 0u, answer, sizeof(answer), &len, &status)
	              == FZN_DEVICE_ERR_SILENT,
	      "silence was not said");
	drop_frames = 0;
	CHECK(!d.session_up, "a silent gateway left the session believed");

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
	CHECK(fzn_device_open(&d) == FZN_DEVICE_OK, "no session");
	answer_wrong_msg = 1;
	CHECK(fzn_device_call(&d, "press", NULL, 0u, answer, sizeof(answer), &len, &status)
	              == FZN_DEVICE_ERR_SILENT,
	      "another message's answer was taken");
	answer_wrong_msg = 0;

	/* WHAT IS NO GRANT begins no session. */
	device_up(&d, &b, &j, &slot, 222u);
	grant_wrong = 1;
	CHECK(fzn_device_open(&d) == FZN_DEVICE_ERR_ANSWER && !d.session_up, "no grant was taken");
	grant_wrong = 0;

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
