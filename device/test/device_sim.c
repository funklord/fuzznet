/*
 * A DEVICE OVER A STREAM, for `tool/live_device.py`: `device/device.h` as a
 * board would run it, its bearer SLIP on stdin and stdout. It asks a call and
 * says on stderr what came back.
 *
 *     device_sim IMAGE UNIT|udp:HOST:PORT NAME [ARGS [PRESSES [LIFE]]]
 *
 * PRESSES calls, 1 by default, a moment apart, in the one session they share,
 * each living LIFE seconds, 60 by default. LIFE 0 is a call already expired, by a
 * clock set back after the session's grant, and so few tries that no second grant
 * sets it right.
 * `udp:` goes straight to a host's port, as a client on a host would. NAME `-` says
 * ARGS rather than calling, and exits 4 unless each was answered (sec 935). What
 * the gateway says unasked is printed as it is heard.
 * Stops when each has been answered or a call's tries run out, each try bounded
 * by `wait_ms`; nothing here waits on anything else.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../device.h"
#include "../../net/udp.h"
#include "../../session/aead_monocypher.h"
#include "../../session/hash_monocypher.h"
#include "../../session/random_system.h"

static uint64_t monotonic_ms(void *ctx)
{
	struct timespec ts;

	(void)ctx;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static int stream_send(void *ctx, const uint8_t *bytes, size_t len)
{
	static uint8_t coded[2u * FZN_BEARER_UNIT_MAX + 2u];
	size_t n = fzn_slip_encode(bytes, len, coded, sizeof(coded)), at = 0;

	(void)ctx;
	while (at < n) {
		ssize_t w = write(1, coded + at, n - at);

		if (w <= 0)
			return 0;
		at += (size_t)w;
	}
	return n != 0;
}

/* ONE UNIT OFF STDIN within `wait_ms`, a byte at a time as a UART gives them. */
static size_t stream_recv(void *ctx, uint8_t *out, size_t cap, unsigned wait_ms)
{
	static fzn_slip_reader_t reader;
	static uint8_t held[FZN_BEARER_UNIT_MAX];
	uint64_t until = monotonic_ms(NULL) + wait_ms;

	(void)ctx;
	reader.buffer = held;
	reader.cap = sizeof(held);
	for (;;) {
		struct pollfd p = { 0, POLLIN, 0 };
		uint64_t now = monotonic_ms(NULL);
		uint8_t byte;
		size_t done;

		if (now >= until || poll(&p, 1u, (int)(until - now)) <= 0 || read(0, &byte, 1u) != 1)
			return 0;
		done = fzn_slip_feed(&reader, byte);
		if (done && done <= cap) {
			memcpy(out, held, done);
			return done;
		}
	}
}

static unsigned long heard_count;

static void heard(void *ctx, const uint8_t *bytes, size_t len)
{
	(void)ctx;
	heard_count++;
	fprintf(stderr, "device: heard %zu byte(s): %.*s\n", len, (int)len, (const char *)bytes);
}

int main(int argc, char **argv)
{
	static fzn_device_t d;
	static fzn_bearer_slot_t slot;
	static uint8_t answer[1024];
	fzn_hash_ops_t hash;
	fzn_aead_ops_t aead;
	fzn_random_ops_t rng;
	fzn_bearer_t bearer;
	fzn_bearer_join_t join;
	static fzn_udp_link_t link;
	const char *args = argc > 4 ? argv[4] : "";
	unsigned long presses = argc > 5 ? strtoul(argv[5], NULL, 10) : 1u, p;
	fzn_device_err_t err;
	size_t len = 0;
	unsigned status = 0;

	if (argc < 4 || !fzn_device_image_from_text(argv[1], strlen(argv[1]), &d.image)) {
		fprintf(stderr, "usage: device_sim IMAGE UNIT NAME [ARGS]\n");
		return 2;
	}
	fzn_hash_monocypher_init(&hash);
	fzn_aead_monocypher_init(&aead);
	fzn_random_system_init(&rng);
	memset(&bearer, 0, sizeof(bearer));
	bearer.unit = strtoul(argv[2], NULL, 10);
	bearer.send = stream_send;
	bearer.recv = stream_recv;
	memset(&join, 0, sizeof(join));
	join.held = &slot;
	join.n_held = 1u;
	join.unit = bearer.unit;
	d.hash = &hash;
	d.aead = &aead;
	d.rng = &rng;
	d.bearer = &bearer;
	d.join = &join;
	d.uptime_ms = monotonic_ms;
	/* A LOOPBACK'S ANSWER COMES AT ONCE, so waits are short and tries many: at 10
	 * per cent of units lost a frame of four pieces each way gets through about
	 * two tries in five, which 8 tries missed often enough to fail a run. */
	d.wait_ms = 400u;
	d.tries = 30u;
	d.life_s = argc > 6 ? (unsigned)strtoul(argv[6], NULL, 10) : 60u;
	if (strncmp(argv[2], "udp:", 4u) == 0) {
		char *colon = strrchr(argv[2] + 4, ':');

		if (!colon)
			return 2;
		*colon = '\0';
		if (fzn_udp_resolve(AF_INET, argv[2] + 4, (uint16_t)strtoul(colon + 1, NULL, 10), &link.to)
		            != FZN_UDP_OK
		    || fzn_udp_bind(AF_INET, NULL, 0u, &link.fd) != FZN_UDP_OK)
			return 2;
		fzn_udp_bearer(&bearer, &link);
	}
	d.heard = heard;
	if (d.life_s == 0u) {
		d.tries = 3u;
		if (fzn_device_open(&d) != FZN_DEVICE_OK)
			return 1;
		d.clock_offset_ms -= 5000;
	}
	for (p = 0; p < presses; p++) {
		const struct timespec moment = { 0, 150000000 };

		if (p)
			(void)nanosleep(&moment, NULL);
		if (strcmp(argv[3], "-") == 0) {
			if ((err = fzn_device_say(&d, (const uint8_t *)args, strlen(args))) != FZN_DEVICE_OK) {
				fprintf(stderr, "device: %s\n", fzn_device_err_str(err));
				return 1;
			}
			fzn_device_listen(&d, d.wait_ms);
			continue;
		}
		err = fzn_device_call(&d, argv[3], (const uint8_t *)args, strlen(args), answer,
		                      sizeof(answer), &len, &status);
		if (err != FZN_DEVICE_OK) {
			fprintf(stderr, "device: %s\n", fzn_device_err_str(err));
			return 1;
		}
		fprintf(stderr, "device: status %u, %zu byte(s): %.*s\n", status, len, (int)len,
		        (const char *)answer);
		if (status != 0u)
			return 3;
		fzn_device_listen(&d, 100u);
	}
	if (strcmp(argv[3], "-") == 0 && heard_count < presses)
		return 4;
	return 0;
}
