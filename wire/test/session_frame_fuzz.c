/* THE FIRST THING A SESSION FRAME MEETS, over bytes that were never one, sec 932.
 * `fzn_session_frame_handle` runs before any key is chosen, so anyone who can put
 * a packet on the wire reaches it, and `fzn_session_frame_open` reads a counter
 * and a window from bytes nothing has yet proved.
 *
 * THREE PROPERTIES:
 *
 *   1. NOTHING ESCAPES THE BUFFER. What an open publishes lies inside the frame,
 *      and a sanitizer catches a read past the end.
 *   2. WHAT DID NOT OPEN MOVED NOTHING. The end is byte for byte what it was, so
 *      no stranger's frame costs a real one its counter.
 *   3. ONLY A FRAME UNCHANGED OPENS, and only once. A valid frame is cut, grown
 *      and flipped, near misses being where an accept path is tested; a counter
 *      proves each kind of refusal was reached.
 */
#include "../session_frame.h"
#include "../../session/aead_monocypher.h"
#include "../../session/hash_monocypher.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 200000ul
#define FUZZ_MIN_CASES 20000u

static uint64_t state = 0x243F6A8885A308D3ull;

static uint32_t draw(void)
{
	state ^= state << 13;
	state ^= state >> 7;
	state ^= state << 17;
	return (uint32_t)(state >> 32);
}

static int failures;

static void fail(const char *what)
{
	failures++;
	fprintf(stderr, "session_frame_fuzz: FAIL: %s\n", what);
}

int main(int argc, char **argv)
{
	static uint8_t buf[FZN_SESSION_FRAME_MAX + 16u], valid[256];
	unsigned long cases = FUZZ_DEFAULT_CASES, i, opened = 0, shape = 0, replay = 0, tag = 0;
	uint8_t root[FZN_AEAD_KEY_LEN], ask[FZN_SESSION_ASK_LEN], grant[FZN_SESSION_GRANT_LEN];
	fzn_hash_ops_t hash;
	fzn_aead_ops_t aead;
	fzn_session_end_t from, to, before;
	size_t valid_len = 0;

	if (argc > 1 && (cases = strtoul(argv[1], NULL, 10)) == 0u)
		cases = FUZZ_DEFAULT_CASES;
	if (cases < FUZZ_MIN_CASES) {
		printf("session_frame_fuzz: %lu cases is below FUZZ_MIN_CASES (%u)\n", cases,
		       (unsigned)FUZZ_MIN_CASES);
		return 1;
	}
	fzn_hash_monocypher_init(&hash);
	fzn_aead_monocypher_init(&aead);
	memset(root, 0x11, sizeof(root));
	memset(ask, 0x12, sizeof(ask));
	memset(grant, 0x13, sizeof(grant));
	if (!fzn_session_end_derive(&from, &hash, root, ask, grant, 1)
	    || !fzn_session_end_derive(&to, &hash, root, ask, grant, 0))
		return 1;

	for (i = 0; i < cases; i++) {
		fzn_session_opened_t got;
		fzn_session_frame_err_t err;
		uint32_t handle;
		size_t len, at;

		/* A FRESH VALID FRAME now and then, so the window goes on moving. */
		if (i % 64u == 0u) {
			static const uint8_t payload[] = "sixteen bytes!!";

			if (fzn_session_frame_seal(&from, (uint32_t)i, 9u, payload, sizeof(payload), valid,
			                           sizeof(valid), &valid_len, &aead)
			    != FZN_SESSION_FRAME_OK)
				return 1;
		}
		if (i % 2u == 0u) {
			/* NEVER A FRAME, though its mark and handle may say so. */
			len = draw() % (sizeof(buf) + 1u);
			for (at = 0; at < len; at++)
				buf[at] = (uint8_t)draw();
			if (len && (draw() & 1u))
				buf[0] = FZN_SESSION_FRAME_MARK;
			if (len > 4u && (draw() & 1u)) {
				buf[1] = (uint8_t)(to.hears_as >> 24);
				buf[2] = (uint8_t)(to.hears_as >> 16);
				buf[3] = (uint8_t)(to.hears_as >> 8);
				buf[4] = (uint8_t)to.hears_as;
			}
		} else {
			/* A NEAR MISS. */
			memcpy(buf, valid, valid_len);
			len = valid_len;
			switch (draw() % 3u) {
			case 0:
				buf[draw() % valid_len] ^= (uint8_t)(1u << (draw() % 8u));
				break;
			case 1:
				len = draw() % valid_len;
				break;
			default:
				len = valid_len + 1u + draw() % 8u;
				break;
			}
		}
		if (fzn_session_frame_handle(buf, len, &handle)
		    && (len < FZN_SESSION_FRAME_OVERHEAD || buf[0] != FZN_SESSION_FRAME_MARK))
			fail("a handle was read from what is no frame");
		before = to;
		err = fzn_session_frame_open(&to, buf, len, &aead, &got);
		switch (err) {
		case FZN_SESSION_FRAME_OK:
			opened++;
			fail("a frame not sealed here opened");
			break;
		case FZN_SESSION_FRAME_ERR_SHAPE:
			shape++;
			break;
		case FZN_SESSION_FRAME_ERR_REPLAY:
			replay++;
			break;
		case FZN_SESSION_FRAME_ERR_TAG:
			tag++;
			break;
		default:
			fail("an answer no frame gives");
			break;
		}
		if (memcmp(&before, &to, sizeof(to)) != 0)
			fail("a refused frame moved the end");

		/* THE REAL ONE, once in a while: it opens, inside its buffer, and
		 * then never again. */
		if (i % 64u == 63u) {
			memcpy(buf, valid, valid_len);
			if (fzn_session_frame_open(&to, buf, valid_len, &aead, &got) != FZN_SESSION_FRAME_OK)
				fail("a valid frame was refused after its near misses");
			else if (got.payload < buf || got.payload + got.payload_len > buf + valid_len)
				fail("an open published what lies outside the frame");
			memcpy(buf, valid, valid_len);
			if (fzn_session_frame_open(&to, buf, valid_len, &aead, &got)
			    != FZN_SESSION_FRAME_ERR_REPLAY)
				fail("a valid frame opened twice");
		}
	}
	printf("session_frame_fuzz: %lu cases: %lu shape, %lu replay, %lu tag, %lu opened\n", cases,
	       shape, replay, tag, opened);
	/* A RUN THAT REACHED NONE OF THESE TESTED NOTHING. */
	if (!shape || !replay || !tag)
		fail("a kind of refusal was never reached");
	return failures ? 1 : 0;
}
