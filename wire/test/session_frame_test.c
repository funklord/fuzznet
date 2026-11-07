/* session_frame_test -- `wire/session_frame.h`, sec 932: both ends agree, each
 * byte is bound, a counter is heard once, and a forgery moves nothing. */
#include "../session_frame.h"
#include "../../session/aead_monocypher.h"
#include "../../session/hash_monocypher.h"

#include <stdio.h>
#include <string.h>

static int failures, checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (ok)
		return;
	failures++;
	fprintf(stderr, "  FAIL session_frame_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, what)

static fzn_hash_ops_t hash;
static fzn_aead_ops_t aead;
static fzn_session_end_t left, right;

static void pair_up(void)
{
	uint8_t root[FZN_AEAD_KEY_LEN], ask[FZN_SESSION_ASK_LEN], grant[FZN_SESSION_GRANT_LEN];

	memset(root, 0x21, sizeof(root));
	memset(ask, 0x22, sizeof(ask));
	memset(grant, 0x23, sizeof(grant));
	CHECK(fzn_session_end_derive(&left, &hash, root, ask, grant, 1), "an end did not derive");
	CHECK(fzn_session_end_derive(&right, &hash, root, ask, grant, 0), "an end did not derive");
}

static size_t seal(fzn_session_end_t *from, uint32_t msg, const char *text, uint8_t *frame)
{
	size_t n = 0;

	CHECK(fzn_session_frame_seal(from, msg, 7u, (const uint8_t *)text, strlen(text), frame,
	                             FZN_SESSION_FRAME_MAX, &n, &aead)
	              == FZN_SESSION_FRAME_OK,
	      "a frame did not seal");
	return n;
}

int main(void)
{
	static uint8_t frame[FZN_SESSION_FRAME_MAX], copy[FZN_SESSION_FRAME_MAX], kept[8][64];
	static const uint8_t none[1] = { 0 };
	uint8_t root[FZN_AEAD_KEY_LEN], ask[FZN_SESSION_ASK_LEN], grant[FZN_SESSION_GRANT_LEN];
	fzn_session_end_t other;
	fzn_session_opened_t got;
	size_t n, i, lens[8];
	uint32_t handle = 0;

	fzn_hash_monocypher_init(&hash);
	fzn_aead_monocypher_init(&aead);

	/* THE COST, which is the point of it. */
	CHECK(FZN_SESSION_FRAME_OVERHEAD == 33u, "a session frame is not 33 bytes");

	/* EACH WAY. */
	pair_up();
	CHECK(left.hears_as == right.speaks_to && left.speaks_to == right.hears_as,
	      "the ends disagree on handles");
	CHECK(memcmp(left.send_key, right.recv_key, FZN_AEAD_KEY_LEN) == 0
	              && memcmp(left.recv_key, right.send_key, FZN_AEAD_KEY_LEN) == 0,
	      "the ends disagree on keys");
	CHECK(memcmp(left.send_key, left.recv_key, FZN_AEAD_KEY_LEN) != 0,
	      "both directions share a key, so a frame could be sent back to its sender");
	n = seal(&left, 5u, "hello", frame);
	CHECK(n == FZN_SESSION_FRAME_OVERHEAD + 5u, "a frame is not its overhead and its payload");
	CHECK(fzn_session_frame_handle(frame, n, &handle) && handle == right.hears_as,
	      "a frame does not name its receiver");
	CHECK(fzn_session_frame_open(&right, frame, n, &aead, &got) == FZN_SESSION_FRAME_OK,
	      "a frame did not open");
	CHECK(got.msg == 5u && got.expires_at == 7u && got.counter == 1u && got.payload_len == 5u
	              && memcmp(got.payload, "hello", 5u) == 0,
	      "a frame opened to something else");
	n = seal(&right, 6u, "back", frame);
	CHECK(fzn_session_frame_open(&left, frame, n, &aead, &got) == FZN_SESSION_FRAME_OK
	              && got.msg == 6u,
	      "the other way did not open");

	/* NO PAYLOAD IS ONE. */
	CHECK(fzn_session_frame_seal(&left, 1u, 0u, NULL, 0u, frame, sizeof(frame), &n, &aead)
	              == FZN_SESSION_FRAME_OK
	              && fzn_session_frame_open(&right, frame, n, &aead, &got) == FZN_SESSION_FRAME_OK
	              && got.payload_len == 0u,
	      "an empty frame did not go");

	/* EVERY BYTE OF IT IS BOUND: the head by the tag, as associated data. */
	pair_up();
	n = seal(&left, 5u, "hello", frame);
	for (i = 0; i < n; i++) {
		fzn_session_end_t before = right;

		memcpy(copy, frame, n);
		copy[i] ^= 0x40u;
		CHECK(fzn_session_frame_open(&right, copy, n, &aead, &got) != FZN_SESSION_FRAME_OK,
		      "a changed byte opened");
		CHECK(memcmp(&before, &right, sizeof(right)) == 0, "a forgery moved the window");
	}
	memcpy(copy, frame, n);
	CHECK(fzn_session_frame_open(&right, copy, n - 1u, &aead, &got) != FZN_SESSION_FRAME_OK,
	      "a short frame opened");
	CHECK(fzn_session_frame_open(&right, frame, n, &aead, &got) == FZN_SESSION_FRAME_OK,
	      "the frame itself did not open after forgeries of it");

	/* ONCE. */
	pair_up();
	n = seal(&left, 5u, "hello", frame);
	memcpy(copy, frame, n);
	CHECK(fzn_session_frame_open(&right, frame, n, &aead, &got) == FZN_SESSION_FRAME_OK,
	      "a frame did not open");
	CHECK(fzn_session_frame_open(&right, copy, n, &aead, &got) == FZN_SESSION_FRAME_ERR_REPLAY,
	      "a frame opened twice");

	/* OUT OF ORDER, each once, and the window's edge. */
	pair_up();
	for (i = 0; i < 8u; i++)
		lens[i] = seal(&left, (uint32_t)i, "x", kept[i]);
	for (i = 8u; i-- > 0u;) {
		memcpy(copy, kept[i], lens[i]);
		CHECK(fzn_session_frame_open(&right, copy, lens[i], &aead, &got) == FZN_SESSION_FRAME_OK,
		      "a late frame inside the window was refused");
		memcpy(copy, kept[i], lens[i]);
		CHECK(fzn_session_frame_open(&right, copy, lens[i], &aead, &got)
		              == FZN_SESSION_FRAME_ERR_REPLAY,
		      "a late frame opened twice");
	}
	pair_up();
	lens[0] = seal(&left, 0u, "x", kept[0]);
	for (i = 0; i < FZN_SESSION_WINDOW; i++) {
		n = seal(&left, 1u, "y", frame);
		if (i + 1u < FZN_SESSION_WINDOW)
			continue;
		CHECK(fzn_session_frame_open(&right, frame, n, &aead, &got) == FZN_SESSION_FRAME_OK,
		      "a frame ahead of the window was refused");
	}
	CHECK(fzn_session_frame_open(&right, kept[0], lens[0], &aead, &got)
	              == FZN_SESSION_FRAME_ERR_REPLAY,
	      "a frame past the window was taken");
	pair_up();
	lens[0] = seal(&left, 0u, "x", kept[0]);
	for (i = 0; i + 1u < FZN_SESSION_WINDOW; i++)
		n = seal(&left, 1u, "y", frame);
	CHECK(fzn_session_frame_open(&right, frame, n, &aead, &got) == FZN_SESSION_FRAME_OK,
	      "a frame did not open");
	CHECK(fzn_session_frame_open(&right, kept[0], lens[0], &aead, &got) == FZN_SESSION_FRAME_OK,
	      "the oldest frame in the window was refused");

	/* A JUMP PAST THE WINDOW forgets what is behind it, and takes nothing back. */
	pair_up();
	right.heard = 1u;
	right.newest = 10u;
	left.sent = 10u + FZN_SESSION_WINDOW * 2u;
	n = seal(&left, 1u, "z", frame);
	CHECK(fzn_session_frame_open(&right, frame, n, &aead, &got) == FZN_SESSION_FRAME_OK
	              && right.heard == 1u,
	      "a jump kept the old window");

	/* NOT THIS END'S, AND NOT THIS SESSION'S. */
	pair_up();
	n = seal(&left, 5u, "hello", frame);
	CHECK(fzn_session_frame_open(&left, frame, n, &aead, &got) == FZN_SESSION_FRAME_ERR_SHAPE,
	      "a frame opened at its own sender");
	memset(root, 0x41, sizeof(root));
	memset(ask, 0x22, sizeof(ask));
	memset(grant, 0x23, sizeof(grant));
	CHECK(fzn_session_end_derive(&other, &hash, root, ask, grant, 0), "an end did not derive");
	CHECK(fzn_session_frame_open(&other, frame, n, &aead, &got) == FZN_SESSION_FRAME_ERR_TAG,
	      "a frame opened under another pair's session");
	/* A RANDOM OF EITHER END CHANGES THE KEYS: why a crash cannot reuse one. */
	memset(root, 0x21, sizeof(root));
	ask[0] ^= 1u;
	CHECK(fzn_session_end_derive(&other, &hash, root, ask, grant, 0), "an end did not derive");
	CHECK(memcmp(other.recv_key, right.recv_key, FZN_AEAD_KEY_LEN) != 0,
	      "the asker's random did not change the key");
	ask[0] ^= 1u;
	grant[0] ^= 1u;
	CHECK(fzn_session_end_derive(&other, &hash, root, ask, grant, 0), "an end did not derive");
	CHECK(memcmp(other.recv_key, right.recv_key, FZN_AEAD_KEY_LEN) != 0,
	      "the granter's random did not change the key");

	/* COUNTER 0 IS NEVER A FRAME, whatever its tag: a window that took it would
	 * read it as none heard. */
	pair_up();
	left.sent = UINT32_MAX - 1u;
	n = seal(&left, 1u, "last", frame);
	CHECK(fzn_session_frame_open(&right, frame, n, &aead, &got) == FZN_SESSION_FRAME_OK,
	      "the last counter did not open");
	CHECK(fzn_session_frame_seal(&left, 1u, 0u, none, 1u, frame, sizeof(frame), &n, &aead)
	              == FZN_SESSION_FRAME_ERR_SPENT
	              && left.sent == UINT32_MAX,
	      "a spent counter went round");
	memset(frame + 5, 0, 4u);
	CHECK(fzn_session_frame_open(&right, frame, n, &aead, &got) == FZN_SESSION_FRAME_ERR_REPLAY,
	      "counter 0 reached the tag");

	/* NOT FRAMES. */
	pair_up();
	CHECK(!fzn_session_frame_handle(frame, FZN_SESSION_FRAME_OVERHEAD - 1u, &handle),
	      "too short a frame named a handle");
	CHECK(!fzn_session_frame_handle(frame, FZN_SESSION_FRAME_MAX + 1u, &handle),
	      "too long a frame named a handle");
	frame[0] = 1u;
	CHECK(!fzn_session_frame_handle(frame, 40u, &handle), "a full frame named a handle");
	CHECK(fzn_session_frame_seal(&left, 1u, 0u, none, 1u, frame, FZN_SESSION_FRAME_OVERHEAD, &n,
	                             &aead)
	              == FZN_SESSION_FRAME_ERR_CAPACITY
	              && left.sent == 0u,
	      "a frame too big for its room spent a counter");
	CHECK(fzn_session_frame_seal(&left, 1u, 0u, frame, FZN_SESSION_FRAME_PAYLOAD_MAX + 1u, copy,
	                             sizeof(copy), &n, &aead)
	              == FZN_SESSION_FRAME_ERR_MALFORMED,
	      "too long a payload sealed");

	printf("session_frame_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
