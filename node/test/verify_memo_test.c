/* verify_memo_test -- `node/verify_memo.h`, sec 931: a signature that verified costs a
 * hash after that, and any byte different is checked as though none had been. */
#include "../verify_memo.h"

#include <stdio.h>
#include <string.h>

static int failures, checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (ok)
		return;
	failures++;
	fprintf(stderr, "  FAIL verify_memo_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, what)

/* A hash good enough to tell these bytes apart. */
static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	(void)ctx;
	for (i = 0; i < in_len; i++) {
		h ^= in[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < out_len; i++) {
		h ^= (uint64_t)i + 0x9e3779b97f4a7c15ull;
		h *= 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 32);
	}
	return 1;
}

/* A signature is good when its first byte is the message's, unless it is revoked. */
static unsigned inner_checks, signs;
static int refuse_all;

static int inner_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                        size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	(void)ctx;
	(void)pubkey;
	inner_checks++;
	return !refuse_all && msg_len && sig[0] == msg[0];
}

static int inner_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	(void)ctx;
	(void)msg;
	(void)msg_len;
	signs++;
	memset(sig, 7, FZN_SIG_LEN);
	return 1;
}

static const fzn_sign_ops_t INNER = { inner_verify, inner_sign, NULL };
static const fzn_hash_ops_t HASH = { stub_hash, NULL };

int main(void)
{
	fzn_verify_memo_t m;
	fzn_sign_ops_t ops;
	uint8_t key[FZN_PUBKEY_LEN], other[FZN_PUBKEY_LEN], sig[FZN_SIG_LEN];
	uint8_t msg[8] = "aaaaaaa", msg2[8] = "aaaaaab";

	memset(key, 1, sizeof(key));
	memset(other, 2, sizeof(other));
	memset(sig, 0, sizeof(sig));
	sig[0] = 'a';
	fzn_verify_memo_init(&m, &INNER, &HASH, &ops);

	CHECK(ops.verify(ops.ctx, key, msg, sizeof(msg), sig) && inner_checks == 1u,
	      "a first check goes to the one beneath");
	CHECK(ops.verify(ops.ctx, key, msg, sizeof(msg), sig) && inner_checks == 1u && m.hits == 1u,
	      "the same bytes again cost no check");

	/* ANY BYTE DIFFERENT IS ANOTHER CHECK. */
	refuse_all = 1;
	CHECK(!ops.verify(ops.ctx, key, msg2, sizeof(msg2), sig) && inner_checks == 2u,
	      "another message was taken from the memo");
	CHECK(!ops.verify(ops.ctx, other, msg, sizeof(msg), sig) && inner_checks == 3u,
	      "another key was taken from the memo");
	sig[63] ^= 1u;
	CHECK(!ops.verify(ops.ctx, key, msg, sizeof(msg), sig) && inner_checks == 4u,
	      "another signature was taken from the memo");
	sig[63] ^= 1u;
	CHECK(!ops.verify(ops.ctx, key, msg, sizeof(msg) - 1u, sig) && inner_checks == 5u,
	      "a shorter message was taken from the memo");

	/* A FAILURE IS NOT KEPT. */
	CHECK(!ops.verify(ops.ctx, other, msg, sizeof(msg), sig) && inner_checks == 6u,
	      "a failure was remembered, not checked again");
	refuse_all = 0;
	CHECK(ops.verify(ops.ctx, other, msg, sizeof(msg), sig) && inner_checks == 7u,
	      "what failed once and holds now did not verify");

	CHECK(ops.sign(ops.ctx, sig, msg, sizeof(msg)) && signs == 1u && sig[0] == 7u,
	      "signing did not reach the one beneath");
	fzn_verify_memo_free(&m);

	printf("verify_memo_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
