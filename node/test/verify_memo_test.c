#define _POSIX_C_SOURCE 200809L

/* verify_memo_test -- `node/verify_memo.h`, sec 931: a signature that verified costs a
 * hash after that, and any byte different is checked as though none had been. */
#include "../verify_memo.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

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
	/* SPREAD AS A REAL HASH SPREADS, sec 1007: the memo's sets are its first bytes. */
	for (i = 0; i < out_len; i++) {
		uint64_t z = h + 0x9e3779b97f4a7c15ull * (i + 1u);

		z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
		z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
		out[i] = (uint8_t)(z ^ (z >> 31));
	}
	return 1;
}

/* A signature is good when its first byte is the message's, unless it is revoked. */
static unsigned inner_checks, signs;
static int refuse_all, sign_truly;

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
	(void)msg_len;
	signs++;
	memset(sig, 7, FZN_SIG_LEN);
	if (sign_truly)
		sig[0] = msg[0];
	return 1;
}

static const fzn_sign_ops_t INNER = { inner_verify, inner_sign, NULL };
static const fzn_hash_ops_t HASH = { stub_hash, NULL };

/* EVERY ONE HELD, sec 1007: as many signatures as a host of 60000 contacts reads, each
 * verified, then all again, twice -- the third pass checks none. Direct-mapped, two that fell
 * in one slot put each other out at every walk, some 50000 checks a round at 20000
 * contacts; and a table of the first size would have run out of room. */
static void test_many_are_all_held(void)
{
	enum { MANY = 250000 };
	fzn_verify_memo_t m;
	fzn_sign_ops_t ops;
	uint8_t key[FZN_PUBKEY_LEN], sig[FZN_SIG_LEN], msg[8];
	unsigned before;
	uint32_t i;
	int ok = 1;

	memset(key, 3, sizeof(key));
	memset(sig, 0, sizeof(sig));
	fzn_verify_memo_init(&m, &INNER, &HASH, &ops);
	for (i = 0; i < MANY; i++) {
		memcpy(msg, &i, sizeof(i));
		memcpy(msg + 4, "memo", 4);
		sig[0] = msg[0];
		ok &= ops.verify(ops.ctx, key, msg, sizeof(msg), sig);
	}
	CHECK(ok, "fixture: every signature verifies");
	before = inner_checks;
	for (i = 0; i < MANY; i++) {
		memcpy(msg, &i, sizeof(i));
		memcpy(msg + 4, "memo", 4);
		sig[0] = msg[0];
		(void)ops.verify(ops.ctx, key, msg, sizeof(msg), sig);
	}
	CHECK(inner_checks == before, "the second pass checked none of what the first verified");
	before = inner_checks;
	for (i = 0; i < MANY; i++) {
		memcpy(msg, &i, sizeof(i));
		memcpy(msg + 4, "memo", 4);
		sig[0] = msg[0];
		(void)ops.verify(ops.ctx, key, msg, sizeof(msg), sig);
	}
	CHECK(inner_checks == before, "a third pass checked none: nothing puts another out");
	CHECK(m.room > FZN_VERIFY_MEMO_SLOTS, "the table grew past its first size");
	CHECK(m.room <= 4u * MANY, "and no further than the load asks: 4 slots a digest at most");
	fzn_verify_memo_free(&m);
}

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

	/* WHAT THIS HOST SIGNS needs no checking when read back, under its own key alone. */
	m.own = key;
	sign_truly = 1;
	memset(msg2, 'c', sizeof(msg2));
	CHECK(ops.sign(ops.ctx, sig, msg2, sizeof(msg2)), "a signature was not made");
	inner_checks = 0;
	CHECK(ops.verify(ops.ctx, key, msg2, sizeof(msg2), sig) && inner_checks == 0u,
	      "what this host signed was checked");
	CHECK(ops.verify(ops.ctx, other, msg2, sizeof(msg2), sig) && inner_checks == 1u,
	      "another key's check was taken from this host's signing");
	m.own = NULL;

	/* KEPT ACROSS A START, sec 938. */
	{
		static char path[128];
		fzn_verify_memo_t again;
		fzn_sign_ops_t ops2;
		uint8_t bytes[1024];
		size_t len;
		FILE *f;

		sig[0] = 'a';
		sig[63] = 0;
		refuse_all = 0;
		sign_truly = 1;
		CHECK(ops.verify(ops.ctx, key, msg, sizeof(msg), sig), "a check did not pass");
		snprintf(path, sizeof(path), "/tmp/fzn-memo-%ld", (long)getpid());
		CHECK(fzn_verify_memo_save(&m, path) == 1, "the memo was not saved");
		f = fopen(path, "rb");
		CHECK(f != NULL, "no file");
		len = f ? fread(bytes, 1u, sizeof(bytes), f) : 0u;
		if (f)
			fclose(f);

		/* TAKEN BACK: a check it held costs nothing. */
		fzn_verify_memo_init(&again, &INNER, &HASH, &ops2);
		CHECK(fzn_verify_memo_load(&again, path, key) >= 1u, "the memo did not come back");
		inner_checks = 0;
		CHECK(ops2.verify(ops2.ctx, key, msg, sizeof(msg), sig) && inner_checks == 0u,
		      "what was saved was checked again");
		msg[0] ^= 1u;
		refuse_all = 1;
		CHECK(!ops2.verify(ops2.ctx, key, msg, sizeof(msg), sig) && inner_checks == 1u,
		      "another message passed on a memo taken back");
		refuse_all = 0;
		msg[0] ^= 1u;
		fzn_verify_memo_free(&again);

		/* NOT OURS, NOT WHOLE, NOT THERE: nothing is believed. */
		fzn_verify_memo_init(&again, &INNER, &HASH, &ops2);
		refuse_all = 1;
		CHECK(fzn_verify_memo_load(&again, path, key) == 0u, "a signature that fails was taken");
		refuse_all = 0;
		bytes[6] ^= 1u;
		f = fopen(path, "wb");
		if (f) {
			fwrite(bytes, 1u, len, f);
			fclose(f);
		}
		CHECK(fzn_verify_memo_load(&again, path, key) == 0u, "a changed digest was taken");
		bytes[6] ^= 1u;
		f = fopen(path, "wb");
		if (f) {
			fwrite(bytes, 1u, len - 1u, f);
			fclose(f);
		}
		CHECK(fzn_verify_memo_load(&again, path, key) == 0u, "a short file was taken");
		bytes[0] ^= 1u;
		f = fopen(path, "wb");
		if (f) {
			fwrite(bytes, 1u, len, f);
			fclose(f);
		}
		CHECK(fzn_verify_memo_load(&again, path, key) == 0u, "another version was taken");
		CHECK(unlink(path) == 0, "fixture: the file");
		CHECK(fzn_verify_memo_load(&again, path, key) == 0u, "no file was a memo");
		CHECK(!again.table, "a refused file made a table");
		fzn_verify_memo_free(&again);
	}
	fzn_verify_memo_free(&m);
	test_many_are_all_held();

	printf("verify_memo_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
