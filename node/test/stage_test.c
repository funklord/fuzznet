/* node stage_test -- a staged change, sec 873: a stage and a confirm signed
 * and opened, refused when bent or of the wrong shape, and held, walked and
 * dropped in the store. A stub signature keyed by a key's first byte, as
 * records_test's, since which key signed is what is tested. */

#include "../stage.h"
#include "../../wire/bytes.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL stage_test.c:%d: %s\n", __LINE__, what);       \
		}                                                                              \
	} while (0)

static void mac(uint8_t out[FZN_SIG_LEN], uint8_t key, const uint8_t *msg, size_t len)
{
	uint64_t h = 0xcbf29ce484222325ull ^ key;
	size_t i;

	for (i = 0; i < len; i++)
		h = (h ^ msg[i]) * 0x100000001b3ull;
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h = (h ^ (uint64_t)i) * 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 56);
	}
}

static uint8_t signing_as;

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t len)
{
	(void)ctx;
	mac(sig, signing_as, msg, len);
	return 1;
}

static int stub_verify(void *ctx, const uint8_t pk[FZN_PUBKEY_LEN], const uint8_t *msg, size_t len,
                       const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	mac(want, pk[0], msg, len);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

static const fzn_sign_ops_t SIGN = { stub_verify, stub_sign, NULL };

/* ---- a store of a few rows ---------------------------------------------- */

#define ROWS 8
static struct row {
	int used;
	fzn_persist_slot_t slot;
	uint8_t subject[32];
	uint8_t bytes[FZN_STAGE_MAX];
	size_t len;
} rows[ROWS];

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	int i;

	(void)ctx;
	for (i = 0; i < ROWS; i++)
		if (rows[i].used && rows[i].slot == slot && !memcmp(rows[i].subject, subject, 32u)) {
			if (rows[i].len > cap)
				return 0;
			memcpy(out, rows[i].bytes, rows[i].len);
			*len = rows[i].len;
			return 1;
		}
	return 0;
}

static int mem_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                    const uint8_t *bytes, size_t len)
{
	int i, free_one = -1;

	(void)ctx;
	if (len > FZN_STAGE_MAX)
		return 0;
	for (i = 0; i < ROWS; i++) {
		if (rows[i].used && rows[i].slot == slot && !memcmp(rows[i].subject, subject, 32u))
			break;
		if (!rows[i].used && free_one < 0)
			free_one = i;
	}
	if (i == ROWS)
		i = free_one;
	if (i < 0)
		return 0;
	rows[i].used = 1;
	rows[i].slot = slot;
	memcpy(rows[i].subject, subject, 32u);
	memcpy(rows[i].bytes, bytes, len);
	rows[i].len = len;
	return 1;
}

static int mem_list(void *ctx, fzn_persist_slot_t slot, uint8_t *out, size_t max, size_t *count)
{
	size_t n = 0;
	int i;

	(void)ctx;
	for (i = 0; i < ROWS; i++)
		if (rows[i].used && rows[i].slot == slot) {
			if (n == max)
				return 0;
			memcpy(out + 32u * n++, rows[i].subject, 32u);
		}
	*count = n;
	return 1;
}

static int mem_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	int i;

	(void)ctx;
	for (i = 0; i < ROWS; i++)
		if (rows[i].used && rows[i].slot == slot && !memcmp(rows[i].subject, subject, 32u))
			rows[i].used = 0;
	return 1;
}

static const fzn_persist_ops_t STORE = { mem_load, mem_save, mem_list, mem_remove, NULL, NULL };

static size_t walked;

static void count_one(void *ctx, const uint8_t *bytes, size_t len, const fzn_stage_t *s)
{
	(void)ctx;
	(void)bytes;
	(void)len;
	walked += s->act == FZN_STAGE_ACT_STAGE;
}

int main(void)
{
	static uint8_t obj[FZN_STAGE_MAX], bent[FZN_STAGE_MAX];
	uint8_t setter[FZN_PUBKEY_LEN], other[FZN_PUBKEY_LEN], token[FZN_STAGE_TOKEN_LEN];
	static const uint8_t REVERT[] = "a setting's bytes, as the setter signed them";
	size_t len = 0, clen = 0;
	fzn_stage_t s;

	memset(setter, 0x44, sizeof(setter));
	memset(other, 0x55, sizeof(other));
	memset(token, 0x0a, sizeof(token));
	signing_as = 0x44;

	CHECK(fzn_stage_issue(setter, &SIGN, FZN_STAGE_ACT_STAGE, token, 123456u, REVERT,
	                      sizeof(REVERT) - 1u, obj, &len)
	              && obj[1] == (uint8_t)FZN_OBJECT_STAGE
	              && fzn_stage_open(obj, len, &SIGN, &s) && s.act == FZN_STAGE_ACT_STAGE
	              && s.deadline_ms == 123456u && s.revert_len == sizeof(REVERT) - 1u
	              && !memcmp(s.revert, REVERT, s.revert_len) && !memcmp(s.token, token, 16u)
	              && !memcmp(s.setter, setter, 32u),
	      "a stage did not open to itself");
	memcpy(bent, obj, len);
	bent[FZN_STAGE_HEAD + 3u] ^= 1u;
	CHECK(!fzn_stage_open(bent, len, &SIGN, &s), "a stage whose revert was changed opened");
	memcpy(bent, obj, len);
	bent[40] ^= 1u;
	CHECK(!fzn_stage_open(bent, len, &SIGN, &s), "a stage whose deadline or token changed opened");
	signing_as = 0x55;
	CHECK(fzn_stage_issue(setter, &SIGN, FZN_STAGE_ACT_STAGE, token, 1u, REVERT, 3u, bent, &clen)
	              && !fzn_stage_open(bent, clen, &SIGN, &s),
	      "a stage signed by a key other than its setter's opened");
	signing_as = 0x44;
	CHECK(!fzn_stage_open(obj, len - 1u, &SIGN, &s) && !fzn_stage_open(obj, len + 1u, &SIGN, &s),
	      "a stage a byte short or long opened");
	CHECK(!fzn_stage_issue(setter, &SIGN, FZN_STAGE_ACT_STAGE, token, 0u, REVERT, 3u, bent, &clen)
	              && !fzn_stage_issue(setter, &SIGN, FZN_STAGE_ACT_STAGE, token, 5u, NULL, 0u, bent,
	                                  &clen)
	              && !fzn_stage_issue(setter, &SIGN, FZN_STAGE_ACT_CONFIRM, token, 5u, NULL, 0u,
	                                  bent, &clen)
	              && !fzn_stage_issue(setter, &SIGN, 3u, token, 0u, NULL, 0u, bent, &clen),
	      "a stage with no deadline or revert, a confirm with a deadline, or an unknown act was "
	      "issued");
	CHECK(fzn_stage_issue(setter, &SIGN, FZN_STAGE_ACT_CONFIRM, token, 0u, NULL, 0u, bent, &clen)
	              && fzn_stage_open(bent, clen, &SIGN, &s) && s.act == FZN_STAGE_ACT_CONFIRM
	              && !s.revert && !s.deadline_ms,
	      "a confirm did not open as one");

	/* HELD, WALKED, DROPPED; a confirm is not held; two setters' stages of
	 * one token are two. */
	memset(rows, 0, sizeof(rows));
	(void)fzn_stage_open(obj, len, &SIGN, &s);
	CHECK(fzn_stage_hold(&STORE, obj, len, &s), "a stage was not held");
	(void)fzn_stage_open(bent, clen, &SIGN, &s);
	CHECK(!fzn_stage_hold(&STORE, bent, clen, &s), "a confirm was held");
	signing_as = 0x55;
	CHECK(fzn_stage_issue(other, &SIGN, FZN_STAGE_ACT_STAGE, token, 9u, REVERT, 3u, bent, &clen)
	              && fzn_stage_open(bent, clen, &SIGN, &s) && fzn_stage_hold(&STORE, bent, clen, &s),
	      "another setter's stage of the same token was not held");
	walked = 0;
	CHECK(fzn_stage_each(&STORE, &SIGN, count_one, NULL) == 2 && walked == 2,
	      "the held stages were not walked, each once");
	CHECK(fzn_stage_drop(&STORE, setter, token), "a held stage was not dropped");
	walked = 0;
	CHECK(fzn_stage_each(&STORE, &SIGN, count_one, NULL) == 1 && walked == 1,
	      "dropping one setter's stage took the other's, or left its own");

	if (failures) {
		fprintf(stderr, "stage_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("node stage_test: all %d checks passed\n", checks);
	return 0;
}
