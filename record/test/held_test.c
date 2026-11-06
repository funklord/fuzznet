/* The record store's delta: record/store_held.h. */

#include "../store_held.h"
#include "../../node/journal.h"

#include <stdio.h>
#include <string.h>

static int failures, checks;

#define CHECK(c, what)                                                      \
	do {                                                                    \
		checks++;                                                           \
		if (!(c)) {                                                         \
			failures++;                                                     \
			fprintf(stderr, "  FAIL held_test.c:%d: %s\n", __LINE__, what); \
		}                                                                   \
	} while (0)

static int refusing, refuse_after = -1, puts_seen, cut_asked;
static uint64_t written[64];
static size_t n_written;

static int b_put(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream, uint64_t seq,
                 const uint8_t *bytes, size_t len)
{
	(void)ctx;
	(void)issuer;
	(void)stream;
	(void)bytes;
	(void)len;
	puts_seen++;
	if (refusing || refuse_after == 0)
		return 0;
	if (refuse_after > 0)
		refuse_after--;
	written[n_written++] = seq;
	return 1;
}

static int b_get(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream, uint64_t seq,
                 uint8_t *out, size_t cap, size_t *len_out, int *found_out)
{
	(void)ctx;
	(void)issuer;
	(void)stream;
	(void)seq;
	(void)out;
	(void)cap;
	(void)len_out;
	*found_out = 0;
	return 0;
}

static int b_cut(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream, uint64_t from,
                 uint64_t below)
{
	(void)ctx;
	(void)issuer;
	(void)stream;
	(void)from;
	(void)below;
	cut_asked++;
	return 1;
}

static const fzn_record_store_ops_t BASE = { b_put, b_get, NULL, b_cut };

int main(void)
{
	static fzn_record_held_t h;
	uint8_t issuer[FZN_PUBKEY_LEN], out[64];
	size_t len = 0;
	int found = 0;

	memset(issuer, 0x41, sizeof(issuer));
	CHECK(FZN_RECORD_HELD_KEPT_STREAM == FZN_NODE_JOURNAL_STREAM, "the kept stream moved");
	fzn_record_held_init(&h, &BASE, 10u);

	CHECK(h.ops.put(h.ops.ctx, issuer, 1u, 1u, (const uint8_t *)"a", 1u) && h.rows == 0u,
	      "a working store's record was held");
	refusing = 1;
	puts_seen = 0;
	CHECK(h.ops.put(h.ops.ctx, issuer, 1u, 2u, (const uint8_t *)"two", 3u), "a refused record was not held");
	CHECK(h.ops.put(h.ops.ctx, issuer, 1u, 3u, (const uint8_t *)"three", 5u) && puts_seen == 1,
	      "the store was asked again after it refused");
	CHECK(h.ops.put(h.ops.ctx, issuer, 1u, 3u, (const uint8_t *)"three", 5u) && h.rows == 2u,
	      "a record put twice was held twice");
	CHECK(h.ops.get(h.ops.ctx, issuer, 1u, 2u, out, sizeof(out), &len, &found) && found && len == 3u
	              && memcmp(out, "two", 3u) == 0,
	      "a held record did not read");
	found = 1;
	CHECK(!h.ops.get(h.ops.ctx, issuer, 1u, 9u, out, sizeof(out), &len, &found) && !found,
	      "a record held nowhere read");

	/* THE BUDGET: the journal's stream stays, another's oldest goes. */
	CHECK(h.ops.put(h.ops.ctx, issuer, 4u, 1u, (const uint8_t *)"cc", 2u), "fixture: another stream");
	CHECK(!h.ops.put(h.ops.ctx, issuer, 4u, 2u, (const uint8_t *)"dddd", 4u) && h.refused == 1u
	              && h.dropped == 1u,
	      "a stream's record past the budget was taken, or shed none of its own");
	CHECK(h.ops.put(h.ops.ctx, issuer, 1u, 4u, (const uint8_t *)"a journal record past the budget", 32u),
	      "the journal's record was refused for want of budget");
	CHECK(h.ops.get(h.ops.ctx, issuer, 1u, 2u, out, sizeof(out), &len, &found) && found,
	      "the journal's record was shed");

	/* A CUT reaches what is held. */
	CHECK(h.ops.cut(h.ops.ctx, issuer, 1u, 2u, 3u) && cut_asked == 1, "a cut did not reach the store");
	found = 1;
	CHECK(!h.ops.get(h.ops.ctx, issuer, 1u, 2u, out, sizeof(out), &len, &found) && !found,
	      "a cut record still read");

	/* FLUSHED IN ORDER, stopping at a refusal. */
	refusing = 0;
	refuse_after = 1;
	n_written = 0;
	CHECK(fzn_record_held_flush(&h) == 1u && h.stuck, "a flush went past a refusal");
	CHECK(written[0] == 3u, "not the oldest went first");
	refuse_after = -1;
	(void)fzn_record_held_flush(&h);
	CHECK(h.rows == 0u && !h.stuck, "a flush left rows");
	fzn_record_held_free(&h);

	printf("held_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
