/* node streams_test -- app streams, sec 632: a host's records kept in
 * order, the newest FZN_STREAM_KEEP of them; a record held twice no error;
 * grants given, read and taken away; a reader given its level's rendition,
 * or the coarsest the record has. A stub hash over a store in memory. */

#include "../streams.h"

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                 \
	do {                                                                              \
		checks++;                                                                 \
		if (!(cond)) {                                                            \
			failures++;                                                       \
			fprintf(stderr, "  FAIL streams_test.c:%d: %s\n", __LINE__, what); \
		}                                                                         \
	} while (0)

static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	(void)ctx;
	for (i = 0; i < in_len; i++)
		h = (h ^ in[i]) * 0x100000001b3ull;
	for (i = 0; i < out_len; i++) {
		h = (h ^ (uint64_t)i) * 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 56);
	}
	return 1;
}

static const fzn_hash_ops_t HASH = { stub_hash, NULL };

/* ---- a store of every slot ---------------------------------------------- */

#define ROWS 2200u
#define ROW_MAX 512u

static struct {
	int used;
	fzn_persist_slot_t slot;
	uint8_t subject[32];
	uint8_t bytes[ROW_MAX];
	size_t len;
} rows[ROWS];

static int find(fzn_persist_slot_t slot, const uint8_t *subject)
{
	int i;

	for (i = 0; i < (int)ROWS; i++)
		if (rows[i].used && rows[i].slot == slot && memcmp(rows[i].subject, subject, 32u) == 0)
			return i;
	return -1;
}

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	int i = find(slot, subject);

	(void)ctx;
	if (i < 0 || rows[i].len > cap)
		return 0;
	memcpy(out, rows[i].bytes, rows[i].len);
	*len = rows[i].len;
	return 1;
}

static int mem_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                    const uint8_t *bytes, size_t len)
{
	int i = find(slot, subject), k;

	(void)ctx;
	if (len > ROW_MAX)
		return 0;
	for (k = 0; i < 0 && k < (int)ROWS; k++)
		if (!rows[k].used)
			i = k;
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
	size_t i, n = 0;

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
	int i = find(slot, subject);

	(void)ctx;
	if (i >= 0)
		rows[i].used = 0;
	return 1;
}

static const fzn_persist_ops_t STORE = { mem_load, mem_save, mem_list, mem_remove, NULL, NULL };
static const fzn_streams_t S = { &STORE, &HASH };

static size_t rows_in(fzn_persist_slot_t slot)
{
	size_t i, n = 0;

	for (i = 0; i < ROWS; i++)
		n += rows[i].used && rows[i].slot == slot;
	return n;
}

/* A record of `levels` renditions, each `levels - k` bytes of `seq`. */
static void record(fzn_stream_record_t *r, uint64_t seq, size_t levels)
{
	size_t k;

	memset(r, 0, sizeof(*r));
	r->seq = seq;
	r->at = 1000u + seq;
	r->levels = levels;
	for (k = 0; k < levels; k++) {
		r->rendition_len[k] = 3u - k;
		memset(r->rendition[k], (int)(0x10u * (k + 1u) + (seq & 0xfu)), r->rendition_len[k]);
	}
}

static void test_records_kept_in_order(void)
{
	fzn_stream_record_t r, got;
	uint8_t origin[32];
	uint64_t i;

	memset(origin, 0x0a, sizeof(origin));
	CHECK(fzn_stream_name_ok("location", 8u) && !fzn_stream_name_ok("Location", 8u)
	              && !fzn_stream_name_ok("", 0u) && !fzn_stream_name_ok("a b", 3u),
	      "a stream name is not 1 to 32 of [a-z0-9_]");
	CHECK(fzn_streams_last(&S, "location", 8u, origin) == 0u, "an empty stream had a record");
	record(&r, 1u, 3u);
	CHECK(fzn_streams_keep(&S, "location", 8u, origin, &r) == FZN_STREAMS_OK
	              && fzn_streams_last(&S, "location", 8u, origin) == 1u
	              && fzn_streams_get(&S, "location", 8u, origin, 1u, &got) == FZN_STREAMS_OK
	              && got.levels == 3u && got.rendition_len[2] == 1u && got.at == 1001u,
	      "a record did not read back as kept");
	CHECK(fzn_streams_keep(&S, "location", 8u, origin, &r) == FZN_STREAMS_OK
	              && fzn_streams_last(&S, "location", 8u, origin) == 1u,
	      "a record kept twice moved the stream");
	record(&r, 5u, 1u);
	CHECK(fzn_streams_keep(&S, "location", 8u, origin, &r) == FZN_STREAMS_OK
	              && fzn_streams_last(&S, "location", 8u, origin) == 5u
	              && fzn_streams_get(&S, "location", 8u, origin, 3u, &got)
	                         == FZN_STREAMS_ERR_ABSENT,
	      "a newer record past a gap was not kept, or the gap read");
	record(&r, 2u, 1u);
	CHECK(fzn_streams_keep(&S, "location", 8u, origin, &r) == FZN_STREAMS_OK
	              && fzn_streams_last(&S, "location", 8u, origin) == 5u
	              && fzn_streams_get(&S, "location", 8u, origin, 2u, &got)
	                         == FZN_STREAMS_ERR_ABSENT,
	      "an older record taken after a newer one moved the stream back");
	CHECK(fzn_streams_get(&S, "other", 5u, origin, 1u, &got) == FZN_STREAMS_ERR_ABSENT,
	      "one stream's record read under another's name");
	/* THE RING: the newest FZN_STREAM_KEEP, the oldest overwritten. */
	for (i = 6u; i <= 5u + FZN_STREAM_KEEP; i++) {
		record(&r, i, 1u);
		(void)fzn_streams_keep(&S, "location", 8u, origin, &r);
	}
	CHECK(fzn_streams_get(&S, "location", 8u, origin, 5u, &got) == FZN_STREAMS_ERR_ABSENT
	              && fzn_streams_get(&S, "location", 8u, origin, 6u, &got) == FZN_STREAMS_OK
	              && rows_in(FZN_PERSIST_STREAM_RECORD) == FZN_STREAM_KEEP,
	      "the ring did not keep the newest records alone");
}

static void test_grants_and_levels(void)
{
	fzn_stream_record_t r, out;
	uint8_t bob[32], fam[32];
	unsigned level = 9;

	memset(bob, 0xb0, sizeof(bob));
	memset(fam, 0xfa, sizeof(fam));
	CHECK(fzn_streams_granted(&S, "location", 8u, bob, &level) == FZN_STREAMS_ERR_DENIED,
	      "a reader nobody granted was granted");
	CHECK(fzn_streams_grant(&S, "location", 8u, bob, 1) == FZN_STREAMS_OK
	              && fzn_streams_grant(&S, "location", 8u, fam, 2) == FZN_STREAMS_OK
	              && fzn_streams_granted(&S, "location", 8u, bob, &level) == FZN_STREAMS_OK
	              && level == 1u
	              && fzn_streams_granted(&S, "other", 5u, bob, &level) == FZN_STREAMS_ERR_DENIED,
	      "a grant did not read back for its stream alone");
	CHECK(fzn_streams_grant(&S, "location", 8u, bob, (int)FZN_STREAM_LEVELS_MAX)
	              == FZN_STREAMS_ERR_MALFORMED,
	      "a level past the most was granted");
	CHECK(fzn_streams_grant(&S, "location", 8u, bob, -1) == FZN_STREAMS_OK
	              && fzn_streams_granted(&S, "location", 8u, bob, &level) == FZN_STREAMS_ERR_DENIED
	              && fzn_streams_grant(&S, "location", 8u, bob, -1) == FZN_STREAMS_ERR_ABSENT,
	      "a grant taken away was still held, or taken twice");
	record(&r, 7u, 3u);
	fzn_streams_render(&r, 1u, &out);
	CHECK(out.levels == 1u && out.rendition_len[0] == r.rendition_len[1]
	              && memcmp(out.rendition[0], r.rendition[1], out.rendition_len[0]) == 0
	              && out.seq == 7u,
	      "a reader granted level 1 was not given that rendition alone");
	record(&r, 8u, 2u);
	fzn_streams_render(&r, 3u, &out);
	CHECK(out.levels == 1u && memcmp(out.rendition[0], r.rendition[1], r.rendition_len[1]) == 0,
	      "a record with fewer levels did not give its coarsest");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	CHECK(0, "deliberate");
	CHECK(failures == before + 1, "a failure counts");
	failures = before;
	checks -= 1;
}

int main(void)
{
	test_the_suite_can_tell_pass_from_fail();
	test_records_kept_in_order();
	test_grants_and_levels();
	if (failures) {
		fprintf(stderr, "node streams_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("node streams_test: all %d checks passed\n", checks);
	return 0;
}
