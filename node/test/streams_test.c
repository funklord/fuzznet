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

/* SAVES THE STORE TAKES before refusing every one, a full disk; -1 for
 * no end. */
static int saves_left = -1;

static int mem_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                    const uint8_t *bytes, size_t len)
{
	int i = find(slot, subject), k;

	(void)ctx;
	if (saves_left == 0)
		return 0;
	if (saves_left > 0)
		saves_left--;
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

/* HUNDREDS, sec 704: 600 hosts' records of one stream listed -- told how
 * many into 64, all into room for them -- where 512 heads of every stream
 * were listed into a fixed table; and 300 grants, past the 256 once held. */
static void test_hundreds(void)
{
	static uint8_t origins[600][32];
	fzn_stream_record_t r;
	uint8_t who[32];
	size_t i, n = 0;
	int kept = 1, granted = 1;

	memset(rows, 0, sizeof(rows));
	for (i = 0; i < 600u && kept; i++) {
		memset(who, 0x40, sizeof(who));
		who[0] = (uint8_t)(i >> 8);
		who[1] = (uint8_t)i;
		record(&r, 1u, 1u);
		kept = fzn_streams_keep(&S, "location", 8u, who, &r) == FZN_STREAMS_OK;
	}
	CHECK(kept, "fixture: 600 hosts' records of one stream");
	CHECK(fzn_streams_origins(&S, "location", 8u, origins, 64u, &n) == FZN_STREAMS_ERR_ROOM
	              && n == 600u
	              && fzn_streams_origins(&S, "location", 8u, origins, 600u, &n) == FZN_STREAMS_OK
	              && n == 600u,
	      "600 hosts did not say how many into 64, or all list into room for them");
	for (i = 0; i < 300u && granted; i++) {
		memset(who, 0x60, sizeof(who));
		who[0] = (uint8_t)(i >> 8);
		who[1] = (uint8_t)i;
		granted = fzn_streams_grant(&S, "location", 8u, who, 1) == FZN_STREAMS_OK;
	}
	CHECK(granted, "300 grants of one stream were not all kept");
}

/* THE OWNER'S NUMBERING, sec 769: a head lost goes on from the ring. */
static void test_next_survives_a_lost_head(void)
{
	static const uint8_t own[32] = { 0x71 };
	fzn_stream_record_t r;
	uint8_t subject_bytes[32 * 4];
	size_t n = 0, i;
	uint64_t seq;

	memset(rows, 0, sizeof(rows));
	CHECK(fzn_streams_next(&S, "location", 8u, own) == 1u, "none written: next is 1");
	for (seq = 1; seq <= FZN_STREAM_KEEP + 6u; seq++) {
		record(&r, seq, 2u);
		CHECK(fzn_streams_keep(&S, "location", 8u, own, &r) == FZN_STREAMS_OK, "kept");
	}
	CHECK(fzn_streams_next(&S, "location", 8u, own) == FZN_STREAM_KEEP + 7u,
	      "next is one past the head");
	CHECK(mem_list(NULL, FZN_PERSIST_STREAM_HEAD, subject_bytes, 4u, &n) && n == 1u,
	      "one head");
	for (i = 0; i < n; i++)
		mem_remove(NULL, FZN_PERSIST_STREAM_HEAD, subject_bytes + 32u * i);
	CHECK(fzn_streams_last(&S, "location", 8u, own) == 0u, "the head is gone");
	CHECK(fzn_streams_next(&S, "location", 8u, own) == FZN_STREAM_KEEP + 7u,
	      "next goes on from the highest the ring holds, past its wrap");
	record(&r, fzn_streams_next(&S, "location", 8u, own), 2u);
	CHECK(fzn_streams_keep(&S, "location", 8u, own, &r) == FZN_STREAMS_OK
	          && fzn_streams_last(&S, "location", 8u, own) == FZN_STREAM_KEEP + 7u,
	      "the write after it is the head again");
}

/* RECORDS `from`..`to` as a host answers them, two levels each. */
static size_t answered(uint8_t *out, uint64_t from, uint64_t to)
{
	size_t at = 0;
	uint64_t seq;
	int b;

	for (seq = from; seq <= to; seq++) {
		for (b = 7; b >= 0; b--)
			out[at++] = (uint8_t)(seq >> (8 * b));
		for (b = 7; b >= 0; b--)
			out[at++] = (uint8_t)((1000u + seq) >> (8 * b));
		out[at++] = 2u;
		out[at++] = 2u;
		out[at++] = (uint8_t)seq;
		out[at++] = 0xa0;
		out[at++] = 1u;
		out[at++] = (uint8_t)seq;
	}
	return at;
}

/* A FULL DISK MID-ANSWER, sec 769: the take stops at the record not kept,
 * so the head stays below it and the next fetch asks for it again. */
static void test_take_stops_at_the_first_not_kept(void)
{
	static const uint8_t host[32] = { 0x72 };
	fzn_stream_record_t r;
	uint8_t bytes[3 * 23];
	size_t len = answered(bytes, 1, 3), taken = 9;
	uint64_t stopped = 0;

	memset(rows, 0, sizeof(rows));
	saves_left = 2; /* record 1 and its head, then nothing */
	CHECK(fzn_streams_take(&S, "location", 8u, host, bytes, len, 3u, &taken, &stopped)
	          == FZN_STREAMS_ERR_BACKEND,
	      "the store's refusal is returned");
	saves_left = -1;
	CHECK(taken == 1u && stopped == 2u, "stopped at record 2, record 1 taken");
	CHECK(fzn_streams_last(&S, "location", 8u, host) == 1u,
	      "the head is below the record not kept");
	CHECK(fzn_streams_get(&S, "location", 8u, host, 3u, &r) == FZN_STREAMS_ERR_ABSENT,
	      "record 3, after it, was not kept either");
	CHECK(fzn_streams_take(&S, "location", 8u, host, bytes, len, 3u, &taken, &stopped)
	              == FZN_STREAMS_OK
	          && taken == 3u && fzn_streams_last(&S, "location", 8u, host) == 3u,
	      "answered again with room, every record is kept");
	CHECK(fzn_streams_get(&S, "location", 8u, host, 2u, &r) == FZN_STREAMS_OK
	          && r.levels == 2u && r.rendition_len[0] == 2u && r.rendition[0][0] == 2u,
	      "record 2 as answered");
	CHECK(fzn_streams_take(&S, "location", 8u, host, bytes, len - 1u, 3u, &taken, &stopped)
	              == FZN_STREAMS_ERR_MALFORMED
	          && taken == 2u,
	      "an answer cut short: those before the cut taken, the cut one malformed");
	CHECK(fzn_streams_take(&S, "location", 8u, host, bytes, len, 4u, &taken, &stopped)
	          == FZN_STREAMS_ERR_MALFORMED,
	      "a count past the bytes");
	bytes[16] = 0u;
	CHECK(fzn_streams_take(&S, "location", 8u, host, bytes, len, 3u, &taken, &stopped)
	              == FZN_STREAMS_ERR_MALFORMED
	          && taken == 0u,
	      "a record of no levels");
}

/* EACH LIMIT AT ITS EDGE, sec 770: a name of 32 and of 33, four levels
 * of 64 bytes and a fifth or a 65th -- each taken at it, refused past. */
static void test_bounds(void)
{
	static const uint8_t host[32] = { 0x73 };
	char name[FZN_STREAM_NAME_MAX + 1u];
	uint8_t q[FZN_STREAM_QUERY_MAX + 8u], answer[2u * (17u + 5u * 66u)];
	const char *got;
	size_t got_len, at, taken;
	uint64_t since, stopped;
	fzn_stream_record_t r, held;
	size_t k;

	memset(rows, 0, sizeof(rows));
	memset(name, 'a', sizeof(name));
	CHECK(fzn_streams_query_encode(name, FZN_STREAM_NAME_MAX, 7u, q, sizeof(q))
	          == FZN_STREAM_QUERY_MAX
	          && fzn_streams_query_decode(q, FZN_STREAM_QUERY_MAX, &got, &got_len, &since)
	          && got_len == FZN_STREAM_NAME_MAX && since == 7u,
	      "a name of 32 is asked and read");
	CHECK(fzn_streams_query_encode(name, FZN_STREAM_NAME_MAX + 1u, 7u, q, sizeof(q)) == 0,
	      "a name of 33 is not asked");
	q[0] = (uint8_t)(FZN_STREAM_NAME_MAX + 1u);
	memset(q + 1, 'a', FZN_STREAM_NAME_MAX + 1u);
	CHECK(!fzn_streams_query_decode(q, FZN_STREAM_QUERY_MAX + 1u, &got, &got_len, &since),
	      "a query naming 33 is not read");
	CHECK(fzn_streams_query_encode(name, 0u, 7u, q, sizeof(q)) == 0, "an empty name");

	memset(&r, 0, sizeof(r));
	r.seq = 1u;
	r.levels = FZN_STREAM_LEVELS_MAX;
	for (k = 0; k < r.levels; k++) {
		r.rendition_len[k] = FZN_STREAM_RENDITION_MAX;
		memset(r.rendition[k], (int)(0x40 + k), FZN_STREAM_RENDITION_MAX);
	}
	at = fzn_streams_record_put(&r, answer, 0, sizeof(answer));
	CHECK(at == 17u + FZN_STREAM_LEVELS_MAX * (1u + FZN_STREAM_RENDITION_MAX)
	          && fzn_streams_take(&S, "app", 3u, host, answer, at, 1u, &taken, &stopped)
	                 == FZN_STREAMS_OK
	          && fzn_streams_get(&S, "app", 3u, host, 1u, &held) == FZN_STREAMS_OK
	          && held.levels == FZN_STREAM_LEVELS_MAX
	          && held.rendition_len[3] == FZN_STREAM_RENDITION_MAX,
	      "four levels of 64 bytes are put, taken and kept");
	CHECK(fzn_streams_record_put(&r, answer, 0, at - 1u) == 0, "a record past its room");
	answer[16] = (uint8_t)(FZN_STREAM_LEVELS_MAX + 1u);
	CHECK(fzn_streams_take(&S, "app", 3u, host, answer, at, 1u, &taken, &stopped)
	          == FZN_STREAMS_ERR_MALFORMED,
	      "a fifth level is not taken");
	answer[16] = (uint8_t)FZN_STREAM_LEVELS_MAX;
	answer[17] = (uint8_t)(FZN_STREAM_RENDITION_MAX + 1u);
	CHECK(fzn_streams_take(&S, "app", 3u, host, answer, at, 1u, &taken, &stopped)
	          == FZN_STREAMS_ERR_MALFORMED,
	      "a rendition of 65 is not taken");
	r.seq = 2u;
	r.levels = FZN_STREAM_LEVELS_MAX + 1u;
	CHECK(fzn_streams_keep(&S, "app", 3u, host, &r) == FZN_STREAMS_ERR_MALFORMED
	          && fzn_streams_record_put(&r, answer, 0, sizeof(answer)) == 0,
	      "a fifth level is neither kept nor put");
	r.levels = 1u;
	r.rendition_len[0] = FZN_STREAM_RENDITION_MAX + 1u;
	CHECK(fzn_streams_keep(&S, "app", 3u, host, &r) == FZN_STREAMS_ERR_MALFORMED
	          && fzn_streams_record_put(&r, answer, 0, sizeof(answer)) == 0,
	      "a rendition of 65 is neither kept nor put");
}

/* WHO MAY ASK, sec 769: a stream query tried with each kind of caller. */
static void test_who_may_ask(void)
{
	fzn_streams_asker_t member = { 1, 0, 0, -1 }, granted = { 0, 1, 0, 2 },
	                    ungranted = { 0, 1, 0, -1 }, group = { 0, 0, 1, 1 },
	                    group_ungranted = { 0, 0, 1, -1 }, removed = { 0, 0, 0, 0 },
	                    past = { 0, 1, 0, (int)FZN_STREAM_LEVELS_MAX };
	unsigned level = 9;
	int whole = 9;

	CHECK(fzn_streams_refuse_query(&member, &whole, &level) == NULL && whole == 1,
	      "a member is given every level");
	CHECK(fzn_streams_refuse_query(&granted, &whole, &level) == NULL && whole == 0
	          && level == 2u,
	      "a contact granted level 2 is given level 2 alone");
	CHECK(fzn_streams_refuse_query(&group, &whole, &level) == NULL && whole == 0 && level == 1u,
	      "a group's member host granted level 1 is given it");
	CHECK(fzn_streams_refuse_query(&ungranted, &whole, &level) != NULL && whole == 0,
	      "a contact not granted is refused");
	CHECK(fzn_streams_refuse_query(&group_ungranted, &whole, &level) != NULL,
	      "a group's host not granted is refused");
	CHECK(fzn_streams_refuse_query(&removed, &whole, &level) != NULL && whole == 0,
	      "a removed contact is refused, whatever level it was once granted");
	CHECK(fzn_streams_refuse_query(&past, &whole, &level) != NULL, "a level past the last");
	CHECK(fzn_streams_refuse_query(NULL, &whole, &level) != NULL, "no asker");
	CHECK(fzn_streams_refuse_local(FZN_ORIGIN_SAME_USER) == NULL, "the node's own user");
	CHECK(fzn_streams_refuse_local(FZN_ORIGIN_LOCAL) != NULL, "another user on this machine");
	CHECK(fzn_streams_refuse_local(FZN_ORIGIN_REMOTE) != NULL, "a remote origin");
	CHECK(fzn_streams_refuse_local(FZN_ORIGIN_NONE) != NULL, "no origin");
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
	test_hundreds();
	test_next_survives_a_lost_head();
	test_take_stops_at_the_first_not_kept();
	test_bounds();
	test_who_may_ask();
	if (failures) {
		fprintf(stderr, "node streams_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("node streams_test: all %d checks passed\n", checks);
	return 0;
}
