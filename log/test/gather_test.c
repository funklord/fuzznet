/* gather_test -- a host's log asked for a page at a time. sec 463.
 *
 * Segments are written here from real classic lines, in a scratch
 * directory of its own that it leaves empty; the host is a function handing
 * the query to `fzn_gather_answer` with a small reply buffer, so the answer
 * must page. */

#define _POSIX_C_SOURCE 200809L

#include "../gather.h"
#ifdef FZN_LOG_PACK_ON
#include "../pack.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int checks, failures;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL gather_test.c:%d: %s\n", __LINE__, what);      \
		}                                                                              \
	} while (0)

static char top[64];

#ifdef FZN_LOG_PACK_ON
/* Any hash: the chain is pack_test's to check, not this file's. */
static int toy(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	size_t i;

	(void)ctx;
	memset(out, 0, out_len);
	for (i = 0; i < in_len; i++)
		out[i % out_len] = (uint8_t)(out[i % out_len] ^ in[i]);
	return 0;
}
#endif
static size_t reply_cap = 600u;
static int answer_garbage;

static int host(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
                size_t cap, size_t *reply_len)
{
	(void)ctx;
	if (answer_garbage) {
		memcpy(reply, "denied no", 9u);
		*reply_len = 9u;
		return 1;
	}
	*reply_len = fzn_gather_answer(top, request, request_len, reply,
	                               cap < reply_cap ? cap : reply_cap);
	return *reply_len > 0u;
}

/* What a fetch saw: each line's position, in order. */
static uint64_t seen[256];
static size_t n_seen;

static void note(void *ctx, const char *line, size_t len)
{
	const char *hash = strchr(line, '#');

	(void)ctx;
	(void)len;
	if (n_seen < 256u && hash)
		seen[n_seen++] = strtoull(hash + 1, NULL, 10);
}

/* A segment of entries `first` .. `first + n - 1`, entry k at time k. */
static int segment(const char *name, const char *program, uint64_t first, size_t n)
{
	static char line[FZN_ENTRY_LINE_MAX];
	char path[300];
	fzn_entry_t e;
	FILE *f;
	size_t k, len = 0;
	int ok;

	(void)snprintf(path, sizeof(path), "%s/%s", top, name);
	f = fopen(path, "w");
	if (!f)
		return 0;
	ok = fputs("#fuzznet-log 1 machine=00000000000000000000000000000000 host=h\n", f) >= 0;
	for (k = 0; k < n && ok; k++) {
		memset(&e, 0, sizeof(e));
		strcpy(e.name.user, "root");
		strcpy(e.name.program, program);
		e.name.pid = 812u;
		e.name.start_ms = 1u;
		e.name.position = first + k;
		e.time_us = (first + k) * 1000000u;
		e.level = FZN_ENTRY_INFO;
		strcpy(e.subsystem, "apply/exec");
		e.text = (const uint8_t *)"a line about the network, long enough to fill a page";
		e.text_len = strlen((const char *)e.text);
		ok = fzn_entry_classic(&e, "h", line, sizeof(line), &len) == FZN_ENTRY_OK
		     && fwrite(line, 1u, len, f) == len;
	}
	return (fclose(f) == 0) && ok;
}

static fzn_gather_query_t query(uint64_t since, uint64_t until, const char *match)
{
	fzn_gather_query_t q;

	memset(&q, 0, sizeof(q));
	q.since_us = since;
	q.until_us = until;
	strcpy(q.program, "netcfgd");
	strcpy(q.match, match);
	return q;
}

/* ---- the flight recorder, sec 464 */

static fzn_ring_t ring;
static int grow_between_pages;
static uint64_t next_position;
static uint8_t text_bytes[2000];

static void put(uint64_t position, size_t text_len)
{
	fzn_entry_t e;

	memset(&e, 0, sizeof(e));
	strcpy(e.name.user, "root");
	strcpy(e.name.program, "fuzznetd");
	e.name.pid = 77u;
	e.name.start_ms = 9u;
	e.name.position = position;
	e.time_us = 1u + position;
	e.level = FZN_ENTRY_DEBUG;
	strcpy(e.subsystem, "node/round");
	memset(text_bytes, (int)('a' + (position % 26u)), text_len);
	e.text = text_bytes;
	e.text_len = text_len;
	(void)fzn_ring_put(&ring, &e);
}

static int ring_host(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
                     size_t cap, size_t *reply_len)
{
	(void)ctx;
	/* ROOM FOR A FEW RECORDS, so the ring pages. */
	*reply_len = fzn_gather_ring_answer(&ring, request, request_len, reply,
	                                    cap < 6000u ? cap : 6000u);
	/* AND THE HOST GOES ON LOGGING between pages. */
	if (grow_between_pages)
		put(next_position++, 300u);
	return *reply_len > 0u;
}

static uint64_t ring_seen[512];
static size_t n_ring_seen;
static int texts_whole;

static void note_entry(void *ctx, const fzn_entry_t *e)
{
	size_t i;

	(void)ctx;
	if (n_ring_seen < 512u)
		ring_seen[n_ring_seen++] = e->name.position;
	for (i = 0; i < e->text_len; i++)
		if (e->text[i] != (uint8_t)('a' + (e->name.position % 26u)))
			texts_whole = 0;
}

static void test_the_ring(void)
{
	size_t got = 0, i;
	int ordered = 1;
	uint8_t reply[6000];

	fzn_ring_init(&ring);
	for (next_position = 0; next_position < 40u; next_position++)
		put(next_position, 100u + (next_position * 47u) % 1500u);
	n_ring_seen = 0;
	texts_whole = 1;
	CHECK(fzn_gather_ring_fetch(ring_host, NULL, 64u, note_entry, NULL, &got) == FZN_GATHER_OK
	              && got == 40u && n_ring_seen == 40u && texts_whole,
	      "every entry of the ring, across pages, each text whole");
	for (i = 0; i < n_ring_seen; i++)
		if (ring_seen[i] != i)
			ordered = 0;
	CHECK(ordered, "oldest first, in order");

	/* A HOST LOGGING BETWEEN PAGES: every position once, none repeated. */
	grow_between_pages = 1;
	n_ring_seen = 0;
	CHECK(fzn_gather_ring_fetch(ring_host, NULL, 64u, note_entry, NULL, &got) == FZN_GATHER_OK
	              && got >= 40u,
	      "a ring that grows while it is read is still read to its end");
	ordered = 1;
	for (i = 1; i < n_ring_seen; i++)
		if (ring_seen[i] != ring_seen[i - 1u] + 1u)
			ordered = 0;
	CHECK(ordered && n_ring_seen && ring_seen[0] == 0u,
	      "and every position comes once, in order, with nothing repeated across pages");
	grow_between_pages = 0;
	CHECK(fzn_gather_ring_answer(&ring, (const uint8_t *)"get peer", 8u, reply, sizeof(reply))
	              == 0u,
	      "a verb line is no ring query");
}

static int consecutive(uint64_t first, size_t n)
{
	size_t i;

	if (n_seen != n)
		return 0;
	for (i = 0; i < n; i++)
		if (seen[i] != first + i)
			return 0;
	return 1;
}

int main(void)
{
	fzn_gather_query_t q;
	size_t lines = 0;
	uint64_t first = 0;
	char path[300];

	(void)snprintf(top, sizeof(top), "/tmp/fzn-gather-test-XXXXXX");
	if (!mkdtemp(top)) {
		fprintf(stderr, "  FAIL gather_test.c: no scratch directory\n");
		return 1;
	}
	/* THE OLDEST PACKED, when packing is built: entries 0..4. */
#ifdef FZN_LOG_PACK_ON
	{
		static const fzn_hash_ops_t TOY = { toy, NULL };
		char log[300], zst[300];
		uint8_t prev[32] = { 0 }, h[32];

		(void)snprintf(log, sizeof(log), "%s/netcfgd.4000000.1.log", top);
		(void)snprintf(zst, sizeof(zst), "%s/netcfgd.4000000.1.log.zst", top);
		CHECK(segment("netcfgd.4000000.1.log", "netcfgd", 0u, 5u)
		              && fzn_log_pack_segment(log, zst, prev, &TOY, h) == FZN_LOG_PACK_OK
		              && remove(log) == 0,
		      "fixture: the oldest segment, packed");
	}
#endif
	CHECK(segment("netcfgd.9000000.2.log", "netcfgd", 5u, 5u)
	              && segment("netcfgd.log", "netcfgd", 10u, 5u)
	              && segment("other.log", "other", 100u, 3u),
	      "fixture: a closed segment, the current file, and another program's");
#ifdef FZN_LOG_PACK_ON
	first = 0u;
#else
	first = 5u;
#endif

	/* EVERYTHING, page by page, oldest first. */
	n_seen = 0;
	q = query(0u, UINT64_MAX, "");
	CHECK(fzn_gather_fetch(host, NULL, &q, 64u, note, NULL, &lines) == FZN_GATHER_OK
	              && lines == 15u - first && consecutive(first, 15u - first),
	      "every line of the program, oldest first and in order, across pages and segments");

	/* A WINDOW. */
	n_seen = 0;
	q = query(7u * 1000000u, 11u * 1000000u, "");
	CHECK(fzn_gather_fetch(host, NULL, &q, 64u, note, NULL, &lines) == FZN_GATHER_OK
	              && consecutive(7u, 5u),
	      "a window from entry 7 to entry 11, ends included, across the two segments");

	/* AN ENTRY AND EVERYTHING IT CAUSED: its instance field. */
	n_seen = 0;
	q = query(0u, UINT64_MAX, "812@1#12");
	CHECK(fzn_gather_fetch(host, NULL, &q, 64u, note, NULL, &lines) == FZN_GATHER_OK
	              && n_seen == 1u && seen[0] == 12u,
	      "a match on an instance field finds that entry");

	/* WHAT IS NOT A QUERY falls through; what is a broken one is refused. */
	{
		uint8_t reply[600];
		uint8_t req[FZN_GATHER_QUERY_MAX];
		size_t len = 0;

		CHECK(fzn_gather_answer(top, (const uint8_t *)"get peer", 8u, reply, sizeof(reply)) == 0u,
		      "a verb line is no query, and is left to the verbs");
		q = query(0u, 1u, "");
		(void)fzn_gather_query_encode(&q, req, sizeof(req), &len);
		CHECK(fzn_gather_answer(top, req, len - 1u, reply, sizeof(reply)) == 0u
		              && fzn_gather_answer(top, req, len + 1u, reply, sizeof(reply)) == 0u,
		      "a query a byte short or long is not answered");
		strcpy(q.program, "a/b");
		CHECK(fzn_gather_query_encode(&q, req, sizeof(req), &len) == FZN_GATHER_ERR_MALFORMED,
		      "a program with a slash is refused");
	}

	/* A HOST THAT ANSWERS SOMETHING ELSE, and one too small for any line. */
	answer_garbage = 1;
	q = query(0u, UINT64_MAX, "");
	CHECK(fzn_gather_fetch(host, NULL, &q, 64u, note, NULL, &lines) == FZN_GATHER_ERR_REFUSED,
	      "a reply that is not a page is refused");
	answer_garbage = 0;
	reply_cap = 60u;
	n_seen = 0;
	CHECK(fzn_gather_fetch(host, NULL, &q, 64u, note, NULL, &lines) == FZN_GATHER_OK
	              && lines == 0u,
	      "a page too small for any line passes them over and ends, rather than looping");
	reply_cap = 600u;

	test_the_ring();

	(void)snprintf(path, sizeof(path), "%s/netcfgd.9000000.2.log", top);
	(void)remove(path);
	(void)snprintf(path, sizeof(path), "%s/netcfgd.4000000.1.log", top);
	(void)remove(path);
	(void)snprintf(path, sizeof(path), "%s/netcfgd.4000000.1.log.zst", top);
	(void)remove(path);
	(void)snprintf(path, sizeof(path), "%s/netcfgd.log", top);
	(void)remove(path);
	(void)snprintf(path, sizeof(path), "%s/other.log", top);
	(void)remove(path);
	CHECK(rmdir(top) == 0, "the scratch directory is empty, and goes");

	if (failures) {
		fprintf(stderr, "gather_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gather_test: all %d checks passed\n", checks);
	return 0;
}
