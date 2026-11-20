/* remote_test -- one search asked of another host, sec 1287 step 2: an ask
 * and an answer written and read back, cursor and window included; the
 * longest answer within its bound; what is not an ask or an answer
 * refused; and the host's whole part, an ask answered from its stores,
 * equal to the same search run where the stores are. */
#include "../remote.h"
#include "../../facet/codec.h"

#include <stdio.h>
#include <string.h>

static int failures, checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL remote_test.c:%d: %s\n", line, what);
	}
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

/* A STORE OF FIXED TEXTS, each keyed by its index, its time 1000 + index. */
static const char *const notes[] = { "thanks for the cake", "the cake was lovely", "see you at the station",
	                             "thank you again", "a lovely day" };

static int run_notes(void *ctx, const fzn_search_query_t *q, const uint8_t *asker, fzn_search_emit_t emit,
                     void *emit_ctx)
{
	size_t i;

	(void)ctx;
	(void)asker;
	for (i = 0; i < sizeof(notes) / sizeof(notes[0]); i++) {
		fzn_search_hit_t h;

		memset(&h, 0, sizeof(h));
		strcpy(h.store, "notes");
		h.key[0] = (uint8_t)i;
		h.key_len = 1u;
		h.time_ms = 1000u + i;
		h.score = fzn_search_score(&q->words, notes[i], strlen(notes[i]));
		if (!h.score)
			continue;
		fzn_search_snippet(q, notes[i], strlen(notes[i]), &h);
		/* A FACET, for the filter (sec 1319): even notes and odd. */
		(void)fzn_search_facet_add(&h, "mood", i % 2u ? "odd" : "even", i % 2u ? 3u : 4u);
		if (!emit(emit_ctx, &h))
			return 1;
	}
	return 1;
}

static int same_hit(const fzn_search_hit_t *a, const fzn_search_hit_t *b)
{
	return !strcmp(a->store, b->store) && a->key_len == b->key_len && !memcmp(a->key, b->key, a->key_len)
	       && a->score == b->score && a->time_ms == b->time_ms && a->snippet_len == b->snippet_len
	       && !memcmp(a->snippet, b->snippet, a->snippet_len);
}

static void test_an_ask_reads_back(void)
{
	static const char *const asked[] = { "notes", "lines" };
	static fzn_search_ask_t back;
	fzn_search_query_t q;
	fzn_search_hit_t after;
	uint8_t out[1024];
	size_t n;

	CHECK(fzn_search_query_init(&q, "Thanks cake", 11u, 7u), "a query was not made");
	q.stores = asked;
	q.n_stores = 2u;
	q.from_ms = 5u;
	q.to_ms = 9000u;
	memset(&after, 0, sizeof(after));
	strcpy(after.store, "lines");
	memset(after.key, 0xab, 40u);
	after.key_len = 40u;
	after.score = 150u;
	after.time_ms = 77u;
	q.after = &after;
	n = fzn_search_ask_write("Thanks cake", 11u, &q, out, sizeof(out));
	CHECK(n && out[0] == 26u && fzn_search_ask_read(out, n, &back) && back.words_len == 11u
	              && !memcmp(back.words, "Thanks cake", 11u) && back.query.n_stores == 2u
	              && !strcmp(back.query.stores[1], "lines") && back.query.from_ms == 5u
	              && back.query.to_ms == 9000u && back.query.k == 7u && back.query.after
	              && back.query.after->key_len == 40u && back.query.after->score == 150u
	              && back.query.after->time_ms == 77u && !strcmp(back.query.after->store, "lines")
	              && back.query.words.n == q.words.n,
	      "an ask did not read back whole");
	CHECK(!fzn_search_ask_read(out, n - 1u, &back), "an ask cut short was read");
	out[1] = 2u;
	CHECK(!fzn_search_ask_read(out, n, &back), "an answer was read as an ask");
	q.after = NULL;
	q.n_stores = 0;
	n = fzn_search_ask_write("cake", 4u, &q, out, sizeof(out));
	CHECK(n && fzn_search_ask_read(out, n, &back) && !back.query.after && !back.query.n_stores,
	      "an ask with no cursor and every store did not read back so");
	CHECK(!fzn_search_ask_write("", 0u, &q, out, sizeof(out)), "an ask of no words was written");
	{
		/* HALF A CURSOR: its store and key there, HAS_AFTER 0. */
		static const uint8_t half[] = { 0x1a, 0x01, 0x01, 'x', 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			                        0x01, 0x00, 0, 0, 0, 0x96, 0, 0, 0, 0, 0, 0, 0, 0x4d,
			                        0x05, 'l', 'i', 'n', 'e', 's', 0x02, 0xab, 0xcd };

		CHECK(!fzn_search_ask_read(half, sizeof(half), &back), "an ask with half a cursor was read");
	}
	{
		static const char *const bad[] = { "no\ttab" };

		q.stores = bad;
		q.n_stores = 1u;
		CHECK(!fzn_search_ask_write("cake", 4u, &q, out, sizeof(out)), "a store name with a tab was written");
	}
}

static void test_an_answer_reads_back(void)
{
	static fzn_search_hit_t hits[FZN_SEARCH_K_MAX], back[FZN_SEARCH_K_MAX];
	static uint8_t out[FZN_SEARCH_ANSWER_MAX];
	size_t i, n, got = 0;
	int more = 0, all = 1;

	/* THE LONGEST: K hits, every field at its bound. */
	for (i = 0; i < FZN_SEARCH_K_MAX; i++) {
		memset(&hits[i], 0, sizeof(hits[i]));
		memset(hits[i].store, 's', FZN_SEARCH_STORE_NAME_MAX);
		memset(hits[i].key, (int)i, FZN_SEARCH_KEY_MAX);
		hits[i].key_len = FZN_SEARCH_KEY_MAX;
		hits[i].score = 1000u - (unsigned)i;
		hits[i].time_ms = 0xffffffffffull + i;
		memset(hits[i].snippet, 'x', FZN_SEARCH_SNIPPET_MAX);
		hits[i].snippet_len = FZN_SEARCH_SNIPPET_MAX;
	}
	n = fzn_search_answer_write(hits, FZN_SEARCH_K_MAX, 1, out, sizeof(out));
	CHECK(n && n <= FZN_SEARCH_ANSWER_MAX && fzn_search_answer_read(out, n, back, FZN_SEARCH_K_MAX, &got, &more)
	              && got == FZN_SEARCH_K_MAX && more == 1,
	      "the longest answer did not fit its bound or read back");
	for (i = 0; i < got; i++)
		all &= same_hit(&hits[i], &back[i]);
	CHECK(all, "a hit of the longest answer read back changed");
	CHECK(!fzn_search_answer_read(out, n, back, FZN_SEARCH_K_MAX - 1u, &got, &more),
	      "an answer of more hits than the room was read");
	n = fzn_search_answer_write(NULL, 0u, 0, out, sizeof(out));
	CHECK(n && fzn_search_answer_read(out, n, back, 1u, &got, &more) && !got && !more,
	      "an empty answer did not read back so");
	hits[0].key_len = 0;
	CHECK(!fzn_search_answer_write(hits, 1u, 0, out, sizeof(out)), "a hit with no key was written");
}

/* THE HOST'S PART equals the search run where the stores are, page by page. */
static void test_a_host_answers_as_the_stores_would(void)
{
	static const fzn_search_store_t stores[] = { { "notes", run_notes, NULL } };
	static fzn_search_hit_t local[FZN_SEARCH_K_MAX], remote[FZN_SEARCH_K_MAX];
	static uint8_t ask[1024], answer[FZN_SEARCH_ANSWER_MAX];
	fzn_search_query_t q;
	size_t n_local = 0, n_remote = 0, len, i, pages = 0, seen = 0;
	int more_local = 0, more_remote = 0, same = 1;
	fzn_search_hit_t after;

	CHECK(fzn_search_query_init(&q, "cake", 4u, 1u), "a query was not made");
	do {
		len = fzn_search_ask_write("cake", 4u, &q, ask, sizeof(ask));
		len = len ? fzn_search_answer_ask(stores, 1u, ask, len, NULL, answer, sizeof(answer)) : 0u;
		if (!len || !fzn_search_answer_read(answer, len, remote, FZN_SEARCH_K_MAX, &n_remote, &more_remote)
		    || !fzn_search_run(stores, 1u, &q, NULL, local, &n_local, &more_local)) {
			same = 0;
			break;
		}
		same &= n_local == n_remote && more_local == more_remote;
		for (i = 0; i < n_local && i < n_remote; i++)
			same &= same_hit(&local[i], &remote[i]);
		seen += n_remote;
		if (n_remote) {
			after = remote[n_remote - 1u];
			q.after = &after;
		}
		pages++;
	} while (more_remote && pages < 10u);
	CHECK(same && seen == 2u && pages == 2u, "a host's answers were not the search run where its stores are");
	CHECK(!fzn_search_answer_ask(stores, 1u, (const uint8_t *)"\x1a\x01", 2u, NULL, answer, sizeof(answer)),
	      "a malformed ask was answered");
}

/* A FILTER CARRIED IN AN ASK, sec 1319: read back whole, run where the
 * stores are -- of the two cake notes only the even one -- and a RANGE,
 * which one hit cannot answer, refused. */
static void test_a_filter_travels_with_the_ask(void)
{
	static const fzn_search_store_t stores[] = { { "notes", run_notes, NULL } };
	static fzn_search_hit_t remote[FZN_SEARCH_K_MAX];
	static uint8_t ask[1024], answer[FZN_SEARCH_ANSWER_MAX], filter[256];
	static fzn_search_ask_t back;
	fzn_facet_term_t p[1], r[1];
	fzn_facet_expr_t e = { p, 1, NULL, 0 }, range = { r, 1, NULL, 0 };
	fzn_search_query_t q;
	size_t n = 0, len = 0, flen = 0;
	int more = 0;

	memset(p, 0, sizeof(p));
	p[0].kind = FZN_FACET_PREFIX;
	p[0].node = (fzn_facet_node_t){ (const uint8_t *)"mood", 4u, (const uint8_t *)"even", 4u };
	CHECK(fzn_facet_expr_encode(&e, filter, sizeof(filter), &flen) == FZN_FACET_OK, "fixture: a filter");
	CHECK(fzn_search_query_init(&q, "cake", 4u, 10u), "fixture: a query");
	q.filter = filter;
	q.filter_len = flen;
	len = fzn_search_ask_write("cake", 4u, &q, ask, sizeof(ask));
	CHECK(len && fzn_search_ask_read(ask, len, &back) && back.query.filter_len == flen
	              && !memcmp(back.query.filter, filter, flen) && back.query.keep,
	      "a filter did not read back with its ask, or nothing keeps by it");
	len = len ? fzn_search_answer_ask(stores, 1u, ask, len, NULL, answer, sizeof(answer)) : 0u;
	CHECK(len && fzn_search_answer_read(answer, len, remote, FZN_SEARCH_K_MAX, &n, &more) && n == 1u
	              && remote[0].key[0] == 0u,
	      "a filtered ask was not answered with the even cake note alone");
	memset(r, 0, sizeof(r));
	r[0].kind = FZN_FACET_RANGE;
	r[0].node = (fzn_facet_node_t){ (const uint8_t *)"mood", 4u, (const uint8_t *)"m", 1u };
	CHECK(fzn_facet_expr_encode(&range, filter, sizeof(filter), &flen) == FZN_FACET_OK
	              && !fzn_search_ask_filter(&back, filter, flen) && !back.query.keep,
	      "a RANGE filter was taken, which one hit cannot answer");
}

/* A HOST'S MORE: one host's K hits and nothing elsewhere fill the page
 * exactly, and only the host knows it holds more. */
static void test_a_host_s_more_is_kept(void)
{
	fzn_search_hit_t two[2], out[2];
	fzn_search_query_t q;
	size_t n = 0;
	int more = 0;

	memset(two, 0, sizeof(two));
	strcpy(two[0].store, "notes");
	strcpy(two[1].store, "notes");
	two[0].key[0] = 1;
	two[1].key[0] = 2;
	two[0].key_len = two[1].key_len = 1u;
	two[0].score = two[1].score = 100u;
	CHECK(fzn_search_query_init(&q, "x", 1u, 2u)
	              && fzn_search_merge(&q, two, 2u, 1, out, &n, &more) && n == 2u && more == 1
	              && fzn_search_merge(&q, two, 2u, 0, out, &n, &more) && n == 2u && more == 0,
	      "a host's word that it holds more was lost, or made up");
}

int main(void)
{
	test_an_ask_reads_back();
	test_an_answer_reads_back();
	test_a_host_answers_as_the_stores_would();
	test_a_filter_travels_with_the_ask();
	test_a_host_s_more_is_kept();
	{
		const int before = failures;

		CHECK(0, "deliberate");
		if (failures != before + 1) {
			printf("search remote_test: the suite cannot fail\n");
			return 1;
		}
		failures = before;
	}
	if (failures) {
		printf("search remote_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("search remote_test: all %d checks passed\n", checks - 1);
	return 0;
}
