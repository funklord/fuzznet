/* search_test -- one search over every store, sec 1287: the words and their
 * score, the engine's one order, one hit per item, the window, the stores
 * asked, a keyset cursor that pages with no gap and no repeat, and the claim
 * the distributed design rests on: hosts each answering their best K after a
 * cursor, merged, give exactly the page one search over everything gives. */
#include "../search.h"
#include "../filter.h"

#include <stdio.h>
#include <string.h>

static int failures, checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL search_test.c:%d: %s\n", line, what);
	}
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

/* ---- the words ------------------------------------------------------------ */

static unsigned score(const char *query, const char *text)
{
	fzn_search_words_t q;

	fzn_search_words_of(query, strlen(query), &q);
	q.open_end = 0;
	return fzn_search_score(&q, text, strlen(text));
}

static void test_the_words(void)
{
	fzn_search_words_t q;

	CHECK(score("thanks", "Thank you so much") == 100u, "a plain ending was not let go, or case not folded");
	CHECK(score("you're welcome", "youre WELCOME here") == 250u,
	      "an apostrophe was kept, or two words together not scored as such");
	CHECK(score("welcome you're", "youre welcome") == 200u, "words out of order were scored as standing together");
	CHECK(score("dinner tonight", "dinner at eight") == 0u, "a text lacking a telling word was found");
	CHECK(score("the dinner", "dinner at eight") == 100u, "a common word was required beside a telling one");
	CHECK(score("the", "the end") == 100u && score("the", "an end") == 0u,
	      "a query of common words alone was not held to them");
	fzn_search_words_of("see y", 5u, &q);
	CHECK(q.open_end && fzn_search_score(&q, "see you there", 13u) == 160u + 50u,
	      "a last word being typed was not taken as begun");
	CHECK(score("förlåt", "Förlåt mig") == 100u, "a word holding letters past ASCII was not found");
	/* PAST ASCII, sec 1297: capitals folded by Unicode's simple folding,
	 * and punctuation and spaces a gap as ASCII marks are. */
	CHECK(score("åsa", "ÅSA kommer") == 100u && score("ÄLG", "en älg") == 100u,
	      "a Latin-1 capital was not folded");
	CHECK(score("łódź", "ŁÓDŹ") == 100u, "a Latin Extended-A capital was not folded");
	CHECK(score("οδος", "ΟΔΟΣ") == 100u, "a Greek capital, or a final sigma, was not folded");
	CHECK(score("москва", "МОСКВА") == 100u && score("ёлка", "ЁЛКА") == 100u,
	      "a Cyrillic capital was not folded");
	CHECK(score("quoted", "it was \xe2\x80\x9cquoted\xe2\x80\x9d") == 100u,
	      "a word in typographic quotes was not found");
	CHECK(score("world", "hello\xe2\x80\x94world") == 100u && score("dinner", "\xc2\xa1" "dinner!") == 100u,
	      "a dash or an inverted mark past ASCII was taken as a letter");
	CHECK(score("don't", "don\xe2\x80\x99t") == 100u, "a typographic apostrophe was not dropped from inside a word");
	CHECK(score("\xc2\xb5m", "5 \xc2\xb5m") == 100u, "the micro sign, a letter, was taken as a gap");
}

/* ---- stores of fixed hits --------------------------------------------------- */

typedef struct {
	const char *name;
	fzn_search_hit_t hits[64];
	size_t n;
} fixed_t;

static int run_fixed(void *ctx, const fzn_search_query_t *q, const uint8_t *asker, fzn_search_emit_t emit,
                     void *emit_ctx)
{
	const fixed_t *f = ctx;
	size_t i;

	(void)q;
	(void)asker;
	for (i = 0; i < f->n; i++)
		if (!emit(emit_ctx, &f->hits[i]))
			break;
	return 1;
}

static void hit(fixed_t *f, uint8_t key, unsigned score_of, uint64_t at)
{
	fzn_search_hit_t *h = &f->hits[f->n++];

	memset(h, 0, sizeof(*h));
	snprintf(h->store, sizeof(h->store), "%s", f->name);
	h->key[0] = key;
	h->key_len = 1u;
	h->score = score_of;
	h->time_ms = at;
}

static uint32_t rnd = 12345u;
static uint32_t next(void)
{
	rnd ^= rnd << 13;
	rnd ^= rnd >> 17;
	rnd ^= rnd << 5;
	return rnd;
}

static void test_one_order_one_hit_each(void)
{
	static fixed_t a, b;
	fzn_search_store_t stores[2] = { { "lines", run_fixed, &a }, { "names", run_fixed, &b } };
	fzn_search_query_t q;
	fzn_search_hit_t out[FZN_SEARCH_K_MAX];
	const char *only[] = { "names" };
	size_t count = 0, i;
	int more = 0, ordered = 1;

	a.name = "lines";
	b.name = "names";
	a.n = b.n = 0;
	hit(&a, 1, 100, 5);
	hit(&a, 2, 200, 1);
	hit(&a, 1, 250, 3); /* item 1 again, better */
	hit(&a, 3, 100, 9);
	hit(&b, 1, 100, 5); /* another store's item 1 is another item */
	CHECK(fzn_search_query_init(&q, "x", 1u, 10u), "fixture: a query");
	CHECK(fzn_search_run(stores, 2, &q, NULL, out, &count, &more) && count == 4u && !more,
	      "every item was not found once");
	for (i = 1; i < count; i++)
		ordered = ordered && fzn_search_before(&out[i - 1u], &out[i]);
	CHECK(ordered && out[0].key[0] == 1 && out[0].score == 250u && !strcmp(out[0].store, "lines"),
	      "the hits were not in the one order, an item's best copy first");
	CHECK(out[2].score == 100u && out[2].time_ms == 9u && out[3].time_ms == 5u
	              && strcmp(out[3].store, "names") == 0,
	      "equal scores were not ordered by time, then store");
	q.k = 2u;
	CHECK(fzn_search_run(stores, 2, &q, NULL, out, &count, &more) && count == 2u && more,
	      "a page of two did not say more");
	q.k = 10u;
	q.stores = only;
	q.n_stores = 1u;
	CHECK(fzn_search_run(stores, 2, &q, NULL, out, &count, &more) && count == 1u && !strcmp(out[0].store, "names"),
	      "a store not asked was searched");
	q.stores = NULL;
	q.n_stores = 0;
	q.from_ms = 4u;
	q.to_ms = 6u;
	CHECK(fzn_search_run(stores, 2, &q, NULL, out, &count, &more) && count == 2u && out[0].time_ms == 5u,
	      "the window let in a hit outside it");
	CHECK(!fzn_search_query_init(&q, "  ,", 3u, 10u) && !fzn_search_query_init(&q, "x", 1u, 0u)
	              && !fzn_search_query_init(&q, "x", 1u, FZN_SEARCH_K_MAX + 1u),
	      "a query of no word, or of a K out of range, was taken");
}

/* PAGING BY CURSOR, and THE DISTRIBUTED CLAIM: random items over three
 * "hosts" -- with copies of one item at two of them -- paged by a cursor;
 * each page from the merge of the hosts' own best-K-after-cursor answers is
 * exactly the page one search over all of it gives, and the pages together
 * hold every item once. */
static void test_pages_merge_as_one(void)
{
	static fixed_t host[3], all, answer[3];
	fzn_search_store_t whole = { "lines", run_fixed, &all }, from[3], answers[3];
	fzn_search_hit_t page[FZN_SEARCH_K_MAX], merged[FZN_SEARCH_K_MAX], last;
	fzn_search_query_t q;
	unsigned char seen[64];
	size_t i, h, count = 0, mcount = 0, pages = 0, total = 0;
	int more = 1, mmore = 0, same = 1, once = 1;

	memset(seen, 0, sizeof(seen));
	all.name = "lines";
	all.n = 0;
	for (h = 0; h < 3u; h++) {
		host[h].name = answer[h].name = "lines";
		host[h].n = 0;
		from[h] = (fzn_search_store_t){ "lines", run_fixed, &host[h] };
		answers[h] = (fzn_search_store_t){ "lines", run_fixed, &answer[h] };
	}
	for (i = 0; i < 40u; i++) {
		const unsigned s = 50u + (unsigned)(next() % 4u) * 50u;
		const uint64_t t = next() % 10u;

		h = i % 3u;
		hit(&host[h], (uint8_t)i, s, t);
		hit(&all, (uint8_t)i, s, t);
		/* THE SAME ITEM HELD AT A SECOND HOST: scored alike there, as a
		 * store must score it, from the item and the query alone. */
		if (i % 7u == 0u)
			hit(&host[(h + 1u) % 3u], (uint8_t)i, s, t);
	}
	CHECK(fzn_search_query_init(&q, "x", 1u, 6u), "fixture: a query of six a page");
	while (more && pages < 20u) {
		CHECK(fzn_search_run(&whole, 1, &q, NULL, page, &count, &more), "one search over everything");
		/* EACH HOST'S OWN ANSWER, then the asker's merge of the three. */
		for (h = 0; h < 3u; h++) {
			size_t n = 0;
			int m = 0;

			(void)fzn_search_run(&from[h], 1, &q, NULL, answer[h].hits, &n, &m);
			answer[h].n = n;
		}
		CHECK(fzn_search_run(answers, 3, &q, NULL, merged, &mcount, &mmore), "the merge of the hosts' answers");
		same = same && mcount == count;
		/* AND BY THE MERGE AN ASKER USES, sec 1287 step 3: the hits as they
		 * came, and whether any host said it holds more. */
		{
			static fzn_search_hit_t gathered[3u * FZN_SEARCH_K_MAX], by_merge[FZN_SEARCH_K_MAX];
			size_t g = 0, bcount = 0, j;
			int held = 0, bmore = 0;

			for (h = 0; h < 3u; h++) {
				size_t n = 0;
				int m = 0;

				(void)fzn_search_run(&from[h], 1, &q, NULL, gathered + g, &n, &m);
				g += n;
				held |= m;
			}
			same = same && fzn_search_merge(&q, gathered, g, held, by_merge, &bcount, &bmore) && bcount == count
			       && bmore == more;
			for (j = 0; j < count && j < bcount; j++)
				same = same && by_merge[j].key[0] == page[j].key[0] && by_merge[j].score == page[j].score;
		}
		for (i = 0; i < count && i < mcount; i++)
			same = same && merged[i].key[0] == page[i].key[0] && merged[i].score == page[i].score;
		for (i = 0; i < count; i++) {
			once = once && !seen[page[i].key[0]];
			seen[page[i].key[0]] = 1;
		}
		total += count;
		if (count) {
			last = page[count - 1u];
			q.after = &last;
		}
		pages++;
	}
	CHECK(same, "a page merged from the hosts' answers was not the page one search over everything gives");
	CHECK(once && total == 40u && !more, "paging by cursor repeated or missed an item");
}

/* THE QUERY'S KEEP, sec 1319: asked of every hit a store emits here, and
 * of none merged from other hosts, which filtered their own. */
static int keep_odd(void *ctx, const fzn_search_hit_t *h)
{
	(void)ctx;
	return h->key[0] % 2u;
}

static void test_keep_runs_where_the_stores_are(void)
{
	static fixed_t f;
	static fzn_search_hit_t out[FZN_SEARCH_K_MAX];
	const fzn_search_store_t store = { "notes", run_fixed, &f };
	fzn_search_query_t q;
	size_t n = 0, i;
	int more = 0, odd = 1;

	f.name = "notes";
	f.n = 0;
	for (i = 0; i < 6u; i++)
		hit(&f, (uint8_t)i, 100u, 1000u + i);
	CHECK(fzn_search_query_init(&q, "cake", 4u, 10u), "fixture: a query");
	q.keep = keep_odd;
	CHECK(fzn_search_run(&store, 1u, &q, NULL, out, &n, &more) && n == 3u, "the run did not keep the odd three");
	for (i = 0; i < n; i++)
		odd &= (out[i].key[0] % 2u) != 0u;
	CHECK(odd, "a hit the keep refused was kept");
	CHECK(fzn_search_merge(&q, f.hits, f.n, 0, out, &n, &more) && n == 6u,
	      "a merge of hits from other hosts filtered them again");
}

/* A STORE THAT STOPPED SHORT, sec 1328: its 2 makes the run partial; a
 * store that finished, not. */
static int run_short(void *ctx, const fzn_search_query_t *q, const uint8_t *asker, fzn_search_emit_t emit,
                     void *emit_ctx)
{
	(void)run_fixed(ctx, q, asker, emit, emit_ctx);
	return 2;
}

static void test_a_store_that_stopped_short(void)
{
	static fixed_t f;
	static fzn_search_hit_t out[FZN_SEARCH_K_MAX];
	fzn_search_store_t store = { "notes", run_short, &f };
	fzn_search_query_t q;
	size_t n = 0;
	int more = 0, partial = 0;

	f.name = "notes";
	f.n = 0;
	hit(&f, 1u, 100u, 1000u);
	CHECK(fzn_search_query_init(&q, "cake", 4u, 10u), "fixture: a query");
	CHECK(fzn_search_run_partial(&store, 1u, &q, NULL, out, &n, &more, &partial) && n == 1u && partial,
	      "a store that stopped short did not make the run partial");
	store.run = run_fixed;
	CHECK(fzn_search_run_partial(&store, 1u, &q, NULL, out, &n, &more, &partial) && n == 1u && !partial,
	      "a store that finished made the run partial");
}

static void test_the_snippet(void)
{
	fzn_search_query_t q;
	fzn_search_hit_t h;
	char text[400];
	size_t i;

	CHECK(fzn_search_query_init(&q, "needle", 6u, 5u), "fixture: a query");
	fzn_search_snippet(&q, "short", 5u, &h);
	CHECK(h.snippet_len == 5u && !strcmp(h.snippet, "short"), "a short text was not given whole");
	for (i = 0; i + 2u <= 300u; i += 2u)
		memcpy(text + i, "\xc3\xa9", 2u);
	memcpy(text + 200, " NEEDLE ", 8u);
	fzn_search_snippet(&q, text, 300u, &h);
	CHECK(h.snippet_len <= FZN_SEARCH_SNIPPET_MAX && strstr(h.snippet, "NEEDLE")
	              && ((unsigned char)h.snippet[0] & 0xC0u) != 0x80u
	              && ((unsigned char)h.snippet[h.snippet_len - 1u] & 0xC0u) != 0xC0u,
	      "a long text's snippet did not hold the word, or cut a character");
}

/* A FILTER WORD, and a null filter refused rather than read: the count was
 * read before the null check (gcc -fanalyzer). */
static void test_a_filter_word(void)
{
	static fzn_search_filter_words_t f;

	CHECK(fzn_search_filter_word(NULL, 0, "kind=photo", 10) == 0, "a null filter was taken");
	memset(&f, 0, sizeof(f));
	CHECK(fzn_search_filter_word(&f, 0, "kind=photo", 10) == 1 && f.n_pos == 1u,
	      "a filter word was not taken");
	CHECK(fzn_search_filter_word(&f, 0, "kind", 4) == 0, "a word with no value was taken");
}

int main(void)
{
	test_a_filter_word();
	test_the_words();
	test_one_order_one_hit_each();
	test_pages_merge_as_one();
	test_the_snippet();
	test_keep_runs_where_the_stores_are();
	test_a_store_that_stopped_short();
	{
		const int before = failures;

		CHECK(0, "deliberate");
		if (failures != before + 1) {
			printf("search_test: the suite cannot fail\n");
			return 1;
		}
		failures = before;
	}
	if (failures) {
		printf("search_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("search_test: all %d checks passed\n", checks - 1);
	return 0;
}
