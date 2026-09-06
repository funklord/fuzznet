/* Tests for catalog/copy.c: what a host still needs, what it has, what it
 * will give.
 *
 * THE CASES THIS FILE EXISTS FOR are the three the design turns on, and none
 * of them is "the walk visits every row". project.md sec 154.
 *
 *   - A holdings announcement must not read the retention table. Retention is
 *     an intention and a holding is a fact, and they diverge in BOTH
 *     directions -- so the two cases that matter are a KEEP whose bytes have
 *     not arrived and a DROP whose bytes are still here.
 *   - An offer must be scoped to the catalogue. A want naming a root this
 *     catalogue does not reference is counted and never served, or a
 *     capability for one catalogue is a capability for the whole blob store.
 *   - The counters must add up, in both groups, on every walk. A count that
 *     does not have to close is a count nobody can check.
 */

#include "../copy.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

#if defined(__GNUC__)
#define FZN_CHECK_PRINTF __attribute__((format(printf, 3, 4)))
#else
#define FZN_CHECK_PRINTF
#endif

static void check_at(int ok, int line, const char *fmt, ...) FZN_CHECK_PRINTF;

static void check_at(int ok, int line, const char *fmt, ...)
{
	va_list ap;

	checks++;
	if (ok)
		return;

	failures++;
	fprintf(stderr, "  FAIL copy_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)
#define REQUIRE(cond, ...)                                   \
	do {                                                 \
		int require_ok = (cond) ? 1 : 0;             \
		check_at(require_ok, __LINE__, __VA_ARGS__); \
		if (!require_ok)                             \
			return;                              \
	} while (0)

static uint8_t ALICE[FZN_PUBKEY_LEN];

/* A moment, deliberately not zero: sec 157 gave retention deadlines and
 * every call that reads retention now names the moment it reads it at.
 * Zero would be the degenerate value everywhere and would hide a reader
 * that ignored the argument. No case here sets a deadline, so every
 * answer is the one sec 154 asserted. */
#define NOW ((uint64_t)1000)

static fzn_catalog_id_t id(uint8_t seed)
{
	fzn_catalog_id_t out;

	memset(out.b, seed, sizeof(out.b));
	return out;
}

static const fzn_catalog_id_t *idp(uint8_t seed)
{
	static fzn_catalog_id_t slots[4];
	static size_t at;

	slots[at] = id(seed);
	at = (at + 1u) % 4u;
	return &slots[(at + 3u) % 4u];
}

static const fzn_catalog_resolve_ops_t ADD_WINS = { fzn_catalog_add_wins, NULL };
static const fzn_catalog_content_ops_t HELD_WINS = { fzn_catalog_content_held_wins, NULL };

static fzn_catalog_entry_t blob_entry(uint8_t seed, uint8_t root_seed, uint64_t blob_len)
{
	fzn_catalog_entry_t e;

	memset(&e, 0, sizeof(e));
	e.id = id(seed);
	e.kind = FZN_CATALOG_CONTENT_BLOB;
	memset(e.root, root_seed, sizeof(e.root));
	e.blob_len = blob_len;
	memcpy(e.issuer, ALICE, FZN_PUBKEY_LEN);
	e.seq = 1;
	return e;
}

static fzn_catalog_entry_t inline_entry(uint8_t seed, const uint8_t *bytes, size_t len)
{
	fzn_catalog_entry_t e;

	memset(&e, 0, sizeof(e));
	e.id = id(seed);
	e.kind = FZN_CATALOG_CONTENT_INLINE;
	e.bytes = bytes;
	e.len = len;
	memcpy(e.issuer, ALICE, FZN_PUBKEY_LEN);
	e.seq = 1;
	return e;
}

/* ---- a holdings seam whose answers the test controls ------------------- */

/* Roots this host has, by their seed byte. A real consumer asks its blob
 * store; what matters here is that the answer is the seam's and not the
 * catalogue's. */
struct store {
	uint8_t roots[8];
	size_t count;
	size_t asked;
};

static int store_holds(void *ctx, const uint8_t root[FZN_BLOB_HASH_LEN], uint64_t len)
{
	struct store *s = ctx;
	size_t i;

	(void)len;
	s->asked++;
	for (i = 0; i < s->count; i++) {
		if (root[0] == s->roots[i])
			return 1;
	}

	return 0;
}

/* ---- the arithmetic, asserted rather than described -------------------- */

/* Every entry examined lands in exactly one class, and the emission counters
 * account for the class the walk selected. copy.h states both sums; this is
 * what makes them a check rather than a paragraph. */
static void closes(const fzn_catalog_copy_t *plan, size_t entries, size_t selected,
                   int line, const char *what)
{
	size_t classified = plan->not_retained + plan->inline_ready + plan->no_content +
	                    plan->already_held + plan->missing + plan->unknown;

	check_at(classified == entries, line,
	         "%s: %zu examined, %zu classified -- the partition leaks", what, entries,
	         classified);
	check_at(plan->written + plan->truncated + plan->duplicates == selected, line,
	         "%s: %zu written + %zu truncated + %zu duplicate does not account for the "
	         "%zu selected",
	         what, plan->written, plan->truncated, plan->duplicates, selected);
}

#define CLOSES(plan, entries, selected, what) closes((plan), (entries), (selected), __LINE__, (what))

/* ------------------------------------------------------------------------ */

/* A HOST ADOPTING A CATALOGUE HOLDS NOTHING, and that is the ordinary first
 * state rather than an edge case -- so a null seam means "nothing here"
 * rather than requiring a stub that always says no. */
static void test_a_fresh_host_wants_everything_it_keeps(void)
{
	fzn_catalog_edge_t rows[4];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_blob_t out[4];
	fzn_catalog_copy_t plan;
	fzn_catalog_t cat;
	fzn_catalog_entry_t e;

	REQUIRE(fzn_catalog_init(&cat, rows, 4, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "the content table would not init");
	REQUIRE(fzn_catalog_retain_all(&cat, 1) == FZN_CATALOG_OK, "keep-all refused");

	e = blob_entry(0x10, 0xa0, 100);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "a blob was refused");
	e = blob_entry(0x11, 0xa1, 200);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "a blob was refused");

	CHECK(fzn_catalog_copy_want(&cat, NULL, NOW, out, 4, &plan) == FZN_CATALOG_OK,
	      "a want list against no store at all was refused");
	CHECK(plan.written == 2, "a host holding nothing wants both blobs, got %zu",
	      plan.written);
	CHECK(plan.already_held == 0, "a null seam must not report anything held");
	CHECK(out[0].len == 100 && out[1].len == 200,
	      "the length a consumer decides with did not travel with the want");
	CLOSES(&plan, 2, plan.missing, "a fresh host's want list");
}

/* THE INTENTION AND THE FACT DIVERGE IN BOTH DIRECTIONS, and a holdings
 * announcement must follow the fact. This is the case sec 152's sentence --
 * "the retention table is that map" -- got wrong, so it is the case this
 * suite exists for. */
static void test_holdings_follow_the_bytes_and_not_the_policy(void)
{
	fzn_catalog_edge_t rows[4];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_blob_t out[4];
	fzn_catalog_copy_t plan;
	fzn_catalog_hold_t holds[4];
	fzn_catalog_t cat;
	fzn_catalog_entry_t e;
	/* 0xa1 is here; 0xa0 is not. */
	struct store store = { { 0xa1, 0, 0, 0, 0, 0, 0, 0 }, 1, 0 };
	fzn_catalog_holdings_ops_t seam = { store_holds, &store };

	REQUIRE(fzn_catalog_init(&cat, rows, 4, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "the content table would not init");
	REQUIRE(fzn_catalog_hold_init(&cat, holds, 4) == FZN_CATALOG_OK,
	        "the retention table would not init");

	/* KEEP, and the bytes have not arrived: retained and not held. */
	e = blob_entry(0x10, 0xa0, 100);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "a blob was refused");
	REQUIRE(fzn_catalog_retain(&cat, idp(0x10), FZN_CATALOG_RETAIN_KEEP) == FZN_CATALOG_OK,
	        "a keep was refused");

	/* DROP, and the bytes are still on disk: held and not retained. */
	e = blob_entry(0x11, 0xa1, 200);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "a blob was refused");
	REQUIRE(fzn_catalog_retain(&cat, idp(0x11), FZN_CATALOG_RETAIN_DROP) == FZN_CATALOG_OK,
	        "a drop was refused");

	REQUIRE(fzn_catalog_copy_holdings(&cat, &seam, out, 4, &plan) == FZN_CATALOG_OK,
	        "a holdings announcement was refused");
	CHECK(plan.written == 1, "one blob is here, announced %zu", plan.written);
	CHECK(out[0].root[0] == 0xa1,
	      "the announcement named the blob this host INTENDS to keep rather than the "
	      "one it actually has");
	CHECK(plan.not_retained == 0,
	      "a holdings announcement read the retention table, which publishes an "
	      "intention as though it were a fact");
	CLOSES(&plan, 2, plan.already_held, "a holdings announcement");

	/* AND THE WANT LIST IS THE OTHER ANSWER OVER THE SAME TWO ROWS. The
	 * DROP is not wanted though nothing here holds an opinion about
	 * whether it is present. */
	REQUIRE(fzn_catalog_copy_want(&cat, &seam, NOW, out, 4, &plan) == FZN_CATALOG_OK,
	        "a want list was refused");
	CHECK(plan.written == 1 && out[0].root[0] == 0xa0,
	      "the want list did not name the kept blob that is missing");
	CHECK(plan.not_retained == 1, "the dropped node was not counted as policy");
	CLOSES(&plan, 2, plan.missing, "a want list beside it");
}

/* AN INLINE VALUE ARRIVED WITH ITS RECORD, so there is nothing to fetch and
 * nothing to announce -- and a node with no content at all is a directory,
 * which is most of a catalogue. */
static void test_only_blobs_are_fetched(void)
{
	fzn_catalog_edge_t rows[4];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_blob_t out[4];
	fzn_catalog_copy_t plan;
	fzn_catalog_t cat;
	fzn_catalog_entry_t e;
	const uint8_t body[4] = { 1, 2, 3, 4 };
	struct store store = { { 0, 0, 0, 0, 0, 0, 0, 0 }, 0, 0 };
	fzn_catalog_holdings_ops_t seam = { store_holds, &store };

	REQUIRE(fzn_catalog_init(&cat, rows, 4, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "the content table would not init");
	REQUIRE(fzn_catalog_retain_all(&cat, 1) == FZN_CATALOG_OK, "keep-all refused");

	e = inline_entry(0x10, body, sizeof(body));
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "inline refused");
	memset(&e, 0, sizeof(e));
	e.id = id(0x11);
	e.kind = FZN_CATALOG_CONTENT_NONE;
	memcpy(e.issuer, ALICE, FZN_PUBKEY_LEN);
	e.seq = 1;
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "a directory was refused");
	e = blob_entry(0x12, 0xa0, 300);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "a blob was refused");

	REQUIRE(fzn_catalog_copy_want(&cat, &seam, NOW, out, 4, &plan) == FZN_CATALOG_OK,
	        "a want list was refused");
	CHECK(plan.written == 1, "only the blob needs fetching, wanted %zu", plan.written);
	CHECK(plan.inline_ready == 1, "the inline value was not counted as already here");
	CHECK(plan.no_content == 1, "the directory was not counted as holding nothing");
	CHECK(store.asked == 1,
	      "the seam was asked about something that is not a blob -- %zu calls for one "
	      "blob",
	      store.asked);
	CLOSES(&plan, 3, plan.missing, "a mixed catalogue");
}

/* SEVERAL NODES SHARING ONE BLOB IS THE REASON TO CHOOSE A BLOB, so the want
 * list must name it once. A duplicate want costs a whole second fetch. */
static void test_a_shared_blob_is_wanted_once(void)
{
	fzn_catalog_edge_t rows[4];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_blob_t out[4];
	fzn_catalog_copy_t plan;
	fzn_catalog_t cat;
	fzn_catalog_entry_t e;

	REQUIRE(fzn_catalog_init(&cat, rows, 4, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "the content table would not init");
	REQUIRE(fzn_catalog_retain_all(&cat, 1) == FZN_CATALOG_OK, "keep-all refused");

	/* Three nodes, two of them the same bytes. */
	e = blob_entry(0x10, 0xa0, 100);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "a blob was refused");
	e = blob_entry(0x11, 0xa0, 100);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "a blob was refused");
	e = blob_entry(0x12, 0xa1, 200);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "a blob was refused");

	REQUIRE(fzn_catalog_copy_want(&cat, NULL, NOW, out, 4, &plan) == FZN_CATALOG_OK,
	        "a want list was refused");
	CHECK(plan.written == 2, "a shared blob was wanted twice: %zu written", plan.written);
	CHECK(plan.duplicates == 1, "the second reference was not counted as a duplicate");
	CLOSES(&plan, 3, plan.missing, "a shared blob");
}

/* THE SECURITY PROPERTY. An offer is scoped to the catalogue, or a want list
 * is a request for any blob whose hash a peer can name -- and a capability
 * for one catalogue silently becomes one for the whole blob store. */
static void test_an_offer_will_not_leave_the_catalogue(void)
{
	fzn_catalog_edge_t rows[4];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_blob_t out[4];
	fzn_catalog_blob_t wants[3];
	fzn_catalog_copy_t plan;
	fzn_catalog_t cat;
	fzn_catalog_entry_t e;
	/* This host holds both its own blob and a stranger's. */
	struct store store = { { 0xa0, 0xff, 0, 0, 0, 0, 0, 0 }, 2, 0 };
	fzn_catalog_holdings_ops_t seam = { store_holds, &store };

	REQUIRE(fzn_catalog_init(&cat, rows, 4, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "the content table would not init");

	e = blob_entry(0x10, 0xa0, 100);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "a blob was refused");
	e = blob_entry(0x11, 0xa1, 200);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "a blob was refused");

	memset(wants, 0, sizeof(wants));
	memset(wants[0].root, 0xa0, FZN_BLOB_HASH_LEN); /* in the catalogue, held */
	wants[0].len = 100;
	memset(wants[1].root, 0xa1, FZN_BLOB_HASH_LEN); /* in the catalogue, not held */
	wants[1].len = 200;
	memset(wants[2].root, 0xff, FZN_BLOB_HASH_LEN); /* HELD, and not this catalogue's */
	wants[2].len = 999;

	REQUIRE(fzn_catalog_copy_offer(&cat, &seam, wants, 3, out, 4, &plan) == FZN_CATALOG_OK,
	        "an offer was refused");
	CHECK(plan.written == 1, "one want is both known and held, offered %zu", plan.written);
	CHECK(out[0].root[0] == 0xa0, "the wrong blob was offered");
	CHECK(plan.unknown == 1,
	      "a want naming a blob outside this catalogue was served, so a want list is a "
	      "request for any blob whose hash a peer can name");
	CHECK(plan.missing == 1, "a known want this host lacks was not counted");
	CLOSES(&plan, 3, plan.already_held, "an offer");

	/* AND THE LENGTH IS THIS CATALOGUE'S. A peer whose number disagrees is
	 * describing a different object under the same hash. */
	memset(wants, 0, sizeof(wants));
	memset(wants[0].root, 0xa0, FZN_BLOB_HASH_LEN);
	wants[0].len = 7;
	REQUIRE(fzn_catalog_copy_offer(&cat, &seam, wants, 1, out, 4, &plan) == FZN_CATALOG_OK,
	        "an offer was refused");
	CHECK(plan.written == 1 && out[0].len == 100,
	      "the peer's length was answered rather than the catalogue's: %llu",
	      (unsigned long long)out[0].len);
}

/* A TRUNCATED WALK KEEPS WALKING, so a caller sizing its array gets the total
 * rather than the prefix that fitted. */
static void test_truncation_reports_the_whole_total(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_blob_t out[1];
	fzn_catalog_copy_t plan;
	fzn_catalog_t cat;
	fzn_catalog_entry_t e;
	size_t i;

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "the content table would not init");
	REQUIRE(fzn_catalog_retain_all(&cat, 1) == FZN_CATALOG_OK, "keep-all refused");

	for (i = 0; i < 4; i++) {
		e = blob_entry((uint8_t)(0x10 + i), (uint8_t)(0xa0 + i), 100 + i);
		REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK,
		        "a blob was refused");
	}

	REQUIRE(fzn_catalog_copy_want(&cat, NULL, NOW, out, 1, &plan) == FZN_CATALOG_OK,
	        "a truncated want list was refused, though truncation is not an error");
	CHECK(plan.written == 1, "more was written than the array holds");
	CHECK(plan.truncated == 3, "the walk stopped at the array rather than reporting the "
	                           "total: %zu truncated",
	      plan.truncated);
	CLOSES(&plan, 4, plan.missing, "a truncated want list");

	/* A CAPACITY OF ZERO IS THE SAME ANSWER WITH NOTHING WRITTEN, which is
	 * how a caller sizes an array before allocating one. */
	REQUIRE(fzn_catalog_copy_want(&cat, NULL, NOW, NULL, 0, &plan) == FZN_CATALOG_OK,
	        "a sizing pass with no array was refused");
	CHECK(plan.written == 0 && plan.truncated == 4,
	      "a sizing pass did not report the whole total: %zu written, %zu truncated",
	      plan.written, plan.truncated);
}

/* A SIZING PASS IS AN UPPER BOUND AND NOT A COUNT, pinned here so a later
 * reader does not take it for an exact figure -- and so that nobody "fixes"
 * it into one without noticing the scratch buffer that would cost.
 *
 * Deduplication compares against what has been WRITTEN, so with no room to
 * write, shared references cannot be recognised as shared. The bound is loose
 * in the safe direction: an array of `written + truncated` is certainly big
 * enough. */
static void test_a_sizing_pass_over_shared_blobs_over_counts(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_blob_t out[4];
	fzn_catalog_copy_t plan;
	fzn_catalog_t cat;
	fzn_catalog_entry_t e;
	size_t i;

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "the content table would not init");
	REQUIRE(fzn_catalog_retain_all(&cat, 1) == FZN_CATALOG_OK, "keep-all refused");

	/* Three nodes, one blob between them. */
	for (i = 0; i < 3; i++) {
		e = blob_entry((uint8_t)(0x10 + i), 0xa0, 100);
		REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK,
		        "a blob was refused");
	}

	REQUIRE(fzn_catalog_copy_want(&cat, NULL, NOW, NULL, 0, &plan) == FZN_CATALOG_OK,
	        "a sizing pass was refused");
	CHECK(plan.truncated == 3 && plan.duplicates == 0,
	      "with no room to write, references cannot be recognised as shared: %zu "
	      "truncated, %zu duplicate",
	      plan.truncated, plan.duplicates);
	CLOSES(&plan, 3, plan.missing, "a sizing pass over a shared blob");

	/* AND THE BOUND IS LOOSE IN THE SAFE DIRECTION: the array it sizes is
	 * big enough, and the walk into it reports the exact figure. */
	REQUIRE(plan.written + plan.truncated <= 4,
	        "the sizing pass asked for more than this test can allocate");
	REQUIRE(fzn_catalog_copy_want(&cat, NULL, NOW, out, plan.written + plan.truncated, &plan) ==
	                FZN_CATALOG_OK,
	        "a want list into the sized array was refused");
	CHECK(plan.written == 1 && plan.truncated == 0 && plan.duplicates == 2,
	      "the sized walk did not report the exact figure: %zu written, %zu truncated",
	      plan.written, plan.truncated);
}

/* THE FILING HAS NO PART IN THE DECISION. Where the bytes go is per-host and
 * does not decide whether to fetch them -- and a catalogue with no filing
 * root at all produces the same list. */
static void test_the_filing_does_not_change_what_is_fetched(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_blob_t before[4];
	fzn_catalog_blob_t after[4];
	fzn_catalog_copy_t plan_before;
	fzn_catalog_copy_t plan_after;
	fzn_catalog_t cat;
	fzn_catalog_entry_t e;

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "the content table would not init");
	REQUIRE(fzn_catalog_retain_all(&cat, 1) == FZN_CATALOG_OK, "keep-all refused");

	REQUIRE(fzn_catalog_assert(&cat, idp(0x01), idp(0x10), ALICE, 1, 1) == FZN_CATALOG_OK,
	        "a link was refused");
	e = blob_entry(0x10, 0xa0, 100);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "a blob was refused");

	REQUIRE(fzn_catalog_copy_want(&cat, NULL, NOW, before, 4, &plan_before) == FZN_CATALOG_OK,
	        "a want list with no filing root was refused");
	REQUIRE(fzn_catalog_filing_root(&cat, idp(0x01)) == FZN_CATALOG_OK,
	        "a filing root was refused");
	REQUIRE(fzn_catalog_copy_want(&cat, NULL, NOW, after, 4, &plan_after) == FZN_CATALOG_OK,
	        "a want list with a filing root was refused");

	CHECK(plan_before.written == plan_after.written &&
	              memcmp(before, after, sizeof(before[0]) * plan_before.written) == 0,
	      "setting a filing root changed what this host fetches, so a per-host "
	      "arrangement is deciding a copy");
}

/* A REFILING CATALOGUE ANSWERS PROGRESS AND NOTHING ELSE. sec 149, and the
 * copy layer is bound by it like everything else -- a want list computed
 * mid-refile would be honest about the bytes and useless about where they go.
 */
static void test_a_refile_holds_the_copy_layer_too(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_blob_t out[4];
	fzn_catalog_blob_t wants[1];
	fzn_catalog_copy_t plan;
	fzn_catalog_t cat;
	fzn_catalog_entry_t e;

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "the content table would not init");
	REQUIRE(fzn_catalog_retain_all(&cat, 1) == FZN_CATALOG_OK, "keep-all refused");
	e = blob_entry(0x10, 0xa0, 100);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "a blob was refused");

	/* Reach through the flag rather than driving a whole refile: what is
	 * under test is that the copy layer honours the hold, not that a
	 * refile sets it -- catalog_test.c already covers the second. */
	cat.busy_with = FZN_CATALOG_JOB_REFILE;
	CHECK(fzn_catalog_copy_want(&cat, NULL, NOW, out, 4, &plan) == FZN_CATALOG_ERR_BUSY,
	      "a want list was computed while a refile held the catalogue");
	CHECK(fzn_catalog_copy_holdings(&cat, NULL, out, 4, &plan) == FZN_CATALOG_ERR_BUSY,
	      "a holdings announcement was made while a refile held the catalogue");
	memset(wants, 0, sizeof(wants));
	CHECK(fzn_catalog_copy_offer(&cat, NULL, wants, 1, out, 4, &plan) ==
	              FZN_CATALOG_ERR_BUSY,
	      "an offer was served while a refile held the catalogue");
	cat.busy_with = FZN_CATALOG_JOB_NONE;

	/* AND A SWEEP HOLDS IT JUST AS A REFILE DOES. sec 155 made the field a
	 * kind; the copy layer reads only whether anybody holds it, and a want
	 * list computed mid-sweep would ask for bytes being deleted as it is
	 * written. */
	cat.busy_with = FZN_CATALOG_JOB_SWEEP;
	CHECK(fzn_catalog_copy_want(&cat, NULL, NOW, out, 4, &plan) == FZN_CATALOG_ERR_BUSY,
	      "a want list was computed while a sweep held the catalogue");
	CHECK(fzn_catalog_copy_offer(&cat, NULL, wants, 1, out, 4, &plan) ==
	              FZN_CATALOG_ERR_BUSY,
	      "an offer was served while a sweep held the catalogue");
	cat.busy_with = FZN_CATALOG_JOB_NONE;
}

/* A PLAN IS ZEROED BEFORE THE ARGUMENTS ARE CHECKED, so a caller that reads
 * the counters after a refusal does not read the previous round's. */
static void test_a_refused_walk_leaves_no_stale_numbers(void)
{
	fzn_catalog_edge_t rows[4];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_blob_t out[4];
	fzn_catalog_copy_t plan;
	fzn_catalog_t cat;
	fzn_catalog_entry_t e;

	REQUIRE(fzn_catalog_init(&cat, rows, 4, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "the content table would not init");
	REQUIRE(fzn_catalog_retain_all(&cat, 1) == FZN_CATALOG_OK, "keep-all refused");
	e = blob_entry(0x10, 0xa0, 100);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "a blob was refused");

	REQUIRE(fzn_catalog_copy_want(&cat, NULL, NOW, out, 4, &plan) == FZN_CATALOG_OK,
	        "a want list was refused");
	REQUIRE(plan.written == 1, "the first walk found nothing to carry into the second");

	CHECK(fzn_catalog_copy_want(NULL, NULL, NOW, out, 4, &plan) == FZN_CATALOG_ERR_MALFORMED,
	      "a null catalogue was accepted");
	CHECK(plan.written == 0,
	      "a refused walk left the previous round's count, so a caller reading the plan "
	      "after an error reads a number about something else");

	CHECK(fzn_catalog_copy_want(&cat, NULL, NOW, NULL, 4, &plan) == FZN_CATALOG_ERR_MALFORMED,
	      "a null array with a nonzero capacity was accepted");
	CHECK(fzn_catalog_copy_want(&cat, NULL, NOW, out, 4, NULL) == FZN_CATALOG_ERR_MALFORMED,
	      "nowhere to answer");
	CHECK(fzn_catalog_copy_offer(&cat, NULL, NULL, 1, out, 4, &plan) ==
	              FZN_CATALOG_ERR_MALFORMED,
	      "a null want list with a nonzero count was accepted");
}

/* A SEAM THAT CANNOT ANSWER SAYS NO, and the consequence is a redundant fetch
 * rather than a host advertising bytes it cannot serve. The half-filled ops
 * struct is the case a consumer actually produces. */
static void test_a_seam_that_cannot_answer_is_not_a_holding(void)
{
	fzn_catalog_edge_t rows[4];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_blob_t out[4];
	fzn_catalog_copy_t plan;
	fzn_catalog_t cat;
	fzn_catalog_entry_t e;
	fzn_catalog_holdings_ops_t empty = { NULL, NULL };

	REQUIRE(fzn_catalog_init(&cat, rows, 4, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "the content table would not init");
	REQUIRE(fzn_catalog_retain_all(&cat, 1) == FZN_CATALOG_OK, "keep-all refused");
	e = blob_entry(0x10, 0xa0, 100);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "a blob was refused");

	REQUIRE(fzn_catalog_copy_want(&cat, &empty, NOW, out, 4, &plan) == FZN_CATALOG_OK,
	        "an ops struct with no callback was refused");
	CHECK(plan.written == 1 && plan.already_held == 0,
	      "a seam with no callback was read as holding the bytes, which makes a host "
	      "advertise what it cannot serve");

	REQUIRE(fzn_catalog_copy_holdings(&cat, &empty, out, 4, &plan) == FZN_CATALOG_OK,
	        "a holdings announcement with no callback was refused");
	CHECK(plan.written == 0, "a host with no way to answer announced %zu blobs",
	      plan.written);
}

/* A CATALOGUE THAT KEEPS NOTHING UNTIL TOLD wants nothing. sec 152 chose that
 * default so adopting a stranger's catalogue does not start filling a disk;
 * this is what that costs a consumer that forgets to say. */
static void test_a_catalogue_keeps_nothing_until_told(void)
{
	fzn_catalog_edge_t rows[4];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_blob_t out[4];
	fzn_catalog_copy_t plan;
	fzn_catalog_t cat;
	fzn_catalog_entry_t e;

	REQUIRE(fzn_catalog_init(&cat, rows, 4, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "the content table would not init");

	e = blob_entry(0x10, 0xa0, 100);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "a blob was refused");

	REQUIRE(fzn_catalog_copy_want(&cat, NULL, NOW, out, 4, &plan) == FZN_CATALOG_OK,
	        "a want list was refused");
	CHECK(plan.written == 0 && plan.not_retained == 1,
	      "a catalogue nobody has set a retention on wanted %zu blobs", plan.written);
	CLOSES(&plan, 1, plan.missing, "a catalogue told to keep nothing");
}

int main(void)
{
	memset(ALICE, 0xa1, sizeof(ALICE));

	test_a_fresh_host_wants_everything_it_keeps();
	test_holdings_follow_the_bytes_and_not_the_policy();
	test_only_blobs_are_fetched();
	test_a_shared_blob_is_wanted_once();
	test_an_offer_will_not_leave_the_catalogue();
	test_truncation_reports_the_whole_total();
	test_a_sizing_pass_over_shared_blobs_over_counts();
	test_the_filing_does_not_change_what_is_fetched();
	test_a_refile_holds_the_copy_layer_too();
	test_a_refused_walk_leaves_no_stale_numbers();
	test_a_seam_that_cannot_answer_is_not_a_holding();
	test_a_catalogue_keeps_nothing_until_told();

	printf("copy_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
