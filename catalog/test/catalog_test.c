/* Tests for catalog/catalog.c: membership, and the two things it is for.
 *
 * THE CASES THIS FILE EXISTS FOR are the two properties the copyright holder
 * named as the point of the design -- that a node may be a member of several
 * sets at once, and that several sets can be combined as search terms -- plus
 * the one that makes those safe to sync: a removal must stick when a stale
 * link arrives afterwards. project.md sec 144.
 *
 * The resolver is a seam, so most of these drive it deliberately rather than
 * through the default: a strategy that is only ever exercised by the one
 * shipped with it has not been shown to be a seam at all.
 */

#include "../catalog.h"

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
	fprintf(stderr, "  FAIL catalog_test.c:%d: ", line);
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

static fzn_catalog_id_t id(uint8_t seed)
{
	fzn_catalog_id_t out;

	memset(out.b, seed, sizeof(out.b));
	return out;
}

/* The same id, as a pointer, for the calls that take one. A small rotating
 * set rather than one static, so two `idp` calls in one expression do not
 * hand back the same buffer -- which would make an argument pair compare
 * equal and quietly change what a case tests. */
static const fzn_catalog_id_t *idp(uint8_t seed)
{
	static fzn_catalog_id_t slots[4];
	static size_t at;

	slots[at] = id(seed);
	at = (at + 1u) % 4u;
	return &slots[(at + 3u) % 4u];
}

static uint8_t ALICE[FZN_PUBKEY_LEN];
static uint8_t BOB[FZN_PUBKEY_LEN];

static const fzn_catalog_resolve_ops_t ADD_WINS = { fzn_catalog_add_wins, NULL };

/* A resolver that always keeps what it holds, so the seam can be shown to be
 * one: if the module ignored `resolve` and compared for itself, this would
 * make no difference and every case below would still pass. */
static int keep_held(void *ctx, const fzn_catalog_edge_t *held,
                     const fzn_catalog_edge_t *offered)
{
	(void)ctx;
	(void)held;
	(void)offered;
	return 0;
}

static const fzn_catalog_resolve_ops_t KEEP_HELD = { keep_held, NULL };

/* ---- the cases --------------------------------------------------------- */

static void test_a_node_belongs_to_several_sets(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_t cat;
	fzn_catalog_id_t out[4];
	fzn_catalog_id_t film = id(0x10);
	fzn_catalog_id_t noir = id(0x20);
	fzn_catalog_id_t nineteen_forties = id(0x21);
	size_t n;

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	CHECK(fzn_catalog_assert(&cat, &noir, &film, ALICE, 1, 1) == FZN_CATALOG_OK,
	      "the first membership was refused");
	CHECK(fzn_catalog_assert(&cat, &nineteen_forties, &film, ALICE, 2, 1) == FZN_CATALOG_OK,
	      "the second membership was refused");

	CHECK(fzn_catalog_linked(&cat, &noir, &film), "the node is not in the first set");
	CHECK(fzn_catalog_linked(&cat, &nineteen_forties, &film),
	      "the node is not in the second set");

	/* THE PROPERTY THE DESIGN EXISTS FOR: a node names its sets, plural,
	 * and nothing had to move for the second one. */
	n = fzn_catalog_parents(&cat, &film, out, 4);
	CHECK(n == 2, "a node in two sets reported %zu parent(s)", n);
}

static void test_sets_combine_as_search_terms(void)
{
	fzn_catalog_edge_t rows[16];
	fzn_catalog_t cat;
	fzn_catalog_id_t out[8];
	fzn_catalog_id_t noir = id(0x20);
	fzn_catalog_id_t forties = id(0x21);
	fzn_catalog_id_t both = id(0x10);
	fzn_catalog_id_t noir_only = id(0x11);
	fzn_catalog_id_t forties_only = id(0x12);
	fzn_catalog_id_t terms[2];
	size_t n;

	REQUIRE(fzn_catalog_init(&cat, rows, 16, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_assert(&cat, &noir, &both, ALICE, 1, 1) == FZN_CATALOG_OK, "a");
	REQUIRE(fzn_catalog_assert(&cat, &forties, &both, ALICE, 2, 1) == FZN_CATALOG_OK, "b");
	REQUIRE(fzn_catalog_assert(&cat, &noir, &noir_only, ALICE, 3, 1) == FZN_CATALOG_OK, "c");
	REQUIRE(fzn_catalog_assert(&cat, &forties, &forties_only, ALICE, 4, 1) == FZN_CATALOG_OK,
	        "d");

	terms[0] = noir;
	terms[1] = forties;
	n = fzn_catalog_intersect(&cat, terms, 2, out, 8);
	CHECK(n == 1, "combining two sets gave %zu result(s), wanted the one in both", n);
	CHECK(n == 1 && memcmp(out[0].b, both.b, FZN_CATALOG_ID_LEN) == 0,
	      "the result is not the node that is in both");

	/* THE CONTROL: each term alone holds two, so the intersection above is
	 * narrowing rather than a query that always answers one. */
	CHECK(fzn_catalog_members(&cat, &noir, out, 8) == 2, "the first term does not hold two");
	CHECK(fzn_catalog_members(&cat, &forties, out, 8) == 2,
	      "the second term does not hold two");

	/* One term is just its members; no terms is not everything. */
	CHECK(fzn_catalog_intersect(&cat, terms, 1, out, 8) == 2,
	      "one term did not answer that term's members");
	CHECK(fzn_catalog_intersect(&cat, terms, 0, out, 8) == 0,
	      "no terms answered something, so an unchosen query returns the world");
}

/*
 * A REMOVAL MUST STICK. An edge deleted from the table would be created
 * afresh by any stale link arriving afterwards, so a removal would undo
 * itself on the next sync. The tombstone is what stops that, and this is the
 * case that would pass if the row were dropped instead.
 */
static void test_a_removal_survives_a_stale_link(void)
{
	fzn_catalog_edge_t rows[4];
	fzn_catalog_t cat;
	fzn_catalog_id_t set = id(0x20);
	fzn_catalog_id_t node = id(0x10);

	/* UNDER THE DEFAULT RESOLVER, not one that keeps whatever it holds --
	 * a keep-held resolver makes this case pass whether or not the
	 * tombstone was stored, which is the fixture answering instead of the
	 * code. Here the stale link loses on its own sequence, and it can only
	 * lose to a row that exists. */
	REQUIRE(fzn_catalog_init(&cat, rows, 4, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_assert(&cat, &set, &node, ALICE, 5, 0) == FZN_CATALOG_OK,
	        "an unlink for an edge never held was refused");
	CHECK(cat.used == 1, "the unlink was not stored, so nothing can meet a stale link");
	CHECK(!fzn_catalog_linked(&cat, &set, &node), "the unlink did not take");

	/* The stale link loses, and the caller is told it lost. */
	CHECK(fzn_catalog_assert(&cat, &set, &node, ALICE, 1, 1) == FZN_CATALOG_ERR_STALE,
	      "a stale link was accepted over a removal");
	CHECK(!fzn_catalog_linked(&cat, &set, &node), "the stale link resurrected the edge");

	/* And a tombstone is tellable from silence, which is what the accessor
	 * is for: linked() says no to both, edge_of() separates them. */
	CHECK(fzn_catalog_edge_of(&cat, &set, &node) != NULL,
	      "a removal is indistinguishable from never having been said");
	CHECK(fzn_catalog_edge_of(&cat, &set, idp(0x99)) == NULL,
	      "an edge nobody asserted reports itself as a tombstone");
}

/* The resolver is consulted rather than reimplemented. With a resolver that
 * keeps what it holds, an add that would win under the default must lose. */
static void test_the_resolver_is_a_seam(void)
{
	fzn_catalog_edge_t rows[4];
	fzn_catalog_t cat;
	fzn_catalog_id_t set = id(0x20);
	fzn_catalog_id_t node = id(0x10);

	REQUIRE(fzn_catalog_init(&cat, rows, 4, &KEEP_HELD) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_assert(&cat, &set, &node, ALICE, 1, 0) == FZN_CATALOG_OK, "unlink");
	CHECK(fzn_catalog_assert(&cat, &set, &node, ALICE, 9, 1) == FZN_CATALOG_ERR_STALE,
	      "a later add won under a resolver that keeps what it holds");
	CHECK(!fzn_catalog_linked(&cat, &set, &node), "and it took effect anyway");

	/* THE CONTROL: the same sequence under add-wins goes the other way, so
	 * the case above is the resolver rather than the module refusing. */
	REQUIRE(fzn_catalog_init(&cat, rows, 4, &ADD_WINS) == FZN_CATALOG_OK, "re-init refused");
	REQUIRE(fzn_catalog_assert(&cat, &set, &node, ALICE, 1, 0) == FZN_CATALOG_OK, "unlink");
	CHECK(fzn_catalog_assert(&cat, &set, &node, ALICE, 9, 1) == FZN_CATALOG_OK,
	      "add-wins refused an add over a removal");
	CHECK(fzn_catalog_linked(&cat, &set, &node), "add-wins did not take effect");
}

/* Adds commute, which is what makes most of a catalogue conflict-free. */
static void test_two_hosts_adding_agree_without_talking(void)
{
	fzn_catalog_edge_t rows_a[4], rows_b[4];
	fzn_catalog_t a, b;
	fzn_catalog_id_t set = id(0x20);
	fzn_catalog_id_t node = id(0x10);

	REQUIRE(fzn_catalog_init(&a, rows_a, 4, &ADD_WINS) == FZN_CATALOG_OK, "a init");
	REQUIRE(fzn_catalog_init(&b, rows_b, 4, &ADD_WINS) == FZN_CATALOG_OK, "b init");

	/* The same two assertions, in opposite orders. */
	REQUIRE(fzn_catalog_assert(&a, &set, &node, ALICE, 1, 1) == FZN_CATALOG_OK, "a1");
	(void)fzn_catalog_assert(&a, &set, &node, BOB, 1, 1);
	REQUIRE(fzn_catalog_assert(&b, &set, &node, BOB, 1, 1) == FZN_CATALOG_OK, "b1");
	(void)fzn_catalog_assert(&b, &set, &node, ALICE, 1, 1);

	CHECK(fzn_catalog_linked(&a, &set, &node) == fzn_catalog_linked(&b, &set, &node),
	      "two hosts given the same adds in different orders disagree");
	CHECK(fzn_catalog_linked(&a, &set, &node), "and neither holds the member");
}

/* A full catalogue refuses loudly rather than dropping the oldest, which is
 * the difference between this and a log. */
static void test_a_full_catalogue_refuses_rather_than_evicts(void)
{
	fzn_catalog_edge_t rows[2];
	fzn_catalog_t cat;
	fzn_catalog_id_t set = id(0x20);

	REQUIRE(fzn_catalog_init(&cat, rows, 2, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_assert(&cat, &set, idp(0x01), ALICE, 1, 1) == FZN_CATALOG_OK, "one");
	REQUIRE(fzn_catalog_assert(&cat, &set, idp(0x02), ALICE, 2, 1) == FZN_CATALOG_OK, "two");
	CHECK(fzn_catalog_assert(&cat, &set, idp(0x03), ALICE, 3, 1) == FZN_CATALOG_ERR_FULL,
	      "a full catalogue accepted a third edge");
	/* AND THE FIRST IS STILL THERE. A catalogue that made room by dropping
	 * would report success and lose a member silently. */
	CHECK(fzn_catalog_linked(&cat, &set, idp(0x01)),
	      "the oldest member was evicted to make room");
	CHECK(cat.used == 2, "the table grew past its capacity");
}

static void test_the_caller_bugs_are_refused(void)
{
	fzn_catalog_edge_t rows[4];
	fzn_catalog_t cat;
	fzn_catalog_id_t out[2];
	fzn_catalog_id_t a = id(0x20);
	fzn_catalog_id_t b = id(0x10);

	CHECK(fzn_catalog_init(NULL, rows, 4, &ADD_WINS) == FZN_CATALOG_ERR_MALFORMED,
	      "a null catalogue was accepted");
	CHECK(fzn_catalog_init(&cat, NULL, 4, &ADD_WINS) == FZN_CATALOG_ERR_MALFORMED,
	      "null rows were accepted");
	CHECK(fzn_catalog_init(&cat, rows, 0, &ADD_WINS) == FZN_CATALOG_ERR_MALFORMED,
	      "a catalogue that can hold nothing was accepted");
	CHECK(fzn_catalog_init(&cat, rows, 4, NULL) == FZN_CATALOG_ERR_MALFORMED,
	      "a catalogue with no resolver was accepted");

	REQUIRE(fzn_catalog_init(&cat, rows, 4, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	/* A set cannot contain itself: listing it among its own members is
	 * wrong in a way a caller cannot tell from a genuine member. */
	CHECK(fzn_catalog_assert(&cat, &a, &a, ALICE, 1, 1) == FZN_CATALOG_ERR_MALFORMED,
	      "a set was made a member of itself");
	CHECK(fzn_catalog_assert(NULL, &a, &b, ALICE, 1, 1) == FZN_CATALOG_ERR_MALFORMED,
	      "a null catalogue accepted an assertion");
	CHECK(fzn_catalog_assert(&cat, NULL, &b, ALICE, 1, 1) == FZN_CATALOG_ERR_MALFORMED,
	      "a null parent");
	CHECK(fzn_catalog_assert(&cat, &a, NULL, ALICE, 1, 1) == FZN_CATALOG_ERR_MALFORMED,
	      "a null child");
	CHECK(fzn_catalog_assert(&cat, &a, &b, NULL, 1, 1) == FZN_CATALOG_ERR_MALFORMED,
	      "a null issuer");
	CHECK(!fzn_catalog_linked(NULL, &a, &b), "a null catalogue reported a membership");
	CHECK(fzn_catalog_members(NULL, &a, out, 2) == 0, "a null catalogue listed members");
	CHECK(fzn_catalog_parents(NULL, &b, out, 2) == 0, "a null catalogue listed parents");
	CHECK(fzn_catalog_intersect(NULL, &a, 1, out, 2) == 0, "a null catalogue intersected");
	CHECK(cat.used == 0, "a refused assertion was stored");
}

/* A listing bounded by the caller stops at the bound rather than writing
 * past it, and says how many it wrote. */
static void test_a_listing_respects_its_bound(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_t cat;
	fzn_catalog_id_t out[2];
	fzn_catalog_id_t set = id(0x20);
	uint8_t i;

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	for (i = 1; i <= 4; i++)
		REQUIRE(fzn_catalog_assert(&cat, &set, idp(i), ALICE, i, 1) == FZN_CATALOG_OK,
		        "a member was refused");

	CHECK(fzn_catalog_members(&cat, &set, out, 2) == 2,
	      "a bounded listing did not stop at its bound");
	CHECK(fzn_catalog_members(&cat, &set, out, 0) == 0, "a zero bound wrote something");
}

/* An unlinked member disappears from listings while its row stays. */
static void test_an_unlinked_member_leaves_the_listings(void)
{
	fzn_catalog_edge_t rows[4];
	fzn_catalog_t cat;
	fzn_catalog_id_t out[4];
	fzn_catalog_id_t set = id(0x20);
	fzn_catalog_id_t node = id(0x10);
	fzn_catalog_id_t terms[1];

	REQUIRE(fzn_catalog_init(&cat, rows, 4, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_assert(&cat, &set, &node, ALICE, 1, 1) == FZN_CATALOG_OK, "link");
	CHECK(fzn_catalog_members(&cat, &set, out, 4) == 1, "the member is not listed");

	REQUIRE(fzn_catalog_assert(&cat, &set, &node, ALICE, 2, 0) == FZN_CATALOG_OK, "unlink");
	CHECK(fzn_catalog_members(&cat, &set, out, 4) == 0, "an unlinked member is still listed");
	CHECK(fzn_catalog_parents(&cat, &node, out, 4) == 0,
	      "an unlinked member still names its set");
	terms[0] = set;
	CHECK(fzn_catalog_intersect(&cat, terms, 1, out, 4) == 0,
	      "an unlinked member is still a search result");
	CHECK(cat.used == 1, "the tombstone was dropped");
}

/* ---- what a node holds -------------------------------------------------- */

static const fzn_catalog_content_ops_t HELD_WINS = { fzn_catalog_content_held_wins, NULL };

/* A content resolver that always takes the offered one, so this seam is shown
 * to be one: if the module compared for itself, this would change nothing. */
static int take_offered(void *ctx, const fzn_catalog_entry_t *held,
                        const fzn_catalog_entry_t *offered)
{
	(void)ctx;
	(void)held;
	(void)offered;
	return 1;
}

static const fzn_catalog_content_ops_t TAKE_OFFERED = { take_offered, NULL };

static fzn_catalog_entry_t inline_entry(uint8_t seed, const uint8_t *bytes, size_t len,
                                        const uint8_t *issuer, uint64_t seq)
{
	fzn_catalog_entry_t e;

	memset(&e, 0, sizeof(e));
	e.id = id(seed);
	e.kind = FZN_CATALOG_CONTENT_INLINE;
	e.bytes = bytes;
	e.len = len;
	memcpy(e.issuer, issuer, FZN_PUBKEY_LEN);
	e.seq = seq;
	return e;
}

static fzn_catalog_entry_t blob_entry(uint8_t seed, uint8_t root_seed, uint64_t blob_len,
                                      const uint8_t *issuer, uint64_t seq)
{
	fzn_catalog_entry_t e;

	memset(&e, 0, sizeof(e));
	e.id = id(seed);
	e.kind = FZN_CATALOG_CONTENT_BLOB;
	memset(e.root, root_seed, sizeof(e.root));
	e.blob_len = blob_len;
	memcpy(e.issuer, issuer, FZN_PUBKEY_LEN);
	e.seq = seq;
	return e;
}

/* ONE MECHANISM, THREE ANSWERS. sec 145: a blob reference is content and must
 * be signed and synced like any other, so the record layer is required either
 * way and only the payload differs. */
static void test_a_node_holds_bytes_or_a_blob_or_nothing(void)
{
	fzn_catalog_edge_t rows[4];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_t cat;
	const uint8_t body[4] = { 1, 2, 3, 4 };
	fzn_catalog_entry_t e;
	const fzn_catalog_entry_t *got;

	REQUIRE(fzn_catalog_init(&cat, rows, 4, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "the content table would not init");

	e = inline_entry(0x10, body, sizeof(body), ALICE, 1);
	CHECK(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "inline bytes were refused");
	got = fzn_catalog_content_of(&cat, idp(0x10));
	REQUIRE(got != NULL, "the inline entry was not held");
	CHECK(got->kind == FZN_CATALOG_CONTENT_INLINE, "the kind did not survive");
	CHECK(got->len == 4 && got->bytes == body, "the bytes did not survive");

	e = blob_entry(0x11, 0xbb, 1u << 20, ALICE, 1);
	CHECK(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "a blob was refused");
	got = fzn_catalog_content_of(&cat, idp(0x11));
	REQUIRE(got != NULL, "the blob entry was not held");
	CHECK(got->kind == FZN_CATALOG_CONTENT_BLOB, "the blob kind did not survive");
	/* THE LENGTH IS WHY A CONSUMER CAN DECIDE BEFORE FETCHING. */
	CHECK(got->blob_len == (1u << 20), "the blob length did not survive");

	memset(&e, 0, sizeof(e));
	e.id = id(0x12);
	e.kind = FZN_CATALOG_CONTENT_NONE;
	memcpy(e.issuer, ALICE, FZN_PUBKEY_LEN);
	e.seq = 1;
	CHECK(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK,
	      "a node holding nothing was refused, though a directory is exactly that");
}

/* A PURE SET IS NOT AN ERROR AND NOT AN ABSENCE. Most of a catalogue's
 * structure is nodes with members and no bytes. */
static void test_a_directory_has_members_and_no_content(void)
{
	fzn_catalog_edge_t rows[4];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_t cat;
	fzn_catalog_id_t out[4];

	REQUIRE(fzn_catalog_init(&cat, rows, 4, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "content init refused");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x20), idp(0x10), ALICE, 1, 1) == FZN_CATALOG_OK,
	        "the membership was refused");

	CHECK(fzn_catalog_members(&cat, idp(0x20), out, 4) == 1, "the set has no members");
	CHECK(fzn_catalog_content_of(&cat, idp(0x20)) == NULL,
	      "a set nobody gave content reports some");
}

/*
 * AN ID IS A NAME, NOT A DIGEST, and this is the case that shows why. sec 145
 * corrects the header's first claim: if a node's id were its content digest,
 * editing the content would change the id and every edge pointing at it would
 * break. A catalogue asked to be easy to edit cannot have that.
 */
static void test_content_changes_and_the_edges_survive(void)
{
	fzn_catalog_edge_t rows[4];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_t cat;
	fzn_catalog_id_t out[4];
	const uint8_t first[2] = { 9, 9 };
	const uint8_t second[3] = { 7, 7, 7 };
	fzn_catalog_entry_t e;
	const fzn_catalog_entry_t *got;

	REQUIRE(fzn_catalog_init(&cat, rows, 4, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "content init refused");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x20), idp(0x10), ALICE, 1, 1) == FZN_CATALOG_OK,
	        "the membership was refused");
	e = inline_entry(0x10, first, sizeof(first), ALICE, 1);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "the first content");

	/* Edit it. Same node, later statement from the same issuer. */
	e = inline_entry(0x10, second, sizeof(second), ALICE, 2);
	CHECK(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK,
	      "an issuer could not edit its own content");
	got = fzn_catalog_content_of(&cat, idp(0x10));
	REQUIRE(got != NULL, "the entry vanished");
	CHECK(got->len == 3 && got->bytes == second, "the edit did not take");

	/* THE POINT: the membership is untouched, because the name did not
	 * move. Under a content-addressed id this edge would now point at a
	 * node that no longer exists. */
	CHECK(fzn_catalog_members(&cat, idp(0x20), out, 4) == 1,
	      "editing a node's content broke the edge pointing at it");
	CHECK(fzn_catalog_linked(&cat, idp(0x20), idp(0x10)),
	      "the node lost its membership when its content changed");
}

/* A kind may change: a value that outgrows a record body becomes a blob, and
 * nothing about the node's identity or its memberships moves. */
static void test_an_entry_may_grow_from_inline_to_blob(void)
{
	fzn_catalog_edge_t rows[4];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_t cat;
	const uint8_t small[2] = { 1, 2 };
	fzn_catalog_entry_t e;
	const fzn_catalog_entry_t *got;

	REQUIRE(fzn_catalog_init(&cat, rows, 4, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "content init refused");
	e = inline_entry(0x10, small, sizeof(small), ALICE, 1);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "inline refused");

	e = blob_entry(0x10, 0xcc, 4096, ALICE, 2);
	CHECK(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK,
	      "a node could not grow from inline bytes to a blob");
	got = fzn_catalog_content_of(&cat, idp(0x10));
	REQUIRE(got != NULL, "the entry vanished");
	CHECK(got->kind == FZN_CATALOG_CONTENT_BLOB, "the kind did not change");
	CHECK(got->len == 0, "the old inline length survived into a blob entry");
}

static void test_the_content_resolver_is_a_seam(void)
{
	fzn_catalog_edge_t rows[4];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_t cat;
	const uint8_t body[1] = { 1 };
	fzn_catalog_entry_t e;

	/* Under held-wins, a second issuer loses. */
	REQUIRE(fzn_catalog_init(&cat, rows, 4, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "content init refused");
	e = inline_entry(0x10, body, 1, ALICE, 1);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "alice");
	e = inline_entry(0x10, body, 1, BOB, 99);
	CHECK(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_ERR_STALE,
	      "another issuer's content displaced what was held");

	/* And with a resolver that takes whatever is offered, it wins -- so the
	 * case above is the seam rather than the module deciding. */
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &TAKE_OFFERED) == FZN_CATALOG_OK,
	        "re-init refused");
	e = inline_entry(0x10, body, 1, ALICE, 1);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "alice again");
	e = inline_entry(0x10, body, 1, BOB, 99);
	CHECK(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK,
	      "a resolver that takes the offered one did not");
}

static void test_the_content_caller_bugs_are_refused(void)
{
	fzn_catalog_edge_t rows[4];
	fzn_catalog_entry_t entries[2];
	fzn_catalog_t cat;
	const uint8_t body[1] = { 1 };
	fzn_catalog_entry_t e;

	REQUIRE(fzn_catalog_init(&cat, rows, 4, &ADD_WINS) == FZN_CATALOG_OK, "init refused");

	/* A CATALOGUE WITH NO CONTENT TABLE REFUSES rather than appearing to
	 * accept and doing nothing -- a consumer using this as structure only
	 * pays for no table and gets no silence either. */
	e = inline_entry(0x10, body, 1, ALICE, 1);
	CHECK(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_ERR_MALFORMED,
	      "a catalogue with no content table accepted content");
	CHECK(fzn_catalog_content_of(&cat, idp(0x10)) == NULL,
	      "a catalogue with no content table answered a lookup");

	CHECK(fzn_catalog_content_init(NULL, entries, 2, &HELD_WINS) == FZN_CATALOG_ERR_MALFORMED,
	      "a null catalogue");
	CHECK(fzn_catalog_content_init(&cat, NULL, 2, &HELD_WINS) == FZN_CATALOG_ERR_MALFORMED,
	      "null rows");
	CHECK(fzn_catalog_content_init(&cat, entries, 0, &HELD_WINS) == FZN_CATALOG_ERR_MALFORMED,
	      "a table that can hold nothing");
	CHECK(fzn_catalog_content_init(&cat, entries, 2, NULL) == FZN_CATALOG_ERR_MALFORMED,
	      "no resolver");

	REQUIRE(fzn_catalog_content_init(&cat, entries, 2, &HELD_WINS) == FZN_CATALOG_OK,
	        "content init refused");
	CHECK(fzn_catalog_content_set(&cat, NULL) == FZN_CATALOG_ERR_MALFORMED, "a null entry");

	/* An inline past what a record body carries is a caller describing
	 * something it could never send. */
	e = inline_entry(0x10, body, FZN_RECORD_BODY_MAX + 1u, ALICE, 1);
	CHECK(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_ERR_MALFORMED,
	      "an inline past a record body was accepted");
	e = inline_entry(0x10, body, FZN_RECORD_BODY_MAX, ALICE, 1);
	CHECK(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK,
	      "an inline exactly at the bound was refused");

	e = inline_entry(0x11, NULL, 4, ALICE, 1);
	CHECK(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_ERR_MALFORMED,
	      "a length with no bytes was accepted");
	/* An empty value IS expressible, which is why a zero-length blob is a
	 * half-filled row rather than an empty one. */
	e = inline_entry(0x11, NULL, 0, ALICE, 1);
	CHECK(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK,
	      "an empty inline value was refused, though a value can be empty");
	e = blob_entry(0x12, 0xbb, 0, ALICE, 1);
	CHECK(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_ERR_MALFORMED,
	      "a blob naming nothing was accepted");

	memset(&e, 0, sizeof(e));
	e.id = id(0x13);
	e.kind = (fzn_catalog_content_t)99;
	memcpy(e.issuer, ALICE, FZN_PUBKEY_LEN);
	CHECK(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_ERR_MALFORMED,
	      "a kind that is none of the three was accepted");

	/* Full refuses loudly here too. */
	e = inline_entry(0x14, body, 1, ALICE, 1);
	CHECK(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_ERR_FULL,
	      "a full content table accepted another entry");
}

static void test_the_kinds_render(void)
{
	const char *n = fzn_catalog_content_str(FZN_CATALOG_CONTENT_NONE);
	const char *i = fzn_catalog_content_str(FZN_CATALOG_CONTENT_INLINE);
	const char *b = fzn_catalog_content_str(FZN_CATALOG_CONTENT_BLOB);

	CHECK(n && i && b && *n && *i && *b, "a kind rendered empty or null");
	CHECK(strcmp(n, i) != 0 && strcmp(i, b) != 0 && strcmp(n, b) != 0,
	      "two kinds read alike");
	CHECK(fzn_catalog_content_str((fzn_catalog_content_t)99)[0] != '\0',
	      "an unknown kind renders empty");
}

static void test_the_errors_render(void)
{
	CHECK(fzn_catalog_err_str(FZN_CATALOG_OK)[0] != '\0', "OK renders empty");
	CHECK(fzn_catalog_err_str(FZN_CATALOG_ERR_MALFORMED)[0] != '\0', "MALFORMED renders empty");
	CHECK(fzn_catalog_err_str(FZN_CATALOG_ERR_FULL)[0] != '\0', "FULL renders empty");
	CHECK(fzn_catalog_err_str(FZN_CATALOG_ERR_STALE)[0] != '\0', "STALE renders empty");
	CHECK(fzn_catalog_err_str((fzn_catalog_err_t)-99)[0] != '\0',
	      "an unknown error renders empty");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	check_at(0, __LINE__, "deliberate");
	CHECK(failures == before + 1, "a failing check did not count");
	failures = before;
	checks -= 1;
}

int main(void)
{
	memset(ALICE, 0xa1, sizeof(ALICE));
	memset(BOB, 0xb0, sizeof(BOB));

	test_a_node_belongs_to_several_sets();
	test_sets_combine_as_search_terms();
	test_a_removal_survives_a_stale_link();
	test_the_resolver_is_a_seam();
	test_two_hosts_adding_agree_without_talking();
	test_a_full_catalogue_refuses_rather_than_evicts();
	test_the_caller_bugs_are_refused();
	test_a_listing_respects_its_bound();
	test_an_unlinked_member_leaves_the_listings();
	test_a_node_holds_bytes_or_a_blob_or_nothing();
	test_a_directory_has_members_and_no_content();
	test_content_changes_and_the_edges_survive();
	test_an_entry_may_grow_from_inline_to_blob();
	test_the_content_resolver_is_a_seam();
	test_the_content_caller_bugs_are_refused();
	test_the_kinds_render();
	test_the_errors_render();
	test_the_suite_can_tell_pass_from_fail();

	printf("catalog_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
