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

/* ---- a signer, so the wire cases run against real records --------------- */

static void tag(uint8_t out[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	uint64_t h = 1469598103934665603u;
	size_t i;

	for (i = 0; i < msg_len; i++) {
		h ^= msg[i];
		h *= 1099511628211u;
	}
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h ^= (uint64_t)i;
		h *= 1099511628211u;
		out[i] = (uint8_t)(h >> 32);
	}
}

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	(void)ctx;
	tag(sig, msg, msg_len);
	return 1;
}

static uint8_t RECORD_SLOT[FZN_RECORD_MAX_LEN];
static uint8_t SUBJECT[FZN_SUBJECT_LEN];

/* Wrap a body in a record signed by `issuer` at `seq`. */
static int as_record(fzn_record_t *out, const uint8_t *issuer, uint64_t seq,
                     const uint8_t *body, size_t body_len)
{
	fzn_sign_ops_t ops;
	size_t wrote = 0;

	memset(&ops, 0, sizeof(ops));
	ops.sign = stub_sign;
	if (fzn_record_sign(issuer, SUBJECT, 5u, 1u, seq, 1u, body, body_len, &ops,
	                    RECORD_SLOT, sizeof(RECORD_SLOT), &wrote) != FZN_RECORD_OK)
		return 0;
	return fzn_record_open(RECORD_SLOT, wrote, out) == FZN_RECORD_OK;
}

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

	/* THE BOUND IS THE WIRE'S, NOT THE RECORD BODY'S, and this case said
	 * FZN_RECORD_BODY_MAX until sec 146 built the encoder. An inline body
	 * is the value plus a 34-byte head, so a value of exactly
	 * FZN_RECORD_BODY_MAX cannot be carried by any record -- the table was
	 * accepting something the wire refuses. */
	CHECK(FZN_CATALOG_INLINE_MAX < FZN_RECORD_BODY_MAX,
	      "the inline bound is not below a record body, so the head costs nothing");
	e = inline_entry(0x10, body, FZN_CATALOG_INLINE_MAX + 1u, ALICE, 1);
	CHECK(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_ERR_MALFORMED,
	      "an inline past what the wire can carry was accepted");
	e = inline_entry(0x10, body, FZN_RECORD_BODY_MAX, ALICE, 1);
	CHECK(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_ERR_MALFORMED,
	      "a value the size of a whole record body was accepted, and it cannot be sent");
	e = inline_entry(0x10, body, FZN_CATALOG_INLINE_MAX, ALICE, 1);
	CHECK(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK,
	      "an inline exactly at the wire bound was refused");

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

/* ---- the wire form ------------------------------------------------------ */

/* An edge survives the round trip, and the issuer and sequence come from the
 * RECORD rather than from anything in the body. sec 146. */
static void test_an_edge_round_trips_through_a_record(void)
{
	fzn_catalog_edge_t rows[4];
	fzn_catalog_t cat;
	uint8_t body[FZN_CATALOG_EDGE_BODY_LEN];
	fzn_record_t rec;
	const fzn_catalog_edge_t *held;
	size_t len = 0;

	REQUIRE(fzn_catalog_edge_encode(idp(0x20), idp(0x10), 1, body, sizeof(body), &len)
	                == FZN_CATALOG_OK,
	        "an edge would not encode");
	CHECK(len == FZN_CATALOG_EDGE_BODY_LEN, "an edge body is not the length promised");
	REQUIRE(as_record(&rec, ALICE, 7u, body, len), "the fixture could not sign");

	REQUIRE(fzn_catalog_init(&cat, rows, 4, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	CHECK(fzn_catalog_apply(&cat, rec) == FZN_CATALOG_OK, "a good edge record was refused");
	CHECK(fzn_catalog_linked(&cat, idp(0x20), idp(0x10)), "the edge did not take");

	/* THE ATTRIBUTION IS THE RECORD'S. There is no field in the body for
	 * an issuer or a sequence, so an assertion cannot be credited to
	 * somebody who did not make it. */
	held = fzn_catalog_edge_of(&cat, idp(0x20), idp(0x10));
	REQUIRE(held != NULL, "the edge was not held");
	CHECK(memcmp(held->issuer, ALICE, FZN_PUBKEY_LEN) == 0,
	      "the edge was attributed to somebody other than the record's signer");
	CHECK(held->seq == 7u, "the edge did not take the record's sequence");
}

/* An unlink travels too, which is what makes a removal syncable at all. */
static void test_an_unlink_travels(void)
{
	fzn_catalog_edge_t rows[4];
	fzn_catalog_t cat;
	uint8_t body[FZN_CATALOG_EDGE_BODY_LEN];
	fzn_record_t rec;
	size_t len = 0;

	REQUIRE(fzn_catalog_init(&cat, rows, 4, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x20), idp(0x10), ALICE, 1, 1) == FZN_CATALOG_OK,
	        "the link was refused");
	REQUIRE(fzn_catalog_edge_encode(idp(0x20), idp(0x10), 0, body, sizeof(body), &len)
	                == FZN_CATALOG_OK,
	        "an unlink would not encode");
	REQUIRE(as_record(&rec, ALICE, 2u, body, len), "the fixture could not sign");
	CHECK(fzn_catalog_apply(&cat, rec) == FZN_CATALOG_OK, "an unlink record was refused");
	CHECK(!fzn_catalog_linked(&cat, idp(0x20), idp(0x10)), "the unlink did not take");
}

static void test_every_content_kind_round_trips(void)
{
	fzn_catalog_edge_t rows[4];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_t cat;
	uint8_t body[FZN_RECORD_BODY_MAX];
	const uint8_t value[5] = { 5, 4, 3, 2, 1 };
	fzn_catalog_entry_t e;
	const fzn_catalog_entry_t *got;
	fzn_record_t rec;
	size_t len = 0;

	REQUIRE(fzn_catalog_init(&cat, rows, 4, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "content init refused");

	/* NONE. */
	memset(&e, 0, sizeof(e));
	e.id = id(0x30);
	e.kind = FZN_CATALOG_CONTENT_NONE;
	REQUIRE(fzn_catalog_content_encode(&e, body, sizeof(body), &len) == FZN_CATALOG_OK,
	        "a set would not encode");
	CHECK(len == FZN_CATALOG_CONTENT_HEAD_LEN, "a set body is not the head alone");
	REQUIRE(as_record(&rec, ALICE, 1u, body, len), "sign a set");
	CHECK(fzn_catalog_apply(&cat, rec) == FZN_CATALOG_OK, "a set record was refused");
	got = fzn_catalog_content_of(&cat, idp(0x30));
	CHECK(got && got->kind == FZN_CATALOG_CONTENT_NONE, "a set did not survive");

	/* INLINE, and the bytes must be a view into the record. */
	e = inline_entry(0x31, value, sizeof(value), ALICE, 0);
	REQUIRE(fzn_catalog_content_encode(&e, body, sizeof(body), &len) == FZN_CATALOG_OK,
	        "inline would not encode");
	CHECK(len == FZN_CATALOG_CONTENT_HEAD_LEN + sizeof(value),
	      "an inline body is not the head plus the value");
	REQUIRE(as_record(&rec, ALICE, 2u, body, len), "sign inline");
	CHECK(fzn_catalog_apply(&cat, rec) == FZN_CATALOG_OK, "an inline record was refused");
	got = fzn_catalog_content_of(&cat, idp(0x31));
	REQUIRE(got != NULL, "inline did not survive");
	CHECK(got->kind == FZN_CATALOG_CONTENT_INLINE && got->len == sizeof(value),
	      "the inline length did not survive");
	CHECK(memcmp(got->bytes, value, sizeof(value)) == 0, "the inline bytes did not survive");
	CHECK(got->bytes >= rec.base && got->bytes < rec.base + rec.len,
	      "the inline bytes are not a view into the record, so they were copied");

	/* BLOB, and the length is what a consumer decides on. */
	e = blob_entry(0x32, 0xdd, 123456789u, ALICE, 0);
	REQUIRE(fzn_catalog_content_encode(&e, body, sizeof(body), &len) == FZN_CATALOG_OK,
	        "a blob would not encode");
	CHECK(len == FZN_CATALOG_BLOB_BODY_LEN, "a blob body is not the length promised");
	REQUIRE(as_record(&rec, ALICE, 3u, body, len), "sign a blob");
	CHECK(fzn_catalog_apply(&cat, rec) == FZN_CATALOG_OK, "a blob record was refused");
	got = fzn_catalog_content_of(&cat, idp(0x32));
	REQUIRE(got != NULL, "the blob did not survive");
	CHECK(got->blob_len == 123456789u, "the blob length did not survive");
	CHECK(got->root[0] == 0xdd, "the blob root did not survive");

	/* AND CONTENT IS ATTRIBUTED FROM THE RECORD, as an edge is. There is no
	 * field in the body for an issuer, so a content assertion cannot be
	 * credited to somebody who did not sign it -- and a decoder reading one
	 * out of the body would be trusting bytes over the signature. */
	CHECK(memcmp(got->issuer, ALICE, FZN_PUBKEY_LEN) == 0,
	      "content was attributed to somebody other than the record's signer");
	CHECK(got->seq == 3u, "content did not take the record's sequence");
}

/*
 * ONE ENCODING OF EACH ASSERTION, ENFORCED. Read loosely, 255 encodings of
 * one statement exist and two implementations that both work produce
 * assertions the other rejects -- chain.h's argument for `delegable`.
 */
static void test_a_non_canonical_body_is_refused(void)
{
	fzn_catalog_edge_t rows[4];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_t cat;
	uint8_t body[FZN_RECORD_BODY_MAX];
	fzn_record_t rec;
	size_t len = 0;
	size_t i;

	REQUIRE(fzn_catalog_init(&cat, rows, 4, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "content init refused");
	REQUIRE(fzn_catalog_edge_encode(idp(0x20), idp(0x10), 1, body, sizeof(body), &len)
	                == FZN_CATALOG_OK, "encode");

	/* THE CONTROL: as encoded, it applies. */
	REQUIRE(as_record(&rec, ALICE, 1u, body, len), "sign");
	REQUIRE(fzn_catalog_apply(&cat, rec) == FZN_CATALOG_OK,
	        "the unmodified body was refused, so every refusal below says nothing");

	/* `present` outside {0,1}, every value of it. */
	for (i = 2; i < 256u; i++) {
		body[FZN_CATALOG_EDGE_BODY_LEN - 1u] = (uint8_t)i;
		REQUIRE(as_record(&rec, ALICE, 2u, body, len), "sign a bent present");
		if (fzn_catalog_apply(&cat, rec) != FZN_CATALOG_ERR_SHAPE) {
			CHECK(0, "a present byte of %zu was accepted", i);
			break;
		}
	}
	CHECK(i == 256u, "the present sweep stopped early");
	body[FZN_CATALOG_EDGE_BODY_LEN - 1u] = 1u;

	/* A length that is not an edge's. */
	REQUIRE(as_record(&rec, ALICE, 3u, body, len - 1u), "sign a short edge");
	CHECK(fzn_catalog_apply(&cat, rec) == FZN_CATALOG_ERR_SHAPE, "a short edge was accepted");
	REQUIRE(as_record(&rec, ALICE, 4u, body, len + 1u), "sign a long edge");
	CHECK(fzn_catalog_apply(&cat, rec) == FZN_CATALOG_ERR_SHAPE, "a long edge was accepted");

	/* A tag that is neither, every value of it. */
	for (i = 0; i < 256u; i++) {
		if (i == FZN_CATALOG_OBJECT_EDGE || i == FZN_CATALOG_OBJECT_CONTENT)
			continue;
		body[0] = (uint8_t)i;
		REQUIRE(as_record(&rec, ALICE, 5u, body, len), "sign a bent tag");
		if (fzn_catalog_apply(&cat, rec) != FZN_CATALOG_ERR_SHAPE) {
			CHECK(0, "a tag of %zu was accepted", i);
			break;
		}
	}
	CHECK(i == 256u, "the tag sweep stopped early");

	/* A content kind that is none of the three. */
	body[0] = (uint8_t)FZN_CATALOG_OBJECT_CONTENT;
	body[FZN_CATALOG_CONTENT_HEAD_LEN - 1u] = 99u;
	REQUIRE(as_record(&rec, ALICE, 6u, body, FZN_CATALOG_CONTENT_HEAD_LEN),
	        "sign a bent kind");
	CHECK(fzn_catalog_apply(&cat, rec) == FZN_CATALOG_ERR_SHAPE,
	      "a content kind that is none of the three was accepted");

	/* A blob length of zero on the wire, which the table refuses too. */
	body[FZN_CATALOG_CONTENT_HEAD_LEN - 1u] = (uint8_t)FZN_CATALOG_CONTENT_BLOB;
	memset(body + FZN_CATALOG_CONTENT_HEAD_LEN, 0, FZN_CATALOG_BLOB_BODY_LEN
	                                                       - FZN_CATALOG_CONTENT_HEAD_LEN);
	REQUIRE(as_record(&rec, ALICE, 7u, body, FZN_CATALOG_BLOB_BODY_LEN), "sign a null blob");
	CHECK(fzn_catalog_apply(&cat, rec) == FZN_CATALOG_ERR_SHAPE,
	      "a blob naming nothing was accepted off the wire");
	/* And a blob body of the wrong length, BOTH WAYS. A check written as
	 * "at least this long" refuses the short one and accepts a long one
	 * carrying trailing bytes nobody signed a meaning for. */
	REQUIRE(as_record(&rec, ALICE, 8u, body, FZN_CATALOG_BLOB_BODY_LEN - 1u),
	        "sign a short blob");
	CHECK(fzn_catalog_apply(&cat, rec) == FZN_CATALOG_ERR_SHAPE, "a short blob was accepted");
	body[FZN_CATALOG_BLOB_BODY_LEN - 1u] = 1u; /* a nonzero length, so only the size is wrong */
	REQUIRE(as_record(&rec, ALICE, 9u, body, FZN_CATALOG_BLOB_BODY_LEN + 1u),
	        "sign a long blob");
	CHECK(fzn_catalog_apply(&cat, rec) == FZN_CATALOG_ERR_SHAPE, "a long blob was accepted");

	/* A NONE body with anything after it is not a longer NONE. */
	body[FZN_CATALOG_CONTENT_HEAD_LEN - 1u] = (uint8_t)FZN_CATALOG_CONTENT_NONE;
	REQUIRE(as_record(&rec, ALICE, 10u, body, FZN_CATALOG_CONTENT_HEAD_LEN + 1u),
	        "sign a long set");
	CHECK(fzn_catalog_apply(&cat, rec) == FZN_CATALOG_ERR_SHAPE, "a long set was accepted");
}

/* THE ENCODER PRODUCES THE CANONICAL BYTE, whatever truthy value it is
 * handed. A caller passing 2 for "present" is passing C's idea of true, and
 * an encoder that wrote it through would put a body on the wire that its own
 * decoder refuses. */
static void test_the_encoder_normalises_present(void)
{
	uint8_t body[FZN_CATALOG_EDGE_BODY_LEN];
	fzn_catalog_edge_t rows[4];
	fzn_catalog_t cat;
	fzn_record_t rec;
	size_t len = 0;

	REQUIRE(fzn_catalog_edge_encode(idp(0x20), idp(0x10), 2, body, sizeof(body), &len)
	                == FZN_CATALOG_OK, "encode with a truthy present");
	CHECK(body[FZN_CATALOG_EDGE_BODY_LEN - 1u] == 1u,
	      "the encoder wrote a truthy value through rather than the canonical one");

	/* And the proof that matters: its own decoder accepts it. */
	REQUIRE(fzn_catalog_init(&cat, rows, 4, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(as_record(&rec, ALICE, 1u, body, len), "sign");
	CHECK(fzn_catalog_apply(&cat, rec) == FZN_CATALOG_OK,
	      "the encoder produced a body its own decoder refuses");

	REQUIRE(fzn_catalog_edge_encode(idp(0x20), idp(0x10), 0, body, sizeof(body), &len)
	                == FZN_CATALOG_OK, "encode absent");
	CHECK(body[FZN_CATALOG_EDGE_BODY_LEN - 1u] == 0u, "absent did not encode as zero");
}

static void test_the_wire_caller_bugs_are_refused(void)
{
	fzn_catalog_edge_t rows[4];
	fzn_catalog_t cat;
	uint8_t body[FZN_CATALOG_EDGE_BODY_LEN];
	fzn_record_t never_opened;
	fzn_catalog_entry_t e;
	size_t len = 0;

	memset(&never_opened, 0, sizeof(never_opened));
	REQUIRE(fzn_catalog_init(&cat, rows, 4, &ADD_WINS) == FZN_CATALOG_OK, "init refused");

	CHECK(fzn_catalog_edge_encode(NULL, idp(0x10), 1, body, sizeof(body), &len)
	              == FZN_CATALOG_ERR_MALFORMED, "a null parent encoded");
	CHECK(fzn_catalog_edge_encode(idp(0x20), NULL, 1, body, sizeof(body), &len)
	              == FZN_CATALOG_ERR_MALFORMED, "a null child encoded");
	CHECK(fzn_catalog_edge_encode(idp(0x20), idp(0x10), 1, NULL, sizeof(body), &len)
	              == FZN_CATALOG_ERR_MALFORMED, "a null buffer encoded");
	CHECK(fzn_catalog_edge_encode(idp(0x20), idp(0x10), 1, body,
	                              FZN_CATALOG_EDGE_BODY_LEN - 1u, &len)
	              == FZN_CATALOG_ERR_MALFORMED, "a buffer one short encoded");
	CHECK(fzn_catalog_content_encode(NULL, body, sizeof(body), &len)
	              == FZN_CATALOG_ERR_MALFORMED, "a null entry encoded");
	e = inline_entry(0x10, NULL, 0, ALICE, 1);
	CHECK(fzn_catalog_content_encode(&e, body, 1u, &len) == FZN_CATALOG_ERR_MALFORMED,
	      "a buffer too small for the head encoded");

	CHECK(fzn_catalog_apply(NULL, never_opened) == FZN_CATALOG_ERR_MALFORMED,
	      "a null catalogue applied");
	CHECK(fzn_catalog_apply(&cat, never_opened) == FZN_CATALOG_ERR_MALFORMED,
	      "a record that was never opened applied");
}

/* ---- the filing --------------------------------------------------------- */

/* EXACTLY ONCE, AND IT IS STRUCTURAL. A node may be a member of several sets
 * -- that is the whole design -- and filed in exactly one of them. sec 147. */
static void test_a_node_is_filed_in_exactly_one_of_its_sets(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_t cat;
	const fzn_catalog_id_t *at;

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x20), idp(0x10), ALICE, 1, 1) == FZN_CATALOG_OK,
	        "first membership");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x21), idp(0x10), ALICE, 2, 1) == FZN_CATALOG_OK,
	        "second membership");

	CHECK(fzn_catalog_filed_under(&cat, idp(0x10)) == NULL,
	      "a node nobody filed reports a filing");

	CHECK(fzn_catalog_file_under(&cat, idp(0x20), idp(0x10)) == FZN_CATALOG_OK,
	      "filing under a set the node belongs to was refused");
	at = fzn_catalog_filed_under(&cat, idp(0x10));
	REQUIRE(at != NULL, "the filing did not take");
	CHECK(memcmp(at->b, idp(0x20)->b, FZN_CATALOG_ID_LEN) == 0, "filed under the wrong set");

	/* Filing it elsewhere MOVES it rather than adding a second place. */
	CHECK(fzn_catalog_file_under(&cat, idp(0x21), idp(0x10)) == FZN_CATALOG_OK,
	      "refiling was refused");
	at = fzn_catalog_filed_under(&cat, idp(0x10));
	REQUIRE(at != NULL, "the refiling lost the node");
	CHECK(memcmp(at->b, idp(0x21)->b, FZN_CATALOG_ID_LEN) == 0, "the refiling did not move it");

	/* AND THE MEMBERSHIPS ARE BOTH STILL THERE. A filing says where bytes
	 * live; it does not narrow what the catalogue says. */
	CHECK(fzn_catalog_linked(&cat, idp(0x20), idp(0x10)),
	      "refiling removed the membership it moved away from");
	CHECK(fzn_catalog_linked(&cat, idp(0x21), idp(0x10)), "the new membership went missing");
}

/* A filing is a subset of the DAG, so there must be an edge to mark. */
static void test_a_filing_needs_a_membership(void)
{
	fzn_catalog_edge_t rows[4];
	fzn_catalog_t cat;

	REQUIRE(fzn_catalog_init(&cat, rows, 4, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	CHECK(fzn_catalog_file_under(&cat, idp(0x20), idp(0x10)) == FZN_CATALOG_ERR_ABSENT,
	      "a node was filed under a set it does not belong to");
	CHECK(cat.used == 0, "the refused filing created the membership");

	/* Nor under one that has been unlinked. */
	REQUIRE(fzn_catalog_assert(&cat, idp(0x20), idp(0x10), ALICE, 1, 1) == FZN_CATALOG_OK,
	        "link");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x20), idp(0x10), ALICE, 2, 0) == FZN_CATALOG_OK,
	        "unlink");
	CHECK(fzn_catalog_file_under(&cat, idp(0x20), idp(0x10)) == FZN_CATALOG_ERR_ABSENT,
	      "a node was filed under a tombstone");
}

/* Unlinking a filed edge clears the filing: a node filed under a directory it
 * has left is a path to a place the catalogue no longer says it belongs. */
static void test_unlinking_clears_the_filing(void)
{
	fzn_catalog_edge_t rows[4];
	fzn_catalog_t cat;

	REQUIRE(fzn_catalog_init(&cat, rows, 4, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x20), idp(0x10), ALICE, 1, 1) == FZN_CATALOG_OK,
	        "link");
	REQUIRE(fzn_catalog_file_under(&cat, idp(0x20), idp(0x10)) == FZN_CATALOG_OK, "file");
	REQUIRE(fzn_catalog_filed_under(&cat, idp(0x10)) != NULL, "the filing did not take");

	REQUIRE(fzn_catalog_assert(&cat, idp(0x20), idp(0x10), ALICE, 2, 0) == FZN_CATALOG_OK,
	        "unlink");
	CHECK(fzn_catalog_filed_under(&cat, idp(0x10)) == NULL,
	      "an unlinked node is still filed under the set it left");

	/* AND IT MUST NOT COME BACK. The accessor already hides a mark on an
	 * absent edge, so the case above passes whether the mark was cleared or
	 * merely hidden -- the difference shows on a RE-LINK. Leaving the mark
	 * would let a peer's re-assertion resurrect a placement this host had
	 * lost, which is the wire deciding where a host keeps its bytes. */
	REQUIRE(fzn_catalog_assert(&cat, idp(0x20), idp(0x10), ALICE, 3, 1) == FZN_CATALOG_OK,
	        "a re-link");
	CHECK(fzn_catalog_filed_under(&cat, idp(0x10)) == NULL,
	      "a re-link resurrected a filing the unlink had cleared");

	/* AND AN ORDINARY RE-LINK DOES NOT WIPE A FILING. Only a removal
	 * clears it; a peer re-asserting a membership must not move where this
	 * host keeps its bytes. */
	REQUIRE(fzn_catalog_file_under(&cat, idp(0x20), idp(0x10)) == FZN_CATALOG_OK, "refile");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x20), idp(0x10), ALICE, 4, 1) == FZN_CATALOG_OK,
	        "a second link from the same issuer");
	CHECK(fzn_catalog_filed_under(&cat, idp(0x10)) != NULL,
	      "an ordinary re-assertion wiped this host's filing");
}

/* THE FILING DOES NOT TRAVEL, which is what makes it per host. */
static void test_a_filing_does_not_come_off_the_wire(void)
{
	fzn_catalog_edge_t rows[4];
	fzn_catalog_t cat;
	uint8_t body[FZN_CATALOG_EDGE_BODY_LEN];
	fzn_record_t rec;
	size_t len = 0;

	REQUIRE(fzn_catalog_init(&cat, rows, 4, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_edge_encode(idp(0x20), idp(0x10), 1, body, sizeof(body), &len)
	                == FZN_CATALOG_OK, "encode");
	CHECK(len == FZN_CATALOG_EDGE_BODY_LEN,
	      "an edge body grew, so the filing may have found a bit on the wire");
	REQUIRE(as_record(&rec, ALICE, 1u, body, len), "sign");
	REQUIRE(fzn_catalog_apply(&cat, rec) == FZN_CATALOG_OK, "apply");

	CHECK(fzn_catalog_filed_under(&cat, idp(0x10)) == NULL,
	      "applying a record from a peer filed the node, so a filing travelled");
	CHECK(fzn_catalog_filing_root_of(&cat) == NULL,
	      "applying a record set a filing root, which is this host's choice");
}

/* The path is root first, and a catalogue with no root refuses to answer. */
static void test_a_path_runs_from_the_root_down(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_t cat;
	fzn_catalog_id_t out[8];
	size_t n;

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	/* root 0x01 -> 0x02 -> 0x03 */
	REQUIRE(fzn_catalog_assert(&cat, idp(0x01), idp(0x02), ALICE, 1, 1) == FZN_CATALOG_OK, "a");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x02), idp(0x03), ALICE, 2, 1) == FZN_CATALOG_OK, "b");
	REQUIRE(fzn_catalog_file_under(&cat, idp(0x01), idp(0x02)) == FZN_CATALOG_OK, "file a");
	REQUIRE(fzn_catalog_file_under(&cat, idp(0x02), idp(0x03)) == FZN_CATALOG_OK, "file b");

	/* NO ROOT, NO PATH -- the holder's requirement is that the tag must
	 * exist, and a library cannot supply one for a caller.
	 *
	 * THE FIXTURE IS ROOTED AT THE ALL-ZERO ID ON PURPOSE. An unset root
	 * reads as zeros, so a chain that stops anywhere else would refuse for
	 * want of a filing parent rather than for want of a root, and the case
	 * would pass with the guard deleted. Filing 0x01 under 0x00 makes the
	 * chain reach exactly what an unset root would compare equal to. */
	REQUIRE(fzn_catalog_assert(&cat, idp(0x00), idp(0x01), ALICE, 9, 1) == FZN_CATALOG_OK,
	        "the zero-rooted membership");
	REQUIRE(fzn_catalog_file_under(&cat, idp(0x00), idp(0x01)) == FZN_CATALOG_OK,
	        "file under the zero id");
	CHECK(fzn_catalog_filed_path(&cat, idp(0x03), out, 8) == 0,
	      "a catalogue with no filing root answered a path");
	/* THE CONTROL: naming that same id as the root makes the path appear,
	 * so the refusal above is the missing root and not a broken chain. */
	REQUIRE(fzn_catalog_filing_root(&cat, idp(0x00)) == FZN_CATALOG_OK, "root the zero id");
	CHECK(fzn_catalog_filed_path(&cat, idp(0x03), out, 8) == 4,
	      "the chain does not reach the zero id, so the case above proves nothing");

	REQUIRE(fzn_catalog_filing_root(&cat, idp(0x01)) == FZN_CATALOG_OK, "set the root");
	n = fzn_catalog_filed_path(&cat, idp(0x03), out, 8);
	CHECK(n == 3, "the path is %zu deep, wanted three", n);
	CHECK(n == 3 && memcmp(out[0].b, idp(0x01)->b, FZN_CATALOG_ID_LEN) == 0,
	      "the path does not begin at the root");
	CHECK(n == 3 && memcmp(out[2].b, idp(0x03)->b, FZN_CATALOG_ID_LEN) == 0,
	      "the path does not end at the node");

	/* The root itself is a path of one. */
	CHECK(fzn_catalog_filed_path(&cat, idp(0x01), out, 8) == 1,
	      "the root is not a path of one");

	/* A node nobody filed has no path, which is an ordinary state. */
	REQUIRE(fzn_catalog_assert(&cat, idp(0x01), idp(0x09), ALICE, 3, 1) == FZN_CATALOG_OK, "c");
	CHECK(fzn_catalog_filed_path(&cat, idp(0x09), out, 8) == 0,
	      "a node nobody filed reported a path");
}

/* A chain that does not reach the root is not a path, and a cycle is bounded
 * rather than trusted. */
static void test_a_path_that_does_not_reach_the_root_is_none(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_t cat;
	fzn_catalog_id_t out[8];

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	/* 0x05 -> 0x06, filed, but the root is 0x01 and nothing joins them. */
	REQUIRE(fzn_catalog_assert(&cat, idp(0x05), idp(0x06), ALICE, 1, 1) == FZN_CATALOG_OK, "a");
	REQUIRE(fzn_catalog_file_under(&cat, idp(0x05), idp(0x06)) == FZN_CATALOG_OK, "file");
	REQUIRE(fzn_catalog_filing_root(&cat, idp(0x01)) == FZN_CATALOG_OK, "root");
	CHECK(fzn_catalog_filed_path(&cat, idp(0x06), out, 8) == 0,
	      "a filing that never reaches the root answered a path");

	/* A CYCLE: file A under B and B under A. One slot per node makes this
	 * expressible, so the walk is bounded rather than promised. */
	REQUIRE(fzn_catalog_assert(&cat, idp(0x06), idp(0x05), ALICE, 2, 1) == FZN_CATALOG_OK, "b");
	REQUIRE(fzn_catalog_file_under(&cat, idp(0x06), idp(0x05)) == FZN_CATALOG_OK, "file back");
	CHECK(fzn_catalog_filed_path(&cat, idp(0x06), out, 8) == 0,
	      "a filing cycle answered a path rather than stopping at the bound");
}

static void test_the_filing_caller_bugs_are_refused(void)
{
	fzn_catalog_edge_t rows[4];
	fzn_catalog_t cat;
	fzn_catalog_id_t out[4];

	REQUIRE(fzn_catalog_init(&cat, rows, 4, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	CHECK(fzn_catalog_filing_root(NULL, idp(0x01)) == FZN_CATALOG_ERR_MALFORMED,
	      "a null catalogue took a root");
	CHECK(fzn_catalog_filing_root(&cat, NULL) == FZN_CATALOG_ERR_MALFORMED, "a null root");
	CHECK(fzn_catalog_filing_root_of(NULL) == NULL, "a null catalogue named a root");
	CHECK(fzn_catalog_file_under(NULL, idp(0x20), idp(0x10)) == FZN_CATALOG_ERR_MALFORMED,
	      "a null catalogue filed something");
	CHECK(fzn_catalog_file_under(&cat, NULL, idp(0x10)) == FZN_CATALOG_ERR_MALFORMED,
	      "a null parent");
	CHECK(fzn_catalog_file_under(&cat, idp(0x20), NULL) == FZN_CATALOG_ERR_MALFORMED,
	      "a null child");
	CHECK(fzn_catalog_filed_under(NULL, idp(0x10)) == NULL,
	      "a null catalogue named a filing");
	CHECK(fzn_catalog_filed_path(NULL, idp(0x10), out, 4) == 0,
	      "a null catalogue answered a path");
	CHECK(fzn_catalog_filed_path(&cat, idp(0x10), NULL, 4) == 0, "a null buffer");
	CHECK(fzn_catalog_filed_path(&cat, idp(0x10), out, 0) == 0, "a zero bound");
}

/* ---- the refile --------------------------------------------------------- */

/* root 0x01 holds 0x02, which holds the file 0x03. */
static void build_filed(fzn_catalog_t *cat, fzn_catalog_edge_t *rows, size_t cap)
{
	REQUIRE(fzn_catalog_init(cat, rows, cap, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_assert(cat, idp(0x01), idp(0x02), ALICE, 1, 1) == FZN_CATALOG_OK, "a");
	REQUIRE(fzn_catalog_assert(cat, idp(0x02), idp(0x03), ALICE, 2, 1) == FZN_CATALOG_OK, "b");
	REQUIRE(fzn_catalog_file_under(cat, idp(0x01), idp(0x02)) == FZN_CATALOG_OK, "file a");
	REQUIRE(fzn_catalog_file_under(cat, idp(0x02), idp(0x03)) == FZN_CATALOG_OK, "file b");
	REQUIRE(fzn_catalog_filing_root(cat, idp(0x01)) == FZN_CATALOG_OK, "root");
}

/*
 * THE WHOLE SEQUENCE. Capture the old arrangement, change the filing, lock,
 * and step -- and each step names the node with the path its file has and the
 * path it should have. sec 148.
 */
static void test_a_refile_names_both_paths(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_move_t moves[8];
	fzn_catalog_refile_t job;
	fzn_catalog_t cat;
	fzn_catalog_id_t node, was[8], now[8];
	size_t was_len = 0, now_len = 0;

	build_filed(&cat, rows, 8);

	/* Captured BEFORE the change, because after it the old paths are gone
	 * and there is nothing to move files from. */
	REQUIRE(fzn_catalog_refile_capture(&cat, &job, moves, 8) == FZN_CATALOG_OK, "capture");
	CHECK(job.used == 2, "two filed nodes were not captured, got %zu", job.used);

	/* A new formation: 0x03 moves up to sit directly under the root. */
	REQUIRE(fzn_catalog_assert(&cat, idp(0x01), idp(0x03), ALICE, 3, 1) == FZN_CATALOG_OK,
	        "the new membership");
	REQUIRE(fzn_catalog_file_under(&cat, idp(0x01), idp(0x03)) == FZN_CATALOG_OK, "refile it");

	REQUIRE(fzn_catalog_refile_begin(&cat, &job) == FZN_CATALOG_OK, "begin");

	/* Sorted by id, so 0x02 comes first on every machine and after every
	 * restart, whatever order the edge table is in. */
	REQUIRE(fzn_catalog_refile_at(&cat, &job, &node, was, 8, &was_len, now, 8, &now_len)
	                == FZN_CATALOG_OK, "the first step");
	CHECK(memcmp(node.b, idp(0x02)->b, FZN_CATALOG_ID_LEN) == 0,
	      "the moves are not in id order");
	CHECK(was_len == 2 && now_len == 2, "0x02 moved, though nothing about it changed");
	REQUIRE(fzn_catalog_refile_advance(&job) == FZN_CATALOG_OK, "advance");

	REQUIRE(fzn_catalog_refile_at(&cat, &job, &node, was, 8, &was_len, now, 8, &now_len)
	                == FZN_CATALOG_OK, "the second step");
	CHECK(memcmp(node.b, idp(0x03)->b, FZN_CATALOG_ID_LEN) == 0, "the second node is wrong");
	/* THE POINT: was root/0x02/0x03, now root/0x03. */
	CHECK(was_len == 3, "the old path is %zu deep, wanted three", was_len);
	CHECK(now_len == 2, "the new path is %zu deep, wanted two", now_len);
	CHECK(was_len == 3 && memcmp(was[1].b, idp(0x02)->b, FZN_CATALOG_ID_LEN) == 0,
	      "the old path does not run through the directory the file was in");
	CHECK(now_len == 2 && memcmp(now[1].b, idp(0x03)->b, FZN_CATALOG_ID_LEN) == 0,
	      "the new path does not end at the node");
	REQUIRE(fzn_catalog_refile_advance(&job) == FZN_CATALOG_OK, "advance");

	CHECK(fzn_catalog_refile_at(&cat, &job, &node, was, 8, &was_len, now, 8, &now_len)
	              == FZN_CATALOG_ERR_ABSENT, "the cursor did not run out");
	CHECK(fzn_catalog_refile_end(&cat, &job) == FZN_CATALOG_OK, "end");
}

/*
 * THE MOVES ARE SORTED BY ID, NOT BY TABLE ORDER, and this fixture files the
 * higher id FIRST so the two disagree. Without the sort the cursor would mean
 * a different node on a machine whose edges arrived in another order, and a
 * job resumed after a restart would repeat one file and skip another.
 */
static void test_the_moves_are_sorted_by_id(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_move_t moves[8];
	fzn_catalog_refile_t job;
	fzn_catalog_t cat;

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	/* 0x33 is filed before 0x22, so the table order is the reverse of the
	 * id order and a capture that kept table order would show it. */
	REQUIRE(fzn_catalog_assert(&cat, idp(0x01), idp(0x33), ALICE, 1, 1) == FZN_CATALOG_OK, "a");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x01), idp(0x22), ALICE, 2, 1) == FZN_CATALOG_OK, "b");
	REQUIRE(fzn_catalog_file_under(&cat, idp(0x01), idp(0x33)) == FZN_CATALOG_OK, "file high");
	REQUIRE(fzn_catalog_file_under(&cat, idp(0x01), idp(0x22)) == FZN_CATALOG_OK, "file low");
	REQUIRE(fzn_catalog_filing_root(&cat, idp(0x01)) == FZN_CATALOG_OK, "root");

	REQUIRE(fzn_catalog_refile_capture(&cat, &job, moves, 8) == FZN_CATALOG_OK, "capture");
	REQUIRE(job.used == 2, "two filed nodes were not captured");
	CHECK(memcmp(moves[0].node.b, idp(0x22)->b, FZN_CATALOG_ID_LEN) == 0,
	      "the moves follow the edge table rather than the id order");
	CHECK(memcmp(moves[1].node.b, idp(0x33)->b, FZN_CATALOG_ID_LEN) == 0,
	      "the second move is not the higher id");
}

/*
 * THE ONLY THING A CATALOGUE ANSWERS MID-REFILE IS PROGRESS, which is the
 * holder's requirement in as many words -- a consumer shows a bar rather than
 * a tree.
 */
static void test_only_progress_answers_during_a_refile(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_move_t moves[8];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_refile_t job;
	fzn_catalog_t cat;
	fzn_catalog_id_t out[8];
	fzn_catalog_entry_t e;
	fzn_record_t rec;
	uint8_t body[FZN_CATALOG_EDGE_BODY_LEN];
	const uint8_t value[1] = { 7 };
	size_t done = 0, total = 0, len = 0;

	build_filed(&cat, rows, 8);
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "content init");
	REQUIRE(fzn_catalog_refile_capture(&cat, &job, moves, 8) == FZN_CATALOG_OK, "capture");

	/* THE CONTROL: everything works before the lock, so the refusals below
	 * are the lock rather than a broken fixture. */
	CHECK(fzn_catalog_linked(&cat, idp(0x01), idp(0x02)), "the fixture has no membership");
	CHECK(fzn_catalog_members(&cat, idp(0x01), out, 8) == 1, "the fixture lists nothing");
	CHECK(fzn_catalog_filed_path(&cat, idp(0x03), out, 8) == 3, "the fixture has no path");

	REQUIRE(fzn_catalog_refile_begin(&cat, &job) == FZN_CATALOG_OK, "begin");

	/* Writes. */
	CHECK(fzn_catalog_assert(&cat, idp(0x01), idp(0x09), ALICE, 9, 1) == FZN_CATALOG_ERR_BUSY,
	      "a membership was asserted during a refile");
	CHECK(fzn_catalog_file_under(&cat, idp(0x01), idp(0x02)) == FZN_CATALOG_ERR_BUSY,
	      "a node was filed during a refile");
	CHECK(fzn_catalog_filing_root(&cat, idp(0x02)) == FZN_CATALOG_ERR_BUSY,
	      "the filing root moved during a refile");
	e = inline_entry(0x03, value, 1, ALICE, 1);
	CHECK(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_ERR_BUSY,
	      "content was set during a refile");

	/* AND A PEER'S RECORD WAITS, which is the one that would otherwise
	 * change the set the cursor is counting through. */
	REQUIRE(fzn_catalog_edge_encode(idp(0x01), idp(0x09), 1, body, sizeof(body), &len)
	                == FZN_CATALOG_OK, "encode");
	REQUIRE(as_record(&rec, BOB, 1u, body, len), "sign");
	CHECK(fzn_catalog_apply(&cat, rec) == FZN_CATALOG_ERR_BUSY,
	      "a peer's record was applied during a refile");

	/* AND A BODY THAT IS NOT OURS ANSWERS BUSY TOO, which is what makes
	 * `apply`'s own guard load-bearing rather than a second copy of the
	 * one in `assert`. Without it this would be classified as SHAPE -- a
	 * catalogue mid-refile telling a caller what it thinks of bytes it has
	 * refused to look at. */
	body[0] = 0xfeu;
	REQUIRE(as_record(&rec, BOB, 2u, body, len), "sign a body that is not ours");
	CHECK(fzn_catalog_apply(&cat, rec) == FZN_CATALOG_ERR_BUSY,
	      "a body that is not a catalogue assertion was classified during a refile");

	/* Reads, all of them. */
	CHECK(!fzn_catalog_linked(&cat, idp(0x01), idp(0x02)),
	      "a membership was readable during a refile");
	CHECK(fzn_catalog_edge_of(&cat, idp(0x01), idp(0x02)) == NULL, "an edge was readable");
	CHECK(fzn_catalog_members(&cat, idp(0x01), out, 8) == 0, "members were listed");
	CHECK(fzn_catalog_parents(&cat, idp(0x02), out, 8) == 0, "parents were listed");
	CHECK(fzn_catalog_intersect(&cat, idp(0x01), 1, out, 8) == 0, "a search answered");
	CHECK(fzn_catalog_content_of(&cat, idp(0x03)) == NULL, "content was readable");
	CHECK(fzn_catalog_filed_path(&cat, idp(0x03), out, 8) == 0, "a path was readable");

	/* AND PROGRESS ANSWERS, which is the whole of what a consumer can do. */
	CHECK(fzn_catalog_refile_progress(&job, &done, &total) == FZN_CATALOG_OK,
	      "progress was refused, so a consumer has nothing to draw");
	CHECK(done == 0 && total == 2, "progress is %zu of %zu, wanted 0 of 2", done, total);

	/* Finish, and the catalogue comes back. */
	REQUIRE(fzn_catalog_refile_advance(&job) == FZN_CATALOG_OK, "advance one");
	CHECK(fzn_catalog_refile_progress(&job, &done, &total) == FZN_CATALOG_OK, "progress");
	CHECK(done == 1, "progress did not advance");
	REQUIRE(fzn_catalog_refile_advance(&job) == FZN_CATALOG_OK, "advance two");
	REQUIRE(fzn_catalog_refile_end(&cat, &job) == FZN_CATALOG_OK, "end");
	CHECK(fzn_catalog_linked(&cat, idp(0x01), idp(0x02)),
	      "the catalogue did not come back after the refile");
}

/*
 * IT SURVIVES A CRASH. The job is plain data over a caller's array, so a
 * consumer writes it to disk; a restart rebuilds the catalogue from records,
 * loads the job and begins the same one.
 */
static void test_a_refile_resumes_after_a_restart(void)
{
	fzn_catalog_edge_t rows[8], rebuilt_rows[8];
	fzn_catalog_move_t moves[8], saved_moves[8];
	fzn_catalog_refile_t job, saved;
	fzn_catalog_t cat, rebuilt;
	fzn_catalog_id_t node, was[8], now[8];
	size_t was_len = 0, now_len = 0, done = 0, total = 0;

	build_filed(&cat, rows, 8);
	REQUIRE(fzn_catalog_refile_capture(&cat, &job, moves, 8) == FZN_CATALOG_OK, "capture");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x01), idp(0x03), ALICE, 3, 1) == FZN_CATALOG_OK,
	        "the new membership");
	REQUIRE(fzn_catalog_file_under(&cat, idp(0x01), idp(0x03)) == FZN_CATALOG_OK, "refile it");
	REQUIRE(fzn_catalog_refile_begin(&cat, &job) == FZN_CATALOG_OK, "begin");
	REQUIRE(fzn_catalog_refile_advance(&job) == FZN_CATALOG_OK, "one move done");

	/* The crash: nothing is unlocked, nothing is ended. What a consumer had
	 * written to disk is the job's bytes and the rows behind it -- copied
	 * here, which is what persisting and reloading amounts to. */
	memcpy(saved_moves, moves, sizeof(saved_moves));
	saved = job;
	saved.moves = saved_moves;

	/* The restart: a fresh catalogue rebuilt from the same records, in a
	 * DIFFERENT edge order, so this proves the cursor does not depend on
	 * the table. */
	REQUIRE(fzn_catalog_init(&rebuilt, rebuilt_rows, 8, &ADD_WINS) == FZN_CATALOG_OK,
	        "rebuild init");
	REQUIRE(fzn_catalog_assert(&rebuilt, idp(0x02), idp(0x03), ALICE, 2, 1) == FZN_CATALOG_OK,
	        "b first this time");
	REQUIRE(fzn_catalog_assert(&rebuilt, idp(0x01), idp(0x03), ALICE, 3, 1) == FZN_CATALOG_OK,
	        "then the new one");
	REQUIRE(fzn_catalog_assert(&rebuilt, idp(0x01), idp(0x02), ALICE, 1, 1) == FZN_CATALOG_OK,
	        "then a");
	REQUIRE(fzn_catalog_file_under(&rebuilt, idp(0x01), idp(0x02)) == FZN_CATALOG_OK, "file a");
	REQUIRE(fzn_catalog_file_under(&rebuilt, idp(0x01), idp(0x03)) == FZN_CATALOG_OK, "file b");
	REQUIRE(fzn_catalog_filing_root(&rebuilt, idp(0x01)) == FZN_CATALOG_OK, "root");

	/* BEGINNING AN ALREADY-STARTED JOB IS WHAT A RESTART DOES, so it must
	 * not be an error -- refusing here would make a crash unrecoverable by
	 * the one path that exists to recover from it. */
	CHECK(fzn_catalog_refile_begin(&rebuilt, &saved) == FZN_CATALOG_OK,
	      "a restarted job could not begin again");
	CHECK(fzn_catalog_refile_progress(&saved, &done, &total) == FZN_CATALOG_OK, "progress");
	CHECK(done == 1 && total == 2, "the restart lost the cursor: %zu of %zu", done, total);

	/* And it picks up at the SECOND move, not the first. */
	REQUIRE(fzn_catalog_refile_at(&rebuilt, &saved, &node, was, 8, &was_len, now, 8, &now_len)
	                == FZN_CATALOG_OK, "the resumed step");
	CHECK(memcmp(node.b, idp(0x03)->b, FZN_CATALOG_ID_LEN) == 0,
	      "the restart resumed at the wrong node");
	CHECK(was_len == 3 && now_len == 2, "the resumed step has the wrong paths");

	REQUIRE(fzn_catalog_refile_advance(&saved) == FZN_CATALOG_OK, "advance");
	CHECK(fzn_catalog_refile_end(&rebuilt, &saved) == FZN_CATALOG_OK, "end");
}

/* A refile that is not finished cannot be ended: unlocking a catalogue whose
 * files are half moved would tell the next reader a tree that is not on the
 * disk. */
static void test_an_unfinished_refile_cannot_be_ended(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_move_t moves[8];
	fzn_catalog_refile_t job;
	fzn_catalog_t cat;
	fzn_catalog_id_t out[8];

	build_filed(&cat, rows, 8);
	REQUIRE(fzn_catalog_refile_capture(&cat, &job, moves, 8) == FZN_CATALOG_OK, "capture");
	REQUIRE(fzn_catalog_refile_begin(&cat, &job) == FZN_CATALOG_OK, "begin");

	CHECK(fzn_catalog_refile_end(&cat, &job) == FZN_CATALOG_ERR_BUSY,
	      "a refile with work left was ended");
	CHECK(fzn_catalog_members(&cat, idp(0x01), out, 8) == 0,
	      "the refused end unlocked the catalogue anyway");

	REQUIRE(fzn_catalog_refile_advance(&job) == FZN_CATALOG_OK, "one");
	CHECK(fzn_catalog_refile_end(&cat, &job) == FZN_CATALOG_ERR_BUSY,
	      "a refile one move short was ended");
	REQUIRE(fzn_catalog_refile_advance(&job) == FZN_CATALOG_OK, "two");
	CHECK(fzn_catalog_refile_advance(&job) == FZN_CATALOG_ERR_ABSENT,
	      "the cursor advanced past the end");
	CHECK(fzn_catalog_refile_end(&cat, &job) == FZN_CATALOG_OK, "a finished refile was refused");
}

static void test_the_refile_caller_bugs_are_refused(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_move_t moves[8];
	fzn_catalog_move_t one[1];
	fzn_catalog_refile_t job, fresh;
	fzn_catalog_t cat;
	fzn_catalog_id_t node, was[8], now[8];
	size_t was_len = 0, now_len = 0, done = 0, total = 0;

	memset(&fresh, 0, sizeof(fresh));
	build_filed(&cat, rows, 8);

	CHECK(fzn_catalog_refile_capture(NULL, &job, moves, 8) == FZN_CATALOG_ERR_MALFORMED,
	      "a null catalogue captured");
	CHECK(fzn_catalog_refile_capture(&cat, NULL, moves, 8) == FZN_CATALOG_ERR_MALFORMED,
	      "a null job");
	CHECK(fzn_catalog_refile_capture(&cat, &job, NULL, 8) == FZN_CATALOG_ERR_MALFORMED,
	      "null rows");
	CHECK(fzn_catalog_refile_capture(&cat, &job, moves, 0) == FZN_CATALOG_ERR_MALFORMED,
	      "a job that can hold nothing");
	/* FULL IS LOUD: a capture holding some of the filed nodes would move
	 * some of the files and leave the rest under stale paths. */
	CHECK(fzn_catalog_refile_capture(&cat, &job, one, 1) == FZN_CATALOG_ERR_FULL,
	      "a capture too small to hold every filed node reported success");

	/* A JOB THAT WAS NEVER CAPTURED IS NOT A JOB. */
	CHECK(fzn_catalog_refile_begin(&cat, &fresh) == FZN_CATALOG_ERR_MALFORMED,
	      "an uncaptured job began");
	CHECK(fzn_catalog_refile_advance(&fresh) == FZN_CATALOG_ERR_MALFORMED,
	      "an uncaptured job advanced");
	CHECK(fzn_catalog_refile_progress(&fresh, &done, &total) == FZN_CATALOG_ERR_MALFORMED,
	      "an uncaptured job reported progress");
	CHECK(fzn_catalog_refile_end(&cat, &fresh) == FZN_CATALOG_ERR_MALFORMED,
	      "an uncaptured job ended");

	REQUIRE(fzn_catalog_refile_capture(&cat, &job, moves, 8) == FZN_CATALOG_OK, "capture");
	CHECK(fzn_catalog_refile_progress(&job, NULL, &total) == FZN_CATALOG_ERR_MALFORMED,
	      "a null done");
	CHECK(fzn_catalog_refile_progress(&job, &done, NULL) == FZN_CATALOG_ERR_MALFORMED,
	      "a null total");
	CHECK(fzn_catalog_refile_at(&cat, &job, NULL, was, 8, &was_len, now, 8, &now_len)
	              == FZN_CATALOG_ERR_MALFORMED, "a null node out");
	CHECK(fzn_catalog_refile_at(&cat, &job, &node, was, 8, NULL, now, 8, &now_len)
	              == FZN_CATALOG_ERR_MALFORMED, "a null was length");

	/* Capturing while a refile runs is refused: the arrangement it would
	 * snapshot is the one being moved out of. */
	REQUIRE(fzn_catalog_refile_begin(&cat, &job) == FZN_CATALOG_OK, "begin");
	CHECK(fzn_catalog_refile_capture(&cat, &fresh, moves, 8) == FZN_CATALOG_ERR_BUSY,
	      "a second capture was taken during a refile");
}

/* A capture needs a filing root, or every old path is empty and every file
 * reads as misplaced. */
/*
 * THE REFILE'S OWN WALK IS BOUNDED TOO, and it is a second walk rather than
 * the same one: it climbs the CAPTURED filing, which the catalogue no longer
 * holds. A cycle in what was captured is therefore expressible even when the
 * catalogue's current filing is a clean tree, so the bound has to be there
 * and has to be tested separately.
 */
static void test_the_captured_walk_is_bounded(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_move_t moves[8];
	fzn_catalog_refile_t job;
	fzn_catalog_t cat;
	fzn_catalog_id_t node, was[8], now[8];
	size_t was_len = 0, now_len = 0;

	/* A capture whose stored parents form a cycle: 0x05 was under 0x06 and
	 * 0x06 under 0x05, and the root is neither. */
	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x06), idp(0x05), ALICE, 1, 1) == FZN_CATALOG_OK, "a");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x05), idp(0x06), ALICE, 2, 1) == FZN_CATALOG_OK, "b");
	REQUIRE(fzn_catalog_file_under(&cat, idp(0x06), idp(0x05)) == FZN_CATALOG_OK, "file a");
	REQUIRE(fzn_catalog_file_under(&cat, idp(0x05), idp(0x06)) == FZN_CATALOG_OK, "file b");
	REQUIRE(fzn_catalog_filing_root(&cat, idp(0x01)) == FZN_CATALOG_OK, "root");
	REQUIRE(fzn_catalog_refile_capture(&cat, &job, moves, 8) == FZN_CATALOG_OK, "capture");
	REQUIRE(job.used == 2, "the cycle was not captured");

	REQUIRE(fzn_catalog_refile_begin(&cat, &job) == FZN_CATALOG_OK, "begin");
	/* IT MUST RETURN rather than run to the end of the stack buffer. An
	 * empty old path is the honest answer: a file whose old location cannot
	 * be named is one the consumer cannot move, and saying so beats
	 * walking off the array. */
	REQUIRE(fzn_catalog_refile_at(&cat, &job, &node, was, 8, &was_len, now, 8, &now_len)
	                == FZN_CATALOG_OK, "the step");
	CHECK(was_len == 0, "a captured filing cycle produced a path of %zu", was_len);

	REQUIRE(fzn_catalog_refile_advance(&job) == FZN_CATALOG_OK, "one");
	REQUIRE(fzn_catalog_refile_advance(&job) == FZN_CATALOG_OK, "two");
	REQUIRE(fzn_catalog_refile_end(&cat, &job) == FZN_CATALOG_OK, "end");
}

static void test_a_capture_needs_a_root(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_move_t moves[8];
	fzn_catalog_refile_t job;
	fzn_catalog_t cat;

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x01), idp(0x02), ALICE, 1, 1) == FZN_CATALOG_OK, "a");
	REQUIRE(fzn_catalog_file_under(&cat, idp(0x01), idp(0x02)) == FZN_CATALOG_OK, "file");
	CHECK(fzn_catalog_refile_capture(&cat, &job, moves, 8) == FZN_CATALOG_ERR_ABSENT,
	      "a capture with no filing root reported success");
}

/* ---- the filesystem seam ------------------------------------------------ */

/* A consumer's naming and moving, recorded so the suite can read them back. */
struct fs_stub {
	char names[8][64];   /* what each id seeds to; index is the seed byte */
	int name_fails;
	int name_empty;
	int move_fails;
	int moves;
	char last_was[FZN_CATALOG_PATH_MAX];
	char last_now[FZN_CATALOG_PATH_MAX];
	char forge[64];      /* a name to hand back for id 0x03, if set */
};

static int fs_name(void *ctx, const fzn_catalog_id_t *node, char *out, size_t cap)
{
	struct fs_stub *st = (struct fs_stub *)ctx;
	unsigned seed = node->b[0];

	if (st->name_fails)
		return 0;
	/* A CONSUMER THAT SUCCEEDS AND NAMES NOTHING is not the same as one
	 * that refuses: it reports a name, and the name is unusable. */
	if (st->name_empty) {
		if (cap > 0)
			out[0] = '\0';
		return 1;
	}
	if (seed == 0x03u && st->forge[0]) {
		snprintf(out, cap, "%s", st->forge);
		return 1;
	}
	snprintf(out, cap, "n%02x", seed);
	return 1;
}

static int fs_move(void *ctx, const char *was, const char *now)
{
	struct fs_stub *st = (struct fs_stub *)ctx;

	if (st->move_fails)
		return 0;
	st->moves++;
	snprintf(st->last_was, sizeof(st->last_was), "%s", was);
	snprintf(st->last_now, sizeof(st->last_now), "%s", now);
	return 1;
}

static void fs_init(struct fs_stub *st, fzn_catalog_fs_ops_t *ops)
{
	memset(st, 0, sizeof(*st));
	ops->name = fs_name;
	ops->move = fs_move;
	ops->ctx = st;
}

/* The library joins; the consumer names. */
static void test_a_path_is_the_segments_joined(void)
{
	struct fs_stub st;
	fzn_catalog_fs_ops_t ops;
	fzn_catalog_id_t ids[3];
	char out[FZN_CATALOG_PATH_MAX];

	fs_init(&st, &ops);
	ids[0] = id(0x01);
	ids[1] = id(0x02);
	ids[2] = id(0x03);

	REQUIRE(fzn_catalog_path_of(ids, 3, &ops, out, sizeof(out)) == FZN_CATALOG_OK,
	        "a path would not build");
	CHECK(strcmp(out, "n01/n02/n03") == 0, "the path is \"%s\"", out);
	REQUIRE(fzn_catalog_path_of(ids, 1, &ops, out, sizeof(out)) == FZN_CATALOG_OK,
	        "a one-segment path would not build");
	CHECK(strcmp(out, "n01") == 0, "a single segment gained a separator: \"%s\"", out);

	/* No ids is no path, rather than a name for the working directory. */
	CHECK(fzn_catalog_path_of(ids, 0, &ops, out, sizeof(out)) == FZN_CATALOG_ERR_PATH,
	      "an empty run produced a path");
}

/*
 * A SEGMENT MAY NOT FORGE A LEVEL OF THE TREE. A consumer naming a node from
 * data hands back whatever it was told, and a name with a separator in it
 * puts the file where nobody filed it -- the same shape as a log body with a
 * newline drawing an entry nobody signed. sec 149.
 */
static void test_a_name_cannot_forge_a_level(void)
{
	struct fs_stub st;
	fzn_catalog_fs_ops_t ops;
	fzn_catalog_id_t ids[2];
	char out[FZN_CATALOG_PATH_MAX];

	fs_init(&st, &ops);
	ids[0] = id(0x01);
	ids[1] = id(0x03);

	/* THE CONTROL: an ordinary name builds. */
	REQUIRE(fzn_catalog_path_of(ids, 2, &ops, out, sizeof(out)) == FZN_CATALOG_OK,
	        "the control path would not build");

	snprintf(st.forge, sizeof(st.forge), "%s", "a/b");
	CHECK(fzn_catalog_path_of(ids, 2, &ops, out, sizeof(out)) == FZN_CATALOG_ERR_PATH,
	      "a name carrying a separator was accepted");
	snprintf(st.forge, sizeof(st.forge), "%s", "..");
	CHECK(fzn_catalog_path_of(ids, 2, &ops, out, sizeof(out)) == FZN_CATALOG_ERR_PATH,
	      "a name that walks out of the filing root was accepted");
	snprintf(st.forge, sizeof(st.forge), "%s", ".");
	CHECK(fzn_catalog_path_of(ids, 2, &ops, out, sizeof(out)) == FZN_CATALOG_ERR_PATH,
	      "a name of \".\" was accepted");
	snprintf(st.forge, sizeof(st.forge), "%s", "");
	st.forge[0] = ' ';
	st.forge[1] = '\0';
	CHECK(fzn_catalog_path_of(ids, 2, &ops, out, sizeof(out)) == FZN_CATALOG_OK,
	      "an ordinary odd name was refused, so the guards are too wide");

	/* AN EMPTY NAME IS NOT A NAME, and a consumer that returns success
	 * while naming nothing would otherwise give a path with an empty
	 * segment -- "a//b", which names a different place on some systems and
	 * nothing at all on others. */
	st.forge[0] = '\0';
	st.name_empty = 1;
	CHECK(fzn_catalog_path_of(ids, 2, &ops, out, sizeof(out)) == FZN_CATALOG_ERR_PATH,
	      "a consumer that named nothing was taken at its word");
	st.name_empty = 0;

	/* A name the consumer will not give is the backend refusing, which is a
	 * different answer from a name it gave that cannot be used. */
	st.name_fails = 1;
	CHECK(fzn_catalog_path_of(ids, 2, &ops, out, sizeof(out)) == FZN_CATALOG_ERR_BACKEND,
	      "a consumer that would not name a node was reported as a bad path");
}

static void test_a_path_is_bounded(void)
{
	struct fs_stub st;
	fzn_catalog_fs_ops_t ops;
	fzn_catalog_id_t ids[3];
	char out[FZN_CATALOG_PATH_MAX];
	char small[8];

	fs_init(&st, &ops);
	ids[0] = id(0x01);
	ids[1] = id(0x02);
	ids[2] = id(0x03);

	memset(small, 0x5a, sizeof(small));
	CHECK(fzn_catalog_path_of(ids, 3, &ops, small, sizeof(small)) == FZN_CATALOG_ERR_PATH,
	      "a path was built into a buffer too small for it");
	CHECK(small[0] == 0x5a, "a refused path wrote a truncated one");

	/* A segment longer than the bound is refused rather than cut. */
	memset(st.forge, 'x', sizeof(st.forge) - 1u);
	st.forge[sizeof(st.forge) - 1u] = '\0';
	CHECK(fzn_catalog_path_of(ids, 3, &ops, out, sizeof(out)) == FZN_CATALOG_OK,
	      "a long but legal segment was refused");
	CHECK(fzn_catalog_path_of(NULL, 3, &ops, out, sizeof(out)) == FZN_CATALOG_ERR_MALFORMED,
	      "a null run");
	CHECK(fzn_catalog_path_of(ids, 3, NULL, out, sizeof(out)) == FZN_CATALOG_ERR_MALFORMED,
	      "null ops");
	CHECK(fzn_catalog_path_of(ids, 3, &ops, NULL, sizeof(out)) == FZN_CATALOG_ERR_MALFORMED,
	      "a null buffer");
	CHECK(fzn_catalog_path_of(ids, 3, &ops, out, 0) == FZN_CATALOG_ERR_MALFORMED,
	      "a zero bound");
}

/*
 * THE STEP ADVANCES ONLY ON A SUCCESSFUL MOVE, which is what this seam is
 * for: sec 148's crash ordering stops being a sentence a consumer has to read
 * and becomes the shape of the code.
 */
static void test_a_step_advances_only_when_the_file_moved(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_move_t moves[8];
	fzn_catalog_refile_t job;
	fzn_catalog_t cat;
	struct fs_stub st;
	fzn_catalog_fs_ops_t ops;
	size_t done = 0, total = 0;

	fs_init(&st, &ops);
	build_filed(&cat, rows, 8);
	REQUIRE(fzn_catalog_refile_capture(&cat, &job, moves, 8) == FZN_CATALOG_OK, "capture");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x01), idp(0x03), ALICE, 3, 1) == FZN_CATALOG_OK,
	        "the new membership");
	REQUIRE(fzn_catalog_file_under(&cat, idp(0x01), idp(0x03)) == FZN_CATALOG_OK, "refile it");
	REQUIRE(fzn_catalog_refile_begin(&cat, &job) == FZN_CATALOG_OK, "begin");

	/* A MOVE THAT FAILS LEAVES THE CURSOR WHERE IT WAS, so a retry repeats
	 * the step rather than skipping a file. */
	st.move_fails = 1;
	CHECK(fzn_catalog_refile_step(&cat, &job, &ops) == FZN_CATALOG_ERR_BACKEND,
	      "a failing move reported success");
	REQUIRE(fzn_catalog_refile_progress(&job, &done, &total) == FZN_CATALOG_OK, "progress");
	CHECK(done == 0, "a failed move advanced the cursor, so a file would be skipped");
	CHECK(st.moves == 0, "the stub counted a move it refused");

	/* And with it working, the step names both paths and advances. */
	st.move_fails = 0;
	CHECK(fzn_catalog_refile_step(&cat, &job, &ops) == FZN_CATALOG_OK, "the first step");
	REQUIRE(fzn_catalog_refile_progress(&job, &done, &total) == FZN_CATALOG_OK, "progress");
	CHECK(done == 1, "a successful move did not advance the cursor");
	CHECK(st.moves == 1, "the move was not made");

	/* The second step is the one that actually moves: root/n02/n03 becomes
	 * root/n03. */
	CHECK(fzn_catalog_refile_step(&cat, &job, &ops) == FZN_CATALOG_OK, "the second step");
	CHECK(strcmp(st.last_was, "n01/n02/n03") == 0, "the old path is \"%s\"", st.last_was);
	CHECK(strcmp(st.last_now, "n01/n03") == 0, "the new path is \"%s\"", st.last_now);

	/* Past the end is how a loop stops. */
	CHECK(fzn_catalog_refile_step(&cat, &job, &ops) == FZN_CATALOG_ERR_ABSENT,
	      "the step did not report the work finished");
	CHECK(fzn_catalog_refile_end(&cat, &job) == FZN_CATALOG_OK, "end");
}

/* A file this host cannot place must be reported, not counted as done. */
static void test_an_unnameable_node_does_not_advance(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_move_t moves[8];
	fzn_catalog_refile_t job;
	fzn_catalog_t cat;
	struct fs_stub st;
	fzn_catalog_fs_ops_t ops;
	size_t done = 0, total = 0;

	fs_init(&st, &ops);
	build_filed(&cat, rows, 8);
	REQUIRE(fzn_catalog_refile_capture(&cat, &job, moves, 8) == FZN_CATALOG_OK, "capture");
	REQUIRE(fzn_catalog_refile_begin(&cat, &job) == FZN_CATALOG_OK, "begin");

	st.name_fails = 1;
	CHECK(fzn_catalog_refile_step(&cat, &job, &ops) == FZN_CATALOG_ERR_BACKEND,
	      "an unnameable node was stepped over");
	REQUIRE(fzn_catalog_refile_progress(&job, &done, &total) == FZN_CATALOG_OK, "progress");
	CHECK(done == 0, "an unnameable node advanced the cursor");
	CHECK(st.moves == 0, "a move was attempted for a node nobody could name");

	/* A forged name is a PATH error rather than a backend one, and equally
	 * does not advance. */
	st.name_fails = 0;
	snprintf(st.forge, sizeof(st.forge), "%s", "../escape");
	/* 0x02 comes first and is nameable, so step once to reach 0x03. */
	REQUIRE(fzn_catalog_refile_step(&cat, &job, &ops) == FZN_CATALOG_OK, "the first step");
	CHECK(fzn_catalog_refile_step(&cat, &job, &ops) == FZN_CATALOG_ERR_PATH,
	      "a forged name was used as a path");
	REQUIRE(fzn_catalog_refile_progress(&job, &done, &total) == FZN_CATALOG_OK, "progress");
	CHECK(done == 1, "a refused path advanced the cursor");
}

static void test_the_seam_caller_bugs_are_refused(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_move_t moves[8];
	fzn_catalog_refile_t job;
	fzn_catalog_t cat;
	struct fs_stub st;
	fzn_catalog_fs_ops_t ops, half;

	fs_init(&st, &ops);
	build_filed(&cat, rows, 8);
	REQUIRE(fzn_catalog_refile_capture(&cat, &job, moves, 8) == FZN_CATALOG_OK, "capture");
	REQUIRE(fzn_catalog_refile_begin(&cat, &job) == FZN_CATALOG_OK, "begin");

	CHECK(fzn_catalog_refile_step(&cat, &job, NULL) == FZN_CATALOG_ERR_MALFORMED,
	      "null ops stepped");
	half = ops;
	half.name = NULL;
	CHECK(fzn_catalog_refile_step(&cat, &job, &half) == FZN_CATALOG_ERR_MALFORMED,
	      "ops with no name stepped");
	half = ops;
	half.move = NULL;
	CHECK(fzn_catalog_refile_step(&cat, &job, &half) == FZN_CATALOG_ERR_MALFORMED,
	      "ops with no move stepped");
	CHECK(st.moves == 0, "a refused step moved something");
}

static void test_the_errors_render(void)
{
	CHECK(fzn_catalog_err_str(FZN_CATALOG_OK)[0] != '\0', "OK renders empty");
	CHECK(fzn_catalog_err_str(FZN_CATALOG_ERR_MALFORMED)[0] != '\0', "MALFORMED renders empty");
	CHECK(fzn_catalog_err_str(FZN_CATALOG_ERR_FULL)[0] != '\0', "FULL renders empty");
	CHECK(fzn_catalog_err_str(FZN_CATALOG_ERR_STALE)[0] != '\0', "STALE renders empty");
	CHECK(fzn_catalog_err_str(FZN_CATALOG_ERR_SHAPE)[0] != '\0', "SHAPE renders empty");
	CHECK(fzn_catalog_err_str(FZN_CATALOG_ERR_ABSENT)[0] != '\0', "ABSENT renders empty");
	CHECK(fzn_catalog_err_str(FZN_CATALOG_ERR_BUSY)[0] != '\0', "BUSY renders empty");
	CHECK(fzn_catalog_err_str(FZN_CATALOG_ERR_BACKEND)[0] != '\0', "BACKEND renders empty");
	CHECK(fzn_catalog_err_str(FZN_CATALOG_ERR_PATH)[0] != '\0', "PATH renders empty");
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
	memset(SUBJECT, 0x51, sizeof(SUBJECT));

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
	test_an_edge_round_trips_through_a_record();
	test_an_unlink_travels();
	test_every_content_kind_round_trips();
	test_a_non_canonical_body_is_refused();
	test_the_encoder_normalises_present();
	test_the_wire_caller_bugs_are_refused();
	test_a_node_is_filed_in_exactly_one_of_its_sets();
	test_a_filing_needs_a_membership();
	test_unlinking_clears_the_filing();
	test_a_filing_does_not_come_off_the_wire();
	test_a_path_runs_from_the_root_down();
	test_a_path_that_does_not_reach_the_root_is_none();
	test_the_filing_caller_bugs_are_refused();
	test_a_refile_names_both_paths();
	test_the_moves_are_sorted_by_id();
	test_only_progress_answers_during_a_refile();
	test_a_refile_resumes_after_a_restart();
	test_an_unfinished_refile_cannot_be_ended();
	test_the_refile_caller_bugs_are_refused();
	test_the_captured_walk_is_bounded();
	test_a_capture_needs_a_root();
	test_a_path_is_the_segments_joined();
	test_a_name_cannot_forge_a_level();
	test_a_path_is_bounded();
	test_a_step_advances_only_when_the_file_moved();
	test_an_unnameable_node_does_not_advance();
	test_the_seam_caller_bugs_are_refused();
	test_the_errors_render();
	test_the_suite_can_tell_pass_from_fail();

	printf("catalog_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
