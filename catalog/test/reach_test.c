/* Tests for catalog/reach.c: what nothing links, and why that can be
 * believed.
 *
 * THE CASES THIS FILE EXISTS FOR are the ones that decide whether the answer
 * may be acted on at all, not the graph walk. project.md sec 156.
 *
 *   - A caller that has not accounted for an issuer this catalogue depends on
 *     is refused, and told which issuer. This is the whole discriminator
 *     between "nobody links this" and "I have not caught up", and sec 155 was
 *     right that without it the module would delete on the strength of a
 *     record this host has not received.
 *   - A tombstone is not a node and does not reach. An absent edge is kept so
 *     a stale link cannot resurrect a membership; if it made its child a node
 *     as well, unlinking something would turn it into permanent garbage this
 *     walk kept proposing.
 *   - Running out of scratch REFUSES where running out of output counts. The
 *     first makes reachable nodes look unreachable, which is a proposal to
 *     delete live data; the second only proposes less.
 */

#include "../reach.h"

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
	fprintf(stderr, "  FAIL reach_test.c:%d: ", line);
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
static uint8_t BOB[FZN_PUBKEY_LEN];

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

/* A frontier that accounts for one issuer at a generous position, which is
 * the ordinary case: a caller that has caught up. */
static fzn_catalog_frontier_t vouch(const uint8_t *issuer, uint64_t received)
{
	fzn_catalog_frontier_t f;

	memset(&f, 0, sizeof(f));
	memcpy(f.issuer, issuer, FZN_PUBKEY_LEN);
	f.received = received;
	return f;
}

static int holds_id(const fzn_catalog_id_t *list, size_t count, uint8_t seed)
{
	fzn_catalog_id_t want = id(seed);
	size_t i;

	for (i = 0; i < count; i++) {
		if (memcmp(list[i].b, want.b, FZN_CATALOG_ID_LEN) == 0)
			return 1;
	}

	return 0;
}

/* ------------------------------------------------------------------------ */

/* THE WALK, AND THE CASE THAT MOTIVATES THE WHOLE MODULE: content nobody
 * links. A node with a content row and no edge at all is exactly the garbage
 * retention cannot name, because nobody ever said anything about it. */
static void test_what_the_roots_do_not_reach(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_id_t scratch[16];
	fzn_catalog_id_t out[8];
	fzn_catalog_id_t roots[1];
	fzn_catalog_frontier_t front[1];
	fzn_catalog_reach_t plan;
	fzn_catalog_t cat;
	fzn_catalog_entry_t e;

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "the content table would not init");

	/* root -> 0x10 -> 0x11, and 0x20 hanging off nothing. */
	REQUIRE(fzn_catalog_assert(&cat, idp(0x01), idp(0x10), ALICE, 1, 1) == FZN_CATALOG_OK,
	        "a link was refused");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x10), idp(0x11), ALICE, 2, 1) == FZN_CATALOG_OK,
	        "a link was refused");
	memset(&e, 0, sizeof(e));
	e.id = id(0x20);
	e.kind = FZN_CATALOG_CONTENT_BLOB;
	memset(e.root, 0xa0, sizeof(e.root));
	e.blob_len = 100;
	memcpy(e.issuer, ALICE, FZN_PUBKEY_LEN);
	e.seq = 3;
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "content was refused");

	roots[0] = id(0x01);
	front[0] = vouch(ALICE, 99);

	REQUIRE(fzn_catalog_unreachable(&cat, roots, 1, front, 1, scratch, 16, out, 8, &plan) ==
	                FZN_CATALOG_OK,
	        "the walk was refused");
	CHECK(plan.reachable == 3, "root, 0x10 and 0x11 are reachable; found %zu",
	      plan.reachable);
	CHECK(plan.unreachable == 1 && holds_id(out, plan.unreachable, 0x20),
	      "content nobody links was not proposed: %zu unreachable", plan.unreachable);
	CHECK(plan.roots == 1, "the root count was not reported");

	/* THE POPULATIONS SUM. Every known node is reachable or is not, and
	 * `fzn_catalog_nodes` is what a caller sizes its arrays from -- so if
	 * these disagreed, a caller sizing correctly could still overflow. */
	CHECK(plan.reachable + plan.unreachable + plan.truncated == fzn_catalog_nodes(&cat),
	      "%zu reachable + %zu unreachable + %zu truncated is not the %zu nodes this "
	      "catalogue knows",
	      plan.reachable, plan.unreachable, plan.truncated, fzn_catalog_nodes(&cat));
}

/* THE DISCRIMINATOR. A caller that has not said how far it has read from an
 * issuer the catalogue depends on is refused, and told which -- because the
 * alternative is answering a question about garbage from a partial view. */
static void test_an_unaccounted_issuer_is_refused_by_name(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_id_t scratch[16];
	fzn_catalog_id_t out[8];
	fzn_catalog_id_t roots[1];
	fzn_catalog_frontier_t front[2];
	fzn_catalog_reach_t plan;
	fzn_catalog_t cat;

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x01), idp(0x10), ALICE, 1, 1) == FZN_CATALOG_OK,
	        "a link was refused");
	/* BOB has said something about this catalogue, so BOB is a dependency
	 * whatever the caller happens to be following. */
	REQUIRE(fzn_catalog_assert(&cat, idp(0x01), idp(0x11), BOB, 1, 1) == FZN_CATALOG_OK,
	        "a link was refused");

	roots[0] = id(0x01);
	front[0] = vouch(ALICE, 99);

	CHECK(fzn_catalog_unreachable(&cat, roots, 1, front, 1, scratch, 16, out, 8, &plan) ==
	              FZN_CATALOG_ERR_INCOMPLETE,
	      "a walk answered while an issuer this catalogue depends on was unaccounted "
	      "for");
	CHECK(plan.unvouched_set && memcmp(plan.unvouched, BOB, FZN_PUBKEY_LEN) == 0,
	      "the refusal did not name the issuer, so a caller cannot act on it");
	CHECK(plan.unreachable == 0,
	      "a refused walk proposed %zu deletions anyway", plan.unreachable);

	/* Accounting for both answers. */
	front[1] = vouch(BOB, 99);
	REQUIRE(fzn_catalog_unreachable(&cat, roots, 1, front, 2, scratch, 16, out, 8, &plan) ==
	                FZN_CATALOG_OK,
	        "a complete frontier was still refused");
	CHECK(plan.unvouched_set == 0, "a successful walk named an unvouched issuer");
	CHECK(plan.reachable == 3 && plan.unreachable == 0, "the walk lost a node");

	/* A FRONTIER BEHIND THE CATALOGUE'S OWN APPLIED SEQUENCE is incoherent:
	 * the caller has applied a record it says it has not read, so whatever
	 * produced the frontier is not describing this catalogue. */
	front[0] = vouch(ALICE, 0);
	CHECK(fzn_catalog_unreachable(&cat, roots, 1, front, 2, scratch, 16, out, 8, &plan) ==
	              FZN_CATALOG_ERR_INCOMPLETE,
	      "a frontier behind this catalogue's own applied sequence was accepted");
	CHECK(plan.unvouched_set && memcmp(plan.unvouched, ALICE, FZN_PUBKEY_LEN) == 0,
	      "the incoherent frontier did not name the issuer");
}

/* A TOMBSTONE IS NOT A NODE AND DOES NOT REACH. sec 144 keeps an absent edge
 * so a stale link cannot resurrect the membership; if it also made its child
 * a node, unlinking something would turn it into permanent garbage this walk
 * kept proposing -- and its author would still have to be vouched for. */
static void test_an_unlinked_child_stops_being_a_node(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_id_t scratch[16];
	fzn_catalog_id_t out[8];
	fzn_catalog_id_t roots[1];
	fzn_catalog_frontier_t front[1];
	fzn_catalog_reach_t plan;
	fzn_catalog_t cat;

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x01), idp(0x10), ALICE, 1, 1) == FZN_CATALOG_OK,
	        "a link was refused");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x01), idp(0x20), ALICE, 2, 1) == FZN_CATALOG_OK,
	        "a link was refused");

	roots[0] = id(0x01);
	front[0] = vouch(ALICE, 99);
	REQUIRE(fzn_catalog_unreachable(&cat, roots, 1, front, 1, scratch, 16, out, 8, &plan) ==
	                FZN_CATALOG_OK,
	        "the walk was refused");
	REQUIRE(plan.reachable == 3, "expected three reachable, found %zu", plan.reachable);

	/* Unlink 0x20. The row stays as a tombstone. */
	REQUIRE(fzn_catalog_assert(&cat, idp(0x01), idp(0x20), ALICE, 3, 0) == FZN_CATALOG_OK,
	        "an unlink was refused");
	REQUIRE(fzn_catalog_unreachable(&cat, roots, 1, front, 1, scratch, 16, out, 8, &plan) ==
	                FZN_CATALOG_OK,
	        "the walk was refused");
	CHECK(plan.reachable == 2, "the unlinked child is still reachable: %zu",
	      plan.reachable);
	CHECK(plan.unreachable == 0,
	      "an unlinked child came back as garbage, so every unlink would leave a node "
	      "this walk proposes for ever");
	CHECK(fzn_catalog_nodes(&cat) == 2, "a tombstone still counts as a node: %zu",
	      fzn_catalog_nodes(&cat));

	/* AND THE TOMBSTONE'S AUTHOR IS STILL A DEPENDENCY. Somebody asserted
	 * the unlink and this host applied it, so a frontier that does not
	 * account for them is still short. */
	{
		fzn_catalog_source_t sources[4];
		size_t dropped = 0;
		size_t n = fzn_catalog_sources(&cat, sources, 4, &dropped);

		CHECK(n == 1 && dropped == 0, "expected one source, found %zu", n);
		CHECK(sources[0].seq == 3,
		      "the highest applied sequence was not the tombstone's: %llu",
		      (unsigned long long)sources[0].seq);
	}
}

/* WHO THIS CATALOGUE DEPENDS ON, which is the fact only the catalogue holds
 * and the input to "am I caught up". */
static void test_sources_names_every_issuer_once(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_source_t sources[4];
	fzn_catalog_source_t one[1];
	fzn_catalog_t cat;
	fzn_catalog_entry_t e;
	size_t dropped = 0;
	size_t n;

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "the content table would not init");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x01), idp(0x10), ALICE, 1, 1) == FZN_CATALOG_OK,
	        "a link was refused");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x01), idp(0x11), ALICE, 5, 1) == FZN_CATALOG_OK,
	        "a link was refused");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x01), idp(0x12), BOB, 2, 1) == FZN_CATALOG_OK,
	        "a link was refused");
	memset(&e, 0, sizeof(e));
	e.id = id(0x10);
	e.kind = FZN_CATALOG_CONTENT_NONE;
	memcpy(e.issuer, BOB, FZN_PUBKEY_LEN);
	e.seq = 7;
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "content was refused");

	n = fzn_catalog_sources(&cat, sources, 4, &dropped);
	CHECK(n == 2 && dropped == 0, "expected two issuers, found %zu (%zu dropped)", n,
	      dropped);
	CHECK(sources[0].seq == 5 && sources[0].rows == 2,
	      "the first issuer's highest applied sequence or row count is wrong: %llu, %zu",
	      (unsigned long long)sources[0].seq, sources[0].rows);
	CHECK(sources[1].seq == 7 && sources[1].rows == 2,
	      "the second issuer's rows were not counted across tables: %llu, %zu",
	      (unsigned long long)sources[1].seq, sources[1].rows);

	/* AN OVERFLOW IS REPORTED, because the scan runs in table order: a host
	 * that overflows drops the same issuers every time and would never
	 * learn it depends on them. */
	n = fzn_catalog_sources(&cat, one, 1, &dropped);
	CHECK(n == 1 && dropped == 1, "an overflowing scan reported %zu written, %zu dropped",
	      n, dropped);
	CHECK(fzn_catalog_sources(&cat, sources, 4, NULL) == 0,
	      "a scan with nowhere to report drops wrote issuers anyway");
}

/* SCRATCH REFUSES WHERE OUTPUT COUNTS, and the asymmetry is the module's
 * whole safety argument in one pair of cases. */
static void test_scratch_refuses_and_output_truncates(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_id_t scratch[16];
	fzn_catalog_id_t out[8];
	fzn_catalog_id_t roots[1];
	fzn_catalog_frontier_t front[1];
	fzn_catalog_reach_t plan;
	fzn_catalog_t cat;
	size_t i;

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	/* A chain of four under the root, and three orphans. */
	REQUIRE(fzn_catalog_assert(&cat, idp(0x01), idp(0x10), ALICE, 1, 1) == FZN_CATALOG_OK,
	        "a link was refused");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x10), idp(0x11), ALICE, 2, 1) == FZN_CATALOG_OK,
	        "a link was refused");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x11), idp(0x12), ALICE, 3, 1) == FZN_CATALOG_OK,
	        "a link was refused");
	for (i = 0; i < 3; i++) {
		REQUIRE(fzn_catalog_assert(&cat, idp((uint8_t)(0x30 + i)),
		                           idp((uint8_t)(0x40 + i)), ALICE, 4 + i,
		                           1) == FZN_CATALOG_OK,
		        "a link was refused");
	}

	roots[0] = id(0x01);
	front[0] = vouch(ALICE, 99);

	/* A SCRATCH TOO SMALL FOR THE REACHABLE SET IS A HARD REFUSAL. Counting
	 * it would leave reachable nodes looking unreachable, which is a
	 * proposal to delete live data -- the one failure direction this module
	 * must not have. */
	CHECK(fzn_catalog_unreachable(&cat, roots, 1, front, 1, scratch, 2, out, 8, &plan) ==
	              FZN_CATALOG_ERR_FULL,
	      "a walk that ran out of scratch answered anyway");
	CHECK(plan.unreachable == 0, "a refused walk proposed %zu deletions",
	      plan.unreachable);

	/* A SHORT OUTPUT ONLY PROPOSES LESS, so it is counted. */
	REQUIRE(fzn_catalog_unreachable(&cat, roots, 1, front, 1, scratch, 16, out, 2, &plan) ==
	                FZN_CATALOG_OK,
	        "a truncated proposal was refused, though it is not an error");
	CHECK(plan.unreachable == 2 && plan.truncated == 4,
	      "%zu written and %zu truncated does not describe six unreachable nodes",
	      plan.unreachable, plan.truncated);
	CHECK(plan.reachable + plan.unreachable + plan.truncated == fzn_catalog_nodes(&cat),
	      "the populations do not sum under truncation");

	/* AND A SCRATCH SIZED BY `fzn_catalog_nodes` CANNOT OVERFLOW, which is
	 * the contract that makes the refusal above avoidable rather than a
	 * trap. */
	REQUIRE(fzn_catalog_nodes(&cat) <= 16, "this test cannot size its own scratch");
	CHECK(fzn_catalog_unreachable(&cat, roots, 1, front, 1, scratch,
	                              fzn_catalog_nodes(&cat), out, 8, &plan) ==
	              FZN_CATALOG_OK,
	      "a scratch sized by fzn_catalog_nodes overflowed, so the sizing contract is "
	      "wrong");
}

/* A ROOT THE CATALOGUE DOES NOT KNOW, AND NO ROOTS AT ALL, both refuse.
 * Either would otherwise report the whole catalogue as garbage from a typo,
 * and this is the one module whose answer gets acted on by deleting. */
static void test_a_bad_root_cannot_condemn_everything(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_id_t scratch[16];
	fzn_catalog_id_t out[8];
	fzn_catalog_id_t roots[1];
	fzn_catalog_frontier_t front[1];
	fzn_catalog_reach_t plan;
	fzn_catalog_t cat;

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x01), idp(0x10), ALICE, 1, 1) == FZN_CATALOG_OK,
	        "a link was refused");
	front[0] = vouch(ALICE, 99);

	roots[0] = id(0xff);
	CHECK(fzn_catalog_unreachable(&cat, roots, 1, front, 1, scratch, 16, out, 8, &plan) ==
	              FZN_CATALOG_ERR_ABSENT,
	      "a root this catalogue does not know was walked from, so a typo condemns "
	      "everything");
	CHECK(plan.unreachable == 0, "a refused walk proposed %zu deletions",
	      plan.unreachable);

	roots[0] = id(0x01);
	CHECK(fzn_catalog_unreachable(&cat, roots, 0, front, 1, scratch, 16, out, 8, &plan) ==
	              FZN_CATALOG_ERR_MALFORMED,
	      "a walk with no roots at all answered, which condemns the whole catalogue");
}

/* A JOB HOLDS THIS TOO. sec 149's rule reaches every reader of the catalogue,
 * and a proposal computed mid-refile would be about an arrangement that is
 * being changed. */
static void test_a_job_holds_the_walk_too(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_id_t scratch[16];
	fzn_catalog_id_t out[8];
	fzn_catalog_id_t roots[1];
	fzn_catalog_frontier_t front[1];
	fzn_catalog_reach_t plan;
	fzn_catalog_t cat;

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x01), idp(0x10), ALICE, 1, 1) == FZN_CATALOG_OK,
	        "a link was refused");
	roots[0] = id(0x01);
	front[0] = vouch(ALICE, 99);

	cat.busy_with = FZN_CATALOG_JOB_SWEEP;
	CHECK(fzn_catalog_unreachable(&cat, roots, 1, front, 1, scratch, 16, out, 8, &plan) ==
	              FZN_CATALOG_ERR_BUSY,
	      "a proposal was computed while a sweep held the catalogue");
	cat.busy_with = FZN_CATALOG_JOB_REFILE;
	CHECK(fzn_catalog_unreachable(&cat, roots, 1, front, 1, scratch, 16, out, 8, &plan) ==
	              FZN_CATALOG_ERR_BUSY,
	      "a proposal was computed while a refile held the catalogue");
	cat.busy_with = FZN_CATALOG_JOB_NONE;
	CHECK(fzn_catalog_unreachable(&cat, roots, 1, front, 1, scratch, 16, out, 8, &plan) ==
	              FZN_CATALOG_OK,
	      "the walk was still refused after the catalogue was given back");
}

/* A DIAMOND IS VISITED ONCE, and a cycle terminates. A membership DAG lets a
 * node have several parents -- that is sec 144's whole point -- so a walk
 * that re-enqueued on every path would revisit exponentially, and one that
 * followed a cycle would not stop at all. */
static void test_several_parents_and_a_cycle(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_id_t scratch[16];
	fzn_catalog_id_t out[8];
	fzn_catalog_id_t roots[1];
	fzn_catalog_frontier_t front[1];
	fzn_catalog_reach_t plan;
	fzn_catalog_t cat;

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	/* root -> a, root -> b, a -> d, b -> d, and d -> root. */
	REQUIRE(fzn_catalog_assert(&cat, idp(0x01), idp(0x10), ALICE, 1, 1) == FZN_CATALOG_OK,
	        "a link was refused");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x01), idp(0x11), ALICE, 2, 1) == FZN_CATALOG_OK,
	        "a link was refused");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x10), idp(0x20), ALICE, 3, 1) == FZN_CATALOG_OK,
	        "a link was refused");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x11), idp(0x20), ALICE, 4, 1) == FZN_CATALOG_OK,
	        "a link was refused");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x20), idp(0x01), ALICE, 5, 1) == FZN_CATALOG_OK,
	        "a link was refused");

	roots[0] = id(0x01);
	front[0] = vouch(ALICE, 99);
	REQUIRE(fzn_catalog_unreachable(&cat, roots, 1, front, 1, scratch, 16, out, 8, &plan) ==
	                FZN_CATALOG_OK,
	        "a walk over a diamond with a cycle in it was refused, or did not return");
	CHECK(plan.reachable == 4, "a node with two parents was counted twice: %zu",
	      plan.reachable);
	CHECK(plan.unreachable == 0, "the walk lost a node");
}

/* SEVERAL ROOTS, because a consumer may have more than one top-level set and
 * the filing root need not be among them. */
static void test_several_roots(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_id_t scratch[16];
	fzn_catalog_id_t out[8];
	fzn_catalog_id_t roots[2];
	fzn_catalog_frontier_t front[1];
	fzn_catalog_reach_t plan;
	fzn_catalog_t cat;

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x01), idp(0x10), ALICE, 1, 1) == FZN_CATALOG_OK,
	        "a link was refused");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x02), idp(0x20), ALICE, 2, 1) == FZN_CATALOG_OK,
	        "a link was refused");
	front[0] = vouch(ALICE, 99);

	roots[0] = id(0x01);
	REQUIRE(fzn_catalog_unreachable(&cat, roots, 1, front, 1, scratch, 16, out, 8, &plan) ==
	                FZN_CATALOG_OK,
	        "the walk was refused");
	CHECK(plan.unreachable == 2, "one root leaves the other tree unreachable: %zu",
	      plan.unreachable);

	roots[1] = id(0x02);
	REQUIRE(fzn_catalog_unreachable(&cat, roots, 2, front, 1, scratch, 16, out, 8, &plan) ==
	                FZN_CATALOG_OK,
	        "the walk was refused");
	CHECK(plan.unreachable == 0 && plan.reachable == 4,
	      "naming both roots left %zu unreachable", plan.unreachable);
	CHECK(plan.roots == 2, "the root count was not reported");
}

/* Arguments, and a plan zeroed before they are checked. */
static void test_arguments(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_id_t scratch[16];
	fzn_catalog_id_t out[8];
	fzn_catalog_id_t roots[1];
	fzn_catalog_frontier_t front[1];
	fzn_catalog_reach_t plan;
	fzn_catalog_t cat;

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x01), idp(0x10), ALICE, 1, 1) == FZN_CATALOG_OK,
	        "a link was refused");
	roots[0] = id(0x01);
	front[0] = vouch(ALICE, 99);

	REQUIRE(fzn_catalog_unreachable(&cat, roots, 1, front, 1, scratch, 16, out, 8, &plan) ==
	                FZN_CATALOG_OK,
	        "the walk was refused");
	REQUIRE(plan.reachable == 2, "the first walk found nothing to carry into the next");

	CHECK(fzn_catalog_unreachable(NULL, roots, 1, front, 1, scratch, 16, out, 8, &plan) ==
	              FZN_CATALOG_ERR_MALFORMED,
	      "a null catalogue was accepted");
	CHECK(plan.reachable == 0,
	      "a refused walk left the previous round's count, so a caller reading the plan "
	      "after an error reads a number about something else");
	CHECK(fzn_catalog_unreachable(&cat, NULL, 1, front, 1, scratch, 16, out, 8, &plan) ==
	              FZN_CATALOG_ERR_MALFORMED,
	      "a null root list was accepted");
	CHECK(fzn_catalog_unreachable(&cat, roots, 1, NULL, 1, scratch, 16, out, 8, &plan) ==
	              FZN_CATALOG_ERR_MALFORMED,
	      "a null frontier with a nonzero count was accepted");
	CHECK(fzn_catalog_unreachable(&cat, roots, 1, front, 1, NULL, 16, out, 8, &plan) ==
	              FZN_CATALOG_ERR_MALFORMED,
	      "a null scratch was accepted");
	CHECK(fzn_catalog_unreachable(&cat, roots, 1, front, 1, scratch, 0, out, 8, &plan) ==
	              FZN_CATALOG_ERR_MALFORMED,
	      "a scratch that can hold nothing was accepted");
	CHECK(fzn_catalog_unreachable(&cat, roots, 1, front, 1, scratch, 16, NULL, 8, &plan) ==
	              FZN_CATALOG_ERR_MALFORMED,
	      "a null output with a nonzero capacity was accepted");
	CHECK(fzn_catalog_unreachable(&cat, roots, 1, front, 1, scratch, 16, out, 8, NULL) ==
	              FZN_CATALOG_ERR_MALFORMED,
	      "nowhere to answer");

	/* AN EMPTY FRONTIER IS NOT MALFORMED -- it is a caller vouching for
	 * nothing, which is refused as INCOMPLETE the moment the catalogue
	 * depends on anybody. The distinction matters: one is a bad call and
	 * the other is a real answer with a next step. */
	CHECK(fzn_catalog_unreachable(&cat, roots, 1, NULL, 0, scratch, 16, out, 8, &plan) ==
	              FZN_CATALOG_ERR_INCOMPLETE,
	      "an empty frontier was read as a bad argument rather than as an unaccounted "
	      "dependency");

	CHECK(fzn_catalog_nodes(NULL) == 0, "a null catalogue counted nodes");
}

int main(void)
{
	memset(ALICE, 0xa1, sizeof(ALICE));
	memset(BOB, 0xb0, sizeof(BOB));

	test_what_the_roots_do_not_reach();
	test_an_unaccounted_issuer_is_refused_by_name();
	test_an_unlinked_child_stops_being_a_node();
	test_sources_names_every_issuer_once();
	test_scratch_refuses_and_output_truncates();
	test_a_bad_root_cannot_condemn_everything();
	test_a_job_holds_the_walk_too();
	test_several_parents_and_a_cycle();
	test_several_roots();
	test_arguments();

	printf("reach_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
