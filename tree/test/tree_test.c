/* WHAT THIS FILE IS TRYING TO BREAK.
 *
 * The interesting cases here are not "does a node parse". They are the three
 * places `tree.h` makes a promise that a naive implementation would quietly
 * fail:
 *
 *   - **A cyclic set must terminate.** Two nodes each claiming the other is
 *     the case a depth-first walk hangs on, and a hang is not a failure a
 *     test suite reports -- it is a suite that never finishes. So the cycle
 *     cases run before anything else, and the file says so when it starts,
 *     because a green line that never printed is the one failure mode this
 *     file cannot report about itself.
 *
 *   - **An unresolved conflict must show up TWICE.** A node claimed by two
 *     parents is the whole point of refusing to resolve, and an
 *     implementation that silently kept the first claim would pass every
 *     other test in this file.
 *
 *   - **Truncation must not look like an answer.** The children of a parent
 *     are sorted, so a full output array does not hold the first `cap` of
 *     them -- it holds `cap` of them in the order they happened to be
 *     admitted. The flag is the only honest report and the test asserts the
 *     flag rather than the contents.
 *
 * AND ORDER EXHAUSTION CARRIES ITS POSITIVE CONTROL. "No key exists between
 * these two" is satisfied by a function that always says so, so every
 * exhaustion case sits next to a neighbouring pair that does have room.
 */

#include "../tree.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void expect(int cond, const char *what)
{
	checks++;
	if (!cond) {
		failures++;
		fprintf(stderr, "  FAIL: %s\n", what);
	}
}

static void expect_err(fzn_tree_err_t got, fzn_tree_err_t want, const char *what)
{
	checks++;
	if (got != want) {
		failures++;
		fprintf(stderr, "  FAIL: %s -- got \"%s\", wanted \"%s\"\n",
		        what, fzn_tree_err_str(got), fzn_tree_err_str(want));
	}
}

/* Node ids that are easy to read in a failure message: id N is N in every
 * byte, so a wrong node names itself. Zero is never used, because all-zero
 * is the root and a node with that id would be its own parent's parent. */
static void id_fill(uint8_t out[FZN_TREE_ID_LEN], uint8_t n)
{
	memset(out, n, (size_t)FZN_TREE_ID_LEN);
}

static const uint8_t root_id[FZN_TREE_ID_LEN] = { 0 };

/* A node built directly rather than through a record, so that the structural
 * tests do not depend on a signer. `fzn_tree_open` is exercised separately
 * against a real record body below. */
static fzn_tree_node_t make(uint8_t *idbuf, uint8_t *parentbuf,
                            uint8_t id, uint8_t parent, uint64_t order)
{
	fzn_tree_node_t n;

	id_fill(idbuf, id);
	if (parent == 0u)
		memset(parentbuf, 0, (size_t)FZN_TREE_ID_LEN);
	else
		id_fill(parentbuf, parent);

	n.id = idbuf;
	n.parent = parentbuf;
	n.content = NULL;
	n.content_len = 0u;
	n.order = order;
	n.content_type = 0u;
	return n;
}

/* THE CASE THAT HANGS A NAIVE IMPLEMENTATION. 1 under 2 and 2 under 1, with
 * a third node genuinely under the root as the control -- without it, "the
 * walk terminated and marked nothing" would pass. */
static void test_a_cycle_terminates_and_loses_nothing(void)
{
	uint8_t ids[3][FZN_TREE_ID_LEN], parents[3][FZN_TREE_ID_LEN];
	fzn_tree_node_t nodes[3];
	uint8_t mark[3];
	fzn_tree_walk_t walk;

	nodes[0] = make(ids[0], parents[0], 1u, 2u, 10u);
	nodes[1] = make(ids[1], parents[1], 2u, 1u, 20u);
	nodes[2] = make(ids[2], parents[2], 3u, 0u, 30u);

	/* THE WALK IS DIRTIED FIRST, and that is what makes the three
	 * assertions below about this function rather than about the stack.
	 *
	 * `walk` was an uninitialised local, so `emitted`, `examined` and
	 * `truncated` were whatever the frame happened to hold -- and a
	 * version of `fzn_tree_reachable` that reset none of them would have
	 * been judged by garbage, passing or failing for reasons no compiler
	 * flag controls. Same discipline as manifest_test.c's refused-signer
	 * case: against a buffer that is already zero, a clear is
	 * indistinguishable from its own absence.
	 *
	 * `examined` had no assertion at all here. Measured 2026-09-03:
	 * deleting its reset in `fzn_tree_reachable` left the whole suite
	 * green, because both readers of that field in the tree --
	 * tree_test.c and tree_fuzz.c -- follow `fzn_tree_children` and never
	 * this function. `walk` is a caller-owned struct the header invites
	 * you to reuse, so without the reset a second call reports the first
	 * one's count added to its own. */
	walk.emitted = 99u;
	walk.examined = 99u;
	walk.truncated = 1;

	expect_err(fzn_tree_reachable(nodes, 3u, mark, sizeof mark, &walk),
	           FZN_TREE_OK, "a cyclic set is walked rather than refused");
	expect(mark[2] != 0u, "the node under the root is reachable");
	expect(mark[0] == 0u, "a node in a cycle is not reachable");
	expect(mark[1] == 0u, "the other node in the cycle is not reachable");
	expect(walk.emitted == 1u, "exactly one node is reachable");
	/* A RANGE RATHER THAN A NUMBER, because the exact count is the
	 * fixed-point schedule and not a promise. `examined` counts each
	 * still-unmarked node once per pass, so it is at least `count` and at
	 * most `count * (depth + 1)`, and the module's own comment bounds the
	 * passes at depth+1. Three nodes here give five; asserting five would
	 * freeze a loop the module is free to improve. The range still catches
	 * the thing under test, since a count carried in from the caller is
	 * far outside it. */
	expect(walk.examined >= 3u && walk.examined <= 3u * 4u,
	       "reachability's examined count is outside what three nodes can "
	       "produce, so it carries what the caller left in the walk");
	expect(walk.truncated == 0, "reachability writes no bounded output");
}

/* A node whose parent has not arrived is unreachable in the same way and by
 * the same code path -- the header says the module does not distinguish the
 * two, and this is what makes that a tested claim rather than a sentence. */
static void test_an_orphan_reads_the_same_as_a_cycle(void)
{
	uint8_t ids[2][FZN_TREE_ID_LEN], parents[2][FZN_TREE_ID_LEN];
	fzn_tree_node_t nodes[2];
	uint8_t mark[2];
	fzn_tree_walk_t walk;

	nodes[0] = make(ids[0], parents[0], 1u, 0u, 10u);
	nodes[1] = make(ids[1], parents[1], 2u, 99u, 20u); /* 99 never arrives */

	expect_err(fzn_tree_reachable(nodes, 2u, mark, sizeof mark, &walk),
	           FZN_TREE_OK, "a set with an orphan is walked");
	expect(mark[0] != 0u, "the rooted node is reachable");
	expect(mark[1] == 0u, "a node waiting for its parent is unreachable");
}

/* Depth, so that the fixed point is shown to iterate rather than to mark one
 * level and stop. A chain of four means at least four passes are needed if a
 * pass only ever propagates one level, and the nodes are deliberately given
 * in the WORST order for that -- deepest first. */
static void test_the_fixed_point_reaches_depth(void)
{
	uint8_t ids[4][FZN_TREE_ID_LEN], parents[4][FZN_TREE_ID_LEN];
	fzn_tree_node_t nodes[4];
	uint8_t mark[4];
	fzn_tree_walk_t walk;
	size_t i;

	nodes[0] = make(ids[0], parents[0], 4u, 3u, 10u);
	nodes[1] = make(ids[1], parents[1], 3u, 2u, 10u);
	nodes[2] = make(ids[2], parents[2], 2u, 1u, 10u);
	nodes[3] = make(ids[3], parents[3], 1u, 0u, 10u);

	expect_err(fzn_tree_reachable(nodes, 4u, mark, sizeof mark, &walk),
	           FZN_TREE_OK, "a deep chain is walked");
	for (i = 0; i < 4u; i++)
		expect(mark[i] != 0u, "every node in a rooted chain is reached");
	expect(walk.emitted == 4u, "all four are counted reachable");
}

/* THE UNRESOLVED CONFLICT, which is the design rather than a defect. Two
 * writers reparent node 3; both records stand, so 3 is a child of 1 AND of 2
 * and a consumer shows it twice. */
static void test_two_parent_claims_both_stand(void)
{
	uint8_t ids[4][FZN_TREE_ID_LEN], parents[4][FZN_TREE_ID_LEN];
	fzn_tree_node_t nodes[4];
	const fzn_tree_node_t *out[4];
	fzn_tree_walk_t walk;
	uint8_t one[FZN_TREE_ID_LEN], two[FZN_TREE_ID_LEN];

	id_fill(one, 1u);
	id_fill(two, 2u);

	nodes[0] = make(ids[0], parents[0], 1u, 0u, 10u);
	nodes[1] = make(ids[1], parents[1], 2u, 0u, 20u);
	nodes[2] = make(ids[2], parents[2], 3u, 1u, 30u); /* claim from A */
	nodes[3] = make(ids[3], parents[3], 3u, 2u, 30u); /* claim from B */

	expect_err(fzn_tree_children(nodes, 4u, one, out, 4u, &walk),
	           FZN_TREE_OK, "children of the first claimed parent");
	expect(walk.emitted == 1u, "node 3 appears under parent 1");

	expect_err(fzn_tree_children(nodes, 4u, two, out, 4u, &walk),
	           FZN_TREE_OK, "children of the second claimed parent");
	expect(walk.emitted == 1u, "node 3 also appears under parent 2");
}

/* Sibling order is (order, id) and the input is deliberately unsorted. The
 * equal-order pair is the tie-break case: 5 and 4 share an order, so id
 * decides and 4 must come first. */
static void test_children_come_back_in_sibling_order(void)
{
	uint8_t ids[4][FZN_TREE_ID_LEN], parents[4][FZN_TREE_ID_LEN];
	fzn_tree_node_t nodes[4];
	const fzn_tree_node_t *out[4];
	fzn_tree_walk_t walk;

	nodes[0] = make(ids[0], parents[0], 9u, 0u, 300u);
	nodes[1] = make(ids[1], parents[1], 5u, 0u, 100u);
	nodes[2] = make(ids[2], parents[2], 4u, 0u, 100u); /* ties with 5 */
	nodes[3] = make(ids[3], parents[3], 7u, 0u, 200u);

	expect_err(fzn_tree_children(nodes, 4u, root_id, out, 4u, &walk),
	           FZN_TREE_OK, "children of the root");
	expect(walk.emitted == 4u, "all four are children of the root");
	expect(out[0]->id[0] == 4u, "equal order breaks to the lower id first");
	expect(out[1]->id[0] == 5u, "then the higher id at the same order");
	expect(out[2]->id[0] == 7u, "then the next order up");
	expect(out[3]->id[0] == 9u, "then the highest order");
}

/* A FULL OUTPUT IS NOT A PREFIX, and the flag is the only thing worth
 * asserting. The control is the same call with room, which must not set it. */
static void test_truncation_is_reported_not_implied(void)
{
	uint8_t ids[3][FZN_TREE_ID_LEN], parents[3][FZN_TREE_ID_LEN];
	fzn_tree_node_t nodes[3];
	const fzn_tree_node_t *out[3];
	fzn_tree_walk_t walk;

	nodes[0] = make(ids[0], parents[0], 1u, 0u, 10u);
	nodes[1] = make(ids[1], parents[1], 2u, 0u, 20u);
	nodes[2] = make(ids[2], parents[2], 3u, 0u, 30u);

	expect_err(fzn_tree_children(nodes, 3u, root_id, out, 2u, &walk),
	           FZN_TREE_OK, "a short output is not an error");
	expect(walk.truncated != 0, "running out of room is reported");
	expect(walk.emitted == 2u, "only what fitted was written");
	expect(walk.examined == 3u, "every node was still considered");

	expect_err(fzn_tree_children(nodes, 3u, root_id, out, 3u, &walk),
	           FZN_TREE_OK, "the control, with room for all three");
	expect(walk.truncated == 0, "a fitting output is not reported truncated");
}

/* Exhaustion, each case beside a pair that has room. */
static void test_order_exhaustion_is_reported_and_still_usable(void)
{
	uint64_t out;

	expect_err(fzn_tree_order_between(0u, 2u, &out), FZN_TREE_OK,
	           "a gap of two has a midpoint");
	expect(out == 1u, "and the midpoint is between them");

	expect_err(fzn_tree_order_between(0u, 1u, &out),
	           FZN_TREE_ORDER_EXHAUSTED, "adjacent neighbours have no gap");
	expect(out == 0u, "and it still writes a usable key");

	expect_err(fzn_tree_order_between(7u, 7u, &out),
	           FZN_TREE_ORDER_EXHAUSTED, "equal neighbours have no gap");
	expect(out == 7u, "and it still writes a usable key");

	/* THE OVERFLOW CASE, which is where a (lo + hi) / 2 implementation
	 * gets the wrong answer rather than a slightly worse one: both
	 * neighbours in the top half of the range is exactly where a list
	 * appended to for a long time lives. */
	expect_err(fzn_tree_order_between(UINT64_MAX - 4u, UINT64_MAX, &out),
	           FZN_TREE_OK, "neighbours at the top of the range have a gap");
	expect(out > UINT64_MAX - 4u && out < UINT64_MAX,
	       "and the midpoint is between them rather than wrapped");

	expect_err(fzn_tree_order_between(9u, 8u, &out), FZN_TREE_ERR_RANGE,
	           "reversed neighbours are refused rather than swapped");
}

/* The encoder and the parser against each other, through a real record body
 * rather than a hand-built struct. */
static void test_body_round_trips_through_a_record(void)
{
	uint8_t parent[FZN_TREE_ID_LEN];
	uint8_t body[FZN_RECORD_BODY_MAX];
	const uint8_t content[] = { 0xde, 0xad, 0xbe, 0xef };
	size_t body_len = 0u;

	id_fill(parent, 7u);
	expect_err(fzn_tree_body(parent, 0x0102030405060708u, 0x1234u,
	                         content, sizeof content,
	                         body, sizeof body, &body_len),
	           FZN_TREE_OK, "a body is encoded");
	expect(body_len == (size_t)FZN_TREE_BODY_HEADER_LEN + sizeof content,
	       "and is the header plus the content");
	expect(memcmp(body + FZN_TREE_OFF_PARENT, parent,
	              (size_t)FZN_TREE_ID_LEN) == 0,
	       "the parent lands at its offset");
	expect(body[FZN_TREE_OFF_ORDER] == 0x01u,
	       "the order is big-endian, high byte first");
	expect(body[FZN_TREE_OFF_CONTENT_TYPE] == 0x12u,
	       "the content type is big-endian too");
	expect(memcmp(body + FZN_TREE_OFF_CONTENT, content,
	              sizeof content) == 0, "and the content follows");

	expect_err(fzn_tree_body(parent, 0u, 0u, content, sizeof content,
	                         body, (size_t)FZN_TREE_BODY_HEADER_LEN, &body_len),
	           FZN_TREE_ERR_CAPACITY,
	           "an output with no room for the content is refused");
	expect_err(fzn_tree_body(parent, 0u, 0u, content,
	                         FZN_TREE_CONTENT_MAX + 1u,
	                         body, sizeof body, &body_len),
	           FZN_TREE_ERR_CONTENT_LEN,
	           "content beyond what a record body holds is refused");
}

static void test_the_root_is_all_zero_and_is_not_a_node(void)
{
	uint8_t id[FZN_TREE_ID_LEN];

	expect(fzn_tree_is_root(root_id) != 0, "all-zero is the root");
	id_fill(id, 1u);
	expect(fzn_tree_is_root(id) == 0, "a real id is not the root");
	memset(id, 0, sizeof id);
	id[FZN_TREE_ID_LEN - 1u] = 1u;
	expect(fzn_tree_is_root(id) == 0,
	       "a single set byte at the END is still not the root");
	expect(fzn_tree_is_root(NULL) == 0, "a null id is not the root");
}

/* Every enumerator renders, and a value that is not one renders as unknown --
 * the same check `record_test` makes, for the same reason: a switch that has
 * fallen behind its enum returns a stale string rather than failing. */
/* EVERY PUBLIC ENTRY REFUSES A MISSING ARGUMENT, and until now none of these
 * had been driven -- 19 of this module's 22 unexercised branches were argument
 * guards, which is what a coverage report is FOR. They are cheap to write and
 * they are not decoration: `fzn_tree_open` taking a record by value means a
 * caller can hand it a zeroed struct, and a guard that has never run is a
 * guard nobody has seen work. */
static void test_a_missing_argument_is_refused(void)
{
	uint8_t ids[3][FZN_TREE_ID_LEN], parents[3][FZN_TREE_ID_LEN];
	fzn_tree_node_t nodes[3], node;
	const fzn_tree_node_t *out[3];
	uint8_t body[FZN_RECORD_BODY_MAX];
	uint8_t mark[3];
	fzn_tree_walk_t walk;
	fzn_record_t closed;
	uint8_t parent[FZN_TREE_ID_LEN];
	const uint8_t content[4] = { 1u, 2u, 3u, 4u };
	uint64_t order = 0u;
	size_t body_len = 0u;
	size_t i;

	memset(parent, 7, sizeof parent);
	memset(&closed, 0, sizeof closed);
	for (i = 0; i < 3u; i++)
		nodes[i] = make(ids[i], parents[i], (uint8_t)(i + 1u), 0u, 10u);

	expect_err(fzn_tree_open(closed, NULL), FZN_TREE_ERR_NULL,
	           "opening into a null node is refused");
	/* A ZEROED RECORD IS NOT AN OPEN ONE, and this is the guard that
	 * matters most here: `fzn_record_t` is passed by value, so nothing
	 * stops a caller handing over a struct `fzn_record_open` never
	 * touched. */
	expect_err(fzn_tree_open(closed, &node), FZN_TREE_ERR_CLOSED,
	           "a record that was never opened is refused");

	expect_err(fzn_tree_body(NULL, 0u, 0u, content, sizeof content,
	                         body, sizeof body, &body_len),
	           FZN_TREE_ERR_NULL, "a null parent is refused");
	expect_err(fzn_tree_body(parent, 0u, 0u, content, sizeof content,
	                         NULL, sizeof body, &body_len),
	           FZN_TREE_ERR_NULL, "a null output is refused");
	expect_err(fzn_tree_body(parent, 0u, 0u, content, sizeof content,
	                         body, sizeof body, NULL),
	           FZN_TREE_ERR_NULL, "a null length is refused");
	/* Content absent but claimed: the mismatch, not the emptiness. An
	 * empty body with a null pointer is legal and is tested elsewhere. */
	expect_err(fzn_tree_body(parent, 0u, 0u, NULL, 5u,
	                         body, sizeof body, &body_len),
	           FZN_TREE_ERR_NULL, "content claimed but absent is refused");

	expect_err(fzn_tree_order_between(0u, 1u, NULL), FZN_TREE_ERR_NULL,
	           "a null order output is refused");

	expect_err(fzn_tree_children(nodes, 3u, NULL, out, 3u, &walk),
	           FZN_TREE_ERR_NULL, "children of a null parent are refused");
	expect_err(fzn_tree_children(nodes, 3u, parent, out, 3u, NULL),
	           FZN_TREE_ERR_NULL, "children with no walk to report are refused");
	expect_err(fzn_tree_children(NULL, 3u, parent, out, 3u, &walk),
	           FZN_TREE_ERR_NULL, "a null node array with a count is refused");
	expect_err(fzn_tree_children(nodes, 3u, parent, NULL, 3u, &walk),
	           FZN_TREE_ERR_NULL, "a null output with a capacity is refused");

	expect_err(fzn_tree_reachable(nodes, 3u, mark, sizeof mark, NULL),
	           FZN_TREE_ERR_NULL, "reachability with no walk is refused");
	expect_err(fzn_tree_reachable(NULL, 3u, mark, sizeof mark, &walk),
	           FZN_TREE_ERR_NULL, "reachability over null nodes is refused");
	expect_err(fzn_tree_reachable(nodes, 3u, NULL, sizeof mark, &walk),
	           FZN_TREE_ERR_NULL, "reachability with no mark array is refused");
	/* A HARD REFUSAL, unlike children's graceful truncation. The two are
	 * deliberately different: a short output for children still answers a
	 * question, while a short mark array cannot terminate the walk at all. */
	expect_err(fzn_tree_reachable(nodes, 3u, mark, 2u, &walk),
	           FZN_TREE_ERR_CAPACITY,
	           "a mark array smaller than the node count is refused outright");

	(void)order;
}

static void test_every_error_renders(void)
{
	expect(strcmp(fzn_tree_err_str(FZN_TREE_OK), "ok") == 0,
	       "ok renders");
	/* EVERY ENUMERATOR, not a sample. A switch that has fallen behind its
	 * enum returns "unknown" for the newest one, and a test naming three of
	 * eight cannot see which. */
	expect(strcmp(fzn_tree_err_str(FZN_TREE_ERR_SHORT_BODY), "unknown") != 0,
	       "SHORT_BODY renders");
	expect(strcmp(fzn_tree_err_str(FZN_TREE_ERR_CONTENT_LEN), "unknown") != 0,
	       "CONTENT_LEN renders");
	expect(strcmp(fzn_tree_err_str(FZN_TREE_ERR_NULL), "unknown") != 0,
	       "NULL renders");
	expect(strcmp(fzn_tree_err_str(FZN_TREE_ERR_CAPACITY), "unknown") != 0,
	       "CAPACITY renders");
	expect(strcmp(fzn_tree_err_str(FZN_TREE_ERR_CLOSED), "unknown") != 0,
	       "CLOSED renders");
	expect(strcmp(fzn_tree_err_str(FZN_TREE_ORDER_EXHAUSTED), "unknown") != 0,
	       "ORDER_EXHAUSTED renders");
	expect(strcmp(fzn_tree_err_str(FZN_TREE_ERR_RANGE), "unknown") != 0,
	       "the newest enumerator is not missing from the switch");
	expect(strcmp(fzn_tree_err_str((fzn_tree_err_t)999), "unknown") == 0,
	       "a value that is not an enumerator renders as unknown");
}

int main(void)
{
	printf("tree_test: body %u + content, content at most %zu bytes\n",
	       (unsigned)FZN_TREE_BODY_HEADER_LEN,
	       (size_t)FZN_TREE_CONTENT_MAX);
	printf("tree_test: cycle cases first; if this is the last line, one hung\n");
	test_a_cycle_terminates_and_loses_nothing();
	test_an_orphan_reads_the_same_as_a_cycle();
	test_the_fixed_point_reaches_depth();
	test_two_parent_claims_both_stand();
	test_children_come_back_in_sibling_order();
	test_truncation_is_reported_not_implied();
	test_order_exhaustion_is_reported_and_still_usable();
	test_body_round_trips_through_a_record();
	test_the_root_is_all_zero_and_is_not_a_node();
	test_a_missing_argument_is_refused();
	test_every_error_renders();
	printf("tree_test: %d checks, %d failure(s)\n", checks, failures);

	return failures == 0 ? 0 : 1;
}
