/* Tests for catalog/sweep.c: planned deletion.
 *
 * THE CASES THIS FILE EXISTS FOR are the three ways deleting one file at a
 * time as a mark is set loses data, and none of them is "the walk visits
 * every row". project.md sec 155.
 *
 *   - A blob two nodes share must survive one of them saying DROP. Sharing is
 *     the reason a caller chooses a blob at all, so this is the ordinary case
 *     rather than the odd one.
 *   - This host may be the last that holds the bytes. Retention is per-host
 *     by design, so "everybody dropped it" is a state the design permits, and
 *     a deletion that cannot ask how many others have a copy cannot tell
 *     tidying up from losing the only one.
 *   - A sweep must be resumable, because a consumer interrupted part way
 *     through cannot reconstruct what it had decided: the marks are still
 *     there and the bytes are gone, and those two facts do not distinguish
 *     done from half done.
 */

#include "../sweep.h"

#ifdef FZN_FLOG_ON
#include "flog.h"

/* Borrowed strings, so anything kept is copied. */
static struct {
	int calls;
	flog_msg_type_t type;
	char subsystem[64];
	char text[512];
} sweep_log_seen;

static int sweep_log_capture(flog_t *p, const flog_msg_t *m)
{
	(void)p;
	sweep_log_seen.calls++;
	sweep_log_seen.type = m->type;
	sweep_log_seen.subsystem[0] = '\0';
	sweep_log_seen.text[0] = '\0';
	if (m->subsystem)
		snprintf(sweep_log_seen.subsystem, sizeof(sweep_log_seen.subsystem), "%s",
		         m->subsystem);
	if (m->text)
		snprintf(sweep_log_seen.text, sizeof(sweep_log_seen.text), "%s", m->text);
	return 0;
}
#endif

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
	fprintf(stderr, "  FAIL sweep_test.c:%d: ", line);
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

/* The moment a capture reads retention at. sec 157: the sweep takes it
 * once, here, because a job that re-read the clock per step would be a
 * different job at every step. Not zero, so a capture that ignored the
 * argument would still be answering a question. */
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

/* ---- the two seams, whose answers the test controls -------------------- */

/* This host holds everything by default, since a sweep is about bytes that
 * are here; a case that wants otherwise sets `absent`. */
struct store {
	uint8_t absent;
	int has_absent;
	size_t others;
	uint8_t lonely;
	int has_lonely;
};

static int store_holds(void *ctx, const uint8_t root[FZN_BLOB_HASH_LEN], uint64_t len)
{
	struct store *s = ctx;

	(void)len;
	if (s->has_absent && root[0] == s->absent)
		return 0;
	return 1;
}

/* Every blob has `others` witnesses except one nominated blob, which has
 * none -- so a case can put exactly one root on the wrong side of the
 * threshold and leave the rest alone. */
static size_t store_others(void *ctx, const uint8_t root[FZN_BLOB_HASH_LEN], uint64_t len)
{
	struct store *s = ctx;

	(void)len;
	if (s->has_lonely && root[0] == s->lonely)
		return 0;
	return s->others;
}

/* Every candidate lands in exactly one counter, and `planned` is what the job
 * actually holds. A count that does not have to add up is a count nobody can
 * check -- sec 154's rule, and this is the same rule over a different walk. */
static void closes(const fzn_catalog_sweep_plan_t *plan, size_t blobs, int line,
                   const char *what)
{
	size_t classified = plan->planned + plan->retained + plan->shared + plan->last_copy +
	                    plan->absent + plan->truncated + plan->duplicates;

	check_at(classified == blobs, line,
	         "%s: %zu blob entries, %zu classified -- the partition leaks", what, blobs,
	         classified);
}

#define CLOSES(plan, blobs, what) closes((plan), (blobs), __LINE__, (what))

/* ------------------------------------------------------------------------ */

/* THE SHARED-BLOB GUARD, and the reason a deletion is planned rather than
 * immediate. Two nodes, one blob, one of them says DROP: the bytes stay,
 * because the other node still wants them and the catalogue would otherwise
 * go on claiming they are there. */
static void test_a_blob_a_retained_node_needs_is_not_swept(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_hold_t holds[4];
	fzn_catalog_removal_t removals[4];
	fzn_catalog_sweep_t job;
	fzn_catalog_sweep_plan_t plan;
	fzn_catalog_t cat;
	fzn_catalog_entry_t e;
	struct store store = { 0, 0, 3, 0, 0 };
	fzn_catalog_holdings_ops_t held = { store_holds, &store };
	fzn_catalog_witness_ops_t seen = { store_others, &store };

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "the content table would not init");
	REQUIRE(fzn_catalog_hold_init(&cat, holds, 4) == FZN_CATALOG_OK,
	        "the retention table would not init");
	REQUIRE(fzn_catalog_retain_all(&cat, 1) == FZN_CATALOG_OK, "keep-all refused");

	/* Two nodes over one blob, and a third over its own. */
	e = blob_entry(0x10, 0xa0, 100);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "a blob was refused");
	e = blob_entry(0x11, 0xa0, 100);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "a blob was refused");
	e = blob_entry(0x12, 0xa1, 200);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "a blob was refused");

	/* One of the two sharers drops, and so does the node with its own. */
	REQUIRE(fzn_catalog_retain(&cat, idp(0x10), FZN_CATALOG_RETAIN_DROP) == FZN_CATALOG_OK,
	        "a drop was refused");
	REQUIRE(fzn_catalog_retain(&cat, idp(0x12), FZN_CATALOG_RETAIN_DROP) == FZN_CATALOG_OK,
	        "a drop was refused");

	REQUIRE(fzn_catalog_sweep_capture(&cat, &held, &seen, 1, NOW, &job, removals, 4, &plan) ==
	                FZN_CATALOG_OK,
	        "a capture was refused");
	CHECK(plan.planned == 1, "planned %zu removals where one node still needs its blob",
	      plan.planned);
	CHECK(plan.shared == 1,
	      "the shared blob was not held back for the node that still keeps it");
	CHECK(job.removals[0].root[0] == 0xa1, "the wrong blob was planned for removal");
	CLOSES(&plan, 3, "a shared blob");
}

/* THE LAST-COPY GUARD. Retention is per-host, so every host dropping a blob
 * is a state the design permits and nothing else prevents. */
static void test_the_last_copy_is_not_swept(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_removal_t removals[4];
	fzn_catalog_sweep_t job;
	fzn_catalog_sweep_plan_t plan;
	fzn_catalog_t cat;
	fzn_catalog_entry_t e;
	/* 0xa1 has no other holder anywhere; 0xa0 has three. */
	struct store store = { 0, 0, 3, 0xa1, 1 };
	fzn_catalog_holdings_ops_t held = { store_holds, &store };
	fzn_catalog_witness_ops_t seen = { store_others, &store };

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "the content table would not init");
	/* Keeping nothing: both nodes are candidates. */
	e = blob_entry(0x10, 0xa0, 100);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "a blob was refused");
	e = blob_entry(0x11, 0xa1, 200);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "a blob was refused");

	REQUIRE(fzn_catalog_sweep_capture(&cat, &held, &seen, 1, NOW, &job, removals, 4, &plan) ==
	                FZN_CATALOG_OK,
	        "a capture was refused");
	CHECK(plan.planned == 1 && job.removals[0].root[0] == 0xa0,
	      "the blob with witnesses was not the one planned");
	CHECK(plan.last_copy == 1,
	      "a blob no other host is known to hold was planned for deletion");
	CLOSES(&plan, 2, "a last copy");

	/* A HIGHER BAR HOLDS BACK MORE, which is what makes the threshold the
	 * caller's rather than this library's. */
	REQUIRE(fzn_catalog_sweep_capture(&cat, &held, &seen, 4, NOW, &job, removals, 4, &plan) ==
	                FZN_CATALOG_OK,
	        "a capture was refused");
	CHECK(plan.planned == 0 && plan.last_copy == 2,
	      "three witnesses satisfied a bar of four: %zu planned", plan.planned);

	/* AND ZERO SWITCHES THE GUARD OFF ENTIRELY. A caller that says zero has
	 * said it takes responsibility -- right for a cache, wrong for the only
	 * copy of a photograph, and only the caller knows which it has. */
	REQUIRE(fzn_catalog_sweep_capture(&cat, &held, &seen, 0, NOW, &job, removals, 4, &plan) ==
	                FZN_CATALOG_OK,
	        "a capture was refused");
	CHECK(plan.planned == 2 && plan.last_copy == 0,
	      "a threshold of zero still consulted the witness seam: %zu planned",
	      plan.planned);
}

/* A SEAM THAT CANNOT ANSWER KEEPS THE BYTES. copy.h takes the same rule in
 * the other direction, and it is one rule: an unanswerable seam yields the
 * conservative answer, which for a fetch is "ask again" and for a deletion is
 * "do not". */
static void test_a_witness_seam_that_cannot_answer_refuses_the_deletion(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_removal_t removals[4];
	fzn_catalog_sweep_t job;
	fzn_catalog_sweep_plan_t plan;
	fzn_catalog_t cat;
	fzn_catalog_entry_t e;
	struct store store = { 0, 0, 3, 0, 0 };
	fzn_catalog_holdings_ops_t held = { store_holds, &store };
	fzn_catalog_witness_ops_t empty = { NULL, NULL };

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "the content table would not init");
	e = blob_entry(0x10, 0xa0, 100);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "a blob was refused");

	REQUIRE(fzn_catalog_sweep_capture(&cat, &held, &empty, 1, NOW, &job, removals, 4, &plan) ==
	                FZN_CATALOG_OK,
	        "a capture with an unanswerable witness seam was refused");
	CHECK(plan.planned == 0 && plan.last_copy == 1,
	      "an ops struct with no callback was read as witnesses, which deletes on the "
	      "strength of an answer nobody gave");

	REQUIRE(fzn_catalog_sweep_capture(&cat, &held, NULL, 1, NOW, &job, removals, 4, &plan) ==
	                FZN_CATALOG_OK,
	        "a capture with no witness seam at all was refused");
	CHECK(plan.planned == 0 && plan.last_copy == 1,
	      "an absent witness seam was read as witnesses");
}

/* BYTES THIS HOST DOES NOT HAVE ARE NOTHING TO DO, not a refusal -- counted
 * apart so an empty sweep is legible. */
static void test_what_is_not_here_is_not_a_removal(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_removal_t removals[4];
	fzn_catalog_sweep_t job;
	fzn_catalog_sweep_plan_t plan;
	fzn_catalog_t cat;
	fzn_catalog_entry_t e;
	struct store store = { 0xa1, 1, 3, 0, 0 };
	fzn_catalog_holdings_ops_t held = { store_holds, &store };
	fzn_catalog_witness_ops_t seen = { store_others, &store };

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "the content table would not init");
	e = blob_entry(0x10, 0xa0, 100);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "a blob was refused");
	e = blob_entry(0x11, 0xa1, 200);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "a blob was refused");

	REQUIRE(fzn_catalog_sweep_capture(&cat, &held, &seen, 1, NOW, &job, removals, 4, &plan) ==
	                FZN_CATALOG_OK,
	        "a capture was refused");
	CHECK(plan.planned == 1 && plan.absent == 1,
	      "a blob this host does not hold was planned for removal: %zu planned, %zu "
	      "absent",
	      plan.planned, plan.absent);
	CLOSES(&plan, 2, "an absent blob");
}

/* THE WHOLE JOB, AND A RESTART IN THE MIDDLE OF IT. The cursor is a count,
 * which means something only because the lock stops the list moving
 * underneath it. */
static void test_a_sweep_survives_a_restart(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_removal_t removals[4];
	fzn_catalog_sweep_t job;
	fzn_catalog_sweep_t reloaded;
	fzn_catalog_removal_t reloaded_rows[4];
	fzn_catalog_sweep_plan_t plan;
	fzn_catalog_removal_t at;
	fzn_catalog_t cat;
	fzn_catalog_entry_t e;
	size_t done;
	size_t total;
	size_t i;
	struct store store = { 0, 0, 3, 0, 0 };
	fzn_catalog_holdings_ops_t held = { store_holds, &store };
	fzn_catalog_witness_ops_t seen = { store_others, &store };

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "the content table would not init");
	/* Inserted in descending id order, so a job that did not sort would
	 * come back in arrival order and the cursor would mean something
	 * different on the next machine. */
	for (i = 0; i < 3; i++) {
		e = blob_entry((uint8_t)(0x30 - i * 0x10), (uint8_t)(0xa0 + i), 100 + i);
		REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK,
		        "a blob was refused");
	}

	REQUIRE(fzn_catalog_sweep_capture(&cat, &held, &seen, 1, NOW, &job, removals, 4, &plan) ==
	                FZN_CATALOG_OK,
	        "a capture was refused");
	REQUIRE(plan.planned == 3, "expected three removals, planned %zu", plan.planned);
	CHECK(job.removals[0].node.b[0] == 0x10 && job.removals[1].node.b[0] == 0x20 &&
	              job.removals[2].node.b[0] == 0x30,
	      "the removals are not sorted by node id, so a cursor into them resumes "
	      "somewhere else on another machine");

	REQUIRE(fzn_catalog_sweep_begin(&cat, &job) == FZN_CATALOG_OK, "begin refused");
	CHECK(cat.busy_with == FZN_CATALOG_JOB_SWEEP, "a sweep did not take the catalogue");
	/* THE CATALOGUE IS HELD, and progress is the one question it answers. */
	CHECK(fzn_catalog_assert(&cat, idp(0x01), idp(0x10), ALICE, 2, 1) ==
	              FZN_CATALOG_ERR_BUSY,
	      "the catalogue was edited while a sweep held it");
	REQUIRE(fzn_catalog_sweep_progress(&job, &done, &total) == FZN_CATALOG_OK,
	        "progress was refused while the sweep held the catalogue");
	CHECK(done == 0 && total == 3, "progress reported %zu of %zu", done, total);

	/* One removal, then the process dies. */
	REQUIRE(fzn_catalog_sweep_at(&job, &at) == FZN_CATALOG_OK, "the first step was absent");
	CHECK(at.node.b[0] == 0x10 && at.root[0] == 0xa2 && at.len == 102,
	      "the first step named the wrong removal");
	REQUIRE(fzn_catalog_sweep_advance(&job) == FZN_CATALOG_OK, "advance refused");

	/* A RESTART: the job is plain data, so a consumer writes it beside its
	 * store and reads it back. Copied here rather than serialised, which
	 * is the same thing without a file. */
	reloaded = job;
	memcpy(reloaded_rows, removals, sizeof(reloaded_rows));
	reloaded.removals = reloaded_rows;
	cat.busy_with = FZN_CATALOG_JOB_NONE;

	REQUIRE(fzn_catalog_sweep_begin(&cat, &reloaded) == FZN_CATALOG_OK,
	        "beginning a job already under way was refused, which is what a restart "
	        "does");
	REQUIRE(fzn_catalog_sweep_progress(&reloaded, &done, &total) == FZN_CATALOG_OK,
	        "progress refused after a restart");
	CHECK(done == 1 && total == 3, "the restart lost the cursor: %zu of %zu", done, total);
	REQUIRE(fzn_catalog_sweep_at(&reloaded, &at) == FZN_CATALOG_OK, "the step was absent");
	CHECK(at.node.b[0] == 0x20, "the restart resumed at the wrong step");

	/* ENDING WITH WORK LEFT IS REFUSED. */
	CHECK(fzn_catalog_sweep_end(&cat, &reloaded) == FZN_CATALOG_ERR_BUSY,
	      "a sweep with work remaining was ended");

	REQUIRE(fzn_catalog_sweep_advance(&reloaded) == FZN_CATALOG_OK, "advance refused");
	REQUIRE(fzn_catalog_sweep_advance(&reloaded) == FZN_CATALOG_OK, "advance refused");
	CHECK(fzn_catalog_sweep_at(&reloaded, &at) == FZN_CATALOG_ERR_ABSENT,
	      "a cursor past the last removal did not report the work finished");
	CHECK(fzn_catalog_sweep_advance(&reloaded) == FZN_CATALOG_ERR_ABSENT,
	      "advancing past the end was accepted");

	REQUIRE(fzn_catalog_sweep_end(&cat, &reloaded) == FZN_CATALOG_OK, "end refused");
	CHECK(cat.busy_with == FZN_CATALOG_JOB_NONE, "the sweep did not give the catalogue back");
	CHECK(fzn_catalog_assert(&cat, idp(0x01), idp(0x10), ALICE, 2, 1) == FZN_CATALOG_OK,
	      "the catalogue was still held after the sweep ended");
}

/* ONE JOB AT A TIME, AND A JOB IS ENDED BY THE JOB THAT STARTED IT. sec 155
 * widened the refile flag into a kind for exactly this: two flags could
 * disagree, and one flag with no kind lets `refile_end` unlock a sweep. */
static void test_a_sweep_and_a_refile_do_not_share_a_catalogue(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_removal_t removals[4];
	fzn_catalog_move_t moves[4];
	fzn_catalog_sweep_t job;
	fzn_catalog_refile_t refile;
	fzn_catalog_sweep_plan_t plan;
	fzn_catalog_t cat;
	fzn_catalog_entry_t e;
	struct store store = { 0, 0, 3, 0, 0 };
	fzn_catalog_holdings_ops_t held = { store_holds, &store };
	fzn_catalog_witness_ops_t seen = { store_others, &store };

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "the content table would not init");
	REQUIRE(fzn_catalog_assert(&cat, idp(0x01), idp(0x10), ALICE, 1, 1) == FZN_CATALOG_OK,
	        "a link was refused");
	REQUIRE(fzn_catalog_filing_root(&cat, idp(0x01)) == FZN_CATALOG_OK,
	        "a filing root was refused");
	/* DELIBERATELY NOT FILED UNDER THE ROOT, so the refile job captures
	 * ZERO moves and `done == used` from the start.
	 *
	 * The first version of this case filed the node, and the refile job it
	 * captured therefore had work outstanding -- so `refile_end` returned
	 * BUSY from its "work remains" check and never reached the job-kind
	 * guard this case exists for. It passed, and it passed for the wrong
	 * reason: the sabotage that deletes the guard left it green. A test
	 * can name the hazard exactly and still cover only the safe path, and
	 * nothing but breaking the code says which. */
	e = blob_entry(0x10, 0xa0, 100);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "a blob was refused");

	REQUIRE(fzn_catalog_sweep_capture(&cat, &held, &seen, 1, NOW, &job, removals, 4, &plan) ==
	                FZN_CATALOG_OK,
	        "a capture was refused");
	REQUIRE(fzn_catalog_refile_capture(&cat, &refile, moves, 4) == FZN_CATALOG_OK,
	        "a refile capture was refused");

	REQUIRE(fzn_catalog_sweep_begin(&cat, &job) == FZN_CATALOG_OK, "sweep begin refused");
	CHECK(fzn_catalog_refile_begin(&cat, &refile) == FZN_CATALOG_ERR_BUSY,
	      "a refile started on a catalogue a sweep was holding");
	/* AND THE OTHER JOB CANNOT UNLOCK THIS ONE. With a bare flag this call
	 * would succeed and hand the catalogue away mid-sweep.
	 *
	 * The refile job has no work outstanding -- see above -- so this call
	 * gets past "work remains" and the ONLY thing that can refuse it is the
	 * job-kind guard. That is what makes this a test of the guard rather
	 * than of the refile's own bookkeeping. */
	REQUIRE(refile.done == refile.used,
	        "the refile job has work outstanding, so this case cannot reach the guard "
	        "it exists for");
	CHECK(fzn_catalog_refile_end(&cat, &refile) == FZN_CATALOG_ERR_BUSY,
	      "a refile ended a sweep's hold on the catalogue");
	CHECK(cat.busy_with == FZN_CATALOG_JOB_SWEEP, "the sweep lost its hold");

	/* A CAPTURE IS REFUSED WHILE ANY JOB HOLDS THE CATALOGUE, since it
	 * would be deciding against an arrangement that is being changed. */
	CHECK(fzn_catalog_sweep_capture(&cat, &held, &seen, 1, NOW, &job, removals, 4, &plan) ==
	              FZN_CATALOG_ERR_BUSY,
	      "a capture ran while a job held the catalogue");

	REQUIRE(fzn_catalog_sweep_advance(&job) == FZN_CATALOG_OK, "advance refused");
	REQUIRE(fzn_catalog_sweep_end(&cat, &job) == FZN_CATALOG_OK, "end refused");
	CHECK(fzn_catalog_refile_begin(&cat, &refile) == FZN_CATALOG_OK,
	      "a refile was refused after the sweep gave the catalogue back");
}

/* A CATALOGUE THAT KEEPS EVERYTHING SWEEPS NOTHING, which is the state a
 * consumer that has said nothing about a node is NOT in -- sec 152 made
 * keeping the thing a host opts into, so the default sweeps. Both directions
 * are asserted, because the counter-intuitive one is the default. */
static void test_retention_decides_the_candidates(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_removal_t removals[4];
	fzn_catalog_sweep_t job;
	fzn_catalog_sweep_plan_t plan;
	fzn_catalog_t cat;
	fzn_catalog_entry_t e;
	struct store store = { 0, 0, 3, 0, 0 };
	fzn_catalog_holdings_ops_t held = { store_holds, &store };
	fzn_catalog_witness_ops_t seen = { store_others, &store };

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "the content table would not init");
	e = blob_entry(0x10, 0xa0, 100);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "a blob was refused");

	REQUIRE(fzn_catalog_sweep_capture(&cat, &held, &seen, 1, NOW, &job, removals, 4, &plan) ==
	                FZN_CATALOG_OK,
	        "a capture was refused");
	CHECK(plan.planned == 1,
	      "a catalogue nobody has set a retention on kept its bytes, though sec 152 "
	      "made keeping the thing a host opts into");

	REQUIRE(fzn_catalog_retain_all(&cat, 1) == FZN_CATALOG_OK, "keep-all refused");
	REQUIRE(fzn_catalog_sweep_capture(&cat, &held, &seen, 1, NOW, &job, removals, 4, &plan) ==
	                FZN_CATALOG_OK,
	        "a capture was refused");
	CHECK(plan.planned == 0 && plan.retained == 1,
	      "a catalogue told to keep everything swept %zu blobs", plan.planned);
	CLOSES(&plan, 1, "a catalogue that keeps everything");
}

/* TRUNCATION IS LOUD. A capture that silently held some of the removals would
 * leave a consumer believing it had reclaimed what it had not. */
static void test_truncation_is_counted(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_removal_t removals[1];
	fzn_catalog_sweep_t job;
	fzn_catalog_sweep_plan_t plan;
	fzn_catalog_t cat;
	fzn_catalog_entry_t e;
	size_t i;
	struct store store = { 0, 0, 3, 0, 0 };
	fzn_catalog_holdings_ops_t held = { store_holds, &store };
	fzn_catalog_witness_ops_t seen = { store_others, &store };

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "the content table would not init");
	for (i = 0; i < 3; i++) {
		e = blob_entry((uint8_t)(0x10 + i), (uint8_t)(0xa0 + i), 100 + i);
		REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK,
		        "a blob was refused");
	}

	REQUIRE(fzn_catalog_sweep_capture(&cat, &held, &seen, 1, NOW, &job, removals, 1, &plan) ==
	                FZN_CATALOG_OK,
	        "a truncated capture was refused, though truncation is reported and not an "
	        "error");
	CHECK(plan.planned == 1 && plan.truncated == 2,
	      "the capture stopped at the array rather than reporting the total: %zu "
	      "planned, %zu truncated",
	      plan.planned, plan.truncated);
	CLOSES(&plan, 3, "a truncated capture");
}

/* ONE BLOB, ONE REMOVAL, however many nodes reach it -- so a consumer is not
 * told to remove the same bytes twice and does not read the second failure as
 * a fault. */
static void test_a_shared_dropped_blob_is_removed_once(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_removal_t removals[4];
	fzn_catalog_sweep_t job;
	fzn_catalog_sweep_plan_t plan;
	fzn_catalog_t cat;
	fzn_catalog_entry_t e;
	size_t i;
	struct store store = { 0, 0, 3, 0, 0 };
	fzn_catalog_holdings_ops_t held = { store_holds, &store };
	fzn_catalog_witness_ops_t seen = { store_others, &store };

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "the content table would not init");
	for (i = 0; i < 3; i++) {
		e = blob_entry((uint8_t)(0x10 + i), 0xa0, 100);
		REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK,
		        "a blob was refused");
	}

	REQUIRE(fzn_catalog_sweep_capture(&cat, &held, &seen, 1, NOW, &job, removals, 4, &plan) ==
	                FZN_CATALOG_OK,
	        "a capture was refused");
	CHECK(plan.planned == 1 && plan.duplicates == 2,
	      "three nodes over one blob produced %zu removals", plan.planned);
	CHECK(job.removals[0].node.b[0] == 0x10,
	      "the node named is not the first in id order, so the choice is not "
	      "deterministic");
	CLOSES(&plan, 3, "a shared dropped blob");
}

/* Arguments, and a plan zeroed before they are checked. */
static void test_arguments(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_removal_t removals[4];
	fzn_catalog_sweep_t job;
	fzn_catalog_sweep_plan_t plan;
	fzn_catalog_removal_t at;
	fzn_catalog_t cat;
	fzn_catalog_entry_t e;
	size_t done;
	size_t total;
	struct store store = { 0, 0, 3, 0, 0 };
	fzn_catalog_holdings_ops_t held = { store_holds, &store };
	fzn_catalog_witness_ops_t seen = { store_others, &store };

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "the content table would not init");
	e = blob_entry(0x10, 0xa0, 100);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "a blob was refused");

	REQUIRE(fzn_catalog_sweep_capture(&cat, &held, &seen, 1, NOW, &job, removals, 4, &plan) ==
	                FZN_CATALOG_OK,
	        "a capture was refused");
	REQUIRE(plan.planned == 1, "the first capture found nothing to carry into the next");

	CHECK(fzn_catalog_sweep_capture(NULL, &held, &seen, 1, NOW, &job, removals, 4, &plan) ==
	              FZN_CATALOG_ERR_MALFORMED,
	      "a null catalogue was accepted");
	CHECK(plan.planned == 0,
	      "a refused capture left the previous round's count, so a caller reading the "
	      "plan after an error reads a number about something else");
	CHECK(fzn_catalog_sweep_capture(&cat, &held, &seen, 1, NOW, &job, removals, 0, &plan) ==
	              FZN_CATALOG_ERR_MALFORMED,
	      "a capacity of zero was accepted, though a job that can hold nothing plans "
	      "nothing and reports success doing it");
	CHECK(fzn_catalog_sweep_capture(&cat, &held, &seen, 1, NOW, &job, removals, 4, NULL) ==
	              FZN_CATALOG_ERR_MALFORMED,
	      "nowhere to answer");

	/* AN UNCAPTURED JOB IS NOT A JOB, so nothing may be begun, read or
	 * ended from one -- which is what stops a zeroed struct being walked as
	 * an empty sweep that succeeds. */
	memset(&job, 0, sizeof(job));
	CHECK(fzn_catalog_sweep_begin(&cat, &job) == FZN_CATALOG_ERR_MALFORMED,
	      "an uncaptured job was begun");
	CHECK(fzn_catalog_sweep_at(&job, &at) == FZN_CATALOG_ERR_MALFORMED,
	      "an uncaptured job answered a step");
	CHECK(fzn_catalog_sweep_advance(&job) == FZN_CATALOG_ERR_MALFORMED,
	      "an uncaptured job advanced");
	CHECK(fzn_catalog_sweep_progress(&job, &done, &total) == FZN_CATALOG_ERR_MALFORMED,
	      "an uncaptured job reported progress");
	CHECK(fzn_catalog_sweep_end(&cat, &job) == FZN_CATALOG_ERR_MALFORMED,
	      "an uncaptured job was ended");
}

/* THE HOLDER'S REQUEST, END TO END. sec 157: "delete this in thirty days" is
 * a retention that changes at a moment, and what makes it a DELETION is that
 * the sweep then finds it -- so the case that matters is not that the mode
 * flips but that the same catalogue, swept at two moments, plans differently.
 *
 * `now` IS READ AT CAPTURE AND NOWHERE ELSE, which is what keeps sec 155's
 * cursor sound: a job that re-read the clock per step would be a different
 * job at every step, and a restart would resume into a decision nobody took.
 */
static void test_a_schedule_becomes_a_sweep(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_hold_t holds[4];
	fzn_catalog_removal_t removals[4];
	fzn_catalog_sweep_t job;
	fzn_catalog_sweep_plan_t plan;
	fzn_catalog_t cat;
	fzn_catalog_entry_t e;
	struct store store = { 0, 0, 3, 0, 0 };
	fzn_catalog_holdings_ops_t held = { store_holds, &store };
	fzn_catalog_witness_ops_t seen = { store_others, &store };

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "the content table would not init");
	REQUIRE(fzn_catalog_hold_init(&cat, holds, 4) == FZN_CATALOG_OK,
	        "the retention table would not init");
	REQUIRE(fzn_catalog_retain_all(&cat, 1) == FZN_CATALOG_OK, "keep-all refused");

	e = blob_entry(0x10, 0xa0, 100);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "a blob was refused");
	REQUIRE(fzn_catalog_retain_until(&cat, idp(0x10), FZN_CATALOG_RETAIN_KEEP, 100,
	                                 FZN_CATALOG_RETAIN_DROP) == FZN_CATALOG_OK,
	        "a scheduled retention was refused");

	REQUIRE(fzn_catalog_sweep_capture(&cat, &held, &seen, 1, 99, &job, removals, 4,
	                                  &plan) == FZN_CATALOG_OK,
	        "a capture was refused");
	CHECK(plan.planned == 0 && plan.retained == 1,
	      "a node still inside its deadline was planned for removal");

	REQUIRE(fzn_catalog_sweep_capture(&cat, &held, &seen, 1, 100, &job, removals, 4,
	                                  &plan) == FZN_CATALOG_OK,
	        "a capture was refused");
	CHECK(plan.planned == 1 && plan.retained == 0,
	      "the deadline passed and the node was not planned: %zu planned, %zu retained",
	      plan.planned, plan.retained);
	CHECK(job.removals[0].root[0] == 0xa0, "the wrong blob was planned");

	/* AND THE SCHEDULE DOES NOT DEFEAT THE GUARDS. A node whose deadline
	 * has passed is a candidate like any other, so a blob a retained node
	 * still needs survives it -- which is the property that would be
	 * easiest to lose by treating a deadline as a licence to delete. */
	e = blob_entry(0x11, 0xa0, 100);
	REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK, "a blob was refused");
	REQUIRE(fzn_catalog_sweep_capture(&cat, &held, &seen, 1, 100, &job, removals, 4,
	                                  &plan) == FZN_CATALOG_OK,
	        "a capture was refused");
	CHECK(plan.planned == 0 && plan.shared == 1,
	      "a blob another node still keeps was removed because a deadline passed");
}

#ifdef FZN_FLOG_ON
/*
 * WHAT A DELETION SAYS WHILE IT IS BEING PLANNED. sec 237.
 *
 * Two moments, and neither is an error, which is exactly why they were
 * silent. A `min_others` of zero is the caller's to give and switches off the
 * only guard between a plan and bytes nobody else holds -- and the plan that
 * comes back is indistinguishable from one that passed the guard, since
 * `last_copy` is zero whether the seam refused nothing or was never asked. A
 * truncated job is called loud by sweep.h and had a counter for a voice.
 *
 * THROUGH THE CATALOGUE'S LOG, because a sweep is something that happens to a
 * catalogue and a consumer has already said where that one talks.
 */
static void test_a_planned_deletion_says_what_it_is_doing(void)
{
	fzn_catalog_edge_t rows[8];
	fzn_catalog_entry_t entries[4];
	fzn_catalog_removal_t removals[4];
	fzn_catalog_removal_t one_row[1];
	fzn_catalog_sweep_t job;
	fzn_catalog_sweep_plan_t plan;
	fzn_catalog_t cat;
	fzn_catalog_entry_t e;
	flog_t log;
	size_t i;
	struct store store = { 0, 0, 3, 0, 0 };
	fzn_catalog_holdings_ops_t held = { store_holds, &store };
	fzn_catalog_witness_ops_t seen = { store_others, &store };

	init_flog_t(&log);
	log.name = NULL;
	log.accepted_msg_type = FLOG_ACCEPT_ALL;
	log.output_func = sweep_log_capture;

	REQUIRE(fzn_catalog_init(&cat, rows, 8, &ADD_WINS) == FZN_CATALOG_OK, "init refused");
	REQUIRE(fzn_catalog_content_init(&cat, entries, 4, &HELD_WINS) == FZN_CATALOG_OK,
	        "the content table would not init");
	for (i = 0; i < 3; i++) {
		e = blob_entry((uint8_t)(0x10 + i), (uint8_t)(0xa0 + i), 100 + i);
		REQUIRE(fzn_catalog_content_set(&cat, &e) == FZN_CATALOG_OK,
		        "a blob was refused");
	}

	/* QUIET UNTIL ASKED. */
	memset(&sweep_log_seen, 0, sizeof(sweep_log_seen));
	REQUIRE(fzn_catalog_sweep_capture(&cat, &held, &seen, 0, NOW, &job, removals, 4,
	                                  &plan) == FZN_CATALOG_OK,
	        "a capture was refused");
	CHECK(sweep_log_seen.calls == 0, "a catalogue nobody gave a log to emitted anyway");

	fzn_catalog_set_log(&cat, &log);

	/* THE GUARD SWITCHED OFF. */
	memset(&sweep_log_seen, 0, sizeof(sweep_log_seen));
	REQUIRE(fzn_catalog_sweep_capture(&cat, &held, &seen, 0, NOW, &job, removals, 4,
	                                  &plan) == FZN_CATALOG_OK,
	        "a capture was refused");
	CHECK(plan.planned > 0 && plan.last_copy == 0, "the fixture did not plan a removal");
	CHECK(sweep_log_seen.calls == 1, "a deletion planned with the guard off said nothing");
	CHECK(sweep_log_seen.type == FLOG_NOTE,
	      "a disabled guard was reported as a fault or filtered as chatter, and it is "
	      "neither -- the caller chose it and it is irreversible");
	CHECK(strcmp(sweep_log_seen.subsystem, "catalog/sweep") == 0,
	      "the event did not name its subsystem");
	CHECK(strstr(sweep_log_seen.text, "min_others") != NULL,
	      "the line does not name the argument that switched the guard off");

	/* AND ON, which is the control: without it the case above passes for a
	 * module that says the same thing on every capture. */
	memset(&sweep_log_seen, 0, sizeof(sweep_log_seen));
	REQUIRE(fzn_catalog_sweep_capture(&cat, &held, &seen, 1, NOW, &job, removals, 4,
	                                  &plan) == FZN_CATALOG_OK,
	        "a capture was refused");
	CHECK(sweep_log_seen.calls == 0,
	      "a capture that consulted the witness seam announced a disabled guard");

	/* A JOB THAT DID NOT FIT. Rows for one, three blobs to remove. */
	memset(&sweep_log_seen, 0, sizeof(sweep_log_seen));
	REQUIRE(fzn_catalog_sweep_capture(&cat, &held, &seen, 1, NOW, &job, one_row, 1,
	                                  &plan) == FZN_CATALOG_OK,
	        "a truncated capture was refused");
	CHECK(plan.truncated == 2, "the fixture did not truncate");
	CHECK(sweep_log_seen.calls == 1, "a truncated sweep said nothing");
	CHECK(sweep_log_seen.type == FLOG_WARN,
	      "a consumer about to believe it reclaimed what it did not was not warned");
	CHECK(strstr(sweep_log_seen.text, "reclaims less") != NULL,
	      "the line reports a count and not its consequence");
}
#endif

int main(void)
{
	memset(ALICE, 0xa1, sizeof(ALICE));

	test_a_blob_a_retained_node_needs_is_not_swept();
	test_the_last_copy_is_not_swept();
	test_a_witness_seam_that_cannot_answer_refuses_the_deletion();
	test_what_is_not_here_is_not_a_removal();
	test_a_sweep_survives_a_restart();
	test_a_sweep_and_a_refile_do_not_share_a_catalogue();
	test_retention_decides_the_candidates();
	test_truncation_is_counted();
	test_a_shared_dropped_blob_is_removed_once();
	test_arguments();
	test_a_schedule_becomes_a_sweep();
#ifdef FZN_FLOG_ON
	test_a_planned_deletion_says_what_it_is_doing();
#endif

	printf("sweep_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
