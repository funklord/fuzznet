/* Tests for catalog/sweep.c: the planner over the new model. sec 321.
 *
 * THE PROPERTY THIS SUITE DEFENDS is that the plan PARTITIONS. Every distinct
 * entity the set names lands in exactly one counter, and the sum is asserted
 * against the population -- so a guard that stopped firing, or one that fired
 * twice, cannot hide behind another counter moving to compensate. The old
 * catalog/sweep.h asserted the same sum for the same reason.
 *
 * EACH GUARD IS DRIVEN WITH A CONTROL THAT PASSES IT. A fixture where every
 * entity is refused would satisfy "nothing was planned" whatever the chain
 * did, so every case here plans at least one row, or says why it cannot.
 *
 * AND THE ORDER OF THE CHAIN IS ASSERTED, not just its members. An entity that
 * would fail two guards must be counted by the FIRST one -- otherwise a
 * consumer reading `last_copy` goes looking for replicas for an entity it
 * actually still wants, which is the wrong remedy for the wrong reason.
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
} log_seen;

static int log_capture(flog_t *p, const flog_msg_t *m)
{
	(void)p;
	log_seen.calls++;
	log_seen.type = m->type;
	log_seen.subsystem[0] = '\0';
	log_seen.text[0] = '\0';
	if (m->subsystem)
		snprintf(log_seen.subsystem, sizeof(log_seen.subsystem), "%s", m->subsystem);
	if (m->text)
		snprintf(log_seen.text, sizeof(log_seen.text), "%s", m->text);
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
	fprintf(stderr, "  FAIL sweep_plan_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

/* Hosts and entities, each a whole subject filled with its own byte. */
static uint8_t me[32], other1[32], other2[32];
static uint8_t e1[FZN_CATALOG_ENTITY_LEN];
static uint8_t e2[FZN_CATALOG_ENTITY_LEN];
static uint8_t e3[FZN_CATALOG_ENTITY_LEN];

static void fixtures(void)
{
	memset(me, 0x01, sizeof(me));
	memset(other1, 0x02, sizeof(other1));
	memset(other2, 0x03, sizeof(other2));
	memset(e1, 0xe1, sizeof(e1));
	memset(e2, 0xe2, sizeof(e2));
	memset(e3, 0xe3, sizeof(e3));
}

/* A HOLDER assertion: "this issuer has these bytes". */
static void holder(fzn_catalog_assertion_t *a, const uint8_t *issuer,
                   const uint8_t *entity)
{
	memset(a, 0, sizeof(*a));
	a->issuer = issuer;  a->issuer_len = 32;
	a->entity = entity;  a->entity_len = FZN_CATALOG_ENTITY_LEN;
	a->name = (const uint8_t *)"held"; a->name_len = 4;
	a->attr_class = FZN_CATALOG_FACT;
	a->scope = FZN_CATALOG_ESTATE;
	a->merge = FZN_CATALOG_UNION;
	a->capability = FZN_CATALOG_CAP_HOLDER;
	a->live = 1;
}

/* A CURATED assertion: something wants this entity. */
static void curated(fzn_catalog_assertion_t *a, const uint8_t *issuer,
                    const uint8_t *entity, int live)
{
	memset(a, 0, sizeof(*a));
	a->issuer = issuer;  a->issuer_len = 32;
	a->entity = entity;  a->entity_len = FZN_CATALOG_ENTITY_LEN;
	a->name = (const uint8_t *)"link"; a->name_len = 4;
	a->attr_class = FZN_CATALOG_LABEL;
	a->scope = FZN_CATALOG_ESTATE;
	a->merge = FZN_CATALOG_UNION;
	a->capability = FZN_CATALOG_CAP_NONE;
	a->live = live;
}

/* Every counter, summed. */
static size_t total(const fzn_catalog_sweep_plan_t *p)
{
	return p->planned + p->retained + p->last_copy +
	       p->absent + p->incomplete + p->truncated;
}

/* Distinct entities in a set, counted independently of the planner so the
 * partition assertion has two witnesses rather than one. */
static size_t distinct(const fzn_catalog_assertion_t *set, size_t n)
{
	size_t i, j, d = 0;

	for (i = 0; i < n; i++) {
		int seen = 0;

		if (set[i].entity_len != FZN_CATALOG_ENTITY_LEN)
			continue;
		for (j = 0; j < i; j++)
			if (set[j].entity_len == set[i].entity_len &&
			    memcmp(set[j].entity, set[i].entity, set[i].entity_len) == 0)
				seen = 1;
		if (!seen)
			d++;
	}
	return d;
}

/* THE PLAIN CASE, and the control for everything below: this host holds e1,
 * two others hold it, nothing curates it, nothing retains it. It goes. */
static void test_plans_a_removal(void)
{
	fzn_catalog_assertion_t set[3];
	fzn_catalog_sweep_t job;
	fzn_catalog_removal_t rows[4], out;
	fzn_catalog_sweep_plan_t plan;

	holder(&set[0], me, e1);
	holder(&set[1], other1, e1);
	holder(&set[2], other2, e1);

	CHECK(fzn_catalog_sweep_capture(set, 3, NULL, me, 32, 2, 0, NULL, &job, rows, 4,
	                                  &plan) == FZN_CATALOG_OK,
	      "a capture over a plain set was refused");
	CHECK(plan.planned == 1, "the removable entity was not planned (%zu)", plan.planned);
	CHECK(total(&plan) == distinct(set, 3),
	      "the plan does not partition: %zu counted over %zu distinct entities",
	      total(&plan), distinct(set, 3));

	CHECK(fzn_catalog_sweep_at(&job, &out) == FZN_CATALOG_OK, "no row at the cursor");
	CHECK(memcmp(out.entity, e1, sizeof(e1)) == 0, "the planned row is not e1");
	CHECK(fzn_catalog_sweep_advance(&job) == FZN_CATALOG_OK, "advance failed");
	CHECK(fzn_catalog_sweep_at(&job, &out) == FZN_CATALOG_ERR_RANGE,
	      "the cursor ran past the end without saying so");
	CHECK(fzn_catalog_sweep_advance(&job) == FZN_CATALOG_ERR_RANGE,
	      "advancing past the end was allowed");

	{
		size_t done = 0, all = 0;

		CHECK(fzn_catalog_sweep_progress(&job, &done, &all) == FZN_CATALOG_OK,
		      "progress failed");
		CHECK(done == 1 && all == 1, "progress is %zu/%zu, not 1/1", done, all);
	}
}

/* EACH GUARD, with the plain case above as its control. */
static void test_each_guard(void)
{
	fzn_catalog_assertion_t set[4];
	fzn_catalog_sweep_t job;
	fzn_catalog_removal_t rows[4];
	fzn_catalog_sweep_plan_t plan;
	fzn_catalog_hold_t hold_rows[2];
	fzn_catalog_holds_t holds;

	/* RETAINED: this host keeps it, so it is not a candidate at all. */
	holder(&set[0], me, e1);
	holder(&set[1], other1, e1);
	holder(&set[2], other2, e1);
	fzn_catalog_holds_init(&holds, hold_rows, 2);
	fzn_catalog_retain(&holds, e1, sizeof(e1), FZN_CATALOG_RETAIN_KEEP);
	fzn_catalog_sweep_capture(set, 3, &holds, me, 32, 2, 0, NULL, &job, rows, 4, &plan);
	CHECK(plan.retained == 1 && plan.planned == 0,
	      "a retained entity was planned (retained=%zu planned=%zu)",
	      plan.retained, plan.planned);
	CHECK(total(&plan) == distinct(set, 3), "retained case does not partition");

	/* BEING CURATED DOES NOT KEEP THE BYTES HERE, which is sec 331 and the
	 * case this suite previously asserted the other way round.
	 *
	 * C8 and C9 make referencing and holding independent axes. An entity
	 * another host curates, held here AND elsewhere, is a REDUNDANT COPY
	 * (C19) -- dropping it reclaims space and destroys nothing, and the
	 * link still resolves through the other holder. Refusing here is what
	 * made a local DROP unable to reclaim anything the estate curated. */
	holder(&set[0], me, e1);
	holder(&set[1], other1, e1);
	holder(&set[2], other2, e1);
	curated(&set[3], other1, e1, 1);
	fzn_catalog_sweep_capture(set, 4, NULL, me, 32, 2, 0, NULL, &job, rows, 4, &plan);
	CHECK(plan.planned == 1,
	      "a redundant copy of a curated entity was not planned, so this host "
	      "cannot reclaim space for anything the estate links to (planned=%zu)",
	      plan.planned);
	CHECK(total(&plan) == distinct(set, 4), "the curated case does not partition");

	/* AND THE LAST COPY OF A CURATED ENTITY IS STILL REFUSED, which is the
	 * safety half and the reason removing the guard costs nothing. The
	 * last-copy guard asks the right question -- do the bytes survive this
	 * removal -- where reachability asked whether anything wanted them. */
	holder(&set[0], me, e1);
	curated(&set[1], other1, e1, 1);
	fzn_catalog_sweep_capture(set, 2, NULL, me, 32, 1, 0, NULL, &job, rows, 4, &plan);
	CHECK(plan.last_copy == 1 && plan.planned == 0,
	      "the only copy of an entity another host curates was planned for "
	      "removal (last_copy=%zu planned=%zu)", plan.last_copy, plan.planned);

	/* ABSENT: this host is not among the holders, so there is nothing here
	 * to remove. A refusal would be wrong -- it is not a guard firing. */
	holder(&set[0], other1, e2);
	holder(&set[1], other2, e2);
	fzn_catalog_sweep_capture(set, 2, NULL, me, 32, 1, 0, NULL, &job, rows, 4, &plan);
	CHECK(plan.absent == 1 && plan.planned == 0,
	      "an entity this host does not hold was planned (absent=%zu planned=%zu)",
	      plan.absent, plan.planned);
	CHECK(total(&plan) == distinct(set, 2), "absent case does not partition");

	/* LAST COPY: this host holds it and nobody else does. */
	holder(&set[0], me, e3);
	fzn_catalog_sweep_capture(set, 1, NULL, me, 32, 1, 0, NULL, &job, rows, 4, &plan);
	CHECK(plan.last_copy == 1 && plan.planned == 0,
	      "the last copy was planned for removal (last_copy=%zu planned=%zu)",
	      plan.last_copy, plan.planned);
	CHECK(total(&plan) == distinct(set, 1), "last-copy case does not partition");

	/* AND min_others OF ZERO SWITCHES IT OFF, which is the caller's to
	 * give -- the same fixture, planned. */
	fzn_catalog_sweep_capture(set, 1, NULL, me, 32, 0, 0, NULL, &job, rows, 4, &plan);
	CHECK(plan.planned == 1 && plan.last_copy == 0,
	      "min_others of 0 did not switch the last-copy guard off");

	/* TRUNCATED: removable, and the rows ran out. */
	holder(&set[0], me, e1);
	holder(&set[1], other1, e1);
	holder(&set[2], me, e2);
	holder(&set[3], other1, e2);
	fzn_catalog_sweep_capture(set, 4, NULL, me, 32, 1, 0, NULL, &job, rows, 1, &plan);
	CHECK(plan.planned == 1 && plan.truncated == 1,
	      "a one-row job did not report the entity that did not fit "
	      "(planned=%zu truncated=%zu)", plan.planned, plan.truncated);
	CHECK(total(&plan) == distinct(set, 4), "truncated case does not partition");
}

/* THE ORDER OF THE CHAIN. An entity failing two guards is counted by the
 * FIRST, because the counter is what tells a consumer which remedy to reach
 * for -- and "go and replicate this" is the wrong answer for something the
 * host was keeping on purpose. */
static void test_the_order(void)
{
	fzn_catalog_assertion_t set[2];
	fzn_catalog_sweep_t job;
	fzn_catalog_removal_t rows[4];
	fzn_catalog_sweep_plan_t plan;
	fzn_catalog_hold_t hold_rows[2];
	fzn_catalog_holds_t holds;

	/* Retained AND a last copy AND curated: retention wins. */
	holder(&set[0], me, e1);
	curated(&set[1], other1, e1, 1);
	fzn_catalog_holds_init(&holds, hold_rows, 2);
	fzn_catalog_retain(&holds, e1, sizeof(e1), FZN_CATALOG_RETAIN_KEEP);
	fzn_catalog_sweep_capture(set, 2, &holds, me, 32, 1, 0, NULL, &job, rows, 4, &plan);
	CHECK(plan.retained == 1 && plan.last_copy == 0,
	      "retention did not win the chain (retained=%zu last_copy=%zu)",
	      plan.retained, plan.last_copy);

	/* Curated AND a last copy: LAST COPY now, because the reachability
	 * guard is gone (sec 331) and the remaining question is whether the
	 * bytes survive -- to which the answer is "not if you remove this one".
	 * "Go and replicate it" is the right remedy for that. */
	fzn_catalog_sweep_capture(set, 2, NULL, me, 32, 1, 0, NULL, &job, rows, 4, &plan);
	CHECK(plan.last_copy == 1,
	      "a curated last copy was not reported as a last copy (last_copy=%zu)",
	      plan.last_copy);
}

/* A DEADLINE MAKES AN ENTITY SWEEPABLE, which is the join between this and
 * retention: "delete this in thirty days" is KEEP until T then DROP, and the
 * planner must see the change at T without anything being rewritten. */
static void test_the_deadline_joins_up(void)
{
	fzn_catalog_assertion_t set[2];
	fzn_catalog_sweep_t job;
	fzn_catalog_removal_t rows[4];
	fzn_catalog_sweep_plan_t plan;
	fzn_catalog_hold_t hold_rows[2];
	fzn_catalog_holds_t holds;

	holder(&set[0], me, e1);
	holder(&set[1], other1, e1);
	fzn_catalog_holds_init(&holds, hold_rows, 2);
	fzn_catalog_retain_until(&holds, e1, sizeof(e1), FZN_CATALOG_RETAIN_KEEP,
	                           100, FZN_CATALOG_RETAIN_DROP);

	fzn_catalog_sweep_capture(set, 2, &holds, me, 32, 1, 99, NULL, &job, rows, 4, &plan);
	CHECK(plan.retained == 1 && plan.planned == 0,
	      "before the deadline the entity was planned");
	fzn_catalog_sweep_capture(set, 2, &holds, me, 32, 1, 100, NULL, &job, rows, 4, &plan);
	CHECK(plan.planned == 1 && plan.retained == 0,
	      "at the deadline the entity was still retained, so a sweep run at "
	      "exactly T disagrees with the due list drawn at T");
}

/* A NEAR MISS IS A DIFFERENT ENTITY. The prefix-compare defect class the old
 * catalog/ suites guarded: a compare that stopped early would fold two
 * entities into one, and the planner would remove bytes on the strength of a
 * decision taken about another file. They differ in the LAST byte, which a
 * truncated compare cannot see at all. */
static void test_a_near_miss_is_another_entity(void)
{
	fzn_catalog_assertion_t set[4];
	fzn_catalog_sweep_t job;
	fzn_catalog_removal_t rows[4];
	fzn_catalog_sweep_plan_t plan;
	static uint8_t near_a[FZN_CATALOG_ENTITY_LEN];
	static uint8_t near_b[FZN_CATALOG_ENTITY_LEN];

	memset(near_a, 0x77, sizeof(near_a));
	memset(near_b, 0x77, sizeof(near_b));
	near_b[FZN_CATALOG_ENTITY_LEN - 1u] ^= 0x01u;

	/* near_a is held here and by another, so it goes. near_b is held only
	 * here, so the last-copy guard keeps it. Folding them together gives
	 * one member of the population instead of two, and either verdict for
	 * both. */
	holder(&set[0], me, near_a);
	holder(&set[1], other1, near_a);
	holder(&set[2], me, near_b);

	fzn_catalog_sweep_capture(set, 3, NULL, me, 32, 1, 0, NULL, &job, rows, 4, &plan);
	CHECK(plan.planned == 1 && plan.last_copy == 1,
	      "two entities differing in their last byte were not told apart "
	      "(planned=%zu last_copy=%zu)", plan.planned, plan.last_copy);
	CHECK(total(&plan) == 2, "the near-miss pair is %zu members, not 2", total(&plan));
	CHECK(fzn_catalog_sweep_at(&job, &rows[3]) == FZN_CATALOG_OK &&
	          memcmp(rows[3].entity, near_a, sizeof(near_a)) == 0,
	      "the planned removal is not the entity that had another holder");
}

/* THE ROWS COME OUT SORTED, whatever order the set arrived in.
 *
 * THE CURSOR IS A COUNT, and a count into an arrival-ordered list resumes
 * somewhere else on another machine -- or on this one, after the set is
 * rebuilt from a store that hands its records back in a different order. A
 * consumer that crashed after removing two of five must resume at the third
 * ROW, and that is only meaningful if the rows are in an order both runs
 * agree on. The entities are fed in descending order here so a planner that
 * merely preserved arrival order fails.
 */
static void test_rows_are_sorted(void)
{
	fzn_catalog_assertion_t set[6];
	fzn_catalog_sweep_t job;
	fzn_catalog_removal_t rows[4], out;
	fzn_catalog_sweep_plan_t plan;
	uint8_t previous[FZN_CATALOG_ENTITY_LEN];
	int first = 1;

	/* e3, e1, e2 -- each held here and by one other, so all three go. */
	holder(&set[0], me, e3);      holder(&set[1], other1, e3);
	holder(&set[2], me, e1);      holder(&set[3], other1, e1);
	holder(&set[4], me, e2);      holder(&set[5], other1, e2);

	fzn_catalog_sweep_capture(set, 6, NULL, me, 32, 1, 0, NULL, &job, rows, 4, &plan);
	CHECK(plan.planned == 3, "three removable entities were not all planned (%zu)",
	      plan.planned);

	memset(previous, 0, sizeof(previous));
	while (fzn_catalog_sweep_at(&job, &out) == FZN_CATALOG_OK) {
		if (!first)
			CHECK(memcmp(previous, out.entity, sizeof(previous)) < 0,
			      "the job's rows are not in ascending entity order, so the "
			      "cursor resumes at a different row on another machine");
		memcpy(previous, out.entity, sizeof(previous));
		first = 0;
		fzn_catalog_sweep_advance(&job);
	}
	CHECK(!first, "the job handed back no rows at all");
}

/* INCOMPLETE: more holders than the planner's scratch, with this host's own
 * assertion beyond the cut.
 *
 * sec 316's asymmetry, and the case a smaller fixture cannot reach. The holder
 * TOTAL survives a short buffer -- written plus dropped -- so the last-copy
 * arithmetic stays sound; what a short buffer hides is whether THIS host is
 * among them, and "did not fit" is indistinguishable from "is not a holder".
 * Those lead to opposite outcomes, so the planner refuses to pick.
 *
 * The control is the same set with this host's assertion FIRST: everything
 * else is identical, so a planner that reported `incomplete` for the size of
 * the set rather than for the missing answer fails here.
 */
static void test_incomplete(void)
{
	enum { MANY = 20 };
	fzn_catalog_assertion_t set[MANY];
	static uint8_t hosts[MANY][32];
	fzn_catalog_sweep_t job;
	fzn_catalog_removal_t rows[4];
	fzn_catalog_sweep_plan_t plan;
	size_t i;

	for (i = 0; i < MANY; i++)
		memset(hosts[i], (int)(0x40u + i), sizeof(hosts[i]));

	/* This host LAST, past the scratch, so its membership cannot be read. */
	for (i = 0; i < MANY - 1u; i++)
		holder(&set[i], hosts[i], e1);
	holder(&set[MANY - 1u], me, e1);

	fzn_catalog_sweep_capture(set, MANY, NULL, me, 32, 1, 0, NULL, &job, rows, 4, &plan);
	CHECK(plan.incomplete == 1 && plan.planned == 0 && plan.absent == 0,
	      "a holder set too large to read was decided anyway (incomplete=%zu "
	      "planned=%zu absent=%zu)", plan.incomplete, plan.planned, plan.absent);
	CHECK(total(&plan) == distinct(set, MANY), "incomplete case does not partition");

	/* THE CONTROL: this host FIRST, everything else the same. */
	holder(&set[0], me, e1);
	for (i = 1; i < MANY; i++)
		holder(&set[i], hosts[i], e1);

	fzn_catalog_sweep_capture(set, MANY, NULL, me, 32, 1, 0, NULL, &job, rows, 4, &plan);
	CHECK(plan.planned == 1 && plan.incomplete == 0,
	      "the control was reported incomplete too, so the refusal is about the "
	      "size of the set rather than about the answer that was missing "
	      "(planned=%zu incomplete=%zu)", plan.planned, plan.incomplete);
}

/* WHAT IT SAYS, AND WHEN IT SAYS NOTHING.
 *
 * Three conditions are legible in the counters and easy not to look at, which
 * is why they are also said aloud. The important one is the last-copy guard
 * being switched off: `last_copy` is zero whether the guard passed or was
 * never asked, so the plan that comes back is identical either way and a
 * reader who did not already suspect it has nothing to notice.
 *
 * THE SILENT CONTROL IS THE HALF THAT MATTERS. Without it, every assertion
 * here passes for a planner that says the same thing on every capture.
 */
#ifdef FZN_FLOG_ON
static void test_what_it_says(void)
{
	fzn_catalog_assertion_t set[4];
	fzn_catalog_sweep_t job;
	fzn_catalog_removal_t rows[4];
	fzn_catalog_sweep_plan_t plan;
	flog_t log;
	size_t i;

	init_flog_t(&log);
	log.name = NULL;
	log.accepted_msg_type = FLOG_ACCEPT_ALL;
	log.output_func = log_capture;

	/* SILENT WITHOUT A HANDLE, which is what NULL has to mean. */
	holder(&set[0], me, e1);
	holder(&set[1], other1, e1);
	memset(&log_seen, 0, sizeof(log_seen));
	fzn_catalog_sweep_capture(set, 2, NULL, me, 32, 0, 0, NULL, &job, rows, 4, &plan);
	CHECK(plan.planned == 1, "the fixture did not plan a removal");
	CHECK(log_seen.calls == 0, "a planner nobody gave a log to emitted anyway");

	/* THE GUARD SWITCHED OFF. */
	memset(&log_seen, 0, sizeof(log_seen));
	fzn_catalog_sweep_capture(set, 2, NULL, me, 32, 0, 0, &log, &job, rows, 4, &plan);
	CHECK(log_seen.calls == 1, "a removal planned with the last-copy guard off said "
	      "nothing, and the plan cannot show it -- last_copy is 0 either way");
	CHECK(log_seen.type == FLOG_NOTE,
	      "a disabled guard was reported as a fault or filtered as chatter, and it is "
	      "neither -- the caller chose it and it is irreversible");
	CHECK(strcmp(log_seen.subsystem, "catalog/sweep") == 0,
	      "the event did not name its subsystem");
	CHECK(strstr(log_seen.text, "min_others") != NULL,
	      "the line does not name the argument that switched the guard off");

	/* AND ON, WITH NOTHING ELSE TO REPORT: the control. */
	memset(&log_seen, 0, sizeof(log_seen));
	fzn_catalog_sweep_capture(set, 2, NULL, me, 32, 1, 0, &log, &job, rows, 4, &plan);
	CHECK(plan.planned == 1, "the control did not plan a removal");
	CHECK(log_seen.calls == 0,
	      "a capture with the guard ON said something, so the planner talks on every "
	      "run and the assertions above hold for the wrong reason");

	/* TRUNCATED IS A WARNING, not a note: a consumer that runs the job to
	 * the end reclaims less than the set offered and nothing else says so. */
	holder(&set[0], me, e1);  holder(&set[1], other1, e1);
	holder(&set[2], me, e2);  holder(&set[3], other1, e2);
	memset(&log_seen, 0, sizeof(log_seen));
	fzn_catalog_sweep_capture(set, 4, NULL, me, 32, 1, 0, &log, &job, rows, 1, &plan);
	CHECK(plan.truncated == 1, "the fixture did not truncate");
	CHECK(log_seen.calls == 1 && log_seen.type == FLOG_WARN,
	      "a truncated job did not warn (calls=%d type=%d)", log_seen.calls,
	      (int)log_seen.type);

	/* INCOMPLETE IS A NOTE, and it must not read as nothing to do. */
	{
		static uint8_t many[20][32];
		fzn_catalog_assertion_t big[20];

		for (i = 0; i < 20; i++)
			memset(many[i], (int)(0x40u + i), sizeof(many[i]));
		for (i = 0; i < 19; i++)
			holder(&big[i], many[i], e1);
		holder(&big[19], me, e1);

		memset(&log_seen, 0, sizeof(log_seen));
		fzn_catalog_sweep_capture(big, 20, NULL, me, 32, 1, 0, &log, &job, rows, 4,
		                            &plan);
		CHECK(plan.incomplete == 1, "the fixture did not leave anything undecided");
		CHECK(log_seen.calls == 1 && log_seen.type == FLOG_NOTE,
		      "entities left undecided on partial data said nothing, so a consumer "
		      "reads an empty plan as nothing to do");
		CHECK(strstr(log_seen.text, "catch up") != NULL,
		      "the line does not say what to do about it");
	}
}
#endif

/* WHAT IS REFUSED, each with a control. */
static void test_refusals(void)
{
	fzn_catalog_assertion_t set[1];
	fzn_catalog_sweep_t job;
	fzn_catalog_removal_t rows[2], out;
	fzn_catalog_sweep_plan_t plan;

	holder(&set[0], me, e1);

	CHECK(fzn_catalog_sweep_capture(set, 1, NULL, me, 32, 0, 0, NULL, NULL, rows, 2,
	                                  &plan) == FZN_CATALOG_ERR_MALFORMED,
	      "a null job captured");
	CHECK(fzn_catalog_sweep_capture(set, 1, NULL, me, 32, 0, 0, NULL, &job, NULL, 2,
	                                  &plan) == FZN_CATALOG_ERR_MALFORMED,
	      "a null row array captured");
	CHECK(fzn_catalog_sweep_capture(set, 1, NULL, me, 32, 0, 0, NULL, &job, rows, 0,
	                                  &plan) == FZN_CATALOG_ERR_MALFORMED,
	      "a zero-capacity job captured");
	CHECK(fzn_catalog_sweep_capture(set, 1, NULL, NULL, 32, 0, 0, NULL, &job, rows, 2,
	                                  &plan) == FZN_CATALOG_ERR_MALFORMED,
	      "a capture with no host key -- it cannot answer this-host-holds");
	CHECK(fzn_catalog_sweep_capture(set, 1, NULL, me, 0, 0, 0, NULL, &job, rows, 2,
	                                  &plan) == FZN_CATALOG_ERR_MALFORMED,
	      "a capture with a zero-length host key");
	CHECK(fzn_catalog_sweep_capture(set, 1, NULL, me, 32, 0, 0, NULL, &job, rows, 2,
	                                  NULL) == FZN_CATALOG_ERR_MALFORMED,
	      "a capture with nowhere to put the plan");
	CHECK(fzn_catalog_sweep_capture(set, 1, NULL, me, 32, 0, 0, NULL, &job, rows, 2,
	                                  &plan) == FZN_CATALOG_OK,
	      "the control -- every argument present -- was refused too");

	/* A PLAN IS ZEROED EVEN WHEN THE CAPTURE IS REFUSED, so a caller that
	 * reads it after an error does not read the previous run's numbers. */
	plan.planned = 99;
	(void)fzn_catalog_sweep_capture(set, 1, NULL, me, 32, 0, 0, NULL, &job, rows, 0, &plan);
	CHECK(plan.planned == 0, "a refused capture left stale counters in the plan");

	/* The cursor refuses an uncaptured job rather than reading its rows. */
	memset(&job, 0, sizeof(job));
	CHECK(fzn_catalog_sweep_at(&job, &out) == FZN_CATALOG_ERR_MALFORMED,
	      "an uncaptured job answered at the cursor");
	CHECK(fzn_catalog_sweep_advance(&job) == FZN_CATALOG_ERR_MALFORMED,
	      "an uncaptured job advanced");
	{
		size_t a = 0, b = 0;

		CHECK(fzn_catalog_sweep_progress(&job, &a, &b) ==
		          FZN_CATALOG_ERR_MALFORMED,
		      "an uncaptured job reported progress");
	}
}

/* AN EMPTY SET IS A CLEAN ZERO, not an error: a host with nothing to say about
 * anything has nothing to sweep, and that must be legible rather than refused. */
static void test_empty(void)
{
	fzn_catalog_sweep_t job;
	fzn_catalog_removal_t rows[2];
	fzn_catalog_sweep_plan_t plan;

	CHECK(fzn_catalog_sweep_capture(NULL, 0, NULL, me, 32, 1, 0, NULL, &job, rows, 2,
	                                  &plan) == FZN_CATALOG_OK,
	      "an empty set was refused");
	CHECK(total(&plan) == 0, "an empty set produced counters");
}

int main(void)
{
	fixtures();

	test_plans_a_removal();
	test_each_guard();
	test_the_order();
	test_the_deadline_joins_up();
	test_a_near_miss_is_another_entity();
	test_rows_are_sorted();
	test_incomplete();
#ifdef FZN_FLOG_ON
	test_what_it_says();
#endif
	test_refusals();
	test_empty();

	printf("sweep_plan_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
