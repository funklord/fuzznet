/* The ladder: node/pressure.h. */

#include "../pressure.h"
#include "../types.h"

#include <stdio.h>
#include <string.h>

static int failures, checks;

#define CHECK(c, what)                                                          \
	do {                                                                        \
		checks++;                                                               \
		if (!(c)) {                                                             \
			failures++;                                                         \
			fprintf(stderr, "  FAIL pressure_test.c:%d: %s\n", __LINE__, what); \
		}                                                                       \
	} while (0)

int main(void)
{
	fzn_pressure_input_t in;
	fzn_pressure_t p;
	unsigned i;
	int moved = 0;
	const uint8_t lines[] = { FZN_CMD_GROUPS, FZN_SUBCMD_GROUPS_LINES_SYNC };
	const uint8_t acts[] = { FZN_CMD_GROUPS, FZN_SUBCMD_GROUPS_SYNC };

	/* THE TABLE, as the header draws it. */
	CHECK(fzn_pressure_admits(FZN_PRESSURE_CALM, FZN_RANK_TRACE), "calm shed a trace");
	CHECK(!fzn_pressure_admits(FZN_PRESSURE_TIGHT, FZN_RANK_TRACE)
	              && fzn_pressure_admits(FZN_PRESSURE_TIGHT, FZN_RANK_REFETCH),
	      "tight's floor moved");
	CHECK(!fzn_pressure_admits(FZN_PRESSURE_SCARCE, FZN_RANK_REFETCH)
	              && fzn_pressure_admits(FZN_PRESSURE_SCARCE, FZN_RANK_USER),
	      "scarce's floor moved");
	CHECK(!fzn_pressure_admits(FZN_PRESSURE_SURVIVAL, FZN_RANK_USER)
	              && fzn_pressure_admits(FZN_PRESSURE_SURVIVAL, FZN_RANK_CONTROL)
	              && fzn_pressure_admits(FZN_PRESSURE_SURVIVAL, FZN_RANK_IDENTITY),
	      "survival's floor moved");

	/* THE HOLDER'S RANKING: high and low. */
	CHECK(fzn_pressure_family_rank(FZN_METER_JOURNAL) >= FZN_RANK_CONTROL
	              && fzn_pressure_family_rank(FZN_METER_EXTENSION) >= FZN_RANK_CONTROL
	              && fzn_pressure_family_rank(FZN_METER_VERBS) >= FZN_RANK_CONTROL
	              && fzn_pressure_family_rank(FZN_METER_LOGS) >= FZN_RANK_CONTROL,
	      "propagation, commands or logging was not kept to the last");
	CHECK(fzn_pressure_family_rank(FZN_METER_FILES) <= FZN_RANK_REFETCH
	              && fzn_pressure_family_rank(FZN_METER_FILE_REFS) <= FZN_RANK_REFETCH
	              && fzn_pressure_family_rank(FZN_METER_STREAMS) <= FZN_RANK_REFETCH,
	      "file transfers or media ranked above the copies");
	CHECK(fzn_pressure_request_rank(FZN_METER_GROUPS, lines, sizeof(lines)) == FZN_RANK_REFETCH,
	      "a group's chat ranked above the copies");
	CHECK(fzn_pressure_request_rank(FZN_METER_GROUPS, acts, sizeof(acts)) >= FZN_RANK_CONTROL,
	      "a group's acts, who may do what, were not control");

	/* EACH RESOURCE ALONE, the worst winning. */
	memset(&in, 0, sizeof(in));
	CHECK(fzn_pressure_level(&in) == FZN_PRESSURE_CALM, "nothing read was not calm");
	in.store_held = 1;
	in.delta_budget = 800u;
	CHECK(fzn_pressure_level(&in) == FZN_PRESSURE_TIGHT, "a store held in RAM was not tight");
	in.delta_bytes = 400u;
	CHECK(fzn_pressure_level(&in) == FZN_PRESSURE_SCARCE, "half the budget was not scarce");
	in.delta_bytes = 700u;
	CHECK(fzn_pressure_level(&in) == FZN_PRESSURE_SURVIVAL, "7/8 of the budget was not survival");
	memset(&in, 0, sizeof(in));
	in.mem_total_kb = 1000000u;
	in.mem_available_kb = 500000u;
	CHECK(fzn_pressure_level(&in) == FZN_PRESSURE_CALM, "half of memory free was not calm");
	in.mem_available_kb = 90000u;
	CHECK(fzn_pressure_level(&in) == FZN_PRESSURE_TIGHT, "9 per cent free was not tight");
	in.mem_available_kb = 40000u;
	CHECK(fzn_pressure_level(&in) == FZN_PRESSURE_SCARCE, "4 per cent free was not scarce");
	in.mem_available_kb = 10000u;
	CHECK(fzn_pressure_level(&in) == FZN_PRESSURE_SURVIVAL, "1 per cent free was not survival");
	in.mem_total_kb = 0u;
	in.mem_available_kb = 0u;
	in.network = FZN_PRESSURE_SCARCE;
	CHECK(fzn_pressure_level(&in) == FZN_PRESSURE_SCARCE, "the network's word was not taken");

	/* UP AT ONCE, DOWN A STEP AT A TIME. */
	memset(&p, 0, sizeof(p));
	CHECK(fzn_pressure_step(&p, FZN_PRESSURE_SURVIVAL, &moved) == FZN_PRESSURE_SURVIVAL && moved,
	      "a host did not rise at once");
	for (i = 0; i + 1u < FZN_PRESSURE_CALM_TICKS; i++) {
		(void)fzn_pressure_step(&p, FZN_PRESSURE_CALM, &moved);
		CHECK(p.state == FZN_PRESSURE_SURVIVAL && !moved, "a host fell before its ticks");
	}
	(void)fzn_pressure_step(&p, FZN_PRESSURE_CALM, &moved);
	CHECK(p.state == FZN_PRESSURE_SCARCE && moved, "a host fell other than one step");
	for (i = 0; i + 1u < FZN_PRESSURE_CALM_TICKS; i++)
		(void)fzn_pressure_step(&p, FZN_PRESSURE_CALM, NULL);
	(void)fzn_pressure_step(&p, FZN_PRESSURE_SCARCE, NULL);
	CHECK(p.calm_ticks == 0u, "a tick at the state did not start the wait again");

	/* RULES move what is below CONTROL, and nothing else. */
	{
		fzn_pressure_rules_t r;
		fzn_rank_t rank = FZN_RANK_IDENTITY;

		memset(&r, 0, sizeof(r));
		CHECK(fzn_pressure_ruled_rank(&r, FZN_METER_GROUPS, lines, sizeof(lines)) == FZN_RANK_REFETCH,
		      "no rule moved a default");
		CHECK(fzn_pressure_rule_value((const uint8_t *)"user", 4u, &rank) && rank == FZN_RANK_USER,
		      "`user` did not read");
		CHECK(!fzn_pressure_rule_value((const uint8_t *)"control", 7u, &rank),
		      "a rule reached the top of the ladder");
		r.set[FZN_RULED_GROUP_LINES] = 1u;
		r.rank[FZN_RULED_GROUP_LINES] = FZN_RANK_USER;
		CHECK(fzn_pressure_ruled_rank(&r, FZN_METER_GROUPS, lines, sizeof(lines)) == FZN_RANK_USER,
		      "a rule did not raise a group's chat");
		CHECK(fzn_pressure_ruled_rank(&r, FZN_METER_GROUPS, acts, sizeof(acts)) >= FZN_RANK_CONTROL,
		      "a rule on chat reached a group's acts");
		r.set[FZN_RULED_FILES] = 1u;
		r.rank[FZN_RULED_FILES] = FZN_RANK_TRACE;
		CHECK(fzn_pressure_ruled_rank(&r, FZN_METER_FILES, NULL, 0u) == FZN_RANK_TRACE
		              && fzn_pressure_ruled_rank(NULL, FZN_METER_FILES, NULL, 0u) == FZN_RANK_REFETCH,
		      "a rule on files did not stand, or NULL was not the defaults");
		CHECK(fzn_pressure_ruled_rank(&r, FZN_METER_JOURNAL, NULL, 0u) >= FZN_RANK_CONTROL
		              && fzn_pressure_ruled_rank(&r, FZN_METER_LOGS, NULL, 0u) >= FZN_RANK_CONTROL,
		      "a rule reached what must work");
		for (i = 0; i < FZN_RULED_COUNT; i++)
			CHECK(strcmp(fzn_pressure_rule_name((fzn_pressure_ruled_t)i), "unknown") != 0,
			      "a ruled kind has no name");
	}

	/* TURNS: one class alone may have it all. */
	{
		fzn_pressure_turns_t t;
		unsigned got[FZN_TURN_CLASSES], c;

		memset(&t, 0, sizeof(t));
		for (i = 0, got[0] = 0; i < 2u * FZN_PRESSURE_TURNS_PER_S; i++)
			got[0] += (unsigned)fzn_pressure_turn(&t, FZN_TURN_LOGGING, 10u);
		CHECK(got[0] == FZN_PRESSURE_TURNS_PER_S, "one class alone did not have every turn");

		/* A FLOOD BESIDE A QUIET CLASS: the quiet one is never kept waiting. */
		memset(&t, 0, sizeof(t));
		(void)fzn_pressure_turn(&t, FZN_TURN_PEERS, 10u);
		(void)fzn_pressure_turn(&t, FZN_TURN_LOGGING, 10u);
		memset(got, 0, sizeof(got));
		for (i = 0; i < 4u * FZN_PRESSURE_TURNS_PER_S; i++)
			got[FZN_TURN_LOGGING] += (unsigned)fzn_pressure_turn(&t, FZN_TURN_LOGGING, 11u);
		for (i = 0; i < 8u; i++)
			got[FZN_TURN_PEERS] += (unsigned)fzn_pressure_turn(&t, FZN_TURN_PEERS, 11u);
		CHECK(got[FZN_TURN_PEERS] == 8u, "a revocation waited behind a flood of logs");
		CHECK(got[FZN_TURN_LOGGING] > FZN_PRESSURE_TURNS_PER_S / 3u, "the flood had no more than its share of idle turns");

		/* ALL ASKING AT ONCE, round and round: equal to within a turn. */
		memset(&t, 0, sizeof(t));
		for (c = 0; c < FZN_TURN_CLASSES; c++)
			(void)fzn_pressure_turn(&t, (fzn_turn_class_t)c, 10u);
		memset(got, 0, sizeof(got));
		for (i = 0; i < 2u * FZN_PRESSURE_TURNS_PER_S; i++)
			for (c = 0; c < FZN_TURN_CLASSES; c++)
				got[c] += (unsigned)fzn_pressure_turn(&t, (fzn_turn_class_t)c, 11u);
		for (c = 0; c < FZN_TURN_CLASSES; c++)
			CHECK(got[c] == FZN_PRESSURE_TURNS_PER_S / FZN_TURN_CLASSES, "a class took other than its share");

		/* EVERY FAMILY OF WHAT MUST WORK HAS A CLASS, and what the ladder sheds none. */
		CHECK(fzn_pressure_turn_class(FZN_METER_JOURNAL) == FZN_TURN_PROPAGATION
		              && fzn_pressure_turn_class(FZN_METER_CONTACT_DEVICES) == FZN_TURN_PEERS
		              && fzn_pressure_turn_class(FZN_METER_EXTENSION) == FZN_TURN_COMMANDS
		              && fzn_pressure_turn_class(FZN_METER_LOGS) == FZN_TURN_LOGGING
		              && fzn_pressure_turn_class(FZN_METER_FILES) == FZN_TURN_CLASSES
		              && fzn_pressure_turn_class(FZN_METER_OTHER) == FZN_TURN_CLASSES,
		      "a family took its turn in the wrong class");
	}

	for (i = 0; i <= FZN_PRESSURE_SURVIVAL; i++)
		CHECK(strcmp(fzn_pressure_state_str((fzn_pressure_state_t)i), "unknown") != 0,
		      "a state has no name");

	printf("pressure_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
