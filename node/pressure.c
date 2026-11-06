/* The ladder. node/pressure.h says what and why. */

#include "pressure.h"
#include "types.h"

#include <string.h>

const char *fzn_pressure_state_str(fzn_pressure_state_t state)
{
	switch (state) {
	case FZN_PRESSURE_CALM:
		return "calm";
	case FZN_PRESSURE_TIGHT:
		return "tight";
	case FZN_PRESSURE_SCARCE:
		return "scarce";
	case FZN_PRESSURE_SURVIVAL:
		return "survival";
	}
	return "unknown";
}

static fzn_pressure_state_t store_level(const fzn_pressure_input_t *in)
{
	if (!in->store_held)
		return FZN_PRESSURE_CALM;
	if (in->delta_budget && in->delta_bytes >= in->delta_budget / 8u * 7u)
		return FZN_PRESSURE_SURVIVAL;
	if (in->delta_budget && in->delta_bytes >= in->delta_budget / 2u)
		return FZN_PRESSURE_SCARCE;
	return FZN_PRESSURE_TIGHT;
}

static fzn_pressure_state_t memory_level(const fzn_pressure_input_t *in)
{
	uint64_t free_percent;

	if (!in->mem_total_kb)
		return FZN_PRESSURE_CALM;
	free_percent = in->mem_available_kb / (in->mem_total_kb / 100u + 1u);
	if (free_percent < 2u)
		return FZN_PRESSURE_SURVIVAL;
	if (free_percent < 5u)
		return FZN_PRESSURE_SCARCE;
	if (free_percent < 10u)
		return FZN_PRESSURE_TIGHT;
	return FZN_PRESSURE_CALM;
}

fzn_pressure_state_t fzn_pressure_level(const fzn_pressure_input_t *in)
{
	fzn_pressure_state_t worst = in->network, s = store_level(in), m = memory_level(in);

	if (s > worst)
		worst = s;
	return m > worst ? m : worst;
}

fzn_pressure_state_t fzn_pressure_step(fzn_pressure_t *p, fzn_pressure_state_t level, int *moved)
{
	fzn_pressure_state_t was = p->state;

	if (level >= p->state) {
		p->state = level;
		p->calm_ticks = 0;
	} else if (++p->calm_ticks >= FZN_PRESSURE_CALM_TICKS) {
		p->state = (fzn_pressure_state_t)(p->state - 1);
		p->calm_ticks = 0;
	}
	if (moved)
		*moved = p->state != was;
	return p->state;
}

int fzn_pressure_admits(fzn_pressure_state_t state, fzn_rank_t rank)
{
	switch (state) {
	case FZN_PRESSURE_CALM:
		return 1;
	case FZN_PRESSURE_TIGHT:
		return rank >= FZN_RANK_REFETCH;
	case FZN_PRESSURE_SCARCE:
		return rank >= FZN_RANK_USER;
	case FZN_PRESSURE_SURVIVAL:
		return rank >= FZN_RANK_CONTROL;
	}
	return 1;
}

fzn_rank_t fzn_pressure_family_rank(fzn_meter_family_t family)
{
	switch (family) {
	case FZN_METER_STREAMS:
		return FZN_RANK_TRACE;
	case FZN_METER_RELAY:
	case FZN_METER_FILE_REFS:
	case FZN_METER_FILES:
		return FZN_RANK_REFETCH;
	case FZN_METER_NOTES:
	case FZN_METER_MESSAGES:
	case FZN_METER_RECONCILE:
		return FZN_RANK_USER;
	case FZN_METER_VERBS:
	case FZN_METER_MEMBERS:
	case FZN_METER_CONTACT_DEVICES:
	case FZN_METER_INTRODUCE:
	case FZN_METER_GROUPS:
	case FZN_METER_JOURNAL:
	case FZN_METER_LOGS:
	case FZN_METER_EXTENSION:
	case FZN_METER_OTHER:
	case FZN_METER_FAMILIES:
		break;
	}
	return FZN_RANK_CONTROL;
}

fzn_rank_t fzn_pressure_request_rank(fzn_meter_family_t family, const uint8_t *payload,
                                     size_t len)
{
	if (payload && len >= 2u && payload[0] == FZN_TYPES_VERSION_SHARED
	    && (payload[1] == FZN_TYPE_GROUP_LINES_SYNC || payload[1] == FZN_TYPE_GROUP_LINES))
		return FZN_RANK_REFETCH;
	return fzn_pressure_family_rank(family);
}

fzn_turn_class_t fzn_pressure_turn_class(fzn_meter_family_t family)
{
	switch (family) {
	case FZN_METER_JOURNAL:
	case FZN_METER_GROUPS:
		return FZN_TURN_PROPAGATION;
	case FZN_METER_MEMBERS:
	case FZN_METER_CONTACT_DEVICES:
	case FZN_METER_INTRODUCE:
		return FZN_TURN_PEERS;
	case FZN_METER_VERBS:
	case FZN_METER_EXTENSION:
		return FZN_TURN_COMMANDS;
	case FZN_METER_LOGS:
		return FZN_TURN_LOGGING;
	default:
		return FZN_TURN_CLASSES;
	}
}

int fzn_pressure_turn(fzn_pressure_turns_t *t, fzn_turn_class_t cls, uint64_t now)
{
	unsigned i, used = 0, active = 0, share, owed = 0;

	if (now != t->second) {
		for (i = 0; i < FZN_TURN_CLASSES; i++) {
			t->asked_before[i] = t->asked[i];
			t->asked[i] = 0;
			t->served[i] = 0;
		}
		t->second = now;
	}
	t->asked[cls]++;
	for (i = 0; i < FZN_TURN_CLASSES; i++) {
		used += t->served[i];
		active += i == (unsigned)cls || t->asked_before[i] || t->asked[i];
	}
	share = FZN_PRESSURE_TURNS_PER_S / active;
	/* WHAT THE OTHERS ARE STILL OWED this second is theirs, whoever else is
	 * asking: so a class past its share takes only what nobody is owed. */
	for (i = 0; i < FZN_TURN_CLASSES; i++)
		if (i != (unsigned)cls && (t->asked_before[i] || t->asked[i]) && t->served[i] < share)
			owed += share - t->served[i];
	if (used + owed >= FZN_PRESSURE_TURNS_PER_S)
		return 0;
	t->served[cls]++;
	return 1;
}

const char *fzn_pressure_rule_name(fzn_pressure_ruled_t ruled)
{
	switch (ruled) {
	case FZN_RULED_STREAMS:
		return "streams";
	case FZN_RULED_RELAY:
		return "relay";
	case FZN_RULED_FILES:
		return "files";
	case FZN_RULED_GROUP_LINES:
		return "group-lines";
	case FZN_RULED_NOTES:
		return "notes";
	case FZN_RULED_MESSAGES:
		return "messages";
	case FZN_RULED_RECONCILE:
		return "reconcile";
	case FZN_RULED_COUNT:
		break;
	}
	return "unknown";
}

int fzn_pressure_rule_value(const uint8_t *value, size_t len, fzn_rank_t *rank)
{
	if (len == 5u && memcmp(value, "trace", 5u) == 0)
		*rank = FZN_RANK_TRACE;
	else if (len == 4u && memcmp(value, "copy", 4u) == 0)
		*rank = FZN_RANK_REFETCH;
	else if (len == 4u && memcmp(value, "user", 4u) == 0)
		*rank = FZN_RANK_USER;
	else
		return 0;
	return 1;
}

fzn_rank_t fzn_pressure_ruled_rank(const fzn_pressure_rules_t *rules, fzn_meter_family_t family,
                                   const uint8_t *payload, size_t len)
{
	fzn_rank_t rank = fzn_pressure_request_rank(family, payload, len);
	int which = -1;

	if (!rules)
		return rank;
	if (family == FZN_METER_GROUPS && rank == FZN_RANK_REFETCH)
		which = FZN_RULED_GROUP_LINES;
	else if (family == FZN_METER_STREAMS)
		which = FZN_RULED_STREAMS;
	else if (family == FZN_METER_RELAY)
		which = FZN_RULED_RELAY;
	else if (family == FZN_METER_FILES || family == FZN_METER_FILE_REFS)
		which = FZN_RULED_FILES;
	else if (family == FZN_METER_NOTES)
		which = FZN_RULED_NOTES;
	else if (family == FZN_METER_MESSAGES)
		which = FZN_RULED_MESSAGES;
	else if (family == FZN_METER_RECONCILE)
		which = FZN_RULED_RECONCILE;
	return which >= 0 && rules->set[which] ? rules->rank[which] : rank;
}
