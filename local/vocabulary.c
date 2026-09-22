/* See vocabulary.h. */

#include "vocabulary.h"

#include "../constant_time/constant_time.h"

#include <stddef.h>

/* Does this rule name this verb?
 *
 * ONE IMPLEMENTATION, called from both public functions, because the two ask
 * the same question of a rule and a second copy is how they would come to
 * disagree. The bounds are part of the question rather than a precondition:
 * a rule whose verb is absent, empty or longer than FZN_VERB_MAX is one this
 * module cannot honour, and a function that skipped that check would report a
 * verb as named by a rule that `fzn_vocabulary_admit` then ignores.
 *
 * Constant-time on the comparison for the same reason `admit` is: the two
 * must not differ in what they leak either. */
static int rule_names(const fzn_verb_rule_t *rule, const uint8_t *verb, size_t verb_len)
{
	if (!rule->verb || rule->verb_len == 0 || rule->verb_len > FZN_VERB_MAX)
		return 0;
	if (rule->verb_len != verb_len)
		return 0;

	return fzn_ct_memeq(rule->verb, verb, verb_len) ? 1 : 0;
}

int fzn_vocabulary_names(const uint8_t *verb, size_t verb_len, const fzn_verb_rule_t *rules,
                          size_t rule_count)
{
	size_t i;

	if (!verb || (!rules && rule_count > 0))
		return 0;

	/* THE SAME BOUND `admit` APPLIES, and it must be the same or the two
	 * answers combine into a contradiction: a verb longer than any rule can
	 * carry is not named by the table, and saying otherwise would have a
	 * caller report "the policy knows this verb and denies you" about a verb
	 * the policy cannot express. */
	if (verb_len == 0 || verb_len > FZN_VERB_MAX)
		return 0;

	for (i = 0; i < rule_count; i++) {
		if (rule_names(&rules[i], verb, verb_len))
			return 1;
	}

	return 0;
}

fzn_peer_verdict_t fzn_vocabulary_admit(const fzn_peer_t *peer, const uint8_t *verb,
                                         size_t verb_len, const fzn_verb_rule_t *rules,
                                         size_t rule_count)
{
	int matched_a_rule = 0;
	int unknown_seen = 0;

	if (!peer || !verb || (!rules && rule_count > 0))
		return FZN_PEER_UNKNOWN;

	/* A verb no rule could name. Definite, and safe to be definite about:
	 * every rule's verb is at most FZN_VERB_MAX, so a longer one matches
	 * nothing whatever the table says. */
	if (verb_len == 0 || verb_len > FZN_VERB_MAX)
		return FZN_PEER_NOT_MEMBER;

	/* THE SCAN CONTINUES PAST A MATCH THAT DID NOT GRANT, and stops at the
	 * first that did. MEMBER is the strongest answer this function has, so
	 * nothing later can improve on it; anything weaker has to keep looking.
	 *
	 * Not for the timing: the verdict goes back to the same peer that
	 * asked, so what an early return would leak is already in the answer.
	 *
	 * THE REASON THIS COMMENT USED TO GIVE WAS UNREACHABLE, and it is worth
	 * replacing rather than deleting because the shape recurs. It said the
	 * whole table is needed because "a rule matching this verb for a group
	 * the peer cannot be shown to hold makes the answer UNKNOWN rather than
	 * NOT_MEMBER, and that rule may sit after one that did not match" --
	 * i.e. that one peer could yield both NOT_MEMBER and UNKNOWN depending
	 * on rule order.
	 *
	 * It cannot. `fzn_peer_group_verdict` branches on `peer->groups_known`,
	 * which is a property of the PEER and does not vary between rules: with
	 * it clear every gid answers UNKNOWN, and with it set every gid answers
	 * MEMBER or NOT_MEMBER. The two verdicts the paragraph set against each
	 * other never coexist for one peer.
	 *
	 * The real reason is the plainer one: a rule that GRANTS may sit after
	 * one that does not, so returning on the first match would answer
	 * NOT_MEMBER for a peer that a later rule admits. That is what the
	 * suite's reordered-table case actually catches -- confirmed by
	 * mutation, since a comment claiming a property is not evidence the
	 * property is held or that anything checks it. */
	for (size_t i = 0; i < rule_count; i++) {
		fzn_peer_verdict_t held;

		/* A rule this module cannot honour is not one it obeys, and the
		 * bound is inside `rule_names` so that `fzn_vocabulary_names`
		 * cannot answer differently. */
		if (!rule_names(&rules[i], verb, verb_len))
			continue;

		matched_a_rule = 1;
		held = fzn_peer_group_verdict(peer, rules[i].gid);
		if (held == FZN_PEER_MEMBER)
			return FZN_PEER_MEMBER;
		if (held == FZN_PEER_UNKNOWN)
			unknown_seen = 1;
	}

	if (!matched_a_rule)
		return FZN_PEER_NOT_MEMBER;

	return unknown_seen ? FZN_PEER_UNKNOWN : FZN_PEER_NOT_MEMBER;
}

/* THE SPELLINGS, and the one place they exist.
 *
 * A designated initialiser per verb so the table is indexed by the enum
 * rather than ordered to match it: a verb inserted in the middle of the enum
 * cannot silently take another's spelling, which an ordered list makes
 * possible and makes invisible.
 *
 * WHAT IT CANNOT CATCH BY ITSELF is a verb ADDED to the enum and forgotten
 * here -- the gap initialises to { NULL, 0, 0 } and `fzn_verb_name` answers
 * NULL, which reads exactly like a value outside the enum. `vocabulary_test`
 * walks 1..FZN_VERB_COUNT-1 and requires every one to have a name, a length
 * equal to that name's, and to parse back to itself. That round trip is the
 * proof; this table is only the data. */
static const struct {
	const char *name;
	size_t len;
	int mutates;
} VERBS[FZN_VERB_COUNT] = {
	[FZN_VERB_NONE]   = { NULL,     0u, 0 },
	[FZN_VERB_STATUS] = { "status", 6u, 0 },
	[FZN_VERB_LOG]    = { "log",    3u, 0 },
	[FZN_VERB_GET]    = { "get",    3u, 0 },
	[FZN_VERB_SET]    = { "set",    3u, 1 },
	[FZN_VERB_LIST]   = { "list",   4u, 0 },
	[FZN_VERB_ADD]    = { "add",    3u, 1 },
	[FZN_VERB_REMOVE] = { "remove", 6u, 1 },
	[FZN_VERB_FETCH]  = { "fetch",  5u, 0 },
	[FZN_VERB_PUT]    = { "put",    3u, 1 },
	[FZN_VERB_GRANT]  = { "grant",  5u, 1 },
	[FZN_VERB_REVOKE] = { "revoke", 6u, 1 }
};

static int in_table(fzn_verb_t verb)
{
	return (size_t)verb < FZN_VERB_COUNT && VERBS[(size_t)verb].name != NULL;
}

const char *fzn_verb_name(fzn_verb_t verb)
{
	return in_table(verb) ? VERBS[(size_t)verb].name : NULL;
}

size_t fzn_verb_name_len(fzn_verb_t verb)
{
	return in_table(verb) ? VERBS[(size_t)verb].len : 0u;
}

int fzn_verb_mutates(fzn_verb_t verb)
{
	return in_table(verb) ? VERBS[(size_t)verb].mutates : 0;
}

fzn_verb_t fzn_verb_parse(const uint8_t *verb, size_t verb_len)
{
	size_t i;

	/* The same bound the table functions apply. A verb longer than a rule
	 * could name is not one this library offers either, and answering
	 * otherwise would let `parse` and `admit` disagree about what a verb
	 * even is. */
	if (!verb || verb_len == 0 || verb_len > FZN_VERB_MAX)
		return FZN_VERB_NONE;
	for (i = 1u; i < FZN_VERB_COUNT; i++) {
		if (VERBS[i].name == NULL || VERBS[i].len != verb_len)
			continue;
		/* NOT constant-time, and deliberately so where `rule_names` is.
		 * Which of fuzznet's published verbs a request names is not a
		 * secret -- the set is in this header and the spelling is on
		 * the wire in clear. `rule_names` compares a verb against a
		 * POLICY, where the timing would say which groups a deployment
		 * has rules for, and that is the one worth hiding. */
		if (fzn_ct_memeq(verb, (const uint8_t *)VERBS[i].name, verb_len))
			return (fzn_verb_t)i;
	}
	return FZN_VERB_NONE;
}

fzn_verb_rule_t fzn_verb_rule(uint32_t gid, fzn_verb_t verb)
{
	fzn_verb_rule_t rule;

	rule.gid = gid;
	rule.verb = in_table(verb) ? (const uint8_t *)VERBS[(size_t)verb].name : NULL;
	rule.verb_len = in_table(verb) ? VERBS[(size_t)verb].len : 0u;
	return rule;
}

int fzn_vocabulary_split(const uint8_t *line, size_t line_len, fzn_request_t *out)
{
	size_t i;

	if (!out)
		return 0;
	/* Zeroed rather than half-filled on every refusal below, so a caller
	 * that ignores the return value reads an empty request instead of
	 * whatever its stack held. */
	out->parsed = FZN_VERB_NONE;
	out->verb = NULL;
	out->verb_len = 0u;
	out->arg = NULL;
	out->arg_len = 0u;
	if (!line || line_len == 0)
		return 0;

	for (i = 0; i < line_len && line[i] != (uint8_t)' '; i++)
		;
	/* A line that begins with a space has no verb. Skipping the leading
	 * space instead would make ` destroy` and `destroy` the same request,
	 * which is the shape of every filter somebody gets past by adding
	 * whitespace. */
	if (i == 0 || i > FZN_VERB_MAX)
		return 0;

	out->verb = line;
	out->verb_len = i;
	out->parsed = fzn_verb_parse(line, i);
	if (i < line_len) {
		/* Everything after the single separating space, unexamined and
		 * possibly empty: `get ` asks for the empty subject, which is
		 * a different request from `get`. */
		out->arg = line + i + 1u;
		out->arg_len = line_len - i - 1u;
	}
	return 1;
}
