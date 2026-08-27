/* See vocabulary.h. */

#include "vocabulary.h"

#include "../constant_time/constant_time.h"

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

		if (!rules[i].verb || rules[i].verb_len == 0 ||
		    rules[i].verb_len > FZN_VERB_MAX)
			continue; /* a rule this module cannot honour is not one it obeys */
		if (rules[i].verb_len != verb_len)
			continue;
		if (!fzn_ct_memeq(rules[i].verb, verb, verb_len))
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
