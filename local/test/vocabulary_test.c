/* The bound raidcfgd asked for, and the tri-state it inherits.
 *
 * The cases worth having are the ones where an answer could be definite and
 * wrong. A verb nobody may ask for is an easy no; a verb somebody may ask for,
 * asked by a peer whose groups could not be read, is the case that decides
 * whether this module is safe to put in front of a destructive command.
 */

#include "../vocabulary.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		fprintf(stderr, "  FAIL vocabulary_test.c:%d: %s\n", line, what);
	}
}

#define check(ok, what) check_at((ok) ? 1 : 0, __LINE__, (what))

static const uint8_t STATUS[] = "status";
static const uint8_t MONITOR[] = "monitor";
static const uint8_t DESTROY[] = "destroy";

#define V(x) (x), (sizeof(x) - 1u)

/* A peer holding `disk` (6) and `cdrom` (24), with a readable group list. */
static void known_peer(fzn_peer_t *p)
{
	memset(p, 0, sizeof(*p));
	p->primary_gid = 1000;
	p->groups[0] = 6;
	p->groups[1] = 24;
	p->group_count = 2;
	p->groups_known = 1;
}

/* The same peer whose /proc read failed. */
static void unknown_peer(fzn_peer_t *p)
{
	known_peer(p);
	p->group_count = 0;
	p->groups_known = 0;
}

int main(void)
{
	fzn_peer_t p;
	/* A consumer's table. This library cannot tell these apart and must
	 * not: `destroy` is here to show that the module treats it exactly as
	 * it treats `status`, and that only the table says otherwise. */
	const fzn_verb_rule_t rules[] = {
		{ 6, V(STATUS) },
		{ 6, V(MONITOR) },
		{ 99, V(DESTROY) }, /* a group this peer does not hold */
	};
	const size_t n = sizeof(rules) / sizeof(rules[0]);

	known_peer(&p);
	check(fzn_vocabulary_admit(&p, V(STATUS), rules, n) == FZN_PEER_MEMBER,
	      "a verb the peer's group may ask for was refused");
	check(fzn_vocabulary_admit(&p, V(MONITOR), rules, n) == FZN_PEER_MEMBER,
	      "a second verb for the same group was refused");
	check(fzn_vocabulary_admit(&p, V(DESTROY), rules, n) == FZN_PEER_NOT_MEMBER,
	      "a verb reserved to a group the peer does not hold was admitted -- which is "
	      "the group boundary this module exists to keep");

	/* A verb in no rule at all. */
	{
		static const uint8_t unknown_verb[] = "reboot";

		check(fzn_vocabulary_admit(&p, V(unknown_verb), rules, n) == FZN_PEER_NOT_MEMBER,
		      "a verb no rule names was admitted");
	}

	/* THE CASE THAT MATTERS. The peer may or may not hold group 6; the
	 * /proc read failed, so nobody can tell. A rule names this verb for
	 * that group, so the answer is UNKNOWN -- and NOT the definite `no`
	 * that a careless implementation returns, nor the `yes` that a
	 * permissive one does. */
	unknown_peer(&p);
	check(fzn_vocabulary_admit(&p, V(STATUS), rules, n) == FZN_PEER_UNKNOWN,
	      "a peer whose groups could not be read got a definite answer about a verb "
	      "some group may ask for");
	check(fzn_vocabulary_admit(&p, V(STATUS), rules, n) != FZN_PEER_MEMBER,
	      "an unreadable group list admitted a verb, turning a failed read into an allow");

	/* But a verb no rule names is still a definite no, even then: nothing
	 * about the peer's groups could change it. */
	{
		static const uint8_t unknown_verb[] = "reboot";

		check(fzn_vocabulary_admit(&p, V(unknown_verb), rules, n) == FZN_PEER_NOT_MEMBER,
		      "a verb no rule names became UNKNOWN because the group list was");
	}

	/* THE TABLE'S ORDER MUST NOT DECIDE THE ANSWER.
	 *
	 * The discriminating half is the READABLE peer below: rule 99 is a
	 * group it does not hold and rule 6 is one it does, in that order, so
	 * an implementation returning on the first match answers NOT_MEMBER
	 * where the rules say MEMBER. Confirmed by mutation.
	 *
	 * The unknown-peer half above it does NOT discriminate, and saying so
	 * is the point: `groups_known` is a property of the peer rather than of
	 * a rule, so an unreadable peer answers UNKNOWN for every gid and an
	 * early return would answer UNKNOWN too. It is kept because it is the
	 * control -- without it, "the reordered table still says MEMBER" is
	 * satisfied by a function that never reports anything else. */
	{
		const fzn_verb_rule_t reordered[] = {
			{ 99, V(STATUS) }, /* a group the peer does not hold */
			{ 6, V(STATUS) },  /* one whose membership is unknown */
		};

		unknown_peer(&p);
		check(fzn_vocabulary_admit(&p, V(STATUS), reordered, 2) == FZN_PEER_UNKNOWN,
		      "the table's order changed the verdict");
		known_peer(&p);
		check(fzn_vocabulary_admit(&p, V(STATUS), reordered, 2) == FZN_PEER_MEMBER,
		      "a readable peer was refused by the reordered table");
	}

	/* THE FRAMING BOUND. Longer than FZN_VERB_MAX is refused, not
	 * truncated: truncation would let a long verb match a short rule. */
	{
		uint8_t long_verb[FZN_VERB_MAX + 8u];

		known_peer(&p);
		memset(long_verb, 'a', sizeof(long_verb));
		memcpy(long_verb, STATUS, sizeof(STATUS) - 1u);
		check(fzn_vocabulary_admit(&p, long_verb, sizeof(long_verb), rules, n) ==
		              FZN_PEER_NOT_MEMBER,
		      "an over-long verb beginning with a real one was admitted, so it was "
		      "truncated rather than refused");
		check(fzn_vocabulary_admit(&p, long_verb, FZN_VERB_MAX, rules, n) ==
		              FZN_PEER_NOT_MEMBER,
		      "a verb exactly at the bound matched a shorter rule");
		check(fzn_vocabulary_admit(&p, STATUS, 0, rules, n) == FZN_PEER_NOT_MEMBER,
		      "an empty verb was admitted");
	}

	/* A prefix must not match, and neither must a longer verb sharing one:
	 * length is compared before the bytes, and both directions are here
	 * because only one of them is the obvious way to get it wrong. */
	check(fzn_vocabulary_admit(&p, STATUS, 3, rules, n) == FZN_PEER_NOT_MEMBER,
	      "a prefix of a real verb was admitted");
	{
		static const uint8_t longer[] = "statuses";

		check(fzn_vocabulary_admit(&p, V(longer), rules, n) == FZN_PEER_NOT_MEMBER,
		      "a verb with a real one as its prefix was admitted");
	}

	/* A rule this module cannot honour is skipped rather than obeyed. */
	{
		const fzn_verb_rule_t bad[] = {
			{ 6, NULL, 6 },
			{ 6, STATUS, 0 },
			{ 6, STATUS, FZN_VERB_MAX + 1u },
		};

		known_peer(&p);
		check(fzn_vocabulary_admit(&p, V(STATUS), bad, 3) == FZN_PEER_NOT_MEMBER,
		      "a malformed rule admitted a verb");
	}

	/* Arguments. An empty table denies everything, which is what a
	 * consumer that has not filled one in yet should get. */
	check(fzn_vocabulary_admit(NULL, V(STATUS), rules, n) == FZN_PEER_UNKNOWN,
	      "a null peer got a definite answer");
	check(fzn_vocabulary_admit(&p, NULL, 6, rules, n) == FZN_PEER_UNKNOWN,
	      "a null verb got a definite answer");
	check(fzn_vocabulary_admit(&p, V(STATUS), NULL, 3) == FZN_PEER_UNKNOWN,
	      "a null table with a non-zero count got a definite answer");
	check(fzn_vocabulary_admit(&p, V(STATUS), NULL, 0) == FZN_PEER_NOT_MEMBER,
	      "an empty table admitted a verb");

	/*
	 * `fzn_vocabulary_names`: WHICH KIND OF NOT_MEMBER IS THIS?
	 *
	 * `admit` gives the same verdict when the table does not cover a verb
	 * and when it covers it and denies this peer. Those are a configuration
	 * finding and an access decision, and they want opposite responses. sec
	 * 203.
	 */
	{
		static const uint8_t unnamed[] = "reboot";

		known_peer(&p);

		/* THE PAIR. Both are NOT_MEMBER and only one is about the peer. */
		check(fzn_vocabulary_admit(&p, V(DESTROY), rules, n) == FZN_PEER_NOT_MEMBER &&
		              fzn_vocabulary_names(V(DESTROY), rules, n) == 1,
		      "a verb the table reserves to another group was reported as one the "
		      "policy does not cover, which sends an operator to the config "
		      "instead of to the group membership");
		check(fzn_vocabulary_admit(&p, V(unnamed), rules, n) == FZN_PEER_NOT_MEMBER &&
		              fzn_vocabulary_names(V(unnamed), rules, n) == 0,
		      "a verb no rule names was reported as one the policy covers, which "
		      "sends an operator to the group membership instead of to the config");

		/* AND IT IS NOT AN AUTHORISATION. A named verb the peer may ask
		 * for and a named verb it may not both answer 1. */
		check(fzn_vocabulary_names(V(STATUS), rules, n) == 1,
		      "a verb the peer may ask for is not named by the table");

		/* THE BOUNDS MUST BE THE SAME AS `admit`'s, or the two combine
		 * into a contradiction: the policy knowing a verb it cannot
		 * express. */
		check(fzn_vocabulary_names(STATUS, 0, rules, n) == 0,
		      "an empty verb was named by the table");
		check(fzn_vocabulary_names(STATUS, FZN_VERB_MAX + 1u, rules, n) == 0,
		      "a verb longer than the table can carry was named by it");
		check(fzn_vocabulary_names(NULL, 6, rules, n) == 0, "a null verb was named");
		check(fzn_vocabulary_names(V(STATUS), NULL, 3) == 0,
		      "a null table with a non-zero count named a verb");
		check(fzn_vocabulary_names(V(STATUS), NULL, 0) == 0,
		      "an empty table named a verb");
	}

	/*
	 * A RULE `admit` IGNORES MUST NOT BE ONE `names` COUNTS. Both call one
	 * predicate for exactly this reason -- otherwise a table of unhonourable
	 * rules would report "the policy covers this verb and denies you" about
	 * a policy that ignores every rule in it.
	 */
	{
		const fzn_verb_rule_t bad[] = {
			{ 6, NULL, 6 },
			{ 6, STATUS, 0 },
			{ 6, STATUS, FZN_VERB_MAX + 1u },
		};

		known_peer(&p);
		check(fzn_vocabulary_admit(&p, V(STATUS), bad, 3) == FZN_PEER_NOT_MEMBER,
		      "a malformed rule admitted a verb");
		check(fzn_vocabulary_names(V(STATUS), bad, 3) == 0,
		      "a rule this module cannot honour was counted as naming a verb, so "
		      "the two functions disagree about what the table says");
	}

	printf("vocabulary_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
