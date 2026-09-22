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

	/* A VERB ONE BYTE OFF A NAMED ONE IS NOT THAT VERB. The rule names
	 * "status" and the peer holds its group; "statuz" is the same length and
	 * differs only in the last byte. The match reads the WHOLE verb, so it
	 * does not admit -- a comparison reading a prefix would grant a peer a
	 * verb no rule names, an authorisation by near miss. Every verb above
	 * differs from the others in an earlier byte, where any length separates
	 * them. */
	{
		static const uint8_t near_status[] = "statuz";

		check(fzn_vocabulary_admit(&p, V(near_status), rules, n) == FZN_PEER_NOT_MEMBER,
		      "a verb one byte off a named one was admitted, so the verb match reads a "
		      "prefix");
		check(fzn_vocabulary_names(V(near_status), rules, n) == 0,
		      "a verb one byte off a named one was reported as named");
	}

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

	/* AND A VERB OF EXACTLY THE BOUND MATCHES A RULE OF EXACTLY THE BOUND.
	 * The over-long case above pairs a MAX-length verb with short rules, so
	 * it answers NOT_MEMBER whether the length checks read `> MAX` or the
	 * tighter `>= MAX`; only a MAX-length verb meeting a MAX-length rule
	 * separates them. FZN_VERB_MAX is the longest verb both the query and a
	 * rule accept, and rejecting the endpoint would refuse a verb the
	 * policy can name. */
	{
		uint8_t max_verb[FZN_VERB_MAX];
		const fzn_verb_rule_t at_max[] = { { 6, max_verb, FZN_VERB_MAX } };

		memset(max_verb, 'z', sizeof(max_verb));
		known_peer(&p);
		check(fzn_vocabulary_admit(&p, max_verb, FZN_VERB_MAX, at_max, 1) ==
		              FZN_PEER_MEMBER,
		      "a verb of exactly FZN_VERB_MAX did not match a rule of the same length");
		check(fzn_vocabulary_names(max_verb, FZN_VERB_MAX, at_max, 1) == 1,
		      "a verb of exactly FZN_VERB_MAX was not named by a rule of the same length");
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

	/* THE VERB TABLE IS PROVED BY A ROUND TRIP, NOT BY BEING READ.
	 *
	 * `VERBS` in vocabulary.c is a designated-initialiser array, so a verb
	 * added to the enum and forgotten there initialises to { NULL, 0, 0 }
	 * and `fzn_verb_name` answers NULL -- which reads exactly like a value
	 * outside the enum. Nothing in the module can tell those apart. This
	 * walks the whole set and requires each to name itself and parse back,
	 * so the gap becomes a failure here instead of a verb that silently
	 * does not exist. */
	{
		fzn_verb_t v;
		size_t named = 0;

		for (v = (fzn_verb_t)1; (size_t)v < FZN_VERB_COUNT;
		     v = (fzn_verb_t)((size_t)v + 1u)) {
			const char *name = fzn_verb_name(v);

			check(name != NULL,
			      "a verb in the enum has no spelling, so it was added to "
			      "vocabulary.h and not to the table in vocabulary.c");
			if (!name)
				continue;
			named++;
			check(fzn_verb_name_len(v) == strlen(name),
			      "a verb's stated length disagrees with its spelling, so a "
			      "caller matching bytes reads past or stops short");
			check(fzn_verb_parse((const uint8_t *)name, strlen(name)) == v,
			      "a verb does not parse back to itself");
		}
		check(named == FZN_VERB_COUNT - 1u,
		      "the walk did not reach every verb");

		/* No two verbs share a spelling. A duplicate would make `parse`
		 * answer the lower one for both, silently, and the round trip
		 * above would still pass for whichever it answered. */
		{
			fzn_verb_t a, b;
			int clash = 0;

			for (a = (fzn_verb_t)1; (size_t)a < FZN_VERB_COUNT;
			     a = (fzn_verb_t)((size_t)a + 1u))
				for (b = (fzn_verb_t)((size_t)a + 1u);
				     (size_t)b < FZN_VERB_COUNT;
				     b = (fzn_verb_t)((size_t)b + 1u))
					if (fzn_verb_name(a) && fzn_verb_name(b) &&
					    strcmp(fzn_verb_name(a), fzn_verb_name(b)) == 0)
						clash = 1;
			check(clash == 0, "two verbs share a spelling");
		}
	}

	/* What `parse` must NOT accept. A near miss matters more than a wholly
	 * different word: the bound and the exactness are what stop `statuses`
	 * reaching a rule written for `status`. */
	check(fzn_verb_parse(NULL, 6u) == FZN_VERB_NONE, "a NULL verb parsed");
	check(fzn_verb_parse((const uint8_t *)"", sizeof("") - 1u) == FZN_VERB_NONE, "an empty verb parsed");
	check(fzn_verb_parse((const uint8_t *)"stat", sizeof("stat") - 1u) == FZN_VERB_NONE, "a prefix of a verb parsed");
	check(fzn_verb_parse((const uint8_t *)"statuses", sizeof("statuses") - 1u) == FZN_VERB_NONE,
	      "a verb with a real one as its prefix parsed");
	check(fzn_verb_parse((const uint8_t *)"STATUS", sizeof("STATUS") - 1u) == FZN_VERB_NONE,
	      "a verb parsed case-insensitively, which needs a locale-independent "
	      "fold this library does not have");
	check(fzn_verb_parse((const uint8_t *)"status", sizeof("status") - 1u) == FZN_VERB_STATUS, "the control did not parse");
	{
		uint8_t big[FZN_VERB_MAX + 2u];

		memset(big, 'a', sizeof(big));
		check(fzn_verb_parse(big, FZN_VERB_MAX + 1u) == FZN_VERB_NONE,
		      "a verb longer than a rule could name was parsed, so `parse` and "
		      "`admit` disagree about what a verb is");
	}

	/* Mutation, which all three consumers would otherwise each list. */
	check(fzn_verb_mutates(FZN_VERB_STATUS) == 0 &&
	      fzn_verb_mutates(FZN_VERB_LOG) == 0 &&
	      fzn_verb_mutates(FZN_VERB_GET) == 0 &&
	      fzn_verb_mutates(FZN_VERB_LIST) == 0 &&
	      fzn_verb_mutates(FZN_VERB_FETCH) == 0,
	      "a reading verb is reported as changing state");
	check(fzn_verb_mutates(FZN_VERB_SET) == 1 &&
	      fzn_verb_mutates(FZN_VERB_ADD) == 1 &&
	      fzn_verb_mutates(FZN_VERB_REMOVE) == 1 &&
	      fzn_verb_mutates(FZN_VERB_PUT) == 1 &&
	      fzn_verb_mutates(FZN_VERB_GRANT) == 1 &&
	      fzn_verb_mutates(FZN_VERB_REVOKE) == 1,
	      "a writing verb is reported as read-only, so a daemon refusing while "
	      "read-only would let it through");
	check(fzn_verb_mutates(FZN_VERB_NONE) == 0, "NONE is not described as mutating");

	/* A rule built from a verb is one the table functions honour -- the
	 * point of the constructor, since a consumer spelling the bytes by
	 * hand is the duplication this set exists to remove. */
	{
		fzn_verb_rule_t r = fzn_verb_rule(6u, FZN_VERB_STATUS);
		fzn_verb_rule_t none = fzn_verb_rule(6u, FZN_VERB_NONE);

		check(fzn_vocabulary_names(V(STATUS), &r, 1) == 1,
		      "a rule built by fzn_verb_rule does not name its own verb");
		known_peer(&p);
		check(fzn_vocabulary_admit(&p, V(STATUS), &r, 1) == FZN_PEER_MEMBER,
		      "a peer in the rule's group was refused its own verb");
		check(fzn_vocabulary_names(V(STATUS), &none, 1) == 0,
		      "a rule for FZN_VERB_NONE named a verb, so a mistyped enum value "
		      "would match rather than fail closed");
	}

	/* SPLITTING A REQUEST LINE. The node stops at the first space and hands
	 * the rest over untouched. */
	{
		fzn_request_t req;

		check(fzn_vocabulary_split((const uint8_t *)"get thing", 9u, &req) == 1 &&
		      req.parsed == FZN_VERB_GET && req.verb_len == 3u &&
		      req.arg_len == 5u && memcmp(req.arg, "thing", 5u) == 0,
		      "a verb and argument did not split");
		check(fzn_vocabulary_split((const uint8_t *)"get a b", 7u, &req) == 1 &&
		      req.arg_len == 3u && memcmp(req.arg, "a b", 3u) == 0,
		      "the argument was tokenised past the first space, which is the "
		      "consumer's business and not this library's");
		check(fzn_vocabulary_split((const uint8_t *)"get", 3u, &req) == 1 &&
		      req.parsed == FZN_VERB_GET && req.arg == NULL && req.arg_len == 0u,
		      "a verb with no argument did not split");
		check(fzn_vocabulary_split((const uint8_t *)"get ", 4u, &req) == 1 &&
		      req.arg != NULL && req.arg_len == 0u,
		      "`get ` and `get` were made the same request -- an empty argument "
		      "is a caller asking for the empty subject, not an absent one");
		check(fzn_vocabulary_split((const uint8_t *)"destroy", 7u, &req) == 1 &&
		      req.parsed == FZN_VERB_NONE && req.verb_len == 7u,
		      "a consumer's own verb was refused rather than handed over as "
		      "NONE, which would make bypass-until-gained impossible");
		check(fzn_vocabulary_split((const uint8_t *)" get", 4u, &req) == 0,
		      "a leading space was skipped, so ` destroy` and `destroy` are the "
		      "same request and a filter is got past with whitespace");
		check(fzn_vocabulary_split((const uint8_t *)"", 0u, &req) == 0,
		      "an empty line split");
		check(fzn_vocabulary_split(NULL, 4u, &req) == 0, "a NULL line split");
		check(fzn_vocabulary_split((const uint8_t *)"get x", 5u, NULL) == 0,
		      "a NULL output split");
		{
			uint8_t big[FZN_VERB_MAX + 2u];

			memset(big, 'a', sizeof(big));
			check(fzn_vocabulary_split(big, FZN_VERB_MAX + 1u, &req) == 0 &&
			      req.verb == NULL && req.verb_len == 0u,
			      "an overlong verb split, or left the request half-filled");
		}
	}

	printf("vocabulary_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
