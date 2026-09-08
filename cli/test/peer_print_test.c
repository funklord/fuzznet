/* Tests for cli/peer_print.c.
 *
 * TWO CASES THIS FILE EXISTS FOR.
 *
 * The first is that `fzn_vocabulary_admit` says FZN_PEER_NOT_MEMBER both when
 * no rule names a verb and when rules name it and this peer holds none of
 * those groups. One is a configuration finding and the other is an access
 * decision about a person, and a daemon logging both as "denied" sends an
 * operator to the wrong half of the system.
 *
 * The second is that a verb is bytes a stranger chose. `vocabulary.h` is
 * explicit that this library "cannot tell `status` from `destroy` and must
 * not learn", so a verb reaches this printer unexamined -- and a newline in
 * one, written into a line unescaped, lets a peer forge a log entry
 * underneath its own denial. A peer that cannot run a command writing the
 * record that says somebody did.
 */

#include "../peer_print.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (ok)
		return;

	failures++;
	fprintf(stderr, "  FAIL peer_print_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static const uint8_t STATUS[] = "status";
static const uint8_t DESTROY[] = "destroy";
static const uint8_t UNNAMED[] = "rebot";

#define V(x) (x), (sizeof(x) - 1u)

static void known_peer(fzn_peer_t *p)
{
	memset(p, 0, sizeof(*p));
	p->pid = 4021;
	p->uid = 1000u;
	p->primary_gid = 1000u;
	p->groups[0] = 6u;
	p->groups[1] = 27u;
	p->group_count = 2u;
	p->groups_known = 1;
}

int main(void)
{
	const fzn_verb_rule_t rules[] = {
		{ 6u, V(STATUS) },
		{ 99u, V(DESTROY) }, /* a group this peer does not hold */
	};
	const size_t n = sizeof(rules) / sizeof(rules[0]);
	fzn_peer_t p;
	char line[FZN_PEER_PRINT_MAX];
	char denied_named[FZN_PEER_PRINT_MAX];
	fzn_peer_verdict_t verdict = FZN_PEER_MEMBER;
	int named = 1;
	size_t len = 0u;

	known_peer(&p);

	/* ADMITTED. */
	CHECK(fzn_peer_print(&p, V(STATUS), rules, n, line, sizeof(line), &len, &verdict,
	                     &named) == 0,
	      "an admitted peer would not render");
	CHECK(verdict == FZN_PEER_MEMBER, "an admitted peer was not MEMBER");
	CHECK(named == 1, "a verb the table names was reported as unnamed");
	CHECK(strstr(line, "admitted") != NULL, "an admission did not say so");

	/* THE FIRST CASE. Two denials that must not read alike. */
	CHECK(fzn_peer_print(&p, V(DESTROY), rules, n, line, sizeof(line), &len, &verdict,
	                     &named) == 0,
	      "a denied peer would not render");
	CHECK(verdict == FZN_PEER_NOT_MEMBER, "a verb reserved to another group was admitted");
	CHECK(named == 1, "a verb the table reserves to another group was reported as unnamed");
	memcpy(denied_named, line, sizeof(line));

	CHECK(fzn_peer_print(&p, V(UNNAMED), rules, n, line, sizeof(line), &len, &verdict,
	                     &named) == 0,
	      "an unnamed verb would not render");
	CHECK(verdict == FZN_PEER_NOT_MEMBER, "an unnamed verb was admitted");
	CHECK(named == 0, "a verb no rule names was reported as named");

	/*
	 * THE SAME VERB, TWO TABLES -- and the first draft of this used two
	 * different verbs, which made the two lines differ whatever the reason
	 * clause said. A sabotage replacing both reasons with a bare "denied"
	 * SURVIVED it: the lines still differed, on the verb. Holding the verb
	 * fixed is what leaves the reason as the only thing that can differ.
	 */
	{
		const fzn_verb_rule_t silent[] = { { 6u, V(STATUS) } };
		char not_covered[FZN_PEER_PRINT_MAX];

		CHECK(fzn_peer_print(&p, V(DESTROY), silent, 1u, not_covered,
		                     sizeof(not_covered), &len, &verdict, &named) == 0,
		      "would not render");
		CHECK(verdict == FZN_PEER_NOT_MEMBER, "an uncovered verb was admitted");
		CHECK(named == 0, "a verb this table does not name was reported as named");
		CHECK(strcmp(not_covered, denied_named) != 0,
		      "one verb, denied for two different reasons, produced the same line -- "
		      "so an operator cannot tell a missing rule from a refused person");
	}

	/* THE SECOND CASE. A newline in a verb must not reach the line. */
	{
		static const uint8_t evil[] = "status\nADMITTED: root ran destroy";

		CHECK(fzn_peer_print(&p, V(evil), rules, n, line, sizeof(line), &len,
		                     &verdict, &named) == 0,
		      "a hostile verb would not render");
		CHECK(strchr(line, '\n') == NULL,
		      "a newline in a verb reached the line, so a peer that cannot run a "
		      "command can forge the record saying somebody did");
		CHECK(strstr(line, "\\x0a") != NULL, "the newline was dropped rather than shown");
		CHECK(verdict == FZN_PEER_NOT_MEMBER, "a hostile verb was admitted");
	}

	/* AND THE ESCAPING MUST NOT BE FORGEABLE. A quote would end the verb
	 * early and a backslash would let `\\x0a` be written as text that reads
	 * like an escaped newline in a verb that had none. */
	{
		static const uint8_t quoted[] = "a\"b\\c";

		CHECK(fzn_peer_print(&p, V(quoted), rules, n, line, sizeof(line), &len,
		                     &verdict, &named) == 0,
		      "a quoted verb would not render");
		CHECK(strstr(line, "\\x22") != NULL && strstr(line, "\\x5c") != NULL,
		      "a quote or a backslash in a verb was passed through, so the escaping "
		      "itself can be forged");
		CHECK(strstr(line, "a\"b") == NULL, "the quote reached the line unescaped");
	}

	/* UNREADABLE IS NOT EMPTY, and `group_count` must not be read when the
	 * list is unknown -- peer.h says it is meaningless then. */
	{
		fzn_peer_t unknown;

		known_peer(&unknown);
		unknown.groups_known = 0;
		unknown.group_count = 2u; /* stale, and must not be believed */

		CHECK(fzn_peer_print(&unknown, V(DESTROY), rules, n, line, sizeof(line), &len,
		                     &verdict, &named) == 0,
		      "a peer with an unreadable list would not render");
		CHECK(verdict == FZN_PEER_UNKNOWN,
		      "a peer whose groups could not be read got a definite answer");
		CHECK(strstr(line, "unreadable") != NULL,
		      "an unreadable group list was not said to be unreadable");
		CHECK(strstr(line, "2 groups") == NULL,
		      "the group count was printed for a peer whose list could not be read, "
		      "and peer.h says that count is meaningless then");

		/* THE PRIMARY GID IS ALWAYS KNOWABLE, so a group that IS this
		 * peer's primary one is a definite MEMBER even here. The
		 * verdict is definite and the knowledge is still partial, which
		 * is why the sentence still says unreadable. */
		{
			const fzn_verb_rule_t primary[] = { { 1000u, V(STATUS) } };

			CHECK(fzn_peer_print(&unknown, V(STATUS), primary, 1u, line,
			                     sizeof(line), &len, &verdict, &named) == 0,
			      "would not render");
			CHECK(verdict == FZN_PEER_MEMBER,
			      "a verb reserved to this peer's own primary group was refused "
			      "because the supplementary list could not be read, which is "
			      "the mirror of the bug peer.h exists for");
			CHECK(strstr(line, "unreadable") != NULL,
			      "a definite admission hid that the list could not be read");
		}
	}

	/* NO PEER. Nothing is known, and unknown denies. */
	CHECK(fzn_peer_print(NULL, V(STATUS), rules, n, line, sizeof(line), &len, &verdict,
	                     &named) == 0,
	      "a null peer would not render");
	CHECK(verdict == FZN_PEER_UNKNOWN, "a null peer got a definite answer");
	CHECK(strstr(line, "no peer") != NULL, "a null peer was described as somebody");

	/* NO VERB IS NOT AN EMPTY ONE. */
	CHECK(fzn_peer_print(&p, NULL, 0u, rules, n, line, sizeof(line), &len, &verdict,
	                     &named) == 0,
	      "a null verb would not render");
	CHECK(strstr(line, "(none)") != NULL,
	      "a caller that passed no verb reads as one that passed an empty string");

	/* THE ANSWERS ARE THE LIBRARY'S, NOT A SECOND DECISION. */
	{
		static const uint8_t probes[][8] = { "status", "destroy", "rebot" };
		size_t i;

		known_peer(&p);
		for (i = 0u; i < sizeof(probes) / sizeof(probes[0]); i++) {
			size_t plen = strlen((const char *)probes[i]);

			CHECK(fzn_peer_print(&p, probes[i], plen, rules, n, line, sizeof(line),
			                     &len, &verdict, &named) == 0,
			      "would not render");
			CHECK(verdict == fzn_vocabulary_admit(&p, probes[i], plen, rules, n),
			      "the printer's verdict is not the library's, so a formatter has "
			      "an opinion about authorisation");
			CHECK(named == fzn_vocabulary_names(probes[i], plen, rules, n),
			      "the printer decided for itself whether the table names a verb "
			      "instead of asking, which is the second implementation sec 200 "
			      "draws the line against");
		}
	}

	/* BOTH OUT-PARAMETERS ARE REQUIRED, and a refusal denies. */
	CHECK(fzn_peer_print(&p, V(STATUS), rules, n, line, sizeof(line), &len, NULL,
	                     &named) != 0,
	      "the verdict was optional after all");
	CHECK(fzn_peer_print(&p, V(STATUS), rules, n, line, sizeof(line), &len, &verdict,
	                     NULL) != 0,
	      "the named flag was optional after all");
	{
		char small[8];
		size_t needed = 0u;

		memset(small, '@', sizeof(small));
		verdict = FZN_PEER_MEMBER;
		named = 1;
		CHECK(fzn_peer_print(&p, V(STATUS), rules, n, small, sizeof(small), &needed,
		                     &verdict, &named) != 0,
		      "a buffer too small was written anyway");
		CHECK(needed > sizeof(small), "the size needed was not reported");
		CHECK(small[0] == '@', "a refused render left bytes in the buffer");
		CHECK(verdict == FZN_PEER_UNKNOWN,
		      "a refused render left an admission standing");
		CHECK(named == 0, "a refused render left a claim about the table");
	}

	/* The widest line this can produce must fit what the header promises:
	 * the largest pid, uid and gid, and a full-length verb every byte of
	 * which escapes to four characters. */
	{
		uint8_t worst[FZN_VERB_MAX];
		fzn_peer_t big;

		memset(worst, 0x01, sizeof(worst));
		known_peer(&big);
		big.pid = (int64_t)-9223372036854775807LL - 1;
		big.uid = 4294967295u;
		big.primary_gid = 4294967295u;
		big.group_count = FZN_PEER_MAX_GROUPS;

		CHECK(fzn_peer_print(&big, worst, sizeof(worst), rules, n, line, sizeof(line),
		                     &len, &verdict, &named) == 0,
		      "the widest line does not fit FZN_PEER_PRINT_MAX");
	}

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	printf("peer_print_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
