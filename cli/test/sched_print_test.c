/* Tests for cli/sched_print.c.
 *
 * THE CASE THIS FILE EXISTS FOR is a consumer about to drop somebody's
 * traffic. `sched.h` says so: "When nothing survives, `FZN_SCHED_ERR_NONE` is
 * the answer and the caller drops." One error code covers every reason, and
 * the reasons want different actions -- so the cases below hold the table
 * UNSELECTABLE in four different senses and require the states and the lines
 * to differ.
 *
 * The one that matters most is the fourth. Links excluded for DIFFERENT
 * reasons have no single fix, and a line naming any one bound would send a
 * reader to change the thing that cannot help.
 */

#include "../sched_print.h"

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
	fprintf(stderr, "  FAIL sched_print_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static fzn_sched_candidate_t link_of(uint32_t id, uint32_t latency, uint16_t loss, uint32_t mtu,
                                     int usable)
{
	fzn_sched_candidate_t l;

	memset(&l, 0, sizeof(l));
	l.id = id;
	l.metric = 10u;
	l.latency_ms = latency;
	l.loss_permille = loss;
	l.mtu = mtu;
	l.usable = usable;
	return l;
}

static size_t line_of(const fzn_sched_candidate_t *links, size_t n, const fzn_class_t *w,
                      fzn_sched_err_t err, size_t chosen, char *out, fzn_sched_line_t *said)
{
	size_t len = 99;

	*said = (fzn_sched_line_t)-1;
	CHECK(fzn_sched_print(links, n, w, err, chosen, out, FZN_SCHED_PRINT_MAX, &len, said)
	              == FZN_SCHED_OK,
	      "rendering refused a selection it should have printed");
	return len;
}

int main(void)
{
	char line[FZN_SCHED_PRINT_MAX];
	char slow[FZN_SCHED_PRINT_MAX];
	char lossy[FZN_SCHED_PRINT_MAX];
	char small[FZN_SCHED_PRINT_MAX];
	char mixed[FZN_SCHED_PRINT_MAX];
	fzn_sched_candidate_t links[3];
	fzn_sched_line_t said;
	size_t len = 0, chosen = 0;

	/* A class that wants a fast, clean, big link. */
	static const fzn_class_t VOICE = { .max_latency_ms = 50u,
		                           .max_loss_permille = 20u,
		                           .min_mtu = 1200u,
		                           .weight_latency = 1u };
	/* One that wants nothing in particular. */
	static const fzn_class_t ANY = { .weight_latency = 1u };

	/* ---- NOTHING TO REPORT ON. */
	len = line_of(NULL, 0u, &VOICE, FZN_SCHED_ERR_NONE, 0u, line, &said);
	CHECK(said == FZN_SCHED_LINE_NONE, "an empty table was given a verdict");
	CHECK(len > 0 && line[len] == '\0', "the line is not terminated at its length");
	CHECK(strstr(line, "cannot say") != NULL, "the line does not say it cannot say");

	/* ---- A LINK WAS CHOSEN. */
	links[0] = link_of(7u, 10u, 5u, 1500u, 1);
	links[1] = link_of(8u, 20u, 5u, 1500u, 1);
	CHECK(fzn_sched_select(links, 2u, &VOICE, &chosen) == FZN_SCHED_OK, "select refused");
	len = line_of(links, 2u, &VOICE, FZN_SCHED_OK, chosen, line, &said);
	CHECK(said == FZN_SCHED_LINE_CHOSEN, "a chosen link was not reported as chosen");
	CHECK(strstr(line, "link 7") != NULL, "the line does not name the link by its id");
	CHECK(strstr(line, "DROPPING") == NULL, "a carried class was reported as dropped");

	/* ---- EVERY LINK DOWN, which is not this class's fault and the line
	 * has to say so or somebody loosens constraints all afternoon. */
	links[0] = link_of(7u, 10u, 0u, 1500u, 0);
	links[1] = link_of(8u, 10u, 0u, 1500u, 0);
	len = line_of(links, 2u, &ANY, FZN_SCHED_ERR_NONE, 0u, line, &said);
	CHECK(said == FZN_SCHED_LINE_NOTHING_UP, "a table of down links blamed the class");
	CHECK(strstr(line, "not the reason") != NULL,
	      "the line does not say the class is not the reason");

	/* ---- ALL TOO SLOW. */
	links[0] = link_of(7u, 500u, 0u, 1500u, 1);
	links[1] = link_of(8u, 900u, 0u, 1500u, 1);
	len = line_of(links, 2u, &VOICE, FZN_SCHED_ERR_NONE, 0u, slow, &said);
	CHECK(said == FZN_SCHED_LINE_TOO_SLOW, "links too slow were not reported as such");
	CHECK(strstr(slow, "max_latency_ms") != NULL, "the line does not name the bound");

	/* ---- ALL TOO LOSSY. */
	links[0] = link_of(7u, 10u, 500u, 1500u, 1);
	links[1] = link_of(8u, 10u, 900u, 1500u, 1);
	len = line_of(links, 2u, &VOICE, FZN_SCHED_ERR_NONE, 0u, lossy, &said);
	CHECK(said == FZN_SCHED_LINE_TOO_LOSSY, "links too lossy were not reported as such");
	CHECK(strstr(lossy, "max_loss_permille") != NULL, "the line does not name the bound");

	/* ---- ALL TOO SMALL. */
	links[0] = link_of(7u, 10u, 0u, 500u, 1);
	links[1] = link_of(8u, 10u, 0u, 600u, 1);
	len = line_of(links, 2u, &VOICE, FZN_SCHED_ERR_NONE, 0u, small, &said);
	CHECK(said == FZN_SCHED_LINE_TOO_SMALL, "links too small were not reported as such");
	CHECK(strstr(small, "min_mtu") != NULL, "the line does not name the bound");

	/* ---- AND EXCLUDED FOR DIFFERENT REASONS, where naming any one bound
	 * would be wrong. This is the state the other three cannot express. */
	links[0] = link_of(7u, 500u, 0u, 1500u, 1);  /* slow */
	links[1] = link_of(8u, 10u, 900u, 1500u, 1); /* lossy */
	links[2] = link_of(9u, 10u, 0u, 500u, 1);    /* small */
	len = line_of(links, 3u, &VOICE, FZN_SCHED_ERR_NONE, 0u, mixed, &said);
	CHECK(said == FZN_SCHED_LINE_NO_SINGLE_FIX,
	      "three links excluded three ways were reported as one fixable cause");
	CHECK(strstr(mixed, "no single change helps") != NULL,
	      "the line offers a fix where there is none");
	CHECK(strstr(mixed, "max_latency_ms") == NULL && strstr(mixed, "min_mtu") == NULL,
	      "the line names a bound to change, which is the mistake this state exists "
	      "to avoid");

	/* ---- AND THE FOUR ARE FOUR SENTENCES. Same error code, same empty
	 * result, and a reader must be sent to four different places. */
	CHECK(strcmp(slow, lossy) != 0 && strcmp(lossy, small) != 0
	              && strcmp(small, mixed) != 0 && strcmp(slow, mixed) != 0,
	      "two tables wanting different actions produced the same sentence, which is "
	      "where FZN_SCHED_ERR_NONE already leaves a caller");

	/* ---- SOME DOWN AND THE REST EXCLUDED ONE WAY still has that one fix,
	 * so a down link is a count rather than a change of verdict. */
	links[0] = link_of(7u, 10u, 0u, 1500u, 0);   /* down */
	links[1] = link_of(8u, 500u, 0u, 1500u, 1);  /* slow */
	len = line_of(links, 2u, &VOICE, FZN_SCHED_ERR_NONE, 0u, line, &said);
	CHECK(said == FZN_SCHED_LINE_TOO_SLOW,
	      "one down link turned a single fixable cause into no single fix");

	/* ---- AN OK NAMING A LINK THAT DOES NOT QUALIFY IS NOT A CHOICE. */
	links[0] = link_of(7u, 500u, 0u, 1500u, 1);
	links[1] = link_of(8u, 500u, 0u, 1500u, 1);
	len = line_of(links, 2u, &VOICE, FZN_SCHED_OK, 0u, line, &said);
	CHECK(said == FZN_SCHED_LINE_NONE,
	      "a link this class excludes was reported as carrying it, which puts this "
	      "printer's name behind a selection the module would not have made");

	/* ---- MALFORMED SAYS NOTHING ABOUT THE LINKS. */
	links[0] = link_of(7u, 10u, 0u, 1500u, 1);
	len = line_of(links, 1u, &VOICE, FZN_SCHED_ERR_MALFORMED, 0u, line, &said);
	CHECK(said == FZN_SCHED_LINE_NONE,
	      "an error about the caller's own arguments was reported as a fact about "
	      "the links");

	/* ---- THE OPERANDS. */
	CHECK(fzn_sched_print(links, 1u, &VOICE, FZN_SCHED_OK, 0u, NULL, sizeof(line), &len,
	                      &said) == FZN_SCHED_ERR_MALFORMED,
	      "printing accepted a null buffer");
	CHECK(fzn_sched_print(links, 1u, &VOICE, FZN_SCHED_OK, 0u, line, sizeof(line), NULL,
	                      &said) == FZN_SCHED_ERR_MALFORMED,
	      "printing accepted a null length");
	CHECK(fzn_sched_print(links, 1u, &VOICE, FZN_SCHED_OK, 0u, line, sizeof(line), &len,
	                      NULL) == FZN_SCHED_ERR_MALFORMED,
	      "printing accepted a null state out-parameter, which is the required half");

	/* ---- A BUFFER TOO SMALL REPORTS WHAT IT NEEDED AND WRITES NOTHING. */
	said = FZN_SCHED_LINE_CHOSEN;
	len = 0;
	CHECK(fzn_sched_print(links, 1u, &VOICE, FZN_SCHED_OK, 0u, line, 4u, &len, &said)
	              == FZN_SCHED_ERR_MALFORMED,
	      "a four-byte buffer took a line");
	CHECK(len > 4u, "the refusal does not say how much room the line needed");
	CHECK(said == FZN_SCHED_LINE_NONE,
	      "a refused render left a verdict behind, which a caller would read as one");

	printf("sched_print_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
