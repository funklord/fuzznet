/* Tests for cli/persist_print.c.
 *
 * THE CASE THIS FILE EXISTS FOR is that one code means two opposite things.
 * FZN_PERSIST_ERR_ABSENT on a first run is routine and on a host that has
 * stored before is DATA LOSS -- and the store answers identically either way,
 * so nothing but the caller's own context tells them apart. A consumer that
 * reports both as "nothing stored yet" has said nothing about the day
 * somebody's identity disappeared.
 *
 * THE SECOND is that a corrupt file is not an attack. `persist.h` says so,
 * and a person told their identity is corrupt will assume the worst thing it
 * could mean unless the line rules it out.
 */

#include "../persist_print.h"

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
	fprintf(stderr, "  FAIL persist_print_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static size_t line_of(fzn_persist_slot_t slot, fzn_persist_err_t err, int had, char *out,
                      fzn_persist_line_t *said)
{
	size_t len = 99;

	*said = (fzn_persist_line_t)-1;
	CHECK(fzn_persist_print(slot, err, had, out, FZN_PERSIST_PRINT_MAX, &len, said)
	              == FZN_PERSIST_OK,
	      "rendering refused a slot it should have printed");
	return len;
}

int main(void)
{
	char line[FZN_PERSIST_PRINT_MAX];
	char fresh[FZN_PERSIST_PRINT_MAX];
	char lost[FZN_PERSIST_PRINT_MAX];
	char corrupt[FZN_PERSIST_PRINT_MAX];
	char unavailable[FZN_PERSIST_PRINT_MAX];
	fzn_persist_line_t said;
	size_t len = 0;

	/* ---- A SLOT THIS DOES NOT KNOW. */
	len = line_of((fzn_persist_slot_t)99u, FZN_PERSIST_OK, 0, line, &said);
	CHECK(said == FZN_PERSIST_LINE_NONE, "an unknown slot was given a verdict");
	CHECK(len > 0 && line[len] == '\0', "the line is not terminated at its length");
	CHECK(strstr(line, "cannot say") != NULL, "the line does not say it cannot say");

	/* ---- READ BACK. */
	len = line_of(FZN_PERSIST_TRUST, FZN_PERSIST_OK, 1, line, &said);
	CHECK(said == FZN_PERSIST_LINE_LOADED, "a successful read was not reported as one");
	CHECK(strstr(line, "trust anchor") != NULL, "the line does not name the slot");
	CHECK(strstr(line, "PROBLEM") == NULL && strstr(line, "ATTENTION") == NULL,
	      "reading state back was reported as a problem");

	/* ---- NOTHING STORED, FIRST RUN: routine. */
	len = line_of(FZN_PERSIST_OWN_PREKEY, FZN_PERSIST_ERR_ABSENT, 0, fresh, &said);
	CHECK(said == FZN_PERSIST_LINE_FRESH, "a first run was not reported as ordinary");
	CHECK(strstr(fresh, "ordinary") != NULL, "the line does not say this is ordinary");
	CHECK(strstr(fresh, "ATTENTION") == NULL, "a first run alarmed");

	/* ---- THE SAME CODE, THE OPPOSITE EVENT. */
	len = line_of(FZN_PERSIST_OWN_PREKEY, FZN_PERSIST_ERR_ABSENT, 1, lost, &said);
	CHECK(said == FZN_PERSIST_LINE_LOST,
	      "a host that has stored before, finding nothing, was told it was a first run");
	CHECK(strstr(lost, "ATTENTION") != NULL,
	      "data loss did not announce itself, and nothing else reports it");
	CHECK(strstr(lost, "removed it") != NULL,
	      "the line does not say something removed the state, which is the whole "
	      "content a reader cannot work out from the code");
	CHECK(strcmp(fresh, lost) != 0,
	      "a first run and data loss produced the same sentence, which is the "
	      "confusion this printer exists to prevent");

	/* ---- CORRUPT IS NOT AN ATTACK, and the file is still there. */
	len = line_of(FZN_PERSIST_TRUST, FZN_PERSIST_ERR_SHAPE, 1, corrupt, &said);
	CHECK(said == FZN_PERSIST_LINE_CORRUPT, "a foreign shape was not reported as such");
	CHECK(strstr(corrupt, "rather than an attack") != NULL,
	      "the line lets a person assume the worst thing a corrupt identity could "
	      "mean, which persist.h rules out in as many words");
	CHECK(strstr(corrupt, "left alone") != NULL,
	      "the line does not say the file is still there, so a person who wants it "
	      "does not know they still have it");

	/* ---- THE STORE ITSELF. */
	len = line_of(FZN_PERSIST_PEER, FZN_PERSIST_ERR_BACKEND, 1, unavailable, &said);
	CHECK(said == FZN_PERSIST_LINE_UNAVAILABLE, "a backend failure was not reported");
	CHECK(strstr(unavailable, "disk rather than its contents") != NULL,
	      "the line does not separate a store that cannot be read from state that is "
	      "wrong, which sends a person to the wrong place");

	/* ---- AND THE CALLER'S OWN BUG. */
	len = line_of(FZN_PERSIST_SEND_CHAIN, FZN_PERSIST_ERR_MALFORMED, 0, line, &said);
	CHECK(said == FZN_PERSIST_LINE_LOCAL, "a caller's bug was not reported as one");
	CHECK(strstr(line, "bug in it") != NULL, "the line does not say whose fault it is");

	/* ---- EVERY SLOT NAMES ITSELF, so a person is told WHICH state is
	 * missing: an anchor and one peer's chain are not the same loss. */
	{
		fzn_persist_slot_t slots[5] = { FZN_PERSIST_TRUST, FZN_PERSIST_OWN_PREKEY,
			                        FZN_PERSIST_PEER, FZN_PERSIST_SEND_CHAIN,
			                        FZN_PERSIST_RECV_CHAIN };
		char seen[5][FZN_PERSIST_PRINT_MAX];
		unsigned i, j;

		for (i = 0; i < 5u; i++) {
			(void)line_of(slots[i], FZN_PERSIST_ERR_ABSENT, 1, seen[i], &said);
			CHECK(said == FZN_PERSIST_LINE_LOST, "a slot did not report the loss");
		}
		for (i = 0; i < 5u; i++) {
			for (j = i + 1u; j < 5u; j++)
				CHECK(strcmp(seen[i], seen[j]) != 0,
				      "two slots produced the same sentence, so a person is "
				      "not told which of their state is gone");
		}
	}

	/* ---- `had_stored` IS READ ONLY FOR ABSENT. */
	{
		char with[FZN_PERSIST_PRINT_MAX];
		char without[FZN_PERSIST_PRINT_MAX];
		fzn_persist_line_t a, b;

		(void)line_of(FZN_PERSIST_TRUST, FZN_PERSIST_ERR_SHAPE, 1, with, &a);
		(void)line_of(FZN_PERSIST_TRUST, FZN_PERSIST_ERR_SHAPE, 0, without, &b);
		CHECK(a == b && strcmp(with, without) == 0,
		      "a corrupt file read differently depending on whether the host had "
		      "stored before, which is a dependency the header says is not there");
	}

	/* ---- THE OPERANDS. */
	CHECK(fzn_persist_print(FZN_PERSIST_TRUST, FZN_PERSIST_OK, 0, NULL, sizeof(line), &len,
	                        &said) == FZN_PERSIST_ERR_MALFORMED,
	      "printing accepted a null buffer");
	CHECK(fzn_persist_print(FZN_PERSIST_TRUST, FZN_PERSIST_OK, 0, line, sizeof(line), NULL,
	                        &said) == FZN_PERSIST_ERR_MALFORMED,
	      "printing accepted a null length");
	CHECK(fzn_persist_print(FZN_PERSIST_TRUST, FZN_PERSIST_OK, 0, line, sizeof(line), &len,
	                        NULL) == FZN_PERSIST_ERR_MALFORMED,
	      "printing accepted a null state out-parameter, which is the required half");

	/* ---- A BUFFER TOO SMALL REPORTS WHAT IT NEEDED AND WRITES NOTHING. */
	said = FZN_PERSIST_LINE_LOADED;
	len = 0;
	CHECK(fzn_persist_print(FZN_PERSIST_TRUST, FZN_PERSIST_ERR_ABSENT, 1, line, 4u, &len,
	                        &said) == FZN_PERSIST_ERR_MALFORMED,
	      "a four-byte buffer took a line");
	CHECK(len > 4u, "the refusal does not say how much room the line needed");
	CHECK(said == FZN_PERSIST_LINE_NONE,
	      "a refused render left a verdict behind, which a caller would read as one");

	printf("persist_print_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
