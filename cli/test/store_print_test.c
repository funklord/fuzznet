/* Tests for cli/store_print.c.
 *
 * THE CASE THIS FILE EXISTS FOR has a cost `record/store.h` states outright:
 * "a caller that treated a broken store as an empty one would REFETCH THE
 * WORLD". Not held and could-not-answer are two negative integers, and one of
 * them is most of what a busy reader asks for while the other means the host
 * should stop asking.
 *
 * THE SECOND is MISPLACED, which is not a failure to find but a wrong find:
 * the store answered with a record that is not the one requested. Folding it
 * into "damaged" would describe a filing problem as a corruption one and send
 * somebody to the wrong file.
 */

#include "../store_print.h"

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
	fprintf(stderr, "  FAIL store_print_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static size_t line_of(fzn_record_store_err_t err, char *out, fzn_record_store_line_t *said)
{
	size_t len = 99;

	*said = (fzn_record_store_line_t)-1;
	CHECK(fzn_record_store_print(err, out, FZN_RECORD_STORE_PRINT_MAX, &len, said) == 1,
	      "rendering refused an answer it should have printed");
	return len;
}

int main(void)
{
	char line[FZN_RECORD_STORE_PRINT_MAX];
	char absent[FZN_RECORD_STORE_PRINT_MAX];
	char backend[FZN_RECORD_STORE_PRINT_MAX];
	char damaged[FZN_RECORD_STORE_PRINT_MAX];
	char misplaced[FZN_RECORD_STORE_PRINT_MAX];
	fzn_record_store_line_t said;
	size_t len = 0;

	/* ---- HELD. */
	len = line_of(FZN_RECORD_STORE_OK, line, &said);
	CHECK(said == FZN_RECORD_STORE_LINE_HELD, "a returned record was not reported");
	CHECK(len > 0 && line[len] == '\0', "the line is not terminated at its length");
	CHECK(strstr(line, "PROBLEM") == NULL && strstr(line, "ATTENTION") == NULL,
	      "a record coming back was reported as a problem");

	/* ---- NOT HELD: the ordinary answer, and it must not alarm. */
	len = line_of(FZN_RECORD_STORE_ERR_ABSENT, absent, &said);
	CHECK(said == FZN_RECORD_STORE_LINE_NOT_HELD, "not held was not reported as such");
	CHECK(strstr(absent, "ordinary") != NULL,
	      "the line does not say this is ordinary, and it is most of what a busy "
	      "reader asks for");
	CHECK(strstr(absent, "PROBLEM") == NULL,
	      "the answer a working host gives constantly was reported as a problem");

	/* ---- THE BROKEN STORE, with the harm named. */
	len = line_of(FZN_RECORD_STORE_ERR_BACKEND, backend, &said);
	CHECK(said == FZN_RECORD_STORE_LINE_UNREADABLE, "a broken store was not reported");
	CHECK(strstr(backend, "not an empty store") != NULL,
	      "the line does not rule out the reading that store.h says would make a "
	      "host refetch the world");
	CHECK(strcmp(absent, backend) != 0,
	      "an empty store and a broken one produced the same sentence, which is the "
	      "confusion this printer exists to prevent");

	/* ---- DAMAGED: this record, not the store. */
	len = line_of(FZN_RECORD_STORE_ERR_SHAPE, damaged, &said);
	CHECK(said == FZN_RECORD_STORE_LINE_DAMAGED, "a bad shape was not reported");
	CHECK(strstr(damaged, "this record rather than the store") != NULL,
	      "the line does not say the fault is one record's, so a reader condemns a "
	      "store over one bad file");

	/* ---- AND THE WRONG FIND. */
	len = line_of(FZN_RECORD_STORE_ERR_MISPLACED, misplaced, &said);
	CHECK(said == FZN_RECORD_STORE_LINE_MISPLACED, "a wrong record was not reported");
	CHECK(strstr(misplaced, "ATTENTION") != NULL,
	      "a store answering with the wrong record did not announce itself");
	CHECK(strstr(misplaced, "index disagrees with its contents") != NULL,
	      "the line does not say what is actually wrong, which is the store's own "
	      "filing rather than any record's bytes");
	CHECK(strcmp(damaged, misplaced) != 0,
	      "a damaged record and a misplaced one produced the same sentence, which "
	      "sends somebody to the wrong file");

	/* ---- THE CALLER'S OWN BUG. */
	len = line_of(FZN_RECORD_STORE_ERR_MALFORMED, line, &said);
	CHECK(said == FZN_RECORD_STORE_LINE_LOCAL, "a caller's bug was not reported as one");
	CHECK(strstr(line, "bug in it") != NULL, "the line does not say whose fault it is");

	/* ---- FIVE ANSWERS, FIVE SENTENCES. */
	CHECK(strcmp(absent, damaged) != 0 && strcmp(backend, damaged) != 0
	              && strcmp(absent, misplaced) != 0 && strcmp(backend, misplaced) != 0,
	      "two answers wanting different responses produced the same sentence");

	/* ---- THE OPERANDS. */
	CHECK(fzn_record_store_print(FZN_RECORD_STORE_OK, NULL, sizeof(line), &len, &said)
	              == 0, "printing accepted a null buffer");
	CHECK(fzn_record_store_print(FZN_RECORD_STORE_OK, line, sizeof(line), NULL, &said)
	              == 0, "printing accepted a null length");
	CHECK(fzn_record_store_print(FZN_RECORD_STORE_OK, line, sizeof(line), &len, NULL)
	              == 0,
	      "printing accepted a null state out-parameter, which is the required half");

	/* ---- A BUFFER TOO SMALL REPORTS WHAT IT NEEDED AND WRITES NOTHING. */
	said = FZN_RECORD_STORE_LINE_HELD;
	len = 0;
	CHECK(fzn_record_store_print(FZN_RECORD_STORE_ERR_MISPLACED, line, 4u, &len, &said)
	              == 0, "a four-byte buffer took a line");
	CHECK(len > 4u, "the refusal does not say how much room the line needed");
	CHECK(said == FZN_RECORD_STORE_LINE_NONE,
	      "a refused render left a verdict behind, which a caller would read as one");

	printf("store_print_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
