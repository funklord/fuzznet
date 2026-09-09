/* Tests for cli/ledger_print.c.
 *
 * THE CASE THIS FILE EXISTS FOR is a pair of zeroes that mean opposite
 * things. `fzn_ledger_confirmed` answers 0 for a peer that has never
 * acknowledged a subject AND for a table nobody can walk; `fzn_ledger_behind`
 * answers "behind" for both. Each is right for a caller deciding whether to
 * send -- the direction that costs a retransmission rather than a delivery --
 * and neither can tell a person whether one peer is out of date or nothing on
 * the screen is evidence.
 *
 * So the cases below hold the RETURN VALUES of the underlying accessors fixed
 * across those two states and require the lines to differ, which is the whole
 * of what `fzn_ledger_sound` was added for.
 */

#include "../ledger_print.h"

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
	fprintf(stderr, "  FAIL ledger_print_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static fzn_ledger_entry_t ROWS[2];

static void key(uint8_t out[FZN_PUBKEY_LEN], uint8_t seed)
{
	memset(out, (int)seed, FZN_PUBKEY_LEN);
}

static void subj(uint8_t out[FZN_SUBJECT_LEN], uint8_t seed)
{
	memset(out, (int)seed, FZN_SUBJECT_LEN);
}

static size_t line_of(const fzn_ledger_t *ledger, const uint8_t *peer, const uint8_t *subject,
                      uint64_t current, char *out, fzn_ledger_line_t *said)
{
	size_t len = 99;

	*said = (fzn_ledger_line_t)-1;
	CHECK(fzn_ledger_print(ledger, peer, subject, 1u, current, out, FZN_LEDGER_PRINT_MAX,
	                       &len, said) == FZN_LEDGER_OK,
	      "rendering refused a ledger it should have printed");
	return len;
}

int main(void)
{
	fzn_ledger_t l;
	uint8_t peer[FZN_PUBKEY_LEN], other[FZN_PUBKEY_LEN], s[FZN_SUBJECT_LEN];
	char line[FZN_LEDGER_PRINT_MAX];
	char unknown_line[FZN_LEDGER_PRINT_MAX];
	char unreadable_line[FZN_LEDGER_PRINT_MAX];
	fzn_ledger_line_t said;
	size_t len = 0;

	key(peer, 0x11);
	key(other, 0x12);
	subj(s, 0x13);

	/* ---- NO LEDGER AT ALL. */
	len = line_of(NULL, peer, s, 5u, line, &said);
	CHECK(said == FZN_LEDGER_LINE_NONE, "a NULL ledger was given a verdict");
	CHECK(len > 0 && line[len] == '\0', "the line is not terminated at its length");
	CHECK(strstr(line, "cannot say") != NULL, "a host with no ledger did not say so");

	CHECK(fzn_ledger_init(&l, ROWS, 2u) == FZN_LEDGER_OK, "init");

	/* ---- READABLE, AND THIS PEER HAS NEVER ACKNOWLEDGED. */
	len = line_of(&l, peer, s, 5u, unknown_line, &said);
	CHECK(said == FZN_LEDGER_LINE_UNKNOWN, "an unacknowledged subject was not UNKNOWN");
	CHECK(strstr(unknown_line, "never acknowledged") != NULL,
	      "the line does not say the peer has not acknowledged this subject");
	CHECK(strstr(unknown_line, "up to date") == NULL,
	      "a peer that has confirmed nothing read as current");

	/* ---- BEHIND: confirmed three, this host holds five. */
	CHECK(fzn_ledger_confirm(&l, peer, s, 1u, 3u) == FZN_LEDGER_OK, "confirm");
	len = line_of(&l, peer, s, 5u, line, &said);
	CHECK(said == FZN_LEDGER_LINE_BEHIND, "an older confirmation was not BEHIND");
	CHECK(strstr(line, "confirmed 3") != NULL, "the line does not carry what was confirmed");
	CHECK(strstr(line, "holds 5") != NULL, "the line does not carry what this host has");

	/* ---- CURRENT at the version asked about. */
	CHECK(fzn_ledger_confirm(&l, peer, s, 1u, 5u) == FZN_LEDGER_OK, "confirm");
	len = line_of(&l, peer, s, 5u, line, &said);
	CHECK(said == FZN_LEDGER_LINE_CURRENT, "a matching confirmation was not CURRENT");
	CHECK(strstr(line, "up to date at 5") != NULL, "the line does not carry the version");

	/* ---- AND AHEAD IS CURRENT, NOT AN ERROR. A peer that confirmed a
	 * version this host has not reached is not behind, and the ledger
	 * refuses to move backwards precisely so this state persists. */
	len = line_of(&l, peer, s, 3u, line, &said);
	CHECK(said == FZN_LEDGER_LINE_CURRENT,
	      "a peer ahead of this host was reported as behind");

	/* ---- ANOTHER PEER IS ITS OWN QUESTION. */
	len = line_of(&l, other, s, 5u, line, &said);
	CHECK(said == FZN_LEDGER_LINE_UNKNOWN,
	      "a ledger holding one peer answered for another");

	/* ---- THE PAIR `fzn_ledger_sound` WAS ADDED FOR. Both of the next two
	 * see `confirmed` answer 0 and `behind` answer non-zero, and they are
	 * opposite sentences. */
	{
		fzn_ledger_t hollow = l;

		hollow.used = hollow.capacity + 1u;
		CHECK(fzn_ledger_confirmed(&hollow, peer, s, 1u) == 0u
		              && fzn_ledger_behind(&hollow, peer, s, 1u, 5u) != 0,
		      "the fixture does not reproduce the two zeroes, so it tests nothing");

		len = line_of(&hollow, peer, s, 5u, unreadable_line, &said);
		CHECK(said == FZN_LEDGER_LINE_UNREADABLE,
		      "a ledger whose own fields disagree was given an answer to believe");
		CHECK(strcmp(unreadable_line, unknown_line) != 0,
		      "an unreadable ledger and a peer that has confirmed nothing produced one "
		      "sentence for two opposite states");
		CHECK(strstr(unreadable_line, "every peer") != NULL,
		      "the line does not say the fault is the table's rather than this peer's, "
		      "which is the difference somebody acts on");
	}

	/* ---- THE OPERANDS. */
	CHECK(fzn_ledger_print(&l, peer, s, 1u, 5u, NULL, sizeof(line), &len, &said)
	              == FZN_LEDGER_ERR_MALFORMED, "printing accepted a null buffer");
	CHECK(fzn_ledger_print(&l, peer, s, 1u, 5u, line, sizeof(line), NULL, &said)
	              == FZN_LEDGER_ERR_MALFORMED, "printing accepted a null length");
	CHECK(fzn_ledger_print(&l, peer, s, 1u, 5u, line, sizeof(line), &len, NULL)
	              == FZN_LEDGER_ERR_MALFORMED,
	      "printing accepted a null state out-parameter, which is the required half");

	/* A null peer or subject is NONE rather than a crash, and must not
	 * read as a measured answer about anybody. */
	len = line_of(&l, NULL, s, 5u, line, &said);
	CHECK(said == FZN_LEDGER_LINE_NONE, "a null peer was given a verdict");
	len = line_of(&l, peer, NULL, 5u, line, &said);
	CHECK(said == FZN_LEDGER_LINE_NONE, "a null subject was given a verdict");

	/* ---- A BUFFER TOO SMALL REPORTS WHAT IT NEEDED AND WRITES NOTHING. */
	said = FZN_LEDGER_LINE_CURRENT;
	len = 0;
	CHECK(fzn_ledger_print(&l, peer, s, 1u, 5u, line, 4u, &len, &said)
	              == FZN_LEDGER_ERR_MALFORMED, "a four-byte buffer took a line");
	CHECK(len > 4u, "the refusal does not say how much room the line needed");
	CHECK(said == FZN_LEDGER_LINE_NONE,
	      "a refused render left a verdict behind, which a caller would read as one");

	printf("ledger_print_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
