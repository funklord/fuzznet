/* Tests for cli/revocation_print.c.
 *
 * THE CASE THIS FILE EXISTS FOR is that a withdrawn entry is not a
 * revocation. chain.h keeps it in the store deliberately -- removing it would
 * let a re-relayed copy be re-admitted "not [as] a one-time resurrection but
 * a loop" -- so a line counting rows reports every capability that was ever
 * revoked and has since been RESTORED as still cut off.
 *
 * The second is that a store which cannot be walked must not read as a host
 * with nothing revoked. That is the fail-OPEN answer: it claims every
 * capability is fine when the truth is that this host cannot say.
 */

#include "../revocation_print.h"

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
	fprintf(stderr, "  FAIL revocation_print_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static fzn_revocation_t ENTRIES[4];

static int store_of(fzn_revocation_store_t *store, size_t in_force, size_t withdrawn)
{
	size_t i;
	size_t n = in_force + withdrawn;

	memset(ENTRIES, 0, sizeof(ENTRIES));
	for (i = 0; i < n && i < 4u; i++) {
		memset(&ENTRIES[i].capability, (int)(0x40u + i), sizeof(ENTRIES[i].capability));
		memset(ENTRIES[i].grantee, (int)(0x50u + i), sizeof(ENTRIES[i].grantee));
		memset(ENTRIES[i].issuer, 0x60, sizeof(ENTRIES[i].issuer));
		ENTRIES[i].withdrawn = i >= in_force ? 1u : 0u;
	}
	if (fzn_revocation_store_init(store, ENTRIES, 4u) != FZN_CHAIN_OK)
		return 0;
	store->used = n;
	return 1;
}

int main(void)
{
	char line[FZN_REVOCATION_PRINT_MAX];
	char none_line[FZN_REVOCATION_PRINT_MAX];
	fzn_revocation_store_t store;
	fzn_revocations_state_t s;
	size_t len = 0;

	/* A NULL STORE KNOWS OF NO REVOCATIONS -- a complete answer about a
	 * real thing, which sec 183 made the contract. */
	s = FZN_REVOCATIONS_UNREADABLE;
	CHECK(fzn_revocation_print(NULL, line, sizeof(line), &len, &s) == FZN_CHAIN_OK,
	      "a null store would not render");
	CHECK(s == FZN_REVOCATIONS_NONE, "a null store was called unreadable");
	memcpy(none_line, line, sizeof(line));

	/* AN EMPTY STORE IS THE SAME ANSWER. */
	CHECK(store_of(&store, 0u, 0u), "the store would not init");
	CHECK(fzn_revocation_print(&store, line, sizeof(line), &len, &s) == FZN_CHAIN_OK,
	      "an empty store would not render");
	CHECK(s == FZN_REVOCATIONS_NONE, "an empty store was not none");

	/* THE CASE THIS FILE EXISTS FOR. One in force, two withdrawn: a
	 * counter of rows says three revoked, and the truth is one. */
	CHECK(store_of(&store, 1u, 2u), "the store would not reinit");
	CHECK(fzn_revocation_print(&store, line, sizeof(line), &len, &s) == FZN_CHAIN_OK,
	      "a holding store would not render");
	CHECK(s == FZN_REVOCATIONS_HOLDING, "a store with entries was not holding");
	CHECK(strstr(line, "1 in force") != NULL,
	      "withdrawn entries were counted as revocations, so capabilities that "
	      "have been restored are reported as still cut off");
	CHECK(strstr(line, "2 since withdrawn") != NULL,
	      "the withdrawn entries were not counted");
	CHECK(strstr(line, "work again") != NULL,
	      "a restored capability is not said to be restored, which is what "
	      "somebody is looking for when a peer says they are back");

	/* AND A STORE OF NOTHING BUT WITHDRAWALS SAYS ZERO IN FORCE. Without
	 * this the case above passes for a printer that always says one. */
	CHECK(store_of(&store, 0u, 3u), "the store would not reinit");
	CHECK(fzn_revocation_print(&store, line, sizeof(line), &len, &s) == FZN_CHAIN_OK,
	      "a withdrawals-only store would not render");
	CHECK(strstr(line, "0 in force") != NULL,
	      "a store holding only withdrawals reported a revocation in force");

	/* AN UNREADABLE STORE IS NOT A HOST WITH NOTHING REVOKED. */
	CHECK(store_of(&store, 2u, 1u), "the store would not reinit");
	store.used = store.capacity + 1u;
	s = FZN_REVOCATIONS_HOLDING;
	CHECK(fzn_revocation_print(&store, line, sizeof(line), &len, &s) == FZN_CHAIN_OK,
	      "an unreadable store would not render");
	CHECK(s == FZN_REVOCATIONS_UNREADABLE,
	      "a store counting more entries than it holds was walked anyway");
	CHECK(strcmp(line, none_line) != 0,
	      "an unreadable store reads as a host with nothing revoked, which claims "
	      "every capability is fine when this host cannot say");

	/* THE STATE IS REQUIRED, and a refusal leaves the fail-closed value. */
	CHECK(store_of(&store, 1u, 0u), "the store would not reinit");
	CHECK(fzn_revocation_print(&store, line, sizeof(line), &len, NULL) ==
	              FZN_CHAIN_ERR_MALFORMED,
	      "the state was optional after all");
	{
		char small[4];
		size_t needed = 0;

		memset(small, '@', sizeof(small));
		s = FZN_REVOCATIONS_NONE;
		CHECK(fzn_revocation_print(&store, small, sizeof(small), &needed, &s) ==
		              FZN_CHAIN_ERR_MALFORMED,
		      "a buffer too small was written anyway");
		CHECK(needed > sizeof(small), "the size needed was not reported");
		CHECK(small[0] == '@', "a refused render left bytes in the buffer");
		CHECK(s == FZN_REVOCATIONS_UNREADABLE,
		      "a refused render left a state claiming nothing is revoked");
	}

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	printf("revocation_print_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
