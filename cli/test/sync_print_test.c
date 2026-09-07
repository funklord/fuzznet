/* Tests for cli/sync_print.c.
 *
 * THE CASE THIS FILE EXISTS FOR is the one a health check gets wrong. "Up to
 * date" and "cannot say" both have a deficit of zero, and a program that
 * grepped the line for a number would call a host that cannot measure its own
 * deficit green -- the fail-open `chain/manifest.h` was written to remove,
 * arriving in a monitoring script.
 *
 * So the state is reported OUT OF BAND and the suite checks the two channels
 * separately: the words differ for a person, and the enum differs for a
 * program. A widget parsing another component's output was sec 168's mistake;
 * this is that lesson spent rather than repeated.
 *
 * The second is that FZN_SYNC_UNMEASURED is zero, so a caller that forgets to
 * read `state_out` sees the conservative answer. The suite writes a
 * reassuring value into the variable first and requires it to be gone.
 */

#include "../sync_print.h"

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
	fprintf(stderr, "  FAIL sync_print_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

#define ISSUERS  2u
#define DEFICITS 40u

static fzn_manifest_issuer_t ISSUER_ROWS[ISSUERS];
static fzn_manifest_deficit_t DEFICIT_ROWS[DEFICITS];

static void deficit_of(fzn_manifest_state_t *st, const uint8_t issuer[FZN_PUBKEY_LEN],
                       size_t n)
{
	size_t i;

	for (i = 0; i < n && i < DEFICITS; i++) {
		memcpy(DEFICIT_ROWS[i].issuer, issuer, FZN_PUBKEY_LEN);
		memset(&DEFICIT_ROWS[i].capability, (int)(0x20u + i),
		       sizeof(DEFICIT_ROWS[i].capability));
		memset(DEFICIT_ROWS[i].grantee, (int)(0x30u + i), FZN_PUBKEY_LEN);
	}
	st->deficit_used = n < DEFICITS ? n : DEFICITS;
}

int main(void)
{
	char line[FZN_SYNC_PRINT_MAX];
	fzn_manifest_state_t st;
	uint8_t peer[FZN_PUBKEY_LEN];
	uint8_t stranger[FZN_PUBKEY_LEN];
	fzn_sync_state_t said;
	size_t len = 0;
	char unmeasured_line[FZN_SYNC_PRINT_MAX];

	memset(peer, 0x91, sizeof(peer));
	memset(stranger, 0x92, sizeof(stranger));

	CHECK(fzn_manifest_init(&st, ISSUER_ROWS, ISSUERS, DEFICIT_ROWS, DEFICITS) ==
	              FZN_MANIFEST_OK,
	      "the manifest state would not init");

	/* THE CONSERVATIVE VALUE IS ZERO, so a caller that never reads the
	 * variable sees "cannot say". Poisoned first, so this proves the call
	 * wrote it rather than that it happened to be zero. */
	said = FZN_SYNC_UP_TO_DATE;
	CHECK(fzn_sync_print(NULL, peer, line, sizeof(line), &len, &said) == FZN_MANIFEST_OK,
	      "a null state would not render");
	CHECK(said == FZN_SYNC_UNMEASURED,
	      "a null state did not report that it cannot say");
	memcpy(unmeasured_line, line, sizeof(line));

	/* AN UNFOLLOWED PEER IS THE SAME FACT. */
	said = FZN_SYNC_UP_TO_DATE;
	CHECK(fzn_sync_print(&st, stranger, line, sizeof(line), &len, &said) ==
	              FZN_MANIFEST_OK,
	      "an unfollowed peer would not render");
	CHECK(said == FZN_SYNC_UNMEASURED, "an unfollowed peer was called measured");

	/* FOLLOWED AND EMPTY IS UP TO DATE. */
	CHECK(fzn_manifest_follow(&st, peer) == FZN_MANIFEST_OK, "follow refused");
	said = FZN_SYNC_UNMEASURED;
	CHECK(fzn_sync_print(&st, peer, line, sizeof(line), &len, &said) == FZN_MANIFEST_OK,
	      "a followed peer would not render");
	CHECK(said == FZN_SYNC_UP_TO_DATE, "a followed empty peer was not up to date");

	/* THE CASE THIS FILE EXISTS FOR, ON BOTH CHANNELS. */
	CHECK(strcmp(line, unmeasured_line) != 0,
	      "up-to-date and cannot-say print the same line, so a person reading the "
	      "output cannot tell them apart");
	CHECK(said != FZN_SYNC_UNMEASURED,
	      "up-to-date and cannot-say report the same state, so a health check "
	      "cannot tell them apart either");

	/* BEHIND, ON BOTH CHANNELS. */
	deficit_of(&st, peer, 3u);
	CHECK(fzn_sync_print(&st, peer, line, sizeof(line), &len, &said) == FZN_MANIFEST_OK,
	      "a peer with a deficit would not render");
	CHECK(said == FZN_SYNC_BEHIND, "a peer with outstanding pairs was not behind");
	CHECK(strstr(line, "3 outstanding") != NULL, "the count is not on the line");
	CHECK(len == strlen(line), "the reported length is not the line's");
	CHECK(line[len - 1u] == '\n', "the line does not end in a newline");

	/* A SHORT REPORT SAYS SO. */
	deficit_of(&st, peer, DEFICITS);
	CHECK(fzn_sync_print(&st, peer, line, sizeof(line), &len, &said) == FZN_MANIFEST_OK,
	      "a large deficit would not render");
	CHECK(said == FZN_SYNC_BEHIND, "a large deficit was not behind");
	CHECK(strstr(line, "short") != NULL,
	      "a report that did not fit failed to say the count is short");

	/* AN OVERFLOWED ISSUER IS UNMEASURED EVEN WITH PAIRS TO LIST. */
	{
		size_t i;

		for (i = 0; i < st.issuer_used; i++)
			if (memcmp(ISSUER_ROWS[i].issuer, peer, FZN_PUBKEY_LEN) == 0)
				ISSUER_ROWS[i].overflowed = 1;

		said = FZN_SYNC_BEHIND;
		CHECK(fzn_sync_print(&st, peer, line, sizeof(line), &len, &said) ==
		              FZN_MANIFEST_OK,
		      "an overflowed peer would not render");
		CHECK(said == FZN_SYNC_UNMEASURED,
		      "a host that knows it dropped pairs reported a count anyway");
	}

	/* THE STATE IS REQUIRED, on fzn_manifest_deficit's argument for its own
	 * out-parameter: an optional one is one every caller ignores, and this
	 * is the one a health check must not. */
	CHECK(fzn_sync_print(&st, peer, line, sizeof(line), &len, NULL) ==
	              FZN_MANIFEST_ERR_MALFORMED,
	      "the state out-parameter was optional after all");

	/* IT REFUSES RATHER THAN TRUNCATES, and says what it needed. */
	{
		char small[8];
		size_t needed = 0;

		memset(small, '@', sizeof(small));
		said = FZN_SYNC_UP_TO_DATE;
		CHECK(fzn_sync_print(&st, peer, small, sizeof(small), &needed, &said) ==
		              FZN_MANIFEST_ERR_MALFORMED,
		      "a buffer too small was written anyway");
		CHECK(needed > sizeof(small), "the size needed was not reported");
		CHECK(small[0] == '@' && small[sizeof(small) - 1u] == '@',
		      "a refused render left bytes in the caller's buffer");
		CHECK(said == FZN_SYNC_UNMEASURED,
		      "a refused render left a reassuring state behind");
	}

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	printf("sync_print_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
