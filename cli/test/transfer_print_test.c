/* Tests for cli/transfer_print.c.
 *
 * THE CASE THIS FILE EXISTS FOR is that three conditions read
 * `in_flight == 0`: not started, stalled and complete. An alerting rule told
 * only the count would page somebody about a finished download and ignore a
 * stuck one -- so the state is reported out of band and the suite requires
 * all three to differ on both channels.
 *
 * The second is that asking for status must not change the transfer.
 * `fzn_transfer_expire` reclaims assignments past their deadline; a reporter
 * that called it would take a peer's outstanding ranges back because somebody
 * ran a health check. The suite renders an overdue transfer repeatedly and
 * then requires the LIBRARY to still be able to reclaim it, which is what
 * proves the printer left it alone rather than that nothing was there.
 */

#include "../transfer_print.h"

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
	fprintf(stderr, "  FAIL transfer_print_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

#define LEAVES 16u

static uint8_t ROOT[FZN_BLOB_HASH_LEN];
static uint8_t PRESENT[FZN_SPOOL_BITMAP_LEN(LEAVES)];
static fzn_transfer_assign_t ASSIGNS[4];
static fzn_spool_ops_t OPS;

static int no_read(void *ctx, uint64_t offset, uint8_t *out, size_t len)
{
	(void)ctx; (void)offset; (void)out; (void)len;
	return 0;
}

static int no_write(void *ctx, uint64_t offset, const uint8_t *bytes, size_t len)
{
	(void)ctx; (void)offset; (void)bytes; (void)len;
	return 0;
}

static int no_sync(void *ctx)
{
	(void)ctx;
	return 0;
}

/* Bits set here and `fzn_spool_open` left to count them: its header says it
 * "recompute[s] `have` from the bits rather than trusting a caller", so the
 * position is the library's count of what the fixture laid down. */
static int spool_at(fzn_spool_t *spool, uint64_t held)
{
	uint64_t i;

	memset(PRESENT, 0, sizeof(PRESENT));
	memset(ROOT, 0xd1, sizeof(ROOT));
	for (i = 0; i < held; i++)
		PRESENT[i >> 3] |= (uint8_t)(1u << (i & 7u));

	OPS.read_at = no_read;
	OPS.write_at = no_write;
	OPS.sync = no_sync;
	OPS.ctx = NULL;
	return fzn_spool_open(spool, ROOT, LEAVES, PRESENT, sizeof(PRESENT), &OPS) ==
	       FZN_SPOOL_OK;
}

int main(void)
{
	char line[FZN_TRANSFER_PRINT_MAX];
	char idle_line[FZN_TRANSFER_PRINT_MAX];
	char stalled_line[FZN_TRANSFER_PRINT_MAX];
	fzn_spool_t spool;
	fzn_transfer_t transfer;
	fzn_transfer_state_t s;
	size_t len = 0;

	/* NO SPOOL IS THE ZERO VALUE, so a caller that ignores the state is
	 * told it was given nothing rather than that all is well. */
	s = FZN_TRANSFER_COMPLETE;
	CHECK(fzn_transfer_print(NULL, NULL, 0u, line, sizeof(line), &len, &s) ==
	              FZN_TRANSFER_OK,
	      "a null spool would not render");
	CHECK(s == FZN_TRANSFER_NOTHING, "a null spool was not reported as nothing");

	/* NOT STARTED. */
	CHECK(spool_at(&spool, 0u), "the spool would not open");
	CHECK(fzn_transfer_open(&transfer, &spool, ASSIGNS, 4u) == FZN_TRANSFER_OK,
	      "the transfer would not open");
	CHECK(fzn_transfer_print(&spool, &transfer, 100u, line, sizeof(line), &len, &s) ==
	              FZN_TRANSFER_OK,
	      "an idle transfer would not render");
	CHECK(s == FZN_TRANSFER_IDLE, "a transfer that has not started was not idle");
	memcpy(idle_line, line, sizeof(line));

	/* STALLED: something held, nothing outstanding, not complete. */
	CHECK(spool_at(&spool, 5u), "the spool would not reopen");
	CHECK(fzn_transfer_open(&transfer, &spool, ASSIGNS, 4u) == FZN_TRANSFER_OK,
	      "the transfer would not reopen");
	CHECK(fzn_transfer_print(&spool, &transfer, 100u, line, sizeof(line), &len, &s) ==
	              FZN_TRANSFER_OK,
	      "a stalled transfer would not render");
	CHECK(s == FZN_TRANSFER_STALLED, "a stopped incomplete transfer was not stalled");
	memcpy(stalled_line, line, sizeof(line));
	CHECK(strcmp(idle_line, stalled_line) != 0,
	      "not-started and stalled print the same line");

	/* COMPLETE, and it is the library's answer rather than have == leaves. */
	CHECK(spool_at(&spool, LEAVES), "the spool would not reopen");
	CHECK(fzn_spool_complete(&spool), "the fixture is not complete, so it proves nothing");
	CHECK(fzn_transfer_open(&transfer, &spool, ASSIGNS, 4u) == FZN_TRANSFER_OK,
	      "the transfer would not reopen");
	CHECK(fzn_transfer_print(&spool, &transfer, 100u, line, sizeof(line), &len, &s) ==
	              FZN_TRANSFER_OK,
	      "a complete transfer would not render");
	CHECK(s == FZN_TRANSFER_COMPLETE, "a complete spool was not complete");
	CHECK(strcmp(line, stalled_line) != 0 && strcmp(line, idle_line) != 0,
	      "complete prints the same line as one of the stopped states, so all "
	      "three conditions that read in_flight == 0 are not separated");

	/* WORKING, and an overdue assignment is reclaimable rather than failed. */
	CHECK(spool_at(&spool, 2u), "the spool would not reopen");
	CHECK(fzn_transfer_open(&transfer, &spool, ASSIGNS, 4u) == FZN_TRANSFER_OK,
	      "the transfer would not reopen");
	{
		fzn_spool_range_t range;

		memset(&range, 0, sizeof(range));
		CHECK(fzn_transfer_next_want(&transfer, 7u, 0u, 4u, 500u, &range) ==
		              FZN_TRANSFER_OK,
		      "the fixture could not put a range in flight");
	}
	CHECK(fzn_transfer_print(&spool, &transfer, 100u, line, sizeof(line), &len, &s) ==
	              FZN_TRANSFER_OK,
	      "a working transfer would not render");
	CHECK(s == FZN_TRANSFER_WORKING, "an outstanding range did not read as working");

	CHECK(fzn_transfer_print(&spool, &transfer, 900u, line, sizeof(line), &len, &s) ==
	              FZN_TRANSFER_OK,
	      "an overdue transfer would not render");
	CHECK(strstr(line, "reclaimable") != NULL,
	      "a passed deadline was not reported as reclaimable");
	CHECK(strstr(line, "fail") == NULL,
	      "a passed deadline was reported as a failure, which it is not");

	/* AND REPORTING DID NOT RECLAIM IT. */
	{
		size_t before = fzn_transfer_in_flight(&transfer);

		CHECK(before == 1u, "the fixture has nothing outstanding to protect");
		fzn_transfer_print(&spool, &transfer, 900u, line, sizeof(line), &len, &s);
		fzn_transfer_print(&spool, &transfer, 900u, line, sizeof(line), &len, &s);
		CHECK(fzn_transfer_in_flight(&transfer) == before,
		      "printing status reclaimed an assignment, so asking a host how it is "
		      "changed what a peer still owes");
		CHECK(fzn_transfer_expire(&transfer, 900u) == 1u,
		      "the library could not reclaim what the printer left alone, so the "
		      "case above proved nothing");
	}

	/* A SPOOL WITH NO SCHEDULER still has a position. */
	CHECK(spool_at(&spool, 9u), "the spool would not reopen");
	CHECK(fzn_transfer_print(&spool, NULL, 100u, line, sizeof(line), &len, &s) ==
	              FZN_TRANSFER_OK,
	      "a spool with no scheduler would not render");
	CHECK(s == FZN_TRANSFER_STALLED, "a held, unscheduled spool was not stalled");
	CHECK(strstr(line, "no scheduler") != NULL, "the missing scheduler was not said");
	CHECK(strstr(line, "9 of 16") != NULL, "the position is not on the line");

	/* THE STATE IS REQUIRED, and a refusal leaves the conservative value. */
	CHECK(fzn_transfer_print(&spool, NULL, 100u, line, sizeof(line), &len, NULL) ==
	              FZN_TRANSFER_ERR_MALFORMED,
	      "the state was optional after all");
	{
		char small[4];
		size_t needed = 0;

		memset(small, '@', sizeof(small));
		s = FZN_TRANSFER_COMPLETE;
		CHECK(fzn_transfer_print(&spool, NULL, 100u, small, sizeof(small), &needed,
		                         &s) == FZN_TRANSFER_ERR_MALFORMED,
		      "a buffer too small was written anyway");
		CHECK(needed > sizeof(small), "the size needed was not reported");
		CHECK(small[0] == '@', "a refused render left bytes in the buffer");
		CHECK(s == FZN_TRANSFER_NOTHING, "a refused render left a reassuring state");
	}

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	printf("transfer_print_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
