/* Tests for cli/reasm_print.c.
 *
 * THE CASE THIS FILE EXISTS FOR is a misreading `chunk/reassembly.h` says a
 * consumer has already had. FZN_REASM_ERR_FULL "no longer means live,
 * unexpired": a slot may be HANDED to the caller and waiting on a release the
 * sweep must not take, so "a consumer reading the old wording would conclude
 * that TIME ALONE FIXES A FULL TABLE. Releasing what it holds is the other
 * half."
 *
 * Three causes, three actions, one return value. The cases below hold the
 * table FULL in all three senses -- same `live`, same `capacity`, the same
 * FZN_REASM_ERR_FULL from accept -- and require the states and the lines to
 * differ.
 */

#include "../reasm_print.h"

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
	fprintf(stderr, "  FAIL reasm_print_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static fzn_partial_t SLOTS[3];
static uint8_t BUFS[3][64];

/*
 * A table a consumer could hold, built directly. `fzn_partial_t` is a public
 * type and every field below is one `chunk/reassembly.c` sets itself; driving
 * accept to reach each arrangement is `chunk/test/reassembly_test.c`'s job.
 *
 * `expires_at` is the STORED deadline, already bounded by `max_hold` -- see
 * that field's comment -- so `<= now` is the whole test, as it is in
 * `fzn_reasm_expire`.
 */
/* EVERY SLOT HERE CARRIES THE SAME SENDER, all zeroes from the memset, which
 * is why `quota` is a parameter rather than the 1 it used to be. With a bound
 * of 1 a single live slot puts that sender at its quota, so the HOLDING cases
 * below were asking for a state this printer no longer produces -- and it was
 * right not to: a table holding one of two, refusing that sender's next chunk
 * with a free slot beside it, is not "holding, with room" in any sense the
 * reader can act on. sec 234. */
static int table_of_quota(fzn_reasm_t *t, size_t live, size_t handed, size_t expired,
                          size_t quota)
{
	size_t i;

	memset(SLOTS, 0, sizeof(SLOTS));
	memset(BUFS, 0, sizeof(BUFS));
	/* SLOTS FIRST. `fzn_reasm_init` walks the array and refuses a slot with
	 * no buffer, so the order is not a preference -- the other way round
	 * returns MALFORMED, which is how this fixture failed when it was
	 * written. sec 230. */
	for (i = 0; i < 3u; i++) {
		if (fzn_reasm_slot_init(&SLOTS[i], BUFS[i], sizeof(BUFS[i])) != FZN_REASM_OK)
			return 0;
	}
	if (fzn_reasm_init(t, SLOTS, 3u, quota, 1000u) != FZN_REASM_OK)
		return 0;
	for (i = 0; i < live && i < 3u; i++) {
		SLOTS[i].live = 1;
		SLOTS[i].handed = (i < handed) ? 1 : 0;
		/* 100 is `now` everywhere below; `<= now` sweeps, so 100 is
		 * past its deadline and 500 is not. */
		SLOTS[i].expires_at = (i < expired) ? 100u : 500u;
	}
	return 1;
}

/* The default: a bound that cannot bind before the table is full, so every
 * case that is about FULLNESS says only that. */
static int table_of(fzn_reasm_t *t, size_t live, size_t handed, size_t expired)
{
	return table_of_quota(t, live, handed, expired, 3u);
}

static size_t line_of(const fzn_reasm_t *t, uint64_t now, char *out, fzn_reasm_line_t *said)
{
	size_t len = 99;

	*said = (fzn_reasm_line_t)-1;
	CHECK(fzn_reasm_print(t, now, out, FZN_REASM_PRINT_MAX, &len, said) == FZN_REASM_OK,
	      "rendering refused a table it should have printed");
	return len;
}

int main(void)
{
	fzn_reasm_t t;
	char line[FZN_REASM_PRINT_MAX];
	char leaked[FZN_REASM_PRINT_MAX];
	char unswept[FZN_REASM_PRINT_MAX];
	char undersized[FZN_REASM_PRINT_MAX];
	char capped[FZN_REASM_PRINT_MAX];
	fzn_reasm_line_t said;
	size_t len = 0;

	/* ---- NO TABLE AT ALL. */
	len = line_of(NULL, 100u, line, &said);
	CHECK(said == FZN_REASM_LINE_NONE, "a NULL table was given an occupancy");
	CHECK(len > 0 && line[len] == '\0', "the line is not terminated at its length");
	CHECK(strstr(line, "cannot say") != NULL, "a host with no table did not say so");

	/* ---- NOTHING HALF-FINISHED. */
	CHECK(table_of(&t, 0u, 0u, 0u), "the fixture does not build");
	len = line_of(&t, 100u, line, &said);
	CHECK(said == FZN_REASM_LINE_EMPTY, "an empty table was not EMPTY");
	CHECK(strstr(line, "nothing half-finished") != NULL, "the line does not say so");

	/* ---- HOLDING, with room. */
	CHECK(table_of(&t, 1u, 0u, 0u), "the fixture does not build");
	len = line_of(&t, 100u, line, &said);
	CHECK(said == FZN_REASM_LINE_HOLDING, "a table with room was not HOLDING");
	CHECK(strstr(line, "holding 1 of 3") != NULL, "the line does not carry the occupancy");
	CHECK(strstr(line, "FULL") == NULL, "a table with room claimed to be full");

	/* ---- REFUSING WITH ROOM, which is the state the six before it could
	 * not express. Same table, same occupancy, same free slot -- only the
	 * per-sender bound differs, and this host is dropping that sender's
	 * chunks with half its capacity idle.
	 *
	 * THE PAIR IS THE POINT. `table_of` above differs from this call in one
	 * argument, so nothing but the bound can account for the two lines
	 * differing -- which is what says the printer is reading
	 * `per_sender_max` rather than something correlated with it. */
	CHECK(table_of_quota(&t, 1u, 0u, 0u, 1u), "the fixture does not build");
	len = line_of(&t, 100u, capped, &said);
	CHECK(said == FZN_REASM_LINE_QUOTA,
	      "a sender at its quota with a slot free was reported as merely holding");
	CHECK(strstr(capped, "REFUSING") != NULL,
	      "the line does not say that something is being refused");
	CHECK(strstr(capped, "2 of 3 slots stand free") != NULL,
	      "the line does not say the capacity is not the bound that binds");
	CHECK(strcmp(capped, line) != 0,
	      "a table refusing a sender and one merely holding produced the same "
	      "sentence, which is the whole distinction this state exists for");

	/* ---- AND A SENDER IS COUNTED ONCE, however many slots it holds.
	 * Every slot in this fixture carries the same all-zero sender, so two
	 * live slots are ONE capped sender and a census that counted slots
	 * would say two. The table needs a third slot for this to be askable
	 * at all -- with two, a sender holding both fills the table and the
	 * FULL arms answer first, which is why the fixture grew. */
	CHECK(table_of_quota(&t, 2u, 0u, 0u, 1u), "the fixture does not build");
	len = line_of(&t, 100u, capped, &said);
	CHECK(said == FZN_REASM_LINE_QUOTA, "two slots of one capped sender was not QUOTA");
	CHECK(strstr(capped, "1 senders hold") != NULL,
	      "one sender holding two slots was counted twice, so the line inflates how "
	      "many peers this bound is refusing");

	/* ---- FULL BECAUSE THE CALLER IS LEAKING. reassembly.h chose
	 * exhaustion as the honest symptom of a caller that never releases. */
	CHECK(table_of(&t, 3u, 3u, 0u), "the fixture does not build");
	len = line_of(&t, 100u, leaked, &said);
	CHECK(said == FZN_REASM_LINE_FULL_HANDED,
	      "a table full of finished messages nobody released was not reported as a leak");
	CHECK(strstr(leaked, "nobody released") != NULL,
	      "the line does not say the slots are finished messages the caller still holds, "
	      "which is a bug in the consumer rather than a size");

	/* ---- FULL BECAUSE NOBODY IS SWEEPING. */
	CHECK(table_of(&t, 3u, 0u, 3u), "the fixture does not build");
	len = line_of(&t, 100u, unswept, &said);
	CHECK(said == FZN_REASM_LINE_FULL_UNSWEPT,
	      "a table full of expired slots was not reported as unswept");
	CHECK(strstr(unswept, "calling expire") != NULL, "the line does not name the fix");

	/* ---- FULL AND NEITHER WAITING NOR RELEASING HELPS. This is the one
	 * the header says a consumer misreads as the case above. */
	CHECK(table_of(&t, 3u, 0u, 0u), "the fixture does not build");
	len = line_of(&t, 100u, undersized, &said);
	CHECK(said == FZN_REASM_LINE_FULL_LIVE,
	      "a table full of live unexpired slots was not reported as undersized");
	CHECK(strstr(undersized, "waiting and releasing will not help") != NULL,
	      "the line does not rule out the two fixes that do not apply, which is what "
	      "the header says a consumer assumes");

	/* ---- AND THE THREE ARE THREE SENTENCES. Same `live`, same
	 * `capacity`, same FZN_REASM_ERR_FULL from accept. */
	CHECK(strcmp(leaked, unswept) != 0 && strcmp(unswept, undersized) != 0
	              && strcmp(leaked, undersized) != 0,
	      "two full tables wanting different actions produced the same sentence, which "
	      "is where the return value already leaves a caller");

	/* ---- A HANDED SLOT IS NOT SWEEPABLE, even past its deadline. Expiry
	 * skips handed slots so the caller can still read the bytes, and a
	 * count that ignored that would promise back slots no sweep returns.
	 *
	 * ASSERTED ON THE COUNT, WHICH IS WHAT MOVES. The first version of this
	 * case used a FULL table and checked the STATE -- and a miscounted
	 * sweepable leaves the state at FULL_HANDED either way, so the sabotage
	 * for it survived. The table needs ROOM for the number to reach a line
	 * at all, because only HOLDING prints it. sec 230. */
	CHECK(table_of(&t, 1u, 1u, 1u), "the fixture does not build");
	len = line_of(&t, 100u, line, &said);
	CHECK(said == FZN_REASM_LINE_HOLDING, "a table with room was not HOLDING");
	CHECK(strstr(line, "0 ready to sweep") != NULL,
	      "an expired HANDED slot was counted as sweepable, so the line offers back a "
	      "slot fzn_reasm_expire will not take");

	/* AND THE SAME SLOT UNHANDED IS SWEEPABLE, which is the control: without
	 * it the assertion above passes for a census that counts nothing. */
	CHECK(table_of(&t, 1u, 0u, 1u), "the fixture does not build");
	len = line_of(&t, 100u, line, &said);
	CHECK(strstr(line, "1 ready to sweep") != NULL,
	      "an expired unhanded slot was not counted as sweepable, so the case above "
	      "proves nothing");

	/* ---- RENDERING RELEASES NOTHING. The census is taken by a printer,
	 * and a printer that swept what it counted would change the thing it
	 * describes. Held by `const` on both signatures; this is the tripwire
	 * for the edit that widens either. */
	CHECK(table_of(&t, 3u, 0u, 3u), "the fixture does not build");
	len = line_of(&t, 100u, line, &said);
	CHECK(SLOTS[0].live && SLOTS[1].live,
	      "rendering released a slot, so a report changed what it described");

	/* ---- THE OPERANDS. */
	CHECK(table_of(&t, 1u, 0u, 0u), "the fixture does not build");
	CHECK(fzn_reasm_print(&t, 100u, NULL, sizeof(line), &len, &said)
	              == FZN_REASM_ERR_MALFORMED, "printing accepted a null buffer");
	CHECK(fzn_reasm_print(&t, 100u, line, sizeof(line), NULL, &said)
	              == FZN_REASM_ERR_MALFORMED, "printing accepted a null length");
	CHECK(fzn_reasm_print(&t, 100u, line, sizeof(line), &len, NULL)
	              == FZN_REASM_ERR_MALFORMED,
	      "printing accepted a null state out-parameter, which is the required half");

	/* ---- A BUFFER TOO SMALL REPORTS WHAT IT NEEDED AND WRITES NOTHING. */
	said = FZN_REASM_LINE_HOLDING;
	len = 0;
	CHECK(fzn_reasm_print(&t, 100u, line, 4u, &len, &said) == FZN_REASM_ERR_MALFORMED,
	      "a four-byte buffer took a line");
	CHECK(len > 4u, "the refusal does not say how much room the line needed");
	CHECK(said == FZN_REASM_LINE_NONE,
	      "a refused render left a verdict behind, which a caller would read as one");

	printf("reasm_print_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
