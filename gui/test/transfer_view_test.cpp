/* Tests for gui/transfer_view.cpp, headless.
 *
 * THE CASE THIS FILE EXISTS FOR is that looking at a transfer does not change
 * it. `fzn_transfer_expire` reclaims assignments past their deadline and
 * returns how many it took; a view that called it while rendering would make
 * a transfer behave differently depending on whether somebody had a window
 * open. So the suite renders a transfer with overdue assignments TWICE and
 * requires the outstanding count to be identical -- and requires the library
 * to still be able to reclaim them afterwards, which is what proves the view
 * left them alone rather than that nothing was there.
 *
 * The second is that "nothing outstanding" is three conditions. Not started,
 * stalled and complete all read `in_flight == 0`, and they are the three
 * things a person looking at a stopped transfer needs to tell apart.
 */

#include "../transfer_view.h"

#include <QApplication>

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
	fprintf(stderr, "  FAIL transfer_view_test.cpp:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

#define LEAVES 16u

/* A store that is never read from or written to.
 *
 * `fzn_spool_open` requires the vtable rather than accepting NULL, which is
 * right -- a spool with no store is a spool that cannot answer `read`. This
 * view never causes a read or a write, so the ops exist to satisfy the
 * constructor and refusing every call is the honest stub: if the widget ever
 * grows a path that touches a leaf, these fail loudly instead of pretending. */
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

static fzn_spool_ops_t OPS;

static uint8_t ROOT[FZN_BLOB_HASH_LEN];
static uint8_t PRESENT[FZN_SPOOL_BITMAP_LEN(LEAVES)];
static fzn_transfer_assign_t SLOTS[4];

/* A spool at a chosen position.
 *
 * The bits are set here and `fzn_spool_open` is left to count them, because
 * its own header says it "recompute[s] `have` from the bits rather than
 * trusting a caller". So the fixture's position is the LIBRARY's count of
 * what the fixture laid down, not a number this file asserted -- which is
 * what makes `held()` worth comparing against anything. Driving sixteen
 * verified writes through `fzn_spool_place` is `spool/`'s own test's job. */
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

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");

	QApplication app(argc, argv);
	fzn_transfer_view view;
	fzn_spool_t spool;
	fzn_transfer_t transfer;

	/* NO SPOOL IS ITS OWN STATE. */
	CHECK(view.shown_state() == fzn_transfer_view::NOTHING,
	      "a fresh view is not in the no-transfer state");

	/* NOT STARTED: nothing held, nothing outstanding. */
	CHECK(spool_at(&spool, 0u), "the spool would not open");
	CHECK(fzn_transfer_open(&transfer, &spool, SLOTS, 4u) == FZN_TRANSFER_OK,
	      "the transfer would not open");
	view.show_transfer(&spool, &transfer, 100u);
	CHECK(view.shown_state() == fzn_transfer_view::IDLE,
	      "a transfer that has not started was not shown as such");
	CHECK(view.held() == 0u && view.total() == LEAVES, "the position is wrong");

	/* STALLED: something held, nothing outstanding, not complete. The
	 * distinction from IDLE is the whole point -- both have in_flight 0. */
	CHECK(spool_at(&spool, 5u), "the spool would not open");
	CHECK(fzn_transfer_open(&transfer, &spool, SLOTS, 4u) == FZN_TRANSFER_OK,
	      "the transfer would not reopen");
	view.show_transfer(&spool, &transfer, 100u);
	CHECK(view.shown_state() == fzn_transfer_view::STALLED,
	      "a stopped, incomplete transfer was not shown as stalled");
	{
		QString stalled = view.state_text();

		CHECK(spool_at(&spool, 0u), "the spool would not open");
		CHECK(fzn_transfer_open(&transfer, &spool, SLOTS, 4u) == FZN_TRANSFER_OK,
		      "the transfer would not reopen");
		view.show_transfer(&spool, &transfer, 100u);
		CHECK(view.state_text() != stalled,
		      "not-started and stalled are shown in the same words, so a reader "
		      "cannot tell a transfer that never began from one that stopped");
	}

	/* COMPLETE, and it is the library's answer. */
	CHECK(spool_at(&spool, LEAVES), "the spool would not open");
	CHECK(fzn_transfer_open(&transfer, &spool, SLOTS, 4u) == FZN_TRANSFER_OK,
	      "the transfer would not reopen");
	CHECK(fzn_spool_complete(&spool), "the fixture is not complete, so it proves nothing");
	view.show_transfer(&spool, &transfer, 100u);
	CHECK(view.shown_state() == fzn_transfer_view::COMPLETE,
	      "a complete spool was not shown as complete");
	CHECK(view.state_text() != QStringLiteral("stalled -- nothing outstanding"),
	      "a finished transfer reads as a stuck one");

	/* WORKING: something outstanding. */
	CHECK(spool_at(&spool, 2u), "the spool would not open");
	CHECK(fzn_transfer_open(&transfer, &spool, SLOTS, 4u) == FZN_TRANSFER_OK,
	      "the transfer would not reopen");
	{
		fzn_spool_range_t range;

		memset(&range, 0, sizeof(range));
		CHECK(fzn_transfer_next_want(&transfer, 7u, 0u, 4u, 500u, &range) ==
		              FZN_TRANSFER_OK,
		      "the fixture could not put a range in flight");
		CHECK(fzn_transfer_in_flight(&transfer) == 1u, "the range is not outstanding");
	}
	view.show_transfer(&spool, &transfer, 100u);
	CHECK(view.shown_state() == fzn_transfer_view::WORKING,
	      "a transfer with an outstanding range was not shown as working");

	/* THE CASE THIS FILE EXISTS FOR. Render at a `now` past the deadline,
	 * twice, and the transfer must be untouched -- the view may say the
	 * assignment is reclaimable and must not reclaim it. */
	{
		size_t before = fzn_transfer_in_flight(&transfer);
		size_t after_one;
		size_t reclaimed;

		CHECK(before == 1u, "the fixture has nothing outstanding to protect");

		view.show_transfer(&spool, &transfer, 900u);
		after_one = fzn_transfer_in_flight(&transfer);
		CHECK(after_one == before,
		      "rendering an overdue transfer reclaimed an assignment, so looking "
		      "at the screen changed what the peer still owes");
		CHECK(view.state_text().contains(QStringLiteral("reclaimable")),
		      "an overdue assignment was not shown as reclaimable");
		CHECK(!view.state_text().contains(QStringLiteral("fail")),
		      "a passed deadline was reported as a failure, which it is not");

		view.show_transfer(&spool, &transfer, 900u);
		CHECK(fzn_transfer_in_flight(&transfer) == before,
		      "rendering twice reclaimed an assignment");

		/* AND THE LIBRARY CAN STILL TAKE IT. Without this the case
		 * above passes for a view that reclaimed nothing because there
		 * was nothing to reclaim. */
		reclaimed = fzn_transfer_expire(&transfer, 900u);
		CHECK(reclaimed == 1u,
		      "the library could not reclaim the assignment the view left alone, "
		      "so the case above proved nothing");
	}

	/* A SPOOL WITH NO SCHEDULER still has a position worth showing. */
	CHECK(spool_at(&spool, 9u), "the spool would not open");
	view.show_transfer(&spool, nullptr, 100u);
	CHECK(view.held() == 9u && view.total() == LEAVES,
	      "a spool without a transfer lost its position");
	CHECK(view.shown_state() != fzn_transfer_view::NOTHING,
	      "a spool without a transfer was shown as no transfer at all");
	CHECK(view.window_text() != QStringLiteral("--"),
	      "a spool without a transfer says nothing about the missing scheduler");

	/* THE ASSERTION THAT KEEPS ONE IMPLEMENTATION. sec 193/195. */
	{
		char want[FZN_TRANSFER_PRINT_MAX];
		fzn_transfer_state_t said = FZN_TRANSFER_NOTHING;
		size_t plen = 0;
		QString expected;

		CHECK(spool_at(&spool, 5u), "the spool would not reopen");
		CHECK(fzn_transfer_open(&transfer, &spool, SLOTS, 4u) == FZN_TRANSFER_OK,
		      "the transfer would not reopen");
		view.show_transfer(&spool, &transfer, 100u);
		CHECK(fzn_transfer_print(&spool, &transfer, 100u, want, sizeof(want), &plen,
		                         &said) == FZN_TRANSFER_OK,
		      "the printer would not render what the widget was given");
		expected = QString::fromLatin1(want);
		while (expected.endsWith(QLatin1Char('\n')))
			expected.chop(1);
		CHECK(view.state_text() == expected,
		      "the widget's words are not the printer's, so one screen has two "
		      "wordings again");
	}

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	printf("transfer_view_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
