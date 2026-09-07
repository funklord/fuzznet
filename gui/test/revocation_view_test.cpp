/* Tests for gui/revocation_view.cpp, headless.
 *
 * THE CASE THIS FILE EXISTS FOR is that a withdrawn entry is not a
 * revocation. `chain.h` keeps it in the store deliberately -- removing it
 * would let a re-relayed copy be re-admitted "not [as] a one-time
 * resurrection but a loop" -- so a screen that counted rows would report every
 * capability that was ever revoked and has since been RESTORED as still
 * revoked. That is the outage the withdrawal design exists to end, drawn on a
 * screen.
 *
 * The second is that a store counting more entries than it holds is not a
 * number to draw. The library's predicates fail closed for such a store and
 * neither can be asked to identify it, so the widget bounds its own walk --
 * and the case here is the one that would read off the end.
 */

#include "../revocation_view.h"

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
	fprintf(stderr, "  FAIL revocation_view_test.cpp:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static fzn_revocation_t ENTRIES[4];

/* A store holding `revocations` entries in force and `withdrawals` whose
 * revocation has been taken back. Filled by hand: the store is caller-owned
 * memory whose shape is public, and admitting real records would exercise
 * `chain/test/revocation_test.c`'s path rather than this file's question. */
static int store_of(fzn_revocation_store_t *store, size_t revocations, size_t withdrawals)
{
	size_t i;
	size_t n = revocations + withdrawals;

	memset(ENTRIES, 0, sizeof(ENTRIES));
	for (i = 0; i < n && i < 4u; i++) {
		memset(&ENTRIES[i].capability, (int)(0x40u + i), sizeof(ENTRIES[i].capability));
		memset(ENTRIES[i].grantee, (int)(0x50u + i), sizeof(ENTRIES[i].grantee));
		memset(ENTRIES[i].issuer, 0x60, sizeof(ENTRIES[i].issuer));
		ENTRIES[i].withdrawn = i >= revocations ? 1u : 0u;
	}
	if (fzn_revocation_store_init(store, ENTRIES, 4u) != FZN_CHAIN_OK)
		return 0;
	store->used = n;
	return 1;
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");

	QApplication app(argc, argv);
	fzn_revocation_view view;
	fzn_revocation_store_t store;

	/* NO STORE IS AN ANSWER, not a mistake -- revocation.h says a null
	 * store means a host that knows of no revocations. */
	CHECK(view.shown_state() == fzn_revocation_view::NOTHING,
	      "a fresh view is not in the no-store state");

	/* AN EMPTY STORE IS NOT AN ABSENT ONE. */
	{
		QString absent = view.state_text();

		CHECK(store_of(&store, 0u, 0u), "the store would not init");
		view.show_store(&store);
		CHECK(view.shown_state() == fzn_revocation_view::EMPTY,
		      "an empty store was not shown as empty");
		CHECK(view.state_text() != absent,
		      "a host with an empty store reads exactly like one with no store");
	}

	/* THE CASE THIS FILE EXISTS FOR. Three entries: one revocation in
	 * force, two withdrawn. A reader counting rows says three revoked; the
	 * truth is one, and the other two work again. */
	{
		CHECK(store_of(&store, 1u, 2u), "the store would not init");
		view.show_store(&store);

		CHECK(view.in_force() == 1u,
		      "withdrawn entries were counted as revocations, so capabilities "
		      "that have been restored are shown as still cut off");
		CHECK(view.withdrawn() == 2u, "the withdrawn entries were not counted");
		CHECK(view.in_force() + view.withdrawn() == 3u,
		      "the two counts do not partition the store");
		CHECK(view.summary_text().contains(QStringLiteral("work again")),
		      "a restored capability is not said to be restored, which is the "
		      "thing somebody is looking for when a peer says they are back");
	}

	/* AND A STORE OF NOTHING BUT WITHDRAWALS SAYS NOTHING IS IN FORCE.
	 * Without this the case above passes for a widget that always reports
	 * one in force. */
	{
		CHECK(store_of(&store, 0u, 3u), "the store would not init");
		view.show_store(&store);
		CHECK(view.in_force() == 0u,
		      "a store holding only withdrawals reported a revocation in force");
		CHECK(view.withdrawn() == 3u, "the withdrawals were not counted");
	}

	/* A STORE COUNTING MORE THAN IT HOLDS IS NOT A NUMBER TO DRAW. Walking
	 * `used` here is the read that goes off the array. */
	{
		CHECK(store_of(&store, 2u, 1u), "the store would not init");
		store.used = store.capacity + 1u;

		view.show_store(&store);
		CHECK(view.shown_state() == fzn_revocation_view::UNREADABLE,
		      "a store counting more entries than it holds was walked anyway");
		CHECK(view.in_force() == 0u && view.withdrawn() == 0u,
		      "a corrupt store produced counts, which are read off the end of "
		      "the array");
		CHECK(view.state_text() != QStringLiteral("nothing withdrawn"),
		      "an unreadable store reads as a host with nothing revoked, which is "
		      "the fail-open answer");
	}

	/* AND A STORE WITH A COUNT BUT NO ARRAY IS THE SAME CONDITION. */
	{
		CHECK(store_of(&store, 2u, 0u), "the store would not init");
		store.entries = NULL;

		view.show_store(&store);
		CHECK(view.shown_state() == fzn_revocation_view::UNREADABLE,
		      "a store with a count and no array was walked anyway");
	}

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	printf("revocation_view_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
