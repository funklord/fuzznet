/* Tests for gui/sync_view.cpp, headless.
 *
 * THE CASE THIS FILE EXISTS FOR is that "up to date" and "cannot say" both
 * report a deficit of zero. manifest.h built `fzn_manifest_overflowed` to
 * separate them, and says what is at stake: an absent or unfollowed state
 * means the deficit is "entirely unmeasured, and reporting an unmeasured
 * deficit as sound is the fail-open this module exists to remove".
 *
 * A screen drawing the number without asking would put that fail-open back at
 * the last possible moment. So the central case asserts that both report zero
 * missing AND that they do not read alike -- the number is the same and the
 * screen must not be.
 */

#include "../sync_view.h"

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
	fprintf(stderr, "  FAIL sync_view_test.cpp:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

#define ISSUERS  2u
#define DEFICITS 40u

static fzn_manifest_issuer_t ISSUER_ROWS[ISSUERS];
static fzn_manifest_deficit_t DEFICIT_ROWS[DEFICITS];

/* Put `n` outstanding pairs from `issuer` into the state's own table.
 *
 * The tables are caller-owned and their shape is public. Driving real
 * admissions would need a signing fixture and would exercise
 * `chain/test/manifest_test.c`'s path -- verification -- rather than this
 * file's question, which is what a screen says about a position. */
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

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");

	QApplication app(argc, argv);
	fzn_sync_view view;
	fzn_manifest_state_t st;
	uint8_t peer[FZN_PUBKEY_LEN];
	uint8_t stranger[FZN_PUBKEY_LEN];
	QString unmeasured;
	QString in_sync;

	memset(peer, 0x91, sizeof(peer));
	memset(stranger, 0x92, sizeof(stranger));

	CHECK(fzn_manifest_init(&st, ISSUER_ROWS, ISSUERS, DEFICIT_ROWS, DEFICITS) ==
	              FZN_MANIFEST_OK,
	      "the manifest state would not init");

	/* A NULL STATE CANNOT SAY, and the widget passes it through rather
	 * than deciding: the library already treats it as unmeasured. */
	view.show_peer(nullptr, peer);
	CHECK(view.shown_state() == fzn_sync_view::UNMEASURED,
	      "a null state was not reported as unable to say");

	/* AN UNFOLLOWED PEER IS THE SAME FACT IN DIFFERENT CLOTHES. */
	view.show_peer(&st, stranger);
	CHECK(view.shown_state() == fzn_sync_view::UNMEASURED,
	      "an unfollowed peer was not reported as unable to say");
	unmeasured = view.state_text();

	/* A FOLLOWED PEER WITH NOTHING OUTSTANDING IS UP TO DATE -- vacuously,
	 * which manifest.h says is the truth rather than a caveat: no manifest
	 * is an empty union is a zero deficit. */
	CHECK(fzn_manifest_follow(&st, peer) == FZN_MANIFEST_OK, "follow refused");
	view.show_peer(&st, peer);
	CHECK(view.shown_state() == fzn_sync_view::IN_SYNC,
	      "a followed peer with nothing outstanding was not up to date");
	in_sync = view.state_text();

	/* THE CASE THIS FILE EXISTS FOR. Both report zero. The screen must
	 * not. */
	CHECK(unmeasured != in_sync,
	      "an unmeasured deficit and an empty one are shown in the same words, "
	      "which is the fail-open manifest.h exists to remove, reintroduced at "
	      "the screen");

	/* BEHIND, WITH A COUNT. */
	deficit_of(&st, peer, 3u);
	view.show_peer(&st, peer);
	CHECK(view.shown_state() == fzn_sync_view::BEHIND,
	      "a peer with outstanding pairs was not shown as behind");
	CHECK(view.state_text().contains(QStringLiteral("3 outstanding")),
	      "the count is not on the screen");

	/* A REPORT THAT DID NOT FIT SAYS SO, on manifest.h's argument that one
	 * which quietly does not fit is "a range nobody asks for again". */
	deficit_of(&st, peer, DEFICITS);
	view.show_peer(&st, peer);
	CHECK(view.shown_state() == fzn_sync_view::BEHIND,
	      "a large deficit was not shown as behind");
	CHECK(view.state_text().contains(QStringLiteral("short")),
	      "a short report did not say the count is short");

	/* AND AN OVERFLOWED ISSUER IS UNMEASURED EVEN WITH A DEFICIT PRESENT.
	 * This is the sticky flag: the host knows it dropped something, so it
	 * cannot say what it is missing however many pairs it can list. */
	{
		size_t i;

		for (i = 0; i < st.issuer_used; i++)
			if (memcmp(ISSUER_ROWS[i].issuer, peer, FZN_PUBKEY_LEN) == 0)
				ISSUER_ROWS[i].overflowed = 1;

		view.show_peer(&st, peer);
		CHECK(view.shown_state() == fzn_sync_view::UNMEASURED,
		      "a peer whose report overflowed was shown as merely behind, so a "
		      "host that knows it lost pairs reports a number anyway");
	}

	/* THE ASSERTION THAT KEEPS ONE IMPLEMENTATION. sec 193, and sec 168's
	 * shape: the widget must SHOW `fzn_sync_print`'s line rather than have
	 * a wording of its own. A relationship, so it survives the words
	 * changing and goes red the moment somebody composes a sentence here
	 * again. */
	{
		char want[FZN_SYNC_PRINT_MAX];
		fzn_sync_state_t said = FZN_SYNC_UNMEASURED;
		size_t len = 0;
		QString expected;

		view.show_peer(&st, peer);
		CHECK(fzn_sync_print(&st, peer, want, sizeof(want), &len, &said) ==
		              FZN_MANIFEST_OK,
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

	printf("sync_view_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
