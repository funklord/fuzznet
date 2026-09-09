/* Tests for gui/ledger_view.cpp, headless.
 *
 * THE CASE THIS FILE EXISTS FOR is that one unreadable ledger voids a screen
 * of green rows. Every accessor in `record/ledger.h` answers an unscannable
 * table in the voice of a readable one -- a version of zero, a count of zero,
 * "behind" -- so rows drawn from one look like measurements and are not. The
 * case below gives the widget peers that would otherwise all be CURRENT and
 * requires the summary to say the opposite.
 *
 * THE SECOND is that `outstanding()` stays zero there, and that this is a
 * refusal rather than a claim: nobody measured how many peers are behind, so
 * the widget reports no number and `shown_state` is what says whether the
 * number means anything.
 *
 * NO SCREEN IS NEEDED AND NONE IS OPENED. `QT_QPA_PLATFORM=offscreen` is set
 * before the QApplication is built, the arrangement `qtty` relies on.
 */

extern "C" {
#include "../../cli/ledger_print.h"
#include "../../record/ledger.h"
}

#include "../ledger_view.h"

#include <QApplication>
#include <QString>
#include <QStringList>

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
	fprintf(stderr, "  FAIL ledger_view_test.cpp:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

/* Two past FZN_LEDGER_VIEW_ROWS_MAX, so the truncation path is reachable. */
#define PEERS_MAX (FZN_LEDGER_VIEW_ROWS_MAX + 2u)

static fzn_ledger_entry_t ENTRIES[PEERS_MAX];
static uint8_t KEYS[PEERS_MAX][FZN_PUBKEY_LEN];
static uint8_t SUBJECT[FZN_SUBJECT_LEN];

/* `confirm_up_to` peers acknowledge `version`; the rest have said nothing. */
static bool ledger_of(fzn_ledger_t *l, size_t peers, size_t confirm_up_to, uint64_t version)
{
	size_t i;

	for (i = 0u; i < PEERS_MAX; i++)
		memset(KEYS[i], static_cast<int>(0x41u + i), FZN_PUBKEY_LEN);
	memset(SUBJECT, 0x5a, sizeof(SUBJECT));

	if (fzn_ledger_init(l, ENTRIES, PEERS_MAX) != FZN_LEDGER_OK)
		return false;
	for (i = 0u; i < confirm_up_to && i < peers; i++) {
		if (fzn_ledger_confirm(l, KEYS[i], SUBJECT, 1u, version) != FZN_LEDGER_OK)
			return false;
	}
	return true;
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);
	fzn_ledger_t l;
	fzn_ledger_view view;
	fzn_ledger_view_row rows[PEERS_MAX];
	QString current_summary;
	size_t i;

	/* ---- NO LEDGER AT ALL is not "everybody is current". */
	view.show_peers(nullptr, nullptr, 0u, 0u, nullptr, 0u);
	CHECK(view.shown_state() == fzn_ledger_view::NOTHING,
	      "a widget with no ledger claims to know something");
	CHECK(!view.summary_text().contains(QStringLiteral("confirmed this version")),
	      "a host tracking nothing read as delivered");
	CHECK(view.rows_text().isEmpty(), "rows were drawn for no ledger");

	CHECK(ledger_of(&l, 3u, 3u, 5u), "the fixture does not build");
	for (i = 0u; i < PEERS_MAX; i++) {
		rows[i].peer = KEYS[i];
		rows[i].label = QStringLiteral("peer ") + QString::number(static_cast<int>(i));
	}

	/* ---- A LEDGER BUT NO PEERS: still nothing. */
	view.show_peers(&l, SUBJECT, 1u, 5u, rows, 0u);
	CHECK(view.shown_state() == fzn_ledger_view::NOTHING,
	      "asking about no peers produced a verdict about some");

	/* ---- ALL THREE CONFIRMED AT THE VERSION THIS HOST HOLDS. */
	view.show_peers(&l, SUBJECT, 1u, 5u, rows, 3u);
	CHECK(view.shown_state() == fzn_ledger_view::CURRENT,
	      "three peers confirmed at the current version were not CURRENT");
	CHECK(view.outstanding() == 0u, "a delivered subject counted an outstanding peer");
	CHECK(view.rows_text().split(QLatin1Char('\n')).size() == 3,
	      "three peers did not produce three rows");
	CHECK(view.rows_text().contains(QStringLiteral("peer 1")),
	      "a row does not carry the consumer's label for the key");
	current_summary = view.summary_text();

	/* ---- ONE BEHIND AND ONE THAT HAS NEVER SPOKEN, which the summary
	 * counts together and the rows keep apart. */
	CHECK(ledger_of(&l, 3u, 1u, 3u), "the fixture does not build");
	view.show_peers(&l, SUBJECT, 1u, 5u, rows, 3u);
	CHECK(view.shown_state() == fzn_ledger_view::BEHIND,
	      "peers that have not confirmed this version were not reported");
	CHECK(view.outstanding() == 3u,
	      "the outstanding count is not every peer -- one behind and two that have "
	      "never spoken, which the summary counts together because the action is the "
	      "same");
	CHECK(view.summary_text() != current_summary,
	      "an undelivered subject produced the same summary as a delivered one");
	CHECK(view.rows_text().contains(QStringLiteral("behind: confirmed 3")),
	      "the row does not say the first peer acknowledged an older version");
	CHECK(view.rows_text().contains(QStringLiteral("never acknowledged")),
	      "the row does not keep a peer that has never spoken apart from one that is "
	      "merely behind, which the summary deliberately collapses");

	/* ---- AN UNREADABLE LEDGER VOIDS A SCREEN OF GREEN ROWS. Every peer
	 * below would be CURRENT on a table that could be walked. */
	{
		fzn_ledger_t hollow;

		CHECK(ledger_of(&hollow, 3u, 3u, 5u), "the fixture does not build");
		hollow.used = hollow.capacity + 1u;
		view.show_peers(&hollow, SUBJECT, 1u, 5u, rows, 3u);
		CHECK(view.shown_state() == fzn_ledger_view::UNREADABLE,
		      "a ledger whose own fields disagree drew three rows of evidence");
		CHECK(!view.summary_text().contains(QStringLiteral("have confirmed")),
		      "an unreadable ledger reported delivery");
		CHECK(view.outstanding() == 0u,
		      "an unreadable ledger reported a number nobody measured");
	}

	/* ---- NO KEY IS DRAWN. */
	CHECK(ledger_of(&l, 3u, 3u, 5u), "the fixture does not build");
	view.show_peers(&l, SUBJECT, 1u, 5u, rows, 3u);
	CHECK(!view.rows_text().contains(QStringLiteral("41414141")),
	      "a row drew the peer key, which is either unreadable at full length or a "
	      "prefix somebody will compare");

	/* ---- A ROW WITH NO PEER IS SKIPPED RATHER THAN DRAWN BLANK. */
	rows[2].peer = nullptr;
	view.show_peers(&l, SUBJECT, 1u, 5u, rows, 3u);
	CHECK(view.rows_text().split(QLatin1Char('\n')).size() == 2,
	      "a row with no peer to ask about was drawn anyway");
	rows[2].peer = KEYS[2];

	/* ---- MORE PEERS THAN THE LIST DRAWS, with the one that has not
	 * confirmed placed PAST the limit: the summary counts it and the rows
	 * cannot show it. */
	CHECK(ledger_of(&l, PEERS_MAX, PEERS_MAX - 1u, 5u), "the fixture does not build");
	view.show_peers(&l, SUBJECT, 1u, 5u, rows, PEERS_MAX);
	CHECK(view.rows_truncated(), "more peers than the list draws was not reported");
	CHECK(view.rows_text().contains(QStringLiteral("more peers")),
	      "the truncation is reported to a caller and not to the person reading it");
	CHECK(view.shown_state() == fzn_ledger_view::BEHIND,
	      "a peer past the row limit that has not confirmed was not counted, so the "
	      "summary describes only what fitted");
	CHECK(view.outstanding() == 1u, "the outstanding count stops at the rows drawn");

	printf("ledger_view_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
