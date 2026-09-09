/* Tests for gui/manifest_view.cpp, headless.
 *
 * THE CASE THIS FILE EXISTS FOR is the one the printer cannot cover. sec 224
 * answers "what is this host missing from THIS issuer"; a consumer following
 * five wants to know whether ANY of them is under-reported, and that answer is
 * this widget's own. So the cases below hold the rows constant and vary which
 * one is understated, and require the summary to change -- a widget that
 * counted good rows instead of the worst one would pass every case with four
 * sound issuers out of five and be wrong about the one that matters.
 *
 * NO SCREEN IS NEEDED AND NONE IS OPENED. `QT_QPA_PLATFORM=offscreen` is set
 * before the QApplication is built, the arrangement `qtty` relies on.
 */

extern "C" {
#include "../../chain/manifest.h"
#include "../../cli/manifest_print.h"
}

#include "../manifest_view.h"

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
	fprintf(stderr, "  FAIL manifest_view_test.cpp:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

/* Two past FZN_MANIFEST_VIEW_ROWS_MAX, so the truncation path is reachable.
 * An accessor nothing exercises is an accessor nobody has seen work. */
#define KEYS_MAX (FZN_MANIFEST_VIEW_ROWS_MAX + 2u)

static fzn_manifest_issuer_t ISSUERS[KEYS_MAX];
static fzn_manifest_deficit_t DEFICIT[8];
static uint8_t KEYS[KEYS_MAX][FZN_PUBKEY_LEN];

/* A state a consumer could hold, built directly. `cli/test/manifest_print_test`
 * argues the technique: what is tested here is what the widget makes of a
 * state, and driving the admit path to reach one is manifest_test's job. */
static bool state_of(fzn_manifest_state_t *state, size_t followed, size_t understated_at,
                     size_t pending_each)
{
	size_t i;
	size_t slot = 0u;

	memset(ISSUERS, 0, sizeof(ISSUERS));
	memset(DEFICIT, 0, sizeof(DEFICIT));
	for (i = 0u; i < KEYS_MAX; i++)
		memset(KEYS[i], static_cast<int>(0x31u + i), FZN_PUBKEY_LEN);

	if (fzn_manifest_init(state, ISSUERS, KEYS_MAX, DEFICIT, 8u) != FZN_MANIFEST_OK)
		return false;

	for (i = 0u; i < followed && i < KEYS_MAX; i++) {
		size_t j;

		memcpy(ISSUERS[i].issuer, KEYS[i], FZN_PUBKEY_LEN);
		ISSUERS[i].overflowed = (i == understated_at) ? 1 : 0;
		for (j = 0u; j < pending_each && slot < 8u; j++, slot++) {
			memcpy(DEFICIT[slot].issuer, KEYS[i], FZN_PUBKEY_LEN);
			memset(&DEFICIT[slot].capability, static_cast<int>(0x60u + slot),
			       sizeof(DEFICIT[slot].capability));
			memset(DEFICIT[slot].grantee, static_cast<int>(0x70u + slot),
			       FZN_PUBKEY_LEN);
		}
	}
	state->issuer_used = followed < KEYS_MAX ? followed : KEYS_MAX;
	state->deficit_used = slot;
	return true;
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);
	fzn_manifest_state_t state;
	fzn_manifest_view view;
	fzn_manifest_view_row rows[KEYS_MAX];
	QString sound_summary;
	size_t i;

	/* ---- NO STATE AT ALL is not "up to date". */
	view.show_issuers(nullptr, nullptr, 0u);
	CHECK(view.shown_state() == fzn_manifest_view::NOTHING,
	      "a widget with no state claims to know something");
	CHECK(!view.summary_text().contains(QStringLiteral("up to date")),
	      "a host tracking nothing read as current, which is the fail-open this whole "
	      "path exists to remove");
	CHECK(view.rows_text().isEmpty(), "rows were drawn for no state");
	CHECK(view.understated() == 0u, "a widget with no state counted understated issuers");

	CHECK(state_of(&state, 3u, 99u, 0u), "the fixture does not build");
	for (i = 0u; i < 3u; i++) {
		rows[i].issuer = KEYS[i];
		rows[i].label = QStringLiteral("issuer ") + QString::number(static_cast<int>(i));
	}

	/* ---- STATE PRESENT BUT NO ROWS: still nothing, because a caller that
	 * named no issuer asked nothing. */
	view.show_issuers(&state, rows, 0u);
	CHECK(view.shown_state() == fzn_manifest_view::NOTHING,
	      "asking about no issuers produced a verdict about some");

	/* ---- THREE SOUND AND UP TO DATE. */
	view.show_issuers(&state, rows, 3u);
	CHECK(view.shown_state() == fzn_manifest_view::COMPLETE,
	      "three sound and empty issuers were not COMPLETE");
	CHECK(view.understated() == 0u, "a sound state counted an understated issuer");
	CHECK(view.summary_text().contains(QStringLiteral("3")),
	      "the summary does not say how many issuers it asked about");
	CHECK(view.rows_text().split(QLatin1Char('\n')).size() == 3,
	      "three issuers did not produce three rows");
	CHECK(view.rows_text().contains(QStringLiteral("issuer 1")),
	      "a row does not carry the consumer's label for the key");
	sound_summary = view.summary_text();

	/* ---- ONE OF THE THREE IS UNDERSTATED, and nothing else changes. The
	 * rows are the same three issuers with the same labels; only the worst
	 * one differs, and the aggregate must follow it rather than the two
	 * that are fine. */
	CHECK(state_of(&state, 3u, 1u, 0u), "the fixture does not build");
	view.show_issuers(&state, rows, 3u);
	CHECK(view.shown_state() == fzn_manifest_view::UNDERSTATED,
	      "two sound issuers outvoted the one whose count is a floor, which is the only "
	      "row that can be hiding an authority this host still honours");
	CHECK(view.understated() == 1u, "the understated issuer was not counted");
	CHECK(view.summary_text() != sound_summary,
	      "an understated issuer produced the same summary as three sound ones");
	CHECK(!view.summary_text().contains(QStringLiteral("up to date")),
	      "a host that knows it is missing revocations read as up to date");

	/* ---- OUTSTANDING BUT SOUND is its own state, between the two. */
	CHECK(state_of(&state, 3u, 99u, 2u), "the fixture does not build");
	view.show_issuers(&state, rows, 3u);
	CHECK(view.shown_state() == fzn_manifest_view::PENDING,
	      "revocations outstanding with every count sound was not PENDING");
	CHECK(view.understated() == 0u, "a sound state counted an understated issuer");
	CHECK(view.rows_text().contains(QStringLiteral("outstanding")),
	      "the rows do not carry the printer's verdict");
	CHECK(!view.rows_text().contains(QStringLiteral("AT LEAST")),
	      "a sound count was hedged in a row");

	/* ---- AN ISSUER THIS STATE DOES NOT FOLLOW is a row of its own and
	 * must not read as up to date. */
	CHECK(state_of(&state, 1u, 99u, 0u), "the fixture does not build");
	view.show_issuers(&state, rows, 3u);
	CHECK(view.rows_text().contains(QStringLiteral("not followed")),
	      "an issuer nothing is tracked from did not say so in its row");

	/* ---- NO KEY IS DRAWN. Thirty-two bytes spell to 64 hex characters,
	 * and a truncation of one is the prefix comparison trust.h refuses to
	 * invite. */
	CHECK(!view.rows_text().contains(QStringLiteral("31313131")),
	      "a row drew the issuer key, which is either unreadable at full length or a "
	      "prefix somebody will compare");

	/* ---- A ROW WITH NO KEY IS SKIPPED RATHER THAN DRAWN BLANK. */
	CHECK(state_of(&state, 3u, 99u, 0u), "the fixture does not build");
	rows[2].issuer = nullptr;
	view.show_issuers(&state, rows, 3u);
	CHECK(view.rows_text().split(QLatin1Char('\n')).size() == 2,
	      "a row with no issuer to ask about was drawn anyway");
	rows[2].issuer = KEYS[2];

	/* ---- MORE ISSUERS THAN THE LIST DRAWS. The summary counts all of
	 * them and the rows say they do not, because a list that silently stops
	 * is one somebody reads as complete. */
	CHECK(state_of(&state, KEYS_MAX, KEYS_MAX - 1u, 0u), "the fixture does not build");
	for (i = 0u; i < KEYS_MAX; i++) {
		rows[i].issuer = KEYS[i];
		rows[i].label = QStringLiteral("issuer ") + QString::number(static_cast<int>(i));
	}
	view.show_issuers(&state, rows, KEYS_MAX);
	CHECK(view.rows_truncated(), "more issuers than the list draws was not reported");
	CHECK(view.rows_text().contains(QStringLiteral("more issuers")),
	      "the truncation is reported to a caller and not to the person reading it");
	CHECK(view.shown_state() == fzn_manifest_view::UNDERSTATED,
	      "an understated issuer PAST the row limit was not counted, so the summary "
	      "describes only what fitted");
	CHECK(view.understated() == 1u,
	      "the understated count stops at the rows drawn rather than the issuers asked "
	      "about");

	printf("manifest_view_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
