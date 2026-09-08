/* Tests for gui/state_view.cpp, headless.
 *
 * THE CASE THIS FILE EXISTS FOR is the pair `fzn_state_get` deliberately
 * refuses to separate. It answers NULL for a tombstone and for a subject
 * nothing ever set, and state.h says why: "a caller asking what a subject
 * says must not have to know that this file remembers who unset it."
 *
 * That is right for code taking a decision and wrong for a person. "Nobody
 * configured this" and "somebody revoked it, and here is who" are the two
 * things somebody staring at a host that will not do what they expect most
 * needs told apart -- so this widget walks for the second, and the suite's
 * central case is that the two do not read alike.
 */

#include "../state_view.h"

extern "C" {
#include "../../record/record.h"
}

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
	fprintf(stderr, "  FAIL state_view_test.cpp:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static uint8_t WIRE[8][FZN_RECORD_MAX_LEN];
static size_t wire_next;

static int fixture_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	uint64_t h = 1469598103934665603u;
	size_t i;

	(void)ctx;
	for (i = 0; i < msg_len; i++) {
		h ^= msg[i];
		h *= 1099511628211u;
	}
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h ^= (uint64_t)i;
		h *= 1099511628211u;
		sig[i] = (uint8_t)(h >> 32);
	}
	return 1;
}

static int make(fzn_record_t *r, const uint8_t issuer[FZN_PUBKEY_LEN],
                const uint8_t subject[FZN_SUBJECT_LEN], uint32_t kind, uint64_t seq,
                const uint8_t *body, size_t body_len)
{
	fzn_sign_ops_t ops;
	uint8_t *slot = WIRE[wire_next % 8u];
	size_t wrote = 0;

	wire_next++;
	memset(&ops, 0, sizeof(ops));
	ops.sign = fixture_sign;

	if (fzn_record_sign(issuer, subject, 1u, kind, seq, 1, body, body_len, &ops, slot,
	                    FZN_RECORD_MAX_LEN, &wrote) != FZN_RECORD_OK)
		return 0;
	return fzn_record_open(slot, wrote, r) == FZN_RECORD_OK;
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");

	QApplication app(argc, argv);
	fzn_state_view view;
	fzn_state_entry_t entries[4];
	fzn_state_t st;
	fzn_record_t rec;
	uint8_t issuer[FZN_PUBKEY_LEN];
	uint8_t subject[FZN_SUBJECT_LEN];
	uint8_t other[FZN_SUBJECT_LEN];
	const uint8_t body[2] = { 'o', 'n' };

	memset(issuer, 0x71, sizeof(issuer));
	memset(subject, 0x81, sizeof(subject));
	memset(other, 0x82, sizeof(other));

	CHECK(view.shown_state() == fzn_state_view::NOTHING,
	      "a fresh view is not in the no-state state");

	CHECK(fzn_state_init(&st, entries, 4) == FZN_STATE_OK, "the state would not init");

	/* NOBODY HAS SET IT. */
	view.show_cell(&st, subject, 5u);
	CHECK(view.shown_state() == fzn_state_view::NEVER_SET,
	      "an unset subject was not shown as unset");
	CHECK(!view.state_text().contains(QStringLiteral("set by")),
	      "an unset subject named somebody");

	/* SET, AND THE ISSUER IS THE LIBRARY'S ANSWER. */
	CHECK(make(&rec, issuer, subject, 5u, 1u, body, sizeof(body)),
	      "the fixture could not sign a record");
	CHECK(fzn_state_apply(&st, &rec) == FZN_STATE_OK, "apply refused");

	view.show_cell(&st, subject, 5u);
	CHECK(view.shown_state() == fzn_state_view::SET, "a set cell was not shown as set");
	CHECK(view.state_text().contains(QStringLiteral(" at 1")),
	      "the sequence is not the record's");
	CHECK(fzn_state_get(&st, subject, 5u) != NULL,
	      "the library does not hold the cell the widget just reported");

	/* THE CASE THIS FILE EXISTS FOR. Clear it: `fzn_state_get` now answers
	 * NULL, exactly as it does for a subject nobody ever set, and the two
	 * must not read alike. */
	{
		QString never_set;

		view.show_cell(&st, other, 5u);
		never_set = view.state_text();

		CHECK(make(&rec, issuer, subject, 5u, 2u, NULL, 0),
		      "the fixture could not sign the clearing record");
		CHECK(fzn_state_clear(&st, &rec) == FZN_STATE_OK, "clear refused");

		CHECK(fzn_state_get(&st, subject, 5u) == NULL,
		      "the library still answers for a cleared cell, so this case proves "
		      "nothing about looking past it");

		view.show_cell(&st, subject, 5u);
		CHECK(view.shown_state() == fzn_state_view::CLEARED,
		      "a cleared cell was not distinguished from one nobody ever set");
		CHECK(view.state_text() != never_set,
		      "cleared and never-set are shown in the same words, which is the "
		      "one thing fzn_state_get cannot tell a caller and the one thing a "
		      "person needs");
		CHECK(view.state_text().contains(QStringLiteral("taken back by")),
		      "a tombstone did not name who cleared it, which is the reason for "
		      "walking at all");
	}

	/* AND A SUBJECT NOBODY TOUCHED IS STILL NEVER_SET after all that --
	 * without this, a widget that called everything CLEARED would pass. */
	view.show_cell(&st, other, 5u);
	CHECK(view.shown_state() == fzn_state_view::NEVER_SET,
	      "an untouched subject was reported as cleared");

	/* A STATE THAT CANNOT BE WALKED IS NOT A CELL TO DRAW. */
	{
		st.used = st.capacity + 1u;
		view.show_cell(&st, subject, 5u);
		CHECK(view.shown_state() == fzn_state_view::UNREADABLE,
		      "a state counting more cells than it holds was walked anyway");
		CHECK(view.state_text() != QStringLiteral("nobody has set this"),
		      "an unreadable state reads as a host with nothing configured, which "
		      "is the fail-open answer");
	}

	/* THE ASSERTION THAT KEEPS ONE IMPLEMENTATION. sec 193/197. */
	{
		char want[FZN_STATE_PRINT_MAX];
		fzn_state_cell_t said = FZN_STATE_CELL_UNREADABLE;
		size_t plen = 0;
		QString expected;

		st.used = 2u;
		view.show_cell(&st, subject, 5u);
		CHECK(fzn_state_print(&st, subject, 5u, want, sizeof(want), &plen, &said) ==
		              FZN_STATE_OK,
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

	printf("state_view_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
