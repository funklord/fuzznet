/* Tests for gui/authz_view.cpp.
 *
 * THE CASE THIS FILE EXISTS FOR is that the screen and `fzn_authz_origin_
 * permitted` never disagree. Whether an origin reaches a kind is the
 * library's answer; a widget that tested `policy.origins` against
 * FZN_ORIGIN_BIT itself would be a second implementation of the rule that
 * actually gates requests -- readable, obvious, and free to drift.
 *
 * So the central case does not assert which origins reach which policy. It
 * builds every combination of origin bits and requires the widget and the
 * library to agree about all of them, which is a relationship rather than a
 * table and survives the rule changing.
 */

#include "../authz_view.h"

extern "C" {
#include "../../trust/trust.h"
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
	fprintf(stderr, "  FAIL authz_view_test.cpp:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static const fzn_origin_t ORIGINS[] = { FZN_ORIGIN_SAME_USER, FZN_ORIGIN_LOCAL,
                                        FZN_ORIGIN_REMOTE };

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");

	QApplication app(argc, argv);
	fzn_authz_view view;
	fzn_cap_id_t cap;
	unsigned bits;
	size_t i;

	memset(&cap, 0xc0, sizeof(cap));

	/* THE CENTRAL CASE. Every combination of the three origin bits, both
	 * guarded and unguarded, and the screen must match the library for
	 * each -- eight times two times three answers. */
	{
		int agreed = 1;
		int reached = 0;
		int refused = 0;

		for (bits = 0; bits < 8u; bits++) {
			unsigned origins = 0;
			int guarded;

			for (i = 0; i < 3u; i++)
				if (bits & (1u << i))
					origins |= FZN_ORIGIN_BIT(ORIGINS[i]);

			for (guarded = 0; guarded < 2; guarded++) {
				fzn_authz_policy_t policy =
				        guarded ? fzn_authz_requires(&cap, origins)
				                : fzn_authz_unguarded(origins);

				view.show_policy(&policy);
				for (i = 0; i < 3u; i++) {
					int library = fzn_authz_origin_permitted(policy,
					                                         ORIGINS[i]);
					int screen = view.shows_origin_permitted(ORIGINS[i]);

					if (library)
						reached++;
					else
						refused++;
					if ((library != 0) != screen)
						agreed = 0;
				}
			}
		}
		CHECK(agreed,
		      "the screen and fzn_authz_origin_permitted disagree about an origin, "
		      "so the widget is deciding reachability rather than showing it");
		/* AND BOTH ANSWERS OCCURRED, or agreeing proves nothing: a
		 * widget that showed no origin at all would agree about every
		 * refusal. */
		CHECK(reached > 0 && refused > 0,
		      "the sweep is all one answer, so agreeing about it proves nothing");
	}

	/* AN UNSPELLED POLICY READS AS UNSPELLED. Both it and a policy written
	 * to refuse everything deny; only one of them is a configuration
	 * fault, and somebody has to be able to find it. */
	{
		fzn_authz_policy_t zeroed;
		fzn_authz_policy_t deliberate = fzn_authz_requires(&cap, 0u);

		memset(&zeroed, 0, sizeof(zeroed));

		view.show_policy(&zeroed);
		CHECK(!view.is_spelled(), "a zeroed policy claims to have been spelled");
		{
			const QString unspelled = view.requirement_text();

			view.show_policy(&deliberate);
			CHECK(view.is_spelled(), "a spelled policy claims otherwise");
			CHECK(view.requirement_text() != unspelled,
			      "a policy nobody wrote and one written to refuse everything "
			      "read the same, so a forgotten policy cannot be found");
		}
		/* Both reach nothing, which is the part that would have made
		 * them look alike. */
		view.show_policy(&zeroed);
		CHECK(view.origins_text() == QStringLiteral("nothing"),
		      "an unspelled policy shows an origin reaching it");
	}

	/* GUARDED AND UNGUARDED ARE DIFFERENT WORDS, for the reason the verdict
	 * enum keeps GRANTED_BY_CHAIN and GRANTED_UNGUARDED apart: a policy
	 * that has drifted to unguarded is a thing somebody is looking for. */
	{
		fzn_authz_policy_t guarded = fzn_authz_requires(&cap, FZN_ORIGIN_ANY);
		fzn_authz_policy_t open = fzn_authz_unguarded(FZN_ORIGIN_ANY);
		QString first;

		view.show_policy(&guarded);
		first = view.requirement_text();
		view.show_policy(&open);
		CHECK(first != view.requirement_text(),
		      "a guarded policy and an unguarded one read the same, so drift to "
		      "unguarded cannot be found by reading");
		CHECK(view.requirement_text().contains(QLatin1String("unguarded")),
		      "an unguarded policy does not say so");
	}

	/* THE CAPABILITY IS SPELLED THE WAY AN ANCHOR IS, because a
	 * thirty-two-byte identifier compared against a differently-formatted
	 * copy of itself cannot be compared. */
	{
		fzn_authz_policy_t policy = fzn_authz_requires(&cap, FZN_ORIGIN_ANY);
		char expected[FZN_TRUST_FINGERPRINT_LEN];

		view.show_policy(&policy);
		CHECK(fzn_trust_fingerprint(cap.b, expected, sizeof(expected)) == FZN_TRUST_OK,
		      "the fixture could not format");
		CHECK(view.requirement_text().contains(QString::fromLatin1(expected)),
		      "the capability is not shown in the library's own spelling");
	}

	/* A NULL POLICY IS THE UNSPELLED STATE, not a crash and not the last
	 * one left on screen. */
	{
		fzn_authz_policy_t open = fzn_authz_unguarded(FZN_ORIGIN_ANY);

		view.show_policy(&open);
		view.show_policy(nullptr);
		CHECK(!view.is_spelled(), "a null policy left the previous one on screen");
		CHECK(view.origins_text() == QStringLiteral("nothing"),
		      "a null policy shows origins reaching it");
	}

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	printf("authz_view_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
