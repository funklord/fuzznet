/* Tests for gui/peer_view.cpp, headless.
 *
 * TWO CASES THIS FILE EXISTS FOR, and both are the tri-state meeting a screen.
 *
 * The first is that every affordance a toolkit offers for membership is
 * two-valued -- a checkbox, a tick, a coloured dot -- and the answer has
 * three values. `peer.h` built the tri-state so that "could not tell" cannot
 * be read as "no", because flattening it the other way "turns a read that
 * failed into an allow". A widget that rendered UNKNOWN as either of the
 * other two would undo that at the last inch, so the three renderings are
 * asserted pairwise distinct here rather than left to whoever edits the words.
 *
 * The second is that an unreadable group list and a genuinely empty one both
 * draw as an empty widget unless something is put there on purpose. peer.h:
 * "a `Groups:` line with no entries is a REAL empty membership ... A missing
 * `Groups:` line is not: that is could not tell."
 */

extern "C" {
#include "../../local/peer.h"
#include "../../local/vocabulary.h"
#include "../../cli/peer_print.h"
}

#include "../peer_view.h"

#include <QApplication>
#include <QString>

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
	fprintf(stderr, "  FAIL peer_view_test.cpp:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static const uint8_t STATUS[] = "status";
static const uint8_t DESTROY[] = "destroy";
static const uint8_t UNNAMED[] = "rebot";

#define V(x) (x), (sizeof(x) - 1u)

static void known_peer(fzn_peer_t *p)
{
	memset(p, 0, sizeof(*p));
	p->pid = 4021;
	p->uid = 1000u;
	p->primary_gid = 1000u;
	p->groups[0] = 6u;
	p->groups[1] = 27u;
	p->group_count = 2u;
	p->groups_known = 1;
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");

	QApplication app(argc, argv);
	fzn_peer_view view;
	const fzn_verb_rule_t rules[] = {
		{ 6u, V(STATUS) },
		{ 99u, V(DESTROY) },
	};
	const size_t n = sizeof(rules) / sizeof(rules[0]);
	fzn_peer_t p;
	QString admitted, denied, cannot_tell;
	QString empty_groups, unreadable_groups;

	known_peer(&p);

	/* THE THREE WORDS. */
	view.show_peer(&p, V(STATUS), rules, n);
	CHECK(view.shown_verdict() == FZN_PEER_MEMBER, "an admitted peer was not MEMBER");
	admitted = view.verdict_text();

	view.show_peer(&p, V(DESTROY), rules, n);
	CHECK(view.shown_verdict() == FZN_PEER_NOT_MEMBER, "a denied peer was not NOT_MEMBER");
	denied = view.verdict_text();

	{
		fzn_peer_t unknown;

		known_peer(&unknown);
		unknown.groups_known = 0;
		view.show_peer(&unknown, V(DESTROY), rules, n);
		CHECK(view.shown_verdict() == FZN_PEER_UNKNOWN,
		      "a peer whose groups could not be read got a definite answer");
		cannot_tell = view.verdict_text();
		unreadable_groups = view.groups_text();
	}

	CHECK(!admitted.isEmpty() && !denied.isEmpty() && !cannot_tell.isEmpty(),
	      "a verdict rendered as nothing at all, which reads as whatever the reader "
	      "expected");
	CHECK(admitted != denied, "an admission and a denial read alike");
	CHECK(cannot_tell != denied,
	      "could-not-tell reads exactly like a denial, so an operator cannot see that "
	      "the evidence was never obtained");
	CHECK(cannot_tell != admitted,
	      "could-not-tell reads exactly like an admission, which is the direction "
	      "peer.h says turns a read that failed into an allow");

	/* AND NOT BY PREFIX EITHER, since a narrow column truncates and two
	 * words sharing a first syllable would collapse again on screen. */
	CHECK(!admitted.startsWith(denied) && !denied.startsWith(admitted),
	      "two verdicts share a prefix, so a truncating label collapses them");
	CHECK(!cannot_tell.startsWith(denied) && !denied.startsWith(cannot_tell),
	      "two verdicts share a prefix, so a truncating label collapses them");

	/* THE SECOND CASE. Read-and-empty is not could-not-read. */
	{
		fzn_peer_t empty;

		known_peer(&empty);
		empty.group_count = 0u;
		empty.groups_known = 1;
		view.show_peer(&empty, V(DESTROY), rules, n);
		empty_groups = view.groups_text();
	}

	CHECK(!empty_groups.isEmpty(),
	      "a peer that belongs to no groups drew an empty widget, which is what an "
	      "unreadable list looks like too");
	CHECK(!unreadable_groups.isEmpty(),
	      "a peer whose groups could not be read drew an empty widget, which is what "
	      "belonging to none looks like too");
	CHECK(empty_groups != unreadable_groups,
	      "a real empty membership and an unreadable list read alike on screen, which "
	      "is the distinction peer.h exists for");

	/* THE COUNT IS NOT SHOWN WHEN THE LIST IS UNKNOWN, because peer.h says
	 * it is meaningless then -- and a stale one is what a caller most
	 * likely has. */
	{
		fzn_peer_t stale;

		known_peer(&stale);
		stale.groups_known = 0;
		stale.group_count = 2u;
		stale.groups[0] = 6u;
		view.show_peer(&stale, V(DESTROY), rules, n);
		CHECK(!view.groups_text().contains(QStringLiteral("6")),
		      "a gid was listed for a peer whose group list could not be read, so a "
		      "meaningless field was shown as a membership");
	}

	/* A COUNT PAST THE ARRAY IS NOT SCANNED. `fzn_peer_group_verdict`
	 * answers UNKNOWN rather than reading on, because reading past the
	 * array can only invent memberships. */
	{
		fzn_peer_t bogus;

		known_peer(&bogus);
		bogus.group_count = FZN_PEER_MAX_GROUPS + 1u;
		view.show_peer(&bogus, V(DESTROY), rules, n);
		CHECK(!view.groups_text().contains(QStringLiteral("27")),
		      "a struct whose count exceeds its array was scanned anyway");
	}

	/* THE TWO DENIALS, which the verdict cannot separate and `named` can. */
	known_peer(&p);
	view.show_peer(&p, V(DESTROY), rules, n);
	CHECK(view.shown_verdict() == FZN_PEER_NOT_MEMBER && view.named(),
	      "a verb the table reserves to another group was reported as one the policy "
	      "does not cover");
	{
		QString reserved = view.summary_text();
		const fzn_verb_rule_t silent[] = { { 6u, V(STATUS) } };

		view.show_peer(&p, V(UNNAMED), rules, n);
		CHECK(view.shown_verdict() == FZN_PEER_NOT_MEMBER && !view.named(),
		      "a verb no rule names was reported as one the policy covers");

		/* THE SAME VERB, TWO TABLES. Two different verbs make the lines
		 * differ on the verb whatever the reason says, which is how the
		 * printer's own version of this check passed a sabotage that
		 * had collapsed both reasons into one word. */
		view.show_peer(&p, V(DESTROY), silent, 1u);
		CHECK(view.shown_verdict() == FZN_PEER_NOT_MEMBER && !view.named(),
		      "a verb this table does not name was reported as covered");
		CHECK(view.summary_text() != reserved,
		      "one verb, denied for two different reasons, read the same on screen");
	}

	/* THE WIDGET AND THE PRINTER MUST AGREE, which is what pins the wiring. */
	{
		char line[FZN_PEER_PRINT_MAX];
		fzn_peer_verdict_t verdict = FZN_PEER_UNKNOWN;
		int named = 0;
		size_t len = 0u;

		view.show_peer(&p, V(STATUS), rules, n);
		CHECK(fzn_peer_print(&p, V(STATUS), rules, n, line, sizeof(line), &len,
		                     &verdict, &named) == 0,
		      "the printer refused what the widget accepted");
		CHECK(view.summary_text() == QString::fromLatin1(line),
		      "the widget composed its own summary instead of showing the printer's");
		CHECK(view.shown_verdict() == verdict,
		      "the widget's verdict and the printer's have drifted apart");
		CHECK(view.named() == (named ? true : false),
		      "the widget and the printer disagree about whether the table names the "
		      "verb");
	}

	/* A HOSTILE VERB REACHES THE SCREEN THROUGH THE PRINTER, so the
	 * escaping has to survive the trip. */
	{
		static const uint8_t evil[] = "status\nADMITTED: root ran destroy";

		view.show_peer(&p, V(evil), rules, n);
		CHECK(!view.summary_text().contains(QLatin1Char('\n')),
		      "a newline in a verb reached the label, so a peer can forge a second "
		      "line in anything that copies this text out");
		CHECK(view.shown_verdict() == FZN_PEER_NOT_MEMBER, "a hostile verb was admitted");
	}

	/* NO PEER IS THE DENYING CASE, not a stale display. */
	view.show_peer(nullptr, V(STATUS), rules, n);
	CHECK(view.shown_verdict() == FZN_PEER_UNKNOWN, "a null peer left the last verdict");
	CHECK(view.verdict_text() == cannot_tell, "a null peer did not read as cannot-tell");
	CHECK(!view.groups_text().isEmpty(), "a null peer left a blank where groups go");
	CHECK(!view.groups_text().contains(QStringLiteral("27")),
	      "a null peer left the previous peer's groups on screen");

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	printf("peer_view_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
