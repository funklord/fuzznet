/*
 * clock_notice_test -- what a person is told of clocks that disagree,
 * fuzznet sec 1507: the text and signature as fuzzypickles' gui_test held
 * them (its test_the_clock_notice_says_who_and_how_far, moved with the
 * code), and the whole notice read from a node that names a sibling.
 */
#include "../clock_notice.h"

#include <QCoreApplication>

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                     \
	do {                                                                                  \
		checks++;                                                                     \
		if (!(cond)) {                                                                \
			failures++;                                                           \
			fprintf(stderr, "  FAIL clock_notice_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                             \
	} while (0)

#define LAPTOP "1a1a000000000000000000000000000000000000000000000000000000000001"

/* A NODE whose clock is unsure, one sibling, the laptop, behind by 600 s. */
static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	(void)ctx;
	if (!strcmp(line, "get clock"))
		return (size_t)snprintf(reply, cap, "ok 0 1 unsure\n");
	if (!strcmp(line, "list clock 0"))
		return (size_t)snprintf(reply, cap, "ok 1 0 " LAPTOP ",behind,600,1000\n");
	if (!strcmp(line, "list contact 0"))
		return (size_t)snprintf(reply, cap, "ok 0 0\n");
	if (!strcmp(line, "list sibling 0"))
		return (size_t)snprintf(reply, cap, "ok 1 0 " LAPTOP ",-,1,0,laptop\n");
	return (size_t)snprintf(reply, cap, "error no such thing\n");
}

int main(int argc, char **argv)
{
	QCoreApplication app(argc, argv);

	fzn_rpc_clock_row_t r[2];
	memset(r, 0, sizeof r);
	memset(r[0].key, 0xaa, 32);
	r[0].ahead = 0;
	r[0].seconds = 600;
	r[0].at = 1000;
	memset(r[1].key, 0xbb, 32);
	r[1].ahead = 1;
	r[1].seconds = 45;
	r[1].at = 2000;
	fzn_rpc_clock_list_t one = {r, 1}, two = {r, 2}, none = {r, 0};
	QHash<QByteArray, QString> names;
	names.insert(QByteArray(32, char(0xaa)), QStringLiteral("bob"));
	fzn_rpc_clock_estate_t unsure{}, right{}, behind{}, ahead{};
	unsure.state = FZN_RPC_CLOCK_UNSURE;
	right.state = FZN_RPC_CLOCK_RIGHT;
	right.devices = 2;
	behind = {95000, 3, FZN_RPC_CLOCK_WRONG};
	ahead = {-7200000, 2, FZN_RPC_CLOCK_WRONG};

	const QString a = fzn_clock_notice_text(unsure, one, names);
	CHECK(a.contains(QStringLiteral("This device's clock and bob's are more than 10 minutes apart")), "the clock notice, check 1");
	CHECK(a.contains(QStringLiteral("bob's clock runs behind this device's, or this one's ahead")), "the clock notice, check 2");
	CHECK(a.contains(QStringLiteral("Check that this device's date and time are right.")), "the clock notice, check 3");
	CHECK(!a.contains(QStringLiteral("other device")), "the clock notice, check 4");

	const QString b = fzn_clock_notice_text(unsure, two, names);
	CHECK(b.contains(QStringLiteral("and a device (bbbbbbbb)'s are more than 45 seconds apart")), "the clock notice, check 5");
	CHECK(b.contains(QStringLiteral("runs ahead of this device's, or this one's behind")), "the clock notice, check 6");
	CHECK(b.contains(QStringLiteral("Clocks disagree with 1 other device(s) too.")), "the clock notice, check 7");
	CHECK(fzn_clock_notice_text(unsure, none, names).isEmpty(), "the clock notice, check 8");
	CHECK(fzn_clock_notice_text(right, none, names).isEmpty(), "the clock notice, check 9");

	/* Right here: it is bob's to set. */
	const QString theirs = fzn_clock_notice_text(right, one, names);
	CHECK(theirs.contains(QStringLiteral("agrees with your other devices', so it is bob's date and time to set.")), "the clock notice, check 10");
	CHECK(!theirs.contains(QStringLiteral("Check that this device's")), "the clock notice, check 11");
	/* Wrong here: this device's, shown with no rows at all. */
	const QString mine = fzn_clock_notice_text(behind, none, names);
	CHECK(mine.contains(QStringLiteral("This device's clock is 95 seconds behind your other devices' (3 measured)")), "the clock notice, check 12");
	CHECK(mine.contains(QStringLiteral("Set this device's date and time.")), "the clock notice, check 13");
	const QString fast = fzn_clock_notice_text(ahead, two, names);
	CHECK(fast.contains(QStringLiteral("This device's clock is 2 hours ahead of your other devices' (2 measured)")), "the clock notice, check 14");
	CHECK(fast.contains(QStringLiteral("Clocks disagree with 2 device(s) because of it.")), "the clock notice, check 15");
	/* As measured live, a few ms short of fifteen minutes: rounded, not cut. */
	const fzn_rpc_clock_estate_t live = {899994, 2, FZN_RPC_CLOCK_WRONG};
	CHECK(fzn_clock_notice_text(live, none, names).contains(QStringLiteral("is 15 minutes behind")), "the clock notice, check 16");

	fzn_rpc_clock_row_t swapped[2] = {r[1], r[0]};
	fzn_rpc_clock_list_t two_swapped = {swapped, 2};
	CHECK(fzn_clock_notice_signature(unsure, two) == fzn_clock_notice_signature(unsure, two_swapped), "the clock notice, check 17");
	swapped[0].ahead = 0;
	CHECK(fzn_clock_notice_signature(unsure, two) != fzn_clock_notice_signature(unsure, two_swapped), "the clock notice, check 18");
	CHECK(fzn_clock_notice_signature(unsure, none) != fzn_clock_notice_signature(behind, none), "the clock notice, check 19");
	CHECK(fzn_clock_notice_signature(unsure, two) != fzn_clock_notice_signature(right, two), "the clock notice, check 20");

	/* THE WHOLE NOTICE FROM THE NODE, the sibling named. */
	{
		QString text, signature;

		CHECK(fzn_clock_notice_read(node, nullptr, &text, &signature)
		              && text.contains(QStringLiteral("This device's clock and laptop's are more than 10 minutes apart"))
		              && !signature.isEmpty(),
		      "the notice read from the node did not name the sibling, or had no signature");
	}
	CHECK(0, "deliberate");
	failures--;
	if (failures) {
		fprintf(stderr, "gui clock_notice_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui clock_notice_test: all %d checks passed\n", checks);
	return 0;
}
