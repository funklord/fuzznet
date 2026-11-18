/*
 * call_bar_test -- one line for the call that matters, fuzznet sec 1238,
 * against a scripted node: hidden with no call; a call ringing here said
 * with Answer and Decline; answered, how long it has run, Mute and Hang
 * up, and its sound carried; muted; hung up, its ending said with how long
 * it ran, then gone; a call missed and one declined said as a person
 * would; and of two calls, the one ringing here shown.
 */
#include "../call_bar.h"
#include "../call_audio.h"

#include <QApplication>
#include <QList>
#include <QPushButton>

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                   \
	do {                                                                                \
		checks++;                                                                   \
		if (!(cond)) {                                                              \
			failures++;                                                         \
			fprintf(stderr, "  FAIL call_bar_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                           \
	} while (0)

#define BOB "b0b0000000000000000000000000000000000000000000000000000000000001"
#define IN "1111222233334444"
#define OUT "aaaabbbbccccdddd"
#define NOW 1700000000u

static char live[512] = "0";
static char ended_in[32] = "", ended_out[32] = "";

static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	(void)ctx;
	if (!strcmp(line, "list call"))
		return (size_t)snprintf(reply, cap, "ok %s\n", live);
	if (!strcmp(line, "list contact 0"))
		return (size_t)snprintf(reply, cap, "ok 1 0 bob," BOB "\n");
	if (!strcmp(line, "get call " IN))
		return (size_t)snprintf(reply, cap, ended_in[0] ? "ok ended %s\n" : "ok live\n", ended_in);
	if (!strcmp(line, "get call " OUT))
		return (size_t)snprintf(reply, cap, ended_out[0] ? "ok ended %s\n" : "ok live\n", ended_out);
	if (!strcmp(line, "set call " IN " answer")) {
		snprintf(live, sizeof live, "1 " IN ",up,1," BOB);
		return (size_t)snprintf(reply, cap, "ok\n");
	}
	if (!strcmp(line, "set call " IN " hangup")) {
		snprintf(live, sizeof live, "0");
		snprintf(ended_in, sizeof ended_in, "ended");
		return (size_t)snprintf(reply, cap, "ok\n");
	}
	/* THE CALL'S SOUND, while it is up: frames taken, none to give. */
	if (!strncmp(line, "add frame ", 10))
		return (size_t)snprintf(reply, cap, "ok sent\n");
	if (!strncmp(line, "list frame ", 11))
		return (size_t)snprintf(reply, cap, "ok 0 0\n");
	return (size_t)snprintf(reply, cap, "error no such thing\n");
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);
	fzn_call_bar bar(node, nullptr);

	bar.audio()->set_test_io([](int16_t *, size_t) { return (size_t)0; }, [](const int16_t *, size_t) {});
	bar.set_now(NOW);
	CHECK(bar.refresh() && bar.isHidden() && bar.said().isEmpty(), "the bar showed with no call");

	/* RINGING HERE: who, and Answer and Decline. */
	snprintf(live, sizeof live, "1 " IN ",ringing-in,3," BOB);
	CHECK(bar.refresh() && !bar.isHidden() && bar.said() == "bob is calling you (video call)"
	              && bar.buttons() == QStringList({ "Answer", "Decline" }),
	      "a call ringing here was not said with Answer and Decline");

	/* ANSWERED: how long, Mute and Hang up, and its sound carried. */
	CHECK(bar.answer() && bar.said() == "In a call with bob, 0:00" && bar.buttons() == QStringList({ "Mute", "Hang up" })
	              && bar.audio()->running() && bar.audio()->id() == IN,
	      "an answered call was not shown up with Mute and Hang up, its sound carried");
	bar.set_now(NOW + 42u);
	CHECK(bar.refresh() && bar.said() == "In a call with bob, 0:42", "a call up did not say how long it has run");
	bar.set_muted(true);
	CHECK(bar.audio()->muted(), "Mute did not mute the call's sound");

	/* HUNG UP: said with how long it ran, then gone. */
	CHECK(bar.hang_up() && bar.said() == "Call with bob ended, 0:42." && !bar.isHidden() && !bar.audio()->running(),
	      "a call hung up was not said ended with how long it ran, or its sound went on");
	bar.set_now(NOW + 42u + FZN_CALL_BAR_ENDED_S);
	CHECK(bar.refresh() && bar.isHidden(), "the ending was still said past its few seconds");

	/* MISSED, AND DECLINED, as a person says them. */
	snprintf(live, sizeof live, "1 " IN ",ringing-in,1," BOB);
	ended_in[0] = '\0';
	bar.refresh();
	snprintf(live, sizeof live, "0");
	snprintf(ended_in, sizeof ended_in, "no-answer");
	CHECK(bar.refresh() && bar.said() == "Missed call from bob.", "a call missed was not said as missed");
	snprintf(live, sizeof live, "1 " OUT ",ringing-out,1," BOB);
	CHECK(bar.refresh() && bar.said() == "Calling bob..." && bar.buttons() == QStringList({ "Hang up" }),
	      "a call ringing out was not said with Hang up");
	snprintf(live, sizeof live, "0");
	snprintf(ended_out, sizeof ended_out, "declined");
	CHECK(bar.refresh() && bar.said() == "bob declined.", "a call declined was not said as declined");

	/* OF TWO, THE ONE RINGING HERE. */
	snprintf(live, sizeof live, "2 " OUT ",up,1," BOB " " IN ",ringing-in,1," BOB);
	CHECK(bar.refresh() && bar.shown_id() == IN && bar.buttons() == QStringList({ "Answer", "Decline" }),
	      "of a call up and one ringing here, the one ringing here was not shown");

	/* A CALL RINGING HERE AS A SCREEN, sec 1247: allowed, the bar grows
	 * while it rings -- Answer tall -- and the host is told once as it
	 * starts; answered, a bar again, the host told it stopped. */
	{
		QList<bool> told;
		bar.on_ringing([&told](bool ringing) { told << ringing; });
		bar.set_screen(true);
		snprintf(live, sizeof live, "0");
		bar.refresh();
		told.clear();
		snprintf(live, sizeof live, "1 " IN ",ringing-in,1," BOB);
		ended_in[0] = '\0';
		QPushButton *answer = nullptr;
		for (QPushButton *b : bar.findChildren<QPushButton *>())
			if (b->text() == "Answer")
				answer = b;
		CHECK(bar.refresh() && bar.screen() && answer && answer->minimumHeight() >= 40 && told == QList<bool>({ true }),
		      "a call ringing here was not a screen with Answer large, or the host not told");
		CHECK(bar.refresh() && told.size() == 1, "the host was told again while the same call rang");
		CHECK(bar.answer() && !bar.screen() && answer->minimumHeight() == 0 && told == QList<bool>({ true, false }),
		      "answered, the bar stayed a screen, or the host was not told it stopped ringing");
	}

	CHECK(0, "deliberate");
	failures--;
	if (failures) {
		fprintf(stderr, "gui call_bar_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui call_bar_test: all %d checks passed\n", checks);
	return 0;
}
