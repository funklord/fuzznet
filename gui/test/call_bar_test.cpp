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
#include "../call_video.h"
#include "../rpc_ask.h"

#include <QApplication>
#include <QColor>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QImage>
#include <QList>
#include <QPushButton>

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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
static int listed; /* `list call` asked */
static char ended_in[32] = "", ended_out[32] = "";

static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	(void)ctx;
	if (!strcmp(line, "list call") && ++listed)
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
	/* RUNG FROM THIS WINDOW (sec 1491): carol, whom the node names no user
	 * for; dave, refused. */
	if (!strcmp(line, "add call carol both")) {
		snprintf(live, sizeof live, "1 " OUT ",ringing-out,3");
		return (size_t)snprintf(reply, cap, "ok " OUT "\n");
	}
	if (!strcmp(line, "add call dave audio"))
		return (size_t)snprintf(reply, cap, "error no such contact\n");
	return (size_t)snprintf(reply, cap, "error no such thing\n");
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);
	/* A NODE THAT CANNOT LIST CALLS (sec 1513): nothing offered. */
	{
		fzn_call_bar dumb([](void *, const char *, char *reply, size_t cap) -> size_t {
			return (size_t)snprintf(reply, cap, "error no such thing\n");
		}, nullptr);
		CHECK(dumb.buttons().isEmpty(), "a bar over a node that lists no calls offered its buttons");
	}
	fzn_call_bar bar(node, nullptr);

	bar.audio()->set_test_io([](int16_t *, size_t) { return (size_t)0; }, [](const int16_t *, size_t) {});
	bar.set_now(NOW);
	CHECK(bar.refresh() && bar.isHidden() && bar.said().isEmpty(), "the bar showed with no call");

	/* RINGING HERE: who, and Answer and Decline. */
	snprintf(live, sizeof live, "1 " IN ",ringing-in,3," BOB);
	CHECK(bar.refresh() && !bar.isHidden() && bar.said() == "bob is calling you (audio and video)"
	              && bar.buttons() == QStringList({ "Decline", "Answer" }),
	      "a call ringing here was not said with Answer and Decline");
	CHECK(bar.who() == "bob" && bar.is_video(), "the call ringing was not said to be with bob, on video");

	/* ANSWERED: how long, Mute and Hang up, and its sound carried. */
	CHECK(bar.answer() && bar.said() == "In a call with bob (audio), 0:00." && bar.buttons() == QStringList({ "Mute", "Hang up" })
	              && bar.audio()->running() && bar.audio()->id() == IN,
	      "an answered call was not shown up with Mute and Hang up, its sound carried");
	/* EACH SECOND, NOTHING ASKED (sec 1262): the bar ticks itself. */
	{
		const int asked = listed;

		bar.set_now(NOW + 7u);
		bar.tick();
		CHECK(bar.said() == "In a call with bob (audio), 0:07." && listed == asked,
		      "a call up did not say its time each second without asking the node");
	}
	bar.set_now(NOW + 42u);
	CHECK(bar.refresh() && bar.said() == "In a call with bob (audio), 0:42.", "a call up did not say how long it has run");
	bar.set_muted(true);
	CHECK(bar.audio()->muted() && bar.buttons() == QStringList({ "Unmute", "Hang up" }),
	      "Mute did not mute the call's sound, or its button did not offer Unmute");
	/* NAMED, for a host or a test (sec 1491). */
	CHECK(bar.objectName() == "call_bar" && bar.findChild<QPushButton *>("call_bar_mute")
	              && bar.findChild<QPushButton *>("call_bar_hangup") && bar.findChild<QPushButton *>("call_bar_answer")
	              && bar.findChild<QPushButton *>("call_bar_decline") && bar.findChild<QPushButton *>("call_bar_camera"),
	      "the bar's widgets were not named for a host to find");
	/* WHY IT ENDED, TO THE HOST'S LOG (sec 1491). */
	QStringList logged;
	bar.on_log([&logged](const QString &line) { logged << line; });

	/* HUNG UP: said with how long it ran, then gone. */
	CHECK(bar.hang_up() && bar.said() == "Call with bob ended, 0:42." && !bar.isHidden() && !bar.audio()->running(),
	      "a call hung up was not said ended with how long it ran, or its sound went on");
	CHECK(logged == QStringList({ "The call with bob ended: ended (0:42)." }),
	      "the call's ending and its reason were not told the host's log");
	bar.set_now(NOW + 42u + FZN_CALL_BAR_ENDED_S);
	CHECK(bar.refresh() && bar.isHidden(), "the ending was still said past its few seconds");

	/* MISSED, AND DECLINED, as a person says them -- a missed one told the
	 * host once, for its notice (sec 1262). */
	QStringList missed;
	bar.on_missed([&missed](const QString &who, bool video) { missed << who + (video ? " video" : " sound"); });
	snprintf(live, sizeof live, "1 " IN ",ringing-in,1," BOB);
	ended_in[0] = '\0';
	bar.refresh();
	snprintf(live, sizeof live, "0");
	snprintf(ended_in, sizeof ended_in, "no-answer");
	CHECK(bar.refresh() && bar.said() == "Missed call from bob." && logged.last() == "Missed call from bob: not answered.",
	      "a call missed was not said as missed, or its reason not logged");
	CHECK(bar.refresh() && missed == QStringList({ "bob sound" }), "a missed call was not told the host once, with who");
	snprintf(live, sizeof live, "1 " OUT ",ringing-out,1," BOB);
	CHECK(bar.refresh() && bar.said() == "Calling bob (audio)..." && bar.buttons() == QStringList({ "Hang up" }),
	      "a call ringing out was not said with Hang up");
	snprintf(live, sizeof live, "0");
	snprintf(ended_out, sizeof ended_out, "declined");
	CHECK(bar.refresh() && bar.said() == "bob declined.", "a call declined was not said as declined");
	/* RUNG FROM HERE (sec 1491): the node names no user, and the bar says
	 * whom this window rang, with what; one refused, said to the log. */
	ended_out[0] = '\0';
	CHECK(bar.ring("carol", FZN_RPC_AUDIO | FZN_RPC_VIDEO) && bar.said() == "Calling carol (audio and video)..."
	              && logged.last() == "Calling carol",
	      "a call rung here did not name whom it rang");
	CHECK(!bar.ring("dave", FZN_RPC_AUDIO) && logged.last().startsWith("dave was not called: "),
	      "a ring refused was not told the log");

	/* OF TWO, THE ONE RINGING HERE. */
	snprintf(live, sizeof live, "2 " OUT ",up,1," BOB " " IN ",ringing-in,1," BOB);
	CHECK(bar.refresh() && bar.shown_id() == IN && bar.buttons() == QStringList({ "Decline", "Answer" }),
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
		/* DECLINE RED ON THE LEFT, ANSWER GREEN ON THE RIGHT (sec 1491). */
		{
			QPushButton *decline = bar.findChild<QPushButton *>("call_bar_decline");
			bar.resize(360, 640);
			bar.show();
			app.processEvents();
			CHECK(answer && decline && decline->geometry().right() < answer->geometry().left()
			              && decline->styleSheet().contains("#d93025") && answer->styleSheet().contains("#1e8e3e"),
			      "the ringing screen did not put Decline red on the left and Answer green on the right");
		}
		CHECK(bar.refresh() && told.size() == 1, "the host was told again while the same call rang");
		CHECK(bar.answer() && !bar.screen() && answer->minimumHeight() == 0 && told == QList<bool>({ true, false }),
		      "answered, the bar stayed a screen, or the host was not told it stopped ringing");
	}

	/* THE OTHER END'S PICTURE IN THE BAR, sec 1262: a video call up, its
	 * channel over a socketpair standing in for the node; a picture come,
	 * shown; the call gone, gone. */
	{
		static const uint8_t ok_status[] = { 0, 3, 19, 0, 0 };
		static uint8_t wire[2 + 8192 + 64];
		fzn_call_bar seen_bar(node, nullptr, QStringLiteral("/nonexistent"));
		QImage red(320, 240, QImage::Format_RGB32);
		int sv[2];
		size_t n = 0, got = 0, len;

		red.fill(QColor(220, 20, 20));
		seen_bar.audio()->set_test_io([](int16_t *, size_t) { return (size_t)0; }, [](const int16_t *, size_t) {});
		seen_bar.set_now(NOW);
		CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0
		              && write(sv[1], ok_status, sizeof(ok_status)) == (ssize_t)sizeof(ok_status)
		              && seen_bar.video()->attach(sv[0], IN),
		      "fixture: the picture's channel attached");
		/* THE CHANNEL'S ASKING, read and set aside. */
		if (read(sv[1], wire, 2) == 2 && (len = (size_t)wire[0] << 8 | wire[1]) + 2u <= sizeof(wire))
			while (got < len && read(sv[1], wire + 2, len) > 0)
				got = len;
		/* A CALL RUNG AS SOUND still shows a picture that comes (sec 1491). */
		snprintf(live, sizeof live, "1 " IN ",up,1," BOB);
		ended_in[0] = '\0';
		seen_bar.refresh();
		CHECK(!seen_bar.picture_shown(), "a picture was shown before one came");
		/* ONE SENT, ECHOED BACK AS THE OTHER END'S. */
		if (seen_bar.video()->send_picture(red) && read(sv[1], wire, 2) == 2) {
			len = (size_t)wire[0] << 8 | wire[1];
			got = 0;
			while (got < len) {
				const ssize_t r = read(sv[1], wire + 2 + got, len - got);
				if (r <= 0)
					break;
				got += (size_t)r;
			}
			n = got == len && write(sv[1], wire, len + 2u) == (ssize_t)(len + 2u) ? len : 0u;
		}
		seen_bar.video()->poll();
		CHECK(n && seen_bar.picture_shown(), "the other end's picture was not shown in the bar, on a call rung as sound");
		/* STOPPED ARRIVING, BLANKED after 1.5 s, not left standing. */
		{
			QElapsedTimer waited;
			waited.start();
			while (waited.elapsed() < FZN_CALL_BAR_STILL_MS + 200)
				app.processEvents(QEventLoop::AllEvents, 50);
			seen_bar.tick();
			CHECK(!seen_bar.picture_shown(), "a picture that stopped arriving was left standing");
		}
		/* THE NODE CLOSED THE CHANNEL: not opened again for this call. */
		close(sv[1]);
		seen_bar.video()->poll();
		seen_bar.refresh();
		CHECK(seen_bar.video()->closed_id() == IN && !seen_bar.video()->running()
		              && seen_bar.video()->trouble() == "The call's picture stopped.",
		      "a channel the node closed was opened again for the same call");
		snprintf(live, sizeof live, "0");
		snprintf(ended_in, sizeof ended_in, "hung-up");
		seen_bar.refresh();
		CHECK(!seen_bar.picture_shown(), "the picture stayed once the call was gone");
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
