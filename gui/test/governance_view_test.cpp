/*
 * governance_view_test -- the estate's governance on a widget, against a
 * node of the test's own that answers each verb in the node's own shape, as
 * `node/admin.c` and `node/daemon.c` answer them. The verbs themselves are
 * `admin_test`'s and the live scripts'; this holds the widget to reading
 * them, acting on the full key a row stands for, asking before a vote, and
 * saying a refusal and a silence in different words. sec 1023.
 */

#include "../governance_view.h"

#include <QApplication>
#include <QListWidget>

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                       \
	do {                                                                                    \
		checks++;                                                                       \
		if (!(cond)) {                                                                  \
			failures++;                                                             \
			fprintf(stderr, "  FAIL governance_view_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                               \
	} while (0)

static const char ROOT_A[] = "aa00000000000000000000000000000000000000000000000000000000000001";
static const char ROOT_B[] = "bb00000000000000000000000000000000000000000000000000000000000002";
static const char DEV_X[] = "cc00000000000000000000000000000000000000000000000000000000000003";
static const char DEV_Y[] = "dd00000000000000000000000000000000000000000000000000000000000004";
static const char NEW_X[] = "ee00000000000000000000000000000000000000000000000000000000000005";

/* THE TEST'S NODE: what it holds, what it was asked, and whether it answers. */
static struct {
	int silent;
	int k;
	int b_is_root;
	int x_votes;
	int staged_left;
	QStringList asked;
} node;

static size_t say(char *reply, size_t cap, const QString &line)
{
	QByteArray b = (line + QLatin1Char('\n')).toUtf8();

	if ((size_t)b.size() >= cap)
		return 0;
	memcpy(reply, b.constData(), (size_t)b.size());
	return (size_t)b.size();
}

static size_t node_ask(void *ctx, const char *line_c, char *reply, size_t cap)
{
	QString line = QString::fromUtf8(line_c);

	(void)ctx;
	node.asked << line;
	if (node.silent)
		return 0;
	if (line == QLatin1String("list root"))
		return say(reply, cap,
		           QStringLiteral("ok %1 %2 %3,acting%4")
		                   .arg(node.k)
		                   .arg(node.b_is_root ? 2 : 1)
		                   .arg(QLatin1String(ROOT_A))
		                   .arg(node.b_is_root ? QStringLiteral(" ") + QLatin1String(ROOT_B)
		                                       : QString()));
	if (line == QLatin1String("list vote")) {
		QString out = QStringLiteral("ok %1 %2").arg(node.k).arg(node.x_votes + 2);
		int i;

		for (i = 0; i < node.x_votes; i++)
			out += QStringLiteral(" %1,%2,standing")
			               .arg(QLatin1String(DEV_X), QLatin1String(i ? ROOT_B : ROOT_A));
		out += QStringLiteral(" %1,%2,withdrawn").arg(QLatin1String(DEV_X), QLatin1String(DEV_Y));
		out += QStringLiteral(" %1,%2,standing").arg(QLatin1String(DEV_Y), QLatin1String(ROOT_B));
		return say(reply, cap, out);
	}
	/* THREE RE-KEYS, TWO TO A PAGE, as `list succession FROM` pages. */
	if (line.startsWith(QLatin1String("list succession "))) {
		int from = line.mid(16).toInt();
		QString out = QStringLiteral("ok 3 %1").arg(from);
		int i;

		for (i = from; i < 3 && i < from + 2; i++)
			out += QStringLiteral(" %1>%2,%3")
			               .arg(QLatin1String(i == 0 ? DEV_X : DEV_Y), QLatin1String(NEW_X),
			                    QLatin1String(i == 2 ? "counting" : "waiting"));
		return say(reply, cap, out);
	}
	if (line == QLatin1String("list staged"))
		return say(reply, cap,
		           node.staged_left
		                   ? QStringLiteral("ok 1 0123456789abcdef0123456789abcdef,1767000000,"
		                                    "relay/enabled")
		                   : QStringLiteral("ok 0"));
	/* THE VOTES ON A SETTING, two pages: A's older vote for `off` superseded by
	 * its newer for `on`, and B's for `on`. */
	if (line == QLatin1String("list record under vote/ 0"))
		return say(reply, cap,
		           QStringLiteral("ok 0 2 1 %1,vote/aa00000000000000/relay/enabled,2,off"
		                          " %2,vote/aa00000000000000/relay/enabled,4,on")
		                   .arg(QLatin1String(ROOT_A), QLatin1String(ROOT_B)));
	if (line == QLatin1String("list record under vote/ 2"))
		return say(reply, cap,
		           QStringLiteral("ok 2 1 0 %1,vote/aa00000000000000/relay/enabled,5,on")
		                   .arg(QLatin1String(ROOT_A)));
	if (line.startsWith(QLatin1String("add vote setting ")))
		return say(reply, cap, QStringLiteral("ok"));
	if (line == QLatin1String("get preset"))
		return say(reply, cap, QStringLiteral("ok userd"));
	if (line == QLatin1String("list preset choices"))
		return say(reply, cap, QStringLiteral("ok 2 userd vault"));
	if (line.startsWith(QLatin1String("set quorum ")))
		return say(reply, cap, QStringLiteral("error the estate's k is a root's to set"));
	if (line == QStringLiteral("add root ") + QLatin1String(ROOT_B)) {
		node.b_is_root = 1;
		return say(reply, cap, QStringLiteral("ok"));
	}
	if (line == QStringLiteral("remove root ") + QLatin1String(ROOT_B)) {
		node.b_is_root = 0;
		return say(reply, cap, QStringLiteral("ok"));
	}
	if (line == QStringLiteral("revoke peer ") + QLatin1String(DEV_X)) {
		node.x_votes++;
		return say(reply, cap, QStringLiteral("ok %1 keeping nothing").arg(QLatin1String(DEV_X)));
	}
	if (line == QStringLiteral("add confirm 0123456789abcdef0123456789abcdef")) {
		node.staged_left = 0;
		return say(reply, cap, QStringLiteral("ok"));
	}
	if (line.startsWith(QLatin1String("add succession ")) || line.startsWith(QLatin1String("set preset ")))
		return say(reply, cap, QStringLiteral("ok"));
	return say(reply, cap, QStringLiteral("malformed what was that"));
}

static int asked_count(const QString &line)
{
	return node.asked.count(line);
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);

	node.k = 2;
	node.x_votes = 1;
	node.staged_left = 1;

	fzn_governance_view view(node_ask, nullptr);

	/* ---- A FOLDING PHONE'S COVER SCREEN, sec 1041: 320 px. The roots' row of
	 * four made the view 370 here, and 380 in fuzzypickles' Estate page; 210 since. */
	CHECK(view.minimumSizeHint().width() <= 320,
	      "the view is wider than a 320 px cover screen");

	/* ---- EVERY PART READ. */
	CHECK(view.k() == 2, "k was not read from list root");
	CHECK(view.rows(view.roots_list()).size() == 1
	              && view.rows(view.roots_list())[0].contains(QLatin1String("this host acts as it")),
	      "the one root was not listed as the one this host acts as");
	CHECK(view.rows(view.votes_list()).size() == 2,
	      "the votes were not one row per key voted against");
	CHECK(view.rows(view.votes_list())[0].contains(QLatin1String("1 of 2, 1 withdrawn")),
	      "a key's row did not count its standing votes against k, the withdrawn apart");
	CHECK(view.rows(view.successions_list()).size() == 3 && asked_count(QStringLiteral(
	                                                                 "list succession 2")) == 1,
	      "the successions were not read across both pages");
	CHECK(view.rows(view.staged_list()).size() == 1
	              && view.rows(view.staged_list())[0].contains(QLatin1String("relay/enabled")),
	      "the staged change was not listed by its key");
	CHECK(view.preset() == QLatin1String("userd")
	              && view.preset_choices() == QStringList({ QStringLiteral("userd"),
	                                                        QStringLiteral("vault") }),
	      "the profile in force and the choices were not shown");

	/* ---- A SETTING'S VOTES, each voter's newest, across both pages: one value,
	 * two voters, and joined with what the listing showed. sec 1029. */
	CHECK(view.rows(view.setting_votes_list()).size() == 1
	              && view.rows(view.setting_votes_list())[0].contains(
	                         QLatin1String("relay/enabled = on"))
	              && view.rows(view.setting_votes_list())[0].contains(QLatin1String("2 of 2")),
	      "a setting's votes were not the voters' newest, counted against k");
	view.select(view.setting_votes_list(), 0);
	CHECK(view.vote_setting()
	              && asked_count(QStringLiteral("add vote setting aa00000000000000 relay/enabled on"))
	                         == 1,
	      "joining a setting's vote did not name its host, key and value");

	/* ---- WHAT WAITS IS COUNTED IN THE TAB'S TITLE. */
	CHECK(view.tab_titles().size() == 5 && view.tab_titles()[1] == QLatin1String("Votes (3)")
	              && view.tab_titles()[3] == QLatin1String("Staged (1)"),
	      "a tab's title did not carry what waits in it");

	/* ---- A ROOT ADDED BY KEY, AND REMOVED BY ITS ROW: the full key. */
	view.set_key(QLatin1String(ROOT_B));
	CHECK(view.add_root() && view.rows(view.roots_list()).size() == 2,
	      "a root added was not listed after");
	view.select(view.roots_list(), 1);
	CHECK(view.remove_root() && asked_count(QStringLiteral("remove root ") + QLatin1String(ROOT_B)) == 1,
	      "removing a selected root did not name its full key");

	/* ---- A REFUSAL IN THE NODE'S WORDS. */
	CHECK(!view.set_k(3) && view.roots_status().contains(QLatin1String("a root's to set")),
	      "a refused k was not said in the node's words");

	/* ---- A VOTE IS ASKED FIRST, and only the second step sends it. */
	view.select(view.votes_list(), 0);
	view.ask_vote();
	CHECK(view.vote_asked() && asked_count(QStringLiteral("revoke peer ") + QLatin1String(DEV_X)) == 0,
	      "asking about a vote sent it, or showed no question");
	view.cancel_vote();
	CHECK(!view.vote_asked() && !view.vote(), "a cancelled vote was sent");
	view.select(view.votes_list(), 0);
	view.ask_vote();
	CHECK(view.vote() && asked_count(QStringLiteral("revoke peer ") + QLatin1String(DEV_X)) == 1
	              && view.rows(view.votes_list())[0].contains(QLatin1String("2 of 2")),
	      "the vote was not sent against the row's full key, or not counted after");

	/* ---- A RE-KEY AND A STAGED CHANGE CONFIRMED BY THEIR ROWS. */
	view.select(view.successions_list(), 0);
	CHECK(view.confirm_succession()
	              && asked_count(QStringLiteral("add succession ") + QLatin1String(DEV_X)) == 1,
	      "confirming a re-key did not name the old key in full");
	view.select(view.staged_list(), 0);
	CHECK(view.confirm_staged() && view.rows(view.staged_list()).isEmpty(),
	      "confirming a staged change did not send its token, or it stayed listed");

	/* ---- A PROFILE CHOSEN. */
	CHECK(view.choose_preset(QStringLiteral("vault"))
	              && asked_count(QStringLiteral("set preset vault")) == 1,
	      "choosing a profile did not ask the node");

	/* ---- A NODE THAT DOES NOT ANSWER SAYS SO, in each part. */
	node.silent = 1;
	CHECK(!view.refresh(), "a silent node was read as answering");
	CHECK(view.roots_status().contains(QLatin1String("did not answer"))
	              && view.votes_status().contains(QLatin1String("did not answer"))
	              && view.successions_status().contains(QLatin1String("did not answer"))
	              && view.staged_status().contains(QLatin1String("did not answer"))
	              && view.preset_status().contains(QLatin1String("did not answer"))
	              && view.rows(view.roots_list()).isEmpty(),
	      "a silent node was not said to be silent in every part");

	printf("governance_view_test: %d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
