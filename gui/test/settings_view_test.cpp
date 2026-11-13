/*
 * settings_view_test -- the node's settings on a widget, sec 1103, against a
 * scripted node behind the ask callback: the schema listed, a flag offering
 * the default beside on and off, where a value stands, the schema's notes, a
 * value set, the default chosen again as a clear, a sensitive value never
 * shown, and a refusal in the node's words.
 */

#include "../settings_view.h"

#include <QApplication>

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                       \
	do {                                                                                    \
		checks++;                                                                       \
		if (!(cond)) {                                                                  \
			failures++;                                                             \
			fprintf(stderr, "  FAIL settings_view_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                               \
	} while (0)

#define GPS "net/gps,flag,host,0,1,off,-,-,sample%20gpsd"
#define RING "call/ring,duration,estate,5,600,45s,s,restart+advertised,how%20long%20a%20call%20rings"
#define TOKEN "net/token,text,host,0,64,-,-,sensitive,a%20token"
#define DEEP "net/deep,count,host,0,9,3,-,advanced,a%20knob"
#define B_HOST "bb00000000000000000000000000000000000000000000000000000000000002"
#define C_HOST "cc00000000000000000000000000000000000000000000000000000000000003"

/* THE NODE: each setting's value, or none, and what it says to a write. */
static char gps[32], ring[32], token[32];
static const char *write_reply = "ok";
static char last[128];

static char *cell(const char *key)
{
	return !strcmp(key, "net/gps") ? gps : !strcmp(key, "call/ring") ? ring : token;
}

static size_t node(void *ctx, const char *line, char *reply, size_t cap)
{
	char key[32];

	(void)ctx;
	if (!strcmp(line, "list schema 0"))
		return (size_t)snprintf(reply, cap, "ok 4 0 %s %s %s %s\n", GPS, RING, TOKEN, DEEP);
	if (!strcmp(line, "list setting-holders call/ring 0"))
		return (size_t)snprintf(reply, cap, "ok 4 0 2 0 %s,4,1700 %s,2,1600\n", B_HOST, C_HOST);
	if (sscanf(line, "get schema %31s", key) == 1)
		return (size_t)snprintf(reply, cap, "ok %s\n",
		                        !strcmp(key, "net/gps") ? GPS : !strcmp(key, "call/ring") ? RING : TOKEN);
	if (sscanf(line, "get setting here %31s", key) == 1 || sscanf(line, "get setting estate %31s", key) == 1) {
		const char *v = cell(key);
		if (!*v)
			return (size_t)snprintf(reply, cap, "ok absent\n");
		return !strncmp(line, "get setting here", 16)
		               ? (size_t)snprintf(reply, cap, "ok host 2 %s\n", v)
		               : (size_t)snprintf(reply, cap, "ok 2 %s\n", v);
	}
	snprintf(last, sizeof last, "%s", line);
	char scope[16], value[32] = "";
	if (sscanf(line, "set setting %15s %31s %31s", scope, key, value) == 3 && !strcmp(write_reply, "ok"))
		snprintf(cell(key), 32, "%s", value);
	if (sscanf(line, "remove setting %15s %31s", scope, key) == 2 && !strcmp(write_reply, "ok"))
		cell(key)[0] = '\0';
	return (size_t)snprintf(reply, cap, "%s\n", write_reply);
}

static bool not_gps(void *ctx, const char *key)
{
	(void)ctx;
	return strcmp(key, "net.gps") != 0;
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);
	fzn_settings_view v(node, nullptr);

	CHECK(v.refresh() && v.keys() == QStringList({ "net.gps", "net.token", "call.ring" }),
	      "the settings were not listed");

	/* A FLAG: the default first, saying what it is, then on and off. */
	CHECK(v.select(0) && v.offered() == QStringList({ "Default (off)", "on", "off" })
	              && v.chosen() == "Default (off)" && v.where() == "Following the default.",
	      "an unset flag did not offer the default first and follow it");
	v.choose("on");
	CHECK(v.apply() && !strcmp(last, "set setting host net/gps on") && v.chosen() == "on"
	              && v.where() == "Set on this host.",
	      "a flag set on was not written for the host, or did not read back");

	/* THE DEFAULT CHOSEN AGAIN IS A CLEAR, not `off` written down. */
	v.choose("Default (off)");
	CHECK(v.apply() && !strcmp(last, "remove setting host net/gps")
	              && v.where() == "Following the default.",
	      "choosing the default wrote a value instead of clearing it");

	/* A DURATION: typed, the node's to judge, its notes said. */
	CHECK(v.select(2) && v.notes().contains("5 s to 600 s") && v.notes().contains("restart")
	              && v.notes().contains("Peers can see"),
	      "a duration's bounds, restart or advertised note was not shown");
	v.choose("2m");
	CHECK(v.apply() && !strcmp(last, "set setting estate call/ring 2m")
	              && v.where().startsWith("Set above this host"),
	      "an estate's duration was not written for the estate");

	/* A SENSITIVE VALUE: set, never shown. */
	snprintf(token, sizeof token, "s3cret");
	CHECK(v.select(1) && v.chosen().isEmpty() && v.notes().contains("it is not shown"),
	      "a sensitive value was shown, or not said to be set");

	/* WHERE A SHARED SETTING HAS REACHED; a host's own is said to be so. */
	v.select(2);
	CHECK(v.reach() && v.reached().contains("version 4") && v.reached().contains("bb00000000000000 has it")
	              && v.reached().contains("cc00000000000000 is behind, at 2"),
	      "where a shared setting has reached was not said host by host");
	v.select(0);
	CHECK(v.reach() && v.reached().contains("this host's own"),
	      "a host's own setting was not said to stay on the host");

	/* ADVANCED SETTINGS WAIT UNTIL ASKED FOR. */
	CHECK(!v.keys().contains("net.deep"), "an advanced setting was listed before it was asked for");
	v.show_advanced(true);
	CHECK(v.keys().contains("net.deep") && v.keys().size() == 4, "show advanced did not list it");
	v.show_advanced(false);
	CHECK(!v.keys().contains("net.deep"), "hiding advanced settings again did not");

	/* GROUPED BY THE FIRST PART, each group where its first key falls. */
	CHECK(v.groups() == QStringList({ "net", "call" }), "the settings were not grouped by first part");

	/* THE HOST'S FILTER: a key it handles itself is not offered. */
	v.set_filter(not_gps, nullptr);
	CHECK(!v.keys().contains("net.gps") && v.keys().contains("net.token"),
	      "a key the host filters out was still offered");
	v.set_filter(nullptr, nullptr);
	CHECK(v.keys().contains("net.gps"), "taking the filter away did not list the key again");

	/* A REFUSAL IN THE NODE'S WORDS. */
	write_reply = "malformed not a duration: forever";
	v.select(2);
	v.choose("forever");
	CHECK(!v.apply() && v.status() == "not a duration: forever",
	      "a refusal was not said in the node's words");

	CHECK(0, "deliberate");
	failures--;
	if (failures) {
		fprintf(stderr, "gui settings_view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui settings_view_test: all %d checks passed\n", checks);
	return 0;
}
