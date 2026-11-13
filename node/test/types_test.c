/* node/types.h, sec 674: the registry of remote request heads, checked
 * against every owner's own constant -- the CMDs apart (sec 1085), no two
 * SUBCMDs of one CMD one, and none in the extension's CMD. */
#include "../types.h"
#include "../members.h"
#include "../messages.h"
#include "../contact_devices.h"
#include "../reconcile.h"
#include "../../notes/sync.h"
#include "../../spool/message.h"
#include "../../log/cause.h"
#include "../../log/gather.h"
#include "../../record/exchange.h"

#include <stdio.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL types_test.c:%d: %s\n", line, what);
	}
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

/* EVERY VERSION-2 TYPE, by its owner's name: what the registry's table
 * says is allocated. */
static const struct {
	const char *name;
	unsigned cmd, subcmd;
} shared[] = {
	{ "notes index query", FZN_CMD_NOTES, FZN_NOTES_SYNC_INDEX_QUERY },
	{ "notes index", FZN_CMD_NOTES, FZN_NOTES_SYNC_INDEX },
	{ "notes records query", FZN_CMD_NOTES, FZN_NOTES_SYNC_RECORDS_QUERY },
	{ "notes records", FZN_CMD_NOTES, FZN_NOTES_SYNC_RECORDS },
	{ "notes purge", FZN_CMD_NOTES, FZN_NOTES_SYNC_PURGE },
	{ "notes purge ack", FZN_CMD_NOTES, FZN_NOTES_SYNC_PURGE_ACK },
	{ "notes purges query", FZN_CMD_NOTES, FZN_NOTES_SYNC_PURGES_QUERY },
	{ "notes purges", FZN_CMD_NOTES, FZN_NOTES_SYNC_PURGES },
	{ "notes writers query", FZN_CMD_NOTES, FZN_NOTES_SYNC_WRITERS_QUERY },
	{ "notes writers", FZN_CMD_NOTES, FZN_NOTES_SYNC_WRITERS },
	{ "members query", FZN_CMD_MEMBERS, FZN_NODE_MEMBERS_QUERY },
	{ "members reply", FZN_CMD_MEMBERS, FZN_NODE_MEMBERS_REPLY },
	{ "notes text push", FZN_CMD_NOTES, FZN_NOTES_SYNC_TEXT_PUSH },
	{ "notes text pushed", FZN_CMD_NOTES, FZN_NOTES_SYNC_TEXT_PUSHED },
	{ "notes wraps query", FZN_CMD_NOTES, FZN_NOTES_SYNC_WRAPS_QUERY },
	{ "notes wraps", FZN_CMD_NOTES, FZN_NOTES_SYNC_WRAPS },
	{ "notes lacks query", FZN_CMD_NOTES, FZN_NOTES_SYNC_LACKS_QUERY },
	{ "notes lacks", FZN_CMD_NOTES, FZN_NOTES_SYNC_LACKS },
	{ "notes give", FZN_CMD_NOTES, FZN_NOTES_SYNC_GIVE },
	{ "notes given", FZN_CMD_NOTES, FZN_NOTES_SYNC_GIVEN },
	{ "messages give", FZN_CMD_MESSAGES, FZN_NODE_MESSAGES_GIVE },
	{ "messages given", FZN_CMD_MESSAGES, FZN_NODE_MESSAGES_GIVEN },
	{ "messages want", FZN_CMD_MESSAGES, FZN_NODE_MESSAGES_WANT },
	{ "messages keys", FZN_CMD_MESSAGES, FZN_NODE_MESSAGES_KEYS },
	{ "messages deliver", FZN_CMD_MESSAGES, FZN_NODE_MESSAGES_DELIVER },
	{ "messages delivered", FZN_CMD_MESSAGES, FZN_NODE_MESSAGES_DELIVERED },
	{ "contact devices offer", FZN_CMD_CONTACTS, FZN_CONTACT_DEVICES_OFFER },
	{ "contact devices taken", FZN_CMD_CONTACTS, FZN_CONTACT_DEVICES_TAKEN },
	{ "contact devices query", FZN_CMD_CONTACTS, FZN_CONTACT_DEVICES_QUERY },
	{ "contact devices list", FZN_CMD_CONTACTS, FZN_CONTACT_DEVICES_LIST },
	{ "contact devices revoked", FZN_CMD_CONTACTS, FZN_CONTACT_DEVICES_REVOKED },
	{ "contact devices records", FZN_CMD_CONTACTS, FZN_CONTACT_DEVICES_RECORDS },
	{ "contact devices estate", FZN_CMD_CONTACTS, FZN_CONTACT_DEVICES_ESTATE },
	{ "contact devices items", FZN_CMD_CONTACTS, FZN_CONTACT_DEVICES_ITEMS },
	{ "contact devices kept estate", FZN_CMD_CONTACTS, FZN_CONTACT_DEVICES_KEPT_ESTATE },
	{ "contact devices kept rows", FZN_CMD_CONTACTS, FZN_CONTACT_DEVICES_KEPT_ROWS },
	{ "contact devices acts", FZN_CMD_CONTACTS, FZN_CONTACT_DEVICES_ACTS },
	{ "contact devices act entries", FZN_CMD_CONTACTS, FZN_CONTACT_DEVICES_ACT_ENTRIES },
	/* LEFT OUT UNTIL sec 1064, and so unseen when each took a number taken. */
	{ "contact devices k setting", FZN_CMD_CONTACTS, FZN_CONTACT_DEVICES_K_SETTING },
	{ "contact devices k set", FZN_CMD_CONTACTS, FZN_CONTACT_DEVICES_K_SET },
	{ "messages holds", FZN_CMD_MESSAGES, FZN_NODE_MESSAGES_HOLDS },
	{ "messages holding", FZN_CMD_MESSAGES, FZN_NODE_MESSAGES_HOLDING },
	{ "relay", FZN_CMD_REACH, FZN_SUBCMD_REACH_RELAY },
	{ "introduce", FZN_CMD_REACH, FZN_SUBCMD_REACH_INTRODUCE },
	{ "notify", FZN_CMD_REACH, FZN_SUBCMD_REACH_NOTIFY },
	{ "group sync", FZN_CMD_GROUPS, FZN_SUBCMD_GROUPS_SYNC },
	{ "group acts", FZN_CMD_GROUPS, FZN_SUBCMD_GROUPS_ACTS },
	{ "group lines sync", FZN_CMD_GROUPS, FZN_SUBCMD_GROUPS_LINES_SYNC },
	{ "group lines", FZN_CMD_GROUPS, FZN_SUBCMD_GROUPS_LINES },
	{ "stream query", FZN_CMD_STREAMS, FZN_SUBCMD_STREAMS_QUERY },
	{ "stream records", FZN_CMD_STREAMS, FZN_SUBCMD_STREAMS_RECORDS },
	{ "file refs want", FZN_CMD_FILES, FZN_SUBCMD_FILES_REFS_WANT },
	{ "file refs", FZN_CMD_FILES, FZN_SUBCMD_FILES_REFS },
	/* NAMED SINCE SEC 1005: absent here, 49 and 51 were taken twice. */
	{ "time ask", FZN_CMD_TIME, FZN_SUBCMD_TIME_ASK },
	{ "time", FZN_CMD_TIME, FZN_SUBCMD_TIME_REPLY },
	{ "call", FZN_CMD_RRPC, FZN_SUBCMD_RRPC_ASK },
	{ "called", FZN_CMD_RRPC, FZN_SUBCMD_RRPC_RESULT },
	{ "session ask", FZN_CMD_SESSION, FZN_SUBCMD_SESSION_ASK },
	{ "session grant", FZN_CMD_SESSION, FZN_SUBCMD_SESSION_GRANT },
	{ "relay session", FZN_CMD_REACH, FZN_SUBCMD_REACH_RELAY_SESSION },
	{ "address", FZN_CMD_REACH, FZN_SUBCMD_REACH_ADDRESS },
	{ "address ask", FZN_CMD_REACH, FZN_SUBCMD_REACH_ADDRESS_ASK },
	{ "routing ask", FZN_CMD_REACH, FZN_SUBCMD_REACH_ROUTING_ASK },
	{ "routing", FZN_CMD_REACH, FZN_SUBCMD_REACH_ROUTING },
};

#define SHARED_N (sizeof(shared) / sizeof(shared[0]))

/* THE CMDS, sec 1085: each below a verb line's first byte, a printable letter;
 * no two one; none the retired 2 or 5 (sec 1087). */
static void test_the_cmds(void)
{
	static const unsigned cmds[] = { FZN_CMD_FILES,    FZN_CMD_CALL,     FZN_CMD_CAUSE,
		                         FZN_CMD_GATHER,   FZN_CMD_RECONCILE, FZN_CMD_EXCHANGE,
		                         FZN_CMD_NOTES,    FZN_CMD_MEMBERS,  FZN_CMD_MESSAGES,
		                         FZN_CMD_CONTACTS, FZN_CMD_REACH,    FZN_CMD_GROUPS,
		                         FZN_CMD_STREAMS,  FZN_CMD_TIME,     FZN_CMD_RRPC,
		                         FZN_CMD_SESSION,  FZN_CMD_STATUS,   FZN_CMD_EXTENSION };
	size_t i, j, n = sizeof(cmds) / sizeof(cmds[0]);
	int low = 1, apart = 1, retired = 0;

	for (i = 0; i < n; i++) {
		low &= cmds[i] < 0x20u;
		retired += cmds[i] == 5u || cmds[i] == 2u;
		for (j = i + 1u; j < n; j++)
			apart &= cmds[i] != cmds[j];
	}
	CHECK(low, "a CMD could open a verb line");
	CHECK(apart, "two CMDs are one number");
	CHECK(retired == 0, "a retired CMD, 2 or 5, was given again");
}

/* NO SUBCMD TWICE IN ONE CMD, and none in the extension's CMD, which is its own. */
static void test_no_two_subcmds_are_one(void)
{
	size_t i, j;
	int clash = 0, extension = 0, retired = 0;

	for (i = 0; i < SHARED_N; i++) {
		for (j = i + 1u; j < SHARED_N; j++)
			if (shared[i].cmd == shared[j].cmd && shared[i].subcmd == shared[j].subcmd) {
				printf("  %s and %s are both %u/%u\n", shared[i].name, shared[j].name,
				       shared[i].cmd, shared[i].subcmd);
				clash++;
			}
		extension += shared[i].cmd == FZN_CMD_EXTENSION;
		if (shared[i].cmd == FZN_CMD_NOTES && (shared[i].subcmd == 13u || shared[i].subcmd == 14u))
			retired++;
	}
	CHECK(SHARED_N == 64u, "the table is not the 64 SUBCMDs the registry lists");
	CHECK(clash == 0, "two SUBCMDs of one CMD are one number");
	CHECK(extension == 0, "fuzznet allocated a SUBCMD in the extension's CMD");
	CHECK(retired == 0, "a retired notes SUBCMD, 13 or 14, was reused");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	CHECK(0, "deliberate");
	CHECK(failures == before + 1, "a failing check did not count");
	failures = before;
	checks -= 1;
}

int main(void)
{
	test_the_cmds();
	test_no_two_subcmds_are_one();
	test_the_suite_can_tell_pass_from_fail();

	printf("types_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
