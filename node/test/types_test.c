/* node/types.h, sec 674: the registry of remote request heads, checked
 * against every owner's own constant -- each version byte its owner's, no
 * two version-2 types one, and none in the extensions' range. */
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
	unsigned type;
} shared[] = {
	{ "notes index query", FZN_NOTES_SYNC_INDEX_QUERY },
	{ "notes index", FZN_NOTES_SYNC_INDEX },
	{ "notes records query", FZN_NOTES_SYNC_RECORDS_QUERY },
	{ "notes records", FZN_NOTES_SYNC_RECORDS },
	{ "notes purge", FZN_NOTES_SYNC_PURGE },
	{ "notes purge ack", FZN_NOTES_SYNC_PURGE_ACK },
	{ "notes purges query", FZN_NOTES_SYNC_PURGES_QUERY },
	{ "notes purges", FZN_NOTES_SYNC_PURGES },
	{ "notes writers query", FZN_NOTES_SYNC_WRITERS_QUERY },
	{ "notes writers", FZN_NOTES_SYNC_WRITERS },
	{ "members query", FZN_NODE_MEMBERS_QUERY },
	{ "members reply", FZN_NODE_MEMBERS_REPLY },
	{ "notes text push", FZN_NOTES_SYNC_TEXT_PUSH },
	{ "notes text pushed", FZN_NOTES_SYNC_TEXT_PUSHED },
	{ "notes wraps query", FZN_NOTES_SYNC_WRAPS_QUERY },
	{ "notes wraps", FZN_NOTES_SYNC_WRAPS },
	{ "notes lacks query", FZN_NOTES_SYNC_LACKS_QUERY },
	{ "notes lacks", FZN_NOTES_SYNC_LACKS },
	{ "notes give", FZN_NOTES_SYNC_GIVE },
	{ "notes given", FZN_NOTES_SYNC_GIVEN },
	{ "messages give", FZN_NODE_MESSAGES_GIVE },
	{ "messages given", FZN_NODE_MESSAGES_GIVEN },
	{ "messages want", FZN_NODE_MESSAGES_WANT },
	{ "messages keys", FZN_NODE_MESSAGES_KEYS },
	{ "messages deliver", FZN_NODE_MESSAGES_DELIVER },
	{ "messages delivered", FZN_NODE_MESSAGES_DELIVERED },
	{ "contact devices offer", FZN_CONTACT_DEVICES_OFFER },
	{ "contact devices taken", FZN_CONTACT_DEVICES_TAKEN },
	{ "contact devices query", FZN_CONTACT_DEVICES_QUERY },
	{ "contact devices list", FZN_CONTACT_DEVICES_LIST },
	{ "contact devices revoked", FZN_CONTACT_DEVICES_REVOKED },
	{ "contact devices records", FZN_CONTACT_DEVICES_RECORDS },
	{ "contact devices estate", FZN_CONTACT_DEVICES_ESTATE },
	{ "contact devices items", FZN_CONTACT_DEVICES_ITEMS },
	{ "messages holds", FZN_NODE_MESSAGES_HOLDS },
	{ "messages holding", FZN_NODE_MESSAGES_HOLDING },
	{ "relay", FZN_TYPE_RELAY },
	{ "introduce", FZN_TYPE_INTRODUCE },
	{ "notify", FZN_TYPE_NOTIFY },
	{ "group sync", FZN_TYPE_GROUP_SYNC },
	{ "group acts", FZN_TYPE_GROUP_ACTS },
	{ "group lines sync", FZN_TYPE_GROUP_LINES_SYNC },
	{ "group lines", FZN_TYPE_GROUP_LINES },
	{ "stream query", FZN_TYPE_STREAM_QUERY },
	{ "stream records", FZN_TYPE_STREAM_RECORDS },
	{ "file refs want", FZN_TYPE_FILE_REFS_WANT },
	{ "file refs", FZN_TYPE_FILE_REFS },
};

#define SHARED_N (sizeof(shared) / sizeof(shared[0]))

static void test_each_version_is_its_owners(void)
{
	CHECK(FZN_MSG_VERSION == FZN_TYPES_VERSION_SPOOL, "spool's version is not the registry's");
	CHECK(FZN_NOTES_SYNC_VERSION == FZN_TYPES_VERSION_SHARED
	              && FZN_NODE_MESSAGES_VERSION == FZN_TYPES_VERSION_SHARED
	              && FZN_CONTACT_DEVICES_VERSION == FZN_TYPES_VERSION_SHARED,
	      "a sharer of version 2 has another version");
	CHECK(FZN_CAUSE_VERSION == FZN_TYPES_VERSION_CAUSE, "the cause envelope's version moved");
	CHECK(FZN_GATHER_VERSION == FZN_TYPES_VERSION_GATHER, "gather's version moved");
	CHECK(FZN_EXCHANGE_VERSION == FZN_TYPES_VERSION_EXCHANGE, "the exchange's version moved");
	CHECK(FZN_RECONCILE_VERSION == FZN_TYPES_VERSION_RECONCILE,
	      "reconciliation's version moved");
	/* BELOW A VERB LINE'S FIRST BYTE, every one: a printable letter. */
	CHECK(FZN_TYPES_VERSION_RECONCILE < 0x20u, "a version byte could open a verb line");
}

static void test_no_two_shared_types_are_one(void)
{
	size_t i, j;
	int clash = 0, extension = 0, retired = 0;

	for (i = 0; i < SHARED_N; i++) {
		for (j = i + 1u; j < SHARED_N; j++)
			if (shared[i].type == shared[j].type) {
				printf("  %s and %s are both %u\n", shared[i].name, shared[j].name,
				       shared[i].type);
				clash++;
			}
		if (shared[i].type >= FZN_TYPES_EXTENSION_FIRST
		    && shared[i].type <= FZN_TYPES_EXTENSION_LAST)
			extension++;
		if (shared[i].type == 13u || shared[i].type == 14u)
			retired++;
	}
	CHECK(SHARED_N == 47u, "the table is not the 47 types the registry lists");
	CHECK(clash == 0, "two version-2 types are one number");
	CHECK(extension == 0, "fuzznet allocated a type in the extensions' range");
	CHECK(retired == 0, "a retired type, 13 or 14, was reused");
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
	test_each_version_is_its_owners();
	test_no_two_shared_types_are_one();
	test_the_suite_can_tell_pass_from_fail();

	printf("types_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
