/* node/meter.h, sec 685: every family by its owner's constants, a cause
 * envelope looked through, a file's root kept as the key, rows by peer and
 * key, a window's rate, and eviction that keeps a family's sums whole. */
#include "../meter.h"
#include "../types.h"
#include "../members.h"
#include "../messages.h"
#include "../contact_devices.h"
#include "../../log/cause.h"
#include "../../notes/sync.h"
#include "../../spool/message.h"
#include "../../log/gather.h"
#include "../../record/exchange.h"
#include "../reconcile.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL meter_test.c:%d: %s\n", line, what);
	}
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static fzn_meter_family_t of(unsigned version, unsigned type)
{
	uint8_t p[2] = { (uint8_t)version, (uint8_t)type };
	uint8_t key[FZN_METER_KEY_MAX];
	size_t key_len = 9;

	return fzn_meter_family_of(p, sizeof(p), key, &key_len);
}

static void test_the_families(void)
{
	CHECK(of(2, FZN_NOTES_SYNC_INDEX_QUERY) == FZN_METER_NOTES
	              && of(2, FZN_NOTES_SYNC_GIVEN) == FZN_METER_NOTES,
	      "notes sync is not notes");
	CHECK(of(2, FZN_NODE_MEMBERS_QUERY) == FZN_METER_MEMBERS, "members is not members");
	CHECK(of(2, FZN_NODE_MESSAGES_GIVE) == FZN_METER_MESSAGES
	              && of(2, FZN_NODE_MESSAGES_HOLDING) == FZN_METER_MESSAGES,
	      "messages is not messages");
	CHECK(of(2, FZN_CONTACT_DEVICES_OFFER) == FZN_METER_CONTACT_DEVICES,
	      "contact devices is not contact devices");
	CHECK(of(2, FZN_TYPE_RELAY) == FZN_METER_RELAY && of(2, FZN_TYPE_NOTIFY) == FZN_METER_INTRODUCE
	              && of(2, FZN_TYPE_GROUP_LINES) == FZN_METER_GROUPS
	              && of(2, FZN_TYPE_STREAM_RECORDS) == FZN_METER_STREAMS
	              && of(2, FZN_TYPE_FILE_REFS) == FZN_METER_FILE_REFS,
	      "one of fuzznetd's own types is in the wrong family");
	CHECK(of(2, FZN_TYPES_EXTENSION_FIRST) == FZN_METER_EXTENSION
	              && of(2, FZN_TYPES_EXTENSION_LAST) == FZN_METER_EXTENSION
	              && of(2, 36) == FZN_METER_OTHER && of(2, 200) == FZN_METER_OTHER,
	      "the extensions' range, or what nobody allocated, is wrong");
	CHECK(of(FZN_GATHER_VERSION, 1) == FZN_METER_LOGS
	              && of(FZN_EXCHANGE_VERSION, 1) == FZN_METER_JOURNAL
	              && of(FZN_RECONCILE_VERSION, 1) == FZN_METER_RECONCILE
	              && of(FZN_MSG_VERSION, FZN_MSG_DATA) == FZN_METER_FILES && of(9, 1) == FZN_METER_OTHER,
	      "a version byte's family is wrong");
	{
		uint8_t key[FZN_METER_KEY_MAX];
		size_t key_len = 0;

		CHECK(fzn_meter_family_of((const uint8_t *)"get status", 10u, key, &key_len)
		              == FZN_METER_VERBS && key_len == 0u,
		      "a verb line is not verbs");
	}
	CHECK(strcmp(fzn_meter_family_name(FZN_METER_CONTACT_DEVICES), "contact-devices") == 0
	              && strcmp(fzn_meter_family_name(FZN_METER_FAMILIES), "other") == 0,
	      "a family's name is wrong");
}

/* A NAME THE ENVELOPE WILL CARRY, as cause_test makes one. */
static fzn_entry_name_t name(uint8_t seed)
{
	fzn_entry_name_t n;

	memset(&n, 0, sizeof(n));
	memset(n.machine, 0x3c, sizeof(n.machine));
	strcpy(n.user, "root");
	strcpy(n.program, "fuzznetd");
	n.pid = 4121u;
	n.start_ms = 1727778896123u;
	n.position = seed;
	return n;
}

static void test_a_file_root_through_a_cause(void)
{
	uint8_t want[FZN_MSG_WANT_LEN], wrapped[256], key[FZN_METER_KEY_MAX];
	fzn_entry_name_t cause, origin;
	size_t key_len = 0, n = 0;

	memset(want, 0, sizeof(want));
	want[0] = FZN_MSG_VERSION;
	want[1] = FZN_MSG_WANT;
	memset(want + FZN_MSG_WANT_OFF_ROOT, 0xab, 32u);
	CHECK(fzn_meter_family_of(want, sizeof(want), key, &key_len) == FZN_METER_FILES
	              && key_len == 32u && key[0] == 0xab && key[31] == 0xab,
	      "a WANT's root is not its key");
	cause = name(7u);
	origin = name(2u);
	CHECK(fzn_cause_wrap(&cause, &origin, want, sizeof(want), wrapped, sizeof(wrapped), &n)
	              == FZN_CAUSE_OK,
	      "fixture: a WANT in a cause envelope");
	key_len = 0;
	CHECK(fzn_meter_family_of(wrapped, n, key, &key_len) == FZN_METER_FILES && key_len == 32u
	              && key[0] == 0xab,
	      "a cause envelope was not looked through");
}

static void test_the_table(void)
{
	static fzn_meter_t m;
	uint8_t root[32];
	size_t i;

	memset(&m, 0, sizeof(m));
	memset(root, 7, sizeof(root));
	fzn_meter_count(&m, FZN_METER_FILES, "10.0.0.1:1", root, 32u, 100u, 0u, 1000u);
	fzn_meter_count(&m, FZN_METER_FILES, "10.0.0.1:1", root, 32u, 0u, 50000u, 1002u);
	fzn_meter_count(&m, FZN_METER_FILES, "10.0.0.1:1", NULL, 0u, 7u, 0u, 1002u);
	fzn_meter_count(&m, FZN_METER_NOTES, "10.0.0.1:1", NULL, 0u, 3u, 4u, 1002u);
	CHECK(m.n[FZN_METER_FILES] == 2u && m.n[FZN_METER_NOTES] == 1u,
	      "rows are not one a peer and key, a table a family");
	CHECK(m.rows[FZN_METER_FILES][0].up == 100u && m.rows[FZN_METER_FILES][0].down == 50000u
	              && m.rows[FZN_METER_FILES][0].first_seen == 1000u
	              && m.rows[FZN_METER_FILES][0].last_seen == 1002u,
	      "a row's sums or times are wrong");
	/* THE WINDOW CLOSES at the first count past it: 50100 bytes over
	 * the six seconds it ran. */
	fzn_meter_count(&m, FZN_METER_FILES, "10.0.0.1:1", root, 32u, 0u, 0u, 1006u);
	CHECK(m.rows[FZN_METER_FILES][0].rate_down == 50000u / 6u
	              && m.rows[FZN_METER_FILES][0].rate_up == 100u / 6u,
	      "the window's rate is wrong");
	/* A FULL TABLE evicts its least recently active row, its bytes kept. */
	for (i = 0; i < FZN_METER_ROWS_MAX; i++) {
		char peer[24];

		(void)snprintf(peer, sizeof(peer), "10.0.1.%zu:1", i);
		fzn_meter_count(&m, FZN_METER_MESSAGES, peer, NULL, 0u, 10u, 1u, 2000u + i);
	}
	fzn_meter_count(&m, FZN_METER_MESSAGES, "10.0.2.0:1", NULL, 0u, 5u, 5u, 3000u);
	CHECK(m.n[FZN_METER_MESSAGES] == FZN_METER_ROWS_MAX && m.evicted_up[FZN_METER_MESSAGES] == 10u
	              && m.evicted_down[FZN_METER_MESSAGES] == 1u
	              && m.n[FZN_METER_FILES] == 2u,
	      "the full table did not evict its oldest, or another family's rows moved");
	{
		int found_new = 0, found_oldest = 0;

		for (i = 0; i < m.n[FZN_METER_MESSAGES]; i++) {
			found_new |= strcmp(m.rows[FZN_METER_MESSAGES][i].peer, "10.0.2.0:1") == 0;
			found_oldest |= strcmp(m.rows[FZN_METER_MESSAGES][i].peer, "10.0.1.0:1") == 0;
		}
		CHECK(found_new && !found_oldest, "the row evicted was not the least recently active");
	}
	/* A PEER PAST THE BOUND is cut, not refused. */
	{
		char long_peer[200];

		memset(long_peer, 'p', sizeof(long_peer) - 1u);
		long_peer[sizeof(long_peer) - 1u] = '\0';
		fzn_meter_count(&m, FZN_METER_LOGS, long_peer, NULL, 0u, 1u, 0u, 4000u);
		CHECK(m.n[FZN_METER_LOGS] == 1u
		              && strlen(m.rows[FZN_METER_LOGS][0].peer) == FZN_METER_PEER_MAX,
		      "a long peer was not cut to the bound");
	}
}

static size_t ask(const fzn_meter_t *m, fzn_origin_t origin, fzn_verb_t verb, const char *arg,
                  char *reply, size_t cap)
{
	fzn_request_t r;

	memset(&r, 0, sizeof(r));
	r.parsed = verb;
	r.arg = (const uint8_t *)arg;
	r.arg_len = strlen(arg);
	return fzn_meter_local(m, origin, &r, reply, cap);
}

/* THE VERBS: totals whole, pages within one reply giving each row once,
 * and the refusals. */
static void test_the_verbs(void)
{
	static fzn_meter_t m;
	char reply[1024];
	size_t i, from = 0, seen = 0, pages = 0;

	memset(&m, 0, sizeof(m));
	for (i = 0; i < 40u; i++) {
		char peer[24];
		uint8_t root[32];

		(void)snprintf(peer, sizeof(peer), "10.0.3.%zu:1", i);
		memset(root, (int)i, sizeof(root));
		fzn_meter_count(&m, FZN_METER_FILES, peer, root, 32u, 1u, 2u, 100u);
	}
	fzn_meter_count(&m, FZN_METER_NOTES, "10.0.0.9:1", NULL, 0u, 5u, 6u, 100u);
	m.evicted_up[FZN_METER_NOTES] = 10u;
	CHECK(ask(&m, FZN_ORIGIN_SAME_USER, FZN_VERB_GET, "transfer", reply, sizeof(reply)) > 0
	              && strcmp(reply, "ok notes,15,6 files,40,80\n") == 0,
	      "get transfer's totals are not each family's, evicted bytes in");
	for (;;) {
		char arg[32], *w;
		size_t n, rows = 0;

		(void)snprintf(arg, sizeof(arg), "transfer %zu", from);
		n = ask(&m, FZN_ORIGIN_SAME_USER, FZN_VERB_LIST, arg, reply, sizeof(reply));
		CHECK(n > 0 && n < sizeof(reply) && strncmp(reply, "ok 41 ", 6) == 0,
		      "a page is not within one reply, or does not say the total");
		if (!n || strncmp(reply, "ok 41 ", 6) != 0)
			return;
		w = strchr(reply + 6, ' ');
		while (w && w[1] && w[1] != '\n') {
			rows++;
			w = strchr(w + 1, ' ');
		}
		if (!rows)
			break;
		seen += rows;
		from += rows;
		pages++;
		if (pages > 50u)
			break;
	}
	CHECK(seen == 41u && pages >= 2u, "the pages did not give every row once over pages");
	CHECK(ask(&m, FZN_ORIGIN_LOCAL, FZN_VERB_LIST, "transfer", reply, sizeof(reply)) > 0
	              && strncmp(reply, "denied", 6) == 0,
	      "another user read the traffic");
	CHECK(ask(&m, FZN_ORIGIN_SAME_USER, FZN_VERB_LIST, "transfer x", reply, sizeof(reply)) > 0
	              && strncmp(reply, "malformed", 9) == 0,
	      "a FROM that is no number was taken");
	CHECK(ask(&m, FZN_ORIGIN_SAME_USER, FZN_VERB_LIST, "sticker", reply, sizeof(reply)) == 0,
	      "another subject was answered");
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
	test_the_families();
	test_a_file_root_through_a_cause();
	test_the_table();
	test_the_verbs();
	test_the_suite_can_tell_pass_from_fail();

	printf("meter_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
