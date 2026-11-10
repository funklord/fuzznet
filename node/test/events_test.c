/* events_test -- local subscribers told what changed, sec 609: a line
 * whole to each, nothing malformed written, one that hung up or whose
 * buffer is full dropped rather than waited on, and no more than
 * FZN_NODE_EVENTS_MAX taken.
 *
 * Over socketpairs, no daemon. HOW IT TERMINATES: fixed loops; the one that
 * fills a subscriber's buffer stops at the first drop or at 100000 lines,
 * whichever is first, and the node's side is non-blocking throughout.
 */

#define _POSIX_C_SOURCE 200809L

#include "../events.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int checks, failures;

#define CHECK(cond, what)                                                                 \
	do {                                                                              \
		checks++;                                                                 \
		if (!(cond)) {                                                            \
			failures++;                                                       \
			fprintf(stderr, "  FAIL events_test.c:%d: %s\n", __LINE__, what); \
		}                                                                         \
	} while (0)

/* What the client end holds to read, without waiting: a non-blocking read. */
static size_t drain(int fd, char *out, size_t cap)
{
	size_t got = 0;
	ssize_t r;
	int flags = fcntl(fd, F_GETFL);

	(void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	while (got + 1u < cap && (r = read(fd, out + got, cap - 1u - got)) > 0)
		got += (size_t)r;
	out[got] = '\0';
	return got;
}

static int pair(int sv[2])
{
	return socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0;
}

/* HELD, sec 899: the application's, and none of fuzznet's. */
static void test_held(void)
{
	static fzn_node_events_t ev;
	int own[2], held[2], other[2];
	char buf[256];

	fzn_node_events_init(&ev);
	CHECK(pair(own) && pair(held) && pair(other) && fzn_node_events_add(&ev, own[0])
	              && fzn_node_events_add_held(&ev, held[0])
	              && fzn_node_events_add_held(&ev, other[0]),
	      "fixture: this node's user's, and two held");
	CHECK(fzn_node_events_publish(&ev, "member", "ab") == 1u, "fuzznet's reaches its own alone");
	CHECK(drain(held[1], buf, sizeof(buf)) == 0u, "a held subscriber hears none of fuzznet's");
	CHECK(fzn_node_events_publish_extension(&ev, "net-drift", NULL) == 3u,
	      "the application's reaches every subscriber");
	CHECK(drain(held[1], buf, sizeof(buf)) && strcmp(buf, "event net-drift -\n") == 0, "whole");
	(void)drain(other[1], buf, sizeof(buf));
	/* DROPPED, a held subscriber stays held in its new place. */
	(void)drain(own[1], buf, sizeof(buf));
	close(own[1]);
	CHECK(fzn_node_events_ready(&ev, own[0]), "the first goes");
	CHECK(fzn_node_events_publish(&ev, "member", "ab") == 0u,
	      "and the last, moved into its place, hears none of fuzznet's");
	fzn_node_events_close(&ev);
}

static void test_lines_whole_and_only_well_formed(void)
{
	fzn_node_events_t ev;
	int a[2], b[2];
	char buf[256];

	fzn_node_events_init(&ev);
	CHECK(pair(a) && pair(b) && fzn_node_events_add(&ev, a[0]) && fzn_node_events_add(&ev, b[0]),
	      "fixture: two subscribers");
	CHECK(fzn_node_events_publish(&ev, "message", NULL) == 2u
	              && fzn_node_events_publish(&ev, "note", "0aff") == 2u,
	      "two events did not reach both subscribers");
	CHECK(drain(a[1], buf, sizeof(buf)) && strcmp(buf, "event message -\nevent note 0aff\n") == 0,
	      "the first subscriber did not read both lines, whole and in order");
	CHECK(drain(b[1], buf, sizeof(buf)) && strcmp(buf, "event message -\nevent note 0aff\n") == 0,
	      "the second subscriber did not read both lines");
	/* NOTHING A SUBSCRIBER COULD NOT SPLIT. */
	CHECK(fzn_node_events_publish(&ev, "two words", NULL) == 0u
	              && fzn_node_events_publish(&ev, "Note", NULL) == 0u
	              && fzn_node_events_publish(&ev, "", NULL) == 0u
	              && fzn_node_events_publish(&ev, "note", "0AFF") == 0u
	              && fzn_node_events_publish(&ev, "note", "id\nevent x") == 0u
	              && fzn_node_events_publish(&ev, "note", "") == 0u
	              && fzn_node_events_publish(&ev, "abcdefghijklmnopq", NULL) == 0u,
	      "a subject or name a subscriber could not split was published");
	CHECK(drain(a[1], buf, sizeof(buf)) == 0u, "a refused event reached a subscriber");
	CHECK(ev.n == 2u && ev.dropped == 0u, "a refused event dropped a subscriber");
	fzn_node_events_close(&ev);
	(void)close(a[1]);
	(void)close(b[1]);
}

static void test_one_gone_or_slow_is_dropped(void)
{
	fzn_node_events_t ev;
	int a[2], b[2], c[2], size = 4096, i;

	fzn_node_events_init(&ev);
	CHECK(pair(a) && pair(b) && pair(c) && fzn_node_events_add(&ev, a[0])
	              && fzn_node_events_add(&ev, b[0]) && fzn_node_events_add(&ev, c[0]),
	      "fixture: three subscribers");
	/* HUNG UP: the next line finds it gone. */
	(void)close(b[1]);
	CHECK(fzn_node_events_publish(&ev, "message", NULL) == 2u && ev.n == 2u && ev.dropped == 1u,
	      "a subscriber that hung up was not dropped at the next event");
	/* SPOKE OUT OF TURN, as the poll reports it: dropped. */
	CHECK(fzn_node_events_ready(&ev, c[0]) && ev.n == 1u && ev.dropped == 2u
	              && !fzn_node_events_ready(&ev, c[0]),
	      "a subscriber the poll reported ready was not dropped, or was dropped twice");
	(void)close(c[1]);
	/* NEVER READS: its buffer fills, and it is dropped rather than waited
	 * on -- a blocking write here would hang this test, which is the
	 * failure the design rules out. */
	(void)setsockopt(a[0], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
	for (i = 0; i < 100000 && ev.n == 1u; i++)
		(void)fzn_node_events_publish(&ev, "message", NULL);
	CHECK(ev.n == 0u && ev.dropped == 3u,
	      "a subscriber that never read was not dropped when its buffer filled");
	/* WHAT IT DID HOLD IS WHOLE LINES: the drop took no partial line. */
	{
		static char all[1u << 20];
		size_t got = drain(a[1], all, sizeof(all)), k;
		int whole = got > 0u && all[got - 1u] == '\n';

		for (k = 0; whole && k < got; k += 16u)
			whole = memcmp(all + k, "event message -\n", 16u) == 0;
		CHECK(whole, "a subscriber dropped for a full buffer was left a partial line");
	}
	(void)close(a[1]);
	CHECK(fzn_node_events_publish(&ev, "message", NULL) == 0u, "an event reached nobody");
	/* ITS ROOM LET GO: every subscriber dropped still leaves the table
	 * allocated, and `make sancheck` found it leaked here (sec 999). */
	fzn_node_events_close(&ev);
}

static void test_room_and_close(void)
{
	static fzn_node_events_t ev;
	static int sv[300][2];
	size_t i;
	char buf[8];

	/* PAST WHAT THE TABLE STARTS WITH, sec 903: each taken and told. */
	fzn_node_events_init(&ev);
	for (i = 0; i < 300u; i++)
		CHECK(pair(sv[i]) && fzn_node_events_add(&ev, sv[i][0]), "a subscriber was not taken");
	CHECK(fzn_node_events_publish(&ev, "message", NULL) == 300u, "one was not told");
	fzn_node_events_close(&ev);
	CHECK(ev.n == 0u, "close left a subscriber");
	/* CLOSED: each client end reads its line, then its end of file. */
	for (i = 0; i < 300u; i++) {
		CHECK(drain(sv[i][1], buf, sizeof(buf)) > 0u, "a line was not there to read");
		(void)close(sv[i][1]);
	}
	CHECK(!fzn_node_events_add(NULL, 0), "an add to nothing was taken");
}

static void test_since_a_cursor(void)
{
	static fzn_node_events_t ev;
	char out[2048], want[64];
	size_t n, i;
	char hex[65];

	fzn_node_events_init(&ev);
	n = fzn_node_events_since(&ev, 0, out, sizeof(out), 1020u);
	out[n] = '\0';
	CHECK(n && strcmp(out, "1 1") == 0, "an empty node's page is not NEXT 1 FIRST 1");
	(void)fzn_node_events_publish(&ev, "record", NULL);
	(void)fzn_node_events_publish(&ev, "note", "0a0b");
	n = fzn_node_events_since(&ev, 0, out, sizeof(out), 1020u);
	out[n] = '\0';
	CHECK(strcmp(out, "3 1 record - note 0a0b") == 0,
	      "two events published with no subscriber were not kept, in order");
	n = fzn_node_events_since(&ev, 2, out, sizeof(out), 1020u);
	out[n] = '\0';
	CHECK(strcmp(out, "3 1 note 0a0b") == 0, "from 2 did not start at the second");
	n = fzn_node_events_since(&ev, 3, out, sizeof(out), 1020u);
	out[n] = '\0';
	CHECK(strcmp(out, "3 1") == 0, "a reader caught up was told something");
	n = fzn_node_events_since(&ev, 9, out, sizeof(out), 1020u);
	out[n] = '\0';
	CHECK(strcmp(out, "3 1") == 0, "a cursor past the end -- a node started again -- was not "
	                               "answered NEXT below it");
	/* PAST THE RING: FIRST moves, and a reader from 1 is shown it fell
	 * behind by FIRST above its cursor. */
	memset(hex, 'f', 64u);
	hex[64] = '\0';
	for (i = 0; i < FZN_NODE_EVENTS_KEPT + 10u; i++)
		(void)fzn_node_events_publish(&ev, "message", hex);
	n = fzn_node_events_since(&ev, 1, out, sizeof(out), 1020u);
	out[n] = '\0';
	(void)snprintf(want, sizeof(want), " %u ", (unsigned)(FZN_NODE_EVENTS_KEPT + 13u - FZN_NODE_EVENTS_KEPT));
	CHECK(n && strstr(out, want) == out + strcspn(out, " "),
	      "a ring passed did not say its first is above the reader's cursor");
	/* WITHIN THE BUDGET: each event here escapes to 6 + 7 + 64 = 77, so
	 * 1020 holds at most twelve of them with the head. */
	{
		size_t spaces = 0, k;

		for (k = 0; k < n; k++)
			spaces += out[k] == ' ';
		CHECK(spaces >= 1u + 2u * 11u && n + 2u * spaces <= 1020u,
		      "a page did not fill its escaped budget, or passed it");
	}
}

int main(void)
{
	test_held();
	test_lines_whole_and_only_well_formed();
	test_one_gone_or_slow_is_dropped();
	test_room_and_close();
	test_since_a_cursor();
	if (failures) {
		fprintf(stderr, "events_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("events_test: all %d checks passed\n", checks);
	return 0;
}
