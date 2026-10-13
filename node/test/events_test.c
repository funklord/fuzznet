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
}

static void test_room_and_close(void)
{
	fzn_node_events_t ev;
	int sv[FZN_NODE_EVENTS_MAX + 1u][2];
	size_t i;
	char buf[8];

	fzn_node_events_init(&ev);
	for (i = 0; i < FZN_NODE_EVENTS_MAX; i++)
		CHECK(pair(sv[i]) && fzn_node_events_add(&ev, sv[i][0]), "fixture: a subscriber");
	CHECK(!fzn_node_events_room(&ev) && pair(sv[i]) && !fzn_node_events_add(&ev, sv[i][0]),
	      "a subscriber past the bound was taken");
	CHECK(write(sv[i][0], "x", 1) == 1, "a subscriber not taken was closed");
	(void)close(sv[i][0]);
	(void)close(sv[i][1]);
	fzn_node_events_close(&ev);
	CHECK(ev.n == 0u && fzn_node_events_room(&ev), "close left a subscriber");
	/* CLOSED: each client end reads its end of file. */
	for (i = 0; i < FZN_NODE_EVENTS_MAX; i++) {
		CHECK(read(sv[i][1], buf, sizeof(buf)) == 0, "a subscriber was not closed");
		(void)close(sv[i][1]);
	}
	CHECK(!fzn_node_events_add(NULL, 0) && !fzn_node_events_room(NULL)
	              && fzn_node_events_publish(NULL, "message", NULL) == 0u,
	      "a missing set was used");
}

int main(void)
{
	test_lines_whole_and_only_well_formed();
	test_one_gone_or_slow_is_dropped();
	test_room_and_close();
	if (failures) {
		fprintf(stderr, "events_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("events_test: all %d checks passed\n", checks);
	return 0;
}
