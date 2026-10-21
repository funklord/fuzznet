/* location/gpsd.h, sec 678, against a stand-in gpsd on loopback: nothing
 * connects until polled; a poll connects and sends WATCH; reports read --
 * the newest fix, once, across a line split between reads -- and a closed
 * gpsd is a link down that a later poll brings back.
 *
 * BOUNDED FROM INSIDE: every wait is a count of polls with a short sleep,
 * every socket non-blocking or with a timeout, and every descriptor closed
 * on the way out. */
#define _POSIX_C_SOURCE 200809L

#include "../gpsd.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL gpsd_test.c:%d: %s\n", line, what);
	}
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static void nap(void)
{
	struct timespec t = { 0, 10000000L };

	(void)nanosleep(&t, NULL);
}

/* A LISTENER on 127.0.0.1, any port: its descriptor, its port in `*port`. */
static int listener(uint16_t *port)
{
	struct sockaddr_in a;
	socklen_t len = sizeof(a);
	int fd = socket(AF_INET, SOCK_STREAM, 0);

	if (fd < 0)
		return -1;
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(fd, 2) != 0
	    || getsockname(fd, (struct sockaddr *)&a, &len) != 0) {
		(void)close(fd);
		return -1;
	}
	*port = ntohs(a.sin_port);
	return fd;
}

/* POLL `g` until a connection waits at `lfd`, then accept it: the
 * connection, or -1 after two hundred polls. */
static int accept_polling(fzn_gpsd_t *g, int lfd)
{
	struct timeval t = { 0, 1000 };
	fzn_location_fix_t f;
	int i, c;

	for (i = 0; i < 200; i++) {
		fd_set r;

		(void)fzn_gpsd_poll(g, &f);
		FD_ZERO(&r);
		FD_SET(lfd, &r);
		t.tv_sec = 0;
		t.tv_usec = 1000;
		if (select(lfd + 1, &r, NULL, NULL, &t) == 1) {
			struct timeval rt = { 2, 0 };

			c = accept(lfd, NULL, NULL);
			if (c >= 0)
				(void)setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &rt, sizeof(rt));
			return c;
		}
		nap();
	}
	return -1;
}

/* POLL until a fix comes: 1 with it, 0 after two hundred polls. */
static int fix_polling(fzn_gpsd_t *g, fzn_location_fix_t *f)
{
	int i;

	for (i = 0; i < 200; i++) {
		if (fzn_gpsd_poll(g, f))
			return 1;
		nap();
	}
	return 0;
}

static void test_watch_then_reports(void)
{
	static const char first[] = "{\"class\":\"VERSION\",\"release\":\"3.22\"}\n"
	                            "{\"class\":\"TPV\",\"mode\":2,\"lat\":1.5,\"lon\":2.5,\"eph\":4}\n"
	                            "{\"class\":\"TPV\",\"mode\":2,\"lat\":1.";
	static const char rest[] = "75,\"lon\":2.5,\"eph\":4}\n";
	fzn_gpsd_t g;
	fzn_location_fix_t f;
	char heard[128];
	uint16_t port = 0;
	int lfd = listener(&port), c;
	ssize_t n;

	if (lfd < 0) {
		CHECK(0, "fixture: no loopback listener");
		return;
	}
	CHECK(fzn_gpsd_init(&g, "127.0.0.1", 0) == 0 && fzn_gpsd_init(&g, "", port) == 0,
	      "a source aimed at port 0, or at no host, was made");
	CHECK(fzn_gpsd_init(&g, "127.0.0.1", port) == 1 && fzn_gpsd_link(&g) == FZN_GPSD_DISCONNECTED
	              && g.fd < 0,
	      "aiming a source connected something");
	c = accept_polling(&g, lfd);
	CHECK(c >= 0, "polling did not connect");
	if (c < 0) {
		(void)close(lfd);
		return;
	}
	n = recv(c, heard, sizeof(heard) - 1u, 0);
	CHECK(n > 0 && memcmp(heard, "?WATCH={\"enable\":true,\"json\":true}\n", (size_t)n) == 0
	              && fzn_gpsd_link(&g) == FZN_GPSD_WATCHING,
	      "the source did not send WATCH and watch");
	/* TWO TPVs AND HALF A THIRD: the newest whole one is the fix, once. */
	CHECK(send(c, first, sizeof(first) - 1u, 0) == (ssize_t)(sizeof(first) - 1u),
	      "fixture: the stand-in's first reports");
	CHECK(fix_polling(&g, &f) && f.lat_e7 == 15000000 && f.lon_e7 == 25000000,
	      "the whole report was not the fix");
	CHECK(!fzn_gpsd_poll(&g, &f), "one fix was given twice");
	CHECK(send(c, rest, sizeof(rest) - 1u, 0) == (ssize_t)(sizeof(rest) - 1u),
	      "fixture: the rest of the split report");
	CHECK(fix_polling(&g, &f) && f.lat_e7 == 17500000,
	      "a report split between reads was not read whole");
	/* gpsd GONE: down, and the next polls connect again. */
	(void)close(c);
	{
		int i, down = 0;

		for (i = 0; i < 200 && !down; i++) {
			(void)fzn_gpsd_poll(&g, &f);
			down = fzn_gpsd_link(&g) != FZN_GPSD_WATCHING;
			nap();
		}
		CHECK(down, "a closed gpsd still read as watching");
	}
	c = accept_polling(&g, lfd);
	CHECK(c >= 0, "the source did not connect again");
	if (c >= 0)
		(void)close(c);
	fzn_gpsd_close(&g);
	CHECK(fzn_gpsd_link(&g) == FZN_GPSD_DISCONNECTED && g.fd < 0,
	      "closing left the link open");
	(void)close(lfd);
}

static void test_nobody_listening(void)
{
	fzn_gpsd_t g;
	fzn_location_fix_t f;
	uint16_t port = 0;
	int lfd = listener(&port), i, got = 0;

	/* A PORT NOTHING HOLDS: the listener's, closed. */
	if (lfd >= 0)
		(void)close(lfd);
	CHECK(lfd >= 0 && fzn_gpsd_init(&g, "127.0.0.1", port), "fixture: a source aimed nowhere");
	for (i = 0; i < 50; i++) {
		got |= fzn_gpsd_poll(&g, &f);
		nap();
	}
	CHECK(!got && fzn_gpsd_link(&g) != FZN_GPSD_WATCHING,
	      "a source with nobody listening watched, or gave a fix");
	fzn_gpsd_close(&g);
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
	test_watch_then_reports();
	test_nobody_listening();
	test_the_suite_can_tell_pass_from_fail();

	printf("gpsd_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
