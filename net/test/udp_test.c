/* The datagram transport over loopback: a real socket per family, a frame
 * pushed through and compared, and the two refusals that keep a frame whole
 * -- an oversize send and a truncated receive -- driven at their boundary.
 * No daemon, no seal: this exercises udp.c alone, the way network_test
 * exercises the pipeline above it. */

#include "udp.h"
#include "frame.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>

/* FZN_UDP_DATAGRAM_MAX is the transport's own name for the sealed-frame
 * maximum; pin it against the generated layout so the two cannot drift. */
_Static_assert(FZN_UDP_DATAGRAM_MAX == SITU_FZN_FRAME_SIZE_MAX,
               "datagram max out of step with the generated frame size");

static int checks;
static int failures;

static void ok(int cond, const char *what)
{
	checks++;
	if (!cond) {
		failures++;
		printf("  FAIL udp_test.c: %s\n", what);
	}
}

/* The ephemeral port the kernel gave a bound socket, read straight from the
 * socket so the test needs no fixed port and cannot collide with anything. */
static uint16_t local_port(int fd, int family)
{
	struct sockaddr_storage ss;
	socklen_t len = sizeof(ss);

	if (getsockname(fd, (struct sockaddr *)&ss, &len) != 0)
		return 0;
	if (family == AF_INET)
		return ntohs(((struct sockaddr_in *)&ss)->sin_port);
	return ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
}

/* A receive timeout so a blocking recv can never hang the suite: if a
 * sabotage breaks the send a roundtrip depends on, the paired recv returns
 * rather than waiting forever for a datagram that will not come. */
static void arm_timeout(int fd)
{
	struct timeval tv;

	tv.tv_sec = 2;
	tv.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

/* Bind a receiver and a sender on `loop`, send `len` bytes of a pattern one
 * way, and assert the bytes arrive whole with a sender address attached. */
static void roundtrip(int family, const char *loop, size_t len)
{
	int rfd = -1, sfd = -1;
	fzn_udp_addr_t to, from;
	uint8_t out[FZN_UDP_DATAGRAM_MAX];
	uint8_t in[FZN_UDP_DATAGRAM_MAX];
	size_t got = 0, i;
	uint16_t port;

	for (i = 0; i < len; i++)
		out[i] = (uint8_t)(i * 7 + 1);

	ok(fzn_udp_bind(family, loop, 0, &rfd) == FZN_UDP_OK,
	   "receiver binds");
	arm_timeout(rfd);
	ok(fzn_udp_bind(family, loop, 0, &sfd) == FZN_UDP_OK,
	   "sender binds");
	port = local_port(rfd, family);
	ok(port != 0, "receiver has a port");
	ok(fzn_udp_resolve(family, loop, port, &to) == FZN_UDP_OK,
	   "numeric address resolves");
	ok(fzn_udp_send(sfd, &to, out, len) == FZN_UDP_OK,
	   "frame sends");
	memset(&from, 0, sizeof(from));
	ok(fzn_udp_recv(rfd, in, sizeof(in), &got, &from) == FZN_UDP_OK,
	   "frame receives");
	ok(got == len, "length preserved");
	ok(memcmp(in, out, len) == 0, "bytes preserved");
	ok(from.len != 0, "sender address carried back");

	fzn_udp_close(rfd);
	fzn_udp_close(sfd);
}

int main(void)
{
	int rfd = -1, sfd = -1, flags;
	fzn_udp_addr_t to, from;
	uint8_t big[FZN_UDP_DATAGRAM_MAX + 1];
	uint8_t small[16];
	size_t got = 0;
	uint16_t port;

	/* v4 and v6 loopback, a small frame and the exact maximum -- the
	 * upper boundary of what one datagram carries. */
	roundtrip(AF_INET, "127.0.0.1", 64);
	roundtrip(AF_INET, "127.0.0.1", FZN_UDP_DATAGRAM_MAX);
	roundtrip(AF_INET6, "::1", 64);
	roundtrip(AF_INET6, "::1", FZN_UDP_DATAGRAM_MAX);

	/* AN ADDRESS BACK TO TEXT, sec 621: both families, the port in host
	 * order, and an address of neither family refused. */
	{
		fzn_udp_addr_t a;
		char host[FZN_UDP_HOST_MAX];
		uint16_t p = 0;

		ok(fzn_udp_resolve(AF_INET, "192.0.2.7", 47001u, &a) == FZN_UDP_OK
		           && fzn_udp_addr_text(&a, host, &p) == FZN_UDP_OK
		           && strcmp(host, "192.0.2.7") == 0 && p == 47001u,
		   "a v4 address read back as itself");
		ok(fzn_udp_resolve(AF_INET6, "2001:db8::5", 258u, &a) == FZN_UDP_OK
		           && fzn_udp_addr_text(&a, host, &p) == FZN_UDP_OK
		           && strcmp(host, "2001:db8::5") == 0 && p == 258u,
		   "a v6 address read back as itself, its port in host order");
		memset(&a, 0, sizeof(a));
		a.len = 16u;
		ok(fzn_udp_addr_text(&a, host, &p) == FZN_UDP_ERR_ADDR,
		   "an address of no family read as one");
	}

	/* BROADCAST LET, sec 624: the socket's own option turned on, so a
	 * LAN probe to a broadcast address is not refused by the kernel. */
	{
		int fd = -1, on = 0;
		socklen_t on_len = sizeof(on);

		ok(fzn_udp_bind(AF_INET, "127.0.0.1", 0, &fd) == FZN_UDP_OK
		           && fzn_udp_broadcast(fd) == FZN_UDP_OK
		           && getsockopt(fd, SOL_SOCKET, SO_BROADCAST, &on, &on_len) == 0 && on,
		   "a socket let broadcast cannot");
		ok(fzn_udp_broadcast(-1) != FZN_UDP_OK, "no socket let broadcast");
		if (fd >= 0)
			fzn_udp_close(fd);
	}

	/* THE PORT BOUND, sec 687: the system's choice for port 0, and that
	 * same port asked for again once the first socket has let it go. */
	{
		int fd = -1, again = -1;
		uint16_t chosen = 0, read_back = 0;

		ok(fzn_udp_bind(AF_INET, "127.0.0.1", 0, &fd) == FZN_UDP_OK
		           && fzn_udp_local_port(fd, &chosen) == FZN_UDP_OK && chosen != 0u,
		   "the port the system chose was not read back");
		if (fd >= 0)
			fzn_udp_close(fd);
		ok(fzn_udp_bind(AF_INET, "127.0.0.1", chosen, &again) == FZN_UDP_OK
		           && fzn_udp_local_port(again, &read_back) == FZN_UDP_OK && read_back == chosen,
		   "a port asked for was not the one read back");
		if (again >= 0)
			fzn_udp_close(again);
		ok(fzn_udp_local_port(-1, &read_back) == FZN_UDP_ERR_MALFORMED,
		   "no socket was read for a port");
	}

	/* Oversize send: one byte past the maximum is refused, not
	 * fragmented. The exact maximum went through above, so the two
	 * together pin the boundary. */
	memset(big, 0xa5, sizeof(big));
	ok(fzn_udp_bind(AF_INET, "127.0.0.1", 0, &sfd) == FZN_UDP_OK,
	   "sender binds for the refusals");
	ok(fzn_udp_resolve(AF_INET, "127.0.0.1", 9, &to) == FZN_UDP_OK,
	   "discard address resolves");
	ok(fzn_udp_send(sfd, &to, big, FZN_UDP_DATAGRAM_MAX + 1) ==
	   FZN_UDP_ERR_OVERSIZED,
	   "one past the maximum is refused");
	ok(fzn_udp_send(sfd, &to, big, 0) == FZN_UDP_ERR_MALFORMED,
	   "a zero-length frame is refused");

	/* Truncated receive: a maximum-sized datagram into a tiny buffer is
	 * refused rather than handed back as a short frame. */
	ok(fzn_udp_bind(AF_INET, "127.0.0.1", 0, &rfd) == FZN_UDP_OK,
	   "receiver binds for truncation");
	arm_timeout(rfd);
	port = local_port(rfd, AF_INET);
	ok(fzn_udp_resolve(AF_INET, "127.0.0.1", port, &to) == FZN_UDP_OK,
	   "truncation target resolves");
	ok(fzn_udp_send(sfd, &to, big, FZN_UDP_DATAGRAM_MAX) == FZN_UDP_OK,
	   "a full datagram sends");
	ok(fzn_udp_recv(rfd, small, sizeof(small), &got, &from) ==
	   FZN_UDP_ERR_TRUNCATED,
	   "an oversize datagram is refused, not truncated");

	/* No DNS: a hostname does not resolve. */
	ok(fzn_udp_resolve(AF_INET, "localhost", 80, &to) ==
	   FZN_UDP_ERR_ADDR,
	   "a hostname is refused, not looked up");
	ok(fzn_udp_resolve(AF_INET, "example.com", 80, &to) ==
	   FZN_UDP_ERR_ADDR,
	   "a second hostname is refused");

	/* Malformed arguments across the surface. */
	ok(fzn_udp_bind(AF_UNIX, NULL, 0, &rfd) == FZN_UDP_ERR_MALFORMED,
	   "a non-IP family is refused");
	ok(fzn_udp_bind(AF_INET, NULL, 0, NULL) == FZN_UDP_ERR_MALFORMED,
	   "bind needs somewhere to put the fd");
	ok(fzn_udp_resolve(AF_INET, NULL, 0, &to) == FZN_UDP_ERR_MALFORMED,
	   "resolve needs a host");
	ok(fzn_udp_send(-1, &to, small, 4) == FZN_UDP_ERR_MALFORMED,
	   "send needs a descriptor");
	ok(fzn_udp_recv(rfd, small, 0, &got, &from) == FZN_UDP_ERR_MALFORMED,
	   "recv needs room");

	/* Non-blocking with nothing queued reports AGAIN, not a failure. */
	flags = fcntl(rfd, F_GETFL);
	ok(flags >= 0 && fcntl(rfd, F_SETFL, flags | O_NONBLOCK) == 0,
	   "receiver goes non-blocking");
	ok(fzn_udp_recv(rfd, small, sizeof(small), &got, &from) ==
	   FZN_UDP_ERR_AGAIN,
	   "an empty non-blocking receive reports AGAIN");

	fzn_udp_close(rfd);
	fzn_udp_close(sfd);

	printf("udp_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
