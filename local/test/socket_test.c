/* The listener, against a real socket in a temporary directory.
 *
 * THE ONE ASSERTION THAT MATTERS is the mode on the path. An AF_UNIX socket
 * is gated by filesystem permissions, `bind` applies the umask, and this test
 * sets the umask to zero first -- so a listener that bound and chmodded
 * afterwards, or did not chmod at all, would publish a world-writable socket
 * and fail here. Everything else in this file is plumbing around that.
 *
 * Bounded and self-contained: one directory under TMPDIR, one process, no
 * fork, both ends of every connection owned here, and the directory removed
 * on the way out.
 */

#if defined(__linux__)
/* `mkdtemp` and `S_ISSOCK` are behind _DEFAULT_SOURCE, which -std=c11 hides.
 * Declared here rather than in the Makefile, as local/peer_linux.c and
 * local/socket.c do, so the file needing the extension is the one asking. It
 * must precede every include. */
#define _GNU_SOURCE
#endif

#include "../socket.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static int failures;
static int checks;

static void check(int ok, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL: %s\n", what);
	}
}

/* Connect to `path`, returning the descriptor or -1. */
static int dial(const char *path)
{
	struct sockaddr_un addr;
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);

	if (fd < 0)
		return -1;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1u);
	if (connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
		close(fd);
		return -1;
	}
	return fd;
}

/* Wait for a connection, then accept it. Returns the accept's verdict, or
 * FZN_SOCKET_ERR_AGAIN if none arrived.
 *
 * THE LISTENER IS NON-BLOCKING FOR THE WHOLE TEST, which is not a detail. An
 * earlier version called accept directly, and the sabotage that removes the
 * in-use check then made this file hang for ever rather than fail: no probe
 * connection was made, and the accept waited for one that was not coming. A
 * hanging test is caught only by whatever timeout wraps it and says nothing
 * about which assertion it was on. Non-blocking makes that case a returned
 * error, and covers FZN_SOCKET_ERR_AGAIN on the way. */
static fzn_socket_err_t wait_accept(int listen_fd, int *out_fd, fzn_peer_t *peer)
{
	struct pollfd pfd = { listen_fd, POLLIN, 0 };

	if (poll(&pfd, 1, 2000) != 1)
		return FZN_SOCKET_ERR_AGAIN;
	return fzn_socket_accept(listen_fd, out_fd, peer);
}

int main(void)
{
	char dir[] = "/tmp/fzn_socket_test_XXXXXX";
	char path[256], longpath[512];
	int listen_fd = -1, client = -1, served = -1;
	fzn_peer_t peer;
	struct stat st;

	if (!mkdtemp(dir)) {
		printf("  FAIL: could not make a temporary directory\n");
		return 1;
	}
	snprintf(path, sizeof(path), "%s/sock", dir);

	/* Zero, so that `bind` would leave the entry world-writable and the
	 * mode assertion below is about this module rather than about the
	 * environment it happened to run in. */
	umask(0);

	check(fzn_socket_listen(path, 0660u, 4, &listen_fd) == FZN_SOCKET_OK,
	      "listening on a fresh path was refused");
	check(listen_fd >= 0, "no descriptor came back");
	check(fcntl(listen_fd, F_SETFL, O_NONBLOCK) == 0, "could not make the listener "
	      "non-blocking");

	/* Nothing is waiting yet, so accept must say so rather than block.
	 * This is the only place FZN_SOCKET_ERR_AGAIN is reachable from. */
	{
		int none = -1;

		check(fzn_socket_accept(listen_fd, &none, &peer) == FZN_SOCKET_ERR_AGAIN,
		      "accepting with nothing waiting did not report AGAIN");
		check(none == -1, "a descriptor came back from an empty accept");
	}

	/* THE MODE. */
	check(stat(path, &st) == 0, "the socket path does not exist after listen");
	check((st.st_mode & 0777u) == 0660u,
	      "the socket path is not the mode asked for -- bind's umask was left in "
	      "place, so the socket was reachable by whoever the umask allowed");
	check(S_ISSOCK(st.st_mode), "the path is not a socket");

	/* No temporary name left behind. */
	{
		char tmp[300];

		snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid());
		check(stat(tmp, &st) != 0, "the temporary name was left in the directory");
	}

	/* ANOTHER INSTANCE MUST NOT TAKE IT. A second listen on a live path is
	 * refused rather than silently stealing the socket from the first --
	 * which would be invisible until something reconnected. */
	{
		int second = -1;
		int probe = -1;
		char sink = 0;

		check(fzn_socket_listen(path, 0660u, 4, &second) == FZN_SOCKET_ERR_IN_USE,
		      "a second listener took a live socket from the first");
		check(second == -1, "a refused listen still handed back a descriptor");

		/* AND THE PROBE IS A REAL CONNECTION, which this test discovered
		 * by accident: the next accept returned the probe's socket
		 * rather than the client's, and reading it gave EOF. Telling a
		 * live socket from a stale one means connecting to it, so a
		 * running instance necessarily sees a connection that closes
		 * without sending anything. Asserted here rather than worked
		 * around, so that a change to how liveness is detected shows up
		 * as this expectation failing. */
		check(wait_accept(listen_fd, &probe, &peer) == FZN_SOCKET_OK,
		      "the liveness probe left no connection to accept");
		check(read(probe, &sink, 1) == 0,
		      "the probe's connection carried data, so it was not the probe");
		close(probe);
	}

	/* Accept, with credentials attached. */
	client = dial(path);
	check(client >= 0, "could not connect to the listener");
	check(wait_accept(listen_fd, &served, &peer) == FZN_SOCKET_OK,
	      "accepting a waiting connection failed");
	check(served >= 0, "no connected descriptor came back");
	check(peer.pid == (int64_t)getpid(), "the peer's pid is not this process");
	check(peer.uid == (uint32_t)getuid(), "the peer's uid is not this user");
	check(peer.groups_known == 1,
	      "supplementary groups were not established for an accepted peer");

	/* The connection works, which is worth one line: a listener that
	 * produced an unusable descriptor would pass everything above. */
	{
		char byte = 'x';
		char got = 0;

		check(write(client, &byte, 1) == 1, "writing to the connection failed");
		check(read(served, &got, 1) == 1 && got == 'x',
		      "the accepted descriptor is not connected to the client");
	}
	close(client);
	close(served);
	client = served = -1;

	/* A STALE PATH IS REPLACED. Closing the descriptor without unlinking
	 * is what a crash leaves behind; a fresh listener must take it over
	 * rather than refusing for ever. */
	close(listen_fd);
	listen_fd = -1;
	check(stat(path, &st) == 0, "the path vanished when the descriptor closed");
	check(fzn_socket_listen(path, 0640u, 4, &listen_fd) == FZN_SOCKET_OK,
	      "a stale socket path was not taken over");
	check(fcntl(listen_fd, F_SETFL, O_NONBLOCK) == 0, "could not make the replacement "
	      "listener non-blocking");
	check(stat(path, &st) == 0 && (st.st_mode & 0777u) == 0640u,
	      "the replacement socket did not get the mode asked for");

	fzn_socket_close(listen_fd, path);
	listen_fd = -1;
	check(stat(path, &st) != 0, "close left the socket path behind");

	/* Paths this cannot serve, refused rather than truncated. */
	memset(longpath, 'a', sizeof(longpath) - 1u);
	longpath[0] = '/';
	longpath[sizeof(longpath) - 1u] = '\0';
	check(fzn_socket_listen(longpath, 0660u, 4, &listen_fd) == FZN_SOCKET_ERR_PATH,
	      "a path longer than sun_path was accepted, so it was truncated into a "
	      "different socket");
	check(fzn_socket_listen("relative/sock", 0660u, 4, &listen_fd) == FZN_SOCKET_ERR_PATH,
	      "a relative path was accepted, which names a socket in whatever directory "
	      "the process happens to be in");
	check(fzn_socket_listen("", 0660u, 4, &listen_fd) == FZN_SOCKET_ERR_PATH,
	      "an empty path was accepted");

	/* Arguments. */
	check(fzn_socket_listen(NULL, 0660u, 4, &listen_fd) == FZN_SOCKET_ERR_MALFORMED,
	      "a null path");
	check(fzn_socket_listen(path, 0660u, 4, NULL) == FZN_SOCKET_ERR_MALFORMED,
	      "a null out descriptor");
	check(fzn_socket_accept(-1, &served, &peer) == FZN_SOCKET_ERR_MALFORMED,
	      "accepting on a negative descriptor");
	check(fzn_socket_accept(0, NULL, &peer) == FZN_SOCKET_ERR_MALFORMED,
	      "a null out descriptor for accept");
	check(fzn_socket_accept(0, &served, NULL) == FZN_SOCKET_ERR_MALFORMED,
	      "a null out peer");
	fzn_socket_close(-1, NULL); /* must simply return */
	check(1, "closing nothing did not crash");

	(void)rmdir(dir);
	printf("socket_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
