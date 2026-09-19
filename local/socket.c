/* See socket.h. */

#if defined(__linux__)
/* For SOCK_CLOEXEC and accept4. Declared here rather than in the Makefile so
 * that the file needing the extension is the one asking for it, exactly as
 * local/peer_linux.c does. */
#define _GNU_SOURCE
#endif

#include "socket.h"

#if defined(__linux__)

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

/* Is somebody listening on `path` already?
 *
 * Connecting is the only way to tell a live socket from one a crash left
 * behind -- they are the same directory entry. A refused connection means the
 * entry is stale; a successful one means an instance owns it. */
static int in_use(const struct sockaddr_un *addr)
{
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	int connected;

	if (fd < 0)
		return 0; /* cannot tell; the bind below will fail honestly */

	connected = connect(fd, (const struct sockaddr *)addr, sizeof(*addr)) == 0;
	close(fd);
	return connected;
}

/* The field a path has to fit, named once so that nothing below repeats the
 * number and nothing above has to know it. */
#define SUN_PATH_LEN (sizeof(((struct sockaddr_un *)0)->sun_path))

/* THE ROOM THE TEMPORARY NAME NEEDS, and the reason the longest path this can
 * bind is shorter than the field.
 *
 * `fzn_socket_listen` binds `<path>.tmp.<pid>` and renames it, so the
 * TEMPORARY name is the one that has to fit -- and that is a property of how
 * this module binds rather than anything a caller can see. raidcfgd reported
 * the consequence on 2026-09-19: a 107-byte path passed their `--check`,
 * which exists to say what would be served and deliberately does not bind,
 * and the daemon then refused the same path at start-up. The flag whose job
 * is to predict the start had approved a configuration that cannot start.
 *
 * The room reserved is for the WIDEST pid rather than for this process's, and
 * that is a fix rather than a simplification. Sizing it from `getpid` made
 * the same path bindable under one pid and refused under the next, which this
 * module did until the report; and a predicate that measured the asking
 * process would be answering about the wrong one, since a dry run happens in
 * a different process from the daemon it predicts. `pid_t` is `int` here, so
 * ten digits covers every value it can hold. */
#define TMP_SUFFIX_MAX (sizeof(".tmp.") - 1u + 10u)

fzn_socket_err_t fzn_socket_path_ok(const char *path)
{
	size_t len;

	if (!path)
		return FZN_SOCKET_ERR_MALFORMED;
	len = strlen(path);
	if (len == 0)
		return FZN_SOCKET_ERR_PATH;
	if (path[0] != '/')
		return FZN_SOCKET_ERR_PATH; /* a directory nobody controls */
	/* Strictly shorter than the field, since the terminator has to fit as
	 * well. Refused rather than truncated: a truncated path names a
	 * different socket, and possibly one somebody else can create first. */
	if (len + TMP_SUFFIX_MAX >= SUN_PATH_LEN)
		return FZN_SOCKET_ERR_PATH;
	return FZN_SOCKET_OK;
}

/* Fill in an address for a path the rule above has already passed, or for the
 * temporary name derived from one. The length guard stays here because that
 * temporary name is BUILT rather than given, and a built name is exactly the
 * kind that is right until the scheme producing it changes. */
static int fill_addr(struct sockaddr_un *addr, const char *path)
{
	size_t len = strlen(path);

	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	if (len == 0 || len >= SUN_PATH_LEN)
		return 0;
	memcpy(addr->sun_path, path, len);
	return 1;
}

fzn_socket_err_t fzn_socket_listen(const char *path, unsigned int mode, int backlog,
                                    int *out_fd)
{
	struct sockaddr_un addr, tmp_addr;
	char tmp_path[SUN_PATH_LEN];
	fzn_socket_err_t verdict;
	int fd;
	int n;

	if (!path || !out_fd)
		return FZN_SOCKET_ERR_MALFORMED;
	/* THE ONE STATEMENT OF THE RULE. Asked here rather than restated, so
	 * that a caller asking the same question ahead of time gets the same
	 * answer by construction rather than by two pieces of code agreeing. */
	verdict = fzn_socket_path_ok(path);
	if (verdict != FZN_SOCKET_OK)
		return verdict;
	if (!fill_addr(&addr, path))
		return FZN_SOCKET_ERR_PATH;

	if (in_use(&addr))
		return FZN_SOCKET_ERR_IN_USE;

	/* THE TEMPORARY NAME, in the same directory so the rename is within
	 * one filesystem. `.tmp.<pid>` rather than mkstemp: the entry is
	 * created by bind rather than by open, so there is nothing to hand a
	 * file descriptor to, and the name only has to be unpredictable enough
	 * that two instances do not collide. */
	n = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%ld", path, (long)getpid());
	if (n < 0 || (size_t)n >= sizeof(tmp_path))
		return FZN_SOCKET_ERR_PATH;
	if (!fill_addr(&tmp_addr, tmp_path))
		return FZN_SOCKET_ERR_PATH;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return FZN_SOCKET_ERR_SYSTEM;

	(void)unlink(tmp_path); /* our own name, from a previous run of this pid */
	if (bind(fd, (const struct sockaddr *)&tmp_addr, sizeof(tmp_addr)) != 0) {
		close(fd);
		return FZN_SOCKET_ERR_SYSTEM;
	}

	/* THE MODE, BEFORE THE PATH IS REACHABLE. bind applied the umask, so
	 * the entry may be more permissive than asked for -- but it is under a
	 * name no client knows, and the rename below is what publishes it. */
	if (chmod(tmp_path, (mode_t)mode) != 0) {
		close(fd);
		(void)unlink(tmp_path);
		return FZN_SOCKET_ERR_SYSTEM;
	}

	if (listen(fd, backlog) != 0) {
		close(fd);
		(void)unlink(tmp_path);
		return FZN_SOCKET_ERR_SYSTEM;
	}

	/* Atomic. A client connecting to `path` finds either the previous
	 * socket or this one, never a partly-configured entry. */
	if (rename(tmp_path, path) != 0) {
		close(fd);
		(void)unlink(tmp_path);
		return FZN_SOCKET_ERR_SYSTEM;
	}

	*out_fd = fd;
	return FZN_SOCKET_OK;
}

fzn_socket_err_t fzn_socket_accept(int listen_fd, int *out_fd, fzn_peer_t *out_peer)
{
	int fd;

	if (listen_fd < 0 || !out_fd || !out_peer)
		return FZN_SOCKET_ERR_MALFORMED;

	for (;;) {
		fd = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
		if (fd >= 0)
			break;
		/* A signal is not a failure of the socket. */
		if (errno == EINTR)
			continue;
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return FZN_SOCKET_ERR_AGAIN;
		return FZN_SOCKET_ERR_SYSTEM;
	}

	/* CREDENTIALS OR NOTHING. A descriptor whose peer cannot be identified
	 * is closed here rather than handed back: there is nothing safe to do
	 * with it, and returning it would invite a caller to try. */
	if (fzn_peer_from_fd(fd, out_peer) != 0) {
		close(fd);
		return FZN_SOCKET_ERR_SYSTEM;
	}

	*out_fd = fd;
	return FZN_SOCKET_OK;
}

void fzn_socket_close(int fd, const char *path)
{
	if (fd >= 0)
		close(fd);
	if (path)
		(void)unlink(path);
}

#else

fzn_socket_err_t fzn_socket_path_ok(const char *path)
{
	(void)path;
	return FZN_SOCKET_ERR_UNSUPPORTED;
}

fzn_socket_err_t fzn_socket_listen(const char *path, unsigned int mode, int backlog,
                                    int *out_fd)
{
	(void)path;
	(void)mode;
	(void)backlog;
	(void)out_fd;
	return FZN_SOCKET_ERR_UNSUPPORTED;
}

fzn_socket_err_t fzn_socket_accept(int listen_fd, int *out_fd, fzn_peer_t *out_peer)
{
	(void)listen_fd;
	(void)out_fd;
	(void)out_peer;
	return FZN_SOCKET_ERR_UNSUPPORTED;
}

void fzn_socket_close(int fd, const char *path)
{
	(void)fd;
	(void)path;
}

#endif
