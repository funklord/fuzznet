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

static int fill_addr(struct sockaddr_un *addr, const char *path)
{
	size_t len = strlen(path);

	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	/* Strictly shorter than the field, since the terminator has to fit.
	 * Refused rather than truncated: a truncated path names a different
	 * socket, and possibly one somebody else can create first. */
	if (len == 0 || len >= sizeof(addr->sun_path))
		return 0;
	if (path[0] != '/')
		return 0; /* relative to a working directory nobody controls */
	memcpy(addr->sun_path, path, len);
	return 1;
}

fzn_socket_err_t fzn_socket_listen(const char *path, unsigned int mode, int backlog,
                                    int *out_fd)
{
	struct sockaddr_un addr, tmp_addr;
	char tmp_path[sizeof(addr.sun_path)];
	int fd;
	int n;

	if (!path || !out_fd)
		return FZN_SOCKET_ERR_MALFORMED;
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
