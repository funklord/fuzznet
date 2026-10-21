/* POSIX: getaddrinfo, and non-blocking set by fcntl rather than by
 * SOCK_NONBLOCK, which is Linux's and the BSDs'. */
#define _POSIX_C_SOURCE 200809L

#include "gpsd.h"
#include "tpv.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define WATCH "?WATCH={\"enable\":true,\"json\":true}\n"

int fzn_gpsd_init(fzn_gpsd_t *g, const char *host, uint16_t port)
{
	size_t n = host ? strlen(host) : 0u;

	if (!g || !n || n > FZN_GPSD_HOST_MAX || !port)
		return 0;
	memset(g, 0, sizeof(*g));
	memcpy(g->host, host, n + 1u);
	g->port = port;
	g->fd = -1;
	g->link = FZN_GPSD_DISCONNECTED;
	return 1;
}

void fzn_gpsd_close(fzn_gpsd_t *g)
{
	if (!g)
		return;
	if (g->fd >= 0)
		(void)close(g->fd);
	g->fd = -1;
	g->link = FZN_GPSD_DISCONNECTED;
	g->buf_len = 0;
}

fzn_gpsd_link_t fzn_gpsd_link(const fzn_gpsd_t *g)
{
	return g ? g->link : FZN_GPSD_DISCONNECTED;
}

static void begin(fzn_gpsd_t *g)
{
	struct addrinfo hints, *res = NULL;
	char port[8];
	int fd;

	(void)snprintf(port, sizeof(port), "%u", (unsigned)g->port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	/* A NAME, NOT ONLY A NUMBER: localhost is the default, and a lookup
	 * of it does not leave the machine. */
	if (getaddrinfo(g->host, port, &hints, &res) != 0 || !res)
		return;
	fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (fd < 0) {
		freeaddrinfo(res);
		return;
	}
	if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) != 0
	    || fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
		(void)close(fd);
		freeaddrinfo(res);
		return;
	}
	if (connect(fd, res->ai_addr, res->ai_addrlen) == 0 || errno == EINPROGRESS) {
		g->fd = fd;
		g->link = FZN_GPSD_CONNECTING;
	} else {
		(void)close(fd);
	}
	freeaddrinfo(res);
}

static void watch(fzn_gpsd_t *g)
{
	int err = 0;
	socklen_t err_len = sizeof(err);
	ssize_t w;

	if (getsockopt(g->fd, SOL_SOCKET, SO_ERROR, &err, &err_len) != 0 || err != 0) {
		fzn_gpsd_close(g);
		return;
	}
	/* A gpsd GONE is EPIPE, not SIGPIPE, where the system can say so. */
#ifdef MSG_NOSIGNAL
	w = send(g->fd, WATCH, sizeof(WATCH) - 1u, MSG_NOSIGNAL);
#else
	w = send(g->fd, WATCH, sizeof(WATCH) - 1u, 0);
#endif
	if (w == (ssize_t)(sizeof(WATCH) - 1u)) {
		g->link = FZN_GPSD_WATCHING;
		return;
	}
	/* NOT CONNECTED YET is still connecting; anything else is down. */
	if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOTCONN))
		return;
	fzn_gpsd_close(g);
}

static void drain(fzn_gpsd_t *g)
{
	for (;;) {
		size_t start = 0, i;
		ssize_t r;

		/* A LINE PAST THE BUFFER is dropped, and reading starts over at
		 * the next newline, rather than the link wedging. */
		if (g->buf_len == sizeof(g->buf))
			g->buf_len = 0;
		r = recv(g->fd, g->buf + g->buf_len, sizeof(g->buf) - g->buf_len, 0);
		if (r == 0) {
			fzn_gpsd_close(g);
			return;
		}
		if (r < 0) {
			if (errno == EINTR)
				continue;
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				fzn_gpsd_close(g);
			return;
		}
		g->buf_len += (size_t)r;
		for (i = 0; i < g->buf_len; i++) {
			fzn_location_fix_t fix;

			if (g->buf[i] != '\n')
				continue;
			if (fzn_location_tpv_parse(g->buf + start, i - start, &fix) == 1) {
				g->latest = fix;
				g->have_latest = 1;
			}
			start = i + 1u;
		}
		if (start) {
			memmove(g->buf, g->buf + start, g->buf_len - start);
			g->buf_len -= start;
		}
	}
}

int fzn_gpsd_poll(fzn_gpsd_t *g, fzn_location_fix_t *out)
{
	if (!g || !out)
		return 0;
	if (g->link == FZN_GPSD_DISCONNECTED)
		begin(g);
	if (g->link == FZN_GPSD_CONNECTING)
		watch(g);
	if (g->link == FZN_GPSD_WATCHING)
		drain(g);
	if (!g->have_latest)
		return 0;
	*out = g->latest;
	g->have_latest = 0;
	return 1;
}
