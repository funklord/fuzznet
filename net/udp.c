/* See udp.h. */

#include "udp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* MSG_TRUNC's "report the true length" behaviour on a datagram is Linux's.
 * Where it is absent, fall back to 0 (a no-op flag): a caller passing a
 * frame-sized buffer cannot then be handed a truncated legitimate frame,
 * because none is larger than the buffer. */
#ifndef MSG_TRUNC
#define MSG_TRUNC 0
#endif

/* The opaque address is exactly a sockaddr_storage. Refuse to build if the
 * platform's is larger, rather than silently truncate an address. */
_Static_assert(sizeof(struct sockaddr_storage) <=
               sizeof(((fzn_udp_addr_t *)0)->storage),
               "fzn_udp_addr storage smaller than sockaddr_storage");

/* Close-on-exec without SOCK_CLOEXEC, which is not POSIX. */
static int set_cloexec(int fd)
{
	int flags = fcntl(fd, F_GETFD);

	if (flags < 0)
		return -1;
	return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

fzn_udp_err_t fzn_udp_bind(int family, const char *addr, uint16_t port,
                           int *out_fd)
{
	struct sockaddr_storage ss;
	socklen_t sslen;
	int fd;

	if (!out_fd)
		return FZN_UDP_ERR_MALFORMED;
	if (family != AF_INET && family != AF_INET6)
		return FZN_UDP_ERR_MALFORMED;

	memset(&ss, 0, sizeof(ss));
	if (family == AF_INET) {
		struct sockaddr_in *v4 = (struct sockaddr_in *)&ss;
		v4->sin_family = AF_INET;
		v4->sin_port = htons(port);
		if (!addr)
			v4->sin_addr.s_addr = htonl(INADDR_ANY);
		else if (inet_pton(AF_INET, addr, &v4->sin_addr) != 1)
			return FZN_UDP_ERR_ADDR;
		sslen = sizeof(*v4);
	} else {
		struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&ss;
		v6->sin6_family = AF_INET6;
		v6->sin6_port = htons(port);
		if (!addr)
			v6->sin6_addr = in6addr_any;
		else if (inet_pton(AF_INET6, addr, &v6->sin6_addr) != 1)
			return FZN_UDP_ERR_ADDR;
		sslen = sizeof(*v6);
	}

	fd = socket(family, SOCK_DGRAM, 0);
	if (fd < 0)
		return FZN_UDP_ERR_SYSTEM;
	if (set_cloexec(fd) != 0) {
		close(fd);
		return FZN_UDP_ERR_SYSTEM;
	}

	/* An AF_INET6 socket carries v4 too by default on many systems,
	 * through v4-mapped addresses. Refuse that: a node opens one socket
	 * per family (udp.h), and an overlap makes which socket a v4 packet
	 * lands on a platform default rather than the caller's choice. */
	if (family == AF_INET6) {
		int on = 1;
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on,
		               sizeof(on)) != 0) {
			close(fd);
			return FZN_UDP_ERR_SYSTEM;
		}
	}

	if (bind(fd, (const struct sockaddr *)&ss, sslen) != 0) {
		close(fd);
		return FZN_UDP_ERR_SYSTEM;
	}

	*out_fd = fd;
	return FZN_UDP_OK;
}

fzn_udp_err_t fzn_udp_resolve(int family, const char *host, uint16_t port,
                              fzn_udp_addr_t *out)
{
	if (!host || !out)
		return FZN_UDP_ERR_MALFORMED;
	if (family != AF_INET && family != AF_INET6)
		return FZN_UDP_ERR_MALFORMED;

	memset(out, 0, sizeof(*out));
	if (family == AF_INET) {
		struct sockaddr_in v4;

		memset(&v4, 0, sizeof(v4));
		v4.sin_family = AF_INET;
		v4.sin_port = htons(port);
		if (inet_pton(AF_INET, host, &v4.sin_addr) != 1)
			return FZN_UDP_ERR_ADDR;
		memcpy(out->storage, &v4, sizeof(v4));
		out->len = sizeof(v4);
	} else {
		struct sockaddr_in6 v6;

		memset(&v6, 0, sizeof(v6));
		v6.sin6_family = AF_INET6;
		v6.sin6_port = htons(port);
		if (inet_pton(AF_INET6, host, &v6.sin6_addr) != 1)
			return FZN_UDP_ERR_ADDR;
		memcpy(out->storage, &v6, sizeof(v6));
		out->len = sizeof(v6);
	}
	return FZN_UDP_OK;
}

fzn_udp_err_t fzn_udp_send(int fd, const fzn_udp_addr_t *to,
                           const uint8_t *frame, size_t len)
{
	ssize_t n;

	if (fd < 0 || !to || !frame || len == 0)
		return FZN_UDP_ERR_MALFORMED;
	if (to->len == 0 || to->len > sizeof(to->storage))
		return FZN_UDP_ERR_MALFORMED;
	/* One frame per datagram, never fragmented (udp.h). A frame the seal
	 * could not have produced is refused here rather than handed to IP
	 * to fragment. */
	if (len > FZN_UDP_DATAGRAM_MAX)
		return FZN_UDP_ERR_OVERSIZED;

	for (;;) {
		n = sendto(fd, frame, len, 0,
		           (const struct sockaddr *)to->storage,
		           (socklen_t)to->len);
		if (n >= 0)
			break;
		if (errno == EINTR)
			continue;
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return FZN_UDP_ERR_AGAIN;
		return FZN_UDP_ERR_SYSTEM;
	}
	/* A datagram is sent whole or not at all; a short count is not the
	 * frame we were asked to send. */
	if ((size_t)n != len)
		return FZN_UDP_ERR_SYSTEM;
	return FZN_UDP_OK;
}

fzn_udp_err_t fzn_udp_recv(int fd, uint8_t *buf, size_t cap, size_t *len,
                           fzn_udp_addr_t *from)
{
	struct sockaddr_storage ss;
	socklen_t sslen;
	ssize_t n;

	if (fd < 0 || !buf || !len || cap == 0)
		return FZN_UDP_ERR_MALFORMED;

	for (;;) {
		sslen = sizeof(ss);
		/* MSG_TRUNC so a datagram larger than cap reports its true
		 * length rather than the copied prefix: a truncated frame is a
		 * different frame, and one an attacker can arrange, so it is
		 * refused below rather than parsed. */
		n = recvfrom(fd, buf, cap, MSG_TRUNC,
		             (struct sockaddr *)&ss, &sslen);
		if (n >= 0)
			break;
		if (errno == EINTR)
			continue;
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return FZN_UDP_ERR_AGAIN;
		return FZN_UDP_ERR_SYSTEM;
	}

	if ((size_t)n > cap)
		return FZN_UDP_ERR_TRUNCATED;

	*len = (size_t)n;
	if (from) {
		memset(from, 0, sizeof(*from));
		if ((size_t)sslen > sizeof(from->storage))
			return FZN_UDP_ERR_SYSTEM;
		memcpy(from->storage, &ss, sslen);
		from->len = (unsigned int)sslen;
	}
	return FZN_UDP_OK;
}

void fzn_udp_close(int fd)
{
	if (fd >= 0)
		close(fd);
}
