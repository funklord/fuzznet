/* A call's media on a held channel, the typed client's half: local/rpc_media.h,
 * fuzznet sec 1113. The messages are node/live.h's, written and read by the
 * codec node/call.situ generates, so this side and the node's cannot differ. */
#include "rpc_media.h"

#include "client.h"
#include "rpc_err.h"
#include "../hex/hex.h"
#include "../node/live.h"
#include "../wire/status.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

_Static_assert(FZN_RPC_MEDIA_MAX == FZN_LIVE_MEDIA_MAX, "one most a whole frame carries");

static int media_fail(fzn_rpc_t *c, int code, const char *text)
{
	if (c) {
		c->error_code = code;
		snprintf(c->error, sizeof(c->error), "%s", text);
	}
	return code;
}

/* A MESSAGE, its two bytes of length first, written whole. */
static int framed_send(int fd, const uint8_t *msg, size_t len, int flags)
{
	uint8_t head[2] = { (uint8_t)(len >> 8), (uint8_t)len };
	struct iovec io[2] = { { head, 2u }, { (void *)(uintptr_t)msg, len } };
	struct msghdr m;
	ssize_t n;

	if (!len || len > FZN_LOCAL_BINARY_MAX)
		return 0;
	memset(&m, 0, sizeof(m));
	m.msg_iov = io;
	m.msg_iovlen = 2;
	do
		n = sendmsg(fd, &m, flags | MSG_NOSIGNAL);
	while (n < 0 && errno == EINTR);
	return n == (ssize_t)(2u + len);
}

/* `want` bytes, waited for up to `ms` in all. */
static int read_within(int fd, uint8_t *out, size_t want, int ms)
{
	size_t got = 0;

	while (got < want) {
		struct pollfd p = { fd, POLLIN, 0 };
		ssize_t n;

		if (poll(&p, 1, ms) <= 0)
			return 0;
		n = recv(fd, out + got, want - got, 0);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return 0;
		got += (size_t)n;
	}
	return 1;
}

int fzn_rpc_media_attach(fzn_rpc_t *c, fzn_rpc_media_t *m, int fd, const uint8_t call[8])
{
	uint8_t msg[FZN_LIVE_HEAD_LEN], head[2], answer[FZN_STATUS_LEN_MAX];
	fzn_live_word_t w;
	fzn_status_t code;
	const uint8_t *why = NULL;
	size_t why_len = 0, n, len;
	int flags;

	if (!m || fd < 0 || !call)
		return media_fail(c, FZN_RPC_ERR_MALFORMED, "no channel to open");
	memset(m, 0, sizeof(*m));
	m->fd = -1;
	memset(&w, 0, sizeof(w));
	w.kind = FZN_LIVE_MEDIA_OPEN;
	memcpy(w.call, call, sizeof(w.call));
	if (!(n = fzn_live_write(&w, msg, sizeof(msg))) || !framed_send(fd, msg, n, 0))
		return media_fail(c, FZN_RPC_ERR_SEND_FAILED, "the node did not take the channel's asking");
	/* THE NODE'S ANSWER, a STATUS, within five seconds. */
	if (!read_within(fd, head, 2u, 5000)
	    || (len = ((size_t)head[0] << 8) | head[1]) == 0 || len > sizeof(answer)
	    || !read_within(fd, answer, len, 5000))
		return media_fail(c, FZN_RPC_ERR_SEND_FAILED, "the node did not answer the channel's asking");
	if (!fzn_status_read(answer, len, &code, &why, &why_len))
		return media_fail(c, FZN_RPC_ERR_MALFORMED, "the node's answer did not parse");
	if (code != FZN_STATUS_OK) {
		char text[sizeof(((fzn_rpc_t *)0)->error)];

		snprintf(text, sizeof(text), "%.*s", (int)why_len, why ? (const char *)why : "");
		return media_fail(c, code == FZN_STATUS_DENIED ? FZN_RPC_ERR_NOT_AUTHORIZED
		                                              : FZN_RPC_ERR_STORAGE_IO,
		                  text[0] ? text : "the node refused the channel");
	}
	flags = fcntl(fd, F_GETFL, 0);
	(void)fcntl(fd, F_SETFL, flags < 0 ? O_NONBLOCK : flags | O_NONBLOCK);
	m->fd = fd;
	memcpy(m->call, call, sizeof(m->call));
	return FZN_RPC_OK;
}

int fzn_rpc_media_open(fzn_rpc_t *c, const char *call_hex, fzn_rpc_media_t *m)
{
	uint8_t call[8];
	int fd = -1, rc;

	if (!c || !call_hex || !m || strlen(call_hex) != 16u || fzn_hex_decode(call_hex, call, 8u) != 0)
		return media_fail(c, FZN_RPC_ERR_MALFORMED, "not a call's id");
	if (!c->node_socket[0])
		return media_fail(c, FZN_RPC_ERR_NO_PEER_TRANSPORT, "no node is set for this client");
	if (fzn_client_connect(c->node_socket, &fd) != FZN_CLIENT_OK)
		return media_fail(c, FZN_RPC_ERR_SEND_FAILED, "the node is not running -- nothing answers there");
	rc = fzn_rpc_media_attach(c, m, fd, call);
	if (rc != FZN_RPC_OK)
		(void)close(fd);
	return rc;
}

int fzn_rpc_media_fd(const fzn_rpc_media_t *m) { return m ? m->fd : -1; }

int fzn_rpc_media_send(fzn_rpc_media_t *m, uint8_t stream, uint32_t seq, uint32_t at_ms,
                       const uint8_t *media, size_t len)
{
	static uint8_t msg[FZN_LOCAL_BINARY_MAX];
	fzn_live_word_t w;
	size_t n;

	if (!m || m->fd < 0)
		return FZN_RPC_ERR_SEND_FAILED;
	if (!media || !len || len > FZN_RPC_MEDIA_MAX)
		return FZN_RPC_ERR_MALFORMED;
	memset(&w, 0, sizeof(w));
	w.kind = FZN_LIVE_MEDIA;
	memcpy(w.call, m->call, sizeof(w.call));
	w.stream = stream;
	w.seq = seq;
	w.at_ms = at_ms;
	w.media = media;
	w.media_len = len;
	if (!(n = fzn_live_write(&w, msg, sizeof(msg))))
		return FZN_RPC_ERR_MALFORMED;
	return framed_send(m->fd, msg, n, MSG_DONTWAIT) ? FZN_RPC_OK : FZN_RPC_ERR_SEND_FAILED;
}

int fzn_rpc_media_recv(fzn_rpc_media_t *m, fzn_rpc_media_frame_t *out)
{
	size_t total = 0;
	fzn_live_word_t w;

	if (!m || m->fd < 0 || !out)
		return FZN_RPC_ERR_SEND_FAILED;
	/* THE LAST FRAME HANDED OUT is dropped now, its media no longer held. */
	if (m->handed) {
		memmove(m->in, m->in + m->handed, m->in_len - m->handed);
		m->in_len -= m->handed;
		m->handed = 0;
	}
	for (;;) {
		ssize_t n;

		if (fzn_local_binary(m->in, m->in_len, &total) == 1 && total && m->in_len >= total)
			break;
		if (m->in_len == sizeof(m->in))
			return FZN_RPC_ERR_MALFORMED;
		n = recv(m->fd, m->in + m->in_len, sizeof(m->in) - m->in_len, MSG_DONTWAIT);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			return 0;
		if (n <= 0)
			return FZN_RPC_ERR_SEND_FAILED;
		m->in_len += (size_t)n;
	}
	if (!fzn_live_read_local(m->in + 2u, total - 2u, &w) || w.kind != FZN_LIVE_MEDIA) {
		memmove(m->in, m->in + total, m->in_len - total);
		m->in_len -= total;
		return 0;
	}
	/* HANDED OUT IN PLACE, and taken off at the next receive. */
	out->stream = w.stream;
	out->from = w.from;
	out->seq = w.seq;
	out->at_ms = w.at_ms;
	out->media = w.media;
	out->media_len = w.media_len;
	m->handed = total;
	return 1;
}

void fzn_rpc_media_close(fzn_rpc_media_t *m)
{
	if (m && m->fd >= 0) {
		(void)close(m->fd);
		m->fd = -1;
	}
}
