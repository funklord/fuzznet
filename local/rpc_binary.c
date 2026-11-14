/* One request in binary on the local leg: local/rpc_binary.h, sec 1152. */
#include "rpc_binary.h"

#include "client.h"
#include "rpc_err.h"
#include "vocabulary.h"
#include "../wire/status.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

/* HOW LONG A NODE MAY TAKE to answer each message, as the text leg waits. */
#define BINARY_WAIT_MS 5000

static int binary_fail(fzn_rpc_t *c, int code, const char *text)
{
	c->error_code = code;
	snprintf(c->error, sizeof(c->error), "%s", text);
	return code;
}

/* The framed messages in `buf`, each handed on; 0 when one is cut short. A
 * STATUS malformed as the FIRST answer is a node that does not read this
 * request -- one from before its category -- and asks for text. */
static int hand_on(fzn_rpc_t *c, const uint8_t *buf, size_t len, fzn_rpc_binary_each_t each,
                   void *ctx, int *text, int *first)
{
	size_t at = 0;

	while (at < len) {
		size_t n;
		fzn_status_t code;
		const uint8_t *why = NULL;
		size_t why_len = 0;

		if (len - at < 2u || (n = ((size_t)buf[at] << 8) | buf[at + 1u]) == 0 || len - at - 2u < n)
			return 0;
		if (*first && fzn_status_read(buf + at + 2u, n, &code, &why, &why_len)
		    && code == FZN_STATUS_MALFORMED) {
			*text = 1;
			return 1;
		}
		*first = 0;
		c->answered = 1;
		each(ctx, buf + at + 2u, n);
		at += 2u + n;
	}
	return 1;
}

int fzn_rpc_binary(fzn_rpc_t *c, const uint8_t *msg, size_t len, fzn_rpc_binary_each_t each,
                   void *ctx, int *text)
{
	static uint8_t buf[2u * FZN_LOCAL_BINARY_MAX + 4u];
	uint8_t head[2];
	struct iovec io[2];
	struct msghdr m;
	size_t have = 0;
	int fd = -1, first = 1;
	ssize_t n;

	if (!c || !text || !each)
		return FZN_RPC_ERR_MALFORMED;
	*text = 0;
	c->error[0] = '\0';
	c->error_code = 0;
	c->answered = 0;
	if (!msg || !len || len > FZN_LOCAL_BINARY_MAX)
		return binary_fail(c, FZN_RPC_ERR_MALFORMED, "a binary request out of size");
	/* A SCRIPTED NODE: binary where it speaks binary, text where it does not. */
	if (c->binary_answer || c->answer) {
		size_t got = 0;
		int rc;

		if (!c->binary_answer) {
			*text = 1;
			return FZN_RPC_OK;
		}
		rc = c->binary_answer(c->binary_ctx, msg, len, buf, sizeof(buf), &got);
		if (rc != FZN_RPC_OK)
			return binary_fail(c, rc, "the node did not answer");
		return hand_on(c, buf, got, each, ctx, text, &first)
		               ? FZN_RPC_OK
		               : binary_fail(c, FZN_RPC_ERR_MALFORMED, "the node's answer was cut short");
	}
	if (!c->node_socket[0])
		return binary_fail(c, FZN_RPC_ERR_NO_PEER_TRANSPORT, "no node is set for this client");
	if (fzn_client_connect(c->node_socket, &fd) != FZN_CLIENT_OK)
		return binary_fail(c, FZN_RPC_ERR_SEND_FAILED, "the node is not running -- nothing answers there");
	head[0] = (uint8_t)(len >> 8);
	head[1] = (uint8_t)len;
	io[0].iov_base = head;
	io[0].iov_len = 2u;
	io[1].iov_base = (void *)(uintptr_t)msg;
	io[1].iov_len = len;
	memset(&m, 0, sizeof(m));
	m.msg_iov = io;
	m.msg_iovlen = 2;
	do
		n = sendmsg(fd, &m, MSG_NOSIGNAL);
	while (n < 0 && errno == EINTR);
	if (n != (ssize_t)(2u + len)) {
		(void)close(fd);
		return binary_fail(c, FZN_RPC_ERR_SEND_FAILED, "the node did not take the request");
	}
	/* EVERY ANSWER, handed on as each is whole, until the node closes. */
	for (;;) {
		struct pollfd p = { fd, POLLIN, 0 };
		size_t used = 0;

		if (poll(&p, 1, BINARY_WAIT_MS) <= 0) {
			(void)close(fd);
			return binary_fail(c, FZN_RPC_ERR_SEND_FAILED, "the node did not answer");
		}
		n = recv(fd, buf + have, sizeof(buf) - have, 0);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0) {
			(void)close(fd);
			return binary_fail(c, FZN_RPC_ERR_SEND_FAILED, "the node's answer was lost");
		}
		if (n == 0)
			break;
		have += (size_t)n;
		/* THE WHOLE MESSAGES SO FAR handed on, a part kept for the next read. */
		while (have - used >= 2u) {
			size_t one = ((size_t)buf[used] << 8) | buf[used + 1u];

			if (!one || one > FZN_LOCAL_BINARY_MAX) {
				(void)close(fd);
				return binary_fail(c, FZN_RPC_ERR_MALFORMED, "the node's answer did not parse");
			}
			if (have - used - 2u < one)
				break;
			if (!hand_on(c, buf + used, 2u + one, each, ctx, text, &first) || *text) {
				(void)close(fd);
				return FZN_RPC_OK;
			}
			used += 2u + one;
		}
		memmove(buf, buf + used, have - used);
		have -= used;
	}
	(void)close(fd);
	if (have)
		return binary_fail(c, FZN_RPC_ERR_MALFORMED, "the node's answer was cut short");
	if (first)
		return binary_fail(c, FZN_RPC_ERR_SEND_FAILED, "the node closed without an answer");
	return FZN_RPC_OK;
}
