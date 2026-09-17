/* See local.h. */

#include "local.h"

#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "../local/line.h"
#include "../version/version.h"

/* A request line longer than this is refused rather than grown without
 * bound -- the line framer returns OVERLONG at the cap. */
#define FZN_NODE_REQUEST_CAP 512u

size_t fzn_node_status_line(fzn_authz_verdict_t verdict, fzn_origin_t origin,
                            char *out, size_t cap)
{
	int n;

	if (!out || cap == 0)
		return 0;
	if (verdict == FZN_AUTHZ_DENIED)
		n = snprintf(out, cap, "denied\n");
	else
		n = snprintf(out, cap, "served %s origin %d fuzznet %s\n",
		             fzn_authz_verdict_str(verdict), (int)origin,
		             fzn_version_string());
	if (n < 0 || (size_t)n >= cap)
		return 0;
	return (size_t)n;
}

static int write_all(int fd, const char *buf, size_t len)
{
	size_t off = 0;

	while (off < len) {
		ssize_t n = write(fd, buf + off, len - off);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		off += (size_t)n;
	}
	return 0;
}

fzn_node_serve_err_t fzn_node_serve_local(const fzn_node_config_t *config,
                                          int fd, const fzn_peer_t *peer)
{
	fzn_origin_t origin;
	fzn_authz_verdict_t verdict;
	fzn_line_t reader;
	uint8_t buf[FZN_NODE_REQUEST_CAP];
	const uint8_t *line;
	size_t line_len;
	char resp[128];
	size_t resp_len;
	struct timeval tv;
	int have_line = 0;

	if (!config || fd < 0 || !peer)
		return FZN_NODE_SERVE_MALFORMED;

	/* A receive timeout so an idle or slow client cannot wedge the
	 * caller: the node serves one connection at a time, and a client
	 * that opens and says nothing must not hold it. */
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	origin = fzn_node_local_origin(config, peer);

	if (fzn_line_init(&reader, buf, sizeof(buf)) != FZN_LINE_OK)
		return FZN_NODE_SERVE_IO;
	while (!have_line) {
		uint8_t chunk[128];
		ssize_t n = read(fd, chunk, sizeof(chunk));

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return FZN_NODE_SERVE_IO;	/* includes the timeout */
		}
		if (n == 0)
			return FZN_NODE_SERVE_IO;	/* closed with no request */
		if (fzn_line_push(&reader, chunk, (size_t)n) != FZN_LINE_OK) {
			/* Overlong: refuse without reading more, and answer a
			 * denial so the client is not left waiting. */
			resp_len = fzn_node_status_line(FZN_AUTHZ_DENIED, origin,
			                                resp, sizeof(resp));
			(void)write_all(fd, resp, resp_len);
			return FZN_NODE_SERVE_DENIED;
		}
		have_line = fzn_line_next(&reader, &line, &line_len);
	}

	/* The request line is not parsed (see local.h). */
	(void)line;
	(void)line_len;

	verdict = fzn_node_decide(config, origin, NULL, 0, 0, NULL, NULL, NULL);
	resp_len = fzn_node_status_line(verdict, origin, resp, sizeof(resp));
	if (resp_len == 0 || write_all(fd, resp, resp_len) != 0)
		return FZN_NODE_SERVE_IO;
	return (verdict == FZN_AUTHZ_DENIED) ? FZN_NODE_SERVE_DENIED
	                                     : FZN_NODE_SERVE_OK;
}
