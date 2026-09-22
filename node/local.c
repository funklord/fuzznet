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
 * bound -- the line framer returns OVERLONG at the cap. The number is
 * `local/vocabulary.h`'s now, because `local/client.h` composes lines against
 * the same bound and a client guessing the server's cap is a client whose
 * too-long request comes back as a denial. */

size_t fzn_node_status_line(fzn_authz_verdict_t verdict, fzn_origin_t origin,
                            char *out, size_t cap)
{
	uint8_t detail[96];
	size_t len = 0;
	int n;

	if (!out || cap == 0)
		return 0;
	/* IT SPEAKS THE REPLY VOCABULARY SINCE sec 365, and `denied` needed no
	 * change: it was already the word, which is part of why that spelling
	 * was chosen for the enum rather than a new one invented beside it.
	 *
	 * The grant gained a leading `ok` and kept everything after it, so the
	 * line is ADDITIVE -- anything matching `served`, `origin N` or the
	 * version still matches -- while the first token is now readable by
	 * `fzn_reply_of` instead of by a substring search each consumer writes.
	 * `served` is redundant under `ok` and stays until consumers have
	 * moved; dropping it is a later change with a reason of its own. */
	/* A BYTE IS HELD BACK FOR THE TERMINATOR. `snprintf` wrote one and this
	 * function's callers have always had a C string; the composer does not,
	 * because a line on the wire is a length and not a string. Dropping the
	 * NUL would have been a silent change -- `local_test` caught it by
	 * reusing its buffer, where `strstr` read the PREVIOUS reply's text
	 * past the new one's end and reported an origin in a denial. So the
	 * guarantee is kept, and kept deliberately rather than by accident. */
	if (verdict == FZN_AUTHZ_DENIED) {
		if (fzn_reply_compose((uint8_t *)out, cap - 1u, &len,
		                      FZN_REPLY_DENIED, NULL, 0u) != FZN_COMPOSE_OK)
			return 0;
		out[len] = '\0';
		return len;
	}
	n = snprintf((char *)detail, sizeof(detail),
	             "served %s origin %d fuzznet %s",
	             fzn_authz_verdict_str(verdict), (int)origin,
	             fzn_version_string());
	/* A detail that did not fit is not truncated into a different one --
	 * `fzn_node_status_line` has always returned 0 rather than a clipped
	 * line, and the composer refuses the same way. */
	if (n < 0 || (size_t)n >= sizeof(detail))
		return 0;
	if (fzn_reply_compose((uint8_t *)out, cap - 1u, &len, FZN_REPLY_OK,
	                      detail, (size_t)n) != FZN_COMPOSE_OK)
		return 0;
	out[len] = '\0';
	return len;
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
                                          int fd, const fzn_peer_t *peer,
                                          fzn_node_local_handler_t on_local,
                                          void *ctx)
{
	fzn_origin_t origin;
	fzn_authz_verdict_t verdict;
	fzn_line_t reader;
	uint8_t buf[FZN_REQUEST_MAX];
	const uint8_t *line;
	size_t line_len;
	fzn_request_t request;
	char resp[FZN_NODE_LOCAL_REPLY_MAX];
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

	verdict = fzn_node_decide(config, origin, NULL, 0, 0, NULL, NULL, NULL);

	/* THE NODE SPLITS THE LINE, AND UNTIL sec 361 IT REFUSED TO. The comment
	 * here said a node that learned to split a request would have learned a
	 * grammar -- which was sec 5's struck claim wearing an argument. The
	 * verbs are fuzznet's, so finding where one ends is fuzznet's too, and
	 * a split done here once is a split three consumers do not each write.
	 *
	 * IT STOPS AT THE FIRST SPACE. What the ARGUMENT means is still the
	 * consumer's, and a library tokenising operands it cannot interpret
	 * would be the overreach the old comment was reaching for.
	 *
	 * A LINE WITH NO VERB IS NOT A REQUEST. `fzn_vocabulary_split` refuses
	 * an empty line, a line of spaces and an overlong verb, and the handler
	 * is not called for one -- there is nothing to hand it. The node still
	 * answers, with its status line, so a client that says nothing useful
	 * is told the node is there rather than left waiting.
	 *
	 * NOT ON A DENIAL. local.h records the divergence from `on_remote` and
	 * why the conservative direction is the right one here. */
	resp_len = 0;
	if (on_local && verdict != FZN_AUTHZ_DENIED &&
	    fzn_vocabulary_split(line, line_len, &request)) {
		size_t n = on_local(ctx, verdict, origin, peer, &request,
		                    resp, sizeof(resp));

		/* A handler claiming more than it was given wrote nothing this
		 * function may send. Sending `sizeof(resp)` of it instead would
		 * be a TRUNCATION, which is a different reply rather than a
		 * shorter one -- the same reason `fzn_node_status_line` returns
		 * 0 rather than a clipped line, and the reason
		 * `local/vocabulary.h` refuses an overlong verb instead of
		 * cutting it down to one that matches a rule. */
		if (n > 0 && n <= sizeof(resp))
			resp_len = n;
	}

	/* No handler, nothing written, or a reply that did not fit: the node
	 * answers for itself. A handler returning 0 is how a consumer asks for
	 * exactly that, so the default is reachable rather than only a
	 * fallback. */
	if (resp_len == 0)
		resp_len = fzn_node_status_line(verdict, origin, resp, sizeof(resp));
	if (resp_len == 0 || write_all(fd, resp, resp_len) != 0)
		return FZN_NODE_SERVE_IO;
	return (verdict == FZN_AUTHZ_DENIED) ? FZN_NODE_SERVE_DENIED
	                                     : FZN_NODE_SERVE_OK;
}
