/* See client.h. */

#include "client.h"

#include "line.h"
#include "socket.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

const char *fzn_client_err_str(fzn_client_err_t err)
{
	switch (err) {
	case FZN_CLIENT_OK:
		return "ok";
	case FZN_CLIENT_ERR_MALFORMED:
		return "malformed";
	case FZN_CLIENT_ERR_PATH:
		return "path";
	case FZN_CLIENT_ERR_CONNECT:
		return "connect";
	case FZN_CLIENT_ERR_IO:
		return "io";
	case FZN_CLIENT_ERR_TIMEOUT:
		return "timeout";
	case FZN_CLIENT_ERR_REQUEST_TOO_LONG:
		return "request too long";
	case FZN_CLIENT_ERR_REPLY_TOO_LONG:
		return "reply too long";
	}
	/* Never NULL, including for a value outside the enum: client.h promises
	 * a caller may hand this straight to a printf. */
	return "unknown";
}

fzn_client_err_t fzn_client_compose(uint8_t *out, size_t cap, size_t *out_len,
                                    const uint8_t *verb, size_t verb_len,
                                    const uint8_t *arg, size_t arg_len)
{
	size_t need;
	size_t i;

	if (!out || !out_len || !verb)
		return FZN_CLIENT_ERR_MALFORMED;
	if (!arg && arg_len)
		return FZN_CLIENT_ERR_MALFORMED;
	if (verb_len == 0)
		return FZN_CLIENT_ERR_MALFORMED;
	if (verb_len > FZN_VERB_MAX)
		return FZN_CLIENT_ERR_REQUEST_TOO_LONG;
	/* A SPACE WOULD SPLIT THE VERB AND A NEWLINE WOULD SPLIT THE REQUEST.
	 * Either lets a caller send something the server reads as other than
	 * what was asked for -- a verb of "get x" arrives as `get` with an
	 * argument, past any rule written for the whole string, and a verb
	 * carrying a newline arrives as two lines. Refused rather than escaped,
	 * because an escape is a second grammar. */
	for (i = 0; i < verb_len; i++)
		if (verb[i] == (uint8_t)' ' || verb[i] == (uint8_t)'\n')
			return FZN_CLIENT_ERR_MALFORMED;

	/* verb, then a space and the argument only when there IS one, then the
	 * terminator. A NULL argument and an empty one differ by that space,
	 * which is the distinction `fzn_vocabulary_split` reads back. */
	need = verb_len + (arg ? 1u + arg_len : 0u) + 1u;
	if (need > FZN_REQUEST_MAX)
		return FZN_CLIENT_ERR_REQUEST_TOO_LONG;
	if (need > cap)
		return FZN_CLIENT_ERR_MALFORMED;

	memcpy(out, verb, verb_len);
	*out_len = verb_len;
	if (arg) {
		out[(*out_len)++] = (uint8_t)' ';
		if (arg_len)
			memcpy(out + *out_len, arg, arg_len);
		*out_len += arg_len;
	}
	out[(*out_len)++] = (uint8_t)'\n';
	return FZN_CLIENT_OK;
}

fzn_client_err_t fzn_client_connect(const char *path, int *out_fd)
{
	struct sockaddr_un addr;
	int fd;

	if (!path || !out_fd)
		return FZN_CLIENT_ERR_MALFORMED;
	/* ASKED BEFORE A DESCRIPTOR EXISTS, and asked of the module that owns
	 * the answer rather than re-derived here. A second opinion about what a
	 * usable path is would be a second thing to be wrong, and this one is
	 * already the listener's. */
	if (fzn_socket_path_ok(path) != FZN_SOCKET_OK)
		return FZN_CLIENT_ERR_PATH;
	if (strlen(path) >= sizeof(addr.sun_path))
		return FZN_CLIENT_ERR_PATH;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return FZN_CLIENT_ERR_IO;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, path, strlen(path));
	while (connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
		if (errno == EINTR)
			continue;
		(void)close(fd);
		return FZN_CLIENT_ERR_CONNECT;
	}
	*out_fd = fd;
	return FZN_CLIENT_OK;
}

static fzn_client_err_t write_all(int fd, const uint8_t *buf, size_t len)
{
	size_t off = 0;

	while (off < len) {
		ssize_t n = write(fd, buf + off, len - off);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return FZN_CLIENT_ERR_IO;
		}
		if (n == 0)
			return FZN_CLIENT_ERR_IO;
		off += (size_t)n;
	}
	return FZN_CLIENT_OK;
}

fzn_client_err_t fzn_client_send(int fd, const uint8_t *verb, size_t verb_len,
                                 const uint8_t *arg, size_t arg_len)
{
	uint8_t line[FZN_REQUEST_MAX];
	size_t line_len = 0;
	fzn_client_err_t err;

	if (fd < 0)
		return FZN_CLIENT_ERR_MALFORMED;
	err = fzn_client_compose(line, sizeof(line), &line_len, verb, verb_len,
	                         arg, arg_len);
	if (err != FZN_CLIENT_OK)
		return err;
	/* THE WHOLE LINE OR NOTHING USEFUL. A partial write leaves the server
	 * holding a prefix it will frame as soon as a newline arrives from
	 * somewhere -- which on a stream socket means the NEXT request's bytes
	 * complete this one. The caller is told IO and the connection is not
	 * reusable, which is honest: what the server has is not what was sent. */
	return write_all(fd, line, line_len);
}

fzn_client_err_t fzn_client_send_verb(int fd, fzn_verb_t verb,
                                      const uint8_t *arg, size_t arg_len)
{
	const char *name = fzn_verb_name(verb);

	/* FZN_VERB_NONE names nothing to send. It is a fine thing to RECEIVE --
	 * it is how a consumer's own verb reads on the server side -- but a
	 * caller asking this to send "not one of fuzznet's" has not said what
	 * it wants, and guessing would be inventing a verb. */
	if (!name)
		return FZN_CLIENT_ERR_MALFORMED;
	return fzn_client_send(fd, (const uint8_t *)name, fzn_verb_name_len(verb),
	                       arg, arg_len);
}

fzn_client_err_t fzn_client_recv(int fd, uint8_t *reply, size_t cap,
                                 size_t *reply_len, unsigned timeout_ms)
{
	fzn_line_t reader;
	const uint8_t *line = NULL;
	size_t line_len = 0;
	struct timeval tv;

	if (fd < 0 || !reply || cap == 0 || !reply_len)
		return FZN_CLIENT_ERR_MALFORMED;
	*reply_len = 0;
	if (timeout_ms) {
		tv.tv_sec = (time_t)(timeout_ms / 1000u);
		tv.tv_usec = (suseconds_t)((timeout_ms % 1000u) * 1000u);
		(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}
	/* FRAMED INTO THE CALLER'S OWN BUFFER, so a reply longer than the
	 * caller allowed is refused by the framer rather than by a length check
	 * after the fact -- there is nowhere for the excess to have been put. */
	if (fzn_line_init(&reader, reply, cap) != FZN_LINE_OK)
		return FZN_CLIENT_ERR_MALFORMED;
	for (;;) {
		uint8_t chunk[128];
		ssize_t n = read(fd, chunk, sizeof(chunk));

		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return FZN_CLIENT_ERR_TIMEOUT;
			return FZN_CLIENT_ERR_IO;
		}
		if (n == 0)
			return FZN_CLIENT_ERR_IO;	/* closed with no reply */
		if (fzn_line_push(&reader, chunk, (size_t)n) != FZN_LINE_OK)
			return FZN_CLIENT_ERR_REPLY_TOO_LONG;
		if (fzn_line_next(&reader, &line, &line_len)) {
			*reply_len = line_len;
			return FZN_CLIENT_OK;
		}
	}
}

void fzn_client_close(int fd)
{
	if (fd >= 0)
		(void)close(fd);
}
