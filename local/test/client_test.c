/* The local-socket client: the grammar it composes, and one real exchange
 * over a real listener.
 *
 * THE HEADLINE PROPERTY IS THE ROUND TRIP. `fzn_client_compose` writes the
 * line and `fzn_vocabulary_split` reads it, and they are the two halves of
 * one wire format -- so the cases below compose and then split, and compare
 * against what went IN rather than against a second copy of the format
 * written here. A test that spelled the expected bytes out would be a third
 * statement of the grammar, and the one most likely to be wrong.
 */

#define _DEFAULT_SOURCE /* mkdtemp under -std=c11 */

#include "../client.h"
#include "../socket.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int checks;
static int failures;

static void ok_at(int cond, int line, const char *what)
{
	checks++;
	if (!cond) {
		failures++;
		printf("  FAIL client_test.c:%d: %s\n", line, what);
	}
}

#define ok(c, what) ok_at((c) ? 1 : 0, __LINE__, (what))

/* Compose, then split, and require the pieces to be what went in. */
static int round_trips(const char *verb, const char *arg, int have_arg)
{
	uint8_t line[FZN_REQUEST_MAX];
	size_t len = 0;
	fzn_request_t req;
	size_t vl = strlen(verb);
	size_t al = have_arg ? strlen(arg) : 0u;

	if (fzn_client_compose(line, sizeof(line), &len, (const uint8_t *)verb, vl,
	                       have_arg ? (const uint8_t *)arg : NULL, al)
	    != FZN_CLIENT_OK)
		return 0;
	/* The terminator is the client's to write and the framer's to strip, so
	 * the split sees the line without it -- which is what `local/line.h`
	 * hands `node/local.c`. */
	if (len == 0 || line[len - 1u] != (uint8_t)'\n')
		return 0;
	if (!fzn_vocabulary_split(line, len - 1u, &req))
		return 0;
	if (req.verb_len != vl || memcmp(req.verb, verb, vl) != 0)
		return 0;
	if (have_arg) {
		if (req.arg == NULL || req.arg_len != al)
			return 0;
		if (al && memcmp(req.arg, arg, al) != 0)
			return 0;
	} else if (req.arg != NULL) {
		return 0;
	}
	return 1;
}

int main(void)
{
	/* The round trip, over the cases that differ in how the argument is
	 * carried -- absent, empty, present, and containing the separator. */
	ok(round_trips("status", NULL, 0), "a verb with no argument did not round-trip");
	ok(round_trips("get", "thing", 1), "a verb and argument did not round-trip");
	ok(round_trips("get", "", 1),
	   "an EMPTY argument did not round-trip -- `get ` and `get` are different "
	   "requests and the client must be able to say both");
	ok(round_trips("set", "a b c", 1),
	   "an argument containing spaces did not round-trip, so one of the two "
	   "halves is tokenising past the first space");
	ok(round_trips("destroy", "raid0", 1),
	   "a consumer's own verb did not round-trip, which sec 298's "
	   "bypass-until-gained needs");

	/* What compose must refuse. A space or a newline inside the verb are the
	 * two that change what the server reads. */
	{
		uint8_t line[FZN_REQUEST_MAX];
		size_t len = 0;
		uint8_t big[FZN_REQUEST_MAX + 8];

		memset(big, 'a', sizeof(big));
		ok(fzn_client_compose(line, sizeof(line), &len,
		                      (const uint8_t *)"", 0u, NULL, 0u)
		       == FZN_CLIENT_ERR_MALFORMED, "an empty verb composed");
		ok(fzn_client_compose(line, sizeof(line), &len,
		                      (const uint8_t *)"get x", 5u, NULL, 0u)
		       == FZN_CLIENT_ERR_MALFORMED,
		   "a verb containing a space composed -- it would arrive as a "
		   "shorter verb with an argument, past any rule written for the "
		   "whole string");
		ok(fzn_client_compose(line, sizeof(line), &len,
		                      (const uint8_t *)"get\nset", 7u, NULL, 0u)
		       == FZN_CLIENT_ERR_MALFORMED,
		   "a verb containing a newline composed -- one request would arrive "
		   "as two");
		ok(fzn_client_compose(line, sizeof(line), &len, big,
		                      (size_t)FZN_VERB_MAX + 1u, NULL, 0u)
		       == FZN_CLIENT_ERR_REQUEST_TOO_LONG, "an overlong verb composed");
		ok(fzn_client_compose(line, sizeof(line), &len,
		                      (const uint8_t *)"get", 3u, big, sizeof(big))
		       == FZN_CLIENT_ERR_REQUEST_TOO_LONG,
		   "a line past FZN_REQUEST_MAX composed, so the server's overlong "
		   "refusal would come back as a denial instead");
		ok(fzn_client_compose(line, 2u, &len, (const uint8_t *)"status", 6u,
		                      NULL, 0u) == FZN_CLIENT_ERR_MALFORMED,
		   "a line was written into a buffer too small for it");
		ok(fzn_client_compose(NULL, sizeof(line), &len,
		                      (const uint8_t *)"get", 3u, NULL, 0u)
		       == FZN_CLIENT_ERR_MALFORMED, "a NULL output composed");
		ok(fzn_client_compose(line, sizeof(line), &len,
		                      (const uint8_t *)"get", 3u, NULL, 4u)
		       == FZN_CLIENT_ERR_MALFORMED,
		   "a NULL argument with a non-zero length composed");
	}

	/* The exact bytes, once, so the round trip above is anchored to
	 * something and not merely self-consistent. If both halves of the
	 * grammar changed together every case above would still pass. */
	{
		uint8_t line[FZN_REQUEST_MAX];
		size_t len = 0;

		ok(fzn_client_compose(line, sizeof(line), &len,
		                      (const uint8_t *)"get", 3u,
		                      (const uint8_t *)"x", 1u) == FZN_CLIENT_OK &&
		   len == 6u && memcmp(line, "get x\n", 6u) == 0,
		   "the composed bytes are not `get x` and a newline");
	}

	/* err_str answers for every enumerator and for a value outside it. */
	{
		int i;
		int all = 1;

		for (i = 0; i >= -7; i--)
			if (fzn_client_err_str((fzn_client_err_t)i) == NULL)
				all = 0;
		ok(all, "an error code rendered as NULL");
		ok(fzn_client_err_str((fzn_client_err_t)-99) != NULL,
		   "a value outside the enum rendered as NULL, which client.h says "
		   "cannot happen because a caller may printf it directly");
	}

	/* ONE REAL EXCHANGE over a real listener: connect, send, the server
	 * accepts and reads the line, answers, and the client reads it back. */
	{
		char dir[] = "/tmp/fzn_client_test_XXXXXX";
		char path[128];
		int listen_fd = -1, srv = -1, cfd = -1;
		fzn_peer_t peer;

		if (!mkdtemp(dir)) {
			ok(0, "a temporary directory could not be made");
		} else {
			uint8_t got[FZN_REQUEST_MAX];
			uint8_t reply[128];
			size_t reply_len = 0;
			ssize_t n;

			snprintf(path, sizeof(path), "%s/sock", dir);
			ok(fzn_socket_listen(path, 0600u, 4, &listen_fd)
			       == FZN_SOCKET_OK, "the listener would not bind");
			ok(fzn_client_connect(path, &cfd) == FZN_CLIENT_OK,
			   "the client would not connect");
			ok(fzn_client_send_verb(cfd, FZN_VERB_STATUS,
			                        (const uint8_t *)"disks", 5u)
			       == FZN_CLIENT_OK, "the client would not send");
			ok(fzn_socket_accept(listen_fd, &srv, &peer) == FZN_SOCKET_OK,
			   "the listener would not accept");
			n = read(srv, got, sizeof(got));
			ok(n == 13 && memcmp(got, "status disks\n", 13u) == 0,
			   "the server did not receive `status disks` and a newline");

			(void)write(srv, "ok\n", 3u);
			ok(fzn_client_recv(cfd, reply, sizeof(reply), &reply_len, 2000u)
			       == FZN_CLIENT_OK && reply_len == 2u &&
			   memcmp(reply, "ok", 2u) == 0,
			   "the client did not read the reply with its terminator "
			   "stripped");

			/* A daemon that says nothing: the client gives up rather than
			 * waiting on it. */
			ok(fzn_client_recv(cfd, reply, sizeof(reply), &reply_len, 200u)
			       == FZN_CLIENT_ERR_TIMEOUT,
			   "a silent daemon did not time the client out");

			/* A reply longer than the caller allowed is refused whole: a
			 * prefix of a reply is a different reply. */
			(void)write(srv, "0123456789abcdef\n", 17u);
			ok(fzn_client_recv(cfd, reply, 8u, &reply_len, 2000u)
			       == FZN_CLIENT_ERR_REPLY_TOO_LONG &&
			   reply_len == 0u,
			   "an over-long reply was accepted or reported a length");

			fzn_client_close(cfd);
			if (srv >= 0)
				(void)close(srv);
			fzn_socket_close(listen_fd, path);
			(void)rmdir(dir);
		}
	}

	/* Refusals that need no socket. */
	ok(fzn_client_send_verb(-1, FZN_VERB_NONE, NULL, 0u)
	       == FZN_CLIENT_ERR_MALFORMED,
	   "FZN_VERB_NONE was sent -- it names nothing, and guessing would be "
	   "inventing a verb");
	ok(fzn_client_connect(NULL, NULL) == FZN_CLIENT_ERR_MALFORMED,
	   "a NULL path connected");

	printf("client_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
