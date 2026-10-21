/* A DAEMON WITH AN EXTENSION, sec 673: fuzznetd's node called with options
 * and verbs of this program's own, as fzpd will call it. `tool/live_ext.py`
 * starts it and asks.
 *
 *   --greeting=WORD   what `get greeting` answers; `--greeting=no` is
 *                     refused, ending the start
 *   --quiet           taken, and nothing else
 *
 *   get greeting      `ok WORD`, or `ok hello` with no --greeting
 *   get garbled       an answer outside the reply vocabulary, which
 *                     fuzznet must answer `error` in its place
 *   status,           answers this program gives and must never be
 *   list contact      asked for: fuzznet answers both itself, `list
 *                     contact` from the same chain of handlers it asks
 *                     this one after
 *
 * Anything else it declines, and fuzznet answers `unsupported`. A remote
 * request of type 128, the first of the extensions' range (`node/types.h`),
 * it answers with type 129 and the bytes it was sent; the rest of the range
 * it declines. */
#include "../daemon.h"

#include <stdio.h>
#include <string.h>

static char greeting[64] = "hello";

static const char *option(void *ctx, const char *name, const char *value)
{
	(void)ctx;
	if (strcmp(name, "--greeting") == 0) {
		if (!value || !*value || strlen(value) >= sizeof(greeting)
		    || strcspn(value, " %,\n") != strlen(value))
			return "a greeting is one word";
		if (strcmp(value, "no") == 0)
			return "this daemon will not say no";
		memcpy(greeting, value, strlen(value) + 1u);
	}
	return NULL;
}

static int is(const fzn_request_t *request, fzn_verb_t verb, const char *arg)
{
	return request->parsed == verb && request->arg && request->arg_len == strlen(arg)
	       && memcmp(request->arg, arg, request->arg_len) == 0;
}

static size_t local(void *ctx, fzn_origin_t origin, const fzn_request_t *request, char *reply,
                    size_t cap)
{
	int n = 0;

	(void)ctx;
	(void)origin;
	if (is(request, FZN_VERB_GET, "greeting"))
		n = snprintf(reply, cap, "ok %s\n", greeting);
	else if (is(request, FZN_VERB_GET, "garbled"))
		n = snprintf(reply, cap, "garbled words\n");
	else if (request->parsed == FZN_VERB_STATUS || is(request, FZN_VERB_LIST, "contact"))
		n = snprintf(reply, cap, "ok the extension answered\n");
	return n > 0 && (size_t)n < cap ? (size_t)n : 0u;
}

static size_t remote(void *ctx, const uint8_t sender[FZN_PUBKEY_LEN], int contact,
                     const uint8_t *request, size_t request_len, uint8_t *reply, size_t cap)
{
	(void)ctx;
	(void)sender;
	(void)contact;
	if (request_len < 2u || request[1] != 128u || request_len > cap)
		return 0;
	memcpy(reply, request, request_len);
	reply[1] = 129u;
	return request_len;
}

static const fzn_daemon_option_t options[] = {
	{ "--greeting", 1, "what `get greeting` answers" },
	{ "--quiet", 0, "taken, and nothing else" },
};

int main(int argc, char **argv)
{
	static const fzn_daemon_ext_t ext = {
		NULL, options, sizeof(options) / sizeof(options[0]), option, local, remote,
	};

	return fzn_daemon_main(argc, argv, &ext);
}
