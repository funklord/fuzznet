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
 *   add mark WORD     a journal record of kind 5, the consumer half's
 *                     (sec 675), written into this host's estate stream
 *   get marks         `ok N LAST`: the marks applied, from every host this
 *                     one follows, and the last one's word; `ok 0` for none
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
#include "../../wire/bytes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char greeting[64] = "hello";

/* THE MARKS APPLIED, each kept once: a start replays the journal from the
 * beginning and hands every one over again. */
#define MARK_KIND 5u
#define MARKS_MAX 32u
static struct {
	uint8_t signer[FZN_PUBKEY_LEN];
	char word[32];
} marks[MARKS_MAX];
static size_t n_marks, last_mark = (size_t)-1;

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
	else if (request->parsed == FZN_VERB_ADD && request->arg && request->arg_len > 5u
	         && request->arg_len < 5u + 32u && memcmp(request->arg, "mark ", 5u) == 0) {
		uint8_t object[2u + 32u];
		size_t w = request->arg_len - 5u;

		object[0] = FZN_SIGNED_VERSION;
		object[1] = (uint8_t)MARK_KIND;
		memcpy(object + 2, request->arg + 5, w);
		n = fzn_daemon_journal_append(object, 2u + w)
		    ? snprintf(reply, cap, "ok\n")
		    : snprintf(reply, cap, "error the mark was not written\n");
	} else if (is(request, FZN_VERB_GET, "marks"))
		n = n_marks ? snprintf(reply, cap, "ok %zu %s\n", n_marks, marks[last_mark].word)
		            : snprintf(reply, cap, "ok 0\n");
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

static int apply(void *ctx, uint32_t kind, const uint8_t *body, size_t len,
                 const uint8_t signer[FZN_PUBKEY_LEN])
{
	size_t i, w = len - 2u;

	(void)ctx;
	if (kind != MARK_KIND || len < 3u || w >= sizeof(marks[0].word))
		return 0;
	for (i = 0; i < n_marks; i++)
		if (memcmp(marks[i].signer, signer, FZN_PUBKEY_LEN) == 0
		    && strlen(marks[i].word) == w && memcmp(marks[i].word, body + 2, w) == 0) {
			last_mark = i;
			return 1;
		}
	if (n_marks == MARKS_MAX)
		return 0;
	memcpy(marks[n_marks].signer, signer, FZN_PUBKEY_LEN);
	memcpy(marks[n_marks].word, body + 2, w);
	marks[n_marks].word[w] = '\0';
	last_mark = n_marks++;
	return 1;
}

static const fzn_daemon_option_t options[] = {
	{ "--greeting", 1, "what `get greeting` answers" },
	{ "--quiet", 0, "taken, and nothing else" },
};

/* ITS SETTINGS, sec 686: one of its own, and -- with FZN_EXT_CLASH set in
 * the environment -- one that claims fuzznet's, which must end the start. */
static const fzn_schema_entry_t settings[] = {
	{ "ext/greeting", FZN_SCHEMA_TEXT, FZN_SCHEMA_HOST, 1u, 16u, "hello", "", 0u,
	  "a greeting the extension may read", NULL },
};
static const fzn_schema_entry_t clashing[] = {
	{ "location/enabled", FZN_SCHEMA_FLAG, FZN_SCHEMA_HOST, 0u, 0u, "off", "", 0u,
	  "fuzznet's, claimed", NULL },
};

int main(int argc, char **argv)
{
	static fzn_daemon_ext_t ext = {
		NULL, options, sizeof(options) / sizeof(options[0]), option, local, remote, apply,
		settings, sizeof(settings) / sizeof(settings[0]),
	};

	if (getenv("FZN_EXT_CLASH"))
		ext.settings = clashing;
	return fzn_daemon_main(argc, argv, &ext);
}
