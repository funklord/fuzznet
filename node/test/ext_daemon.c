/* A DAEMON WITH AN EXTENSION, sec 673: fuzznetd's node called with options
 * and verbs of this program's own, as fzpd will call it. `tool/live_ext.py`
 * starts it and asks.
 *
 *   --greeting=WORD   what `get greeting` answers; `--greeting=no` is
 *                     refused, ending the start
 *   --quiet           taken, and nothing else
 *   --poke=PATH       a FIFO to watch among its own descriptors (sec 831);
 *                     of what is written there, `T<ms>\n` is a time on the
 *                     monotonic clock to measure the read's lateness
 *                     against, `L` asks the next tick for an in-process
 *                     `status`, and `S` stops the node (sec 835)
 *   --own-word=WORD   this program's own option, parsed here and NOT
 *                     handed to fuzznet, as netcfgd's are: kept over a
 *                     restart only through `restart_argv` (sec 835)
 *
 *   get greeting      `ok WORD`, or `ok hello` with no --greeting
 *   get garbled       an answer outside the reply vocabulary, which
 *                     fuzznet must answer `error` in its place
 *   add mark WORD     a journal record of kind 5, the consumer half's
 *                     (sec 675), written into this host's estate stream
 *   get marks         `ok N LAST`: the marks applied, from every host this
 *                     one follows, and the last one's word; `ok 0` for none
 *   get pokes         `ok N`: the bytes read from --poke's FIFO, each read
 *                     when the node's loop said it was readable
 *   get ticks         `ok N`: the times the node's loop called its tick
 *   get late          `ok MS`: the latest a `T` poke was read, past its time
 *   get inproc        the reply `fzn_daemon_local` gave the last `L`'s tick,
 *                     or `ok none`
 *   get nested        `ok N`: what `fzn_daemon_local` answers asked from
 *                     inside a local request, which must be 0
 *   get own           `ok WORD`, --own-word's, or `ok none`
 *   status,           answers this program gives and must never be
 *   list contact      asked for: fuzznet answers both itself, `list
 *                     contact` from the same chain of handlers it asks
 *                     this one after
 *
 * Anything else it declines, and fuzznet answers `unsupported`. A remote
 * request of type 128, the first of the extensions' range (`node/types.h`),
 * it answers with type 129 and the bytes it was sent; the rest of the range
 * it declines. */
#define _POSIX_C_SOURCE 200809L

#include "../daemon.h"
#include "../../wire/bytes.h"

#include <fcntl.h>
#include <sys/file.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static char greeting[64] = "hello";
static char own_word[32] = "none";

/* ITS OWN DESCRIPTOR AND TIMER, sec 831. The FIFO opened read and write,
 * so it is never at its end of file: opened to read alone, a FIFO whose
 * writer has gone is readable for ever, and the loop would spin. */
static char poke_path[256];
static int poke_fd = -1;
static unsigned long pokes, ticks;
/* WHAT THE POKES ASKED, sec 835. */
static char poke_line[32];
static size_t poke_line_len;
static unsigned long late_ms;
static int want_inproc;
static char inproc[256] = "ok none\n";

static unsigned long mono_ms(void)
{
	struct timespec ts;

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	return (unsigned long)ts.tv_sec * 1000ul + (unsigned long)ts.tv_nsec / 1000000ul;
}

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
	if (strcmp(name, "--poke") == 0) {
		if (!value || !*value || strlen(value) >= sizeof(poke_path))
			return "a poke is a FIFO's path";
		memcpy(poke_path, value, strlen(value) + 1u);
	}
	return NULL;
}

static size_t own_fds(void *ctx, int *out, size_t cap)
{
	(void)ctx;
	if (poke_fd < 0 && poke_path[0])
		poke_fd = open(poke_path, O_RDWR | O_NONBLOCK);
	if (poke_fd < 0 || cap < 1u)
		return 0;
	out[0] = poke_fd;
	return 1;
}

static void own_ready(void *ctx, int fd)
{
	char buf[256];
	ssize_t n, i;

	(void)ctx;
	if ((n = read(fd, buf, sizeof(buf))) <= 0)
		return;
	pokes += (unsigned long)n;
	/* ONLY WHAT `ready` MAY DO, sec 835: the bytes taken into memory, and
	 * a stop. */
	for (i = 0; i < n; i++) {
		char c = buf[i];

		if (poke_line_len) {
			if (c == '\n') {
				unsigned long at, now = mono_ms();

				poke_line[poke_line_len] = '\0';
				at = strtoul(poke_line + 1, NULL, 10);
				if (now > at && now - at > late_ms)
					late_ms = now - at;
				poke_line_len = 0;
			} else if (poke_line_len + 1u < sizeof(poke_line))
				poke_line[poke_line_len++] = c;
		} else if (c == 'T')
			poke_line[poke_line_len++] = c;
		else if (c == 'L')
			want_inproc = 1;
		else if (c == 'S')
			fzn_daemon_stop();
	}
}

static void own_tick(void *ctx, uint64_t now)
{
	(void)ctx;
	(void)now;
	ticks++;
	if (want_inproc) {
		size_t n = fzn_daemon_local("status", inproc, sizeof(inproc) - 1u);

		want_inproc = 0;
		if (n)
			inproc[n] = '\0';
		else
			(void)snprintf(inproc, sizeof(inproc), "ok refused\n");
	}
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
	else if (is(request, FZN_VERB_GET, "pokes"))
		n = snprintf(reply, cap, "ok %lu\n", pokes);
	else if (is(request, FZN_VERB_GET, "ticks"))
		n = snprintf(reply, cap, "ok %lu\n", ticks);
	else if (is(request, FZN_VERB_GET, "late"))
		n = snprintf(reply, cap, "ok %lu\n", late_ms);
	else if (is(request, FZN_VERB_GET, "inproc"))
		n = snprintf(reply, cap, "%s", inproc);
	else if (is(request, FZN_VERB_GET, "nested")) {
		char inner[64];

		n = snprintf(reply, cap, "ok %zu\n", fzn_daemon_local("status", inner, sizeof(inner)));
	} else if (is(request, FZN_VERB_GET, "own"))
		n = snprintf(reply, cap, "ok %s\n", own_word);
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
	{ "--poke", 1, "a FIFO to watch among its own descriptors" },
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
		settings, sizeof(settings) / sizeof(settings[0]), own_fds, own_ready, own_tick,
		NULL,
	};

	static char *given[64];
	int i, n = 0;

	if (getenv("FZN_EXT_CLASH"))
		ext.settings = clashing;
	/* ITS OWN OPTION TAKEN OUT, as netcfgd takes its own before calling
	 * the node, and the whole argv kept for a restart, sec 835. */
	if (argc >= (int)(sizeof(given) / sizeof(given[0])))
		return 2;
	for (i = 0; i < argc; i++) {
		if (strncmp(argv[i], "--own-word=", 11u) == 0) {
			if (strlen(argv[i] + 11) >= sizeof(own_word))
				return 2;
			memcpy(own_word, argv[i] + 11, strlen(argv[i] + 11) + 1u);
			continue;
		}
		given[n++] = argv[i];
	}
	given[n] = NULL;
	ext.restart_argv = argv;
	n = fzn_daemon_main(n, given, &ext);
	/* RETURNED FROM A STOP, sec 835: the socket and the face file are gone
	 * already, before this program's own shutdown work and its exit -- the
	 * atexit that removes the face at an exit is not what a follower can
	 * wait for. 3 when either is left. */
	for (i = 0; i < argc; i++) {
		char face[300];
		const char *dir = NULL, *sock = NULL;

		if (strncmp(argv[i], "--fuzznet-dir=", 14u) == 0)
			dir = argv[i] + 14;
		if (strncmp(argv[i], "--socket=", 9u) == 0)
			sock = argv[i] + 9;
		if (dir && (size_t)snprintf(face, sizeof(face), "%s/face", dir) < sizeof(face)
		    && access(face, F_OK) == 0) {
			fprintf(stderr, "ext_daemon: returned with %s left\n", face);
			return 3;
		}
		/* AND THE CLAIM FREE: a lock of this process's own, on another
		 * open of the file, is refused while the node still holds it. */
		if (dir && (size_t)snprintf(face, sizeof(face), "%s/claim", dir) < sizeof(face)) {
			int cfd = open(face, O_RDWR);

			if (cfd >= 0 && flock(cfd, LOCK_EX | LOCK_NB) != 0) {
				fprintf(stderr, "ext_daemon: returned with the claim held\n");
				return 3;
			}
			if (cfd >= 0)
				(void)close(cfd);
		}
		if (sock && access(sock, F_OK) == 0) {
			fprintf(stderr, "ext_daemon: returned with %s left\n", sock);
			return 3;
		}
	}
	return n;
}
