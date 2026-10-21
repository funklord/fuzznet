/*
 * FUZZNETD'S NODE AS A CALL, sec 666 stage 3 (sec 670): everything fuzznetd
 * does -- its options, its store, the claim and the face or follower it
 * makes this process, the local and remote hops and the rounds -- behind
 * one function, so another daemon of the same identity's work (fzpd, sec
 * 666) runs this node rather than a copy of it. fuzznetd's own main is a
 * call to it with no extension.
 *
 * ONCE PER PROCESS, and it does not return while it serves: it reads its
 * options from `argv` as fuzznetd's command line, keeps `argv` to start
 * again in place (sec 638), installs signal handlers and an atexit, and
 * answers the process's exit status.
 */
#ifndef FZN_NODE_DAEMON_H
#define FZN_NODE_DAEMON_H

#include <stddef.h>

#include "../chain/authz.h"
#include "../local/vocabulary.h"

/* AN OPTION A DAEMON TAKES BESIDE FUZZNET'S, sec 673: `name` as it is
 * typed, `--profile`; with `takes_value`, given as `--profile=VALUE`, and
 * without it, alone. `help` is its line in the usage text, or NULL. */
typedef struct fzn_daemon_option {
	const char *name;
	int takes_value;
	const char *help;
} fzn_daemon_option_t;

/* WHAT A DAEMON ADDS TO THE NODE (sec 666 stage 4, as sec 672 rewrote it):
 * the shape of commands on their way into fuzznet, so that one moving in
 * changes nothing for a client.
 *
 *   - Options are parsed by fuzznet's one parser: fuzznet's own first, so
 *     an option fuzznet comes to take is fuzznet's from then on, and then
 *     these. One neither takes is refused, as before.
 *   - Local verbs reach `local` only when fuzznet's own handlers decline
 *     them, so a verb fuzznet comes to answer is fuzznet's from then on
 *     and the extension's copy is dead. That holds only for a verb spelled
 *     in fuzznet's grammar -- the vocabulary's verbs, a subject, escaped
 *     words -- answering in its reply vocabulary (`fzn_reply_t`): a reply
 *     that is not one is answered `error` in its place.
 *
 * Every member may be NULL or 0; a NULL extension is fuzznetd. */
typedef struct fzn_daemon_ext {
	void *ctx;
	const fzn_daemon_option_t *options;
	size_t n_options;
	/* One of `options` given: `value` NULL for an option that takes none.
	 * NULL to take it, or why it is refused, which ends the start. */
	const char *(*option)(void *ctx, const char *name, const char *value);
	/* A local verb fuzznet's handlers declined, `origin` as fuzznet judged
	 * the caller: the reply's length in `reply`, at most `cap`, ending in
	 * a newline; 0 for one this extension does not answer either, which
	 * is then `unsupported`. */
	size_t (*local)(void *ctx, fzn_origin_t origin, const fzn_request_t *request, char *reply,
	                size_t cap);
} fzn_daemon_ext_t;

/* RUN THE NODE as fuzznetd with `argc` and `argv`, and what `ext` adds,
 * NULL for nothing: the exit status, as fuzznetd's main would return it.
 * `ext` must outlive the call. */
int fzn_daemon_main(int argc, char **argv, const fzn_daemon_ext_t *ext);

#endif /* FZN_NODE_DAEMON_H */
