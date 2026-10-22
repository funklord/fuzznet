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
#include <stdint.h>

#include "../chain/authz.h"
#include "../chain/chain.h"
#include "../local/vocabulary.h"
#include "../state/schema.h"

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
 *   - Remote requests reach `remote` only when they are version 2's and of
 *     a type in the extensions' range (`node/types.h`), which fuzznet
 *     allocates none of. A type an extension uses is listed there with its
 *     owner, so that moving into fuzznet it keeps its number. One in that
 *     range that no extension takes is answered `unsupported`.
 *   - Journal records of the consumer half of kinds (1 to 127,
 *     `wire/bytes.h`) reach `apply` from every host's estate stream this
 *     node follows; `fzn_daemon_journal_append` writes them into this
 *     host's. A host that does not know a kind keeps and serves its
 *     records all the same, so a kind that moves into fuzznet finds its
 *     history already in each journal.
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
	/* A remote request of an extension's type, from `sender`, a member of
	 * this estate or -- `contact` nonzero -- a contact granted the share
	 * capability alone: the reply's length in `reply`, at most `cap`; 0
	 * for one it does not answer, which is then `unsupported`. */
	size_t (*remote)(void *ctx, const uint8_t sender[FZN_PUBKEY_LEN], int contact,
	                 const uint8_t *request, size_t request_len, uint8_t *reply, size_t cap);
	/* A journal record of a consumer-half kind, `body` its object --
	 * FZN_SIGNED_VERSION, then the kind, then the extension's own bytes --
	 * written by `signer`, a host whose stream this node follows: 1
	 * applied, 0 refused, -1 to wait for a later round. Records are handed
	 * over again at every start, the journal replaying from the beginning,
	 * so applying must be idempotent. */
	int (*apply)(void *ctx, uint32_t kind, const uint8_t *body, size_t len,
	             const uint8_t signer[FZN_PUBKEY_LEN]);
	/* THE SETTINGS IT READS, declared, sec 686: listed by `list schema`
	 * after fuzznet's and checked by `set setting` as fuzznet's are. A key
	 * fuzznet declares, or one declared twice, ends the start: a cell has
	 * one owner, and keeps its key when it moves into fuzznet. */
	const fzn_schema_entry_t *settings;
	size_t n_settings;
} fzn_daemon_ext_t;

/* RUN THE NODE as fuzznetd with `argc` and `argv`, and what `ext` adds,
 * NULL for nothing: the exit status, as fuzznetd's main would return it.
 * `ext` must outlive the call. */
int fzn_daemon_main(int argc, char **argv, const fzn_daemon_ext_t *ext);

/* WRITE AN EXTENSION'S RECORD into this host's estate stream, signed as
 * this host, from inside one of the extension's calls while the node
 * serves: `object`, `len` bytes, opening with FZN_SIGNED_VERSION and a
 * consumer-half kind. 1 written, 0 for a node keeping no journal, a kind
 * of the library's, or a store that refused it. The node's next round
 * applies it here and carries it to the hosts that follow this one. */
int fzn_daemon_journal_append(const uint8_t *object, size_t len);

#endif /* FZN_NODE_DAEMON_H */
