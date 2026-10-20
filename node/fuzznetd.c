/* fuzznetd: the shared node of sec 298 and sec 300 -- a daemon a consumer who
 * does not want to write its own can run. It opens the local access socket
 * (always) and the remote UDP socket (when a port is given), then runs the
 * access loop: every caller is authenticated by the hop it arrived on and
 * authorised by the node core. This main is glue; the loop and the three
 * access methods are node/serve.h and what it composes.
 *
 * The remote hop binds but serves nobody until peers are provisioned -- a
 * frame from an unknown sender has no session to open it and is dropped.
 *
 * IT STILL DOES NOT MINT A PEER: deciding what a peer is granted and which
 * prekeys are pinned is not something a daemon should do on its own say-so.
 * WHERE ITS OWN KEY LIVES is settled, by sec 136's "generate it when absent":
 * with `--fuzznet-dir` and no `--identity` the daemon loads its identity from
 * there, or creates a self-rooted one when it holds none, through
 * `node/identity.h`. sec 375. What it also does is LOAD a set a consumer has
 * already provisioned, from the same store. Reading what somebody else decided is not
 * deciding it, and without this the daemon could bind the remote hop and
 * serve nobody for ever -- raidcfgd reported exactly that on 2026-09-22.
 *
 * TWO DIRECTORIES SINCE sec 392, by the holder's rule that anything needed to
 * keep an attacker out lives in the core one whatever its size: identity,
 * anchor, pinned prekeys, ratchet positions and revocations under
 * `--fuzznet-dir`; the peers a node serves and the pairings a device holds
 * under `--fuzznet-store`, which defaults to the core directory when omitted
 * (`fzn_persist_slot_is_core`). They replace the one `--store DIR`.
 *
 * `--fuzznet-dir` is opt-in. Without it the daemon behaves as before and a
 * consumer that fills the state itself and calls `fzn_node_run` is
 * unaffected. With it, a store that cannot be read is FATAL rather than
 * empty: a daemon that starts having silently served nobody is the failure
 * this exists to end, and `sec 366` records the same argument one layer
 * down.
 */

/* POSIX, as the other backends ask: the log's clock and its O_CLOEXEC. */
#define _POSIX_C_SOURCE 200809L

#include "serve.h"
#include "talk.h"
#include "routing.h"
#include "contact_card.h"
#include "contact_request.h"
#include "groups.h"
#include "group_lines.h"
#include "streams.h"
#include "catalog.h"
#include "file_refs.h"
#include "../claim/claim.h"
#include "../local/client.h"
#include "../local/escape.h"
#ifdef FZN_CLAIM_FILE_ON
#include "../claim/claim_file.h"
#endif
#include "../session/box.h"
#include "state_dir.h"
#include "../contact/contact.h"
#include "admin.h"
#include "caller.h"
#include "identity.h"
#include "pair.h"
#include "revoke.h"
#include "roots.h"
#include "roster.h"
#include "succession.h"
#ifdef FZN_RECORD_STORE_FILE_ON
#include "journal.h"
#include "opjournal.h"
#include "messages.h"
#include "apply.h"
#ifdef FZN_LOG_PACK_ON
#include "log_buckets.h"
#include "piece_buckets.h"
#include "heard.h"
#include "../chunk/erasure.h"
#include "pieces.h"
#endif
#include "reconcile.h"
#include "settings.h"
#include "siblings.h"
#endif
#include "peer_persist.h"
#include "notes.h"
#include "../notes/received.h"
#include "../notes/share.h"
#include "members.h"
#include "received.h"
#ifdef FZN_SPOOL_FILE_ON
#include "files.h"
#include "shelf.h"
#endif
#include "../local/socket.h"
#include "../net/udp.h"
#include "../link/link.h"
#include "../persist/persist_file.h"
#include "../chain/service.h"
#include "../constant_time/constant_time.h"
#include "../chain/sign_monocypher.h"
#include "../cli/cli.h"
#include "../provision/provision.h"
#include "../session/aead_monocypher.h"
#include "../session/agree_monocypher.h"
#include "../session/hash_monocypher.h"
#include "../session/random_system.h"

#include "../log/entry.h"
#include "../log/cause.h"
#include "../log/view.h"
#include "../log/rules.h"
#ifdef FZN_LOG_FILE_ON
#include "../log/gather.h"
#include "../log/logger.h"
#endif
#ifdef FZN_LOG_PACK_ON
#include "../log/copy.h"
#include "../log/pack.h"
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* THE DAEMON'S LOG, sec 461: the first consumer of sec 456's logging.
 *
 * EVERY MESSAGE THE SERVING DAEMON SAYS goes through `say`, which writes the
 * line it always wrote to stderr -- so a journal, a terminal and a script
 * reading the old lines see no change -- and, built with FZN_LOG_FILE, logs
 * it as an entry: into the flight recorder whatever its level, and into
 * `fuzznetd.log` when the level is kept. The command line's own errors, and
 * the one-shot modes that print a card or a prekey, stay on stderr alone.
 *
 * THE FLIGHT RECORDER IS WRITTEN OUT on a crash, by a handler that only
 * opens, writes and closes, and on an error entry, at most once a minute:
 * `DIR/fuzznetd.PID.ring`, a dump `fzn_ring_load` reads back.
 *
 * EACH ROUND, settled segments are packed (with FZN_LOG_PACK) and the
 * `--log-rule=` lines applied. Rules are lines on the command line for now,
 * as the holder allowed; sec 428 has them become replicated state. */
#define FZND_LOG_RULES_MAX 16u
#define FZND_SAY_MAX 1024u

static struct {
	/* THE RULES, OF LOGS AND OF CONVERSATIONS ALIKE, sec 531: one set, read
	 * whether or not this build writes log files. */
	fzn_retain_rule_t rules[FZND_LOG_RULES_MAX];
	size_t n_rules;
	/* THE RULES SET WHILE RUNNING, sec 475: read from the store on every
	 * pass, so `add retention` applies from the next round. */
	const fzn_persist_ops_t *store;
	/* THE ESTATE'S RULES, sec 476: resolved from the running root records
	 * on every pass, so a root's change applies once it has been pulled. */
	const fzn_node_roots_t *roots;
	/* WHO THIS NODE IS, for a rule's scope, sec 480: its key once known.
	 * Until then a rule scoped to a host reaches nothing here. */
	int has_host;
	uint8_t host[FZN_PUBKEY_LEN];
#ifdef FZN_LOG_FILE_ON
	int on;
	fzn_logger_t logger;
	fzn_ring_t ring;
#ifdef FZN_LOG_PACK_ON
	/* What verifies a copy's signatures. */
	const fzn_sign_ops_t *verify;
	/* AND ITS SIGNER, sec 482: every trailer this node packs is signed
	 * with its key, once the key is known. */
	int has_signer;
	fzn_log_pack_signer_t signer;
#endif
	const fzn_hash_ops_t *hash;
	char ring_path[FZN_LOGGER_PATH_MAX + 32u];
	uint64_t last_dump_us;
	/* Set by the rotation hook, cleared by the loop: the hook runs inside
	 * `fzn_logger_log`, whose line is not written yet, so it must not log. */
	int rotated;
	/* Whether members may gather this host's log, sec 463: host-private
	 * unless `--log-scope=estate`, as sec 428 has the holder decide. */
	int estate_scope;
#endif
} dlog;

#ifdef FZN_LOG_FILE_ON
static uint64_t log_now_us(void)
{
	struct timespec t;

	if (clock_gettime(CLOCK_REALTIME, &t) != 0 || t.tv_sec < 0)
		return 0;
	return ((uint64_t)t.tv_sec * 1000000u) + ((uint64_t)t.tv_nsec / 1000u);
}
#endif

#ifdef FZN_LOG_FILE_ON
/* The ring's bytes into its dump file: open, two writes, close -- nothing
 * a signal handler may not call. */
static void write_ring(void)
{
	const uint8_t *a, *b;
	size_t al = 0, bl = 0;
	int fd;

	if (!dlog.ring_path[0])
		return;
	fd = open(dlog.ring_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return;
	fzn_ring_spans(&dlog.ring, &a, &al, &b, &bl);
	if (al)
		(void)!write(fd, a, al);
	if (bl)
		(void)!write(fd, b, bl);
	(void)close(fd);
}

static void on_crash(int sig)
{
	write_ring();
	(void)signal(sig, SIG_DFL);
	(void)raise(sig);
}
#endif

/* One message of the serving daemon: its old stderr line, and an entry. */
#if defined(__GNUC__)
#define FZND_SAY_PRINTF __attribute__((format(printf, 3, 4)))
#else
#define FZND_SAY_PRINTF
#endif
static void say(fzn_entry_level_t level, const char *subsystem, const char *fmt, ...) FZND_SAY_PRINTF;

/* The same, caused by `cause` and `origin` (both or neither), its own name
 * in `*named`; 1 when it was logged and named. */
#if defined(__GNUC__)
#define FZND_SAY_CAUSED_PRINTF __attribute__((format(printf, 6, 7)))
#else
#define FZND_SAY_CAUSED_PRINTF
#endif
static int say_caused(fzn_entry_level_t level, const char *subsystem,
                      const fzn_entry_name_t *cause, const fzn_entry_name_t *origin,
                      fzn_entry_name_t *named, const char *fmt, ...) FZND_SAY_CAUSED_PRINTF;

/* STDERR KEEPS WHAT IT HAD: down to information. A debug entry -- a round
 * begun, a request answered -- goes to the ring, and to the file when its
 * level is kept, not to a terminal. */
static int say_v(fzn_entry_level_t level, const char *subsystem, const fzn_entry_name_t *cause,
                 const fzn_entry_name_t *origin, fzn_entry_name_t *named, const char *fmt,
                 va_list ap)
{
	char text[FZND_SAY_MAX];
	int k = vsnprintf(text, sizeof(text), fmt, ap);

	if (k < 0)
		return 0;
	if (level <= FZN_ENTRY_INFO)
		fprintf(stderr, "fuzznetd: %s\n", text);
#ifdef FZN_LOG_FILE_ON
	if (dlog.on) {
		size_t len = (size_t)k < sizeof(text) ? (size_t)k : sizeof(text) - 1u;
		int logged = fzn_logger_log(&dlog.logger, level, subsystem, cause, origin,
		                            (const uint8_t *)text, len, named)
		             == FZN_LOGGER_OK;

		/* ON AN ERROR, the minutes before it, at most once a minute. */
		if (level <= FZN_ENTRY_ERROR && log_now_us() - dlog.last_dump_us > 60u * 1000000u) {
			dlog.last_dump_us = log_now_us();
			write_ring();
		}
		return logged && named;
	}
#else
	(void)subsystem;
	(void)cause;
	(void)origin;
#endif
	(void)named;
	return 0;
}

static void say(fzn_entry_level_t level, const char *subsystem, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void)say_v(level, subsystem, NULL, NULL, NULL, fmt, ap);
	va_end(ap);
}

static int say_caused(fzn_entry_level_t level, const char *subsystem,
                      const fzn_entry_name_t *cause, const fzn_entry_name_t *origin,
                      fzn_entry_name_t *named, const char *fmt, ...)
{
	va_list ap;
	int r;

	va_start(ap, fmt);
	r = say_v(level, subsystem, cause, origin, named, fmt, ap);
	va_end(ap);
	return r;
}

/* THE ROUND'S OWN ENTRY, sec 462: every request a round makes through
 * `peer_ask` carries it as cause and origin, so the hosts answering log
 * their work under it. NULL when nothing was logged to name it. */
static fzn_entry_name_t round_name;
static int round_named;

static const fzn_entry_name_t *round_cause(void)
{
	return round_named ? &round_name : NULL;
}

/* THE LOCAL SUBSCRIBERS, sec 609: told `event SUBJECT NAME` when something
 * changes, here or brought from a peer, so a UI need not poll. */
static fzn_node_events_t node_events;

static void publish(const char *subject, const char *name)
{
	(void)fzn_node_events_publish(&node_events, subject, name);
}

/* A LOCAL REQUEST, and its subscribers told when it changed something: a
 * change verb the node answered `ok` publishes its subject -- the first
 * word after the verb -- naming the item when the next word is one (hex).
 * A change one UI makes reaches the others. sec 609. */
static size_t routing_local(const fzn_request_t *request, char *reply, size_t reply_cap);
static size_t card_local(const fzn_request_t *request, char *reply, size_t reply_cap);
static size_t request_local(fzn_origin_t origin, const fzn_request_t *request, char *reply,
                            size_t cap);
static size_t identity_local(fzn_origin_t origin, const fzn_request_t *request, char *reply,
                             size_t cap);
static size_t capability_local(fzn_origin_t origin, const fzn_request_t *request, char *reply,
                               size_t cap);
static size_t grant_local(fzn_origin_t origin, const fzn_request_t *request, char *reply,
                          size_t cap);
static size_t relay_local(fzn_origin_t origin, const fzn_request_t *request, char *reply,
                          size_t cap);
static size_t sibling_local(fzn_origin_t origin, const fzn_request_t *request, char *reply,
                            size_t cap);
static size_t join_local(fzn_origin_t origin, const fzn_request_t *request, char *reply,
                         size_t cap);
static size_t admin_chain_local(fzn_origin_t origin, const fzn_request_t *request, char *reply,
                                size_t cap);
static size_t address_local(const fzn_request_t *request, char *reply, size_t cap);
static size_t link_local(const fzn_request_t *request, char *reply, size_t cap);
static size_t streams_local(fzn_origin_t origin, const fzn_request_t *request, char *reply,
                            size_t cap);
static size_t device_local(fzn_origin_t origin, const fzn_request_t *request, char *reply,
                           size_t cap);
static size_t catalog_local(fzn_origin_t origin, const fzn_request_t *request, char *reply,
                            size_t cap);
static void index_catalog(void);
static void catalog_skip(const uint8_t *issuer, uint64_t to);
/* `fetch lan`, sec 624: its probes sent, how many, and why none. */
static size_t lan_probe(const char **why, char *address, size_t address_cap);
/* WHEN THE LAST PROBES WENT, seconds, for `get lan` (sec 659). */
static uint64_t lan_probed_at;

static size_t local_handle(void *ctx, fzn_authz_verdict_t verdict, fzn_origin_t origin,
                           const fzn_peer_t *peer, const fzn_request_t *request, char *reply,
                           size_t reply_cap)
{
	size_t n = routing_local(request, reply, reply_cap);

	if (!n)
		n = card_local(request, reply, reply_cap);
	if (!n)
		n = request_local(origin, request, reply, reply_cap);
	if (!n)
		n = identity_local(origin, request, reply, reply_cap);
	if (!n)
		n = join_local(origin, request, reply, reply_cap);
	if (!n)
		n = admin_chain_local(origin, request, reply, reply_cap);
	if (!n)
		n = sibling_local(origin, request, reply, reply_cap);
	if (!n)
		n = relay_local(origin, request, reply, reply_cap);
	if (!n)
		n = capability_local(origin, request, reply, reply_cap);
	if (!n)
		n = grant_local(origin, request, reply, reply_cap);
	if (!n)
		n = address_local(request, reply, reply_cap);
	if (!n)
		n = link_local(request, reply, reply_cap);
	if (!n)
		n = streams_local(origin, request, reply, reply_cap);
	if (!n)
		n = device_local(origin, request, reply, reply_cap);
	if (!n)
		n = catalog_local(origin, request, reply, reply_cap);
	if (n)
		return n;
	n = fzn_node_admin_handle(ctx, verdict, origin, peer, request, reply, reply_cap);
	char subject[FZN_NODE_EVENTS_SUBJECT_MAX + 1u], name[FZN_NODE_EVENTS_NAME_MAX + 1u];
	size_t at = 0, s = 0, k = 0;

	if (n < 2u || n > reply_cap || memcmp(reply, "ok", 2u) != 0 || (n > 2u && reply[2] != ' '
	                                                               && reply[2] != '\n'))
		return n;
	switch (request->parsed) {
	case FZN_VERB_ADD:
	case FZN_VERB_SET:
	case FZN_VERB_REMOVE:
	case FZN_VERB_PUT:
	case FZN_VERB_FETCH:
	case FZN_VERB_GRANT:
	case FZN_VERB_REVOKE:
		break;
	default:
		return n;
	}
	while (at < request->arg_len && request->arg[at] != ' ' && s < FZN_NODE_EVENTS_SUBJECT_MAX)
		subject[s++] = (char)request->arg[at++];
	subject[s] = '\0';
	if (at < request->arg_len && request->arg[at] != ' ')
		return n;
	while (at < request->arg_len && request->arg[at] == ' ')
		at++;
	while (at < request->arg_len && request->arg[at] != ' ' && k < FZN_NODE_EVENTS_NAME_MAX)
		name[k++] = (char)request->arg[at++];
	name[k] = '\0';
	/* A NAME ONLY WHEN IT IS AN ITEM'S ID: a contact named in words, or a
	 * word cut short, is `-`, and the subscriber reads the subject again. */
	if (k == 0u || (at < request->arg_len && request->arg[at] != ' ')
	    || strspn(name, "0123456789abcdef") != k)
		publish(subject, NULL);
	else
		publish(subject, name);
	return n;
}

/* EVERY REQUEST A PULL OR A SHARE'S CALLER SENDS, in an envelope naming the
 * round, sec 465 -- the roots and votes pulls the library makes included,
 * which this daemon never sees. 0, sending it bare, when the round has no
 * name. */
static size_t caller_wrap(void *ctx, const uint8_t *in, size_t in_len, uint8_t *out,
                          size_t out_cap)
{
	const fzn_entry_name_t *cause = round_cause();
	size_t n = 0;

	(void)ctx;
	if (!cause || in_len > 0xffffu
	    || fzn_cause_wrap(cause, cause, in, in_len, out, out_cap, &n) != FZN_CAUSE_OK)
		return 0;
	return n;
}

/* THE OTHER END: a request that came with its causes, logged as their
 * work. */
static void on_caused(void *ctx, const uint8_t *sender, const fzn_entry_name_t *cause,
                      const fzn_entry_name_t *origin)
{
	(void)ctx;
	(void)say_caused(FZN_ENTRY_DEBUG, "node/remote", cause, origin, NULL,
	                 "answering %02x%02x%02x%02x", sender ? sender[0] : 0u,
	                 sender ? sender[1] : 0u, sender ? sender[2] : 0u, sender ? sender[3] : 0u);
}

/* PACKED AND PRUNED, once a round and after a rotation. */
static int hex_bytes(const char *text, uint8_t *out, size_t len);

#ifdef FZN_LOG_FILE_ON
/* Programs one log round tends at most. */
#define FZND_LOG_PROGRAMS_MAX 32u

/* THE ACCOUNT'S PROGRAMS, sec 486: every program with a log file in the
 * account's directory -- a host is the account's node (sec 430), so its
 * node packs, signs and prunes them all, not only its own. This one first. */
static size_t log_programs(char (*out)[FZN_ENTRY_WORD_MAX + 1u])
{
	static char found[FZND_LOG_PROGRAMS_MAX][FZN_ENTRY_WORD_MAX + 1u];
	size_t n = 1, n_found = 0, k;

	strcpy(out[0], "fuzznetd");
	if (fzn_logger_programs(dlog.logger.dir, found, FZND_LOG_PROGRAMS_MAX, &n_found)
	    != FZN_LOGGER_OK)
		return n;
	for (k = 0; k < n_found && n < FZND_LOG_PROGRAMS_MAX; k++)
		if (strcmp(found[k], "fuzznetd") != 0)
			memcpy(out[n++], found[k], sizeof(found[k]));
	return n;
}
#endif

#if defined(FZN_LOG_FILE_ON) || defined(FZN_RECORD_STORE_FILE_ON)
/* THE MACHINE, for a rule's `machine=`: the logger's reading of it, or
 * none in a build without log files, which no machine-scoped rule reaches. */
static const uint8_t *here_machine(void)
{
#ifdef FZN_LOG_FILE_ON
	if (dlog.on)
		return dlog.logger.self.machine;
#endif
	{
		static const uint8_t none[FZN_ENTRY_MACHINE_LEN];

		return none;
	}
}

#ifdef FZN_RECORD_STORE_FILE_ON
/* A VERB AN ADMIN RAN HERE REMOTELY, sec 543: said, with who ran it, so a
 * node's log shows what was done to it from elsewhere. */
static void remote_ran(void *ctx, const uint8_t *sender, const uint8_t *what, size_t len)
{
	(void)ctx;
	say(FZN_ENTRY_NOTE, "node/remote-admin", "%02x%02x%02x%02x ran %.*s", sender[0], sender[1],
	    sender[2], sender[3], (int)len, (const char *)what);
}

/* THE ESTATE'S CONFIGURATION, sec 540: set by verbs, carried by the journal,
 * judged and kept by the apply context. */
static fzn_node_settings_t node_settings;

/* RETENTION RULES AS SETTINGS, sec 540: every value in force under a key
 * `retention/...`, the estate's and this host's own, each a rule's line. */
struct setting_rules {
	fzn_retain_rule_t *rules;
	size_t *n;
	size_t unread;
};

static void setting_rule(void *ctx, const fzn_setting_t *s, fzn_setting_rank_t rank)
{
	struct setting_rules *sr = (struct setting_rules *)ctx;

	(void)rank;
	if (s->key_len < 11u || memcmp(s->key, "retention/", 10u) != 0)
		return;
	if (s->scope != FZN_SCOPE_ESTATE
	    && !(s->scope == FZN_SCOPE_HOST && dlog.has_host
	         && memcmp(s->about, dlog.host, FZN_PUBKEY_LEN) == 0))
		return;
	if (*sr->n >= FZN_RETAIN_RULES_MAX
	    || fzn_retain_parse((const char *)s->value, s->value_len, &sr->rules[*sr->n])
	               != FZN_RETAIN_OK) {
		sr->unread++;
		return;
	}
	(*sr->n)++;
}
#endif

#ifdef FZN_RECORD_STORE_FILE_ON
/* THIS HOST'S OLDER RULES INTO ITS SETTINGS, sec 541, at every start: a
 * rule this node could not yet write as a setting -- it stands nowhere in an
 * estate -- is tried again. */
static void retention_to_settings(const fzn_node_identity_t *id)
{
	size_t moved = 0;

	if (fzn_node_settings_take_rules(&node_settings, id->pubkey, &moved) != FZN_NODE_SETTINGS_OK)
		say(FZN_ENTRY_WARNING, "log", "this host's older retention rules did not read");
	else if (moved)
		say(FZN_ENTRY_INFO, "log", "%zu retention rule(s) moved into this host's settings",
		    moved);
}
#endif

/* EVERY RULE THERE IS, sec 531: the command line's, the store's (sec 475)
 * and the estate's (sec 476), as one set, whatever data each names; and since
 * sec 540 those kept as settings. A store whose rules will not read applies
 * the others, and says so. */
static size_t gather_rules(fzn_retain_rule_t rules[FZN_RETAIN_RULES_MAX])
{
	size_t n_rules, held = 0;

	memcpy(rules, dlog.rules, dlog.n_rules * sizeof(rules[0]));
	n_rules = dlog.n_rules;
	if (dlog.store) {
		fzn_log_rules_err_t rerr = fzn_log_rules_list(dlog.store, rules + n_rules,
		                                              FZN_LOG_RULES_MAX, &held);

		if (rerr != FZN_LOG_RULES_OK)
			say(FZN_ENTRY_WARNING, "log", "the stored log rules: %s",
			    fzn_log_rules_err_str(rerr));
		else
			n_rules += held;
	}
	/* AND THE ESTATE'S, combined with these as one rule set: the holder's
	 * answer of 2026-10-03. */
	if (dlog.roots) {
		size_t unread = 0;

		held = 0;
		if (fzn_node_roots_retention(dlog.roots, rules + n_rules,
		                             FZN_RETAIN_RULES_MAX - n_rules, &held, &unread)
		    != FZN_NODE_ROOTS_OK)
			say(FZN_ENTRY_WARNING, "log", "the estate's log rules did not resolve");
		else
			n_rules += held;
		if (unread)
			say(FZN_ENTRY_WARNING, "log",
			    "%zu of the estate's log rules were passed over: past the rules one "
			    "pass weighs, or not ones this build reads",
			    unread);
	}
#ifdef FZN_RECORD_STORE_FILE_ON
	if (node_settings.store) {
		struct setting_rules sr = { rules, &n_rules, 0 };

		if (fzn_node_settings_each(&node_settings, setting_rule, &sr) != FZN_NODE_SETTINGS_OK)
			say(FZN_ENTRY_WARNING, "log", "the retention rules kept as settings did not read");
		if (sr.unread)
			say(FZN_ENTRY_WARNING, "log",
			    "%zu retention rule(s) kept as settings were passed over: past the rules "
			    "one pass weighs, or not rules",
			    sr.unread);
	}
#endif
	return n_rules;
}
#endif

/* WHERE ARCHIVED LOG SEGMENTS GO, sec 588: `--log-archive=DIR`, or
 * `archive/` under the log directory. */
static const char *log_archive;

/* The archive's directory into `out`: `--log-archive=DIR`, or `archive/`
 * under the log directory. */
static void archive_where(char *out, size_t cap)
{
	if (log_archive)
		(void)snprintf(out, cap, "%s", log_archive);
	else
		(void)snprintf(out, cap, "%s/archive", dlog.logger.dir);
}

#if defined(FZN_LOG_FILE_ON) && defined(FZN_LOG_PACK_ON)
/* THE FOSSILS HELD BY ENOUGH HOSTS, sec 592: of this node's archived
 * segments the archive's rules would prune, those the last round found on
 * at least `archive/replicas` hosts, this one counted. Only these are
 * pruned; one not counted yet stays, so the guarantee fails safe. */
#define FZND_REPLICA_NAMES 256u
static char replica_ok[FZND_REPLICA_NAMES][FZN_BUCKETS_REF_MAX + 1u];
static size_t n_replica_ok;

/* WHETHER `name` MAY GO: its ref, `ctx` its prefix -- `o/` for this node's
 * own, `c/HOSTHEX/` for a copy (sec 593) -- among those confirmed. */
static int replicas_enough(void *ctx, const char *name)
{
	char ref[FZN_BUCKETS_REF_MAX + 1u];
	size_t i;

	if (!ctx || snprintf(ref, sizeof(ref), "%s%s", (const char *)ctx, name) >= (int)sizeof(ref))
		return 0;
	for (i = 0; i < n_replica_ok; i++)
		if (strcmp(replica_ok[i], ref) == 0)
			return 1;
	return 0;
}

/* Whether any of `rules` archives. */
static int has_archive_rule(const fzn_retain_rule_t *rules, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (rules[i].kind == FZN_RETAIN_ARCHIVE)
			return 1;
	return 0;
}

/* THE FOSSIL CLASS, secs 588 and 589: this node's packed segments an archive
 * rule marks moved to the archive -- before the rules over entries could
 * take them -- and then the archive's own rules applied to it. */
static void archive_round(const fzn_retain_rule_t *rules, size_t n_rules,
                          const fzn_retain_rule_t *all_rules, size_t n_all,
                          char (*programs)[FZN_ENTRY_WORD_MAX + 1u], size_t n_programs)
{
	static fzn_retain_rule_t archived_rules[FZN_RETAIN_RULES_MAX];
	static char held[FZND_LOG_PROGRAMS_MAX][FZN_ENTRY_WORD_MAX + 1u];
	char where[600];
	size_t pi, n_archived, n_held = 0, moved = 0;

	archive_where(where, sizeof(where));
	if (has_archive_rule(rules, n_rules)) {
		for (pi = 0; pi < n_programs; pi++) {
			if (fzn_log_pack_archive(dlog.logger.dir, programs[pi], rules, n_rules, where,
			                         log_now_us(), &moved)
			    != FZN_LOG_PACK_OK)
				say(FZN_ENTRY_WARNING, "log", "segments of %s could not all be archived",
				    programs[pi]);
			else if (moved)
				say(FZN_ENTRY_INFO, "log", "%zu segment(s) of %s archived to %s", moved,
				    programs[pi], where);
		}
	}
	/* THE ARCHIVE'S OWN RULES, sec 589: prune and keep naming `archived`,
	 * over every program the archive holds -- one that no longer logs
	 * among them -- whole segments, and no policy: a fossil stays until a
	 * rule prunes it. */
	n_archived = fzn_retain_select_archived(all_rules, n_all, dlog.has_host ? dlog.host : NULL,
	                                        dlog.logger.self.machine, archived_rules);
	if (n_archived && dlog.hash
	    && fzn_logger_programs(where, held, FZND_LOG_PROGRAMS_MAX, &n_held) == FZN_LOGGER_OK)
		for (pi = 0; pi < n_held; pi++) {
			size_t gone = 0, repacked = 0;

			/* NO FOSSIL BELOW ITS REPLICAS, sec 592. */
			if (fzn_log_pack_retain_held(where, held[pi], archived_rules, n_archived,
			                             dlog.hash, dlog.has_signer ? &dlog.signer : NULL,
			                             log_now_us(), replicas_enough, (void *)"o/", &gone,
			                             &repacked)
			    != FZN_LOG_PACK_OK)
				say(FZN_ENTRY_WARNING, "log",
				    "the archive's rules could not all be applied to %s", held[pi]);
			else if (gone)
				say(FZN_ENTRY_INFO, "log", "%zu archived segment(s) of %s pruned", gone,
				    held[pi]);
		}
	/* AND ITS COPIES', sec 591: rules naming `copy archived`, each copy
	 * directory under ARCHIVE/copy/ by the ones naming no source or its. */
	n_archived = fzn_retain_select_archived_copies(all_rules, n_all,
	                                               dlog.has_host ? dlog.host : NULL,
	                                               dlog.logger.self.machine, archived_rules);
	if (n_archived && dlog.hash) {
		static fzn_retain_rule_t source_rules[FZN_RETAIN_RULES_MAX];
		char copies[sizeof(where) + 8u];
		struct dirent *e;
		DIR *d;

		if (snprintf(copies, sizeof(copies), "%s/copy", where) >= (int)sizeof(copies)
		    || (d = opendir(copies)) == NULL)
			return;
		while ((e = readdir(d)) != NULL) {
			char sub[sizeof(copies) + 80u];
			uint8_t source[32];
			size_t n_source, p;

			if (strlen(e->d_name) != 64u || strspn(e->d_name, "0123456789abcdef") != 64u
			    || !hex_bytes(e->d_name, source, sizeof(source))
			    || snprintf(sub, sizeof(sub), "%s/%s", copies, e->d_name) >= (int)sizeof(sub))
				continue;
			n_source = fzn_retain_select_source(archived_rules, n_archived, source,
			                                    source_rules);
			n_held = 0;
			if (!n_source
			    || fzn_logger_programs(sub, held, FZND_LOG_PROGRAMS_MAX, &n_held)
			               != FZN_LOGGER_OK)
				continue;
			for (p = 0; p < n_held; p++) {
				size_t gone = 0, repacked = 0;
				char prefix[72];

				/* NO COPY BELOW ITS REPLICAS EITHER, sec 593. */
				if (snprintf(prefix, sizeof(prefix), "c/%s/", e->d_name) >= (int)sizeof(prefix))
					continue;
				if (fzn_log_pack_retain_held(sub, held[p], source_rules, n_source, dlog.hash,
				                             dlog.has_signer ? &dlog.signer : NULL,
				                             log_now_us(), replicas_enough, prefix, &gone,
				                             &repacked)
				    != FZN_LOG_PACK_OK)
					say(FZN_ENTRY_WARNING, "log/copy", "the archived copies' rules could not "
					    "all be applied to %s of %.8s", held[p], e->d_name);
				else if (gone)
					say(FZN_ENTRY_INFO, "log/copy",
					    "%zu archived copied segment(s) of %s of %.8s pruned", gone, held[p],
					    e->d_name);
			}
		}
		(void)closedir(d);
	}
}
#endif


static void log_round(void)
{
#ifdef FZN_LOG_FILE_ON
	static fzn_retain_rule_t rules[FZN_RETAIN_RULES_MAX], all_rules[FZN_RETAIN_RULES_MAX];
	static char programs[FZND_LOG_PROGRAMS_MAX][FZN_ENTRY_WORD_MAX + 1u];
	size_t n = 0, n_rules = 0, n_all = 0, n_programs, pi;

	if (!dlog.on)
		return;
	n_programs = log_programs(programs);
#ifdef FZN_LOG_PACK_ON
	for (pi = 0; pi < n_programs && dlog.hash; pi++) {
		if (fzn_log_pack_dir(dlog.logger.dir, programs[pi], dlog.hash,
		                     dlog.has_signer ? &dlog.signer : NULL, log_now_us(),
		                     FZN_LOG_PACK_SETTLE_DEFAULT, &n)
		    != FZN_LOG_PACK_OK)
			say(FZN_ENTRY_WARNING, "log", "closed segments of %s would not all pack",
			    programs[pi]);
		else if (n)
			say(FZN_ENTRY_INFO, "log", "%zu segment(s) of %s packed", n, programs[pi]);
	}
#endif
	n_rules = gather_rules(rules);
	/* ONLY THE RULES THAT REACH THIS NODE, sec 480: a rule scoped to
	 * another host or machine is that one's. */
	n_all = n_rules;
	memcpy(all_rules, rules, n_all * sizeof(rules[0]));
	n_rules = fzn_retain_select_here(rules, n_rules, dlog.has_host ? dlog.host : NULL,
	                                 dlog.logger.self.machine, rules);
#ifdef FZN_LOG_PACK_ON
	/* THE FOSSIL CLASS FIRST, sec 588: a packed segment an archive rule
	 * marks is moved before the rules over entries could take it. */
	archive_round(rules, n_rules, all_rules, n_all, programs, n_programs);
	/* THE RULES OVER ENTRIES TOO, sec 474: a packed segment some of whose
	 * lines go is repacked without them. */
	for (pi = 0; pi < n_programs && n_rules && dlog.hash; pi++) {
		size_t gone = 0, repacked = 0;

		if (fzn_log_pack_retain(dlog.logger.dir, programs[pi], rules, n_rules, dlog.hash,
		                        dlog.has_signer ? &dlog.signer : NULL, log_now_us(), &gone,
		                        &repacked)
		    != FZN_LOG_PACK_OK)
			say(FZN_ENTRY_WARNING, "log", "the log rules could not all be applied to %s",
			    programs[pi]);
		else if (gone || repacked)
			say(FZN_ENTRY_INFO, "log",
			    "%zu segment(s) of %s removed and %zu repacked by the rules", gone,
			    programs[pi], repacked);
	}
#else
	for (pi = 0; pi < n_programs && n_rules; pi++) {
		if (fzn_logger_retain(dlog.logger.dir, programs[pi], rules, n_rules, log_now_us(), &n)
		    != FZN_LOGGER_OK)
			say(FZN_ENTRY_WARNING, "log", "the log rules could not all be applied to %s",
			    programs[pi]);
		else if (n)
			say(FZN_ENTRY_INFO, "log", "%zu segment(s) of %s removed by the rules", n,
			    programs[pi]);
	}
#endif
#ifdef FZN_LOG_PACK_ON
	/* THE COPIES' RULES, sec 483: each copy directory planned whole by the
	 * rules naming `copy`, every copy a source host's bytes under its
	 * signature -- and of those, by the ones naming no source or naming
	 * the directory's, sec 487. EVERY PROGRAM A COPY DIRECTORY HOLDS, sec
	 * 573: the bucket exchange brings a host's every program, where
	 * `--log-copy` named the few it fetched. */
	{
		static fzn_retain_rule_t copy_rules[FZN_RETAIN_RULES_MAX];
		static fzn_retain_rule_t source_rules[FZN_RETAIN_RULES_MAX];
		char copies[FZN_LOGGER_PATH_MAX + 8u];
		size_t n_copy = fzn_retain_select_copies(all_rules, n_all,
		                                         dlog.has_host ? dlog.host : NULL,
		                                         dlog.logger.self.machine, copy_rules);
		struct dirent *e;
		DIR *d;

		if (n_copy && snprintf(copies, sizeof(copies), "%s/copy", dlog.logger.dir)
		                      < (int)sizeof(copies)
		    && (d = opendir(copies)) != NULL) {
			while ((e = readdir(d)) != NULL) {
				char sub[FZN_LOGGER_PATH_MAX + 80u];
				uint8_t source[32];
				static char held[FZND_LOG_PROGRAMS_MAX][FZN_ENTRY_WORD_MAX + 1u];
				size_t gone = 0, p, n_source, n_held = 0;

				if (strlen(e->d_name) != 64u
				    || strspn(e->d_name, "0123456789abcdef") != 64u
				    || !hex_bytes(e->d_name, source, sizeof(source))
				    || snprintf(sub, sizeof(sub), "%s/%s", copies, e->d_name)
				               >= (int)sizeof(sub))
					continue;
				n_source = fzn_retain_select_source(copy_rules, n_copy, source,
				                                    source_rules);
				if (!n_source
				    || fzn_logger_programs(sub, held, FZND_LOG_PROGRAMS_MAX, &n_held)
				               != FZN_LOGGER_OK)
					continue;
				for (p = 0; p < n_held; p++) {
					/* THE FOSSIL CLASS FOR COPIES, sec 590, before their
					 * rules: archive/copy/HOSTHEX/. */
					if (has_archive_rule(source_rules, n_source)) {
						char where[FZN_LOGGER_PATH_MAX + 8u], arch[FZN_LOGGER_PATH_MAX + 96u];
						size_t moved = 0;

						archive_where(where, sizeof(where));
						(void)mkdir(where, 0700);
						if (snprintf(arch, sizeof(arch), "%s/copy", where) < (int)sizeof(arch))
							(void)mkdir(arch, 0700);
						if (snprintf(arch, sizeof(arch), "%s/copy/%s", where, e->d_name)
						            >= (int)sizeof(arch)
						    || fzn_log_pack_archive(sub, held[p], source_rules, n_source,
						                            arch, log_now_us(), &moved)
						               != FZN_LOG_PACK_OK)
							say(FZN_ENTRY_WARNING, "log/copy", "copies of %s of %.8s could not "
							    "all be archived", held[p], e->d_name);
						else if (moved)
							say(FZN_ENTRY_INFO, "log/copy",
							    "%zu copied segment(s) of %s of %.8s archived", moved, held[p],
							    e->d_name);
					}
					if (fzn_logger_retain(sub, held[p], source_rules, n_source, log_now_us(),
					                      &gone)
					    != FZN_LOGGER_OK)
						say(FZN_ENTRY_WARNING, "log/copy", "the copy rules could not all "
						    "be applied to %s of %.8s", held[p], e->d_name);
					else if (gone)
						say(FZN_ENTRY_INFO, "log/copy",
						    "%zu copied segment(s) of %s of %.8s removed", gone, held[p],
						    e->d_name);
				}
			}
			(void)closedir(d);
		}
	}
#endif
#endif
}

#ifdef FZN_LOG_FILE_ON
/* A MEMBER GATHERING THIS HOST'S LOG, sec 463: answered at estate scope,
 * refused in words at host-private, which is the default. */
static size_t logs_remote(void *ctx, const uint8_t *sender, const uint8_t *request,
                          size_t request_len, uint8_t *reply, size_t reply_cap)
{
	static const char REFUSAL[] = "denied this host's log is host-private\n";

	(void)ctx;
	if (!request || request_len < 2u || request[0] != FZN_GATHER_VERSION)
		return 0;
	if (request[1] != FZN_GATHER_QUERY && request[1] != FZN_GATHER_RING_QUERY)
		return 0;
	if (!dlog.on || !dlog.estate_scope) {
		if (reply_cap < sizeof(REFUSAL) - 1u)
			return 0;
		memcpy(reply, REFUSAL, sizeof(REFUSAL) - 1u);
		return sizeof(REFUSAL) - 1u;
	}
	/* THE FLIGHT RECORDER, sec 464: each page at debug, so asking for it
	 * does not crowd out what it holds. */
	if (request[1] == FZN_GATHER_RING_QUERY) {
		(void)say_caused(FZN_ENTRY_DEBUG, "log/gather", NULL, NULL, NULL,
		                 "the ring gathered by %02x%02x%02x%02x", sender ? sender[0] : 0u,
		                 sender ? sender[1] : 0u, sender ? sender[2] : 0u,
		                 sender ? sender[3] : 0u);
		return fzn_gather_ring_answer(&dlog.ring, request, request_len, reply, reply_cap);
	}
	(void)say_caused(FZN_ENTRY_INFO, "log/gather", NULL, NULL, NULL,
	                 "the log gathered by %02x%02x%02x%02x", sender ? sender[0] : 0u,
	                 sender ? sender[1] : 0u, sender ? sender[2] : 0u, sender ? sender[3] : 0u);
	return fzn_gather_answer(dlog.logger.dir, request, request_len, reply, reply_cap);
}

/* MANY HOSTS' LINES, MERGED BY TIME, sec 466: each host's collected here,
 * then sorted and printed. The TIME field leads every line and sorts as text
 * in time order; ties keep the order they arrived in. Bounded, so a
 * troubleshooter asking an estate for everything gets told when it stops. */
#define FZND_GATHER_BYTES_MAX (64u * 1024u * 1024u)

struct gline {
	char *text;
	size_t seq; /* arrival, for ties */
};

struct gathered {
	struct gline *lines;
	size_t n, cap, bytes;
	int full;
	const char *host; /* for a ring entry's line */
};

static void keep_line(void *ctx, const char *line, size_t len)
{
	struct gathered *g = ctx;
	char *copy;

	if (g->full)
		return;
	if (g->bytes + len + 1u > FZND_GATHER_BYTES_MAX) {
		g->full = 1;
		return;
	}
	if (g->n == g->cap) {
		size_t cap = g->cap ? g->cap * 2u : 1024u;
		struct gline *more = realloc(g->lines, cap * sizeof(*more));

		if (!more) {
			g->full = 1;
			return;
		}
		g->lines = more;
		g->cap = cap;
	}
	copy = malloc(len + 1u);
	if (!copy) {
		g->full = 1;
		return;
	}
	memcpy(copy, line, len);
	copy[len] = '\0';
	g->lines[g->n].text = copy;
	g->lines[g->n].seq = g->n;
	g->n++;
	g->bytes += len + 1u;
}

/* A ring entry as a classic line, shown with the host asked. */
static void keep_entry(void *ctx, const fzn_entry_t *e)
{
	static char line[FZN_ENTRY_LINE_MAX];
	struct gathered *g = ctx;
	size_t len = 0;

	if (fzn_entry_classic(e, g->host, line, sizeof(line), &len) == FZN_ENTRY_OK)
		keep_line(ctx, line, len ? len - 1u : 0u);
}

/* Time order by the leading TIME field, then arrival. */
static int by_time(const void *a, const void *b)
{
	const struct gline *x = a, *y = b;
	int c = strncmp(x->text, y->text, 27u);

	return c ? c : (x->seq < y->seq ? -1 : (x->seq > y->seq ? 1 : 0));
}

/* NOTHING LOGGED FROM HERE: the logger is mid-entry. The loop sees the flag. */
static void on_rotated(void *ctx)
{
	(void)ctx;
	dlog.rotated = 1;
}
#endif

/* Hex to bytes, for an identity, a root or a device's prekey record on the
 * command line.
 *
 * LOCAL ON PURPOSE. This is the fourth hand-rolled hex table in the tree --
 * `cli/peer_print.c` writes one, `persist/persist_file.c` writes one for
 * filenames, and a test writes a third -- so a shared helper is clearly
 * wanted. It is not extracted here: `harmonization.md` says an extraction
 * spanning modules is its own deliberate piece of work with the whole picture
 * in view, and `cli/` is the natural home but is build-time optional
 * (FZN_CLI=0), which a daemon must not depend on. Recorded as a signal
 * instead. sec 368. */
static int hex_bytes(const char *text, uint8_t *out, size_t len)
{
	size_t i;

	if (!text || strlen(text) != len * 2u)
		return 0;
	for (i = 0; i < len; i++) {
		unsigned j;
		unsigned byte = 0;

		for (j = 0; j < 2u; j++) {
			char c = text[(i * 2u) + j];
			unsigned v;

			if (c >= '0' && c <= '9')
				v = (unsigned)(c - '0');
			else if (c >= 'a' && c <= 'f')
				v = 10u + (unsigned)(c - 'a');
			else if (c >= 'A' && c <= 'F')
				v = 10u + (unsigned)(c - 'A');
			else
				return 0;
			byte = (byte << 4) | v;
		}
		out[i] = (uint8_t)byte;
	}
	return 1;
}

static int hex_pubkey(const char *text, uint8_t out[FZN_PUBKEY_LEN])
{
	return hex_bytes(text, out, FZN_PUBKEY_LEN);
}

/* THE CLOCK, AND THE UNIT NOTHING IN THIS LIBRARY STATES.
 *
 * `frame/freshness.h` compares `now` against an `expires_at` that arrived
 * from a peer, and neither it nor `wire/frame.situ` nor sec 4.3 says what
 * either counts in. The library never sources a clock -- `now` is always the
 * caller's -- so the unit is settled per deployment by everyone agreeing,
 * which is a thing that works right up until two consumers do not.
 *
 * This daemon uses SECONDS SINCE THE UNIX EPOCH, which is what `time()`
 * gives and what a peer stamping an expiry will reach for. Stated here
 * because a daemon has to choose; whether fuzznet should MANDATE it rather
 * than leave it to agreement is the holder's, and sec 368 records it. */
static void print_hex(FILE *f, const uint8_t *bytes, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		fprintf(f, "%02x", bytes[i]);
}

static uint64_t wall_clock(void)
{
	time_t t = time(NULL);

	return (t < 0) ? 0u : (uint64_t)t;
}

/* The wall clock in milliseconds, which a note's times are in. */
static uint64_t wall_ms(void)
{
	struct timespec ts;

	/* C11's, so nothing here needs a POSIX feature macro for it. */
	if (timespec_get(&ts, TIME_UTC) != TIME_UTC || ts.tv_sec < 0)
		return 0u;
	return ((uint64_t)ts.tv_sec * 1000u) + ((uint64_t)ts.tv_nsec / 1000000u);
}

/* A LIFETIME PLUS A SKEW, which is what freshness.h asks for and the term it
 * says a consumer gets wrong in the direction that looks safe. Ten minutes:
 * a command lifetime of five and five minutes of tolerated clock skew. A
 * deployment wanting different values sets them by writing its own node
 * rather than by this daemon growing two more flags for numbers almost
 * nobody changes. */
#define FZND_MAX_AHEAD 600u
/* THE WINDOW, by freshness.h's rule: capacity >= peak arrival rate x
 * lifetime. Every request this daemon sends lives 300 s, so a slot taken is
 * held 300 s. It was 256, sized for votes and notes, and a file fetch --
 * one request a span, sec 491 -- filled it in about eight seconds on a
 * loopback, after which the node refused every request from anybody until
 * slots expired: measured, a fetch placed 3984 leaves and then the peer
 * answered nothing, roots and votes included, for the rest of the run.
 * 32768 slots of 24 bytes, 768 KiB, hold about 109 requests a second for
 * the whole lifetime. */
#define FZND_REPLAY_ENTRIES 32768u

/* HOW LONG A PAIRING CARD MAY WAIT TO BE ACCEPTED. The card carries no
 * secret -- the node's root, the node's prekey, and a grant only the device's
 * key can use -- so this bounds how long a card photographed off a screen
 * stays worth accepting, not what it can reveal. A day: long enough to carry
 * a card to a device, short enough that a stale one is not a standing
 * invitation. The GRANT inside it does not expire; a lost device is revoked,
 * which is the capability model's answer (sec 1). */
#define FZND_CARD_LIFETIME 86400u

/* HOW OFTEN A MEMBER ASKS ITS ROOT WHAT IT HAS REVOKED. fuzzypickles sweeps
 * its siblings on the same period, and it bounds the same thing: how long a
 * device the root cut off goes on being served here. A pull blocks the loop
 * for as long as the root takes to answer, at most 3 s a page, which is the
 * price of asking from the loop's own thread. sec 384. */
#define FZND_PULL_EVERY 60u
/* The operation journal's default byte budget, sec 523; the writes a
 * generation takes before the next opens, and how many are kept, sec 524.
 * A file-store record slot is 702 bytes, so a generation is about 46 MB of
 * entries at most, and the two kept about 92 MB. */
#define FZND_OP_JOURNAL_BUDGET (64ull * 1024u * 1024u)
#define FZND_OP_JOURNAL_ROTATE 65536u
#define FZND_OP_JOURNAL_KEEP 2u

/* THE PEERS A NODE PULLS VOTES FROM: `--root-at` for the pairing it joined
 * with, and `--pull-from` for any other node it holds a pairing to. Each has
 * its own socket and reassembly table, so a late answer from one is never
 * read as another's. Eight, because an estate's nodes are a household's and
 * every one costs a pull a minute. sec 401. */
#define FZND_PULL_TARGETS_MAX 8u
/* AND THE SIBLINGS A ROUND ADDS, sec 586: as many again, after them. */
#define FZND_SIBLING_TARGETS_MAX 8u
#define FZND_ROUND_TARGETS_MAX (FZND_PULL_TARGETS_MAX + FZND_SIBLING_TARGETS_MAX)

#ifdef FZN_SPOOL_FILE_ON
/* LONG NOTES' TEXTS, on the shelf under the store directory, served to any
 * peer the remote hop admits and fetched from the pull peers each round. The
 * node's reply buffer and a pull's reassembly are both sized to the shelf's
 * largest DATA, since the default reply is 512 bytes and one leaf is more.
 * sec 424. */
static fzn_node_shelf_t shelf;
/* THE NODE'S FILES, sec 490, beside the texts. */
static fzn_node_files_t files;
static int files_on;
static int shelf_on;

/* The node's notes seal a long text onto the shelf and open it back. */
static int shelf_seal(void *ctx, const uint8_t *text, size_t len, fzn_note_blob_ref_t *ref)
{
	return fzn_node_shelf_put((fzn_node_shelf_t *)ctx, text, len, ref) == FZN_NODE_SHELF_OK;
}

static int shelf_open(void *ctx, const fzn_note_blob_ref_t *ref, uint8_t *out, size_t cap,
                      size_t *out_len)
{
	fzn_note_err_t text_err = FZN_NOTE_OK;

	return fzn_node_shelf_open((fzn_node_shelf_t *)ctx, ref, out, cap, out_len, &text_err)
	       == FZN_NODE_SHELF_OK;
}

#define FZND_REPLY_TEXTS_MAX                                                                  \
	(FZN_NODE_SHELF_REPLY_MAX > FZN_NOTES_SYNC_REPLY_MAX ? FZN_NODE_SHELF_REPLY_MAX          \
	                                                     : FZN_NOTES_SYNC_REPLY_MAX)
/* AND A FILE'S DATA, sec 494, the largest of the three. */
#define FZND_REPLY_MAX                                                                        \
	(FZN_NODE_FILES_REPLY_MAX > FZND_REPLY_TEXTS_MAX ? FZN_NODE_FILES_REPLY_MAX              \
	                                                 : FZND_REPLY_TEXTS_MAX)
#else
#define FZND_REPLY_MAX FZN_NOTES_SYNC_REPLY_MAX
#endif

/* THE NODE'S REPLY BUFFER, and each pull's reassembly, sized to the largest
 * answer a peer sends -- a shelf's DATA, a notes sync's RECORDS -- since the
 * default reply is 512 bytes. secs 424 and 432. */
static uint8_t node_reply[FZND_REPLY_MAX];
#define FZND_PULL_REPLY_MAX FZND_REPLY_MAX

/* THE REQUESTS THIS NODE REASSEMBLES, sec 447: a request past one frame
 * arrives in pieces, and sec 370 gave the node a table to put them back
 * together -- which this daemon never handed it, so every such request was
 * dropped and its caller timed out. Four at once, each up to 32 KiB, one a
 * sender, held a minute. A request past 32 KiB is still refused, by the
 * table, which is a bound rather than a silence the caller cannot tell from
 * the network. */
#define FZND_REQUEST_SLOTS 4u
#define FZND_REQUEST_MAX (32u * 1024u)

/* THE CONTACTS AS THE USER'S ROSTER, sec 489: pulled with the votes from
 * every peer, and the arrivals named. */
static fzn_node_roster_t node_roster;
static int roster_on;
/* The successions this node holds, sec 499: loaded with the votes they ride
 * beside, judged by the same store. */
static fzn_node_successions_t node_successions;
static int successions_on;

static int admin_member(void *ctx, const uint8_t *key)
{
	return fzn_node_admin_is_member((const fzn_node_admin_t *)ctx, key);
}

/* The node's notes, when it keeps them: answered on the socket, served to
 * peers and pulled from them each round. sec 431, 432. */
static fzn_node_notes_t node_notes;
static int notes_on;

/* What the shelf and the notes ask a pull peer through: its caller, as a
 * votes pull does. */
struct peer_asking {
	fzn_caller_t *caller;
	uint64_t now;
	const char *host;
};

/* ---- links and traffic, sec 631 ------------------------------------------------
 *
 * WHAT EACH LINK IS DOING, measured where this daemon asks its peers: a link
 * is one address, as fuzzypickles' link has it, its latency and loss the
 * `link/` table's estimate -- a pessimistic prior that every answer and every
 * silence moves -- and beside it what crossed it: requests asked and
 * answered, bytes sent and received. In memory only, as fuzzypickles kept
 * theirs: a restart begins again. Read with `list link`. */

#define FZND_LINKS_MAX 64u
/* THE PRIOR, pessimistic as `link.h` asks: a link nothing has answered on
 * is not made to look instant. */
#define FZND_LINK_PRIOR_MS 1000u
#define FZND_LINK_PRIOR_LOSS 250u

static fzn_link_entry_t link_entries[FZND_LINKS_MAX];
static fzn_link_table_t link_table;
static struct link_meter {
	fzn_udp_addr_t at;
	uint64_t asked, answered, sent, received;
} link_meters[FZND_LINKS_MAX];
static size_t n_link_meters;
/* Links met past FZND_LINKS_MAX: not measured, and counted so `list link`
 * says so rather than reading as everything. */
static uint64_t links_unmeasured;

static uint64_t mono_ms(void)
{
	struct timespec t;

	if (clock_gettime(CLOCK_MONOTONIC, &t) != 0 || t.tv_sec < 0)
		return 0;
	return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}

/* THE LINK TO `at`, registered with the prior when first met; its index,
 * or FZND_LINKS_MAX past the bound. Ids are index + 1. */
static size_t link_of(const fzn_udp_addr_t *at)
{
	size_t i;

	if (!link_table.entries)
		(void)fzn_link_table_init(&link_table, link_entries, FZND_LINKS_MAX);
	for (i = 0; i < n_link_meters; i++)
		if (link_meters[i].at.len == at->len
		    && memcmp(link_meters[i].at.storage, at->storage, at->len) == 0)
			return i;
	if (n_link_meters == FZND_LINKS_MAX
	    || fzn_link_register(&link_table, (uint32_t)n_link_meters + 1u, 0u, FZND_LINK_PRIOR_MS,
	                         FZND_LINK_PRIOR_LOSS, FZN_UDP_DATAGRAM_MAX)
	               != FZN_LINK_OK) {
		links_unmeasured++;
		return FZND_LINKS_MAX;
	}
	memset(&link_meters[n_link_meters], 0, sizeof(link_meters[0]));
	link_meters[n_link_meters].at = *at;
	return n_link_meters++;
}

/* `list link`, sec 631: `ok COUNT UNMEASURED` and per link
 * `HOST:PORT,LATENCY,LOSS,OBSERVATIONS,AGE,ASKED,ANSWERED,SENT,RECEIVED` --
 * latency in ms and loss per mille as estimated, `-` for both on a link
 * nothing has been observed on (sec 202: a prior is no measurement), age the
 * seconds since the last observation. */
static size_t link_local(const fzn_request_t *request, char *reply, size_t cap)
{
	size_t at, i;
	uint64_t now = mono_ms();

	if (request->parsed != FZN_VERB_LIST || !request->arg || request->arg_len != 4u
	    || memcmp(request->arg, "link", 4u) != 0)
		return 0;
	at = (size_t)snprintf(reply, cap, "ok %zu %llu", n_link_meters,
	                      (unsigned long long)links_unmeasured);
	for (i = 0; i < n_link_meters && at < cap; i++) {
		const fzn_link_entry_t *e = fzn_link_get(&link_table, (uint32_t)i + 1u);
		const struct link_meter *m = &link_meters[i];
		char host[FZN_UDP_HOST_MAX], lat[24], loss[24], age[24];
		uint16_t port = 0;
		size_t k;

		if (!e || fzn_udp_addr_text(&m->at, host, &port) != FZN_UDP_OK)
			continue;
		if (e->observations) {
			(void)snprintf(lat, sizeof(lat), "%lu", (unsigned long)e->latency_ms);
			(void)snprintf(loss, sizeof(loss), "%u", (unsigned)e->loss_permille);
			(void)snprintf(age, sizeof(age), "%llu",
			               (unsigned long long)(now > e->last_seen ? (now - e->last_seen) / 1000u
			                                                      : 0u));
		} else {
			(void)snprintf(lat, sizeof(lat), "-");
			(void)snprintf(loss, sizeof(loss), "-");
			(void)snprintf(age, sizeof(age), "-");
		}
		k = (size_t)snprintf(reply + at, cap - at, " %s:%u,%s,%s,%llu,%s,%llu,%llu,%llu,%llu", host,
		                     (unsigned)port, lat, loss, (unsigned long long)e->observations, age,
		                     (unsigned long long)m->asked, (unsigned long long)m->answered,
		                     (unsigned long long)m->sent, (unsigned long long)m->received);
		if (at + k >= cap)
			break;
		at += k;
	}
	return at + (size_t)snprintf(reply + at, cap > at ? cap - at : 0u, "\n");
}

/* A REQUEST SENT on link `li`, counted. */
static void link_asked(size_t li, size_t request_len)
{
	if (li < FZND_LINKS_MAX) {
		link_meters[li].asked++;
		link_meters[li].sent += request_len;
	}
}

/* ITS ANSWER, `reply_len` bytes `began` ms after it was sent; or with `lost`
 * none. */
static void link_answered(size_t li, uint64_t began, size_t reply_len, int lost)
{
	uint64_t ended = mono_ms();

	if (li >= FZND_LINKS_MAX)
		return;
	if (lost) {
		(void)fzn_link_observe_loss(&link_table, (uint32_t)li + 1u, ended);
		return;
	}
	link_meters[li].answered++;
	link_meters[li].received += reply_len;
	(void)fzn_link_observe_ack(&link_table, (uint32_t)li + 1u,
	                           ended > began ? (uint32_t)(ended - began) : 0u, ended);
}

/* A REFUSAL IN WORDS, sec 455: every binary message here opens with a small
 * version byte, so a reply opening with a letter is the peer's own reply
 * line -- a contact suspended, a capability it was not granted. Said as the
 * peer said it, since the caller will only see an answer that does not
 * parse. */
static void said_refusal(const char *host, const uint8_t *reply, size_t reply_len)
{
	const uint8_t *detail = NULL;
	size_t detail_len = 0, len = reply_len;

	while (len && (reply[len - 1u] == '\n' || reply[len - 1u] == '\r'))
		len--;
	if (len && reply[0] >= 'a' && reply[0] <= 'z'
	    && fzn_reply_of(reply, len, &detail, &detail_len) != FZN_REPLY_OK)
		say(FZN_ENTRY_WARNING, "node/peer", "%s refused: %.*s", host ? host : "a peer",
		        (int)(len > 200u ? 200u : len), (const char *)reply);
}

static int peer_ask(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
                    size_t reply_cap, size_t *reply_len)
{
	struct peer_asking *asking = (struct peer_asking *)ctx;
	uint32_t msg = 0;
	size_t li = link_of(&asking->caller->node);
	uint64_t began = mono_ms();

	/* ITS ENVELOPE, if any, is the caller's `wrap`, sec 465. */
	link_asked(li, request_len);
	if (fzn_caller_send(asking->caller, request, request_len, asking->now + 300u, &msg)
	            != FZN_CALLER_OK
	    || fzn_caller_recv(asking->caller, msg, reply, reply_cap, reply_len, 3000u)
	               != FZN_CALLER_OK) {
		link_answered(li, began, 0, 1);
		return 0;
	}
	link_answered(li, began, *reply_len, 0);
	said_refusal(asking->host, reply, *reply_len);
	return 1;
}

struct pull_target {
	const char *host;
	long port;
	int is_root_at;
	uint8_t node[FZN_PUBKEY_LEN];
	fzn_node_pairing_t pairing;
	fzn_caller_t caller;
	fzn_reasm_t table;
	fzn_partial_t slot;
	uint8_t slot_buf[FZND_PULL_REPLY_MAX];
	int fd;
};

/* A ROUND'S STEPS, in order, sec 636: the loop runs one each pass and
 * answers between them. 0 is no round under way. */
enum {
	ROUND_START = 1,
	ROUND_JOURNAL,
	ROUND_JOURNAL_SETTLE,
	ROUND_RECONCILE,
	ROUND_ROUTING,
	ROUND_ROUTING_AFTER,
	ROUND_GRANTS,
	ROUND_MESSAGES,
	ROUND_MESSAGES_AFTER,
	ROUND_MEMBERS,
	ROUND_NOTES,
	ROUND_NOTES_SETTLE,
	ROUND_RECEIVED_IN_ROUND,
	ROUND_RECEIVED_SETTLE_IN_ROUND,
	ROUND_CONTACTS,
	ROUND_CONTACTS_SETTLE,
	ROUND_GROUPS,
	ROUND_GROUPS_SETTLE,
	ROUND_GROUP_LINES_SETTLE,
	ROUND_GROUP_SHARES_SETTLE,
	ROUND_REFERENCES,
	ROUND_REFERENCES_SETTLE,
	ROUND_END,
	/* A FRESH WRITE'S STEPS, not the round's (`fresh_*_plan`). */
	ROUND_MESSAGES_ROUND,
	ROUND_DELIVER,
	/* WHAT THE USER ASKED FOR AT ONCE: `fetch stream`, `fetch address`. */
	ROUND_STREAMS,
	ROUND_STREAMS_SETTLE,
	/* A SHARE ACCEPTED, pulled at once (sec 437). */
	ROUND_RECEIVED,
	ROUND_SHARES_SETTLE,
	ROUND_ADDRESS,
	ROUND_ADDRESS_SETTLE
};

/* WHAT THE LOOP RUNS, a step a pass, 0 ending it: the round; or what a
 * write made here sends at once, sec 449 and 528 -- the same steps, every
 * peer asked at once and the loop answering between, where the write's
 * pulls and deliveries once asked in turn and answered nobody. */
static const int round_plan[] = {
	ROUND_START,    ROUND_JOURNAL,         ROUND_JOURNAL_SETTLE,  ROUND_RECONCILE,
	ROUND_ROUTING,  ROUND_ROUTING_AFTER,   ROUND_GRANTS,          ROUND_MESSAGES,        ROUND_MESSAGES_AFTER,
	ROUND_MEMBERS,  ROUND_NOTES,           ROUND_NOTES_SETTLE,    ROUND_RECEIVED_IN_ROUND,
	ROUND_RECEIVED_SETTLE_IN_ROUND,        ROUND_CONTACTS,        ROUND_CONTACTS_SETTLE,
	ROUND_GROUPS,   ROUND_GROUPS_SETTLE,   ROUND_GROUP_LINES_SETTLE,
	ROUND_GROUP_SHARES_SETTLE,             ROUND_REFERENCES,      ROUND_REFERENCES_SETTLE,
	ROUND_END,      0
};
/* A NOTE WRITTEN HERE: in the journal, pushed with it (sec 519), then the
 * notes' work with each peer. */
static const int fresh_notes_plan[] = {
	ROUND_JOURNAL, ROUND_JOURNAL_SETTLE, ROUND_MESSAGES_ROUND, ROUND_MEMBERS,
	ROUND_NOTES,   ROUND_NOTES_SETTLE,   0
};
/* A MESSAGE WRITTEN HERE: the journal pushed, keys given and asked, the
 * line delivered. */
static const int fresh_messages_plan[] = {
	ROUND_JOURNAL, ROUND_JOURNAL_SETTLE, ROUND_MESSAGES_ROUND, ROUND_DELIVER, 0
};
/* A STREAM FETCH ASKED (sec 632), and WHERE THIS HOST IS SEEN (sec 621). */
static const int streams_plan[] = { ROUND_STREAMS, ROUND_STREAMS_SETTLE, 0 };
static const int received_plan[] = { ROUND_RECEIVED, ROUND_SHARES_SETTLE, 0 };
static const int address_plan[] = { ROUND_ADDRESS, ROUND_ADDRESS_SETTLE, 0 };

/* THE PEERS THAT DID NOT ANSWER THIS ROUND, sec 587, by where they are: a
 * peer whose journal pull goes unanswered is passed over by the rest of the
 * round, which otherwise waited out a timeout at every step -- a root away
 * cost a member every exchange of its round before its siblings were asked.
 * Kept by host and port rather than on the target, since a round rebuilds
 * its sibling targets after the pull; cleared when a round starts, so each
 * round asks every peer again. */
static struct {
	const char *host;
	long port;
} silent[FZND_ROUND_TARGETS_MAX];
static size_t n_silent;

static int silent_peer(const struct pull_target *pt)
{
	size_t i;

	for (i = 0; i < n_silent; i++)
		if (silent[i].port == pt->port && strcmp(silent[i].host, pt->host) == 0)
			return 1;
	return 0;
}

static void silent_mark(const struct pull_target *pt)
{
	if (n_silent < FZND_ROUND_TARGETS_MAX && !silent_peer(pt)) {
		silent[n_silent].host = pt->host;
		silent[n_silent].port = pt->port;
		n_silent++;
	}
}

/* The members the last round's pulls proved, sec 445, kept so the writer set
 * can be rebuilt between rounds. */
static uint8_t pulled_members[FZN_NODE_NOTES_WRITERS][FZN_PUBKEY_LEN];
static size_t n_pulled_members;

/* THE WRITERS BEYOND THIS NODE AND ITS PULL PEERS, rebuilt from what is live
 * now, sec 451: the estate's standing roots (sec 450), the peers paired to
 * this node that are no contact (sec 436), and the members the last round
 * proved. Asked every pass of the loop, so a device paired or un-paired on
 * the socket is a writer, or not, at once rather than after a restart. */
static void admit_writers(const fzn_node_state_t *state, const fzn_node_roots_t *roots)
{
	static uint8_t keys[FZN_NODE_NOTES_WRITERS][FZN_PUBKEY_LEN];
	size_t n, i;

	if (!notes_on)
		return;
	n = fzn_node_roots_standing(roots, keys, FZN_NODE_NOTES_WRITERS);
	for (i = 0; i < state->peer_count && n < FZN_NODE_NOTES_WRITERS; i++)
		if (!fzn_node_peer_contact(&state->config, &state->peers[i]))
			memcpy(keys[n++], state->peers[i].sender, FZN_PUBKEY_LEN);
	for (i = 0; i < n_pulled_members && n < FZN_NODE_NOTES_WRITERS; i++)
		memcpy(keys[n++], pulled_members[i], FZN_PUBKEY_LEN);
	(void)fzn_node_notes_admit_members(&node_notes, (const uint8_t (*)[FZN_PUBKEY_LEN])keys, n);
}

/* ---- the round's conversations, sec 636 ------------------------------------
 *
 * A ROUND STEP THAT ASKS EVERY PEER AT ONCE: one conversation with each
 * (`node/talk.h`), every request awaited by the loop beside the requests it
 * answers, and the round going on only once all are over. Where the round
 * asked its peers one after another, each silent one cost a timeout and
 * every host waited out the others' rounds; here a step's silent peers
 * cost one timeout together, and this host answers while it waits.
 *
 * Metered as `peer_ask` meters, a link's requests and answers counted and
 * a refusal in words said. */
_Static_assert(FZND_PULL_REPLY_MAX >= 16384u, "a members page fits the round's answers");

static fzn_node_asks_t round_asks;
static uint8_t round_reply[FZND_PULL_REPLY_MAX];
static size_t round_pending;


static uint64_t round_clock_ms(void)
{
	return mono_ms();
}

static void round_talk_over(void *ctx)
{
	(void)ctx;
	if (round_pending)
		round_pending--;
}

/* A CONVERSATION'S METER: its link, and when its request went -- metered as
 * `peer_ask` meters, a link's requests and answers counted and a refusal
 * in words said. */
struct meter {
	const struct pull_target *pt;
	int silences; /* a round target, passed over once silent; a contact's host is not */
	size_t li;
	const char *host;
	uint64_t began;
};

/* AN ANSWER, or none: and a peer that does not answer passed over by the
 * rest of the round, as one whose journal pull went unanswered is (sec
 * 587) -- a sibling loaded mid-round (sec 586) is asked first here, and
 * every later step would otherwise wait out its silence again. */
static void meter_answer(struct meter *m, const uint8_t *reply, size_t reply_len)
{
	link_answered(m->li, m->began, reply_len, !reply);
	if (reply)
		said_refusal(m->host, reply, reply_len);
	else if (m->pt && m->silences)
		silent_mark(m->pt);
}

static void meter_asked(struct meter *m, size_t request_len)
{
	link_asked(m->li, request_len);
	m->began = mono_ms();
}

struct round_talk {
	fzn_node_talk_t talk;
	const struct pull_target *pt;
	struct meter m;
	uint8_t request[FZN_NODE_MEMBERS_QUERY_LEN];
	fzn_node_members_pulling_t members;
	fzn_node_members_err_t merr;
	uint8_t got[FZN_NODE_NOTES_WRITERS][FZN_PUBKEY_LEN];
};
static struct round_talk round_talks[FZND_ROUND_TARGETS_MAX];
static size_t n_round_talks;

/* A CONVERSATION WITH `pt` STARTED, its first request already written:
 * awaited by the round, `over` told when it ends, or, when it will not
 * leave, counted lost. `silences`: `pt` is a round target, passed over
 * once silent. 1 when awaited. */
static int talk_start_over(fzn_node_talk_t *talk, struct meter *m, const struct pull_target *pt,
                           uint64_t now, fzn_node_talk_step_fn step, fzn_node_talk_over_fn over,
                           int silences, void *ctx, uint8_t *request, size_t cap, size_t len)
{
	m->pt = pt;
	m->silences = silences;
	m->li = link_of(&pt->caller.node);
	m->host = pt->host;
	meter_asked(m, len);
	if (fzn_node_talk_start(talk, &round_asks, (fzn_caller_t *)&pt->caller, now + 300u, 3000u,
	                        step, over, ctx, request, cap, len)) {
		round_pending++;
		return 1;
	}
	link_answered(m->li, m->began, 0, 1);
	if (m->silences)
		silent_mark(pt);
	return 0;
}

/* A ROUND TARGET'S CONVERSATION: the round told when it is over. */
static int talk_start(fzn_node_talk_t *talk, struct meter *m, const struct pull_target *pt,
                      uint64_t now, fzn_node_talk_step_fn step, void *ctx, uint8_t *request,
                      size_t cap, size_t len)
{
	return talk_start_over(talk, m, pt, now, step, round_talk_over, 1, ctx, request, cap, len);
}

/* A MEMBERS PAGE'S ANSWER, or none: metered, and the pull carried on. */
static int members_talk_step(void *ctx, const uint8_t *reply, size_t reply_len, uint8_t *request,
                             size_t cap, size_t *request_len)
{
	struct round_talk *rt = ctx;
	int done = 0;

	meter_answer(&rt->m, reply, reply_len);
	rt->merr = fzn_node_members_pull_step(&rt->members, reply, reply_len, request, cap,
	                                      request_len, &done);
	if (rt->merr != FZN_NODE_MEMBERS_OK || done)
		return 0;
	meter_asked(&rt->m, *request_len);
	return 1;
}

/* THE ESTATE'S MEMBERS, sec 445, asked of every peer at once: each admitted
 * on the proof of its chain against this node's own root, so a note a
 * member wrote and a peer relays is taken. Rebuilt every round, so a member
 * revoked since drops out. `members_settle` takes what came. */
static void members_start(const struct pull_target *pulls, size_t npulls, uint64_t now,
                          const fzn_node_config_t *config,
                          const fzn_revocation_store_t *revocations)
{
	size_t t, len;

	n_round_talks = 0;
	if (!notes_on)
		return;
	for (t = 0; t < npulls && n_round_talks < FZND_ROUND_TARGETS_MAX; t++) {
		struct round_talk *rt = &round_talks[n_round_talks];

		if (silent_peer(&pulls[t]))
			continue;
		rt->pt = &pulls[t];
		len = 0;
		if (fzn_node_members_pull_begin(&rt->members, config->root,
		                                &config->remote_capability, now,
		                                node_notes.author.sign, revocations, rt->got,
		                                FZN_NODE_NOTES_WRITERS, rt->request,
		                                sizeof(rt->request), &len)
		    != FZN_NODE_MEMBERS_OK)
			continue;
		n_round_talks++;
		rt->merr = FZN_NODE_MEMBERS_ERR_NO_ANSWER;
		(void)talk_start(&rt->talk, &rt->m, &pulls[t], now, members_talk_step, rt,
		                 rt->request, sizeof(rt->request), len);
	}
}

/* WHAT THE MEMBERS' CONVERSATIONS BROUGHT, every peer's in turn, the
 * writers admitted from them. */
static void members_settle(const fzn_node_state_t *state, const fzn_node_roots_t *roots)
{
	size_t i, k, n = 0;

	if (!notes_on)
		return;
	for (i = 0; i < n_round_talks; i++) {
		const struct round_talk *rt = &round_talks[i];

		if (rt->merr != FZN_NODE_MEMBERS_OK) {
			say(FZN_ENTRY_WARNING, "members", "members from %s: %s", rt->pt->host,
			    fzn_node_members_err_str(rt->merr));
			continue;
		}
		if (rt->members.refused)
			say(FZN_ENTRY_WARNING, "members", "%zu member(s) from %s did not prove",
			    rt->members.refused, rt->pt->host);
		for (k = 0; k < rt->members.count && n < FZN_NODE_NOTES_WRITERS; k++)
			memcpy(pulled_members[n++], rt->got[k], FZN_PUBKEY_LEN);
	}
	n_pulled_members = n;
	admit_writers(state, roots);
}

#ifdef FZN_RECORD_STORE_FILE_ON
/* THE JOURNAL, sec 501: every key's estate stream this node follows, in
 * `records/` under the core directory, served to members and pulled from the
 * pull peers each round. */
static fzn_node_journal_t node_journal;
static int journal_on;

/* THE NODE'S CONVERSATIONS, sec 527: lines on every device's stream 3,
 * carried by the journal; keys carried member to member each round. */
static fzn_node_messages_t node_messages;
static int messages_on;

/* THE OPERATION JOURNAL, secs 523 and 524: switchable, off unless asked
 * for. Every write to this node's persistent state, entered by hash on its
 * own stream, in generations under `opjournal/`, a directory each named by
 * its number, which nothing serves. */
static fzn_node_journal_t op_nj[FZN_OPJOURNAL_GENERATIONS_MAX];
static char op_dir[FZN_RECORD_STORE_FILE_PATH_MAX];
static const uint8_t *op_issuer;
static const fzn_sign_ops_t *op_sign;
static const fzn_hash_ops_t *op_hash;
static fzn_opjournal_t op_oj;
static fzn_persist_ops_t op_ops;

static int op_generation_dir(uint64_t generation, char *out, size_t cap)
{
	int w = snprintf(out, cap, "%s/%llu", op_dir, (unsigned long long)generation);

	return w > 0 && (size_t)w < cap;
}

static fzn_node_journal_t *op_generation_open(void *ctx, uint64_t generation)
{
	fzn_node_journal_t *nj = &op_nj[generation % FZN_OPJOURNAL_GENERATIONS_MAX];
	char dir[FZN_RECORD_STORE_FILE_PATH_MAX];

	(void)ctx;
	if (!op_generation_dir(generation, dir, sizeof(dir))
	    || (mkdir(dir, 0700) != 0 && errno != EEXIST))
		return NULL;
	fzn_node_journal_close(nj);
	if (fzn_node_journal_init(nj, dir, op_sign, op_hash) != FZN_NODE_JOURNAL_OK
	    || fzn_node_journal_follow_stream(nj, op_issuer, FZN_OPJOURNAL_STREAM, NULL)
	               != FZN_NODE_JOURNAL_OK)
		return NULL;
	return nj;
}

/* DROPPED WHOLE: the generation's one stream file, named by the store that
 * wrote it rather than spelled here, then its directory. */
static void op_generation_drop(void *ctx, uint64_t generation)
{
	fzn_node_journal_t *nj = &op_nj[generation % FZN_OPJOURNAL_GENERATIONS_MAX];
	char dir[FZN_RECORD_STORE_FILE_PATH_MAX];
	fzn_record_store_file_t file;

	(void)ctx;
	fzn_node_journal_close(nj);
	memset(nj, 0, sizeof(*nj));
	if (!op_generation_dir(generation, dir, sizeof(dir)) || !fzn_record_store_file_open(&file, dir))
		return;
	(void)fzn_record_store_file_forget(&file, op_issuer, FZN_OPJOURNAL_STREAM);
	(void)rmdir(dir);
}

/* WHICH GENERATIONS EXIST: the directories under `opjournal/` named by a
 * number, which must run unbroken. Nonzero unless they do not. */
static int op_generations_held(uint64_t *first, uint64_t *last)
{
	DIR *d = opendir(op_dir);
	struct dirent *ent;
	uint64_t count = 0;

	*first = *last = 0u;
	if (!d)
		return 0;
	while ((ent = readdir(d)) != NULL) {
		char *end = NULL;
		unsigned long long g;

		if (ent->d_name[0] < '1' || ent->d_name[0] > '9')
			continue;
		g = strtoull(ent->d_name, &end, 10);
		if (!end || *end != '\0')
			continue;
		if (*first == 0u || g < *first)
			*first = g;
		if (g > *last)
			*last = g;
		count++;
	}
	(void)closedir(d);
	return count == 0u
	       || (*last - *first + 1u == count && count <= FZN_OPJOURNAL_GENERATIONS_MAX);
}

/* Open it over `*ops`, and make `*ops` the journalled ops. A replay opens
 * only a journal that exists, and writes none into being. */
static int op_journal_open(const char *store_dir, const uint8_t issuer[FZN_PUBKEY_LEN],
                           const fzn_sign_ops_t *sign, const fzn_hash_ops_t *hash,
                           uint64_t budget, uint64_t rotate_at, int replaying,
                           const fzn_persist_ops_t **ops)
{
	int w = snprintf(op_dir, sizeof(op_dir), "%s/opjournal", store_dir);

	if (w <= 0 || (size_t)w >= sizeof(op_dir) || (mkdir(op_dir, 0700) != 0 && errno != EEXIST))
		return 0;
	memset(&op_oj, 0, sizeof(op_oj));
	if (!op_generations_held(&op_oj.first, &op_oj.last) || (replaying && op_oj.last == 0u))
		return 0;
	op_issuer = issuer;
	op_sign = sign;
	op_hash = hash;
	op_oj.generations.open = op_generation_open;
	op_oj.generations.drop = op_generation_drop;
	op_oj.keep = FZND_OP_JOURNAL_KEEP;
	op_oj.rotate_at = rotate_at;
	op_oj.base = *ops;
	op_oj.issuer = issuer;
	op_oj.sign = sign;
	op_oj.hash = hash;
	op_oj.now = wall_ms;
	op_oj.budget = budget;
	if (!fzn_opjournal_start(&op_oj))
		return 0;
	fzn_opjournal_ops(&op_oj, &op_ops);
	*ops = &op_ops;
	return 1;
}

/* What the roots call for every act logged: the act's own signed object, as
 * the next record of its signer's estate stream. sec 502. */
static int journal_logged(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN],
                          const fzn_sign_ops_t *sign, uint8_t kind,
                          const uint8_t act[FZN_ROOT_ACT_ID_LEN], const uint8_t *record,
                          size_t len)
{
	(void)kind;
	(void)act;
	return fzn_node_journal_append_object((fzn_node_journal_t *)ctx, pubkey, sign, record, len,
	                                      wall_ms(), NULL)
	       == FZN_NODE_JOURNAL_OK;
}

/* What the notes' author calls for every note record, sec 517: the next of
 * this node's stream 0, chained and kept, and handed back for the claims
 * index. */
static int journal_chain(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN],
                         const fzn_sign_ops_t *sign, uint32_t kind,
                         const uint8_t subject[FZN_SUBJECT_LEN],
                         const uint8_t *body, size_t body_len, uint64_t now_ms, uint8_t *record,
                         size_t cap, size_t *record_len)
{
	return fzn_node_journal_write((fzn_node_journal_t *)ctx, issuer, FZN_NOTE_STREAM, sign, kind,
	                              subject, body, body_len, now_ms, record, cap, record_len, NULL)
	       == FZN_NODE_JOURNAL_OK;
}

#endif

/* THE JOURNAL FOR `roots`, sec 508: opened once in `records/` under
 * `store_dir`, and `roots` then log every act into it and judge every cut by
 * it. The running daemon and `--pair` both come here, since an act logged
 * anywhere else is an act no peer ever sees. 1 when the journal is open; 0
 * with no store directory, a records directory that will not open, or a
 * build without the record file store. */
static int journal_for(const char *store_dir, fzn_node_roots_t *roots, const fzn_sign_ops_t *sign,
                       const fzn_hash_ops_t *hash, const fzn_persist_ops_t *keep)
{
#ifdef FZN_RECORD_STORE_FILE_ON
	static char records_dir[FZN_RECORD_STORE_FILE_PATH_MAX];

	if (!journal_on) {
		int w;

		if (!store_dir)
			return 0;
		w = snprintf(records_dir, sizeof(records_dir), "%s/records", store_dir);
		if (w <= 0 || (size_t)w >= sizeof(records_dir)
		    || (mkdir(records_dir, 0700) != 0 && errno != EEXIST)
		    || fzn_node_journal_init(&node_journal, records_dir, sign, hash)
		               != FZN_NODE_JOURNAL_OK)
			return 0;
		journal_on = 1;
	}
	/* THE SPINE AND THE BASES IN THE NODE'S STORE, secs 546 and 547, so an
	 * act cut from the journal is still judged and a cut stream is read
	 * from where it starts. */
	if (keep)
		node_journal.keep = keep;
	if (roots) {
		roots->logged = journal_logged;
		roots->logged_ctx = &node_journal;
		if (fzn_node_roots_set_journal(roots, &node_journal) != FZN_NODE_ROOTS_OK)
			return 0;
	}
	return 1;
#else
	(void)store_dir;
	(void)roots;
	(void)sign;
	(void)hash;
	(void)keep;
	return 0;
#endif
}

#ifdef FZN_RECORD_STORE_FILE_ON
/* A PUSH TAKEN, sec 519: a member's notes arrive in the journal, and a hub
 * that pulls from nobody hears them only so. The loop feeds the index at
 * once rather than at the next round, as the notes' own push did. */
static int journal_pushed;

static size_t journal_remote(void *ctx, const uint8_t *request, size_t request_len,
                             uint8_t *reply, size_t reply_cap)
{
	size_t n = fzn_node_journal_answer((fzn_node_journal_t *)ctx, request, request_len, reply,
	                                   reply_cap);

	if (n && request_len >= 2u && request[0] == FZN_EXCHANGE_VERSION
	    && request[1] == FZN_EXCHANGE_PUSH)
		journal_pushed = 1;
	return n;
}

/* THE NODES WHOSE NOTES THIS NODE FILES, sec 519: itself, the estate's
 * root node, the peers paired to it that are no contact, and the members
 * the last round proved -- the keys that write notes, where roots are keys
 * that write acts. Each one's notes stream is followed, and its records fed
 * into the index from a cursor kept for it here. */
#define NOTES_STREAMS_MAX (FZN_NODE_JOURNAL_STREAMS_MAX / 2u)
static uint8_t notes_keys[NOTES_STREAMS_MAX][FZN_PUBKEY_LEN];
static size_t n_notes_keys;
static struct notes_cursor {
	uint8_t key[FZN_PUBKEY_LEN];
	uint64_t at;
} notes_cursors[NOTES_STREAMS_MAX];
static size_t n_notes_cursors;

/* The journal applied to the node's subsystems, sec 503. */
static fzn_node_apply_t node_apply;

/* FOLLOW THE ESTATE: this node's own keys, the roots that stand, the peers
 * paired to it that are no contact, and the members the last round proved.
 * Asked every round, so a member paired since is followed from its first
 * act. Following is idempotent. The nodes among them are followed on their
 * notes stream too (sec 519). */
static void follow_estate(const uint8_t identity[FZN_PUBKEY_LEN], const fzn_node_state_t *state,
                          const fzn_node_roots_t *roots)
{
	static uint8_t keys[FZN_NODE_JOURNAL_STREAMS_MAX][FZN_PUBKEY_LEN];
	size_t n = 0, i;

	if (!journal_on)
		return;
	memcpy(keys[n++], identity, FZN_PUBKEY_LEN);
	memcpy(keys[n++], state->config.root, FZN_PUBKEY_LEN);
	if (roots) {
		if (roots->key_held)
			memcpy(keys[n++], roots->key, FZN_PUBKEY_LEN);
		n += fzn_node_roots_standing(roots, keys + n, FZN_NODE_JOURNAL_STREAMS_MAX / 2u - n);
	}
	for (i = 0; i < state->peer_count && n < FZN_NODE_JOURNAL_STREAMS_MAX; i++)
		if (!fzn_node_peer_contact(&state->config, &state->peers[i]))
			memcpy(keys[n++], state->peers[i].sender, FZN_PUBKEY_LEN);
	for (i = 0; i < n_pulled_members && n < FZN_NODE_JOURNAL_STREAMS_MAX; i++)
		memcpy(keys[n++], pulled_members[i], FZN_PUBKEY_LEN);
	/* EVERY MEMBER THE GRANTS NAME, sec 579: a member that writes no notes
	 * is proved by none, and its stream -- its prekey among it -- reached
	 * only the root it pushes to. The grants indexed from the estate's
	 * streams name every key granted the member capability; following each
	 * is what lets siblings find one another. A key followed twice is one
	 * follow. */
	for (i = 0; i < node_apply.grants_used && n < FZN_NODE_JOURNAL_STREAMS_MAX; i++)
		if (memcmp(node_apply.grants[i].capability.b, state->config.remote_capability.b,
		           FZN_CAP_ID_LEN) == 0)
			memcpy(keys[n++], node_apply.grants[i].grantee, FZN_PUBKEY_LEN);
	for (i = 0; i < n; i++)
		if (fzn_node_journal_follow(&node_journal, keys[i], NULL) == FZN_NODE_JOURNAL_FULL) {
			say(FZN_ENTRY_WARNING, "journal", "no room to follow another key's stream");
			break;
		}
	/* THE NODES' NOTES STREAMS: the same keys less the roots. */
	n_notes_keys = 0;
	memcpy(notes_keys[n_notes_keys++], identity, FZN_PUBKEY_LEN);
	memcpy(notes_keys[n_notes_keys++], state->config.root, FZN_PUBKEY_LEN);
	for (i = 0; i < state->peer_count && n_notes_keys < NOTES_STREAMS_MAX; i++)
		if (!fzn_node_peer_contact(&state->config, &state->peers[i]))
			memcpy(notes_keys[n_notes_keys++], state->peers[i].sender, FZN_PUBKEY_LEN);
	for (i = 0; i < n_pulled_members && n_notes_keys < NOTES_STREAMS_MAX; i++)
		memcpy(notes_keys[n_notes_keys++], pulled_members[i], FZN_PUBKEY_LEN);
	for (i = 0; i < n_notes_keys; i++)
		if (fzn_node_journal_follow_stream(&node_journal, notes_keys[i], FZN_NOTE_STREAM, NULL)
		    == FZN_NODE_JOURNAL_FULL) {
			say(FZN_ENTRY_WARNING, "journal", "no room to follow another node's notes");
			break;
		}
	/* THEIR CATALOGUE, sec 633: the same nodes' stream 4, this estate's
	 * alone -- a user's library is its own devices'. */
	for (i = 0; i < n_notes_keys; i++)
		if (fzn_node_journal_follow_stream(&node_journal, notes_keys[i], FZN_CATALOG_STREAM, NULL)
		    == FZN_NODE_JOURNAL_FULL) {
			say(FZN_ENTRY_WARNING, "journal", "no room to follow another node's catalogue");
			break;
		}
	/* THEIR CONVERSATIONS, sec 527: the same nodes' stream 3. Measured
	 * against the DISTINCT keys, as the devices are counted: a node that
	 * is its own root lists its key twice, and counting the copy warned on
	 * every start of a node with nobody to fall short of. */
	if (messages_on) {
		size_t distinct = 0, j;

		for (i = 0; i < n_notes_keys; i++) {
			for (j = 0; j < i && memcmp(notes_keys[j], notes_keys[i], FZN_PUBKEY_LEN) != 0;
			     j++)
				;
			distinct += j == i;
		}
		if (fzn_node_messages_devices(&node_messages,
		                              (const uint8_t(*)[FZN_PUBKEY_LEN])notes_keys,
		                              n_notes_keys)
		    < (distinct < FZN_MESSAGES_DEVICES_MAX ? distinct : FZN_MESSAGES_DEVICES_MAX))
			say(FZN_ENTRY_WARNING, "messages",
			    "not every node's conversations are followed");
	}
}

/* A note record out of the journal's store, for the index. */
static int journal_read(void *ctx, const uint8_t key[FZN_PUBKEY_LEN], uint64_t seq, uint8_t *out,
                        size_t cap, size_t *out_len)
{
	fzn_record_t rec;

	(void)ctx;
	if (fzn_record_store_get(&node_journal.store, key, FZN_NOTE_STREAM, seq, out, cap, &rec)
	    != FZN_RECORD_STORE_OK)
		return 0;
	*out_len = rec.len;
	return 1;
}

/* THE INDEX FED FROM THE JOURNAL, sec 519: every node's notes stream from
 * where this run last left it -- from its base at start (sec 547), which
 * rebuilds the index from what is held, so a record kept and not filed
 * before a crash is filed now. */
static void index_notes(void)
{
	size_t i, k;
	int changed = 0;

	if (!journal_on || !notes_on)
		return;
	for (i = 0; i < n_notes_keys; i++) {
		fzn_node_notes_index_tally_t t;
		fzn_notes_err_t err;
		struct notes_cursor *c = NULL;
		uint64_t to = fzn_node_journal_received(&node_journal, notes_keys[i], FZN_NOTE_STREAM);

		for (k = 0; k < n_notes_cursors && !c; k++)
			if (memcmp(notes_cursors[k].key, notes_keys[i], FZN_PUBKEY_LEN) == 0)
				c = &notes_cursors[k];
		if (!c) {
			if (n_notes_cursors >= NOTES_STREAMS_MAX)
				break;
			c = &notes_cursors[n_notes_cursors++];
			memcpy(c->key, notes_keys[i], FZN_PUBKEY_LEN);
			/* FROM THE STREAM'S BASE, sec 547: below it is cut. */
			c->at = fzn_node_journal_base(&node_journal, notes_keys[i], FZN_NOTE_STREAM)
			        - 1u;
		}
		if (c->at >= to)
			continue;
		err = fzn_node_notes_index_stream(&node_notes, journal_read, NULL, notes_keys[i], &c->at,
		                                  to, &t);
		if (err != FZN_NOTES_OK)
			say(FZN_ENTRY_WARNING, "notes/index", "a notes stream would not all file: %s",
			    fzn_notes_err_str(err));
		else if (t.filed || t.purged || t.waiting)
			say(FZN_ENTRY_INFO, "notes/index",
			    "%zu note record(s) filed, %zu purge(s), %zu held already%s", t.filed,
			    t.purged, t.held, t.waiting ? ", a writer not yet admitted waits" : "");
		if (err == FZN_NOTES_OK && (t.filed || t.purged))
			changed = 1;
	}
	if (changed)
		publish("note", NULL);
}

/* THE JOURNAL APPLIED, sec 503: every object pulled, handed to the subsystem
 * that keeps its kind, with its signer's chain rebuilt from the grants held. */

/* THIS HOST'S PREKEY INTO ITS ESTATE STREAM, sec 579, at every start, so each
 * sibling can pair it: carried once, and again only when the agreement key
 * carried is not this identity's. Not the whole record: the identity signs
 * its record afresh at every load (`node/identity.c`), dated then, so the
 * bytes differ at each start while the key does not. The record is public
 * by design; what makes a sibling keep it is that this host carried it
 * about itself. */
static void carry_prekey(const fzn_node_identity_t *id)
{
	uint8_t kept[FZN_PREKEY_LEN_TOTAL];
	fzn_prekey_record_t held, own;
	fzn_node_siblings_err_t err;

	if (fzn_node_siblings_prekey(node_apply.store, id->pubkey, kept) == FZN_NODE_SIBLINGS_OK
	    && fzn_prekey_open(kept, sizeof(kept), &held) == FZN_PREKEY_OK
	    && fzn_prekey_open(id->prekey_record, FZN_PREKEY_LEN_TOTAL, &own) == FZN_PREKEY_OK
	    && memcmp(held.prekey, own.prekey, FZN_PREKEY_LEN) == 0)
		return;
	if (fzn_node_journal_append_object(&node_journal, id->pubkey, id->sign, id->prekey_record,
	                                   FZN_PREKEY_LEN_TOTAL, wall_clock() * 1000u, NULL)
	    != FZN_NODE_JOURNAL_OK) {
		say(FZN_ENTRY_WARNING, "node/siblings",
		    "this host's prekey is not in its estate stream: no sibling can pair it");
		return;
	}
	err = fzn_node_siblings_learn(node_apply.store, id->sign, id->prekey_record,
	                              FZN_PREKEY_LEN_TOTAL, id->pubkey);
	if (err != FZN_NODE_SIBLINGS_OK)
		say(FZN_ENTRY_WARNING, "node/siblings", "this host's prekey was carried and not kept: %s",
		    fzn_node_siblings_err_str(err));
	else
		say(FZN_ENTRY_INFO, "node/siblings", "this host's prekey carried in its estate stream");
}

static void apply_journal(void)
{
	fzn_node_apply_tally_t tally;
	fzn_node_pull_err_t err;

	if (!journal_on || !node_apply.journal)
		return;
	err = fzn_node_apply_round(&node_apply, &tally);
	if (err != FZN_NODE_PULL_OK)
		say(FZN_ENTRY_WARNING, "journal", "applying the journal: %s",
		    fzn_node_pull_err_str(err));
	else if (tally.applied || tally.grants || tally.refused || tally.waiting)
		say(tally.refused ? FZN_ENTRY_WARNING : FZN_ENTRY_INFO, "journal",
		    "%zu object(s) applied, %zu grant(s) indexed, %zu refused, %zu stream(s) waiting "
		    "on a chain",
		    tally.applied, tally.grants, tally.refused, tally.waiting);
	/* THE ESTATE'S STATE CHANGED -- settings, contacts, groups, grants -- sec
	 * 609. */
	if (err == FZN_NODE_PULL_OK && (tally.applied || tally.grants))
		publish("estate", NULL);
}

/* WHAT THIS NODE HOLDS OF THE ESTATE'S STATE, served to a member, sec 551. */
/* WHAT ONE CALLER IS SERVED OF THE APPEND-ONLY KINDS, sec 567: every
 * bucket when it holds the retention capability, and otherwise only its
 * own -- its user's conversations, which here means it is one of the
 * devices whose lines this node follows. Decided once a request. */
struct serving_to {
	const uint8_t *sender;
	int holds; /* -1 not asked yet */
};

/* The retention capability, NULL on a node that derives none. */
static const fzn_cap_id_t *retention_capability;

static int serves_bucket(void *ctx, fzn_buckets_kind_t kind, const uint8_t subject[FZN_PUBKEY_LEN])
{
	struct serving_to *to = (struct serving_to *)ctx;
	size_t d;

	/* A PIECE goes only to the host it was placed on, sec 597, whatever
	 * else the caller may hold. */
	if (kind == FZN_BUCKETS_PIECES)
		return memcmp(subject, to->sender, FZN_PUBKEY_LEN) == 0;
	if (to->holds < 0)
		to->holds = retention_capability
		            && fzn_node_apply_holds(&node_apply, to->sender, retention_capability);
	if (to->holds)
		return 1;
	/* A HOST'S OWN LOG is its own to be served, sec 571. */
	if (kind == FZN_BUCKETS_LOGS)
		return memcmp(subject, to->sender, FZN_PUBKEY_LEN) == 0;
	if (kind == FZN_BUCKETS_MESSAGES && messages_on)
		for (d = 0; d < node_messages.m.device_count; d++)
			if (memcmp(node_messages.devices[d], to->sender, FZN_PUBKEY_LEN) == 0)
				return 1;
	return 0;
}

/* A NOTE CLAIM RECONCILED, sec 555: filed as the index files one, a writer
 * not admitted yet left to be offered again. */
static fzn_node_apply_outcome_t notes_file(void *ctx, const uint8_t *record, size_t len)
{
	switch (fzn_node_notes_file((fzn_node_notes_t *)ctx, record, len, NULL)) {
	case FZN_NOTES_OK:
		return FZN_NODE_APPLY_APPLIED;
	case FZN_NOTES_ERR_DENIED:
		return FZN_NODE_APPLY_WAITING;
	case FZN_NOTES_ERR_FULL:
	case FZN_NOTES_ERR_BACKEND:
		return FZN_NODE_APPLY_NOT_SAVED;
	default:
		return FZN_NODE_APPLY_REFUSED;
	}
}

static int messages_upgrade(void);

/* WHAT A CONVERSATIONS ROUND IS ASKED BY: the store, and the message
 * rules and policies that reach this node, gathered once a pass. */
static struct line_rules {
	fzn_retain_rule_t rules[FZN_RETAIN_RULES_MAX];
	size_t n;
	uint64_t now_ms;
} line_rules;

/* A LINE RECONCILED, sec 564: filed by the messages store, waiting when
 * its key is not here yet. */
static fzn_node_apply_outcome_t line_file(void *ctx, const uint8_t contact[FZN_PUBKEY_LEN],
                                          uint32_t epoch, const uint8_t *item, size_t len)
{
	int waiting = 0;

	(void)ctx;
	switch (fzn_node_messages_file(&node_messages, contact, epoch, item, len, &waiting)) {
	case FZN_MESSAGES_OK: {
		/* A LINE FILED FROM A PEER, its conversation named, sec 609. */
		char hex[2u * FZN_PUBKEY_LEN + 1u];
		size_t i;

		for (i = 0; i < FZN_PUBKEY_LEN; i++)
			(void)snprintf(hex + 2u * i, 3u, "%02x", contact[i]);
		publish("message", hex);
		return waiting ? FZN_NODE_APPLY_WAITING : FZN_NODE_APPLY_APPLIED;
	}
	case FZN_MESSAGES_ERR_BACKEND:
		return FZN_NODE_APPLY_NOT_SAVED;
	default:
		return FZN_NODE_APPLY_REFUSED;
	}
}

/* A MONTH THIS NODE WOULD HOLD, by its rules, sec 566: one it would trim
 * is not fetched. A store that cannot answer fetches, as before rules were
 * asked: a month fetched and trimmed costs a fetch. */
static int line_wanted(void *ctx, const uint8_t contact[FZN_PUBKEY_LEN], uint32_t epoch)
{
	const struct line_rules *lr = (const struct line_rules *)ctx;
	int wanted = 1;

	return fzn_messages_wanted(&node_messages.m, lr->rules, lr->n, lr->now_ms, contact, epoch,
	                           &wanted)
	                       == FZN_MESSAGES_OK
	               ? wanted
	               : 1;
}

#if defined(FZN_LOG_FILE_ON) && defined(FZN_LOG_PACK_ON)
/* THIS HOST'S LOG AS BUCKET ITEMS, sec 571: its packed segments, and the
 * copies of other hosts' it keeps, carried by the bucket exchange. Ready
 * once the log directory and this host's key are known. */
static fzn_log_buckets_t node_logs;
static fzn_buckets_t logs_store;
static fzn_reconcile_filer_t logs_filer;
static int logs_ready;
static fzn_retain_rule_t logs_own[FZN_RETAIN_RULES_MAX], logs_copy[FZN_RETAIN_RULES_MAX];
/* THE PIECES OF ARCHIVED SEGMENTS, sec 597: this host's fossils cut and
 * placed one piece to a host, and the pieces placed on this one, kept
 * under the archive's `pieces/`. Ready with the logs, when there is an
 * archive. */
static fzn_piece_buckets_t node_pieces;
static fzn_reconcile_filer_t pieces_filer;
static int pieces_ready;


static int logs_up(void)
{
	if (logs_ready)
		return 1;
	if (!dlog.on || !dlog.has_host || !dlog.hash || !dlog.verify || !node_apply.store)
		return 0;
	logs_store.store = node_apply.store;
	logs_store.hash = dlog.hash;
	if (!fzn_log_buckets_init(&node_logs, &logs_store, dlog.logger.dir, dlog.hash, dlog.verify,
	                          dlog.host))
		return 0;
	/* THIS HOST'S ARCHIVE, sec 588: where `log_round` moves segments,
	 * still held from there. */
	{
		int k = snprintf(node_logs.archive, sizeof(node_logs.archive), "%s%s",
		                 log_archive ? log_archive : dlog.logger.dir,
		                 log_archive ? "" : "/archive");

		/* ONE THAT DOES NOT FIT IS NONE, rather than a path cut short. */
		if (k < 0 || (size_t)k >= sizeof(node_logs.archive))
			node_logs.archive[0] = '\0';
	}
	fzn_log_buckets_filer(&node_logs, &logs_filer);
	if (node_logs.archive[0]) {
		char dir[sizeof(node_logs.archive) + 8u];

		if (snprintf(dir, sizeof(dir), "%s/pieces", node_logs.archive) < (int)sizeof(dir)
		    && fzn_piece_buckets_init(&node_pieces, &logs_store, dir, dlog.hash, dlog.verify,
		                              dlog.host)) {
			fzn_piece_buckets_filer(&node_pieces, &pieces_filer);
			pieces_ready = 1;
		}
	}
	logs_ready = 1;
	return 1;
}
#endif

/* A LINE PUSHED AND KEPT, sec 569: its key, when this node's, given at the
 * round's key exchange. */
static void line_pushed(void *ctx, const uint8_t contact[FZN_PUBKEY_LEN], uint32_t epoch,
                        const uint8_t *item, size_t len)
{
	fzn_node_messages_pushed((fzn_node_messages_t *)ctx, contact, epoch, item, len);
}

#if defined(FZN_LOG_FILE_ON) && defined(FZN_LOG_PACK_ON)
/* A PIECE ASKED BY ID is also served to the host whose item it is a piece
 * of, sec 599, which counts its pieces and rebuilds from them; its head
 * says whose. */
static int serves_piece(void *ctx, fzn_buckets_kind_t kind, const uint8_t subject[FZN_PUBKEY_LEN],
                        const uint8_t id[FZN_BUCKETS_ID_LEN])
{
	const struct serving_to *to = (const struct serving_to *)ctx;
	uint8_t host[FZN_PUBKEY_LEN];

	(void)subject;
	return kind == FZN_BUCKETS_PIECES && pieces_ready
	       && fzn_piece_buckets_host(&node_pieces, id, host)
	       && memcmp(host, to->sender, FZN_PUBKEY_LEN) == 0;
}
#define SERVES_PIECE serves_piece
#else
#define SERVES_PIECE NULL
#endif

static size_t holdings_remote(void *ctx, const uint8_t *sender, const uint8_t *request,
                              size_t request_len, uint8_t *reply, size_t reply_cap)
{
	const fzn_node_apply_t *ap = (const fzn_node_apply_t *)ctx;
	struct serving_to to = { sender, -1 };
	fzn_reconcile_gate_t gate = { serves_bucket, &to, SERVES_PIECE };
	fzn_reconcile_filer_t lines = { line_file, line_wanted, &line_rules, NULL, NULL, NULL };
	fzn_reconcile_server_t srv;

	if (!sender)
		return 0;
	memset(&srv, 0, sizeof(srv));
	srv.store = ap->store;
	srv.hash = ap->hash;
	srv.journal = ap->journal;
	srv.gate = &gate;
	/* A MEMBER'S LINES PUSHED, sec 569, filed and judged as fetched ones. */
	srv.takers[FZN_BUCKETS_MESSAGES] = messages_on ? &lines : NULL;
#if defined(FZN_LOG_FILE_ON) && defined(FZN_LOG_PACK_ON)
	srv.takers[FZN_BUCKETS_LOGS] = logs_up() ? &logs_filer : NULL;
	srv.takers[FZN_BUCKETS_PIECES] = pieces_ready ? &pieces_filer : NULL;
#endif
	srv.sender = sender;
	return fzn_reconcile_serve(&srv, request, request_len, reply, reply_cap);
}

/* WHETHER A PULL PEER IS OF THIS NODE'S ESTATE, sec 556: `--root-at` is its
 * root by construction; a `--pull-from` peer is when the chain this node was
 * paired under starts at this estate's root or a member of its root set. A
 * plain `--accept` pairs a device to a node of ANOTHER estate, whose objects
 * no judgment here ranks, so reconciling with it fetched them every round to
 * wait for ever. Decided from what this node holds, not from what the peer
 * says. A pairing with no chain cannot be judged and is reconciled with, as
 * before: passing over a peer of this estate would lose state, including
 * one of another only costs a round's bytes. */
static int peer_in_estate(const struct pull_target *pt)
{
	fzn_chain_hop_t hop;
	const uint8_t *grantor;

	if (pt->is_root_at || pt->pairing.hop_count == 0u)
		return 1;
	if (fzn_hop_open(pt->pairing.chain[0], FZN_HOP_LEN, &hop) != FZN_CHAIN_OK)
		return 0;
	grantor = fzn_hop_grantor(hop);
	return fzn_ct_memeq(grantor, node_apply.root, FZN_PUBKEY_LEN)
	       || (node_apply.roots && node_apply.roots->ops.member
	           && node_apply.roots->ops.member(node_apply.roots->ops.ctx, grantor));
}

#if defined(FZN_LOG_FILE_ON) && defined(FZN_LOG_PACK_ON)
/* THE FOSSILS THEIR PIECES HOLD, sec 599: of this host's cut fossils, the
 * ids whose pieces enough distinct hosts were found holding this round. */
#define FZND_PIECES_COUNTED 256u
static uint8_t pieces_ok[FZND_PIECES_COUNTED][FZN_BUCKETS_ID_LEN];
static size_t n_pieces_ok;

static int pieces_enough(const uint8_t id[FZN_BUCKETS_ID_LEN])
{
	size_t i;

	for (i = 0; i < n_pieces_ok; i++)
		if (memcmp(pieces_ok[i], id, FZN_BUCKETS_ID_LEN) == 0)
			return 1;
	return 0;
}

/* THE PULL TARGET THAT IS `key`, of the estate and answering this round,
 * or NULL. */
static struct pull_target *keeper_target(struct pull_target *pulls, size_t npulls,
                                         const uint8_t key[FZN_PUBKEY_LEN])
{
	size_t t;

	for (t = 0; t < npulls; t++)
		if (memcmp(pulls[t].pairing.node, key, FZN_PUBKEY_LEN) == 0 && !silent_peer(&pulls[t])
		    && peer_in_estate(&pulls[t]))
			return &pulls[t];
	return NULL;
}

/* WHICH PIECES OF `id` THEIR KEEPERS HOLD, asked this round: this host's
 * own by its file, each other's by asking that keeper -- a peer of the
 * estate that answered -- whether it holds the piece, the length and no
 * byte. Bit i of the result for piece i; bit i of `*answered` for a keeper
 * that was asked and answered, held or not. */
static uint32_t pieces_kept(struct pull_target *pulls, size_t npulls, uint64_t now,
                            const uint8_t id[FZN_BUCKETS_ID_LEN], unsigned n,
                            const uint8_t (*keepers)[FZN_PUBKEY_LEN], uint32_t *answered)
{
	static uint8_t reply[FZND_PULL_REPLY_MAX];
	uint32_t here = 0, kept = 0;
	unsigned i;

	(void)fzn_pieces_held(node_pieces.dir, id, &here);
	for (i = 0; i < n; i++) {
		uint8_t piece_id[FZN_BUCKETS_ID_LEN];

		if (memcmp(keepers[i], dlog.host, FZN_PUBKEY_LEN) == 0) {
			kept |= here & (1u << i);
			continue;
		}
		if (!fzn_piece_buckets_piece_id(&node_pieces, id, i, piece_id, NULL))
			continue;
		{
			struct pull_target *pt = keeper_target(pulls, npulls, keepers[i]);
			struct peer_asking asking = { pt ? &pt->caller : NULL, now, pt ? pt->host : NULL };
			int has = 0;

			if (pt
			    && fzn_reconcile_peer_holds(FZN_BUCKETS_PIECES, piece_id, peer_ask, &asking,
			                                reply, sizeof(reply), &has)
			               == FZN_RECONCILE_OK) {
				*answered |= 1u << i;
				if (has)
					kept |= 1u << i;
			}
		}
	}
	return kept;
}

/* The most fossils one round repairs, as many as it cuts: each may fetch k
 * pieces and is rebuilt whole. */
#define FZND_REPAIRS_PER_ROUND 8u

/* EVERY PIECE OF `id` HELD HERE AGAIN, sec 600: from the pieces here and,
 * short of k, those their keepers hold, fetched by id; the item rebuilt,
 * checked against its id, cut again and placed again -- on `cut_for`,
 * which since sec 601 may name a new keeper for a piece whose keeper is
 * gone; that piece's old id is let go here once the rebuild no longer
 * needs its copy. 0 when too few pieces could be had this round. */
static int pieces_back(struct pull_target *pulls, size_t npulls, uint64_t now,
                       const uint8_t id[FZN_BUCKETS_ID_LEN], unsigned k, unsigned m,
                       const uint8_t (*keepers)[FZN_PUBKEY_LEN], uint32_t kept,
                       const uint8_t (*cut_for)[FZN_PUBKEY_LEN])
{
	static uint8_t reply[FZND_PULL_REPLY_MAX];
	char name[FZN_LOG_BUCKETS_NAME_MAX + 1u];
	uint32_t here = 0;
	unsigned i, local = 0;
	size_t item_len = 0, len = 0, written = 0, placed = 0;
	uint64_t closed;
	uint8_t *item;
	int ok;

	(void)fzn_pieces_held(node_pieces.dir, id, &here);
	for (i = 0; i < k + m; i++)
		local += (here >> i) & 1u;
	for (i = 0; i < k + m && local < k; i++) {
		struct pull_target *pt;
		uint8_t piece_id[FZN_BUCKETS_ID_LEN], of[FZN_BUCKETS_ID_LEN], *bytes;
		uint64_t size = 0;
		unsigned index = 0;

		if (!((kept & ~here) >> i & 1u) || !(pt = keeper_target(pulls, npulls, keepers[i]))
		    || !fzn_piece_buckets_piece_id(&node_pieces, id, i, piece_id, &size)
		    || size == 0u || size > FZN_BUCKETS_LARGE_MAX || (bytes = malloc((size_t)size)) == NULL)
			continue;
		{
			struct peer_asking asking = { &pt->caller, now, pt->host };

			ok = fzn_reconcile_fetch_one(FZN_BUCKETS_PIECES, piece_id, dlog.hash, bytes,
			                             (size_t)size, &len, peer_ask, &asking, reply,
			                             sizeof(reply))
			             == FZN_RECONCILE_OK
			     && len
			     && fzn_pieces_keep(node_pieces.dir, bytes, len, of, &index) == FZN_PIECES_OK
			     && memcmp(of, id, FZN_BUCKETS_ID_LEN) == 0 && index == i;
		}
		free(bytes);
		if (ok)
			local++;
	}
	if (local < k || fzn_pieces_item_len(node_pieces.dir, id, &item_len) != FZN_PIECES_OK
	    || (item = malloc(item_len)) == NULL)
		return 0;
	/* THE ITEM AS THE LOGS KIND HOLDS IT, its name in front: the month its
	 * pieces were placed under is the segment's. */
	ok = fzn_pieces_rebuild(node_pieces.dir, FZN_BUCKETS_LOGS, id, dlog.hash, item, item_len,
	                        &len, NULL)
	             == FZN_PIECES_OK
	     && len > 1u && item[0] != 0u && (size_t)item[0] < len
	     && (size_t)item[0] <= FZN_LOG_BUCKETS_NAME_MAX;
	if (ok) {
		memcpy(name, item + 1, item[0]);
		name[item[0]] = '\0';
		closed = fzn_log_copy_packed_time(name);
		/* A PIECE MOVING TO ANOTHER KEEPER is other bytes now: its old id
		 * goes before the new is cut over its file. */
		for (i = 0; ok && i < k + m; i++)
			if (memcmp(keepers[i], cut_for[i], FZN_PUBKEY_LEN) != 0)
				ok = fzn_piece_buckets_let_go(&node_pieces, id, i);
		ok = ok && closed
		     && fzn_pieces_cut(node_pieces.dir, FZN_BUCKETS_LOGS, id, dlog.host, cut_for, item,
		                       len, k, m, &written)
		                == FZN_PIECES_OK
		     && fzn_piece_buckets_place(&node_pieces, id, fzn_message_epoch_of(closed / 1000u), k,
		                                m, cut_for, &placed);
	}
	free(item);
	return ok;
}

/* A PIECE ITS KEEPER LOST, put back, sec 600: each keeper that answered and
 * does not hold its piece is pushed it again by id -- its bucket otherwise
 * agrees with this host's, so a push by bucket passes it over -- after the
 * pieces are held here again where this host let its copies go. How many
 * were taken. */
static size_t repair_pieces(struct pull_target *pulls, size_t npulls, uint64_t now,
                            const uint8_t id[FZN_BUCKETS_ID_LEN], unsigned k, unsigned m,
                            const uint8_t (*keepers)[FZN_PUBKEY_LEN], uint32_t kept,
                            uint32_t answered)
{
	static uint8_t reply[FZND_PULL_REPLY_MAX];
	uint32_t here = 0, missing = answered & ~kept;
	size_t sent = 0;
	unsigned i;

	if (!missing)
		return 0;
	(void)fzn_pieces_held(node_pieces.dir, id, &here);
	if ((missing & ~here) && !pieces_back(pulls, npulls, now, id, k, m, keepers, kept, keepers)) {
		say(FZN_ENTRY_WARNING, "log/copy", "a fossil's lost pieces could not be rebuilt: "
		                                   "too few of its pieces could be had");
		return 0;
	}
	for (i = 0; i < k + m; i++) {
		struct pull_target *pt;
		uint8_t piece_id[FZN_BUCKETS_ID_LEN], subject[FZN_PUBKEY_LEN], scratch[1];
		uint32_t month = 0;
		size_t len = 0;
		fzn_reconcile_bucket_tally_t t;

		if (!((missing >> i) & 1u) || !(pt = keeper_target(pulls, npulls, keepers[i]))
		    || !fzn_piece_buckets_piece_id(&node_pieces, id, i, piece_id, NULL)
		    || fzn_buckets_item(&logs_store, FZN_BUCKETS_PIECES, piece_id, scratch,
		                        sizeof(scratch), &len, subject, &month)
		               != FZN_BUCKETS_LARGE)
			continue;
		{
			struct peer_asking asking = { &pt->caller, now, pt->host };

			if (fzn_reconcile_push_one(&logs_store, FZN_BUCKETS_PIECES, subject, month,
			                           piece_id, &pieces_filer, peer_ask, &asking, reply,
			                           sizeof(reply), &t)
			            == FZN_RECONCILE_OK
			    && t.sent)
				sent++;
		}
	}
	return sent;
}

/* A PIECE WHOSE KEEPER IS GONE, moved, sec 601: a keeper that did not
 * answer and has not been heard from for `archive/gone` -- one never heard
 * from is heard now, so silence is counted from when this host first
 * asked -- has its piece rebuilt and placed on the best-ranked host of
 * those that answered this round, this one among them, not keeping one of
 * the fossil's pieces already; then pushed it. How many were moved. */
static size_t move_gone(struct pull_target *pulls, size_t npulls, uint64_t now,
                        const uint8_t id[FZN_BUCKETS_ID_LEN], unsigned k, unsigned m,
                        const uint8_t (*keepers)[FZN_PUBKEY_LEN], uint32_t kept,
                        uint32_t answered, uint64_t now_us, uint32_t gone_s)
{
	static uint8_t hosts[FZN_PIECE_BUCKETS_HOSTS_MAX][FZN_PUBKEY_LEN];
	static uint8_t cut_for[FZN_ERASURE_PIECES_MAX][FZN_PUBKEY_LEN];
	static uint8_t old_ids[FZN_ERASURE_PIECES_MAX][FZN_BUCKETS_ID_LEN];
	static uint8_t reply[FZND_PULL_REPLY_MAX];
	size_t order[FZN_PIECE_BUCKETS_HOSTS_MAX], n_hosts = 0, t, j, next = 0, moved = 0;
	uint32_t gone = 0;
	unsigned i;

	for (i = 0; i < k + m; i++) {
		uint64_t heard = 0;

		if (memcmp(keepers[i], dlog.host, FZN_PUBKEY_LEN) == 0 || ((answered >> i) & 1u))
			continue;
		if (fzn_heard_when(node_apply.store, keepers[i], &heard) != FZN_HEARD_OK) {
			(void)fzn_heard_mark(node_apply.store, keepers[i], now_us);
			continue;
		}
		if (now_us > heard && (now_us - heard) / 1000000u > gone_s)
			gone |= 1u << i;
	}
	if (!gone)
		return 0;
	/* THE HOSTS IT COULD GO TO: answering, of the estate, keeping none. */
	memcpy(hosts[n_hosts++], dlog.host, FZN_PUBKEY_LEN);
	for (t = 0; t < npulls && n_hosts < FZN_PIECE_BUCKETS_HOSTS_MAX; t++)
		if (!silent_peer(&pulls[t]) && peer_in_estate(&pulls[t])) {
			for (j = 0; j < n_hosts
			            && memcmp(hosts[j], pulls[t].pairing.node, FZN_PUBKEY_LEN) != 0;
			     j++)
				;
			if (j == n_hosts)
				memcpy(hosts[n_hosts++], pulls[t].pairing.node, FZN_PUBKEY_LEN);
		}
	for (j = 0; j < n_hosts; j++)
		for (i = 0; i < k + m; i++)
			if (memcmp(hosts[j], keepers[i], FZN_PUBKEY_LEN) == 0) {
				memcpy(hosts[j], hosts[--n_hosts], FZN_PUBKEY_LEN);
				j--;
				break;
			}
	if (!n_hosts
	    || !fzn_piece_buckets_rank(dlog.hash, id, (const uint8_t (*)[32])hosts, n_hosts, order))
		return 0;
	memcpy(cut_for, keepers, (size_t)(k + m) * FZN_PUBKEY_LEN);
	for (i = 0; i < k + m && next < n_hosts; i++)
		if ((gone >> i) & 1u) {
			memcpy(cut_for[i], hosts[order[next++]], FZN_PUBKEY_LEN);
			/* ITS OLD ID, before the cut gives the ref a new one: what the
			 * release names (sec 602). */
			if (!fzn_piece_buckets_piece_id(&node_pieces, id, i, old_ids[i], NULL))
				memset(old_ids[i], 0, FZN_BUCKETS_ID_LEN);
		}
	if (!pieces_back(pulls, npulls, now, id, k, m, keepers, kept,
	                 (const uint8_t (*)[32])cut_for)) {
		say(FZN_ENTRY_WARNING, "log/copy", "a piece whose keeper is gone could not be moved: "
		                                   "too few of its fossil's pieces could be had");
		return 0;
	}
	/* AND PUSHED NOW to its new keeper, rather than a round later. */
	for (i = 0; i < k + m; i++) {
		struct pull_target *pt;
		uint8_t piece_id[FZN_BUCKETS_ID_LEN], subject[FZN_PUBKEY_LEN], scratch[1];
		uint32_t month = 0;
		size_t len = 0;
		fzn_reconcile_bucket_tally_t pushed;

		if (!((gone >> i) & 1u) || memcmp(cut_for[i], keepers[i], FZN_PUBKEY_LEN) == 0)
			continue;
		moved++;
		(void)fzn_heard_mark(node_apply.store, cut_for[i], now_us);
		if (!fzn_piece_buckets_piece_id(&node_pieces, id, i, piece_id, NULL)
		    || fzn_buckets_item(&logs_store, FZN_BUCKETS_PIECES, piece_id, scratch,
		                        sizeof(scratch), &len, subject, &month)
		               != FZN_BUCKETS_LARGE)
			continue;
		/* THE OLD KEEPER RELEASED, should it come back, sec 602: signed,
		 * so only this host can have it let go a piece of this host's. */
		if (dlog.has_signer
		    && !fzn_piece_buckets_release(&node_pieces, dlog.signer.sign, dlog.host, id, i,
		                                  old_ids[i], keepers[i], month))
			say(FZN_ENTRY_WARNING, "log/copy", "a moved piece's release could not be kept");
		if (!(pt = keeper_target(pulls, npulls, cut_for[i])))
			continue;
		{
			struct peer_asking asking = { &pt->caller, now, pt->host };

			(void)fzn_reconcile_push_one(&logs_store, FZN_BUCKETS_PIECES, subject, month,
			                             piece_id, &pieces_filer, peer_ask, &asking, reply,
			                             sizeof(reply), &pushed);
		}
	}
	return moved;
}

/* THIS HOST'S CUT FOSSILS COUNTED, sec 599, each round after the
 * exchange: a fossil is held by its pieces once k + min(m, R - 1) of them
 * sit on distinct hosts -- R `archive/replicas`, so pieces bear the losses
 * whole replicas would -- and this host then lets go of its copies of the
 * pieces their keepers hold. Each keeper is a distinct host by placement. */
static void count_pieces(struct pull_target *pulls, size_t npulls, uint64_t now, unsigned want)
{
	static uint8_t keepers[FZN_ERASURE_PIECES_MAX][FZN_PUBKEY_LEN];
	size_t counted = 0, short_of = 0, let_go = 0, put_back = 0, repairs = 0, moved = 0;
	uint64_t now_us = wall_ms() * 1000u;
	uint32_t gone_s = fzn_node_settings_gone_s(&node_settings);
	struct dirent *e;
	DIR *d;

	n_pieces_ok = 0;
	if (!pieces_ready || !dlog.has_host)
		return;
	/* EVERY PEER THAT ANSWERED THIS ROUND WAS HEARD, sec 601, by
	 * `mark_heard` earlier in the round (sec 616). */
	(void)pulls;
	(void)npulls;
	if ((d = opendir(node_pieces.dir)) == NULL)
		return;
	while ((e = readdir(d)) != NULL && counted < FZND_PIECES_COUNTED) {
		uint8_t id[FZN_BUCKETS_ID_LEN];
		unsigned k = 0, m = 0, need, held = 0, i;
		uint32_t kept, here = 0, answered = 0;
		char hex[65];

		/* `IDHEX.cut`: the id read from the name's first 64. */
		if (strlen(e->d_name) != 68u || strcmp(e->d_name + 64, ".cut") != 0
		    || strspn(e->d_name, "0123456789abcdef") != 64u)
			continue;
		memcpy(hex, e->d_name, 64u);
		hex[64] = '\0';
		if (!hex_bytes(hex, id, sizeof(id))
		    || !fzn_piece_buckets_cut_of(&node_pieces, id, &k, &m, keepers))
			continue;
		counted++;
		kept = pieces_kept(pulls, npulls, now, id, k + m, (const uint8_t (*)[32])keepers,
		                   &answered);
		for (i = 0; i < k + m; i++)
			held += (kept >> i) & 1u;
		/* A KEEPER THAT ANSWERED WITHOUT ITS PIECE is given it back; one
		 * gone, its piece moves. Both cost a rebuild, so they share the
		 * round's bound. */
		if ((answered & ~kept) && repairs < FZND_REPAIRS_PER_ROUND) {
			repairs++;
			put_back += repair_pieces(pulls, npulls, now, id, k, m,
			                          (const uint8_t (*)[32])keepers, kept, answered);
		}
		if (repairs < FZND_REPAIRS_PER_ROUND) {
			size_t n_moved = move_gone(pulls, npulls, now, id, k, m,
			                           (const uint8_t (*)[32])keepers, kept, answered, now_us,
			                           gone_s);

			if (n_moved) {
				repairs++;
				moved += n_moved;
				continue;
			}
		}
		need = k + (want > 1u ? (m < want - 1u ? m : want - 1u) : 0u);
		if (held < need) {
			short_of++;
			continue;
		}
		if (n_pieces_ok < FZND_PIECES_COUNTED)
			memcpy(pieces_ok[n_pieces_ok++], id, FZN_BUCKETS_ID_LEN);
		/* ITS KEEPERS HOLD THEM: this host's copies go. */
		(void)fzn_pieces_held(node_pieces.dir, id, &here);
		for (i = 0; i < k + m; i++)
			if (memcmp(keepers[i], dlog.host, FZN_PUBKEY_LEN) != 0
			    && ((kept & here) >> i) & 1u) {
				if (fzn_piece_buckets_let_go(&node_pieces, id, i))
					let_go++;
				else
					say(FZN_ENTRY_WARNING, "log/copy", "a piece of %.8s would not be let go",
					    e->d_name);
			}
	}
	(void)closedir(d);
	if (counted)
		say(FZN_ENTRY_INFO, "log/copy",
		    "pieces: %zu cut fossil(s), %zu held by too few hosts, %zu piece(s) let go to "
		    "their keepers, %zu put back, %zu moved off gone hosts", counted, short_of, let_go,
		    put_back, moved);
}

/* THE FOSSILS OF ONE ARCHIVE DIRECTORY WEIGHED, sec 592: each the `rules`
 * would prune, its ref `prefix` and its name, asked of each peer of the
 * estate that answered this round -- held or not, the length and no byte
 * (`fzn_reconcile_peer_holds`) -- and confirmed when `want` hosts or more
 * hold it, this one counted. One a peer let go is not held. `*weighed` and
 * `*short_of` count. */
static void weigh(struct pull_target *pulls, size_t npulls, uint64_t now, const char *dir,
                  const char *prefix, const fzn_retain_rule_t *rules, size_t n, unsigned want,
                  size_t *weighed, size_t *short_of)
{
	static char held[FZND_LOG_PROGRAMS_MAX][FZN_ENTRY_WORD_MAX + 1u];
	static char names[FZND_REPLICA_NAMES][FZN_LOG_PACK_NAME_MAX];
	static uint8_t reply[FZND_PULL_REPLY_MAX];
	size_t n_held = 0, p, i, t, n_names;

	if (fzn_logger_programs(dir, held, FZND_LOG_PROGRAMS_MAX, &n_held) != FZN_LOGGER_OK)
		return;
	for (p = 0; p < n_held; p++) {
		n_names = 0;
		if (fzn_log_pack_plan(dir, held[p], rules, n, log_now_us(), names, FZND_REPLICA_NAMES,
		                      &n_names)
		    != FZN_LOG_PACK_OK)
			continue;
		for (i = 0; i < n_names; i++) {
			char ref[FZN_BUCKETS_REF_MAX + 1u];
			uint8_t id[FZN_BUCKETS_ID_LEN];
			uint64_t len = 0;
			unsigned holders = 1;

			(*weighed)++;
			if (snprintf(ref, sizeof(ref), "%s%s", prefix, names[i]) >= (int)sizeof(ref)
			    || fzn_buckets_by_ref(&logs_store, FZN_BUCKETS_LOGS, (const uint8_t *)ref,
			                          strlen(ref), id, &len)
			               != FZN_BUCKETS_OK) {
				(*short_of)++;
				continue;
			}
			/* HELD BY ITS PIECES, sec 599: as good as `want` replicas. */
			if (prefix[0] == 'o' && pieces_enough(id)) {
				if (n_replica_ok < FZND_REPLICA_NAMES)
					memcpy(replica_ok[n_replica_ok++], ref, sizeof(replica_ok[0]));
				continue;
			}
			for (t = 0; t < npulls && holders < want; t++) {
				struct peer_asking asking = { &pulls[t].caller, now, pulls[t].host };
				int has = 0;

				if (silent_peer(&pulls[t]) || !peer_in_estate(&pulls[t]))
					continue;
				if (fzn_reconcile_peer_holds(FZN_BUCKETS_LOGS, id, peer_ask, &asking, reply,
				                             sizeof(reply), &has)
				            == FZN_RECONCILE_OK
				    && has)
					holders++;
			}
			if (holders >= want && n_replica_ok < FZND_REPLICA_NAMES)
				memcpy(replica_ok[n_replica_ok++], ref, sizeof(replica_ok[0]));
			else
				(*short_of)++;
		}
	}
}

/* THE ARCHIVE'S REPLICAS COUNTED, sec 592, each round after the exchange:
 * this node's fossils its archive's rules would prune, and since sec 593
 * its archived copies the rules over them would, each weighed, those held
 * by `archive/replicas` hosts or more confirmed for the log pass to
 * prune. */
static void count_replicas(struct pull_target *pulls, size_t npulls, uint64_t now)
{
	static fzn_retain_rule_t all[FZN_RETAIN_RULES_MAX], rules[FZN_RETAIN_RULES_MAX];
	static fzn_retain_rule_t source_rules[FZN_RETAIN_RULES_MAX];
	char where[600], copies[608];
	size_t n_all, n, weighed = 0, short_of = 0;
	unsigned want;
	struct dirent *e;
	DIR *d;

	n_replica_ok = 0;
	if (!logs_ready)
		return;
	n_all = gather_rules(all);
	archive_where(where, sizeof(where));
	want = fzn_node_settings_replicas(&node_settings);
	count_pieces(pulls, npulls, now, want);
	n = fzn_retain_select_archived(all, n_all, dlog.has_host ? dlog.host : NULL,
	                               dlog.logger.self.machine, rules);
	if (n)
		weigh(pulls, npulls, now, where, "o/", rules, n, want, &weighed, &short_of);
	n = fzn_retain_select_archived_copies(all, n_all, dlog.has_host ? dlog.host : NULL,
	                                      dlog.logger.self.machine, rules);
	if (n && snprintf(copies, sizeof(copies), "%s/copy", where) < (int)sizeof(copies)
	    && (d = opendir(copies)) != NULL) {
		while ((e = readdir(d)) != NULL) {
			char sub[sizeof(copies) + 80u], prefix[72];
			uint8_t source[32];
			size_t n_source;

			if (strlen(e->d_name) != 64u || strspn(e->d_name, "0123456789abcdef") != 64u
			    || !hex_bytes(e->d_name, source, sizeof(source))
			    || snprintf(sub, sizeof(sub), "%s/%s", copies, e->d_name) >= (int)sizeof(sub))
				continue;
			n_source = fzn_retain_select_source(rules, n, source, source_rules);
			if (n_source
			    && snprintf(prefix, sizeof(prefix), "c/%s/", e->d_name) < (int)sizeof(prefix))
				weigh(pulls, npulls, now, sub, prefix, source_rules, n_source, want,
				      &weighed, &short_of);
		}
		(void)closedir(d);
	}
	if (weighed)
		say(short_of ? FZN_ENTRY_INFO : FZN_ENTRY_DEBUG, "log",
		    "replicas: %zu fossil(s) the archive's rules would prune, %zu held by fewer than "
		    "%u host(s) and kept", weighed, short_of, want);
}
#endif

#if defined(FZN_LOG_FILE_ON) && defined(FZN_LOG_PACK_ON)
/* The most fossils one round cuts: each is read whole and coded. */
#define FZND_CUTS_PER_ROUND 8u

/* THIS HOST'S FOSSILS CUT INTO PIECES, sec 597, each once: where the estate
 * has `archive/erasure`'s k + m hosts or more -- this one and every peer of
 * the estate that answered this round -- each archived segment of this
 * host's is cut, as the item the logs kind holds it as, and piece i placed
 * on the i-th host in rendezvous order for it. Fewer hosts and none is cut:
 * the whole replicas of sec 592 are the estate's then. */
static void cut_fossils(struct pull_target *pulls, size_t npulls)
{
	static uint8_t hosts[FZN_PIECE_BUCKETS_HOSTS_MAX][FZN_PUBKEY_LEN];
	static uint8_t keepers[FZN_ERASURE_PIECES_MAX][FZN_PUBKEY_LEN];
	size_t order[FZN_PIECE_BUCKETS_HOSTS_MAX], n_hosts = 0, t, i, cut = 0;
	unsigned k = 0, m = 0;
	struct dirent *e;
	DIR *d;

	if (!pieces_ready || !node_logs.archive[0] || !dlog.has_host)
		return;
	fzn_node_settings_erasure(&node_settings, &k, &m);
	memcpy(hosts[n_hosts++], dlog.host, FZN_PUBKEY_LEN);
	for (t = 0; t < npulls && n_hosts < FZN_PIECE_BUCKETS_HOSTS_MAX; t++) {
		/* ITS NODE KEY, the one it keeps pieces under: the pairing's, which
		 * for `--root-at` is the root node rather than the estate's root. */
		const uint8_t *key = pulls[t].pairing.node;

		if (silent_peer(&pulls[t]) || !peer_in_estate(&pulls[t]))
			continue;
		for (i = 0; i < n_hosts && memcmp(hosts[i], key, FZN_PUBKEY_LEN) != 0; i++)
			;
		if (i == n_hosts)
			memcpy(hosts[n_hosts++], key, FZN_PUBKEY_LEN);
	}
	if (n_hosts < k + m || (d = opendir(node_logs.archive)) == NULL)
		return;
	while ((e = readdir(d)) != NULL && cut < FZND_CUTS_PER_ROUND) {
		uint64_t closed = fzn_log_copy_packed_time(e->d_name), size = 0, piece_size = 0;
		char ref[FZN_BUCKETS_REF_MAX + 1u], first[FZN_BUCKETS_REF_MAX + 1u], hex[65];
		char path[sizeof(node_logs.archive) + 260u];
		uint8_t id[FZN_BUCKETS_ID_LEN], check[FZN_BUCKETS_ID_LEN], piece_id[FZN_BUCKETS_ID_LEN];
		size_t name_len = strlen(e->d_name), written = 0, placed = 0, got;
		int ok;
		uint8_t *item;
		FILE *f;

		if (!closed || name_len > FZN_LOG_BUCKETS_NAME_MAX
		    || snprintf(ref, sizeof(ref), "o/%s", e->d_name) >= (int)sizeof(ref)
		    || snprintf(path, sizeof(path), "%s/%s", node_logs.archive, e->d_name)
		               >= (int)sizeof(path)
		    || fzn_buckets_by_ref(&logs_store, FZN_BUCKETS_LOGS, (const uint8_t *)ref,
		                          strlen(ref), id, &size)
		               != FZN_BUCKETS_OK
		    || size <= 1u + name_len || size > FZN_BUCKETS_LARGE_MAX)
			continue;
		/* CUT ONCE: its first piece placed is the mark. */
		for (i = 0; i < FZN_BUCKETS_ID_LEN; i++)
			(void)snprintf(hex + 2u * i, 3u, "%02x", id[i]);
		if (snprintf(first, sizeof(first), "p/%s.0", hex) >= (int)sizeof(first)
		    || fzn_buckets_by_ref(&logs_store, FZN_BUCKETS_PIECES, (const uint8_t *)first,
		                          strlen(first), piece_id, &piece_size)
		               == FZN_BUCKETS_OK)
			continue;
		/* THE ITEM AS THE LOGS KIND HOLDS IT, its name in front, checked
		 * against its id before it is cut. */
		item = malloc((size_t)size);
		if (!item)
			break;
		item[0] = (uint8_t)name_len;
		memcpy(item + 1, e->d_name, name_len);
		f = fopen(path, "rb");
		got = f ? fread(item + 1u + name_len, 1u, (size_t)size - 1u - name_len, f) : 0u;
		if (f)
			(void)fclose(f);
		/* EACH PIECE NAMES ITS KEEPER, so the keepers come first. */
		ok = got == (size_t)size - 1u - name_len
		     && fzn_buckets_id(dlog.hash, item, (size_t)size, check)
		     && memcmp(check, id, FZN_BUCKETS_ID_LEN) == 0
		     && fzn_piece_buckets_rank(dlog.hash, id, (const uint8_t (*)[32])hosts, n_hosts,
		                               order);
		for (i = 0; ok && i < k + m; i++)
			memcpy(keepers[i], hosts[order[i]], FZN_PUBKEY_LEN);
		ok = ok
		     && fzn_pieces_cut(node_pieces.dir, FZN_BUCKETS_LOGS, id, dlog.host,
		                       (const uint8_t (*)[32])keepers, item, (size_t)size, k, m,
		                       &written)
		                == FZN_PIECES_OK;
		free(item);
		if (!ok) {
			say(FZN_ENTRY_WARNING, "log/copy", "%s could not be cut into pieces", e->d_name);
			continue;
		}
		if (!fzn_piece_buckets_place(&node_pieces, id, fzn_message_epoch_of(closed / 1000u), k,
		                             m, (const uint8_t (*)[32])keepers, &placed)) {
			say(FZN_ENTRY_WARNING, "log/copy", "the pieces of %s could not all be placed",
			    e->d_name);
			continue;
		}
		cut++;
	}
	(void)closedir(d);
	if (cut)
		say(FZN_ENTRY_INFO, "log/copy",
		    "%zu archived segment(s) cut into %u + %u pieces over %zu host(s)", cut, k, m,
		    n_hosts);
}
#endif

/* ---- the routing manifest, sec 611 ------------------------------------------ */

/* This node's key and crypto, for signing the estate's manifest: set at
 * startup, NULL until then. */
static const uint8_t *routing_self;
static const fzn_sign_ops_t *routing_sign;
static const fzn_hash_ops_t *routing_hash;

#define ROUTING_METRIC_KEY "net/metric"
#define ROUTING_PUBLIC_KEY "routing/public"
#define ROUTING_ADVERTISE_KEY "routing/advertise"
/* An entry's metric where its host sets none: the middle, so a host can
 * be put before or after the others. */
#define ROUTING_METRIC_DEFAULT 100u

struct routing_hosts {
	uint8_t about[FZN_ROUTING_ENTRIES_MAX * 2u][FZN_PUBKEY_LEN];
	size_t n;
};

static void routing_collect(void *ctx, const fzn_setting_t *s, fzn_setting_rank_t rank)
{
	struct routing_hosts *h = (struct routing_hosts *)ctx;

	(void)rank;
	if (s->scope == FZN_SCOPE_HOST && s->set
	    && s->key_len == sizeof(FZN_NODE_SETTINGS_ADDRESS_KEY) - 1u
	    && memcmp(s->key, FZN_NODE_SETTINGS_ADDRESS_KEY, s->key_len) == 0
	    && h->n < sizeof(h->about) / sizeof(h->about[0]))
		memcpy(h->about[h->n++], s->about, FZN_PUBKEY_LEN);
}

/* An estate cell that reads `1`. */
static int estate_flag(const char *key)
{
	uint8_t value[FZN_SETTING_VALUE_MAX];
	fzn_setting_rank_t rank;
	size_t len = 0;

	return node_apply.root
	       && fzn_node_settings_get(&node_settings, FZN_SCOPE_ESTATE, node_apply.root,
	                                (const uint8_t *)key, strlen(key), value, &len, &rank)
	       && len == 1u && value[0] == '1';
}

/* THE ESTATE'S MANIFEST AS ITS SETTINGS SAY, fuzzypickles' "deterministic
 * projection": every host cell `net/address` an entry, at its `net/metric`
 * -- 0 to 255, 100 unset -- over UDP; `routing/public` its public_relay.
 * Every member derives the same document from the same settings. */
static void routing_derive(fzn_routing_t *out)
{
	static struct routing_hosts hosts;
	size_t i;

	memset(out, 0, sizeof(*out));
	hosts.n = 0;
	(void)fzn_node_settings_each(&node_settings, routing_collect, &hosts);
	for (i = 0; i < hosts.n; i++) {
		char host[FZN_NODE_SETTINGS_HOST_MAX + 1u];
		uint8_t value[FZN_SETTING_VALUE_MAX];
		fzn_setting_rank_t rank;
		size_t len = 0, k;
		unsigned metric = ROUTING_METRIC_DEFAULT, m = 0;
		uint16_t port = 0;

		if (!fzn_node_settings_address(&node_settings, hosts.about[i], host, &port))
			continue;
		if (fzn_node_settings_get(&node_settings, FZN_SCOPE_HOST, hosts.about[i],
		                          (const uint8_t *)ROUTING_METRIC_KEY,
		                          sizeof(ROUTING_METRIC_KEY) - 1u, value, &len, &rank)
		    && len > 0u && len <= 3u) {
			for (k = 0; k < len && value[k] >= '0' && value[k] <= '9'; k++)
				m = m * 10u + (unsigned)(value[k] - '0');
			if (k == len && m <= 255u)
				metric = m;
		}
		/* AN ADDRESS TWICE -- two hosts claiming one -- is listed once. */
		(void)fzn_routing_add(out, host, strlen(host), port, FZN_ROUTING_TRANSPORT_UDP,
		                      (uint8_t)metric);
	}
	out->public_relay = estate_flag(ROUTING_PUBLIC_KEY);
}

/* `get routing` ASKED OF `asking`, and the answer kept as the manifest of
 * the user whose root is `root` when it verifies against that root and is
 * newer than the one held: this estate's, from a member (sec 611), or a
 * contact's, from one of its hosts (sec 614). 1 when one was taken. */
/* A `get routing` ANSWER from `host`, `len` bytes of `reply` (which has a
 * byte to spare): the manifest kept when it verifies for `root`. 1 when
 * kept. */
static int routing_take(const char *host, uint8_t *reply, size_t len,
                        const uint8_t root[FZN_PUBKEY_LEN], uint64_t now)
{
	static uint8_t bytes[FZN_ROUTING_MAX];
	size_t n;
	fzn_routing_t got;

	if (!routing_hash || !routing_sign || !node_apply.store || len < 4u
	    || memcmp(reply, "ok ", 3u) != 0)
		return 0;
	while (len && (reply[len - 1u] == '\n' || reply[len - 1u] == '\r'))
		len--;
	n = (len - 3u) / 2u;
	if ((len - 3u) % 2u || n > sizeof(bytes))
		return 0;
	reply[len] = '\0';
	if (!hex_bytes((const char *)reply + 3, bytes, n)
	    || fzn_routing_decode(bytes, n, &got) != FZN_ROUTING_OK
	    || fzn_routing_verify(&got, routing_hash, routing_sign, root, node_apply.admin_capability,
	                          now)
	               != FZN_ROUTING_OK
	    || fzn_routing_keep(node_apply.store, root, &got) != FZN_ROUTING_OK)
		return 0;
	say(FZN_ENTRY_INFO, "routing", "routing manifest taken from %s: generation %llu, %zu host(s)",
	    host ? host : "a peer", (unsigned long long)got.generation, got.n);
	publish("routing", NULL);
	return 1;
}

/* EVERY PEER OF THE ESTATE THAT ANSWERED THIS ROUND, HEARD, secs 601 and
 * 616: what a keeper of a piece, and the writer of a line, are judged gone
 * by. Each round, whatever this build keeps. */
static void mark_heard(struct pull_target *pulls, size_t npulls)
{
	uint64_t now_us = wall_ms() * 1000u;
	size_t t;

	if (!node_apply.store)
		return;
	for (t = 0; t < npulls; t++)
		if (!silent_peer(&pulls[t]) && peer_in_estate(&pulls[t]))
			(void)fzn_heard_mark(node_apply.store, pulls[t].pairing.node, now_us);
}

/* THE ESTATE'S MANIFEST, each round, sec 611: signed afresh by the root or
 * an admin when what the settings say has changed, at one past the
 * generation held; taken by any other member from a peer of the estate
 * that answers, once it verifies against the estate's root. */
static void routing_start(struct pull_target *pulls, size_t npulls, uint64_t now);

static void routing_round(struct pull_target *pulls, size_t npulls, uint64_t now)
{
	static uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	static fzn_routing_t derived, held;
	uint8_t hash[FZN_ROUTING_HASH_LEN];
	size_t hop_count = 0;
	int have;

	if (!node_apply.root || !routing_self || !routing_sign || !routing_hash || !node_apply.store)
		return;
	have = fzn_routing_load(node_apply.store, node_apply.root, &held) == FZN_ROUTING_OK;
	if (node_apply.admin_capability
	    && fzn_node_apply_chain(&node_apply, routing_self, node_apply.admin_capability, hops,
	                            &hop_count)
	    && (hop_count || memcmp(routing_self, node_apply.root, FZN_PUBKEY_LEN) == 0)) {
		routing_derive(&derived);
		if (!fzn_routing_content_hash(&derived, routing_hash, hash)
		    || (have && memcmp(hash, held.content_hash, FZN_ROUTING_HASH_LEN) == 0))
			return;
		if (fzn_routing_sign(&derived, routing_hash, routing_sign, routing_self,
		                     (const uint8_t (*)[FZN_HOP_LEN])hops, hop_count,
		                     have ? held.generation + 1u : 1u, wall_ms())
		            != FZN_ROUTING_OK
		    || fzn_routing_keep(node_apply.store, node_apply.root, &derived) != FZN_ROUTING_OK) {
			say(FZN_ENTRY_WARNING, "routing", "the estate's routing manifest would not be signed");
			return;
		}
		say(FZN_ENTRY_INFO, "routing", "routing manifest signed: generation %llu, %zu host(s)",
		    (unsigned long long)derived.generation, derived.n);
		publish("routing", NULL);
		return;
	}
	/* NOT A SIGNER: the newest a peer of the estate holds, every peer
	 * asked at once (sec 636). */
	routing_start(pulls, npulls, now);
}

/* `get routing [KEY]`, locally: this estate's manifest, or the user's whose
 * root is KEY, as held -- `ok GENERATION SIGNER PUBLIC ADDRESS:PORT:METRIC
 * ...`, the signer's first eight bytes in hex, the entries in their order.
 * 0 for any other request. */
static size_t routing_local(const fzn_request_t *request, char *reply, size_t reply_cap)
{
	uint8_t key[FZN_PUBKEY_LEN];
	char hex[65];
	fzn_routing_t r;
	size_t at, i;
	int k;

	if (request->parsed != FZN_VERB_GET || request->arg_len < 7u
	    || memcmp(request->arg, "routing", 7u) != 0
	    || (request->arg_len > 7u && request->arg[7] != ' '))
		return 0;
	if (request->arg_len == 7u) {
		if (!node_apply.root)
			return (size_t)snprintf(reply, reply_cap, "error no estate\n");
		memcpy(key, node_apply.root, FZN_PUBKEY_LEN);
	} else {
		if (request->arg_len != 8u + 64u)
			return (size_t)snprintf(reply, reply_cap, "malformed get routing [KEY]\n");
		memcpy(hex, request->arg + 8, 64u);
		hex[64] = '\0';
		if (!hex_bytes(hex, key, sizeof(key)))
			return (size_t)snprintf(reply, reply_cap, "malformed get routing [KEY]\n");
	}
	if (!node_apply.store || fzn_routing_load(node_apply.store, key, &r) != FZN_ROUTING_OK)
		return (size_t)snprintf(reply, reply_cap, "error no routing manifest held\n");
	k = snprintf(reply, reply_cap, "ok %llu %02x%02x%02x%02x%02x%02x%02x%02x %d",
	             (unsigned long long)r.generation, r.signer[0], r.signer[1], r.signer[2],
	             r.signer[3], r.signer[4], r.signer[5], r.signer[6], r.signer[7],
	             r.public_relay);
	if (k <= 0 || (size_t)k >= reply_cap)
		return 0;
	at = (size_t)k;
	for (i = 0; i < r.n; i++) {
		k = snprintf(reply + at, reply_cap - at, " %s:%u:%u", r.entries[i].address,
		             (unsigned)r.entries[i].port, (unsigned)r.entries[i].metric);
		if (k <= 0 || (size_t)k >= reply_cap - at)
			return 0;
		at += (size_t)k;
	}
	if (at + 1u >= reply_cap)
		return 0;
	reply[at++] = '\n';
	return at;
}

/* WHETHER THIS HOST KEEPS `contact`'S LINES by the rules reaching it, sec
 * 613: what a contact's delivery is filed or refused by, and what a
 * member's question about a line it holds is answered by (sec 615). */
static int keeps_here(void *ctx, const uint8_t contact[FZN_PUBKEY_LEN])
{
	static fzn_retain_rule_t rules[FZN_RETAIN_RULES_MAX];
	size_t n;

	(void)ctx;
	n = fzn_retain_select_messages(rules, gather_rules(rules), dlog.has_host ? dlog.host : NULL,
	                               here_machine(), rules);
	return fzn_messages_keeps(rules, n, contact);
}

/* A LINE A CONTACT DELIVERS, sec 613: filed under the sender's key -- the
 * conversation a contact's lines are filed under -- when this host keeps
 * that conversation by the rules reaching it, and refused otherwise, so
 * the sender tries another of this user's hosts. */
static size_t messages_contact(void *ctx, const uint8_t *sender, const uint8_t *request,
                               size_t request_len, uint8_t *reply, size_t reply_cap)
{
	size_t len;
	int fresh = node_messages.fresh;

	(void)ctx;
	if (!messages_on)
		return 0;
	node_messages.fresh = 0;
	len = fzn_node_messages_contact(&node_messages, sender, keeps_here(NULL, sender), request,
	                                request_len, reply, reply_cap);
	/* A LINE FILED, its conversation named, as one reconciled is (sec 609). */
	if (node_messages.fresh) {
		char hex[2u * FZN_PUBKEY_LEN + 1u];
		size_t i;

		for (i = 0; i < FZN_PUBKEY_LEN; i++)
			(void)snprintf(hex + 2u * i, 3u, "%02x", sender[i]);
		publish("message", hex);
	}
	node_messages.fresh |= fresh;
	return len;
}

/* `get routing`, from a member always and from a contact only while the
 * estate advertises -- refused otherwise as anything a contact may not ask
 * is, so a refusal says nothing it would not. sec 611. */
static size_t routing_remote(void *ctx, const uint8_t *sender, int contact,
                             const uint8_t *request, size_t request_len, uint8_t *reply,
                             size_t reply_cap)
{
	static uint8_t bytes[FZN_ROUTING_MAX];
	fzn_routing_t r;
	size_t len = 0, i;

	(void)ctx;
	(void)sender;
	while (request_len && (request[request_len - 1u] == '\n' || request[request_len - 1u] == '\r'))
		request_len--;
	if (request_len != 11u || memcmp(request, "get routing", 11u) != 0)
		return 0;
	if ((contact && !estate_flag(ROUTING_ADVERTISE_KEY)) || !node_apply.root
	    || fzn_routing_load(node_apply.store, node_apply.root, &r) != FZN_ROUTING_OK
	    || fzn_routing_encode(&r, bytes, sizeof(bytes), &len) != FZN_ROUTING_OK
	    || reply_cap < 3u + 2u * len + 1u)
		return 0;
	memcpy(reply, "ok ", 3u);
	for (i = 0; i < len; i++)
		(void)snprintf((char *)reply + 3u + 2u * i, 3u, "%02x", bytes[i]);
	reply[3u + 2u * len] = '\n';
	return 3u + 2u * len + 1u;
}

/* ONE ROUND OF RECONCILIATION against every pull peer, sec 551: what the
 * journal did not bring -- cut before this node saw it -- fetched from what
 * the peer holds, every round, so a gap one peer leaves another fills. */
static void reconcile_estate(struct pull_target *pulls, size_t npulls, uint64_t now)
{
	static uint8_t reply[FZND_PULL_REPLY_MAX];
	fzn_reconcile_notes_t notes = { notes_file, &node_notes };
	size_t t, lacked = 0, applied = 0, waiting = 0, refused = 0, foreign = 0;
	size_t lines_lacked = 0, lines_filed = 0, lines_passed = 0, lines_pushed = 0;
	size_t segments_taken = 0, segments_refused = 0, segments_pushed = 0;
	size_t pieces_taken = 0, pieces_pushed = 0, pieces_refused = 0;

	if (!node_apply.store || !node_apply.journal || !node_apply.root)
		return;
	{
		static fzn_retain_rule_t gathered[FZN_RETAIN_RULES_MAX];
		size_t n = gather_rules(gathered);

		if (messages_on) {
			line_rules.n = fzn_retain_select_messages(gathered, n,
			                                          dlog.has_host ? dlog.host : NULL,
			                                          here_machine(), line_rules.rules);
			line_rules.now_ms = wall_ms();
		}
#if defined(FZN_LOG_FILE_ON) && defined(FZN_LOG_PACK_ON)
		/* THIS HOST'S SEGMENTS TAKEN, and the rules a fetch asks, sec 571. */
		if (logs_up()) {
			size_t taken = 0, let_go = 0;

			if (!fzn_log_buckets_scan(&node_logs, &taken, &let_go))
				say(FZN_ENTRY_WARNING, "log/copy", "taking this host's segments as items "
				                                   "failed part way");
			node_logs.own_rules = logs_own;
			node_logs.n_own = fzn_retain_select_here(gathered, n, dlog.host, here_machine(),
			                                         logs_own);
			node_logs.copy_rules = logs_copy;
			node_logs.n_copy = fzn_retain_select_copies(gathered, n, dlog.host,
			                                             here_machine(), logs_copy);
			node_logs.now_us = wall_ms() * 1000u;
			cut_fossils(pulls, npulls);
		}
#endif
	}
	for (t = 0; t < npulls; t++) {
		struct peer_asking asking = { &pulls[t].caller, now, pulls[t].host };
		fzn_reconcile_tally_t tally;

		if (silent_peer(&pulls[t]))
			continue;

		if (!peer_in_estate(&pulls[t])) {
			foreign++;
			continue;
		}
		fzn_reconcile_err_t err = fzn_reconcile_round(&node_apply, notes_on ? &notes : NULL,
		                                              peer_ask, &asking, reply, sizeof(reply),
		                                              &tally);

		if (err != FZN_RECONCILE_OK) {
			say(FZN_ENTRY_WARNING, "reconcile", "the estate's state from %s: %s",
			    pulls[t].host, fzn_reconcile_err_str(err));
			continue;
		}
		if (tally.applied || tally.refused || tally.full)
			say(tally.refused || tally.full ? FZN_ENTRY_WARNING : FZN_ENTRY_INFO, "reconcile",
			    "%zu object(s) from %s, %zu refused, %zu class(es) too large to list",
			    tally.applied, pulls[t].host, tally.refused, tally.full);
		lacked += tally.lacked;
		applied += tally.applied;
		waiting += tally.waiting;
		refused += tally.refused;
		/* THEN THE CONVERSATIONS, by bucket (sec 564): a device away past
		 * the journal's window is handed the lines it missed. After the
		 * classes, so a member's chain is here before its lines. */
		if (messages_on && messages_upgrade()) {
			fzn_reconcile_filer_t lines = { line_file, line_wanted, &line_rules, NULL, NULL, NULL };
			fzn_reconcile_bucket_tally_t bt;

			err = fzn_reconcile_buckets(&node_messages.buckets, FZN_BUCKETS_MESSAGES, &lines,
			                            peer_ask, &asking, reply, sizeof(reply), &bt);
			if (err != FZN_RECONCILE_OK) {
				say(FZN_ENTRY_WARNING, "reconcile", "conversations from %s: %s",
				    pulls[t].host, fzn_reconcile_err_str(err));
				continue;
			}
			if (bt.applied || bt.waiting || bt.refused || bt.full)
				say(bt.refused || bt.full ? FZN_ENTRY_WARNING : FZN_ENTRY_INFO, "reconcile",
				    "%zu line(s) from %s, %zu waiting for a key, %zu refused%s",
				    bt.applied + bt.waiting, pulls[t].host, bt.waiting, bt.refused,
				    bt.full ? ", too many months to list" : "");
			lines_lacked += bt.lacked;
			lines_filed += bt.applied + bt.waiting;
			lines_passed += bt.passed;
			/* AND PUSHED, sec 569: what the peer lacks, for a peer that
			 * cannot reach this node, through the gate a peer asking would
			 * meet. When both reach each other each pull already brought it,
			 * so this costs one listing. */
			{
				struct serving_to to = {
					pulls[t].is_root_at ? node_apply.root : pulls[t].node, -1
				};
				fzn_reconcile_gate_t gate = { serves_bucket, &to, NULL };

				fzn_reconcile_sent_t owed = { line_pushed, &node_messages };

				err = fzn_reconcile_push(&node_messages.buckets, FZN_BUCKETS_MESSAGES, &gate,
				                         NULL, &owed, peer_ask, &asking, reply, sizeof(reply),
				                         &bt);
				if (err != FZN_RECONCILE_OK) {
					say(FZN_ENTRY_WARNING, "reconcile", "conversations to %s: %s",
					    pulls[t].host, fzn_reconcile_err_str(err));
					continue;
				}
				if (bt.sent || bt.refused)
					say(bt.refused ? FZN_ENTRY_WARNING : FZN_ENTRY_INFO, "reconcile",
					    "%zu line(s) pushed to %s, %zu refused there", bt.sent,
					    pulls[t].host, bt.refused);
				lines_pushed += bt.sent;
			}
		}
#if defined(FZN_LOG_FILE_ON) && defined(FZN_LOG_PACK_ON)
		/* AND LOGS, both ways, sec 571: what this host is served of the
		 * peer's -- its own, or every source's with the retention
		 * capability -- and what the peer may hold of this host's. */
		if (logs_ready) {
			struct serving_to to = {
				pulls[t].is_root_at ? node_apply.root : pulls[t].node, -1
			};
			fzn_reconcile_gate_t gate = { serves_bucket, &to, NULL };
			fzn_reconcile_bucket_tally_t lt;

			err = fzn_reconcile_buckets(&logs_store, FZN_BUCKETS_LOGS, &logs_filer, peer_ask,
			                            &asking, reply, sizeof(reply), &lt);
			if (err != FZN_RECONCILE_OK)
				say(FZN_ENTRY_WARNING, "log/copy", "logs from %s: %s", pulls[t].host,
				    fzn_reconcile_err_str(err));
			else {
				segments_taken += lt.applied;
				segments_refused += lt.refused;
			}
			err = fzn_reconcile_push(&logs_store, FZN_BUCKETS_LOGS, &gate, &logs_filer, NULL,
			                         peer_ask, &asking, reply, sizeof(reply), &lt);
			if (err != FZN_RECONCILE_OK)
				say(FZN_ENTRY_WARNING, "log/copy", "logs to %s: %s", pulls[t].host,
				    fzn_reconcile_err_str(err));
			else
				segments_pushed += lt.sent;
		}
		/* AND PIECES, sec 597: those placed on this host fetched, those
		 * placed on the peer pushed, through the same gate. */
		if (pieces_ready) {
			struct serving_to to = { pulls[t].pairing.node, -1 };
			fzn_reconcile_gate_t gate = { serves_bucket, &to, NULL };
			fzn_reconcile_bucket_tally_t pt;

			err = fzn_reconcile_buckets(&logs_store, FZN_BUCKETS_PIECES, &pieces_filer,
			                            peer_ask, &asking, reply, sizeof(reply), &pt);
			if (err != FZN_RECONCILE_OK)
				say(FZN_ENTRY_WARNING, "log/copy", "pieces from %s: %s", pulls[t].host,
				    fzn_reconcile_err_str(err));
			else
				pieces_taken += pt.applied;
			err = fzn_reconcile_push(&logs_store, FZN_BUCKETS_PIECES, &gate, &pieces_filer,
			                         NULL, peer_ask, &asking, reply, sizeof(reply), &pt);
			if (err != FZN_RECONCILE_OK)
				say(FZN_ENTRY_WARNING, "log/copy", "pieces to %s: %s", pulls[t].host,
				    fzn_reconcile_err_str(err));
			else {
				pieces_pushed += pt.sent;
				pieces_refused += pt.refused;
			}
		}
#endif
	}
#if defined(FZN_LOG_FILE_ON) && defined(FZN_LOG_PACK_ON)
	if (pieces_taken || pieces_pushed || pieces_refused)
		say(pieces_refused ? FZN_ENTRY_WARNING : FZN_ENTRY_INFO, "log/copy",
		    "pieces of archived segments: %zu taken, %zu pushed, %zu refused there",
		    pieces_taken, pieces_pushed, pieces_refused);
#else
	(void)pieces_taken;
	(void)pieces_pushed;
	(void)pieces_refused;
#endif
	/* EVERY PASS THAT RAN SAYS SO, at debug, as the trim's and the cut's do. */
	say(FZN_ENTRY_DEBUG, "reconcile",
	    "reconcile pass: %zu peer(s), %zu of another estate passed over, %zu lacked, "
	    "%zu applied, %zu waiting, %zu refused; lines %zu lacked, %zu filed, %zu month(s) "
	    "passed over, %zu pushed; segments %zu taken, %zu refused, %zu pushed",
	    npulls, foreign, lacked, applied, waiting, refused, lines_lacked, lines_filed,
	    lines_passed, lines_pushed, segments_taken, segments_refused, segments_pushed);
}

/* STREAMS THIS NODE IS BEHIND A PEER'S BASE ON, sec 552: the peer cut what
 * this node never pulled, so each takes the peer's base -- reconciliation
 * brings the state those records carried -- and the reader of the stream is
 * moved up with it. */
static void rebase_missed(struct pull_target *pulls, size_t npulls, size_t t, uint64_t now,
                          const fzn_exchange_tally_t *tally)
{
	static uint8_t reply[FZND_PULL_REPLY_MAX];
	static struct peer_asking others[FZND_ROUND_TARGETS_MAX];
	static fzn_reconcile_witness_t witnesses[FZND_ROUND_TARGETS_MAX];
	struct peer_asking asking = { &pulls[t].caller, now, pulls[t].host };
	size_t i, k, moved = 0, n_witnesses = 0;

	/* EVERY OTHER PULL PEER OF THIS ESTATE WITNESSES THE BRIDGE, sec 557. */
	for (k = 0; k < npulls; k++)
		if (k != t && peer_in_estate(&pulls[k]) && !silent_peer(&pulls[k])) {
			others[n_witnesses].caller = &pulls[k].caller;
			others[n_witnesses].now = now;
			others[n_witnesses].host = pulls[k].host;
			witnesses[n_witnesses].ask = peer_ask;
			witnesses[n_witnesses].ctx = &others[n_witnesses];
			n_witnesses++;
		}

	for (i = 0; i < tally->missing && i < FZN_EXCHANGE_MISSED_MAX; i++) {
		const uint8_t *issuer = tally->missed[i].issuer;
		uint32_t stream = tally->missed[i].stream;
		uint64_t base = 0;
		size_t confirmed = 0;
		fzn_reconcile_err_t err = fzn_reconcile_rebase(&node_journal, peer_ask, &asking,
		                                               witnesses, n_witnesses, issuer, stream,
		                                               reply, sizeof(reply), &base, &confirmed);

		if (err != FZN_RECONCILE_OK) {
			say(FZN_ENTRY_WARNING, "journal", "a stream behind %s's base would not move: %s",
			    pulls[t].host, fzn_reconcile_err_str(err));
			continue;
		}
		if (!base)
			continue;
		moved++;
		if (stream == FZN_NODE_JOURNAL_STREAM)
			say(confirmed ? FZN_ENTRY_INFO : FZN_ENTRY_WARNING, "journal",
			    "an estate stream moved up to %s's base, its bridge confirmed by %zu other "
			    "peer(s) of %zu asked",
			    pulls[t].host, confirmed, n_witnesses);
		if (stream == FZN_NOTE_STREAM)
			for (k = 0; k < n_notes_cursors; k++)
				if (memcmp(notes_cursors[k].key, issuer, FZN_PUBKEY_LEN) == 0
				    && notes_cursors[k].at < base - 1u)
					notes_cursors[k].at = base - 1u;
		if (stream == FZN_MESSAGE_STREAM && messages_on)
			fzn_node_messages_skip(&node_messages, issuer, base - 1u);
		if (stream == FZN_CATALOG_STREAM)
			catalog_skip(issuer, base - 1u);
	}
	if (tally->missing > moved)
		say(FZN_ENTRY_WARNING, "journal",
		    "%zu stream(s) %s claims no longer hold what this node lacks, %zu moved up to "
		    "its base",
		    tally->missing, pulls[t].host, moved);
	else
		say(FZN_ENTRY_INFO, "journal", "%zu stream(s) moved up to %s's base", moved,
		    pulls[t].host);
}

/* ONE ROUND OF THE JOURNAL against every pull peer. */
/* PUSHED BACK, sec 512: what this node holds of every stream `pt` follows,
 * so a hub that pulls from nobody still hears this member. */
static void push_one(struct pull_target *pt, uint64_t now)
{
	static uint8_t reply[FZND_PULL_REPLY_MAX];
	struct peer_asking asking = { &pt->caller, now, pt->host };
	fzn_exchange_push_tally_t pushed;
	fzn_exchange_err_t perr = fzn_node_journal_push(&node_journal, peer_ask, &asking, reply,
	                                                sizeof(reply), &pushed);

	if (perr != FZN_EXCHANGE_OK)
		say(FZN_ENTRY_WARNING, "journal", "pushing to %s: %s", pt->host,
		    fzn_exchange_err_str(perr));
	else if (pushed.taken || pushed.refused || pushed.forks)
		say(pushed.refused || pushed.forks ? FZN_ENTRY_WARNING : FZN_ENTRY_INFO, "journal",
		    "%zu record(s) pushed to %s, %zu refused, %zu forked", pushed.taken, pt->host,
		    pushed.refused, pushed.forks);
}

#endif

#ifdef FZN_RECORD_STORE_FILE_ON
/* ---- THE JOURNAL'S CONVERSATIONS, sec 636: a pull and then a push with
 * every peer at once, each pull and push steps (`record/exchange.h`).
 * Pulls from two peers may plan the same records; the second to come is
 * taken as held, so it costs only the bytes. Begun by `journal_start`,
 * said by `journal_settle` as the round in turn said them. */
#define FZND_JOURNAL_MESSAGE_MAX                                                               \
	(FZND_PULL_REPLY_MAX < FZN_EXCHANGE_PUSH_HEAD_LEN + 16u * (2u + FZN_RECORD_MAX_LEN)         \
	         ? FZND_PULL_REPLY_MAX                                                             \
	         : FZN_EXCHANGE_PUSH_HEAD_LEN + 16u * (2u + FZN_RECORD_MAX_LEN))
_Static_assert(FZND_JOURNAL_MESSAGE_MAX >= FZN_EXCHANGE_REPLY_MIN,
               "a journal message carries a record of the largest size");

struct journal_talk {
	fzn_node_talk_t talk;
	struct meter m;
	size_t t; /* the peer's place in the round's targets */
	int pushing;
	fzn_exchange_pulling_t pull;
	fzn_exchange_pushing_t push;
	fzn_exchange_err_t pull_err, push_err;
	uint8_t message[FZND_JOURNAL_MESSAGE_MAX];
};
static struct journal_talk journal_talks[FZND_ROUND_TARGETS_MAX];
static size_t n_journal_talks;

/* THE PUSH, once the pull is over, as the round in turn pushed after it. */
static int journal_push_begin(struct journal_talk *jt, uint8_t *request, size_t cap,
                              size_t *request_len)
{
	jt->pushing = 1;
	jt->push_err = fzn_exchange_push_begin(&jt->push, &node_journal.journal, &node_journal.store,
	                                       request, cap, request_len);
	if (jt->push_err != FZN_EXCHANGE_OK)
		return 0;
	meter_asked(&jt->m, *request_len);
	return 1;
}

static int journal_talk_step(void *ctx, const uint8_t *reply, size_t reply_len, uint8_t *request,
                             size_t cap, size_t *request_len)
{
	struct journal_talk *jt = ctx;
	int done = 0;

	meter_answer(&jt->m, reply, reply_len);
	if (!jt->pushing) {
		jt->pull_err = fzn_exchange_pull_step(&jt->pull, reply, reply_len, request, cap,
		                                      request_len, &done);
		/* UNANSWERED: passed over for the rest of the round, sec 587, and
		 * not pushed to. Any other end of the pull, the push. */
		if (jt->pull_err == FZN_EXCHANGE_ERR_NO_ANSWER)
			return 0;
		if (jt->pull_err != FZN_EXCHANGE_OK || done)
			return journal_push_begin(jt, request, cap, request_len);
		meter_asked(&jt->m, *request_len);
		return 1;
	}
	jt->push_err = fzn_exchange_push_step(&jt->push, reply, reply_len, request, cap, request_len,
	                                      &done);
	if (jt->push_err != FZN_EXCHANGE_OK || done)
		return 0;
	meter_asked(&jt->m, *request_len);
	return 1;
}

static void journal_start(struct pull_target *pulls, size_t npulls, uint64_t now)
{
	size_t t, len;

	n_journal_talks = 0;
	if (!journal_on)
		return;
	for (t = 0; t < npulls && n_journal_talks < FZND_ROUND_TARGETS_MAX; t++) {
		struct journal_talk *jt = &journal_talks[n_journal_talks];

		if (silent_peer(&pulls[t]))
			continue;
		jt->t = t;
		jt->pushing = 0;
		jt->push_err = FZN_EXCHANGE_OK;
		memset(&jt->push.tally, 0, sizeof(jt->push.tally));
		len = 0;
		jt->pull_err = fzn_exchange_pull_begin(&jt->pull, &node_journal.journal,
		                                       &node_journal.store, node_journal.sign,
		                                       node_journal.hash, FZN_NODE_JOURNAL_WINDOW,
		                                       jt->message, sizeof(jt->message), &len);
		if (jt->pull_err != FZN_EXCHANGE_OK)
			continue;
		n_journal_talks++;
		jt->pull_err = FZN_EXCHANGE_ERR_NO_ANSWER;
		(void)talk_start(&jt->talk, &jt->m, &pulls[t], now, journal_talk_step, jt, jt->message,
		                 sizeof(jt->message), len);
	}
}

/* WHAT THE JOURNAL'S CONVERSATIONS BROUGHT, said peer by peer; a peer whose
 * streams it no longer holds rebased, in turn. */
static void journal_settle(struct pull_target *pulls, size_t npulls, uint64_t now)
{
	size_t i;

	for (i = 0; i < n_journal_talks; i++) {
		const struct journal_talk *jt = &journal_talks[i];
		const fzn_exchange_tally_t *tally = &jt->pull.tally;
		const fzn_exchange_push_tally_t *pushed = &jt->push.tally;
		const char *host = pulls[jt->t].host;

		if (jt->pull_err == FZN_EXCHANGE_ERR_NO_ANSWER) {
			/* PASSED OVER FOR THE REST OF THE ROUND, sec 587. */
			say(FZN_ENTRY_WARNING, "journal", "%s did not answer; passed over this round",
			    host);
			continue;
		}
		if (jt->pull_err != FZN_EXCHANGE_OK)
			say(FZN_ENTRY_WARNING, "journal", "the journal from %s: %s", host,
			    fzn_exchange_err_str(jt->pull_err));
		else if (tally->missing)
			rebase_missed(pulls, npulls, jt->t, now, tally);
		else if (tally->learned || tally->refused || tally->forks)
			say(tally->forks ? FZN_ENTRY_WARNING : FZN_ENTRY_INFO, "journal",
			    "%zu record(s) from %s, %zu refused, %zu stream(s) stopped at a fork",
			    tally->learned, host, tally->refused, tally->forks);
		if (jt->push_err != FZN_EXCHANGE_OK)
			say(FZN_ENTRY_WARNING, "journal", "pushing to %s: %s", host,
			    fzn_exchange_err_str(jt->push_err));
		else if (pushed->taken || pushed->refused || pushed->forks)
			say(pushed->refused || pushed->forks ? FZN_ENTRY_WARNING : FZN_ENTRY_INFO, "journal",
			    "%zu record(s) pushed to %s, %zu refused, %zu forked", pushed->taken, host,
			    pushed->refused, pushed->forks);
	}
}
#endif

#ifdef FZN_RECORD_STORE_FILE_ON
/* WHAT THE JOURNAL BROUGHT, pulled or pushed, absorbed: a hub that pulls
 * from nobody absorbs what its members push. Nonzero when it went. */
/* ONCE, with every device followed: a store from before sec 536 is
 * rebuilt so its lines are kept in rows. CALLED BEFORE THE FIRST PULL, sec
 * 560: a pull can move a stream up to a peer's base and let go of the
 * records below, and for a store from before rows those records are its
 * lines' only copy -- rebuilt afterwards, from the window, they would be
 * lost. Nonzero once the store is at this layout. */
static int messages_upgrade(void)
{
	static int upgraded;
	fzn_messages_err_t err;
	int rebuilt = 0;

	if (!messages_on)
		return 0;
	if (upgraded)
		return 1;
	err = fzn_messages_upgrade(&node_messages.m, &rebuilt);
	if (err != FZN_MESSAGES_OK) {
		say(FZN_ENTRY_WARNING, "messages", "keeping lines in rows: %s",
		    fzn_messages_err_str(err));
		return 0;
	}
	upgraded = 1;
	if (rebuilt)
		say(FZN_ENTRY_INFO, "messages", "conversations rebuilt, their lines kept in rows");
	/* AND EACH LINE'S ITEM, sec 564, from what the journal holds, before a
	 * pull can move a stream up past it. Once per store. */
	{
		size_t added = 0;

		err = fzn_messages_items_backfill(&node_messages.m, &added);
		if (err != FZN_MESSAGES_OK)
			say(FZN_ENTRY_WARNING, "messages", "keeping lines' items: %s",
			    fzn_messages_err_str(err));
		else if (added)
			say(FZN_ENTRY_INFO, "messages", "%zu line(s) kept as items, to be handed on",
			    added);
	}
	return 1;
}

static int messages_absorb(void)
{
	fzn_node_messages_tally_t t;
	fzn_messages_err_t err;

	if (!messages_upgrade())
		return 0;
	err = fzn_node_messages_absorb(&node_messages, &t);
	if (err != FZN_MESSAGES_OK) {
		say(FZN_ENTRY_WARNING, "messages", "absorbing: %s", fzn_messages_err_str(err));
		return 0;
	}
	if (t.marks)
		say(FZN_ENTRY_INFO, "messages", "%zu mark(s) absorbed", t.marks);
	/* A SUBSCRIBER TOLD CONVERSATIONS CHANGED, sec 609. */
	if (t.read || t.marks)
		publish("message", NULL);
	return 1;
}

/* How often the rules trim conversations, sec 531: they go by the month,
 * so an hour is soon enough. */
#define FZND_TRIM_EVERY 3600u

/* CONVERSATIONS TRIMMED BY THE RULES, sec 531: the rules naming `messages`
 * that reach this node, from the one set the logs' are drawn from. No rule
 * trims nothing -- there is no default deletion of messages. */
static fzn_group_lines_t group_lines; /* sec 629, defined with its lines below */

/* A GROUP'S SEALED LINES TRIMMED AS ITS CONVERSATION WAS, sec 664: each
 * host's from its base while a line's month is gone from the group's
 * conversation here -- a rule trimmed it -- so a line a rule pruned is not
 * kept, nor served to a member, sealed. A month no rule trimmed keeps
 * every line, nothing being trimmed by default (sec 531). */
static size_t group_lines_trim_gone(void)
{
	static uint8_t ids[FZN_GROUPS_HELD_MAX][FZN_GROUP_ID_LEN];
	static fzn_group_line_head_t heads[FZN_GROUP_HOSTS_MAX];
	static uint8_t bytes[FZN_GROUP_LINE_MAX];
	static fzn_group_line_t peeked;
	size_t n = 0, i, k, nh, len, removed, total = 0;
	uint32_t s, upto;

	if (!group_lines.store || !node_messages.m.store
	    || fzn_group_log_list(node_apply.store, ids, FZN_GROUPS_HELD_MAX, &n) != FZN_GROUP_LOG_OK)
		return 0;
	for (i = 0; i < n; i++) {
		nh = 0;
		if (fzn_group_lines_heads(&group_lines, ids[i], heads, FZN_GROUP_HOSTS_MAX, &nh)
		    != FZN_GROUP_LINES_OK)
			continue;
		for (k = 0; k < nh; k++) {
			upto = heads[k].base;
			for (s = heads[k].base + 1u; s <= heads[k].have; s++) {
				len = 0;
				if (fzn_group_lines_get(&group_lines, ids[i], heads[k].host, s, bytes,
				                        sizeof(bytes), &len)
				            != FZN_GROUP_LINES_OK
				    || fzn_group_line_peek(bytes, len, &peeked) != FZN_GROUP_LINE_OK
				    || !fzn_messages_month_gone(&node_messages.m, ids[i],
				                                fzn_message_epoch_of(peeked.stime)))
					break;
				upto = s;
			}
			removed = 0;
			if (upto > heads[k].base
			    && fzn_group_lines_trim(&group_lines, ids[i], heads[k].host, upto, &removed)
			               == FZN_GROUP_LINES_OK)
				total += removed;
		}
	}
	return total;
}

static void messages_trim(uint64_t now)
{
	static fzn_retain_rule_t rules[FZN_RETAIN_RULES_MAX];
	static uint64_t next_trim;
	fzn_messages_trim_tally_t tally;
	fzn_messages_err_t err;
	size_t n, gathered;

	if (now < next_trim && next_trim <= now + FZND_TRIM_EVERY)
		return;
	next_trim = now + FZND_TRIM_EVERY;
	gathered = gather_rules(rules);
	n = fzn_retain_select_messages(rules, gathered, dlog.has_host ? dlog.host : NULL,
	                               here_machine(), rules);
	memset(&tally, 0, sizeof(tally));
	err = n ? fzn_messages_trim(&node_messages.m, rules, n, wall_ms(), &tally) : FZN_MESSAGES_OK;
	if (err != FZN_MESSAGES_OK) {
		say(FZN_ENTRY_WARNING, "messages", "trimming by the rules: %s",
		    fzn_messages_err_str(err));
		return;
	}
	if (tally.months)
		say(FZN_ENTRY_INFO, "messages",
		    "%zu month(s) of %zu conversation(s) trimmed by the rules", tally.months,
		    tally.conversations);
	/* AND THE GROUPS' SEALED COPIES WITH THEM, sec 664. */
	if (n) {
		size_t sealed = group_lines_trim_gone();

		if (sealed)
			say(FZN_ENTRY_INFO, "messages", "%zu sealed group line(s) trimmed with their month",
			    sealed);
	}
	/* EVERY PASS THAT RAN SAYS SO, at debug: that nothing was trimmed reads
	 * the same as a pass that never happened, and `make livecheck` waits on
	 * this line before believing either. */
	say(FZN_ENTRY_DEBUG, "messages",
	    "trim pass: %zu of %zu rule(s) over conversations here, %zu month(s) trimmed", n,
	    gathered, tally.months);
}

/* CONVERSATIONS, sec 527: what the journal brought absorbed, then keys
 * given to and asked of every pull peer, then the rules' trim. */
/* ---- THE MESSAGES' KEYS WITH EACH PEER, a conversation, sec 636: one
 * peer after another, as the round asked them -- a key one peer takes is
 * given no more, so asking them all at once would give it to each -- each
 * request awaited by the loop. */
struct keys_talk {
	fzn_node_talk_t talk;
	struct meter m;
	fzn_node_messages_rounding_t r;
	struct pull_target *peers[FZND_ROUND_TARGETS_MAX];
	size_t n, at;
	uint64_t now;
	uint8_t request[FZN_NODE_MESSAGES_REQUEST_MAX];
};
static struct keys_talk keys_talk;

_Static_assert(FZND_PULL_REPLY_MAX >= FZN_NODE_MESSAGES_REPLY_MAX,
               "a keys answer fits the round's answers");

static void keys_next_peer(struct keys_talk *kt);

static int keys_talk_step(void *ctx, const uint8_t *reply, size_t reply_len, uint8_t *request,
                          size_t cap, size_t *request_len)
{
	struct keys_talk *kt = ctx;
	const char *host = kt->peers[kt->at]->host;
	int done = 0, ok;

	meter_answer(&kt->m, reply, reply_len);
	ok = fzn_node_messages_round_step(&kt->r, reply, reply_len, request, cap, request_len,
	                                  &done);
	/* AN ANSWER'S KEYS, wiped once taken: the loop's buffer holds them. */
	if (reply)
		memset(round_reply, 0, reply_len);
	if (!ok) {
		say(FZN_ENTRY_WARNING, "messages", "keys with %s: no answer", host);
		return 0;
	}
	if (done) {
		const fzn_node_messages_tally_t *t = &kt->r.tally;

		if (t->given || t->refused || t->taken)
			say(t->refused ? FZN_ENTRY_WARNING : FZN_ENTRY_INFO, "messages",
			    "keys with %s: %zu given, %zu refused, %zu taken, %zu still lacked", host,
			    t->given, t->refused, t->taken, t->lacking);
		return 0;
	}
	meter_asked(&kt->m, *request_len);
	return 1;
}

static void keys_talk_over(void *ctx)
{
	struct keys_talk *kt = ctx;

	kt->at++;
	keys_next_peer(kt);
	if (round_pending)
		round_pending--;
}

/* THE NEXT PEER's exchange begun, the round's count held for it; none left
 * when there is nothing to give or ask. */
static void keys_next_peer(struct keys_talk *kt)
{
	size_t len;
	int done;

	for (; kt->at < kt->n; kt->at++) {
		len = 0;
		done = 0;
		if (!fzn_node_messages_round_begin(&kt->r, &node_messages, kt->request,
		                                   sizeof(kt->request), &len, &done)
		    || done)
			return;
		if (talk_start_over(&kt->talk, &kt->m, kt->peers[kt->at], kt->now, keys_talk_step,
		                    keys_talk_over, 1, kt, kt->request, sizeof(kt->request), len))
			return;
		/* NOT SENT: wiped, and said as the round said no answer. */
		memset(kt->request, 0, sizeof(kt->request));
		say(FZN_ENTRY_WARNING, "messages", "keys with %s: no answer", kt->peers[kt->at]->host);
	}
}

/* THE MESSAGES' ROUND: what came absorbed and trimmed, then the keys with
 * each peer not silent, in turn. */
static void messages_round(struct pull_target *pulls, size_t npulls, uint64_t now)
{
	size_t p;

	if (!messages_absorb())
		return;
	messages_trim(now);
	keys_talk.n = keys_talk.at = 0;
	keys_talk.now = now;
	for (p = 0; p < npulls && keys_talk.n < FZND_ROUND_TARGETS_MAX; p++)
		if (!silent_peer(&pulls[p]))
			keys_talk.peers[keys_talk.n++] = &pulls[p];
	/* EACH PEER'S EXCHANGE COUNTED AS IT STARTS, the next begun before the
	 * last is released, so the round waits for the whole chain. */
	keys_next_peer(&keys_talk);
}

/* THE JOURNAL'S WINDOW, sec 548: hourly, every followed estate, notes and
 * conversations stream cut below the first record younger than the window
 * -- `journal/window` days, 60 unset -- and no further than its own reader
 * has got: apply, the notes index, the messages store. Each keeps what it
 * read, so the journal holds only what is in transit and recent. Every
 * stream is compared in milliseconds (sec 561). */
static void journal_cut(uint64_t now)
{
	static uint64_t next_cut;
	uint64_t span, cut_before, total = 0;
	size_t i, k, streams = 0, forgot = 0;

	if (!journal_on || !node_journal.keep)
		return;
	if (now < next_cut && next_cut <= now + FZND_TRIM_EVERY)
		return;
	next_cut = now + FZND_TRIM_EVERY;
	span = (uint64_t)fzn_node_settings_window_days(&node_settings) * 86400u;
	if (now <= span)
		return;
	cut_before = now - span;
	for (i = 0; i < node_journal.journal.used; i++) {
		const fzn_journal_entry_t *e = &node_journal.entries[i];
		uint64_t below;
		size_t n = 0;
		fzn_node_journal_err_t err;

		if (e->stream == FZN_NODE_JOURNAL_STREAM) {
			below = fzn_node_journal_cut_point(&node_journal, e->issuer, e->stream,
			                                   e->applied, cut_before * 1000u);
		} else if (e->stream == FZN_NOTE_STREAM && notes_on) {
			uint64_t indexed = 0;

			for (k = 0; k < n_notes_cursors; k++)
				if (memcmp(notes_cursors[k].key, e->issuer, FZN_PUBKEY_LEN) == 0)
					indexed = notes_cursors[k].at;
			below = fzn_node_journal_cut_point(&node_journal, e->issuer, e->stream, indexed,
			                                   cut_before * 1000u);
		} else if (e->stream == FZN_MESSAGE_STREAM && messages_on) {
			below = fzn_node_messages_cut_point(&node_messages, e->issuer,
			                                    cut_before * 1000u);
		} else {
			continue;
		}
		err = fzn_node_journal_cut(&node_journal, e->issuer, e->stream, below, &n);
		if (err != FZN_NODE_JOURNAL_OK) {
			say(FZN_ENTRY_WARNING, "journal", "a stream would not cut: %s",
			    fzn_node_journal_err_str(err));
			continue;
		}
		total += n;
		streams += n != 0u;
	}
	if (total)
		say(FZN_ENTRY_INFO, "journal",
		    "%llu record(s) older than the window cut from %zu stream(s)",
		    (unsigned long long)total, streams);
	/* AND THE CLEARS LEARNED BEFORE IT, sec 549: no journal holds an older
	 * set to arrive late any more. */
	if (node_settings.store) {
		fzn_node_settings_err_t serr =
		        fzn_node_settings_forget_clears(&node_settings, cut_before, &forgot);

		if (serr != FZN_NODE_SETTINGS_OK)
			say(FZN_ENTRY_WARNING, "settings", "clears past the window: %s",
			    fzn_node_settings_err_str(serr));
	}
	/* EVERY PASS THAT RAN SAYS SO, at debug, as the trim's does. */
	say(FZN_ENTRY_DEBUG, "journal",
	    "cut pass: a window of %llu day(s), %llu record(s) cut, %zu clear(s) forgotten",
	    (unsigned long long)(span / 86400u), (unsigned long long)total, forgot);
}
#endif

/* Every note each pull peer holds that this node lacks or holds older,
 * admitted as any record is. sec 432. */
/* THE NOTES' WORK WITH EACH PEER once the estate's members are known: the
 * texts, wrap keys and purges, sec 519. The round's own members come from
 * its conversations (`members_start`, sec 636), and so do its exchanges with
 * each peer (`notes_start`) -- a note written here sends them at once by
 * the same steps (`fresh_notes_plan`). */
static void notes_before_peers(void)
{
#ifdef FZN_RECORD_STORE_FILE_ON
	index_notes();
	index_catalog();
#endif
	/* A PURGE NOT SAID, sec 519: marked here, and no follower told. */
	{
		static size_t untold;

		if (node_notes.purges_untold != untold) {
			untold = node_notes.purges_untold;
			say(FZN_ENTRY_WARNING, "notes/purge",
			    "%zu purge(s) marked here were not written to the journal", untold);
		}
	}
}

static void notes_after_peers(void)
{
	/* AND WHAT THE SILENT PIN, sec 472: a purge waiting a month on nodes
	 * gone as long is released from them, every round. */
	{
		size_t released = 0, finished = 0;

		if (!fzn_node_notes_release_purges(&node_notes, &released, &finished))
			say(FZN_ENTRY_WARNING, "notes/purge", "the purges would not read");
		else if (released)
			say(FZN_ENTRY_INFO, "notes/purge",
			        "%zu silent node(s) released from purges, %zu purge(s) finished",
			        released, finished);
	}
#ifdef FZN_SPOOL_FILE_ON
	/* EVERY NOTE'S CONTENT IS A BLOB, sec 514, and names what to fetch: each held is
	 * wanted on the shelf, which answers at once for a text already here,
	 * so the texts follow their notes in the same round. sec 432. */
	if (shelf_on
	    && fzn_notes_view_load(&node_notes.store, node_notes.author.view) == FZN_NOTES_OK) {
		const fzn_notes_view_t *v = node_notes.author.view;
		size_t i;

		for (i = 0; i < v->count; i++) {
			fzn_note_blob_ref_t ref;

			if (fzn_notes_ref_of(&v->nodes[i], &ref))
				(void)fzn_node_shelf_want(&shelf, ref.root, ref.length);
		}
	}
#endif
}

static void wraps_said(const char *host, fzn_notes_sync_err_t werr, const fzn_notes_wrap_tally_t *wt)
{
	if (werr != FZN_NOTES_SYNC_OK)
		say(FZN_ENTRY_WARNING, "notes/wrap", "wrap keys with %s: %s", host,
		        fzn_notes_sync_err_str(werr));
	else if (wt->taken || wt->refused || wt->given)
		say(wt->refused ? FZN_ENTRY_WARNING : FZN_ENTRY_INFO, "notes/wrap",
		        "wrap keys with %s: %zu taken, %zu refused, %zu given", host, wt->taken,
		        wt->refused, wt->given);
}

static void texts_said(const char *host, int ok, const fzn_node_notes_text_tally_t *tt)
{
	if (!ok)
		say(FZN_ENTRY_WARNING, "notes/text", "texts to %s: no answer", host);
	else if (tt->pushed || tt->refused)
		say(FZN_ENTRY_INFO, "notes/text", "%zu text(s) to %s in %zu span(s), %zu refused",
		        tt->pushed, host, tt->spans, tt->refused);
}

static void purges_said(const char *host, fzn_notes_sync_err_t err,
                        const fzn_notes_purge_tally_t *pt)
{
	if (err != FZN_NOTES_SYNC_OK)
		say(FZN_ENTRY_WARNING, "notes/purge", "purges with %s: %s", host,
		        fzn_notes_sync_err_str(err));
	else if (pt->erased || pt->finished || pt->taken || pt->refused || pt->declined)
		say(FZN_ENTRY_INFO, "notes/purge",
		        "purges with %s: %zu erased there, %zu finished, "
		        "%zu taken, %zu refused, %zu declined",
		        host, pt->erased, pt->finished, pt->taken, pt->refused, pt->declined);
}

/* ---- THE NOTES' CONVERSATIONS, sec 636: with every peer at once, its wrap
 * keys, its texts and its purges each a conversation of its own, so a
 * silent peer costs the step one timeout rather than one for each. Begun
 * by `notes_start`, told by `notes_settle`. */
_Static_assert(FZND_PULL_REPLY_MAX >= FZN_NOTES_SYNC_WRAPS_REPLY_MAX,
               "a wrap keys answer fits the round's answers");
_Static_assert(FZND_PULL_REPLY_MAX
                       >= FZN_NOTES_SYNC_LIST_HEAD_LEN
                                  + (FZN_NOTES_SYNC_PURGES_MAX * FZN_TREE_ID_LEN),
               "a purges list fits the round's answers");

struct notes_talk {
	const struct pull_target *pt;
	struct {
		fzn_node_talk_t talk;
		struct meter m;
		uint8_t request[FZN_NOTES_SYNC_WRAPS_REPLY_MAX];
		fzn_notes_wrapping_t state;
		fzn_notes_sync_err_t err;
	} wraps;
	struct {
		fzn_node_talk_t talk;
		struct meter m;
		uint8_t request[FZN_NODE_NOTES_TEXT_REQUEST_MAX];
		fzn_node_notes_texting_t state;
		int ok;
	} texts;
	struct {
		fzn_node_talk_t talk;
		struct meter m;
		uint8_t request[FZN_NOTES_SYNC_PURGE_ACK_LEN];
		fzn_notes_purging_t state;
		fzn_notes_sync_err_t err;
	} purges;
};
static struct notes_talk notes_talks[FZND_ROUND_TARGETS_MAX];
static size_t n_notes_talks;

static int wraps_talk_step(void *ctx, const uint8_t *reply, size_t reply_len, uint8_t *request,
                           size_t cap, size_t *request_len)
{
	struct notes_talk *nt = ctx;
	int done = 0;

	meter_answer(&nt->wraps.m, reply, reply_len);
	nt->wraps.err = fzn_notes_sync_wraps_step(&nt->wraps.state, reply, reply_len, request, cap,
	                                          request_len, &done);
	if (nt->wraps.err != FZN_NOTES_SYNC_OK || done)
		return 0;
	meter_asked(&nt->wraps.m, *request_len);
	return 1;
}

static int texts_talk_step(void *ctx, const uint8_t *reply, size_t reply_len, uint8_t *request,
                           size_t cap, size_t *request_len)
{
	struct notes_talk *nt = ctx;
	int done = 0;

	meter_answer(&nt->texts.m, reply, reply_len);
	nt->texts.ok = fzn_node_notes_push_texts_step(&nt->texts.state, reply, reply_len, request,
	                                              cap, request_len, &done);
	if (!nt->texts.ok || done)
		return 0;
	meter_asked(&nt->texts.m, *request_len);
	return 1;
}

static int purges_talk_step(void *ctx, const uint8_t *reply, size_t reply_len, uint8_t *request,
                            size_t cap, size_t *request_len)
{
	struct notes_talk *nt = ctx;
	int done = 0;

	meter_answer(&nt->purges.m, reply, reply_len);
	nt->purges.err = fzn_notes_sync_purges_step(&nt->purges.state, reply, reply_len, request,
	                                            cap, request_len, &done);
	if (nt->purges.err != FZN_NOTES_SYNC_OK || done)
		return 0;
	meter_asked(&nt->purges.m, *request_len);
	return 1;
}

/* THE NOTES' WORK WITH EVERY PEER, begun: what each exchange asks first,
 * and a conversation for each that asks anything. */
static void notes_start(struct pull_target *pulls, size_t npulls, uint64_t now)
{
	size_t t, len;
	int done;

	n_notes_talks = 0;
	if (!notes_on)
		return;
	notes_before_peers();
	for (t = 0; t < npulls && n_notes_talks < FZND_ROUND_TARGETS_MAX; t++) {
		struct notes_talk *nt = &notes_talks[n_notes_talks];

		if (silent_peer(&pulls[t]))
			continue;
		n_notes_talks++;
		nt->pt = &pulls[t];
		/* THEIR WRAP KEYS, sec 520, both ways: a note this node holds the
		 * records of is unreadable here until its wrap key arrives. */
		len = 0;
		done = 0;
		nt->wraps.err = fzn_notes_sync_wraps_begin(&nt->wraps.state, &node_notes.store, 1,
		                                           nt->wraps.request,
		                                           sizeof(nt->wraps.request), &len, &done);
		if (nt->wraps.err == FZN_NOTES_SYNC_OK && !done
		    && !talk_start(&nt->wraps.talk, &nt->wraps.m, &pulls[t], now, wraps_talk_step, nt,
		                   nt->wraps.request, sizeof(nt->wraps.request), len))
			nt->wraps.err = FZN_NOTES_SYNC_NO_ANSWER;
		/* THEIR TEXTS, sec 448: a pushed note whose text stayed here
		 * would be a note nobody there could read. */
		len = 0;
		done = 0;
		nt->texts.ok = fzn_node_notes_push_texts_begin(&nt->texts.state, &node_notes,
		                                               nt->texts.request,
		                                               sizeof(nt->texts.request), &len,
		                                               &done);
		if (nt->texts.ok && !done
		    && !talk_start(&nt->texts.talk, &nt->texts.m, &pulls[t], now, texts_talk_step, nt,
		                   nt->texts.request, sizeof(nt->texts.request), len))
			nt->texts.ok = 0;
		/* THE PURGE CONVERSATION, driven from this side. sec 433. */
		len = 0;
		done = 0;
		nt->purges.err = fzn_notes_sync_purges_begin(
		        &nt->purges.state, &node_notes.store, node_notes.author.policy,
		        node_notes.pulls[t].key, nt->purges.request, sizeof(nt->purges.request), &len,
		        &done);
		if (nt->purges.err == FZN_NOTES_SYNC_OK && !done
		    && !talk_start(&nt->purges.talk, &nt->purges.m, &pulls[t], now, purges_talk_step,
		                   nt, nt->purges.request, sizeof(nt->purges.request), len))
			nt->purges.err = FZN_NOTES_SYNC_NO_ANSWER;
	}
}

/* WHAT THE NOTES' CONVERSATIONS DID, said peer by peer as the round in turn
 * said it, and the work after them. */
static void notes_settle(void)
{
	size_t i;

	if (!notes_on)
		return;
	for (i = 0; i < n_notes_talks; i++) {
		const struct notes_talk *nt = &notes_talks[i];

		wraps_said(nt->pt->host, nt->wraps.err, &nt->wraps.state.tally);
		texts_said(nt->pt->host, nt->texts.ok, &nt->texts.state.tally);
		purges_said(nt->pt->host, nt->purges.err, &nt->purges.state.tally);
	}
	notes_after_peers();
}

/* SHARES THIS NODE ACCEPTED, as pull targets, sec 437: each sharer's node at
 * the address `add received` recorded, asked under the pairing its card
 * made. Reloaded when the verbs change the table. */
struct share_target {
	struct pull_target pt;
	char host[FZN_NODE_RECEIVED_HOST_MAX + 1u];
	uint8_t sharer[FZN_PUBKEY_LEN];
};

static struct share_target shares_in[FZN_NODE_RECEIVED_MAX];
static size_t nshares_in;
/* The running admin, whose `received_fresh` the loop reads. */
static fzn_node_admin_t *running_admin;

#ifdef FZN_RECORD_STORE_FILE_ON
static int contact_stands(void *ctx, const uint8_t contact[FZN_PUBKEY_LEN])
{
	static fzn_group_t held;

	/* A GROUP HELD STANDS, sec 629: its conversation is keyed by its id,
	 * which no contact list holds, and its lines go by the group's own
	 * way rather than a contact's. */
	return fzn_node_admin_contact_stands((const fzn_node_admin_t *)ctx, contact)
	       || (node_apply.store
	           && fzn_group_log_get(node_apply.store, contact, &held) == FZN_GROUP_LOG_OK);
}

static int contact_removed(void *ctx, const uint8_t contact[FZN_PUBKEY_LEN])
{
	return fzn_node_admin_contact_removed((const fzn_node_admin_t *)ctx, contact);
}

/* A LINE GIVEN UP ON, secs 607 and 616, each round: a line this user's
 * devices handed over for a contact that no longer stands -- removed, or
 * not active on the roster -- or are still sending to one removed, is
 * marked not delivered, here or on whichever device first notices, and the mark goes
 * out at once so every device stops waiting on it. */
static void messages_give_up(void)
{
	size_t marked = 0;

	if (!messages_on || !running_admin)
		return;
	if (fzn_node_messages_give_up(&node_messages, contact_stands, contact_removed, running_admin,
	                              &marked)
	    != FZN_MESSAGES_OK)
		say(FZN_ENTRY_WARNING, "messages", "lines for contacts that no longer stand could not "
		                                   "all be marked");
	else if (marked) {
		say(FZN_ENTRY_INFO, "messages", "%zu line(s) handed over or still being sent for a "
		                                "contact that no longer stands, marked not delivered",
		    marked);
		node_messages.fresh = 1;
	}
}
#endif

#ifdef FZN_RECORD_STORE_FILE_ON
/* THE GRANT `sponsor` MADE TO `self` for `cap`, in the applied index, into
 * `hop`: 1 found, 0 not. */
static int grant_from(const uint8_t sponsor[FZN_PUBKEY_LEN], const uint8_t self[FZN_PUBKEY_LEN],
                      const fzn_cap_id_t *cap, uint8_t hop[FZN_HOP_LEN])
{
	size_t i;

	for (i = 0; i < node_apply.grants_used; i++)
		if (memcmp(node_apply.grants[i].grantor, sponsor, FZN_PUBKEY_LEN) == 0
		    && memcmp(node_apply.grants[i].grantee, self, FZN_PUBKEY_LEN) == 0
		    && memcmp(node_apply.grants[i].capability.b, cap->b, FZN_CAP_ID_LEN) == 0) {
			memcpy(hop, node_apply.grants[i].hop, FZN_HOP_LEN);
			return 1;
		}
	return 0;
}

/* SIBLINGS PAIRED, sec 579, each round once the journal is applied. For
 * every member whose prekey this node keeps, and who stands as a member
 * now -- a removed or revoked one is not paired:
 *
 *   - this node pairs it, as `add peer` would, unless this node serves it
 *     already -- the member this node admitted keeps the grant it joined
 *     with -- and logs the grant in its stream;
 *   - and once the member's own grant to this node has arrived, this node
 *     builds its pairing to that member from the grant and the member's
 *     prekey, unless it holds a pairing to it already -- the one it joined
 *     through above all, which it grants through.
 *
 * Each side is the other's half: one member's grant is the pairing the
 * other accepts. How many it paired: the round pushes again when any, so
 * the grants reach the root this round and not the next. */
static size_t pair_siblings(const fzn_node_identity_t *id, uint64_t now)
{
	static uint8_t hosts[FZN_NODE_SIBLINGS_MAX][FZN_PUBKEY_LEN];
	static uint8_t chain[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	uint8_t prekey[FZN_PREKEY_LEN_TOTAL];
	size_t n = 0, i, paired = 0, accepted = 0;

	if (!running_admin || !node_apply.store || !node_apply.capability)
		return 0;
	if (fzn_node_siblings_list(node_apply.store, hosts, FZN_NODE_SIBLINGS_MAX, &n)
	    != FZN_NODE_SIBLINGS_OK) {
		say(FZN_ENTRY_WARNING, "node/siblings", "the siblings' prekeys would not list");
		return 0;
	}
	for (i = 0; i < n; i++) {
		fzn_node_pairing_t pairing;
		fzn_setting_rank_t rank;
		const char *why = NULL;
		size_t hop_count = 0;
		int r;

		if (memcmp(hosts[i], id->pubkey, FZN_PUBKEY_LEN) == 0
		    || fzn_node_apply_rank(&node_apply, hosts[i], FZN_SCOPE_HOST, hosts[i], &rank) != 1
		    || fzn_node_siblings_prekey(node_apply.store, hosts[i], prekey)
		               != FZN_NODE_SIBLINGS_OK)
			continue;
		r = fzn_node_admin_pair_sibling(running_admin, prekey, &why);
		if (r > 0)
			paired++;
		else if (r < 0)
			say(FZN_ENTRY_WARNING, "node/siblings", "a sibling was not paired: %s",
			    why ? why : "its prekey would not open");
		if (fzn_node_pairing_load(node_apply.store, hosts[i], &pairing) == FZN_PERSIST_OK) {
			fzn_wipe(&pairing, sizeof(pairing));
			continue;
		}
		/* ITS CHAIN, then its grant to this node: verified whole, under
		 * the root the walk reached. */
		if (!fzn_node_apply_chain(&node_apply, hosts[i], node_apply.capability, chain,
		                          &hop_count)
		    || hop_count + 1u > FZN_CHAIN_MAX_HOPS
		    || !grant_from(hosts[i], id->pubkey, node_apply.capability, chain[hop_count]))
			continue;
		if (fzn_node_pairing_from_grant(id, hop_count ? chain[0] + FZN_HOP_OFF_GRANTOR : hosts[i],
		                                (const uint8_t (*)[FZN_HOP_LEN])chain, hop_count + 1u,
		                                prekey, now, node_apply.store, &pairing)
		    == FZN_NODE_PAIR_OK) {
			accepted++;
			fzn_wipe(&pairing, sizeof(pairing));
		} else {
			say(FZN_ENTRY_WARNING, "node/siblings",
			    "a sibling's grant to this node did not make a pairing");
		}
	}
	if (paired || accepted)
		say(FZN_ENTRY_INFO, "node/siblings", "%zu sibling(s) paired, %zu pairing(s) taken",
		    paired, accepted);
	return paired;
}
#endif

/* A TARGET'S SOCKET AND CALLER, for a `pt` whose host, port and pairing are
 * set: a socket bound, the host resolved, its reassembly made, and the
 * caller filled from the pairing. 1 ready; 0 with nothing open and the
 * pairing wiped. */
static int open_target_on(struct pull_target *pt, int fd, int family,
                          const uint8_t self[FZN_PUBKEY_LEN], const fzn_hash_ops_t *hash,
                          const fzn_aead_ops_t *aead, const fzn_random_ops_t *rng);

static int open_target(struct pull_target *pt, int family, const uint8_t self[FZN_PUBKEY_LEN],
                       const fzn_hash_ops_t *hash, const fzn_aead_ops_t *aead,
                       const fzn_random_ops_t *rng)
{
	return open_target_on(pt, -1, family, self, hash, aead, rng);
}

/* `fd` an open socket to keep using, or -1 to bind a new one. */
static int open_target_on(struct pull_target *pt, int fd, int family,
                          const uint8_t self[FZN_PUBKEY_LEN], const fzn_hash_ops_t *hash,
                          const fzn_aead_ops_t *aead, const fzn_random_ops_t *rng)
{
	pt->fd = -1;
	if ((fd < 0 && fzn_udp_bind(family, NULL, 0, &fd) != FZN_UDP_OK)
	    || fzn_udp_resolve(family, pt->host, (uint16_t)pt->port, &pt->caller.node) != FZN_UDP_OK
	    || fzn_reasm_slot_init(&pt->slot, pt->slot_buf, sizeof(pt->slot_buf)) != FZN_REASM_OK
	    || fzn_reasm_init(&pt->table, &pt->slot, 1, 1u, 60u) != FZN_REASM_OK) {
		if (fd >= 0)
			fzn_udp_close(fd);
		fzn_wipe(&pt->pairing, sizeof(pt->pairing));
		return 0;
	}
	pt->fd = fd;
	fzn_node_pairing_caller(&pt->pairing, self, &pt->caller);
	pt->caller.fd = fd;
	pt->caller.hash = hash;
	pt->caller.aead = aead;
	pt->caller.rng = rng;
	pt->caller.reasm = &pt->table;
	pt->caller.hops = 1u;
	pt->caller.wrap = caller_wrap;
	return 1;
}

#ifdef FZN_RECORD_STORE_FILE_ON
/* THE SIBLINGS A ROUND ASKS, sec 586 (files alone since sec 580): every
 * member whose prekey this node keeps, to which it holds a pairing
 * (`pair_siblings`), and whose address is a setting (`net/address`) -- less
 * any the command line names already, the root among them -- built into
 * `pulls` after the `npulls` the command line gave, at most
 * FZND_SIBLING_TARGETS_MAX. So the journal, reconciliation, notes, messages,
 * texts and files all ask them as they ask a pull peer, and the estate
 * keeps syncing while the root is away. Rebuilt each round: a sibling paired
 * or given an address since is asked from then. How many were built. */
static char sibling_hosts[FZND_SIBLING_TARGETS_MAX][FZN_NODE_SETTINGS_HOST_MAX + 1u];
static size_t n_sibling_targets;

/* ---- introductions, sec 623 ------------------------------------------------ */

static fzn_node_relay_t relay_tables;
#define FZND_RELAY_SEEN_S 300u

/* A SIBLING'S SOCKET, KEPT ACROSS ROUNDS: a hole a NAT opens is opened for
 * one socket, and a sibling reached through an introduction is reached on
 * the socket the introduction was made from. Rebuilt targets reuse it. */
#define FZND_INTRO_MAX 16u
/* How long an introduced address is used, seconds. */
#define FZND_INTRO_S 600u

static struct sibling_socket {
	uint8_t key[FZN_PUBKEY_LEN];
	int fd;
} sibling_sockets[FZND_SIBLING_TARGETS_MAX];
static size_t n_sibling_sockets;

static struct introduced {
	uint8_t key[FZN_PUBKEY_LEN];
	char host[FZN_UDP_HOST_MAX];
	uint16_t port;
	uint64_t until;
	int due;
} introduced[FZND_INTRO_MAX];

static struct introduced *intro_of(const uint8_t key[FZN_PUBKEY_LEN], int make)
{
	size_t i, free_one = FZND_INTRO_MAX;

	for (i = 0; i < FZND_INTRO_MAX; i++) {
		if (introduced[i].until || introduced[i].due) {
			if (memcmp(introduced[i].key, key, FZN_PUBKEY_LEN) == 0)
				return &introduced[i];
		} else if (free_one == FZND_INTRO_MAX) {
			free_one = i;
		}
	}
	if (!make || free_one == FZND_INTRO_MAX)
		return NULL;
	memset(&introduced[free_one], 0, sizeof(introduced[free_one]));
	memcpy(introduced[free_one].key, key, FZN_PUBKEY_LEN);
	return &introduced[free_one];
}

static int sibling_fd(const uint8_t key[FZN_PUBKEY_LEN])
{
	size_t i;

	for (i = 0; i < n_sibling_sockets; i++)
		if (memcmp(sibling_sockets[i].key, key, FZN_PUBKEY_LEN) == 0)
			return sibling_sockets[i].fd;
	return -1;
}

static size_t load_siblings(struct pull_target *pulls, size_t npulls, int family,
                            const uint8_t self[FZN_PUBKEY_LEN], const uint8_t *root,
                            const fzn_hash_ops_t *hash, const fzn_aead_ops_t *aead,
                            const fzn_random_ops_t *rng)
{
	static uint8_t hosts[FZN_NODE_SIBLINGS_MAX][FZN_PUBKEY_LEN];
	static struct sibling_socket kept[FZND_SIBLING_TARGETS_MAX];
	size_t n = 0, i, t, built = 0, n_kept = 0;
	uint64_t now = wall_clock();

	for (i = 0; i < n_sibling_targets; i++)
		fzn_wipe(&pulls[npulls + i].pairing, sizeof(pulls[npulls + i].pairing));
	n_sibling_targets = 0;
	if (!node_apply.store
	    || fzn_node_siblings_list(node_apply.store, hosts, FZN_NODE_SIBLINGS_MAX, &n)
	               != FZN_NODE_SIBLINGS_OK)
		n = 0;
	for (i = 0; i < n && built < FZND_SIBLING_TARGETS_MAX; i++) {
		struct pull_target *pt = &pulls[npulls + built];
		struct introduced *in = intro_of(hosts[i], 0);
		uint16_t port = 0;
		int fd;

		if (memcmp(hosts[i], self, FZN_PUBKEY_LEN) == 0)
			continue;
		for (t = 0; t < npulls
		            && memcmp(pulls[t].is_root_at ? root : pulls[t].node, hosts[i],
		                      FZN_PUBKEY_LEN) != 0;
		     t++)
			;
		if (t < npulls)
			continue;
		memset(pt, 0, sizeof(*pt));
		pt->fd = -1;
		/* AN INTRODUCED ADDRESS FIRST, sec 623, while it lasts; else the
		 * sibling's own `net/address`. */
		if (in && in->until > now && in->port) {
			(void)snprintf(sibling_hosts[built], sizeof(sibling_hosts[built]), "%s", in->host);
			port = in->port;
		} else if (!fzn_node_settings_address(&node_settings, hosts[i], sibling_hosts[built],
		                                      &port)) {
			continue;
		}
		if (fzn_node_pairing_load(node_apply.store, hosts[i], &pt->pairing) != FZN_PERSIST_OK)
			continue;
		memcpy(pt->node, hosts[i], FZN_PUBKEY_LEN);
		pt->host = sibling_hosts[built];
		pt->port = port;
		fd = sibling_fd(hosts[i]);
		if (!open_target_on(pt, fd, family, self, hash, aead, rng)) {
			say(FZN_ENTRY_WARNING, "node/siblings", "could not reach for a sibling at %s",
			    sibling_hosts[built]);
			continue;
		}
		memcpy(kept[n_kept].key, hosts[i], FZN_PUBKEY_LEN);
		kept[n_kept++].fd = pt->fd;
		built++;
	}
	/* A SOCKET NO SIBLING USES NOW is closed. */
	for (i = 0; i < n_sibling_sockets; i++) {
		for (t = 0; t < n_kept && kept[t].fd != sibling_sockets[i].fd; t++)
			;
		if (t == n_kept && sibling_sockets[i].fd >= 0)
			fzn_udp_close(sibling_sockets[i].fd);
	}
	memcpy(sibling_sockets, kept, n_kept * sizeof(kept[0]));
	n_sibling_sockets = n_kept;
	n_sibling_targets = built;
	return built;
}

/* THE CAPABILITIES THIS NODE KNOWS, by the names its verbs use. */
static const fzn_cap_id_t *known_capability(size_t i, const char **name)
{
	const fzn_node_config_t *c = running_admin && running_admin->state
	                                     ? &running_admin->state->config
	                                     : NULL;

	if (!c)
		return NULL;
	switch (i) {
	case 0:
		*name = "member";
		return &c->remote_capability;
	case 1:
		*name = "admin";
		return c->has_admin ? &c->admin_capability : NULL;
	case 2:
		*name = "share";
		return c->has_share ? &c->share_capability : NULL;
	case 3:
		*name = "retention";
		return c->has_retention ? &c->retention_capability : NULL;
	}
	return NULL;
}
#define KNOWN_CAPABILITIES 4u

/* THE EXPIRY of chain `hops`' last hop, 0 for none or no chain. */
static uint64_t chain_expires(uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN], size_t hop_count)
{
	fzn_chain_hop_t hop;

	return hop_count && fzn_hop_open(hops[hop_count - 1u], FZN_HOP_LEN, &hop) == FZN_CHAIN_OK
	               ? fzn_hop_expires_at(hop)
	               : 0u;
}

/* `list capability`, sec 638: `ok N NAME,HOLDS,HOPS,EXPIRES ...` -- fzpd's
 * `cap-list`: for each capability this node knows -- member, and admin,
 * share and retention where it knows them -- whether it holds it now,
 * verified as it is answered (a root does; any other key by a chain from a
 * root, neither expired nor revoked: `fzn_node_apply_holds`), its chain's
 * hops, and when its last hop expires, 0 for never. A capability it does not
 * hold is said so, with 0 hops. */
static size_t capability_local(fzn_origin_t origin, const fzn_request_t *request, char *reply,
                               size_t cap)
{
	static uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	const uint8_t *self = routing_self;
	size_t i, n = 0, at;

	if (request->parsed != FZN_VERB_LIST || !request->arg || request->arg_len != 10u
	    || memcmp(request->arg, "capability", 10u) != 0)
		return 0;
	if (origin != FZN_ORIGIN_SAME_USER)
		return (size_t)snprintf(reply, cap, "denied this node's capabilities are its own "
		                                    "user's\n");
	if (!self || !node_apply.store)
		return (size_t)snprintf(reply, cap, "error this node holds no grants to read\n");
	for (i = 0; i < KNOWN_CAPABILITIES; i++) {
		const char *name;

		n += known_capability(i, &name) != NULL;
	}
	at = (size_t)snprintf(reply, cap, "ok %zu", n);
	for (i = 0; i < KNOWN_CAPABILITIES && at < cap; i++) {
		const char *name = NULL;
		const fzn_cap_id_t *c = known_capability(i, &name);
		size_t hop_count = 0;
		int holds;

		if (!c)
			continue;
		holds = fzn_node_apply_holds(&node_apply, self, c);
		if (!holds || !fzn_node_apply_chain(&node_apply, self, c, hops, &hop_count))
			hop_count = 0;
		at += (size_t)snprintf(reply + at, cap - at, " %s,%d,%zu,%llu", name, holds ? 1 : 0,
		                       hop_count, (unsigned long long)chain_expires(hops, hop_count));
	}
	return at + (size_t)snprintf(reply + at, cap > at ? cap - at : 0u, "\n");
}

/* `list grant [FROM]`, sec 638: `ok TOTAL FROM GRANTEE,NAME,EXPIRES,STANDS
 * ...` -- fzpd's `cap-granted`: every grant this node signed that its index
 * holds, a page at a time; NAME the capability's, or `other`; EXPIRES 0 for
 * never; STANDS 1 when the grantee holds the capability now -- revoked or
 * expired, 0 -- read from the revocations as answered, never kept. */
static size_t grant_local(fzn_origin_t origin, const fzn_request_t *request, char *reply,
                          size_t cap)
{
	const uint8_t *self = routing_self, *arg = request->arg;
	size_t arg_len = request->arg_len, i, total = 0, from = 0, at, k, seen = 0;

	if (request->parsed != FZN_VERB_LIST || !arg || arg_len < 5u || memcmp(arg, "grant", 5u) != 0
	    || (arg_len > 5u && arg[5] != ' '))
		return 0;
	if (origin != FZN_ORIGIN_SAME_USER)
		return (size_t)snprintf(reply, cap, "denied this node's grants are its own user's\n");
	for (k = 6u; k < arg_len; k++) {
		if (arg[k] < '0' || arg[k] > '9' || from > 100000u)
			return (size_t)snprintf(reply, cap, "malformed list grant [FROM]\n");
		from = from * 10u + (size_t)(arg[k] - '0');
	}
	if (!self)
		return (size_t)snprintf(reply, cap, "error this node holds no grants to read\n");
	for (i = 0; i < node_apply.grants_used; i++)
		total += memcmp(node_apply.grants[i].grantor, self, FZN_PUBKEY_LEN) == 0;
	at = (size_t)snprintf(reply, cap, "ok %zu %zu", total, from);
	for (i = 0; i < node_apply.grants_used; i++) {
		const fzn_node_grant_t *g = &node_apply.grants[i];
		const char *name = "other";
		fzn_chain_hop_t hop;
		char entry[160];
		size_t c, j;
		int len;

		if (memcmp(g->grantor, self, FZN_PUBKEY_LEN) != 0 || seen++ < from)
			continue;
		for (c = 0; c < KNOWN_CAPABILITIES; c++) {
			const char *cn = NULL;
			const fzn_cap_id_t *known = known_capability(c, &cn);

			if (known && memcmp(known, &g->capability, sizeof(*known)) == 0)
				name = cn;
		}
		len = snprintf(entry, sizeof(entry), " ");
		for (j = 0; j < FZN_PUBKEY_LEN; j++)
			len += snprintf(entry + len, sizeof(entry) - (size_t)len, "%02x", g->grantee[j]);
		len += snprintf(entry + len, sizeof(entry) - (size_t)len, ",%s,%llu,%d", name,
		                (unsigned long long)(fzn_hop_open(g->hop, FZN_HOP_LEN, &hop)
		                                                     == FZN_CHAIN_OK
		                                             ? fzn_hop_expires_at(hop)
		                                             : 0u),
		                fzn_node_apply_holds(&node_apply, g->grantee, &g->capability) ? 1 : 0);
		/* A PAGE IS WHAT FITS: the next one starts at the first left out. */
		if (len <= 0 || at + (size_t)len + 2u > cap)
			break;
		memcpy(reply + at, entry, (size_t)len);
		at += (size_t)len;
	}
	return at + (size_t)snprintf(reply + at, cap > at ? cap - at : 0u, "\n");
}

/* `list sibling [FROM]`, sec 638: `ok TOTAL FROM KEY,WHERE,PAIRED,HEARD ...`,
 * every other host of this estate this node knows, a page at a time --
 * fzpd's `sibling-list`: those whose prekey the estate's stream carried,
 * and the members paired into this node, which is how a root knows the
 * devices that joined through it. WHERE is where it is reached, as a round
 * reaches it (an introduced address while it lasts, else its
 * `net/address`), or `-`; PAIRED is `paired` when either holds a pairing
 * to the other, else `unpaired`;
 * HEARD the seconds since it last answered, or `-` for never. This node's
 * own user only: it names where every host of the estate is. */
static size_t sibling_local(fzn_origin_t origin, const fzn_request_t *request, char *reply,
                            size_t cap)
{
	static uint8_t hosts[FZN_NODE_SIBLINGS_MAX][FZN_PUBKEY_LEN];
	const uint8_t *self = routing_self;
	size_t n = 0, i, total = 0, from = 0, at, k;
	uint64_t now = wall_clock(), now_us = wall_ms() * 1000u;
	const uint8_t *arg = request->arg;
	size_t arg_len = request->arg_len;

	if (request->parsed != FZN_VERB_LIST || !arg || arg_len < 7u || memcmp(arg, "sibling", 7u) != 0
	    || (arg_len > 7u && arg[7] != ' '))
		return 0;
	if (origin != FZN_ORIGIN_SAME_USER)
		return (size_t)snprintf(reply, cap, "denied where this estate's hosts are is its own "
		                                    "user's\n");
	for (k = 8u; k < arg_len; k++) {
		if (arg[k] < '0' || arg[k] > '9' || from > 100000u)
			return (size_t)snprintf(reply, cap, "malformed list sibling [FROM]\n");
		from = from * 10u + (size_t)(arg[k] - '0');
	}
	if (!node_apply.store || !self
	    || fzn_node_siblings_list(node_apply.store, hosts, FZN_NODE_SIBLINGS_MAX, &n)
	               != FZN_NODE_SIBLINGS_OK)
		return (size_t)snprintf(reply, cap, "error the siblings would not read\n");
	/* AND THE MEMBERS PAIRED INTO THIS NODE, each once. */
	if (running_admin && running_admin->state)
		for (i = 0; i < running_admin->state->peer_count && n < FZN_NODE_SIBLINGS_MAX; i++) {
			const fzn_node_peer_t *pe = &running_admin->state->peers[i];

			if (fzn_node_peer_contact(&running_admin->state->config, pe))
				continue;
			for (k = 0; k < n && memcmp(hosts[k], pe->sender, FZN_PUBKEY_LEN) != 0; k++)
				;
			if (k == n)
				memcpy(hosts[n++], pe->sender, FZN_PUBKEY_LEN);
		}
	for (i = 0; i < n; i++)
		total += memcmp(hosts[i], self, FZN_PUBKEY_LEN) != 0;
	at = (size_t)snprintf(reply, cap, "ok %zu %zu", total, from);
	for (i = 0, k = 0; i < n && at < cap; i++) {
		struct introduced *in;
		fzn_node_pairing_t pairing;
		char where[FZN_NODE_SETTINGS_HOST_MAX + 8u], heard[24],
		        entry[FZN_NODE_SETTINGS_HOST_MAX + 128u];
		uint16_t port = 0;
		uint64_t when = 0;
		int paired, len;
		size_t j;

		if (memcmp(hosts[i], self, FZN_PUBKEY_LEN) == 0 || k++ < from)
			continue;
		in = intro_of(hosts[i], 0);
		if (in && in->until > now && in->port)
			(void)snprintf(where, sizeof(where), "%s:%u", in->host, (unsigned)in->port);
		else if (fzn_node_settings_address(&node_settings, hosts[i], where, &port)) {
			size_t w = strlen(where);

			(void)snprintf(where + w, sizeof(where) - w, ":%u", (unsigned)port);
		} else
			(void)snprintf(where, sizeof(where), "-");
		paired = fzn_node_pairing_load(node_apply.store, hosts[i], &pairing) == FZN_PERSIST_OK;
		fzn_wipe(&pairing, sizeof(pairing));
		for (j = 0; !paired && running_admin && running_admin->state
		            && j < running_admin->state->peer_count;
		     j++)
			paired = memcmp(running_admin->state->peers[j].sender, hosts[i], FZN_PUBKEY_LEN)
			         == 0;
		if (fzn_heard_when(node_apply.store, hosts[i], &when) == FZN_HEARD_OK)
			(void)snprintf(heard, sizeof(heard), "%llu",
			               (unsigned long long)(now_us > when ? (now_us - when) / 1000000u : 0u));
		else
			(void)snprintf(heard, sizeof(heard), "-");
		len = snprintf(entry, sizeof(entry), " ");
		for (j = 0; j < FZN_PUBKEY_LEN; j++)
			len += snprintf(entry + len, sizeof(entry) - (size_t)len, "%02x", hosts[i][j]);
		len += snprintf(entry + len, sizeof(entry) - (size_t)len, ",%s,%s,%s", where,
		                paired ? "paired" : "unpaired", heard);
		/* A PAGE IS WHAT FITS: the next one starts at the first left out. */
		if (len <= 0 || at + (size_t)len + 2u > cap)
			break;
		memcpy(reply + at, entry, (size_t)len);
		at += (size_t)len;
	}
	return at + (size_t)snprintf(reply + at, cap > at ? cap - at : 0u, "\n");
}

/* THE TYPES of an introduction, in notes-sync's space after the relay's 35:
 * INTRODUCE asks a peer to introduce a sibling; NOTIFY tells that sibling
 * where the asker asked from. Answered in words. */
#define FZND_INTRO_VERSION 2u
#define FZND_INTRODUCE_TYPE 37u
#define FZND_NOTIFY_TYPE 38u

/* SIBLINGS UNANSWERED LAST ROUND are due an introduction, sec 623. */
static void intro_note_silent(struct pull_target *pulls, size_t from, size_t to)
{
	size_t i;

	for (i = from; i < to; i++)
		if (silent_peer(&pulls[i])) {
			struct introduced *in = intro_of(pulls[i].node, 1);

			if (in)
				in->due = 1;
		}
}

/* INTRODUCE each sibling due one, through the first peer that is not one
 * and answered: asked from the sibling's own socket, so the peer sees the
 * mapping the sibling's answer must come back to; the address it says the
 * sibling said hello from used for this round and the next ten minutes,
 * and a hello sent there at once, opening this host's NAT's way to it. */
static void introduce_siblings(struct pull_target *pulls, size_t npulls_base, size_t npulls,
                               int family, uint64_t now)
{
	size_t i, k;

	for (i = npulls_base; i < npulls; i++) {
		struct pull_target *pt = &pulls[i];
		struct introduced *in = intro_of(pt->node, 0);
		uint8_t request[2u + FZN_PUBKEY_LEN], reply[160];
		char host[FZN_UDP_HOST_MAX];
		unsigned port = 0;
		size_t len = 0;

		if (!in || !in->due)
			continue;
		/* A HELLO ALREADY HEARD FROM IT, sec 624 -- a LAN probe answered,
		 * or its own hellos to this host -- needs nobody to introduce it. */
		{
			fzn_udp_addr_t at;
			uint64_t when = 0;
			char seen[FZN_UDP_HOST_MAX];
			uint16_t seen_port = 0;

			if (fzn_node_relay_where(&relay_tables, pt->node, &at, &when)
			    && when + FZND_RELAY_SEEN_S >= now
			    && fzn_udp_addr_text(&at, seen, &seen_port) == FZN_UDP_OK) {
				in->due = 0;
				(void)snprintf(in->host, sizeof(in->host), "%s", seen);
				in->port = seen_port;
				in->until = now + FZND_INTRO_S;
				(void)snprintf((char *)sibling_hosts[i - npulls_base],
				               sizeof(sibling_hosts[i - npulls_base]), "%s", seen);
				pt->port = (long)seen_port;
				pt->caller.node = at;
				(void)fzn_caller_hello(&pt->caller, pt->fd, now + 60u);
				say(FZN_ENTRY_INFO, "node/siblings", "a sibling found where it said hello, %s %u",
				    seen, (unsigned)seen_port);
				continue;
			}
		}
		for (k = 0; k < npulls_base && silent_peer(&pulls[k]); k++)
			;
		if (k == npulls_base)
			return;
		{
			fzn_caller_t via = pulls[k].caller;
			uint32_t msg = 0;

			via.fd = pt->fd;
			request[0] = FZND_INTRO_VERSION;
			request[1] = FZND_INTRODUCE_TYPE;
			memcpy(request + 2, pt->node, FZN_PUBKEY_LEN);
			if (fzn_caller_send(&via, request, sizeof(request), now + 300u, &msg)
			            != FZN_CALLER_OK
			    || fzn_caller_recv(&via, msg, reply, sizeof(reply) - 1u, &len, 3000u)
			               != FZN_CALLER_OK) {
				say(FZN_ENTRY_DEBUG, "node/siblings", "an introduction asked of %s: no answer",
				    pulls[k].host);
				continue;
			}
			pulls[k].caller.next_msg = via.next_msg;
		}
		reply[len] = '\0';
		if (sscanf((const char *)reply, "ok %45s %u", host, &port) != 2 || !port
		    || port > 65535u) {
			say(FZN_ENTRY_DEBUG, "node/siblings", "an introduction refused: %.120s",
			    (const char *)reply);
			continue;
		}
		in->due = 0;
		(void)snprintf(in->host, sizeof(in->host), "%s", host);
		in->port = (uint16_t)port;
		in->until = now + FZND_INTRO_S;
		/* THIS ROUND, at once: the target turned to the introduced
		 * address, on the same socket, and a hello there. */
		(void)snprintf((char *)sibling_hosts[i - npulls_base],
		               sizeof(sibling_hosts[i - npulls_base]), "%s", host);
		pt->port = (long)port;
		if (fzn_udp_resolve(family, host, (uint16_t)port, &pt->caller.node) == FZN_UDP_OK)
			(void)fzn_caller_hello(&pt->caller, pt->fd, now + 60u);
		say(FZN_ENTRY_INFO, "node/siblings", "a sibling introduced at %s %u", host, port);
	}
}
#endif

static void load_received(int family, const uint8_t self[FZN_PUBKEY_LEN],
                          const fzn_hash_ops_t *hash, const fzn_aead_ops_t *aead,
                          const fzn_random_ops_t *rng)
{
	static fzn_node_received_t rows[FZN_NODE_RECEIVED_MAX];
	size_t count = 0, i;

	for (i = 0; i < nshares_in; i++) {
		if (shares_in[i].pt.fd >= 0)
			fzn_udp_close(shares_in[i].pt.fd);
		fzn_wipe(&shares_in[i].pt.pairing, sizeof(shares_in[i].pt.pairing));
	}
	nshares_in = 0;
	if (!notes_on
	    || fzn_node_received_list(node_notes.store.ops, rows, FZN_NODE_RECEIVED_MAX, &count)
	               != FZN_NODE_RECEIVED_OK)
		return;
	for (i = 0; i < count; i++) {
		struct share_target *sh = &shares_in[nshares_in];
		struct pull_target *pt = &sh->pt;

		memset(sh, 0, sizeof(*sh));
		pt->fd = -1;
		memcpy(sh->host, rows[i].host, rows[i].host_len);
		sh->host[rows[i].host_len] = '\0';
		memcpy(sh->sharer, rows[i].sharer, FZN_PUBKEY_LEN);
		pt->host = sh->host;
		pt->port = rows[i].port;
		/* A ROW WITH NO PAIRING is reported and skipped: the others are
		 * still pulled. */
		if (fzn_node_pairing_load(node_notes.store.ops, rows[i].sharer, &pt->pairing)
		    != FZN_PERSIST_OK) {
			say(FZN_ENTRY_WARNING, "notes/received", "a share from %s holds no pairing", sh->host);
			continue;
		}
		if (!open_target(pt, family, self, hash, aead, rng)) {
			say(FZN_ENTRY_WARNING, "notes/received", "could not reach for a share at %s", sh->host);
			continue;
		}
		nshares_in++;
	}
}

/* Each share into its sharer's tree: `targets`, `n` of them, an accepted
 * share's (`contacts`, its sharer a contact that must stand) or a group
 * member's host (sec 630, its membership checked when it was loaded).
 * sec 437. */
/* A GROUP'S MEMBERS' HOSTS ASKED FOR THEIR SHARES, sec 630. */
#define FZND_GROUP_SHARES_MAX 32u

struct share_talk {
	fzn_node_talk_t talk;
	struct meter m;
	fzn_notes_received_t seam;
	fzn_persist_ops_t ops;
	fzn_notes_store_t tree; /* the sharer's, which its writers are admitted to */
	int wrapping, live;
	fzn_notes_pulling_t pull;
	fzn_notes_wrapping_t wraps;
	fzn_notes_sync_err_t pull_err, wraps_err;
	uint8_t request[FZN_NOTES_SYNC_PULL_REQUEST_MAX > FZN_NOTES_SYNC_WRAPS_REPLY_MAX
	                        ? FZN_NOTES_SYNC_PULL_REQUEST_MAX
	                        : FZN_NOTES_SYNC_WRAPS_REPLY_MAX];
};
#define FZND_SHARE_TALKS_MAX                                                                  \
	(FZN_NODE_RECEIVED_MAX > FZND_GROUP_SHARES_MAX ? FZN_NODE_RECEIVED_MAX : FZND_GROUP_SHARES_MAX)
_Static_assert(FZND_PULL_REPLY_MAX >= FZN_NOTES_SYNC_REPLY_MAX,
               "a notes answer fits the round's answers");
static struct share_talk share_talks[FZND_SHARE_TALKS_MAX];
static struct share_target *shares_now;
static size_t n_shares_now, shares_suspended;
static int shares_contacts, shares_begun; /* a pass to settle, begun since the last */

/* A SHARE'S PULL, then AND THEIR WRAP KEYS, sec 520: asked, never given. */
static int share_talk_step(void *ctx, const uint8_t *reply, size_t reply_len, uint8_t *request,
                           size_t cap, size_t *request_len)
{
	struct share_talk *st = ctx;
	int done = 0;

	meter_answer(&st->m, reply, reply_len);
	if (!st->wrapping) {
		st->pull_err = fzn_notes_sync_pull_step(&st->pull, reply, reply_len, request, cap,
		                                        request_len, &done);
		if (st->pull_err == FZN_NOTES_SYNC_OK && !done) {
			meter_asked(&st->m, *request_len);
			return 1;
		}
		/* WHATEVER THE PULL CAME TO, the keys: as the round in turn did. */
		st->wrapping = 1;
		done = 0;
		st->wraps_err = fzn_notes_sync_wraps_begin(&st->wraps, &st->tree, 0, request, cap,
		                                           request_len, &done);
	} else
		st->wraps_err = fzn_notes_sync_wraps_step(&st->wraps, reply, reply_len, request, cap,
		                                          request_len, &done);
	if (st->wraps_err != FZN_NOTES_SYNC_OK || done)
		return 0;
	meter_asked(&st->m, *request_len);
	return 1;
}

/* EACH SHARE INTO ITS SHARER'S TREE, every sharer at once: `targets`, `n`
 * of them, an accepted share's (`contacts`, its sharer a contact that must
 * stand) or a group member's host (sec 630, its membership checked when it
 * was loaded). sec 437. Said by `shares_settle`. */
static void shares_start(struct share_target *targets, size_t n_targets, int contacts,
                         uint64_t now)
{
	size_t i, len;
	int done;

	shares_now = targets;
	n_shares_now = 0;
	shares_suspended = 0;
	shares_contacts = contacts;
	if (!notes_on)
		return;
	shares_begun = 1;
	n_shares_now = n_targets < FZND_SHARE_TALKS_MAX ? n_targets : FZND_SHARE_TALKS_MAX;
	for (i = 0; i < n_shares_now; i++) {
		struct share_talk *st = &share_talks[i];

		st->live = 0;
		st->wrapping = 0;
		st->pull_err = st->wraps_err = FZN_NOTES_SYNC_NO_ANSWER;
		/* A REMOVED CONTACT'S SHARE IS NOT PULLED, sec 576, the holder's
		 * of 2026-10-09: what it shared stays (sec 478), and nothing new
		 * comes while it is removed. Adding it back pulls on from where it
		 * was. */
		if (contacts && running_admin
		    && !fzn_node_admin_contact_stands(running_admin, targets[i].sharer)) {
			shares_suspended++;
			continue;
		}
		if (fzn_notes_received_ops(&st->seam, node_notes.store.ops, node_notes.store.hash,
		                           targets[i].sharer, &st->ops)
		            != FZN_NOTES_OK
		    || fzn_notes_store_init(&st->tree, &st->ops, node_notes.store.hash) != FZN_NOTES_OK)
			continue;
		st->live = 1;
		len = 0;
		done = 0;
		st->pull_err = fzn_notes_sync_pull_shared_begin(&st->pull, &st->tree,
		                                                node_notes.author.sign, st->request,
		                                                sizeof(st->request), &len, &done);
		if (st->pull_err == FZN_NOTES_SYNC_OK)
			(void)talk_start_over(&st->talk, &st->m, &targets[i].pt, now, share_talk_step,
			                      round_talk_over, 0, st, st->request, sizeof(st->request),
			                      len);
	}
}

/* WHAT THE SHARES' CONVERSATIONS BROUGHT, said sharer by sharer, and their
 * texts asked -- of a sharer that answered. */
static void shares_settle(void)
{
	size_t i;

	if (!notes_on || !shares_begun)
		return;
	shares_begun = 0;
	for (i = 0; i < n_shares_now; i++) {
		struct share_talk *st = &share_talks[i];
		struct share_target *target = &shares_now[i];
		const fzn_notes_sync_tally_t *tally = &st->pull.tally;

		if (!st->live)
			continue;
		if (st->pull_err != FZN_NOTES_SYNC_OK)
			say(FZN_ENTRY_WARNING, "notes/received", "shared notes from %s: %s", target->host,
			        fzn_notes_sync_err_str(st->pull_err));
		else if (tally->learned || tally->refused)
			say(FZN_ENTRY_INFO, "notes/received", "%zu shared note record(s) from %s, %zu refused",
			        tally->learned, target->host, tally->refused);
		if (st->wraps_err != FZN_NOTES_SYNC_OK)
			say(FZN_ENTRY_WARNING, "notes/received", "shared wrap keys from %s: %s",
			        target->host, fzn_notes_sync_err_str(st->wraps_err));
#ifdef FZN_SPOOL_FILE_ON
		/* THE SHARED NOTES' TEXTS, sec 438: each blob one of them names is
		 * wanted on the shelf and asked of the sharer, which serves a
		 * contact the texts of what it shares and nothing else -- once it
		 * has answered this round: one that answered neither the pull nor
		 * the keys is not asked a third time. */
		if (shelf_on
		    && !(st->pull_err == FZN_NOTES_SYNC_NO_ANSWER
		         && st->wraps_err == FZN_NOTES_SYNC_NO_ANSWER)
		    && fzn_notes_view_load(&st->tree, node_notes.author.view) == FZN_NOTES_OK) {
			const fzn_notes_view_t *v = node_notes.author.view;
			struct peer_asking asking = { &target->pt.caller, wall_clock(), target->host };
			size_t k, got;

			for (k = 0; k < v->count; k++) {
				fzn_note_blob_ref_t ref;

				if (fzn_notes_ref_of(&v->nodes[k], &ref))
					(void)fzn_node_shelf_want(&shelf, ref.root, ref.length);
			}
			got = fzn_node_shelf_fetch_wants(&shelf, peer_ask, &asking);
			if (got)
				say(FZN_ENTRY_INFO, "notes/received", "%zu shared text(s) from %s", got,
				        target->host);
		}
#endif
	}
	/* EVERY PASS SAYS SO, at debug: a share passed over reads the same as
	 * one with nothing new, and the live check waits on this line. */
	if (shares_contacts)
		say(FZN_ENTRY_DEBUG, "notes/received", "received pass: %zu share(s), %zu of removed "
		                                       "contacts passed over", n_shares_now, shares_suspended);
	else
		say(FZN_ENTRY_DEBUG, "notes/received", "group share pass: %zu member host(s) asked",
		    n_shares_now);
}

static void pull_received(uint64_t now)
{
	shares_start(shares_in, nshares_in, 1, now);
}

/* ---- a contact's devices, sec 614 ------------------------------------------
 *
 * Every device of a contact pairs every host of this user, and the other way
 * round, with no card: each side builds its half from the other's prekey
 * record, and what crosses is the entries saying whose the keys are
 * (`node/contact_devices.h`). Each round, for each standing contact, this
 * node offers its estate's devices to one of the contact's hosts, asks it
 * for the contact's hosts and its routing manifest, and asks each member for
 * the contact devices it kept; then pairs every contact device kept, as a
 * host, and builds a pairing to every contact host kept, as a device. */

#define FZND_CONTACT_TARGETS_MAX 32u

static const fzn_node_identity_t *contact_id;
static int contact_family;
static const fzn_hash_ops_t *contact_hash_ops;
static const fzn_aead_ops_t *contact_aead_ops;
static const fzn_random_ops_t *contact_rng_ops;

/* A HOST OF A CONTACT this node delivers to: the pairing derived from its
 * prekey, the contact it is a host of, and its metric in that contact's
 * manifest -- 255 when the manifest does not list it. */
struct contact_target {
	struct pull_target pt;
	char host[FZN_CONTACT_DEVICE_ADDRESS_MAX + 1u];
	uint8_t contact[FZN_PUBKEY_LEN];
	unsigned metric;
	/* Unanswered at this round's delivery, sec 622: tried through a relay. */
	int down;
};

static struct contact_target contact_targets[FZND_CONTACT_TARGETS_MAX];
static size_t ncontact_targets;

static const uint8_t *estate_owner(void)
{
	return node_apply.root ? node_apply.root : (contact_id ? contact_id->pubkey : NULL);
}

/* THIS ESTATE'S DEVICES AS ENTRIES: every member whose prekey is kept --
 * this node among them -- with its chain from the root for the member
 * capability and its `net/address`; with `hosts` set, only those with an
 * address, and only this node unless the estate advertises (sec 611). */
static size_t estate_devices(fzn_contact_device_t *out, size_t cap, int hosts)
{
	static uint8_t keys[FZN_NODE_SIBLINGS_MAX][FZN_PUBKEY_LEN];
	const uint8_t *owner = estate_owner();
	int advertise = estate_flag(ROUTING_ADVERTISE_KEY);
	size_t n = 0, count = 0, i;

	if (!contact_id || !owner || !node_apply.store
	    || fzn_node_siblings_list(node_apply.store, keys, FZN_NODE_SIBLINGS_MAX, &n)
	               != FZN_NODE_SIBLINGS_OK)
		n = 0;
	/* THIS NODE FIRST, from its identity when no sibling store holds it. */
	for (i = 0; i <= n && count < cap; i++) {
		const uint8_t *key = i == 0 ? contact_id->pubkey : keys[i - 1u];
		fzn_contact_device_t *d = &out[count];
		fzn_setting_rank_t rank;
		char host[FZN_NODE_SETTINGS_HOST_MAX + 1u];
		uint16_t port = 0;
		size_t hop_count = 0;

		if (i > 0 && memcmp(key, contact_id->pubkey, FZN_PUBKEY_LEN) == 0)
			continue;
		if (i > 0 && (!advertise && hosts))
			break;
		memset(d, 0, sizeof(*d));
		memcpy(d->owner, owner, FZN_PUBKEY_LEN);
		if (i == 0)
			memcpy(d->record, contact_id->prekey_record, FZN_PREKEY_LEN_TOTAL);
		else if (fzn_node_apply_rank(&node_apply, key, FZN_SCOPE_HOST, key, &rank) != 1
		         || fzn_node_siblings_prekey(node_apply.store, key, d->record)
		                    != FZN_NODE_SIBLINGS_OK)
			continue;
		if (memcmp(key, owner, FZN_PUBKEY_LEN) != 0
		    && (!node_apply.capability
		        || !fzn_node_apply_chain(&node_apply, key, node_apply.capability, d->hops,
		                                 &hop_count)
		        || hop_count == 0u))
			continue;
		d->hop_count = hop_count;
		if (fzn_node_settings_address(&node_settings, key, host, &port)
		    && strlen(host) <= FZN_CONTACT_DEVICE_ADDRESS_MAX) {
			d->address_len = strlen(host);
			memcpy(d->address, host, d->address_len + 1u);
			d->port = port;
		} else if (hosts) {
			continue;
		}
		count++;
	}
	return count;
}

static fzn_contact_device_t devices_page[FZN_CONTACT_DEVICES_MAX];
static size_t devices_page_n;

static int hosts_at(void *ctx, size_t i, fzn_contact_device_t *out)
{
	(void)ctx;
	if (i == 0)
		devices_page_n = estate_devices(devices_page, FZN_CONTACT_DEVICES_MAX, 1);
	if (i >= devices_page_n)
		return 0;
	*out = devices_page[i];
	return 1;
}

static int kept_at(void *ctx, size_t i, fzn_contact_device_t *out)
{
	(void)ctx;
	if (i == 0
	    && fzn_contact_device_list(node_apply.store, devices_page, FZN_CONTACT_DEVICES_MAX,
	                               &devices_page_n)
	               != FZN_CONTACT_DEVICE_OK)
		devices_page_n = 0;
	if (i >= devices_page_n)
		return 0;
	*out = devices_page[i];
	return 1;
}

/* WHETHER `d` IS ONE TO KEEP for the contact `owner` speaks as: owned by
 * it, verifying, no key of this estate's, and kept. */
static int keep_device(const uint8_t owner[FZN_PUBKEY_LEN], const fzn_contact_device_t *d)
{
	fzn_contact_device_err_t err;

	if (!running_admin || memcmp(d->owner, owner, FZN_PUBKEY_LEN) != 0
	    || !node_apply.capability || !contact_id
	    || memcmp(fzn_contact_device_key(d), contact_id->pubkey, FZN_PUBKEY_LEN) == 0
	    || fzn_contact_device_verify(d, contact_id->sign, node_apply.capability, wall_clock())
	               != FZN_CONTACT_DEVICE_OK)
		return 0;
	err = fzn_contact_device_keep(node_apply.store, d);
	return err == FZN_CONTACT_DEVICE_OK || err == FZN_CONTACT_DEVICE_ERR_STALE;
}

/* SET WHEN A CONTACT'S DEVICE WAS KEPT while a request was being answered:
 * the loop pairs it once the answer is out. */
static int contact_pair_due;

/* AN OFFER FROM A CONTACT: kept, and paired by the loop afterwards. NOT
 * PAIRED HERE: pairing reloads the running peer set in place, and the
 * request being answered holds a pointer into it -- the reply was sealed
 * under whichever peer the reload left at that slot, measured in sec 614
 * as an offer answered under another device's session and timing out. */
static int take_offered(void *ctx, const fzn_contact_device_t *d)
{
	if (!keep_device((const uint8_t *)ctx, d))
		return 0;
	contact_pair_due = 1;
	/* AN OFFER FROM A USER THIS ONE ASKED is the answer, sec 619. */
	(void)fzn_contact_asked_answered(node_apply.store, (const uint8_t *)ctx);
	return 1;
}

/* EVERY CONTACT DEVICE KEPT whose owner stands, paired as a host pairs a
 * device; how many were new. */
static size_t pair_contact_devices(void)
{
	static fzn_contact_device_t kept[FZN_CONTACT_DEVICES_MAX];
	size_t n = 0, i, paired = 0;

	if (!running_admin || !node_apply.store
	    || fzn_contact_device_list(node_apply.store, kept, FZN_CONTACT_DEVICES_MAX, &n)
	               != FZN_CONTACT_DEVICE_OK)
		return 0;
	for (i = 0; i < n; i++) {
		const char *why = NULL;
		int r;

		if (!fzn_node_admin_contact_stands(running_admin, kept[i].owner))
			continue;
		r = fzn_node_admin_pair_contact_device(running_admin, &kept[i], &why);
		if (r > 0)
			paired++;
		else if (r < 0)
			say(FZN_ENTRY_WARNING, "contact/devices", "a contact's device was not paired: %s",
			    why ? why : "it would not pair");
	}
	return paired;
}

/* A CONTACT'S OFFER OR QUERY (`owner` the contact), or a member's query for
 * what this node kept (`owner` NULL). */
static size_t contact_devices_remote(void *ctx, const uint8_t *owner, const uint8_t *request,
                                     size_t request_len, uint8_t *reply, size_t reply_cap)
{
	size_t n;

	(void)ctx;
	if (!owner)
		return fzn_contact_devices_query_answer(request, request_len, NULL, kept_at, NULL, reply,
		                                        reply_cap);
	n = fzn_contact_devices_offer_answer(request, request_len, take_offered, (void *)owner, reply,
	                                     reply_cap);
	return n ? n
	         : fzn_contact_devices_query_answer(request, request_len, hosts_at, NULL, NULL,
	                                            reply, reply_cap);
}

/* A HOST A CONTACT NAMED: kept when it is the contact's. One with no
 * address that is the host asked is reached where it was asked. */
struct hosts_taking {
	const uint8_t *contact;
	const uint8_t *asked;
	const char *host;
	uint16_t port;
	size_t kept;
};

static void take_host(void *ctx, const fzn_contact_device_t *d)
{
	struct hosts_taking *ht = (struct hosts_taking *)ctx;
	fzn_contact_device_t filled = *d;

	if (!filled.port && ht->asked
	    && memcmp(fzn_contact_device_key(d), ht->asked, FZN_PUBKEY_LEN) == 0 && ht->host
	    && strlen(ht->host) <= FZN_CONTACT_DEVICE_ADDRESS_MAX) {
		filled.address_len = strlen(ht->host);
		memcpy(filled.address, ht->host, filled.address_len + 1u);
		filled.port = ht->port;
	}
	if (keep_device(ht->contact, &filled))
		ht->kept++;
}

/* WHAT A MEMBER KEPT: taken when its owner is a contact standing here. */
static void take_kept(void *ctx, const fzn_contact_device_t *d)
{
	size_t *kept = (size_t *)ctx;

	if (running_admin && fzn_node_admin_contact_stands(running_admin, d->owner)
	    && keep_device(d->owner, d))
		(*kept)++;
}

/* THE CONTACT HOSTS THIS NODE DELIVERS TO, rebuilt: each kept device with
 * an address whose owner stands, a pairing derived from its prekey, in
 * its contact's manifest order. */
static void load_contact_targets(void)
{
	static fzn_contact_device_t kept[FZN_CONTACT_DEVICES_MAX];
	size_t n = 0, i, j;

	for (i = 0; i < ncontact_targets; i++) {
		if (contact_targets[i].pt.fd >= 0)
			fzn_udp_close(contact_targets[i].pt.fd);
		fzn_wipe(&contact_targets[i].pt.pairing, sizeof(contact_targets[i].pt.pairing));
	}
	ncontact_targets = 0;
	if (!running_admin || !contact_id || !running_admin->state->config.has_share
	    || fzn_contact_device_list(node_apply.store, kept, FZN_CONTACT_DEVICES_MAX, &n)
	               != FZN_CONTACT_DEVICE_OK)
		return;
	for (i = 0; i < n && ncontact_targets < FZND_CONTACT_TARGETS_MAX; i++) {
		struct contact_target *ct = &contact_targets[ncontact_targets];
		fzn_routing_t r;

		if (!kept[i].port || !fzn_node_admin_contact_stands(running_admin, kept[i].owner))
			continue;
		memset(ct, 0, sizeof(*ct));
		ct->pt.fd = -1;
		memcpy(ct->host, kept[i].address, kept[i].address_len + 1u);
		memcpy(ct->contact, kept[i].owner, FZN_PUBKEY_LEN);
		ct->pt.host = ct->host;
		ct->pt.port = kept[i].port;
		ct->metric = 255u;
		if (fzn_routing_load(node_apply.store, kept[i].owner, &r) == FZN_ROUTING_OK)
			for (j = 0; j < r.n; j++)
				if (r.entries[j].port == kept[i].port
				    && r.entries[j].address_len == kept[i].address_len
				    && memcmp(r.entries[j].address, kept[i].address, kept[i].address_len)
				               == 0)
					ct->metric = r.entries[j].metric;
		if (fzn_node_pairing_derive(contact_id, kept[i].record,
		                            &running_admin->state->config.share_capability, wall_clock(),
		                            &ct->pt.pairing)
		            != FZN_NODE_PAIR_OK
		    || !open_target(&ct->pt, contact_family, contact_id->pubkey, contact_hash_ops,
		                    contact_aead_ops, contact_rng_ops))
			continue;
		ncontact_targets++;
	}
	/* BY CONTACT, THEN METRIC: insertion, a handful at most. */
	for (i = 1; i < ncontact_targets; i++)
		for (j = i; j > 0; j--) {
			struct contact_target *a = &contact_targets[j - 1u], *b = &contact_targets[j];
			int c = memcmp(a->contact, b->contact, FZN_PUBKEY_LEN);
			struct contact_target t;

			if (c < 0 || (c == 0 && a->metric <= b->metric))
				break;
			t = *a;
			*a = *b;
			*b = t;
		}
}

#define FZND_SETTLE_EVERY 3600u
/* How many lines one settle pass weighs. */
#define FZND_SETTLE_MAX 16u

/* LINES SETTLED, sec 615, each round: every contact's line this node filed
 * and has not marked settled, asked of each other member of the estate --
 * through the pull target paired to it, a member with none never answering
 * -- and marked once every one holds it or keeps none of that conversation. */
static void settle_lines(struct pull_target *pulls, size_t npulls)
{
	static uint8_t keys[FZN_NODE_SIBLINGS_MAX][FZN_PUBKEY_LEN];
	static fzn_node_messages_member_t members[FZN_NODE_SIBLINGS_MAX];
	static struct peer_asking asking[FZN_NODE_SIBLINGS_MAX];
	fzn_node_messages_settlement_t t;
	fzn_messages_err_t err;
	size_t n = 0, m = 0, i, k;

	if (!messages_on || !contact_id || !node_apply.store
	    || fzn_node_siblings_list(node_apply.store, keys, FZN_NODE_SIBLINGS_MAX, &n)
	               != FZN_NODE_SIBLINGS_OK)
		return;
	for (i = 0; i < n; i++) {
		fzn_setting_rank_t rank;

		if (memcmp(keys[i], contact_id->pubkey, FZN_PUBKEY_LEN) == 0
		    || fzn_node_apply_rank(&node_apply, keys[i], FZN_SCOPE_HOST, keys[i], &rank) != 1)
			continue;
		members[m].key = keys[i];
		members[m].ask = NULL;
		members[m].ctx = NULL;
		for (k = 0; k < npulls; k++)
			if (!silent_peer(&pulls[k])
			    && memcmp(pulls[k].pairing.node, keys[i], FZN_PUBKEY_LEN) == 0) {
				asking[m].caller = &pulls[k].caller;
				asking[m].now = wall_clock();
				asking[m].host = pulls[k].host;
				members[m].ask = peer_ask;
				members[m].ctx = &asking[m];
				break;
			}
		m++;
	}
	err = fzn_node_messages_settle(&node_messages, members, m, FZND_SETTLE_MAX, &t);
	if (err != FZN_MESSAGES_OK)
		say(FZN_ENTRY_WARNING, "messages/settle", "settling: %s", fzn_messages_err_str(err));
	else if (t.weighed)
		say(FZN_ENTRY_INFO, "messages/settle",
		    "%zu line(s) weighed over %zu member(s): %zu settled, %zu waiting", t.weighed, m,
		    t.settled, t.waiting);
}

/* WHETHER `key`, A DEVICE OF THIS USER, IS GONE, sec 616: no longer a
 * member, or heard from last longer ago than `archive/gone` (sec 601). A
 * member never heard here is not judged gone: this node cannot tell. */
static int device_gone(const uint8_t key[FZN_PUBKEY_LEN], uint64_t now_us, uint64_t gone_us)
{
	fzn_setting_rank_t rank;
	uint64_t at = 0;

	if (fzn_node_apply_rank(&node_apply, key, FZN_SCOPE_HOST, key, &rank) != 1)
		return 1;
	return fzn_heard_when(node_apply.store, key, &at) == FZN_HEARD_OK && at + gone_us < now_us;
}

/* A DEVICE'S CLAIM ON A LINE, for choosing who takes it over: the hash of
 * the line's id and the device's key, highest wins (rendezvous, as pieces
 * are placed, sec 597). */
static int claim(const uint8_t id[FZN_MESSAGE_ID_LEN], const uint8_t key[FZN_PUBKEY_LEN],
                 uint8_t out[32])
{
	uint8_t in[FZN_MESSAGE_ID_LEN + FZN_PUBKEY_LEN];

	memcpy(in, id, FZN_MESSAGE_ID_LEN);
	memcpy(in + FZN_MESSAGE_ID_LEN, key, FZN_PUBKEY_LEN);
	return contact_hash_ops && contact_hash_ops->hash(contact_hash_ops->ctx, out, 32, in, sizeof(in));
}

/* A LINE ANOTHER DEVICE WROTE, sec 616: this device sends it when its
 * writer is gone and, of the user's devices not gone, this one's claim on
 * it is the highest -- so one device takes it over, and every device that
 * judges alike picks the same one. */
static int takes_over_line(void *ctx, const uint8_t writer[FZN_PUBKEY_LEN],
                           const uint8_t id[FZN_MESSAGE_ID_LEN])
{
	static uint8_t keys[FZN_NODE_SIBLINGS_MAX][FZN_PUBKEY_LEN];
	uint64_t now_us = wall_ms() * 1000u;
	uint64_t gone_us = (uint64_t)fzn_node_settings_gone_s(&node_settings) * 1000000u;
	uint8_t mine[32], theirs[32];
	size_t n = 0, i;

	(void)ctx;
	if (!contact_id || !node_apply.store || !device_gone(writer, now_us, gone_us)
	    || !claim(id, contact_id->pubkey, mine)
	    || fzn_node_siblings_list(node_apply.store, keys, FZN_NODE_SIBLINGS_MAX, &n)
	               != FZN_NODE_SIBLINGS_OK)
		return 0;
	for (i = 0; i < n; i++) {
		if (memcmp(keys[i], contact_id->pubkey, FZN_PUBKEY_LEN) == 0
		    || memcmp(keys[i], writer, FZN_PUBKEY_LEN) == 0
		    || device_gone(keys[i], now_us, gone_us))
			continue;
		if (!claim(id, keys[i], theirs) || memcmp(theirs, mine, 32) > 0)
			return 0;
	}
	return 1;
}

/* THIS HOST'S CONTACT CARD, sec 617: its estate entry, the estate's
 * manifest's first entries as seeds, and `name` (may be empty), signed by
 * this host, encoded into `bytes` in no more than `limit` bytes -- seeds
 * dropped, last first, until it fits. 1 built; 0 when this host has no
 * estate entry, nowhere to be asked, or no card fits. */
static int own_card(fzn_contact_card_t *card, const uint8_t *name, size_t name_len, size_t limit,
                    uint8_t *bytes, size_t *len)
{
	static fzn_contact_device_t own[1];
	fzn_routing_t r;
	size_t i;

	memset(card, 0, sizeof(*card));
	if (name_len > FZN_CONTACT_CARD_NAME_MAX || !contact_id || estate_devices(own, 1u, 0) != 1u)
		return 0;
	memcpy(card->name, name, name_len);
	card->name_len = name_len;
	card->host = own[0];
	if (node_apply.store && node_apply.root
	    && fzn_routing_load(node_apply.store, node_apply.root, &r) == FZN_ROUTING_OK)
		for (i = 0; i < r.n && card->n_seeds < FZN_CONTACT_CARD_SEEDS_MAX; i++) {
			fzn_contact_card_seed_t *seed = &card->seeds[card->n_seeds++];

			memcpy(seed->address, r.entries[i].address, r.entries[i].address_len);
			seed->address[r.entries[i].address_len] = '\0';
			seed->address_len = r.entries[i].address_len;
			seed->port = r.entries[i].port;
			seed->transport = r.entries[i].transport;
			seed->metric = r.entries[i].metric;
		}
	for (;;) {
		if (fzn_contact_card_sign(card, contact_id->sign) != FZN_CONTACT_CARD_OK
		    || fzn_contact_card_encode(card, bytes, FZN_CONTACT_CARD_MAX, len)
		               != FZN_CONTACT_CARD_OK)
			return 0;
		if (*len <= limit)
			return 1;
		if (card->n_seeds == 0u)
			return 0;
		card->n_seeds--;
	}
}

/* `get card [NAME]`, sec 617: this host's contact card as text, `ok
 * FZC1:...`, fitting a reply line. 0 for any other request. */
static size_t card_local(const fzn_request_t *request, char *reply, size_t reply_cap)
{
	static fzn_contact_card_t card;
	static uint8_t bytes[FZN_CONTACT_CARD_MAX];
	static char text[FZN_CONTACT_CARD_TEXT_MAX];
	size_t len = 0, n = 0, limit;

	if (request->parsed != FZN_VERB_GET || request->arg_len < 4u
	    || memcmp(request->arg, "card", 4u) != 0
	    || (request->arg_len > 4u && request->arg[4] != ' '))
		return 0;
	if (request->arg_len > 5u) {
		n = request->arg_len - 5u;
		if (n > FZN_CONTACT_CARD_NAME_MAX
		    || !fzn_contact_name_ok((const char *)request->arg + 5, n))
			return (size_t)snprintf(reply, reply_cap, "malformed get card [NAME]\n");
	}
	/* `ok `, the prefix, five bits a character, and the newline. */
	limit = reply_cap > 4u + FZN_CONTACT_CARD_TEXT_PREFIX_LEN
	                ? (reply_cap - 4u - FZN_CONTACT_CARD_TEXT_PREFIX_LEN - 1u) * 5u / 8u
	                : 0u;
	if (!own_card(&card, request->arg + 5, n, limit, bytes, &len)
	    || fzn_contact_card_text(bytes, len, text, sizeof(text)) != FZN_CONTACT_CARD_OK)
		return (size_t)snprintf(reply, reply_cap,
		                        "error no card: this host has no address and its estate no "
		                        "manifest entry\n");
	return (size_t)snprintf(reply, reply_cap, "ok %s\n", text);
}

/* ---- contact requests, sec 619 ------------------------------------------ */

/* A REQUEST LIVES A WEEK, fuzzypickles' default; at most this many boxes
 * are opened a minute, since any stranger may send one and each costs an
 * agreement and several signatures. */
#define FZND_REQUEST_LIFE_S (7u * 86400u)
#define FZND_BOXES_A_MINUTE 32u

static int asked_due;

static void hex_of(const uint8_t *b, size_t n, char *out)
{
	static const char H[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < n; i++) {
		out[2u * i] = H[b[i] >> 4];
		out[2u * i + 1u] = H[b[i] & 15u];
	}
	out[2u * n] = '\0';
}

/* Whether `key` is this estate's: this host, its root, or a member. */
static int ours(const uint8_t key[FZN_PUBKEY_LEN])
{
	fzn_setting_rank_t rank;

	return (contact_id && memcmp(key, contact_id->pubkey, FZN_PUBKEY_LEN) == 0)
	       || (node_apply.root && memcmp(key, node_apply.root, FZN_PUBKEY_LEN) == 0)
	       || fzn_node_apply_rank(&node_apply, key, FZN_SCOPE_HOST, key, &rank) == 1;
}

/* A BOX A STRANGER SENT, sec 619: opened, read as a contact request to
 * this host, checked, and queued for this user to approve -- or, from a
 * contact already standing, its card's host kept as that contact's
 * device. Anything else is dropped without a word. */
static void contact_box(void *ctx, const uint8_t *box, size_t len)
{
	static uint64_t window, opened;
	static uint8_t plain[FZN_UDP_DATAGRAM_MAX];
	static fzn_contact_request_t r;
	uint64_t now = wall_clock();
	size_t n = 0;
	char hex[2u * FZN_PUBKEY_LEN + 1u];
	fzn_contact_request_err_t err;

	(void)ctx;
	if (!contact_id || !running_admin || !node_apply.store || !node_apply.capability)
		return;
	if (now >= window + 60u || window > now) {
		window = now;
		opened = 0;
	}
	if (opened >= FZND_BOXES_A_MINUTE)
		return;
	opened++;
	if (fzn_box_open(contact_id->agree_secret, contact_id->agree, contact_id->hash,
	                 contact_aead_ops, box, len, plain, sizeof(plain), &n)
	            != FZN_BOX_OK
	    || fzn_contact_request_decode(plain, n, &r) != FZN_CONTACT_REQUEST_OK)
		return;
	err = fzn_contact_request_verify(&r, contact_id->sign, node_apply.capability,
	                                 contact_id->pubkey, now);
	if (err != FZN_CONTACT_REQUEST_OK) {
		say(FZN_ENTRY_DEBUG, "contact/request", "a contact request refused: %s",
		    fzn_contact_request_err_str(err));
		return;
	}
	if (ours(r.card.host.owner))
		return;
	hex_of(r.card.host.owner, FZN_PUBKEY_LEN, hex);
	if (fzn_node_admin_contact_stands(running_admin, r.card.host.owner)) {
		if (keep_device(r.card.host.owner, &r.card.host))
			contact_pair_due = 1;
		return;
	}
	if (fzn_contact_request_keep(node_apply.store, &r, now) != FZN_CONTACT_REQUEST_OK) {
		say(FZN_ENTRY_WARNING, "contact/request", "a contact request could not be kept");
		return;
	}
	say(FZN_ENTRY_INFO, "contact/request", "a contact request from %.16s, waiting", hex);
	publish("request", hex);
}

/* EVERY REQUEST THIS USER SENT AND NOT YET ANSWERED, sent again: sealed
 * afresh to the asked host's prekey and sent to its address and every
 * seed. Each round, and at once after one is made. */
static void send_asked(void)
{
	static int fd = -1;
	static fzn_contact_asked_t asked[FZN_CONTACT_ASKED_MAX];
	static uint8_t bytes[FZN_CONTACT_REQUEST_MAX], box[FZN_UDP_DATAGRAM_MAX];
	size_t n = 0, i, k, len = 0, box_len = 0, sent = 0;
	uint64_t now = wall_clock();

	if (!contact_id || !node_apply.store || !contact_rng_ops
	    || fzn_contact_asked_list(node_apply.store, asked, FZN_CONTACT_ASKED_MAX, &n)
	               != FZN_CONTACT_REQUEST_OK)
		return;
	for (i = 0; i < n; i++) {
		const fzn_contact_card_t *c = &asked[i].card;

		if (asked[i].answered || asked[i].request.expires_at < now
		    || fzn_contact_request_encode(&asked[i].request, bytes, sizeof(bytes), &len)
		               != FZN_CONTACT_REQUEST_OK
		    || fzn_box_seal(contact_id->agree, contact_id->hash, contact_aead_ops,
		                    contact_rng_ops, c->host.record + FZN_PREKEY_OFF_PREKEY, bytes, len,
		                    box, sizeof(box), &box_len)
		               != FZN_BOX_OK)
			continue;
		if (fd < 0 && fzn_udp_bind(contact_family, NULL, 0, &fd) != FZN_UDP_OK) {
			fd = -1;
			return;
		}
		for (k = 0; k <= c->n_seeds; k++) {
			const char *host = k == 0 ? c->host.address : c->seeds[k - 1u].address;
			uint16_t port = k == 0 ? c->host.port : c->seeds[k - 1u].port;
			fzn_udp_addr_t to;

			if (port && fzn_udp_resolve(contact_family, host, port, &to) == FZN_UDP_OK
			    && fzn_udp_send(fd, &to, box, box_len) == FZN_UDP_OK)
				sent++;
		}
	}
	if (sent)
		say(FZN_ENTRY_DEBUG, "contact/request", "%zu contact request datagram(s) sent", sent);
}

/* The next word of `*at`, `*left` bytes left. */
static int next_word(const uint8_t **at, size_t *left, const uint8_t **w, size_t *w_len)
{
	while (*left && **at == ' ') {
		(*at)++;
		(*left)--;
	}
	*w = *at;
	while (*left && **at != ' ') {
		(*at)++;
		(*left)--;
	}
	*w_len = (size_t)(*at - *w);
	return *w_len > 0u;
}

static int unhex32(const uint8_t *w, size_t n, uint8_t out[FZN_PUBKEY_LEN])
{
	char hex[2u * FZN_PUBKEY_LEN + 1u];

	if (n != 2u * FZN_PUBKEY_LEN)
		return 0;
	memcpy(hex, w, n);
	hex[n] = '\0';
	return hex_bytes(hex, out, FZN_PUBKEY_LEN);
}

/* `add contact NAME CARD` -- a card as text, or a path to a file holding
 * it -- asks the user it names for contact: the card checked, its root
 * added as NAME and its host kept, and a request carrying this host's card
 * sent until that user's first offer answers it. */
static size_t request_contact(const uint8_t *name, size_t name_len, const uint8_t *arg,
                              size_t arg_len, char *reply, size_t cap)
{
	static char text[FZN_CONTACT_CARD_TEXT_MAX + 1u];
	static uint8_t bytes[FZN_CONTACT_CARD_MAX], own_bytes[FZN_CONTACT_CARD_MAX];
	static fzn_contact_card_t card;
	static fzn_contact_asked_t a;
	char hex[2u * FZN_PUBKEY_LEN + 1u];
	const char *why = NULL;
	size_t len = 0, text_len, own_len = 0;
	uint64_t now = wall_clock();

	if (arg_len >= 5u && memcmp(arg, FZN_CONTACT_CARD_TEXT_PREFIX, 5u) == 0) {
		if (arg_len > FZN_CONTACT_CARD_TEXT_MAX)
			return (size_t)snprintf(reply, cap, "malformed not a contact card\n");
		memcpy(text, arg, arg_len);
		text_len = arg_len;
	} else {
		char path[1024];
		FILE *f;

		if (arg_len >= sizeof(path))
			return (size_t)snprintf(reply, cap, "malformed add contact NAME CARD|PATH\n");
		memcpy(path, arg, arg_len);
		path[arg_len] = '\0';
		/* AN ABSOLUTE PATH ONLY, sec 662: a relative one is read in the daemon's
		 * working directory, which no client sees. */
		if (path[0] != '/')
			return (size_t)snprintf(reply, cap, "malformed the card's path is absolute\n");
		if ((f = fopen(path, "r")) == NULL)
			return (size_t)snprintf(reply, cap, "error the card file would not open\n");
		text_len = fread(text, 1, sizeof(text) - 1u, f);
		fclose(f);
		while (text_len && (text[text_len - 1u] == '\n' || text[text_len - 1u] == '\r'))
			text_len--;
	}
	if (fzn_contact_card_from_text(text, text_len, bytes, sizeof(bytes), &len)
	            != FZN_CONTACT_CARD_OK
	    || fzn_contact_card_decode(bytes, len, &card) != FZN_CONTACT_CARD_OK)
		return (size_t)snprintf(reply, cap, "malformed not a contact card\n");
	if (!contact_id || !node_apply.capability
	    || fzn_contact_card_verify(&card, contact_id->sign, node_apply.capability, now)
	               != FZN_CONTACT_CARD_OK)
		return (size_t)snprintf(reply, cap, "error the card does not hold\n");
	if (ours(card.host.owner) || ours(fzn_contact_device_key(&card.host)))
		return (size_t)snprintf(reply, cap, "error that card is this estate's own\n");
	switch (fzn_node_admin_contact_add(running_admin, card.host.owner, (const char *)name,
	                                   name_len, &why)) {
	case 0:
		break;
	case -2:
		return (size_t)snprintf(reply, cap, "malformed %s\n", why ? why : "a contact name");
	case -3:
		return (size_t)snprintf(reply, cap, "denied %s\n", why ? why : "no standing");
	default:
		return (size_t)snprintf(reply, cap, "error %s\n", why ? why : "not added");
	}
	(void)keep_device(card.host.owner, &card.host);
	/* THE REQUEST, carrying this host's card; small enough, with its box,
	 * for one datagram. */
	memset(&a, 0, sizeof(a));
	a.card = card;
	if (!own_card(&a.request.card, NULL, 0, FZN_UDP_DATAGRAM_MAX - FZN_BOX_OVERHEAD - 124u,
	              own_bytes, &own_len))
		return (size_t)snprintf(reply, cap,
		                        "error added, and no request sent: this host has no card\n");
	memcpy(a.request.target, fzn_contact_device_key(&card.host), FZN_PUBKEY_LEN);
	if (!contact_rng_ops->fill(contact_rng_ops->ctx, a.request.nonce, sizeof(a.request.nonce)))
		return (size_t)snprintf(reply, cap, "error added, and no request sent\n");
	a.request.expires_at = now + FZND_REQUEST_LIFE_S;
	if (fzn_contact_request_sign(&a.request, contact_id->sign) != FZN_CONTACT_REQUEST_OK
	    || fzn_contact_asked_keep(node_apply.store, &a) != FZN_CONTACT_REQUEST_OK)
		return (size_t)snprintf(reply, cap, "error added, and no request kept\n");
	contact_pair_due = 1;
	asked_due = 1;
	hex_of(card.host.owner, FZN_PUBKEY_LEN, hex);
	return (size_t)snprintf(reply, cap, "ok %s\n", hex);
}

/* THE REQUEST VERBS, sec 619, this node's own user only:
 *
 *   add contact NAME CARD|PATH   ask for contact by a card (`FZC1:...`)
 *   list request                 `ok COUNT ROOT,NAME,RECEIVED ...`, oldest first
 *   grant request ROOT NAME      approve: ROOT added as NAME, its host kept
 *   remove request ROOT          reject
 *
 * `add contact NAME KEY` is admin's, as before; 0 for anything not these. */
static size_t request_local(fzn_origin_t origin, const fzn_request_t *request, char *reply,
                            size_t cap)
{
	static fzn_contact_request_held_t held[FZN_CONTACT_REQUESTS_MAX];
	const uint8_t *at = request->arg, *subject, *a1 = NULL, *a2 = NULL;
	size_t left = request->arg_len, subject_len, n1 = 0, n2 = 0, n = 0, i, k;
	uint8_t root[FZN_PUBKEY_LEN];
	int card;

	if (!at || !next_word(&at, &left, &subject, &subject_len))
		return 0;
	(void)next_word(&at, &left, &a1, &n1);
	(void)next_word(&at, &left, &a2, &n2);
	card = request->parsed == FZN_VERB_ADD && subject_len == 7u
	       && memcmp(subject, "contact", 7u) == 0 && n2 > 0u
	       && !(n2 == 2u * FZN_PUBKEY_LEN && unhex32(a2, n2, root));
	if (!card
	    && !(subject_len == 7u && memcmp(subject, "request", 7u) == 0
	         && (request->parsed == FZN_VERB_LIST || request->parsed == FZN_VERB_GRANT
	             || request->parsed == FZN_VERB_REMOVE)))
		return 0;
	if (origin != FZN_ORIGIN_SAME_USER)
		return (size_t)snprintf(reply, cap, "denied contact requests need this node's own "
		                                    "user\n");
	if (!running_admin || !node_apply.store)
		return (size_t)snprintf(reply, cap, "error this node keeps no contacts\n");
	if (card)
		return request_contact(a1, n1, a2, n2, reply, cap);
	if (request->parsed == FZN_VERB_LIST) {
		size_t at_out;

		if (fzn_contact_request_list(node_apply.store, held, FZN_CONTACT_REQUESTS_MAX, &n)
		    != FZN_CONTACT_REQUEST_OK)
			return (size_t)snprintf(reply, cap, "error the requests would not list\n");
		at_out = (size_t)snprintf(reply, cap, "ok %zu", n);
		for (i = 0; i < n && at_out < cap; i++) {
			char hex[2u * FZN_PUBKEY_LEN + 1u];
			const fzn_contact_card_t *c = &held[i].request.card;

			hex_of(c->host.owner, FZN_PUBKEY_LEN, hex);
			k = (size_t)snprintf(reply + at_out, cap - at_out, " %s,%.*s,%llu", hex,
			                     c->name_len ? (int)c->name_len : 1,
			                     c->name_len ? c->name : "-",
			                     (unsigned long long)held[i].received_at);
			if (at_out + k >= cap)
				break;
			at_out += k;
		}
		return at_out + (size_t)snprintf(reply + at_out, cap - at_out, "\n");
	}
	if (!a1 || !unhex32(a1, n1, root))
		return (size_t)snprintf(reply, cap, request->parsed == FZN_VERB_GRANT
		                                            ? "malformed grant request ROOT NAME\n"
		                                            : "malformed remove request ROOT\n");
	if (request->parsed == FZN_VERB_REMOVE)
		return fzn_contact_request_drop(node_apply.store, root) == FZN_CONTACT_REQUEST_OK
		               ? (size_t)snprintf(reply, cap, "ok\n")
		               : (size_t)snprintf(reply, cap, "error no request from that root\n");
	{
		static fzn_contact_request_held_t one;
		const char *why = NULL;

		if (!a2)
			return (size_t)snprintf(reply, cap, "malformed grant request ROOT NAME\n");
		if (fzn_contact_request_get(node_apply.store, root, &one) != FZN_CONTACT_REQUEST_OK)
			return (size_t)snprintf(reply, cap, "error no request from that root\n");
		switch (fzn_node_admin_contact_add(running_admin, root, (const char *)a2, n2, &why)) {
		case 0:
			break;
		case -2:
			return (size_t)snprintf(reply, cap, "malformed %s\n", why ? why : "a contact name");
		case -3:
			return (size_t)snprintf(reply, cap, "denied %s\n", why ? why : "no standing");
		default:
			return (size_t)snprintf(reply, cap, "error %s\n", why ? why : "not added");
		}
		(void)keep_device(root, &one.request.card.host);
		(void)fzn_contact_request_drop(node_apply.store, root);
		contact_pair_due = 1;
		return (size_t)snprintf(reply, cap, "ok\n");
	}
}

/* ---- identity backup and reset, sec 620 ------------------------------------ */

/* WHERE THIS NODE'S STATE IS: the core directory, and the bulk store's when
 * it is another (`--fuzznet-store`). */
static const char *state_core_dir, *state_bulk_dir;
/* SET BY A RESET: the loop wipes once more and stops. */
static int identity_reset;

/* ---- an estate joined at runtime, sec 638 ---------------------------------
 *
 * `add join CARD|PATH HOST PORT` does what `fuzznetd --accept=CARD --join` does
 * -- this device joins the estate whose root signed CARD, its anchor
 * pinned to that root -- keeps where the root is reached, answers, and
 * then starts again in place: its sockets closed and the same program
 * executed with the same arguments, so the boot that follows comes up
 * joined, pulling from the root it kept, with no second writer on the
 * store and nothing for its client to do but connect again. Re-reading
 * every store a join changes inside the running daemon was the
 * alternative, and every one keyed by the root is. */
static struct {
	const fzn_node_identity_t *id;
	fzn_trust_t *trust;
	const fzn_persist_ops_t *store;
} joining;
/* SET BY A JOIN: the loop starts the daemon again. */
static int rejoin_due;
static char **daemon_argv;

static size_t join_local(fzn_origin_t origin, const fzn_request_t *request, char *reply,
                         size_t cap)
{
	const uint8_t *at = request->arg, *subject, *w_card = NULL, *w_host = NULL, *w_port = NULL;
	size_t left = request->arg_len, subject_len, n_card = 0, n_host = 0, n_port = 0;
	uint8_t card[FZN_PROVISION_MAX_LEN];
	char text[FZN_PROVISION_TEXT_MAX_LEN], where[FZN_UDP_HOST_MAX + 8u];
	fzn_node_pairing_t paired;
	fzn_node_pair_err_t perr;
	size_t card_len = 0, i;
	unsigned long port = 0;
	int k;

	if (request->parsed != FZN_VERB_ADD || !at || !next_word(&at, &left, &subject, &subject_len)
	    || subject_len != 4u || memcmp(subject, "join", 4u) != 0)
		return 0;
	if (origin != FZN_ORIGIN_SAME_USER)
		return (size_t)snprintf(reply, cap, "denied joining an estate is this node's own "
		                                    "user's\n");
	if (!joining.id || !joining.trust || !joining.store)
		return (size_t)snprintf(reply, cap, "error this node keeps no state to join with\n");
	if (!next_word(&at, &left, &w_card, &n_card) || !next_word(&at, &left, &w_host, &n_host)
	    || !next_word(&at, &left, &w_port, &n_port) || left || n_card >= sizeof(text)
	    || n_host >= FZN_UDP_HOST_MAX || n_port > 5u)
		return (size_t)snprintf(reply, cap, "malformed add join CARD|PATH HOST PORT\n");
	for (i = 0; i < n_port; i++) {
		if (w_port[i] < '0' || w_port[i] > '9')
			return (size_t)snprintf(reply, cap, "malformed add join CARD HOST PORT\n");
		port = port * 10u + (unsigned long)(w_port[i] - '0');
	}
	if (port == 0u || port > 65535u)
		return (size_t)snprintf(reply, cap, "malformed the port is 1 to 65535\n");
	/* THE CARD ITSELF, or A FILE HOLDING IT: a card is longer than a request
	 * line's 512 bytes, as `add contact`'s is. */
	if (n_card >= FZN_PROVISION_TEXT_PREFIX_LEN
	    && memcmp(w_card, FZN_PROVISION_TEXT_PREFIX, FZN_PROVISION_TEXT_PREFIX_LEN) == 0) {
		memcpy(text, w_card, n_card);
		text[n_card] = '\0';
	} else {
		char path[1024];
		size_t got;
		FILE *f;

		if (n_card >= sizeof(path))
			return (size_t)snprintf(reply, cap, "malformed add join CARD|PATH HOST PORT\n");
		memcpy(path, w_card, n_card);
		path[n_card] = '\0';
		/* AN ABSOLUTE PATH ONLY, sec 662. */
		if (path[0] != '/')
			return (size_t)snprintf(reply, cap, "malformed the card's path is absolute\n");
		if ((f = fopen(path, "r")) == NULL)
			return (size_t)snprintf(reply, cap, "error the card file would not open\n");
		got = fread(text, 1, sizeof(text) - 1u, f);
		fclose(f);
		while (got && (text[got - 1u] == '\n' || text[got - 1u] == '\r'))
			got--;
		text[got] = '\0';
	}
	if (fzn_provision_from_text(text, card, sizeof(card), &card_len) != FZN_PROVISION_OK)
		return (size_t)snprintf(reply, cap, "malformed that is not a card\n");
	perr = fzn_node_join(joining.id, card, card_len, wall_clock(), joining.store, joining.trust,
	                     &paired);
	fzn_wipe(&paired, sizeof(paired));
	if (perr != FZN_NODE_PAIR_OK)
		return (size_t)snprintf(reply, cap, "error not joined: %s\n",
		                        fzn_node_pair_err_str(perr));
	/* WHERE THE ROOT IS, kept under its key: what a start with no
	 * `--root-at` pulls from. */
	k = snprintf(where, sizeof(where), "%.*s %lu", (int)n_host, (const char *)w_host, port);
	if (k <= 0 || (size_t)k >= sizeof(where)
	    || !joining.store->save(joining.store->ctx, FZN_PERSIST_ROOT_AT,
	                            fzn_trust_root(joining.trust), (const uint8_t *)where, (size_t)k))
		return (size_t)snprintf(reply, cap, "error joined, and where the root is reached "
		                                    "was not kept: start with --root-at\n");
	rejoin_due = 1;
	say(FZN_ENTRY_NOTE, "node/identity", "joined the estate rooted at %02x%02x%02x%02x, "
	                                     "reached at %s; starting again",
	    fzn_trust_root(joining.trust)[0], fzn_trust_root(joining.trust)[1],
	    fzn_trust_root(joining.trust)[2], fzn_trust_root(joining.trust)[3], where);
	k = snprintf(reply, cap, "ok ");
	for (i = 0; i < FZN_PUBKEY_LEN && (size_t)k + 2u < cap; i++)
		k += snprintf(reply + k, cap - (size_t)k, "%02x", fzn_trust_root(joining.trust)[i]);
	return (size_t)k + (size_t)snprintf(reply + k, cap - (size_t)k, "\n");
}

/* `set admin CHAIN|PATH`, sec 658: the admin chain `grant admin` answered
 * on the granting node -- its hops as hex, `h` before each as that answer
 * writes them, or a file holding them, the chain being longer than a
 * request line -- kept here as `fuzznetd --set-admin` keeps it, judged
 * against the running revocations, and then the daemon starts again in
 * place, as a join does, so the boot that follows acts with it. The
 * holder's choice for an estate made and joined, verbs on a running
 * daemon (sec 638), reaching the one grant that still wanted a command. */
static size_t admin_chain_local(fzn_origin_t origin, const fzn_request_t *request, char *reply,
                                size_t cap)
{
	static uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	static fzn_node_admin_chain_t kept;
	static char text[4096];
	const uint8_t *at = request->arg, *subject, *w;
	size_t left = request->arg_len, subject_len, w_len, n = 0, len;
	fzn_node_revoke_err_t rerr;
	const char *p;

	if (request->parsed != FZN_VERB_SET || !at || !next_word(&at, &left, &subject, &subject_len)
	    || subject_len != 5u || memcmp(subject, "admin", 5u) != 0)
		return 0;
	if (origin != FZN_ORIGIN_SAME_USER)
		return (size_t)snprintf(reply, cap, "denied an admin chain is this node's own user's\n");
	if (!running_admin || !running_admin->state || !running_admin->state->config.has_admin
	    || !joining.id || !joining.store)
		return (size_t)snprintf(reply, cap, "error this node keeps no admin capability\n");
	if (!next_word(&at, &left, &w, &w_len))
		return (size_t)snprintf(reply, cap, "malformed set admin CHAIN|PATH\n");
	/* THE CHAIN, or A FILE HOLDING IT: a hex hop or an `h` begins a chain,
	 * anything else names a file. The rest of the line is the chain. */
	len = (size_t)(request->arg + request->arg_len - w);
	if (w[0] == 'h' || (w[0] >= '0' && w[0] <= '9') || (w[0] >= 'a' && w[0] <= 'f')
	    || (w[0] >= 'A' && w[0] <= 'F')) {
		if (len >= sizeof(text))
			return (size_t)snprintf(reply, cap, "malformed a chain too long\n");
		memcpy(text, w, len);
		text[len] = '\0';
	} else {
		char path[1024];
		FILE *f;
		size_t got;

		if (w_len >= sizeof(path) || left)
			return (size_t)snprintf(reply, cap, "malformed set admin CHAIN|PATH\n");
		memcpy(path, w, w_len);
		path[w_len] = '\0';
		if (path[0] != '/')
			return (size_t)snprintf(reply, cap, "malformed the path is absolute\n");
		f = fopen(path, "rb");
		if (!f)
			return (size_t)snprintf(reply, cap, "error the chain's file would not open\n");
		got = fread(text, 1u, sizeof(text) - 1u, f);
		(void)fclose(f);
		text[got] = '\0';
	}
	for (p = text; *p;) {
		char item[(FZN_HOP_LEN * 2u) + 1u];

		while (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t')
			p++;
		if (!*p)
			break;
		if (*p == 'h')
			p++;
		if (n >= FZN_CHAIN_MAX_HOPS - 1u || strlen(p) < FZN_HOP_LEN * 2u)
			return (size_t)snprintf(reply, cap, "malformed not a chain of hops\n");
		memcpy(item, p, FZN_HOP_LEN * 2u);
		item[FZN_HOP_LEN * 2u] = '\0';
		if (!hex_bytes(item, hops[n], FZN_HOP_LEN))
			return (size_t)snprintf(reply, cap, "malformed not a chain of hops\n");
		n++;
		p += FZN_HOP_LEN * 2u;
	}
	if (!n)
		return (size_t)snprintf(reply, cap, "malformed not a chain of hops\n");
	rerr = fzn_node_admin_chain_set(joining.store, running_admin->revocations, joining.id,
	                                running_admin->state->config.root,
	                                &running_admin->state->config.admin_capability,
	                                (const uint8_t (*)[FZN_HOP_LEN])hops, n, wall_clock(), &kept);
	if (rerr != FZN_NODE_REVOKE_OK)
		return (size_t)snprintf(reply, cap, "error %s\n", fzn_node_revoke_err_str(rerr));
	say(FZN_ENTRY_INFO, "node/admin", "an admin chain of %zu hop(s) kept; starting again", n);
	rejoin_due = 1;
	return (size_t)snprintf(reply, cap, "ok %zu\n", n);
}

/* STARTED AGAIN IN PLACE after a join: every descriptor past the standard
 * three closed -- the sockets, so the new start can bind them again -- and
 * this program executed with its own arguments. Returns only when it could
 * not be, having said so. */
static int start_again(int lfd, const char *sock_path)
{
	long fd, max = sysconf(_SC_OPEN_MAX);

	fzn_socket_close(lfd, sock_path);
	if (max < 0 || max > 65536)
		max = 65536;
	for (fd = 3; fd < max; fd++)
		(void)close((int)fd);
	if (daemon_argv) {
		execv("/proc/self/exe", daemon_argv);
		execvp(daemon_argv[0], daemon_argv);
	}
	fprintf(stderr, "fuzznetd: joined, and could not start again: start it once more\n");
	return 1;
}

/* `put backup DIR` and `remove identity KEY`, this node's own user only:
 *
 *   put backup DIR         every file of this node's state copied into DIR,
 *                          an empty directory of this user's at mode 0700;
 *                          with a bulk store apart, the core goes in
 *                          DIR/fuzznet-dir and the store in
 *                          DIR/fuzznet-store. `ok FILES`. Restoring is
 *                          copying them back; there is no format.
 *   remove identity KEY    KEY must be this node's own key: every file of
 *                          its state wiped, and the node stops. `ok FILES`.
 *
 * 0 for anything else. */
static size_t identity_local(fzn_origin_t origin, const fzn_request_t *request, char *reply,
                             size_t cap)
{
	const uint8_t *at = request->arg, *subject, *a1 = NULL;
	size_t left = request->arg_len, subject_len, n1 = 0, copied = 0, more = 0;
	const char *why = NULL;
	char path[1024];
	int backup;

	if (!at || !next_word(&at, &left, &subject, &subject_len))
		return 0;
	/* `get identity`, sec 648: `ok HOST ROOT` -- this host's key and its
	 * user's, the root a group lists it under, which `get prekey`'s host
	 * key is only for a user of one host. */
	if (request->parsed == FZN_VERB_GET && subject_len == 8u
	    && memcmp(subject, "identity", 8u) == 0) {
		char host[FZN_PUBKEY_LEN * 2u + 1u], root[FZN_PUBKEY_LEN * 2u + 1u];

		if (origin != FZN_ORIGIN_SAME_USER)
			return (size_t)snprintf(reply, cap,
			                        "denied this node's identity is its own user's\n");
		if (!contact_id || !estate_owner())
			return (size_t)snprintf(reply, cap, "error this node has no identity yet\n");
		hex_of(contact_id->pubkey, FZN_PUBKEY_LEN, host);
		hex_of(estate_owner(), FZN_PUBKEY_LEN, root);
		return (size_t)snprintf(reply, cap, "ok %s %s\n", host, root);
	}
	backup = request->parsed == FZN_VERB_PUT && subject_len == 6u
	         && memcmp(subject, "backup", 6u) == 0;
	if (!backup
	    && !(request->parsed == FZN_VERB_REMOVE && subject_len == 8u
	         && memcmp(subject, "identity", 8u) == 0))
		return 0;
	if (origin != FZN_ORIGIN_SAME_USER)
		return (size_t)snprintf(reply, cap, "denied this node's identity is its own user's\n");
	if (!state_core_dir)
		return (size_t)snprintf(reply, cap, "error this node keeps no state directory\n");
	(void)next_word(&at, &left, &a1, &n1);
	if (!a1 || n1 >= sizeof(path))
		return (size_t)snprintf(reply, cap, backup ? "malformed put backup DIR\n"
		                                           : "malformed remove identity KEY\n");
	memcpy(path, a1, n1);
	path[n1] = '\0';
	if (backup) {
		char core[1100], bulk[1100];

		/* AN ABSOLUTE PATH ONLY, sec 662: a backup holds the identity's seed,
		 * and a relative one would land where the daemon was started. */
		if (path[0] != '/')
			return (size_t)snprintf(reply, cap, "malformed put backup DIR, DIR absolute\n");
		if (!fzn_state_dir_backup_ok(path, &why))
			return (size_t)snprintf(reply, cap, "error %s\n", why);
		if (!state_bulk_dir) {
			if (!fzn_state_dir_copy(state_core_dir, path, &copied, &why))
				return (size_t)snprintf(reply, cap, "error the backup is partial: %s\n",
				                        why);
			return (size_t)snprintf(reply, cap, "ok %zu\n", copied);
		}
		(void)snprintf(core, sizeof(core), "%s/fuzznet-dir", path);
		(void)snprintf(bulk, sizeof(bulk), "%s/fuzznet-store", path);
		if (mkdir(core, 0700) != 0 || mkdir(bulk, 0700) != 0
		    || !fzn_state_dir_copy(state_core_dir, core, &copied, &why)
		    || !fzn_state_dir_copy(state_bulk_dir, bulk, &more, &why))
			return (size_t)snprintf(reply, cap, "error the backup is partial: %s\n",
			                        why ? why : "a directory would not be made");
		return (size_t)snprintf(reply, cap, "ok %zu\n", copied + more);
	}
	{
		uint8_t key[FZN_PUBKEY_LEN];

		/* THE IDENTITY NAMED, and no other: fuzzypickles' rule, so a reset
		 * meant for one node cannot discard another's. */
		if (!contact_id || !unhex32(a1, n1, key)
		    || memcmp(key, contact_id->pubkey, FZN_PUBKEY_LEN) != 0)
			return (size_t)snprintf(reply, cap,
			                        "denied that is not this node's identity\n");
		if (!fzn_state_dir_wipe(state_core_dir, &copied, &why)
		    || (state_bulk_dir && !fzn_state_dir_wipe(state_bulk_dir, &more, &why)))
			return (size_t)snprintf(reply, cap, "error the wipe stopped short: %s\n", why);
		identity_reset = 1;
		say(FZN_ENTRY_WARNING, "node/identity",
		    "this node's identity reset: %zu file(s) of its state wiped, and it stops",
		    copied + more);
		return (size_t)snprintf(reply, cap, "ok %zu\n", copied + more);
	}
}

/* ---- the address this host is seen at, sec 621 ---------------------------- */

/* WHAT EACH PEER SAW, kept in memory: advisory, as fuzzypickles keeps it --
 * a host behind a NAT that maps per destination is seen at a different
 * port by each, and saying so is the point of keeping several. */
#define FZND_OBSERVED_MAX 32u

static struct observed {
	uint8_t reporter[FZN_PUBKEY_LEN];
	char host[FZN_UDP_HOST_MAX];
	uint16_t port;
	uint64_t at;
} observed[FZND_OBSERVED_MAX];
static size_t n_observed;
static int address_due;
/* THE ROUND'S PULL TARGETS, `main`'s, so a verb can count what a round
 * would ask. */
static struct pull_target *loop_pulls;
static const size_t *loop_npulls;

/* ONE PEER ASKED where it sees this host; the answer kept, replacing that
 * peer's earlier one. */
/* A `get address` ANSWER from `pt`: where it sees this host, kept. */
static void address_take(const struct pull_target *pt, const uint8_t *reply, size_t reply_len,
                         uint64_t now)
{
	char text[128], host[FZN_UDP_HOST_MAX];
	size_t i;
	unsigned port = 0;
	int used = 0;

	if (reply_len >= sizeof(text))
		return;
	memcpy(text, reply, reply_len);
	text[reply_len] = '\0';
	if (sscanf(text, "ok %45s %u%n", host, &port, &used) != 2 || port == 0u || port > 65535u)
		return;
	for (i = 0; i < n_observed; i++)
		if (memcmp(observed[i].reporter, pt->pairing.node, FZN_PUBKEY_LEN) == 0)
			break;
	if (i == n_observed) {
		if (n_observed == FZND_OBSERVED_MAX)
			return;
		n_observed++;
	}
	memcpy(observed[i].reporter, pt->pairing.node, FZN_PUBKEY_LEN);
	memcpy(observed[i].host, host, sizeof(host));
	observed[i].port = (uint16_t)port;
	observed[i].at = now;
}

/* EVERY PEER THIS HOST REACHES asked: the estate's pull peers and
 * siblings, and every contact host. Asked when the user asks (`fetch
 * address`), not each round: fuzzypickles' "asking is a button". */
/* `fetch address` asks every peer where it sees this host, at once;
 * `get address` answers what they said, `ok COUNT AGREE
 * REPORTER,HOST,PORT,AT ...` -- AGREE 1 when every one saw the same, 0 when
 * they differ, which is a NAT mapping each destination apart. Advertising
 * one is `set setting host net/address HOST PORT`, the user's act. 0 for
 * any other request. */
/* AN ADDRESS OF THE LOCAL NETWORK'S, by its text: IPv4's private ranges,
 * link-local and loopback, IPv6's unique-local, link-local and loopback.
 * sec 659. */
static int local_scope(const char *host)
{
	unsigned a = 0, b = 0;

	if (sscanf(host, "%u.%u.", &a, &b) == 2)
		return a == 10u || a == 127u || (a == 192u && b == 168u) || (a == 169u && b == 254u)
		       || (a == 172u && b >= 16u && b <= 31u);
	/* inet_ntop's text, in lower case. */
	return !strcmp(host, "::1") || !strncmp(host, "fe80:", 5u) || !strncmp(host, "fc", 2u)
	       || !strncmp(host, "fd", 2u);
}

static size_t address_local(const fzn_request_t *request, char *reply, size_t cap)
{
	size_t at, i, k;
	int agree = 1;

	/* `fetch lan`, sec 624: probes sent at once, and said -- `ok SENT
	 * ADDRESS`, or `ok 0 -` and why none was, so a client need not guess
	 * (fuzzypickles' sec 282). */
	if (request->arg && request->arg_len == 3u && memcmp(request->arg, "lan", 3u) == 0
	    && request->parsed == FZN_VERB_FETCH) {
		char address[FZN_UDP_HOST_MAX];
		const char *why = NULL;
		size_t sent = lan_probe(&why, address, sizeof(address));

		if (!sent && why)
			return (size_t)snprintf(reply, cap, "ok 0 - %s\n", why);
		lan_probed_at = wall_clock();
		return (size_t)snprintf(reply, cap, "ok %zu %s\n", sent, address);
	}
	/* `get lan`, sec 659: `ok N KEY,HOST,PORT,AT ...`, the hellos heard since
	 * the last probe went from an address of the local network's -- the
	 * answers a probe gets, from hosts this host knows, nobody else
	 * answering one (sec 624). A pull peer's hello from the wider network
	 * is in the same table, and kept out by its address. AT in seconds. */
	if (request->arg && request->arg_len == 3u && memcmp(request->arg, "lan", 3u) == 0
	    && request->parsed == FZN_VERB_GET) {
		static char rows[FZN_NODE_RELAY_SEEN_MAX * 120u];
		size_t s_i, shown = 0, used = 0;

		for (s_i = 0; s_i < FZN_NODE_RELAY_SEEN_MAX; s_i++) {
			const fzn_node_relay_seen_t *e = &relay_tables.seen[s_i];
			char host[FZN_UDP_HOST_MAX], key[2u * FZN_PUBKEY_LEN + 1u];
			uint16_t port = 0;
			int r;

			if (!e->used || !lan_probed_at || e->when < lan_probed_at
			    || fzn_udp_addr_text(&e->at, host, &port) != FZN_UDP_OK || !local_scope(host))
				continue;
			hex_of(e->key, FZN_PUBKEY_LEN, key);
			r = snprintf(rows + used, sizeof(rows) - used, " %s,%s,%u,%llu", key, host,
			             (unsigned)port, (unsigned long long)e->when);
			/* ROOM IN THE REPLY FOR THE HEAD, THE ROWS AND THE NEWLINE, or
			 * the list ends here. */
			if (r < 0 || used + (size_t)r >= sizeof(rows) || used + (size_t)r + 24u > cap)
				break;
			used += (size_t)r;
			shown++;
		}
		at = (size_t)snprintf(reply, cap, "ok %zu", shown);
		memcpy(reply + at, rows, used);
		at += used;
		return at + (size_t)snprintf(reply + at, cap - at, "\n");
	}
	if (!request->arg || request->arg_len != 7u || memcmp(request->arg, "address", 7u) != 0
	    || (request->parsed != FZN_VERB_GET && request->parsed != FZN_VERB_FETCH))
		return 0;
	/* `fetch address`, sec 653: `ok COUNT`, the hosts the ask will reach --
	 * every sibling not silent, every share's and every contact's, as
	 * `address_start` takes them -- or `ok 0 WHY` with nobody to ask, so a
	 * client tells "nobody to ask" from "asked, no answer yet", as `fetch
	 * lan` does (sec 639). */
	if (request->parsed == FZN_VERB_FETCH) {
		size_t count = nshares_in + ncontact_targets;

		for (i = 0; loop_pulls && loop_npulls && i < *loop_npulls; i++)
			count += !silent_peer(&loop_pulls[i]);
		if (!count)
			return (size_t)snprintf(reply, cap,
			                        "ok 0 no sibling, share or contact host to ask\n");
		address_due = 1;
		return (size_t)snprintf(reply, cap, "ok %zu\n", count);
	}
	for (i = 1; i < n_observed; i++)
		if (observed[i].port != observed[0].port
		    || strcmp(observed[i].host, observed[0].host) != 0)
			agree = 0;
	at = (size_t)snprintf(reply, cap, "ok %zu %d", n_observed, agree);
	for (i = 0; i < n_observed && at < cap; i++) {
		char hex[2u * FZN_PUBKEY_LEN + 1u];

		hex_of(observed[i].reporter, FZN_PUBKEY_LEN, hex);
		k = (size_t)snprintf(reply + at, cap - at, " %.16s,%s,%u,%llu", hex, observed[i].host,
		                     (unsigned)observed[i].port, (unsigned long long)observed[i].at);
		if (at + k >= cap)
			break;
		at += k;
	}
	return at + (size_t)snprintf(reply + at, cap - at, "\n");
}

/* EACH ROUND: every contact asked through the first of its hosts that
 * answers -- a received share's pairing first -- the members asked for what
 * they kept, every contact device kept paired here, and the targets
 * rebuilt. */
/* A MEMBER'S KEPT DEVICES, asked as a conversation of the round. sec 636. */
_Static_assert(FZND_PULL_REPLY_MAX >= FZN_CONTACT_DEVICES_REPLY_MAX,
               "a devices page fits the round's answers");

struct devices_talk {
	fzn_node_talk_t talk;
	struct meter m;
	uint8_t request[FZN_CONTACT_DEVICES_QUERY_LEN];
	fzn_contact_devices_querying_t q;
};
static struct devices_talk devices_talks[FZND_ROUND_TARGETS_MAX];
static size_t n_devices_talks, contacts_asked, contacts_kept;

static int devices_talk_step(void *ctx, const uint8_t *reply, size_t reply_len, uint8_t *request,
                             size_t cap, size_t *request_len)
{
	struct devices_talk *dt = ctx;
	int done = 0, ok;

	meter_answer(&dt->m, reply, reply_len);
	ok = fzn_contact_devices_query_step(&dt->q, reply, reply_len, request, cap, request_len,
	                                    &done);
	if (!ok || done)
		return 0;
	meter_asked(&dt->m, *request_len);
	return 1;
}

/* ---- A CONTACT'S EXCHANGE, a conversation of the round, sec 636: this
 * estate's devices offered, the contact's hosts asked, its manifest
 * fetched, as the round once asked them in turn -- with every contact at once,
 * and through its next host when one does not answer, as the round in
 * turn tried them. */
#define FZND_CONTACT_HOSTS_TRIED 8u

struct contact_talk {
	fzn_node_talk_t talk;
	struct meter m;
	uint8_t contact[FZN_PUBKEY_LEN];
	struct pull_target *hosts[FZND_CONTACT_HOSTS_TRIED];
	const char *names[FZND_CONTACT_HOSTS_TRIED];
	size_t n_hosts, at;
	int phase, ok;
	size_t offered;
	fzn_contact_devices_querying_t q;
	struct hosts_taking ht;
	uint64_t now;
	uint8_t request[FZN_CONTACT_DEVICES_OFFER_MAX];
};
enum { CONTACT_OFFER = 1, CONTACT_QUERY = 2, CONTACT_ROUTING = 3 };
static struct contact_talk contact_talks[FZND_CONTACT_TARGETS_MAX + FZN_NODE_RECEIVED_MAX];
static size_t n_contact_talks;
static fzn_contact_device_t contact_own[FZN_NODE_SIBLINGS_MAX];
static size_t n_contact_own;

/* THE NEXT REQUEST of the exchange with the host at `ct->at`, from its
 * phase on: an offer of the next own device, the hosts query, the manifest.
 * 0 when one could not be written. */
static int contact_next(struct contact_talk *ct, uint8_t *request, size_t cap, size_t *len)
{
	if (ct->phase == CONTACT_OFFER && ct->offered < n_contact_own)
		return fzn_contact_devices_offer_request(&contact_own[ct->offered], request, cap, len);
	if (ct->phase == CONTACT_OFFER) {
		ct->phase = CONTACT_QUERY;
		return fzn_contact_devices_query_begin(&ct->q, FZN_CONTACT_DEVICES_HOSTS, take_host,
		                                       &ct->ht, request, cap, len);
	}
	if (cap < 11u)
		return 0;
	memcpy(request, "get routing", 11u);
	*len = 11u;
	return 1;
}

static int contact_talk_step(void *ctx, const uint8_t *reply, size_t reply_len, uint8_t *request,
                             size_t cap, size_t *request_len)
{
	static uint8_t routing_reply[FZND_PULL_REPLY_MAX + 1u];
	struct contact_talk *ct = ctx;
	int done = 0;

	meter_answer(&ct->m, reply, reply_len);
	if (!reply)
		return 0;
	if (ct->phase == CONTACT_OFFER) {
		if (fzn_contact_devices_offer_reply(reply, reply_len) < 0)
			return 0;
		ct->offered++;
	} else if (ct->phase == CONTACT_QUERY) {
		if (!fzn_contact_devices_query_step(&ct->q, reply, reply_len, request, cap,
		                                    request_len, &done))
			return 0;
		if (!done) {
			meter_asked(&ct->m, *request_len);
			return 1;
		}
		ct->phase = CONTACT_ROUTING;
	} else {
		/* THE MANIFEST, taken when it verifies; the exchange stands either
		 * way, as it did when asked in turn. Copied out: the answer is the
		 * loop's, with no byte to spare. */
		if (reply_len <= FZND_PULL_REPLY_MAX) {
			memcpy(routing_reply, reply, reply_len);
			(void)routing_take(ct->names[ct->at], routing_reply, reply_len, ct->contact,
			                   ct->now);
		}
		ct->ok = 1;
		return 0;
	}
	if (!contact_next(ct, request, cap, request_len))
		return 0;
	meter_asked(&ct->m, *request_len);
	return 1;
}

static void contact_talk_over(void *ctx);

/* THE EXCHANGE THROUGH `ct->hosts[ct->at]`, begun; through the next host
 * while one cannot be. 1 when one is awaited. */
static int contact_talk_begin(struct contact_talk *ct)
{
	size_t len;

	for (; ct->at < ct->n_hosts; ct->at++) {
		struct pull_target *pt = ct->hosts[ct->at];

		ct->phase = CONTACT_OFFER;
		ct->offered = 0;
		ct->ht.contact = ct->contact;
		ct->ht.asked = pt->pairing.node;
		ct->ht.host = ct->names[ct->at];
		ct->ht.port = (uint16_t)pt->port;
		ct->ht.kept = 0;
		len = 0;
		if (!contact_next(ct, ct->request, sizeof(ct->request), &len))
			continue;
		if (talk_start_over(&ct->talk, &ct->m, pt, ct->now, contact_talk_step,
		                    contact_talk_over, 0, ct, ct->request, sizeof(ct->request), len))
			return 1;
	}
	return 0;
}

/* ONE CONTACT'S EXCHANGE OVER: answered, said; or tried through its next
 * host. */
static void contact_talk_over(void *ctx)
{
	struct contact_talk *ct = ctx;

	if (round_pending)
		round_pending--;
	if (ct->ok) {
		/* A CONTACT THAT ANSWERS has answered any request to it, sec 619. */
		(void)fzn_contact_asked_answered(node_apply.store, ct->contact);
		if (ct->ht.kept)
			say(FZN_ENTRY_DEBUG, "contact/devices",
			    "%zu device(s) offered to %s, %zu host(s) kept", n_contact_own,
			    ct->names[ct->at], ct->ht.kept);
		contacts_asked++;
		return;
	}
	ct->at++;
	(void)contact_talk_begin(ct);
}

static void contact_round(struct pull_target *pulls, size_t npulls, uint64_t now)
{
	size_t i, k;

	contacts_asked = 0;
	contacts_kept = 0;
	n_contact_talks = 0;
	n_devices_talks = 0;
	if (!running_admin || !contact_id || !node_apply.store)
		return;
	/* THE HOSTS KEPT SO FAR, so a member's first round asks the contact
	 * through one it learned last round, or from another member. */
	load_contact_targets();
	/* EACH STANDING CONTACT ONCE, its hosts in the order the round tried
	 * them: a conversation through the first, the next when it does not
	 * answer, every contact at once (sec 636). */
	n_contact_own = estate_devices(contact_own, FZN_NODE_SIBLINGS_MAX, 0);
	for (i = 0; i < nshares_in + ncontact_targets; i++) {
		struct pull_target *pt = i < nshares_in ? &shares_in[i].pt
		                                        : &contact_targets[i - nshares_in].pt;
		const uint8_t *contact = i < nshares_in ? shares_in[i].sharer
		                                        : contact_targets[i - nshares_in].contact;
		const char *host = i < nshares_in ? shares_in[i].host
		                                  : contact_targets[i - nshares_in].host;
		struct contact_talk *ct;

		if (!fzn_node_admin_contact_stands(running_admin, contact))
			continue;
		for (k = 0; k < n_contact_talks
		            && memcmp(contact_talks[k].contact, contact, FZN_PUBKEY_LEN) != 0;
		     k++)
			;
		if (k == n_contact_talks) {
			if (n_contact_talks
			    == sizeof(contact_talks) / sizeof(contact_talks[0]))
				continue;
			ct = &contact_talks[n_contact_talks++];
			memcpy(ct->contact, contact, FZN_PUBKEY_LEN);
			ct->n_hosts = ct->at = 0;
			ct->ok = 0;
			ct->now = now;
		}
		ct = &contact_talks[k];
		if (ct->n_hosts < FZND_CONTACT_HOSTS_TRIED) {
			ct->hosts[ct->n_hosts] = pt;
			ct->names[ct->n_hosts++] = host;
		}
	}
	for (k = 0; k < n_contact_talks; k++)
		(void)contact_talk_begin(&contact_talks[k]);
	/* WHAT THE ESTATE'S MEMBERS KEEP, asked of every one at once, sec 636;
	 * `contact_settle` pairs and says what came. */
	for (i = 0; i < npulls && n_devices_talks < FZND_ROUND_TARGETS_MAX; i++) {
		struct devices_talk *dt = &devices_talks[n_devices_talks];
		size_t len = 0;

		if (silent_peer(&pulls[i]) || !peer_in_estate(&pulls[i])
		    || !fzn_contact_devices_query_begin(&dt->q, FZN_CONTACT_DEVICES_KEPT, take_kept,
		                                        &contacts_kept, dt->request,
		                                        sizeof(dt->request), &len))
			continue;
		n_devices_talks++;
		(void)talk_start(&dt->talk, &dt->m, &pulls[i], now, devices_talk_step, dt,
		                 dt->request, sizeof(dt->request), len);
	}
}

/* THE CONTACT PASS'S END: the devices the members keep paired, and said. */
static void contact_settle(void)
{
	size_t paired;

	if (!running_admin || !contact_id || !node_apply.store)
		return;
	paired = pair_contact_devices();
	contact_pair_due = 0;
	load_contact_targets();
	say(FZN_ENTRY_DEBUG, "contact/devices",
	    "contact pass: %zu contact(s) asked, %zu kept from members, %zu paired, %zu host(s) "
	    "to deliver to",
	    contacts_asked, contacts_kept, paired, ncontact_targets);
}

/* ---- groups, sec 626 ------------------------------------------------------- */

/* GROUP_SYNC, in notes-sync's space after the introduction's 38: the
 * asker's head of each group it holds that the asked host's user is in --
 * id, place and head hash -- answered with GROUP_ACTS, the acts the asker
 * lacks, in log order. A group the asker does not list is sent whole: that
 * is how a member's host first learns a group. */
#define FZND_GROUP_VERSION 2u
#define FZND_GROUP_SYNC_TYPE 39u
#define FZND_GROUP_ACTS_TYPE 40u
#define FZND_GROUP_ENTRY_LEN (FZN_GROUP_ID_LEN + 4u + 32u)
/* Heads in one request: a request is one frame. */
#define FZND_GROUP_SYNC_MAX 12u

static fzn_node_groups_t node_groups;

/* THIS HOST'S OWN ACTS A FORK DROPPED, made again on the kept head once the
 * sync that dropped them is done: the log is not offered into from inside
 * an offer. sec 626. */
#define FZND_GROUP_REDO_MAX 16u
static struct {
	uint8_t kind, setting;
	uint8_t group[FZN_GROUP_ID_LEN];
	uint8_t subject[FZN_PUBKEY_LEN];
	uint64_t value;
} group_redo[FZND_GROUP_REDO_MAX];
static size_t n_group_redo;

static void group_dropped(void *ctx, const uint8_t *bytes, size_t len)
{
	fzn_group_act_t a;

	(void)ctx;
	if (n_group_redo == FZND_GROUP_REDO_MAX || !contact_id
	    || fzn_group_act_decode(bytes, len, &a) != FZN_GROUP_ACT_OK
	    || memcmp(fzn_contact_device_key(&a.signer), contact_id->pubkey, FZN_PUBKEY_LEN) != 0)
		return;
	group_redo[n_group_redo].kind = a.kind;
	group_redo[n_group_redo].setting = a.setting;
	memcpy(group_redo[n_group_redo].group, a.group, FZN_GROUP_ID_LEN);
	memcpy(group_redo[n_group_redo].subject, a.subject, FZN_PUBKEY_LEN);
	group_redo[n_group_redo].value = a.value;
	n_group_redo++;
}

/* EACH DROPPED ACT MADE AGAIN, where it still means something: one made
 * moot or no longer allowed by the act it lost to is let go. */
static void group_redo_all(void)
{
	size_t i, made = 0;

	for (i = 0; i < n_group_redo; i++)
		made += fzn_node_groups_act(&node_groups, group_redo[i].kind, group_redo[i].group,
		                            group_redo[i].subject, group_redo[i].setting,
		                            group_redo[i].value, NULL)
		        == FZN_GROUP_LOG_OK;
	if (n_group_redo)
		say(FZN_ENTRY_INFO, "node/groups", "%zu act(s) of this host's lost a fork, %zu made again",
		    n_group_redo, made);
	n_group_redo = 0;
}

static int groups_signer(void *ctx, fzn_contact_device_t *out)
{
	(void)ctx;
	return contact_id && estate_devices(out, 1u, 0) == 1u;
}

/* WHOSE `sender` IS, as a group knows a user: this estate's own user for a
 * member host, a contact's root for a contact's host; 0 for anyone else. */
static int group_owner_of(const uint8_t *sender, uint8_t owner[FZN_PUBKEY_LEN], int *own)
{
	fzn_setting_rank_t rank;

	*own = 0;
	if (fzn_node_apply_rank(&node_apply, sender, FZN_SCOPE_HOST, sender, &rank) == 1
	    && estate_owner()) {
		memcpy(owner, estate_owner(), FZN_PUBKEY_LEN);
		*own = 1;
		return 1;
	}
	return running_admin && fzn_node_admin_contact_of(running_admin, sender, owner);
}

/* WHERE `owner`'S LAST REMOVAL from group `id` ends: one past the place of
 * the last REMOVE act naming it, 0 when none does. sec 649. */
static uint32_t group_removal_end(const uint8_t *id, const fzn_group_t *g, const uint8_t *owner)
{
	static uint8_t act[FZN_GROUP_ACT_MAX];
	static fzn_group_act_t a;
	uint32_t s, end = 0;
	size_t n = 0;

	for (s = 0; s < g->seq; s++)
		if (fzn_group_log_act(&node_groups.log, id, s, act, sizeof(act), &n) == FZN_GROUP_LOG_OK
		    && fzn_group_act_decode(act, n, &a) == FZN_GROUP_ACT_OK
		    && a.kind == FZN_GROUP_ACT_REMOVE
		    && memcmp(a.subject, owner, FZN_PUBKEY_LEN) == 0)
			end = s + 1u;
	return end;
}

/* THE ACTS AN ASKER LACKS of group `id`, from the head it gave -- or
 * whole -- appended to `reply` as length and bytes while they fit; none
 * at or past `until` when it is not 0. */
static size_t group_acts_from(const uint8_t *id, const uint8_t *asked, uint8_t *reply,
                              size_t at, size_t cap, size_t *count, uint32_t until)
{
	static fzn_group_t g;
	static uint8_t act[FZN_GROUP_ACT_MAX];
	static fzn_group_act_t a;
	uint8_t hash[32];
	uint32_t from = 0, s;
	size_t n = 0;

	if (fzn_group_log_get(node_apply.store, id, &g) != FZN_GROUP_LOG_OK)
		return at;
	if (asked) {
		uint32_t seq = fzn_get_be32(asked + FZN_GROUP_ID_LEN);
		const uint8_t *head = asked + FZN_GROUP_ID_LEN + 4u;

		if (seq == g.seq && memcmp(head, g.head, 32u) == 0)
			return at;
		/* ON THIS LOG, the acts after it; off it, all but the create act,
		 * so the asker meets the fork where it starts. */
		from = 1u;
		if (seq >= 1u && seq <= g.seq
		    && fzn_group_log_act(&node_groups.log, id, seq - 1u, act, sizeof(act), &n)
		               == FZN_GROUP_LOG_OK
		    && fzn_group_act_decode(act, n, &a) == FZN_GROUP_ACT_OK
		    && fzn_group_act_hash(&a, node_groups.log.hash, hash) == FZN_GROUP_ACT_OK
		    && memcmp(hash, head, 32u) == 0)
			from = seq;
	}
	for (s = from; s < g.seq && (!until || s < until); s++) {
		if (fzn_group_log_act(&node_groups.log, id, s, act, sizeof(act), &n) != FZN_GROUP_LOG_OK
		    || at + 2u + n > cap)
			break;
		fzn_put_be16(reply + at, (uint16_t)n);
		memcpy(reply + at + 2u, act, n);
		at += 2u + n;
		(*count)++;
	}
	return at;
}

static int member_host_owner(const uint8_t *host, uint8_t owner[FZN_PUBKEY_LEN]);

/* GROUP_SYNC ANSWERED: the acts of every group held that the asker's user
 * is in -- every group, for this estate's own hosts. The asker is a host of
 * this estate, a contact's, or a member's host a group held here lists
 * (sec 642): a member's other hosts are told the log as a contact's are. */
static size_t group_sync_remote(const uint8_t *sender, const uint8_t *request,
                                size_t request_len, uint8_t *reply, size_t reply_cap)
{
	static uint8_t ids[FZN_GROUPS_HELD_MAX][FZN_GROUP_ID_LEN];
	static fzn_group_t g;
	uint8_t owner[FZN_PUBKEY_LEN];
	size_t n = 0, i, k, entries, at = 4u, count = 0;
	size_t cap = reply_cap < FZND_PULL_REPLY_MAX ? reply_cap : FZND_PULL_REPLY_MAX;
	int own;

	if (request_len < 3u
	    || request_len != 3u + (size_t)request[2] * FZND_GROUP_ENTRY_LEN || request[2] > FZND_GROUP_SYNC_MAX)
		return (size_t)snprintf((char *)reply, reply_cap, "malformed a group sync\n");
	if (!node_apply.store || !node_groups.log.store
	    || (!group_owner_of(sender, owner, &own) && !member_host_owner(sender, owner)))
		return (size_t)snprintf((char *)reply, reply_cap, "denied groups only to members\n");
	entries = request[2];
	if (cap < 4u
	    || fzn_group_log_list(node_apply.store, ids, FZN_GROUPS_HELD_MAX, &n) != FZN_GROUP_LOG_OK)
		return (size_t)snprintf((char *)reply, reply_cap, "error the groups did not read\n");
	for (i = 0; i < n; i++) {
		const uint8_t *asked = NULL;
		uint32_t until = 0;

		if (fzn_group_log_get(node_apply.store, ids[i], &g) != FZN_GROUP_LOG_OK)
			continue;
		/* A REMOVED MEMBER IS TOLD ITS REMOVAL, sec 649, and nothing after
		 * it: the acts up to the last that removed it, so its host stops
		 * holding itself a member. Anyone else not in the group, nothing. */
		if (!own && !fzn_group_is_member(&g, owner)
		    && !(until = group_removal_end(ids[i], &g, owner)))
			continue;
		for (k = 0; k < entries && !asked; k++)
			if (memcmp(request + 3u + k * FZND_GROUP_ENTRY_LEN, ids[i], FZN_GROUP_ID_LEN) == 0)
				asked = request + 3u + k * FZND_GROUP_ENTRY_LEN;
		at = group_acts_from(ids[i], asked, reply, at, cap, &count, until);
	}
	reply[0] = FZND_GROUP_VERSION;
	reply[1] = FZND_GROUP_ACTS_TYPE;
	fzn_put_be16(reply + 2, (uint16_t)count);
	return at;
}

/* A GROUP LEARNED FROM ANOTHER HOST is named here by its id's first 8
 * bytes in hex, until its user renames it. */
static void group_named(const uint8_t *id)
{
	char name[FZN_CONTACT_NAME_MAX + 1u];
	size_t len = 0, i;

	if (fzn_node_group_name(node_apply.store, id, name, &len) == FZN_CONTACT_OK)
		return;
	for (i = 0; i < 8u; i++)
		(void)snprintf(name + 2u * i, 3u, "%02x", id[i]);
	(void)fzn_node_group_rename(node_apply.store, id, name, 16u);
}

/* ONE GROUP_SYNC's REQUEST, its heads from `ids[*i]` on: those of the groups
 * the asked host's user is in -- every one held, when it is this estate's
 * own -- a dozen at most. A request with none still asks: the asked host
 * sends what this user is in. Its length. */
static size_t group_sync_request(const uint8_t (*ids)[FZN_GROUP_ID_LEN], size_t n, size_t *i,
                                 const uint8_t *owner, int own, uint8_t *request)
{
	static fzn_group_t g;
	size_t entries = 0;

	for (; *i < n && entries < FZND_GROUP_SYNC_MAX; (*i)++) {
		uint8_t *e = request + 3u + entries * FZND_GROUP_ENTRY_LEN;

		if (fzn_group_log_get(node_apply.store, ids[*i], &g) != FZN_GROUP_LOG_OK
		    || (!own && !fzn_group_is_member(&g, owner)))
			continue;
		memcpy(e, g.id, FZN_GROUP_ID_LEN);
		fzn_put_be32(e + FZN_GROUP_ID_LEN, g.seq);
		memcpy(e + FZN_GROUP_ID_LEN + 4u, g.head, 32u);
		entries++;
	}
	request[0] = FZND_GROUP_VERSION;
	request[1] = FZND_GROUP_SYNC_TYPE;
	request[2] = (uint8_t)entries;
	return 3u + entries * FZND_GROUP_ENTRY_LEN;
}

/* A GROUP_ACTS answer taken into the log: how many acts were; -1 when it is
 * not one. */
static long group_acts_take(const uint8_t *reply, size_t len)
{
	size_t count, k, at;
	long taken = 0;

	if (!reply || len < 4u || reply[0] != FZND_GROUP_VERSION || reply[1] != FZND_GROUP_ACTS_TYPE)
		return -1;
	count = fzn_get_be16(reply + 2);
	for (k = 0, at = 4u; k < count && at + 2u <= len; k++) {
		size_t act_len = fzn_get_be16(reply + at);
		fzn_group_offer_t did;
		size_t dropped = 0;
		fzn_group_act_t a;
		uint8_t id[FZN_GROUP_ID_LEN];

		if (at + 2u + act_len > len)
			break;
		if (fzn_group_log_offer(&node_groups.log, reply + at + 2u, act_len, &did, &dropped)
		            == FZN_GROUP_LOG_OK
		    && (did == FZN_GROUP_OFFER_TAKEN || did == FZN_GROUP_OFFER_REPLACED)) {
			taken++;
			if (fzn_group_act_decode(reply + at + 2u, act_len, &a) == FZN_GROUP_ACT_OK) {
				if (a.kind == FZN_GROUP_ACT_CREATE)
					(void)fzn_group_act_hash(&a, node_groups.log.hash, id);
				else
					memcpy(id, a.group, FZN_GROUP_ID_LEN);
				group_named(id);
			}
			if (did == FZN_GROUP_OFFER_REPLACED)
				say(FZN_ENTRY_INFO, "node/groups",
				    "a group's log forked; the lower act kept, %zu act(s) dropped", dropped);
		}
		at += 2u + act_len;
	}
	return taken;
}

/* ONE HOST of user `owner` -- this estate's own when `own` -- asked for the
 * acts of the groups it and this host share, and what comes taken: a
 * conversation of the round, sec 636, with every sibling, contact (sec 644)
 * and member's host at once, each its own copy of the groups held, since
 * each pages them apart. */
struct group_sync_talk {
	fzn_node_talk_t talk;
	struct meter m;
	uint8_t ids[FZN_GROUPS_HELD_MAX][FZN_GROUP_ID_LEN];
	size_t n, i, taken;
	const uint8_t *owner;
	int own;
	uint8_t request[3u + FZND_GROUP_SYNC_MAX * FZND_GROUP_ENTRY_LEN];
};
static struct group_sync_talk group_sync_talks[FZND_ROUND_TARGETS_MAX + FZND_CONTACT_TARGETS_MAX
                                              + FZND_GROUP_SHARES_MAX];
static size_t n_group_sync_talks;

static int group_sync_step(void *ctx, const uint8_t *reply, size_t reply_len, uint8_t *request,
                           size_t cap, size_t *request_len)
{
	struct group_sync_talk *gt = ctx;
	long got;

	(void)cap;
	meter_answer(&gt->m, reply, reply_len);
	if ((got = group_acts_take(reply, reply_len)) < 0)
		return 0;
	gt->taken += (size_t)got;
	if (gt->i >= gt->n)
		return 0;
	*request_len = group_sync_request((const uint8_t (*)[FZN_GROUP_ID_LEN])gt->ids, gt->n,
	                                  &gt->i, gt->owner, gt->own, request);
	meter_asked(&gt->m, *request_len);
	return 1;
}

/* A GROUP SYNC, started: with a sibling (`own`), every group held; with
 * a member's host, those its user is in. */
static void group_sync_start(struct pull_target *pt, const uint8_t *owner, int own, uint64_t now)
{
	struct group_sync_talk *gt;
	size_t len;

	if (n_group_sync_talks >= sizeof(group_sync_talks) / sizeof(group_sync_talks[0]))
		return;
	gt = &group_sync_talks[n_group_sync_talks];
	gt->n = gt->i = gt->taken = 0;
	gt->owner = owner;
	gt->own = own;
	if (fzn_group_log_list(node_apply.store, gt->ids, FZN_GROUPS_HELD_MAX, &gt->n)
	    != FZN_GROUP_LOG_OK)
		return;
	n_group_sync_talks++;
	len = group_sync_request((const uint8_t (*)[FZN_GROUP_ID_LEN])gt->ids, gt->n, &gt->i, owner,
	                         own, gt->request);
	(void)talk_start(&gt->talk, &gt->m, pt, now, group_sync_step, gt, gt->request,
	                 sizeof(gt->request), len);
}

/* ---- a group's lines, sec 629 ------------------------------------------------- */

/* GROUP_LINES_SYNC asks, for one group, what lies past each head the
 * asker gives -- a sealing host and the last of its lines held; GROUP_LINES
 * answers each line as its place and its sealed bytes, oldest first per
 * host. A host the asker does not name is answered from its first line. */
#define FZND_GROUP_LINES_SYNC_TYPE 41u
#define FZND_GROUP_LINES_TYPE 42u
#define FZND_GROUP_HEAD_LEN (FZN_PUBKEY_LEN + 4u)
#define FZND_GROUP_HEADS_MAX 24u

static fzn_group_lines_t group_lines;

static size_t group_lines_remote(const uint8_t *sender, const uint8_t *request,
                                 size_t request_len, uint8_t *reply, size_t reply_cap)
{
	static fzn_group_line_head_t heads[FZN_GROUP_HOSTS_MAX];
	static fzn_group_t g;
	static uint8_t line[FZN_GROUP_LINE_MAX];
	uint8_t owner[FZN_PUBKEY_LEN];
	size_t n = 0, i, k, at = 4u, count = 0, len = 0, entries;
	size_t cap = reply_cap < FZND_PULL_REPLY_MAX ? reply_cap : FZND_PULL_REPLY_MAX;
	int own;

	if (request_len < 3u + FZN_GROUP_ID_LEN
	    || request[2u + FZN_GROUP_ID_LEN] > FZND_GROUP_HEADS_MAX
	    || request_len != 3u + FZN_GROUP_ID_LEN
	                              + (size_t)request[2u + FZN_GROUP_ID_LEN] * FZND_GROUP_HEAD_LEN)
		return (size_t)snprintf((char *)reply, reply_cap, "malformed a group lines sync\n");
	entries = request[2u + FZN_GROUP_ID_LEN];
	/* A MEMBER'S HOST too, sec 643, for a group listing its user, as a
	 * contact's host is answered. */
	if (!group_lines.store
	    || (!group_owner_of(sender, owner, &own) && !member_host_owner(sender, owner))
	    || fzn_group_log_get(node_apply.store, request + 2, &g) != FZN_GROUP_LOG_OK
	    || (!own && !fzn_group_is_member(&g, owner)))
		return (size_t)snprintf((char *)reply, reply_cap, "denied lines only to members\n");
	if (cap < 4u
	    || fzn_group_lines_heads(&group_lines, g.id, heads, FZN_GROUP_HOSTS_MAX, &n)
	               != FZN_GROUP_LINES_OK)
		return (size_t)snprintf((char *)reply, reply_cap, "error the lines did not read\n");
	for (i = 0; i < n; i++) {
		uint32_t from = 0, s;

		for (k = 0; k < entries; k++) {
			const uint8_t *e = request + 3u + FZN_GROUP_ID_LEN + k * FZND_GROUP_HEAD_LEN;

			if (memcmp(e, heads[i].host, FZN_PUBKEY_LEN) == 0)
				from = fzn_get_be32(e + FZN_PUBKEY_LEN);
		}
		/* FROM THE BASE, sec 664: the lines a rule trimmed here are gone,
		 * and an answer starting past what was asked tells the asker so. */
		if (from < heads[i].base)
			from = heads[i].base;
		for (s = from + 1u; s <= heads[i].have; s++) {
			if (fzn_group_lines_get(&group_lines, g.id, heads[i].host, s, line, sizeof(line), &len)
			            != FZN_GROUP_LINES_OK
			    || at + 6u + len > cap)
				break;
			fzn_put_be32(reply + at, s);
			fzn_put_be16(reply + at + 4u, (uint16_t)len);
			memcpy(reply + at + 6u, line, len);
			at += 6u + len;
			count++;
		}
	}
	reply[0] = FZND_GROUP_VERSION;
	reply[1] = FZND_GROUP_LINES_TYPE;
	fzn_put_be16(reply + 2, (uint16_t)count);
	return at;
}

/* GROUP_LINES_SYNC for group `id`: the heads held here, into `request`.
 * Its length, or 0. */
static size_t group_lines_request(const uint8_t id[FZN_GROUP_ID_LEN], uint8_t *request)
{
	static fzn_group_line_head_t heads[FZN_GROUP_HOSTS_MAX];
	size_t n = 0, i, entries;

	if (fzn_group_lines_heads(&group_lines, id, heads, FZN_GROUP_HOSTS_MAX, &n)
	    != FZN_GROUP_LINES_OK)
		return 0;
	entries = n < FZND_GROUP_HEADS_MAX ? n : FZND_GROUP_HEADS_MAX;
	request[0] = FZND_GROUP_VERSION;
	request[1] = FZND_GROUP_LINES_SYNC_TYPE;
	memcpy(request + 2, id, FZN_GROUP_ID_LEN);
	request[2u + FZN_GROUP_ID_LEN] = (uint8_t)entries;
	for (i = 0; i < entries; i++) {
		uint8_t *e = request + 3u + FZN_GROUP_ID_LEN + i * FZND_GROUP_HEAD_LEN;

		memcpy(e, heads[i].host, FZN_PUBKEY_LEN);
		fzn_put_be32(e + FZN_PUBKEY_LEN, heads[i].have);
	}
	return 3u + FZN_GROUP_ID_LEN + entries * FZND_GROUP_HEAD_LEN;
}

/* A GROUP_LINES answer taken: how many lines were kept; 0 for anything
 * else. */
static size_t group_lines_take(const uint8_t *reply, size_t len)
{
	static fzn_group_line_t peeked;
	uint8_t last_host[FZN_PUBKEY_LEN];
	size_t count, k, at, taken = 0;
	int any = 0;

	if (!reply || len < 4u || reply[0] != FZND_GROUP_VERSION || reply[1] != FZND_GROUP_LINES_TYPE)
		return 0;
	count = fzn_get_be16(reply + 2);
	for (k = 0, at = 4u; k < count && at + 6u <= len; k++) {
		size_t line_len = fzn_get_be16(reply + at + 4u);
		int first;

		if (at + 6u + line_len > len)
			break;
		/* A HOST'S FIRST LINE HERE may start past this head -- its sender
		 * trimmed the lines before (sec 664) -- and is taken from there;
		 * every later one in order, as ever. */
		first = fzn_group_line_peek(reply + at + 6u, line_len, &peeked) == FZN_GROUP_LINE_OK
		        && (!any || memcmp(last_host, peeked.host, FZN_PUBKEY_LEN) != 0);
		if (first) {
			memcpy(last_host, peeked.host, FZN_PUBKEY_LEN);
			any = 1;
		}
		taken += (first ? fzn_group_lines_put_from : fzn_group_lines_put)(
		                 &group_lines, fzn_get_be32(reply + at), reply + at + 6u, line_len)
		         == FZN_GROUP_LINES_OK;
		at += 6u + line_len;
	}
	return taken;
}

/* THIS HOST'S OWN UNSENT LINES in group `g` sealed, sec 629: each OUT line
 * this device wrote to the group's conversation and has not marked, sealed
 * under the current epoch as this host's next line, then marked
 * delivered -- given to the group, which carries it on. */
/* AN UNSENT LINE OF THIS HOST'S, to be sealed. */
static int seal_wanted(const fzn_message_t *p, const uint8_t *self)
{
	return p->direction == FZN_MESSAGE_OUT && p->state == 0u && p->readable
	       && memcmp(p->device, self, FZN_PUBKEY_LEN) == 0;
}

/* EVERY UNSENT LINE OF THIS HOST'S, sealed oldest first -- not the newest
 * page's alone (sec 657): a page holds every member's lines, so a line of
 * this host's with twenty from others filed after it was off the page,
 * and never sealed. Pages are walked back until one holds a line of this
 * host's already sealed, past which none is unsent -- a pass seals all it
 * finds, oldest first -- then sealed deepest first. */
static size_t group_seal_own(const fzn_group_t *g, const fzn_contact_device_t *own)
{
	static fzn_message_t page[FZN_MESSAGES_PAGE_MAX];
	static fzn_group_line_t line;
	static uint8_t bytes[FZN_GROUP_LINE_MAX];
	static size_t at_pages[FZN_MESSAGES_WALK_MAX / FZN_MESSAGES_PAGE_MAX + 1u];
	uint8_t secret[FZN_GROUP_SECRET_LEN];
	const uint8_t *self = fzn_contact_device_key(own);
	fzn_group_line_head_t head;
	size_t count = 0, i, len = 0, sealed = 0, offset = 0, n_pages = 0, k;
	int more = 1, done = 0;

	if (!fzn_group_is_member(g, own->owner)
	    || fzn_node_groups_secret(&node_groups, g->id, g->epoch, secret) != FZN_GROUP_LOG_OK)
		return 0;
	/* WHICH PAGES HOLD ONE. */
	while (more && !done && n_pages < sizeof(at_pages) / sizeof(at_pages[0])) {
		int wanted = 0;

		if (fzn_messages_page(&node_messages.m, g->id, offset, page, FZN_MESSAGES_PAGE_MAX,
		                      &count, &more)
		    != FZN_MESSAGES_OK)
			break;
		for (i = 0; i < count; i++) {
			wanted |= seal_wanted(&page[i], self);
			done |= page[i].direction == FZN_MESSAGE_OUT && page[i].state != 0u
			        && memcmp(page[i].device, self, FZN_PUBKEY_LEN) == 0;
		}
		if (wanted)
			at_pages[n_pages++] = offset;
		offset += count;
		if (!count)
			break;
	}
	/* DEEPEST FIRST, and in each OLDEST FIRST: the page is newest first. */
	for (k = n_pages; k-- > 0;) {
		if (fzn_messages_page(&node_messages.m, g->id, at_pages[k], page, FZN_MESSAGES_PAGE_MAX,
		                      &count, &more)
		    != FZN_MESSAGES_OK)
			break;
		for (i = count; i-- > 0;) {
			const fzn_message_t *p = &page[i];

			if (!seal_wanted(p, self)
			    || fzn_group_lines_head(&group_lines, g->id, self, &head) != FZN_GROUP_LINES_OK)
				continue;
			memset(&line, 0, sizeof(line));
			memcpy(line.group, g->id, FZN_GROUP_ID_LEN);
			line.epoch = g->epoch;
			memcpy(line.sender, own->owner, FZN_PUBKEY_LEN);
			memcpy(line.host, self, FZN_PUBKEY_LEN);
			memcpy(line.id, p->id, FZN_GROUP_LINE_ID_LEN);
			line.stime = p->stime;
			memcpy(line.text, p->text, p->text_len);
			line.text_len = p->text_len;
			if (fzn_group_line_seal(&line, secret, contact_hash_ops, contact_aead_ops,
			                        contact_rng_ops, bytes, sizeof(bytes), &len)
			            != FZN_GROUP_LINE_OK
			    || fzn_group_lines_put(&group_lines, head.have + 1u, bytes, len)
			               != FZN_GROUP_LINES_OK
			    || fzn_group_lines_filed(&group_lines, g->id, self, head.have + 1u)
			               != FZN_GROUP_LINES_OK) {
				k = 0;
				break;
			}
			(void)fzn_messages_mark(&node_messages.m, g->id, FZN_MESSAGE_OUT, p->id,
			                        FZN_MESSAGE_DELIVERED);
			sealed++;
		}
	}
	fzn_wipe(secret, sizeof(secret));
	return sealed;
}

/* THE LINES HELD AND NOT YET FILED in group `g`, filed: opened under their
 * epoch's secret, admitted, and written into the group's conversation as
 * IN under their filed id with their sender kept -- unless this user wrote
 * them, whose own devices carry them already. A line whose epoch's secret
 * is not here yet waits for it; one that will not open or is not admitted
 * is passed over. */
static size_t group_file(const fzn_group_t *g, const fzn_contact_device_t *own)
{
	static fzn_group_line_head_t heads[FZN_GROUP_HOSTS_MAX];
	static uint8_t bytes[FZN_GROUP_LINE_MAX];
	static fzn_group_line_t line;
	uint8_t secret[FZN_GROUP_SECRET_LEN], filed_id[FZN_GROUP_LINE_ID_LEN];
	size_t n = 0, i, len = 0, filed = 0;
	uint32_t s;

	if (fzn_group_lines_heads(&group_lines, g->id, heads, FZN_GROUP_HOSTS_MAX, &n)
	    != FZN_GROUP_LINES_OK)
		return 0;
	for (i = 0; i < n; i++) {
		/* FROM THE BASE, sec 664: none below it is held. */
		for (s = (heads[i].filed > heads[i].base ? heads[i].filed : heads[i].base) + 1u;
		     s <= heads[i].have; s++) {
			int written = 0;

			if (fzn_group_lines_get(&group_lines, g->id, heads[i].host, s, bytes, sizeof(bytes),
			                        &len)
			            != FZN_GROUP_LINES_OK
			    || fzn_group_line_peek(bytes, len, &line) != FZN_GROUP_LINE_OK
			    || fzn_node_groups_secret(&node_groups, g->id, line.epoch, secret)
			               != FZN_GROUP_LOG_OK)
				break;
			if (fzn_group_line_open(bytes, len, secret, contact_hash_ops, contact_aead_ops, &line)
			            == FZN_GROUP_LINE_OK
			    && fzn_group_line_admit(g, &line) == FZN_GROUP_LINE_OK
			    && memcmp(line.sender, own->owner, FZN_PUBKEY_LEN) != 0
			    && fzn_group_lines_filed_id(contact_hash_ops, line.host, line.id, filed_id)
			    && fzn_group_lines_sender_keep(&group_lines, g->id, filed_id, line.sender)
			               == FZN_GROUP_LINES_OK
			    && fzn_messages_import(&node_messages.m, g->id, FZN_MESSAGE_IN, filed_id,
			                           line.stime, (const char *)line.text, line.text_len,
			                           &written)
			               == FZN_MESSAGES_OK)
				filed += written != 0;
			if (fzn_group_lines_filed(&group_lines, g->id, heads[i].host, s)
			    != FZN_GROUP_LINES_OK)
				break;
		}
	}
	fzn_wipe(secret, sizeof(secret));
	fzn_wipe(&line, sizeof(line));
	return filed;
}

/* ---- a group's shares, sec 630 ----------------------------------------------- */

/* EVERY OTHER MEMBER'S HOSTS, paired as a contact's devices are, and asked
 * for what their members share with the group: every host its group lists
 * that says where it is reached, all at once, into the member's one tree.
 * Not the first alone (sec 630 asked one): a member whose first-listed
 * device is off shared nothing until it came back. sec 641. */
static struct share_target group_shares_in[FZND_GROUP_SHARES_MAX];
static size_t ngroup_shares_in;

/* `h`'s HOST act's signer: its record, and where it is reached. */
static int group_host_device(const fzn_group_t *g, const fzn_group_host_t *h,
                             fzn_contact_device_t *out)
{
	static uint8_t bytes[FZN_GROUP_ACT_MAX];
	static fzn_group_act_t a;
	size_t len = 0;

	if (fzn_group_log_act(&node_groups.log, g->id, h->seq, bytes, sizeof(bytes), &len)
	            != FZN_GROUP_LOG_OK
	    || fzn_group_act_decode(bytes, len, &a) != FZN_GROUP_ACT_OK
	    || memcmp(fzn_contact_device_key(&a.signer), h->key, FZN_PUBKEY_LEN) != 0)
		return 0;
	*out = a.signer;
	return 1;
}

/* EVERY OTHER MEMBER'S HOSTS, paired and opened afresh from the log as it
 * stands: at the groups round's start, to sync the log with (sec 642), and
 * again for the share pass, after the round's acts are taken. */
static void member_targets_build(uint64_t now)
{
	static uint8_t ids[FZN_GROUPS_HELD_MAX][FZN_GROUP_ID_LEN];
	static fzn_group_t g;
	static fzn_contact_device_t own, d;
	size_t n = 0, i, k, paired = 0;
	const char *why;

	for (i = 0; i < ngroup_shares_in; i++) {
		if (group_shares_in[i].pt.fd >= 0)
			fzn_udp_close(group_shares_in[i].pt.fd);
		fzn_wipe(&group_shares_in[i].pt.pairing, sizeof(group_shares_in[i].pt.pairing));
	}
	ngroup_shares_in = 0;
	if (!running_admin || !contact_id || !running_admin->state->config.has_share
	    || !groups_signer(NULL, &own)
	    || fzn_group_log_list(node_apply.store, ids, FZN_GROUPS_HELD_MAX, &n) != FZN_GROUP_LOG_OK)
		return;
	for (i = 0; i < n; i++) {
		if (fzn_group_log_get(node_apply.store, ids[i], &g) != FZN_GROUP_LOG_OK
		    || !fzn_group_is_member(&g, own.owner))
			continue;
		for (k = 0; k < g.n_hosts; k++) {
			const fzn_group_host_t *h = &g.hosts[k];
			struct share_target *sh = &group_shares_in[ngroup_shares_in];
			int r;

			if (memcmp(h->owner, own.owner, FZN_PUBKEY_LEN) == 0
			    || !fzn_group_is_member(&g, h->owner) || !group_host_device(&g, h, &d))
				continue;
			/* PAIRED as this host's: it asks here as its member. */
			r = fzn_node_admin_pair_group_host(running_admin, &d, &why);
			paired += r > 0;
			if (r < 0)
				say(FZN_ENTRY_DEBUG, "node/groups", "a member's host was not paired: %s",
				    why ? why : "it would not pair");
			/* ASKED, every host of the member that is reached somewhere. */
			if (ngroup_shares_in == FZND_GROUP_SHARES_MAX || !d.port || !d.address_len
			    || d.address_len > FZN_NODE_RECEIVED_HOST_MAX)
				continue;
			memset(sh, 0, sizeof(*sh));
			sh->pt.fd = -1;
			memcpy(sh->host, d.address, d.address_len);
			sh->host[d.address_len] = '\0';
			memcpy(sh->sharer, h->owner, FZN_PUBKEY_LEN);
			sh->pt.host = sh->host;
			sh->pt.port = d.port;
			if (fzn_node_pairing_derive(contact_id, d.record,
			                            &running_admin->state->config.share_capability, now,
			                            &sh->pt.pairing)
			            != FZN_NODE_PAIR_OK
			    || !open_target(&sh->pt, contact_family, contact_id->pubkey, contact_hash_ops,
			                    contact_aead_ops, contact_rng_ops))
				continue;
			ngroup_shares_in++;
		}
	}
	if (paired)
		say(FZN_ENTRY_INFO, "node/groups", "%zu member host(s) paired", paired);
}

static void group_shares_round(uint64_t now)
{
	member_targets_build(now);
	shares_start(group_shares_in, ngroup_shares_in, 0, now);
}

/* THE LINES ROUND, sec 629, after the acts and the tending: this host's own
 * new lines sealed; every sibling, and one host of each contact, asked for
 * the lines past this host's heads in each group the two share; and what
 * arrived filed. */
/* ---- A GROUP'S LINES, conversations of the round, sec 636: one with
 * each sibling, and with each contact host chosen for a group, every peer
 * at once and each peer's groups in turn -- so the conversations are as
 * many as the peers, whatever the groups. */
#define FZND_LINES_REQUEST_MAX (3u + FZN_GROUP_ID_LEN + FZND_GROUP_HEADS_MAX * FZND_GROUP_HEAD_LEN)

static uint8_t lines_groups[FZN_GROUPS_HELD_MAX][FZN_GROUP_ID_LEN];
static size_t n_lines_groups, lines_sealed, lines_taken;
static int lines_on;

struct lines_talk {
	fzn_node_talk_t talk;
	struct meter m;
	struct pull_target *pt;
	uint16_t groups[FZN_GROUPS_HELD_MAX]; /* places in `lines_groups` */
	size_t n, at;
	int silences;
	uint8_t request[FZND_LINES_REQUEST_MAX];
};
static struct lines_talk lines_talks[FZND_ROUND_TARGETS_MAX + FZND_CONTACT_TARGETS_MAX
                                     + FZND_GROUP_SHARES_MAX];
static size_t n_lines_talks;

/* THE NEXT GROUP's request, from `lt->at` on; 0 when none is left. */
static int lines_next(struct lines_talk *lt, uint8_t *request, size_t *len)
{
	for (; lt->at < lt->n; lt->at++)
		if ((*len = group_lines_request(lines_groups[lt->groups[lt->at]], request)) != 0)
			return 1;
	return 0;
}

static int lines_talk_step(void *ctx, const uint8_t *reply, size_t reply_len, uint8_t *request,
                           size_t cap, size_t *request_len)
{
	struct lines_talk *lt = ctx;

	(void)cap;
	meter_answer(&lt->m, reply, reply_len);
	if (!reply)
		return 0;
	lines_taken += group_lines_take(reply, reply_len);
	lt->at++;
	if (!lines_next(lt, request, request_len))
		return 0;
	meter_asked(&lt->m, *request_len);
	return 1;
}

/* THE CONVERSATION WITH `pt`, found or made. */
static struct lines_talk *lines_talk_for(struct pull_target *pt, int silences)
{
	size_t i;

	for (i = 0; i < n_lines_talks; i++)
		if (lines_talks[i].pt == pt)
			return &lines_talks[i];
	if (n_lines_talks == sizeof(lines_talks) / sizeof(lines_talks[0]))
		return NULL;
	lines_talks[n_lines_talks].pt = pt;
	lines_talks[n_lines_talks].n = 0;
	lines_talks[n_lines_talks].at = 0;
	lines_talks[n_lines_talks].silences = silences;
	return &lines_talks[n_lines_talks++];
}

/* EVERY GROUP THIS USER IS IN: its own lines sealed, then its lines asked
 * of each sibling and of one host of each contact in it. */
static void group_lines_start(struct pull_target *pulls, size_t npulls, uint64_t now)
{
	static uint8_t ids[FZN_GROUPS_HELD_MAX][FZN_GROUP_ID_LEN];
	static fzn_group_t g;
	static fzn_contact_device_t own;
	uint8_t done[FZND_CONTACT_TARGETS_MAX][FZN_PUBKEY_LEN];
	size_t n = 0, i, j, k, ndone, len;

	n_lines_groups = lines_sealed = lines_taken = n_lines_talks = 0;
	lines_on = 0;
	if (!group_lines.store || !contact_hash_ops || !contact_aead_ops || !contact_rng_ops
	    || !groups_signer(NULL, &own)
	    || fzn_group_log_list(node_apply.store, ids, FZN_GROUPS_HELD_MAX, &n) != FZN_GROUP_LOG_OK)
		return;
	lines_on = 1;
	for (i = 0; i < n; i++) {
		size_t gi;
		struct lines_talk *lt;

		if (fzn_group_log_get(node_apply.store, ids[i], &g) != FZN_GROUP_LOG_OK
		    || !fzn_group_is_member(&g, own.owner))
			continue;
		lines_sealed += group_seal_own(&g, &own);
		gi = n_lines_groups;
		memcpy(lines_groups[n_lines_groups++], g.id, FZN_GROUP_ID_LEN);
		for (j = 0; j < npulls; j++)
			if (!silent_peer(&pulls[j]) && peer_in_estate(&pulls[j])
			    && (lt = lines_talk_for(&pulls[j], 1)) != NULL)
				lt->groups[lt->n++] = (uint16_t)gi;
		for (j = 0, ndone = 0; j < ncontact_targets; j++) {
			struct contact_target *ct = &contact_targets[j];

			for (k = 0; k < ndone && memcmp(done[k], ct->contact, FZN_PUBKEY_LEN) != 0; k++)
				;
			if (k < ndone || ct->down || ct->pt.fd < 0 || !fzn_group_is_member(&g, ct->contact))
				continue;
			if ((lt = lines_talk_for(&ct->pt, 0)) != NULL)
				lt->groups[lt->n++] = (uint16_t)gi;
			memcpy(done[ndone++], ct->contact, FZN_PUBKEY_LEN);
		}
		/* EVERY MEMBER'S HOST the groups round opened, sec 643: a line
		 * reached a member who is no contact only through a contact in
		 * common, as the log's acts did before sec 642. */
		for (j = 0; j < ngroup_shares_in; j++) {
			struct share_target *sh = &group_shares_in[j];

			if (sh->pt.fd < 0 || !fzn_group_is_member(&g, sh->sharer))
				continue;
			if ((lt = lines_talk_for(&sh->pt, 0)) != NULL)
				lt->groups[lt->n++] = (uint16_t)gi;
		}
	}
	for (i = 0; i < n_lines_talks; i++) {
		struct lines_talk *lt = &lines_talks[i];

		len = 0;
		if (lines_next(lt, lt->request, &len))
			(void)talk_start_over(&lt->talk, &lt->m, lt->pt, now, lines_talk_step,
			                      round_talk_over, lt->silences, lt, lt->request,
			                      sizeof(lt->request), len);
	}
}

/* THE LINES PASS'S END: each group's lines filed, and said. */
static void group_lines_settle(void)
{
	static fzn_group_t g;
	static fzn_contact_device_t own;
	size_t i, filed = 0;

	if (!lines_on || !groups_signer(NULL, &own))
		return;
	for (i = 0; i < n_lines_groups; i++)
		if (fzn_group_log_get(node_apply.store, lines_groups[i], &g) == FZN_GROUP_LOG_OK)
			filed += group_file(&g, &own);
	if (lines_sealed || lines_taken || filed)
		say(FZN_ENTRY_INFO, "node/groups", "lines pass: %zu sealed, %zu taken, %zu filed",
		    lines_sealed, lines_taken, filed);
}

/* THE GROUPS ROUND, sec 626: every sibling, and one host of each contact
 * who is in a group held here, asked for what it has. */

static void group_round(struct pull_target *pulls, size_t npulls, uint64_t now)
{
	uint8_t done[FZND_CONTACT_TARGETS_MAX][FZN_PUBKEY_LEN];
	size_t ndone = 0, i, k;

	static unsigned idle_rounds;
	static uint8_t held[FZN_GROUPS_HELD_MAX][FZN_GROUP_ID_LEN];
	size_t n_held = 0;

	n_group_sync_talks = 0;
	lines_on = 0;
	if (!running_admin || !contact_id || !node_apply.store || !node_groups.log.store)
		return;
	/* A HOST HOLDING NO GROUP asks its siblings every tenth round, not
	 * every round, sec 631: a request each sibling answers while its own
	 * single-threaded round waits on others is not free, and measured in
	 * `live_erasure.py` it took a six-host round past half a minute. A new
	 * device learns its user's groups within ten rounds; one holding any
	 * asks every round. A listing that fails counts as holding some. */
	if (fzn_group_log_list(node_apply.store, held, FZN_GROUPS_HELD_MAX, &n_held)
	            != FZN_GROUP_LOG_OK
	    || n_held > 0u || idle_rounds++ % 10u == 0u)
		for (i = 0; i < npulls; i++)
			if (!silent_peer(&pulls[i]) && peer_in_estate(&pulls[i]))
				group_sync_start(&pulls[i], estate_owner(), 1, now);
	for (i = 0; i < ncontact_targets; i++) {
		struct contact_target *ct = &contact_targets[i];

		for (k = 0; k < ndone && memcmp(done[k], ct->contact, FZN_PUBKEY_LEN) != 0; k++)
			;
		if (k < ndone || ct->down || ct->pt.fd < 0)
			continue;
		group_sync_start(&ct->pt, ct->contact, 0, now);
		memcpy(done[ndone++], ct->contact, FZN_PUBKEY_LEN);
	}
	/* EVERY MEMBER'S HOST, sec 642, each a conversation of the round --
	 * opened here from the log held, not left from the last share pass,
	 * which a daemon just started has not run: a member's host otherwise learns another
	 * member's acts only through a contact, and a contact knows a user's
	 * hosts only from that user's -- so with one host of a member down,
	 * its other hosts' acts reached nobody who was not that user's
	 * contact. Every host, not one per member, for that reason. */
	member_targets_build(now);
	for (i = 0; i < ngroup_shares_in; i++)
		if (group_shares_in[i].pt.fd >= 0)
			group_sync_start(&group_shares_in[i].pt, group_shares_in[i].sharer, 0, now);
}

/* THE GROUPS ROUND'S END, once its siblings have answered: what came taken
 * stock of, and this host's duties done. */
static void group_settle(struct pull_target *pulls, size_t npulls, uint64_t now)
{
	size_t i, taken = 0;

	if (!running_admin || !contact_id || !node_apply.store || !node_groups.log.store)
		return;
	for (i = 0; i < n_group_sync_talks; i++)
		taken += group_sync_talks[i].taken;
	group_redo_all();
	/* THIS HOST'S DUTIES to every group held, sec 627: named among its
	 * hosts, the epoch's secret drawn, sealed, backfilled, opened. */
	{
		static uint8_t ids[FZN_GROUPS_HELD_MAX][FZN_GROUP_ID_LEN];
		size_t n = 0, made = 0, one;

		if (fzn_group_log_list(node_apply.store, ids, FZN_GROUPS_HELD_MAX, &n) == FZN_GROUP_LOG_OK)
			for (i = 0; i < n; i++)
				if (fzn_node_groups_tend(&node_groups, ids[i], &one) == FZN_GROUP_LOG_OK)
					made += one;
		if (made)
			say(FZN_ENTRY_INFO, "node/groups", "%zu group act(s) made tending", made);
	}
	if (taken)
		say(FZN_ENTRY_INFO, "node/groups", "group pass: %zu act(s) taken", taken);
	/* THE LINES ASKED, the round waiting; `group_lines_settle` files them. */
	group_lines_start(pulls, npulls, now);
}

/* ---- app streams, sec 632 --------------------------------------------------------
 *
 * STREAM_QUERY, type 43, asks a host for its own records of one stream past
 * a place; STREAM_RECORDS, type 44, answers them oldest first, each at the
 * level the asker may read -- every level for this user's own hosts, the
 * granted one for a contact or a group member, nothing without a grant.
 * One question a requester every two seconds. */
#define FZND_STREAM_QUERY_TYPE 43u
#define FZND_STREAM_RECORDS_TYPE 44u
#define FZND_STREAM_EVERY_S 2u
#define FZND_STREAM_ASKERS 32u
#define FZND_STREAM_FETCHES_MAX 8u

static fzn_streams_t node_streams;
static struct {
	uint8_t key[FZN_PUBKEY_LEN];
	uint64_t at;
} stream_askers[FZND_STREAM_ASKERS];
/* `fetch stream NAME [WHO]` asked, carried out at the loop's next turn. */
static struct {
	char name[FZN_STREAM_NAME_MAX + 1u];
	size_t name_len;
	uint8_t who[FZN_PUBKEY_LEN]; /* a contact's root, a group's id, or zero: own hosts */
	int group;
} stream_fetches[FZND_STREAM_FETCHES_MAX];
static size_t n_stream_fetches;

/* WHOSE `host` IS as one of this user's groups lists it (sec 630). */
static int member_host_owner(const uint8_t *host, uint8_t owner[FZN_PUBKEY_LEN])
{
	static fzn_contact_device_t own;

	return node_apply.store && groups_signer(NULL, &own)
	       && fzn_node_group_host_owner(node_apply.store, own.owner, host, owner);
}

static int hexval(uint8_t c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/* ONE QUESTION A REQUESTER every FZND_STREAM_EVERY_S: 1 when this one may. */
static int stream_ask_allowed(const uint8_t *key, uint64_t now)
{
	size_t i, oldest = 0;

	for (i = 0; i < FZND_STREAM_ASKERS; i++) {
		if (memcmp(stream_askers[i].key, key, FZN_PUBKEY_LEN) == 0) {
			if (now < stream_askers[i].at + FZND_STREAM_EVERY_S && now >= stream_askers[i].at)
				return 0;
			stream_askers[i].at = now;
			return 1;
		}
		if (stream_askers[i].at < stream_askers[oldest].at)
			oldest = i;
	}
	memcpy(stream_askers[oldest].key, key, FZN_PUBKEY_LEN);
	stream_askers[oldest].at = now;
	return 1;
}

/* A STREAM GRANT IS THE USER'S, sec 660, the holder's of 2026-10-20 for
 * every stream (fuzzypickles' sec 103 had it for location): kept as an
 * estate setting, `stream/grant/` and 32 hex of a hash of the stream's name
 * and the grantee, its value the level -- carried to every host of the
 * estate in the journal, under the settings' authority -- not in one
 * host's slot 61. */
#define STREAM_GRANT_KEY_LEN (13u + 32u)
static int stream_grant_key(const char *name, size_t name_len, const uint8_t *who,
                            uint8_t key[STREAM_GRANT_KEY_LEN])
{
	uint8_t input[FZN_STREAM_NAME_MAX + 1u + FZN_PUBKEY_LEN], digest[16];
	char hex[33];

	if (!contact_hash_ops || name_len > FZN_STREAM_NAME_MAX)
		return 0;
	memcpy(input, name, name_len);
	input[name_len] = '/';
	memcpy(input + name_len + 1u, who, FZN_PUBKEY_LEN);
	if (!contact_hash_ops->hash(contact_hash_ops->ctx, digest, sizeof(digest), input,
	                            name_len + 1u + FZN_PUBKEY_LEN))
		return 0;
	hex_of(digest, sizeof(digest), hex);
	memcpy(key, "stream/grant/", 13u);
	memcpy(key + 13u, hex, 32u);
	return 1;
}

/* THE LEVEL `who` IS GRANTED of `name`: the estate's setting, or a grant
 * this host kept before sec 660 in its own slot. 1 with it in `*level`. */
static int stream_granted(const char *name, size_t name_len, const uint8_t *who,
                          unsigned *level)
{
	uint8_t key[STREAM_GRANT_KEY_LEN], value[FZN_SETTING_VALUE_MAX];
	size_t len = 0;
	fzn_setting_rank_t rank;

	if (node_settings.store && node_settings.estate && stream_grant_key(name, name_len, who, key)
	    && fzn_node_settings_get(&node_settings, FZN_SCOPE_ESTATE, node_settings.estate, key,
	                             sizeof(key), value, &len, &rank)
	    && len == 1u && value[0] >= '0' && value[0] < (uint8_t)('0' + FZN_STREAM_LEVELS_MAX)) {
		*level = (unsigned)(value[0] - '0');
		return 1;
	}
	return fzn_streams_granted(&node_streams, name, name_len, who, level) == FZN_STREAMS_OK;
}

/* THE LEVEL `owner` MAY READ of stream `name`: its own grant, or the
 * finest of the groups' it is in. -1 for none. */
static int stream_level_of(const char *name, size_t name_len, const uint8_t *owner)
{
	static uint8_t groups[FZN_GROUPS_HELD_MAX][FZN_GROUP_ID_LEN];
	unsigned level;
	int best = -1;
	size_t n = 0, i;

	if (stream_granted(name, name_len, owner, &level))
		best = (int)level;
	if (fzn_node_group_ids_of(node_apply.store, owner, groups, FZN_GROUPS_HELD_MAX, &n)
	    == FZN_CONTACT_OK)
		for (i = 0; i < n; i++)
			if (stream_granted(name, name_len, groups[i], &level)
			    && (best < 0 || (int)level < best))
				best = (int)level;
	return best;
}

static size_t put_record(const fzn_stream_record_t *r, uint8_t *out, size_t at, size_t cap)
{
	size_t k, need = 8u + 8u + 1u;

	for (k = 0; k < r->levels; k++)
		need += 1u + r->rendition_len[k];
	if (at + need > cap)
		return at;
	fzn_put_be64(out + at, r->seq);
	fzn_put_be64(out + at + 8u, r->at);
	out[at + 16u] = (uint8_t)r->levels;
	at += 17u;
	for (k = 0; k < r->levels; k++) {
		out[at++] = (uint8_t)r->rendition_len[k];
		memcpy(out + at, r->rendition[k], r->rendition_len[k]);
		at += r->rendition_len[k];
	}
	return at;
}

static size_t streams_remote(const uint8_t *sender, const uint8_t *request, size_t request_len,
                             uint8_t *reply, size_t reply_cap)
{
	static fzn_stream_record_t r, given;
	uint8_t owner[FZN_PUBKEY_LEN];
	size_t name_len, at = 4u, count = 0;
	size_t cap = reply_cap < FZND_PULL_REPLY_MAX ? reply_cap : FZND_PULL_REPLY_MAX;
	const char *name;
	uint64_t since, last, s, now = wall_clock();
	int own, level;

	if (request_len < 3u || request_len != 3u + (size_t)request[2] + 8u
	    || !fzn_stream_name_ok((const char *)request + 3, request[2]))
		return (size_t)snprintf((char *)reply, reply_cap, "malformed a stream query\n");
	name = (const char *)request + 3;
	name_len = request[2];
	since = fzn_get_be64(request + 3u + name_len);
	if (!contact_id || !node_streams.store
	    || (!group_owner_of(sender, owner, &own) && !member_host_owner(sender, owner)))
		return (size_t)snprintf((char *)reply, reply_cap, "denied streams to whom it grants\n");
	level = own ? 0 : stream_level_of(name, name_len, owner);
	if (level < 0)
		return (size_t)snprintf((char *)reply, reply_cap, "denied that stream is not granted\n");
	if (!stream_ask_allowed(sender, now))
		return (size_t)snprintf((char *)reply, reply_cap, "denied asked too soon\n");
	/* THIS HOST'S OWN STREAM, never another's it holds. */
	last = fzn_streams_last(&node_streams, name, name_len, contact_id->pubkey);
	for (s = since + 1u; s <= last && cap > at; s++) {
		size_t before = at;

		if (fzn_streams_get(&node_streams, name, name_len, contact_id->pubkey, s, &r)
		    != FZN_STREAMS_OK)
			continue;
		if (!own)
			fzn_streams_render(&r, (unsigned)level, &given);
		at = put_record(own ? &r : &given, reply, at, cap);
		if (at == before)
			break;
		count++;
	}
	reply[0] = FZND_GROUP_VERSION;
	reply[1] = FZND_STREAM_RECORDS_TYPE;
	fzn_put_be16(reply + 2, (uint16_t)count);
	return at;
}

/* ASK ONE HOST for its records of stream `name` past those held of it. */
/* STREAM_QUERY for stream `name` of `origin`, past what is held of it. Its
 * length. */
static size_t stream_query(const char *name, size_t name_len, const uint8_t *origin,
                           uint8_t *request)
{
	request[0] = FZND_GROUP_VERSION;
	request[1] = FZND_STREAM_QUERY_TYPE;
	request[2] = (uint8_t)name_len;
	memcpy(request + 3, name, name_len);
	fzn_put_be64(request + 3u + name_len, fzn_streams_last(&node_streams, name, name_len, origin));
	return 3u + name_len + 8u;
}

/* STREAM_RECORDS from `origin`'s host, kept: how many. */
static size_t stream_take(const char *name, size_t name_len, const uint8_t *origin,
                          const uint8_t *reply, size_t len)
{
	static fzn_stream_record_t r;
	size_t at, count, k, l, taken = 0;

	if (!reply || len < 4u || reply[0] != FZND_GROUP_VERSION
	    || reply[1] != FZND_STREAM_RECORDS_TYPE)
		return 0;
	count = fzn_get_be16(reply + 2);
	for (k = 0, at = 4u; k < count && at + 17u <= len; k++) {
		memset(&r, 0, sizeof(r));
		r.seq = fzn_get_be64(reply + at);
		r.at = fzn_get_be64(reply + at + 8u);
		r.levels = reply[at + 16u];
		at += 17u;
		if (r.levels == 0u || r.levels > FZN_STREAM_LEVELS_MAX)
			break;
		for (l = 0; l < r.levels; l++) {
			if (at >= len || reply[at] > FZN_STREAM_RENDITION_MAX || len - at - 1u < reply[at])
				return taken;
			r.rendition_len[l] = reply[at++];
			memcpy(r.rendition[l], reply + at, r.rendition_len[l]);
			at += r.rendition_len[l];
		}
		taken += fzn_streams_keep(&node_streams, name, name_len, origin, &r) == FZN_STREAMS_OK;
	}
	return taken;
}

/* ---- A HOST ASKED ITS ITEMS IN TURN, every host at once, sec 636: where
 * it sees this host (`fetch address`), or the streams asked of it (`fetch
 * stream`). A conversation each, at most FZND_HOST_TALKS_AT_ONCE awaited and
 * the rest begun as those end, so the asks table is never the limit. */
#define FZND_HOST_TALKS_MAX                                                                   \
	(FZND_ROUND_TARGETS_MAX + FZN_NODE_RECEIVED_MAX + FZND_CONTACT_TARGETS_MAX               \
	 + FZND_GROUP_SHARES_MAX)
#define FZND_HOST_TALKS_AT_ONCE 32u
#define FZND_FILE_REFS_REQUEST_MAX (3u + 32u * FZN_BLOB_HASH_LEN)
#define FZND_HOST_REQUEST_MAX                                                                 \
	(FZND_FILE_REFS_REQUEST_MAX > 3u + FZN_STREAM_NAME_MAX + 8u ? FZND_FILE_REFS_REQUEST_MAX     \
	                                                             : 3u + FZN_STREAM_NAME_MAX + 8u)
_Static_assert(FZND_HOST_TALKS_AT_ONCE <= FZN_NODE_ASKS_MAX, "the host talks fit the asks table");

enum { HOST_ADDRESS = 1, HOST_STREAMS = 2, HOST_ROUTING = 3, HOST_FILE_REFS = 4 };

struct host_talk {
	fzn_node_talk_t talk;
	struct meter m;
	struct pull_target *pt;
	int kind, silences;
	size_t items[FZND_STREAM_FETCHES_MAX]; /* stream fetches, by place */
	size_t n_items, at;
	uint64_t now;
	uint8_t request[FZND_HOST_REQUEST_MAX];
};
static struct host_talk host_talks[FZND_HOST_TALKS_MAX];
/* THE ONE REQUEST every host is asked, for the kinds that share one. */
static uint8_t host_shared_request[FZND_HOST_REQUEST_MAX];
static size_t host_shared_len, file_refs_taken;
static size_t n_host_talks, host_talks_begun, streams_asked, streams_taken, streams_begun;

/* ITEM `ht->at`'s REQUEST. */
static size_t host_request(struct host_talk *ht)
{
	size_t f = ht->items[ht->at];

	if (ht->kind == HOST_ADDRESS) {
		memcpy(ht->request, "get address", 11u);
		return 11u;
	}
	if (ht->kind == HOST_ROUTING || ht->kind == HOST_FILE_REFS) {
		memcpy(ht->request, host_shared_request, host_shared_len);
		return host_shared_len;
	}
	streams_asked++;
	return stream_query(stream_fetches[f].name, stream_fetches[f].name_len, ht->pt->pairing.node,
	                    ht->request);
}

static void routing_answer(const char *host, const uint8_t *reply, size_t reply_len,
                           uint64_t now);
static void file_refs_take(const uint8_t *reply, size_t reply_len);

static int host_talk_step(void *ctx, const uint8_t *reply, size_t reply_len, uint8_t *request,
                          size_t cap, size_t *request_len)
{
	struct host_talk *ht = ctx;

	(void)request;
	(void)cap;
	meter_answer(&ht->m, reply, reply_len);
	if (!reply)
		return 0;
	if (ht->kind == HOST_ADDRESS)
		address_take(ht->pt, reply, reply_len, ht->now);
	else if (ht->kind == HOST_ROUTING)
		routing_answer(ht->pt->host, reply, reply_len, ht->now);
	else if (ht->kind == HOST_FILE_REFS)
		file_refs_take(reply, reply_len);
	else
		streams_taken += stream_take(stream_fetches[ht->items[ht->at]].name,
		                             stream_fetches[ht->items[ht->at]].name_len,
		                             ht->pt->pairing.node, reply, reply_len);
	if (++ht->at >= ht->n_items)
		return 0;
	*request_len = host_request(ht);
	meter_asked(&ht->m, *request_len);
	return 1;
}

static void host_talks_begin(void);

static void host_talk_over(void *ctx)
{
	(void)ctx;
	/* THE NEXT BEGUN BEFORE THIS ONE IS RELEASED, so the step waits for all. */
	host_talks_begin();
	if (round_pending)
		round_pending--;
}

/* EVERY HOST NOT YET BEGUN, while fewer than FZND_HOST_TALKS_AT_ONCE wait. */
static void host_talks_begin(void)
{
	while (host_talks_begun < n_host_talks && round_pending < FZND_HOST_TALKS_AT_ONCE) {
		struct host_talk *ht = &host_talks[host_talks_begun++];
		size_t len = host_request(ht);

		(void)talk_start_over(&ht->talk, &ht->m, ht->pt, ht->now, host_talk_step,
		                      host_talk_over, ht->silences, ht, ht->request,
		                      sizeof(ht->request), len);
	}
}

/* `pt`'S CONVERSATION, found or made. */
static struct host_talk *host_talk_for(struct pull_target *pt, int kind, int silences,
                                       uint64_t now)
{
	size_t i;

	for (i = 0; i < n_host_talks; i++)
		if (host_talks[i].pt == pt)
			return &host_talks[i];
	if (n_host_talks == FZND_HOST_TALKS_MAX)
		return NULL;
	host_talks[n_host_talks].pt = pt;
	host_talks[n_host_talks].kind = kind;
	host_talks[n_host_talks].silences = silences;
	host_talks[n_host_talks].n_items = 0;
	host_talks[n_host_talks].at = 0;
	host_talks[n_host_talks].now = now;
	return &host_talks[n_host_talks++];
}

static void host_add(struct pull_target *pt, int kind, int silences, size_t item, uint64_t now)
{
	struct host_talk *ht = host_talk_for(pt, kind, silences, now);

	if (ht && ht->n_items < FZND_STREAM_FETCHES_MAX)
		ht->items[ht->n_items++] = item;
}

/* EVERY PEER THIS HOST REACHES asked where it sees this host: the estate's
 * pull peers and siblings, and every contact host. Asked when the user asks
 * (`fetch address`), not each round: fuzzypickles' "asking is a button". */
static void address_start(struct pull_target *pulls, size_t npulls, uint64_t now)
{
	size_t i;

	n_host_talks = host_talks_begun = 0;
	for (i = 0; i < npulls; i++)
		if (!silent_peer(&pulls[i]))
			host_add(&pulls[i], HOST_ADDRESS, 1, 0, now);
	for (i = 0; i < nshares_in; i++)
		host_add(&shares_in[i].pt, HOST_ADDRESS, 0, 0, now);
	for (i = 0; i < ncontact_targets; i++)
		host_add(&contact_targets[i].pt, HOST_ADDRESS, 0, 0, now);
	host_talks_begin();
}

static void address_settle(void)
{
	say(FZN_ENTRY_INFO, "net/address", "%zu peer(s) have said where they see this host",
	    n_observed);
}

/* THE FETCHES ASKED, carried out: a contact's hosts, a group's members'
 * hosts, or this user's own -- each asked once. */
static void streams_start(struct pull_target *pulls, size_t npulls, uint64_t now)
{
	static fzn_group_t g;
	static const uint8_t zero[FZN_PUBKEY_LEN];
	size_t f, i;

	n_host_talks = host_talks_begun = 0;
	streams_asked = streams_taken = 0;
	/* THE FETCHES ASKED SO FAR: one asked meanwhile waits for the next. */
	streams_begun = n_stream_fetches;
	for (f = 0; f < streams_begun; f++) {
		if (memcmp(stream_fetches[f].who, zero, FZN_PUBKEY_LEN) == 0) {
			for (i = 0; i < npulls; i++)
				if (!silent_peer(&pulls[i]) && peer_in_estate(&pulls[i]))
					host_add(&pulls[i], HOST_STREAMS, 1, f, now);
			continue;
		}
		if (stream_fetches[f].group
		    && fzn_group_log_get(node_apply.store, stream_fetches[f].who, &g) == FZN_GROUP_LOG_OK) {
			for (i = 0; i < ngroup_shares_in; i++)
				if (fzn_group_is_member(&g, group_shares_in[i].sharer)
				    && group_shares_in[i].pt.fd >= 0)
					host_add(&group_shares_in[i].pt, HOST_STREAMS, 0, f, now);
			continue;
		}
		for (i = 0; i < ncontact_targets; i++)
			if (memcmp(contact_targets[i].contact, stream_fetches[f].who, FZN_PUBKEY_LEN) == 0
			    && contact_targets[i].pt.fd >= 0)
				host_add(&contact_targets[i].pt, HOST_STREAMS, 0, f, now);
	}
	host_talks_begin();
}

/* THE ESTATE'S MANIFEST asked of each peer of it at once, by a member that
 * does not sign it (sec 611; 636). */
static void routing_start(struct pull_target *pulls, size_t npulls, uint64_t now)
{
	size_t t;

	n_host_talks = host_talks_begun = 0;
	memcpy(host_shared_request, "get routing", 11u);
	host_shared_len = 11u;
	for (t = 0; t < npulls; t++)
		if (!silent_peer(&pulls[t]) && peer_in_estate(&pulls[t]))
			host_add(&pulls[t], HOST_ROUTING, 1, 0, now);
	host_talks_begin();
}

/* A `get routing` ANSWER, taken by `routing_take`: copied out,
 * since the take writes a byte past the answer. */
static void routing_answer(const char *host, const uint8_t *reply, size_t reply_len,
                           uint64_t now)
{
	static uint8_t copy[FZND_PULL_REPLY_MAX + 1u];

	if (!node_apply.root || reply_len > FZND_PULL_REPLY_MAX)
		return;
	memcpy(copy, reply, reply_len);
	(void)routing_take(host, copy, reply_len, node_apply.root, now);
}

static void streams_settle(void)
{
	/* THOSE CARRIED OUT GONE, any asked meanwhile kept for the next. */
	memmove(stream_fetches, stream_fetches + streams_begun,
	        (n_stream_fetches - streams_begun) * sizeof(stream_fetches[0]));
	n_stream_fetches -= streams_begun;
	say(FZN_ENTRY_INFO, "node/streams", "stream fetch: %zu host(s) asked, %zu record(s) taken",
	    streams_asked, streams_taken);
}

/* `list device CONTACT|KEY [FROM]`, sec 645: `ok TOTAL FROM KEY,ADDRESS,PORT
 * ...`, the contact's devices this node keeps (sec 614) -- each its host
 * key, and where it says it is reached, `-` and 0 for nowhere -- a page at a
 * time. The contact's own key is a user's; these are its hosts'. The node's
 * own user only. */
static size_t device_local(fzn_origin_t origin, const fzn_request_t *request, char *reply,
                           size_t cap)
{
	static fzn_contact_device_t kept[FZN_CONTACT_DEVICES_MAX];
	static size_t mine[FZN_CONTACT_DEVICES_MAX];
	const uint8_t *at = request->arg, *subject, *w;
	size_t left = request->arg_len, subject_len, w_len, n = 0, count = 0, from = 0, i, out;
	fzn_contact_t c;

	if (request->parsed != FZN_VERB_LIST || !at || !next_word(&at, &left, &subject, &subject_len)
	    || subject_len != 6u || memcmp(subject, "device", 6u) != 0)
		return 0;
	if (origin != FZN_ORIGIN_SAME_USER)
		return (size_t)snprintf(reply, cap, "denied devices need this node's own user\n");
	if (!next_word(&at, &left, &w, &w_len))
		return (size_t)snprintf(reply, cap, "malformed list device CONTACT|KEY [FROM]\n");
	/* A NAME, or THE USER'S KEY as 64 hex: names are this host's alone
	 * (sec 516), and a sibling keeps a contact's devices it has no name
	 * for. */
	if (w_len == FZN_PUBKEY_LEN * 2u) {
		for (i = 0; i < FZN_PUBKEY_LEN; i++) {
			int hi = hexval(w[2u * i]), lo = hexval(w[2u * i + 1u]);

			if (hi < 0 || lo < 0)
				break;
			c.key[i] = (uint8_t)(hi * 16 + lo);
		}
		if (i < FZN_PUBKEY_LEN)
			return (size_t)snprintf(reply, cap, "malformed not hex\n");
	} else if (!node_apply.store
	           || fzn_contact_find(node_apply.store, (const char *)w, w_len, &c)
	                      != FZN_CONTACT_OK) {
		return (size_t)snprintf(reply, cap, "error no such contact\n");
	}
	if (!node_apply.store)
		return (size_t)snprintf(reply, cap, "error this node keeps no devices\n");
	if (next_word(&at, &left, &w, &w_len))
		for (i = 0; i < w_len; i++) {
			if (w[i] < '0' || w[i] > '9' || from > FZN_CONTACT_DEVICES_MAX)
				return (size_t)snprintf(reply, cap, "malformed not an index\n");
			from = (from * 10u) + (size_t)(w[i] - '0');
		}
	if (fzn_contact_device_list(node_apply.store, kept, FZN_CONTACT_DEVICES_MAX, &n)
	    != FZN_CONTACT_DEVICE_OK)
		return (size_t)snprintf(reply, cap, "error the devices did not read\n");
	for (i = 0; i < n; i++)
		if (memcmp(kept[i].owner, c.key, FZN_PUBKEY_LEN) == 0)
			mine[count++] = i;
	if (from > count)
		return (size_t)snprintf(reply, cap, "malformed past the last device\n");
	out = (size_t)snprintf(reply, cap, "ok %zu %zu", count, from);
	for (i = from; i < count; i++) {
		const fzn_contact_device_t *d = &kept[mine[i]];
		char key[FZN_PUBKEY_LEN * 2u + 1u];
		size_t need = 1u + FZN_PUBKEY_LEN * 2u + 1u + (d->address_len ? d->address_len : 1u)
		              + 1u + 5u;

		/* ROOM FOR THIS ONE AND THE NEWLINE, or the page ends here. */
		if (out + need + 2u > cap)
			break;
		hex_of(fzn_contact_device_key(d), FZN_PUBKEY_LEN, key);
		out += (size_t)snprintf(reply + out, cap - out, " %s,%.*s,%u", key,
		                        d->address_len ? (int)d->address_len : 1,
		                        d->address_len ? d->address : "-",
		                        d->address_len ? (unsigned)d->port : 0u);
	}
	return out + (size_t)snprintf(reply + out, cap - out, "\n");
}

/* THE STREAM VERBS, the node's own user's:
 *
 *     add stream NAME HEX [HEX ...]   a record of this host's, a rendition a
 *                                     level, the most exact first: `ok SEQ`
 *     grant stream NAME WHO LEVEL     WHO a contact or @GROUP may read LEVEL,
 *                                     on every host of the user's (sec 660):
 *                                     `ok`, or `ok host` where this host may
 *                                     not set the estate's settings, and the
 *                                     grant is this host's alone
 *     revoke stream NAME WHO          the same, `ok` or `ok host`
 *     get stream NAME WHO             `ok LEVEL`, or `ok none`: what WHO was
 *                                     granted (sec 645)
 *     fetch stream NAME [WHO]         asked at once of WHO's hosts, or of
 *                                     this user's own
 *     list stream NAME                `ok COUNT ORIGIN,SEQ,AT,HEX[,HEX...]
 *                                     ...`, the newest 16 held of each host */
static size_t streams_local(fzn_origin_t origin, const fzn_request_t *request, char *reply,
                            size_t cap)
{
	static fzn_stream_record_t r;
	static uint8_t heads[256][32];
	const uint8_t *at = request->arg, *subject, *name, *w;
	size_t left = request->arg_len, subject_len, name_len, w_len, k;
	uint8_t who[FZN_PUBKEY_LEN];
	int group = 0;

	if (!at || !next_word(&at, &left, &subject, &subject_len) || subject_len != 6u
	    || memcmp(subject, "stream", 6u) != 0)
		return 0;
	if (request->parsed != FZN_VERB_ADD && request->parsed != FZN_VERB_GRANT
	    && request->parsed != FZN_VERB_REVOKE && request->parsed != FZN_VERB_FETCH
	    && request->parsed != FZN_VERB_LIST && request->parsed != FZN_VERB_GET)
		return 0;
	if (origin != FZN_ORIGIN_SAME_USER)
		return (size_t)snprintf(reply, cap, "denied streams need this node's own user\n");
	if (!node_streams.store || !contact_id)
		return (size_t)snprintf(reply, cap, "error this node keeps no streams\n");
	if (!next_word(&at, &left, &name, &name_len)
	    || !fzn_stream_name_ok((const char *)name, name_len))
		return (size_t)snprintf(reply, cap, "malformed name a stream, [a-z0-9_]\n");
	if (request->parsed == FZN_VERB_ADD) {
		memset(&r, 0, sizeof(r));
		while (next_word(&at, &left, &w, &w_len)) {
			if (r.levels == FZN_STREAM_LEVELS_MAX || w_len % 2u
			    || w_len / 2u > FZN_STREAM_RENDITION_MAX)
				return (size_t)snprintf(reply, cap, "malformed at most %u renditions of %u bytes\n",
				                        FZN_STREAM_LEVELS_MAX, FZN_STREAM_RENDITION_MAX);
			for (k = 0; k < w_len / 2u; k++) {
				int hi = hexval(w[2u * k]), lo = hexval(w[2u * k + 1u]);

				if (hi < 0 || lo < 0)
					return (size_t)snprintf(reply, cap, "malformed not hex\n");
				r.rendition[r.levels][k] = (uint8_t)(hi * 16 + lo);
			}
			r.rendition_len[r.levels++] = w_len / 2u;
		}
		if (!r.levels)
			return (size_t)snprintf(reply, cap, "malformed add stream NAME HEX [HEX ...]\n");
		r.seq = fzn_streams_last(&node_streams, (const char *)name, name_len, contact_id->pubkey)
		        + 1u;
		r.at = wall_clock();
		if (fzn_streams_keep(&node_streams, (const char *)name, name_len, contact_id->pubkey, &r)
		    != FZN_STREAMS_OK)
			return (size_t)snprintf(reply, cap, "error the record would not keep\n");
		return (size_t)snprintf(reply, cap, "ok %llu\n", (unsigned long long)r.seq);
	}
	if (request->parsed == FZN_VERB_LIST) {
		size_t n = 0, out, i;
		uint64_t last, s;

		/* EVERY HOST HELD: this one's own, and each fetched from. */
		out = (size_t)snprintf(reply, cap, "ok");
		if (fzn_streams_origins(&node_streams, (const char *)name, name_len, heads, 256u, &n)
		    != FZN_STREAMS_OK)
			return (size_t)snprintf(reply, cap, "error the stream did not list\n");
		for (i = 0; i < n; i++) {
			const uint8_t *o = heads[i];
			char hex[17];

			last = fzn_streams_last(&node_streams, (const char *)name, name_len, o);
			hex_of(o, 8u, hex);
			for (s = last > 16u ? last - 15u : 1u; last && s <= last && out < cap; s++) {
				if (fzn_streams_get(&node_streams, (const char *)name, name_len, o, s, &r)
				    != FZN_STREAMS_OK)
					continue;
				out += (size_t)snprintf(reply + out, cap - out, " %s,%llu,%llu", hex,
				                        (unsigned long long)r.seq, (unsigned long long)r.at);
				for (k = 0; k < r.levels && out < cap; k++) {
					char rendition[2u * FZN_STREAM_RENDITION_MAX + 1u];

					hex_of(r.rendition[k], r.rendition_len[k], rendition);
					out += (size_t)snprintf(reply + out, cap - out, ",%s",
					                        r.rendition_len[k] ? rendition : "-");
				}
			}
		}
		if (out >= cap)
			return (size_t)snprintf(reply, cap, "error the list does not fit a reply\n");
		return out + (size_t)snprintf(reply + out, cap - out, "\n");
	}
	/* WHO: a contact's name, or @GROUP; absent for fetch, this user's own. */
	memset(who, 0, sizeof(who));
	if (next_word(&at, &left, &w, &w_len)) {
		fzn_contact_t c;

		if (w_len > 1u && w[0] == '@') {
			if (fzn_node_group_find(node_apply.store, (const char *)w + 1, w_len - 1u, who)
			    != FZN_CONTACT_OK)
				return (size_t)snprintf(reply, cap, "error no such group\n");
			group = 1;
		} else if (fzn_contact_find(node_apply.store, (const char *)w, w_len, &c)
		           == FZN_CONTACT_OK) {
			memcpy(who, c.key, FZN_PUBKEY_LEN);
		} else {
			return (size_t)snprintf(reply, cap, "error no such contact\n");
		}
	} else if (request->parsed != FZN_VERB_FETCH) {
		return (size_t)snprintf(reply, cap, "malformed name who\n");
	}
	if (request->parsed == FZN_VERB_FETCH) {
		if (n_stream_fetches == FZND_STREAM_FETCHES_MAX)
			return (size_t)snprintf(reply, cap, "error too many fetches waiting\n");
		memcpy(stream_fetches[n_stream_fetches].name, name, name_len);
		stream_fetches[n_stream_fetches].name_len = name_len;
		memcpy(stream_fetches[n_stream_fetches].who, who, FZN_PUBKEY_LEN);
		stream_fetches[n_stream_fetches].group = group;
		n_stream_fetches++;
		return (size_t)snprintf(reply, cap, "ok\n");
	}
	if (request->parsed == FZN_VERB_GET) {
		unsigned level = 0;

		return stream_granted((const char *)name, name_len, who, &level)
		               ? (size_t)snprintf(reply, cap, "ok %u\n", level)
		               : (size_t)snprintf(reply, cap, "ok none\n");
	}
	/* THE USER'S GRANT, sec 660: the estate's setting written -- judged as
	 * any setting is -- and a grant this host kept before in its own slot
	 * taken away, so it cannot outlast a revocation made anywhere. */
	{
		uint8_t key[STREAM_GRANT_KEY_LEN], value;
		unsigned held = 0;
		int had_local = fzn_streams_granted(&node_streams, (const char *)name, name_len, who,
		                                    &held)
		                == FZN_STREAMS_OK;
		fzn_node_settings_err_t serr;

		if (!node_settings.store || !node_settings.estate
		    || !stream_grant_key((const char *)name, name_len, who, key))
			return (size_t)snprintf(reply, cap, "error this node keeps no estate settings\n");
		if (request->parsed == FZN_VERB_REVOKE) {
			if (!stream_granted((const char *)name, name_len, who, &held))
				return (size_t)snprintf(reply, cap, "error no such grant\n");
			if (had_local)
				(void)fzn_streams_grant(&node_streams, (const char *)name, name_len, who, -1);
			serr = fzn_node_settings_write(&node_settings, FZN_SCOPE_ESTATE,
			                               node_settings.estate, key, sizeof(key), 0, NULL, 0u);
			/* A HOST THAT MAY NOT SET THE ESTATE'S still stops serving its own
			 * stream, as fuzzypickles' sec 103 has it -- `ok host`, so its
			 * client can say the others keep what they had. */
			if (serr != FZN_NODE_SETTINGS_OK)
				return had_local ? (size_t)snprintf(reply, cap, "ok host\n")
				                 : (size_t)snprintf(reply, cap, "error %s\n",
				                                    fzn_node_settings_err_str(serr));
			journal_pushed = 1;
			return (size_t)snprintf(reply, cap, "ok\n");
		}
		if (!next_word(&at, &left, &w, &w_len) || w_len != 1u || w[0] < '0'
		    || w[0] >= (int)('0' + FZN_STREAM_LEVELS_MAX))
			return (size_t)snprintf(reply, cap, "malformed grant stream NAME WHO LEVEL\n");
		value = w[0];
		serr = fzn_node_settings_write(&node_settings, FZN_SCOPE_ESTATE, node_settings.estate,
		                               key, sizeof(key), 1, &value, 1u);
		/* REFUSED, THIS HOST ALONE: a host with no authority over the
		 * estate's settings grants its own stream, kept as before sec 660,
		 * and says so -- `ok host` (fuzzypickles' sec 103). */
		if (serr == FZN_NODE_SETTINGS_REFUSED)
			return fzn_streams_grant(&node_streams, (const char *)name, name_len, who,
			                         value - '0')
			               == FZN_STREAMS_OK
			               ? (size_t)snprintf(reply, cap, "ok host\n")
			               : (size_t)snprintf(reply, cap, "error the grant would not keep\n");
		if (serr != FZN_NODE_SETTINGS_OK)
			return (size_t)snprintf(reply, cap, "error %s\n", fzn_node_settings_err_str(serr));
		if (had_local)
			(void)fzn_streams_grant(&node_streams, (const char *)name, name_len, who, -1);
		journal_pushed = 1;
		return (size_t)snprintf(reply, cap, "ok\n");
	}
}

/* ---- the catalogue, sec 633 ------------------------------------------------------
 *
 * EACH ESTATE HOST'S STREAM 4, read from where this run last left it -- from
 * its base at start, which rebuilds the table from what the journal holds --
 * into `node_catalog`. */
static fzn_node_catalog_t node_catalog;
static struct catalog_cursor {
	uint8_t key[FZN_PUBKEY_LEN];
	uint64_t at;
} catalog_cursors[NOTES_STREAMS_MAX];
static size_t n_catalog_cursors;

static void catalog_skip(const uint8_t *issuer, uint64_t to)
{
	size_t k;

	for (k = 0; k < n_catalog_cursors; k++)
		if (memcmp(catalog_cursors[k].key, issuer, FZN_PUBKEY_LEN) == 0
		    && catalog_cursors[k].at < to)
			catalog_cursors[k].at = to;
}

static void index_catalog(void)
{
	static uint8_t bytes[FZN_RECORD_MAX_LEN];
	size_t i, k, taken = 0;

	if (!journal_on)
		return;
	for (i = 0; i < n_notes_keys; i++) {
		struct catalog_cursor *c = NULL;
		uint64_t to = fzn_node_journal_received(&node_journal, notes_keys[i], FZN_CATALOG_STREAM);

		for (k = 0; k < n_catalog_cursors && !c; k++)
			if (memcmp(catalog_cursors[k].key, notes_keys[i], FZN_PUBKEY_LEN) == 0)
				c = &catalog_cursors[k];
		if (!c) {
			if (n_catalog_cursors >= NOTES_STREAMS_MAX)
				break;
			c = &catalog_cursors[n_catalog_cursors++];
			memcpy(c->key, notes_keys[i], FZN_PUBKEY_LEN);
			c->at = fzn_node_journal_base(&node_journal, notes_keys[i], FZN_CATALOG_STREAM) - 1u;
		}
		for (; c->at < to; c->at++) {
			fzn_record_t rec;

			if (fzn_record_store_get(&node_journal.store, notes_keys[i], FZN_CATALOG_STREAM,
			                         c->at + 1u, bytes, sizeof(bytes), &rec)
			    != FZN_RECORD_STORE_OK)
				break;
			taken += fzn_node_catalog_take(&node_catalog, fzn_record_issuer(rec),
			                               fzn_record_subject(rec), fzn_record_seq(rec),
			                               fzn_record_kind(rec), fzn_record_body(rec),
			                               fzn_record_body_len(rec))
			         == FZN_NODE_CATALOG_OK;
		}
	}
	if (taken) {
		say(FZN_ENTRY_INFO, "catalog", "%zu catalogue record(s) taken", taken);
		publish("catalog", NULL);
	}
}

/* THE CATALOGUE VERBS, the node's own user's, sec 633:
 *
 *     add catalog ROOT NAME VALUE   this host asserts NAME of a file it
 *                                   holds: a label, every host's kept apart
 *     remove catalog ROOT NAME      and takes it back
 *     list catalog [ROOT]           `ok COUNT ROOT,NAME,VALUE,ISSUER ...`, the
 *                                   live assertions, each named by its issuer
 *     get catalog ROOT              `ok COUNT ISSUER ...`, the hosts holding it */
/* A CATALOGUE VALUE ON THE SOCKET, sec 652: one word in, %XX for a byte
 * that is a space, a comma, a % or a control, as `add message` takes a
 * text (secs 527, 651); escaped so on the way out, so a file name with a
 * space or a comma is neither cut nor splits a row. */
static int catalog_unescape(const uint8_t *in, size_t n, uint8_t *out, size_t cap, size_t *len)
{
	return fzn_unescape(in, n, out, cap, len); /* local/escape.h, sec 668 */
}

/* A WORD OF DIGITS ALONE as a count, at most a catalogue's worth. */
static int catalog_from(const uint8_t *w, size_t n, size_t *out)
{
	size_t i, v = 0;

	if (!n || n > 6u)
		return 0;
	for (i = 0; i < n; i++) {
		if (w[i] < '0' || w[i] > '9')
			return 0;
		v = (v * 10u) + (size_t)(w[i] - '0');
	}
	*out = v;
	return 1;
}

static size_t catalog_escape(const uint8_t *b, size_t n, char *out, size_t cap)
{
	size_t w = 0;

	/* WHOLE OR NOTHING, as before: a value cut short would read as another. */
	return fzn_escape(b, n, out, cap, &w) == n ? w : 0u;
}

static size_t catalog_local(fzn_origin_t origin, const fzn_request_t *request, char *reply,
                            size_t cap)
{
	static fzn_catalog_assertion_t set[FZN_NODE_CATALOG_MAX];
	static uint8_t plain[FZN_NODE_CATALOG_VALUE_MAX];
	static char shown[3u * FZN_NODE_CATALOG_VALUE_MAX];
	static uint8_t body[FZN_RECORD_MAX_LEN];
	const uint8_t *at = request->arg, *subject, *w, *name = NULL, *value = NULL;
	size_t left = request->arg_len, subject_len, w_len, name_len = 0, value_len = 0, n, i, k, out;
	size_t live = 0, len = 0, from = 0, plain_len = 0;
	uint8_t root[FZN_PUBKEY_LEN];
	int have_root = 0, fact = 0;

	if (!at || !next_word(&at, &left, &subject, &subject_len) || subject_len != 7u
	    || memcmp(subject, "catalog", 7u) != 0)
		return 0;
	if (request->parsed != FZN_VERB_ADD && request->parsed != FZN_VERB_REMOVE
	    && request->parsed != FZN_VERB_LIST && request->parsed != FZN_VERB_GET)
		return 0;
	if (origin != FZN_ORIGIN_SAME_USER)
		return (size_t)snprintf(reply, cap, "denied the catalogue needs this node's own user\n");
	if (!journal_on || !contact_id)
		return (size_t)snprintf(reply, cap, "error this node keeps no catalogue\n");
	if (next_word(&at, &left, &w, &w_len)) {
		/* A LISTING'S FROM, digits alone, sec 652: `list catalog [ROOT]
		 * [FROM]`, a page at a time as `list contact` is. */
		if (request->parsed == FZN_VERB_LIST && catalog_from(w, w_len, &from))
			w = NULL;
		else if (w_len != 2u * FZN_PUBKEY_LEN || !unhex32(w, 2u * FZN_PUBKEY_LEN, root))
			return (size_t)snprintf(reply, cap, "malformed name a file by its root\n");
		else
			have_root = 1;
	}
	if (request->parsed == FZN_VERB_LIST) {
		if (have_root && next_word(&at, &left, &w, &w_len) && !catalog_from(w, w_len, &from))
			return (size_t)snprintf(reply, cap, "malformed list catalog [ROOT] [FROM]\n");
	} else {
		(void)next_word(&at, &left, &name, &name_len);
		(void)next_word(&at, &left, &value, &value_len);
	}
	/* NOTHING PAST THE LAST WORD: a value is one escaped word, sec 652 --
	 * `name Holiday Movie.mp4` kept "Holiday" and dropped the rest. */
	if (next_word(&at, &left, &w, &w_len))
		return (size_t)snprintf(reply, cap, "malformed a value is one word, a space %%20\n");
	index_catalog();
	if (request->parsed == FZN_VERB_GET) {
		static fzn_catalog_issuer_t who[64];
		size_t count = 0, dropped = 0;

		if (!have_root)
			return (size_t)snprintf(reply, cap, "malformed get catalog ROOT\n");
		n = fzn_node_catalog_assertions(&node_catalog, root, set, FZN_NODE_CATALOG_MAX);
		if (fzn_catalog_holders(set, n, root, FZN_PUBKEY_LEN, who, 64u, &count, &dropped)
		    != FZN_CATALOG_OK)
			return (size_t)snprintf(reply, cap, "error the holders did not read\n");
		out = (size_t)snprintf(reply, cap, "ok %zu", count);
		for (i = 0; i < count && out < cap; i++) {
			char hex[17];

			hex_of(who[i].issuer, 8u, hex);
			out += (size_t)snprintf(reply + out, cap - out, " %s", hex);
		}
		return out < cap ? out + (size_t)snprintf(reply + out, cap - out, "\n")
		                 : (size_t)snprintf(reply, cap, "error too many to say\n");
	}
	if (request->parsed == FZN_VERB_LIST) {
		n = fzn_node_catalog_assertions(&node_catalog, have_root ? root : NULL, set,
		                                FZN_NODE_CATALOG_MAX);
		for (i = 0; i < n; i++)
			live += set[i].live != 0;
		if (from > live)
			return (size_t)snprintf(reply, cap, "malformed past the last assertion\n");
		/* `ok TOTAL FROM ROOT,NAME,VALUE,ISSUER ...`, VALUE escaped, as many
		 * as fit: the next page is asked FROM plus those shown (sec 652). */
		out = (size_t)snprintf(reply, cap, "ok %zu %zu", live, from);
		for (i = 0, k = 0; i < n; i++) {
			char entity[2u * FZN_PUBKEY_LEN + 1u], issuer[17], row[600];
			size_t shown_len;
			int r;

			if (!set[i].live || k++ < from)
				continue;
			hex_of(set[i].entity, FZN_PUBKEY_LEN, entity);
			hex_of(set[i].issuer, 8u, issuer);
			shown_len = catalog_escape(set[i].value, set[i].value_len, shown, sizeof(shown));
			r = snprintf(row, sizeof(row), " %s,%.*s,%.*s,%s", entity, (int)set[i].name_len,
			             (const char *)set[i].name, (int)shown_len, shown, issuer);
			/* ROOM FOR THE ROW AND THE NEWLINE, or the page ends here. */
			if (r < 0 || (size_t)r >= sizeof(row) || out + (size_t)r + 2u > cap)
				break;
			memcpy(reply + out, row, (size_t)r);
			out += (size_t)r;
		}
		return out + (size_t)snprintf(reply + out, cap - out, "\n");
	}
	if (!have_root || !name || name_len > FZN_NODE_CATALOG_NAME_MAX
	    || (request->parsed == FZN_VERB_ADD && !value))
		return (size_t)snprintf(reply, cap, request->parsed == FZN_VERB_ADD
		                                        ? "malformed add catalog ROOT NAME VALUE\n"
		                                        : "malformed remove catalog ROOT NAME\n");
	if (request->parsed == FZN_VERB_ADD) {
		fzn_catalog_assertion_t a;
		uint64_t length = 0;

		/* HELD HERE, C5e's HOLDER: a host asserts what it holds. */
		if (!files_on || fzn_node_files_held(&files, root, &length) != FZN_NODE_FILES_OK)
			return (size_t)snprintf(reply, cap, "error that file is not held here\n");
		if (!catalog_unescape(value, value_len, plain, sizeof(plain), &plain_len))
			return (size_t)snprintf(reply, cap, "malformed a value too long, or a bad escape\n");
		/* A DURATION IS A FACT, sec 652, carried as C3's hint: whole
		 * milliseconds, which a holder that derives it supersedes. Every
		 * other name is a label. */
		fact = name_len == 8u && memcmp(name, "duration", 8u) == 0;
		if (fact) {
			for (k = 0; k < plain_len && plain[k] >= '0' && plain[k] <= '9'; k++)
				;
			if (!plain_len || plain_len > 19u || k != plain_len)
				return (size_t)snprintf(reply, cap,
				                        "malformed a duration is whole milliseconds\n");
		}
		memset(&a, 0, sizeof(a));
		a.name = name;
		a.name_len = name_len;
		a.value = plain;
		a.value_len = plain_len;
		a.attr_class = fact ? FZN_CATALOG_FACT : FZN_CATALOG_LABEL;
		a.scope = FZN_CATALOG_ESTATE;
		a.merge = FZN_CATALOG_DISTINCT;
		a.capability = FZN_CATALOG_CAP_HOLDER;
		if (plain_len > FZN_NODE_CATALOG_VALUE_MAX
		    || fzn_catalog_attribute_encode(&a, body, sizeof(body), &len) != FZN_CATALOG_OK)
			return (size_t)snprintf(reply, cap, "malformed a name or value too long\n");
	} else {
		memcpy(body, name, name_len);
		len = name_len;
	}
	if (fzn_node_journal_append_on(&node_journal, contact_id->pubkey, FZN_CATALOG_STREAM,
	                               contact_id->sign,
	                               request->parsed == FZN_VERB_ADD ? FZN_CATALOG_ATTRIBUTE_KIND
	                                                               : FZN_CATALOG_RETRACT_KIND,
	                               root, body, len, wall_ms(), NULL)
	    != FZN_NODE_JOURNAL_OK)
		return (size_t)snprintf(reply, cap, "error the journal would not take it\n");
	index_catalog();
	journal_pushed = 1;
	return (size_t)snprintf(reply, cap, "ok\n");
}

/* ---- the references of the estate's files, sec 634 --------------------------------
 *
 * THE FILE VERBS, with every reference they see kept: a put's answer, and
 * one a fetch or an export is given. And a ROOT where a verb wants a REF is
 * read as the reference held for it, so a host that was told the key by a
 * sibling needs no reference typed: `fetch file ROOT`, `get file ROOT PATH`.
 * `get reference ROOT` answers it, `ok REF`. */
static int unhex_n(const uint8_t *w, size_t n, uint8_t *out, size_t len)
{
	size_t i;

	if (n != 2u * len)
		return 0;
	for (i = 0; i < len; i++) {
		int hi = hexval(w[2u * i]), lo = hexval(w[2u * i + 1u]);

		if (hi < 0 || lo < 0)
			return 0;
		out[i] = (uint8_t)(hi * 16 + lo);
	}
	return 1;
}

static size_t files_local_refs(void *ctx, fzn_origin_t origin, const fzn_request_t *request,
                               char *reply, size_t reply_cap)
{
	static uint8_t arg[FZN_REQUEST_MAX + 2u * FZN_NODE_FILE_REF_LEN];
	uint8_t ref[FZN_NODE_FILE_REF_LEN], root[FZN_BLOB_HASH_LEN];
	const uint8_t *at = request->arg, *subject, *w;
	size_t left = request->arg_len, subject_len, w_len, n;
	fzn_request_t req = *request;
	char hex[2u * FZN_NODE_FILE_REF_LEN + 1u];

	if (!at || !next_word(&at, &left, &subject, &subject_len))
		return fzn_node_files_local(ctx, origin, request, reply, reply_cap);
	/* `get reference ROOT`. */
	if (request->parsed == FZN_VERB_GET && subject_len == 9u
	    && memcmp(subject, "reference", 9u) == 0) {
		if (origin != FZN_ORIGIN_SAME_USER)
			return (size_t)snprintf(reply, reply_cap, "denied references are this user's\n");
		if (!next_word(&at, &left, &w, &w_len) || !unhex_n(w, w_len, root, sizeof(root)))
			return (size_t)snprintf(reply, reply_cap, "malformed get reference ROOT\n");
		if (!fzn_node_file_ref_get(node_apply.store, root, ref))
			return (size_t)snprintf(reply, reply_cap, "error no reference held for it\n");
		hex_of(ref, sizeof(ref), hex);
		return (size_t)snprintf(reply, reply_cap, "ok %s\n", hex);
	}
	if (subject_len != 4u || memcmp(subject, "file", 4u) != 0 || origin != FZN_ORIGIN_SAME_USER
	    || !node_apply.store || !next_word(&at, &left, &w, &w_len))
		return fzn_node_files_local(ctx, origin, request, reply, reply_cap);
	/* A REFERENCE GIVEN is kept; a ROOT where one is wanted is read as the
	 * reference held -- `get file ROOT` alone is the status, and stays, and
	 * so does `get file ROOT check`, the scrub (sec 492): read as `REF
	 * check` it was an export of the plaintext to `./check`, fuzzypickles'
	 * report, sec 650. */
	if (unhex_n(w, w_len, ref, sizeof(ref))) {
		(void)fzn_node_file_ref_keep(node_apply.store, ref);
	} else if ((request->parsed == FZN_VERB_FETCH
	            || (request->parsed == FZN_VERB_GET && left > 0u
	                && !(left == 6u && memcmp(at, " check", 6u) == 0)))
	           && unhex_n(w, w_len, root, sizeof(root))
	           && fzn_node_file_ref_get(node_apply.store, root, ref)) {
		hex_of(ref, sizeof(ref), hex);
		n = (size_t)snprintf((char *)arg, sizeof(arg), "file %s%.*s", hex, (int)left,
		                     (const char *)at);
		if (n < sizeof(arg)) {
			req.arg = arg;
			req.arg_len = n;
		}
	}
	n = fzn_node_files_local(ctx, origin, &req, reply, reply_cap);
	/* A PUT'S ANSWER, `ok REF TIER`. */
	if (request->parsed == FZN_VERB_PUT && n > 3u + 2u * FZN_NODE_FILE_REF_LEN
	    && memcmp(reply, "ok ", 3u) == 0
	    && unhex_n((const uint8_t *)reply + 3, 2u * FZN_NODE_FILE_REF_LEN, ref, sizeof(ref)))
		(void)fzn_node_file_ref_keep(node_apply.store, ref);
	return n;
}

/* FILE_REFS_WANT, type 45: roots whose references the asker lacks;
 * FILE_REFS, type 46, answers those held here. To this estate's hosts
 * alone, and asked of them alone. */
#define FZND_FILE_REFS_WANT_TYPE 45u
#define FZND_FILE_REFS_TYPE 46u
#define FZND_FILE_REFS_MAX 32u

static size_t file_refs_remote(const uint8_t *sender, const uint8_t *request, size_t request_len,
                               uint8_t *reply, size_t reply_cap)
{
	uint8_t owner[FZN_PUBKEY_LEN], ref[FZN_NODE_FILE_REF_LEN];
	size_t n, i, at = 3u, count = 0;
	int own = 0;

	if (request_len < 3u || request[2] > FZND_FILE_REFS_MAX
	    || request_len != 3u + (size_t)request[2] * FZN_BLOB_HASH_LEN)
		return (size_t)snprintf((char *)reply, reply_cap, "malformed a reference want\n");
	if (!node_apply.store || !group_owner_of(sender, owner, &own) || !own)
		return (size_t)snprintf((char *)reply, reply_cap,
		                        "denied references to this estate's hosts alone\n");
	n = request[2];
	for (i = 0; i < n && at + FZN_NODE_FILE_REF_LEN <= reply_cap; i++)
		if (fzn_node_file_ref_get(node_apply.store, request + 3u + i * FZN_BLOB_HASH_LEN, ref)) {
			memcpy(reply + at, ref, FZN_NODE_FILE_REF_LEN);
			at += FZN_NODE_FILE_REF_LEN;
			count++;
		}
	reply[0] = FZND_GROUP_VERSION;
	reply[1] = FZND_FILE_REFS_TYPE;
	reply[2] = (uint8_t)count;
	fzn_wipe(ref, sizeof(ref));
	return at;
}

/* EVERY ROOT THE CATALOGUE LISTS without a reference here, asked of each
 * sibling until one answers it. sec 634. */
/* A FILE_REFS answer, each reference asked for kept: one asked for, and no
 * other -- an answer names nothing new. */
static void file_refs_take(const uint8_t *reply, size_t len)
{
	size_t k, j, want = host_shared_request[2];

	if (len < 3u || reply[0] != FZND_GROUP_VERSION || reply[1] != FZND_FILE_REFS_TYPE
	    || len != 3u + (size_t)reply[2] * FZN_NODE_FILE_REF_LEN)
		return;
	for (k = 0; k < reply[2]; k++) {
		const uint8_t *r = reply + 3u + k * FZN_NODE_FILE_REF_LEN;

		for (j = 0; j < want && memcmp(host_shared_request + 3u + j * FZN_BLOB_HASH_LEN, r,
		                               FZN_BLOB_HASH_LEN) != 0;
		     j++)
			;
		if (j < want && fzn_node_file_ref_keep(node_apply.store, r))
			file_refs_taken++;
	}
	/* THE KEYS IN IT, wiped: the loop's buffer holds the answer. */
	fzn_wipe(round_reply, len);
}

/* EVERY FILE THE CATALOGUE NAMES whose reference is not held here, asked of
 * each peer of the estate at once (sec 634; 636). */
static void file_refs_round(struct pull_target *pulls, size_t npulls, uint64_t now)
{
	static fzn_catalog_assertion_t set[FZN_NODE_CATALOG_MAX];
	uint8_t ref[FZN_NODE_FILE_REF_LEN];
	size_t n, i, k, want = 0;

	n_host_talks = host_talks_begun = 0;
	file_refs_taken = 0;
	if (!journal_on || !node_apply.store)
		return;
	n = fzn_node_catalog_assertions(&node_catalog, NULL, set, FZN_NODE_CATALOG_MAX);
	for (i = 0; i < n && want < FZND_FILE_REFS_MAX; i++) {
		uint8_t *slot = host_shared_request + 3u + want * FZN_BLOB_HASH_LEN;

		if (!set[i].live || set[i].entity_len != FZN_BLOB_HASH_LEN
		    || fzn_node_file_ref_get(node_apply.store, set[i].entity, ref))
			continue;
		for (k = 0; k < want
		            && memcmp(host_shared_request + 3u + k * FZN_BLOB_HASH_LEN, set[i].entity,
		                      FZN_BLOB_HASH_LEN) != 0;
		     k++)
			;
		if (k == want) {
			memcpy(slot, set[i].entity, FZN_BLOB_HASH_LEN);
			want++;
		}
	}
	if (!want)
		return;
	host_shared_request[0] = FZND_GROUP_VERSION;
	host_shared_request[1] = FZND_FILE_REFS_WANT_TYPE;
	host_shared_request[2] = (uint8_t)want;
	host_shared_len = 3u + want * FZN_BLOB_HASH_LEN;
	for (i = 0; i < npulls; i++)
		if (!silent_peer(&pulls[i]) && peer_in_estate(&pulls[i]))
			host_add(&pulls[i], HOST_FILE_REFS, 1, 0, now);
	host_talks_begin();
}

static void file_refs_settle(void)
{
	if (file_refs_taken)
		say(FZN_ENTRY_INFO, "files", "%zu file reference(s) from this estate's hosts",
		    file_refs_taken);
	file_refs_taken = 0;
}

/* ---- relaying, sec 622 ------------------------------------------------------- */

/* THE TYPES, in notes-sync's space after settlement's 34: RELAY carries a
 * target's key and a frame sealed for it. Answered in words. */
#define FZND_RELAY_VERSION 2u
#define FZND_RELAY_TYPE 35u
#define FZND_RELAY_HEAD_LEN (2u + FZN_PUBKEY_LEN)
/* WHERE A TARGET SAID HELLO FROM is trusted this long, seconds: past it a
 * NAT's mapping may have gone. */
/* HOW OFTEN A HOST SAYS HELLO to the peers it pulls from, seconds: under
 * the half-minute a NAT commonly keeps a quiet mapping. */
#define FZND_HELLO_EVERY 20u
#define FZND_RELAY_QUOTA_ROWS 32u

/* A HOST CELL OF THIS HOST'S as a number: `def` unset or not digits. */
static uint64_t host_number(const char *key, uint64_t def)
{
	uint8_t value[FZN_SETTING_VALUE_MAX];
	fzn_setting_rank_t rank;
	size_t len = 0, i;
	uint64_t n = 0;

	if (!contact_id
	    || !fzn_node_settings_get(&node_settings, FZN_SCOPE_HOST, contact_id->pubkey,
	                              (const uint8_t *)key, strlen(key), value, &len, &rank)
	    || len == 0u || len > 19u)
		return def;
	for (i = 0; i < len; i++) {
		if (value[i] < '0' || value[i] > '9')
			return def;
		n = n * 10u + (uint64_t)(value[i] - '0');
	}
	return n;
}

/* THE QUOTA, per requester KEY -- fuzzypickles' was per source address,
 * and here a sender is its key (sec 596): `relay/quota` bytes, 100 MiB,
 * in `relay/window` seconds, a day; 0 bytes is unlimited. A full table
 * refuses rather than evicting a row whose window still runs. 1 charged. */
static struct {
	uint8_t key[FZN_PUBKEY_LEN];
	uint64_t start, used, refused;
	int set;
} relay_rows[FZND_RELAY_QUOTA_ROWS];

static int relay_charge(const uint8_t key[FZN_PUBKEY_LEN], size_t bytes, uint64_t now)
{
#define rows relay_rows
	uint64_t quota = host_number("relay/quota", 100u * 1024u * 1024u);
	uint64_t window = host_number("relay/window", 86400u);
	size_t i, free_row = FZND_RELAY_QUOTA_ROWS;

	for (i = 0; i < FZND_RELAY_QUOTA_ROWS; i++) {
		if (rows[i].set && memcmp(rows[i].key, key, FZN_PUBKEY_LEN) == 0)
			break;
		/* A ROW WHOSE WINDOW ENDED, or a clock set back, is free. */
		if (free_row == FZND_RELAY_QUOTA_ROWS
		    && (!rows[i].set || now >= rows[i].start + window || rows[i].start > now))
			free_row = i;
	}
	if (i == FZND_RELAY_QUOTA_ROWS) {
		if (free_row == FZND_RELAY_QUOTA_ROWS)
			return 0;
		i = free_row;
		memcpy(rows[i].key, key, FZN_PUBKEY_LEN);
		rows[i].start = now;
		rows[i].used = 0;
		rows[i].refused = 0;
		rows[i].set = 1;
	}
	if (now >= rows[i].start + window || rows[i].start > now) {
		rows[i].start = now;
		rows[i].used = 0;
		rows[i].refused = 0;
	}
	if (quota && rows[i].used + bytes > quota) {
		rows[i].refused++;
		return 0;
	}
	rows[i].used += bytes;
	return 1;
#undef rows
}

/* `get relay`, sec 638: `ok ENABLED QUOTA WINDOW N KEY,USED,REFUSED ...` --
 * fzpd's `relay-status`. ENABLED is `relay/enabled`; QUOTA the bytes a peer
 * may have relayed in WINDOW seconds, 0 for no bound; then each peer whose
 * window still runs, by its key (sec 596, a sender is its key), with the
 * bytes relayed for it and the frames refused it over the quota. This
 * node's own user only: it names who relays through this host, which a
 * relay learns and must not pass on (fuzzypickles' sec 10). As many peers
 * as fit one reply, N saying how many there are. */
static size_t relay_local(fzn_origin_t origin, const fzn_request_t *request, char *reply,
                          size_t cap)
{
	uint64_t quota = host_number("relay/quota", 100u * 1024u * 1024u);
	uint64_t window = host_number("relay/window", 86400u), now = wall_clock();
	size_t i, n = 0, at, j;
	int k;

	if (request->parsed != FZN_VERB_GET || !request->arg || request->arg_len != 5u
	    || memcmp(request->arg, "relay", 5u) != 0)
		return 0;
	if (origin != FZN_ORIGIN_SAME_USER)
		return (size_t)snprintf(reply, cap, "denied who relays through this host is its own "
		                                    "user's\n");
	for (i = 0; i < FZND_RELAY_QUOTA_ROWS; i++)
		n += relay_rows[i].set && now < relay_rows[i].start + window
		     && relay_rows[i].start <= now;
	at = (size_t)snprintf(reply, cap, "ok %u %llu %llu %zu",
	                      host_number("relay/enabled", 0) == 1u ? 1u : 0u,
	                      (unsigned long long)quota, (unsigned long long)window, n);
	for (i = 0; i < FZND_RELAY_QUOTA_ROWS && at + 100u < cap; i++) {
		if (!relay_rows[i].set || now >= relay_rows[i].start + window
		    || relay_rows[i].start > now)
			continue;
		at += (size_t)snprintf(reply + at, cap - at, " ");
		for (j = 0; j < FZN_PUBKEY_LEN; j++) {
			k = snprintf(reply + at, cap - at, "%02x", relay_rows[i].key[j]);
			at += k > 0 ? (size_t)k : 0u;
		}
		at += (size_t)snprintf(reply + at, cap - at, ",%llu,%llu",
		                       (unsigned long long)relay_rows[i].used,
		                       (unsigned long long)relay_rows[i].refused);
	}
	return at + (size_t)snprintf(reply + at, cap > at ? cap - at : 0u, "\n");
}

/* A FRAME TO RELAY, sec 622: forwarded, unread, from this host's serving
 * socket to where its target last said hello, and the target's answers to
 * it routed back to the asker -- when this host relays (`relay/enabled`),
 * the asker is a member or a standing contact, the frame came straight
 * from it (one hop: what a relay sends on goes with no hops left, and is
 * never sent on again), the frame inside is the asker's own, the target
 * said hello recently, and the quota allows. Answered in words. */
static size_t introduce_remote(const uint8_t *sender, const uint8_t *request,
                               size_t request_len, uint8_t *reply, size_t reply_cap);

static size_t relay_remote(void *ctx, const uint8_t *sender, const uint8_t *request,
                           size_t request_len, uint8_t *reply, size_t reply_cap)
{
	static uint8_t frame[FZN_UDP_DATAGRAM_MAX];
	const fzn_node_state_t *st = running_admin ? running_admin->state : NULL;
	uint8_t owner[FZN_PUBKEY_LEN];
	fzn_setting_rank_t rank;
	fzn_peek_t head;
	fzn_udp_addr_t to;
	uint64_t when = 0, now = wall_clock();
	size_t inner_len;

	(void)ctx;
	if (request_len >= 2u && request[0] == FZND_GROUP_VERSION
	    && request[1] == FZND_GROUP_SYNC_TYPE)
		return group_sync_remote(sender, request, request_len, reply, reply_cap);
	if (request_len >= 2u && request[0] == FZND_GROUP_VERSION
	    && request[1] == FZND_GROUP_LINES_SYNC_TYPE)
		return group_lines_remote(sender, request, request_len, reply, reply_cap);
	if (request_len >= 2u && request[0] == FZND_GROUP_VERSION
	    && request[1] == FZND_STREAM_QUERY_TYPE)
		return streams_remote(sender, request, request_len, reply, reply_cap);
	if (request_len >= 2u && request[0] == FZND_GROUP_VERSION
	    && request[1] == FZND_FILE_REFS_WANT_TYPE)
		return file_refs_remote(sender, request, request_len, reply, reply_cap);
	if (request_len >= 2u && request[0] == FZND_RELAY_VERSION
	    && (request[1] == FZND_INTRODUCE_TYPE || request[1] == FZND_NOTIFY_TYPE))
		return introduce_remote(sender, request, request_len, reply, reply_cap);
	if (request_len < FZND_RELAY_HEAD_LEN + 1u || request[0] != FZND_RELAY_VERSION
	    || request[1] != FZND_RELAY_TYPE)
		return 0;
	inner_len = request_len - FZND_RELAY_HEAD_LEN;
#define RELAY_NO(text) ((size_t)snprintf((char *)reply, reply_cap, "denied %s\n", text))
	if (!st || st->udp_fd < 0 || !st->asking_from || host_number("relay/enabled", 0) != 1u)
		return RELAY_NO("this host relays nothing");
	if (!fzn_node_admin_contact_of(running_admin, sender, owner)
	    && fzn_node_apply_rank(&node_apply, sender, FZN_SCOPE_HOST, sender, &rank) != 1)
		return RELAY_NO("relayed only for this estate and its contacts");
	if (st->asking_hops == 0u)
		return RELAY_NO("relayed already: one hop and never two");
	if (inner_len > sizeof(frame)
	    || fzn_seal_peek(request + FZND_RELAY_HEAD_LEN, inner_len, &head) != FZN_SEAL_OK
	    || memcmp(head.sender, sender, FZN_PUBKEY_LEN) != 0)
		return RELAY_NO("not a frame of the asker's own");
	if (!fzn_node_relay_where(&relay_tables, request + 2, &to, &when)
	    || when + FZND_RELAY_SEEN_S < now)
		return RELAY_NO("that host has not said where it is");
	if (!relay_charge(sender, inner_len, now))
		return RELAY_NO("over this host's relay quota");
	memcpy(frame, request + FZND_RELAY_HEAD_LEN, inner_len);
	/* NO HOPS LEFT: outside the seal, so writable, and what refuses a
	 * second relay. */
	frame[1] = 0u;
	fzn_node_relay_route(&relay_tables, request + 2, head.msg, st->asking_from, now);
	if (fzn_udp_send(st->udp_fd, &to, frame, inner_len) != FZN_UDP_OK)
		return RELAY_NO("the frame would not send");
#undef RELAY_NO
	return (size_t)snprintf((char *)reply, reply_cap, "ok\n");
}

/* AN INTRODUCTION, sec 623, fuzzypickles' rendezvous among an estate's
 * own hosts. INTRODUCE, from a member, names a host
 * that said hello here: answered `ok HOST PORT`, where it said hello from,
 * and that host sent a NOTIFY from this host's serving socket -- through
 * its NAT's open way -- naming the asker and where the asker asked from.
 * NOTIFY, from a member, has this host say hello to that address from its
 * serving socket, opening its own NAT's way to the asker. Both sides then
 * reach each other on the sockets the introduction was made from. */
static size_t introduce_remote(const uint8_t *sender, const uint8_t *request,
                               size_t request_len, uint8_t *reply, size_t reply_cap)
{
	const fzn_node_state_t *st = running_admin ? running_admin->state : NULL;
	char host[FZN_UDP_HOST_MAX];
	uint8_t owner[FZN_PUBKEY_LEN];
	fzn_setting_rank_t rank;
	fzn_udp_addr_t at;
	uint64_t when = 0, now = wall_clock();
	uint16_t port = 0;
	int member = fzn_node_apply_rank(&node_apply, sender, FZN_SCOPE_HOST, sender, &rank) == 1;

#define INTRO_NO(text) ((size_t)snprintf((char *)reply, reply_cap, "denied %s\n", text))
	if (!st || st->udp_fd < 0 || !contact_id || !node_apply.store)
		return INTRO_NO("this host serves no introductions");
	if (request[1] == FZND_INTRODUCE_TYPE) {
		static uint8_t notify[2u + FZN_PUBKEY_LEN + 1u + FZN_UDP_HOST_MAX + 2u];
		fzn_node_pairing_t pairing;
		fzn_caller_t c;
		char asker[FZN_UDP_HOST_MAX];
		uint16_t asker_port = 0;
		uint32_t msg = 0;
		size_t n;

		if (request_len != 2u + FZN_PUBKEY_LEN)
			return INTRO_NO("malformed introduce");
		/* ONE USER'S OWN HOSTS: an introduction tells where a host is, and
		 * that is the estate's to know. */
		if (!member)
			return INTRO_NO("introductions only within this estate");
		if (!fzn_node_relay_where(&relay_tables, request + 2, &at, &when)
		    || when + FZND_RELAY_SEEN_S < now || fzn_udp_addr_text(&at, host, &port) != FZN_UDP_OK)
			return INTRO_NO("that host has not said where it is");
		/* THE NOTIFY, sent and not waited on: its answer comes to the
		 * serving socket, and opens there as nothing. */
		if (st->asking_from && fzn_udp_addr_text(st->asking_from, asker, &asker_port) == FZN_UDP_OK
		    && fzn_node_pairing_load(node_apply.store, request + 2, &pairing) == FZN_PERSIST_OK) {
			memset(&c, 0, sizeof(c));
			fzn_node_pairing_caller(&pairing, contact_id->pubkey, &c);
			c.fd = st->udp_fd;
			c.node = at;
			c.hash = contact_hash_ops;
			c.aead = contact_aead_ops;
			c.rng = contact_rng_ops;
			c.hops = 1u;
			n = strlen(asker);
			notify[0] = FZND_INTRO_VERSION;
			notify[1] = FZND_NOTIFY_TYPE;
			memcpy(notify + 2, sender, FZN_PUBKEY_LEN);
			notify[2u + FZN_PUBKEY_LEN] = (uint8_t)n;
			memcpy(notify + 3u + FZN_PUBKEY_LEN, asker, n);
			fzn_put_be16(notify + 3u + FZN_PUBKEY_LEN + n, asker_port);
			(void)fzn_caller_send(&c, notify, 5u + FZN_PUBKEY_LEN + n, now + 60u, &msg);
			fzn_wipe(&pairing, sizeof(pairing));
			fzn_wipe(&c, sizeof(c));
		}
		return (size_t)snprintf((char *)reply, reply_cap, "ok %s %u\n", host, (unsigned)port);
	}
	/* NOTIFY: from a member, about a member or a standing contact. */
	{
		fzn_node_pairing_t pairing;
		fzn_caller_t c;
		const uint8_t *who = request + 2;
		size_t n;

		if (request_len < 3u + FZN_PUBKEY_LEN)
			return INTRO_NO("malformed notify");
		n = request[2u + FZN_PUBKEY_LEN];
		if (n == 0u || n >= FZN_UDP_HOST_MAX || request_len != 5u + FZN_PUBKEY_LEN + n)
			return INTRO_NO("malformed notify");
		if (!member)
			return INTRO_NO("only this estate introduces");
		if (fzn_node_apply_rank(&node_apply, who, FZN_SCOPE_HOST, who, &rank) != 1
		    && !fzn_node_admin_contact_of(running_admin, who, owner))
			return INTRO_NO("not a host this one knows");
		memcpy(host, request + 3u + FZN_PUBKEY_LEN, n);
		host[n] = '\0';
		port = fzn_get_be16(request + 3u + FZN_PUBKEY_LEN + n);
		if (!port || fzn_node_pairing_load(node_apply.store, who, &pairing) != FZN_PERSIST_OK)
			return INTRO_NO("no way to that host");
		memset(&c, 0, sizeof(c));
		fzn_node_pairing_caller(&pairing, contact_id->pubkey, &c);
		c.hash = contact_hash_ops;
		c.aead = contact_aead_ops;
		c.rng = contact_rng_ops;
		if (fzn_udp_resolve(contact_family, host, port, &c.node) == FZN_UDP_OK)
			(void)fzn_caller_hello(&c, st->udp_fd, now + 60u);
		fzn_wipe(&pairing, sizeof(pairing));
		fzn_wipe(&c, sizeof(c));
		return (size_t)snprintf((char *)reply, reply_cap, "ok\n");
	}
#undef INTRO_NO
}


/* THE REQUEST SENT THROUGH THE RELAY, sec 622: sealed for `target`, handed
 * to `relay` from the target's own socket, so the target's answer, routed
 * back by the relay, arrives where the target's caller reads it -- under
 * `*msg`. The relay's own answer comes to that socket too, under its key,
 * and the target's caller passes it over as not its own. */
static int relay_send(struct pull_target *target, struct pull_target *relay,
                      const uint8_t *request, size_t request_len, uint64_t now, uint32_t *msg)
{
	static uint8_t inner[FZN_UDP_DATAGRAM_MAX], outer[FZND_RELAY_HEAD_LEN + FZN_UDP_DATAGRAM_MAX];
	fzn_caller_t via;
	uint32_t outer_msg = 0;
	size_t inner_len = 0;

	if (fzn_caller_seal(&target->caller, request, request_len, now + 300u, msg, inner,
	                    sizeof(inner), &inner_len)
	    != FZN_CALLER_OK)
		return 0;
	outer[0] = FZND_RELAY_VERSION;
	outer[1] = FZND_RELAY_TYPE;
	memcpy(outer + 2, target->pairing.node, FZN_PUBKEY_LEN);
	memcpy(outer + FZND_RELAY_HEAD_LEN, inner, inner_len);
	via = relay->caller;
	via.fd = target->caller.fd;
	if (fzn_caller_send(&via, outer, FZND_RELAY_HEAD_LEN + inner_len, now + 300u, &outer_msg)
	    != FZN_CALLER_OK)
		return 0;
	relay->caller.next_msg = via.next_msg;
	return 1;
}

/* HELLO, sec 622, every FZND_HELLO_EVERY seconds: a NOP from the serving
 * socket to each peer this host pulls from, so one that relays knows where
 * this host is reached and a NAT keeps the way open. */
static void say_hello(struct pull_target *pulls, size_t npulls, int serving_fd, uint64_t now)
{
	static uint64_t next;
	size_t i;

	if (serving_fd < 0 || (now < next && next <= now + FZND_HELLO_EVERY))
		return;
	next = now + FZND_HELLO_EVERY;
	for (i = 0; i < npulls; i++)
		(void)fzn_caller_hello(&pulls[i].caller, serving_fd, now + 60u);
}

/* ---- LAN discovery, sec 624 ------------------------------------------------- */

#define FZND_LAN_PORTS_MAX 16u
#define FZND_PROBES_A_MINUTE 32u


/* A PROBE ANSWERED, sec 624: from a key this host knows -- a member, or a
 * contact or its device -- a sealed hello from this host's serving socket
 * to where the probe came from, which tells the prober where this host is
 * on the LAN. No larger than the probe, and nothing kept. Anything else
 * goes unanswered, so a stranger learns nothing of this host. */
static void lan_probe_heard(void *ctx, const uint8_t *probe, size_t len,
                            const fzn_udp_addr_t *from)
{
	static uint64_t window, answered;
	const fzn_node_state_t *st = running_admin ? running_admin->state : NULL;
	const uint8_t *who = probe + 2;
	fzn_node_pairing_t pairing;
	fzn_contact_device_t d;
	fzn_setting_rank_t rank;
	uint8_t owner[FZN_PUBKEY_LEN];
	fzn_caller_t c;
	uint64_t now = wall_clock();
	int have;

	(void)ctx;
	if (!st || st->udp_fd < 0 || !contact_id || !node_apply.store || len != FZN_NODE_PROBE_LEN
	    || probe[1] != 1u || memcmp(who, contact_id->pubkey, FZN_PUBKEY_LEN) == 0)
		return;
	if (now >= window + 60u || window > now) {
		window = now;
		answered = 0;
	}
	if (answered >= FZND_PROBES_A_MINUTE)
		return;
	if (fzn_node_apply_rank(&node_apply, who, FZN_SCOPE_HOST, who, &rank) != 1
	    && !fzn_node_admin_contact_of(running_admin, who, owner))
		return;
	have = fzn_node_pairing_load(node_apply.store, who, &pairing) == FZN_PERSIST_OK;
	if (!have && running_admin->state->config.has_share
	    && fzn_contact_device_get(node_apply.store, who, &d) == FZN_CONTACT_DEVICE_OK)
		have = fzn_node_pairing_derive(contact_id, d.record,
		                               &running_admin->state->config.share_capability, now,
		                               &pairing)
		       == FZN_NODE_PAIR_OK;
	if (!have)
		return;
	answered++;
	memset(&c, 0, sizeof(c));
	fzn_node_pairing_caller(&pairing, contact_id->pubkey, &c);
	c.node = *from;
	c.hash = contact_hash_ops;
	c.aead = contact_aead_ops;
	c.rng = contact_rng_ops;
	(void)fzn_caller_hello(&c, st->udp_fd, now + 60u);
	fzn_wipe(&pairing, sizeof(pairing));
	fzn_wipe(&c, sizeof(c));
}

/* `fetch lan`, sec 624: a probe sent from the serving socket to the LAN
 * discovery address -- this host's cell `net/discovery`, 255.255.255.255
 * unset, and none at all when it is `off` -- at every port a sibling or a
 * contact's host advertises. Its answers are hellos, noted where they came
 * from; a sibling silent at its own address is then asked there
 * (`introduce_siblings`). How many were sent, the address in `address`;
 * with none, `*why` says why. */
static size_t lan_probe(const char **why, char *out, size_t out_cap)
{
	static uint8_t hosts[FZN_NODE_SIBLINGS_MAX][FZN_PUBKEY_LEN];
	static fzn_contact_device_t kept[FZN_CONTACT_DEVICES_MAX];
	const fzn_node_state_t *st = running_admin ? running_admin->state : NULL;
	uint8_t probe[FZN_NODE_PROBE_LEN], value[FZN_SETTING_VALUE_MAX];
	char address[FZN_UDP_HOST_MAX] = "255.255.255.255", host[FZN_NODE_SETTINGS_HOST_MAX + 1u];
	uint16_t ports[FZND_LAN_PORTS_MAX], port;
	fzn_setting_rank_t rank;
	size_t n = 0, nports = 0, i, k, len = 0, sent = 0;

	*why = NULL;
	if (out_cap)
		out[0] = '\0';
	if (!st || st->udp_fd < 0 || !contact_id || !node_apply.store) {
		*why = "this host serves no udp socket to probe from";
		return 0;
	}
	if (fzn_node_settings_get(&node_settings, FZN_SCOPE_HOST, contact_id->pubkey,
	                          (const uint8_t *)"net/discovery", 13u, value, &len, &rank)
	    && len > 0u && len < sizeof(address)) {
		memcpy(address, value, len);
		address[len] = '\0';
	}
	/* SWITCHED OFF: nothing broadcast at all. fzpd could not be -- an empty
	 * address still broadcast (fuzzypickles' sec 282). */
	if (strcmp(address, "off") == 0) {
		*why = "LAN discovery is off (net/discovery)";
		return 0;
	}
	(void)snprintf(out, out_cap, "%s", address);
	if (fzn_node_siblings_list(node_apply.store, hosts, FZN_NODE_SIBLINGS_MAX, &n)
	    == FZN_NODE_SIBLINGS_OK)
		for (i = 0; i < n && nports < FZND_LAN_PORTS_MAX; i++) {
			port = 0;
			if (memcmp(hosts[i], contact_id->pubkey, FZN_PUBKEY_LEN) == 0
			    || !fzn_node_settings_address(&node_settings, hosts[i], host, &port))
				continue;
			for (k = 0; k < nports && ports[k] != port; k++)
				;
			if (k == nports)
				ports[nports++] = port;
		}
	n = 0;
	if (fzn_contact_device_list(node_apply.store, kept, FZN_CONTACT_DEVICES_MAX, &n)
	    == FZN_CONTACT_DEVICE_OK)
		for (i = 0; i < n && nports < FZND_LAN_PORTS_MAX; i++) {
			if (!kept[i].port)
				continue;
			for (k = 0; k < nports && ports[k] != kept[i].port; k++)
				;
			if (k == nports)
				ports[nports++] = kept[i].port;
		}
	memset(probe, 0, sizeof(probe));
	probe[0] = FZN_NODE_PROBE_MARK;
	probe[1] = 1u;
	memcpy(probe + 2, contact_id->pubkey, FZN_PUBKEY_LEN);
	if (!nports) {
		*why = "no sibling or contact host advertises a port to probe";
		return 0;
	}
	if (!contact_rng_ops || !contact_rng_ops->fill(contact_rng_ops->ctx, probe + 2 + FZN_PUBKEY_LEN, 8u)) {
		*why = "the probe would not be drawn";
		return 0;
	}
	(void)fzn_udp_broadcast(st->udp_fd);
	for (i = 0; i < nports; i++) {
		fzn_udp_addr_t to;

		if (fzn_udp_resolve(contact_family, address, ports[i], &to) == FZN_UDP_OK
		    && fzn_udp_send(st->udp_fd, &to, probe, sizeof(probe)) == FZN_UDP_OK)
			sent++;
	}
	say(FZN_ENTRY_INFO, "net/lan", "%zu LAN probe(s) sent to %s", sent, address);
	if (!sent)
		*why = "no probe would send to that address";
	return sent;
}

/* LINES DELIVERED TO CONTACTS, secs 613 and 614: every line this node wrote
 * and has not yet delivered, offered to each standing contact through its
 * hosts in turn -- a received share's pairing first, then the hosts kept in
 * its manifest's order -- until one holds them. Each round, and at once
 * after a line is written. */
/* A LINE DELIVERED AND NOT SETTLED is offered again hourly, and at start,
 * so the answer can say it settled (sec 615): 1 when this delivery is the
 * hour's. */
static int settle_due(uint64_t now)
{
	static uint64_t next_settle;
	int settle = now >= next_settle || next_settle > now + FZND_SETTLE_EVERY;

	if (settle)
		next_settle = now + FZND_SETTLE_EVERY;
	return settle;
}

/* ---- DELIVERY, a conversation of the round, sec 636: one with each
 * standing contact, every contact at once -- its hosts in turn, the next
 * after a refusal or no answer, then through a relay each that did not
 * answer, as the round in turn delivered. Awaited on `asks`
 * directly, since a relayed request is sent through one host's caller and
 * answered on another's. */
#define FZND_DELIVER_HOSTS 8u

struct deliver_talk {
	uint8_t contact[FZN_PUBKEY_LEN];
	struct {
		struct pull_target *pt;
		const char *name;
		long target; /* its place in `contact_targets`, or -1 for a sharer's */
	} hosts[FZND_DELIVER_HOSTS];
	size_t n_hosts, at, relay;
	int relaying, settle;
	uint64_t now;
	struct meter m;
	fzn_node_messages_delivering_t d;
	fzn_messages_err_t err;
	uint8_t request[FZN_NODE_MESSAGES_DELIVER_MAX];
};
static struct deliver_talk deliver_talks[FZND_CONTACT_TARGETS_MAX + FZN_NODE_RECEIVED_MAX];
static size_t n_deliver_talks;

static void deliver_host(struct deliver_talk *dt);
static void deliver_relay_next(struct deliver_talk *dt);

static void deliver_over(struct deliver_talk *dt)
{
	(void)dt;
	if (round_pending)
		round_pending--;
}

/* A HOST'S TURN OVER: said as the round in turn said it, and the next. */
static void deliver_host_done(struct deliver_talk *dt)
{
	const fzn_node_messages_delivery_t *d = &dt->d.tally;

	if (!dt->relaying) {
		const char *host = dt->hosts[dt->at].name;
		long ti = dt->hosts[dt->at].target;

		if (dt->err != FZN_MESSAGES_OK)
			say(FZN_ENTRY_WARNING, "messages/deliver", "delivering to %s: %s", host,
			    fzn_messages_err_str(dt->err));
		else if (d->sent)
			say(FZN_ENTRY_INFO, "messages/deliver",
			    "%zu line(s) offered to %s: %zu delivered, %zu settled, %zu refused, %zu "
			    "unanswered",
			    d->sent, host, d->delivered, d->settled, d->refused, d->unanswered);
		if (ti >= 0)
			contact_targets[ti].down = dt->err == FZN_MESSAGES_OK && d->unanswered;
		/* ALL OF THEM TAKEN, OR NONE WAITING: this contact is done. A
		 * refusal or no answer tries its next host. */
		if (dt->err == FZN_MESSAGES_OK && !d->refused && !d->unanswered) {
			deliver_over(dt);
			return;
		}
		dt->at++;
		if (dt->at < dt->n_hosts) {
			deliver_host(dt);
			return;
		}
		/* THROUGH A RELAY, sec 622: each host that did not answer asked
		 * through another of the contact's that did. */
		dt->relaying = 1;
		dt->at = 0;
		dt->relay = 0;
		deliver_relay_next(dt);
		return;
	}
	if (dt->err == FZN_MESSAGES_OK && d->sent) {
		say(FZN_ENTRY_INFO, "messages/deliver",
		    "%zu line(s) offered to %s through %s: %zu delivered, %zu settled, %zu refused, "
		    "%zu unanswered",
		    d->sent, dt->hosts[dt->at].name, dt->hosts[dt->relay].name, d->delivered,
		    d->settled, d->refused, d->unanswered);
		if (!d->unanswered && !d->refused) {
			dt->at++;
			dt->relay = 0;
			deliver_relay_next(dt);
			return;
		}
	}
	dt->relay++;
	deliver_relay_next(dt);
}

static void deliver_answered(void *ctx, const uint8_t *reply, size_t reply_len);

/* THE REQUEST IN `dt->request` SENT, to the host or through the relay, and
 * its answer awaited; one that cannot leave answered as none. */
static void deliver_send(struct deliver_talk *dt, size_t len)
{
	struct pull_target *pt = dt->hosts[dt->at].pt;
	uint32_t msg = 0;
	int sent;

	if (!dt->relaying) {
		meter_asked(&dt->m, len);
		sent = fzn_node_asks_send(&round_asks, &pt->caller, dt->request, len, dt->now + 300u,
		                          3000u, deliver_answered, dt);
	} else
		sent = relay_send(pt, dt->hosts[dt->relay].pt, dt->request, len, dt->now, &msg)
		       && fzn_node_asks_await(&round_asks, &pt->caller, msg, 3000u, deliver_answered,
		                              dt);
	if (!sent)
		deliver_answered(dt, NULL, 0);
}

static void deliver_answered(void *ctx, const uint8_t *reply, size_t reply_len)
{
	struct deliver_talk *dt = ctx;
	size_t len = 0;
	int done = 0;

	if (!dt->relaying)
		meter_answer(&dt->m, reply, reply_len);
	dt->err = fzn_node_messages_deliver_step(&dt->d, reply, reply_len, dt->request,
	                                         sizeof(dt->request), &len, &done);
	if (dt->err == FZN_MESSAGES_OK && !done) {
		deliver_send(dt, len);
		return;
	}
	deliver_host_done(dt);
}

/* THE DELIVERY TO `dt->hosts[dt->at]`, direct or through `dt->relay`,
 * begun. */
static void deliver_host(struct deliver_talk *dt)
{
	size_t len = 0;
	int done = 0;

	if (!dt->relaying) {
		dt->m.pt = dt->hosts[dt->at].pt;
		dt->m.silences = 0;
		dt->m.li = link_of(&dt->hosts[dt->at].pt->caller.node);
		dt->m.host = dt->hosts[dt->at].name;
	}
	dt->err = fzn_node_messages_deliver_begin(&dt->d, &node_messages, dt->contact, dt->settle,
	                                          dt->request, sizeof(dt->request), &len, &done);
	if (dt->err == FZN_MESSAGES_OK && !done) {
		deliver_send(dt, len);
		return;
	}
	deliver_host_done(dt);
}

/* THE NEXT HOST THAT DID NOT ANSWER, with the next of its contact's that
 * did, as the round in turn paired them; the contact over when none is
 * left. */
static void deliver_relay_next(struct deliver_talk *dt)
{
	for (; dt->at < dt->n_hosts; dt->at++, dt->relay = 0) {
		long ti = dt->hosts[dt->at].target;

		if (ti < 0 || !contact_targets[ti].down)
			continue;
		for (; dt->relay < dt->n_hosts; dt->relay++) {
			long ri = dt->hosts[dt->relay].target;

			if (dt->relay == dt->at || ri < 0 || contact_targets[ri].down)
				continue;
			deliver_host(dt);
			return;
		}
	}
	deliver_over(dt);
}

/* EVERY STANDING CONTACT DELIVERED TO, at once: its hosts in the order
 * the round in turn tried them. */
static void deliver_start(uint64_t now)
{
	size_t i, k;
	int settle;

	n_deliver_talks = 0;
	if (!messages_on)
		return;
	settle = settle_due(now);
	for (i = 0; i < nshares_in + ncontact_targets; i++) {
		struct pull_target *pt = i < nshares_in ? &shares_in[i].pt
		                                        : &contact_targets[i - nshares_in].pt;
		const uint8_t *contact = i < nshares_in ? shares_in[i].sharer
		                                        : contact_targets[i - nshares_in].contact;
		const char *host = i < nshares_in ? shares_in[i].host
		                                  : contact_targets[i - nshares_in].host;
		struct deliver_talk *dt;

		if (running_admin && !fzn_node_admin_contact_stands(running_admin, contact))
			continue;
		for (k = 0; k < n_deliver_talks
		            && memcmp(deliver_talks[k].contact, contact, FZN_PUBKEY_LEN) != 0;
		     k++)
			;
		if (k == n_deliver_talks) {
			if (n_deliver_talks == sizeof(deliver_talks) / sizeof(deliver_talks[0]))
				continue;
			dt = &deliver_talks[n_deliver_talks++];
			memcpy(dt->contact, contact, FZN_PUBKEY_LEN);
			dt->n_hosts = 0;
			dt->now = now;
			dt->settle = settle;
		}
		dt = &deliver_talks[k];
		if (dt->n_hosts < FZND_DELIVER_HOSTS) {
			dt->hosts[dt->n_hosts].pt = pt;
			dt->hosts[dt->n_hosts].name = host;
			dt->hosts[dt->n_hosts++].target = i < nshares_in ? -1 : (long)(i - nshares_in);
		}
	}
	for (k = 0; k < n_deliver_talks; k++) {
		struct deliver_talk *dt = &deliver_talks[k];

		dt->at = 0;
		dt->relaying = 0;
		round_pending++;
		deliver_host(dt);
	}
}

/* A NOTE'S HISTORY TRIMMED BY THE RULES, sec 581, each round before the
 * texts are collected, so a version let go takes its text in the same round.
 * Kept by default, as the holder decided: no history rule trims nothing. */
static void history_trim(void)
{
	static fzn_retain_rule_t rules[FZN_RETAIN_RULES_MAX];
	size_t gathered, n, removed = 0;
	fzn_notes_err_t err;

	if (!notes_on)
		return;
	gathered = gather_rules(rules);
	n = fzn_retain_select_history(rules, gathered, dlog.has_host ? dlog.host : NULL,
	                              here_machine(), rules);
	err = n ? fzn_notes_history_trim(&node_notes.store, rules, n, wall_ms(), &removed)
	        : FZN_NOTES_OK;
	if (err != FZN_NOTES_OK) {
		say(FZN_ENTRY_WARNING, "notes", "trimming the history by the rules: %s",
		    fzn_notes_err_str(err));
		return;
	}
	if (removed)
		say(FZN_ENTRY_INFO, "notes", "%zu earlier version(s) let go by the rules", removed);
	say(FZN_ENTRY_DEBUG, "notes", "history pass: %zu of %zu rule(s), %zu version(s) let go", n,
	    gathered, removed);
}

#ifdef FZN_SPOOL_FILE_ON
/* COLLECTING THE SHELF, sec 443: a text no note names, this node's or a
 * sharer's, goes. Run after each round's fetches, so a text just wanted is
 * kept by its want. */
static int keep_blob(void *ctx, const uint8_t root[FZN_BLOB_HASH_LEN])
{
	return fzn_node_notes_names_blob((fzn_node_notes_t *)ctx, root);
}

static int shelf_collect(void *ctx, int (*keep)(void *keep_ctx, const uint8_t *root),
                         void *keep_ctx, size_t *kept, size_t *removed)
{
	return fzn_node_shelf_collect((fzn_node_shelf_t *)ctx, keep, keep_ctx, kept, removed)
	       == FZN_NODE_SHELF_OK;
}

/* PUSHED TEXTS, sec 448, over the shelf. */
static int shelf_place(void *ctx, const uint8_t *root, uint64_t length, const uint8_t *data,
                       size_t data_len, int *complete)
{
	fzn_node_shelf_t *sh = (fzn_node_shelf_t *)ctx;
	uint64_t have = 0;

	if (!data) {
		*complete = fzn_node_shelf_held(sh, root, &have) == FZN_NODE_SHELF_OK
		            && have == length;
		return 1;
	}
	return fzn_node_shelf_place(sh, root, length, data, data_len, complete)
	       == FZN_NODE_SHELF_OK;
}

static int shelf_span(void *ctx, const uint8_t *root, uint64_t first, uint8_t *out, size_t cap,
                      size_t *out_len, uint64_t *count)
{
	return fzn_node_shelf_data_at((fzn_node_shelf_t *)ctx, root, first, out, cap, out_len,
	                              count)
	       == FZN_NODE_SHELF_OK;
}

static void collect_texts(void)
{
	size_t kept = 0, removed = 0;

	if (!shelf_on || !notes_on)
		return;
	fzn_node_notes_history_refresh(&node_notes);
	if (fzn_node_shelf_collect(&shelf, keep_blob, &node_notes, &kept, &removed)
	    != FZN_NODE_SHELF_OK)
		say(FZN_ENTRY_ERROR, "shelf/collect", "the shelf would not all be collected");
	else if (removed)
		say(FZN_ENTRY_INFO, "shelf/collect", "%zu text(s) no note names removed, %zu kept", removed,
		        kept);
}

/* THE SHELF RE-VERIFIED AT REST, sec 452: a few texts every half minute,
 * in turn, so a bad sector or a file edited underneath is found by the node
 * rather than by the next reader. A text that fails stops being held and is
 * fetched again by the round, which wants every text a note names. */
#define FZND_SCRUB_EVERY 30u
#define FZND_SCRUB_STEPS 4u

/* THE FILES AT REST, sec 492: one file a scrub period, since a file can be
 * gigabytes. A file that fails loses the leaves that changed and stays a
 * want, so the next round fetches them back. */
static void scrub_files(uint64_t now)
{
	static uint64_t next_scrub;
	fzn_node_files_err_t err;
	uint64_t dropped = 0;
	int checked = 0;

	if (!files_on || (now < next_scrub && next_scrub <= now + FZND_SCRUB_EVERY))
		return;
	next_scrub = now + FZND_SCRUB_EVERY;
	err = fzn_node_files_scrub_step(&files, &checked, &dropped);
	if (err != FZN_NODE_FILES_OK)
		say(FZN_ENTRY_ERROR, "files/scrub", "the files' check at rest: %s",
		    fzn_node_files_err_str(err));
	else if (dropped && (files.fresh = 1))
		say(FZN_ENTRY_WARNING, "files/scrub",
		    "file %02x%02x%02x%02x failed its check at rest; %llu leaf(s) are fetched again",
		    files.scrub_after[0], files.scrub_after[1], files.scrub_after[2],
		    files.scrub_after[3], (unsigned long long)dropped);
}

static void scrub_shelf(uint64_t now)
{
	static uint64_t next_scrub;
	uint8_t began[FZN_BLOB_HASH_LEN];
	size_t i;

	/* A CLOCK SET BACK leaves a schedule further ahead than one period,
	 * which waiting would honour for as long as the clock was wrong: due
	 * now instead. sec 469. */
	if (!shelf_on || (now < next_scrub && next_scrub <= now + FZND_SCRUB_EVERY))
		return;
	next_scrub = now + FZND_SCRUB_EVERY;
	for (i = 0; i < FZND_SCRUB_STEPS; i++) {
		int checked = 0, dropped = 0;
		fzn_node_shelf_err_t err = fzn_node_shelf_scrub_step(&shelf, &checked, &dropped);

		if (err != FZN_NODE_SHELF_OK) {
			say(FZN_ENTRY_ERROR, "shelf/scrub", "the shelf's check at rest: %s",
			        fzn_node_shelf_err_str(err));
			return;
		}
		if (dropped) {
			char hex[(FZN_BLOB_HASH_LEN * 2u) + 1u];
			size_t k;

			for (k = 0; k < FZN_BLOB_HASH_LEN; k++)
				(void)snprintf(hex + (k * 2u), 3u, "%02x", shelf.scrub_after[k]);
			say(FZN_ENTRY_WARNING, "shelf/scrub", "text %s failed its check at rest; it is fetched "
			                "again",
			        hex);
		}
		/* A SHELF SMALLER THAN A BATCH: the batch stops once the walk is
		 * back at the text it began with, not round and round. */
		if (!checked || (i > 0u && memcmp(shelf.scrub_after, began, sizeof(began)) == 0))
			return;
		if (i == 0u)
			memcpy(began, shelf.scrub_after, sizeof(began));
	}
}

/* A contact may fetch the texts of the notes shared with it, sec 438: the
 * shelf answers a root the notes say a note in that contact's share has. */
static int shared_text_permit(void *ctx, const uint8_t root[FZN_BLOB_HASH_LEN])
{
	return fzn_node_notes_shares_blob(&node_notes, (const uint8_t *)ctx, root);
}

static size_t shared_text(void *ctx, const uint8_t *sender, const uint8_t *request,
                          size_t request_len, uint8_t *reply, size_t reply_cap)
{
	return fzn_node_shelf_answer_permitted((const fzn_node_shelf_t *)ctx, shared_text_permit,
	                                       (void *)(uintptr_t)sender, request, request_len,
	                                       reply, reply_cap);
}
#endif

#ifdef FZN_SPOOL_FILE_ON
/* Every remembered text, from each pull peer in turn until it is here. */
/* FILES WANTED HERE, sec 491: each fetched from the pull peers in turn, a
 * bounded amount a round -- the rest on the next, from where the sidecar
 * says it is -- until one of them has given the whole of it. */
#define FZND_FILE_LEAVES_A_ROUND 4096u

_Static_assert(FZND_PULL_REPLY_MAX >= FZN_NODE_FILES_REPLY_MAX,
               "a pull's reassembly holds a file's largest DATA");

/* SEVERAL SPANS OUT AT ONCE, sec 494: the window's ceiling, and the slots
 * one reassembly table shared by the peers of a fetch keeps for their
 * replies. Two spans of 64 leaves, about 136 KB in flight: a socket's default
 * receive buffer holds about a hundred datagrams, and a window past it loses
 * replies to the kernel rather than to the network. */
#define FZND_FETCH_WINDOW 2u

/* A caller as a file fetch's peer: a request sent, and the reply to any of
 * its requests taken. */
struct fetch_peer {
	fzn_caller_t *caller;
	uint64_t now;
};

static int fetch_send(void *ctx, const uint8_t *request, size_t request_len, uint32_t *msg)
{
	struct fetch_peer *p = (struct fetch_peer *)ctx;

	return fzn_caller_send(p->caller, request, request_len, p->now + 300u, msg) == FZN_CALLER_OK;
}

static int fetch_poll(void *ctx, uint8_t *reply, size_t reply_cap, size_t *reply_len,
                      uint32_t *msg, unsigned timeout_ms)
{
	struct fetch_peer *p = (struct fetch_peer *)ctx;

	return fzn_caller_recv_any(p->caller, msg, reply, reply_cap, reply_len,
	                           timeout_ms ? timeout_ms : 1u)
	       == FZN_CALLER_OK;
}

static void fetch_files(struct pull_target *pulls, size_t npulls, uint64_t now)
{
	static uint8_t roots[FZN_NODE_FILES_WANTS_MAX][FZN_BLOB_HASH_LEN];
	static uint64_t lengths[FZN_NODE_FILES_WANTS_MAX];
	static uint8_t slot_bufs[FZND_FETCH_WINDOW][FZND_PULL_REPLY_MAX];
	static fzn_partial_t slots[FZND_FETCH_WINDOW];
	static fzn_reasm_t table;
	static int table_ready;
	fzn_node_files_peer_t peers[FZN_NODE_FILES_PEERS_MAX];
	struct fetch_peer fp[FZN_NODE_FILES_PEERS_MAX];
	fzn_reasm_t *kept[FZN_NODE_FILES_PEERS_MAX];
	const char *hosts[FZN_NODE_FILES_PEERS_MAX];
	size_t n, w, t, n_peers = 0, i;

	if (!files_on)
		return;
	files.fresh = 0;
	n = fzn_node_files_wanted(&files, roots, lengths, FZN_NODE_FILES_WANTS_MAX);
	if (!n)
		return;
	if (!table_ready) {
		for (i = 0; i < FZND_FETCH_WINDOW; i++)
			if (fzn_reasm_slot_init(&slots[i], slot_bufs[i], sizeof(slot_bufs[i]))
			    != FZN_REASM_OK)
				return;
		if (fzn_reasm_init(&table, slots, FZND_FETCH_WINDOW, FZND_FETCH_WINDOW, 60u)
		    != FZN_REASM_OK)
			return;
		table_ready = 1;
	}
	/* THE PULL PEERS -- the siblings a round adds among them, sec 586 --
	 * AND THE CONTACTS SHARING WITH THIS NODE, sec 493 -- a contact's node
	 * answers for what it made public or shared here -- AND, sec 631's 6b,
	 * EVERY CONTACT'S HOST AND EVERY GROUP MEMBER'S, which answer for what
	 * they granted this user or a group it is in: a file sent by reference
	 * is fetched from whoever granted it. Each lent the fetch's
	 * reassembly table while it runs. */
	for (t = 0; t < npulls + nshares_in + ncontact_targets + ngroup_shares_in
	            && n_peers < FZN_NODE_FILES_PEERS_MAX;
	     t++) {
		size_t u = t - npulls;
		struct pull_target *pt =
		        t < npulls                                   ? &pulls[t]
		        : u < nshares_in                             ? &shares_in[u].pt
		        : u - nshares_in < ncontact_targets          ? &contact_targets[u - nshares_in].pt
		                                                     : &group_shares_in[u - nshares_in
		                                                                        - ncontact_targets]
		                                                                .pt;
		fzn_caller_t *caller = &pt->caller;

		if (t < npulls ? silent_peer(pt) : pt->fd < 0)
			continue;
		if (t >= npulls + nshares_in && t < npulls + nshares_in + ncontact_targets
		    && contact_targets[u - nshares_in].down)
			continue;
		fp[n_peers].caller = caller;
		fp[n_peers].now = now;
		kept[n_peers] = caller->reasm;
		caller->reasm = &table;
		hosts[n_peers] = pt->host;
		peers[n_peers].send = fetch_send;
		peers[n_peers].poll = fetch_poll;
		peers[n_peers].ctx = &fp[n_peers];
		n_peers++;
	}
	for (w = 0; w < n && w < FZN_NODE_FILES_WANTS_MAX && n_peers; w++) {
		uint64_t placed = 0;
		size_t holders = 0;
		fzn_node_files_err_t err =
		        fzn_node_files_fetch_many(&files, roots[w], peers, n_peers, wall_ms,
		                                  FZND_FETCH_WINDOW, FZND_FILE_LEAVES_A_ROUND, &placed,
		                                  &holders);

		if (err == FZN_NODE_FILES_OK && placed)
			say(FZN_ENTRY_INFO, "files", "file %02x%02x%02x%02x, %llu bytes, whole from %zu peer(s)",
			    roots[w][0], roots[w][1], roots[w][2], roots[w][3],
			    (unsigned long long)lengths[w], holders);
		else if (placed) {
			say(FZN_ENTRY_DEBUG, "files", "%llu leaf(s) of file %02x%02x%02x%02x from %zu peer(s)",
			    (unsigned long long)placed, roots[w][0], roots[w][1], roots[w][2],
			    roots[w][3], holders);
			/* MORE AT ONCE, not at the next round: the budget is what lets
			 * the loop answer between batches, not a rate. */
			files.fresh = 1;
		}
		if (err != FZN_NODE_FILES_OK && err != FZN_NODE_FILES_ERR_NOT_THERE
		    && err != FZN_NODE_FILES_ERR_ABSENT)
			say(FZN_ENTRY_WARNING, "files", "file %02x%02x%02x%02x: %s", roots[w][0],
			    roots[w][1], roots[w][2], roots[w][3], fzn_node_files_err_str(err));
	}
	(void)hosts;
	for (i = 0; i < n_peers; i++)
		fp[i].caller->reasm = kept[i];
}

/* A CONTACT'S FILE REQUEST, and a grantee forgotten: the admin's hooks.
 * sec 493. */
static size_t files_shared(void *ctx, const uint8_t *sender, const uint8_t *request,
                           size_t request_len, uint8_t *reply, size_t reply_cap)
{
	return fzn_node_files_answer_shared((const fzn_node_files_t *)ctx, sender, request,
	                                    request_len, reply, reply_cap);
}

static int files_forget(void *ctx, const uint8_t *grantee)
{
	size_t gone = 0;

	return fzn_node_files_forget((fzn_node_files_t *)ctx, grantee, &gone) == FZN_NODE_FILES_OK;
}

/* THE REMOTE HOP'S BLOB MESSAGES, sec 491: a file held whole answers first,
 * and anything else is the shelf's, which says "absent" for what it lacks. */
static size_t blob_remote(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
                          size_t reply_cap)
{
	size_t n = files_on ? fzn_node_files_answer(&files, request, request_len, reply, reply_cap)
	                    : 0u;

	return n ? n : fzn_node_shelf_remote(ctx, request, request_len, reply, reply_cap);
}

static void fetch_texts(struct pull_target *pulls, size_t npulls, uint64_t now)
{
	size_t t;

	if (!shelf_on)
		return;
	shelf.fresh = 0;
	for (t = 0; t < npulls; t++) {
		struct peer_asking asking = { &pulls[t].caller, now, pulls[t].host };
		size_t got;

		if (silent_peer(&pulls[t]))
			continue;
		got = fzn_node_shelf_fetch_wants(&shelf, peer_ask, &asking);

		if (got)
			say(FZN_ENTRY_INFO, "shelf/fetch", "%zu text(s) from %s", got, pulls[t].host);
	}
}
#endif

static void usage(const char *prog)
{
	fprintf(stderr,
	        "usage: %s --socket=PATH [--group GID] [--udp-port=PORT]"
	        " [--udp6] [--identity HEX] [--root HEX]"
	        " [fuzznet options]\n"
	        "       %s --fuzznet-dir=DIR --pair=PREKEY_HEX [--delegable] [fuzznet options]\n"
	        "       %s --fuzznet-dir=DIR --prekey\n"
	        "       %s --fuzznet-dir=DIR --new-root\n"
	        "       %s --fuzznet-dir=DIR --set-admin CHAIN [fuzznet options]\n"
	        "       %s --fuzznet-dir=DIR --accept=CARD [--join]\n"
	        "       %s --fuzznet-dir=DIR --ask LINE --node=ROOT_HEX --to HOST PORT [--udp6]\n"
	        "a member of an estate may add --root-at HOST PORT when serving, and any\n"
	        "node --pull-from NODE_HEX HOST PORT (up to 8) for a node it holds a\n"
	        "pairing to: it pulls their revocation votes at start and every %u seconds\n"
	        "--quorum K: a revocation needs K distinct entitled issuers, a root alone\n"
	        "counting as K (default 2), until a root sets the estate's k (set quorum K)\n"
	        "serving logs to --log-dir=DIR (default /var/log/fuzznet for root, else\n"
	        "$XDG_STATE_HOME/fuzznet/log) at --log-level=LEVEL (info), rotating at\n"
	        "--log-segment=BYTES, pruned by --log-rule=\"prune|keep PROG|* [level=CEWNIVDT]\n"
	        "[subsystem=PATH] age|size|count N\" as it rotates, `archive` moving\n"
	        "packed segments to --log-archive=DIR (LOGDIR/archive) instead;\n"
	        "--no-log-file keeps stderr only; --log-scope=estate lets members gather it\n"
	        "--op-journal[=BYTES] enters every write to this node's state in a journal\n"
	        "of its own, by hash, keeping up to BYTES of written state (64 MiB), in\n"
	        "generations of --op-journal-rotate=WRITES (65536), the newest two kept;\n"
	        "--op-journal-replay=ENTRY [--op-journal-generation=N] --into=DIR writes\n"
	        "the state as of that entry of generation N (the newest) into a fresh\n"
	        "store at DIR, and exits\n"
	        "--check-log[=PROGRAM] walks a packed log's chain and its signatures;\n"
	        "a host's packed logs travel by the bucket exchange, as its rules hold them\n"
	        "       %s --fuzznet-dir=DIR --gather=PROGRAM [--since=SECONDS] [--match=TEXT]\n"
	        "              [--node=ROOT_HEX --to HOST PORT] [--root-at HOST PORT]\n"
	        "              [--pull-from NODE_HEX HOST PORT]...  print hosts' log lines,\n"
	        "              merged by time; --gather-ring prints their flight recorders,\n"
	        "              and --short shortens what repeats from line to line\n"
	        "%s",
	        prog, prog, prog, prog, prog, prog, prog, FZND_PULL_EVERY, prog, fzn_cli_usage());
}

/* PAIR ONE DEVICE AND EXIT.
 *
 * The device's prekey record arrives out of band -- it is what the device
 * publishes, self-signed -- and the node answers with a card: its root, its
 * prekey, and the device's grant. The peer is saved to the store before the
 * card is printed, so a card never exists for a pairing the node forgot. A
 * running daemon loads its peers at start, so it serves the device from its
 * next start; pairing into a live daemon needs a local verb, which is the
 * vocabulary's to add and not this main's.
 *
 * WHAT THE DEVICE IS GRANTED IS THE ONE CAPABILITY THE REMOTE HOP CHECKS,
 * `config.remote_capability`, derived from `--fuzznet-service` and
 * `--fuzznet-product`. The composition, and the refusal of a node that is
 * not its own root, are `node/pair.h`'s, where a suite reaches them. */
static int pair_device(const fzn_node_identity_t *id, const fzn_node_config_t *config,
                       const fzn_node_authority_t *authority, int delegable,
                       const fzn_persist_ops_t *store, const char *store_dir,
                       const char *prekey_hex, uint64_t now)
{
	uint8_t record_bytes[FZN_PREKEY_LEN_TOTAL];
	uint8_t card[FZN_PROVISION_MAX_LEN];
	char text[FZN_PROVISION_TEXT_MAX_LEN];
	fzn_prekey_record_t record;
	fzn_node_pair_err_t perr;
	size_t card_len = 0;

	if (!hex_bytes(prekey_hex, record_bytes, sizeof(record_bytes))
	    || fzn_prekey_open(record_bytes, sizeof(record_bytes), &record) != FZN_PREKEY_OK) {
		fprintf(stderr, "fuzznetd: --pair is not a prekey record (%u hex characters)\n",
		        (unsigned)(FZN_PREKEY_LEN_TOTAL * 2u));
		return 2;
	}
	perr = fzn_node_pair(id, config->root, &config->remote_capability, authority, delegable,
	                     store, record, now, now + FZND_CARD_LIFETIME, card, sizeof(card),
	                     &card_len);
	if (perr != FZN_NODE_PAIR_OK) {
		fprintf(stderr, "fuzznetd: not paired: %s\n", fzn_node_pair_err_str(perr));
		return 1;
	}
	/* THE GRANT, LOGGED UNDER THIS NODE, sec 497: a device paired before a
	 * revocation's line keeps its standing only if its grant is in this
	 * node's stream, and a peer rebuilds the device's chain from it -- so it
	 * goes into the journal, sec 508. Read back from the peer set just
	 * saved. */
	{
		static fzn_node_roots_t logged;
		static fzn_node_peer_t peers[FZN_NODE_PEERS_MAX];
		size_t nroots = 0, npeers = 0, i;
		int done = 0;

		if (fzn_node_roots_init(&logged, config->root, id->sign, id->hash)
		            == FZN_NODE_ROOTS_OK
		    && fzn_node_roots_load(&logged, store, &nroots) == FZN_NODE_ROOTS_OK
		    && journal_for(store_dir, &logged, id->sign, id->hash, store)
		    && fzn_node_peers_load(store, peers, FZN_NODE_PEERS_MAX, &npeers)
		               == FZN_PERSIST_OK)
			for (i = 0; i < npeers && !done; i++) {
				fzn_chain_hop_t hop;
				const uint8_t *last;

				if (memcmp(peers[i].sender, record.host, FZN_PUBKEY_LEN) != 0
				    || peers[i].hop_count == 0u)
					continue;
				last = peers[i].hop_bytes[peers[i].hop_count - 1u];
				done = fzn_hop_open(last, FZN_HOP_LEN, &hop) == FZN_CHAIN_OK
				       && fzn_node_roots_log_signed(&logged, store, id->pubkey, id->sign,
				                                    fzn_hop_grantor(hop),
				                                    (uint8_t)FZN_ROOT_ACT_GRANT, last,
				                                    FZN_HOP_LEN) == FZN_NODE_ROOTS_OK;
			}
		if (!done)
			fprintf(stderr, "fuzznetd: paired, and the grant is not in this node's journal: "
			                "no peer can rebuild the device's chain, and it would fall at "
			                "this node's revocation\n");
	}
	if (fzn_provision_text(card, card_len, text, sizeof(text)) != FZN_PROVISION_OK) {
		fprintf(stderr, "fuzznetd: the device is saved but its card would not encode; "
		                "pair it again\n");
		return 1;
	}
	fprintf(stderr, "fuzznetd: paired ");
	print_hex(stderr, record.host, FZN_PUBKEY_LEN);
	fprintf(stderr, "\n");
	printf("%s\n", text);
	return 0;
}

/* ---- a follower, sec 666 stage 1 --------------------------------------------
 *
 * THE FACE IS THE PROCESS HOLDING THE CLAIM on its core directory (sec 132;
 * `claim/`): it alone runs the remote hop, the rounds and signing. Another
 * fuzznet daemon of the same identity started beside it is a FOLLOWER: it
 * serves its own local socket and forwards every request to the face --
 * whose socket the face writes into `face` in the core directory -- passing
 * the answer back; it writes nothing to the store. Each second it tries the
 * claim, and taking it starts again in place, to boot as the face. */
#define FACE_FILE "face"

/* THE CORE DIRECTORY THIS PROCESS IS THE FACE OF, or NULL. */
static const char *face_dir;
static char face_written[1100];

static void face_unwrite(void)
{
	if (face_written[0])
		(void)unlink(face_written);
}

static void face_write(const char *core_dir, const char *sock)
{
	char tmp[1110];
	FILE *f;

	(void)snprintf(face_written, sizeof(face_written), "%s/" FACE_FILE, core_dir);
	(void)snprintf(tmp, sizeof(tmp), "%s.new", face_written);
	if (!(f = fopen(tmp, "w"))) {
		face_written[0] = '\0';
		return;
	}
	(void)fprintf(f, "%s\n", sock);
	if (fclose(f) != 0 || rename(tmp, face_written) != 0) {
		(void)unlink(tmp);
		face_written[0] = '\0';
		return;
	}
	(void)atexit(face_unwrite);
}

static void face_path_of(const char *core_dir, char *out, size_t cap)
{
	(void)snprintf(out, cap, "%s/" FACE_FILE, core_dir);
}

static void say_to(int fd, const char *text)
{
	(void)!write(fd, text, strlen(text));
}

/* WHERE THE FACE SERVES, as it wrote: 1 with its socket's path in `out`. */
static int face_socket(const char *core_dir, char *out, size_t cap)
{
	char path[1100];
	FILE *f;
	size_t n;

	face_path_of(core_dir, path, sizeof(path));
	if (!(f = fopen(path, "r")))
		return 0;
	n = fread(out, 1u, cap - 1u, f);
	(void)fclose(f);
	while (n && (out[n - 1u] == '\n' || out[n - 1u] == '\r'))
		n--;
	out[n] = '\0';
	return n > 0u && out[0] == '/';
}

/* ONE REQUEST from `cfd`, forwarded and answered. A client of another user
 * is refused here: the face judges the follower, which is this user, so a
 * stranger forwarded would be served as this user. */
static void follow_one(int cfd, const fzn_peer_t *peer, const char *core_dir)
{
	uint8_t line[FZN_REQUEST_MAX + 2u], reply[1u << 17];
	char face[1100];
	size_t got = 0, reply_len = 0, i;
	int ffd = -1;

	if (peer->uid != (uint32_t)getuid()) {
		say_to(cfd, "denied a follower serves its own user alone\n");
		return;
	}
	while (got < sizeof(line)) {
		ssize_t n = read(cfd, line + got, sizeof(line) - got);

		if (n <= 0)
			return;
		got += (size_t)n;
		if (memchr(line, '\n', got))
			break;
	}
	for (i = 0; i < got && line[i] != '\n'; i++)
		;
	if (i == got) {
		say_to(cfd, "malformed a request is one line\n");
		return;
	}
	if (i >= 10u && memcmp(line, "get events", 10u) == 0) {
		say_to(cfd, "unsupported a follower forwards requests, not events: ask the face\n");
		return;
	}
	if (!face_socket(core_dir, face, sizeof(face))
	    || fzn_client_connect(face, &ffd) != FZN_CLIENT_OK) {
		say_to(cfd, "error the face is not answering\n");
		return;
	}
	/* THE LINE AS IT CAME, its newline included. */
	if (write(ffd, line, i + 1u) != (ssize_t)(i + 1u)
	    || fzn_client_recv(ffd, reply, sizeof(reply) - 1u, &reply_len, 30000u) != FZN_CLIENT_OK)
		say_to(cfd, "error the face did not answer\n");
	else {
		reply[reply_len++] = '\n';
		(void)!write(cfd, reply, reply_len);
	}
	fzn_client_close(ffd);
}

static int follower_main(const char *sock_path, const char *core_dir, fzn_claim_t *claim)
{
	int lfd = -1;

	if (!sock_path) {
		fprintf(stderr, "fuzznetd: another process is this identity's face, and with no local "
		                "socket there is nothing to follow it for\n");
		return 1;
	}
	if (fzn_socket_listen(sock_path, 0777u, 16, &lfd) != FZN_SOCKET_OK) {
		fprintf(stderr, "fuzznetd: could not listen on %s\n", sock_path);
		return 1;
	}
	fprintf(stderr, "fuzznetd: following the face of %s, serving on %s\n", core_dir, sock_path);
	for (;;) {
		struct pollfd pfd = { lfd, POLLIN, 0 };
		int r = poll(&pfd, 1, 1000);

		if (r > 0 && (pfd.revents & POLLIN)) {
			int cfd = -1;
			fzn_peer_t peer;

			if (fzn_socket_accept(lfd, &cfd, &peer) == FZN_SOCKET_OK) {
				follow_one(cfd, &peer, core_dir);
				(void)close(cfd);
			}
		}
		/* THE FACE GONE, its claim released: this process starts again as
		 * the face. */
		if (fzn_claim_take(claim) == FZN_CLAIM_OK) {
			fprintf(stderr, "fuzznetd: the face is gone; starting again as the face\n");
			return start_again(lfd, sock_path);
		}
	}
}

int main(int argc, char **argv)
{
	const char *sock_path = NULL;

	daemon_argv = argv;
	fzn_hash_ops_t hash_ops;
	fzn_aead_ops_t aead_ops;
	fzn_random_ops_t rng_ops;
	fzn_sign_ops_t sign_ops;
	fzn_sign_seat_t seat;
	/* A SECOND SIGNER for the root key this node may hold beside its
	 * identity, sec 409: two keys, two seats, never one signer re-armed. */
	static fzn_sign_monocypher_t root_signer;
	fzn_sign_ops_t root_sign_ops;
	fzn_sign_seat_t root_seat;
	int new_root = 0;
	fzn_agree_ops_t agree_ops;
	fzn_sign_monocypher_t signer;
	static fzn_persist_file_t core_file, bulk_file;
	static fzn_persist_route_t route;
	static fzn_persist_ops_t routed;
	const fzn_persist_ops_t *store_ops = NULL;
	static fzn_agree_secret_t agree_secret;
	static fzn_trust_t trust;
	static fzn_node_identity_t identity;
	int booted = 0;
	fzn_replay_window_t replay;
	static fzn_replay_entry_t replay_entries[FZND_REPLAY_ENTRIES];
	const char *store_dir = NULL;	/* the core directory, for messages */
	const char *bulk_dir = NULL;
	const char *identity_hex = NULL;
	const char *root_hex = NULL;
	long group = -1;
	long udp_port = -1;
	int family = AF_INET;
	fzn_node_state_t state;
	fzn_cli_t cli;
	const char *pair_hex = NULL;
	int show_prekey = 0;
	const char *accept_text = NULL;
	const char *set_admin = NULL;
	static fzn_node_admin_chain_t own_admin;
	int delegable = 0, join = 0;
	static fzn_node_pairing_t estate;
	static fzn_node_authority_t authority;
	const fzn_node_authority_t *my_authority = NULL;
	const char *ask_line = NULL;
	const char *to_host = NULL;
	long to_port = -1;
	static struct pull_target pulls[FZND_ROUND_TARGETS_MAX];
	static size_t npulls = 0;
	fzn_revocation_store_t *running = NULL;
	fzn_node_roots_t *running_roots = NULL;
	long quorum = 2;
	/* THE DAEMON'S LOG, sec 461. */
	const char *log_dir = NULL;
	fzn_entry_level_t log_keep = FZN_ENTRY_INFO;
	uint64_t log_segment = 0;
	int log_file = 1;
	int op_journal = 0;
	unsigned long long op_journal_budget = FZND_OP_JOURNAL_BUDGET;
	unsigned long long op_journal_rotate = FZND_OP_JOURNAL_ROTATE;
	unsigned long long replay_generation = 0;
	/* REPLAY AND EXIT, sec 523: the state as of an entry, into a store. */
	const char *replay_into = NULL;
	unsigned long long replay_to = 0;
	int replaying = 0;
	int log_estate = 0;
	/* GATHERING, sec 463: the troubleshooter's end. */
	const char *gather_program = NULL, *gather_match = "";
	/* `--check-log[=PROGRAM]`: walk a program's packed log, sec 482. */
	const char *check_log = NULL;
	int gather_ring = 0;
	int gather_short = 0;
	uint64_t gather_since_s = 0;
	int has_capability = 0;
	int lfd = -1, ufd = -1, i, serving = 0;

	loop_pulls = pulls;
	loop_npulls = &npulls;
	fzn_cli_init(&cli);

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--group") && i + 1 < argc) {
			group = strtol(argv[++i], NULL, 10);
		} else if (!strcmp(argv[i], "--identity") && i + 1 < argc) {
			identity_hex = argv[++i];
		} else if (!strcmp(argv[i], "--root") && i + 1 < argc) {
			root_hex = argv[++i];
		} else if (!strcmp(argv[i], "--new-root")) {
			new_root = 1;
		} else if (!strcmp(argv[i], "--set-admin") && i + 1 < argc) {
			set_admin = argv[++i];
		} else if (!strcmp(argv[i], "--delegable")) {
			delegable = 1;
		} else if (!strcmp(argv[i], "--join")) {
			join = 1;
		} else if (!strcmp(argv[i], "--ask") && i + 1 < argc) {
			ask_line = argv[++i];
		} else if (!strcmp(argv[i], "--quorum") && i + 1 < argc) {
			char *end = NULL;

			quorum = strtol(argv[++i], &end, 10);
			if (!end || *end || quorum < 1 || quorum > 64) {
				fprintf(stderr, "fuzznetd: --quorum: a count from 1 to 64\n");
				return 2;
			}
		} else if (!strcmp(argv[i], "--root-at") && i + 2 < argc) {
			if (npulls >= FZND_PULL_TARGETS_MAX) {
				fprintf(stderr, "fuzznetd: at most %u peers to pull from\n",
				        FZND_PULL_TARGETS_MAX);
				return 2;
			}
			pulls[npulls].host = argv[++i];
			pulls[npulls].port = strtol(argv[++i], NULL, 10);
			pulls[npulls].is_root_at = 1;
			npulls++;
		} else if (!strcmp(argv[i], "--pull-from") && i + 3 < argc) {
			if (npulls >= FZND_PULL_TARGETS_MAX) {
				fprintf(stderr, "fuzznetd: at most %u peers to pull from\n",
				        FZND_PULL_TARGETS_MAX);
				return 2;
			}
			if (!hex_pubkey(argv[++i], pulls[npulls].node)) {
				fprintf(stderr, "fuzznetd: --pull-from: a node key is 64 hex digits\n");
				return 2;
			}
			pulls[npulls].host = argv[++i];
			pulls[npulls].port = strtol(argv[++i], NULL, 10);
			pulls[npulls].is_root_at = 0;
			npulls++;
		} else if (!strncmp(argv[i], "--log-dir=", 10u)) {
			log_dir = argv[i] + 10;
		} else if (!strncmp(argv[i], "--log-archive=", 14u) && argv[i][14]) {
			log_archive = argv[i] + 14;
		} else if (!strcmp(argv[i], "--no-log-file")) {
			log_file = 0;
		} else if (!strcmp(argv[i], "--op-journal")) {
			op_journal = 1;
		} else if (!strncmp(argv[i], "--op-journal-replay=", 20u)) {
			char *end = NULL;

			op_journal = 1;
			replaying = 1;
			replay_to = strtoull(argv[i] + 20, &end, 10);
			if (!end || *end != '\0') {
				fprintf(stderr, "fuzznetd: --op-journal-replay=ENTRY: an entry's number\n");
				return 2;
			}
		} else if (!strncmp(argv[i], "--op-journal-generation=", 24u)) {
			char *end = NULL;

			replay_generation = strtoull(argv[i] + 24, &end, 10);
			if (!end || *end != '\0' || replay_generation == 0u) {
				fprintf(stderr, "fuzznetd: --op-journal-generation=N: a generation's "
				                "number\n");
				return 2;
			}
		} else if (!strncmp(argv[i], "--op-journal-rotate=", 20u)) {
			char *end = NULL;

			op_journal = 1;
			op_journal_rotate = strtoull(argv[i] + 20, &end, 10);
			if (!end || *end != '\0' || op_journal_rotate == 0u) {
				fprintf(stderr, "fuzznetd: --op-journal-rotate=WRITES: writes a generation "
				                "takes\n");
				return 2;
			}
		} else if (!strncmp(argv[i], "--into=", 7u)) {
			replay_into = argv[i] + 7;
		} else if (!strncmp(argv[i], "--op-journal=", 13u)) {
			char *end = NULL;

			op_journal = 1;
			op_journal_budget = strtoull(argv[i] + 13, &end, 10);
			if (!end || *end != '\0' || op_journal_budget == 0u) {
				fprintf(stderr, "fuzznetd: --op-journal=BYTES: a byte budget\n");
				return 2;
			}
		} else if (!strncmp(argv[i], "--log-scope=", 12u)) {
			if (!strcmp(argv[i] + 12, "estate")) {
				log_estate = 1;
			} else if (!strcmp(argv[i] + 12, "host-private")) {
				log_estate = 0;
			} else {
				fprintf(stderr, "fuzznetd: --log-scope: host-private or estate\n");
				return 2;
			}
		} else if (!strncmp(argv[i], "--log-copy", 10u) || !strncmp(argv[i], "--log-push", 10u)) {
			/* RETIRED, sec 573, said rather than left to read as unknown: a
			 * host's logs travel by the bucket exchange both ways, held as its
			 * retention rules say and served to holders of retention. */
			fprintf(stderr, "fuzznetd: %.10s is retired: logs travel by the bucket exchange "
			                "both ways; to hold fewer copies, `--log-rule=policy log drop` and "
			                "keep rules naming `copy`\n",
			        argv[i]);
			return 2;
		} else if (!strcmp(argv[i], "--check-log") || !strncmp(argv[i], "--check-log=", 12u)) {
			check_log = argv[i][11] == '=' ? argv[i] + 12 : "fuzznetd";
		} else if (!strncmp(argv[i], "--gather=", 9u)) {
			gather_program = argv[i] + 9;
		} else if (!strcmp(argv[i], "--gather-ring")) {
			gather_ring = 1;
		} else if (!strcmp(argv[i], "--short")) {
			gather_short = 1;
		} else if (!strncmp(argv[i], "--match=", 8u)) {
			gather_match = argv[i] + 8;
		} else if (!strncmp(argv[i], "--since=", 8u)) {
			char *end = NULL;
			unsigned long long v = strtoull(argv[i] + 8, &end, 10);

			if (!end || *end) {
				fprintf(stderr, "fuzznetd: --since: seconds before now\n");
				return 2;
			}
			gather_since_s = (uint64_t)v;
		} else if (!strncmp(argv[i], "--log-level=", 12u)) {
			static const char *const NAMES[] = { "critical", "error", "warning", "note",
				                             "info", "verbose", "debug", "trace" };
			const char *v = argv[i] + 12;
			int found = 0, l;

			for (l = 1; l <= 8; l++)
				if (!strcmp(v, NAMES[l - 1])
				    || (v[0] && !v[1]
				        && v[0] == fzn_entry_level_letter((fzn_entry_level_t)l))) {
					log_keep = (fzn_entry_level_t)l;
					found = 1;
				}
			if (!found) {
				fprintf(stderr, "fuzznetd: --log-level: one of critical, error, warning, "
				                "note, info, verbose, debug, trace, or its letter\n");
				return 2;
			}
		} else if (!strncmp(argv[i], "--log-segment=", 14u)) {
			char *end = NULL;
			unsigned long long v = strtoull(argv[i] + 14, &end, 10);

			if (!end || *end || v < 4096u) {
				fprintf(stderr, "fuzznetd: --log-segment: bytes, at least 4096\n");
				return 2;
			}
			log_segment = (uint64_t)v;
		} else if (!strncmp(argv[i], "--log-rule=", 11u)) {
			const char *v = argv[i] + 11;

			if (dlog.n_rules >= FZND_LOG_RULES_MAX
			    || fzn_retain_parse(v, strlen(v), &dlog.rules[dlog.n_rules])
			               != FZN_RETAIN_OK) {
				fprintf(stderr, "fuzznetd: --log-rule: at most %u rules, each "
				                "\"prune|keep PROGRAM|* [level=LETTERS] [subsystem=PATH] "
				                "age|size|count N[unit]\" or \"prune|keep messages "
				                "[contact=KEY] age|size|count N[unit]\"\n",
				        FZND_LOG_RULES_MAX);
				return 2;
			}
#ifndef FZN_LOG_FILE_ON
			/* A LOG RULE WITH NO LOGS is refused rather than ignored; a rule
			 * over conversations, sec 531, needs none. */
			if (dlog.rules[dlog.n_rules].data == FZN_RETAIN_LOG) {
				fprintf(stderr, "fuzznetd: --log-rule: built without log files\n");
				return 2;
			}
#elif !defined(FZN_LOG_PACK_ON)
			/* AN ENTRY RULE REWRITES SEGMENTS, which only the packing build
			 * does (sec 474): refused here rather than silently ignored. */
			if (fzn_retain_rule_selects_entries(&dlog.rules[dlog.n_rules])) {
				fprintf(stderr, "fuzznetd: --log-rule: a level or a subsystem needs "
				                "the build with zstd\n");
				return 2;
			}
#endif
			dlog.n_rules++;
		} else if (!strcmp(argv[i], "--to") && i + 2 < argc) {
			to_host = argv[++i];
			to_port = strtol(argv[++i], NULL, 10);
		} else {
			/* FUZZNET'S OWN OPTIONS ARE FUZZNET'S PARSER'S, so this
			 * daemon, the config dialog and every consumer refuse the
			 * same values in the same words (sec 140). */
			int claimed = 0;
			fzn_cli_err_t cerr = fzn_cli_arg(&cli, argv[i], &claimed);

			if (claimed && cerr != FZN_CLI_OK) {
				fprintf(stderr, "fuzznetd: %s: %s\n", argv[i],
				        fzn_cli_err_str(cerr));
				return 2;
			}
			if (!claimed) {
				usage(argv[0]);
				return 2;
			}
		}
	}
	/* THE NODE'S OPTIONS ARE FUZZNET'S PARSER'S since sec 421, read back
	 * here into the names this main has always used. */
	sock_path = cli.socket;
	udp_port = cli.has_udp_port ? (long)cli.udp_port : -1;
	if (cli.udp6)
		family = AF_INET6;
	pair_hex = cli.pair;
	show_prekey = cli.prekey;
	accept_text = cli.accept;
	/* A NODE THAT SERVES ONLY THE REMOTE HOP needs no local socket, and the
	 * loop has always taken a listen fd of -1 (sec 381). */
	if (!sock_path && !pair_hex && !show_prekey && !new_root && !accept_text && !ask_line
	    && !gather_program && !gather_ring && !check_log
	    && !set_admin && !replaying && udp_port < 0 && !cli.dir) {
		usage(argv[0]);
		return 2;
	}
	/* THE DEFAULT SOCKET, sec 663, the holder's of 2026-10-20: a daemon that
	 * serves a store and is told no `--socket` serves on
	 * `$XDG_RUNTIME_DIR/fuzznet/fuzznetd.sock` (`local/socket.h`), its
	 * directory made this user's and 0700, where a client looks when it is
	 * told nowhere. A one-shot command serves nothing and takes none. */
	serving = cli.dir && !pair_hex && !show_prekey && !new_root && !accept_text && !ask_line
	          && !gather_program && !gather_ring && !check_log && !set_admin && !replaying;
	if (!sock_path && serving) {
		static char default_sock[108]; /* sun_path's length on Linux */
		fzn_socket_err_t serr = fzn_socket_default_path(default_sock, sizeof(default_sock));

		if (serr == FZN_SOCKET_OK)
			serr = fzn_socket_default_dir_make(default_sock);
		if (serr != FZN_SOCKET_OK) {
			fprintf(stderr, "fuzznetd: no --socket given, and the default socket %s cannot "
			                "be served: %s\n", default_sock,
			        serr == FZN_SOCKET_ERR_PATH ? "its directory is not this user's own and "
			                                      "mode 0700, or the path is too long"
			                                    : "its directory could not be made");
			return 1;
		}
		sock_path = default_sock;
	}

	memset(&state, 0, sizeof(state));
	state.config.uid = (uint32_t)getuid();
	state.config.local_origins = FZN_ORIGIN_BIT(FZN_ORIGIN_SAME_USER);
	if (group >= 0) {
		state.config.has_service_gid = 1;
		state.config.service_gid = (uint32_t)group;
		state.config.local_origins |= FZN_ORIGIN_BIT(FZN_ORIGIN_LOCAL);
	}
	state.udp_fd = -1;

	/* THE REMOTE HOP COULD NOT SERVE A SINGLE FRAME BEFORE THIS.
	 *
	 * `serve_ready_datagram` hands `state->hash`, `aead`, `sign` and
	 * `replay` to `fzn_node_serve_datagram`, and this main zeroed the
	 * state and filled none of them -- so a daemon started with
	 * `--udp-port` bound a socket, loaded peers once sec 367 let it, and
	 * dropped everything that arrived. Looking configured while serving
	 * nobody is the symptom these last sections exist to end, so the ops
	 * are wired here and the identity is required rather than defaulted.
	 *
	 * NO SECRET IS NEEDED TO SERVE. Verifying a peer's chain needs the
	 * root's PUBLIC key, opening its frames needs the session key that
	 * came with the peer record, and sealing a reply needs the same
	 * session key -- `fzn_node_seal_reply` carries no capability and signs
	 * nothing. So this daemon holds no private key at all, which is why it
	 * can read its identity from a command line. Minting is what needs a
	 * secret, and this daemon still does not mint. */
	fzn_hash_monocypher_init(&hash_ops);
	fzn_aead_monocypher_init(&aead_ops);
	fzn_random_system_init(&rng_ops);
	memset(&signer, 0, sizeof(signer));
	fzn_sign_monocypher_init(&sign_ops, &signer);
	fzn_sign_monocypher_seat_init(&seat, &signer);
	fzn_sign_monocypher_init(&root_sign_ops, &root_signer);
	fzn_sign_monocypher_seat_init(&root_seat, &root_signer);
	fzn_agree_monocypher_init(&agree_ops);
	if (fzn_replay_init(&replay, replay_entries, FZND_REPLAY_ENTRIES,
	                    FZND_MAX_AHEAD) != FZN_FRESH_OK) {
		fprintf(stderr, "fuzznetd: the replay window would not initialise\n");
		return 1;
	}
	state.hash = &hash_ops;
	state.aead = &aead_ops;
	state.sign = &sign_ops;
	state.rng = &rng_ops;
	state.replay = &replay;
	state.clock = wall_clock;

	/* THE CAPABILITY THE REMOTE HOP REQUIRES, which this main never set.
	 * `state` is zeroed, so the hop required the all-zero capability id --
	 * one `fzn_service_capability` refuses to make, because a capability
	 * naming no service must not exist. No correctly provisioned peer could
	 * present it: the daemon bound, loaded its peers, and denied every one.
	 * It is derived from fuzznet's own options, and a remote hop without
	 * them is refused here rather than bound -- before the store is
	 * opened, so a refused command line creates nothing. sec 376. */
	if (cli.service != FZN_SERVICE_NONE || cli.product != FZN_PRODUCT_NONE) {
		if (fzn_service_capability(cli.service, cli.product, NULL, 0, &hash_ops,
		                           &state.config.remote_capability) != FZN_CHAIN_OK
		    || fzn_service_capability(cli.service, cli.product,
		                              (const uint8_t *)FZN_NODE_ADMIN_NAME,
		                              sizeof(FZN_NODE_ADMIN_NAME) - 1u, &hash_ops,
		                              &state.config.admin_capability) != FZN_CHAIN_OK
		    || fzn_service_capability(cli.service, cli.product,
		                              (const uint8_t *)FZN_NODE_RETENTION_NAME,
		                              sizeof(FZN_NODE_RETENTION_NAME) - 1u, &hash_ops,
		                              &state.config.retention_capability) != FZN_CHAIN_OK) {
			fprintf(stderr, "fuzznetd: the remote capability needs both "
			                "--fuzznet-service and --fuzznet-product\n");
			return 2;
		}
		has_capability = 1;
		state.config.has_admin = 1;
		state.config.has_retention = 1;
	}
	if ((udp_port >= 0 || pair_hex) && !has_capability) {
		fprintf(stderr, "fuzznetd: %s needs --fuzznet-service and --fuzznet-product: "
		                "the remote hop checks one capability, and with none "
		                "configured it would require one nobody can hold\n",
		        pair_hex ? "--pair" : "--udp-port");
		return 2;
	}

	/* THE STORE, OPENED BEFORE THE IDENTITY because the identity may live
	 * in it. A store that cannot be opened is fatal, for the reason the
	 * peer load below gives. */
	store_dir = cli.dir;
	bulk_dir = cli.store ? cli.store : cli.dir;
	state_core_dir = store_dir;
	state_bulk_dir = (cli.store && store_dir && strcmp(cli.store, store_dir) != 0) ? cli.store
	                                                                            : NULL;
	/* THE FACE OR A FOLLOWER, sec 666: a daemon that serves a store takes
	 * the claim on its core directory before booting anything -- a follower
	 * writes nothing -- and one that cannot take it follows the face. */
#ifdef FZN_CLAIM_FILE_ON
	if (serving && store_dir) {
		static fzn_claim_file_t claim_file;
		static fzn_claim_ops_t claim_ops;
		static fzn_claim_t claim;
		char claim_path[1100];
		fzn_claim_err_t cerr;

		/* NO DIRECTORY MADE HERE: a store that is not there is fatal, as
		 * it always was, so a mistyped `--fuzznet-dir` is refused rather
		 * than started empty. */
		(void)snprintf(claim_path, sizeof(claim_path), "%s/claim", store_dir);
		if (fzn_claim_file_open(&claim_file, claim_path, &claim_ops) != FZN_CLAIM_OK
		    || fzn_claim_init(&claim, &claim_ops) != FZN_CLAIM_OK) {
			fprintf(stderr, "fuzznetd: the claim at %s would not open -- is %s a store?\n",
			        claim_path, store_dir);
			return 1;
		}
		cerr = fzn_claim_take(&claim);
		if (cerr == FZN_CLAIM_ERR_HELD)
			return follower_main(sock_path, store_dir, &claim);
		if (cerr != FZN_CLAIM_OK) {
			fprintf(stderr, "fuzznetd: the claim at %s cannot be decided\n", claim_path);
			return 1;
		}
		face_dir = store_dir;
	}
#endif
	if (store_dir) {
		route.core = fzn_persist_file_init(&core_file, store_dir);
		route.store = (bulk_dir == store_dir) ? route.core
		                                      : fzn_persist_file_init(&bulk_file, bulk_dir);
		if (!route.core || !route.store) {
			fprintf(stderr, "fuzznetd: could not open %s\n",
			        route.core ? bulk_dir : store_dir);
			return 1;
		}
		fzn_persist_route_ops(&route, &routed);
		store_ops = &routed;
		dlog.store = store_ops;
	} else if (cli.store) {
		fprintf(stderr, "fuzznetd: --fuzznet-store needs --fuzznet-dir: the identity "
		                "and what keeps attackers out live in the core directory\n");
		return 2;
	}

	/* THIS NODE'S OWN IDENTITY, from the store, when none was named.
	 *
	 * `--identity` keeps its meaning: a daemon that serves with a public
	 * key alone and holds no secret, which sec 368 built and which a
	 * deployment keeping its root key elsewhere still wants. Without it and
	 * with a store, the daemon becomes a node that owns its key -- and the
	 * store is asked, per part, whether it holds it, because generating
	 * over a store that was merely unreadable would replace this node with
	 * a stranger. A partial store is refused by name; which part is gone
	 * and what to do about it is the operator's. */
	if (!identity_hex && store_ops) {
		fzn_node_identity_env_t env;
		fzn_node_identity_found_t found;
		fzn_node_identity_err_t ierr;
		int created = 0;

		env.store = store_ops;
		env.rng = &rng_ops;
		env.seat = &seat;
		env.sign = &sign_ops;
		env.hash = &hash_ops;
		env.agree = &agree_ops;
		env.log = NULL; /* this main reports on stderr below */
		found.seed = fzn_persist_file_holds(&core_file, FZN_PERSIST_OWN_IDENTITY, NULL);
		found.prekey = fzn_persist_file_holds(&core_file, FZN_PERSIST_OWN_PREKEY, NULL);
		found.trust = fzn_persist_file_holds(&core_file, FZN_PERSIST_TRUST, NULL);
		ierr = fzn_node_identity_boot(&env, &found, wall_clock(), &agree_secret, &trust,
		                              &identity, &created);
		if (ierr != FZN_NODE_IDENTITY_OK) {
			fprintf(stderr, "fuzznetd: no identity from %s: %s\n", store_dir,
			        fzn_node_identity_err_str(ierr));
			if (ierr == FZN_NODE_IDENTITY_PARTIAL)
				fprintf(stderr, "fuzznetd: identity %s, prekey %s, anchor %s\n",
				        found.seed == FZN_PERSIST_OK ? "present" : "absent",
				        found.prekey == FZN_PERSIST_OK ? "present" : "absent",
				        found.trust == FZN_PERSIST_OK ? "present" : "absent");
			return 1;
		}
		memcpy(state.node_pubkey, identity.pubkey, FZN_PUBKEY_LEN);
		memcpy(state.config.root, fzn_trust_root(&trust), FZN_PUBKEY_LEN);
		booted = 1;
		fprintf(stderr, "fuzznetd: identity ");
		print_hex(stderr, identity.pubkey, FZN_PUBKEY_LEN);
		fprintf(stderr, " %s %s\n", created ? "created in" : "loaded from", store_dir);
#ifdef FZN_RECORD_STORE_FILE_ON
		/* THE OPERATION JOURNAL WRAPS THE STORE FROM HERE, sec 523: its
		 * entries are signed as this node, so not before the identity.
		 * The one write before it is the identity's own seed, a slot that
		 * keeps no bytes anyway. Everything handed the store after this
		 * is handed the journalled ops. */
		if (op_journal) {
			if (!op_journal_open(store_dir, identity.pubkey, &sign_ops, &hash_ops,
			                     op_journal_budget, op_journal_rotate, replaying,
			                     &store_ops)) {
				fprintf(stderr, "fuzznetd: --op-journal: no operation journal in "
				                "%s/opjournal, or its generations do not run unbroken\n",
				        store_dir);
				return 1;
			}
			dlog.store = store_ops;
			/* REPLAY AND EXIT: the replayable slots as they stood after
			 * entry `replay_to`, into a fresh store at `replay_into`. */
			if (replaying) {
				static fzn_persist_file_t into_file;
				const fzn_persist_ops_t *into;
				fzn_opjournal_replay_tally_t rt;

				if (!replay_into || (mkdir(replay_into, 0700) != 0 && errno != EEXIST)
				    || !(into = fzn_persist_file_init(&into_file, replay_into))) {
					fprintf(stderr, "fuzznetd: --op-journal-replay needs --into=DIR, a "
					                "directory it can make\n");
					return 2;
				}
				if (!fzn_opjournal_replay(&op_oj, replay_generation, replay_to, into, &rt)) {
					fprintf(stderr, "fuzznetd: generation %llu is not held whole (%llu to "
					                "%llu are), or the replay stopped at an entry that will "
					                "not read, or a write %s refused\n",
					        replay_generation ? replay_generation
					                          : (unsigned long long)op_oj.last,
					        (unsigned long long)op_oj.first, (unsigned long long)op_oj.last,
					        replay_into);
					return 1;
				}
				printf("replayed into %s: %zu saved, %zu removed, %zu missing, %zu "
				       "skipped\n",
				       replay_into, rt.saved, rt.removed, rt.missing, rt.skipped);
				return 0;
			}
			fprintf(stderr, "fuzznetd: operation journal on, generations %llu to %llu, "
			                "%llu entr%s in the newest, %llu byte(s) kept of %llu\n",
			        (unsigned long long)op_oj.first, (unsigned long long)op_oj.last,
			        (unsigned long long)fzn_opjournal_entries(&op_oj, 0u),
			        fzn_opjournal_entries(&op_oj, 0u) == 1u ? "y" : "ies",
			        (unsigned long long)op_oj.kept, (unsigned long long)op_journal_budget);
		}
#endif

		/* A NODE THAT HAS JOINED AN ESTATE grants through the hop its root
		 * gave it, which it holds as its pairing to that root (sec 383). A
		 * joined node without one still serves; it cannot pair, and
		 * `fzn_node_pair` says so when asked. */
		if (memcmp(state.config.root, identity.pubkey, FZN_PUBKEY_LEN) != 0) {
			fprintf(stderr, "fuzznetd: member of the estate rooted at ");
			print_hex(stderr, state.config.root, FZN_PUBKEY_LEN);
			fprintf(stderr, "\n");
			/* Found by shape: joined through a member, the pairing
			 * is filed under that member, not the root. sec 391. */
			if (fzn_node_pairing_estate(store_ops, state.config.root, identity.pubkey,
			                            &estate) == FZN_PERSIST_OK) {
				authority.hops = (const uint8_t (*)[FZN_HOP_LEN])estate.chain;
				authority.hop_count = estate.hop_count;
				my_authority = &authority;
			}
		}
	}

	/* The node's own public identity, and the root its peers' chains must
	 * reach. They are the same key for a node that provisioned its own
	 * peers -- `node/provision.h` says the identity IS the root when a
	 * node mints -- so `--root` is an override for the case where somebody
	 * else is root, not a second thing to remember. */
	if (identity_hex && !hex_pubkey(identity_hex, state.node_pubkey)) {
		fprintf(stderr, "fuzznetd: --identity is not 64 hex characters\n");
		return 2;
	}
	if (identity_hex)
		memcpy(state.config.root, state.node_pubkey, FZN_PUBKEY_LEN);
	if (root_hex && !hex_pubkey(root_hex, state.config.root)) {
		fprintf(stderr, "fuzznetd: --root is not 64 hex characters\n");
		return 2;
	}

	/* THIS NODE'S PREKEY RECORD, which is what another node pairs it by:
	 * the other half of `--pair`, for the node that is the device. Self-
	 * signed, so it proves authorship and not identity -- the operator
	 * carrying it to the pairing node is what vouches for it. */
	if (show_prekey) {
		if (!booted) {
			fprintf(stderr, "fuzznetd: --prekey needs --fuzznet-dir, and no --identity\n");
			return 2;
		}
		print_hex(stdout, identity.prekey_record, FZN_PREKEY_LEN_TOTAL);
		printf("\n");
		return 0;
	}

	/* THIS NODE'S ADMIN CHAIN, sec 416: the `h` items `grant admin` answered,
	 * verified from a root of the estate -- the set this node holds -- for
	 * the admin capability, naming this node, and kept in the core
	 * directory. Offline, as `--pair` is; the daemon votes on it from its
	 * next start. */
	if (set_admin) {
		static fzn_node_roots_t held;
		static fzn_revocation_t none[1];
		static uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
		fzn_revocation_store_t judged;
		fzn_node_revoke_err_t rerr;
		const char *at = set_admin;
		size_t n = 0, nroots = 0;

		if (!booted || !store_ops || !has_capability) {
			fprintf(stderr, "fuzznetd: --set-admin needs --fuzznet-dir and the service "
			                "options its capability is derived from\n");
			return 2;
		}
		while (*at) {
			char item[(FZN_HOP_LEN * 2u) + 1u];

			while (*at == ' ')
				at++;
			if (!*at)
				break;
			if (*at == 'h')
				at++;
			if (n >= FZN_CHAIN_MAX_HOPS - 1u || strlen(at) < FZN_HOP_LEN * 2u) {
				fprintf(stderr, "fuzznetd: --set-admin is not a chain of hops\n");
				return 2;
			}
			memcpy(item, at, FZN_HOP_LEN * 2u);
			item[FZN_HOP_LEN * 2u] = '\0';
			if (!hex_bytes(item, hops[n], FZN_HOP_LEN)) {
				fprintf(stderr, "fuzznetd: --set-admin is not a chain of hops\n");
				return 2;
			}
			n++;
			at += FZN_HOP_LEN * 2u;
		}
		if (fzn_revocation_store_init(&judged, none, 1u) != FZN_CHAIN_OK
		    || fzn_node_roots_init(&held, state.config.root, &sign_ops, &hash_ops)
		               != FZN_NODE_ROOTS_OK
		    || fzn_node_roots_load(&held, store_ops, &nroots) != FZN_NODE_ROOTS_OK
		    || fzn_node_roots_attach(&held, &judged) != FZN_NODE_ROOTS_OK) {
			fprintf(stderr, "fuzznetd: --set-admin could not restore the roots\n");
			return 1;
		}
		rerr = fzn_node_admin_chain_set(store_ops, &judged, &identity, state.config.root,
		                                &state.config.admin_capability,
		                                (const uint8_t (*)[FZN_HOP_LEN])hops, n, wall_clock(),
		                                &own_admin);
		if (rerr != FZN_NODE_REVOKE_OK) {
			fprintf(stderr, "fuzznetd: --set-admin: %s\n", fzn_node_revoke_err_str(rerr));
			return 1;
		}
		fprintf(stderr, "fuzznetd: admin chain of %zu hop(s) kept\n", n);
		return 0;
	}

	/* A ROOT KEY OF THIS NODE'S OWN, sec 409: generated, saved in the core
	 * directory, and its public key printed. It is a root only once a
	 * standing root adds it -- `add root KEY` on that root's node. */
	if (new_root) {
		static fzn_node_roots_t mine;

		if (!booted || !store_ops) {
			fprintf(stderr, "fuzznetd: --new-root needs --fuzznet-dir\n");
			return 2;
		}
		if (fzn_node_roots_init(&mine, identity.pubkey, &sign_ops, &hash_ops)
		            != FZN_NODE_ROOTS_OK) {
			fprintf(stderr, "fuzznetd: --new-root could not start\n");
			return 1;
		}
		{
			fzn_node_roots_err_t rerr = fzn_node_roots_key_create(&mine, store_ops, &rng_ops,
			                                                      &root_seat,
			                                                      &root_sign_ops);

			if (rerr != FZN_NODE_ROOTS_OK) {
				fprintf(stderr, "fuzznetd: --new-root: %s\n",
				        fzn_node_roots_err_str(rerr));
				return 1;
			}
		}
		print_hex(stdout, mine.key, FZN_PUBKEY_LEN);
		printf("\n");
		return 0;
	}

	/* THE DEVICE'S HALF OF `--pair`: accept a node's card and keep the
	 * pairing. It prints the node's root, which is the name the pairing is
	 * filed under and what the device asks the node by. sec 377. */
	if (accept_text) {
		uint8_t card[FZN_PROVISION_MAX_LEN];
		size_t card_len = 0;
		fzn_node_pairing_t paired;
		fzn_node_pair_err_t perr;

		if (!booted) {
			fprintf(stderr, "fuzznetd: --accept needs --fuzznet-dir, and no --identity\n");
			return 2;
		}
		if (fzn_provision_from_text(accept_text, card, sizeof(card), &card_len)
		    != FZN_PROVISION_OK) {
			fprintf(stderr, "fuzznetd: --accept is not a card\n");
			return 2;
		}
		perr = join ? fzn_node_join(&identity, card, card_len, wall_clock(), store_ops,
		                            &trust, &paired)
		            : fzn_node_pairing_accept(&identity, card, card_len, wall_clock(),
		                                      store_ops, &paired);
		if (perr != FZN_NODE_PAIR_OK) {
			fprintf(stderr, "fuzznetd: not accepted: %s\n", fzn_node_pair_err_str(perr));
			return 1;
		}
		if (join) {
			fprintf(stderr, "fuzznetd: joined the estate rooted at ");
			print_hex(stderr, fzn_trust_root(&trust), FZN_PUBKEY_LEN);
			fprintf(stderr, " through ");
		} else {
			fprintf(stderr, "fuzznetd: paired to ");
		}
		print_hex(stderr, paired.node, FZN_PUBKEY_LEN);
		fprintf(stderr, "\n");
		print_hex(stdout, paired.node, FZN_PUBKEY_LEN);
		printf("\n");
		fzn_wipe(&paired, sizeof(paired));
		return 0;
	}

	/* THE DEVICE ASKING THE NODE IT IS PAIRED TO, which is the other half of
	 * the remote hop and what a device could not do from a command line.
	 * The line is fuzznet's grammar (sec 381); the credentials are the
	 * stored pairing, looked up by the node's root; the address is given,
	 * since a pairing carries none. Prints the reply line and exits 0 when
	 * it is `ok`. */
	/* CHECKING A LOG'S CHAIN, sec 482: offline, from the log directory,
	 * every packed segment of a program verified against the one before
	 * and every signature checked; who signed said, this node by name. */
	if (check_log) {
#ifdef FZN_LOG_PACK_ON
		static fzn_log_pack_report_t report;
		char dir[FZN_LOGGER_PATH_MAX];
		const char *where = log_dir;
		fzn_log_pack_err_t perr;

		if (!where) {
			if (fzn_logger_default_dir(dir, sizeof(dir)) != FZN_LOGGER_OK) {
				fprintf(stderr, "fuzznetd: --check-log: no log directory\n");
				return 2;
			}
			where = dir;
		}
		perr = fzn_log_pack_check(where, check_log, &hash_ops, &sign_ops, &report);
		if (perr != FZN_LOG_PACK_OK) {
			fprintf(stderr, "fuzznetd: %s's log: %s, at %s, after %zu that held\n", check_log,
			        fzn_log_pack_err_str(perr), report.broken, report.segments);
			return 1;
		}
		printf("fuzznetd: %s's log: %zu packed segment(s), the chain holds; %zu signed%s%s\n",
		       check_log, report.segments, report.signed_count,
		       !report.signed_count ? ""
		       : report.signers_differ ? ", by more than one key"
		       : (booted && memcmp(report.signer, identity.pubkey, FZN_PUBKEY_LEN) == 0)
		               ? ", by this node"
		               : ", by another node",
		       report.signed_count < report.segments ? "; the rest unsigned" : "");
		return 0;
#else
		fprintf(stderr, "fuzznetd: --check-log: built without packing (FZN_LOG_PACK)\n");
		return 2;
#endif
	}
#ifdef FZN_LOG_FILE_ON
	/* GATHERING, secs 463, 464 and 466: from the host --node and --to name,
	 * and from every host --root-at and --pull-from name, one after
	 * another; their lines merged by time and printed. A host that does
	 * not answer is said and the rest are still asked. */
	if (gather_program || gather_ring) {
		static fzn_partial_t slots[1];
		static uint8_t slot_buf[1][1u << 17];
		static struct gathered g;
		size_t ntargets = npulls + (to_host ? 1u : 0u), t, k;
		int failed = 0;

		if (!booted || ntargets == 0u || (to_host && (!cli.has_node || to_port < 0
		                                               || to_port > 65535))) {
			fprintf(stderr, "fuzznetd: --gather needs --fuzznet-dir, and --node with "
			                "--to, or --root-at or --pull-from\n");
			return 2;
		}
		for (t = 0; t < ntargets; t++) {
			fzn_node_pairing_t pairing;
			fzn_reasm_t table;
			fzn_caller_t caller;
			const char *host;
			long port;
			int fd = -1, ok;
			size_t got = 0;
			fzn_gather_err_t gerr;

			if (to_host && t == 0u) {
				host = to_host;
				port = to_port;
				ok = fzn_node_pairing_load(store_ops, cli.node, &pairing) == FZN_PERSIST_OK;
			} else {
				struct pull_target *pt = &pulls[t - (to_host ? 1u : 0u)];

				host = pt->host;
				port = pt->port;
				if (pt->is_root_at) {
					ok = my_authority != NULL;
					pairing = estate;
				} else {
					ok = fzn_node_pairing_load(store_ops, pt->node, &pairing)
					     == FZN_PERSIST_OK;
				}
			}
			if (!ok) {
				fprintf(stderr, "fuzznetd: %s: this node holds no pairing to it\n", host);
				failed = 1;
				continue;
			}
			memset(&caller, 0, sizeof(caller));
			if (port < 0 || port > 65535 || fzn_udp_bind(family, NULL, 0, &fd) != FZN_UDP_OK
			    || fzn_udp_resolve(family, host, (uint16_t)port, &caller.node) != FZN_UDP_OK
			    || fzn_reasm_slot_init(&slots[0], slot_buf[0], sizeof(slot_buf[0]))
			               != FZN_REASM_OK
			    || fzn_reasm_init(&table, slots, 1, 1u, 60u) != FZN_REASM_OK) {
				fprintf(stderr, "fuzznetd: %s: could not reach for it\n", host);
				fzn_wipe(&pairing, sizeof(pairing));
				if (fd >= 0)
					fzn_udp_close(fd);
				failed = 1;
				continue;
			}
			fzn_node_pairing_caller(&pairing, identity.pubkey, &caller);
			fzn_wipe(&pairing, sizeof(pairing));
			caller.fd = fd;
			caller.hash = &hash_ops;
			caller.aead = &aead_ops;
			caller.rng = &rng_ops;
			caller.reasm = &table;
			caller.hops = 1u;
			{
				struct peer_asking asking = { &caller, wall_clock(), host };

				g.host = host;
				if (gather_ring) {
					gerr = fzn_gather_ring_fetch(peer_ask, &asking, 256u, keep_entry, &g,
					                             &got);
				} else {
					fzn_gather_query_t q;
					uint64_t now_us = wall_clock() * 1000000u;

					memset(&q, 0, sizeof(q));
					q.since_us = gather_since_s && gather_since_s * 1000000u < now_us
					                     ? now_us - (gather_since_s * 1000000u)
					                     : 0u;
					q.until_us = UINT64_MAX;
					(void)snprintf(q.program, sizeof(q.program), "%s", gather_program);
					(void)snprintf(q.match, sizeof(q.match), "%s", gather_match);
					gerr = fzn_gather_fetch(peer_ask, &asking, &q, 4096u, keep_line, &g,
					                        &got);
				}
			}
			fzn_wipe(&caller, sizeof(caller));
			fzn_udp_close(fd);
			if (gerr != FZN_GATHER_OK) {
				fprintf(stderr, "fuzznetd: %s: %s\n", host, fzn_gather_err_str(gerr));
				failed = 1;
			} else {
				fprintf(stderr, "fuzznetd: %zu %s from %s\n", got,
				        gather_ring ? "ring entr(ies)" : "line(s)", host);
			}
		}
		qsort(g.lines, g.n, sizeof(*g.lines), by_time);
		{
			/* --short, sec 467: each line read back and shown as the viewer
			 * shortens it against the one before; one that will not read
			 * is printed as it came. */
			static uint8_t text_a[FZN_ENTRY_TEXT_MAX], text_b[FZN_ENTRY_TEXT_MAX];
			static char shown[FZN_ENTRY_LINE_MAX + 64u];
			static const uint8_t no_machine[FZN_ENTRY_MACHINE_LEN];
			fzn_entry_t cur, prev;
			char cur_host[FZN_ENTRY_WORD_MAX + 1u], prev_host[FZN_ENTRY_WORD_MAX + 1u];
			int have_prev = 0;

			for (k = 0; k < g.n; k++) {
				const char *line = g.lines[k].text;
				size_t len = 0;

				if (gather_short
				    && fzn_entry_classic_parse(line, strlen(line), no_machine, &cur, cur_host,
				                               k % 2u ? text_b : text_a, FZN_ENTRY_TEXT_MAX)
				               == FZN_ENTRY_OK
				    && fzn_entry_view(have_prev ? &prev : NULL, prev_host, &cur, cur_host,
				                      shown, sizeof(shown), &len)
				               == FZN_ENTRY_OK) {
					fwrite(shown, 1u, len, stdout);
					prev = cur;
					memcpy(prev_host, cur_host, sizeof(prev_host));
					have_prev = 1;
				} else {
					printf("%s\n", line);
				}
				free(g.lines[k].text);
			}
		}
		free(g.lines);
		if (g.full)
			fprintf(stderr, "fuzznetd: stopped at %u MiB; ask with --since or --match\n",
			        FZND_GATHER_BYTES_MAX / (1024u * 1024u));
		return failed ? 1 : 0;
	}
#else
	if (gather_program || gather_ring) {
		fprintf(stderr, "fuzznetd: --gather: built without log files (FZN_LOG_FILE)\n");
		return 2;
	}
	/* --short, --match and --since shape a gathering, which this build
	 * refuses above; alone they ask for nothing, as in the build with logs. */
	(void)gather_short;
	(void)gather_match;
	(void)gather_since_s;
#endif
	if (ask_line) {
		static fzn_partial_t slots[1];
		/* A GATHERED PAGE is as large as the host's reply buffer. */
		static uint8_t slot_buf[1][1u << 17];
		static uint8_t answer[1u << 17];
		uint8_t node_root[FZN_PUBKEY_LEN];
		fzn_node_pairing_t pairing;
		fzn_reasm_t table;
		fzn_caller_t caller;
		fzn_caller_err_t cerr;
		size_t answer_len = 0;
		uint32_t msg = 0;
		int fd = -1, rc;

		if (!booted || !cli.has_node || !to_host || to_port < 0 || to_port > 65535) {
			fprintf(stderr, "fuzznetd: --ask needs --fuzznet-dir, --node and --to\n");
			return 2;
		}
		memcpy(node_root, cli.node, FZN_PUBKEY_LEN);
		if (fzn_node_pairing_load(store_ops, node_root, &pairing) != FZN_PERSIST_OK) {
			fprintf(stderr, "fuzznetd: not paired to that node\n");
			return 1;
		}
		memset(&caller, 0, sizeof(caller));
		if (fzn_udp_bind(family, NULL, 0, &fd) != FZN_UDP_OK
		    || fzn_udp_resolve(family, to_host, (uint16_t)to_port, &caller.node)
		               != FZN_UDP_OK
		    || fzn_reasm_slot_init(&slots[0], slot_buf[0], sizeof(slot_buf[0]))
		               != FZN_REASM_OK
		    || fzn_reasm_init(&table, slots, 1, 1u, 60u) != FZN_REASM_OK) {
			fprintf(stderr, "fuzznetd: could not set up the request\n");
			fzn_wipe(&pairing, sizeof(pairing));
			if (fd >= 0)
				fzn_udp_close(fd);
			return 1;
		}
		fzn_node_pairing_caller(&pairing, identity.pubkey, &caller);
		fzn_wipe(&pairing, sizeof(pairing));
		caller.fd = fd;
		caller.hash = &hash_ops;
		caller.aead = &aead_ops;
		caller.rng = &rng_ops;
		caller.reasm = &table;
		caller.hops = 1u;
		/* The expiry sits inside the node's horizon: FZND_MAX_AHEAD is the
		 * lifetime plus the skew this daemon tolerates, and a request
		 * expiring later than that is refused as from the future. */
		cerr = fzn_caller_send(&caller, (const uint8_t *)ask_line, strlen(ask_line),
		                       wall_clock() + (FZND_MAX_AHEAD / 2u), &msg);
		if (cerr == FZN_CALLER_OK)
			cerr = fzn_caller_recv(&caller, msg, answer, sizeof(answer), &answer_len,
			                       3000u);
		fzn_wipe(&caller, sizeof(caller));
		fzn_udp_close(fd);
		if (cerr != FZN_CALLER_OK) {
			fprintf(stderr, "fuzznetd: no answer: %s\n", fzn_caller_err_str(cerr));
			return 1;
		}
		rc = fzn_reply_ok(fzn_reply_of(answer, answer_len, NULL, NULL)) ? 0 : 1;
		if (answer_len && answer[answer_len - 1u] == '\n')
			answer_len--;
		printf("%.*s\n", (int)answer_len, (const char *)answer);
		return rc;
	}

	if (pair_hex) {
		if (!booted) {
			fprintf(stderr, "fuzznetd: --pair needs --fuzznet-dir, and no --identity: "
			                "pairing mints, so the node must hold its key\n");
			return 2;
		}
		/* THROUGH THIS NODE'S ROOT KEY, sec 411, when it holds one that
		 * stands and is not its estate's root by identity: the key's grant
		 * to the identity, and the adds that make the key a root, travel on
		 * the card. Otherwise the chain it joined with, as before. */
		if (memcmp(state.config.root, identity.pubkey, FZN_PUBKEY_LEN) != 0) {
			static fzn_node_roots_t pair_roots;
			static uint8_t grant[FZN_HOP_LEN];
			static uint8_t proof[FZN_PROVISION_PROOF_MAX][FZN_PROVISION_PROOF_ITEM_LEN];
			static fzn_node_authority_t through_key;
			size_t nroots = 0;
			fzn_node_roots_err_t rerr;

			if (fzn_node_roots_init(&pair_roots, state.config.root, &sign_ops, &hash_ops)
			            != FZN_NODE_ROOTS_OK
			    || fzn_node_roots_load(&pair_roots, store_ops, &nroots) != FZN_NODE_ROOTS_OK
			    || fzn_node_roots_key_load(&pair_roots, store_ops, &root_seat,
			                               &root_sign_ops) != FZN_NODE_ROOTS_OK) {
				fprintf(stderr, "fuzznetd: --pair could not restore the roots in %s\n",
				        store_dir);
				return 1;
			}
			/* THE KEY'S GRANT GOES INTO THE JOURNAL, sec 508, or no peer
			 * rebuilds the chain the card carries. */
			if (!journal_for(store_dir, &pair_roots, &sign_ops, &hash_ops, store_ops))
				fprintf(stderr, "fuzznetd: no journal in %s/records: a grant through the "
				                "root key reaches no peer\n", store_dir);
			/* AS A ROOT BY IDENTITY FIRST, sec 419: one hop and the proof,
			 * a shorter card than a root key's two hops. */
			rerr = fzn_node_roots_identity_root(&pair_roots, store_ops, identity.pubkey,
			                                    proof, &through_key);
			if (rerr == FZN_NODE_ROOTS_NOT_ROOT)
				rerr = fzn_node_roots_self_grant(&pair_roots, store_ops, identity.pubkey,
				                                 &state.config.remote_capability, grant,
				                                 proof, &through_key);
			if (rerr == FZN_NODE_ROOTS_OK) {
				my_authority = &through_key;
			} else if (rerr != FZN_NODE_ROOTS_NOT_ROOT) {
				fprintf(stderr, "fuzznetd: not paired through the root key: %s\n",
				        fzn_node_roots_err_str(rerr));
				return 1;
			}
		}
		return pair_device(&identity, &state.config, my_authority, delegable, store_ops,
		                   store_dir, pair_hex, wall_clock());
	}
	/* REFUSED RATHER THAN BOUND. A remote hop with no identity seals its
	 * replies as from the zero key and verifies chains against a zero
	 * root, which no real peer can satisfy -- so it would bind, look
	 * healthy, and drop every frame. That is the exact failure this wiring
	 * closes, and starting anyway would reintroduce it with more moving
	 * parts. */
	if (udp_port >= 0 && !identity_hex && !booted) {
		fprintf(stderr, "fuzznetd: --udp-port needs --identity or --fuzznet-dir\n");
		return 2;
	}

	/* THE LOG OPENS BEFORE ANYTHING IS SAID, sec 461. A machine with no
	 * machine-id, or a directory that will not open, is said and served
	 * through: the daemon's work does not wait on its log. */
#ifdef FZN_LOG_FILE_ON
	if (log_file) {
		fzn_entry_name_t self;
		char host[FZN_ENTRY_WORD_MAX + 1u], dir[FZN_LOGGER_PATH_MAX];
		fzn_logger_err_t lerr = FZN_LOGGER_OK;

		if (!log_dir) {
			lerr = fzn_logger_default_dir(dir, sizeof(dir));
			log_dir = dir;
		}
		if (lerr == FZN_LOGGER_OK)
			lerr = fzn_logger_identify(&self, host, "fuzznetd", NULL);
		fzn_ring_init(&dlog.ring);
		if (lerr == FZN_LOGGER_OK)
			lerr = fzn_logger_open(&dlog.logger, &self, host, log_dir, log_keep, &dlog.ring,
			                       log_segment);
		if (lerr != FZN_LOGGER_OK) {
			fprintf(stderr, "fuzznetd: no log file: %s\n", fzn_logger_err_str(lerr));
		} else {
			int sigs[] = { SIGSEGV, SIGBUS, SIGABRT, SIGFPE, SIGILL };
			size_t k;

			dlog.on = 1;
			dlog.estate_scope = log_estate;
			dlog.hash = &hash_ops;
#ifdef FZN_LOG_PACK_ON
			dlog.verify = &sign_ops;
#endif
			dlog.logger.rotated = on_rotated;
			(void)snprintf(dlog.ring_path, sizeof(dlog.ring_path), "%s/fuzznetd.%lu.ring",
			               dlog.logger.dir, (unsigned long)self.pid);
			for (k = 0; k < sizeof(sigs) / sizeof(sigs[0]); k++)
				(void)signal(sigs[k], on_crash);
			say(FZN_ENTRY_NOTE, "log", "logging to %s at level %c", dlog.logger.dir,
			    fzn_entry_level_letter(log_keep));
		}
	}
#else
	(void)log_dir;
	(void)log_keep;
	(void)log_segment;
	(void)log_file;
	(void)log_estate;
#endif

	/* The socket mode lets a client connect; the authoritative gate is the
	 * in-process peer-credential check, which the kernel fills and no
	 * client can forge. A deployment may tighten ownership and mode on
	 * top of that. */
	if (sock_path && fzn_socket_listen(sock_path, 0777u, 16, &lfd) != FZN_SOCKET_OK) {
		say(FZN_ENTRY_ERROR, "node", "could not listen on %s", sock_path);
		return 1;
	}
	state.listen_fd = lfd;
	/* WHERE THE FACE SERVES, sec 666, for a follower to forward to: written
	 * by the claim's holder alone, removed at its exit. */
	if (face_dir && sock_path)
		face_write(face_dir, sock_path);

	if (udp_port >= 0) {
		if (fzn_udp_bind(family, NULL, (uint16_t)udp_port, &ufd) !=
		    FZN_UDP_OK) {
			say(FZN_ENTRY_ERROR, "node", "could not bind udp port %ld",
			        udp_port);
			fzn_socket_close(lfd, sock_path);
			return 1;
		}
		state.udp_fd = ufd;
		state.config.serves_remote = 1;
	}

	/* THE PEERS A CONSUMER ALREADY PROVISIONED, if a store was named.
	 *
	 * Static rather than automatic because the set is about 96 KiB at
	 * FZN_NODE_PEERS_MAX and a daemon's main frame is not where that
	 * belongs; `state.peers` borrows it for the life of the process, which
	 * is what `fzn_node_state_t` asks of it.
	 *
	 * A STORE THAT CANNOT BE READ IS FATAL. Serving nobody is what this
	 * exists to end, so starting anyway -- with the sockets bound and an
	 * empty peer set -- would reproduce the symptom while looking healthy.
	 * The one honest exception is a store that is simply EMPTY: that is a
	 * deployment which has provisioned nothing yet, and it is reported
	 * rather than refused. */
	if (store_ops) {
		static fzn_node_peer_t peers[FZN_NODE_PEERS_MAX];
		static fzn_node_admin_t admin;
		static fzn_revocation_t revoked_entries[FZN_NODE_REVOCATIONS_MAX];
		static fzn_revocation_store_t revoked;
		static fzn_node_roots_t estate_roots;
		/* ADMINS AND THEIR CONFIRMATIONS, sec 415: the admin table at the
		 * store's ceiling, and a confirmation table set before anything
		 * is loaded, since an admin admitted before it could never be
		 * confirmed. */
		static fzn_revocation_admin_t admins[32];
		static fzn_revocation_confirm_t confirms[FZN_NODE_REVOCATIONS_MAX];
		size_t loaded = 0, nrevoked = 0, nroots = 0;

		/* THE REVOCATIONS THIS NODE ISSUED, admitted again before any
		 * peer is served -- a node that served first and remembered
		 * second would answer a revoked device in the gap. A record that
		 * will not admit is fatal for the same reason. sec 380. */
		/* THE ESTATE'S ROOTS FIRST, sec 407: the set grown from the pinned
		 * root, attached before any revocation is re-admitted, so one by
		 * a member root admits and a removed root's after its cut does
		 * not count. With nothing stored, the pinned root alone. */
		if (fzn_revocation_store_init(&revoked, revoked_entries,
		                              FZN_NODE_REVOCATIONS_MAX) != FZN_CHAIN_OK
		    || fzn_revocation_store_set_quorum(&revoked, (size_t)quorum,
		                                       state.config.has_admin
		                                               ? &state.config.admin_capability
		                                               : NULL,
		                                       state.config.has_admin ? admins : NULL,
		                                       state.config.has_admin ? 32u : 0u)
		               != FZN_CHAIN_OK
		    || (state.config.has_admin
		        && fzn_revocation_store_set_confirmations(&revoked, confirms,
		                                                  FZN_NODE_REVOCATIONS_MAX, &hash_ops)
		                   != FZN_CHAIN_OK)
		    || fzn_node_roots_init(&estate_roots, state.config.root, &sign_ops, &hash_ops)
		               != FZN_NODE_ROOTS_OK
		    || fzn_node_roots_load(&estate_roots, store_ops, &nroots) != FZN_NODE_ROOTS_OK
		    || fzn_node_roots_key_load(&estate_roots, store_ops, &root_seat, &root_sign_ops)
		               != FZN_NODE_ROOTS_OK
		    || fzn_node_roots_attach(&estate_roots, &revoked) != FZN_NODE_ROOTS_OK
		    || fzn_node_admin_chain_load(store_ops, &own_admin) < 0
		    || fzn_node_revocations_load(store_ops, &revoked, state.config.root,
		                                 my_authority, fzn_node_admin_chain_view(&own_admin),
		                                 &sign_ops, &hash_ops, &nrevoked)
		               != FZN_PERSIST_OK) {
			say(FZN_ENTRY_ERROR, "revoke", "could not restore the revocations in %s",
			        store_dir);
			fzn_socket_close(lfd, sock_path);
			if (ufd >= 0)
				fzn_udp_close(ufd);
			return 1;
		}
		/* ADMINS' RETENTION RECORDS, sec 479, once the revocations that
		 * say which admins stand are loaded. NOT FATAL: they decide how long
		 * logs stay, and a node that cannot judge them -- no admin
		 * capability configured -- serves on and says so. */
		{
			size_t nadmin = 0;

			if (fzn_node_roots_load_admin_retention(&estate_roots, store_ops,
			                                        state.config.root, &nadmin)
			    != FZN_NODE_ROOTS_OK)
				say(FZN_ENTRY_WARNING, "roots",
				    "an admin's retention record in %s would not admit", store_dir);
			else if (nadmin)
				say(FZN_ENTRY_INFO, "roots", "%zu admin retention record(s) from %s",
				    nadmin, store_dir);
		}
		/* THE ESTATE'S k, when a root has set one; `--quorum` until then.
		 * sec 418. */
		(void)fzn_revocation_store_set_k(&revoked,
		                                 fzn_node_roots_quorum(&estate_roots, (uint8_t)quorum));
		if (revoked.quorum != (size_t)quorum)
			say(FZN_ENTRY_NOTE, "revoke", "the estate's k is %zu, set by a root",
			        revoked.quorum);
		state.config.revocations = &revoked;
		running = &revoked;
		running_roots = &estate_roots;
		dlog.roots = running_roots;
#ifdef FZN_RECORD_STORE_FILE_ON
		/* THE JOURNAL, sec 501, in `records/` under the core directory:
		 * opened, every act logged from here on mirrored into it, and the
		 * estate followed. NOT FATAL, and NOT QUIET: since sec 505 the
		 * journal is the only way the estate's acts travel, so a node that
		 * cannot keep one still serves, and says it is alone. */
		/* AND JUDGES BY IT, sec 506: a cut is a record id in the signer's
		 * stream, and every store attached to the roots asks the journal. */
		if (store_dir && !journal_for(store_dir, &estate_roots, &sign_ops, &hash_ops, store_ops))
			say(FZN_ENTRY_WARNING, "journal",
			    "no journal kept in %s/records: this node's votes, roots and "
			    "settings reach no peer, and no peer's reach it",
			    store_dir);
#else
		say(FZN_ENTRY_WARNING, "journal",
		    "built without the record file store: this node's votes, roots and settings "
		    "reach no peer, and no peer's reach it");
#endif
		if (nrevoked)
			say(FZN_ENTRY_INFO, "revoke", "%zu revocation(s) from %s", nrevoked,
			        store_dir);
		if (nroots)
			say(FZN_ENTRY_INFO, "roots", "%zu root record(s) from %s", nroots,
			        store_dir);
		fzn_persist_err_t err;

		err = fzn_node_peers_load(store_ops, peers, FZN_NODE_PEERS_MAX, &loaded);
		if (err != FZN_PERSIST_OK) {
			say(FZN_ENTRY_ERROR, "node/peers", "could not load peers from %s (%d)",
			        bulk_dir, (int)err);
			fzn_socket_close(lfd, sock_path);
			if (ufd >= 0)
				fzn_udp_close(ufd);
			return 1;
		}
		state.peers = peers;
		state.peer_count = loaded;
		say(FZN_ENTRY_INFO, "node/peers", "%zu peer(s) from %s", loaded, bulk_dir);

		/* FUZZNET'S OWN VERBS, answered by the node about itself, when it
		 * holds what they need: its key, a store, and the capability it
		 * grants. `add peer` then pairs a device into the RUNNING node,
		 * which `--pair` could only do for its next start. sec 378. */
		if (booted && has_capability) {
			admin.state = &state;
			admin.peers = peers;
			admin.peers_cap = FZN_NODE_PEERS_MAX;
			admin.id = &identity;
			admin.store = store_ops;
			/* IDS ARE DRAWN, a group's among them (sec 516), whether or
			 * not the roster below loads. */
			admin.rng = &rng_ops;
			memcpy(dlog.host, identity.pubkey, FZN_PUBKEY_LEN);
			dlog.has_host = 1;
#ifdef FZN_LOG_FILE_ON
#ifdef FZN_LOG_PACK_ON
			memcpy(dlog.signer.key, identity.pubkey, FZN_PUBKEY_LEN);
			dlog.signer.sign = identity.sign;
			dlog.has_signer = identity.sign != NULL;
#endif
#endif
			admin.card_lifetime = FZND_CARD_LIFETIME;
			running_admin = &admin;
			admin.revocations = &revoked;
			admin.authority = my_authority;
			admin.roots = &estate_roots;
			admin.admin_chain = &own_admin;
			/* THE CONTACTS AS THE USER'S ROSTER, sec 489: loaded, then every
			 * contact named here from before carried onto it as this node's
			 * add, so the members pull them. NOT FATAL: a node that cannot
			 * keep the roster keeps its contacts on itself, as before. */
			{
				size_t nroster = 0, carried = 0;
				fzn_node_roster_err_t rerr =
				        fzn_node_roster_init(&node_roster, state.config.root,
				                             &state.config.remote_capability, &sign_ops,
				                             &estate_roots.ops, &hash_ops);

				/* EACH RECORD WRITTEN AS A ROOT, in the root's log. sec 413. */
				node_roster.wrote = fzn_node_admin_log_roster;
				node_roster.wrote_ctx = &admin;
				if (rerr == FZN_NODE_ROSTER_OK)
					rerr = fzn_node_roster_load(&node_roster, store_ops, &nroster);
				if (rerr == FZN_NODE_ROSTER_OK)
					rerr = fzn_node_roster_carry_names(&node_roster, store_ops, &identity,
					                                   my_authority, &rng_ops, &carried);
				if (rerr == FZN_NODE_ROSTER_OK || rerr == FZN_NODE_ROSTER_NO_STANDING) {
					admin.roster = &node_roster;
					roster_on = 1;
				}
				if (rerr != FZN_NODE_ROSTER_OK)
					say(FZN_ENTRY_WARNING, "contact/roster", "the contacts' roster: %s",
					    fzn_node_roster_err_str(rerr));
				if (nroster || carried)
					say(FZN_ENTRY_INFO, "contact/roster",
					    "%zu roster record(s) from %s, %zu contact(s) carried onto it",
					    nroster, store_dir, carried);
			}
			/* THE SUCCESSIONS, sec 499: a re-keyed device's references read
			 * through to its new key. NOT FATAL, as the roster is not: a node
			 * that cannot hold them serves on its old keys. */
			{
				size_t nsucc = 0;
				fzn_persist_err_t serr = FZN_PERSIST_ERR_MALFORMED;

				if (fzn_node_successions_init(&node_successions, &hash_ops)
				    == FZN_NODE_REVOKE_OK)
					serr = fzn_node_successions_load(&node_successions, store_ops,
					                                 &revoked, state.config.root,
					                                 &sign_ops, &nsucc);
				if (serr == FZN_PERSIST_OK) {
					admin.successions = &node_successions;
					successions_on = 1;
				} else {
					say(FZN_ENTRY_WARNING, "votes", "the successions: %s",
					    fzn_persist_err_str(serr));
				}
				if (nsucc)
					say(FZN_ENTRY_INFO, "votes", "%zu succession(s) from %s", nsucc,
					    store_dir);
			}
#ifdef FZN_RECORD_STORE_FILE_ON
			if (journal_on) {
				admin.journal_remote = journal_remote;
				admin.journal_ctx = &node_journal;
				/* CONVERSATIONS, sec 527, before the estate is followed, so
				 * its nodes' stream 3 is followed with the rest. */
				if (fzn_node_messages_init(&node_messages, store_ops, &node_journal,
				                           identity.pubkey, &sign_ops, &rng_ops, &aead_ops,
				                           &hash_ops, wall_ms)
				    == FZN_MESSAGES_OK) {
					messages_on = 1;
					node_messages.keeps = keeps_here;
					node_messages.takes_over = takes_over_line;
					admin.messages_local = fzn_node_messages_local;
					admin.messages_remote = fzn_node_messages_remote;
					admin.messages_ctx = &node_messages;
				} else {
					say(FZN_ENTRY_WARNING, "messages", "no conversations: the journal refused");
				}
				follow_estate(identity.pubkey, &state, &estate_roots);
				node_apply.journal = &node_journal;
				node_apply.revocations = &revoked;
				node_apply.roots = &estate_roots;
				node_apply.roster = roster_on ? &node_roster : NULL;
				node_apply.successions = successions_on ? &node_successions : NULL;
				node_apply.store = store_ops;
				node_apply.root = state.config.root;
				node_apply.capability = &state.config.remote_capability;
				node_apply.admin_capability =
				        state.config.has_admin ? &state.config.admin_capability : NULL;
				node_apply.sign = &sign_ops;
				node_apply.hash = &hash_ops;
				node_apply.now = wall_clock;
				/* THE ESTATE'S CONFIGURATION, sec 540, judged by the same
				 * context that applies it. */
				node_settings.store = store_ops;
				node_settings.hash = &hash_ops;
				node_settings.verify = &sign_ops;
				node_settings.journal = &node_journal;
				node_settings.id = &identity;
				node_settings.apply = &node_apply;
				node_settings.estate = state.config.root;
				node_settings.now = wall_clock;
				node_apply.settings = &node_settings;
				admin.holdings_remote = holdings_remote;
				admin.holdings_ctx = &node_apply;
				retention_capability = state.config.has_retention
				                               ? &state.config.retention_capability
				                               : NULL;
				admin.settings_local = fzn_node_settings_local;
				admin.settings_ctx = &node_settings;
				admin.settings = &node_settings;
				admin.remote_ran = remote_ran;
				/* THE GRANTS FROM THE STORE, sec 545, before any record is
				 * applied, so a chain does not depend on the journal still
				 * holding the grant that made it. */
				{
					size_t grants = 0;

					if (!fzn_node_apply_load_grants(&node_apply, &grants))
						say(FZN_ENTRY_WARNING, "journal",
						    "the grants kept in %s would not load; chains rebuild from "
						    "the journal alone",
						    store_dir);
					else if (grants)
						say(FZN_ENTRY_INFO, "journal", "%zu grant(s) from %s", grants,
						    store_dir);
				}
				apply_journal();
				retention_to_settings(&identity);
				carry_prekey(&identity);
				/* THE ESTATE'S k AS A ROOT SET IT, sec 542, from the start
				 * rather than from the first round. */
				if (running)
					(void)fzn_revocation_store_set_k(
					        running,
					        fzn_node_settings_quorum(
					                &node_settings,
					                fzn_node_roots_quorum(running_roots, (uint8_t)quorum)));
			}
#endif
			state.on_local = local_handle;
			state.on_local_ctx = &admin;
			/* THE ESTATE'S ROUTING MANIFEST, sec 611. */
			admin.routing_remote = routing_remote;
			admin.messages_contact = messages_contact;
			admin.contact_devices = contact_devices_remote;
			/* RELAYING, sec 622. */
			admin.relay_remote = relay_remote;
			state.relay = &relay_tables;
			/* A LAN PROBE, sec 624. */
			state.on_probe = lan_probe_heard;
			/* GROUPS, sec 626. */
			node_groups.log.store = node_apply.store;
			node_groups.log.hash = &hash_ops;
			node_groups.log.sign = &sign_ops;
			node_groups.log.member = node_apply.capability;
			node_groups.host_sign = &sign_ops;
			node_groups.signer = groups_signer;
			node_groups.rng = &rng_ops;
			node_groups.clock = wall_clock;
			node_groups.forget = fzn_node_admin_group_forget;
			node_groups.forget_ctx = &admin;
			node_groups.log.dropped = group_dropped;
			/* EPOCH SECRETS, sec 627: sealed to prekeys, this host's
			 * opening its own. */
			node_groups.agree = identity.agree;
			node_groups.aead = &aead_ops;
			node_groups.agree_secret = identity.agree_secret;
			/* A GROUP'S LINES, sec 629. */
			group_lines.store = node_apply.store;
			group_lines.hash = &hash_ops;
			/* APP STREAMS, sec 632. */
			node_streams.store = node_apply.store;
			node_streams.hash = &hash_ops;
			if (node_groups.log.store && node_groups.log.member)
				admin.groups = &node_groups;
			/* A STRANGER'S CONTACT REQUEST, sec 619. */
			state.on_box = contact_box;
			routing_self = identity.pubkey;
			routing_sign = &sign_ops;
			routing_hash = &hash_ops;
			fzn_node_events_init(&node_events);
			state.events = &node_events;
			state.on_remote = fzn_node_admin_remote;
			state.on_remote_ctx = &admin;
			admin.caused = on_caused;
#ifdef FZN_LOG_FILE_ON
			admin.logs_remote = logs_remote;
#endif
#ifdef FZN_SPOOL_FILE_ON
			{
				char shelf_dir[FZN_NODE_SHELF_DIR_MAX];
				int n = snprintf(shelf_dir, sizeof(shelf_dir), "%s/text", bulk_dir);

				if (n > 0 && (size_t)n < sizeof(shelf_dir)
				    && fzn_node_shelf_init(&shelf, shelf_dir, &hash_ops, &aead_ops,
				                           &rng_ops)
				               == FZN_NODE_SHELF_OK) {
					shelf_on = 1;
					admin.text_local = fzn_node_shelf_local;
					admin.text_remote = blob_remote;
					admin.text_ctx = &shelf;
				} else {
					say(FZN_ENTRY_WARNING, "shelf", "no shelf for texts under %s",
					        bulk_dir);
				}
				n = snprintf(shelf_dir, sizeof(shelf_dir), "%s/files", bulk_dir);
				if (n > 0 && (size_t)n < sizeof(shelf_dir)
				    && fzn_node_files_init(&files, shelf_dir, &hash_ops, &aead_ops,
				                           &rng_ops)
				               == FZN_NODE_FILES_OK) {
					admin.files_local = files_local_refs;
					admin.files_shared = files_shared;
					admin.files_forget = files_forget;
					admin.files_ctx = &files;
					files.store = store_ops;
					files_on = 1;
				} else {
					say(FZN_ENTRY_WARNING, "files", "no store for files under %s",
					    bulk_dir);
				}
			}
#endif
			/* NOTES, sec 431: admitted from this node and the nodes it
			 * pulls from, which are the nodes they will sync with. */
			state.reply = node_reply;
			state.reply_cap = sizeof(node_reply);
			{
				/* ADMITTED: the nodes it pulls from, as the base; the
				 * nodes paired to it join from the live table, sec 451.
				 * sec 433. */
				static uint8_t writers[FZND_PULL_TARGETS_MAX + FZN_NODE_PEERS_MAX]
				                      [FZN_PUBKEY_LEN];
				uint8_t pull_keys[FZND_PULL_TARGETS_MAX][FZN_PUBKEY_LEN];
				size_t w, nw = 0;

				for (w = 0; w < npulls; w++) {
					memcpy(pull_keys[w],
					       pulls[w].is_root_at ? state.config.root : pulls[w].node,
					       FZN_PUBKEY_LEN);
					memcpy(writers[nw++], pull_keys[w], FZN_PUBKEY_LEN);
				}
				/* THE PAIRED PEERS ARE NOT IN THE BASE, sec 451:
				 * `admit_writers` adds them from the live table, so
				 * one un-paired on the socket stops being a writer. */
				if (fzn_node_notes_init(&node_notes, store_ops, &hash_ops, &sign_ops,
				                        &rng_ops, identity.pubkey,
				                        (const uint8_t (*)[FZN_PUBKEY_LEN])writers, nw,
				                        (const uint8_t (*)[FZN_PUBKEY_LEN])pull_keys, npulls,
				                        wall_ms)
				    == FZN_NOTES_OK) {
					admit_writers(&state, running_roots);
#ifdef FZN_SPOOL_FILE_ON
					if (shelf_on) {
						node_notes.seal = shelf_seal;
						node_notes.open = shelf_open;
						node_notes.text_ctx = &shelf;
						node_notes.collect = shelf_collect;
						node_notes.place = shelf_place;
						node_notes.span = shelf_span;
						admin.text_shared = shared_text;
						admin.text_shared_ctx = &shelf;
					}
#endif
#ifdef FZN_RECORD_STORE_FILE_ON
					/* EVERY NOTE RECORD IS CHAINED, sec 517: with no
					 * journal, no note is written, and the verbs say so. */
					if (journal_on) {
						node_notes.chain = journal_chain;
						node_notes.chain_ctx = &node_journal;
					}
#endif
					admin.notes_local = fzn_node_notes_local;
					admin.notes_remote = fzn_node_notes_remote;
					admin.notes_ctx = &node_notes;
					notes_on = 1;
					/* SHARING, sec 436: a contact's chain for the share
					 * capability verifies against this node's own key. */
					if (has_capability
					    && fzn_notes_share_capability(cli.service, cli.product, &hash_ops,
					                                  &state.config.share_capability)
					               == FZN_NOTES_OK) {
						memcpy(state.config.share_root, identity.pubkey, FZN_PUBKEY_LEN);
						state.config.has_share = 1;
					}
				} else {
					say(FZN_ENTRY_WARNING, "notes", "no notes: the store cannot list");
				}
			}
		}
	}

	/* A MEMBER PULLS WHAT ITS ROOT REVOKED. The pairing it joined with is
	 * what makes it the root's caller, and the address is given because a
	 * pairing carries none (sec 377). The first pull runs before the first
	 * frame is served; a root that does not answer is reported and not
	 * fatal, since what was pulled before is already loaded from slot 10
	 * and refusing to serve would cut off every device the root did not
	 * revoke. sec 384. */
	{
		static fzn_partial_t request_slots[FZND_REQUEST_SLOTS];
		static uint8_t request_bufs[FZND_REQUEST_SLOTS][FZND_REQUEST_MAX];
		static fzn_reasm_t requests;
		size_t r;
		int ok = 1;

		for (r = 0; r < FZND_REQUEST_SLOTS; r++)
			ok = ok
			     && fzn_reasm_slot_init(&request_slots[r], request_bufs[r],
			                            sizeof(request_bufs[r]))
			                == FZN_REASM_OK;
		if (ok
		    && fzn_reasm_init(&requests, request_slots, FZND_REQUEST_SLOTS, 1u, 60u)
		               == FZN_REASM_OK)
			state.reassembly = &requests;
		else
			say(FZN_ENTRY_WARNING, "node", "no request reassembly; requests past one frame "
			                "are dropped");
	}

	/* A NODE KEEPING NOTES LOOPS TOO, with no estate peer to pull: a
	 * share it accepts is pulled on the same round. sec 437. And so does
	 * one reassembling requests, since the loop is what expires a request
	 * whose sender stopped part way. sec 447. */
	/* THE ROOT THIS DEVICE JOINED THROUGH, where `add join` kept it, sec
	 * 638: pulled from as `--root-at` would be, when the command line names
	 * no peer. */
	if (!npulls && booted && store_ops && fzn_trust_source_of(&trust) == FZN_TRUST_PINNED) {
		static char kept[FZN_UDP_HOST_MAX + 8u];
		size_t n = 0;
		char *space;

		if (store_ops->load(store_ops->ctx, FZN_PERSIST_ROOT_AT, fzn_trust_root(&trust),
		                    (uint8_t *)kept, sizeof(kept) - 1u, &n)
		    && n) {
			kept[n] = '\0';
			space = strrchr(kept, ' ');
			if (space && space != kept) {
				*space = '\0';
				pulls[0].host = kept;
				pulls[0].port = strtol(space + 1, NULL, 10);
				pulls[0].is_root_at = 1;
				npulls = 1;
			}
		}
	}

	if (npulls || notes_on || state.reassembly) {
		uint64_t next_pull = 0, last_fresh_round = 0, round_now = 0, round_began_ms = 0;
		int round_step = 0;
		const int *plan = round_plan;
		size_t plan_at = 0;
		/* THE COMMAND LINE'S PEERS; a round adds the siblings after them. */
		size_t npulls_base = npulls;
		size_t t;

		/* A PULL NEEDS A STORE TO KEEP WHAT IT LEARNS, and `--root-at`
		 * needs a node that joined through the root: a node that joined
		 * through a member holds its pairing to that member, and names
		 * it with `--pull-from` instead. */
		if (npulls && (!running || !store_ops)) {
			say(FZN_ENTRY_ERROR, "node", "pulling votes needs --fuzznet-dir");
			fzn_socket_close(lfd, sock_path);
			if (ufd >= 0)
				fzn_udp_close(ufd);
			return 2;
		}
		for (t = 0; t < npulls; t++) {
			struct pull_target *pt = &pulls[t];
			int fd = -1;

			pt->fd = -1;
			if (pt->is_root_at) {
				if (!my_authority
				    || memcmp(estate.node, state.config.root, FZN_PUBKEY_LEN) != 0) {
					say(FZN_ENTRY_ERROR, "node", "--root-at needs a node that joined an "
					                "estate through its root; name a member with "
					                "--pull-from");
					fzn_socket_close(lfd, sock_path);
					if (ufd >= 0)
						fzn_udp_close(ufd);
					return 2;
				}
				pt->pairing = estate;
			} else if (fzn_node_pairing_load(store_ops, pt->node, &pt->pairing)
			           != FZN_PERSIST_OK) {
				say(FZN_ENTRY_ERROR, "node", "--pull-from %s: this node holds no pairing to "
				                "that node", pt->host);
				fzn_socket_close(lfd, sock_path);
				if (ufd >= 0)
					fzn_udp_close(ufd);
				return 2;
			}
			if (pt->port < 0 || pt->port > 65535
			    || fzn_udp_bind(family, NULL, 0, &fd) != FZN_UDP_OK
			    || fzn_udp_resolve(family, pt->host, (uint16_t)pt->port, &pt->caller.node)
			               != FZN_UDP_OK
			    || fzn_reasm_slot_init(&pt->slot, pt->slot_buf, sizeof(pt->slot_buf))
			               != FZN_REASM_OK
			    || fzn_reasm_init(&pt->table, &pt->slot, 1, 1u, 60u) != FZN_REASM_OK) {
				say(FZN_ENTRY_ERROR, "node", "could not reach for the peer at %s",
				        pt->host);
				fzn_socket_close(lfd, sock_path);
				if (fd >= 0)
					fzn_udp_close(fd);
				if (ufd >= 0)
					fzn_udp_close(ufd);
				return 1;
			}
			pt->fd = fd;
			fzn_node_pairing_caller(&pt->pairing, identity.pubkey, &pt->caller);
			pt->caller.fd = fd;
			pt->caller.hash = &hash_ops;
			pt->caller.aead = &aead_ops;
			pt->caller.rng = &rng_ops;
			pt->caller.reasm = &pt->table;
			pt->caller.hops = 1u;
			pt->caller.wrap = caller_wrap;
		}

		load_received(family, identity.pubkey, &hash_ops, &aead_ops, &rng_ops);
		/* A CONTACT'S DEVICES, sec 614: paired and delivered to as this
		 * identity, over sockets of this family. */
		contact_id = &identity;
		joining.id = &identity;
		joining.trust = &trust;
		joining.store = store_ops;
		contact_family = family;
		contact_hash_ops = &hash_ops;
		contact_aead_ops = &aead_ops;
		contact_rng_ops = &rng_ops;
		load_contact_targets();
		/* THE ROUND'S CONVERSATIONS, awaited by the loop. sec 636. */
		fzn_node_asks_init(&round_asks, round_reply, sizeof(round_reply), round_clock_ms);
		state.asks = &round_asks;
		say(FZN_ENTRY_NOTE, "node", "serving%s%s%s, pulling from %zu peer(s) every %us",
		        sock_path ? " on " : "", sock_path ? sock_path : "",
		        (udp_port >= 0) ? " udp" : "", npulls, FZND_PULL_EVERY);
		for (;;) {
			uint64_t now = wall_clock();

			admit_writers(&state, running_roots);
#ifdef FZN_LOG_FILE_ON
			/* A ROTATION THE LOGGER MADE packs and prunes now, outside it. */
			if (dlog.rotated) {
				dlog.rotated = 0;
				log_round();
			}
#endif
#ifdef FZN_SPOOL_FILE_ON
			scrub_shelf(now);
			scrub_files(now);
#endif

			/* EVERY PEER EACH ROUND, one after another. A peer that does
			 * not answer is reported and the next is asked: what one
			 * peer cannot say another may, which is the point of asking
			 * more than one. sec 401. */
			/* DUE, OR SCHEDULED BY A CLOCK SINCE SET BACK: a round more
			 * than one period away was planned by a clock that read later
			 * than this one does, and waiting for it would stop every pull
			 * for as long as the clock had been wrong. sec 469. */
			if (!round_step && (now >= next_pull || next_pull > now + FZND_PULL_EVERY)) {
				plan = round_plan;
				plan_at = 0;
				round_step = plan[0];
				round_now = now;
				round_began_ms = mono_ms();
			}
			/* THE ROUND A STEP AT A TIME, sec 636: one step each pass of
			 * this loop, and between steps the loop answers whoever asked
			 * meanwhile -- a sibling mid-round no longer waits out this
			 * host's whole round for an answer. Every step reads the
			 * round's one clock, as the round in one piece did. */
			/* A STEP STILL WAITING on its conversations holds the next. */
			if (round_step && !round_pending) {
				switch (round_step) {
				case ROUND_START:
					/* EVERY PEER ASKED AGAIN, sec 587 -- and a sibling that did
					 * not answer last round introduced first, sec 623. */
#ifdef FZN_RECORD_STORE_FILE_ON
					intro_note_silent(pulls, npulls_base, npulls);
#endif
					n_silent = 0;
#ifdef FZN_RECORD_STORE_FILE_ON
					npulls = npulls_base + load_siblings(pulls, npulls_base, family,
					                                     identity.pubkey, state.config.root,
					                                     &hash_ops, &aead_ops, &rng_ops);
					introduce_siblings(pulls, npulls_base, npulls, family, round_now);
#endif
					round_named = say_caused(FZN_ENTRY_DEBUG, "node/round", NULL, NULL,
					                         &round_name, "a round with %zu peer(s)", npulls);
					break;
				case ROUND_JOURNAL:
					/* THE ESTATE'S ACTS, sec 505: roots, votes, confirmations,
					 * settings, contacts and successions all arrive in the
					 * journal, pulled and applied before anything reads them.
					 * The journal follows the members the last round's notes
					 * proved, so a member paired since is read from its first
					 * act a round later. */
#ifdef FZN_RECORD_STORE_FILE_ON
					if (plan == round_plan) {
						follow_estate(identity.pubkey, &state, running_roots);
						(void)messages_upgrade();
					}
					/* Every peer at once, the round waiting. sec 636. */
					journal_start(pulls, npulls, round_now);
#endif
					break;
				case ROUND_JOURNAL_SETTLE:
#ifdef FZN_RECORD_STORE_FILE_ON
					journal_settle(pulls, npulls, round_now);
					if (plan == round_plan)
						apply_journal();
#endif
					break;
				case ROUND_RECONCILE:
#ifdef FZN_RECORD_STORE_FILE_ON
					reconcile_estate(pulls, npulls, round_now);
#endif
					break;
				case ROUND_ROUTING:
#ifdef FZN_RECORD_STORE_FILE_ON
					/* The manifest of every peer at once, the round waiting. */
					routing_round(pulls, npulls, round_now);
#endif
					break;
				case ROUND_ROUTING_AFTER:
#ifdef FZN_RECORD_STORE_FILE_ON
					mark_heard(pulls, npulls);
#if defined(FZN_LOG_FILE_ON) && defined(FZN_LOG_PACK_ON)
					count_replicas(pulls, npulls, round_now);
#endif
#endif
					break;
				case ROUND_GRANTS:
#ifdef FZN_RECORD_STORE_FILE_ON
					/* A GRANT JUST LOGGED, PUSHED NOW, sec 585: logged after
					 * the round's push, it would wait a round for the next. */
					if (pair_siblings(&identity, round_now))
						for (t = 0; t < npulls; t++)
							if (!silent_peer(&pulls[t]))
								push_one(&pulls[t], round_now);
					/* AND THE SIBLINGS AGAIN, sec 586: an address or a pairing
					 * the journal brought this round is asked from now, by the
					 * rest of the round, not from the next. */
					npulls = npulls_base + load_siblings(pulls, npulls_base, family,
					                                     identity.pubkey, state.config.root,
					                                     &hash_ops, &aead_ops, &rng_ops);
#endif
					break;
				case ROUND_MESSAGES:
#ifdef FZN_RECORD_STORE_FILE_ON
					/* The keys with each peer, the round waiting. sec 636. */
					messages_round(pulls, npulls, round_now);
#endif
					break;
				case ROUND_MESSAGES_AFTER:
#ifdef FZN_RECORD_STORE_FILE_ON
					messages_give_up();
					settle_lines(pulls, npulls);
					/* THE NOTES INDEX FIRST, so the cut sees how far it has
					 * read: a notes stream is cut no further than its cursor,
					 * which the round's own index has not moved yet. sec 555. */
					index_notes();
					index_catalog();
					journal_cut(round_now);
#endif
					/* THE ESTATE'S k MAY HAVE ARRIVED WITH THEM, sec 418 -- as a
					 * root's setting since sec 542, which outranks the older
					 * records. */
					if (running)
						(void)fzn_revocation_store_set_k(
						        running,
#ifdef FZN_RECORD_STORE_FILE_ON
						        fzn_node_settings_quorum(
						                &node_settings,
						                fzn_node_roots_quorum(running_roots, (uint8_t)quorum))
#else
						        fzn_node_roots_quorum(running_roots, (uint8_t)quorum)
#endif
						);
					/* CONTACTS ADDED ON ANOTHER MEMBER, sec 489, named here so
					 * they can be shared with and removed by name. */
					if (roster_on && running_admin) {
						size_t named = 0;

						if (fzn_node_roster_name_arrivals(&node_roster, store_ops, running,
						                                  running ? running->quorum : 0u,
						                                  admin_member, running_admin,
						                                  round_now * 1000u, &named)
						    != FZN_NODE_ROSTER_OK)
							say(FZN_ENTRY_WARNING, "contact/roster",
							    "contacts that arrived would not all be named");
						else if (named)
							say(FZN_ENTRY_INFO, "contact/roster",
							    "%zu contact(s) added on another member, named here", named);
					}
					break;
				case ROUND_MEMBERS:
					/* THE ESTATE'S MEMBERS, asked of every peer at once, the
					 * round waiting on their answers. sec 636. */
					members_start(pulls, npulls, round_now, &state.config, running);
					break;
				case ROUND_NOTES:
					/* NOTES, then TEXTS, secs 432 and 424: a note's text is
					 * fetched once the note naming it has arrived. Each
					 * peer's asked at once, the round waiting on them. */
					members_settle(&state, running_roots);
					notes_start(pulls, npulls, round_now);
					break;
				case ROUND_NOTES_SETTLE:
					notes_settle();
					break;
				case ROUND_RECEIVED_IN_ROUND:
				case ROUND_RECEIVED:
					/* Every sharer at once, the round waiting. sec 636. */
					pull_received(round_now);
					break;
				case ROUND_RECEIVED_SETTLE_IN_ROUND:
				case ROUND_SHARES_SETTLE:
				case ROUND_GROUP_SHARES_SETTLE:
					shares_settle();
					break;
#ifdef FZN_RECORD_STORE_FILE_ON
				case ROUND_MESSAGES_ROUND:
					messages_round(pulls, npulls, round_now);
					break;
				case ROUND_DELIVER:
					deliver_start(round_now);
					break;
#endif
				case ROUND_STREAMS:
					streams_start(pulls, npulls, round_now);
					break;
				case ROUND_STREAMS_SETTLE:
					streams_settle();
					break;
				case ROUND_ADDRESS:
					address_start(pulls, npulls, round_now);
					break;
				case ROUND_ADDRESS_SETTLE:
					address_settle();
					break;
				case ROUND_CONTACTS:
					contact_round(pulls, npulls, round_now);
					break;
				case ROUND_CONTACTS_SETTLE:
					contact_settle();
					break;
				case ROUND_GROUPS:
					group_round(pulls, npulls, round_now);
					break;
				case ROUND_GROUPS_SETTLE:
					group_settle(pulls, npulls, round_now);
					break;
				case ROUND_GROUP_LINES_SETTLE:
					group_lines_settle();
					group_shares_round(round_now);
					break;
				case ROUND_REFERENCES:
					file_refs_round(pulls, npulls, round_now);
					send_asked();
					/* Every contact at once, the round waiting. sec 636. */
					deliver_start(round_now);
					break;
				case ROUND_REFERENCES_SETTLE:
					file_refs_settle();
					break;
				case ROUND_END:
					/* THE ROUND'S END IN ONE STEP, from the history pass on: the
					 * live checks take "history pass" for a round done, so what
					 * follows it runs before anything is answered, as it did. */
					history_trim();
#ifdef FZN_SPOOL_FILE_ON
					fetch_texts(pulls, npulls, round_now);
					fetch_files(pulls, npulls, round_now);
					collect_texts();
#endif
					/* THE LOG LAST, sec 476: packing and the rules after the
					 * pulls, so an estate rule pulled this round applies this
					 * round rather than the next. */
					log_round();
					next_pull = wall_clock() + FZND_PULL_EVERY;
					/* THE ROUND'S END, said: a round answers between its
					 * steps, so what it produced is read once this is
					 * logged, not at a marker on the way (sec 637). */
					say(FZN_ENTRY_DEBUG, "node/round", "a round's end, %llu ms",
					    (unsigned long long)(mono_ms() - round_began_ms));
					break;
				}
				round_step = plan[++plan_at];
			}
			/* WHAT RUNS BETWEEN ROUNDS waits for the round to end, as it
			 * did when the round was one piece: each asks the same peers
			 * the round is asking, from state the round is moving. */
			if (!round_step) {
#ifdef FZN_SPOOL_FILE_ON
				/* A TEXT JUST ASKED FOR is fetched now, not at the next
				 * round. sec 424. */
				if (shelf.fresh)
					fetch_texts(pulls, npulls, now);
				if (files.fresh)
					fetch_files(pulls, npulls, now);
#endif
				/* A TRASH JUST EMPTIED is carried to the pull peers now, not
				 * at the next round. sec 433. */
				/* HELLO to the peers it pulls from, sec 622. */
				say_hello(pulls, npulls, state.udp_fd, now);
				/* A STREAM FETCH ASKED, at once, sec 632; WHERE THIS HOST IS
				 * SEEN, asked now, sec 621: each a plan of its own, every host
				 * at once and the loop answering meanwhile (sec 636). One
				 * waits for the other's end, its flag kept. */
				if (n_stream_fetches && !round_step) {
					plan = streams_plan;
					plan_at = 0;
					round_step = plan[0];
					round_now = now;
				}
				if (address_due && !round_step) {
					address_due = 0;
					plan = address_plan;
					plan_at = 0;
					round_step = plan[0];
					round_now = now;
				}
				/* A CONTACT JUST ASKED FOR is asked now, not a round later.
				 * sec 619. */
				if (asked_due) {
					asked_due = 0;
					send_asked();
				}
				/* A CONTACT'S DEVICE JUST OFFERED is paired now, the answer
				 * that kept it being out. sec 614. */
				if (contact_pair_due) {
					size_t paired;

					contact_pair_due = 0;
					paired = pair_contact_devices();
					if (paired)
						say(FZN_ENTRY_INFO, "contact/devices",
						    "%zu contact device(s) paired as offered", paired);
				}
				/* A SHARE JUST ACCEPTED is pulled now. sec 437. */
				if (!round_step && running_admin && running_admin->received_fresh) {
					running_admin->received_fresh = 0;
					load_received(family, identity.pubkey, &hash_ops, &aead_ops, &rng_ops);
					plan = received_plan;
					plan_at = 0;
					round_step = plan[0];
					round_now = now;
				}
				/* A WRITE HERE GOES OUT NOW, sec 449, a round at most every
				 * two seconds, so a burst of edits is one round rather than
				 * one each. */
				if (notes_on && node_notes.fresh
				    && (now >= last_fresh_round + 2u || last_fresh_round > now)) {
					node_notes.fresh = 0;
					last_fresh_round = now;
					/* THE NOTE GOES IN THE JOURNAL, sec 519, pushed with it:
					 * the steps from the next pass on. */
					plan = fresh_notes_plan;
					plan_at = 0;
					round_step = plan[0];
					round_now = now;
				}
			}
#ifdef FZN_RECORD_STORE_FILE_ON
			/* A MESSAGE WRITTEN HERE GOES AT ONCE, sec 528: the journal
			 * pushed, then keys given and asked, rather than waiting for
			 * the next round. The same two-second floor as notes'. */
			if (!round_step && messages_on && node_messages.fresh
			    && (now >= last_fresh_round + 2u || last_fresh_round > now)) {
				node_messages.fresh = 0;
				last_fresh_round = now;
				plan = fresh_messages_plan;
				plan_at = 0;
				round_step = plan[0];
				round_now = now;
			}
			if (journal_pushed) {
				journal_pushed = 0;
				index_notes();
				index_catalog();
				(void)messages_absorb();
			}
			/* A WRITE THE OPERATION JOURNAL MISSED, sec 523: made, and not
			 * entered, so a replay will not show it; or a rotation put off,
			 * sec 524, so the newest generation grows past its size. Said
			 * once per change. */
			{
				static size_t unrecorded, unkept, unrotated;

				if (op_journal
				    && (op_oj.unrecorded != unrecorded || op_oj.unkept != unkept
				        || op_oj.unrotated != unrotated)) {
					unrecorded = op_oj.unrecorded;
					unkept = op_oj.unkept;
					unrotated = op_oj.unrotated;
					say(FZN_ENTRY_WARNING, "opjournal",
					    "%zu write(s) not entered, %zu whose bytes were not kept, %zu "
					    "rotation(s) put off",
					    unrecorded, unkept, unrotated);
				}
			}
#endif
#ifdef FZN_SPOOL_FILE_ON
			/* A NOTE PURGED HERE takes its blobs at once, sec 520: its
			 * wrap key went with the purge, and every blob its history
			 * names is named by no held note now. */
			if (node_notes.purged_fresh) {
				node_notes.purged_fresh = 0;
				collect_texts();
			}
#endif
			/* A REQUEST NEVER FINISHED gives its slot back. */
			if (state.reassembly)
				(void)fzn_reasm_expire(state.reassembly, wall_clock());
			/* MID-ROUND, between steps, only what is waiting is answered and
			 * the next step follows at once; a step waiting on its
			 * conversations waits here, their answers polled with the rest. */
			(void)fzn_node_run_once(&state, round_step && !round_pending ? 0 : 1000);
			/* AN IDENTITY RESET, sec 620, its answer out: wiped once more,
			 * for what was written since, and stopped. */
			if (identity_reset) {
				size_t wiped = 0;
				const char *why = NULL;

				(void)fzn_state_dir_wipe(state_core_dir, &wiped, &why);
				if (state_bulk_dir)
					(void)fzn_state_dir_wipe(state_bulk_dir, &wiped, &why);
				fzn_socket_close(lfd, sock_path);
				if (ufd >= 0)
					fzn_udp_close(ufd);
				return 0;
			}
			/* A JOIN, its answer out: started again, joined. sec 638. */
			if (rejoin_due)
				return start_again(lfd, sock_path);
		}
	}

	say(FZN_ENTRY_NOTE, "node", "serving%s%s%s", sock_path ? " on " : "",
	        sock_path ? sock_path : "", (udp_port >= 0) ? " udp" : "");
	/* UNTIL THE PROCESS IS SIGNALLED, or a reset or a join ends it, sec 638:
	 * a node with nothing to pull still serves both verbs. */
	while (!identity_reset && !rejoin_due)
		(void)fzn_node_run_once(&state, 1000);
	if (rejoin_due)
		return start_again(lfd, sock_path);
	if (identity_reset) {
		size_t wiped = 0;
		const char *why = NULL;

		(void)fzn_state_dir_wipe(state_core_dir, &wiped, &why);
		if (state_bulk_dir)
			(void)fzn_state_dir_wipe(state_bulk_dir, &wiped, &why);
	}

	/* Unreached in normal operation; named so the sockets read as closed
	 * rather than leaked. */
	fzn_socket_close(lfd, sock_path);
	if (ufd >= 0)
		fzn_udp_close(ufd);
	return 0;
}
