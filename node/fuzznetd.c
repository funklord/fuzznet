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
#include "reconcile.h"
#include "settings.h"
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

/* Programs `--log-copy` may name, sec 486. */
#define FZND_COPY_PROGRAMS_MAX 8u

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
	/* COPIES OF THE PULL PEERS' LOGS, sec 483: `--log-copy[=PROGRAM]`,
	 * opt-in, given once a program, sec 486. None copies nothing. */
	const char *copy_programs[FZND_COPY_PROGRAMS_MAX];
	size_t n_copy_programs;
	/* AND THIS NODE'S OWN, PUSHED, sec 488: `--log-push[=PROGRAM]`, to the
	 * pull peers that take copies of it. */
	const char *push_programs[FZND_COPY_PROGRAMS_MAX];
	size_t n_push_programs;
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
	 * the directory's, sec 487. */
	if (dlog.n_copy_programs) {
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
				size_t gone = 0, p, n_source;

				if (strlen(e->d_name) != 64u
				    || strspn(e->d_name, "0123456789abcdef") != 64u
				    || !hex_bytes(e->d_name, source, sizeof(source))
				    || snprintf(sub, sizeof(sub), "%s/%s", copies, e->d_name)
				               >= (int)sizeof(sub))
					continue;
				n_source = fzn_retain_select_source(copy_rules, n_copy, source,
				                                    source_rules);
				for (p = 0; p < dlog.n_copy_programs && n_source; p++) {
					if (fzn_logger_retain(sub, dlog.copy_programs[p], source_rules,
					                      n_source, log_now_us(), &gone)
					    != FZN_LOGGER_OK)
						say(FZN_ENTRY_WARNING, "log/copy", "the copy rules could not all "
						    "be applied to %s of %.8s", dlog.copy_programs[p], e->d_name);
					else if (gone)
						say(FZN_ENTRY_INFO, "log/copy",
						    "%zu copied segment(s) of %s of %.8s removed", gone,
						    dlog.copy_programs[p], e->d_name);
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
#ifdef FZN_LOG_PACK_ON
	/* COPIES PUSHED TO THIS NODE, sec 488: taken for the programs it keeps
	 * copies of, whatever its own log's scope, since they are the sender's
	 * log and the sender chose to send them. */
	if (request[1] == FZN_LOG_COPY_PUSH_QUERY || request[1] == FZN_LOG_COPY_PUSH_PART) {
		static const char NONE[] = "denied this host keeps no log copies\n";
		fzn_log_copy_took_note_t note;
		size_t n;

		if (!dlog.on || !sender || !dlog.hash || !dlog.verify) {
			if (reply_cap < sizeof(NONE) - 1u)
				return 0;
			memcpy(reply, NONE, sizeof(NONE) - 1u);
			return sizeof(NONE) - 1u;
		}
		n = fzn_log_copy_take(dlog.logger.dir, sender, dlog.copy_programs, dlog.n_copy_programs,
		                      dlog.hash, dlog.verify, request, request_len, reply, reply_cap,
		                      &note);
		if (note.kept)
			say(FZN_ENTRY_INFO, "log/copy", "%s kept, pushed by %02x%02x%02x%02x", note.name,
			    sender[0], sender[1], sender[2], sender[3]);
		else if (note.refused)
			say(FZN_ENTRY_WARNING, "log/copy", "%s refused, pushed by %02x%02x%02x%02x: %s",
			    note.name, sender[0], sender[1], sender[2], sender[3],
			    fzn_log_copy_err_str(FZN_LOG_COPY_ERR_VERIFY));
		return n;
	}
#endif
	if ((request[1] != FZN_GATHER_QUERY && request[1] != FZN_GATHER_RING_QUERY
#ifdef FZN_LOG_PACK_ON
	        && request[1] != FZN_LOG_COPY_SEGMENTS_QUERY
	        && request[1] != FZN_LOG_COPY_PART_QUERY
#endif
	        ))
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
#ifdef FZN_LOG_PACK_ON
	/* A COPY BEING TAKEN, sec 483: the same gate as gathering, and each
	 * part at debug, since a copy is many of them. */
	if (request[1] == FZN_LOG_COPY_SEGMENTS_QUERY || request[1] == FZN_LOG_COPY_PART_QUERY) {
		(void)say_caused(FZN_ENTRY_DEBUG, "log/copy", NULL, NULL, NULL,
		                 "the log copied by %02x%02x%02x%02x", sender ? sender[0] : 0u,
		                 sender ? sender[1] : 0u, sender ? sender[2] : 0u,
		                 sender ? sender[3] : 0u);
		return fzn_log_copy_answer(dlog.logger.dir, request, request_len, reply, reply_cap);
	}
#endif
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

static int peer_ask(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
                    size_t reply_cap, size_t *reply_len)
{
	struct peer_asking *asking = (struct peer_asking *)ctx;
	uint32_t msg = 0;
	const uint8_t *detail = NULL;
	size_t detail_len = 0, len;

	/* ITS ENVELOPE, if any, is the caller's `wrap`, sec 465. */
	if (fzn_caller_send(asking->caller, request, request_len, asking->now + 300u, &msg)
	            != FZN_CALLER_OK
	    || fzn_caller_recv(asking->caller, msg, reply, reply_cap, reply_len, 3000u)
	               != FZN_CALLER_OK)
		return 0;
	/* A REFUSAL IN WORDS, sec 455: every binary message here opens with a
	 * small version byte, so a reply opening with a letter is the peer's
	 * own reply line -- a contact suspended, a capability it was not
	 * granted. Said as the peer said it, since the caller will only see
	 * an answer that does not parse. */
	len = *reply_len;
	while (len && (reply[len - 1u] == '\n' || reply[len - 1u] == '\r'))
		len--;
	if (len && reply[0] >= 'a' && reply[0] <= 'z'
	    && fzn_reply_of(reply, len, &detail, &detail_len) != FZN_REPLY_OK)
		say(FZN_ENTRY_WARNING, "node/peer", "%s refused: %.*s", asking->host ? asking->host : "a peer",
		        (int)(len > 200u ? 200u : len), (const char *)reply);
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

#ifdef FZN_LOG_PACK_ON
/* COPIES OF THE PULL PEERS' LOGS, sec 483: each peer's packed segments of
 * the program `--log-copy` names, verified against the chain and the
 * peer's own signature before they are kept. A peer that keeps its log
 * host-private answers in words and is said, as gathering says it. */
/* `program` added to `list` once, a word a segment name can carry, at most
 * FZND_COPY_PROGRAMS_MAX; 0, said, otherwise. secs 486, 488. */
static int add_program(const char **list, size_t *n, const char *program, const char *flag)
{
	size_t k;

	if (!program[0] || strchr(program, '/') || strchr(program, '.')
	    || strlen(program) > FZN_ENTRY_WORD_MAX) {
		fprintf(stderr, "fuzznetd: %s: a program's name, with no / or .\n", flag);
		return 0;
	}
	for (k = 0; k < *n; k++)
		if (!strcmp(list[k], program))
			return 1;
	if (*n >= FZND_COPY_PROGRAMS_MAX) {
		fprintf(stderr, "fuzznetd: %s: at most %u programs\n", flag, FZND_COPY_PROGRAMS_MAX);
		return 0;
	}
	list[(*n)++] = program;
	return 1;
}

/* THIS NODE'S LOG, PUSHED, sec 488: each program `--log-push` names, to
 * each pull peer, a bounded amount a round -- the rest on the next, from
 * where the peer says it is. A peer that takes no copies of it says so, at
 * debug, since most will not. */
#define FZND_PUSH_BUDGET (4u * 1024u * 1024u)

static void push_logs(struct pull_target *pulls, size_t npulls, uint64_t now)
{
	size_t t;

	if (!dlog.on || !dlog.n_push_programs || !dlog.has_signer)
		return;
	for (t = 0; t < npulls * dlog.n_push_programs; t++) {
		struct pull_target *peer = &pulls[t / dlog.n_push_programs];
		const char *program = dlog.push_programs[t % dlog.n_push_programs];
		struct peer_asking asking = { &peer->caller, now, peer->host };
		fzn_log_copy_tally_t tally;
		fzn_log_copy_err_t err;

		err = fzn_log_copy_push(peer_ask, &asking, dlog.logger.dir, program, FZND_PUSH_BUDGET,
		                        &tally);
		if (err == FZN_LOG_COPY_ERR_DECLINED)
			say(FZN_ENTRY_DEBUG, "log/push", "%s takes no copies of %s", peer->host, program);
		else if (err == FZN_LOG_COPY_ERR_VERIFY)
			say(FZN_ENTRY_WARNING, "log/push", "%s refused %s: %s", peer->host, tally.refused,
			    fzn_log_copy_err_str(err));
		else if (err != FZN_LOG_COPY_OK)
			say(FZN_ENTRY_WARNING, "log/push", "pushing %s to %s: %s", program, peer->host,
			    fzn_log_copy_err_str(err));
		if (tally.copied)
			say(FZN_ENTRY_INFO, "log/push", "%zu segment(s) of %s, %zu bytes, kept by %s",
			    tally.copied, program, tally.bytes, peer->host);
	}
}

static void copy_logs(struct pull_target *pulls, size_t npulls, uint64_t now)
{
	size_t t;

	if (!dlog.on || !dlog.n_copy_programs)
		return;
	for (t = 0; t < npulls * dlog.n_copy_programs; t++) {
		/* EACH PEER, EACH PROGRAM, sec 486: every program a chain of its
		 * own in the peer's copy directory. */
		struct pull_target *peer = &pulls[t / dlog.n_copy_programs];
		const char *program = dlog.copy_programs[t % dlog.n_copy_programs];
		struct peer_asking asking = { &peer->caller, now, peer->host };
		char dir[FZN_LOGGER_PATH_MAX + 80u];
		fzn_log_copy_tally_t tally;
		fzn_log_copy_err_t err;

		if (!fzn_log_copy_dir(dlog.logger.dir, peer->node, dir, sizeof(dir)))
			continue;
		if (!dlog.hash || !dlog.verify)
			return;
		err = fzn_log_copy_pull(peer_ask, &asking, program, peer->node, dir, dlog.hash,
		                        dlog.verify, &tally);
		if (err == FZN_LOG_COPY_ERR_VERIFY)
			say(FZN_ENTRY_WARNING, "log/copy", "a copy of %s from %s refused at %s: %s", program,
			    peer->host, tally.refused, fzn_log_copy_err_str(err));
		else if (err != FZN_LOG_COPY_OK)
			say(FZN_ENTRY_WARNING, "log/copy", "copying %s from %s: %s", program, peer->host,
			    fzn_log_copy_err_str(err));
		if (tally.copied)
			say(FZN_ENTRY_INFO, "log/copy", "%zu segment(s) of %s, %zu bytes, copied from %s",
			    tally.copied, program, tally.bytes, peer->host);
	}
}
#endif

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
	}
}

/* THE JOURNAL APPLIED, sec 503: every object pulled, handed to the subsystem
 * that keeps its kind, with its signer's chain rebuilt from the grants held. */
static fzn_node_apply_t node_apply;

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
}

/* WHAT THIS NODE HOLDS OF THE ESTATE'S STATE, served to a member, sec 551. */
static size_t holdings_remote(void *ctx, const uint8_t *request, size_t request_len,
                              uint8_t *reply, size_t reply_cap)
{
	const fzn_node_apply_t *ap = (const fzn_node_apply_t *)ctx;

	return fzn_reconcile_answer(ap->store, ap->hash, ap->journal, request, request_len, reply,
	                            reply_cap);
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

/* A LINE RECONCILED, sec 564: filed by the messages store, waiting when
 * its key is not here yet. */
static fzn_node_apply_outcome_t line_file(void *ctx, const uint8_t contact[FZN_PUBKEY_LEN],
                                          uint32_t epoch, const uint8_t *item, size_t len)
{
	int waiting = 0;

	switch (fzn_node_messages_file((fzn_node_messages_t *)ctx, contact, epoch, item, len,
	                               &waiting)) {
	case FZN_MESSAGES_OK:
		return waiting ? FZN_NODE_APPLY_WAITING : FZN_NODE_APPLY_APPLIED;
	case FZN_MESSAGES_ERR_BACKEND:
		return FZN_NODE_APPLY_NOT_SAVED;
	default:
		return FZN_NODE_APPLY_REFUSED;
	}
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

/* ONE ROUND OF RECONCILIATION against every pull peer, sec 551: what the
 * journal did not bring -- cut before this node saw it -- fetched from what
 * the peer holds, every round, so a gap one peer leaves another fills. */
static void reconcile_estate(struct pull_target *pulls, size_t npulls, uint64_t now)
{
	static uint8_t reply[FZND_PULL_REPLY_MAX];
	fzn_reconcile_notes_t notes = { notes_file, &node_notes };
	size_t t, lacked = 0, applied = 0, waiting = 0, refused = 0, foreign = 0;
	size_t lines_lacked = 0, lines_filed = 0, lines_passed = 0;

	if (!node_apply.store || !node_apply.journal || !node_apply.root)
		return;
	for (t = 0; t < npulls; t++) {
		struct peer_asking asking = { &pulls[t].caller, now, pulls[t].host };
		fzn_reconcile_tally_t tally;

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
			fzn_reconcile_filer_t lines = { line_file, NULL, &node_messages };
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
		}
	}
	/* EVERY PASS THAT RAN SAYS SO, at debug, as the trim's and the cut's do. */
	say(FZN_ENTRY_DEBUG, "reconcile",
	    "reconcile pass: %zu peer(s), %zu of another estate passed over, %zu lacked, "
	    "%zu applied, %zu waiting, %zu refused; lines %zu lacked, %zu filed, %zu month(s) "
	    "passed over",
	    npulls, foreign, lacked, applied, waiting, refused, lines_lacked, lines_filed,
	    lines_passed);
}

/* STREAMS THIS NODE IS BEHIND A PEER'S BASE ON, sec 552: the peer cut what
 * this node never pulled, so each takes the peer's base -- reconciliation
 * brings the state those records carried -- and the reader of the stream is
 * moved up with it. */
static void rebase_missed(struct pull_target *pulls, size_t npulls, size_t t, uint64_t now,
                          const fzn_exchange_tally_t *tally)
{
	static uint8_t reply[FZND_PULL_REPLY_MAX];
	static struct peer_asking others[FZND_PULL_TARGETS_MAX];
	static fzn_reconcile_witness_t witnesses[FZND_PULL_TARGETS_MAX];
	struct peer_asking asking = { &pulls[t].caller, now, pulls[t].host };
	size_t i, k, moved = 0, n_witnesses = 0;

	/* EVERY OTHER PULL PEER OF THIS ESTATE WITNESSES THE BRIDGE, sec 557. */
	for (k = 0; k < npulls; k++)
		if (k != t && peer_in_estate(&pulls[k])) {
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
static void pull_journal(struct pull_target *pulls, size_t npulls, uint64_t now)
{
	static uint8_t reply[FZND_PULL_REPLY_MAX];
	size_t t;

	if (!journal_on)
		return;
	for (t = 0; t < npulls; t++) {
		struct peer_asking asking = { &pulls[t].caller, now, pulls[t].host };
		fzn_exchange_tally_t tally;
		fzn_exchange_err_t err = fzn_node_journal_pull(&node_journal, peer_ask, &asking, reply,
		                                               sizeof(reply), &tally);

		if (err != FZN_EXCHANGE_OK)
			say(FZN_ENTRY_WARNING, "journal", "the journal from %s: %s", pulls[t].host,
			    fzn_exchange_err_str(err));
		else if (tally.missing)
			rebase_missed(pulls, npulls, t, now, &tally);
		else if (tally.learned || tally.refused || tally.forks)
			say(tally.forks ? FZN_ENTRY_WARNING : FZN_ENTRY_INFO, "journal",
			    "%zu record(s) from %s, %zu refused, %zu stream(s) stopped at a fork",
			    tally.learned, pulls[t].host, tally.refused, tally.forks);
		/* AND PUSHED BACK, sec 512: what this node holds of every stream
		 * the peer follows, so a hub that pulls from nobody still hears
		 * this member. */
		{
			fzn_exchange_push_tally_t pushed;
			fzn_exchange_err_t perr = fzn_node_journal_push(&node_journal, peer_ask, &asking,
			                                                reply, sizeof(reply), &pushed);

			if (perr != FZN_EXCHANGE_OK)
				say(FZN_ENTRY_WARNING, "journal", "pushing to %s: %s", pulls[t].host,
				    fzn_exchange_err_str(perr));
			else if (pushed.taken || pushed.refused || pushed.forks)
				say(pushed.refused || pushed.forks ? FZN_ENTRY_WARNING : FZN_ENTRY_INFO,
				    "journal", "%zu record(s) pushed to %s, %zu refused, %zu forked",
				    pushed.taken, pulls[t].host, pushed.refused, pushed.forks);
		}
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
	return 1;
}

/* How often the rules trim conversations, sec 531: they go by the month,
 * so an hour is soon enough. */
#define FZND_TRIM_EVERY 3600u

/* CONVERSATIONS TRIMMED BY THE RULES, sec 531: the rules naming `messages`
 * that reach this node, from the one set the logs' are drawn from. No rule
 * trims nothing -- there is no default deletion of messages. */
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
	/* EVERY PASS THAT RAN SAYS SO, at debug: that nothing was trimmed reads
	 * the same as a pass that never happened, and `make livecheck` waits on
	 * this line before believing either. */
	say(FZN_ENTRY_DEBUG, "messages",
	    "trim pass: %zu of %zu rule(s) over conversations here, %zu month(s) trimmed", n,
	    gathered, tally.months);
}

/* CONVERSATIONS, sec 527: what the journal brought absorbed, then keys
 * given to and asked of every pull peer, then the rules' trim. */
static void messages_round(struct pull_target *pulls, size_t npulls, uint64_t now)
{
	fzn_node_messages_tally_t t;
	size_t p;

	if (!messages_absorb())
		return;
	messages_trim(now);
	for (p = 0; p < npulls; p++) {
		struct peer_asking asking = { &pulls[p].caller, now, pulls[p].host };

		memset(&t, 0, sizeof(t));
		if (!fzn_node_messages_round(&node_messages, peer_ask, &asking, &t))
			say(FZN_ENTRY_WARNING, "messages", "keys with %s: no answer", pulls[p].host);
		else if (t.given || t.refused || t.taken)
			say(t.refused ? FZN_ENTRY_WARNING : FZN_ENTRY_INFO, "messages",
			    "keys with %s: %zu given, %zu refused, %zu taken, %zu still lacked",
			    pulls[p].host, t.given, t.refused, t.taken, t.lacking);
	}
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
static void pull_notes(struct pull_target *pulls, size_t npulls, uint64_t now,
                       const fzn_node_state_t *state,
                       const fzn_revocation_store_t *revocations,
                       const fzn_node_roots_t *roots)
{
	const fzn_node_config_t *config = &state->config;
	uint8_t (*members)[FZN_PUBKEY_LEN] = pulled_members;
	size_t t, n_members = 0;

	if (!notes_on)
		return;
	/* THE ESTATE'S MEMBERS FIRST, sec 445: each pull peer's, admitted on
	 * the proof of their chains against this node's own root, so a note a
	 * member wrote and a peer relays is taken. Rebuilt every round, so a
	 * member revoked since drops out. */
	for (t = 0; t < npulls; t++) {
		struct peer_asking asking = { &pulls[t].caller, now, pulls[t].host };
		size_t got = 0, refused = 0;
		fzn_node_members_err_t merr = fzn_node_members_pull(
		        peer_ask, &asking, config->root, &config->remote_capability, now,
		        node_notes.author.sign, revocations, members + n_members,
		        FZN_NODE_NOTES_WRITERS - n_members, &got, &refused);

		if (merr != FZN_NODE_MEMBERS_OK)
			say(FZN_ENTRY_WARNING, "members", "members from %s: %s", pulls[t].host,
			        fzn_node_members_err_str(merr));
		else if (refused)
			say(FZN_ENTRY_WARNING, "members", "%zu member(s) from %s did not prove", refused,
			        pulls[t].host);
		n_members += got;
	}
	n_pulled_members = n_members;
	admit_writers(state, roots);
#ifdef FZN_RECORD_STORE_FILE_ON
	index_notes();
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
	/* THE NOTES THEMSELVES COME IN THE JOURNAL, sec 519: pulled and pushed
	 * with every other stream, and filed by `index_notes`. What is left to
	 * say to each peer here is their texts and the purge conversation. */
	for (t = 0; t < npulls; t++) {
		struct peer_asking asking = { &pulls[t].caller, now, pulls[t].host };
		fzn_notes_sync_err_t err;

		/* THEIR WRAP KEYS, sec 520, both ways: a note this node holds the
		 * records of is unreadable here until its wrap key arrives. */
		{
			fzn_notes_wrap_tally_t wt;
			fzn_notes_sync_err_t werr = fzn_notes_sync_wraps(&node_notes.store, peer_ask,
			                                                 &asking, 1, &wt);

			if (werr != FZN_NOTES_SYNC_OK)
				say(FZN_ENTRY_WARNING, "notes/wrap", "wrap keys with %s: %s", pulls[t].host,
				        fzn_notes_sync_err_str(werr));
			else if (wt.taken || wt.refused || wt.given)
				say(wt.refused ? FZN_ENTRY_WARNING : FZN_ENTRY_INFO, "notes/wrap",
				        "wrap keys with %s: %zu taken, %zu refused, %zu given", pulls[t].host,
				        wt.taken, wt.refused, wt.given);
		}
		/* THEIR TEXTS, sec 448: a pushed note whose text stayed here
		 * would be a note nobody there could read. */
		{
			fzn_node_notes_text_tally_t tt;

			if (!fzn_node_notes_push_texts(&node_notes, peer_ask, &asking, &tt))
				say(FZN_ENTRY_WARNING, "notes/text", "texts to %s: no answer", pulls[t].host);
			else if (tt.pushed || tt.refused)
				say(FZN_ENTRY_INFO, "notes/text", "%zu text(s) to %s in %zu span(s), %zu refused",
				        tt.pushed, pulls[t].host, tt.spans, tt.refused);
		}
		/* THE PURGE CONVERSATION, driven from this side. sec 433. */
		{
			fzn_notes_purge_tally_t pt;

			err = fzn_notes_sync_purges(&node_notes.store, node_notes.author.policy,
			                            node_notes.pulls[t].key, peer_ask, &asking, &pt);
			if (err != FZN_NOTES_SYNC_OK)
				say(FZN_ENTRY_WARNING, "notes/purge", "purges with %s: %s", pulls[t].host,
				        fzn_notes_sync_err_str(err));
			else if (pt.erased || pt.finished || pt.taken || pt.refused || pt.declined)
				say(FZN_ENTRY_INFO, "notes/purge",
				        "purges with %s: %zu erased there, %zu finished, "
				        "%zu taken, %zu refused, %zu declined",
				        pulls[t].host, pt.erased, pt.finished, pt.taken, pt.refused,
				        pt.declined);
		}
	}
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
		int fd = -1;

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
		if (fzn_udp_bind(family, NULL, 0, &fd) != FZN_UDP_OK
		    || fzn_udp_resolve(family, sh->host, rows[i].port, &pt->caller.node)
		               != FZN_UDP_OK
		    || fzn_reasm_slot_init(&pt->slot, pt->slot_buf, sizeof(pt->slot_buf))
		               != FZN_REASM_OK
		    || fzn_reasm_init(&pt->table, &pt->slot, 1, 1u, 60u) != FZN_REASM_OK) {
			say(FZN_ENTRY_WARNING, "notes/received", "could not reach for a share at %s", sh->host);
			if (fd >= 0)
				fzn_udp_close(fd);
			fzn_wipe(&pt->pairing, sizeof(pt->pairing));
			continue;
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
		nshares_in++;
	}
}

/* Each accepted share into its sharer's tree. sec 437. */
static void pull_received(uint64_t now)
{
	size_t i;

	if (!notes_on)
		return;
	for (i = 0; i < nshares_in; i++) {
		static fzn_notes_received_t seam;
		static fzn_persist_ops_t ops;
		fzn_notes_store_t tree;
		struct peer_asking asking = { &shares_in[i].pt.caller, now, shares_in[i].host };
		fzn_notes_sync_tally_t tally;
		fzn_notes_sync_err_t err;

		if (fzn_notes_received_ops(&seam, node_notes.store.ops, node_notes.store.hash,
		                           shares_in[i].sharer, &ops)
		            != FZN_NOTES_OK
		    || fzn_notes_store_init(&tree, &ops, node_notes.store.hash) != FZN_NOTES_OK)
			continue;
		err = fzn_notes_sync_pull_shared(&tree, node_notes.author.sign, peer_ask, &asking,
		                                 &tally);
		if (err != FZN_NOTES_SYNC_OK)
			say(FZN_ENTRY_WARNING, "notes/received", "shared notes from %s: %s", shares_in[i].host,
			        fzn_notes_sync_err_str(err));
		else if (tally.learned || tally.refused)
			say(FZN_ENTRY_INFO, "notes/received", "%zu shared note record(s) from %s, %zu refused",
			        tally.learned, shares_in[i].host, tally.refused);
		/* AND THEIR WRAP KEYS, sec 520: asked, never given. */
		{
			fzn_notes_wrap_tally_t wt;
			fzn_notes_sync_err_t werr = fzn_notes_sync_wraps(&tree, peer_ask, &asking, 0, &wt);

			if (werr != FZN_NOTES_SYNC_OK)
				say(FZN_ENTRY_WARNING, "notes/received", "shared wrap keys from %s: %s",
				        shares_in[i].host, fzn_notes_sync_err_str(werr));
		}
#ifdef FZN_SPOOL_FILE_ON
		/* THE SHARED NOTES' TEXTS, sec 438: each blob one of them names is
		 * wanted on the shelf and asked of the sharer, which serves a
		 * contact the texts of what it shares and nothing else. */
		if (shelf_on && fzn_notes_view_load(&tree, node_notes.author.view) == FZN_NOTES_OK) {
			const fzn_notes_view_t *v = node_notes.author.view;
			size_t k, got;

			for (k = 0; k < v->count; k++) {
				fzn_note_blob_ref_t ref;

				if (fzn_notes_ref_of(&v->nodes[k], &ref))
					(void)fzn_node_shelf_want(&shelf, ref.root, ref.length);
			}
			got = fzn_node_shelf_fetch_wants(&shelf, peer_ask, &asking);
			if (got)
				say(FZN_ENTRY_INFO, "notes/received", "%zu shared text(s) from %s", got,
				        shares_in[i].host);
		}
#endif
	}
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
	/* THE PULL PEERS AND THE CONTACTS SHARING WITH THIS NODE, sec 493 --
	 * a contact's node answers for what it made public or shared here --
	 * each lent the fetch's reassembly table while it runs. */
	for (t = 0; t < npulls + nshares_in && n_peers < FZN_NODE_FILES_PEERS_MAX; t++) {
		fzn_caller_t *caller = t < npulls ? &pulls[t].caller : &shares_in[t - npulls].pt.caller;

		if (t >= npulls && shares_in[t - npulls].pt.fd < 0)
			continue;
		fp[n_peers].caller = caller;
		fp[n_peers].now = now;
		kept[n_peers] = caller->reasm;
		caller->reasm = &table;
		hosts[n_peers] = t < npulls ? pulls[t].host : shares_in[t - npulls].host;
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
		size_t got = fzn_node_shelf_fetch_wants(&shelf, peer_ask, &asking);

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
	        "[subsystem=PATH] age|size|count N\" as it rotates;\n"
	        "--no-log-file keeps stderr only; --log-scope=estate lets members gather it\n"
	        "--op-journal[=BYTES] enters every write to this node's state in a journal\n"
	        "of its own, by hash, keeping up to BYTES of written state (64 MiB), in\n"
	        "generations of --op-journal-rotate=WRITES (65536), the newest two kept;\n"
	        "--op-journal-replay=ENTRY [--op-journal-generation=N] --into=DIR writes\n"
	        "the state as of that entry of generation N (the newest) into a fresh\n"
	        "store at DIR, and exits\n"
	        "--check-log[=PROGRAM] walks a packed log's chain and its signatures;\n"
	        "--log-copy[=PROGRAM] keeps verified copies of the pull peers' packed logs,\n"
	        "and takes the ones members push, once a program, up to 8;\n"
	        "--log-push[=PROGRAM] pushes this node's to the pull peers that take them\n"
	        "(host-private by default)\n"
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

int main(int argc, char **argv)
{
	const char *sock_path = NULL;
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
	static struct pull_target pulls[FZND_PULL_TARGETS_MAX];
	size_t npulls = 0;
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
	int lfd = -1, ufd = -1, i;

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
		} else if (!strcmp(argv[i], "--log-copy") || !strncmp(argv[i], "--log-copy=", 11u)) {
#ifdef FZN_LOG_PACK_ON
			if (!add_program(dlog.copy_programs, &dlog.n_copy_programs,
			                 argv[i][10] == '=' ? argv[i] + 11 : "fuzznetd", "--log-copy"))
				return 2;
#else
			fprintf(stderr, "fuzznetd: --log-copy: built without packing (FZN_LOG_PACK)\n");
			return 2;
#endif
		} else if (!strcmp(argv[i], "--log-push") || !strncmp(argv[i], "--log-push=", 11u)) {
#ifdef FZN_LOG_PACK_ON
			if (!add_program(dlog.push_programs, &dlog.n_push_programs,
			                 argv[i][10] == '=' ? argv[i] + 11 : "fuzznetd", "--log-push"))
				return 2;
#else
			fprintf(stderr, "fuzznetd: --log-push: built without packing (FZN_LOG_PACK)\n");
			return 2;
#endif
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
	    && !set_admin && !replaying && udp_port < 0) {
		usage(argv[0]);
		return 2;
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
		                              &state.config.admin_capability) != FZN_CHAIN_OK) {
			fprintf(stderr, "fuzznetd: the remote capability needs both "
			                "--fuzznet-service and --fuzznet-product\n");
			return 2;
		}
		has_capability = 1;
		state.config.has_admin = 1;
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
			state.on_local = fzn_node_admin_handle;
			state.on_local_ctx = &admin;
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
					admin.files_local = fzn_node_files_local;
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
	if (npulls || notes_on || state.reassembly) {
		uint64_t next_pull = 0, last_fresh_round = 0;
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
			if (now >= next_pull || next_pull > now + FZND_PULL_EVERY) {
				round_named = say_caused(FZN_ENTRY_DEBUG, "node/round", NULL, NULL,
				                         &round_name, "a round with %zu peer(s)", npulls);
				/* THE ESTATE'S ACTS, sec 505: roots, votes, confirmations,
				 * settings, contacts and successions all arrive in the
				 * journal, pulled and applied before anything reads them.
				 * The journal follows the members the last round's notes
				 * proved, so a member paired since is read from its first
				 * act a round later. */
#ifdef FZN_RECORD_STORE_FILE_ON
				follow_estate(identity.pubkey, &state, running_roots);
				(void)messages_upgrade();
				pull_journal(pulls, npulls, now);
				apply_journal();
				reconcile_estate(pulls, npulls, now);
				messages_round(pulls, npulls, now);
				/* THE NOTES INDEX FIRST, so the cut sees how far it has
				 * read: a notes stream is cut no further than its cursor,
				 * which the round's own index has not moved yet. sec 555. */
				index_notes();
				journal_cut(now);
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
					                                  now * 1000u, &named)
					    != FZN_NODE_ROSTER_OK)
						say(FZN_ENTRY_WARNING, "contact/roster",
						    "contacts that arrived would not all be named");
					else if (named)
						say(FZN_ENTRY_INFO, "contact/roster",
						    "%zu contact(s) added on another member, named here", named);
				}
				/* NOTES, then TEXTS, secs 432 and 424: a note's text is
				 * fetched once the note naming it has arrived. */
				pull_notes(pulls, npulls, now, &state, running, running_roots);
#ifdef FZN_LOG_PACK_ON
				copy_logs(pulls, npulls, now);
#endif
				pull_received(now);
#ifdef FZN_SPOOL_FILE_ON
				fetch_texts(pulls, npulls, now);
				fetch_files(pulls, npulls, now);
				collect_texts();
#endif
				/* THE LOG LAST, sec 476: packing and the rules after the
				 * pulls, so an estate rule pulled this round applies this
				 * round rather than the next. */
				log_round();
#ifdef FZN_LOG_PACK_ON
				/* AND WHAT IT PACKED, PUSHED, sec 488. */
				push_logs(pulls, npulls, now);
#endif
				next_pull = wall_clock() + FZND_PULL_EVERY;
			}
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
			/* A SHARE JUST ACCEPTED is pulled now. sec 437. */
			if (running_admin && running_admin->received_fresh) {
				running_admin->received_fresh = 0;
				load_received(family, identity.pubkey, &hash_ops, &aead_ops, &rng_ops);
				pull_received(now);
			}
			/* A WRITE HERE GOES OUT NOW, sec 449, a round at most every
			 * two seconds, so a burst of edits is one round rather than
			 * one each. */
			if (notes_on && node_notes.fresh
			    && (now >= last_fresh_round + 2u || last_fresh_round > now)) {
				node_notes.fresh = 0;
				last_fresh_round = now;
				/* THE NOTE GOES IN THE JOURNAL, sec 519, pushed with it. */
#ifdef FZN_RECORD_STORE_FILE_ON
				pull_journal(pulls, npulls, now);
				messages_round(pulls, npulls, now);
#endif
				pull_notes(pulls, npulls, now, &state, running, running_roots);
			}
#ifdef FZN_RECORD_STORE_FILE_ON
			/* A MESSAGE WRITTEN HERE GOES AT ONCE, sec 528: the journal
			 * pushed, then keys given and asked, rather than waiting for
			 * the next round. The same two-second floor as notes'. */
			if (messages_on && node_messages.fresh
			    && (now >= last_fresh_round + 2u || last_fresh_round > now)) {
				node_messages.fresh = 0;
				last_fresh_round = now;
				pull_journal(pulls, npulls, now);
				messages_round(pulls, npulls, now);
			}
			if (journal_pushed) {
				journal_pushed = 0;
				index_notes();
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
			(void)fzn_node_run_once(&state, 1000);
		}
	}

	say(FZN_ENTRY_NOTE, "node", "serving%s%s%s", sock_path ? " on " : "",
	        sock_path ? sock_path : "", (udp_port >= 0) ? " udp" : "");
	fzn_node_run(&state);	/* until the process is signalled */

	/* Unreached in normal operation; named so the sockets read as closed
	 * rather than leaked. */
	fzn_socket_close(lfd, sock_path);
	if (ufd >= 0)
		fzn_udp_close(ufd);
	return 0;
}
