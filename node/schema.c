#include "presets.h"
#include "schema.h"
#include "permit.h"
#include "../state/scope.h"
#include "../local/escape.h"

#include <stdio.h>
#include <string.h>

/* `K+M`: each 1 to 31, together at most 32, as `fzn_node_settings_erasure`
 * reads it. */
static const char *erasure_check(const uint8_t *value, size_t len)
{
	uint64_t k = 0, m = 0;
	size_t plus;

	for (plus = 0; plus < len && value[plus] != '+'; plus++)
		;
	if (plus == len || !fzn_schema_count(value, plus, 1u, 31u, &k)
	    || !fzn_schema_count(value + plus + 1u, len - plus - 1u, 1u, 31u, &m) || k + m > 32u)
		return "not K+M, each 1 to 31 and together at most 32";
	return NULL;
}

/* THE LOG'S LEVELS BY NAME, most severe first, as `--log-level` takes them:
 * a name, or the letter a log line carries. */
static const char *const LOG_LEVELS[] = { "critical", "error",   "warning", "note",
	                                  "info",     "verbose", "debug",   "trace" };
static const char LOG_LETTERS[] = "CEWNIVDT";

int fzn_node_schema_log_level(const uint8_t *value, size_t len)
{
	int l;

	if (!value)
		return 0;
	for (l = 0; l < 8; l++)
		if ((len == strlen(LOG_LEVELS[l]) && memcmp(value, LOG_LEVELS[l], len) == 0)
		    || (len == 1u && value[0] == (uint8_t)LOG_LETTERS[l]))
			return l + 1;
	return 0;
}

/* WHERE A RULE PUTS A KIND OF WORK, sec 917: nothing it says reaches what must
 * work, which `node/pressure.h` keeps out of a rule's reach. */
static const char *pressure_rank_check(const uint8_t *value, size_t len)
{
	if ((len == 5u && memcmp(value, "trace", 5u) == 0)
	    || (len == 4u && (memcmp(value, "copy", 4u) == 0 || memcmp(value, "user", 4u) == 0)))
		return NULL;
	return "trace, copy or user";
}

static const char *remote_permit_check(const uint8_t *value, size_t len)
{
	return fzn_node_remote_permit_check(value, len);
}

static const char *permit_check(const uint8_t *value, size_t len)
{
	return fzn_node_permit_check(value, len);
}

static const char *events_permit_check(const uint8_t *value, size_t len)
{
	return fzn_node_permit_events_check(value, len);
}

/* `group/member`, sec 868: group names apart by single spaces, each one
 * `fzn_scope_group_id` takes, none twice. */
static const char *member_check(const uint8_t *value, size_t len)
{
	static const char WHY[] = "group names of a-z, 0-9 and ._-, 1 to 32 bytes, apart by "
	                          "single spaces, none twice";
	uint8_t id[FZN_SUBJECT_LEN], seen[16][FZN_SUBJECT_LEN];
	size_t at = 0, n_seen = 0, i;

	while (at < len) {
		size_t start = at;

		while (at < len && value[at] != ' ')
			at++;
		if (!fzn_scope_group_id(value + start, at - start, id) || n_seen == 16u)
			return WHY;
		for (i = 0; i < n_seen; i++)
			if (memcmp(seen[i], id, sizeof(id)) == 0)
				return WHY;
		memcpy(seen[n_seen++], id, sizeof(id));
		if (at < len && ++at == len)
			return WHY;	/* a trailing space */
	}
	return n_seen ? NULL : WHY;
}

static const char *log_level_check(const uint8_t *value, size_t len)
{
	return fzn_node_schema_log_level(value, len)
	               ? NULL
	               : "one of critical, error, warning, note, info, verbose, debug, trace, "
	                 "or its letter";
}

static const char *log_scope_check(const uint8_t *value, size_t len)
{
	return (len == 12u && memcmp(value, "host-private", 12u) == 0)
	                       || (len == 6u && memcmp(value, "estate", 6u) == 0)
	               ? NULL
	               : "host-private or estate";
}

#define ESTATE FZN_SCHEMA_ESTATE
#define HOST FZN_SCHEMA_HOST

/* EVERY CELL A READER HERE READS, with the reader's own default and bounds
 * (sec 686's inventory). Where a reader takes more than this declares, the
 * declaration is the narrower: a write is refused that the reader would
 * have taken, never the reverse. */
const fzn_schema_entry_t fzn_node_schema_own[] = {
	{ "revocation/k", FZN_SCHEMA_COUNT, ESTATE, 1u, 255u, "", "root signatures",
	  FZN_SCHEMA_SAFE_HIGHER,
	  "the estate's k: root signatures a revocation needs, a root's to set (sec 542)", NULL, 0u },
	{ "journal/window", FZN_SCHEMA_COUNT, ESTATE, 1u, 36500u, "60", "days", 0u,
	  "how far back the journal reaches; a clear older than this is forgotten (sec 548)", NULL, 0u },
	{ "archive/replicas", FZN_SCHEMA_COUNT, ESTATE, 1u, 16u, "2", "hosts", FZN_SCHEMA_ADVANCED,
	  "how many hosts hold an archived segment before it is pruned (sec 592)", NULL, 0u },
	{ "archive/erasure", FZN_SCHEMA_TEXT, ESTATE, 3u, 5u, "4+2", "data+parity pieces",
	  FZN_SCHEMA_ADVANCED, "how an archived segment is cut into pieces (sec 597)", erasure_check, 0u },
	{ "archive/gone", FZN_SCHEMA_DURATION, ESTATE, 1u, 315360000u, "14d", "", FZN_SCHEMA_ADVANCED,
	  "how long a keeper may be silent before its pieces are placed elsewhere (sec 601)", NULL, 0u },
	{ "routing/public", FZN_SCHEMA_FLAG, ESTATE, 0u, 0u, "off", "",
	  FZN_SCHEMA_SAFE_LOWER | FZN_SCHEMA_ADVERTISED,
	  "the routing manifest offers this estate's hosts as public relays (sec 611)", NULL, 0u },
	{ "routing/advertise", FZN_SCHEMA_FLAG, ESTATE, 0u, 0u, "off", "",
	  FZN_SCHEMA_SAFE_LOWER | FZN_SCHEMA_ADVERTISED,
	  "contacts are told every host of the estate, not only this node (sec 614)", NULL, 0u },
	{ "stream/grant/", FZN_SCHEMA_COUNT, ESTATE, 0u, 3u, "", "level", FZN_SCHEMA_VERB,
	  "the level a grantee holds of a stream, by `grant stream` (sec 660)", NULL, 0u },
	{ "contact/name/", FZN_SCHEMA_TEXT, ESTATE, 1u, 32u, "", "", FZN_SCHEMA_VERB,
	  "a contact's name, the user's on every host, by `add contact`, which checks it (sec "
	  "699)",
	  NULL, 0u },
	{ "net/address", FZN_SCHEMA_ADDRESS, HOST, 0u, 253u, "", "", FZN_SCHEMA_ADVERTISED,
	  "where this host is reached, HOST PORT, an admin's to correct (sec 579)", NULL, 0u },
	{ "host/name", FZN_SCHEMA_TEXT, HOST, 1u, 32u, "", "", 0u,
	  "what this host's user calls it -- laptop, phone -- as every device of the estate "
	  "lists it (sec 848)",
	  NULL, 0u },
	{ "local/permit/", FZN_SCHEMA_TEXT, HOST, 1u, 256u, "", "", 0u,
	  "which local users and groups may read (r) or change (rw) a verb's subject on this "
	  "host: group:NAME=r user:NAME=rw, #ID for a NAME (sec 852)",
	  permit_check, 0u },
	{ FZN_REMOTE_PERMIT_KEY_PREFIX, FZN_SCHEMA_TEXT, HOST, 1u, 256u, "", "", 0u,
	  "which hosts of the estate may call this procedure here: member, admin, root, "
	  "host:HEX or none, apart by spaces (sec 921)",
	  remote_permit_check, 0u },
	{ FZN_REMOTE_PERMIT_KEY, FZN_SCHEMA_TEXT, HOST, 1u, 256u, "", "", 0u,
	  "the same, for every procedure with no rule of its own; member when unset (sec 921)",
	  remote_permit_check, 0u },
	{ FZN_PRESET_CHOSEN_KEY, FZN_SCHEMA_TEXT, HOST, 1u, 32u, "", "", FZN_SCHEMA_ADVANCED,
	  "the profile this host's user chose, by `set preset` (sec 908)", NULL, 0u },
	{ FZN_PRESET_APPLIED_KEY, FZN_SCHEMA_TEXT, HOST, 1u, 64u, "", "", FZN_SCHEMA_ADVANCED,
	  "the profile last applied here, and its revisions (sec 908)", NULL, 0u },
	{ "local/events", FZN_SCHEMA_TEXT, HOST, 1u, 256u, "", "", 0u,
	  "which local users and groups may hold `get events`, hearing what this application "
	  "publishes and none of fuzznet's: local:NAME=r local:@GROUP=r, or any=r for every "
	  "local user (secs 899, 933)",
	  events_permit_check, 0u },
	{ "pressure/rank/", FZN_SCHEMA_TEXT, HOST, 1u, 16u, "", "", FZN_SCHEMA_ADVANCED,
	  "where a kind of work stands when this host is short of disk, memory or network: "
	  "trace, copy or user, for streams, relay, files, group-lines, notes, messages, "
	  "reconcile (sec 917)",
	  pressure_rank_check, 0u },
	{ "group/member", FZN_SCHEMA_TEXT, HOST, 1u, 255u, "", "", 0u,
	  "the groups this host is in, first first: a group's settings stand here where the "
	  "host sets none of its own, and the first group listed that sets one wins (sec 868)",
	  member_check, 0u },
	{ "net/metric", FZN_SCHEMA_COUNT, HOST, 0u, 255u, "100", "",
	  FZN_SCHEMA_ADVANCED | FZN_SCHEMA_ADVERTISED,
	  "this host's place in the routing manifest, lower first (sec 611)", NULL, 0u },
	{ "net/discovery", FZN_SCHEMA_TEXT, HOST, 1u, 45u, "255.255.255.255", "", FZN_SCHEMA_ADVANCED,
	  "where `fetch lan` sends its probe, or `off` (sec 624)", NULL, 0u },
	{ "location/enabled", FZN_SCHEMA_FLAG, HOST, 0u, 0u, "off", "", FZN_SCHEMA_SAFE_LOWER,
	  "sample gpsd into the location stream; off, a position being the most sensitive thing "
	  "kept (sec 678)",
	  NULL, 0u },
	{ "location/gpsd", FZN_SCHEMA_ADDRESS, HOST, 0u, 253u, "localhost 2947", "", 0u,
	  "where gpsd is (sec 678)", NULL, 0u },
	{ "location/every", FZN_SCHEMA_COUNT, HOST, 1u, 86400u, "30", "seconds", 0u,
	  "the least time between fixes kept (sec 678)", NULL, 0u },
	{ "location/accuracy", FZN_SCHEMA_COUNT, HOST, 0u, 61440u, "100", "metres", 0u,
	  "a fix less certain than this is dropped; 0 keeps every fix (sec 678)", NULL, 0u },
	{ "log/level", FZN_SCHEMA_TEXT, HOST, 1u, 8u, "", "", 0u,
	  "the least severe level this host's log file keeps, critical to trace; unset, "
	  "`--log-level`'s, info by default (sec 735)",
	  log_level_check, 0u },
	{ "log/segment", FZN_SCHEMA_COUNT, HOST, 4096u, 1099511627776u, "", "bytes",
	  FZN_SCHEMA_ADVANCED,
	  "the size a log segment is rotated at; unset, `--log-segment`'s (sec 735)", NULL, 0u },
	{ "log/scope", FZN_SCHEMA_TEXT, HOST, 6u, 12u, "", "", FZN_SCHEMA_SENSITIVE,
	  "host-private, or estate to let the estate's members gather this host's log; unset, "
	  "`--log-scope`'s, host-private by default (sec 735)",
	  log_scope_check, 0u },
	{ "invite/confirm", FZN_SCHEMA_FLAG, HOST, 0u, 0u, "off", "", FZN_SCHEMA_SAFE_HIGHER,
	  "an invite waits for this host's user unless `add invite open` says not (sec 896)", NULL, 0u },
	{ "relay/enabled", FZN_SCHEMA_FLAG, HOST, 0u, 0u, "off", "", FZN_SCHEMA_SAFE_LOWER,
	  "this host relays frames for others (sec 622)", NULL, 0u },
	{ "relay/quota", FZN_SCHEMA_COUNT, HOST, 0u, 1000000000000000000u, "104857600", "bytes",
	  0u, "what one requester may relay through this host a window; 0 for no bound (sec 622)",
	  NULL, 0u },
	{ "relay/window", FZN_SCHEMA_COUNT, HOST, 1u, 31536000u, "86400", "seconds", 0u,
	  "the window a relay quota counts over (sec 622)", NULL, 0u },
	{ "remote/admin", FZN_SCHEMA_FLAG, HOST, 0u, 0u, "off", "",
	  FZN_SCHEMA_SENSITIVE | FZN_SCHEMA_SAFE_LOWER,
	  "an admin or a root may run this node's verbs remotely (sec 543)", NULL, 0u },
	{ "retention/", FZN_SCHEMA_TEXT, ESTATE | HOST, 1u, 256u, "", "", FZN_SCHEMA_VERB,
	  "one retention rule, by `add retention` (sec 541)", NULL, 0u },
	{ "sticker/", FZN_SCHEMA_TEXT, ESTATE | HOST, 1u, 256u, "", "", FZN_SCHEMA_VERB,
	  "a saved sticker pack, by `put sticker` or `add sticker` (sec 681)", NULL, 0u },
};
const size_t fzn_node_schema_own_n = sizeof(fzn_node_schema_own) / sizeof(fzn_node_schema_own[0]);

const fzn_schema_entry_t *fzn_node_schema_find(const fzn_node_schema_t *schema, const uint8_t *key,
                                               size_t len)
{
	const fzn_schema_entry_t *e = fzn_schema_find(fzn_node_schema_own, fzn_node_schema_own_n,
	                                              key, len);

	if (!e && schema)
		e = fzn_schema_find(schema->extra, schema->n_extra, key, len);
	return e;
}

const char *fzn_node_schema_unusable(const fzn_node_schema_t *schema, const fzn_setting_t *s,
                                     const uint8_t own[FZN_PUBKEY_LEN],
                                     const fzn_schema_entry_t **entry)
{
	const fzn_schema_entry_t *e;

	if (entry)
		*entry = NULL;
	if (!s || !s->set
	    || !(s->scope == FZN_SCOPE_ESTATE
	         || (s->scope == FZN_SCOPE_HOST && own && s->about
	             && memcmp(s->about, own, FZN_PUBKEY_LEN) == 0)))
		return NULL;
	e = fzn_node_schema_find(schema, s->key, s->key_len);
	if (!e)
		return NULL;
	if (entry)
		*entry = e;
	return fzn_schema_check(e, s->value, s->value_len);
}

const char *fzn_node_schema_refused(const fzn_schema_entry_t *extra, size_t n)
{
	size_t i, j;

	for (i = 0; i < n; i++) {
		const char *key = extra[i].key;

		if (!key || !key[0] || !extra[i].scopes
		    || (extra[i].scopes & ~(unsigned)(FZN_SCHEMA_ESTATE | FZN_SCHEMA_HOST))
		    || extra[i].type < FZN_SCHEMA_FLAG || extra[i].type > FZN_SCHEMA_TEXT)
			return key ? key : "(no key)";
		for (j = 0; j < fzn_node_schema_own_n; j++)
			if (fzn_schema_overlap(key, fzn_node_schema_own[j].key))
				return key;
		for (j = 0; j < i; j++)
			if (fzn_schema_overlap(key, extra[j].key))
				return key;
	}
	return NULL;
}

static int next_word(const uint8_t **at, size_t *left, const uint8_t **w, size_t *n)
{
	while (*left && **at == ' ') {
		(*at)++;
		(*left)--;
	}
	if (!*left)
		return 0;
	*w = *at;
	while (*left && **at != ' ') {
		(*at)++;
		(*left)--;
	}
	*n = (size_t)(*at - *w);
	return 1;
}

static int all_digits(const uint8_t *w, size_t n)
{
	size_t i;

	if (!n || n > 10u)
		return 0;
	for (i = 0; i < n; i++)
		if (w[i] < '0' || w[i] > '9')
			return 0;
	return 1;
}

/* TEXT ESCAPED into `out`, or `-` for none: 0 when it does not fit. */
static size_t escaped(const char *text, char *out, size_t cap)
{
	size_t n = text ? strlen(text) : 0u, written = 0;

	if (!n)
		return cap > 1u ? (size_t)snprintf(out, cap, "-") : 0u;
	if (fzn_escape((const uint8_t *)text, n, out, cap, &written) != n || written >= cap)
		return 0;
	out[written] = '\0';
	return written;
}

/* ONE ROW, into `out`: its length, or 0 when it does not fit. */
static size_t row_of(const fzn_schema_entry_t *e, char *out, size_t cap)
{
	char def[96], unit[96], summary[600], flags[96];
	int n;

	flags[0] = '\0';
	if (e->flags & FZN_SCHEMA_RESTART)
		(void)strcat(flags, "+restart");
	if (e->flags & FZN_SCHEMA_SENSITIVE)
		(void)strcat(flags, "+sensitive");
	if (e->flags & FZN_SCHEMA_ADVANCED)
		(void)strcat(flags, "+advanced");
	if (e->flags & FZN_SCHEMA_VERB)
		(void)strcat(flags, "+verb");
	if (e->flags & FZN_SCHEMA_SAFE_LOWER)
		(void)strcat(flags, "+safe-lower");
	if (e->flags & FZN_SCHEMA_SAFE_HIGHER)
		(void)strcat(flags, "+safe-higher");
	if (e->flags & FZN_SCHEMA_ADVERTISED)
		(void)strcat(flags, "+advertised");
	if (!escaped(e->def, def, sizeof(def)) || !escaped(e->unit, unit, sizeof(unit))
	    || !escaped(e->summary, summary, sizeof(summary)))
		return 0;
	n = snprintf(out, cap, "%s,%s,%s,%llu,%llu,%s,%s,%s,%s", e->key, fzn_schema_type_name(e->type),
	             e->scopes == (FZN_SCHEMA_ESTATE | FZN_SCHEMA_HOST) ? "estate+host"
	             : e->scopes == FZN_SCHEMA_ESTATE                   ? "estate"
	                                                                : "host",
	             (unsigned long long)e->min, (unsigned long long)e->max, def, unit,
	             flags[0] ? flags + 1 : "-", summary);
	return n < 0 || (size_t)n >= cap ? 0u : (size_t)n;
}

static int opens(const fzn_schema_entry_t *e, const uint8_t *prefix, size_t len)
{
	return !len || (strlen(e->key) >= len && memcmp(e->key, prefix, len) == 0);
}

#define REPLY(...) ((size_t)snprintf(reply, cap, __VA_ARGS__))

static size_t list_schema(const fzn_node_schema_t *schema, const uint8_t *prefix, size_t prefix_len,
                          size_t from, char *reply, size_t cap)
{
	const fzn_schema_entry_t *tables[2] = { fzn_node_schema_own, schema ? schema->extra : NULL };
	size_t sizes[2] = { fzn_node_schema_own_n, schema ? schema->n_extra : 0u };
	size_t total = 0, index = 0, at, t, i;
	int full = 0;

	for (t = 0; t < 2u; t++)
		for (i = 0; i < sizes[t]; i++)
			total += opens(&tables[t][i], prefix, prefix_len) ? 1u : 0u;
	at = (size_t)snprintf(reply, cap, "ok %zu %zu", total, from);
	for (t = 0; t < 2u && !full; t++)
		for (i = 0; i < sizes[t] && !full; i++) {
			char row[900];
			size_t n;

			if (!opens(&tables[t][i], prefix, prefix_len) || index++ < from)
				continue;
			n = row_of(&tables[t][i], row, sizeof(row));
			/* ROOM FOR THE ROW, its space and the newline. */
			if (!n || at + 1u + n + 1u >= cap) {
				full = 1;
				break;
			}
			reply[at++] = ' ';
			memcpy(reply + at, row, n);
			at += n;
		}
	reply[at++] = '\n';
	reply[at] = '\0';
	return at;
}

size_t fzn_node_schema_local(void *ctx, fzn_origin_t origin, const fzn_request_t *request,
                             char *reply, size_t cap)
{
	const fzn_node_schema_t *schema = ctx;
	const uint8_t *at = request ? request->arg : NULL, *w, *prefix = NULL;
	size_t left = request ? request->arg_len : 0u, n, prefix_len = 0, from = 0, i;

	(void)origin;
	if (!at || !next_word(&at, &left, &w, &n) || n != 6u || memcmp(w, "schema", 6u) != 0)
		return 0;
	if (request->parsed != FZN_VERB_LIST && request->parsed != FZN_VERB_GET)
		return 0;
	if (!reply || cap < 2u)
		return 0;
	if (request->parsed == FZN_VERB_GET) {
		const fzn_schema_entry_t *e;
		char row[900];

		if (!next_word(&at, &left, &w, &n) || left)
			return REPLY("malformed get schema KEY\n");
		e = fzn_node_schema_find(schema, w, n);
		if (!e)
			return REPLY("error no such setting is declared\n");
		n = row_of(e, row, sizeof(row));
		return n && n + 4u < cap ? REPLY("ok %s\n", row) : REPLY("error the row does not fit\n");
	}
	/* `list schema [PREFIX] [FROM]`: a FROM is all digits. */
	if (next_word(&at, &left, &w, &n)) {
		if (!all_digits(w, n)) {
			prefix = w;
			prefix_len = n;
			if (!next_word(&at, &left, &w, &n))
				return list_schema(schema, prefix, prefix_len, 0u, reply, cap);
		}
		if (left || !all_digits(w, n))
			return REPLY("malformed list schema [PREFIX] [FROM]\n");
		for (i = 0; i < n; i++)
			from = from * 10u + (size_t)(w[i] - '0');
	}
	return list_schema(schema, prefix, prefix_len, from, reply, cap);
}
