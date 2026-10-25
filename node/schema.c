#include "schema.h"
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
	{ "revocation/k", FZN_SCHEMA_COUNT, ESTATE, 1u, 255u, "", "root signatures", 0u,
	  "the estate's k: root signatures a revocation needs, a root's to set (sec 542)", NULL },
	{ "journal/window", FZN_SCHEMA_COUNT, ESTATE, 1u, 36500u, "60", "days", 0u,
	  "how far back the journal reaches; a clear older than this is forgotten (sec 548)", NULL },
	{ "archive/replicas", FZN_SCHEMA_COUNT, ESTATE, 1u, 16u, "2", "hosts", FZN_SCHEMA_ADVANCED,
	  "how many hosts hold an archived segment before it is pruned (sec 592)", NULL },
	{ "archive/erasure", FZN_SCHEMA_TEXT, ESTATE, 3u, 5u, "4+2", "data+parity pieces",
	  FZN_SCHEMA_ADVANCED, "how an archived segment is cut into pieces (sec 597)", erasure_check },
	{ "archive/gone", FZN_SCHEMA_DURATION, ESTATE, 1u, 315360000u, "14d", "", FZN_SCHEMA_ADVANCED,
	  "how long a keeper may be silent before its pieces are placed elsewhere (sec 601)", NULL },
	{ "routing/public", FZN_SCHEMA_FLAG, ESTATE, 0u, 0u, "off", "", 0u,
	  "the routing manifest offers this estate's hosts as public relays (sec 611)", NULL },
	{ "routing/advertise", FZN_SCHEMA_FLAG, ESTATE, 0u, 0u, "off", "", 0u,
	  "contacts are told every host of the estate, not only this node (sec 614)", NULL },
	{ "stream/grant/", FZN_SCHEMA_COUNT, ESTATE, 0u, 3u, "", "level", FZN_SCHEMA_VERB,
	  "the level a grantee holds of a stream, by `grant stream` (sec 660)", NULL },
	{ "contact/name/", FZN_SCHEMA_TEXT, ESTATE, 1u, 32u, "", "", FZN_SCHEMA_VERB,
	  "a contact's name, the user's on every host, by `add contact`, which checks it (sec "
	  "699)",
	  NULL },
	{ "net/address", FZN_SCHEMA_ADDRESS, HOST, 0u, 253u, "", "", 0u,
	  "where this host is reached, HOST PORT, an admin's to correct (sec 579)", NULL },
	{ "net/metric", FZN_SCHEMA_COUNT, HOST, 0u, 255u, "100", "", FZN_SCHEMA_ADVANCED,
	  "this host's place in the routing manifest, lower first (sec 611)", NULL },
	{ "net/discovery", FZN_SCHEMA_TEXT, HOST, 1u, 45u, "255.255.255.255", "", FZN_SCHEMA_ADVANCED,
	  "where `fetch lan` sends its probe, or `off` (sec 624)", NULL },
	{ "location/enabled", FZN_SCHEMA_FLAG, HOST, 0u, 0u, "off", "", 0u,
	  "sample gpsd into the location stream; off, a position being the most sensitive thing "
	  "kept (sec 678)",
	  NULL },
	{ "location/gpsd", FZN_SCHEMA_ADDRESS, HOST, 0u, 253u, "localhost 2947", "", 0u,
	  "where gpsd is (sec 678)", NULL },
	{ "location/every", FZN_SCHEMA_COUNT, HOST, 1u, 86400u, "30", "seconds", 0u,
	  "the least time between fixes kept (sec 678)", NULL },
	{ "location/accuracy", FZN_SCHEMA_COUNT, HOST, 0u, 1000000u, "100", "metres", 0u,
	  "a fix less certain than this is dropped; 0 keeps every fix (sec 678)", NULL },
	{ "log/level", FZN_SCHEMA_TEXT, HOST, 1u, 8u, "", "", 0u,
	  "the least severe level this host's log file keeps, critical to trace; unset, "
	  "`--log-level`'s, info by default (sec 735)",
	  log_level_check },
	{ "log/segment", FZN_SCHEMA_COUNT, HOST, 4096u, 1099511627776u, "", "bytes",
	  FZN_SCHEMA_ADVANCED,
	  "the size a log segment is rotated at; unset, `--log-segment`'s (sec 735)", NULL },
	{ "log/scope", FZN_SCHEMA_TEXT, HOST, 6u, 12u, "", "", FZN_SCHEMA_SENSITIVE,
	  "host-private, or estate to let the estate's members gather this host's log; unset, "
	  "`--log-scope`'s, host-private by default (sec 735)",
	  log_scope_check },
	{ "relay/enabled", FZN_SCHEMA_FLAG, HOST, 0u, 0u, "off", "", 0u,
	  "this host relays frames for others (sec 622)", NULL },
	{ "relay/quota", FZN_SCHEMA_COUNT, HOST, 0u, 1000000000000000000u, "104857600", "bytes",
	  0u, "what one requester may relay through this host a window; 0 for no bound (sec 622)",
	  NULL },
	{ "relay/window", FZN_SCHEMA_COUNT, HOST, 1u, 31536000u, "86400", "seconds", 0u,
	  "the window a relay quota counts over (sec 622)", NULL },
	{ "remote/admin", FZN_SCHEMA_FLAG, HOST, 0u, 0u, "off", "", FZN_SCHEMA_SENSITIVE,
	  "an admin or a root may run this node's verbs remotely (sec 543)", NULL },
	{ "retention/", FZN_SCHEMA_TEXT, ESTATE | HOST, 1u, 256u, "", "", FZN_SCHEMA_VERB,
	  "one retention rule, by `add retention` (sec 541)", NULL },
	{ "sticker/", FZN_SCHEMA_TEXT, ESTATE | HOST, 1u, 256u, "", "", FZN_SCHEMA_VERB,
	  "a saved sticker pack, by `put sticker` or `add sticker` (sec 681)", NULL },
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
	char def[96], unit[96], summary[600], flags[40];
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
