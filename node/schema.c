#include "presets.h"
#include "schema.h"
#include "permit.h"
#include "../state/scope.h"
#include "../local/escape.h"
#include "../wire/generated/settings_registry.h"

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

/* ONE WORD OF A LIST node/settings_registry.situ declares, sec 1414: the
 * generated validator `validate`'s verdict on `value`. */
static int one_word(situ_err_t (*validate)(situ_view_t), const uint8_t *value, size_t len)
{
	situ_msg_t m;
	situ_view_t v;

	if (!value || len > UINT32_MAX)
		return 0;
	situ_msg_init(&m, (uint8_t *)(uintptr_t)value, (uint32_t)len);
	return situ_view_at(&m, 0u, (uint32_t)len, &v) == SITU_OK && validate(v) == SITU_OK;
}

/* WHERE A RULE PUTS A KIND OF WORK, sec 917: nothing it says reaches what must
 * work, which `node/pressure.h` keeps out of a rule's reach. The words are
 * the registry's `pressure_rank_word`. */
static const char *pressure_rank_check(const uint8_t *value, size_t len)
{
	return one_word(fzn_settings_registry_pressure_rank_validate, value, len) ? NULL : "trace, copy or user";
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
 * `fzn_scope_group_id` takes, none twice -- node/permit.situ's group_list
 * since sec 1441. */
static const char *member_check(const uint8_t *value, size_t len)
{
	return fzn_node_group_list_check(value, len);
}

/* The registry's `log_level_word`, which `fzn_node_schema_log_level` reads. */
static const char *log_level_check(const uint8_t *value, size_t len)
{
	return one_word(fzn_settings_registry_log_level_validate, value, len)
	               ? NULL
	               : "one of critical, error, warning, note, info, verbose, debug, trace, "
	                 "or its letter";
}

/* The registry's `log_scope_word`. */
static const char *log_scope_check(const uint8_t *value, size_t len)
{
	return one_word(fzn_settings_registry_log_scope_validate, value, len) ? NULL : "host-private or estate";
}

/* `library/keep`, sec 1473: words of the registry's `keep_word` apart by
 * single spaces, none twice. */
static const char *keep_check(const uint8_t *value, size_t len)
{
	static const char *const why = "music, video, photos or all, apart by single spaces, none twice";
	size_t at = 0, end, k;

	if (!value || !len)
		return why;
	while (at < len) {
		for (end = at; end < len && value[end] != ' '; end++)
			;
		if (end == at || !one_word(fzn_settings_registry_keep_validate, value + at, end - at))
			return why;
		/* none twice: an earlier word the same */
		for (k = 0; k < at;) {
			size_t e2 = k;

			while (e2 < len && value[e2] != ' ')
				e2++;
			if (e2 - k == end - at && !memcmp(value + k, value + at, end - at))
				return why;
			k = e2 + 1u;
		}
		if (end < len && end + 1u == len)
			return why; /* a trailing space */
		at = end + 1u;
	}
	return NULL;
}

/* THE HAND-ONLY CHECKS, by key: the grammars the registry types as
 * printable text of their bounds (sec 1330), attached to its rows here. */
static const struct {
	const char *key;
	const char *(*check)(const uint8_t *value, size_t len);
} hand_checks[] = {
	{ "archive/erasure", erasure_check },   { "local/permit/", permit_check },
	{ "remote/permit/", remote_permit_check }, { "remote/permit", remote_permit_check },
	{ "local/events", events_permit_check }, { "group/member", member_check },
	{ "library/keep", keep_check },
};

/* A REGISTRY CELL'S TYPE, by situ's name for it (situ 7febf9ed): a cell
 * situ adds that this table has no type for reads as none, which
 * `fzn_node_schema_refused` would refuse in an extension's table and
 * settings_registry_test refuses here. */
static fzn_schema_type_t type_of(uint32_t cell)
{
	switch (cell) {
	case FZN_SETTINGS_REGISTRY_NODE_CELL_COUNT:
		return FZN_SCHEMA_COUNT;
	case FZN_SETTINGS_REGISTRY_NODE_CELL_TEXT:
		return FZN_SCHEMA_TEXT;
	case FZN_SETTINGS_REGISTRY_NODE_CELL_DURATION:
		return FZN_SCHEMA_DURATION;
	case FZN_SETTINGS_REGISTRY_NODE_CELL_FLAG:
		return FZN_SCHEMA_FLAG;
	case FZN_SETTINGS_REGISTRY_NODE_CELL_ADDRESS:
		return FZN_SCHEMA_ADDRESS;
	/* ONE WORD OF A LIST, sec 1414: text to a client, its grammar the
	 * registry's, checked by the cell's own (`check_of`). */
	case FZN_SETTINGS_REGISTRY_NODE_CELL_PRESSURE_RANK:
	case FZN_SETTINGS_REGISTRY_NODE_CELL_LOG_LEVEL:
	case FZN_SETTINGS_REGISTRY_NODE_CELL_LOG_SCOPE:
		return FZN_SCHEMA_TEXT;
	default:
		return (fzn_schema_type_t)0;
	}
}

/* A CELL'S OWN CHECK, where its grammar is the registry's: NULL for none. */
static const char *(*check_of(uint32_t cell))(const uint8_t *, size_t)
{
	switch (cell) {
	case FZN_SETTINGS_REGISTRY_NODE_CELL_PRESSURE_RANK:
		return pressure_rank_check;
	case FZN_SETTINGS_REGISTRY_NODE_CELL_LOG_LEVEL:
		return log_level_check;
	case FZN_SETTINGS_REGISTRY_NODE_CELL_LOG_SCOPE:
		return log_scope_check;
	default:
		return NULL;
	}
}

static void row_of_registry(const fzn_settings_registry_node_entry_t *g, fzn_schema_entry_t *e)
{
	size_t k;

	memset(e, 0, sizeof(*e));
	e->key = g->key;
	e->type = type_of(g->cell);
	e->scopes = (g->scope & FZN_SETTINGS_REGISTRY_SCOPE_ESTATE ? FZN_SCHEMA_ESTATE : 0u)
	            | (g->scope & FZN_SETTINGS_REGISTRY_SCOPE_HOST ? FZN_SCHEMA_HOST : 0u);
	/* TEXT AND AN ADDRESS ARE BOUNDED IN BYTES, the others in value. */
	if (e->type == FZN_SCHEMA_TEXT || e->type == FZN_SCHEMA_ADDRESS) {
		e->min = g->min_size;
		e->max = g->max_size == UINT32_MAX ? 0u : g->max_size;
	} else {
		e->min = g->has_min ? (uint64_t)g->min : 0u;
		e->max = g->has_max ? (uint64_t)g->max : 0u;
	}
	e->def = g->def ? g->def : "";
	e->unit = g->unit ? g->unit : "";
	e->flags = (g->display & FZN_SETTINGS_REGISTRY_DISPLAY_RESTART ? FZN_SCHEMA_RESTART : 0u)
	           | (g->display & FZN_SETTINGS_REGISTRY_DISPLAY_SENSITIVE ? FZN_SCHEMA_SENSITIVE : 0u)
	           | (g->display & FZN_SETTINGS_REGISTRY_DISPLAY_ADVANCED ? FZN_SCHEMA_ADVANCED : 0u)
	           | (g->display & FZN_SETTINGS_REGISTRY_DISPLAY_VERB ? FZN_SCHEMA_VERB : 0u)
	           | (g->display & FZN_SETTINGS_REGISTRY_DISPLAY_ADVERTISED ? FZN_SCHEMA_ADVERTISED : 0u)
	           | (g->safe == FZN_SETTINGS_REGISTRY_SAFE_LOWER ? FZN_SCHEMA_SAFE_LOWER : 0u)
	           | (g->safe == FZN_SETTINGS_REGISTRY_SAFE_HIGHER ? FZN_SCHEMA_SAFE_HIGHER : 0u);
	e->summary = g->summary;
	e->every_ms = g->window_ms;
	e->check = check_of(g->cell);
	for (k = 0; k < sizeof(hand_checks) / sizeof(hand_checks[0]); k++)
		if (strcmp(hand_checks[k].key, g->key) == 0)
			e->check = hand_checks[k].check;
}

/* EVERY CELL A READER HERE READS, sec 1412: node/settings_registry.situ's
 * rows, made once into the entries an extension's table is written in, in
 * the registry's order, which `list schema` gives. Built on first use; a
 * host reads its settings from one thread. */
const fzn_schema_entry_t *fzn_node_schema_own(void)
{
	static fzn_schema_entry_t own[FZN_SETTINGS_REGISTRY_NODE_COUNT];
	static int built;
	size_t i;

	if (!built) {
		for (i = 0; i < FZN_SETTINGS_REGISTRY_NODE_COUNT; i++)
			row_of_registry(&fzn_settings_registry_node_entries[i], &own[i]);
		built = 1;
	}
	return own;
}

const size_t fzn_node_schema_own_n = FZN_SETTINGS_REGISTRY_NODE_COUNT;

const fzn_schema_entry_t *fzn_node_schema_find(const fzn_node_schema_t *schema, const uint8_t *key,
                                               size_t len)
{
	const fzn_schema_entry_t *e = fzn_schema_find(fzn_node_schema_own(), fzn_node_schema_own_n,
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
			if (fzn_schema_overlap(key, fzn_node_schema_own()[j].key))
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
	const fzn_schema_entry_t *tables[2] = { fzn_node_schema_own(), schema ? schema->extra : NULL };
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
