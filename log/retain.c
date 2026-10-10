/* See retain.h. */

#include "retain.h"

#include <stdio.h>
#include <string.h>

/* Segments one plan ranks; past it a plan refuses rather than guesses. */
#define PLAN_MAX 4096u

const char *fzn_retain_err_str(fzn_retain_err_t err)
{
	switch (err) {
	case FZN_RETAIN_OK:
		return "ok";
	case FZN_RETAIN_ERR_MALFORMED:
		return "malformed";
	}
	return "unknown";
}

/* ---- a rule's line ------------------------------------------------------- */

static int next_word(const char **at, const char *end, const char **w, size_t *n)
{
	while (*at < end && **at == ' ')
		(*at)++;
	if (*at >= end)
		return 0;
	*w = *at;
	while (*at < end && **at != ' ')
		(*at)++;
	*n = (size_t)(*at - *w);
	return 1;
}

static int is(const char *w, size_t n, const char *word)
{
	return n == strlen(word) && memcmp(w, word, n) == 0;
}

static int program_ok(const char *w, size_t n)
{
	size_t i;

	if (n == 0u || n > FZN_ENTRY_WORD_MAX)
		return 0;
	if (n == 1u && w[0] == '*')
		return 1;
	for (i = 0; i < n; i++) {
		char c = w[i];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		      || c == '_' || c == '-' || c == '.' || c == '+' || c == '$'))
			return 0;
	}
	return 1;
}

/* A subsystem path: `[a-z0-9_]` words joined by `/`, as `log/entry.h`'s. */
static int subsystem_ok(const char *w, size_t n)
{
	size_t i;

	if (n == 0u || n > FZN_ENTRY_SUBSYSTEM_MAX || w[0] == '/' || w[n - 1u] == '/')
		return 0;
	for (i = 0; i < n; i++) {
		char c = w[i];

		if (c == '/' && w[i + 1u] == '/')
			return 0;
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		      || c == '_' || c == '-' || c == '.' || c == '/'))
			return 0;
	}
	return 1;
}

/* `CEWNIVDT` letters as level bits, each once. */
static int levels_of(const char *w, size_t n, uint16_t *out)
{
	static const char LETTERS[] = "CEWNIVDT";
	size_t i;

	*out = 0;
	if (n == 0u)
		return 0;
	for (i = 0; i < n; i++) {
		const char *at = memchr(LETTERS, w[i], 8u);
		uint16_t bit;

		if (!at || w[i] == '\0')
			return 0;
		bit = (uint16_t)(1u << (unsigned)(at - LETTERS + 1));
		if (*out & bit)
			return 0;
		*out |= bit;
	}
	return 1;
}

/* `%XX`-escaped text into `out`: 1 to FZN_RETAIN_MATCH_MAX bytes, no NUL,
 * and every byte that must be escaped escaped -- so one match has one
 * spelling apart from the case of its hex digits. */
static int match_of(const char *w, size_t n, uint8_t *out, size_t *len)
{
	size_t i, k = 0;

	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)w[i];

		if (k == FZN_RETAIN_MATCH_MAX)
			return 0;
		if (c == '%') {
			unsigned v = 0, j;

			if (i + 2u >= n)
				return 0;
			for (j = 1; j <= 2u; j++) {
				char h = w[i + j];

				v <<= 4;
				if (h >= '0' && h <= '9')
					v |= (unsigned)(h - '0');
				else if (h >= 'A' && h <= 'F')
					v |= (unsigned)(h - 'A' + 10);
				else if (h >= 'a' && h <= 'f')
					v |= (unsigned)(h - 'a' + 10);
				else
					return 0;
			}
			if (v == 0u)
				return 0;
			out[k++] = (uint8_t)v;
			i += 2u;
		} else if (c < 0x21u || c == ',' || c == 0x7fu) {
			return 0;
		} else {
			out[k++] = c;
		}
	}
	*len = k;
	return k > 0u;
}

/* `n` bytes from 2n lowercase hex digits -- one spelling, so one scope has
 * one text. */
static int hex_of(const char *w, size_t len, uint8_t *out, size_t n)
{
	size_t i;

	if (len != n * 2u)
		return 0;
	for (i = 0; i < len; i++) {
		char c = w[i];
		unsigned v;

		if (c >= '0' && c <= '9')
			v = (unsigned)(c - '0');
		else if (c >= 'a' && c <= 'f')
			v = (unsigned)(c - 'a' + 10);
		else
			return 0;
		if (i % 2u == 0u)
			out[i / 2u] = (uint8_t)(v << 4);
		else
			out[i / 2u] = (uint8_t)(out[i / 2u] | v);
	}
	return 1;
}

/* Digits, then at most one unit letter, the product within a u64. */
static int number(const char *w, size_t n, fzn_retain_limit_t limit, uint64_t *out)
{
	uint64_t v = 0, mult = 1;
	size_t i, digits = n;

	if (n == 0u)
		return 0;
	if (w[n - 1u] < '0' || w[n - 1u] > '9') {
		char u = w[n - 1u];

		digits = n - 1u;
		if (limit == FZN_RETAIN_AGE)
			mult = u == 's' ? 1000000u
			     : u == 'm' ? 60u * 1000000u
			     : u == 'h' ? 3600u * (uint64_t)1000000u
			     : u == 'd' ? 86400u * (uint64_t)1000000u
			                : 0u;
		else if (limit == FZN_RETAIN_SIZE)
			mult = u == 'K' ? 1024u
			     : u == 'M' ? 1024u * 1024u
			     : u == 'G' ? 1024u * 1024u * (uint64_t)1024u
			                : 0u;
		else
			mult = 0;
		if (mult == 0u)
			return 0;
	} else if (limit == FZN_RETAIN_AGE) {
		mult = 1000000u;
	}
	if (digits == 0u || digits > 20u)
		return 0;
	for (i = 0; i < digits; i++) {
		unsigned d;

		if (w[i] < '0' || w[i] > '9')
			return 0;
		d = (unsigned)(w[i] - '0');
		if (v > (UINT64_MAX - d) / 10u)
			return 0;
		v = (v * 10u) + d;
	}
	if (v > UINT64_MAX / mult)
		return 0;
	*out = v * mult;
	return 1;
}

fzn_retain_err_t fzn_retain_parse(const char *line, size_t len, fzn_retain_rule_t *out)
{
	const char *at = line, *end, *w[12], *limit_w, *value_w;
	size_t n[12], count = 0, i, first = 2, program = 1, limit_n, value_n;

	if (!line || !out)
		return FZN_RETAIN_ERR_MALFORMED;
	memset(out, 0, sizeof(*out));
	if (len && line[len - 1u] == '\n')
		len--;
	end = line + len;
	while (count < 12u && next_word(&at, end, &w[count], &n[count]))
		count++;
	/* POLICY log|messages|history keep|drop [host=] [machine=], secs 566,
	 * 581. */
	if (count >= 3u && is(w[0], n[0], "policy")) {
		out->kind = FZN_RETAIN_POLICY;
		if (is(w[1], n[1], "messages"))
			out->data = FZN_RETAIN_MESSAGES;
		else if (is(w[1], n[1], "history"))
			out->data = FZN_RETAIN_HISTORY;
		else if (!is(w[1], n[1], "log"))
			return FZN_RETAIN_ERR_MALFORMED;
		if (is(w[2], n[2], "drop"))
			out->drop = 1;
		else if (!is(w[2], n[2], "keep"))
			return FZN_RETAIN_ERR_MALFORMED;
		if (count > 5u)
			return FZN_RETAIN_ERR_MALFORMED;
		for (i = 3; i < count; i++) {
			if (n[i] > 5u && memcmp(w[i], "host=", 5u) == 0 && !out->has_host) {
				if (!hex_of(w[i] + 5, n[i] - 5u, out->host, sizeof(out->host)))
					return FZN_RETAIN_ERR_MALFORMED;
				out->has_host = 1;
			} else if (n[i] > 8u && memcmp(w[i], "machine=", 8u) == 0 && !out->has_machine) {
				if (!hex_of(w[i] + 8, n[i] - 8u, out->machine, sizeof(out->machine)))
					return FZN_RETAIN_ERR_MALFORMED;
				out->has_machine = 1;
			} else {
				return FZN_RETAIN_ERR_MALFORMED;
			}
		}
		return FZN_RETAIN_OK;
	}
	/* KIND [log|messages] PROGRAM [copy] [source=] [host=] [machine=]
	 * [level=] [subsystem=] [text=] LIMIT N, or KIND messages [contact=]
	 * [host=] [machine=] LIMIT N: the data word is sec 531's, and a rule
	 * without one is a log rule as every rule before it was. */
	if (count >= 2u && is(w[1], n[1], "messages")) {
		out->data = FZN_RETAIN_MESSAGES;
		program = 0;
	} else if (count >= 2u && is(w[1], n[1], "history")) {
		/* A NOTE HISTORY RULE, sec 581: a scope at most. */
		out->data = FZN_RETAIN_HISTORY;
		program = 0;
	} else if (count >= 3u && is(w[1], n[1], "log")) {
		program = 2;
		first = 3;
	}
	if (count < first + 2u || count > first + 8u)
		return FZN_RETAIN_ERR_MALFORMED;
	for (i = first; i < count - 2u; i++) {
		if (n[i] > 8u && memcmp(w[i], "contact=", 8u) == 0 && !out->has_contact
		    && out->data == FZN_RETAIN_MESSAGES) {
			if (!hex_of(w[i] + 8, n[i] - 8u, out->contact, sizeof(out->contact)))
				return FZN_RETAIN_ERR_MALFORMED;
			out->has_contact = 1;
		} else if (n[i] > 6u && memcmp(w[i], "level=", 6u) == 0 && !out->levels) {
			if (!levels_of(w[i] + 6, n[i] - 6u, &out->levels))
				return FZN_RETAIN_ERR_MALFORMED;
		} else if (n[i] == 4u && memcmp(w[i], "copy", 4u) == 0 && !out->copy) {
			out->copy = 1;
		} else if (n[i] == 8u && memcmp(w[i], "archived", 8u) == 0 && !out->archived) {
			out->archived = 1;
		} else if (n[i] > 7u && memcmp(w[i], "source=", 7u) == 0 && !out->has_source) {
			if (!hex_of(w[i] + 7, n[i] - 7u, out->source, sizeof(out->source)))
				return FZN_RETAIN_ERR_MALFORMED;
			out->has_source = 1;
		} else if (n[i] > 5u && memcmp(w[i], "host=", 5u) == 0 && !out->has_host) {
			if (!hex_of(w[i] + 5, n[i] - 5u, out->host, sizeof(out->host)))
				return FZN_RETAIN_ERR_MALFORMED;
			out->has_host = 1;
		} else if (n[i] > 8u && memcmp(w[i], "machine=", 8u) == 0 && !out->has_machine) {
			if (!hex_of(w[i] + 8, n[i] - 8u, out->machine, sizeof(out->machine)))
				return FZN_RETAIN_ERR_MALFORMED;
			out->has_machine = 1;
		} else if (n[i] > 5u && memcmp(w[i], "text=", 5u) == 0 && !out->match_len) {
			if (!match_of(w[i] + 5, n[i] - 5u, out->match, &out->match_len))
				return FZN_RETAIN_ERR_MALFORMED;
		} else if (n[i] > 10u && memcmp(w[i], "subsystem=", 10u) == 0 && !out->subsystem[0]) {
			if (!subsystem_ok(w[i] + 10, n[i] - 10u))
				return FZN_RETAIN_ERR_MALFORMED;
			memcpy(out->subsystem, w[i] + 10, n[i] - 10u);
			out->subsystem[n[i] - 10u] = '\0';
		} else {
			return FZN_RETAIN_ERR_MALFORMED;
		}
	}
	/* A COPY IS KEPT OR REMOVED WHOLE, sec 483. */
	if (out->copy && (out->levels || out->subsystem[0] || out->match_len))
		return FZN_RETAIN_ERR_MALFORMED;
	/* WHOSE COPIES, only of copies, sec 487. */
	if (out->has_source && !out->copy)
		return FZN_RETAIN_ERR_MALFORMED;
	/* A MESSAGE RULE NAMES NO LOG SELECTOR, sec 531: its lines are sealed
	 * and go by the month, so nothing but a contact and a scope chooses
	 * among them. */
	if (out->data == FZN_RETAIN_MESSAGES
	    && (out->copy || out->has_source || out->levels || out->subsystem[0] || out->match_len))
		return FZN_RETAIN_ERR_MALFORMED;
	/* A HISTORY RULE NAMES NONE: a note's versions are weighed as one list
	 * each. A contact is refused above, `contact=` being a message rule's. */
	if (out->data == FZN_RETAIN_HISTORY
	    && (out->copy || out->has_source || out->levels || out->subsystem[0] || out->match_len))
		return FZN_RETAIN_ERR_MALFORMED;
	/* The limit and its number are the last two words: read into words of
	 * their own, since the program may be the third. */
	limit_w = w[count - 2u];
	limit_n = n[count - 2u];
	value_w = w[count - 1u];
	value_n = n[count - 1u];
	if (is(w[0], n[0], "prune"))
		out->kind = FZN_RETAIN_PRUNE;
	else if (is(w[0], n[0], "keep"))
		out->kind = FZN_RETAIN_KEEP;
	else if (is(w[0], n[0], "archive"))
		out->kind = FZN_RETAIN_ARCHIVE;
	else
		return FZN_RETAIN_ERR_MALFORMED;
	/* A RULE OVER THE ARCHIVE, sec 589: prune or keep, of this node's own
	 * log's whole segments. */
	if (out->archived
	    && ((out->kind != FZN_RETAIN_PRUNE && out->kind != FZN_RETAIN_KEEP)
	        || out->data != FZN_RETAIN_LOG || out->copy || out->has_source || out->levels
	        || out->subsystem[0] || out->match_len))
		return FZN_RETAIN_ERR_MALFORMED;
	/* AN ARCHIVE RULE MOVES WHOLE SEGMENTS, sec 588 -- this node's own, or
	 * since sec 590 copies, a source's or all -- so no entry selector and
	 * no other kind's data. */
	if (out->kind == FZN_RETAIN_ARCHIVE
	    && (out->data != FZN_RETAIN_LOG || out->levels || out->subsystem[0] || out->match_len))
		return FZN_RETAIN_ERR_MALFORMED;
	if (program) {
		if (!program_ok(w[program], n[program]))
			return FZN_RETAIN_ERR_MALFORMED;
		memcpy(out->program, w[program], n[program]);
		out->program[n[program]] = '\0';
	}
	if (is(limit_w, limit_n, "age"))
		out->limit = FZN_RETAIN_AGE;
	else if (is(limit_w, limit_n, "size"))
		out->limit = FZN_RETAIN_SIZE;
	else if (is(limit_w, limit_n, "count"))
		out->limit = FZN_RETAIN_COUNT;
	else
		return FZN_RETAIN_ERR_MALFORMED;
	if (!number(value_w, value_n, out->limit, &out->value))
		return FZN_RETAIN_ERR_MALFORMED;
	return FZN_RETAIN_OK;
}

static int rule_ok(const fzn_retain_rule_t *r);

fzn_retain_err_t fzn_retain_text(const fzn_retain_rule_t *rule, char *out, size_t cap,
                                 size_t *len)
{
	static const char LETTERS[] = "CEWNIVDT";
	char levels[9], unit[2] = { 0, 0 }, match[(FZN_RETAIN_MATCH_MAX * 3u) + 7u];
	char scope[9u + 64u + 8u + 64u + 6u + 64u + 9u + 32u + 1u];
	char what[16u + FZN_ENTRY_WORD_MAX];
	uint64_t v;
	size_t i, k = 0;
	int n;

	if (!rule || !out || !len || !rule_ok(rule))
		return FZN_RETAIN_ERR_MALFORMED;
	for (i = 0; i < 8u; i++)
		if (rule->levels & (1u << (i + 1u)))
			levels[k++] = LETTERS[i];
	levels[k] = '\0';
	/* THE MATCH, escaped as the parser reads it, hex in capitals. */
	match[0] = '\0';
	if (rule->match_len) {
		size_t m = 0;

		memcpy(match, " text=", 6u);
		m = 6u;
		for (i = 0; i < rule->match_len; i++) {
			unsigned char c = rule->match[i];

			if (c < 0x21u || c == '%' || c == ',' || c == 0x7fu) {
				(void)snprintf(match + m, 4u, "%%%02X", c);
				m += 3u;
			} else {
				match[m++] = (char)c;
			}
		}
		match[m] = '\0';
	}
	/* THE SCOPE, source then host then machine, hex in lower case as the
	 * parser reads it. secs 480, 487. */
	{
		size_t m = 0;

		scope[0] = '\0';
		if (rule->has_contact) {
			memcpy(scope, " contact=", 9u);
			m = 9u;
			for (i = 0; i < sizeof(rule->contact); i++, m += 2u)
				(void)snprintf(scope + m, 3u, "%02x", rule->contact[i]);
		}
		if (rule->has_source) {
			memcpy(scope + m, " source=", 8u);
			m += 8u;
			for (i = 0; i < sizeof(rule->source); i++, m += 2u)
				(void)snprintf(scope + m, 3u, "%02x", rule->source[i]);
		}
		if (rule->has_host) {
			memcpy(scope + m, " host=", 6u);
			m += 6u;
			for (i = 0; i < sizeof(rule->host); i++, m += 2u)
				(void)snprintf(scope + m, 3u, "%02x", rule->host[i]);
		}
		if (rule->has_machine) {
			memcpy(scope + m, " machine=", 9u);
			m += 9u;
			for (i = 0; i < sizeof(rule->machine); i++, m += 2u)
				(void)snprintf(scope + m, 3u, "%02x", rule->machine[i]);
		}
		scope[m] = '\0';
	}
	v = rule->value;
	if (rule->limit == FZN_RETAIN_AGE) {
		static const struct { uint64_t us; char u; } AGE[] = {
			{ 86400u * (uint64_t)1000000u, 'd' }, { 3600u * (uint64_t)1000000u, 'h' },
			{ 60u * (uint64_t)1000000u, 'm' },    { 1000000u, 's' },
		};

		/* A whole number of seconds at least: the parser takes no finer. */
		if (v % 1000000u)
			return FZN_RETAIN_ERR_MALFORMED;
		for (i = 0; i < 4u; i++)
			if (v % AGE[i].us == 0u) {
				v /= AGE[i].us;
				unit[0] = AGE[i].u;
				break;
			}
	} else if (rule->limit == FZN_RETAIN_SIZE && v) {
		static const struct { uint64_t b; char u; } SIZE[] = {
			{ 1024u * 1024u * (uint64_t)1024u, 'G' }, { 1024u * 1024u, 'M' }, { 1024u, 'K' },
		};

		for (i = 0; i < 3u; i++)
			if (v % SIZE[i].b == 0u) {
				v /= SIZE[i].b;
				unit[0] = SIZE[i].u;
				break;
			}
	}
	/* THE DATA WORD, sec 531: written for a message rule, and for a log
	 * rule only where its program would read as one, so every log rule
	 * before keeps its text and its stored row. */
	if (rule->kind == FZN_RETAIN_POLICY) {
		n = snprintf(out, cap, "policy %s %s%s",
		             rule->data == FZN_RETAIN_MESSAGES  ? "messages"
		             : rule->data == FZN_RETAIN_HISTORY ? "history"
		                                                : "log",
		             rule->drop ? "drop" : "keep", scope);
		if (n <= 0 || (size_t)n >= cap)
			return FZN_RETAIN_ERR_MALFORMED;
		*len = (size_t)n;
		return FZN_RETAIN_OK;
	}
	if (rule->data == FZN_RETAIN_MESSAGES)
		(void)snprintf(what, sizeof(what), "messages");
	else if (rule->data == FZN_RETAIN_HISTORY)
		(void)snprintf(what, sizeof(what), "history");
	else if (strcmp(rule->program, "log") == 0 || strcmp(rule->program, "messages") == 0
	         || strcmp(rule->program, "history") == 0)
		(void)snprintf(what, sizeof(what), "log %s", rule->program);
	else
		(void)snprintf(what, sizeof(what), "%s", rule->program);
	n = snprintf(out, cap, "%s %s%s%s%s%s%s%s%s %s %llu%s",
	             rule->kind == FZN_RETAIN_PRUNE    ? "prune"
	             : rule->kind == FZN_RETAIN_ARCHIVE ? "archive"
	                                                : "keep",
	             what,
	             rule->copy ? " copy" : rule->archived ? " archived" : "", scope,
	             k ? " level=" : "", levels, rule->subsystem[0] ? " subsystem=" : "",
	             rule->subsystem, match,
	             rule->limit == FZN_RETAIN_AGE    ? "age"
	             : rule->limit == FZN_RETAIN_SIZE ? "size"
	                                              : "count",
	             (unsigned long long)v, unit);
	if (n <= 0 || (size_t)n >= cap)
		return FZN_RETAIN_ERR_MALFORMED;
	*len = (size_t)n;
	return FZN_RETAIN_OK;
}

/* ---- the plan ------------------------------------------------------------ */

/* Newest first: by closing time, ties by index so the order is total. */
static void rank(const fzn_retain_segment_t *s, size_t n, size_t *order)
{
	size_t i, j;

	for (i = 0; i < n; i++)
		order[i] = i;
	/* INSERTION SORT, bounded by PLAN_MAX: a qsort comparator cannot see
	 * the segments without a global. */
	for (i = 1; i < n; i++) {
		size_t k = order[i];

		for (j = i; j > 0u; j--) {
			size_t p = order[j - 1u];

			if (s[p].closed_us > s[k].closed_us
			    || (s[p].closed_us == s[k].closed_us && p < k))
				break;
			order[j] = p;
		}
		order[j] = k;
	}
}

/* Whether segment `seg`, at `place` newest-first with `before` bytes newer
 * than it, falls within the rule's limit. */
static int within(const fzn_retain_rule_t *r, const fzn_retain_segment_t *seg, size_t place,
                  uint64_t before, uint64_t now_us)
{
	switch (r->limit) {
	case FZN_RETAIN_AGE:
		return seg->closed_us >= now_us || now_us - seg->closed_us <= r->value;
	case FZN_RETAIN_SIZE:
		return before < r->value;
	case FZN_RETAIN_COUNT:
		return (uint64_t)place < r->value;
	}
	return 1;
}

static int matches(const fzn_retain_rule_t *r, const char *program)
{
	return r->data == FZN_RETAIN_LOG
	       && (strcmp(r->program, "*") == 0 || strcmp(r->program, program) == 0);
}

static int rule_ok(const fzn_retain_rule_t *r)
{
	/* A POLICY: a kind, keep or drop, and a scope or none. */
	if (r->kind == FZN_RETAIN_POLICY)
		return (r->data == FZN_RETAIN_LOG || r->data == FZN_RETAIN_MESSAGES
		        || r->data == FZN_RETAIN_HISTORY)
		       && (r->drop == 0 || r->drop == 1) && r->program[0] == '\0' && !r->levels
		       && !r->subsystem[0] && !r->match_len && !r->copy && !r->archived && !r->has_source
		       && !r->has_contact && r->limit == 0 && r->value == 0u
		       && (r->has_host == 0 || r->has_host == 1)
		       && (r->has_machine == 0 || r->has_machine == 1);
	if (r->drop)
		return 0;
	/* A MESSAGE RULE: no program, no log selector, a contact or none; a
	 * HISTORY RULE the same with no contact. */
	if (r->data == FZN_RETAIN_MESSAGES
	    || (r->data == FZN_RETAIN_HISTORY && !r->has_contact))
		return (r->kind == FZN_RETAIN_PRUNE || r->kind == FZN_RETAIN_KEEP)
		       && (r->limit == FZN_RETAIN_AGE || r->limit == FZN_RETAIN_SIZE
		           || r->limit == FZN_RETAIN_COUNT)
		       && r->program[0] == '\0' && !r->levels && !r->subsystem[0] && !r->match_len
		       && !r->copy && !r->archived && !r->has_source
		       && (r->has_contact == 0 || r->has_contact == 1)
		       && (r->has_host == 0 || r->has_host == 1)
		       && (r->has_machine == 0 || r->has_machine == 1);
	/* AN ARCHIVE RULE: a log segment rule, of this node's own log or of
	 * copies. */
	if (r->kind == FZN_RETAIN_ARCHIVE
	    && (r->data != FZN_RETAIN_LOG || r->levels || r->subsystem[0] || r->match_len))
		return 0;
	return r->data == FZN_RETAIN_LOG && !r->has_contact
	       && (r->kind == FZN_RETAIN_PRUNE || r->kind == FZN_RETAIN_KEEP
	           || r->kind == FZN_RETAIN_ARCHIVE)
	       && (r->limit == FZN_RETAIN_AGE || r->limit == FZN_RETAIN_SIZE
	           || r->limit == FZN_RETAIN_COUNT)
	       && memchr(r->program, '\0', sizeof(r->program)) != NULL
	       && program_ok(r->program, strlen(r->program))
	       && (r->levels & ~(uint16_t)0x1feu) == 0u
	       && memchr(r->subsystem, '\0', sizeof(r->subsystem)) != NULL
	       && (!r->subsystem[0] || subsystem_ok(r->subsystem, strlen(r->subsystem)))
	       && r->match_len <= FZN_RETAIN_MATCH_MAX
	       && memchr(r->match, '\0', r->match_len) == NULL
	       && (r->has_host == 0 || r->has_host == 1)
	       && (r->has_source == 0 || (r->has_source == 1 && r->copy == 1))
	       && (r->copy == 0 || (r->copy == 1 && !r->levels && !r->subsystem[0] && !r->match_len))
	       && (r->archived == 0
	           || (r->archived == 1 && !r->copy && !r->levels && !r->subsystem[0]
	               && !r->match_len
	               && (r->kind == FZN_RETAIN_PRUNE || r->kind == FZN_RETAIN_KEEP)))
	       && (r->has_machine == 0 || r->has_machine == 1);
}

int fzn_retain_reaches(const fzn_retain_rule_t *rule, const uint8_t host[32],
                       const uint8_t machine[FZN_ENTRY_MACHINE_LEN])
{
	if (!rule)
		return 0;
	/* A SCOPE NAMED AND NOT KNOWN HERE reaches nothing: a rule meant for
	 * one node must not be taken as everyone's for want of a key. */
	if (rule->has_host && (!host || memcmp(rule->host, host, sizeof(rule->host)) != 0))
		return 0;
	if (rule->has_machine
	    && (!machine || memcmp(rule->machine, machine, sizeof(rule->machine)) != 0))
		return 0;
	return 1;
}

size_t fzn_retain_select_here(const fzn_retain_rule_t *in, size_t n, const uint8_t host[32],
                              const uint8_t machine[FZN_ENTRY_MACHINE_LEN],
                              fzn_retain_rule_t *out)
{
	size_t i, k = 0;

	if (!in || !out)
		return 0;
	for (i = 0; i < n; i++)
		if (in[i].data == FZN_RETAIN_LOG && !in[i].copy && !in[i].archived
		    && fzn_retain_reaches(&in[i], host, machine))
			out[k++] = in[i];
	return k;
}

size_t fzn_retain_select_messages(const fzn_retain_rule_t *in, size_t n, const uint8_t host[32],
                                  const uint8_t machine[FZN_ENTRY_MACHINE_LEN],
                                  fzn_retain_rule_t *out)
{
	size_t i, k = 0;

	if (!in || !out)
		return 0;
	for (i = 0; i < n; i++)
		if (in[i].data == FZN_RETAIN_MESSAGES && fzn_retain_reaches(&in[i], host, machine))
			out[k++] = in[i];
	return k;
}

size_t fzn_retain_select_history(const fzn_retain_rule_t *in, size_t n, const uint8_t host[32],
                                 const uint8_t machine[FZN_ENTRY_MACHINE_LEN],
                                 fzn_retain_rule_t *out)
{
	size_t i, k = 0;

	if (!in || !out)
		return 0;
	for (i = 0; i < n; i++)
		if (in[i].data == FZN_RETAIN_HISTORY && fzn_retain_reaches(&in[i], host, machine))
			out[k++] = in[i];
	return k;
}

size_t fzn_retain_select_archived(const fzn_retain_rule_t *in, size_t n, const uint8_t host[32],
                                  const uint8_t machine[FZN_ENTRY_MACHINE_LEN],
                                  fzn_retain_rule_t *out)
{
	size_t i, k = 0;

	if (!in || !out)
		return 0;
	for (i = 0; i < n; i++)
		if (in[i].data == FZN_RETAIN_LOG && in[i].archived
		    && fzn_retain_reaches(&in[i], host, machine))
			out[k++] = in[i];
	return k;
}

size_t fzn_retain_select_copies(const fzn_retain_rule_t *in, size_t n, const uint8_t host[32],
                                const uint8_t machine[FZN_ENTRY_MACHINE_LEN],
                                fzn_retain_rule_t *out)
{
	size_t i, k = 0;

	if (!in || !out)
		return 0;
	for (i = 0; i < n; i++)
		if (in[i].data == FZN_RETAIN_LOG
		    && (in[i].copy || in[i].kind == FZN_RETAIN_POLICY)
		    && fzn_retain_reaches(&in[i], host, machine))
			out[k++] = in[i];
	return k;
}

size_t fzn_retain_select_source(const fzn_retain_rule_t *in, size_t n, const uint8_t source[32],
                                fzn_retain_rule_t *out)
{
	size_t i, k = 0;

	if (!in || !out || !source)
		return 0;
	for (i = 0; i < n; i++)
		if ((in[i].copy || in[i].kind == FZN_RETAIN_POLICY)
		    && (!in[i].has_source
		        || memcmp(in[i].source, source, sizeof(in[i].source)) == 0))
			out[k++] = in[i];
	return k;
}

int fzn_retain_policy_drops(const fzn_retain_rule_t *rules, size_t n, fzn_retain_data_t data)
{
	int drop = 0;
	size_t i;

	if (!rules)
		return 0;
	for (i = 0; i < n; i++) {
		if (rules[i].kind != FZN_RETAIN_POLICY || rules[i].data != data)
			continue;
		if (!rules[i].drop)
			return 0;
		drop = 1;
	}
	return drop;
}

int fzn_retain_rule_selects_entries(const fzn_retain_rule_t *rule)
{
	return rule && (rule->levels || rule->subsystem[0] || rule->match_len);
}

int fzn_retain_reads_entries(const char *program, const fzn_retain_rule_t *rules,
                             size_t n_rules)
{
	size_t r;

	if (!program || !rules)
		return 0;
	for (r = 0; r < n_rules; r++)
		if (matches(&rules[r], program) && fzn_retain_rule_selects_entries(&rules[r]))
			return 1;
	return 0;
}

fzn_retain_err_t fzn_retain_plan(const char *program, const fzn_retain_segment_t *segments,
                                 size_t n, const fzn_retain_rule_t *rules, size_t n_rules,
                                 uint64_t now_us, uint8_t *remove)
{
	fzn_retain_err_t err;
	size_t i;

	if (!remove && n)
		return FZN_RETAIN_ERR_MALFORMED;
	/* THE MARKS, into the caller's array, then read down to one bit. */
	err = fzn_retain_marks(program, segments, n, rules, n_rules, now_us, remove);
	if (err != FZN_RETAIN_OK)
		return err;
	for (i = 0; i < n; i++)
		remove[i] = (uint8_t)(remove[i] == FZN_RETAIN_MARK_PRUNED);
	return FZN_RETAIN_OK;
}

fzn_retain_err_t fzn_retain_marks(const char *program, const fzn_retain_segment_t *segments,
                                  size_t n, const fzn_retain_rule_t *rules, size_t n_rules,
                                  uint64_t now_us, uint8_t *marks)
{
	static size_t order[PLAN_MAX];
	size_t i, r;
	uint8_t *remove = marks;

	if (!program || (!segments && n) || (!rules && n_rules) || (!marks && n) || n > PLAN_MAX
	    || n_rules > FZN_RETAIN_RULES_MAX || !program_ok(program, strlen(program))
	    || strcmp(program, "*") == 0)
		return FZN_RETAIN_ERR_MALFORMED;
	for (r = 0; r < n_rules; r++)
		if (!rule_ok(&rules[r]))
			return FZN_RETAIN_ERR_MALFORMED;
	rank(segments, n, order);
	for (i = 0; i < n; i++)
		remove[i] = 0;
	{
		/* UNDER A DROP POLICY every segment is marked as a prune rule would
		 * mark it, so only a keep rule -- of segments or of entries -- holds
		 * any of it. sec 566. */
		int drops = fzn_retain_policy_drops(rules, n_rules, FZN_RETAIN_LOG);
		uint64_t before = 0;

		for (i = 0; i < n; i++) {
			const fzn_retain_segment_t *seg = &segments[order[i]];
			int pruned = 0, kept = 0, archived = 0;

			for (r = 0; r < n_rules; r++) {
				const fzn_retain_rule_t *rule = &rules[r];

				if (!matches(rule, program) || fzn_retain_rule_selects_entries(rule))
					continue;
				if (within(rule, seg, i, before, now_us)) {
					if (rule->kind == FZN_RETAIN_KEEP)
						kept = 1;
				} else if (rule->kind == FZN_RETAIN_PRUNE) {
					pruned = 1;
				} else if (rule->kind == FZN_RETAIN_ARCHIVE) {
					archived = 1;
				}
			}
			/* ARCHIVE WINS OVER PRUNE, sec 588: a segment both would take
			 * is moved, not removed. */
			remove[order[i]] =
			        (uint8_t)((archived ? FZN_RETAIN_MARK_ARCHIVED
			                            : (pruned || drops ? FZN_RETAIN_MARK_PRUNED : 0u))
			                  | (kept ? FZN_RETAIN_MARK_KEPT : 0u));
			before = (UINT64_MAX - before < seg->bytes) ? UINT64_MAX : before + seg->bytes;
		}
	}
	return FZN_RETAIN_OK;
}

/* ---- the entry walk, sec 474 --------------------------------------------- */

/* `path` is `prefix` or below it. */
static int under(const char *path, const char *prefix)
{
	size_t n = strlen(prefix);

	return strncmp(path, prefix, n) == 0 && (path[n] == '\0' || path[n] == '/');
}

fzn_retain_err_t fzn_retain_walk_init(fzn_retain_walk_t *walk, const char *program,
                                      const fzn_retain_rule_t *rules, size_t n_rules,
                                      uint64_t now_us)
{
	size_t r;

	if (!walk || !program || (!rules && n_rules) || n_rules > FZN_RETAIN_RULES_MAX
	    || !program_ok(program, strlen(program)) || strcmp(program, "*") == 0)
		return FZN_RETAIN_ERR_MALFORMED;
	memset(walk, 0, sizeof(*walk));
	for (r = 0; r < n_rules; r++) {
		if (!rule_ok(&rules[r]))
			return FZN_RETAIN_ERR_MALFORMED;
		walk->applies[r] = matches(&rules[r], program)
		                   && fzn_retain_rule_selects_entries(&rules[r]);
	}
	walk->rules = rules;
	walk->n_rules = n_rules;
	walk->now_us = now_us;
	return FZN_RETAIN_OK;
}

/* `text` holds `match`. */
static int holds(const uint8_t *text, size_t text_len, const uint8_t *match, size_t match_len)
{
	size_t i;

	if (match_len > text_len)
		return 0;
	for (i = 0; i + match_len <= text_len; i++)
		if (memcmp(text + i, match, match_len) == 0)
			return 1;
	return 0;
}

int fzn_retain_walk_entry(fzn_retain_walk_t *walk, uint8_t mark, uint64_t time_us,
                          fzn_entry_level_t level, const char *subsystem, const uint8_t *text,
                          size_t text_len, uint64_t bytes)
{
	int pruned = (mark & FZN_RETAIN_MARK_PRUNED) != 0;
	int kept = (mark & FZN_RETAIN_MARK_KEPT) != 0;
	size_t r;

	if (!walk || !subsystem || (!text && text_len))
		return 0;
	for (r = 0; r < walk->n_rules; r++) {
		const fzn_retain_rule_t *rule = &walk->rules[r];
		int in;

		if (!walk->applies[r])
			continue;
		if (rule->levels && ((unsigned)level > 8u || !(rule->levels & (1u << (unsigned)level))))
			continue;
		if (rule->subsystem[0] && !under(subsystem, rule->subsystem))
			continue;
		if (rule->match_len && !holds(text, text_len, rule->match, rule->match_len))
			continue;
		/* NEWEST FIRST: what the rule has selected before this entry is
		 * what is newer than it. */
		switch (rule->limit) {
		case FZN_RETAIN_AGE:
			in = time_us >= walk->now_us || walk->now_us - time_us <= rule->value;
			break;
		case FZN_RETAIN_SIZE:
			in = walk->bytes[r] < rule->value;
			break;
		default:
			in = walk->seen[r] < rule->value;
			break;
		}
		walk->seen[r]++;
		walk->bytes[r] = (UINT64_MAX - walk->bytes[r] < bytes) ? UINT64_MAX
		                                                       : walk->bytes[r] + bytes;
		if (in) {
			if (rule->kind == FZN_RETAIN_KEEP)
				kept = 1;
		} else if (rule->kind == FZN_RETAIN_PRUNE) {
			pruned = 1;
		}
	}
	return pruned && !kept;
}
