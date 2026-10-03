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
	const char *at = line, *end, *w[7];
	size_t n[7], count = 0, i;

	if (!line || !out)
		return FZN_RETAIN_ERR_MALFORMED;
	memset(out, 0, sizeof(*out));
	if (len && line[len - 1u] == '\n')
		len--;
	end = line + len;
	while (count < 7u && next_word(&at, end, &w[count], &n[count]))
		count++;
	/* KIND PROGRAM [level=] [subsystem=] LIMIT N: four words to six. */
	if (count < 4u || count > 6u)
		return FZN_RETAIN_ERR_MALFORMED;
	for (i = 2; i < count - 2u; i++) {
		if (n[i] > 6u && memcmp(w[i], "level=", 6u) == 0 && !out->levels) {
			if (!levels_of(w[i] + 6, n[i] - 6u, &out->levels))
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
	/* The limit and its number are the last two words. */
	w[2] = w[count - 2u];
	n[2] = n[count - 2u];
	w[3] = w[count - 1u];
	n[3] = n[count - 1u];
	if (is(w[0], n[0], "prune"))
		out->kind = FZN_RETAIN_PRUNE;
	else if (is(w[0], n[0], "keep"))
		out->kind = FZN_RETAIN_KEEP;
	else
		return FZN_RETAIN_ERR_MALFORMED;
	if (!program_ok(w[1], n[1]))
		return FZN_RETAIN_ERR_MALFORMED;
	memcpy(out->program, w[1], n[1]);
	out->program[n[1]] = '\0';
	if (is(w[2], n[2], "age"))
		out->limit = FZN_RETAIN_AGE;
	else if (is(w[2], n[2], "size"))
		out->limit = FZN_RETAIN_SIZE;
	else if (is(w[2], n[2], "count"))
		out->limit = FZN_RETAIN_COUNT;
	else
		return FZN_RETAIN_ERR_MALFORMED;
	if (!number(w[3], n[3], out->limit, &out->value))
		return FZN_RETAIN_ERR_MALFORMED;
	return FZN_RETAIN_OK;
}

static int rule_ok(const fzn_retain_rule_t *r);

fzn_retain_err_t fzn_retain_text(const fzn_retain_rule_t *rule, char *out, size_t cap,
                                 size_t *len)
{
	static const char LETTERS[] = "CEWNIVDT";
	char levels[9], unit[2] = { 0, 0 };
	uint64_t v;
	size_t i, k = 0;
	int n;

	if (!rule || !out || !len || !rule_ok(rule))
		return FZN_RETAIN_ERR_MALFORMED;
	for (i = 0; i < 8u; i++)
		if (rule->levels & (1u << (i + 1u)))
			levels[k++] = LETTERS[i];
	levels[k] = '\0';
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
	n = snprintf(out, cap, "%s %s%s%s%s%s %s %llu%s",
	             rule->kind == FZN_RETAIN_PRUNE ? "prune" : "keep", rule->program,
	             k ? " level=" : "", levels, rule->subsystem[0] ? " subsystem=" : "",
	             rule->subsystem,
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
	return strcmp(r->program, "*") == 0 || strcmp(r->program, program) == 0;
}

static int rule_ok(const fzn_retain_rule_t *r)
{
	return (r->kind == FZN_RETAIN_PRUNE || r->kind == FZN_RETAIN_KEEP)
	       && (r->limit == FZN_RETAIN_AGE || r->limit == FZN_RETAIN_SIZE
	           || r->limit == FZN_RETAIN_COUNT)
	       && memchr(r->program, '\0', sizeof(r->program)) != NULL
	       && program_ok(r->program, strlen(r->program))
	       && (r->levels & ~(uint16_t)0x1feu) == 0u
	       && memchr(r->subsystem, '\0', sizeof(r->subsystem)) != NULL
	       && (!r->subsystem[0] || subsystem_ok(r->subsystem, strlen(r->subsystem)));
}

int fzn_retain_rule_selects_entries(const fzn_retain_rule_t *rule)
{
	return rule && (rule->levels || rule->subsystem[0]);
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
		uint64_t before = 0;

		for (i = 0; i < n; i++) {
			const fzn_retain_segment_t *seg = &segments[order[i]];
			int pruned = 0, kept = 0;

			for (r = 0; r < n_rules; r++) {
				const fzn_retain_rule_t *rule = &rules[r];

				if (!matches(rule, program) || fzn_retain_rule_selects_entries(rule))
					continue;
				if (within(rule, seg, i, before, now_us)) {
					if (rule->kind == FZN_RETAIN_KEEP)
						kept = 1;
				} else if (rule->kind == FZN_RETAIN_PRUNE) {
					pruned = 1;
				}
			}
			remove[order[i]] = (uint8_t)((pruned ? FZN_RETAIN_MARK_PRUNED : 0u)
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

int fzn_retain_walk_entry(fzn_retain_walk_t *walk, uint8_t mark, uint64_t time_us,
                          fzn_entry_level_t level, const char *subsystem, uint64_t bytes)
{
	int pruned = (mark & FZN_RETAIN_MARK_PRUNED) != 0;
	int kept = (mark & FZN_RETAIN_MARK_KEPT) != 0;
	size_t r;

	if (!walk || !subsystem)
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
