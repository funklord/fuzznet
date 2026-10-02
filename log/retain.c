/* See retain.h. */

#include "retain.h"

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
	const char *at = line, *end, *w[4], *extra;
	size_t n[4], i, extra_n;

	if (!line || !out)
		return FZN_RETAIN_ERR_MALFORMED;
	memset(out, 0, sizeof(*out));
	if (len && line[len - 1u] == '\n')
		len--;
	end = line + len;
	for (i = 0; i < 4u; i++)
		if (!next_word(&at, end, &w[i], &n[i]))
			return FZN_RETAIN_ERR_MALFORMED;
	if (next_word(&at, end, &extra, &extra_n))
		return FZN_RETAIN_ERR_MALFORMED;
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
	       && program_ok(r->program, strlen(r->program));
}

fzn_retain_err_t fzn_retain_plan(const char *program, const fzn_retain_segment_t *segments,
                                 size_t n, const fzn_retain_rule_t *rules, size_t n_rules,
                                 uint64_t now_us, uint8_t *remove)
{
	static size_t order[PLAN_MAX];
	size_t i, r;

	if (!program || (!segments && n) || (!rules && n_rules) || (!remove && n) || n > PLAN_MAX
	    || !program_ok(program, strlen(program)) || strcmp(program, "*") == 0)
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

				if (!matches(rule, program))
					continue;
				if (within(rule, seg, i, before, now_us)) {
					if (rule->kind == FZN_RETAIN_KEEP)
						kept = 1;
				} else if (rule->kind == FZN_RETAIN_PRUNE) {
					pruned = 1;
				}
			}
			remove[order[i]] = (uint8_t)(pruned && !kept);
			before = (UINT64_MAX - before < seg->bytes) ? UINT64_MAX : before + seg->bytes;
		}
	}
	return FZN_RETAIN_OK;
}
