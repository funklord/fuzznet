/* rules_test -- the retention rules a node keeps: one rule one entry under
 * its canonical text, either spelling removing it, order, the bound, and an
 * entry that will not read, over `persist/`'s seam in memory. sec 475. */

#include "../rules.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (ok)
		return;
	failures++;
	fprintf(stderr, "  FAIL rules_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, what)

#define MEM_ROWS 80u

struct row {
	int used;
	fzn_persist_slot_t slot;
	uint8_t subject[FZN_PUBKEY_LEN];
	uint8_t bytes[512];
	size_t len;
};

static struct row rows[MEM_ROWS];
static int no_list;

static struct row *find(fzn_persist_slot_t slot, const uint8_t *subject)
{
	size_t i;

	for (i = 0; i < MEM_ROWS; i++)
		if (rows[i].used && rows[i].slot == slot && subject
		    && memcmp(rows[i].subject, subject, FZN_PUBKEY_LEN) == 0)
			return &rows[i];
	return NULL;
}

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	struct row *r = find(slot, subject);

	(void)ctx;
	if (!r || r->len > cap)
		return 0;
	memcpy(out, r->bytes, r->len);
	*len = r->len;
	return 1;
}

static int mem_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                    const uint8_t *bytes, size_t len)
{
	struct row *r = find(slot, subject);
	size_t i;

	(void)ctx;
	for (i = 0; !r && i < MEM_ROWS; i++)
		if (!rows[i].used)
			r = &rows[i];
	if (!r || !subject || len > sizeof(r->bytes))
		return 0;
	r->used = 1;
	r->slot = slot;
	memcpy(r->subject, subject, FZN_PUBKEY_LEN);
	memcpy(r->bytes, bytes, len);
	r->len = len;
	return 1;
}

static int mem_list(void *ctx, fzn_persist_slot_t slot, uint8_t *out, size_t max, size_t *count)
{
	size_t i, n = 0;

	(void)ctx;
	if (no_list)
		return 0;
	for (i = 0; i < MEM_ROWS; i++)
		if (rows[i].used && rows[i].slot == slot) {
			if (n == max)
				return 0;
			memcpy(out + (n * FZN_PUBKEY_LEN), rows[i].subject, FZN_PUBKEY_LEN);
			n++;
		}
	*count = n;
	return 1;
}

static int mem_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	struct row *r = find(slot, subject);

	(void)ctx;
	if (r)
		r->used = 0;
	return 1;
}

static const fzn_persist_ops_t OPS = { mem_load, mem_save, mem_list, mem_remove, NULL };

static int toy_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	size_t i;

	(void)ctx;
	memset(out, 0x5c, out_len);
	for (i = 0; i < in_len; i++)
		out[i % out_len] = (uint8_t)((out[i % out_len] * 31u) ^ in[i]);
	return 1; /* nonzero is success, as the seam says */
}

static int refusing_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in,
                         size_t in_len)
{
	(void)ctx;
	(void)in;
	(void)in_len;
	memset(out, 0, out_len);
	return 0;
}

static const fzn_hash_ops_t HASH = { toy_hash, NULL };
static const fzn_hash_ops_t REFUSING = { refusing_hash, NULL };

static fzn_retain_rule_t rule(const char *line)
{
	fzn_retain_rule_t r;

	if (fzn_retain_parse(line, strlen(line), &r) != FZN_RETAIN_OK)
		memset(&r, 0, sizeof(r));
	return r;
}

static const char *text_of(const fzn_retain_rule_t *r)
{
	static char t[FZN_RETAIN_TEXT_MAX];
	size_t len = 0;

	return fzn_retain_text(r, t, sizeof(t), &len) == FZN_RETAIN_OK ? t : "refused";
}

int main(void)
{
	fzn_retain_rule_t a = rule("prune * age 720h"), b = rule("keep netcfgd level=TD age 90d");
	fzn_retain_rule_t held[FZN_LOG_RULES_MAX + 1u], x;
	size_t n = 9, i;
	int ok = 1;

	CHECK(fzn_log_rules_add(&OPS, &HASH, &a, 5u) == FZN_LOG_RULES_OK
	              && fzn_log_rules_add(&OPS, &HASH, &b, 6u) == FZN_LOG_RULES_OK,
	      "two rules are kept");
	x = rule("prune * age 30d");
	CHECK(fzn_log_rules_add(&OPS, &HASH, &x, 7u) == FZN_LOG_RULES_ERR_TAKEN,
	      "the first again, spelt in days, is the same rule");
	CHECK(fzn_log_rules_list(&OPS, held, FZN_LOG_RULES_MAX, &n) == FZN_LOG_RULES_OK && n == 2u
	              && strcmp(text_of(&held[0]), "keep netcfgd level=DT age 90d") == 0
	              && strcmp(text_of(&held[1]), "prune * age 30d") == 0,
	      "listed in the order of their canonical texts, in canonical spelling");
	CHECK(fzn_log_rules_remove(&OPS, &HASH, &x) == FZN_LOG_RULES_OK
	              && fzn_log_rules_list(&OPS, held, FZN_LOG_RULES_MAX, &n) == FZN_LOG_RULES_OK
	              && n == 1u && fzn_log_rules_remove(&OPS, &HASH, &x) == FZN_LOG_RULES_ERR_ABSENT,
	      "removed by the other spelling, and removing again is absent");
	CHECK(fzn_log_rules_add(&OPS, &REFUSING, &a, 8u) == FZN_LOG_RULES_ERR_BACKEND,
	      "a hash that refuses files nothing");
	memset(&x, 0, sizeof(x));
	CHECK(fzn_log_rules_add(&OPS, &HASH, &x, 8u) == FZN_LOG_RULES_ERR_MALFORMED,
	      "a rule that is not one is refused");
	no_list = 1;
	CHECK(fzn_log_rules_add(&OPS, &HASH, &a, 9u) == FZN_LOG_RULES_ERR_BACKEND,
	      "a store that cannot list refuses to add");
	no_list = 0;
	for (i = 1; i < FZN_LOG_RULES_MAX && ok; i++) {
		char line[64];

		snprintf(line, sizeof(line), "prune * count %zu", i);
		x = rule(line);
		ok = fzn_log_rules_add(&OPS, &HASH, &x, 10u) == FZN_LOG_RULES_OK;
	}
	CHECK(ok, "fixture: the rules fill to their bound");
	CHECK(fzn_log_rules_add(&OPS, &HASH, &a, 11u) == FZN_LOG_RULES_ERR_FULL,
	      "one past the bound is refused");
	/* AN ENTRY THAT WILL NOT READ is SHAPE, not a rule quietly missing. */
	for (i = 0; i < MEM_ROWS; i++)
		if (rows[i].used && rows[i].slot == FZN_PERSIST_LOG_RULE) {
			rows[i].bytes[rows[i].len - 9u] ^= 0x20u;
			break;
		}
	CHECK(fzn_log_rules_list(&OPS, held, FZN_LOG_RULES_MAX, &n) == FZN_LOG_RULES_ERR_SHAPE,
	      "a held rule whose text no longer parses makes the list refuse");
	if (failures) {
		fprintf(stderr, "rules_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("rules_test: all %d checks passed\n", checks);
	return 0;
}
