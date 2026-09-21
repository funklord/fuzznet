/* Tests for catalog/shard.c: where the key-range boundaries fall. sec 337.
 *
 * THE PROPERTY THIS SUITE DEFENDS is that NO SHARD IS SMALLER THAN THE
 * PRIVACY CONTROL. C26 makes the shard size the anonymity set, so a shard
 * holding fewer entries than `min_entries` is not a smaller shard -- it is a
 * range where a fetch reveals more than the number promises, and it would sit
 * at the END of the key space where nobody would think to look for it.
 *
 * That is the case a division gets wrong and a test is the only thing that
 * catches: 3000 keys at 1024 each is two shards of 1024 and one of 952, unless
 * the remainder is absorbed. Every case below that does not divide evenly
 * checks the minimum across EVERY shard rather than the count.
 */

#include "../shard.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

#if defined(__GNUC__)
#define FZN_CHECK_PRINTF __attribute__((format(printf, 3, 4)))
#else
#define FZN_CHECK_PRINTF
#endif

static void check_at(int ok, int line, const char *fmt, ...) FZN_CHECK_PRINTF;

static void check_at(int ok, int line, const char *fmt, ...)
{
	va_list ap;

	checks++;
	if (ok)
		return;

	failures++;
	fprintf(stderr, "  FAIL shard_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

#define MAX_KEYS 4096u

static fzn_catalog_shard_key_t keys[MAX_KEYS];
static fzn_catalog_shard_t plan[64];

/* Ascending keys, distinct in their LAST bytes so a comparison that stopped
 * early would see them all as equal and call the list unsorted. */
static void fill(size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		memset(keys[i].b, 0, sizeof(keys[i].b));
		keys[i].b[FZN_CATALOG_SHARD_KEY_LEN - 4u] = (uint8_t)(i >> 24);
		keys[i].b[FZN_CATALOG_SHARD_KEY_LEN - 3u] = (uint8_t)(i >> 16);
		keys[i].b[FZN_CATALOG_SHARD_KEY_LEN - 2u] = (uint8_t)(i >> 8);
		keys[i].b[FZN_CATALOG_SHARD_KEY_LEN - 1u] = (uint8_t)i;
	}
}

/* Every shard holds at least the minimum, and together they hold everything. */
static int minimum_held(size_t n, size_t k)
{
	size_t got = 0, i;

	for (i = 0; i < n; i++) {
		if (plan[i].entries < k)
			return 0;
		got += plan[i].entries;
	}
	return got != 0;
}

static size_t total_entries(size_t n)
{
	size_t got = 0, i;

	for (i = 0; i < n; i++)
		got += plan[i].entries;
	return got;
}

/* THE CASE A DIVISION GETS WRONG. */
static void test_the_remainder_is_absorbed(void)
{
	size_t n = 0;
	size_t k = 1024;

	/* 3000 at 1024: two shards, the second holding 1976. A division would
	 * give three, the last holding 952 -- a range at the END of the key
	 * space with an anonymity set of 952 where 1024 was promised. */
	fill(3000);
	CHECK(fzn_catalog_shard_plan(keys, 3000, k, plan, 64, &n) == FZN_CATALOG_OK,
	      "planning 3000 keys was refused");
	CHECK(n == 2, "3000 keys at 1024 gave %zu shards, not 2", n);
	CHECK(minimum_held(n, k),
	      "a shard holds fewer than the minimum, so the end of the key space has "
	      "a weaker anonymity set than the rest and a fetch there reveals more");
	CHECK(plan[1].entries == 1976, "the last shard holds %zu, not the remainder",
	      plan[1].entries);
	CHECK(total_entries(n) == 3000, "the plan covers %zu keys, not 3000",
	      total_entries(n));

	/* AND THE LAST SHARD IS BOUNDED: absorbing the tail cannot make it
	 * larger than 2k-1, or the guarantee would be "at least k" with no
	 * ceiling and one shard could swallow the register. */
	CHECK(plan[n - 1u].entries < 2u * k,
	      "the last shard holds %zu, which is 2k or more", plan[n - 1u].entries);

	/* An exact multiple divides exactly, with no remainder to absorb. */
	fill(2048);
	CHECK(fzn_catalog_shard_plan(keys, 2048, k, plan, 64, &n) == FZN_CATALOG_OK,
	      "planning an exact multiple was refused");
	CHECK(n == 2 && plan[0].entries == 1024 && plan[1].entries == 1024,
	      "an exact multiple did not divide exactly (%zu shards)", n);
}

/* A REGISTER SMALLER THAN ONE SHARD IS ONE SHARD, not a short one: the whole
 * register is then the anonymity set, which is the best available. */
static void test_a_small_register(void)
{
	size_t n = 0;

	fill(10);
	CHECK(fzn_catalog_shard_plan(keys, 10, 1024, plan, 64, &n) == FZN_CATALOG_OK,
	      "planning a register smaller than one shard was refused");
	CHECK(n == 1 && plan[0].entries == 10,
	      "a ten-key register gave %zu shards holding %zu, not one holding ten",
	      n, n ? plan[0].entries : 0);

	fill(1);
	CHECK(fzn_catalog_shard_plan(keys, 1, 1024, plan, 64, &n) == FZN_CATALOG_OK &&
	          n == 1 && plan[0].entries == 1,
	      "a one-key register was not one shard");

	/* An empty register is no shards and not an error: there is nothing to
	 * fetch, which is a state rather than a fault. */
	CHECK(fzn_catalog_shard_plan(keys, 0, 1024, plan, 64, &n) == FZN_CATALOG_OK &&
	          n == 0,
	      "an empty register was not an empty plan");
}

/* THE DEFAULT IS THE PRIVACY CONTROL, and it is the number C26 names. */
static void test_the_default(void)
{
	size_t n = 0;

	CHECK(FZN_CATALOG_SHARD_ENTRIES_MIN == 1024u,
	      "the shard minimum is %u, and sec 337 settled 1024",
	      (unsigned)FZN_CATALOG_SHARD_ENTRIES_MIN);

	fill(4096);
	CHECK(fzn_catalog_shard_plan(keys, 4096, FZN_CATALOG_SHARD_ENTRIES_MIN, plan, 64,
	                             &n) == FZN_CATALOG_OK && n == 4,
	      "4096 keys at the default gave %zu shards, not 4", n);
	CHECK(minimum_held(n, FZN_CATALOG_SHARD_ENTRIES_MIN),
	      "a shard holds fewer than the default minimum");
}

/* WHICH SHARD HOLDS A KEY, including the two edges. */
static void test_shard_of(void)
{
	size_t n = 0, at = 0;
	fzn_catalog_shard_key_t probe;

	fill(3000);
	fzn_catalog_shard_plan(keys, 3000, 1024, plan, 64, &n);

	CHECK(fzn_catalog_shard_of(plan, n, &keys[0], &at) == FZN_CATALOG_OK && at == 0,
	      "the first key is not in the first shard (at=%zu)", at);
	CHECK(fzn_catalog_shard_of(plan, n, &keys[1023], &at) == FZN_CATALOG_OK && at == 0,
	      "the last key of the first shard is not in it (at=%zu)", at);
	CHECK(fzn_catalog_shard_of(plan, n, &keys[1024], &at) == FZN_CATALOG_OK && at == 1,
	      "the first key of the second shard is not in it (at=%zu)", at);
	CHECK(fzn_catalog_shard_of(plan, n, &keys[2999], &at) == FZN_CATALOG_OK && at == 1,
	      "the last key is not in the last shard (at=%zu)", at);

	/* A KEY BELOW THE FIRST SHARD'S START belongs to the first shard: the
	 * ranges cover the whole key space, and the plan's first key is the
	 * lowest the register HAD, not the lowest that could exist. */
	memset(probe.b, 0, sizeof(probe.b));
	CHECK(fzn_catalog_shard_of(plan, n, &probe, &at) == FZN_CATALOG_OK && at == 0,
	      "a key below the register's lowest fell outside every shard, so a "
	      "lookup for it would have nowhere to go (at=%zu)", at);

	/* And one above everything belongs to the last. */
	memset(probe.b, 0xff, sizeof(probe.b));
	CHECK(fzn_catalog_shard_of(plan, n, &probe, &at) == FZN_CATALOG_OK &&
	          at == n - 1u,
	      "a key above the register's highest fell outside every shard (at=%zu)", at);

	CHECK(fzn_catalog_shard_of(plan, 0, &keys[0], &at) == FZN_CATALOG_ERR_ABSENT,
	      "an empty plan answered which shard holds a key");
}

/* WHAT IS REFUSED, each with a control. */
static void test_refusals(void)
{
	size_t n = 0;
	fzn_catalog_shard_key_t swap;

	fill(2048);

	CHECK(fzn_catalog_shard_plan(keys, 2048, 0, plan, 64, &n) ==
	          FZN_CATALOG_ERR_MALFORMED, "a minimum of zero planned");
	CHECK(fzn_catalog_shard_plan(NULL, 2048, 1024, plan, 64, &n) ==
	          FZN_CATALOG_ERR_MALFORMED, "a null key list planned");
	CHECK(fzn_catalog_shard_plan(keys, 2048, 1024, plan, 64, NULL) ==
	          FZN_CATALOG_ERR_MALFORMED, "planning with nowhere to put the count");
	/* A TRUNCATED PLAN DROPS THE TAIL OF THE KEY SPACE, so a consumer would
	 * build an index that answers for part of it. Loud. */
	CHECK(fzn_catalog_shard_plan(keys, 2048, 1024, plan, 1, &n) ==
	          FZN_CATALOG_ERR_RANGE, "a plan too small for the shards succeeded");
	CHECK(fzn_catalog_shard_plan(keys, 2048, 1024, plan, 64, &n) == FZN_CATALOG_OK,
	      "the control -- every argument in range -- was refused too");

	/* UNSORTED KEYS PRODUCE OVERLAPPING RANGES, and an index over
	 * overlapping ranges cannot say which blob holds a key. */
	swap = keys[100];
	keys[100] = keys[900];
	keys[900] = swap;
	CHECK(fzn_catalog_shard_plan(keys, 2048, 1024, plan, 64, &n) ==
	          FZN_CATALOG_ERR_MALFORMED,
	      "an unsorted key list planned, and its ranges overlap");
	CHECK(n == 0, "a refused plan left a count behind");
	swap = keys[100];
	keys[100] = keys[900];
	keys[900] = swap;
	CHECK(fzn_catalog_shard_plan(keys, 2048, 1024, plan, 64, &n) == FZN_CATALOG_OK,
	      "the control -- sorted again -- was refused too");

	/* EQUAL ADJACENT KEYS ARE SORTED. A register may hold two entries under
	 * one key, and refusing that would be refusing the register. */
	keys[500] = keys[499];
	CHECK(fzn_catalog_shard_plan(keys, 2048, 1024, plan, 64, &n) == FZN_CATALOG_OK,
	      "two entries under one key were refused as unsorted");
}

int main(void)
{
	test_the_remainder_is_absorbed();
	test_a_small_register();
	test_the_default();
	test_shard_of();
	test_refusals();

	printf("shard_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
