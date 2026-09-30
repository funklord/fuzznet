/* Tests for state/scope.c: the scope vocabulary and its semantics. sec 420.
 *
 * THE PROPERTY netcfgd asked be designed in is the narrowest scope at zero,
 * so the cases here hold the direction of every default: a zeroed byte, an
 * unknown byte and an unspelled name all travel least. The subject cases
 * assert relationships -- change the scope or the id and the subject changes
 * -- rather than any thirty-two bytes, which would pin this stub hash.
 */

#include "../scope.h"

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
	fprintf(stderr, "  FAIL scope_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

static int hash_refuses;

static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	(void)ctx;
	if (hash_refuses)
		return 0;
	for (i = 0; i < in_len; i++) {
		h ^= in[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < out_len; i++) {
		h ^= (uint64_t)i + 0x9e3779b97f4a7c15ull;
		h *= 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 32);
	}
	return 1;
}

static const fzn_hash_ops_t HASH = { stub_hash, NULL };

/* THE NARROWEST AT ZERO: a zeroed byte is host-private, and so is a byte this
 * build does not know -- it travels nowhere and has no cell. */
static void test_the_default_travels_least(void)
{
	CHECK(FZN_SCOPE_HOST_PRIVATE == 0, "the zero scope is not host-private");
	CHECK(fzn_scope_read(0u) == FZN_SCOPE_HOST_PRIVATE, "a zeroed byte is not host-private");
	CHECK(!fzn_scope_known(FZN_SCOPE_COUNT) && !fzn_scope_known(255u)
	              && fzn_scope_read((uint8_t)FZN_SCOPE_COUNT) == FZN_SCOPE_HOST_PRIVATE
	              && fzn_scope_read(255u) == FZN_SCOPE_HOST_PRIVATE,
	      "a scope this build does not know was read as something that travels");
	CHECK(!fzn_scope_replicates(FZN_SCOPE_HOST_PRIVATE)
	              && !fzn_scope_replicates((fzn_scope_t)FZN_SCOPE_COUNT),
	      "host-private or an unknown scope replicates");
	CHECK(fzn_scope_read((uint8_t)FZN_SCOPE_ESTATE) == FZN_SCOPE_ESTATE,
	      "a known scope was not read as itself");
}

/* REACH: host and estate reach every host, a group only its members, and
 * host-private nobody. Widening is judged by reach, not by number. */
static void test_reach_and_widening(void)
{
	CHECK(fzn_scope_reaches(FZN_SCOPE_HOST, 0) && fzn_scope_reaches(FZN_SCOPE_ESTATE, 0),
	      "a host or estate value did not reach a host outside any group");
	CHECK(fzn_scope_reaches(FZN_SCOPE_GROUP, 1) && !fzn_scope_reaches(FZN_SCOPE_GROUP, 0),
	      "a group value reached a non-member, or missed a member");
	CHECK(!fzn_scope_reaches(FZN_SCOPE_HOST_PRIVATE, 1),
	      "a host-private value reached anybody");
	CHECK(fzn_scope_widens(FZN_SCOPE_GROUP, FZN_SCOPE_HOST)
	              && fzn_scope_widens(FZN_SCOPE_HOST_PRIVATE, FZN_SCOPE_GROUP)
	              && fzn_scope_widens(FZN_SCOPE_GROUP, FZN_SCOPE_ESTATE),
	      "a change that reaches new hosts was not called widening");
	CHECK(!fzn_scope_widens(FZN_SCOPE_HOST, FZN_SCOPE_ESTATE)
	              && !fzn_scope_widens(FZN_SCOPE_ESTATE, FZN_SCOPE_GROUP)
	              && !fzn_scope_widens(FZN_SCOPE_HOST, FZN_SCOPE_HOST_PRIVATE)
	              && !fzn_scope_widens(FZN_SCOPE_GROUP, FZN_SCOPE_GROUP),
	      "a change that reaches no new host was called widening");
	CHECK(!fzn_scope_widens(FZN_SCOPE_HOST, (fzn_scope_t)FZN_SCOPE_COUNT),
	      "a move to an unknown scope was called widening");
}

/* THE NAMES round-trip, exactly; anything else is no scope. */
static void test_the_names(void)
{
	fzn_scope_t s = FZN_SCOPE_ESTATE;
	unsigned i;

	for (i = 0; i < FZN_SCOPE_COUNT; i++) {
		const char *name = fzn_scope_name((fzn_scope_t)i);
		fzn_scope_t back = FZN_SCOPE_HOST_PRIVATE;

		CHECK(name && fzn_scope_parse((const uint8_t *)name, strlen(name), &back)
		              && back == (fzn_scope_t)i,
		      "scope %u did not round-trip its name", i);
	}
	CHECK(!fzn_scope_name((fzn_scope_t)FZN_SCOPE_COUNT), "an unknown scope has a name");
	CHECK(!fzn_scope_parse((const uint8_t *)"Estate", 6u, &s)
	              && !fzn_scope_parse((const uint8_t *)"host-privat", 11u, &s)
	              && !fzn_scope_parse((const uint8_t *)"hosts", 5u, &s) && s == FZN_SCOPE_ESTATE,
	      "a misspelling parsed, or wrote the answer anyway");
}

/* A SCOPE IS A KIND OF SUBJECT: one id under two scopes is two subjects, two
 * ids under one scope are two, and host-private has none. */
static void test_the_subject(void)
{
	uint8_t id[FZN_SUBJECT_LEN], other[FZN_SUBJECT_LEN];
	uint8_t host[FZN_SUBJECT_LEN], group[FZN_SUBJECT_LEN], estate[FZN_SUBJECT_LEN];
	uint8_t again[FZN_SUBJECT_LEN], out[FZN_SUBJECT_LEN];

	memset(id, 0x11, sizeof(id));
	memset(other, 0x22, sizeof(other));
	CHECK(fzn_scope_subject(FZN_SCOPE_HOST, id, &HASH, host) == FZN_SCOPE_OK
	              && fzn_scope_subject(FZN_SCOPE_GROUP, id, &HASH, group) == FZN_SCOPE_OK
	              && fzn_scope_subject(FZN_SCOPE_ESTATE, id, &HASH, estate) == FZN_SCOPE_OK,
	      "a replicated scope derived no subject");
	CHECK(memcmp(host, group, sizeof(host)) != 0 && memcmp(group, estate, sizeof(host)) != 0
	              && memcmp(host, estate, sizeof(host)) != 0,
	      "one id under two scopes gave one subject");
	CHECK(fzn_scope_subject(FZN_SCOPE_HOST, other, &HASH, again) == FZN_SCOPE_OK
	              && memcmp(again, host, sizeof(host)) != 0,
	      "two hosts gave one subject");
	CHECK(fzn_scope_subject(FZN_SCOPE_HOST, id, &HASH, again) == FZN_SCOPE_OK
	              && memcmp(again, host, sizeof(host)) == 0,
	      "the derivation is not deterministic");
	CHECK(memcmp(host, id, sizeof(id)) != 0, "a host's subject is its bare key, unlabelled");

	memset(out, 0xee, sizeof(out));
	CHECK(fzn_scope_subject(FZN_SCOPE_HOST_PRIVATE, id, &HASH, out) == FZN_SCOPE_ERR_PRIVATE
	              && out[0] == 0xeeu,
	      "host-private derived a subject, or wrote one");
	CHECK(fzn_scope_subject((fzn_scope_t)FZN_SCOPE_COUNT, id, &HASH, out)
	              == FZN_SCOPE_ERR_MALFORMED
	              && out[0] == 0xeeu,
	      "an unknown scope derived a subject");
	hash_refuses = 1;
	CHECK(fzn_scope_subject(FZN_SCOPE_HOST, id, &HASH, out) == FZN_SCOPE_ERR_MALFORMED
	              && out[0] == 0xeeu,
	      "a refusing hash was reported as a subject");
	hash_refuses = 0;
	CHECK(fzn_scope_subject(FZN_SCOPE_HOST, NULL, &HASH, out) == FZN_SCOPE_ERR_MALFORMED
	              && fzn_scope_subject(FZN_SCOPE_HOST, id, NULL, out) == FZN_SCOPE_ERR_MALFORMED,
	      "a missing id or hash was not refused");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	check_at(0, __LINE__, "deliberate");
	CHECK(failures == before + 1, "a failing check did not count");
	failures = before;
	checks -= 1;
}

int main(void)
{
	test_the_default_travels_least();
	test_reach_and_widening();
	test_the_names();
	test_the_subject();
	test_the_suite_can_tell_pass_from_fail();

	printf("scope_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
