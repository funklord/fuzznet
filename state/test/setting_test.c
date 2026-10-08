/* Tests for state/setting.c: a setting as a signed object, its cell, and
 * which of two stands within a rank. sec 540.
 *
 * The cell cases assert relationships -- change the scope, what it is about
 * or the key and the cell changes -- rather than thirty-two bytes, which
 * would pin this stub hash. The signature is a keyed stub: what matters here
 * is that a byte changed anywhere makes it fail, and that the setter it is
 * checked against is the one inside the object.
 */

#include "../setting.h"
#include "../../wire/bytes.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL setting_test.c:%d: %s\n", __LINE__, what);      \
		}                                                                              \
	} while (0)

/* ---- a stub hash and a keyed stub signature ---------------------------------- */

static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	(void)ctx;
	for (i = 0; i < in_len; i++)
		h = (h ^ in[i]) * 0x100000001b3ull;
	for (i = 0; i < out_len; i++) {
		h = (h ^ ((uint64_t)i + 0x9e3779b97f4a7c15ull)) * 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 56);
	}
	return 1;
}

static const fzn_hash_ops_t HASH = { stub_hash, NULL };

static void mac(uint8_t out[FZN_SIG_LEN], uint8_t key, const uint8_t *msg, size_t len)
{
	uint64_t h = 0xcbf29ce484222325ull ^ key;
	size_t i;

	for (i = 0; i < len; i++)
		h = (h ^ msg[i]) * 0x100000001b3ull;
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h = (h ^ (uint64_t)i) * 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 56);
	}
}

static uint8_t signing_as;

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t len)
{
	(void)ctx;
	mac(sig, signing_as, msg, len);
	return 1;
}

static int stub_verify(void *ctx, const uint8_t pk[FZN_PUBKEY_LEN], const uint8_t *msg, size_t len,
                       const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	mac(want, pk[0], msg, len);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

static const fzn_sign_ops_t SIGN = { stub_verify, stub_sign, NULL };

static void key(uint8_t out[FZN_PUBKEY_LEN], uint8_t seed)
{
	memset(out, seed, FZN_PUBKEY_LEN);
}

/* ---- cases --------------------------------------------------------------------- */

static uint8_t obj[FZN_SETTING_MAX], obj2[FZN_SETTING_MAX];
static size_t len, len2;

static int issue(uint8_t setter, fzn_scope_t scope, uint8_t about, uint64_t version,
                 const char *k, int set, const char *value, uint8_t *out, size_t *out_len)
{
	uint8_t who[FZN_PUBKEY_LEN], subject[FZN_SUBJECT_LEN];

	key(who, setter);
	key(subject, about);
	signing_as = setter;
	return fzn_setting_issue(who, &SIGN, scope, subject, version, (const uint8_t *)k, strlen(k),
	                         set, (const uint8_t *)value, value ? strlen(value) : 0u, out,
	                         out_len)
	       == FZN_SETTING_OK;
}

static void test_the_object(void)
{
	fzn_setting_t s;

	CHECK(issue(0x10, FZN_SCOPE_ESTATE, 0x10, 7u, "retention/a", 1, "prune messages age 30d", obj,
	            &len)
	              && fzn_setting_open(obj, len, &SIGN, &s) == FZN_SETTING_OK,
	      "an estate setting issued does not open");
	CHECK(s.setter[0] == 0x10 && s.scope == FZN_SCOPE_ESTATE && s.about[0] == 0x10
	              && s.version == 7u && s.key_len == 11u && memcmp(s.key, "retention/a", 11u) == 0
	              && s.set == 1 && s.value_len == 22u
	              && memcmp(s.value, "prune messages age 30d", 22u) == 0
	              && obj[1] == (uint8_t)FZN_OBJECT_SETTING,
	      "it opens to other than what was issued");
	CHECK(issue(0x20, FZN_SCOPE_HOST, 0x20, 1u, "x", 0, NULL, obj2, &len2)
	              && len2 == FZN_SETTING_MIN && fzn_setting_open(obj2, len2, &SIGN, &s) == FZN_SETTING_OK
	              && s.set == 0 && s.value_len == 0u,
	      "a clear of a one-byte key is not the shortest setting, or does not open");
}

static void test_what_is_refused(void)
{
	uint8_t who[FZN_PUBKEY_LEN], subject[FZN_SUBJECT_LEN], bad[FZN_SETTING_MAX];
	fzn_setting_t s;
	char long_key[FZN_SETTING_KEY_MAX + 2u], long_value[FZN_SETTING_VALUE_MAX + 2u];

	key(who, 0x10);
	key(subject, 0x10);
	memset(long_key, 'k', sizeof(long_key) - 1u);
	long_key[sizeof(long_key) - 1u] = '\0';
	memset(long_value, 'v', sizeof(long_value) - 1u);
	long_value[sizeof(long_value) - 1u] = '\0';
	CHECK(!issue(0x10, FZN_SCOPE_ESTATE, 0x10, 1u, "Upper", 1, "v", obj2, &len2)
	              && !issue(0x10, FZN_SCOPE_ESTATE, 0x10, 1u, "a b", 1, "v", obj2, &len2)
	              && !issue(0x10, FZN_SCOPE_ESTATE, 0x10, 1u, "", 1, "v", obj2, &len2)
	              && !issue(0x10, FZN_SCOPE_ESTATE, 0x10, 1u, long_key, 1, "v", obj2, &len2),
	      "a key of other than a-z 0-9 ._/- or out of length was issued");
	CHECK(!issue(0x10, FZN_SCOPE_ESTATE, 0x10, 1u, "k", 1, "tab\there", obj2, &len2)
	              && !issue(0x10, FZN_SCOPE_ESTATE, 0x10, 1u, "k", 1, long_value, obj2, &len2)
	              && !issue(0x10, FZN_SCOPE_ESTATE, 0x10, 1u, "k", 0, "a value", obj2, &len2),
	      "an unprintable or long value, or a clear with a value, was issued");
	signing_as = 0x10;
	CHECK(fzn_setting_issue(who, &SIGN, FZN_SCOPE_GROUP, subject, 1u, (const uint8_t *)"k", 1u, 1,
	                        (const uint8_t *)"v", 1u, obj2, &len2)
	              == FZN_SETTING_ERR_SCOPE
	              && fzn_setting_issue(who, &SIGN, FZN_SCOPE_HOST_PRIVATE, subject, 1u,
	                                   (const uint8_t *)"k", 1u, 1, (const uint8_t *)"v", 1u, obj2,
	                                   &len2)
	                         == FZN_SETTING_ERR_SCOPE,
	      "a scope with no cell, or one not served, was issued");
	/* The object above, each way broken. */
	memcpy(bad, obj, len);
	bad[len - 1u] ^= 1u;
	CHECK(fzn_setting_open(bad, len, &SIGN, &s) == FZN_SETTING_ERR_SIGNATURE,
	      "a signature changed was not refused as one");
	memcpy(bad, obj, len);
	bad[FZN_SETTING_OFF_VERSION + 7u] ^= 1u;
	CHECK(fzn_setting_open(bad, len, &SIGN, &s) == FZN_SETTING_ERR_SIGNATURE,
	      "a version changed under the signature was not refused");
	memcpy(bad, obj, len);
	bad[FZN_SETTING_OFF_SETTER] = 0x30;
	CHECK(fzn_setting_open(bad, len, &SIGN, &s) == FZN_SETTING_ERR_SIGNATURE,
	      "another setter named over the same signature was not refused");
	memcpy(bad, obj, len);
	bad[1] = (uint8_t)FZN_OBJECT_SUCCESSION;
	CHECK(fzn_setting_open(bad, len, &SIGN, &s) == FZN_SETTING_ERR_SHAPE,
	      "another object's tag was opened as a setting");
	memcpy(bad, obj, len);
	bad[len] = 0u;
	CHECK(fzn_setting_open(bad, len + 1u, &SIGN, &s) == FZN_SETTING_ERR_SHAPE
	              && fzn_setting_open(obj, len - 1u, &SIGN, &s) == FZN_SETTING_ERR_SHAPE,
	      "a byte past the signature, or one short, was not refused as shape");
	memcpy(bad, obj, len);
	bad[FZN_SETTING_OFF_KEY_LEN]++;
	CHECK(fzn_setting_open(bad, len, &SIGN, &s) == FZN_SETTING_ERR_SHAPE,
	      "a key length that does not account for the bytes was not refused");
}

static void test_the_cell(void)
{
	uint8_t a[FZN_SUBJECT_LEN], b[FZN_SUBJECT_LEN], about[FZN_SUBJECT_LEN];
	uint8_t other[FZN_SUBJECT_LEN];
	fzn_setting_t s, t;

	key(about, 0x20);
	key(other, 0x21);
	CHECK(fzn_setting_cell_of(FZN_SCOPE_HOST, about, (const uint8_t *)"k", 1u, &HASH, a)
	              && fzn_setting_cell_of(FZN_SCOPE_ESTATE, about, (const uint8_t *)"k", 1u, &HASH, b)
	              && memcmp(a, b, sizeof(a)) != 0,
	      "a host's cell and the estate's under one key and id are one cell");
	CHECK(fzn_setting_cell_of(FZN_SCOPE_HOST, other, (const uint8_t *)"k", 1u, &HASH, b)
	              && memcmp(a, b, sizeof(a)) != 0,
	      "two hosts' cells under one key are one cell");
	CHECK(fzn_setting_cell_of(FZN_SCOPE_HOST, about, (const uint8_t *)"kk", 2u, &HASH, b)
	              && memcmp(a, b, sizeof(a)) != 0,
	      "two keys of one host are one cell");
	/* WHO SET IT, AND WHAT TO, ARE NOT THE CELL. */
	CHECK(issue(0x20, FZN_SCOPE_HOST, 0x20, 1u, "k", 1, "one", obj, &len)
	              && issue(0x10, FZN_SCOPE_HOST, 0x20, 9u, "k", 0, NULL, obj2, &len2)
	              && fzn_setting_open(obj, len, &SIGN, &s) == FZN_SETTING_OK
	              && fzn_setting_open(obj2, len2, &SIGN, &t) == FZN_SETTING_OK
	              && fzn_setting_cell(&s, &HASH, b) && memcmp(a, b, sizeof(a)) == 0
	              && fzn_setting_cell(&t, &HASH, b) && memcmp(a, b, sizeof(a)) == 0,
	      "two settings of one cell by two setters name two cells");
	CHECK(!fzn_setting_cell_of(FZN_SCOPE_HOST_PRIVATE, about, (const uint8_t *)"k", 1u, &HASH, b),
	      "a host-private value was given a cell");
}

static void test_which_stands(void)
{
	fzn_setting_t s, t;

	/* THE HIGHER VERSION, whoever set it. */
	CHECK(issue(0x10, FZN_SCOPE_HOST, 0x20, 2u, "k", 1, "two", obj, &len)
	              && issue(0x40, FZN_SCOPE_HOST, 0x20, 3u, "k", 1, "three", obj2, &len2)
	              && fzn_setting_open(obj, len, &SIGN, &s) == FZN_SETTING_OK
	              && fzn_setting_open(obj2, len2, &SIGN, &t) == FZN_SETTING_OK
	              && fzn_setting_supersedes(&t, &s) && !fzn_setting_supersedes(&s, &t),
	      "the higher version does not stand");
	/* AT ONE VERSION, THE GREATER SETTER KEY. */
	CHECK(issue(0x10, FZN_SCOPE_HOST, 0x20, 3u, "k", 1, "ten", obj, &len)
	              && fzn_setting_open(obj, len, &SIGN, &s) == FZN_SETTING_OK
	              && fzn_setting_supersedes(&t, &s) && !fzn_setting_supersedes(&s, &t),
	      "at one version the greater setter key does not stand");
	/* ONE SETTER, ONE VERSION, TWO STATEMENTS: settled one way, and a
	 * setting does not supersede itself. */
	CHECK(issue(0x40, FZN_SCOPE_HOST, 0x20, 3u, "k", 0, NULL, obj, &len)
	              && fzn_setting_open(obj, len, &SIGN, &s) == FZN_SETTING_OK
	              && fzn_setting_supersedes(&t, &s) && !fzn_setting_supersedes(&s, &t)
	              && !fzn_setting_supersedes(&t, &t),
	      "an equivocation is not settled one way, or a setting supersedes itself");
}

int main(void)
{
	test_the_object();
	test_what_is_refused();
	test_the_cell();
	test_which_stands();
	if (failures) {
		fprintf(stderr, "setting_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("setting_test: all %d checks passed\n", checks);
	return 0;
}
