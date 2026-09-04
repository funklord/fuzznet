/* Tests for disclose/disclose.c: the salt convention and what it buys.
 *
 * THE CASE THIS SUITE EXISTS FOR is `test_the_salt_is_what_hides_the_field`.
 * Everything else here checks a shape, and shapes are cheap. The module's
 * whole reason to exist is that a leaf is a hash of a field, so a field with
 * a small domain falls out of the root unless something unguessable is
 * hashed with it -- and a construction that omits the salt still commits,
 * still proves, still verifies and still round-trips. It fails only at the
 * one thing it was for, silently.
 *
 * So the salt is not asserted to be present. It is asserted to DEFEAT A
 * SEARCH, with a control showing the same search succeeding when the salt is
 * known -- otherwise "not found" is consistent with the search being broken.
 */

#include "../disclose.h"

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
	fprintf(stderr, "  FAIL disclose_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

#define REQUIRE(cond, ...)                                    \
	do {                                                  \
		int require_ok = (cond) ? 1 : 0;              \
		check_at(require_ok, __LINE__, __VA_ARGS__);  \
		if (!require_ok)                              \
			return;                               \
	} while (0)

static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	(void)ctx;
	for (i = 0; i < in_len; i++) {
		h ^= in[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < out_len; i++) {
		h ^= (uint64_t)i + 0x9e3779b97f4a7c15ull;
		h *= 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 24);
	}
	return 1;
}

static const fzn_hash_ops_t HASH = { stub_hash, NULL };

/* A counting source, so a salt is unpredictable to the code under test and
 * reproducible to whoever reads a failure. `real_crypto_test.c` gives the
 * reason a suite does not draw from the system pool. */
static unsigned salt_counter;

static int counting_fill(void *ctx, uint8_t *out, size_t len)
{
	size_t i;

	(void)ctx;
	for (i = 0; i < len; i++)
		out[i] = (uint8_t)(salt_counter * 131u + i * 17u + 3u);
	salt_counter++;
	return 1;
}

static int refusing_fill(void *ctx, uint8_t *out, size_t len)
{
	(void)ctx;
	(void)out;
	(void)len;
	return 0;
}

static const fzn_random_ops_t RNG = { counting_fill, NULL };
static const fzn_random_ops_t NO_RNG = { refusing_fill, NULL };

#define FIELDS 4u

struct statement {
	uint8_t committed[FIELDS][FZN_DISCLOSE_MAX_LEN];
	size_t lens[FIELDS];
	uint8_t leaves[FIELDS][FZN_BLOB_HASH_LEN];
	uint8_t root[FZN_BLOB_HASH_LEN];
};

/* Commit every field, fold the leaves, take the root. Returns 0 on any
 * refusal so a caller can abandon rather than assert over a root that was
 * never built. */
static int commit_all(struct statement *st, const char *const *fields, unsigned n)
{
	fzn_blob_tree_t tree;
	unsigned i;

	fzn_blob_tree_init(&tree);
	for (i = 0; i < n; i++) {
		if (fzn_disclose_commit(&RNG, (const uint8_t *)fields[i], strlen(fields[i]),
		                        st->committed[i], FZN_DISCLOSE_MAX_LEN,
		                        &st->lens[i]) != FZN_DISCLOSE_OK)
			return 0;
		if (fzn_disclose_leaf(&HASH, st->committed[i], st->lens[i],
		                      st->leaves[i]) != FZN_DISCLOSE_OK)
			return 0;
		if (fzn_blob_tree_push(&HASH, &tree, st->leaves[i]) != FZN_BLOB_OK)
			return 0;
	}

	return fzn_blob_tree_root(&HASH, &tree, st->root) == FZN_BLOB_OK;
}

static const char *const FIELDS_TEXT[FIELDS] = {
	"region: north",
	"street and number",
	"bearing 043",
	"accuracy 3m"
};

static void test_one_root_serves_every_field(void)
{
	struct statement st;
	uint8_t proof[FZN_BLOB_MAX_DEPTH * FZN_BLOB_HASH_LEN];
	unsigned count = 0;
	unsigned i;

	REQUIRE(commit_all(&st, FIELDS_TEXT, FIELDS), "the statement did not commit");

	for (i = 0; i < FIELDS; i++) {
		const uint8_t *field = NULL;
		size_t field_len = 0;

		REQUIRE(fzn_blob_proof_build(&HASH, &st.leaves[0][0], FIELDS, i, proof,
		                             sizeof(proof), &count) == FZN_BLOB_OK,
		        "the proof for field %u did not build", i);
		CHECK(fzn_disclose_verify(&HASH, st.committed[i], st.lens[i], i, FIELDS, proof,
		                          count, st.root, &field, &field_len)
		              == FZN_DISCLOSE_OK,
		      "field %u did not verify against the root that commits it", i);
		CHECK(field_len == strlen(FIELDS_TEXT[i])
		              && memcmp(field, FIELDS_TEXT[i], field_len) == 0,
		      "field %u came back as something else", i);
		/* THE VIEW POINTS INTO THE CALLER'S BUFFER, past the salt, and
		 * not at a copy. project.md sec 86 is what happens when the
		 * buffer behind such a view goes out of scope first. */
		CHECK(field == st.committed[i] + FZN_DISCLOSE_SALT_LEN,
		      "field %u was handed back as a copy rather than a view", i);
	}
}

/*
 * THE CASE THE MODULE EXISTS FOR.
 *
 * A leaf is a hash of a committed field. If the field alone were hashed,
 * anybody holding the root could search its domain -- and a recipient holding
 * one proof holds the sibling standing where a withheld field is, so the
 * search is one they can actually run.
 *
 * The salt is asserted here by what it DEFEATS, not by being present. A
 * one-byte field has 256 possible values; the search below tries all of them.
 * With the salt known it finds the field, which is what makes the failure to
 * find it without the salt attributable to the salt rather than to a loop
 * that could not have matched anything.
 */
static void test_the_salt_is_what_hides_the_field(void)
{
	uint8_t committed[FZN_DISCLOSE_MAX_LEN];
	uint8_t leaf[FZN_BLOB_HASH_LEN];
	uint8_t again[FZN_DISCLOSE_MAX_LEN];
	uint8_t leaf_again[FZN_BLOB_HASH_LEN];
	uint8_t candidate[FZN_DISCLOSE_MAX_LEN];
	uint8_t guess_leaf[FZN_BLOB_HASH_LEN];
	uint8_t wrong_salt[FZN_DISCLOSE_SALT_LEN];
	const uint8_t secret = 0xc7u;
	size_t len = 0, len_again = 0;
	unsigned g;
	int found_with_salt = 0;
	int found_without = 0;

	salt_counter = 0;
	REQUIRE(fzn_disclose_commit(&RNG, &secret, 1u, committed, sizeof(committed), &len)
	                == FZN_DISCLOSE_OK,
	        "the one-byte field did not commit");
	REQUIRE(fzn_disclose_leaf(&HASH, committed, len, leaf) == FZN_DISCLOSE_OK,
	        "the leaf did not hash");

	/* A FRESH SALT EVERY TIME. Two commitments of the same field must not
	 * share a leaf, or a recipient learns that two statements say the same
	 * thing without being shown either. */
	REQUIRE(fzn_disclose_commit(&RNG, &secret, 1u, again, sizeof(again), &len_again)
	                == FZN_DISCLOSE_OK,
	        "the second commitment failed");
	REQUIRE(fzn_disclose_leaf(&HASH, again, len_again, leaf_again) == FZN_DISCLOSE_OK,
	        "the second leaf did not hash");
	CHECK(memcmp(committed, again, FZN_DISCLOSE_SALT_LEN) != 0,
	      "two commitments of one field drew the same salt");
	CHECK(memcmp(leaf, leaf_again, FZN_BLOB_HASH_LEN) != 0,
	      "two commitments of one field have the same leaf, so a recipient can tell "
	      "they say the same thing without being shown either");

	/* THE SEARCH, WITH THE SALT KNOWN. It must succeed, or the refusal
	 * below is evidence of nothing. */
	memcpy(candidate, committed, FZN_DISCLOSE_SALT_LEN);
	for (g = 0; g < 256u; g++) {
		candidate[FZN_DISCLOSE_SALT_LEN] = (uint8_t)g;
		if (fzn_disclose_leaf(&HASH, candidate, FZN_DISCLOSE_SALT_LEN + 1u,
		                      guess_leaf) != FZN_DISCLOSE_OK)
			continue;
		if (memcmp(guess_leaf, leaf, FZN_BLOB_HASH_LEN) == 0) {
			found_with_salt = 1;
			CHECK((uint8_t)g == secret,
			      "the search matched a leaf but recovered the wrong byte, so it "
			      "is not the search it claims to be");
			break;
		}
	}
	CHECK(found_with_salt,
	      "knowing the salt did not recover a one-byte field, so the search is broken "
	      "and the refusal below proves nothing");

	/* AND THE SAME SEARCH WITHOUT IT. One wrong salt stands for every salt
	 * an attacker does not hold: 2^128 of them, of which this is one. */
	memcpy(wrong_salt, committed, FZN_DISCLOSE_SALT_LEN);
	wrong_salt[0] = (uint8_t)(wrong_salt[0] ^ 0xffu);
	memcpy(candidate, wrong_salt, FZN_DISCLOSE_SALT_LEN);
	for (g = 0; g < 256u; g++) {
		candidate[FZN_DISCLOSE_SALT_LEN] = (uint8_t)g;
		if (fzn_disclose_leaf(&HASH, candidate, FZN_DISCLOSE_SALT_LEN + 1u,
		                      guess_leaf) != FZN_DISCLOSE_OK)
			continue;
		if (memcmp(guess_leaf, leaf, FZN_BLOB_HASH_LEN) == 0)
			found_without = 1;
	}
	CHECK(!found_without,
	      "the field was recovered without the salt, so the salt is not doing what "
	      "this module exists to do");
}

static void test_a_disclosure_is_bound_to_its_place(void)
{
	struct statement st;
	uint8_t proof[FZN_BLOB_MAX_DEPTH * FZN_BLOB_HASH_LEN];
	uint8_t bent[FZN_DISCLOSE_MAX_LEN];
	uint8_t other_root[FZN_BLOB_HASH_LEN];
	const uint8_t *field = NULL;
	size_t field_len = 0;
	unsigned count = 0;

	REQUIRE(commit_all(&st, FIELDS_TEXT, FIELDS), "the statement did not commit");
	REQUIRE(fzn_blob_proof_build(&HASH, &st.leaves[0][0], FIELDS, 1u, proof, sizeof(proof),
	                             &count) == FZN_BLOB_OK,
	        "the proof did not build");

	/* THE RIGHT FIELD AT THE WRONG INDEX. A disclosure says "this is field
	 * one of four"; moving it is a different claim about the same
	 * statement, and the tree's shape refuses it. */
	CHECK(fzn_disclose_verify(&HASH, st.committed[1], st.lens[1], 2u, FIELDS, proof, count,
	                          st.root, &field, &field_len) == FZN_DISCLOSE_ERR_PROOF,
	      "a field verified at an index that is not its own");

	/* A SMALLER COUNT IS A DIFFERENT STATEMENT. `leaf_count` is bound into
	 * the root, so a sender cannot pretend a statement has fewer fields
	 * than it has -- which would be hiding their EXISTENCE rather than
	 * their contents. */
	CHECK(fzn_disclose_verify(&HASH, st.committed[1], st.lens[1], 1u, 2u, proof, count,
	                          st.root, &field, &field_len) == FZN_DISCLOSE_ERR_PROOF,
	      "a recipient accepted a claim that the statement has fewer fields than it has");

	/* A TAMPERED FIELD. */
	memcpy(bent, st.committed[1], st.lens[1]);
	bent[FZN_DISCLOSE_SALT_LEN] = (uint8_t)(bent[FZN_DISCLOSE_SALT_LEN] ^ 0x40u);
	CHECK(fzn_disclose_verify(&HASH, bent, st.lens[1], 1u, FIELDS, proof, count, st.root,
	                          &field, &field_len) == FZN_DISCLOSE_ERR_PROOF,
	      "a modified field verified against the issuer's root");

	/* A TAMPERED SALT, which is the same refusal by a different route and
	 * worth its own case: a recipient who changes the salt changes the
	 * leaf, so a disclosure cannot be re-salted to say something else. */
	memcpy(bent, st.committed[1], st.lens[1]);
	bent[0] = (uint8_t)(bent[0] ^ 0x40u);
	CHECK(fzn_disclose_verify(&HASH, bent, st.lens[1], 1u, FIELDS, proof, count, st.root,
	                          &field, &field_len) == FZN_DISCLOSE_ERR_PROOF,
	      "a re-salted field verified against the issuer's root");

	/* ANOTHER STATEMENT'S ROOT. */
	memcpy(other_root, st.root, sizeof(other_root));
	other_root[0] = (uint8_t)(other_root[0] ^ 0x40u);
	CHECK(fzn_disclose_verify(&HASH, st.committed[1], st.lens[1], 1u, FIELDS, proof, count,
	                          other_root, &field, &field_len) == FZN_DISCLOSE_ERR_PROOF,
	      "a field verified against a root that does not commit it");

	/* AND A REFUSAL HANDS BACK NOTHING, on every one of those paths. A
	 * caller that reads the field without reading the status must not get
	 * the last one that verified. */
	CHECK(field == NULL && field_len == 0,
	      "a refused disclosure left a field with the caller");

	/* THE CONTROL: the same disclosure at its own index verifies, so every
	 * refusal above is about what was changed rather than about a fixture
	 * that never worked. */
	CHECK(fzn_disclose_verify(&HASH, st.committed[1], st.lens[1], 1u, FIELDS, proof, count,
	                          st.root, &field, &field_len) == FZN_DISCLOSE_OK,
	      "the untouched disclosure did not verify, so the refusals above pass for the "
	      "wrong reason");
}

static void test_an_empty_field_is_still_a_field(void)
{
	uint8_t committed[FZN_DISCLOSE_MAX_LEN];
	uint8_t other[FZN_DISCLOSE_MAX_LEN];
	const uint8_t *field = NULL;
	size_t len = 0, other_len = 0, field_len = 99u;

	salt_counter = 40u;
	REQUIRE(fzn_disclose_commit(&RNG, NULL, 0, committed, sizeof(committed), &len)
	                == FZN_DISCLOSE_OK,
	        "an empty field would not commit");
	CHECK(len == FZN_DISCLOSE_SALT_LEN, "an empty field committed to %zu bytes", len);
	CHECK(fzn_disclose_field(committed, len, &field, &field_len) == FZN_DISCLOSE_OK
	              && field_len == 0,
	      "an empty field did not read back as empty");

	/* AND IT IS STILL HIDDEN. Without a salt every empty field in every
	 * statement would share one leaf hash and be recognisable at sight,
	 * which is the one case where "there is nothing to hide" is wrong: the
	 * fact that this field is empty is itself the content. */
	REQUIRE(fzn_disclose_commit(&RNG, NULL, 0, other, sizeof(other), &other_len)
	                == FZN_DISCLOSE_OK,
	        "the second empty field would not commit");
	CHECK(memcmp(committed, other, FZN_DISCLOSE_SALT_LEN) != 0,
	      "two empty fields committed identically, so an empty one is recognisable");
}

static void test_a_refusing_source_leaves_the_buffer_alone(void)
{
	uint8_t out[FZN_DISCLOSE_MAX_LEN];
	static const uint8_t FIELD[] = "something worth hiding";
	size_t len = 0;
	size_t i;
	int untouched = 1;

	memset(out, 0xee, sizeof(out));
	CHECK(fzn_disclose_commit(&NO_RNG, FIELD, sizeof(FIELD), out, sizeof(out), &len)
	              == FZN_DISCLOSE_ERR_NO_SALT,
	      "a refusing entropy source was not reported");
	for (i = 0; i < sizeof(out); i++)
		untouched = untouched && out[i] == 0xeeu;
	CHECK(untouched,
	      "a refused commitment wrote into the caller's buffer -- and what it would "
	      "have written is the field itself");
	CHECK(len == 0, "a refused commitment reported a length");
}

static void test_every_guard_refuses_its_own_argument(void)
{
	uint8_t out[FZN_DISCLOSE_MAX_LEN];
	uint8_t leaf[FZN_BLOB_HASH_LEN];
	uint8_t root[FZN_BLOB_HASH_LEN];
	static const uint8_t FIELD[] = "x";
	const uint8_t *field = NULL;
	size_t len = 0, field_len = 0;

	memset(root, 0x11, sizeof(root));

	CHECK(fzn_disclose_commit(&RNG, FIELD, 1u, NULL, sizeof(out), &len)
	              == FZN_DISCLOSE_ERR_MALFORMED, "commit accepted a null out");
	CHECK(fzn_disclose_commit(&RNG, FIELD, 1u, out, sizeof(out), NULL)
	              == FZN_DISCLOSE_ERR_MALFORMED, "commit accepted a null out_len");
	CHECK(fzn_disclose_commit(&RNG, NULL, 1u, out, sizeof(out), &len)
	              == FZN_DISCLOSE_ERR_MALFORMED, "commit accepted a null field with a length");
	CHECK(fzn_disclose_commit(&RNG, FIELD, FZN_DISCLOSE_MAX_FIELD + 1u, out, sizeof(out),
	                          &len) == FZN_DISCLOSE_ERR_MALFORMED,
	      "commit accepted a field past the maximum");
	CHECK(fzn_disclose_commit(&RNG, FIELD, 1u, out, FZN_DISCLOSE_SALT_LEN, &len)
	              == FZN_DISCLOSE_ERR_MALFORMED, "commit accepted a buffer one byte short");
	CHECK(fzn_disclose_commit(NULL, FIELD, 1u, out, sizeof(out), &len)
	              == FZN_DISCLOSE_ERR_NO_SALT, "commit accepted a null source");

	CHECK(fzn_disclose_leaf(NULL, out, FZN_DISCLOSE_MAX_LEN, leaf) == FZN_DISCLOSE_ERR_HASH,
	      "leaf accepted a null hash");
	CHECK(fzn_disclose_leaf(&HASH, out, FZN_DISCLOSE_MAX_LEN, NULL)
	              == FZN_DISCLOSE_ERR_MALFORMED, "leaf accepted a null out");
	CHECK(fzn_disclose_leaf(&HASH, NULL, FZN_DISCLOSE_MAX_LEN, leaf)
	              == FZN_DISCLOSE_ERR_SHAPE, "leaf accepted null bytes");
	CHECK(fzn_disclose_leaf(&HASH, out, FZN_DISCLOSE_SALT_LEN - 1u, leaf)
	              == FZN_DISCLOSE_ERR_SHAPE, "leaf accepted something shorter than a salt");
	CHECK(fzn_disclose_leaf(&HASH, out, FZN_DISCLOSE_MAX_LEN + 1u, leaf)
	              == FZN_DISCLOSE_ERR_SHAPE, "leaf accepted something past the maximum");

	CHECK(fzn_disclose_field(out, FZN_DISCLOSE_MAX_LEN, NULL, &field_len)
	              == FZN_DISCLOSE_ERR_MALFORMED, "field accepted a null out");
	CHECK(fzn_disclose_field(out, FZN_DISCLOSE_SALT_LEN - 1u, &field, &field_len)
	              == FZN_DISCLOSE_ERR_SHAPE, "field accepted something shorter than a salt");

	CHECK(fzn_disclose_verify(&HASH, out, FZN_DISCLOSE_MAX_LEN, 0, 1u, NULL, 0, NULL,
	                          &field, &field_len) == FZN_DISCLOSE_ERR_MALFORMED,
	      "verify accepted a null root");
	CHECK(fzn_disclose_verify(&HASH, out, FZN_DISCLOSE_MAX_LEN, 0, 1u, NULL, 0, root, NULL,
	                          &field_len) == FZN_DISCLOSE_ERR_MALFORMED,
	      "verify accepted a null field_out");
}

static void test_err_str_names_every_arm(void)
{
	CHECK(strcmp(fzn_disclose_err_str(FZN_DISCLOSE_OK), "ok") == 0, "OK is misnamed");
	CHECK(strcmp(fzn_disclose_err_str(FZN_DISCLOSE_ERR_MALFORMED), "unknown") != 0,
	      "MALFORMED falls through to unknown");
	CHECK(strcmp(fzn_disclose_err_str(FZN_DISCLOSE_ERR_SHAPE), "unknown") != 0,
	      "SHAPE falls through to unknown");
	CHECK(strcmp(fzn_disclose_err_str(FZN_DISCLOSE_ERR_NO_SALT), "unknown") != 0,
	      "NO_SALT falls through to unknown");
	CHECK(strcmp(fzn_disclose_err_str(FZN_DISCLOSE_ERR_HASH), "unknown") != 0,
	      "HASH falls through to unknown");
	CHECK(strcmp(fzn_disclose_err_str(FZN_DISCLOSE_ERR_PROOF), "unknown") != 0,
	      "PROOF falls through to unknown");
	CHECK(strcmp(fzn_disclose_err_str((fzn_disclose_err_t)99), "unknown") == 0,
	      "a value outside the enum is not called unknown");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	CHECK(0, "deliberate");
	CHECK(failures == before + 1, "a failing check did not count");
	failures = before;
	checks -= 1;
}

/*
 * EVERY OPERAND OF EVERY GUARD, not the first one of each.
 *
 * The guards are conjunctions and the suite failed the first operand, so
 * `make coverage` reported the rest as never taken both ways while the guard
 * looked tested. sec 88 measured what an unreached operand is worth: the
 * operand after the first is what stands between a partially initialised
 * caller and a null dereference, and a vtable with a null member is what a
 * consumer has who filled it in two steps.
 */
static void test_the_operands_the_first_one_hides(void)
{
	fzn_random_ops_t no_fill = { NULL, NULL };
	fzn_hash_ops_t no_hash = { NULL, NULL };
	uint8_t field[8], committed[FZN_DISCLOSE_SALT_LEN + 8];
	uint8_t leaf[FZN_BLOB_HASH_LEN];
	size_t committed_len = 0;

	memset(field, 0x71, sizeof(field));
	memset(committed, 0x72, sizeof(committed));

	/* THE RNG SEAM'S SECOND OPERAND. A commit with no salt source must
	 * refuse rather than fall back to a predictable salt, which is the
	 * whole reason the convention exists (sec 72). */
	CHECK(fzn_disclose_commit(NULL, field, sizeof(field), committed, sizeof(committed),
	                          &committed_len)
	      == FZN_DISCLOSE_ERR_NO_SALT, "commit accepted a null rng");
	CHECK(fzn_disclose_commit(&no_fill, field, sizeof(field), committed, sizeof(committed),
	                          &committed_len)
	      == FZN_DISCLOSE_ERR_NO_SALT, "commit accepted an rng struct whose fill member is null");

	/* And the hash seam's, on both functions that take one. */
	CHECK(fzn_disclose_leaf(NULL, committed, sizeof(committed), leaf) == FZN_DISCLOSE_ERR_HASH,
	      "leaf accepted a null hash");
	CHECK(fzn_disclose_leaf(&no_hash, committed, sizeof(committed), leaf)
	      == FZN_DISCLOSE_ERR_HASH, "leaf accepted a hash struct whose member is null");
	CHECK(fzn_disclose_leaf(&HASH, committed, sizeof(committed), NULL)
	      == FZN_DISCLOSE_ERR_MALFORMED, "leaf accepted a null out");
}

int main(void)
{
	test_one_root_serves_every_field();
	test_the_salt_is_what_hides_the_field();
	test_a_disclosure_is_bound_to_its_place();
	test_an_empty_field_is_still_a_field();
	test_a_refusing_source_leaves_the_buffer_alone();
	test_every_guard_refuses_its_own_argument();
	test_err_str_names_every_arm();
	test_the_suite_can_tell_pass_from_fail();

	test_the_operands_the_first_one_hides();

	printf("disclose_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
