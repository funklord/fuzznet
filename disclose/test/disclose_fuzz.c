/*
 * A fuzz harness for the disclosure verifier.
 *
 * WHY THIS ONE. `fzn_disclose_verify` is a decoder of stranger bytes and was
 * the only one in this library without a harness -- project.md sec 77 made
 * that argument for `provision/` and this module, added hours later, became
 * its exception. EVERY argument it takes arrives from the sender: the
 * committed field, the index it claims, the number of fields the statement
 * has, the sibling hashes, and the root it is checked against. A recipient
 * verifies nothing about any of them beforehand, because there is nothing to
 * verify -- a disclosure is a claim.
 *
 * THE PROPERTIES ARE ABOUT BINDING, which is what a spot invariant cannot
 * see. An overrun would be caught by a sanitizer -- `make check` runs this
 * suite under one, sec 86 -- and none of the following would:
 *
 *   1. A DISCLOSURE IS BOUND TO ITS PLACE. What verifies at index i must not
 *      verify at any other, or a recipient can be told the street is the
 *      bearing. The tree's shape is what refuses it, and the harness offers
 *      every wrong index rather than one.
 *   2. A DISCLOSURE IS BOUND TO ITS STATEMENT. `field_count` is folded into
 *      the root, so claiming a statement has fewer fields than it has is a
 *      different root -- that is what stops a sender hiding the EXISTENCE of
 *      fields rather than their contents.
 *   3. NOTHING IS HANDED BACK ON A REFUSAL. A caller that reads the field
 *      without reading the status must get nothing, not the last field that
 *      verified.
 *   4. WHAT COMES BACK IS A VIEW, not a copy: the pointer is the caller's own
 *      buffer past the salt. sec 86 is what a view whose buffer died looks
 *      like, and it looks like a pass.
 *
 * MUTATIONS ARE ON A REAL STATEMENT, not on random bytes. A uniformly random
 * buffer is refused at the leaf hash and reaches nothing; the cases with
 * teeth are a genuine disclosure with one bit of the field bent, one bit of
 * the salt, one bit of a sibling, one bit of the root, or a number changed.
 * Floors below are on those STATES rather than on call counts, for
 * `prekey_fuzz`'s reason.
 */

#include "../disclose.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u
#define FUZZ_MIN_CASES 1000u

/* Enough fields for a tree with a real climb and few enough that every wrong
 * index can be offered rather than sampled. */
#define MAX_FIELDS 8u
#define MAX_FIELD_BYTES 48u

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

static uint32_t salt_state = 1u;

static uint32_t next(uint32_t *state)
{
	*state ^= *state << 13;
	*state ^= *state >> 17;
	*state ^= *state << 5;
	return *state;
}

/* Deterministic, so a failing case is reproducible from its seed alone, and
 * distinct per call so that two commitments never share a salt -- which is
 * the property the module exists for and would be silently lost by a source
 * that repeated. */
static int counting_fill(void *ctx, uint8_t *out, size_t len)
{
	size_t i;

	(void)ctx;
	for (i = 0; i < len; i++)
		out[i] = (uint8_t)(next(&salt_state) >> 11);
	return 1;
}

static const fzn_random_ops_t RNG = { counting_fill, NULL };

struct coverage {
	unsigned long verified;
	unsigned long refused;
	unsigned long bent_field;
	unsigned long bent_salt;
	unsigned long bent_proof;
	unsigned long bent_root;
	unsigned long wrong_index;
	unsigned long wrong_count;
	unsigned long empty_fields;
};

struct statement {
	uint8_t committed[MAX_FIELDS][FZN_DISCLOSE_SALT_LEN + MAX_FIELD_BYTES];
	size_t lens[MAX_FIELDS];
	uint8_t leaves[MAX_FIELDS][FZN_BLOB_HASH_LEN];
	uint8_t root[FZN_BLOB_HASH_LEN];
	unsigned n;
};

static int build(struct statement *st, uint32_t *state, struct coverage *cov)
{
	fzn_blob_tree_t tree;
	unsigned i;

	st->n = 1u + (next(state) % MAX_FIELDS);
	fzn_blob_tree_init(&tree);

	for (i = 0; i < st->n; i++) {
		uint8_t field[MAX_FIELD_BYTES];
		size_t len = next(state) % (MAX_FIELD_BYTES + 1u);
		size_t k;

		if (len == 0)
			cov->empty_fields++;
		for (k = 0; k < len; k++)
			field[k] = (uint8_t)next(state);

		if (fzn_disclose_commit(&RNG, field, len, st->committed[i],
		                        sizeof(st->committed[i]), &st->lens[i])
		    != FZN_DISCLOSE_OK)
			return 0;
		if (fzn_disclose_leaf(&HASH, st->committed[i], st->lens[i], st->leaves[i])
		    != FZN_DISCLOSE_OK)
			return 0;
		if (fzn_blob_tree_push(&HASH, &tree, st->leaves[i]) != FZN_BLOB_OK)
			return 0;
	}

	return fzn_blob_tree_root(&HASH, &tree, st->root) == FZN_BLOB_OK;
}

/* Every refusal must look the same from outside: a status, and nothing in the
 * caller's out-parameters. Checked after every call rather than at the end,
 * because a decoder that is briefly wrong and then right is still wrong. */
static int refusal_is_clean(fzn_disclose_err_t err, const uint8_t *field, size_t field_len)
{
	if (err == FZN_DISCLOSE_OK)
		return 1;
	return field == NULL && field_len == 0;
}

static int fuzz_one(uint32_t seed, struct coverage *cov)
{
	uint32_t state = seed ? seed : 1u;
	struct statement st;
	uint8_t proof[FZN_BLOB_MAX_DEPTH * FZN_BLOB_HASH_LEN];
	uint8_t bent[FZN_DISCLOSE_SALT_LEN + MAX_FIELD_BYTES];
	uint8_t root[FZN_BLOB_HASH_LEN];
	const uint8_t *field = NULL;
	size_t field_len = 0;
	unsigned count = 0;
	unsigned index;
	unsigned shape;
	fzn_disclose_err_t err;

	salt_state = seed ? seed : 1u;
	if (!build(&st, &state, cov))
		return 1;

	index = next(&state) % st.n;
	if (fzn_blob_proof_build(&HASH, &st.leaves[0][0], st.n, index, proof, sizeof(proof),
	                         &count) != FZN_BLOB_OK)
		return 1;

	/* ---- the untouched disclosure ---------------------------------- */
	err = fzn_disclose_verify(&HASH, st.committed[index], st.lens[index], index, st.n,
	                          proof, count, st.root, &field, &field_len);
	if (err != FZN_DISCLOSE_OK)
		return 1;
	cov->verified++;
	if (field_len != st.lens[index] - FZN_DISCLOSE_SALT_LEN)
		return 1;
	/* A VIEW, not a copy. */
	if (field != st.committed[index] + FZN_DISCLOSE_SALT_LEN)
		return 1;

	/* ---- bound to its place: every OTHER index must refuse ---------- */
	if (st.n > 1u) {
		unsigned j;

		for (j = 0; j < st.n; j++) {
			if (j == index)
				continue;
			field = NULL;
			field_len = 0;
			err = fzn_disclose_verify(&HASH, st.committed[index], st.lens[index], j,
			                          st.n, proof, count, st.root, &field,
			                          &field_len);
			if (err == FZN_DISCLOSE_OK)
				return 1;
			if (!refusal_is_clean(err, field, field_len))
				return 1;
		}
		cov->wrong_index++;
	}

	/* ---- bound to its statement: a different field count ------------ */
	{
		uint64_t claimed = 1u + (next(&state) % (MAX_FIELDS + 2u));

		if (claimed != st.n) {
			field = NULL;
			field_len = 0;
			err = fzn_disclose_verify(&HASH, st.committed[index], st.lens[index],
			                          index, claimed, proof, count, st.root, &field,
			                          &field_len);
			if (err == FZN_DISCLOSE_OK)
				return 1;
			if (!refusal_is_clean(err, field, field_len))
				return 1;
			cov->wrong_count++;
		}
	}

	/* ---- one bit bent, in one of four places ------------------------ */
	shape = next(&state) % 4u;
	memcpy(bent, st.committed[index], st.lens[index]);
	memcpy(root, st.root, sizeof(root));

	if (shape == 0u && st.lens[index] > FZN_DISCLOSE_SALT_LEN) {
		size_t at = FZN_DISCLOSE_SALT_LEN
		            + (next(&state) % (st.lens[index] - FZN_DISCLOSE_SALT_LEN));

		bent[at] ^= (uint8_t)(1u << (next(&state) % 8u));
		cov->bent_field++;
	} else if (shape == 1u) {
		bent[next(&state) % FZN_DISCLOSE_SALT_LEN] ^= (uint8_t)(1u << (next(&state) % 8u));
		cov->bent_salt++;
	} else if (shape == 2u && count > 0u) {
		size_t at = next(&state) % ((size_t)count * FZN_BLOB_HASH_LEN);

		proof[at] ^= (uint8_t)(1u << (next(&state) % 8u));
		cov->bent_proof++;
	} else {
		root[next(&state) % FZN_BLOB_HASH_LEN] ^= (uint8_t)(1u << (next(&state) % 8u));
		cov->bent_root++;
	}

	field = NULL;
	field_len = 0;
	err = fzn_disclose_verify(&HASH, bent, st.lens[index], index, st.n, proof, count, root,
	                          &field, &field_len);
	if (err == FZN_DISCLOSE_OK)
		return 1;
	if (!refusal_is_clean(err, field, field_len))
		return 1;
	cov->refused++;

	return 0;
}

#ifdef FZN_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint32_t seed = 1u;
	size_t i;
	struct coverage cov = { 0, 0, 0, 0, 0, 0, 0, 0, 0 };

	for (i = 0; i < size; i++)
		seed = (seed * 31u) + data[i];
	if (seed == 0u)
		seed = 1u;
	(void)fuzz_one(seed, &cov);
	return 0;
}
#else

static unsigned long floor_of(unsigned long cases, unsigned long per)
{
	unsigned long f = cases / per;

	return f == 0u ? 1u : f;
}

int main(int argc, char **argv)
{
	unsigned long cases = FUZZ_DEFAULT_CASES;
	struct coverage cov = { 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	unsigned long c;

	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
	}

	if (cases < FUZZ_MIN_CASES) {
		printf("disclose_fuzz: %lu cases is below FUZZ_MIN_CASES (%u); every "
		       "coverage floor below that is cleared by a single lucky hit, so "
		       "this run will not report success. Re-run with %u or more.\n",
		       cases, (unsigned)FUZZ_MIN_CASES, (unsigned)FUZZ_MIN_CASES);
		return 1;
	}

	for (c = 0; c < cases; c++) {
		if (fuzz_one((uint32_t)c + 1u, &cov)) {
			printf("disclose_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	/* FLOORS ON STATES. A run that never bent a salt has not tested the
	 * thing this module exists for, however many disclosures it verified;
	 * one that never offered a wrong field count has not tested that a
	 * sender cannot hide how many fields a statement has. */
	if (cov.verified < floor_of(cases, 2u) || cov.refused < floor_of(cases, 2u)
	    || cov.bent_field < floor_of(cases, 8u) || cov.bent_salt < floor_of(cases, 8u)
	    || cov.bent_proof < floor_of(cases, 8u) || cov.bent_root < floor_of(cases, 8u)
	    || cov.wrong_index < floor_of(cases, 4u) || cov.wrong_count < floor_of(cases, 4u)
	    || cov.empty_fields < floor_of(cases, 20u)) {
		printf("disclose_fuzz: REACHED TOO LITTLE -- %lu verified, %lu refused, "
		       "%lu bent fields, %lu bent salts, %lu bent proofs, %lu bent roots, "
		       "%lu wrong indexes, %lu wrong counts, %lu empty fields in %lu "
		       "cases.\n",
		       cov.verified, cov.refused, cov.bent_field, cov.bent_salt,
		       cov.bent_proof, cov.bent_root, cov.wrong_index, cov.wrong_count,
		       cov.empty_fields, cases);
		return 1;
	}

	printf("disclose_fuzz: %lu cases, %lu verified, %lu refused, %lu bent fields, "
	       "%lu bent salts, %lu bent proofs, %lu bent roots, %lu wrong indexes, "
	       "%lu wrong counts, %lu empty fields; every disclosure stayed bound to its "
	       "place and its statement\n",
	       cases, cov.verified, cov.refused, cov.bent_field, cov.bent_salt,
	       cov.bent_proof, cov.bent_root, cov.wrong_index, cov.wrong_count,
	       cov.empty_fields);
	return 0;
}
#endif
