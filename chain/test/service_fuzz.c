/*
 * A fuzz harness for chain/service.c: distinct triples, distinct ids.
 *
 * WHAT THE HEADER CLAIMS is an injectivity, and it names the failure it is
 * guarding against in the same breath: "the encoding is unambiguous because
 * the variable field is last ... no two distinct triples produce the same
 * input. If a field is ever added, it goes BEFORE the name or it brings a
 * length prefix with it; appending one after a variable-length field is how
 * two different capabilities come to hash the same."
 *
 * So the oracle is a map from derived id back to the triple that produced
 * it. Every derivation is looked up; a hit must carry the same (service,
 * product, name) or two capabilities have become one -- which, in a system
 * where a verifier derives the capability it requires and compares, is one
 * grant standing for another.
 *
 * THE NAMES CARRY ZERO BYTES AND VARY IN LENGTH, deliberately, and the
 * first draft of this comment gave the wrong reason. It said the fixture
 * existed to catch the product being moved after the name. Sabotaged, that
 * SURVIVED -- correctly: a fixed four-byte field after the only variable
 * one is still uniquely decodable from the right, so the encoding stays
 * injective and the oracle is right to find no collision. The header's
 * hazard is a SECOND variable-length field, or a hash that does not see
 * the length. What the zero bytes reach is the second: a derivation that
 * pads its input to a fixed size and hashes all of it makes "a" and "a\0"
 * one capability, and only a name that IS a shorter name plus zeros can
 * show it. A fixture of printable names of one length would never reach
 * it. The varying length is what reaches a name hashed in part -- two
 * six-byte names sharing a four-byte prefix -- which `service_test` cannot
 * see, because "read" and "write" differ in their first byte.
 *
 * THE HASH IS A STUB and that is fine: what is on trial is the ENCODING that
 * feeds it. A collision in a 32-byte output from a decent stub over short
 * inputs is astronomically unlikely, so a collision found here is the
 * encoding, not the hash. The pair derivation is checked for the same
 * injectivity plus its own refusal: PRODUCT_ANY as the record's product is
 * refused, because a record does not belong to every project.
 */

#include "../service.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u
#define FUZZ_MIN_CASES 1000u

#define SERVICES 3u
#define PRODUCTS 3u
#define NAME_MAX 6u
#define DERIVATIONS 24u

static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	(void)ctx;
	h ^= (uint64_t)out_len;
	h *= 0x100000001b3ull;
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

struct seen {
	fzn_cap_id_t id;
	uint32_t service, product;
	uint8_t name[NAME_MAX];
	size_t name_len;
	int used;
};

struct coverage {
	unsigned long derived;
	unsigned long repeated_same;
	unsigned long zero_in_name;
	unsigned long empty_name;
	unsigned long refused_service;
	unsigned long refused_product;
	unsigned long refused_long;
	unsigned long pair_refused_any;
	unsigned long pair_derived;
};

static uint32_t next(uint32_t *state)
{
	*state ^= *state << 13;
	*state ^= *state >> 17;
	*state ^= *state << 5;
	return *state;
}

static int record(struct seen *table, unsigned *used, const fzn_cap_id_t *id,
                  uint32_t service, uint32_t product, const uint8_t *name, size_t name_len,
                  struct coverage *cov)
{
	unsigned i;

	for (i = 0; i < *used; i++) {
		if (memcmp(&table[i].id, id, sizeof(*id)) != 0)
			continue;
		if (table[i].service == service && table[i].product == product &&
		    table[i].name_len == name_len && memcmp(table[i].name, name, name_len) == 0) {
			cov->repeated_same++;
			return 1;
		}
		printf("  MODEL: (%u, %u, %zu-byte name) and (%u, %u, %zu-byte name) derived "
		       "the same capability -- two grants have become one\n",
		       table[i].service, table[i].product, table[i].name_len, service,
		       product, name_len);
		return 0;
	}
	if (*used < DERIVATIONS * 2u) {
		table[*used].id = *id;
		table[*used].service = service;
		table[*used].product = product;
		memcpy(table[*used].name, name, name_len);
		table[*used].name_len = name_len;
		table[*used].used = 1;
		(*used)++;
	}
	return 1;
}

static int fuzz_one(uint32_t seed, struct coverage *cov)
{
	uint32_t state = seed;
	struct seen table[DERIVATIONS * 2u];
	unsigned used = 0, d;

	memset(table, 0, sizeof(table));

	for (d = 0; d < DERIVATIONS; d++) {
		uint32_t service = next(&state) % (SERVICES + 1u);   /* 0 is NONE */
		uint32_t product = next(&state) % (PRODUCTS + 1u);   /* 0 is NONE */
		uint8_t name[NAME_MAX + 1u];
		size_t name_len = next(&state) % (NAME_MAX + 1u);
		fzn_cap_id_t id, before, scoped, any;
		fzn_chain_err_t err;
		size_t i;
		int has_zero = 0;

		if ((next(&state) % 5u) == 0u)
			product = FZN_PRODUCT_ANY;
		/* NAMES WITH ZEROS IN THEM, because a big-endian small integer is
		 * mostly zeros and the ambiguity needs a name that can look like
		 * one. */
		for (i = 0; i < name_len; i++) {
			name[i] = (uint8_t)((next(&state) % 3u) == 0u ? 0u : 'a' + (next(&state) % 4u));
			if (name[i] == 0u)
				has_zero = 1;
		}

		memset(&before, 0x5a, sizeof(before));
		id = before;
		err = fzn_service_capability(service, product, name_len ? name : NULL, name_len,
		                             &HASH, &id);

		if (service == FZN_SERVICE_NONE || product == FZN_PRODUCT_NONE) {
			if (err != FZN_CHAIN_ERR_MALFORMED) {
				printf("  MODEL: an unspelled %s was accepted -- a capability "
				       "naming no service now exists to be presented\n",
				       service == FZN_SERVICE_NONE ? "service" : "product");
				return 1;
			}
			if (memcmp(&id, &before, sizeof(id)) != 0) {
				printf("  MODEL: a refused derivation wrote to out\n");
				return 1;
			}
			if (service == FZN_SERVICE_NONE)
				cov->refused_service++;
			else
				cov->refused_product++;
			continue;
		}
		if (err != FZN_CHAIN_OK) {
			printf("  MODEL: a well-formed derivation was refused with %d\n", (int)err);
			return 1;
		}
		cov->derived++;
		if (has_zero)
			cov->zero_in_name++;
		if (name_len == 0u)
			cov->empty_name++;
		if (!record(table, &used, &id, service, product, name, name_len, cov))
			return 1;

		/* THE PAIR. Same injectivity for both halves, and the header's
		 * one refusal: a record's product cannot be ANY. */
		err = fzn_service_capability_pair(service, product, name_len ? name : NULL,
		                                  name_len, &HASH, &scoped, &any);
		if (product == FZN_PRODUCT_ANY) {
			if (err != FZN_CHAIN_ERR_MALFORMED) {
				printf("  MODEL: a pair was derived for a record whose product is "
				       "ANY, which asks the wrong question\n");
				return 1;
			}
			cov->pair_refused_any++;
			continue;
		}
		if (err != FZN_CHAIN_OK) {
			printf("  MODEL: the pair was refused with %d\n", (int)err);
			return 1;
		}
		if (memcmp(&scoped, &id, sizeof(id)) != 0) {
			printf("  MODEL: the pair's scoped half is not the single derivation "
			       "for the same triple\n");
			return 1;
		}
		if (memcmp(&scoped, &any, sizeof(id)) == 0) {
			printf("  MODEL: the scoped and see-everything capabilities are the "
			       "same id, so the filter filters nothing\n");
			return 1;
		}
		if (!record(table, &used, &any, service, FZN_PRODUCT_ANY, name, name_len, cov))
			return 1;
		cov->pair_derived++;
	}

	/* A NAME PAST THE BOUND is refused, and out is untouched. */
	{
		uint8_t big[FZN_SERVICE_NAME_MAX + 1u];
		fzn_cap_id_t id, before;

		memset(big, 'x', sizeof(big));
		memset(&before, 0x5a, sizeof(before));
		id = before;
		if (fzn_service_capability(1u, 1u, big, sizeof(big), &HASH, &id) !=
		    FZN_CHAIN_ERR_MALFORMED || memcmp(&id, &before, sizeof(id)) != 0) {
			printf("  MODEL: a name past FZN_SERVICE_NAME_MAX was accepted or wrote "
			       "to out\n");
			return 1;
		}
		cov->refused_long++;
	}
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
		printf("service_fuzz: %lu cases is below FUZZ_MIN_CASES (%u).\n", cases,
		       (unsigned)FUZZ_MIN_CASES);
		return 1;
	}

	for (c = 0; c < cases; c++) {
		if (fuzz_one((uint32_t)c + 1u, &cov)) {
			printf("service_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	/* `zero_in_name` IS THE FLOOR THAT MATTERS: without names carrying zero
	 * bytes a derivation that pads its input and hashes the padding is
	 * unreachable, and that sabotage would survive. */
	if (cov.derived < floor_of(cases, 1u) || cov.repeated_same < floor_of(cases, 4u)
	    || cov.zero_in_name < floor_of(cases, 1u) || cov.empty_name < floor_of(cases, 4u)
	    || cov.refused_service < floor_of(cases, 1u)
	    || cov.refused_product < floor_of(cases, 1u)
	    || cov.pair_refused_any < floor_of(cases, 2u) || cov.pair_derived < floor_of(cases, 1u)) {
		printf("service_fuzz: REACHED TOO LITTLE -- %lu derived, %lu repeats, %lu with "
		       "a zero in the name, %lu empty names, %lu/%lu refused service/product, "
		       "%lu pairs refused ANY, %lu pairs derived, in %lu cases.\n",
		       cov.derived, cov.repeated_same, cov.zero_in_name, cov.empty_name,
		       cov.refused_service, cov.refused_product, cov.pair_refused_any,
		       cov.pair_derived, cases);
		return 1;
	}

	printf("service_fuzz: %lu cases, %lu derived (%lu with a zero byte in the name, "
	       "%lu empty), %lu same-triple repeats agreed, %lu/%lu unspelled refused, %lu "
	       "long names refused, %lu pairs refused ANY, %lu pairs derived, and no two "
	       "distinct triples ever shared an id\n",
	       cases, cov.derived, cov.zero_in_name, cov.empty_name, cov.repeated_same,
	       cov.refused_service, cov.refused_product, cov.refused_long,
	       cov.pair_refused_any, cov.pair_derived);
	return 0;
}
#endif
