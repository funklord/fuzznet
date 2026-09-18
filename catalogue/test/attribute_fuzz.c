/*
 * A fuzz harness for the ATTRIBUTE codec in catalogue/catalogue.c
 * (fzn_catalogue_attribute_encode / _decode). The codec decodes RECORD BODIES
 * that arrive from other hosts over the network, in a cooperative and
 * poisoning-prone estate -- so the bytes are untrusted, and a decoder that
 * reads out of bounds or accepts a non-canonical form is a real hazard: the
 * first is a crash a peer can trigger, the second breaks the signature the
 * body is under (C8, "one encoding of each assertion, enforced"). This asks
 * those two properties of random and of valid input, and is careful about
 * which case proves which.
 *
 *   1. DECODE NEVER MISBEHAVES ON ARBITRARY BYTES. Random bodies of every
 *      length, including oversized ones, must return OK or an error and never
 *      read past the buffer (the sanitizer build is what makes this bite). A
 *      body that DOES decode must borrow its name and value from within the
 *      input, never outside it, and take its issuer and entity from the
 *      caller's pointers verbatim.
 *
 *   2. THE ENCODING IS CANONICAL, BOTH WAYS. A valid assertion encoded then
 *      decoded comes back field-for-field, and re-encoding the decoded form is
 *      byte-identical -- and, the sharper half, ANY random body that decodes
 *      must re-encode to exactly itself. That is the property the signature
 *      relies on: if two byte strings decoded to one assertion, a peer could
 *      re-sign a different spelling of what a host said.
 *
 * The second property is the one worth having: a defect that accepted a
 * trailing byte, or a slack length, would decode a body that did not
 * re-encode to itself and be caught here, while every field still looked
 * plausible.
 */

#include "../catalogue.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u

/* Below this the floors are cleared by a single lucky case. Same number and
 * reasoning as the other harnesses here. */
#define FUZZ_MIN_CASES 1000u

/* Oversized on purpose: larger than a record body, so the oversize rejection
 * and decode's bounds are exercised, not just the legal range. */
#define RAND_BODY_MAX 700u

struct coverage {
	unsigned long roundtrip;    /* valid assertions encoded and recovered */
	unsigned long rand_ok;      /* random bodies that decoded */
	unsigned long rand_refused; /* random bodies refused */
};

static uint32_t next(uint32_t *state)
{
	*state ^= *state << 13;
	*state ^= *state >> 17;
	*state ^= *state << 5;
	return *state;
}

/* A random VALID assertion: axes in range, name up to its field's max, value
 * bounded so the whole body fits a record. name/value borrow the buffers. */
static void rand_valid(uint32_t *st, fzn_catalogue_assertion_t *a,
                       uint8_t *name, uint8_t *value)
{
	size_t room, i;

	memset(a, 0, sizeof(*a));
	a->attr_class = (fzn_catalogue_class_t)(1u + next(st) % 3u);
	a->scope = (fzn_catalogue_scope_t)(1u + next(st) % 3u);
	a->merge = (fzn_catalogue_merge_t)(1u + next(st) % 3u);
	a->capability = (fzn_catalogue_capability_t)(1u + next(st) % 3u);
	a->name_len = next(st) % (FZN_CATALOGUE_ATTR_NAME_MAX + 1u);
	for (i = 0; i < a->name_len; i++)
		name[i] = (uint8_t)next(st);
	a->name = a->name_len ? name : NULL;
	room = (size_t)FZN_RECORD_BODY_MAX - FZN_CATALOGUE_ATTR_HEAD_LEN - 2u
	     - a->name_len;
	a->value_len = next(st) % (room + 1u);
	for (i = 0; i < a->value_len; i++)
		value[i] = (uint8_t)next(st);
	a->value = a->value_len ? value : NULL;
}

/* Nonzero on a property failure. */
static int fuzz_one(uint32_t seed, struct coverage *cov)
{
	uint32_t st = seed;
	uint8_t iss[32], ent[32];
	size_t i;

	for (i = 0; i < 32; i++) {
		iss[i] = (uint8_t)next(&st);
		ent[i] = (uint8_t)next(&st);
	}

	if (next(&st) & 1u) {
		/* Property 2, forward: a valid assertion round-trips and re-encodes
		 * byte-identically. */
		fzn_catalogue_assertion_t a, got;
		uint8_t name[FZN_CATALOGUE_ATTR_NAME_MAX];
		uint8_t value[FZN_RECORD_BODY_MAX];
		uint8_t body[FZN_RECORD_BODY_MAX], reenc[FZN_RECORD_BODY_MAX];
		size_t len = 0, len2 = 0;

		rand_valid(&st, &a, name, value);
		if (fzn_catalogue_attribute_encode(&a, body, sizeof(body), &len)
		    != FZN_CATALOGUE_OK)
			return 1; /* a valid assertion must encode */
		if (fzn_catalogue_attribute_decode(iss, 32, ent, 32, body, len, &got)
		    != FZN_CATALOGUE_OK)
			return 1; /* what we encoded must decode */
		if (got.attr_class != a.attr_class || got.scope != a.scope
		    || got.merge != a.merge || got.capability != a.capability
		    || got.name_len != a.name_len || got.value_len != a.value_len)
			return 1;
		if (a.name_len && memcmp(got.name, a.name, a.name_len) != 0)
			return 1;
		if (a.value_len && memcmp(got.value, a.value, a.value_len) != 0)
			return 1;
		if (fzn_catalogue_attribute_encode(&got, reenc, sizeof(reenc), &len2)
		    != FZN_CATALOGUE_OK)
			return 1;
		if (len2 != len || memcmp(reenc, body, len) != 0)
			return 1; /* not canonical */
		cov->roundtrip++;
	} else {
		/* Property 1, and property 2 in reverse: bytes near a valid body --
		 * and some wholly wild -- never misbehave, and any that decode
		 * re-encode to exactly themselves. Mutating a real body (flip, drop or
		 * add tail bytes) exercises the decoder right at its boundary, where a
		 * slack length or a trailing byte would slip through; pure-random bytes
		 * almost never get past the tag, so they test little but the crash. */
		fzn_catalogue_assertion_t a, got;
		uint8_t name[FZN_CATALOGUE_ATTR_NAME_MAX];
		uint8_t value[FZN_RECORD_BODY_MAX];
		uint8_t body[RAND_BODY_MAX];
		fzn_catalogue_err_t e;
		size_t body_len = 0, k, flips;

		if (next(&st) % 4u == 0u) {
			/* wild: pure random bytes, any length including oversized. */
			body_len = next(&st) % (RAND_BODY_MAX + 1u);
			for (i = 0; i < body_len; i++)
				body[i] = (uint8_t)next(&st);
		} else {
			/* near-valid: a real body, then perturbed. */
			uint8_t valid[FZN_RECORD_BODY_MAX];
			size_t vlen = 0;
			unsigned mode;

			rand_valid(&st, &a, name, value);
			if (fzn_catalogue_attribute_encode(&a, valid, sizeof(valid), &vlen)
			    != FZN_CATALOGUE_OK)
				return 1;
			memcpy(body, valid, vlen);
			body_len = vlen;
			mode = next(&st) % 3u;
			if (mode == 1u && body_len > FZN_CATALOGUE_ATTR_HEAD_LEN)
				body_len -= 1u + next(&st) % 3u;          /* truncate */
			else if (mode == 2u && body_len + 3u <= RAND_BODY_MAX) {
				size_t add = 1u + next(&st) % 3u;         /* extend */
				for (k = 0; k < add; k++)
					body[body_len + k] = (uint8_t)next(&st);
				body_len += add;
			}
			flips = next(&st) % 4u;                        /* flip 0..3 bytes */
			for (k = 0; k < flips && body_len; k++)
				body[next(&st) % body_len] ^= (uint8_t)(1u + next(&st) % 255u);
		}

		e = fzn_catalogue_attribute_decode(iss, 32, ent, 32, body, body_len, &got);
		if (e == FZN_CATALOGUE_OK) {
			uint8_t reenc[FZN_RECORD_BODY_MAX];
			size_t len2 = 0;

			/* borrowed views lie within the input; no OOB borrow. */
			if (got.name_len
			    && (got.name < body || got.name + got.name_len > body + body_len))
				return 1;
			if (got.value_len
			    && (got.value < body || got.value + got.value_len > body + body_len))
				return 1;
			/* issuer and entity are the caller's pointers, not the body's. */
			if (got.issuer != iss || got.entity != ent)
				return 1;
			/* canonical: a body that decodes re-encodes to exactly itself. */
			if (fzn_catalogue_attribute_encode(&got, reenc, sizeof(reenc), &len2)
			    != FZN_CATALOGUE_OK)
				return 1;
			if (len2 != body_len || memcmp(reenc, body, body_len) != 0)
				return 1;
			cov->rand_ok++;
		} else {
			cov->rand_refused++;
		}
	}
	return 0;
}

#ifdef FZN_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint32_t seed = 1u;
	size_t i;
	struct coverage cov = { 0, 0, 0 };

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
	struct coverage cov = { 0, 0, 0 };
	unsigned long c;

	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
	}
	if (cases < FUZZ_MIN_CASES) {
		printf("attribute_fuzz: %lu cases is below FUZZ_MIN_CASES (%u), so this "
		       "run will not report success. Re-run with %u or more.\n",
		       cases, (unsigned)FUZZ_MIN_CASES, (unsigned)FUZZ_MIN_CASES);
		return 1;
	}

	for (c = 0; c < cases; c++) {
		if (fuzz_one((uint32_t)c + 1u, &cov)) {
			printf("attribute_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	/* FLOORS ON THE STATES THAT MAKE THE PROPERTIES MEAN ANYTHING. A run that
	 * never round-tripped a valid assertion has not tested canonical encoding;
	 * one where no random body ever decoded has tested only the refusals; one
	 * where none was ever refused has tested only the accepts. Each half of
	 * the decoder has to have been reached. */
	if (cov.roundtrip < floor_of(cases, 4u)
	    || cov.rand_ok < floor_of(cases, 50u)
	    || cov.rand_refused < floor_of(cases, 4u)) {
		printf("attribute_fuzz: REACHED TOO LITTLE -- %lu round-trips, %lu random "
		       "bodies decoded, %lu refused in %lu cases.\n",
		       cov.roundtrip, cov.rand_ok, cov.rand_refused, cases);
		return 1;
	}

	printf("attribute_fuzz: %lu cases, %lu valid round-trips (canonical), %lu "
	       "random bodies decoded and re-encoded to themselves, %lu refused\n",
	       cases, cov.roundtrip, cov.rand_ok, cov.rand_refused);
	return 0;
}
#endif
