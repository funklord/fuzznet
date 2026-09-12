/*
 * A fuzz harness for record/ledger.c, against a max-per-key map.
 *
 * WHAT THE LEDGER PROMISES is small enough to state as a function, which is
 * what makes this an oracle rather than a property. For each (peer, subject,
 * kind) the confirmed version is the HIGHEST ever confirmed -- "a
 * confirmation never moves backwards", and `ledger.h`'s argument for that is
 * not caution: an acknowledgement that arrives late is reordering rather
 * than retraction, so the higher number is the better evidence. `behind` is
 * then `confirmed < current`, an unknown peer answers zero (the direction
 * that costs a retransmission rather than a skipped delivery), and a version
 * of zero is refused because zero is what an absent row already says.
 *
 * A max over a map is a second implementation of all of that in a dozen
 * lines, and it does not share a line with `ledger.c`. So every answer the
 * ledger gives is checked against it, over confirmations that arrive in a
 * random order -- which is the case the header's argument is about and the
 * case two hand-written confirmations cannot produce.
 *
 * WHAT A STALE CONFIRMATION MUST DO is the half worth reading twice: it is
 * REPORTED, and the table is unchanged. So the harness asserts both -- the
 * error code, and that every answer afterwards still matches the max. A
 * ledger that absorbed the stale value silently would give the right error
 * and the wrong table, or the wrong error and the right table, and only
 * asking both catches either.
 *
 * CAPACITY IS SMALL ON PURPOSE. A new key against a full table is refused
 * with FZN_LEDGER_ERR_FULL and the model must not record it; a KNOWN key
 * against a full table still updates, because it needs no row. The floor on
 * the first is what stops a fixture too roomy to ever fill from testing the
 * refusal the header describes.
 */

#include "../ledger.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u
#define FUZZ_MIN_CASES 1000u

#define PEERS 3u
#define SUBJECTS 2u
#define KINDS 2u
#define KEYS (PEERS * SUBJECTS * KINDS)
#define MAX_ROWS 8u
#define STEPS 24u

struct coverage {
	unsigned long advanced;
	unsigned long stale;
	unsigned long zero_refused;
	unsigned long full_refused;
	unsigned long known_on_full;
	unsigned long behind_yes;
	unsigned long behind_no;
	unsigned long unknown_asked;
};

static uint32_t next(uint32_t *state)
{
	*state ^= *state << 13;
	*state ^= *state >> 17;
	*state ^= *state << 5;
	return *state;
}

static void peer_of(uint8_t out[FZN_PUBKEY_LEN], unsigned which)
{
	memset(out, (int)(0x20u + which), FZN_PUBKEY_LEN);
}

static void subject_of(uint8_t out[FZN_SUBJECT_LEN], unsigned which)
{
	memset(out, (int)(0x40u + which), FZN_SUBJECT_LEN);
}

static int check_all(const fzn_ledger_t *ledger, const uint64_t *model, unsigned known_keys)
{
	unsigned p, s, k;

	for (p = 0; p < PEERS; p++)
		for (s = 0; s < SUBJECTS; s++)
			for (k = 0; k < KINDS; k++) {
				unsigned key = (p * SUBJECTS + s) * KINDS + k;
				uint8_t peer[FZN_PUBKEY_LEN], subject[FZN_SUBJECT_LEN];
				uint64_t got;

				peer_of(peer, p);
				subject_of(subject, s);
				got = fzn_ledger_confirmed(ledger, peer, subject, k);
				if (got != model[key]) {
					printf("  MODEL: key %u confirmed at %llu, and the highest "
					       "ever confirmed is %llu\n", key,
					       (unsigned long long)got,
					       (unsigned long long)model[key]);
					return 0;
				}
			}
	if (fzn_ledger_count(ledger) != known_keys) {
		printf("  MODEL: the ledger counts %zu rows and %u keys have been "
		       "confirmed\n", fzn_ledger_count(ledger), known_keys);
		return 0;
	}
	return 1;
}

static int fuzz_one(uint32_t seed, struct coverage *cov)
{
	uint32_t state = seed;
	fzn_ledger_entry_t rows[MAX_ROWS];
	fzn_ledger_t ledger;
	uint64_t model[KEYS];
	unsigned cap, known = 0, step;

	memset(model, 0, sizeof(model));
	memset(rows, 0, sizeof(rows));
	cap = 1u + (next(&state) % MAX_ROWS);
	if (fzn_ledger_init(&ledger, rows, cap) != FZN_LEDGER_OK)
		return 1;
	if (!fzn_ledger_sound(&ledger)) {
		printf("  MODEL: a fresh ledger is not sound\n");
		return 1;
	}

	for (step = 0; step < STEPS; step++) {
		unsigned p = next(&state) % PEERS;
		unsigned s = next(&state) % SUBJECTS;
		unsigned k = next(&state) % KINDS;
		unsigned key = (p * SUBJECTS + s) * KINDS + k;
		uint8_t peer[FZN_PUBKEY_LEN], subject[FZN_SUBJECT_LEN];

		peer_of(peer, p);
		subject_of(subject, s);

		if ((next(&state) % 4u) != 3u) {
			/* CONFIRM, at a version drawn small so that out-of-order
			 * arrivals are common rather than a coincidence. */
			uint64_t version = next(&state) % 6u;
			fzn_ledger_err_t err = fzn_ledger_confirm(&ledger, peer, subject, k,
			                                          version);

			if (version == 0u) {
				if (err != FZN_LEDGER_ERR_MALFORMED) {
					printf("  MODEL: a version of zero was accepted, so "
					       "'confirmed nothing' and 'never heard of' are one "
					       "state\n");
					return 1;
				}
				cov->zero_refused++;
			} else if (model[key] == 0u && known >= cap) {
				/* A NEW KEY AGAINST A FULL TABLE. */
				if (err != FZN_LEDGER_ERR_FULL) {
					printf("  MODEL: a full ledger took a new key, answering "
					       "%d\n", (int)err);
					return 1;
				}
				cov->full_refused++;
			} else if (version > model[key]) {
				if (err != FZN_LEDGER_OK) {
					printf("  MODEL: a confirmation that advances %llu to %llu "
					       "was refused with %d\n",
					       (unsigned long long)model[key],
					       (unsigned long long)version, (int)err);
					return 1;
				}
				if (model[key] == 0u)
					known++;
				else if (known >= cap)
					cov->known_on_full++;
				model[key] = version;
				cov->advanced++;
			} else {
				/* STALE OR EQUAL: reported, and the table unchanged.
				 * Equal is stale too -- it moves nothing forward. */
				if (err != FZN_LEDGER_ERR_STALE) {
					printf("  MODEL: a confirmation of %llu against %llu held "
					       "answered %d rather than stale\n",
					       (unsigned long long)version,
					       (unsigned long long)model[key], (int)err);
					return 1;
				}
				cov->stale++;
			}
		} else {
			/* ASK. `behind` must agree with the model's max, and an
			 * unknown key must answer behind -- the direction that
			 * costs a retransmission and never a skipped delivery. */
			uint64_t current = 1u + (next(&state) % 6u);
			int behind = fzn_ledger_behind(&ledger, peer, subject, k, current);
			int want = model[key] < current;

			if (behind != want) {
				printf("  MODEL: behind(%llu) says %d with %llu confirmed\n",
				       (unsigned long long)current, behind,
				       (unsigned long long)model[key]);
				return 1;
			}
			if (model[key] == 0u)
				cov->unknown_asked++;
			if (behind)
				cov->behind_yes++;
			else
				cov->behind_no++;
		}

		if (!check_all(&ledger, model, known))
			return 1;
	}
	return 0;
}

#ifdef FZN_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint32_t seed = 1u;
	size_t i;
	struct coverage cov = { 0, 0, 0, 0, 0, 0, 0, 0 };

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
	struct coverage cov = { 0, 0, 0, 0, 0, 0, 0, 0 };
	unsigned long c;

	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
	}
	if (cases < FUZZ_MIN_CASES) {
		printf("ledger_fuzz: %lu cases is below FUZZ_MIN_CASES (%u).\n", cases,
		       (unsigned)FUZZ_MIN_CASES);
		return 1;
	}

	for (c = 0; c < cases; c++) {
		if (fuzz_one((uint32_t)c + 1u, &cov)) {
			printf("ledger_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	if (cov.advanced < floor_of(cases, 1u) || cov.stale < floor_of(cases, 2u)
	    || cov.zero_refused < floor_of(cases, 4u) || cov.full_refused < floor_of(cases, 10u)
	    || cov.known_on_full < floor_of(cases, 20u) || cov.behind_yes < floor_of(cases, 4u)
	    || cov.behind_no < floor_of(cases, 10u) || cov.unknown_asked < floor_of(cases, 10u)) {
		printf("ledger_fuzz: REACHED TOO LITTLE -- %lu advanced, %lu stale, %lu zero "
		       "refused, %lu full refusals, %lu known keys updated on a full table, "
		       "%lu behind, %lu not behind, %lu unknown asked, in %lu cases.\n",
		       cov.advanced, cov.stale, cov.zero_refused, cov.full_refused,
		       cov.known_on_full, cov.behind_yes, cov.behind_no, cov.unknown_asked,
		       cases);
		return 1;
	}

	printf("ledger_fuzz: %lu cases, %lu advanced, %lu stale and reported, %lu zero "
	       "refused, %lu new keys refused on a full table, %lu known keys updated on "
	       "one, %lu behind, %lu not, %lu unknown peers asked, and the max agreed "
	       "throughout\n",
	       cases, cov.advanced, cov.stale, cov.zero_refused, cov.full_refused,
	       cov.known_on_full, cov.behind_yes, cov.behind_no, cov.unknown_asked);
	return 0;
}
#endif
