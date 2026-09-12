/*
 * A fuzz harness for chain/chain_store.c, against a map of expiries.
 *
 * `chain_store.h` states the store's semantics precisely enough to write
 * down as a function, which is what makes this an oracle and not a set of
 * properties:
 *
 *   - a chain for a triple already held REPLACES it, unconditionally --
 *     "a shorter-lived chain evicts a longer-lived one", stated because it
 *     "was neither stated nor tested";
 *   - lookup withholds an expired chain, and `now` is required for that;
 *   - expiry alone deletes nothing: an expired entry "stays, is counted,
 *     and is withheld by lookup";
 *   - a DEAD entry is spent before a live chain is refused, and it is
 *     STILL a refusal when every entry is live -- "eviction is for the
 *     useless".
 *
 * So the model is a map from (root, capability, grantee) to an expiry, and
 * every answer the store gives is checked against it: what lookup finds,
 * what count says, and whether admit accepted or refused. The clock is the
 * harness's, advanced at random, so entries die while the store holds them
 * and the eviction path is reached rather than described.
 *
 * WHICH DEAD SLOT IS SPENT IS NOT MODELLED, and deliberately. The header
 * says the first in array order and that "a deterministic one can be
 * tested" -- chain_store_test does. From outside, every dead entry is
 * withheld by lookup and every one is counted, so which of them a new chain
 * replaced is not observable through the API this harness uses. A model
 * that tracked array order would be a model of the implementation.
 *
 * THE CHAINS ARE REAL. `fzn_chain_store_admit` verifies before storing, so
 * a fixture that handed it bytes that do not verify would be testing the
 * refusal path over and over. Every chain here is one hop, minted by the
 * root with the same stub signer chain_test.c uses, and admitted while it
 * is live -- the refusals of a chain that does not verify are chain_test's
 * subject and are not asserted twice.
 */

#include "../chain_store.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u
#define FUZZ_MIN_CASES 1000u

#define CAPS 2u
#define GRANTEES 3u
#define TRIPLES (CAPS * GRANTEES)
#define MAX_SLOTS 4u
#define STEPS 24u

/* ---- the same signer chain_test.c uses ----------------------------------- */

static void mac(uint8_t out[FZN_SIG_LEN], uint8_t identity, const uint8_t *msg, size_t len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	h ^= (uint64_t)identity;
	h *= 0x100000001b3ull;
	for (i = 0; i < len; i++) {
		h ^= (uint64_t)msg[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h ^= (uint64_t)i + 1u;
		h *= 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 56);
	}
}

struct stub {
	uint8_t identity;
};

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	struct stub *s = ctx;

	mac(sig, s->identity, msg, msg_len);
	return 1;
}

static int stub_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	mac(want, pubkey[0], msg, msg_len);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

/* Byte 0 is the seed, because the verifier derives identity from it. */
static void expand(uint8_t *out, size_t len, uint8_t seed)
{
	size_t i;

	out[0] = seed;
	for (i = 1; i < len; i++)
		out[i] = (uint8_t)(seed ^ (uint8_t)i);
}

/* ---- the model ----------------------------------------------------------- */

struct held {
	uint64_t expires;
	int present;
};

struct coverage {
	unsigned long inserted;
	unsigned long replaced;
	unsigned long replaced_shorter;
	unsigned long evicted_dead;
	unsigned long refused_full;
	unsigned long found;
	unsigned long withheld_expired;
	unsigned long missed;
};

static uint32_t next(uint32_t *state)
{
	*state ^= *state << 13;
	*state ^= *state >> 17;
	*state ^= *state << 5;
	return *state;
}

static int check_all(const fzn_chain_store_t *store, const struct held *model,
                     const uint8_t *root, uint64_t now, struct coverage *cov)
{
	unsigned c, g, counted = 0;

	for (c = 0; c < CAPS; c++)
		for (g = 0; g < GRANTEES; g++) {
			unsigned t = c * GRANTEES + g;
			fzn_cap_id_t cap;
			uint8_t grantee[FZN_PUBKEY_LEN];
			const uint8_t *bytes = NULL;
			size_t len = 0;
			int found, want;

			expand(cap.b, FZN_CAP_ID_LEN, (uint8_t)(0x30u + c));
			expand(grantee, FZN_PUBKEY_LEN, (uint8_t)(1u + g));
			found = fzn_chain_store_lookup(store, root, &cap, grantee, now, &bytes, &len);
			want = model[t].present && model[t].expires > now;
			if (found != want) {
				printf("  MODEL: lookup of triple %u at now=%llu says %d; the model "
				       "holds present=%d expires=%llu\n", t, (unsigned long long)now,
				       found, model[t].present, (unsigned long long)model[t].expires);
				return 0;
			}
			if (found && (!bytes || len == 0u)) {
				printf("  MODEL: a found chain came back with no bytes\n");
				return 0;
			}
			if (model[t].present)
				counted++;
			if (want)
				cov->found++;
			else if (model[t].present)
				cov->withheld_expired++;
			else
				cov->missed++;
		}
	if (fzn_chain_store_count(store) != counted) {
		printf("  MODEL: the store counts %zu and the model holds %u (expired "
		       "entries included, as the header says)\n",
		       fzn_chain_store_count(store), counted);
		return 0;
	}
	return 1;
}

static int fuzz_one(uint32_t seed, struct coverage *cov)
{
	uint32_t state = seed;
	fzn_chain_entry_t slots[MAX_SLOTS];
	fzn_chain_store_t store;
	struct held model[TRIPLES];
	struct stub stub;
	fzn_sign_ops_t sign;
	uint8_t root[FZN_PUBKEY_LEN];
	unsigned cap, step;
	uint64_t now = 100u;

	memset(model, 0, sizeof(model));
	memset(slots, 0, sizeof(slots));
	expand(root, FZN_PUBKEY_LEN, 0);
	stub.identity = 0;
	sign.sign = stub_sign;
	sign.verify = stub_verify;
	sign.ctx = &stub;
	cap = 1u + (next(&state) % MAX_SLOTS);
	if (fzn_chain_store_init(&store, slots, cap) != FZN_CHAIN_OK)
		return 1;

	for (step = 0; step < STEPS; step++) {
		unsigned pick = next(&state) % 4u;

		if (pick < 3u) {
			/* ADMIT a live one-hop chain for a random triple. */
			unsigned c = next(&state) % CAPS, g = next(&state) % GRANTEES;
			unsigned t = c * GRANTEES + g;
			uint64_t expires = now + 1u + (next(&state) % 8u);
			uint8_t bytes[FZN_HOP_LEN], grantee[FZN_PUBKEY_LEN];
			fzn_cap_id_t capability;
			fzn_chain_hop_t hop;
			fzn_chain_err_t err;
			unsigned held_count = 0, dead = 0, i;

			expand(capability.b, FZN_CAP_ID_LEN, (uint8_t)(0x30u + c));
			expand(grantee, FZN_PUBKEY_LEN, (uint8_t)(1u + g));
			if (fzn_chain_mint(root, grantee, &capability, now, expires, 0, &sign, bytes)
			    != FZN_CHAIN_OK ||
			    fzn_hop_open(bytes, FZN_HOP_LEN, &hop) != FZN_CHAIN_OK) {
				printf("  MODEL: the fixture could not mint a hop\n");
				return 1;
			}
			for (i = 0; i < TRIPLES; i++)
				if (model[i].present) {
					held_count++;
					if (model[i].expires <= now)
						dead++;
				}

			err = fzn_chain_store_admit(&store, &hop, 1u, root, &capability, now, &sign,
			                            NULL, NULL);

			if (model[t].present) {
				/* REPLACEMENT, UNCONDITIONAL. */
				if (err != FZN_CHAIN_OK) {
					printf("  MODEL: a chain for a held triple was refused with "
					       "%d rather than replacing\n", (int)err);
					return 1;
				}
				if (expires < model[t].expires)
					cov->replaced_shorter++;
				cov->replaced++;
				model[t].expires = expires;
			} else if (held_count < cap) {
				if (err != FZN_CHAIN_OK) {
					printf("  MODEL: a chain was refused with %d and the store "
					       "had room (%u of %u)\n", (int)err, held_count, cap);
					return 1;
				}
				model[t].present = 1;
				model[t].expires = expires;
				cov->inserted++;
			} else if (dead > 0u) {
				/* A DEAD ENTRY IS SPENT. Which one is the store's; the
				 * model drops the first dead it finds, and the two
				 * agree on everything the API can show. */
				if (err != FZN_CHAIN_OK) {
					printf("  MODEL: a full store with %u dead entries refused "
					       "with %d rather than spending one\n", dead, (int)err);
					return 1;
				}
				for (i = 0; i < TRIPLES; i++)
					if (model[i].present && model[i].expires <= now) {
						model[i].present = 0;
						break;
					}
				model[t].present = 1;
				model[t].expires = expires;
				cov->evicted_dead++;
			} else {
				/* EVERY ENTRY LIVE: a refusal, not an eviction. */
				if (err != FZN_CHAIN_ERR_STORE_FULL) {
					printf("  MODEL: a full store of live chains answered %d "
					       "rather than FULL -- so which chain a host holds "
					       "depends on arrival order\n", (int)err);
					return 1;
				}
				cov->refused_full++;
			}
		} else {
			/* TIME PASSES, so entries die in place. */
			now += 1u + (next(&state) % 5u);
		}

		if (!check_all(&store, model, root, now, cov))
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
		printf("chain_store_fuzz: %lu cases is below FUZZ_MIN_CASES (%u).\n", cases,
		       (unsigned)FUZZ_MIN_CASES);
		return 1;
	}

	for (c = 0; c < cases; c++) {
		if (fuzz_one((uint32_t)c + 1u, &cov)) {
			printf("chain_store_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	/* THE FLOORS ARE THE FOUR SENTENCES OF THE HEADER. A run with no
	 * shorter-lived replacement has not tested "cuts both ways"; one with
	 * no dead eviction has not tested "spent before refused"; one with no
	 * FULL has not tested "still a refusal when every entry is live"; and
	 * one with nothing withheld has not tested that expiry deletes nothing. */
	if (cov.inserted < floor_of(cases, 1u) || cov.replaced < floor_of(cases, 2u)
	    || cov.replaced_shorter < floor_of(cases, 10u)
	    || cov.evicted_dead < floor_of(cases, 10u) || cov.refused_full < floor_of(cases, 10u)
	    || cov.withheld_expired < floor_of(cases, 2u) || cov.found < floor_of(cases, 1u)) {
		printf("chain_store_fuzz: REACHED TOO LITTLE -- %lu inserted, %lu replaced "
		       "(%lu shorter), %lu dead evicted, %lu refused full, %lu found, %lu "
		       "withheld expired, in %lu cases.\n",
		       cov.inserted, cov.replaced, cov.replaced_shorter, cov.evicted_dead,
		       cov.refused_full, cov.found, cov.withheld_expired, cases);
		return 1;
	}

	printf("chain_store_fuzz: %lu cases, %lu inserted, %lu replaced (%lu by a "
	       "shorter-lived chain), %lu dead entries spent, %lu refused full of live "
	       "chains, %lu lookups found, %lu withheld as expired, and the map agreed "
	       "throughout\n",
	       cases, cov.inserted, cov.replaced, cov.replaced_shorter, cov.evicted_dead,
	       cov.refused_full, cov.found, cov.withheld_expired);
	return 0;
}
#endif
