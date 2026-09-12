/*
 * A fuzz harness for record/store.c, over a backend that lies.
 *
 * WHAT THE STORE PROMISES, from its header: it does not verify and a caller
 * must, but it checks the ADDRESS in both directions. `put` reads (issuer,
 * stream, seq) out of the record so nothing can be filed under a name that
 * is not its own, and `get` compares what came back against what was asked
 * for -- "so a store that returns the wrong record answers
 * FZN_RECORD_STORE_ERR_MISPLACED rather than handing a caller somebody
 * else's bytes under the name it asked for." sec 132 rests on that: a shared
 * cache is not a shared trust domain, and this check is what keeps it so.
 *
 * SO THE BACKEND HERE IS HOSTILE BY CONSTRUCTION. `store_test.c` has a table
 * with knobs -- a nominated wrong slot, a truncation, a hard failure -- and
 * exercises each once. This one turns the knobs at random on every read and
 * asks the only question that matters across all of them: **did the caller
 * ever receive bytes that were not the bytes filed under the name it used?**
 * The oracle is a map kept here of what was put where, and a `get` that
 * answers OK must hand back exactly that or the store has done the thing
 * its header says it cannot.
 *
 * WHAT A LYING BACKEND MAY CAUSE is any refusal. What it may never cause is
 * a wrong success. That asymmetry is the property, and it is why the harness
 * does not assert WHICH error a lie produces -- store_test.c pins those --
 * only that the answer was not OK-with-the-wrong-bytes.
 *
 * AND THE BACKEND IS NOT ALLOWED TO LIE ABOUT A PUT. A put that the backend
 * accepted is in the oracle; a put it refused is not; the harness does not
 * let the backend accept a put and then forget it, because that is a
 * different module's failure and would make the oracle wrong rather than
 * the store.
 */

#include "../store.h"
#include "../record.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u
#define FUZZ_MIN_CASES 1000u

#define ISSUERS 2u
#define STREAMS 2u
#define SEQS 4u
#define ADDRESSES (ISSUERS * STREAMS * SEQS)
#define SLOTS 16
#define STEPS 24u

/* ---- signing, the same stub store_test.c uses ---------------------------- */

static uint8_t SUBJECT[FZN_SUBJECT_LEN];

static void tag(uint8_t out[FZN_SIG_LEN], const uint8_t key[FZN_PUBKEY_LEN],
                const uint8_t *msg, size_t msg_len)
{
	uint64_t h = 1469598103934665603u;
	size_t i;

	for (i = 0; i < FZN_PUBKEY_LEN; i++) {
		h ^= key[i];
		h *= 1099511628211u;
	}
	for (i = 0; i < msg_len; i++) {
		h ^= msg[i];
		h *= 1099511628211u;
	}
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h ^= (uint64_t)i;
		h *= 1099511628211u;
		out[i] = (uint8_t)(h >> 32);
	}
}

static uint8_t signing_key[FZN_PUBKEY_LEN];

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	(void)ctx;
	tag(sig, signing_key, msg, msg_len);
	return 1;
}

static int stub_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	tag(want, pubkey, msg, msg_len);
	return memcmp(want, sig, FZN_SIG_LEN) == 0 ? 1 : 0;
}

static fzn_sign_ops_t SIGN;

/* ---- a backend that lies on demand --------------------------------------- */

struct slot {
	uint8_t issuer[FZN_PUBKEY_LEN];
	uint32_t stream;
	uint64_t seq;
	uint8_t bytes[FZN_RECORD_MAX_LEN];
	size_t len;
	int used;
};

enum lie { HONEST, WRONG_SLOT, TRUNCATE, HARD_FAIL, LIE_KINDS };

struct table {
	struct slot slots[SLOTS];
	int next_lie;      /* what the NEXT get will do */
	int wrong_slot;    /* which slot a WRONG_SLOT answer hands back */
	int refuse_puts;   /* a put the backend will not take */
};

static int table_put(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream,
                     uint64_t seq, const uint8_t *bytes, size_t len)
{
	struct table *t = ctx;
	int i;

	if (t->refuse_puts || len > FZN_RECORD_MAX_LEN)
		return 0;
	for (i = 0; i < SLOTS; i++) {
		if (t->slots[i].used && t->slots[i].stream == stream && t->slots[i].seq == seq &&
		    memcmp(t->slots[i].issuer, issuer, FZN_PUBKEY_LEN) == 0)
			break;
	}
	if (i == SLOTS)
		for (i = 0; i < SLOTS && t->slots[i].used; i++)
			;
	if (i == SLOTS)
		return 0;
	memcpy(t->slots[i].issuer, issuer, FZN_PUBKEY_LEN);
	t->slots[i].stream = stream;
	t->slots[i].seq = seq;
	memcpy(t->slots[i].bytes, bytes, len);
	t->slots[i].len = len;
	t->slots[i].used = 1;
	return 1;
}

static int table_get(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream,
                     uint64_t seq, uint8_t *out, size_t cap, size_t *len_out, int *found_out)
{
	struct table *t = ctx;
	int i, lie = t->next_lie;

	t->next_lie = HONEST;
	*found_out = 0;
	if (lie == HARD_FAIL) {
		*found_out = 1;
		return 0;
	}
	if (lie == WRONG_SLOT) {
		i = t->wrong_slot;
	} else {
		for (i = 0; i < SLOTS; i++)
			if (t->slots[i].used && t->slots[i].stream == stream &&
			    t->slots[i].seq == seq &&
			    memcmp(t->slots[i].issuer, issuer, FZN_PUBKEY_LEN) == 0)
				break;
		if (i == SLOTS)
			return 0;
	}
	if (!t->slots[i].used)
		return 0;
	*found_out = 1;
	if (t->slots[i].len > cap)
		return 0;
	memcpy(out, t->slots[i].bytes, t->slots[i].len);
	*len_out = t->slots[i].len;
	if (lie == TRUNCATE && *len_out > 8u)
		*len_out -= 5u;
	return 1;
}

/* ---- the oracle: what was filed where ------------------------------------ */

struct filed {
	uint8_t bytes[FZN_RECORD_MAX_LEN];
	size_t len;
	int present;
};

struct coverage {
	unsigned long honest_hit;
	unsigned long honest_miss;
	unsigned long lie_refused;
	unsigned long lie_survived_honestly;
	unsigned long put_refused;
	unsigned long overwritten;
};

static uint32_t next(uint32_t *state)
{
	*state ^= *state << 13;
	*state ^= *state >> 17;
	*state ^= *state << 5;
	return *state;
}

static void issuer_of(uint8_t out[FZN_PUBKEY_LEN], unsigned which)
{
	memset(out, (int)(0x10u + which), FZN_PUBKEY_LEN);
}

static int fuzz_one(uint32_t seed, struct coverage *cov)
{
	uint32_t state = seed;
	struct table table;
	struct filed filed[ADDRESSES];
	fzn_record_store_ops_t ops;
	fzn_record_store_t store;
	unsigned step;

	memset(&table, 0, sizeof(table));
	memset(filed, 0, sizeof(filed));
	table.next_lie = HONEST;
	ops.put = table_put;
	ops.get = table_get;
	ops.ctx = &table;
	if (fzn_record_store_init(&store, &ops) != FZN_RECORD_STORE_OK)
		return 1;

	for (step = 0; step < STEPS; step++) {
		unsigned who = next(&state) % ISSUERS;
		unsigned stream = next(&state) % STREAMS;
		unsigned seqi = next(&state) % SEQS;
		unsigned addr = (who * STREAMS + stream) * SEQS + seqi;
		uint8_t issuer[FZN_PUBKEY_LEN];

		issuer_of(issuer, who);
		memcpy(signing_key, issuer, FZN_PUBKEY_LEN);

		if ((next(&state) % 3u) == 0u) {
			/* PUT. The body is random so two records at one address
			 * differ, which is what makes "the right bytes" a real
			 * question rather than "any bytes". */
			uint8_t body[24], bytes[FZN_RECORD_MAX_LEN];
			size_t len = 0, i;
			fzn_record_t rec;
			fzn_record_store_err_t err;

			for (i = 0; i < sizeof(body); i++)
				body[i] = (uint8_t)next(&state);
			if (fzn_record_sign(issuer, SUBJECT, stream, 1u, (uint64_t)seqi + 1u, 1u,
			                    body, sizeof(body), &SIGN, bytes, sizeof(bytes),
			                    &len) != FZN_RECORD_OK ||
			    fzn_record_open(bytes, len, &rec) != FZN_RECORD_OK)
				return 1;
			table.refuse_puts = (next(&state) % 8u) == 0u;
			err = fzn_record_store_put(&store, rec);
			if (table.refuse_puts) {
				if (err == FZN_RECORD_STORE_OK) {
					printf("  MODEL: the backend refused a put and the store "
					       "reported it stored\n");
					return 1;
				}
				cov->put_refused++;
			} else if (err != FZN_RECORD_STORE_OK) {
				printf("  MODEL: an honest put was refused with %s\n",
				       fzn_record_store_err_str(err));
				return 1;
			} else {
				if (filed[addr].present)
					cov->overwritten++;
				memcpy(filed[addr].bytes, bytes, len);
				filed[addr].len = len;
				filed[addr].present = 1;
			}
			table.refuse_puts = 0;
		} else {
			/* GET, with the backend told what to do. */
			uint8_t out[FZN_RECORD_MAX_LEN];
			fzn_record_t view;
			fzn_record_store_err_t err;
			int lie = (int)(next(&state) % (LIE_KINDS + 2u));

			if (lie >= LIE_KINDS)
				lie = HONEST;   /* honesty weighted, so hits happen */
			table.next_lie = lie;
			table.wrong_slot = (int)(next(&state) % SLOTS);
			memset(out, 0, sizeof(out));
			err = fzn_record_store_get(&store, issuer, stream, (uint64_t)seqi + 1u,
			                           out, sizeof(out), &view);

			if (err == FZN_RECORD_STORE_OK) {
				/* THE PROPERTY. Whatever the backend did, an OK
				 * carries exactly what was filed under this name. */
				if (!filed[addr].present) {
					printf("  MODEL: get answered OK at an address nothing was "
					       "ever filed under (the backend was told to %s)\n",
					       lie == WRONG_SLOT ? "hand back a wrong slot" :
					       lie == TRUNCATE ? "truncate" :
					       lie == HARD_FAIL ? "fail" : "be honest");
					return 1;
				}
				if (view.len != filed[addr].len ||
				    memcmp(view.base, filed[addr].bytes,
				           filed[addr].len) != 0) {
					printf("  MODEL: get answered OK with bytes that are not "
					       "the bytes filed under this name (the backend was "
					       "told to %s)\n",
					       lie == WRONG_SLOT ? "hand back a wrong slot" :
					       lie == TRUNCATE ? "truncate" : "be honest");
					return 1;
				}
				if (lie == HONEST)
					cov->honest_hit++;
				else
					cov->lie_survived_honestly++;
			} else if (lie == HONEST) {
				if (filed[addr].present && err != FZN_RECORD_STORE_ERR_ABSENT) {
					printf("  MODEL: an honest get of a filed record answered "
					       "%s\n", fzn_record_store_err_str(err));
					return 1;
				}
				if (filed[addr].present) {
					printf("  MODEL: an honest backend holding the record "
					       "answered absent\n");
					return 1;
				}
				cov->honest_miss++;
			} else {
				cov->lie_refused++;
			}
		}
	}
	return 0;
}

#ifdef FZN_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint32_t seed = 1u;
	size_t i;
	struct coverage cov = { 0, 0, 0, 0, 0, 0 };

	SIGN.sign = stub_sign;
	SIGN.verify = stub_verify;
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
	struct coverage cov = { 0, 0, 0, 0, 0, 0 };
	unsigned long c;

	SIGN.sign = stub_sign;
	SIGN.verify = stub_verify;
	memset(SUBJECT, 0x5b, sizeof(SUBJECT));

	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
	}
	if (cases < FUZZ_MIN_CASES) {
		printf("store_fuzz: %lu cases is below FUZZ_MIN_CASES (%u).\n", cases,
		       (unsigned)FUZZ_MIN_CASES);
		return 1;
	}

	for (c = 0; c < cases; c++) {
		if (fuzz_one((uint32_t)c + 1u, &cov)) {
			printf("store_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	/* `lie_survived_honestly` HAS NO FLOOR AND IS PRINTED: it counts a
	 * wrong-slot answer that happened to name the slot actually holding
	 * the record, which the store rightly accepts. Requiring it would be
	 * requiring luck. The floor that matters is `lie_refused`: a run where
	 * no lie was refused has tested an honest backend twice. */
	if (cov.honest_hit < floor_of(cases, 2u) || cov.honest_miss < floor_of(cases, 4u)
	    || cov.lie_refused < floor_of(cases, 2u) || cov.put_refused < floor_of(cases, 20u)
	    || cov.overwritten < floor_of(cases, 20u)) {
		printf("store_fuzz: REACHED TOO LITTLE -- %lu honest hits, %lu honest "
		       "misses, %lu lies refused, %lu puts refused, %lu overwrites, in %lu "
		       "cases.\n",
		       cov.honest_hit, cov.honest_miss, cov.lie_refused, cov.put_refused,
		       cov.overwritten, cases);
		return 1;
	}

	printf("store_fuzz: %lu cases, %lu honest hits, %lu honest misses, %lu lies "
	       "refused, %lu lies that happened to be true, %lu puts refused, %lu "
	       "overwrites, and no caller ever received bytes under the wrong name\n",
	       cases, cov.honest_hit, cov.honest_miss, cov.lie_refused,
	       cov.lie_survived_honestly, cov.put_refused, cov.overwritten);
	return 0;
}
#endif
