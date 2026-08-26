/* A fuzz harness for the revocation admission path.
 *
 * project.md sec 4.2 has revocation carried on contact, so a record arrives
 * from a peer that is NOT its issuer -- every field of it is a stranger's,
 * including the issuer it names and the signature it offers. That is the
 * hostile surface, and `chain/test/chain_fuzz.c` does not touch it: that
 * harness feeds `fzn_revocation_t`, the already-verified form, straight to
 * `fzn_chain_verify`. Nothing exercised admission.
 *
 * MODEL-BASED RATHER THAN INVARIANT-BASED, which is the difference worth
 * stating. The other harnesses assert properties that must hold -- nothing
 * written out of bounds, no two entries sharing a nonce. This one keeps an
 * independent SHADOW of what the store should contain, decides for itself
 * what each record ought to do to it, and after every call asserts the two
 * agree exactly, in both directions.
 *
 * That is stronger, and it catches the class this module's failure actually
 * belongs to. A revocation bug is not an overrun; it is a record admitted
 * that should not have been -- a carrier inventing a revocation -- or one
 * silently dropped that should have been kept, which un-revokes a stolen
 * device. Neither breaks a spot invariant. Both break the model.
 *
 * RECORDS ARE REAL BYTES NOW (2026-08-27), issued through
 * `fzn_revocation_issue` and verified over their own signed body. This
 * harness used to fill structs and point every one of them at a single
 * shared string literal, so the field it set and the bytes the module
 * verified had nothing to do with each other -- and a genuine record
 * replayed with its grantee rewritten was admitted, permanently, against any
 * host an attacker named.
 *
 * The shadow is a second implementation of the rules on purpose, for the
 * reason chain_fuzz gives: a model that asked the module what it did would
 * agree with it always, including when both are wrong.
 *
 * Bounded and seeded like the others, and it counts what it reached --
 * admissions, refusals, duplicates, a full store and both answers from the
 * parser must all occur, or the run exercised less than it appears to.
 */

#include "../revocation.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u

/* THE FLOOR BELOW WHICH THIS HARNESS REFUSES TO REPORT SUCCESS AT ALL.
 *
 * `floor_of` below was fixed to never return zero, which closed CASES=1: a run
 * that demanded nothing could no longer pass by demanding nothing. It did not
 * close the case above it. A floor of ONE is cleared by luck -- the rarest
 * branch these harnesses reach occurs about once in 130 cases, so a 199-case
 * run hits it once and every counter then reports a real, honest, meaningless
 * number. Measured before this: `receive_fuzz 199` and `peer_fuzz 199` both
 * exited 0 with plausible counts.
 *
 * So this is a bound on the RUN rather than on the counters, and it lives in
 * the harness rather than in the Makefile deliberately. The Makefile is not
 * what somebody runs when they are chasing a crash under a sanitizer -- they
 * run this binary directly, with a small number, and read the exit code. A
 * bound that exists only in the thing that invokes the binary is not a bound
 * on the binary.
 *
 * 1000 is chosen against the floors themselves, which ask for one occurrence
 * per 200 cases: below that, every floor in this file collapses to the single
 * hit luck supplies. A run under it is not a shorter version of the campaign,
 * it is a different and much weaker claim, so it is refused rather than
 * reported. */
#define FUZZ_MIN_CASES 1000u
#define STORE_CAP 6
#define CANARY 16
#define CANARY_BYTE 0x7e

/* The toy MAC every harness and unit test in this module shares. Its answer
 * depends on the message as well as on the key, which is what makes "is this
 * field inside the signed range?" a question with an observable answer. */
static void mac(uint8_t out[FZN_SIG_LEN], uint8_t identity, const uint8_t *msg, size_t len)
{
	uint64_t h = 0xcbf29ce484222325ull;

	h ^= (uint64_t)identity;
	h *= 0x100000001b3ull;
	for (size_t i = 0; i < len; i++) {
		h ^= (uint64_t)msg[i];
		h *= 0x100000001b3ull;
	}
	for (size_t i = 0; i < FZN_SIG_LEN; i++) {
		h ^= (uint64_t)i + 1u;
		h *= 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 56);
	}
}

static int stub_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	if (!msg || msg_len == 0)
		return 0;
	mac(want, pubkey[0], msg, msg_len);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

struct arena {
	uint8_t front[CANARY];
	fzn_revocation_t entries[STORE_CAP];
	uint8_t back[CANARY];
};

/* The shadow: what the store ought to hold, maintained independently. */
struct model {
	fzn_revocation_t held[STORE_CAP];
	size_t used;
};

struct coverage {
	unsigned long admitted;
	unsigned long duplicate;
	unsigned long refused;
	unsigned long full;
	unsigned long shape_ok;
	unsigned long shape_refused;
};

static int model_holds(const struct model *m, const uint8_t *cap, const uint8_t *grantee)
{
	for (size_t i = 0; i < m->used; i++) {
		if (memcmp(m->held[i].capability, cap, FZN_CAP_ID_LEN) == 0 &&
		    memcmp(m->held[i].grantee, grantee, FZN_PUBKEY_LEN) == 0)
			return 1;
	}
	return 0;
}

/* Do the store and the model agree, as SETS and in both directions? */
static const char *agree(const struct arena *a, const fzn_revocation_store_t *store,
                         const struct model *m)
{
	for (size_t i = 0; i < CANARY; i++) {
		if (a->front[i] != CANARY_BYTE || a->back[i] != CANARY_BYTE)
			return "a write landed outside the store's entries";
	}

	if (store->used != m->used)
		return "the store and the model hold different numbers of revocations";
	if (store->used > store->capacity)
		return "the store holds more than its capacity";

	for (size_t i = 0; i < store->used; i++) {
		if (!model_holds(m, store->entries[i].capability, store->entries[i].grantee))
			return "the store holds a revocation the rules would not admit";
	}
	for (size_t i = 0; i < m->used; i++) {
		if (!fzn_revocation_covers(store, m->held[i].capability, m->held[i].grantee))
			return "the store dropped a revocation, un-revoking a device";
	}

	/* Its own entries must be a set: a duplicate is a slot spent for
	 * nothing, and the store fails open when it runs out of them. */
	for (size_t i = 0; i < store->used; i++) {
		for (size_t k = i + 1; k < store->used; k++) {
			if (memcmp(store->entries[i].capability,
			           store->entries[k].capability, FZN_CAP_ID_LEN) == 0 &&
			    memcmp(store->entries[i].grantee, store->entries[k].grantee,
			           FZN_PUBKEY_LEN) == 0)
				return "the store holds the same revocation twice";
		}
	}

	return NULL;
}

/* The shape rules as a second implementation, so that `fzn_revocation_open`
 * is held to accepting exactly the set the layout describes. */
static int shape_is_ours(const uint8_t *bytes, size_t len)
{
	if (len != FZN_REVOCATION_LEN)
		return 0;
	if (bytes[FZN_REV_OFF_VERSION] != 1u)
		return 0;
	if (bytes[FZN_REV_OFF_OBJECT] != 2u)
		return 0;
	return 1;
}

static int fuzz_one(const uint8_t *data, size_t len, struct coverage *cov)
{
	struct arena arena;
	fzn_revocation_store_t store;
	struct model model;
	fzn_sign_ops_t sign;
	uint8_t root[FZN_PUBKEY_LEN];
	size_t pos = 0;

	memset(&arena, CANARY_BYTE, sizeof(arena));
	memset(arena.entries, 0, sizeof(arena.entries));
	memset(&model, 0, sizeof(model));
	memset(root, 0x01, sizeof(root));

	sign.verify = stub_verify;
	sign.sign = NULL;
	sign.ctx = NULL;

	if (fzn_revocation_store_init(&store, arena.entries, STORE_CAP) != FZN_CHAIN_OK)
		return 0;

	while (pos + 4 <= len) {
		uint8_t bytes[FZN_REVOCATION_LEN];
		uint8_t capability[FZN_CAP_ID_LEN], grantee[FZN_PUBKEY_LEN];
		uint8_t issuer[FZN_PUBKEY_LEN];
		fzn_revocation_record_t record;
		fzn_chain_err_t err, want;
		const char *broke;
		int issuer_ok, sig_ok, shape_ok, opened;

		/* Small sets, so duplicates and a full store both actually
		 * happen. With random 32-byte values neither would, and the
		 * paths this file exists to check would never be reached --
		 * the failure recorded against the reassembly harness. */
		memset(capability, data[pos] & 0x03u, FZN_CAP_ID_LEN);
		memset(grantee, data[pos + 1] & 0x07u, FZN_PUBKEY_LEN);

		/* Usually the root, sometimes a carrier pretending. The
		 * "sometimes" is what makes the pinning check testable at all,
		 * which chain_fuzz learned the hard way. */
		issuer_ok = (data[pos + 2] & 0x07u) != 0;
		memset(issuer, issuer_ok ? 0x01u : (uint8_t)(0x80u + data[pos + 2]),
		       FZN_PUBKEY_LEN);

		sig_ok = (data[pos + 3] & 0x03u) != 0;
		shape_ok = (data[pos + 3] & 0x40u) == 0;

		if (fzn_revocation_encode(bytes, issuer, capability, grantee, 1000) !=
		    FZN_CHAIN_OK) {
			printf("  MODEL: the generator could not encode a record\n");
			return 1;
		}
		/* `sig_ok` is a statement about THE ISSUER'S signature, so the
		 * signature written is the issuer's or it is rubbish. Every
		 * other identity keeps a good signature, which is what makes a
		 * verifier that asks the wrong party visible: it gets a yes
		 * where the rules below say no. */
		if (sig_ok)
			mac(bytes + FZN_REV_OFF_SIGNATURE, issuer[0], bytes,
			    FZN_REVOCATION_BODY_LEN);
		else
			memset(bytes + FZN_REV_OFF_SIGNATURE, 0x5a, FZN_SIG_LEN);

		/* And sometimes the bytes are not our shape at all, which is
		 * the parser's business rather than admission's. */
		if (!shape_ok)
			bytes[FZN_REV_OFF_OBJECT] = (uint8_t)(1u + (data[pos + 3] >> 7));

		pos += 4;

		opened = fzn_revocation_open(bytes, FZN_REVOCATION_LEN, &record) == FZN_CHAIN_OK;
		if (opened != shape_is_ours(bytes, FZN_REVOCATION_LEN)) {
			printf("  MODEL: the parser and the layout disagree\n");
			return 1;
		}
		if (!opened) {
			cov->shape_refused++;
			continue;
		}
		cov->shape_ok++;

		/* What the rules say should happen, derived here rather than
		 * asked of the module. */
		if (!issuer_ok)
			want = FZN_CHAIN_ERR_WRONG_ROOT;
		else if (!sig_ok)
			want = FZN_CHAIN_ERR_CHAIN_INVALID;
		else if (model_holds(&model, capability, grantee))
			want = FZN_CHAIN_OK; /* already known is success */
		else if (model.used == STORE_CAP)
			want = FZN_CHAIN_ERR_STORE_FULL;
		else
			want = FZN_CHAIN_OK;

		err = fzn_revocation_admit(&store, record, root, &sign);

		if (err != want) {
			printf("  MODEL: admit returned %d, rules say %d\n", (int)err, (int)want);
			return 1;
		}

		if (want == FZN_CHAIN_OK) {
			if (model_holds(&model, capability, grantee)) {
				cov->duplicate++;
			} else {
				memcpy(model.held[model.used].capability, capability,
				       FZN_CAP_ID_LEN);
				memcpy(model.held[model.used].grantee, grantee, FZN_PUBKEY_LEN);
				model.used++;
				cov->admitted++;
			}
		} else if (want == FZN_CHAIN_ERR_STORE_FULL) {
			cov->full++;
		} else {
			cov->refused++;
		}

		broke = agree(&arena, &store, &model);
		if (broke) {
			printf("  MODEL: %s\n", broke);
			return 1;
		}
	}

	return 0;
}

#ifdef FZN_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct coverage cov = { 0, 0, 0, 0, 0, 0 };

	(void)fuzz_one(data, size, &cov);
	return 0;
}
#else

static uint32_t next(uint32_t *state)
{
	*state = (*state * 1103515245u) + 12345u;
	return (*state >> 16) & 0xffffu;
}


/* THE FLOOR A COUNTER MUST CLEAR, AND IT IS NEVER ZERO.
 *
 * These floors were written as `floor_of(cases, 200u)` directly. Integer division
 * makes that ZERO for any run under 200 cases, and `unsigned < 0` is never
 * true -- so every coverage floor in this file switched itself off silently,
 * exactly when somebody lowered CASES. Which is precisely what one does when
 * running under a sanitizer, the case the Makefile advertises.
 *
 * Measured before this: `make fuzz CASES=199` exited 0 with chain_fuzz
 * reporting "0 delegated", the counter whose own comment says a run without
 * it "proves less than it says". At CASES=1 it reported 0 accepted and 0
 * delegated and still passed.
 *
 * One is the weakest honest floor: a harness that reached the interesting
 * path zero times out of one case has still reached it zero times. */
static unsigned long floor_of(unsigned long cases, unsigned long per)
{
	unsigned long n = cases / per;

	return n != 0ul ? n : 1ul;
}

int main(int argc, char **argv)
{
	unsigned long cases = FUZZ_DEFAULT_CASES;
	struct coverage cov = { 0, 0, 0, 0, 0, 0 };
	uint8_t buf[128];

	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
	}

	if (cases < FUZZ_MIN_CASES) {
		printf("revocation_fuzz: %lu cases is below FUZZ_MIN_CASES (%u), so this run will "
		       "not report success -- every coverage floor below that is "
		       "cleared by a single lucky hit. Re-run with %u or more.\n",
		       cases, (unsigned)FUZZ_MIN_CASES, (unsigned)FUZZ_MIN_CASES);
		return 1;
	}

	for (unsigned long c = 0; c < cases; c++) {
		uint32_t state = (uint32_t)c + 1u;
		size_t len = (size_t)(next(&state) % (sizeof(buf) + 1u));

		for (size_t i = 0; i < len; i++)
			buf[i] = (uint8_t)next(&state);

		if (fuzz_one(buf, len, &cov)) {
			printf("revocation_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	/* Every path this file is about has to occur. A full store in
	 * particular: it is the refusal that fails OPEN, so a run that never
	 * filled one has not tested the case that matters most. The two parser
	 * counters are the same argument: a parser that refused everything
	 * would satisfy a run that never watched it accept anything. */
	if (cov.admitted < floor_of(cases, 200u) || cov.refused < floor_of(cases, 200u) ||
	    cov.duplicate < floor_of(cases, 200u) || cov.full == 0 ||
	    cov.shape_ok < floor_of(cases, 200u) || cov.shape_refused < floor_of(cases, 200u)) {
		printf("revocation_fuzz: REACHED TOO LITTLE -- %lu admitted, %lu refused, "
		       "%lu duplicate, %lu full, %lu shapes accepted, %lu shapes refused in "
		       "%lu cases.\n",
		       cov.admitted, cov.refused, cov.duplicate, cov.full, cov.shape_ok,
		       cov.shape_refused, cases);
		return 1;
	}

	printf("revocation_fuzz: %lu cases, %lu admitted, %lu refused, %lu duplicate, "
	       "%lu full, %lu shapes accepted, %lu shapes refused, model agreed throughout\n",
	       cases, cov.admitted, cov.refused, cov.duplicate, cov.full, cov.shape_ok,
	       cov.shape_refused);
	return 0;
}
#endif
