/* A fuzz harness for the revocation admission path.
 *
 * project.md sec 4.2 has revocation carried on contact, so a record arrives
 * from a peer that is NOT its issuer -- every field of it is a stranger's,
 * including the issuer it names and the signature it offers. That is the
 * hostile surface, and `chain/tests/chain_fuzz.c` does not touch it: that
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
 * The shadow is a second implementation of the rules on purpose, for the
 * reason chain_fuzz gives: a model that asked the module what it did would
 * agree with it always, including when both are wrong.
 *
 * Bounded and seeded like the others, and it counts what it reached --
 * admissions, refusals, duplicates and a full store must all occur, or the
 * run exercised less than it appears to.
 */

#include "../revocation.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u
#define STORE_CAP 6
#define CANARY 16
#define CANARY_BYTE 0x7e

static const uint8_t REGION[] = "a revocation, as the schema would lay it out";

struct stub {
	int answer;
};

static int stub_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	(void)pubkey;
	(void)msg;
	(void)msg_len;
	(void)sig;
	return ((struct stub *)ctx)->answer;
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

static int fuzz_one(const uint8_t *data, size_t len, struct coverage *cov)
{
	struct arena arena;
	fzn_revocation_store_t store;
	struct model model;
	struct stub stub = { 1 };
	fzn_sign_ops_t sign;
	uint8_t root[FZN_PUBKEY_LEN];
	size_t pos = 0;

	memset(&arena, CANARY_BYTE, sizeof(arena));
	memset(arena.entries, 0, sizeof(arena.entries));
	memset(&model, 0, sizeof(model));
	memset(root, 0x01, sizeof(root));

	sign.verify = stub_verify;
	sign.sign = NULL;
	sign.ctx = &stub;

	if (fzn_revocation_store_init(&store, arena.entries, STORE_CAP) != FZN_OK)
		return 0;

	while (pos + 4 <= len) {
		fzn_revocation_record_t r;
		fzn_err_t err, want;
		const char *broke;
		int issuer_ok, sig_ok, region_ok;

		memset(&r, 0, sizeof(r));

		/* Small sets, so duplicates and a full store both actually
		 * happen. With random 32-byte values neither would, and the
		 * paths this file exists to check would never be reached --
		 * the failure recorded against the reassembly harness. */
		memset(r.capability, data[pos] & 0x03u, FZN_CAP_ID_LEN);
		memset(r.grantee, data[pos + 1] & 0x07u, FZN_PUBKEY_LEN);

		/* Usually the root, sometimes a carrier pretending. The
		 * "sometimes" is what makes the pinning check testable at all,
		 * which chain_fuzz learned the hard way. */
		issuer_ok = (data[pos + 2] & 0x07u) != 0;
		memset(r.issuer, issuer_ok ? 0x01u : (uint8_t)(0x80u + data[pos + 2]),
		       FZN_PUBKEY_LEN);

		sig_ok = (data[pos + 3] & 0x03u) != 0;
		stub.answer = sig_ok;

		region_ok = (data[pos + 3] & 0x40u) == 0;
		r.signed_region = region_ok ? REGION : NULL;
		r.signed_region_len = region_ok ? sizeof(REGION) - 1 : 0;
		r.issued_at = 1000;
		pos += 4;

		/* What the rules say should happen, derived here rather than
		 * asked of the module. */
		if (!region_ok)
			want = FZN_ERR_MALFORMED;
		else if (!issuer_ok)
			want = FZN_ERR_WRONG_ROOT;
		else if (!sig_ok)
			want = FZN_ERR_CHAIN_INVALID;
		else if (model_holds(&model, r.capability, r.grantee))
			want = FZN_OK; /* already known is success */
		else if (model.used == STORE_CAP)
			want = FZN_ERR_STORE_FULL;
		else
			want = FZN_OK;

		err = fzn_revocation_admit(&store, &r, root, &sign);

		if (err != want) {
			printf("  MODEL: admit returned %d, rules say %d\n", (int)err, (int)want);
			return 1;
		}

		if (want == FZN_OK) {
			if (model_holds(&model, r.capability, r.grantee)) {
				cov->duplicate++;
			} else {
				memcpy(model.held[model.used].capability, r.capability,
				       FZN_CAP_ID_LEN);
				memcpy(model.held[model.used].grantee, r.grantee,
				       FZN_PUBKEY_LEN);
				model.used++;
				cov->admitted++;
			}
		} else if (want == FZN_ERR_STORE_FULL) {
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
	struct coverage cov = { 0, 0, 0, 0 };

	(void)fuzz_one(data, size, &cov);
	return 0;
}
#else

static uint32_t next(uint32_t *state)
{
	*state = (*state * 1103515245u) + 12345u;
	return (*state >> 16) & 0xffffu;
}

int main(int argc, char **argv)
{
	unsigned long cases = FUZZ_DEFAULT_CASES;
	struct coverage cov = { 0, 0, 0, 0 };
	uint8_t buf[128];

	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
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
	 * filled one has not tested the case that matters most. */
	if (cov.admitted < cases / 200u || cov.refused < cases / 200u ||
	    cov.duplicate < cases / 200u || cov.full == 0) {
		printf("revocation_fuzz: REACHED TOO LITTLE -- %lu admitted, %lu refused, "
		       "%lu duplicate, %lu full in %lu cases.\n",
		       cov.admitted, cov.refused, cov.duplicate, cov.full, cases);
		return 1;
	}

	printf("revocation_fuzz: %lu cases, %lu admitted, %lu refused, %lu duplicate, "
	       "%lu full, model agreed throughout\n",
	       cases, cov.admitted, cov.refused, cov.duplicate, cov.full);
	return 0;
}
#endif
