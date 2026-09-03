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
 * IT NAMES TWO ROOTS (2026-08-27), and that is not breadth for its own
 * sake. It pinned one, and `fzn_revocation_admit` refuses any other issuer,
 * so every entry the store or the model could hold carried that single key
 * -- which left the model's issuer term decided by nothing at all. Proven
 * by deleting the comparison: the whole run's output was byte-identical.
 * The state the term exists for is a store holding two revocations that
 * differ ONLY in who withdrew them, which is what a host anchoring two
 * roots reaches on an ordinary day, and no harness in the tree modelled it.
 *
 * Bounded and seeded like the others, and it counts what it reached --
 * admissions, refusals, duplicates, a full store, both answers from the
 * parser, and the two states above must all occur, or the run exercised
 * less than it appears to.
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

/* Expand a one-byte identity into a full-length value.
 *
 * BYTE 0 IS THE SEED, BECAUSE THE STUB ABOVE KEYS ITS MAC OFF `pubkey[0]`.
 * Every later byte varies with its position, and that is the half this
 * harness was missing: it built every key and capability as thirty-two
 * copies of one seed, so a value answered any prefix exactly as it answered
 * the whole. `memeq(a, b, 1)` and `memeq(a, b, FZN_PUBKEY_LEN)` were the
 * same function over everything generated here, and all three comparisons
 * in `chain/revocation.c`'s `same()` could be cut to a single byte without
 * one of 200000 cases noticing. */
static void expand(uint8_t *out, size_t len, uint8_t seed)
{
	out[0] = seed;
	for (size_t i = 1; i < len; i++)
		out[i] = (uint8_t)(seed ^ (uint8_t)i);
}

/* The same value with only its LAST byte changed -- the pair that decides a
 * comparison's LENGTH.
 *
 * Position-varying values do not close the gap on their own: two built from
 * equal seeds are equal everywhere, so a truncated comparison still answers
 * what a full one would. A near miss agrees on every byte a short read
 * reaches and differs on one it does not, so a single pair settles every
 * truncation from one byte to thirty-one.
 *
 * Identity is untouched, so a near-miss issuer still signs and verifies and
 * reaches the duplicate test rather than being turned away at the
 * signature. That is what makes the fail-open direction reachable: a
 * duplicate test reading a prefix calls two genuine revocations one, drops
 * the second, and returns FZN_CHAIN_OK. */
static void expand_near(uint8_t *out, size_t len, uint8_t seed)
{
	expand(out, len, seed);
	out[len - 1] = (uint8_t)(out[len - 1] ^ 0xffu);
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
	unsigned long issuer_only;
	unsigned long near_miss;
};

static int model_holds(const struct model *m, const uint8_t *issuer, const fzn_cap_id_t *cap,
                       const uint8_t *grantee)
{
	for (size_t i = 0; i < m->used; i++) {
		if (memcmp(m->held[i].issuer, issuer, FZN_PUBKEY_LEN) == 0 &&
		    memcmp(m->held[i].capability.b, cap, FZN_CAP_ID_LEN) == 0 &&
		    memcmp(m->held[i].grantee, grantee, FZN_PUBKEY_LEN) == 0)
			return 1;
	}
	return 0;
}

/* THE TWO COUNTERS BELOW EXIST BECAUSE A MODEL TERM NO INPUT CAN DECIDE IS
 * NOT A MODEL TERM. Each names a state the store has to reach, and each is
 * floored in `main`, so a later change to the generator that stops producing
 * it fails the run instead of quietly reporting the same numbers.
 *
 * Does the model already hold an entry with this capability and grantee but
 * a DIFFERENT issuer? That pair -- two revocations differing only in who
 * withdrew them -- is the whole reason `model_holds` compares the issuer at
 * all, and this harness could not reach it: it pinned one root, and
 * `fzn_revocation_admit` refuses every other issuer, so every entry the
 * store or the model could hold carried that one key. Proven: deleting the
 * issuer comparison from `model_holds` left this file's output
 * byte-identical over 20000 cases. Two roots is what gives the term
 * something to decide, and a host anchoring two roots keeps one store, so
 * the state is the deployment rather than a contrivance. */
static int model_holds_under_another_issuer(const struct model *m, const uint8_t *issuer,
                                            const fzn_cap_id_t *cap, const uint8_t *grantee)
{
	for (size_t i = 0; i < m->used; i++) {
		if (memcmp(m->held[i].capability.b, cap, FZN_CAP_ID_LEN) == 0 &&
		    memcmp(m->held[i].grantee, grantee, FZN_PUBKEY_LEN) == 0 &&
		    memcmp(m->held[i].issuer, issuer, FZN_PUBKEY_LEN) != 0)
			return 1;
	}
	return 0;
}

static int differs_only_in_the_last_byte(const uint8_t *a, const uint8_t *b, size_t len)
{
	return memcmp(a, b, len - 1u) == 0 && a[len - 1u] != b[len - 1u];
}

/* And does it hold one this entry agrees with in two fields and differs from
 * in the third only at its LAST byte? That is the pair a comparison's LENGTH
 * decides, and the store reaching it is what makes a truncated `same()`
 * observable: the duplicate test calls the two one revocation, drops the
 * second, and returns FZN_CHAIN_OK. */
static int model_holds_a_near_miss(const struct model *m, const uint8_t *issuer,
                                   const fzn_cap_id_t *cap, const uint8_t *grantee)
{
	for (size_t i = 0; i < m->used; i++) {
		const fzn_revocation_t *e = &m->held[i];
		int issuer_same = memcmp(e->issuer, issuer, FZN_PUBKEY_LEN) == 0;
		int cap_same = memcmp(e->capability.b, cap, FZN_CAP_ID_LEN) == 0;
		int grantee_same = memcmp(e->grantee, grantee, FZN_PUBKEY_LEN) == 0;

		if (cap_same && grantee_same &&
		    differs_only_in_the_last_byte(e->issuer, issuer, FZN_PUBKEY_LEN))
			return 1;
		if (issuer_same && grantee_same &&
		    differs_only_in_the_last_byte(e->capability.b, cap->b, FZN_CAP_ID_LEN))
			return 1;
		if (issuer_same && cap_same &&
		    differs_only_in_the_last_byte(e->grantee, grantee, FZN_PUBKEY_LEN))
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
		if (!model_holds(m, store->entries[i].issuer, &store->entries[i].capability,
		                 store->entries[i].grantee))
			return "the store holds a revocation the rules would not admit";
	}
	for (size_t i = 0; i < m->used; i++) {
		if (!fzn_revocation_covers(store, m->held[i].issuer, &m->held[i].capability,
		                           m->held[i].grantee))
			return "the store dropped a revocation, un-revoking a device";
	}

	/* Its own entries must be a set: a duplicate is a slot spent for
	 * nothing, and the store fails open when it runs out of them. */
	for (size_t i = 0; i < store->used; i++) {
		for (size_t k = i + 1; k < store->used; k++) {
			if (memcmp(store->entries[i].issuer, store->entries[k].issuer,
			           FZN_PUBKEY_LEN) == 0 &&
			    memcmp(store->entries[i].capability.b,
			           store->entries[k].capability.b, FZN_CAP_ID_LEN) == 0 &&
			    memcmp(store->entries[i].grantee, store->entries[k].grantee,
			           FZN_PUBKEY_LEN) == 0)
				return "the store holds the same revocation twice";
		}
	}

	return NULL;
}

/* The constants the oracle restates, named and asserted against the header.
 * Same discipline as `chain/test/chain_fuzz.c` and `record/test/record_fuzz.c`
 * -- the value is written out so the oracle stays a SECOND implementation
 * rather than a second reading of the enum, and the assert is what makes a
 * deliberate change fail at this line instead of on some seed. */
#define WANT_REV_VERSION 1u
#define WANT_REV_OBJECT  129u

_Static_assert(WANT_REV_VERSION == (unsigned)FZN_SIGNED_VERSION,
               "oracle: the version byte moved");
_Static_assert(WANT_REV_OBJECT == (unsigned)FZN_OBJECT_REVOCATION,
               "oracle: the object byte moved");

/* The shape rules as a second implementation, so that `fzn_revocation_open`
 * is held to accepting exactly the set the layout describes. */
static int shape_is_ours(const uint8_t *bytes, size_t len)
{
	if (len != FZN_REVOCATION_LEN)
		return 0;
	if (bytes[FZN_REV_OFF_VERSION] != WANT_REV_VERSION)
		return 0;
	if (bytes[FZN_REV_OFF_OBJECT] != WANT_REV_OBJECT)
		return 0;
	return 1;
}

static int fuzz_one(const uint8_t *data, size_t len, struct coverage *cov)
{
	struct arena arena;
	fzn_revocation_store_t store;
	struct model model;
	fzn_sign_ops_t sign;
	uint8_t roots[2][FZN_PUBKEY_LEN];
	size_t pos = 0;

	memset(&arena, CANARY_BYTE, sizeof(arena));
	memset(arena.entries, 0, sizeof(arena.entries));
	memset(&model, 0, sizeof(model));

	/* TWO ROOTS, ONE STORE, AND EACH RECORD ADMITTED UNDER THE ROOT IT
	 * NAMES. See `model_holds_under_another_issuer` for what pinning a
	 * single root cost: the model's issuer term was decided by nothing,
	 * and deleting it changed no byte of this file's output. chain_fuzz
	 * records the same trap in the same words -- always naming the root
	 * puts a term in the model that no input can decide. */
	expand(roots[0], FZN_PUBKEY_LEN, 0x01u);
	expand(roots[1], FZN_PUBKEY_LEN, 0x02u);

	sign.verify = stub_verify;
	sign.sign = NULL;
	sign.ctx = NULL;

	if (fzn_revocation_store_init(&store, arena.entries, STORE_CAP) != FZN_CHAIN_OK)
		return 0;

	while (pos + 4 <= len) {
		uint8_t bytes[FZN_REVOCATION_LEN];
		uint8_t grantee[FZN_PUBKEY_LEN];
		fzn_cap_id_t capability;
		uint8_t issuer[FZN_PUBKEY_LEN];
		fzn_revocation_record_t record;
		fzn_chain_err_t err, want;
		const char *broke;
		unsigned which;
		int issuer_ok, sig_ok, shape_ok, opened;

		/* WHICH OF THE TWO ROOTS THIS RECORD IS OFFERED TO. The store
		 * is one store either way, so it ends up holding entries from
		 * both -- including pairs that differ only in the issuer. */
		which = data[pos + 2] & 1u;

		/* Small sets, so duplicates and a full store both actually
		 * happen. With random 32-byte values neither would, and the
		 * paths this file exists to check would never be reached --
		 * the failure recorded against the reassembly harness.
		 *
		 * Sometimes a NEAR MISS instead -- the same value with only
		 * its last byte changed. That is the pair `same()`'s length
		 * decides, and without it every value here was one byte
		 * repeated and the length decided nothing. */
		if ((data[pos + 3] & 0x0cu) == 0)
			expand_near(capability.b, FZN_CAP_ID_LEN, data[pos] & 0x03u);
		else
			expand(capability.b, FZN_CAP_ID_LEN, data[pos] & 0x03u);
		if ((data[pos + 3] & 0x30u) == 0)
			expand_near(grantee, FZN_PUBKEY_LEN, data[pos + 1] & 0x07u);
		else
			expand(grantee, FZN_PUBKEY_LEN, data[pos + 1] & 0x07u);

		/* Usually the root this record is offered to, sometimes a
		 * carrier pretending. The "sometimes" is what makes the
		 * pinning check testable at all, which chain_fuzz learned the
		 * hard way -- and one of those pretenders is the root with a
		 * single byte changed at the far end, which is what makes the
		 * pin's LENGTH testable too. */
		issuer_ok = (data[pos + 2] & 0x0eu) != 0;
		if (issuer_ok)
			memcpy(issuer, roots[which], FZN_PUBKEY_LEN);
		else if ((data[pos + 2] & 0x70u) == 0)
			expand_near(issuer, FZN_PUBKEY_LEN, (uint8_t)(0x01u + which));
		else
			expand(issuer, FZN_PUBKEY_LEN, (uint8_t)(0x80u + data[pos + 2]));

		sig_ok = (data[pos + 3] & 0x03u) != 0;
		shape_ok = (data[pos + 3] & 0x40u) == 0;

		if (fzn_revocation_encode(bytes, (uint8_t)FZN_OBJECT_REVOCATION, issuer,
		                          &capability, grantee, 1000, NULL) !=
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
			bytes[FZN_REV_OFF_OBJECT] =
			        (data[pos + 3] >> 7) ? (uint8_t)FZN_OBJECT_REVOCATION
			                             : (uint8_t)FZN_OBJECT_HOP;

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
		else if (model_holds(&model, issuer, &capability, grantee))
			want = FZN_CHAIN_OK; /* already known is success */
		else if (model.used == STORE_CAP)
			want = FZN_CHAIN_ERR_STORE_FULL;
		else
			want = FZN_CHAIN_OK;

		err = fzn_revocation_admit(&store, fzn_revocation_offer_root(record), roots[which], &sign, NULL);

		if (err != want) {
			printf("  MODEL: admit returned %d, rules say %d\n", (int)err, (int)want);
			return 1;
		}

		if (want == FZN_CHAIN_OK) {
			if (model_holds(&model, issuer, &capability, grantee)) {
				cov->duplicate++;
			} else {
				/* Counted BEFORE the append, so each counts the
				 * entry that reached the state rather than
				 * every entry that stays in it. */
				if (model_holds_under_another_issuer(&model, issuer,
				                                     &capability, grantee))
					cov->issuer_only++;
				if (model_holds_a_near_miss(&model, issuer, &capability,
				                            grantee))
					cov->near_miss++;
				memcpy(model.held[model.used].capability.b, capability.b,
				       FZN_CAP_ID_LEN);
				memcpy(model.held[model.used].grantee, grantee, FZN_PUBKEY_LEN);
				memcpy(model.held[model.used].issuer, issuer, FZN_PUBKEY_LEN);
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
	struct coverage cov = { 0, 0, 0, 0, 0, 0, 0, 0 };

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
	struct coverage cov = { 0, 0, 0, 0, 0, 0, 0, 0 };
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
	/* The last two are floors on the STATES the model's own terms need in
	 * order to be decided by anything, rather than on paths through the
	 * module. A run that never held two entries differing only in their
	 * issuer has not tested the issuer comparison, however many records it
	 * pushed through; a run that never held two differing only in a
	 * field's last byte has not tested any comparison's length. Both were
	 * unreachable before, and a counter is what stops them becoming
	 * unreachable again without a word. */
	if (cov.admitted < floor_of(cases, 200u) || cov.refused < floor_of(cases, 200u) ||
	    cov.duplicate < floor_of(cases, 200u) || cov.full == 0 ||
	    cov.shape_ok < floor_of(cases, 200u) || cov.shape_refused < floor_of(cases, 200u) ||
	    cov.issuer_only < floor_of(cases, 200u) || cov.near_miss < floor_of(cases, 200u)) {
		printf("revocation_fuzz: REACHED TOO LITTLE -- %lu admitted, %lu refused, "
		       "%lu duplicate, %lu full, %lu shapes accepted, %lu shapes refused, "
		       "%lu issuer-only pairs, %lu near misses in %lu cases.\n",
		       cov.admitted, cov.refused, cov.duplicate, cov.full, cov.shape_ok,
		       cov.shape_refused, cov.issuer_only, cov.near_miss, cases);
		return 1;
	}

	printf("revocation_fuzz: %lu cases, %lu admitted, %lu refused, %lu duplicate, "
	       "%lu full, %lu shapes accepted, %lu shapes refused, %lu issuer-only pairs, "
	       "%lu near misses, model agreed throughout\n",
	       cases, cov.admitted, cov.refused, cov.duplicate, cov.full, cov.shape_ok,
	       cov.shape_refused, cov.issuer_only, cov.near_miss);
	return 0;
}
#endif
