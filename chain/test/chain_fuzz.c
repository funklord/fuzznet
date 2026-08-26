/* A fuzz harness for the capability chain and the revocation store.
 *
 * project.md sec 4.2 is what this is protecting. A chain arrives from the
 * network entire -- hop count, every key, every date, and the revocations
 * offered alongside it -- so all of it is a stranger's to choose.
 *
 * WHAT IT ASSERTS IS DIFFERENT FROM THE REASSEMBLY HARNESS, and the
 * difference is worth stating because it decides what this is worth.
 * chain.c owns no buffers, so there is nothing here for a canary to guard;
 * a bug in it is not an overrun, it is an ACCEPTANCE. So the invariants are
 * the security properties the header claims, checked against every verdict:
 *
 *   - a chain that verifies is rooted at the pinned root, links end to
 *     end, is single-capability, and has no hop whose grant was revoked;
 *   - a chain that verifies reports the last hop's grantee, and an expiry
 *     that is the soonest real one across its hops;
 *   - a REFUSED chain leaves *out untouched, so a caller cannot half-read
 *     a rejected chain -- a claim chain.h makes and nothing else measures
 *     over arbitrary input;
 *   - verification never costs more signature checks than there are hops.
 *
 * The last one is a denial-of-service property rather than a correctness
 * one: signature verification is the expensive operation, and a chain that
 * could buy more of them than it has hops would be a way to spend a
 * receiver's CPU for the price of one datagram.
 *
 * Bounded and seeded exactly as chunk/test/reassembly_fuzz.c is, and for
 * the reasons given there at length. It counts what it reached and refuses
 * to report success below a floor, because that harness reported success
 * over 200000 cases while reaching almost nothing.
 */

#include "../chain.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u
#define MAX_HOPS FZN_CHAIN_MAX_HOPS
#define MAX_REVS 4

static const uint8_t REGION[] = "a hop, as the schema would lay it out";

struct stub {
	int calls;
	int answer;
	int fail_on;
};

static int stub_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	struct stub *s = (struct stub *)ctx;

	(void)pubkey;
	(void)sig;
	(void)msg;
	(void)msg_len;
	s->calls++;
	if (s->fail_on && s->calls == s->fail_on)
		return 0;
	return s->answer;
}

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	(void)ctx;
	(void)msg;
	(void)msg_len;
	memset(sig, 0x5a, FZN_SIG_LEN);
	return 1;
}

struct coverage {
	unsigned long verified_ok;
	unsigned long refused;
	unsigned long delegated_ok;
};

/* Re-derive, from the hops themselves, whether this chain should have been
 * accepted. Deliberately a SECOND implementation of the rules rather than a
 * call into the first: a checker that asked chain.c whether chain.c was
 * right would agree with it always, including when both are wrong. */
static int ought_to_verify(const fzn_chain_hop_t *hops, size_t n, const uint8_t *root,
                           const uint8_t *cap, uint64_t now, const fzn_revocation_t *revs,
                           size_t nrevs)
{
	if (n == 0 || n > MAX_HOPS)
		return 0;
	if (memcmp(hops[0].grantor, root, FZN_PUBKEY_LEN) != 0)
		return 0;

	for (size_t i = 0; i < n; i++) {
		if (!hops[i].signed_region || hops[i].signed_region_len == 0)
			return 0;
		if (memcmp(hops[i].capability, cap, FZN_CAP_ID_LEN) != 0)
			return 0;
		if (i > 0) {
			if (memcmp(hops[i].grantor, hops[i - 1].grantee, FZN_PUBKEY_LEN) != 0)
				return 0;
			if (!hops[i - 1].delegable)
				return 0;
		}
		if (hops[i].expires_at != FZN_NO_EXPIRY) {
			if (hops[i].expires_at <= hops[i].issued_at)
				return 0;
			if (hops[i].expires_at <= now)
				return 0;
		}
		for (size_t r = 0; r < nrevs; r++) {
			if (memcmp(revs[r].capability, hops[i].capability, FZN_CAP_ID_LEN) == 0 &&
			    memcmp(revs[r].grantee, hops[i].grantee, FZN_PUBKEY_LEN) == 0)
				return 0;
		}
	}
	return 1;
}

/* The soonest real expiry, recomputed independently. */
static uint64_t ought_expiry(const fzn_chain_hop_t *hops, size_t n)
{
	uint64_t soonest = FZN_NO_EXPIRY;

	for (size_t i = 0; i < n; i++) {
		if (hops[i].expires_at == FZN_NO_EXPIRY)
			continue;
		if (soonest == FZN_NO_EXPIRY || hops[i].expires_at < soonest)
			soonest = hops[i].expires_at;
	}
	return soonest;
}

static int fuzz_one(const uint8_t *data, size_t len, struct coverage *cov)
{
	fzn_chain_hop_t hops[MAX_HOPS];
	fzn_revocation_t revs[MAX_REVS];
	uint8_t root[FZN_PUBKEY_LEN], cap[FZN_CAP_ID_LEN];
	struct stub stub = { 0, 1, 0 };
	fzn_sign_ops_t sign;
	fzn_chain_t out, before;
	size_t n, nrevs;
	uint64_t now;
	fzn_chain_err_t err;
	size_t pos = 0;

	if (len < 8)
		return 0;

	sign.verify = stub_verify;
	sign.sign = stub_sign;
	sign.ctx = &stub;

	memset(root, data[0] & 0x03u, sizeof(root));
	memset(cap, data[1] & 0x03u, sizeof(cap));
	now = data[2] * 100u;
	stub.answer = (data[3] & 0x0fu) != 0; /* usually good, sometimes not */
	stub.fail_on = (data[4] & 0x1fu) == 0 ? 1 + (data[4] >> 5) : 0;
	n = 1u + (data[5] % (MAX_HOPS + 1u)); /* sometimes one past the ceiling */
	nrevs = data[6] % (MAX_REVS + 1u);
	pos = 8;

	/* Hops are built to LINK most of the time. A chain assembled from
	 * uniform random keys never links past hop 0, so every rule beyond
	 * the first would be unreachable -- the failure the reassembly
	 * harness was rebuilt to avoid. */
	for (size_t i = 0; i < n && i < MAX_HOPS; i++) {
		uint8_t b = (pos + 4 <= len) ? data[pos] : (uint8_t)i;
		uint8_t linked = (pos + 4 <= len) ? (data[pos + 1] & 0x07u) : 1u;

		memset(&hops[i], 0, sizeof(hops[i]));
		if (i == 0) {
			/* Usually the pinned root, sometimes NOT -- and the
			 * "sometimes not" is the whole value of this line. An
			 * earlier version always rooted hop 0 correctly, so a
			 * chain rooted elsewhere never occurred, and deleting
			 * the pinning check in chain.c changed no outcome and
			 * was invisible to 200000 cases. A generator that
			 * cannot produce the input a check rejects cannot test
			 * that check. */
			if ((data[pos + 2] & 0x07u) == 0)
				memset(hops[i].grantor, (uint8_t)(0xd0u + b), FZN_PUBKEY_LEN);
			else
				memcpy(hops[i].grantor, root, FZN_PUBKEY_LEN);
		}
		else if (linked)
			memcpy(hops[i].grantor, hops[i - 1].grantee, FZN_PUBKEY_LEN);
		else
			memset(hops[i].grantor, b, FZN_PUBKEY_LEN);

		memset(hops[i].grantee, (uint8_t)(0x10u + i), FZN_PUBKEY_LEN);
		if ((b & 0x0fu) != 0)
			memcpy(hops[i].capability, cap, FZN_CAP_ID_LEN);
		else
			memset(hops[i].capability, b, FZN_CAP_ID_LEN);

		hops[i].issued_at = 100;
		hops[i].expires_at = ((b >> 4) & 1u) ? 0u : (uint64_t)b * 50u;
		hops[i].delegable = (linked & 1u) ? 1 : 0;
		hops[i].signed_region = REGION;
		hops[i].signed_region_len = sizeof(REGION) - 1;
		pos += 4;
	}
	if (n > MAX_HOPS)
		n = MAX_HOPS + 1u; /* let the module refuse it */

	for (size_t r = 0; r < nrevs; r++) {
		memset(&revs[r], 0, sizeof(revs[r]));
		memcpy(revs[r].capability, cap, FZN_CAP_ID_LEN);
		memset(revs[r].grantee, (uint8_t)(0x10u + (r % MAX_HOPS)), FZN_PUBKEY_LEN);
	}

	memset(&out, 0xab, sizeof(out));
	before = out;

	err = fzn_chain_verify(hops, n, root, cap, now, &sign, nrevs ? revs : NULL, nrevs,
	                       &out);

	if (err == FZN_CHAIN_OK) {
		cov->verified_ok++;

		if (n == 0 || n > MAX_HOPS) {
			printf("  INVARIANT: accepted a chain of %zu hops\n", n);
			return 1;
		}
		if (!ought_to_verify(hops, n, root, cap, now, nrevs ? revs : NULL, nrevs)) {
			printf("  INVARIANT: accepted a chain the rules refuse\n");
			return 1;
		}
		if (memcmp(out.grantee, hops[n - 1].grantee, FZN_PUBKEY_LEN) != 0) {
			printf("  INVARIANT: reported the wrong grantee\n");
			return 1;
		}
		if (out.hop_count != n) {
			printf("  INVARIANT: hop_count %zu, wanted %zu\n", out.hop_count, n);
			return 1;
		}
		if (out.expires_at != ought_expiry(hops, n)) {
			printf("  INVARIANT: expiry %llu, wanted %llu\n",
			       (unsigned long long)out.expires_at,
			       (unsigned long long)ought_expiry(hops, n));
			return 1;
		}
	} else {
		cov->refused++;

		/* chain.h claims a refused chain leaves *out untouched. */
		if (memcmp(&before, &out, sizeof(before)) != 0) {
			printf("  INVARIANT: a refused chain wrote into *out\n");
			return 1;
		}
		/* And that a chain the rules accept is not refused -- the
		 * other direction, which catches an over-eager refusal that
		 * would look like safety. */
		if (stub.answer && !stub.fail_on && n <= MAX_HOPS &&
		    ought_to_verify(hops, n, root, cap, now, nrevs ? revs : NULL, nrevs)) {
			printf("  INVARIANT: refused a chain the rules accept (err %d)\n",
			       (int)err);
			return 1;
		}
	}

	if ((size_t)stub.calls > n) {
		printf("  INVARIANT: %d signature checks for %zu hops\n", stub.calls, n);
		return 1;
	}

	/* Delegation, on a chain that verified. */
	if (err == FZN_CHAIN_OK && n < MAX_HOPS) {
		fzn_chain_hop_t fresh;
		uint8_t grantee[FZN_PUBKEY_LEN];

		memset(grantee, 0xf0, sizeof(grantee));
		if (fzn_chain_delegate(hops, n, root, cap, now, grantee, 0, 0, REGION,
		                       sizeof(REGION) - 1, &sign, nrevs ? revs : NULL, nrevs,
		                       &fresh) == FZN_CHAIN_OK) {
			cov->delegated_ok++;

			if (!hops[n - 1].delegable) {
				printf("  INVARIANT: delegated from a chain that forbids it\n");
				return 1;
			}
			if (out.expires_at != FZN_NO_EXPIRY &&
			    (fresh.expires_at == FZN_NO_EXPIRY ||
			     fresh.expires_at > out.expires_at)) {
				printf("  INVARIANT: delegation widened the expiry\n");
				return 1;
			}
		}
	}

	return 0;
}

#ifdef FZN_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct coverage cov = { 0, 0, 0 };

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
	struct coverage cov = { 0, 0, 0 };
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
			printf("chain_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	/* Both directions must occur, or the run proves only one of them.
	 * A harness that never accepted a chain would report success against
	 * a verify that refused everything; one that never refused would
	 * report success against a verify that accepted everything. */
	/* DELEGATION IS FLOORED LOWER, and the number is chosen from the
	 * observed rate rather than picked. A successful delegation needs a
	 * chain that verifies AND a last hop marked delegable, so it is the
	 * rarest thing here: 151 in 20000 when this was written. A floor of
	 * cases/200 would sit at 100 and fail on any drift, which is the way a
	 * floor stops meaning anything -- it gets raised until it is noise.
	 * cases/1000 leaves seven times the observed margin and still catches
	 * delegation disappearing, which is what it is for. */
	if (cov.verified_ok < floor_of(cases, 200u) || cov.refused < floor_of(cases, 200u) ||
	    cov.delegated_ok < floor_of(cases, 1000u)) {
		printf("chain_fuzz: REACHED TOO LITTLE -- %lu accepted, %lu refused, "
		       "%lu delegated in %lu cases. All must happen or this run proves "
		       "less than it says.\n",
		       cov.verified_ok, cov.refused, cov.delegated_ok, cases);
		return 1;
	}

	printf("chain_fuzz: %lu cases, %lu accepted, %lu refused, %lu delegated, "
	       "no invariant broken\n",
	       cases, cov.verified_ok, cov.refused, cov.delegated_ok);
	return 0;
}
#endif
