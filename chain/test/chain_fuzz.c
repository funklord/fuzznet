/* A fuzz harness for the capability chain and its canonical encoding.
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
 *   - verification never costs more signature checks than there are hops;
 *   - the PARSER accepts a byte string exactly when the layout says it
 *     should, and a chain that survives a container round trip verifies to
 *     the same verdict it did before.
 *
 * The fourth is a denial-of-service property rather than a correctness one:
 * signature verification is the expensive operation, and a chain that could
 * buy more of them than it has hops would be a way to spend a receiver's CPU
 * for the price of one datagram.
 *
 * HOPS ARE REAL BYTES NOW (2026-08-27). This harness used to fill structs
 * and point every hop's `signed_region` at one shared string literal, which
 * was possible only because nothing related a hop's bytes to its fields --
 * and that gap was a total authorization bypass, invisible here across
 * 200000 cases per run. Every hop below is encoded and signed over its own
 * body, so a field this harness sets is a field the verifier reads out of
 * the bytes.
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
#define MAX_HOPS FZN_CHAIN_MAX_HOPS
#define MAX_REVS 4

/* The same toy MAC the unit tests use: an answer that depends on every byte
 * of the message and on who signed. A stub that ignored either could not
 * tell a verifier which reads the signed bytes from one which reads a struct
 * beside them, and telling those apart is what this file is now for. */
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

/* ONE CONTEXT FOR BOTH HALVES OF THE SEAM, and this is not tidiness.
 *
 * `fzn_sign_ops_t` carries a single `ctx` shared by `verify` and `sign`, so
 * a harness that gave the signer its own struct and swapped `ctx` before
 * delegating handed that struct to the VERIFIER as well -- `fzn_chain_delegate`
 * re-verifies the chain before signing anything. The verifier then read a
 * four-byte counter out of a one-byte struct. AddressSanitizer caught it on
 * the first sanitized run of this file; a plain -Os build had reported 20000
 * clean cases. `identity` lives here for that reason.
 *
 * It is set per case, because a delegation is signed by the chain's current
 * grantee and a keyed verifier will not accept anybody else's signature. */
struct stub {
	int calls;
	uint8_t identity;
};

static int stub_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	struct stub *s = (struct stub *)ctx;
	uint8_t want[FZN_SIG_LEN];

	s->calls++;
	if (!msg || msg_len == 0)
		return 0;
	mac(want, pubkey[0], msg, msg_len);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	struct stub *s = (struct stub *)ctx;

	if (!msg || msg_len == 0)
		return 0;
	mac(sig, s->identity, msg, msg_len);
	return 1;
}

struct coverage {
	unsigned long verified_ok;
	unsigned long refused;
	unsigned long delegated_ok;
	unsigned long shape_ok;
	unsigned long shape_refused;
};

/* WHOSE SIGNATURE IS GOOD, decided by the generator and consulted by the
 * model.
 *
 * `good` is a set of identities, indexed by the low five bits of the key.
 * Every identity this generator mints is a key of repeated bytes, so those
 * bits ARE the identity. A hop whose grantor is in the set is signed
 * correctly; one whose grantor is not gets a signature that will not verify.
 * The model asks the same question of `fzn_hop_grantor` that chain.c should
 * be asking of the verifier, and when the two disagree the harness says so.
 *
 * The verdict is a function of the KEY and of the BYTES, never of the call
 * number. This harness used to answer from a call counter, so which
 * signature was good depended on WHEN it was checked rather than on whose it
 * was -- and the two total bypasses in chain.c were invisible across 200000
 * cases apiece. */
static int signature_is_good(uint32_t good, const uint8_t *pubkey)
{
	return (int)((good >> (pubkey[0] & 31u)) & 1u);
}

/* Re-derive, from the hops themselves, whether this chain should have been
 * accepted. Deliberately a SECOND implementation of the rules rather than a
 * call into the first: a checker that asked chain.c whether chain.c was
 * right would agree with it always, including when both are wrong. */
static int ought_to_verify(const fzn_chain_hop_t *hops, size_t n, const uint8_t *root,
                           const uint8_t *cap, uint64_t now, const fzn_revocation_t *revs,
                           size_t nrevs, uint32_t good)
{
	if (n == 0 || n > MAX_HOPS)
		return 0;
	if (memcmp(fzn_hop_grantor(hops[0]), root, FZN_PUBKEY_LEN) != 0)
		return 0;

	for (size_t i = 0; i < n; i++) {
		/* Each hop signed by the grantor giving its authority away, and
		 * by nobody else. */
		if (!signature_is_good(good, fzn_hop_grantor(hops[i])))
			return 0;
		if (memcmp(fzn_hop_capability(hops[i]), cap, FZN_CAP_ID_LEN) != 0)
			return 0;
		if (i > 0) {
			if (memcmp(fzn_hop_grantor(hops[i]), fzn_hop_grantee(hops[i - 1]),
			           FZN_PUBKEY_LEN) != 0)
				return 0;
			if (!fzn_hop_delegable(hops[i - 1]))
				return 0;
		}
		if (fzn_hop_expires_at(hops[i]) != FZN_NO_EXPIRY) {
			if (fzn_hop_expires_at(hops[i]) <= fzn_hop_issued_at(hops[i]))
				return 0;
			if (fzn_hop_expires_at(hops[i]) <= now)
				return 0;
		}
		for (size_t r = 0; r < nrevs; r++) {
			if (memcmp(revs[r].capability, fzn_hop_capability(hops[i]),
			           FZN_CAP_ID_LEN) == 0 &&
			    memcmp(revs[r].grantee, fzn_hop_grantee(hops[i]), FZN_PUBKEY_LEN) == 0)
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
		if (fzn_hop_expires_at(hops[i]) == FZN_NO_EXPIRY)
			continue;
		if (soonest == FZN_NO_EXPIRY || fzn_hop_expires_at(hops[i]) < soonest)
			soonest = fzn_hop_expires_at(hops[i]);
	}
	return soonest;
}

/* The shape rules, as a second implementation. `fzn_hop_open` must accept
 * exactly this set -- no more, which would be a canonicality hole, and no
 * less, which would refuse hops a correct peer produces. */
static int shape_is_ours(const uint8_t *bytes, size_t len)
{
	if (len != FZN_HOP_LEN)
		return 0;
	if (bytes[FZN_HOP_OFF_VERSION] != 1u)
		return 0;
	if (bytes[FZN_HOP_OFF_OBJECT] != 1u)
		return 0;
	if (bytes[FZN_HOP_OFF_DELEGABLE] > 1u)
		return 0;
	return 1;
}

static int fuzz_one(const uint8_t *data, size_t len, struct coverage *cov)
{
	uint8_t hop_bytes[MAX_HOPS + 1][FZN_HOP_LEN];
	fzn_chain_hop_t hops[MAX_HOPS + 1];
	fzn_revocation_t revs[MAX_REVS];
	uint8_t root[FZN_PUBKEY_LEN], cap[FZN_CAP_ID_LEN];
	struct stub stub = { 0, 0 };
	fzn_sign_ops_t sign;
	fzn_chain_t out, before;
	size_t n, nrevs, built;
	uint64_t now;
	uint32_t good = 0xffffffffu;
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
	/* Usually every signature is good, sometimes none is. */
	good = (data[3] & 0x0fu) != 0 ? 0xffffffffu : 0u;
	/* And sometimes exactly ONE identity's signature is bad, which is the
	 * case that separates a correct verifier from either bypass. It is
	 * chosen from the bytes this generator actually mints identities from
	 * -- roots are 0..3 and grantees 0x10..0x17 -- because a bit picked
	 * uniformly out of 32 would usually name a key no hop presents, and a
	 * mask that decides nothing tests nothing. */
	if ((data[4] & 0x07u) == 0) {
		static const uint8_t IDENTITIES[] = { 0, 1, 2, 3, 0x10, 0x11, 0x12, 0x13,
			                              0x14, 0x15, 0x16, 0x17 };

		good &= ~(1u << (IDENTITIES[(data[4] >> 3) % (sizeof(IDENTITIES) /
		                                              sizeof(IDENTITIES[0]))] &
		                 31u));
	}
	n = 1u + (data[5] % (MAX_HOPS + 1u)); /* sometimes one past the ceiling */
	nrevs = data[6] % (MAX_REVS + 1u);
	pos = 8;

	/* Hops are built to LINK most of the time. A chain assembled from
	 * uniform random keys never links past hop 0, so every rule beyond
	 * the first would be unreachable -- the failure the reassembly
	 * harness was rebuilt to avoid. */
	built = n <= MAX_HOPS ? n : MAX_HOPS + 1u;
	for (size_t i = 0; i < built; i++) {
		uint8_t b = (pos + 4 <= len) ? data[pos] : (uint8_t)i;
		uint8_t linked = (pos + 4 <= len) ? (data[pos + 1] & 0x07u) : 1u;
		uint8_t grantor[FZN_PUBKEY_LEN], grantee[FZN_PUBKEY_LEN];
		uint8_t hop_cap[FZN_CAP_ID_LEN];

		if (i == 0) {
			/* Usually the pinned root, sometimes NOT -- and the
			 * "sometimes not" is the whole value of this line. An
			 * earlier version always rooted hop 0 correctly, so a
			 * chain rooted elsewhere never occurred, and deleting
			 * the pinning check in chain.c changed no outcome and
			 * was invisible to 200000 cases. A generator that
			 * cannot produce the input a check rejects cannot test
			 * that check. */
			if ((pos + 4 <= len) && (data[pos + 2] & 0x07u) == 0)
				memset(grantor, (uint8_t)(0xd0u + b), FZN_PUBKEY_LEN);
			else
				memcpy(grantor, root, FZN_PUBKEY_LEN);
		}
		else if (linked)
			memcpy(grantor, fzn_hop_grantee(hops[i - 1]), FZN_PUBKEY_LEN);
		else
			memset(grantor, b, FZN_PUBKEY_LEN);

		memset(grantee, (uint8_t)(0x10u + i), FZN_PUBKEY_LEN);
		if ((b & 0x0fu) != 0)
			memcpy(hop_cap, cap, FZN_CAP_ID_LEN);
		else
			memset(hop_cap, b, FZN_CAP_ID_LEN);

		if (fzn_hop_encode(hop_bytes[i], grantor, grantee, hop_cap, 100,
		                   ((b >> 4) & 1u) ? 0u : (uint64_t)b * 50u,
		                   (linked & 1u) ? 1 : 0) != FZN_CHAIN_OK) {
			printf("  INVARIANT: the generator could not encode a hop\n");
			return 1;
		}

		/* Signed correctly exactly when the grantor's identity is in
		 * the good set, which is what the model consults. */
		if (signature_is_good(good, grantor))
			mac(hop_bytes[i] + FZN_HOP_OFF_SIGNATURE, grantor[0], hop_bytes[i],
			    FZN_HOP_BODY_LEN);
		else
			memset(hop_bytes[i] + FZN_HOP_OFF_SIGNATURE, 0x5a, FZN_SIG_LEN);

		if (fzn_hop_open(hop_bytes[i], FZN_HOP_LEN, &hops[i]) != FZN_CHAIN_OK) {
			printf("  INVARIANT: a canonically encoded hop would not open\n");
			return 1;
		}
		pos += 4;
	}

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
		if (!ought_to_verify(hops, n, root, cap, now, nrevs ? revs : NULL, nrevs,
		                     good)) {
			printf("  INVARIANT: accepted a chain the rules refuse\n");
			return 1;
		}
		if (memcmp(out.grantee, fzn_hop_grantee(hops[n - 1]), FZN_PUBKEY_LEN) != 0) {
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
		if (n <= MAX_HOPS &&
		    ought_to_verify(hops, n, root, cap, now, nrevs ? revs : NULL, nrevs, good)) {
			printf("  INVARIANT: refused a chain the rules accept (err %d)\n",
			       (int)err);
			return 1;
		}
	}

	if ((size_t)stub.calls > n) {
		printf("  INVARIANT: %d signature checks for %zu hops\n", stub.calls, n);
		return 1;
	}

	/* THE CONTAINER MUST NOT CHANGE A VERDICT. A framing that loses or
	 * reorders a byte turns every chain into a bad signature, and one that
	 * quietly tolerates a length mismatch is how a stranger appends
	 * padding a receiver has to store. */
	if (n <= MAX_HOPS) {
		uint8_t packed[FZN_CHAIN_MAX_LEN];
		fzn_chain_hop_t reopened[FZN_CHAIN_MAX_HOPS];
		fzn_chain_t again;
		size_t packed_len = 0, reopened_n = 0;

		if (fzn_chain_pack(hops, n, packed, sizeof(packed), &packed_len) !=
		    FZN_CHAIN_OK) {
			printf("  INVARIANT: could not pack a chain of %zu hops\n", n);
			return 1;
		}
		if (fzn_chain_open(packed, packed_len, reopened, &reopened_n) != FZN_CHAIN_OK ||
		    reopened_n != n) {
			printf("  INVARIANT: a packed chain did not open as itself\n");
			return 1;
		}
		memset(&again, 0xab, sizeof(again));
		stub.calls = 0;
		if (fzn_chain_verify(reopened, reopened_n, root, cap, now, &sign,
		                     nrevs ? revs : NULL, nrevs, &again) != err) {
			printf("  INVARIANT: the container changed the verdict\n");
			return 1;
		}
	}

	/* THE PARSER, over a valid hop with one byte rewritten. Random 179-byte
	 * strings are never our shape, so a harness that only fed those would
	 * report a parser that refuses everything as correct. Mutating one byte
	 * of something valid is what produces both answers. */
	{
		uint8_t probe[FZN_HOP_LEN];
		fzn_chain_hop_t view;
		size_t off = (size_t)data[7] % FZN_HOP_LEN;
		size_t probe_len = ((data[7] & 0x80u) != 0) ? FZN_HOP_LEN
		                                            : FZN_HOP_LEN - (data[6] & 0x03u);
		int accepted;

		memcpy(probe, hop_bytes[0], FZN_HOP_LEN);
		probe[off] = (uint8_t)(probe[off] ^ (data[3] | 1u));
		accepted = fzn_hop_open(probe, probe_len, &view) == FZN_CHAIN_OK;
		if (accepted != shape_is_ours(probe, probe_len)) {
			printf("  INVARIANT: the parser and the layout disagree at offset %zu\n",
			       off);
			return 1;
		}
		if (accepted) {
			cov->shape_ok++;
			if (view.base != probe) {
				printf("  INVARIANT: an opened view does not address its "
				       "own bytes\n");
				return 1;
			}
		} else {
			cov->shape_refused++;
		}
	}

	/* Delegation, on a chain that verified. The signer has to be the
	 * chain's current grantee, or a keyed verifier refuses the hop it
	 * produces -- which is the seam telling the truth. */
	if (err == FZN_CHAIN_OK && n < MAX_HOPS) {
		uint8_t fresh[FZN_HOP_LEN];
		fzn_chain_hop_t fresh_view;
		uint8_t grantee[FZN_PUBKEY_LEN];

		memset(grantee, 0xf0, sizeof(grantee));
		stub.identity = fzn_hop_grantee(hops[n - 1])[0];
		if (fzn_chain_delegate(hops, n, root, cap, now, grantee, 0, 0, &sign,
		                       nrevs ? revs : NULL, nrevs, fresh) == FZN_CHAIN_OK) {
			cov->delegated_ok++;

			if (!fzn_hop_delegable(hops[n - 1])) {
				printf("  INVARIANT: delegated from a chain that forbids it\n");
				return 1;
			}
			if (fzn_hop_open(fresh, FZN_HOP_LEN, &fresh_view) != FZN_CHAIN_OK) {
				printf("  INVARIANT: a delegated hop does not open\n");
				return 1;
			}
			if (out.expires_at != FZN_NO_EXPIRY &&
			    (fzn_hop_expires_at(fresh_view) == FZN_NO_EXPIRY ||
			     fzn_hop_expires_at(fresh_view) > out.expires_at)) {
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
	struct coverage cov = { 0, 0, 0, 0, 0 };

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
	struct coverage cov = { 0, 0, 0, 0, 0 };
	uint8_t buf[128];

	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
	}

	if (cases < FUZZ_MIN_CASES) {
		printf("chain_fuzz: %lu cases is below FUZZ_MIN_CASES (%u), so this run will "
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
			printf("chain_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	/* Both directions must occur, or the run proves only one of them.
	 * A harness that never accepted a chain would report success against
	 * a verify that refused everything; one that never refused would
	 * report success against a verify that accepted everything. The two
	 * parser counters are the same argument one layer down: a parser that
	 * refused every byte string would satisfy a run that never saw it
	 * accept one.
	 *
	 * DELEGATION IS FLOORED LOWER, and the number is chosen from the
	 * observed rate rather than picked. A successful delegation needs a
	 * chain that verifies AND a last hop marked delegable, so it is the
	 * rarest thing here. A floor of cases/200 would fail on any drift,
	 * which is the way a floor stops meaning anything -- it gets raised
	 * until it is noise. cases/1000 still catches delegation
	 * disappearing, which is what it is for. */
	if (cov.verified_ok < floor_of(cases, 200u) || cov.refused < floor_of(cases, 200u) ||
	    cov.delegated_ok < floor_of(cases, 1000u) ||
	    cov.shape_ok < floor_of(cases, 200u) || cov.shape_refused < floor_of(cases, 1000u)) {
		printf("chain_fuzz: REACHED TOO LITTLE -- %lu accepted, %lu refused, "
		       "%lu delegated, %lu shapes accepted, %lu shapes refused in %lu cases. "
		       "All must happen or this run proves less than it says.\n",
		       cov.verified_ok, cov.refused, cov.delegated_ok, cov.shape_ok,
		       cov.shape_refused, cases);
		return 1;
	}

	printf("chain_fuzz: %lu cases, %lu accepted, %lu refused, %lu delegated, "
	       "%lu shapes accepted, %lu shapes refused, no invariant broken\n",
	       cases, cov.verified_ok, cov.refused, cov.delegated_ok, cov.shape_ok,
	       cov.shape_refused);
	return 0;
}
#endif
