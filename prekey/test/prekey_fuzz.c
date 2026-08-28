/* A fuzz harness for the prekey pin path.
 *
 * WHY THIS ONE AND NOT ANOTHER. Every other decoder of stranger bytes in this
 * library has a harness -- chain, revocation, record, reassembly, freshness,
 * peer, vocabulary, blob. `prekey/` was the exception, and it is the module
 * whose input is most obviously an attacker's: a prekey record travels, it is
 * self-signed so it authenticates only its own author, and `fzn_prekey_pin`
 * MUTATES LOCAL TRUST STATE from it.
 *
 * MODEL-BASED, NOT INVARIANT-BASED, for the reason revocation_fuzz gives. A
 * pin bug is not an overrun. It is a record accepted that should not have
 * been -- a rolled-back prekey, a stranger's key adopted into a pinned peer --
 * or one refused that should have been kept, which stops a legitimate
 * rotation. Neither breaks a spot invariant; both break a model.
 *
 * So this keeps an independent SHADOW of what the peer should hold, decides
 * for itself what each record ought to do, and asserts the two agree in both
 * directions after every call. The shadow is a second implementation of the
 * rules on purpose: one that asked the module what it did would agree with it
 * always, including when both are wrong.
 *
 * RECORDS ARE REAL BYTES, issued through `fzn_prekey_issue` and verified over
 * their own signed body -- the mistake revocation_fuzz was found to have made
 * once, where every record pointed at one shared literal and the field a case
 * set had nothing to do with the bytes the module read.
 */

#include "../prekey.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u

/* Below this the coverage floors below are cleared by a single lucky case, so
 * a run refuses rather than reporting a success that means nothing. Same
 * number and same reasoning as the other harnesses here. */
#define FUZZ_MIN_CASES 1000u

/* Two hosts, so that "a different host is refused" is a state the generator
 * can reach, and two prekeys per host so a rotation and a rollback are both
 * expressible. */
#define HOSTS 2u

static uint8_t signing_as;

static void mac(uint8_t out[FZN_SIG_LEN], uint8_t identity, const uint8_t *msg, size_t len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	h ^= identity;
	h *= 0x100000001b3ull;
	for (i = 0; i < len; i++) {
		h ^= msg[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h ^= (uint64_t)i + 0x9e3779b97f4a7c15ull;
		h *= 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 24);
	}
}

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	(void)ctx;
	mac(sig, signing_as, msg, msg_len);
	return 1;
}

/* KEYED ON THE PUBLIC KEY, so a signature made by one host does not verify
 * under another. Without that, "the record verifies under the host it names"
 * is unfalsifiable and the whole harness proves nothing. */
static int stub_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	mac(want, pubkey[0], msg, msg_len);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

static const fzn_sign_ops_t OPS = { stub_verify, stub_sign, NULL };

static void expand(uint8_t *out, size_t n, uint8_t seed)
{
	size_t i;

	for (i = 0; i < n; i++)
		out[i] = (uint8_t)(seed + (i * 7u));
}

/* The shadow: what the peer SHOULD hold. */
struct shadow {
	int pinned;
	uint8_t host;                       /* the seed, which is the key's first byte */
	uint8_t prekey[FZN_PREKEY_LEN];
	uint64_t created_at;
	fzn_trust_source_t source;
};

struct coverage {
	unsigned long first_use;
	unsigned long rotations;
	unsigned long rollbacks;
	unsigned long wrong_host;
	unsigned long forged;
	unsigned long redelivery;
	unsigned long ties;
};

static uint32_t next(uint32_t *state)
{
	*state ^= *state << 13;
	*state ^= *state >> 17;
	*state ^= *state << 5;
	return *state;
}

/* What the rules say this record must do, decided without asking the module.
 * Returns the verdict the module is required to produce. */
static fzn_prekey_err_t model(const struct shadow *sh, uint8_t host_seed, uint8_t signer_seed,
                              const uint8_t *prekey, uint64_t created_at)
{
	if (signer_seed != host_seed)
		return FZN_PREKEY_ERR_SIGNATURE;
	if (!sh->pinned)
		return FZN_PREKEY_OK;
	if (host_seed != sh->host)
		return FZN_PREKEY_ERR_WRONG_HOST;
	if (memcmp(prekey, sh->prekey, FZN_PREKEY_LEN) == 0 && created_at == sh->created_at)
		return FZN_PREKEY_OK;
	if (created_at <= sh->created_at)
		return FZN_PREKEY_ERR_ROLLBACK;
	return FZN_PREKEY_OK;
}

static int fuzz_one(uint32_t seed, struct coverage *cov)
{
	uint32_t state = seed;
	fzn_prekey_peer_t peer;
	struct shadow sh;
	unsigned round;

	fzn_prekey_peer_init(&peer);
	memset(&sh, 0, sizeof(sh));

	for (round = 0; round < 8u; round++) {
		uint8_t host[FZN_PUBKEY_LEN], prekey[FZN_PREKEY_LEN];
		uint8_t bytes[FZN_PREKEY_LEN_TOTAL];
		fzn_prekey_record_t record;
		fzn_prekey_err_t want, got;
		fzn_trust_source_t source;
		uint8_t host_seed, signer_seed, prekey_seed;
		uint64_t created_at;
		const uint8_t *anchor;

		host_seed = (uint8_t)(0x40u + (next(&state) % HOSTS));
		/* Sometimes signed by somebody else, which is the forgery a
		 * self-signed record has to refuse on its own. */
		signer_seed = (next(&state) % 4u) == 0u
		                      ? (uint8_t)(0x80u + (next(&state) % 3u))
		                      : host_seed;
		prekey_seed = (uint8_t)(0x10u + (next(&state) % 3u));
		/* Timestamps clustered so that rotations, rollbacks and exact
		 * ties are all reachable rather than merely possible. */
		created_at = 100u + (next(&state) % 4u);
		source = (next(&state) & 1u) ? FZN_TRUST_PINNED : FZN_TRUST_ADOPTED;

		expand(host, sizeof(host), host_seed);
		expand(prekey, sizeof(prekey), prekey_seed);
		signing_as = signer_seed;
		if (fzn_prekey_issue(host, prekey, created_at, &OPS, bytes) != FZN_PREKEY_OK) {
			printf("  INVARIANT: issuing a record refused\n");
			return 1;
		}
		if (fzn_prekey_open(bytes, sizeof(bytes), &record) != FZN_PREKEY_OK) {
			printf("  INVARIANT: a record this library issued does not open\n");
			return 1;
		}

		want = model(&sh, host_seed, signer_seed, prekey, created_at);
		got = fzn_prekey_pin(&peer, record, &OPS, source, 1000u + round);

		if (want != got) {
			printf("  INVARIANT: model says %s, module says %s\n",
			       fzn_prekey_err_str(want), fzn_prekey_err_str(got));
			return 1;
		}

		if (signer_seed != host_seed)
			cov->forged++;
		else if (!sh.pinned)
			cov->first_use++;
		else if (host_seed != sh.host)
			cov->wrong_host++;
		else if (want == FZN_PREKEY_ERR_ROLLBACK)
			cov->rollbacks++;
		else if (created_at == sh.created_at)
			cov->redelivery++;
		else
			cov->rotations++;
		if (sh.pinned && host_seed == sh.host && created_at == sh.created_at
		    && memcmp(prekey, sh.prekey, FZN_PREKEY_LEN) != 0)
			cov->ties++;

		/* THE SHADOW MOVES ONLY WHERE THE RULES SAY IT DOES. Anything
		 * that is not a first use or an accepted rotation must leave it
		 * exactly as it was -- which is the half a spot invariant
		 * cannot express. */
		if (got == FZN_PREKEY_OK) {
			if (!sh.pinned) {
				sh.pinned = 1;
				sh.host = host_seed;
				sh.source = source;
				memcpy(sh.prekey, prekey, FZN_PREKEY_LEN);
				sh.created_at = created_at;
			} else if (created_at > sh.created_at) {
				/* A rotation. The SOURCE IS NOT TOUCHED: a
				 * rotation is not a new first use, and a peer
				 * able to raise ADOPTED to PINNED by rotating
				 * would launder its own provenance. */
				memcpy(sh.prekey, prekey, FZN_PREKEY_LEN);
				sh.created_at = created_at;
			}
		}

		/* And the module must agree with the shadow in every field,
		 * after every call, including the refused ones. */
		anchor = fzn_trust_root(&peer.trust);
		if (!sh.pinned) {
			if (anchor) {
				printf("  INVARIANT: anchored with nothing accepted\n");
				return 1;
			}
			continue;
		}
		if (!anchor) {
			printf("  INVARIANT: the peer lost its anchor\n");
			return 1;
		}
		if (anchor[0] != sh.host) {
			printf("  INVARIANT: anchored to %02x, model says %02x\n", anchor[0],
			       sh.host);
			return 1;
		}
		if (memcmp(peer.prekey, sh.prekey, FZN_PREKEY_LEN) != 0) {
			printf("  INVARIANT: the stored prekey is not the model's\n");
			return 1;
		}
		if (peer.created_at != sh.created_at) {
			printf("  INVARIANT: stored timestamp %llu, model says %llu\n",
			       (unsigned long long)peer.created_at,
			       (unsigned long long)sh.created_at);
			return 1;
		}
		if (fzn_trust_source_of(&peer.trust) != sh.source) {
			printf("  INVARIANT: provenance moved -- a rotation laundered it\n");
			return 1;
		}
	}

	return 0;
}

#ifdef FZN_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint32_t seed = 1u;
	size_t i;
	struct coverage cov = { 0, 0, 0, 0, 0, 0, 0 };

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
	struct coverage cov = { 0, 0, 0, 0, 0, 0, 0 };
	unsigned long c;

	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
	}

	if (cases < FUZZ_MIN_CASES) {
		printf("prekey_fuzz: %lu cases is below FUZZ_MIN_CASES (%u), so this run will "
		       "not report success -- every coverage floor below that is cleared by "
		       "a single lucky hit. Re-run with %u or more.\n",
		       cases, (unsigned)FUZZ_MIN_CASES, (unsigned)FUZZ_MIN_CASES);
		return 1;
	}

	for (c = 0; c < cases; c++) {
		if (fuzz_one((uint32_t)c + 1u, &cov)) {
			printf("prekey_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	/* FLOORS ON STATES, NOT ON CALLS. A run that never offered a rollback
	 * has not tested the rule this module exists for, however many records
	 * it pinned; one that never offered a forged signature has not tested
	 * that a self-signed record authenticates only its own author; and one
	 * that never hit an exact timestamp tie has not tested the case where
	 * two prekeys claim one instant and neither can be ordered. */
	if (cov.first_use < floor_of(cases, 4u) || cov.rotations < floor_of(cases, 8u)
	    || cov.rollbacks < floor_of(cases, 8u) || cov.wrong_host < floor_of(cases, 8u)
	    || cov.forged < floor_of(cases, 8u) || cov.redelivery < floor_of(cases, 20u)
	    || cov.ties < floor_of(cases, 50u)) {
		printf("prekey_fuzz: REACHED TOO LITTLE -- %lu first uses, %lu rotations, "
		       "%lu rollbacks, %lu wrong hosts, %lu forged, %lu redeliveries, "
		       "%lu ties in %lu cases.\n",
		       cov.first_use, cov.rotations, cov.rollbacks, cov.wrong_host, cov.forged,
		       cov.redelivery, cov.ties, cases);
		return 1;
	}

	printf("prekey_fuzz: %lu cases, %lu first uses, %lu rotations, %lu rollbacks, "
	       "%lu wrong hosts, %lu forged, %lu redeliveries, %lu ties, model agreed "
	       "throughout\n",
	       cases, cov.first_use, cov.rotations, cov.rollbacks, cov.wrong_host, cov.forged,
	       cov.redelivery, cov.ties);
	return 0;
}
#endif
