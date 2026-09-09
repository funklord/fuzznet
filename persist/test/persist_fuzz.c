/* A fuzz harness for the persisted formats.
 *
 * THE HOSTILE SURFACE HERE IS A FILE, which is why this exists at all.
 * Every other byte parser in this tree has a harness -- `chain`, `manifest`,
 * `revocation`, `prekey`, `provision`, `record` -- and `persist` did not,
 * although `persist/persist_file.c` goes to some length over the bytes it
 * writes: mode 0600 at creation so a prekey secret is never briefly
 * world-readable, and an atomic rename so a torn trust anchor cannot be read
 * as a whole one. A format defended that carefully is one somebody can reach.
 *
 * THE PROPERTY, AND IT IS NOT AN INVARIANT. The other harnesses assert that
 * nothing is written out of bounds, or keep a shadow model of a table. A pure
 * serialisation pair admits a sharper question:
 *
 *   NO SINGLE-BYTE MUTATION MAY BE ACCEPTED AND STILL RE-PACK TO THE
 *   ORIGINAL BYTES.
 *
 * A mutation that survives both is a byte the format WRITES AND DOES NOT
 * READ -- two encodings of one blob. `head_check` in `persist.c` refuses a
 * trailing byte for exactly that reason, in its own words: "'ignore what you
 * do not understand' is how one format becomes several." A field the decoder
 * drops is the same fault one position further in, and no length check can
 * see it.
 *
 * IT FOUND ONE. `pack` writes `adopted_at` for every anchor and
 * `fzn_trust_pin` and `fzn_trust_self` take no timestamp, so for a PINNED or
 * a SELF anchor those eight bytes were written as zero and read by nobody --
 * in the trust blob and again inside every peer blob, which embeds one.
 * project.md sec 232. The refusal that closes it is asserted below rather
 * than assumed, because a property that has never failed is a property nobody
 * has watched work.
 *
 * TRUNCATION IS THE SECOND PROPERTY. Every prefix shorter than the whole must
 * be refused, since `head_check` is exact rather than "at least" -- and a
 * decoder that read one byte past a short buffer would be found here rather
 * than by a consumer whose file was cut short by a full disk.
 *
 * NO CRYPTO SEAM IS TOUCHED. Three of the four blobs decode without one;
 * `fzn_persist_secret_open` takes an `fzn_agree_ops_t` to re-derive a public
 * key and is left to `persist_test.c`, which has a binding to hand. Saying so
 * matters: a harness that quietly covered three of four would report a pass
 * over a subset, which is the shape this tree keeps meeting.
 */

#include "../persist.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u

/* Below this the coverage floors are cleared by a single lucky case, so a run
 * refuses rather than reporting a success that means nothing. Same number and
 * same reasoning as the other harnesses here. */
#define FUZZ_MIN_CASES 1000u

#define BLOB_MAX 128u

struct coverage {
	unsigned long trust;
	unsigned long peer;
	unsigned long chain;
	unsigned long pinned;
	unsigned long adopted;
	unsigned long self_rooted;
	unsigned long refused;
	unsigned long reflected;
	unsigned long truncations;
};

static uint32_t next_rand(uint32_t *seed)
{
	*seed = (*seed * 1103515245u) + 12345u;
	return (*seed >> 16) & 0x7fffu;
}

static void fill(uint32_t *seed, uint8_t *out, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		out[i] = (uint8_t)(next_rand(seed) & 0xffu);
	/* A KEY OF ALL ZEROES IS REFUSED BY `trust/trust.c`, so a fixture that
	 * produced one would spend its case on a rejection that says nothing
	 * about the format. One byte forced non-zero is enough. */
	if (len)
		out[0] = (uint8_t)(out[0] | 1u);
}

/* Pack a trust anchor of the given provenance. Returns 0 if the fixture
 * could not be built, which is a fault in this file rather than in the
 * module and is reported as one. */
static int pack_trust(uint32_t *seed, fzn_trust_source_t source, uint8_t *out, size_t *len)
{
	fzn_trust_t t;
	uint8_t key[FZN_PUBKEY_LEN];

	fzn_trust_init(&t);
	fill(seed, key, sizeof(key));

	if (source == FZN_TRUST_PINNED) {
		if (fzn_trust_pin(&t, key) != FZN_TRUST_OK)
			return 0;
	} else if (source == FZN_TRUST_ADOPTED) {
		/* NON-ZERO, so the adopted case actually carries a timestamp
		 * the decoder has to read back. A zero here would make every
		 * mutation of those bytes look like the pinned case. */
		if (fzn_trust_adopt(&t, key, (uint64_t)next_rand(seed) + 1u) != FZN_TRUST_OK)
			return 0;
	} else {
		if (fzn_trust_self(&t, key) != FZN_TRUST_OK)
			return 0;
	}

	return fzn_persist_trust_pack(&t, out, BLOB_MAX, len) == FZN_PERSIST_OK;
}

static int pack_peer(uint32_t *seed, uint8_t *out, size_t *len)
{
	fzn_prekey_peer_t p;
	uint8_t key[FZN_PUBKEY_LEN];

	fzn_prekey_peer_init(&p);
	fill(seed, key, sizeof(key));
	if (fzn_trust_adopt(&p.trust, key, (uint64_t)next_rand(seed) + 1u) != FZN_TRUST_OK)
		return 0;
	fill(seed, p.prekey, sizeof(p.prekey));
	p.created_at = (uint64_t)next_rand(seed) + 1u;

	return fzn_persist_peer_pack(&p, out, BLOB_MAX, len) == FZN_PERSIST_OK;
}

static int pack_chain(uint32_t *seed, uint8_t *out, size_t *len)
{
	fzn_ratchet_chain_t c;

	memset(&c, 0, sizeof(c));
	fill(seed, c.key, sizeof(c.key));
	c.seq = (uint64_t)next_rand(seed);

	return fzn_persist_chain_pack(&c, out, BLOB_MAX, len) == FZN_PERSIST_OK;
}

/* Open a blob of the given tag and re-pack what came back. Returns 1 when the
 * blob was accepted, and writes the re-packed bytes to `again`. */
static int open_and_repack(int kind, const uint8_t *blob, size_t len, uint8_t *again,
                           size_t *again_len)
{
	if (kind == 0) {
		fzn_trust_t t;

		fzn_trust_init(&t);
		if (fzn_persist_trust_open(blob, len, &t) != FZN_PERSIST_OK)
			return 0;
		return fzn_persist_trust_pack(&t, again, BLOB_MAX, again_len) == FZN_PERSIST_OK;
	}
	if (kind == 1) {
		fzn_prekey_peer_t p;

		fzn_prekey_peer_init(&p);
		if (fzn_persist_peer_open(blob, len, &p) != FZN_PERSIST_OK)
			return 0;
		return fzn_persist_peer_pack(&p, again, BLOB_MAX, again_len) == FZN_PERSIST_OK;
	}
	{
		fzn_ratchet_chain_t c;

		memset(&c, 0, sizeof(c));
		if (fzn_persist_chain_open(blob, len, &c) != FZN_PERSIST_OK)
			return 0;
		return fzn_persist_chain_pack(&c, again, BLOB_MAX, again_len) == FZN_PERSIST_OK;
	}
}

static int fuzz_one(uint32_t seed, struct coverage *cov)
{
	uint8_t blob[BLOB_MAX], mutated[BLOB_MAX], again[BLOB_MAX];
	size_t len = 0, again_len = 0;
	int kind = (int)(next_rand(&seed) % 3u);
	size_t at;
	uint8_t delta;

	if (kind == 0) {
		fzn_trust_source_t src;
		unsigned pick = next_rand(&seed) % 3u;

		src = pick == 0 ? FZN_TRUST_PINNED
		                : (pick == 1 ? FZN_TRUST_ADOPTED : FZN_TRUST_SELF);
		if (!pack_trust(&seed, src, blob, &len)) {
			printf("persist_fuzz: the fixture could not pack a trust anchor\n");
			return 0;
		}
		cov->trust++;
		if (src == FZN_TRUST_PINNED)
			cov->pinned++;
		else if (src == FZN_TRUST_ADOPTED)
			cov->adopted++;
		else
			cov->self_rooted++;
	} else if (kind == 1) {
		if (!pack_peer(&seed, blob, &len)) {
			printf("persist_fuzz: the fixture could not pack a peer\n");
			return 0;
		}
		cov->peer++;
	} else {
		if (!pack_chain(&seed, blob, &len)) {
			printf("persist_fuzz: the fixture could not pack a chain\n");
			return 0;
		}
		cov->chain++;
	}

	/* THE CONTROL. An unmutated blob must open and re-pack to itself, or
	 * every comparison below is against a baseline that does not hold. */
	if (!open_and_repack(kind, blob, len, again, &again_len) || again_len != len
	    || memcmp(again, blob, len) != 0) {
		printf("persist_fuzz: kind %d does not round-trip unmutated, so nothing "
		       "below means anything\n",
		       kind);
		return 0;
	}

	/* ---- THE PROPERTY. */
	at = (size_t)next_rand(&seed) % len;
	delta = (uint8_t)((next_rand(&seed) % 255u) + 1u);
	memcpy(mutated, blob, len);
	mutated[at] = (uint8_t)(mutated[at] ^ delta);

	if (!open_and_repack(kind, mutated, len, again, &again_len)) {
		cov->refused++;
	} else if (again_len == len && memcmp(again, blob, len) == 0) {
		printf("persist_fuzz: kind %d byte %zu can be changed and the blob still\n"
		       "persist_fuzz: opens to the same value and re-packs to the original\n"
		       "persist_fuzz: bytes -- a byte this format writes and does not read,\n"
		       "persist_fuzz: which is two encodings of one blob.\n",
		       kind, at);
		return 0;
	} else {
		cov->reflected++;
	}

	/* ---- AND EVERY SHORT PREFIX IS REFUSED, since `head_check` is exact
	 * rather than "at least". */
	{
		size_t cut = (size_t)next_rand(&seed) % len;
		fzn_trust_t t;
		fzn_prekey_peer_t p;
		fzn_ratchet_chain_t c;
		fzn_persist_err_t err;

		if (kind == 0) {
			fzn_trust_init(&t);
			err = fzn_persist_trust_open(blob, cut, &t);
		} else if (kind == 1) {
			fzn_prekey_peer_init(&p);
			err = fzn_persist_peer_open(blob, cut, &p);
		} else {
			memset(&c, 0, sizeof(c));
			err = fzn_persist_chain_open(blob, cut, &c);
		}
		if (err == FZN_PERSIST_OK) {
			printf("persist_fuzz: kind %d accepted a %zu-byte prefix of a "
			       "%zu-byte blob\n",
			       kind, cut, len);
			return 0;
		}
		cov->truncations++;
	}

	return 1;
}

#ifdef FZN_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint32_t seed = 1u;
	size_t i;
	struct coverage cov = { 0, 0, 0, 0, 0, 0, 0, 0, 0 };

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
	struct coverage cov = { 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	unsigned long i;

	if (argc > 1)
		cases = strtoul(argv[1], NULL, 10);
	if (cases < FUZZ_MIN_CASES) {
		printf("persist_fuzz: %lu cases is below the floor of %u, at which the\n"
		       "persist_fuzz: coverage checks below are cleared by luck.\n",
		       cases, FUZZ_MIN_CASES);
		return 1;
	}

	for (i = 0; i < cases; i++) {
		if (!fuzz_one((uint32_t)(i + 1u), &cov))
			return 1;
	}

	/* FLOORS ON WHAT WAS REACHED, NOT ON CALLS. A run that never packed a
	 * PINNED anchor never tested the eight bytes sec 232 found unread; one
	 * that never saw a mutation REFLECTED rather than refused has only
	 * watched the length and tag checks work, which are the easy half. */
	if (cov.trust < floor_of(cases, 6u) || cov.peer < floor_of(cases, 6u)
	    || cov.chain < floor_of(cases, 6u) || cov.pinned < floor_of(cases, 20u)
	    || cov.adopted < floor_of(cases, 20u) || cov.self_rooted < floor_of(cases, 20u)
	    || cov.refused < floor_of(cases, 20u) || cov.reflected < floor_of(cases, 20u)) {
		printf("persist_fuzz: REACHED TOO LITTLE -- %lu trust, %lu peer, %lu chain, "
		       "%lu pinned, %lu adopted, %lu self, %lu refused, %lu reflected in "
		       "%lu cases.\n",
		       cov.trust, cov.peer, cov.chain, cov.pinned, cov.adopted,
		       cov.self_rooted, cov.refused, cov.reflected, cases);
		return 1;
	}

	printf("persist_fuzz: %lu cases, %lu trust, %lu peer, %lu chain "
	       "(%lu pinned, %lu adopted, %lu self), %lu mutations refused, "
	       "%lu reflected, %lu truncations refused\n",
	       cases, cov.trust, cov.peer, cov.chain, cov.pinned, cov.adopted,
	       cov.self_rooted, cov.refused, cov.reflected, cov.truncations);
	return 0;
}
#endif
