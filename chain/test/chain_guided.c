/* Chain verification under a coverage-guided fuzzer, with a real oracle.
 *
 * `chain_fuzz.c` beside it generates chains and compares against a model.
 * This one asks a narrower and sharper question: **when `fzn_chain_verify`
 * says yes, is it right?** Everything it accepts is re-checked here against
 * the things sec 4.2 says an accepted chain must satisfy -- pinned root,
 * unbroken grantor/grantee linkage, the capability asked for, nothing
 * expired, nothing revoked, each hop signed by its own grantor, and the
 * reported grantee being the last hop's.
 *
 * A false ACCEPT is an authorisation bypass and is the only failure worth
 * hunting this hard. A false reject is a bug too, but it fails safe and a
 * model-based harness already covers that direction.
 *
 * IDENTITIES ARE ONE BYTE WIDE ON PURPOSE. A 32-byte key drawn from fuzzer
 * bytes never collides, so linkage never holds, so the accept path is never
 * reached and the campaign explores rejection code for ever. Expanding a
 * single byte to fill the key makes `grantor == previous grantee` something
 * a mutation can stumble into. Getting this wrong is the same mistake as the
 * reassembly harness's -- a run that cannot reach the interesting code,
 * reporting millions of clean executions.
 *
 * THE HOPS ARE ENCODED AND SIGNED (2026-08-27). This harness used to fill
 * structs and point each hop's signed region at eight bytes of fuzzer input
 * that had nothing to do with its fields. That gap was a total authorization
 * bypass and this file was green on it; the oracle below could not have
 * asked about it, because there were no bytes for a field to be inside. Now
 * the fuzzer chooses the fields, they are encoded canonically, and a
 * signature is written -- correctly or not, per identity -- over the body
 * the verifier will read.
 *
 * The signature verdict is still the fuzzer's to choose, per identity. Real
 * Ed25519 here would mean no generated chain ever verifies, which is the
 * same dead end as non-colliding keys.
 */

#include "../chain.h"
#include "../revocation.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MAX_REVOCATIONS 4

struct cursor {
	const uint8_t *p;
	size_t n, i;
};

static uint8_t take8(struct cursor *c)
{
	return c->i < c->n ? c->p[c->i++] : 0u;
}

static uint64_t take64(struct cursor *c)
{
	uint64_t v = 0;

	for (int i = 0; i < 8; i++)
		v = (v << 8) | take8(c);
	return v;
}

/* The toy MAC shared with the unit tests: an answer that depends on the
 * message as well as on the key. */
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

/* The fuzzer's per-KEY verdict on each signature, taken from a bitmask so a
 * single mutated byte can flip one identity's signature from good to bad.
 *
 * IT IS INDEXED BY THE KEY, NOT BY THE CALL NUMBER, AND THAT IS THE POINT.
 *
 * This read `(s->good >> (s->calls++ % 16u)) & 1u`: the verdict was a
 * function of WHEN a verification happened rather than of WHOSE signature was
 * being checked, and `pubkey` was thrown away with a `(void)`. So the two most
 * damaging mutations in chain.c changed nothing this harness could observe.
 * Verifying every hop under `hop->grantee` accepts a chain with no root
 * signature in it at all; verifying every hop under the pinned `root` lets one
 * signature by the root be grafted anywhere. Both are total authorisation
 * bypasses and both were green here.
 *
 * The mask now decides which identities the GENERATOR signs correctly for,
 * and the verifier below is an ordinary keyed check over the bytes. So the
 * oracle can ask the same question of `fzn_hop_grantor` that chain.c should
 * be asking of the seam.
 *
 * Identities in this harness are one byte wide (see the header comment), so
 * the low bits of the key ARE the identity and a 16-bit mask covers them. */
struct stub {
	unsigned calls;
};

static int stub_signature_is_good(uint16_t good, const uint8_t *pubkey)
{
	return (int)((good >> (pubkey[0] % 16u)) & 1u);
}

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

static int same(const uint8_t *a, const uint8_t *b, size_t n)
{
	return memcmp(a, b, n) == 0;
}

/* Expand a one-byte identity into a full-length value.
 *
 * BYTE 0 IS THE SEED -- the header above says why identities are one byte
 * wide, and the MAC and the good-signature mask both read that byte. Every
 * later byte varies with its position.
 *
 * IT USED TO BE THIRTY-TWO COPIES OF THE SEED, which made every length
 * constant in chain.c unobservable here: a value of one repeated byte
 * answers any prefix exactly as it answers the whole, so a pin, a linkage
 * or a capability comparison could read one byte and this file's oracle --
 * which compares the same values at full length -- would agree with it. */
static void expand(uint8_t *out, size_t len, uint8_t seed)
{
	out[0] = seed;
	for (size_t i = 1; i < len; i++)
		out[i] = (uint8_t)(seed ^ (uint8_t)i);
}

/* The same value with only its LAST byte changed -- the pair that decides a
 * comparison's LENGTH, and the reason position-varying values are not
 * enough on their own: two built from equal seeds are equal everywhere, so
 * a truncated comparison still answers what a full one would.
 *
 * Identity is untouched, so a near-miss grantor is still signed and
 * verified and reaches the structural comparison rather than being refused
 * at the signature. That is what makes the FALSE ACCEPT reachable, which is
 * the only failure this file hunts: a linkage comparison reading a prefix
 * joins two hops that do not join, and the oracle below says so. */
static void expand_near(uint8_t *out, size_t len, uint8_t seed)
{
	expand(out, len, seed);
	out[len - 1] = (uint8_t)(out[len - 1] ^ 0xffu);
}

/* The oracle. Returns non-zero when an ACCEPTED chain fails one of the
 * conditions. Deliberately written from sec 4.2 rather than from chain.c, so
 * that a mistake shared with the implementation does not cancel out.
 *
 * EACH HOP'S SIGNATURE UNDER ITS OWN GRANTOR could not be asked while the
 * stub answered by call number: a verdict that did not depend on the key made
 * "verified under the right key" a question with no observable answer. It is
 * sec 4.2's "verified against a pinned root rather than adopted" -- a chain
 * is a chain because each grantor signed the hop giving its authority away,
 * and the root's signature is the one that ties it to the pin. */
static int accepted_chain_is_sound(const fzn_chain_hop_t *hops, size_t hop_count,
                                   const uint8_t *root, const uint8_t *capability, uint64_t now,
                                   const fzn_revocation_t *revs, size_t rev_count,
                                   uint16_t good, const fzn_chain_t *out)
{
	if (hop_count == 0)
		return 1;
	if (!same(fzn_hop_grantor(hops[0]), root, FZN_PUBKEY_LEN))
		return 1;

	for (size_t i = 0; i < hop_count; i++) {
		if (!stub_signature_is_good(good, fzn_hop_grantor(hops[i])))
			return 1;
		if (!same(fzn_hop_capability(hops[i]), capability, FZN_CAP_ID_LEN))
			return 1;
		if (fzn_hop_expires_at(hops[i]) != FZN_NO_EXPIRY &&
		    fzn_hop_expires_at(hops[i]) <= now)
			return 1;
		if (i > 0 && !same(fzn_hop_grantor(hops[i]), fzn_hop_grantee(hops[i - 1]),
		                   FZN_PUBKEY_LEN))
			return 1;
		if (i > 0 && !fzn_hop_delegable(hops[i - 1]))
			return 1;
		for (size_t r = 0; r < rev_count; r++)
			if (same(revs[r].issuer, root, FZN_PUBKEY_LEN) &&
			    same(revs[r].capability, fzn_hop_capability(hops[i]),
			         FZN_CAP_ID_LEN) &&
			    same(revs[r].grantee, fzn_hop_grantee(hops[i]), FZN_PUBKEY_LEN))
				return 1;
	}

	if (!same(out->grantee, fzn_hop_grantee(hops[hop_count - 1]), FZN_PUBKEY_LEN))
		return 1;
	if (!same(out->root, root, FZN_PUBKEY_LEN))
		return 1;

	return 0;
}

/* `accepted`, when given, reports whether fzn_chain_verify said yes.
 *
 * IT IS WHAT KEEPS THE TWO NAMED BYPASS CASES ALIVE NOW THAT THE VERIFIER IS
 * KEYED OVER THE MESSAGE. Under the old key-only stub, "verify under the
 * grantee" and "verify under the pinned root" turned a refusal into an
 * acceptance, which this file's accept-oracle could see. With a signature
 * that binds the bytes as well as the key, both mutations instead refuse
 * EVERYTHING -- and a harness that only inspects what was accepted is
 * perfectly happy with a verifier that accepts nothing. So two built-in
 * cases below are marked as having to verify, and failing to is a failure.
 * That is a wider net than the old one, not a narrower one: it also catches
 * any other refusal that should not have happened. */
static int drive(const uint8_t *data, size_t size, int *accepted)
{
	static uint8_t hop_bytes[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	fzn_chain_hop_t hops[FZN_CHAIN_MAX_HOPS];
	fzn_revocation_t revs[MAX_REVOCATIONS];
	/* The store over that array, since `fzn_chain_verify` takes one now.
	 * `capacity` is the array's real length; only `used` follows the
	 * corpus. */
	fzn_revocation_store_t rev_store = { revs, MAX_REVOCATIONS, 0 };
	uint8_t root[FZN_PUBKEY_LEN], capability[FZN_CAP_ID_LEN];
	struct cursor c = { data, size, 0 };
	struct stub stub = { 0 };
	uint16_t good;
	fzn_sign_ops_t sign;
	fzn_chain_t out;
	size_t hop_count, rev_count;
	uint64_t now;

	if (accepted)
		*accepted = 0;
	if (size < 16)
		return 0;

	expand(root, FZN_PUBKEY_LEN, take8(&c));
	expand(capability, FZN_CAP_ID_LEN, take8(&c));
	now = take64(&c);
	good = (uint16_t)((take8(&c) << 8) | take8(&c));
	hop_count = take8(&c) % (FZN_CHAIN_MAX_HOPS + 1u);
	rev_count = take8(&c) % (MAX_REVOCATIONS + 1u);

	memset(hops, 0, sizeof(hops));
	for (size_t i = 0; i < hop_count; i++) {
		uint8_t grantor[FZN_PUBKEY_LEN], grantee[FZN_PUBKEY_LEN];
		uint8_t hop_cap[FZN_CAP_ID_LEN];
		uint64_t issued_at, expires_at;
		uint8_t grantor_seed, grantee_seed, cap_seed, fill, near;
		int delegable;

		/* EIGHT BYTES PER HOP, READ IN THE ORDER THE CORPUS BELOW
		 * WRITES THEM, then used. Reading them all first is what lets
		 * the last one decide how the first three are built without
		 * moving any of them -- the layout is a corpus format and a
		 * reordering silently reinterprets every stored case. */
		grantor_seed = take8(&c);
		grantee_seed = take8(&c);
		cap_seed = take8(&c);
		issued_at = take8(&c);
		expires_at = take8(&c);
		delegable = take8(&c) & 1;
		/* Signed correctly exactly when the grantor's identity is in
		 * the mask, and with rubbish otherwise.
		 *
		 * BOTH BYTES ARE CONSUMED EITHER WAY. Taking one only on the
		 * bad-signature branch would make a hop cost seven bytes or
		 * eight depending on the mask, so every later hop in a
		 * multi-hop case would read from a different offset than the
		 * one it was written at -- and a corpus entry would mean
		 * something different after a one-bit change to the mask. */
		fill = take8(&c);
		near = take8(&c);

		/* THE EIGHTH BYTE WAS DISCARDED AND NOW CHOOSES A NEAR MISS,
		 * which costs the corpus nothing: it is read where it always
		 * was, and the pattern below is absent from every built-in
		 * case, so each still means what its comment says.
		 *
		 * A near miss is the value that ought to match with only its
		 * last byte changed, and it is the only input that decides a
		 * comparison's LENGTH. It matters most on the grantor, where
		 * a linkage comparison reading a prefix joins two hops that do
		 * not join -- a FALSE ACCEPT, which is what this file exists
		 * to find. */
		expand(grantor, FZN_PUBKEY_LEN, grantor_seed);
		expand(grantee, FZN_PUBKEY_LEN, grantee_seed);
		expand(hop_cap, FZN_CAP_ID_LEN, cap_seed);
		if ((near & 0xc0u) == 0xc0u)
			expand_near(grantor, FZN_PUBKEY_LEN, grantor_seed);
		if ((near & 0x30u) == 0x30u)
			expand_near(grantee, FZN_PUBKEY_LEN, grantee_seed);
		if ((near & 0x0cu) == 0x0cu)
			expand_near(hop_cap, FZN_CAP_ID_LEN, cap_seed);

		if (fzn_hop_encode(hop_bytes[i], grantor, grantee, hop_cap, issued_at,
		                   expires_at, delegable) != FZN_CHAIN_OK)
			return 0;

		if (stub_signature_is_good(good, grantor))
			mac(hop_bytes[i] + FZN_HOP_OFF_SIGNATURE, grantor[0], hop_bytes[i],
			    FZN_HOP_BODY_LEN);
		else
			memset(hop_bytes[i] + FZN_HOP_OFF_SIGNATURE, fill, FZN_SIG_LEN);

		if (fzn_hop_open(hop_bytes[i], FZN_HOP_LEN, &hops[i]) != FZN_CHAIN_OK)
			return 0;
	}

	memset(revs, 0, sizeof(revs));
	for (size_t r = 0; r < rev_count; r++) {
		uint8_t rev_cap_seed = take8(&c);
		uint8_t rev_grantee_seed = take8(&c);
		/* An entry names WHO withdrew it, and the byte is taken from
		 * the input like every other field: a corpus that could only
		 * ever name the pinned root would leave the issuer comparison
		 * with nothing to decide. */
		uint8_t rev_issuer_seed = take8(&c);
		/* And a fourth, choosing a near miss, on the same reasoning as
		 * the hops: a comparison that could only ever be handed values
		 * differing in their first byte leaves its LENGTH deciding
		 * nothing. */
		uint8_t rev_near = take8(&c);

		expand(revs[r].capability, FZN_CAP_ID_LEN, rev_cap_seed);
		expand(revs[r].grantee, FZN_PUBKEY_LEN, rev_grantee_seed);
		expand(revs[r].issuer, FZN_PUBKEY_LEN, rev_issuer_seed);
		if ((rev_near & 0xc0u) == 0xc0u)
			expand_near(revs[r].capability, FZN_CAP_ID_LEN, rev_cap_seed);
		if ((rev_near & 0x30u) == 0x30u)
			expand_near(revs[r].grantee, FZN_PUBKEY_LEN, rev_grantee_seed);
		if ((rev_near & 0x0cu) == 0x0cu)
			expand_near(revs[r].issuer, FZN_PUBKEY_LEN, rev_issuer_seed);
	}

	sign.verify = stub_verify;
	sign.sign = NULL;
	sign.ctx = &stub;
	memset(&out, 0, sizeof(out));

	rev_store.used = rev_count;
	if (fzn_chain_verify(hops, hop_count, root, capability, now, &sign, &rev_store,
	                     &out) != FZN_CHAIN_OK)
		return 0;

	if (accepted)
		*accepted = 1;

	return accepted_chain_is_sound(hops, hop_count, root, capability, now, revs, rev_count,
	                               good, &out);
}

#ifdef FZN_LIBFUZZER

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (drive(data, size, NULL))
		__builtin_trap();
	return 0;
}

#else

/* A valid single-hop chain, and the same with the signature marked bad. Short
 * enough to read; the guided run supplies breadth.
 *
 * The layout is `drive`'s: root, capability, eight bytes of `now`, two bytes
 * of the good-signature mask, the hop count, the revocation count, then eight
 * bytes per hop -- grantor, grantee, capability, issued_at, expires_at,
 * delegable, the signature fill and a near-miss selector -- and finally four
 * bytes per revocation: capability, grantee, issuer, near-miss selector.
 *
 * Every case here declares NO revocations, so the fourth revocation byte
 * costs them nothing; the eighth hop byte was always read and thrown away,
 * and none of these cases carries the bit pattern that now selects a near
 * miss, so each still means exactly what its comment says. */
static const uint8_t CASE_VALID[] = { 7, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 0,
	                              7, 3, 9, 0, 0, 0, 1, 1 };
static const uint8_t CASE_BADSIG[] = { 7, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 1, 0,
	                               7, 3, 9, 0, 0, 0, 1, 1 };
static const uint8_t CASE_TWOHOP[] = { 7, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 2, 0,
	                               7, 3, 9, 0, 0, 1, 1, 1, 3, 4, 9, 0, 0, 0, 2, 2 };

/* THE TWO CASES THAT NAME THE BYPASSES, and they are here rather than left to
 * the campaign because a corpus is not evidence a mutation is caught -- it is
 * evidence somebody once ran a fuzzer.
 *
 * Both are two-hop chains root(7) -> 3 -> 4 that a correct chain.c REFUSES,
 * so both are silent today. Each becomes an accepted-but-unsound chain under
 * exactly one mutation.
 *
 * NO_ROOT_SIG clears bit 7, so the root's own signature is bad and every
 * other identity's is good. Correct code refuses at hop 0. Verifying each hop
 * under `hop->grantee` instead checks keys 3 and 4 -- the root is never asked
 * to have signed anything -- and accepts.
 *
 * MID_BADSIG clears bit 3, so the middle identity's signature is bad.
 * Correct code refuses at hop 1. Verifying every hop under the pinned `root`
 * instead checks key 7 twice and accepts, which is how one signature by the
 * root gets grafted onto a hop the root never granted. */
static const uint8_t CASE_NO_ROOT_SIG[] = { 7, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0x7f, 2, 0,
	                                    7, 3, 9, 0, 0, 1, 1, 1, 3, 4, 9, 0, 0, 0, 2, 2 };
static const uint8_t CASE_MID_BADSIG[] = { 7, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xf7, 2, 0,
	                                   7, 3, 9, 0, 0, 1, 1, 1, 3, 4, 9, 0, 0, 0, 2, 2 };

/* AND THE THREE THAT NAME A TRUNCATED COMPARISON, which is a mutation no
 * case in this tree could catch.
 *
 * Every value these harnesses built was thirty-two copies of one seed, so a
 * comparison of one byte answered exactly as a comparison of thirty-two
 * did, and every length constant in chain.c decided nothing. Measured
 * against the tree as it stood: cutting `hop_is_revoked`'s issuer
 * comparison to a single byte left `make test` green.
 *
 * Each case below sets the eighth byte of a hop -- the near-miss selector --
 * so that one field is the value that ought to match with only its LAST
 * byte changed. Correct code refuses all three: the first is rooted one byte
 * from the pin, the second joins one byte short, the third names a
 * capability one byte from the one asked for. Each is signed correctly, so
 * nothing else can be doing the refusing; and each becomes an accepted chain
 * the oracle calls unsound the moment the matching comparison reads a prefix
 * instead of the whole value.
 *
 * They are here rather than left to the campaign for the reason the two
 * above are: a corpus is not evidence a mutation is caught. */
static const uint8_t CASE_NEAR_ROOT[] = { 7, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 0,
	                                  7, 3, 9, 0, 0, 0, 1, 0xc0 };
static const uint8_t CASE_NEAR_LINK[] = { 7, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 2, 0,
	                                  7, 3, 9, 0, 0, 1, 1, 1, 3, 4, 9, 0, 0, 0, 2, 0xc0 };
static const uint8_t CASE_NEAR_CAP[] = { 7, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 0,
	                                 7, 3, 9, 0, 0, 0, 1, 0x0c };

int main(int argc, char **argv)
{
	static uint8_t buf[65536];
	int failures = 0, cases = 0;

	if (argc > 1) {
		for (int i = 1; i < argc; i++) {
			FILE *f = fopen(argv[i], "rb");
			size_t n;

			if (!f) {
				printf("  FAIL: cannot open %s\n", argv[i]);
				failures++;
				continue;
			}
			n = fread(buf, 1, sizeof(buf), f);
			fclose(f);
			cases++;
			if (drive(buf, n, NULL)) {
				printf("  FAIL: %s -- an accepted chain was unsound\n", argv[i]);
				failures++;
			}
		}
	} else {
		static const struct {
			const char *name;
			const uint8_t *data;
			size_t size;
			int must_accept;
		} BUILTIN[] = {
			{ "a valid one-hop chain", CASE_VALID, sizeof(CASE_VALID), 1 },
			{ "a one-hop chain with a bad signature", CASE_BADSIG,
			  sizeof(CASE_BADSIG), 0 },
			{ "a valid two-hop chain", CASE_TWOHOP, sizeof(CASE_TWOHOP), 1 },
			{ "a chain whose root never signed", CASE_NO_ROOT_SIG,
			  sizeof(CASE_NO_ROOT_SIG), 0 },
			{ "a chain whose middle hop is unsigned", CASE_MID_BADSIG,
			  sizeof(CASE_MID_BADSIG), 0 },
			{ "a chain rooted one byte from the pin", CASE_NEAR_ROOT,
			  sizeof(CASE_NEAR_ROOT), 0 },
			{ "a chain that joins one byte short", CASE_NEAR_LINK,
			  sizeof(CASE_NEAR_LINK), 0 },
			{ "a chain naming a capability one byte off", CASE_NEAR_CAP,
			  sizeof(CASE_NEAR_CAP), 0 },
		};

		for (size_t i = 0; i < sizeof(BUILTIN) / sizeof(BUILTIN[0]); i++) {
			int accepted = 0;

			cases++;
			if (drive(BUILTIN[i].data, BUILTIN[i].size, &accepted)) {
				printf("  FAIL: %s -- accepted, and unsound\n", BUILTIN[i].name);
				failures++;
			}
			/* The positive controls. Two of the five must verify,
			 * and a run in which they do not is a run whose four
			 * refusal cases prove nothing -- see `drive`. */
			if (BUILTIN[i].must_accept && !accepted) {
				printf("  FAIL: %s -- was REFUSED, so every case here is "
				       "satisfied by a verifier that accepts nothing\n",
				       BUILTIN[i].name);
				failures++;
			}
		}
	}

	printf("chain_guided: %d case(s), %d failure(s)\n", cases, failures);
	return failures == 0 ? 0 : 1;
}

#endif
