/* Chain verification under a coverage-guided fuzzer, with a real oracle.
 *
 * `chain_fuzz.c` beside it generates chains and compares against a model.
 * This one asks a narrower and sharper question: **when `fzn_chain_verify`
 * says yes, is it right?** Everything it accepts is re-checked here against
 * the six things sec 4.2 says an accepted chain must satisfy -- pinned root,
 * unbroken grantor/grantee linkage, the capability asked for, nothing
 * expired, nothing revoked, and the reported grantee being the last hop's.
 *
 * A false ACCEPT is an authorisation bypass and is the only failure worth
 * hunting this hard. A false reject is a bug too, but it fails safe and a
 * model-based harness already covers that direction.
 *
 * IDENTITIES ARE ONE BYTE WIDE ON PURPOSE. A 32-byte key drawn from fuzzer
 * bytes never collides, so linkage never holds, so the accept path is never
 * reached and the campaign explores rejection code for ever. Expanding a
 * single byte to fill the key makes `hops[i].grantor == hops[i-1].grantee`
 * something a mutation can stumble into. Getting this wrong is the same
 * mistake as the reassembly harness's -- a run that cannot reach the
 * interesting code, reporting millions of clean executions.
 *
 * The signature check is a stub driven by the input, so the fuzzer decides
 * per hop whether a signature verifies. Real Ed25519 here would mean no
 * generated chain ever verifies, which is the same dead end.
 */

#include "../chain.h"
#include "../revocation.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MAX_REVOCATIONS 4
#define SIGNED_LEN      8

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

/* The fuzzer's per-hop verdict on each signature, taken from a bitmask so a
 * single mutated byte can flip one hop's signature from good to bad. */
struct stub {
	uint16_t good;
	unsigned calls;
};

static int stub_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	struct stub *s = (struct stub *)ctx;
	unsigned which = s->calls++;

	(void)pubkey;
	(void)msg;
	(void)msg_len;
	(void)sig;
	return (s->good >> (which % 16u)) & 1u;
}

static int same(const uint8_t *a, const uint8_t *b, size_t n)
{
	return memcmp(a, b, n) == 0;
}

/* The oracle. Returns non-zero when an ACCEPTED chain fails one of the six.
 * Deliberately written from sec 4.2 rather than from chain.c, so that a
 * mistake shared with the implementation does not cancel out. */
static int accepted_chain_is_sound(const fzn_chain_hop_t *hops, size_t hop_count,
                                   const uint8_t *root, const uint8_t *capability, uint64_t now,
                                   const fzn_revocation_t *revs, size_t rev_count,
                                   const fzn_chain_t *out)
{
	if (hop_count == 0)
		return 1;
	if (!same(hops[0].grantor, root, FZN_PUBKEY_LEN))
		return 1;

	for (size_t i = 0; i < hop_count; i++) {
		if (!same(hops[i].capability, capability, FZN_CAP_ID_LEN))
			return 1;
		if (hops[i].expires_at != FZN_NO_EXPIRY && hops[i].expires_at <= now)
			return 1;
		if (i > 0 && !same(hops[i].grantor, hops[i - 1].grantee, FZN_PUBKEY_LEN))
			return 1;
		for (size_t r = 0; r < rev_count; r++)
			if (same(revs[r].capability, hops[i].capability, FZN_CAP_ID_LEN) &&
			    same(revs[r].grantee, hops[i].grantee, FZN_PUBKEY_LEN))
				return 1;
	}

	if (!same(out->grantee, hops[hop_count - 1].grantee, FZN_PUBKEY_LEN))
		return 1;
	if (!same(out->root, root, FZN_PUBKEY_LEN))
		return 1;

	return 0;
}

static int drive(const uint8_t *data, size_t size)
{
	fzn_chain_hop_t hops[FZN_CHAIN_MAX_HOPS];
	fzn_revocation_t revs[MAX_REVOCATIONS];
	static uint8_t signed_regions[FZN_CHAIN_MAX_HOPS][SIGNED_LEN];
	uint8_t root[FZN_PUBKEY_LEN], capability[FZN_CAP_ID_LEN];
	struct cursor c = { data, size, 0 };
	struct stub stub = { 0, 0 };
	fzn_sign_ops_t sign;
	fzn_chain_t out;
	size_t hop_count, rev_count;
	uint64_t now;

	if (size < 16)
		return 0;

	memset(root, take8(&c), sizeof(root));
	memset(capability, take8(&c), sizeof(capability));
	now = take64(&c);
	stub.good = (uint16_t)((take8(&c) << 8) | take8(&c));
	hop_count = take8(&c) % (FZN_CHAIN_MAX_HOPS + 1u);
	rev_count = take8(&c) % (MAX_REVOCATIONS + 1u);

	memset(hops, 0, sizeof(hops));
	for (size_t i = 0; i < hop_count; i++) {
		memset(hops[i].grantor, take8(&c), FZN_PUBKEY_LEN);
		memset(hops[i].grantee, take8(&c), FZN_PUBKEY_LEN);
		memset(hops[i].capability, take8(&c), FZN_CAP_ID_LEN);
		hops[i].issued_at = take8(&c);
		hops[i].expires_at = take8(&c);
		hops[i].delegable = take8(&c) & 1;
		memset(hops[i].signature, take8(&c), FZN_SIG_LEN);
		memset(signed_regions[i], take8(&c), SIGNED_LEN);
		hops[i].signed_region = signed_regions[i];
		hops[i].signed_region_len = SIGNED_LEN;
	}

	memset(revs, 0, sizeof(revs));
	for (size_t r = 0; r < rev_count; r++) {
		memset(revs[r].capability, take8(&c), FZN_CAP_ID_LEN);
		memset(revs[r].grantee, take8(&c), FZN_PUBKEY_LEN);
	}

	sign.verify = stub_verify;
	sign.ctx = &stub;
	memset(&out, 0, sizeof(out));

	if (fzn_chain_verify(hops, hop_count, root, capability, now, &sign, revs, rev_count,
	                     &out) != FZN_OK)
		return 0;

	return accepted_chain_is_sound(hops, hop_count, root, capability, now, revs, rev_count,
	                               &out);
}

#ifdef FZN_LIBFUZZER

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (drive(data, size))
		__builtin_trap();
	return 0;
}

#else

/* A valid single-hop chain, and the same with the signature marked bad. Short
 * enough to read; the guided run supplies breadth. */
static const uint8_t CASE_VALID[] = { 7, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 0,
	                              7, 3, 9, 0, 0, 0, 1, 1 };
static const uint8_t CASE_BADSIG[] = { 7, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 1, 0,
	                               7, 3, 9, 0, 0, 0, 1, 1 };
static const uint8_t CASE_TWOHOP[] = { 7, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 2, 0,
	                               7, 3, 9, 0, 0, 1, 1, 1, 3, 4, 9, 0, 0, 0, 2, 2 };

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
			if (drive(buf, n)) {
				printf("  FAIL: %s -- an accepted chain was unsound\n", argv[i]);
				failures++;
			}
		}
	} else {
		const uint8_t *builtin[] = { CASE_VALID, CASE_BADSIG, CASE_TWOHOP };
		const size_t sizes[] = { sizeof(CASE_VALID), sizeof(CASE_BADSIG),
			                 sizeof(CASE_TWOHOP) };

		for (size_t i = 0; i < 3; i++) {
			cases++;
			if (drive(builtin[i], sizes[i])) {
				printf("  FAIL: built-in case %zu accepted an unsound chain\n", i);
				failures++;
			}
		}
	}

	printf("chain_guided: %d case(s), %d failure(s)\n", cases, failures);
	return failures == 0 ? 0 : 1;
}

#endif
