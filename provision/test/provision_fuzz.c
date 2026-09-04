/*
 * A fuzz harness for the provisioning card's two decoders.
 *
 * WHY THIS ONE. `provision/` is the newest decoder of stranger bytes in this
 * library and was the only wire object without a harness. It is also the one
 * whose input arrives most directly from outside: `fzn_provision_from_text`
 * eats a string somebody's camera produced from a code on a poster, and
 * `fzn_provision_open` eats the bytes that come out of it. Every other such
 * decoder here has a harness -- chain, revocation, record, reassembly,
 * freshness, peer, vocabulary, blob, prekey, tree, seal.
 *
 * THE PROPERTY THIS EXISTS FOR IS CANONICALITY, and it is a model property
 * rather than a spot invariant. An overrun would be caught by a sanitizer; two
 * strings decoding to one card would not be caught by anything. So the
 * assertion is a round trip in both directions:
 *
 *   from_text(s) accepted  =>  text(that card) is byte-identical to s
 *   text(card)             =>  from_text of it gives back the same card
 *
 * The first is the one with teeth. `provision.c` refuses a set padding bit for
 * exactly this reason, and the check is one line -- so it is the kind of line
 * a later edit removes as redundant, and nothing except this would notice. A
 * card whose text is not unique is a card where "the code I scanned" names two
 * things, which a signature over the bytes cannot repair.
 *
 * THE GENERATOR MUTATES REAL CARDS, not only random bytes. A uniformly random
 * 423-byte buffer is refused at the version byte and reaches nothing; a
 * uniformly random string is refused at the prefix. Both are generated anyway
 * -- a decoder must survive them -- but the cases that matter are a genuine
 * card with one byte bent, and a genuine string with one character changed,
 * deleted, inserted, or lowercased. The coverage floors below are on those
 * STATES rather than on call counts, for prekey_fuzz's reason: a run that
 * never lowercased a character has not tested the rule that a scanned card is
 * uppercase, however many strings it decoded.
 *
 * THE SIGNER DEPENDS ON WHO SIGNS AS WELL AS ON WHAT, copied from the unit
 * suite with its reason: a stub returning the same bytes for every key would
 * make "verified under the root the card names" a claim with no content, and
 * every forged-card case would pass for the wrong reason.
 */

#include "../provision.h"

#include "../../chain/chain.h"
#include "../../prekey/prekey.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u

/* Below this the floors are cleared by a single lucky case, so a run refuses
 * rather than reporting a success that means nothing. Same number and same
 * reasoning as the other harnesses here. */
#define FUZZ_MIN_CASES 1000u

#define SPONSOR 0x11
#define DEVICE  0x22
#define ATTACK  0x99

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

static int stub_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	mac(want, pubkey[0], msg, msg_len);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

static const fzn_sign_ops_t OPS = { stub_verify, stub_sign, NULL };

struct coverage {
	unsigned long text_ok;
	unsigned long text_refused;
	unsigned long bytes_ok;
	unsigned long bytes_refused;
	unsigned long verified;
	unsigned long bad_signature;
	unsigned long expired;
	unsigned long lowercased;
	unsigned long padding_bit;
	unsigned long truncated;
};

/* A tiny deterministic source, so a failing case is reproducible from its
 * seed alone -- the reason real_crypto_test gives for not drawing from the
 * system pool. */
static uint32_t next(uint32_t *state)
{
	*state ^= *state << 13;
	*state ^= *state >> 17;
	*state ^= *state << 5;
	return *state;
}

static void expand(uint8_t out[FZN_PUBKEY_LEN], uint8_t seed)
{
	size_t i;

	out[0] = seed;
	for (i = 1; i < FZN_PUBKEY_LEN; i++)
		out[i] = (uint8_t)(seed * 31u + i);
}

/* A genuine card, or 0 if the fixture would not build. */
static int build(uint8_t card[FZN_PROVISION_LEN_TOTAL], uint64_t expires_at, uint8_t signer)
{
	uint8_t root[FZN_PUBKEY_LEN], device[FZN_PUBKEY_LEN];
	uint8_t prekey_pub[FZN_PREKEY_LEN];
	uint8_t hop[FZN_HOP_LEN], rec[FZN_PREKEY_LEN_TOTAL];
	fzn_cap_id_t cap;
	size_t len = 0;

	memset(&cap, 0x5a, sizeof(cap));
	expand(root, SPONSOR);
	expand(device, DEVICE);
	memset(prekey_pub, 0x77, sizeof(prekey_pub));

	signing_as = SPONSOR;
	if (fzn_chain_mint(root, device, &cap, 100, 0, 1, &OPS, hop) != FZN_CHAIN_OK)
		return 0;
	if (fzn_prekey_issue(root, prekey_pub, 100, &OPS, rec) != FZN_PREKEY_OK)
		return 0;

	signing_as = signer;
	return fzn_provision_pack(root, hop, rec, expires_at, &OPS, card,
	                          FZN_PROVISION_LEN_TOTAL, &len) == FZN_PROVISION_OK
	       && len == FZN_PROVISION_LEN_TOTAL;
}

/* Every refusal path shares this: whatever came back, nothing may claim a
 * length other than the card's, and an accepted card must carry our version
 * and tag. Checked after every call rather than at the end, because a decoder
 * that is briefly wrong and then right again is still wrong. */
static int bytes_invariants(fzn_provision_err_t err, const uint8_t *bytes, size_t len,
                            fzn_provision_card_t card)
{
	if (err != FZN_PROVISION_OK)
		return 0;
	if (len != FZN_PROVISION_LEN_TOTAL)
		return 1;
	if (card.base != bytes)
		return 1;
	if (bytes[FZN_PROVISION_OFF_VERSION] != 1u)
		return 1;
	if (bytes[FZN_PROVISION_OFF_OBJECT] != (uint8_t)FZN_OBJECT_PROVISION)
		return 1;
	/* The views must land inside the buffer the caller owns. */
	if (card.root != bytes + FZN_PROVISION_OFF_ROOT)
		return 1;
	if (card.hop != bytes + FZN_PROVISION_OFF_HOP)
		return 1;
	if (card.prekey != bytes + FZN_PROVISION_OFF_PREKEY)
		return 1;
	return 0;
}

static int fuzz_one(uint32_t seed, struct coverage *cov)
{
	uint32_t state = seed ? seed : 1u;
	uint8_t card[FZN_PROVISION_LEN_TOTAL];
	uint8_t back[FZN_PROVISION_LEN_TOTAL];
	char text[FZN_PROVISION_TEXT_LEN];
	char again[FZN_PROVISION_TEXT_LEN];
	fzn_provision_card_t opened;
	fzn_provision_err_t err;
	size_t back_len = 0;
	unsigned shape = next(&state) % 8u;
	uint64_t expires_at = (next(&state) % 2u) ? (uint64_t)(next(&state) % 2000u) : 0u;
	uint8_t signer = (next(&state) % 4u) ? SPONSOR : ATTACK;

	if (!build(card, expires_at, signer))
		return 1;

	/* ---- the byte decoder ----------------------------------------- */
	if (shape == 0u) {
		/* Uniformly random. Refused at the version byte almost always,
		 * and a decoder must survive it anyway. */
		size_t i;

		for (i = 0; i < sizeof(card); i++)
			card[i] = (uint8_t)next(&state);
	} else if (shape == 1u) {
		card[next(&state) % FZN_PROVISION_LEN_TOTAL] ^= (uint8_t)(1u << (next(&state) % 8u));
	}

	err = fzn_provision_open(card, sizeof(card), &opened);
	if (bytes_invariants(err, card, sizeof(card), opened))
		return 1;
	if (err == FZN_PROVISION_OK) {
		fzn_provision_err_t v;

		cov->bytes_ok++;
		v = fzn_provision_verify(opened, &OPS, 1000u);
		if (v == FZN_PROVISION_OK)
			cov->verified++;
		else if (v == FZN_PROVISION_ERR_SIGNATURE)
			cov->bad_signature++;
		else if (v == FZN_PROVISION_ERR_EXPIRED)
			cov->expired++;
		else
			return 1; /* no other verdict is reachable from a card */
	} else {
		cov->bytes_refused++;
		/* A REFUSED CARD MUST LEAVE NOTHING BEHIND. `fzn_provision_open`
		 * memsets before it validates, so a caller that ignores the
		 * status reads a zeroed view rather than a stale one from the
		 * last card -- the hazard `wire/seal.c` records for its own
		 * refusals. */
		if (opened.base || opened.root || opened.hop || opened.prekey
		    || opened.expires_at)
			return 1;
	}

	/* A short or long buffer is never a card, whatever it contains. */
	if (fzn_provision_open(card, FZN_PROVISION_LEN_TOTAL - 1u, &opened) == FZN_PROVISION_OK)
		return 1;
	if (fzn_provision_open(card, FZN_PROVISION_LEN_TOTAL + 1u, &opened) == FZN_PROVISION_OK)
		return 1;

	/* ---- the text decoder, and the round trip ---------------------- */
	if (!build(card, expires_at, signer))
		return 1;
	if (fzn_provision_text(card, sizeof(card), text, sizeof(text)) != FZN_PROVISION_OK)
		return 1;

	if (shape == 2u) {
		size_t at = FZN_PROVISION_TEXT_PREFIX_LEN
		            + (next(&state) % FZN_PROVISION_TEXT_BODY_LEN);

		if (text[at] >= 'A' && text[at] <= 'Z') {
			text[at] = (char)(text[at] - 'A' + 'a');
			cov->lowercased++;
		}
	} else if (shape == 3u) {
		/* Raise the final character, which sets the padding bit the
		 * encoder always leaves clear. */
		size_t last = strlen(text) - 1u;

		if (text[last] != '7' && text[last] != 'Z') {
			text[last] = (char)(text[last] + 1);
			cov->padding_bit++;
		}
	} else if (shape == 4u) {
		text[strlen(text) - 1u] = '\0';
		cov->truncated++;
	} else if (shape == 5u) {
		text[FZN_PROVISION_TEXT_PREFIX_LEN
		     + (next(&state) % FZN_PROVISION_TEXT_BODY_LEN)] = (char)(next(&state) % 128u);
	} else if (shape == 6u) {
		size_t i;

		for (i = 0; i < sizeof(text) - 1u; i++)
			text[i] = (char)(next(&state) % 128u);
		text[sizeof(text) - 1u] = '\0';
	}

	err = fzn_provision_from_text(text, back, sizeof(back), &back_len);
	if (err == FZN_PROVISION_OK) {
		cov->text_ok++;
		if (back_len != FZN_PROVISION_LEN_TOTAL)
			return 1;
		/* CANONICALITY, which is what this harness is for. Re-encoding
		 * an accepted string must reproduce it exactly; if it does not,
		 * two strings decode to one card and "the code I scanned" has
		 * stopped naming one thing. */
		if (fzn_provision_text(back, back_len, again, sizeof(again)) != FZN_PROVISION_OK)
			return 1;
		if (strcmp(again, text) != 0)
			return 1;
	} else {
		cov->text_refused++;
		if (err != FZN_PROVISION_ERR_SHAPE && err != FZN_PROVISION_ERR_MALFORMED)
			return 1;
	}

	return 0;
}

#ifdef FZN_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint32_t seed = 1u;
	size_t i;
	struct coverage cov = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

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
	struct coverage cov = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	unsigned long c;

	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
	}

	if (cases < FUZZ_MIN_CASES) {
		printf("provision_fuzz: %lu cases is below FUZZ_MIN_CASES (%u), so this run "
		       "will not report success -- every coverage floor below that is cleared "
		       "by a single lucky hit. Re-run with %u or more.\n",
		       cases, (unsigned)FUZZ_MIN_CASES, (unsigned)FUZZ_MIN_CASES);
		return 1;
	}

	for (c = 0; c < cases; c++) {
		if (fuzz_one((uint32_t)c + 1u, &cov)) {
			printf("provision_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	/* FLOORS ON STATES, NOT ON CALLS. A run that never lowercased a
	 * character has not tested that a scanned card is uppercase; one that
	 * never set the padding bit has not tested the rule that makes a card's
	 * text unique; and one that never met a card signed by a stranger has
	 * not tested that the envelope binds its parts. */
	if (cov.text_ok < floor_of(cases, 4u) || cov.text_refused < floor_of(cases, 4u)
	    || cov.bytes_ok < floor_of(cases, 4u) || cov.bytes_refused < floor_of(cases, 8u)
	    || cov.verified < floor_of(cases, 8u) || cov.bad_signature < floor_of(cases, 8u)
	    || cov.expired < floor_of(cases, 20u) || cov.lowercased < floor_of(cases, 20u)
	    || cov.padding_bit < floor_of(cases, 20u) || cov.truncated < floor_of(cases, 20u)) {
		printf("provision_fuzz: REACHED TOO LITTLE -- %lu text ok, %lu text refused, "
		       "%lu bytes ok, %lu bytes refused, %lu verified, %lu bad signature, "
		       "%lu expired, %lu lowercased, %lu padding bit, %lu truncated in %lu "
		       "cases.\n",
		       cov.text_ok, cov.text_refused, cov.bytes_ok, cov.bytes_refused,
		       cov.verified, cov.bad_signature, cov.expired, cov.lowercased,
		       cov.padding_bit, cov.truncated, cases);
		return 1;
	}

	printf("provision_fuzz: %lu cases, %lu text ok, %lu text refused, %lu bytes ok, "
	       "%lu bytes refused, %lu verified, %lu bad signature, %lu expired, "
	       "%lu lowercased, %lu padding bit, %lu truncated; canonical throughout\n",
	       cases, cov.text_ok, cov.text_refused, cov.bytes_ok, cov.bytes_refused,
	       cov.verified, cov.bad_signature, cov.expired, cov.lowercased, cov.padding_bit,
	       cov.truncated);
	return 0;
}
#endif
