/* Tests for cli/provision_print.c.
 *
 * THE CASE THIS FILE EXISTS FOR is the recombined card, and a LINE makes it
 * worse than a screen does. An attacker can put a GENUINE root beside their
 * own prekey and sign the envelope themselves; the root field then reads
 * correctly, and somebody pairing by comparing a fingerprint out of band
 * compares exactly that field.
 *
 * A fingerprint on a screen is gone when the window closes. A fingerprint in
 * a LOG outlives the moment, is read later by somebody who was not there, and
 * carries none of the doubt the operator had. So it is not printed at all
 * until the card verifies, and the suite asserts its ABSENCE for every state
 * short of that rather than asserting a message.
 */

#include "../provision_print.h"

#include "../../prekey/prekey.h"
#include "../../trust/trust.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (ok)
		return;

	failures++;
	fprintf(stderr, "  FAIL provision_print_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

/* ---- a signer that can be told who it is ------------------------------- */

static uint8_t signing_as;

static void tag(uint8_t out[FZN_SIG_LEN], uint8_t who, const uint8_t *msg, size_t msg_len)
{
	uint64_t h = 1469598103934665603u ^ who;
	size_t i;

	for (i = 0; i < msg_len; i++) {
		h ^= msg[i];
		h *= 1099511628211u;
	}
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h ^= (uint64_t)i;
		h *= 1099511628211u;
		out[i] = (uint8_t)(h >> 32);
	}
}

static void expand(uint8_t out[FZN_PUBKEY_LEN], uint8_t seed)
{
	size_t i;

	out[0] = seed;
	for (i = 1; i < FZN_PUBKEY_LEN; i++)
		out[i] = (uint8_t)(seed * 31u + i);
}

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	(void)ctx;
	tag(sig, signing_as, msg, msg_len);
	return 1;
}

/* Verification recovers the signer from the key it is given, so a signature
 * made as one key does not check out under another. */
static int stub_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	tag(want, pubkey[0], msg, msg_len);
	return memcmp(want, sig, sizeof(want)) == 0;
}

static fzn_sign_ops_t OPS;

#define SPONSOR 0x11
#define DEVICE  0x22
#define ATTACK  0x99

struct fixture {
	uint8_t root[FZN_PUBKEY_LEN];
	uint8_t device[FZN_PUBKEY_LEN];
	uint8_t hop[FZN_HOP_LEN];
	uint8_t prekey_pub[FZN_PREKEY_LEN];
	uint8_t prekey[FZN_PREKEY_LEN_TOTAL];
	uint8_t card[FZN_PROVISION_LEN_TOTAL];
	size_t card_len;
};

static int build_as(struct fixture *f, uint8_t prekey_owner, uint8_t card_signer,
                    uint64_t expires_at)
{
	fzn_cap_id_t cap;
	uint8_t owner_key[FZN_PUBKEY_LEN];

	memset(f, 0, sizeof(*f));
	memset(&cap, 0x5a, sizeof(cap));
	expand(f->root, SPONSOR);
	expand(f->device, DEVICE);
	expand(owner_key, prekey_owner);
	memset(f->prekey_pub, 0x77, sizeof(f->prekey_pub));

	signing_as = SPONSOR;
	if (fzn_chain_mint(f->root, f->device, &cap, 100, 0, 1, &OPS, f->hop) != FZN_CHAIN_OK)
		return 0;

	signing_as = prekey_owner;
	if (fzn_prekey_issue(owner_key, f->prekey_pub, 100, &OPS, f->prekey) != FZN_PREKEY_OK)
		return 0;

	signing_as = card_signer;
	return fzn_provision_pack(f->root, f->hop, f->prekey, expires_at, &OPS, f->card,
	                          sizeof(f->card), &f->card_len) == FZN_PROVISION_OK;
}


static int fingerprint_of(const uint8_t key[FZN_PUBKEY_LEN], char out[FZN_TRUST_FINGERPRINT_LEN])
{
	return fzn_trust_fingerprint(key, out, FZN_TRUST_FINGERPRINT_LEN) == FZN_TRUST_OK;
}

int main(void)
{
	static char line[FZN_PROVISION_PRINT_MAX];
	struct fixture genuine;
	char root_print[FZN_TRUST_FINGERPRINT_LEN];
	fzn_provision_line_t s;
	size_t len = 0;

	memset(&OPS, 0, sizeof(OPS));
	OPS.sign = stub_sign;
	OPS.verify = stub_verify;

	CHECK(build_as(&genuine, SPONSOR, SPONSOR, 0u), "the fixture could not build a card");
	CHECK(fingerprint_of(genuine.root, root_print), "the fixture could not spell a root");

	/* NO CARD IS THE ZERO VALUE. */
	s = FZN_PROVISION_LINE_USABLE;
	CHECK(fzn_provision_print(NULL, 0, &OPS, 50u, line, sizeof(line), &len, &s) ==
	              FZN_PROVISION_OK,
	      "a null card would not render");
	CHECK(s == FZN_PROVISION_LINE_NOTHING, "a null card was not reported as nothing");

	/* A VERIFIED CARD SHOWS ITS ROOT. */
	CHECK(fzn_provision_print(genuine.card, genuine.card_len, &OPS, 50u, line,
	                          sizeof(line), &len, &s) == FZN_PROVISION_OK,
	      "a genuine card would not render");
	CHECK(s == FZN_PROVISION_LINE_USABLE, "a genuine, in-date card was not usable");
	CHECK(strstr(line, root_print) != NULL,
	      "a verified card does not carry the library's fingerprint of its root");

	/* THE CASE THIS FILE EXISTS FOR. The attacker signs the envelope, so
	 * the card names the genuine root beside a prekey they issued. The
	 * root field is CORRECT -- that is what makes it dangerous. */
	{
		struct fixture recombined;

		CHECK(build_as(&recombined, ATTACK, ATTACK, 0u),
		      "the fixture could not build a recombined card");
		CHECK(fzn_provision_print(recombined.card, recombined.card_len, &OPS, 50u,
		                          line, sizeof(line), &len, &s) == FZN_PROVISION_OK,
		      "the recombined card would not render");
		CHECK(s == FZN_PROVISION_LINE_REFUSED,
		      "a card signed by somebody else was not refused");
		CHECK(strstr(line, root_print) == NULL,
		      "a card that did not verify put the genuine root's fingerprint in a "
		      "log, where it is read later by somebody who was not there");
	}

	/* NO VERIFIER IS NOT A WEAK YES. */
	CHECK(fzn_provision_print(genuine.card, genuine.card_len, NULL, 50u, line,
	                          sizeof(line), &len, &s) == FZN_PROVISION_OK,
	      "an unchecked card would not render");
	CHECK(s == FZN_PROVISION_LINE_UNCHECKED, "a card nobody checked was not unchecked");
	CHECK(strstr(line, root_print) == NULL,
	      "a card nobody verified offered a fingerprint to compare");

	/* AND THE CODE IS STILL THERE, because a card is public. */
	CHECK(strstr(line, FZN_PROVISION_TEXT_PREFIX) != NULL,
	      "the offering side was given no code text to show");

	/* NO CLOCK IS ITS OWN STATE, and it still shows the root: the
	 * signature verified, so the parts do belong together. */
	CHECK(fzn_provision_print(genuine.card, genuine.card_len, &OPS, 0u, line,
	                          sizeof(line), &len, &s) == FZN_PROVISION_OK,
	      "an undated card would not render");
	CHECK(s == FZN_PROVISION_LINE_UNDATED, "a card verified with no clock was dated");
	CHECK(strstr(line, root_print) != NULL,
	      "a verified card withheld its root merely because no clock was given");

	/* EXPIRED WITHHOLDS THE ROOT, which is sec 171's conservative choice
	 * rather than a consequence of the enum's order -- an expired card's
	 * signature is good and its parts do belong together, and showing the
	 * fingerprint would invite somebody to compare and accept it. */
	{
		struct fixture dated;

		CHECK(build_as(&dated, SPONSOR, SPONSOR, 100u),
		      "the fixture could not build a dated card");
		CHECK(fzn_provision_print(dated.card, dated.card_len, &OPS, 500u, line,
		                          sizeof(line), &len, &s) == FZN_PROVISION_OK,
		      "an expired card would not render");
		CHECK(s == FZN_PROVISION_LINE_EXPIRED, "an expired card was not expired");
		CHECK(strstr(line, root_print) == NULL,
		      "an expired card offered a fingerprint to compare");
		CHECK(FZN_PROVISION_LINE_EXPIRED < FZN_PROVISION_LINE_UNDATED,
		      "the enum's order no longer makes `>= UNDATED` mean verified and in "
		      "date, so the fingerprint threshold has stopped meaning anything");
	}

	/* BYTES THAT ARE NOT A CARD ARE REFUSED. */
	{
		uint8_t rubbish[FZN_PROVISION_LEN_TOTAL];

		memset(rubbish, 0x5c, sizeof(rubbish));
		CHECK(fzn_provision_print(rubbish, sizeof(rubbish), &OPS, 50u, line,
		                          sizeof(line), &len, &s) == FZN_PROVISION_OK,
		      "rubbish would not render");
		CHECK(s == FZN_PROVISION_LINE_REFUSED, "bytes that are not a card were not refused");
	}

	/* THE STATE IS REQUIRED, and a refusal leaves the conservative value. */
	CHECK(fzn_provision_print(genuine.card, genuine.card_len, &OPS, 50u, line,
	                          sizeof(line), &len, NULL) == FZN_PROVISION_ERR_MALFORMED,
	      "the state was optional after all");
	{
		char small[4];
		size_t needed = 0;

		memset(small, '@', sizeof(small));
		s = FZN_PROVISION_LINE_USABLE;
		CHECK(fzn_provision_print(genuine.card, genuine.card_len, &OPS, 50u, small,
		                          sizeof(small), &needed, &s) ==
		              FZN_PROVISION_ERR_MALFORMED,
		      "a buffer too small was written anyway");
		CHECK(needed > sizeof(small), "the size needed was not reported");
		CHECK(small[0] == '@', "a refused render left bytes in the buffer");
		CHECK(s == FZN_PROVISION_LINE_NOTHING, "a refused render left a usable state");
	}

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	printf("provision_print_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
