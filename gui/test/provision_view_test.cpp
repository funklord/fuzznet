/* Tests for gui/provision_view.cpp, headless.
 *
 * THE CASE THIS FILE EXISTS FOR is the recombined card. An attacker can put a
 * GENUINE root beside their OWN prekey and sign the envelope themselves; the
 * root field then reads correctly, and a user pairing by comparing a
 * fingerprint out of band compares exactly that field, finds it right, and
 * accepts. The envelope signature is the only thing that says the three parts
 * came from one hand -- provision.h: "The parts may each be genuine and not
 * belong together."
 *
 * So the assertion is not that a fingerprint appears when things are well. It
 * is that the fingerprint is ABSENT for every card that did not verify, and
 * it is written as a comparison against `fzn_trust_fingerprint`'s own output
 * rather than against a message, because a security property tested by
 * matching a refusal string is one a reworded string switches off.
 *
 * The second is the level. A card's text is 682 characters; it fits version
 * 15 at level L and no version at M, Q or H, and lowercasing it -- which
 * leaves QR alphanumeric mode -- makes it fit nowhere. provision.h chose
 * uppercase base32 for exactly that reason and nothing checked it.
 */

#include "../provision_view.h"
#include "../qr_view.h"

extern "C" {
#include "../../prekey/prekey.h"
#include "../../trust/trust.h"
}

#include <QApplication>

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
	fprintf(stderr, "  FAIL provision_view_test.cpp:%d: %s\n", line, what);
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

static QString fingerprint_of(const uint8_t key[FZN_PUBKEY_LEN])
{
	char text[FZN_TRUST_FINGERPRINT_LEN];

	if (fzn_trust_fingerprint(key, text, sizeof(text)) != FZN_TRUST_OK)
		return QString();
	return QString::fromLatin1(text);
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");

	QApplication app(argc, argv);
	fzn_provision_view view;
	struct fixture genuine;
	QString root_print;

	memset(&OPS, 0, sizeof(OPS));
	OPS.sign = stub_sign;
	OPS.verify = stub_verify;

	CHECK(build_as(&genuine, SPONSOR, SPONSOR, 0u), "the fixture could not build a card");
	root_print = fingerprint_of(genuine.root);
	CHECK(!root_print.isEmpty(), "the fixture could not spell a fingerprint");

	/* NO CARD IS ITS OWN STATE. */
	CHECK(view.shown_state() == fzn_provision_view::NOTHING,
	      "a fresh view is not in the no-card state");
	CHECK(view.code_text().isEmpty(), "a fresh view carries a code");

	/* A VERIFIED CARD SHOWS ITS FINGERPRINT, and it is the library's
	 * spelling of the card's own root rather than this widget's. */
	view.show_card(genuine.card, genuine.card_len, &OPS, 50u);
	CHECK(view.shown_state() == fzn_provision_view::USABLE,
	      "a genuine, unexpired card was not shown as usable");
	CHECK(view.state_text().contains(root_print),
	      "a verified card does not show the library's fingerprint of its root");

	/* THE CASE THIS FILE EXISTS FOR. The attacker signs the envelope, so
	 * the card names the genuine root beside a prekey they issued. The
	 * root field is CORRECT -- that is what makes it dangerous -- and the
	 * signature is not, so no fingerprint may be offered to compare. */
	{
		struct fixture recombined;

		CHECK(build_as(&recombined, ATTACK, ATTACK, 0u),
		      "the fixture could not build a recombined card");

		view.show_card(recombined.card, recombined.card_len, &OPS, 50u);
		CHECK(view.shown_state() == fzn_provision_view::REFUSED,
		      "a card whose envelope was signed by somebody else was not refused");
		CHECK(!view.state_text().contains(root_print),
		      "a card that did not verify offered the genuine root's fingerprint, "
		      "which is the one field a user compares and the one an attacker "
		      "can get right");
	}

	/* NO VERIFIER IS NOT A WEAK YES. Same genuine card, nobody asked to
	 * check it: the fingerprint is still withheld, because nothing has
	 * bound this root to this prekey. */
	view.show_card(genuine.card, genuine.card_len, nullptr, 50u);
	CHECK(view.shown_state() == fzn_provision_view::UNCHECKED,
	      "a card nobody verified was not shown as unchecked");
	CHECK(!view.state_text().contains(root_print),
	      "a card nobody verified offered a fingerprint to compare");

	/* AND THE CODE IS STILL DRAWN, because a card is public and the
	 * offering side has nothing to check its own card against. */
	CHECK(!view.code_text().isEmpty(),
	      "the offering side was given no code to show");
	CHECK(view.code_text().startsWith(QStringLiteral(FZN_PROVISION_TEXT_PREFIX)),
	      "the code does not carry the card's own text form");

	/* NO CLOCK IS ITS OWN STATE. Verified, but the expiry -- the field
	 * that stops an old card being replayed -- was never looked at. */
	view.show_card(genuine.card, genuine.card_len, &OPS, 0u);
	CHECK(view.shown_state() == fzn_provision_view::UNDATED,
	      "a card verified without a clock was reported as dated");
	CHECK(view.state_text() != QStringLiteral("verified, and in date"),
	      "a card whose expiry was never checked says it is in date");

	/* EXPIRED IS ITS OWN STATE, and not a flavour of refused. */
	{
		struct fixture dated;

		CHECK(build_as(&dated, SPONSOR, SPONSOR, 100u),
		      "the fixture could not build a dated card");

		view.show_card(dated.card, dated.card_len, &OPS, 50u);
		CHECK(view.shown_state() == fzn_provision_view::USABLE,
		      "a card inside its expiry was not usable");

		view.show_card(dated.card, dated.card_len, &OPS, 500u);
		CHECK(view.shown_state() == fzn_provision_view::EXPIRED,
		      "a card past its expiry was not shown as expired");
		CHECK(!view.state_text().contains(root_print),
		      "an expired card still offered a fingerprint to compare");
	}

	/* BYTES THAT ARE NOT A CARD ARE REFUSED, and said to be. */
	{
		uint8_t rubbish[FZN_PROVISION_LEN_TOTAL];

		memset(rubbish, 0x5c, sizeof(rubbish));
		view.show_card(rubbish, sizeof(rubbish), &OPS, 50u);
		CHECK(view.shown_state() == fzn_provision_view::REFUSED,
		      "bytes that are not a card were not refused");
		CHECK(view.code_text().isEmpty(),
		      "bytes that are not a card were offered as a code");
	}

	/* THE LEVEL IS FORCED, NOT CHOSEN. A card's text fits version 15 at L
	 * and no version at M, Q or H -- so this is not a preference and a
	 * later card layout that grows past a code must fail here. */
	{
		static char text[FZN_PROVISION_TEXT_LEN];
		size_t n;

		CHECK(fzn_provision_text(genuine.card, genuine.card_len, text,
		                         sizeof(text)) == FZN_PROVISION_OK,
		      "the card would not render as text");
		n = strlen(text);

		CHECK(fzn_provision_view::code_level() == FZN_QR_LEVEL_L,
		      "the pairing code is not encoded at the only level that fits");
		CHECK(fzn_qr_version_for(text, n, FZN_QR_LEVEL_L) > 0u,
		      "a card does not fit a QR code at level L, so pairing by code "
		      "cannot work at all");
		CHECK(fzn_qr_version_for(text, n, FZN_QR_LEVEL_M) == 0u &&
		              fzn_qr_version_for(text, n, FZN_QR_LEVEL_Q) == 0u &&
		              fzn_qr_version_for(text, n, FZN_QR_LEVEL_H) == 0u,
		      "a card fits at a level above L, so the claim that L is forced "
		      "is no longer true and the comment saying so is wrong");

		/* AND UPPERCASE IS LOAD-BEARING. Lowercasing leaves QR
		 * alphanumeric mode, and provision.h chose base32 for exactly
		 * that reason. */
		{
			static char lowered[FZN_PROVISION_TEXT_LEN];
			size_t i;

			memcpy(lowered, text, sizeof(lowered));
			for (i = 0; i < n; i++)
				if (lowered[i] >= 'A' && lowered[i] <= 'Z')
					lowered[i] = (char)(lowered[i] + 32);

			CHECK(fzn_qr_version_for(lowered, n, FZN_QR_LEVEL_L) == 0u,
			      "a lowercased card still fits, so provision.h's reason for "
			      "uppercase base32 is not the one stated");
		}
	}

	/* THE CODE THE WIDGET DREW IS THE CARD'S OWN TEXT, not something it
	 * composed. */
	view.show_card(genuine.card, genuine.card_len, &OPS, 50u);
	{
		static char text[FZN_PROVISION_TEXT_LEN];

		CHECK(fzn_provision_text(genuine.card, genuine.card_len, text,
		                         sizeof(text)) == FZN_PROVISION_OK,
		      "the card would not render as text");
		CHECK(view.code_text() == QString::fromLatin1(text),
		      "the widget's code is not the library's text form of the card");
	}

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	printf("provision_view_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
