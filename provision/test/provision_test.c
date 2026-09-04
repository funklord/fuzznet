/* Tests for provision/provision.c: the card a device is handed out of band.
 *
 * THE CASE THIS SUITE EXISTS FOR is `test_the_envelope_binds_the_parts`. Every
 * other test here checks a shape, and shapes are cheap; the envelope's whole
 * reason to exist is that the three objects inside a card are individually
 * PUBLIC -- a hop is a grant anyone can verify, a prekey record is published
 * by definition, a root is an identity -- so without a signature over the
 * concatenation anybody can assemble a card out of genuine parts that were
 * never issued together. That test builds exactly that card and requires it to
 * be refused.
 *
 * THE SIGNER DEPENDS ON WHO SIGNS AS WELL AS ON WHAT, copied from
 * prekey_test.c along with its reason: a stub returning the same bytes for
 * every key would make "signed by the root" a claim with no content, and would
 * pass the recombination test above for the wrong reason.
 */

#include "../provision.h"

#include "../../chain/chain.h"
#include "../../prekey/prekey.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

#if defined(__GNUC__)
#define FZN_CHECK_PRINTF __attribute__((format(printf, 3, 4)))
#else
#define FZN_CHECK_PRINTF
#endif

static void check_at(int ok, int line, const char *fmt, ...) FZN_CHECK_PRINTF;

static void check_at(int ok, int line, const char *fmt, ...)
{
	va_list ap;

	checks++;
	if (ok)
		return;

	failures++;
	fprintf(stderr, "  FAIL provision_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

/* Abandons the case as well as reporting, for a fixture that did not build.
 * prekey_test.c has the incident that produced it. */
#define REQUIRE(cond, ...)                                    \
	do {                                                  \
		int require_ok = (cond) ? 1 : 0;              \
		check_at(require_ok, __LINE__, __VA_ARGS__);  \
		if (!require_ok)                              \
			return;                               \
	} while (0)

/* Identity is the key's first byte; every key here carries its seed there. */
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

static uint8_t signing_as;

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

static int refuse_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	(void)ctx;
	(void)sig;
	(void)msg;
	(void)msg_len;
	return 0;
}

static const fzn_sign_ops_t OPS = { stub_verify, stub_sign, NULL };
static const fzn_sign_ops_t REFUSER = { stub_verify, refuse_sign, NULL };

static void expand(uint8_t out[FZN_PUBKEY_LEN], uint8_t seed)
{
	size_t i;

	out[0] = seed;
	for (i = 1; i < FZN_PUBKEY_LEN; i++)
		out[i] = (uint8_t)(seed * 31u + i);
}

#define SPONSOR 0x11
#define DEVICE  0x22
#define ATTACK  0x99

/* A whole fixture: the three objects, and a card over them. Built by real
 * mints rather than by filler, so the offsets in the header are checked
 * against parsers that refuse a wrong length rather than against themselves. */
typedef struct fixture {
	uint8_t root[FZN_PUBKEY_LEN];
	uint8_t device[FZN_PUBKEY_LEN];
	uint8_t hop[FZN_HOP_LEN];
	uint8_t prekey_pub[FZN_PREKEY_LEN];
	uint8_t prekey[FZN_PREKEY_LEN_TOTAL];
	uint8_t card[FZN_PROVISION_LEN_TOTAL];
	size_t card_len;
} fixture_t;

/* Build a card. `prekey_owner` is who issues the prekey record and
 * `card_signer` who signs the envelope, so a caller can build the recombined
 * card by naming two different people. */
static int build_as(fixture_t *f, uint8_t prekey_owner, uint8_t card_signer,
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

static int build(fixture_t *f)
{
	return build_as(f, SPONSOR, SPONSOR, 0);
}

static void test_the_layout_is_what_the_header_says(void)
{
	fixture_t f;

	CHECK(FZN_PROVISION_OFF_ROOT == 2u, "root is not where the table says");
	CHECK(FZN_PROVISION_OFF_HOP == 34u, "hop is not where the table says");
	CHECK(FZN_PROVISION_OFF_PREKEY == 213u, "prekey is not where the table says");
	CHECK(FZN_PROVISION_OFF_EXPIRES_AT == 351u, "expires_at is not where the table says");
	CHECK(FZN_PROVISION_OFF_SIGNATURE == 359u, "signature is not where the table says");
	CHECK(FZN_PROVISION_BODY_LEN == 359u, "the signed body changed size");
	CHECK(FZN_PROVISION_LEN_TOTAL == 423u, "the card changed size");

	REQUIRE(build(&f), "the fixture did not build");
	CHECK(f.card_len == FZN_PROVISION_LEN_TOTAL, "pack reported %zu bytes", f.card_len);
	CHECK(f.card[FZN_PROVISION_OFF_VERSION] == 1u, "the version byte is not 1");
	CHECK(f.card[FZN_PROVISION_OFF_OBJECT] == 134u, "the object tag is not the card's");
	CHECK(memcmp(f.card + FZN_PROVISION_OFF_ROOT, f.root, FZN_PUBKEY_LEN) == 0,
	      "the root did not land at its offset");
	CHECK(memcmp(f.card + FZN_PROVISION_OFF_HOP, f.hop, FZN_HOP_LEN) == 0,
	      "the hop did not land at its offset");
	CHECK(memcmp(f.card + FZN_PROVISION_OFF_PREKEY, f.prekey, FZN_PREKEY_LEN_TOTAL) == 0,
	      "the prekey record did not land at its offset");
}

/* THE OFFSETS ARE CHECKED BY PARSERS THAT REFUSE A WRONG LENGTH, which is
 * worth more than comparing them against themselves: a mis-slice by one byte
 * gives `fzn_hop_open` 179 bytes starting in the wrong place, and it says so.
 * The three inner objects are then verified, so the card is shown to carry
 * usable material and not merely bytes of the right size. */
static void test_a_card_carries_objects_that_still_open(void)
{
	fixture_t f;
	fzn_provision_card_t card;
	fzn_chain_hop_t hop;
	fzn_prekey_record_t rec;

	REQUIRE(build(&f), "the fixture did not build");
	REQUIRE(fzn_provision_open(f.card, f.card_len, &card) == FZN_PROVISION_OK,
	        "a card this file packed did not open");

	CHECK(fzn_hop_open(card.hop, FZN_HOP_LEN, &hop) == FZN_CHAIN_OK,
	      "the hop slice is not a hop");
	CHECK(fzn_prekey_open(card.prekey, FZN_PREKEY_LEN_TOTAL, &rec) == FZN_PREKEY_OK,
	      "the prekey slice is not a prekey record");
	CHECK(fzn_prekey_verify(rec, &OPS) == FZN_PREKEY_OK,
	      "the prekey record in the card does not verify");
	CHECK(memcmp(card.root, f.root, FZN_PUBKEY_LEN) == 0, "the root view is wrong");
	CHECK(card.expires_at == 0u, "expires_at did not round trip");
	CHECK(fzn_provision_verify(card, &OPS, 0) == FZN_PROVISION_OK,
	      "a card this file signed did not verify");
}

/* THE CASE THE ENVELOPE EXISTS FOR.
 *
 * An attacker holds no key of the sponsor's and needs none: a hop is public
 * and a prekey record is published. They take the genuine hop -- which really
 * does name this device, minted by the real sponsor -- and pair it with their
 * OWN prekey record, which is self-signed and perfectly valid. A device with
 * no envelope to check would pin the real root, verify the real grant, and
 * then establish its session with the attacker.
 *
 * Both ways out are closed, and the test walks both:
 *
 *   sign the recombined card as themselves, keeping the real root
 *       -> the envelope does not verify under the root the card names
 *   swap the root to their own so the envelope verifies
 *       -> the hop no longer verifies under the root that was pinned
 */
static void test_the_envelope_binds_the_parts(void)
{
	fixture_t genuine;
	fixture_t forged;
	fzn_provision_card_t card;
	fzn_chain_hop_t hop;
	uint8_t attacker_root[FZN_PUBKEY_LEN];

	REQUIRE(build(&genuine), "the genuine fixture did not build");

	/* The attacker's card: the sponsor's root and hop, the attacker's
	 * prekey record, signed by the attacker. */
	REQUIRE(build_as(&forged, ATTACK, ATTACK, 0), "the forged fixture did not build");
	CHECK(memcmp(forged.hop, genuine.hop, FZN_HOP_LEN) == 0,
	      "the forged card does not carry the genuine hop, so it tests nothing");
	CHECK(memcmp(forged.prekey, genuine.prekey, FZN_PREKEY_LEN_TOTAL) != 0,
	      "the forged card carries the genuine prekey, so it tests nothing");

	REQUIRE(fzn_provision_open(forged.card, forged.card_len, &card) == FZN_PROVISION_OK,
	        "the forged card did not open, so the refusal below proves nothing");
	CHECK(fzn_provision_verify(card, &OPS, 0) == FZN_PROVISION_ERR_SIGNATURE,
	      "a card assembled from genuine parts by a stranger was accepted");

	/* The other way out: make the envelope verify by naming the attacker's
	 * own root. It verifies -- and the grant inside it now grants nothing,
	 * because the hop was never signed by that root. */
	expand(attacker_root, ATTACK);
	memcpy(forged.card + FZN_PROVISION_OFF_ROOT, attacker_root, FZN_PUBKEY_LEN);
	signing_as = ATTACK;
	REQUIRE(fzn_provision_pack(attacker_root, genuine.hop, forged.prekey, 0, &OPS,
	                           forged.card, sizeof(forged.card),
	                           &forged.card_len) == FZN_PROVISION_OK,
	        "the second forged card did not pack");
	REQUIRE(fzn_provision_open(forged.card, forged.card_len, &card) == FZN_PROVISION_OK,
	        "the second forged card did not open");
	CHECK(fzn_provision_verify(card, &OPS, 0) == FZN_PROVISION_OK,
	      "the attacker cannot sign a card naming their own root, so the leg below "
	      "is untested");
	REQUIRE(fzn_hop_open(card.hop, FZN_HOP_LEN, &hop) == FZN_CHAIN_OK,
	        "the hop slice stopped opening");
	CHECK(!stub_verify(NULL, card.root, forged.card + FZN_PROVISION_OFF_HOP,
	                   FZN_HOP_LEN - FZN_SIG_LEN,
	                   forged.card + FZN_PROVISION_OFF_HOP + FZN_HOP_LEN - FZN_SIG_LEN),
	      "the genuine hop verified under the attacker's root");
}

static void test_every_signed_byte_is_signed(void)
{
	fixture_t f;
	size_t i;
	int accepted = 0;

	REQUIRE(build(&f), "the fixture did not build");

	for (i = 0; i < FZN_PROVISION_BODY_LEN; i++) {
		fzn_provision_card_t card;
		uint8_t bent[FZN_PROVISION_LEN_TOTAL];
		fzn_provision_err_t err;

		memcpy(bent, f.card, sizeof(bent));
		bent[i] ^= 0x40u;

		err = fzn_provision_open(bent, sizeof(bent), &card);
		if (err != FZN_PROVISION_OK) {
			/* Bytes 0 and 1 are the version and the tag, so a bent
			 * one is refused at the shape gate before any key is
			 * touched. Refused is refused. */
			CHECK(i < FZN_PROVISION_OFF_ROOT,
			      "byte %zu was refused for its shape and should not be", i);
			continue;
		}
		if (fzn_provision_verify(card, &OPS, 0) == FZN_PROVISION_OK)
			accepted++;
	}

	CHECK(accepted == 0, "%d bent bytes inside the signed body were accepted", accepted);
}

static void test_open_refuses_what_is_not_our_shape(void)
{
	fixture_t f;
	fzn_provision_card_t card;
	uint8_t bent[FZN_PROVISION_LEN_TOTAL];

	REQUIRE(build(&f), "the fixture did not build");

	CHECK(fzn_provision_open(f.card, FZN_PROVISION_LEN_TOTAL - 1u, &card)
	      == FZN_PROVISION_ERR_SHAPE, "a short card was not refused");
	CHECK(fzn_provision_open(f.card, FZN_PROVISION_LEN_TOTAL + 1u, &card)
	      == FZN_PROVISION_ERR_SHAPE, "a long card was not refused");
	CHECK(fzn_provision_open(f.card, 0, &card) == FZN_PROVISION_ERR_SHAPE,
	      "an empty buffer was not refused");

	memcpy(bent, f.card, sizeof(bent));
	bent[FZN_PROVISION_OFF_VERSION] = 2u;
	CHECK(fzn_provision_open(bent, sizeof(bent), &card) == FZN_PROVISION_ERR_SHAPE,
	      "a card of another version was not refused");

	/* A CARD IS NOT ANY OF THE THINGS INSIDE IT. Every tag the library
	 * allocates is tried, because the tag byte is the whole of what stops
	 * an envelope signature being read as one of its own parts. */
	memcpy(bent, f.card, sizeof(bent));
	bent[FZN_PROVISION_OFF_OBJECT] = (uint8_t)FZN_OBJECT_HOP;
	CHECK(fzn_provision_open(bent, sizeof(bent), &card) == FZN_PROVISION_ERR_SHAPE,
	      "a hop's tag was accepted as a card's");
	bent[FZN_PROVISION_OFF_OBJECT] = (uint8_t)FZN_OBJECT_PREKEY;
	CHECK(fzn_provision_open(bent, sizeof(bent), &card) == FZN_PROVISION_ERR_SHAPE,
	      "a prekey's tag was accepted as a card's");
	bent[FZN_PROVISION_OFF_OBJECT] = (uint8_t)FZN_OBJECT_RECORD;
	CHECK(fzn_provision_open(bent, sizeof(bent), &card) == FZN_PROVISION_ERR_SHAPE,
	      "a record's tag was accepted as a card's");
	bent[FZN_PROVISION_OFF_OBJECT] = 0u;
	CHECK(fzn_provision_open(bent, sizeof(bent), &card) == FZN_PROVISION_ERR_SHAPE,
	      "a consumer-half tag was accepted as a card's");
}

static void test_the_expiry_is_bounded_and_optional(void)
{
	fixture_t f;
	fzn_provision_card_t card;

	REQUIRE(build_as(&f, SPONSOR, SPONSOR, 500), "the fixture did not build");
	REQUIRE(fzn_provision_open(f.card, f.card_len, &card) == FZN_PROVISION_OK,
	        "the card did not open");

	CHECK(card.expires_at == 500u, "expires_at did not round trip big-endian");
	CHECK(fzn_provision_verify(card, &OPS, 499) == FZN_PROVISION_OK,
	      "a card was refused before its expiry");
	CHECK(fzn_provision_verify(card, &OPS, 500) == FZN_PROVISION_OK,
	      "a card was refused ON its expiry, which is inside its life");
	CHECK(fzn_provision_verify(card, &OPS, 501) == FZN_PROVISION_ERR_EXPIRED,
	      "an expired card was accepted");
	CHECK(fzn_provision_verify(card, &OPS, 0) == FZN_PROVISION_OK,
	      "a caller with no clock was refused");

	REQUIRE(build_as(&f, SPONSOR, SPONSOR, 0), "the never-expiring fixture did not build");
	REQUIRE(fzn_provision_open(f.card, f.card_len, &card) == FZN_PROVISION_OK,
	        "the never-expiring card did not open");
	CHECK(fzn_provision_verify(card, &OPS, 0xffffffffffffffffull) == FZN_PROVISION_OK,
	      "a card with no expiry expired");
}

/* THE ORDER IS THE PROPERTY, not either check on its own. `expires_at` is
 * inside the signed body, so a reader that consulted it first would be acting
 * on a number the forger chose. Bending the expiry must therefore report
 * SIGNATURE -- if it ever reports EXPIRED, the checks have swapped. */
static void test_the_signature_is_checked_before_the_expiry(void)
{
	fixture_t f;
	fzn_provision_card_t card;
	uint8_t bent[FZN_PROVISION_LEN_TOTAL];

	REQUIRE(build_as(&f, SPONSOR, SPONSOR, 0), "the fixture did not build");

	memcpy(bent, f.card, sizeof(bent));
	/* An expiry of 1: long past, and not what the sponsor signed. */
	memset(bent + FZN_PROVISION_OFF_EXPIRES_AT, 0, 8);
	bent[FZN_PROVISION_OFF_EXPIRES_AT + 7u] = 1u;

	REQUIRE(fzn_provision_open(bent, sizeof(bent), &card) == FZN_PROVISION_OK,
	        "the bent card did not open");
	CHECK(card.expires_at == 1u, "the bend did not take, so the order is untested");
	CHECK(fzn_provision_verify(card, &OPS, 1000) == FZN_PROVISION_ERR_SIGNATURE,
	      "a forged expiry was acted on before the signature was checked");
}

static void test_the_text_round_trips(void)
{
	fixture_t f;
	char text[FZN_PROVISION_TEXT_LEN];
	uint8_t back[FZN_PROVISION_LEN_TOTAL];
	size_t back_len = 0;
	size_t i;
	int outside = 0;

	REQUIRE(build(&f), "the fixture did not build");
	REQUIRE(fzn_provision_text(f.card, f.card_len, text, sizeof(text)) == FZN_PROVISION_OK,
	        "the card did not encode");

	CHECK(strlen(text) == FZN_PROVISION_TEXT_PREFIX_LEN + FZN_PROVISION_TEXT_BODY_LEN,
	      "the text is %zu characters, wanted %u", strlen(text),
	      (unsigned)(FZN_PROVISION_TEXT_PREFIX_LEN + FZN_PROVISION_TEXT_BODY_LEN));
	CHECK(FZN_PROVISION_TEXT_BODY_LEN == 677u,
	      "677 characters is what 423 bytes of unpadded base32 comes to");
	CHECK(strncmp(text, FZN_PROVISION_TEXT_PREFIX, FZN_PROVISION_TEXT_PREFIX_LEN) == 0,
	      "the version prefix is missing");

	/* EVERY CHARACTER IS IN QR ALPHANUMERIC MODE, which is the entire
	 * reason for base32 over base64 and is a claim the header makes. The
	 * mode's alphabet is 0-9 A-Z space and $%*+-./: -- the card uses a
	 * subset, and this refuses anything outside it. */
	for (i = 0; text[i]; i++) {
		char c = text[i];

		if ((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == ':')
			continue;
		outside++;
	}
	CHECK(outside == 0, "%d characters are outside QR alphanumeric mode", outside);

	REQUIRE(fzn_provision_from_text(text, back, sizeof(back), &back_len) == FZN_PROVISION_OK,
	        "the text did not decode");
	CHECK(back_len == FZN_PROVISION_LEN_TOTAL, "the decode gave %zu bytes", back_len);
	CHECK(memcmp(back, f.card, FZN_PROVISION_LEN_TOTAL) == 0,
	      "the card did not survive the round trip");
}

static void test_the_text_is_canonical(void)
{
	fixture_t f;
	char text[FZN_PROVISION_TEXT_LEN];
	char bent[FZN_PROVISION_TEXT_LEN];
	uint8_t back[FZN_PROVISION_LEN_TOTAL];
	size_t back_len = 0;
	size_t last;

	REQUIRE(build(&f), "the fixture did not build");
	REQUIRE(fzn_provision_text(f.card, f.card_len, text, sizeof(text)) == FZN_PROVISION_OK,
	        "the card did not encode");

	memcpy(bent, text, sizeof(bent));
	bent[0] = 'G';
	CHECK(fzn_provision_from_text(bent, back, sizeof(back), &back_len)
	      == FZN_PROVISION_ERR_SHAPE, "a string with another prefix was decoded");

	memcpy(bent, text, sizeof(bent));
	bent[strlen(bent) - 1u] = '\0';
	CHECK(fzn_provision_from_text(bent, back, sizeof(back), &back_len)
	      == FZN_PROVISION_ERR_SHAPE, "a truncated string was decoded");

	/* LOWERCASE IS REFUSED, NOT FOLDED. QR alphanumeric mode has no
	 * lowercase in it, so a lowercase card did not come out of a code this
	 * library wrote -- and folding would give two strings for one card. */
	memcpy(bent, text, sizeof(bent));
	{
		size_t i;
		int folded = 0;

		for (i = FZN_PROVISION_TEXT_PREFIX_LEN; bent[i]; i++) {
			if (bent[i] >= 'A' && bent[i] <= 'Z') {
				bent[i] = (char)(bent[i] - 'A' + 'a');
				folded = 1;
				break;
			}
		}
		REQUIRE(folded, "no letter to lowercase, so the case below is untested");
	}
	CHECK(fzn_provision_from_text(bent, back, sizeof(back), &back_len)
	      == FZN_PROVISION_ERR_SHAPE, "a lowercased card was decoded");

	memcpy(bent, text, sizeof(bent));
	bent[FZN_PROVISION_TEXT_PREFIX_LEN] = '1';
	CHECK(fzn_provision_from_text(bent, back, sizeof(back), &back_len)
	      == FZN_PROVISION_ERR_SHAPE, "a character outside the alphabet was decoded");

	/* THE SPARE BIT OF THE LAST CHARACTER MUST BE ZERO. 423 bytes is 3384
	 * bits and 677 characters carry 3385, so exactly one bit is padding.
	 * Left unchecked, two strings decode to one card -- and then "the code
	 * I scanned" names two things, which is not a property a signature over
	 * the bytes can repair. The encoder always emits an even final value,
	 * so raising it by one sets that bit. */
	memcpy(bent, text, sizeof(bent));
	last = strlen(bent) - 1u;
	REQUIRE(bent[last] != '7', "the final character is the top of the alphabet");
	if (bent[last] == 'Z')
		bent[last] = '2';
	else
		bent[last] = (char)(bent[last] + 1);
	CHECK(fzn_provision_from_text(bent, back, sizeof(back), &back_len)
	      == FZN_PROVISION_ERR_SHAPE,
	      "a string whose padding bit was set decoded to the same card");
}

static void test_every_guard_refuses_its_own_argument(void)
{
	fixture_t f;
	fzn_provision_card_t card;
	char text[FZN_PROVISION_TEXT_LEN];
	uint8_t out[FZN_PROVISION_LEN_TOTAL];
	size_t len = 0;

	REQUIRE(build(&f), "the fixture did not build");

	CHECK(fzn_provision_pack(NULL, f.hop, f.prekey, 0, &OPS, out, sizeof(out), &len)
	      == FZN_PROVISION_ERR_MALFORMED, "pack accepted a null root");
	CHECK(fzn_provision_pack(f.root, NULL, f.prekey, 0, &OPS, out, sizeof(out), &len)
	      == FZN_PROVISION_ERR_MALFORMED, "pack accepted a null hop");
	CHECK(fzn_provision_pack(f.root, f.hop, NULL, 0, &OPS, out, sizeof(out), &len)
	      == FZN_PROVISION_ERR_MALFORMED, "pack accepted a null prekey");
	CHECK(fzn_provision_pack(f.root, f.hop, f.prekey, 0, &OPS, NULL, sizeof(out), &len)
	      == FZN_PROVISION_ERR_MALFORMED, "pack accepted a null out");
	CHECK(fzn_provision_pack(f.root, f.hop, f.prekey, 0, &OPS, out, sizeof(out), NULL)
	      == FZN_PROVISION_ERR_MALFORMED, "pack accepted a null out_len");
	CHECK(fzn_provision_pack(f.root, f.hop, f.prekey, 0, &OPS, out,
	                         FZN_PROVISION_LEN_TOTAL - 1u, &len)
	      == FZN_PROVISION_ERR_MALFORMED, "pack accepted a buffer one byte short");
	CHECK(fzn_provision_pack(f.root, f.hop, f.prekey, 0, NULL, out, sizeof(out), &len)
	      == FZN_PROVISION_ERR_SIGNER, "pack accepted a null signer");

	CHECK(fzn_provision_open(NULL, FZN_PROVISION_LEN_TOTAL, &card)
	      == FZN_PROVISION_ERR_MALFORMED, "open accepted null bytes");
	CHECK(fzn_provision_open(f.card, f.card_len, NULL) == FZN_PROVISION_ERR_MALFORMED,
	      "open accepted a null out");

	REQUIRE(fzn_provision_open(f.card, f.card_len, &card) == FZN_PROVISION_OK,
	        "the card did not open");
	CHECK(fzn_provision_verify(card, NULL, 0) == FZN_PROVISION_ERR_SIGNER,
	      "verify accepted a null verifier");
	{
		fzn_provision_card_t empty;

		memset(&empty, 0, sizeof(empty));
		CHECK(fzn_provision_verify(empty, &OPS, 0) == FZN_PROVISION_ERR_MALFORMED,
		      "verify accepted a card that was never opened");
	}

	/*
	 * THE SECOND OPERANDS, which the cases above never reach.
	 *
	 * Each guard here is a conjunction, and a suite that fails the FIRST
	 * operand never evaluates the second: `fzn_provision_pack(..., NULL,
	 * ...)` returns before `sign->sign` is looked at. So three branches sat
	 * reachable and untested, and `make coverage` named them --
	 * project.md sec 75 listed them and sec 76 recorded the decision to
	 * report rather than close them.
	 *
	 * They are closed now because the states are real rather than
	 * contrived. **A vtable with a null member is what a partially
	 * initialised consumer has**: a struct zeroed at declaration and
	 * filled in later, with one line not yet written or a branch that
	 * skipped it. That is not a caller passing NULL by mistake -- it is a
	 * caller who believes they have a signer.
	 *
	 * The distinction matters for what is returned. A null `sign` and a
	 * null `sign->sign` are both ERR_SIGNER rather than ERR_MALFORMED,
	 * because in both the seam is the thing that is absent, and
	 * `chain.h`'s convention is that a caller told MALFORMED goes looking
	 * at their arguments while one told SIGNER goes looking at their
	 * crypto.
	 */
	{
		fzn_sign_ops_t half_signer = { stub_verify, NULL, NULL };
		fzn_sign_ops_t half_verifier = { NULL, stub_sign, NULL };
		fzn_provision_card_t opened;
		fzn_provision_card_t partial;
		size_t len = 0;

		CHECK(fzn_provision_pack(f.root, f.hop, f.prekey, 0, &half_signer, out,
		                         sizeof(out), &len) == FZN_PROVISION_ERR_SIGNER,
		      "pack accepted a signer struct whose sign is null -- which is what a "
		      "consumer that filled the vtable in two steps and got interrupted has");
		CHECK(len == 0u, "a refused pack reported a length");

		REQUIRE(fzn_provision_open(f.card, f.card_len, &opened) == FZN_PROVISION_OK,
		        "the card did not open");
		CHECK(fzn_provision_verify(opened, &half_verifier, 0) == FZN_PROVISION_ERR_SIGNER,
		      "verify accepted a verifier struct whose verify is null");

		/* A CARD WITH A BASE AND NO ROOT, which `fzn_provision_open`
		 * cannot produce -- it sets both or neither. This is a caller
		 * assembling the view by hand, and the guard exists precisely
		 * because the struct is public and nothing stops them. Without
		 * it the signature check would read a null pointer as a key. */
		partial = opened;
		partial.root = NULL;
		CHECK(fzn_provision_verify(partial, &OPS, 0) == FZN_PROVISION_ERR_MALFORMED,
		      "verify accepted a card view with a base and no root, and would have "
		      "read a null pointer as the key it checks against");
	}

	CHECK(fzn_provision_text(NULL, f.card_len, text, sizeof(text))
	      == FZN_PROVISION_ERR_MALFORMED, "text accepted null bytes");
	CHECK(fzn_provision_text(f.card, f.card_len, NULL, sizeof(text))
	      == FZN_PROVISION_ERR_MALFORMED, "text accepted a null out");
	CHECK(fzn_provision_text(f.card, f.card_len, text, FZN_PROVISION_TEXT_LEN - 1u)
	      == FZN_PROVISION_ERR_MALFORMED, "text accepted a buffer one byte short");
	CHECK(fzn_provision_text(f.card, f.card_len - 1u, text, sizeof(text))
	      == FZN_PROVISION_ERR_SHAPE, "text accepted something that is not a card");

	CHECK(fzn_provision_from_text(NULL, out, sizeof(out), &len)
	      == FZN_PROVISION_ERR_MALFORMED, "from_text accepted a null string");
	CHECK(fzn_provision_from_text("FZN1:", NULL, sizeof(out), &len)
	      == FZN_PROVISION_ERR_MALFORMED, "from_text accepted a null out");
	CHECK(fzn_provision_from_text("FZN1:", out, sizeof(out), NULL)
	      == FZN_PROVISION_ERR_MALFORMED, "from_text accepted a null out_len");
	CHECK(fzn_provision_from_text("FZN1:", out, FZN_PROVISION_LEN_TOTAL - 1u, &len)
	      == FZN_PROVISION_ERR_MALFORMED, "from_text accepted a buffer one byte short");
	CHECK(fzn_provision_from_text("FZN1:", out, sizeof(out), &len)
	      == FZN_PROVISION_ERR_SHAPE, "from_text accepted a prefix with no card after it");
}

static void test_a_refusing_signer_is_reported(void)
{
	fixture_t f;
	uint8_t out[FZN_PROVISION_LEN_TOTAL];
	size_t len = 0;

	REQUIRE(build(&f), "the fixture did not build");
	CHECK(fzn_provision_pack(f.root, f.hop, f.prekey, 0, &REFUSER, out, sizeof(out), &len)
	      == FZN_PROVISION_ERR_SIGNER, "a signer that refused was reported as something else");
	CHECK(len == 0u, "a refused pack reported a length");
}

static void test_err_str_names_every_arm(void)
{
	CHECK(strcmp(fzn_provision_err_str(FZN_PROVISION_OK), "ok") == 0, "OK is misnamed");
	CHECK(strcmp(fzn_provision_err_str(FZN_PROVISION_ERR_MALFORMED), "unknown") != 0,
	      "MALFORMED falls through to unknown");
	CHECK(strcmp(fzn_provision_err_str(FZN_PROVISION_ERR_SHAPE), "unknown") != 0,
	      "SHAPE falls through to unknown");
	CHECK(strcmp(fzn_provision_err_str(FZN_PROVISION_ERR_SIGNATURE), "unknown") != 0,
	      "SIGNATURE falls through to unknown");
	CHECK(strcmp(fzn_provision_err_str(FZN_PROVISION_ERR_SIGNER), "unknown") != 0,
	      "SIGNER falls through to unknown");
	CHECK(strcmp(fzn_provision_err_str(FZN_PROVISION_ERR_EXPIRED), "unknown") != 0,
	      "EXPIRED falls through to unknown");
	CHECK(strcmp(fzn_provision_err_str((fzn_provision_err_t)99), "unknown") == 0,
	      "a value outside the enum is not called unknown");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	CHECK(0, "deliberate");
	CHECK(failures == before + 1, "a failing check did not count");
	failures = before;
	checks -= 1;
}

int main(void)
{
	test_the_layout_is_what_the_header_says();
	test_a_card_carries_objects_that_still_open();
	test_the_envelope_binds_the_parts();
	test_every_signed_byte_is_signed();
	test_open_refuses_what_is_not_our_shape();
	test_the_expiry_is_bounded_and_optional();
	test_the_signature_is_checked_before_the_expiry();
	test_the_text_round_trips();
	test_the_text_is_canonical();
	test_every_guard_refuses_its_own_argument();
	test_a_refusing_signer_is_reported();
	test_err_str_names_every_arm();
	test_the_suite_can_tell_pass_from_fail();

	printf("provision_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
