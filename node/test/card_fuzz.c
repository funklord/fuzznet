/*
 * A fuzz harness for a contact's card and request, `node/contact_card.c`
 * and `node/contact_request.c`: sec 689's journey 2, 1:1 chat, at its first
 * step. A card is what a stranger scans, and a request is what a stranger
 * sends; both are written wholly by somebody this user does not know yet.
 *
 * THE CLAIMS: a card or request decodes to one thing and holds only as its
 * host signed it, and two strings never name one card.
 *
 * Each case makes a card -- a host, up to four seeds, a name or none, an
 * expiry -- and a request on it, signs both with contact_request_test's
 * stub signature (a keyed hash: as discriminating as a real one, and
 * fast), and then bends the bytes and the text: bits flipped, cut short,
 * grown, a slice repeated, two bytes swapped, or a letter's case changed.
 *
 * THE PROPERTIES:
 *   1. ROUND TRIP: a signed card encodes, decodes and encodes again to the
 *      same bytes, holds, and its text gives back those bytes; a request
 *      the same, holding at its target.
 *   2. ONE ENCODING: bytes that decode encode back as themselves, and text
 *      that reads is the text of the bytes it gives.
 *   3. ONLY AS SIGNED: bent bytes that decode and hold are the bytes signed.
 *   4. ONLY WHERE NAMED: a request holds at no other target.
 *
 * FLOORS: a run in which no bent card or request decoded, or no bent text
 * read, has not tested what it claims.
 */

#include "../contact_request.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 3000u
#define FUZZ_MIN_CASES 1000u
#define NOW 2000u

static int failures;

static void fail(const char *what, unsigned long c)
{
	failures++;
	if (failures <= 10)
		fprintf(stderr, "  FAIL card_fuzz.c: case %lu: %s\n", c, what);
}

static uint64_t state = 0xd1b54a32d192ed03ull;

static uint64_t next(void)
{
	state ^= state << 13;
	state ^= state >> 7;
	state ^= state << 17;
	return state;
}

/* ---- contact_request_test's stub signature ------------------------------ */

static void mac(uint8_t out[FZN_SIG_LEN], uint8_t key, const uint8_t *msg, size_t len)
{
	uint64_t h = 0xcbf29ce484222325ull ^ key;
	size_t i;

	for (i = 0; i < len; i++)
		h = (h ^ msg[i]) * 0x100000001b3ull;
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h = (h ^ (uint64_t)i) * 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 56);
	}
}

static uint8_t signing_as;

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t len)
{
	(void)ctx;
	mac(sig, signing_as, msg, len);
	return 1;
}

static int stub_verify(void *ctx, const uint8_t pk[FZN_PUBKEY_LEN], const uint8_t *msg, size_t len,
                       const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	mac(want, pk[0], msg, len);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

static const fzn_sign_ops_t SIGN = { stub_verify, stub_sign, NULL };

static uint8_t target[FZN_PUBKEY_LEN], elsewhere[FZN_PUBKEY_LEN];
static fzn_cap_id_t member;

/* ---- a card and a request, made ------------------------------------------- */

static size_t an_address(char *out)
{
	return (size_t)sprintf(out, "10.%u.%u.%u", (unsigned)(next() % 256u),
	                       (unsigned)(next() % 256u), (unsigned)(1u + next() % 254u));
}

static int made(fzn_contact_request_t *r)
{
	static const char *const names[] = { "", "carol", "bob", "a_much_longer_name" };
	uint8_t first = (uint8_t)(1u + next() % 254u), agree[FZN_PREKEY_LEN];
	const char *name = names[next() % 4u];
	size_t i;

	memset(r, 0, sizeof(*r));
	memset(r->card.host.owner, first, FZN_PUBKEY_LEN);
	memset(agree, first ^ 0x5au, sizeof(agree));
	signing_as = first;
	if (fzn_prekey_issue(r->card.host.owner, agree, 1000u + next() % 100000u, &SIGN,
	                     r->card.host.record)
	    != FZN_PREKEY_OK)
		return 0;
	if (next() % 4u) {
		r->card.host.address_len = an_address(r->card.host.address);
		r->card.host.port = (uint16_t)(1u + next() % 65535u);
	}
	r->card.n_seeds = (size_t)(next() % (FZN_CONTACT_CARD_SEEDS_MAX + 1u));
	if (!r->card.host.address_len && !r->card.n_seeds)
		r->card.n_seeds = 1u;
	for (i = 0; i < r->card.n_seeds; i++) {
		r->card.seeds[i].address_len = an_address(r->card.seeds[i].address);
		r->card.seeds[i].port = (uint16_t)(1u + next() % 65535u);
		r->card.seeds[i].transport = (uint8_t)(next() % 2u);
		r->card.seeds[i].metric = (uint8_t)next();
	}
	r->card.name_len = strlen(name);
	memcpy(r->card.name, name, r->card.name_len);
	r->card.expires_at = (next() & 1u) ? 0u : NOW + 1u + next() % 100000u;
	if (fzn_contact_card_sign(&r->card, &SIGN) != FZN_CONTACT_CARD_OK)
		return 0;
	memcpy(r->target, target, FZN_PUBKEY_LEN);
	for (i = 0; i < FZN_CONTACT_REQUEST_NONCE_LEN; i++)
		r->nonce[i] = (uint8_t)next();
	r->expires_at = NOW + 1u + next() % FZN_CONTACT_REQUEST_LIFE_MAX;
	return fzn_contact_request_sign(r, &SIGN) == FZN_CONTACT_REQUEST_OK;
}

/* ---- bent ---------------------------------------------------------------- */

static size_t bend(uint8_t *b, size_t len, size_t cap)
{
	size_t k, i, j;
	uint8_t t;

	switch (next() % 6u) {
	case 1:
		if (len)
			return (size_t)(next() % len);
		break;
	case 2:
		if (len < cap) {
			for (k = 1u + next() % 8u; k > 0u && len < cap; k--)
				b[len++] = (uint8_t)next();
			return len;
		}
		break;
	case 3:
		if (len >= 8u) {
			i = next() % (len - 4u);
			memmove(b + i + 4u, b + i, len - i - 4u);
			return len;
		}
		break;
	case 4:
		if (len >= 2u) {
			i = next() % len;
			j = next() % len;
			t = b[i];
			b[i] = b[j];
			b[j] = t;
			return len;
		}
		break;
	case 5:
		/* A LETTER'S CASE, which a QR reader or a person may change. */
		if (len) {
			i = next() % len;
			if ((b[i] >= 'A' && b[i] <= 'Z') || (b[i] >= 'a' && b[i] <= 'z'))
				b[i] ^= 0x20u;
			else
				b[i] ^= 1u;
			return len;
		}
		break;
	default:
		break;
	}
	for (k = 1u + next() % 3u; k > 0u && len; k--)
		b[next() % len] ^= (uint8_t)(1u << (next() % 8u));
	return len;
}

int main(int argc, char **argv)
{
	static fzn_contact_request_t r, back;
	static fzn_contact_card_t card_back;
	static uint8_t card[FZN_CONTACT_CARD_MAX + 16u], again[FZN_CONTACT_REQUEST_MAX + 16u];
	static uint8_t request[FZN_CONTACT_REQUEST_MAX + 16u], bent[FZN_CONTACT_REQUEST_MAX + 16u];
	static char text[FZN_CONTACT_CARD_TEXT_MAX + 16u], text_again[FZN_CONTACT_CARD_TEXT_MAX];
	unsigned long cases = FUZZ_DEFAULT_CASES, c;
	unsigned long cards_decoded = 0, requests_decoded = 0, texts_read = 0;

	if (argc > 1)
		cases = strtoul(argv[1], NULL, 10);
	if (cases < FUZZ_MIN_CASES)
		cases = FUZZ_MIN_CASES;
	memset(target, 0x77, sizeof(target));
	memset(elsewhere, 0x78, sizeof(elsewhere));
	memset(member.b, 0x44, sizeof(member.b));

	for (c = 0; c < cases; c++) {
		size_t card_len = 0, request_len = 0, len = 0, n, text_len;

		if (!made(&r)) {
			fail("a well-formed card or request could not be signed", c);
			continue;
		}

		/* 1. ROUND TRIP, the card. */
		if (fzn_contact_card_encode(&r.card, card, sizeof(card), &card_len) != FZN_CONTACT_CARD_OK
		    || fzn_contact_card_decode(card, card_len, &card_back) != FZN_CONTACT_CARD_OK
		    || fzn_contact_card_encode(&card_back, again, sizeof(again), &len)
		               != FZN_CONTACT_CARD_OK
		    || len != card_len || memcmp(again, card, len) != 0
		    || fzn_contact_card_verify(&card_back, &SIGN, &member, NOW) != FZN_CONTACT_CARD_OK) {
			fail("a signed card does not round-trip and hold", c);
			continue;
		}
		if (fzn_contact_card_text(card, card_len, text, sizeof(text)) != FZN_CONTACT_CARD_OK
		    || fzn_contact_card_from_text(text, strlen(text), again, sizeof(again), &len)
		               != FZN_CONTACT_CARD_OK
		    || len != card_len || memcmp(again, card, len) != 0)
			fail("a card's text does not give back its bytes", c);

		/* 1 and 4, the request. */
		if (fzn_contact_request_encode(&r, request, sizeof(request), &request_len)
		            != FZN_CONTACT_REQUEST_OK
		    || fzn_contact_request_decode(request, request_len, &back) != FZN_CONTACT_REQUEST_OK
		    || fzn_contact_request_encode(&back, again, sizeof(again), &len)
		               != FZN_CONTACT_REQUEST_OK
		    || len != request_len || memcmp(again, request, len) != 0
		    || fzn_contact_request_verify(&back, &SIGN, &member, target, NOW)
		               != FZN_CONTACT_REQUEST_OK) {
			fail("a signed request does not round-trip and hold at its target", c);
			continue;
		}
		if (fzn_contact_request_verify(&back, &SIGN, &member, elsewhere, NOW)
		    == FZN_CONTACT_REQUEST_OK)
			fail("a request held at a target it does not name", c);

		/* 2 and 3, the card's bytes bent. */
		memcpy(bent, card, card_len);
		n = bend(bent, card_len, FZN_CONTACT_CARD_MAX + 16u);
		if (fzn_contact_card_decode(bent, n, &card_back) == FZN_CONTACT_CARD_OK) {
			cards_decoded++;
			if (fzn_contact_card_encode(&card_back, again, sizeof(again), &len)
			            != FZN_CONTACT_CARD_OK
			    || len != n || memcmp(again, bent, n) != 0)
				fail("bent card bytes decoded that do not encode back as themselves", c);
			if (fzn_contact_card_verify(&card_back, &SIGN, &member, NOW) == FZN_CONTACT_CARD_OK
			    && (n != card_len || memcmp(bent, card, n) != 0))
				fail("a bent card held", c);
		}

		/* 2 and 3, the request's bytes bent. */
		memcpy(bent, request, request_len);
		n = bend(bent, request_len, sizeof(bent));
		if (fzn_contact_request_decode(bent, n, &back) == FZN_CONTACT_REQUEST_OK) {
			requests_decoded++;
			if (fzn_contact_request_encode(&back, again, sizeof(again), &len)
			            != FZN_CONTACT_REQUEST_OK
			    || len != n || memcmp(again, bent, n) != 0)
				fail("bent request bytes decoded that do not encode back as themselves", c);
			if (fzn_contact_request_verify(&back, &SIGN, &member, target, NOW)
			            == FZN_CONTACT_REQUEST_OK
			    && (n != request_len || memcmp(bent, request, n) != 0))
				fail("a bent request held", c);
		}

		/* 2, the text bent: two strings never name one card. */
		text_len = strlen(text);
		n = bend((uint8_t *)text, text_len, sizeof(text) - 1u);
		text[n] = '\0';
		if (fzn_contact_card_from_text(text, n, again, sizeof(again), &len)
		    == FZN_CONTACT_CARD_OK) {
			texts_read++;
			if (fzn_contact_card_text(again, len, text_again, sizeof(text_again))
			            != FZN_CONTACT_CARD_OK
			    || strcmp(text_again, text) != 0)
				fail("bent text read that is not the text of the bytes it gives", c);
		}
	}

	if (cards_decoded == 0u)
		fail("no bent card decoded: its shape check was never met past", cases);
	if (requests_decoded == 0u)
		fail("no bent request decoded", cases);
	if (texts_read == 0u)
		fail("no bent text read", cases);
	printf("card_fuzz: %lu cases, %lu bent cards decoded, %lu bent requests decoded, %lu bent "
	       "texts read, %d failure(s)\n",
	       cases, cards_decoded, requests_decoded, texts_read, failures);
	return failures ? 1 : 0;
}
