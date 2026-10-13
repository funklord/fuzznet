/* node contact_card_test -- a contact card, sec 617: its encoding, what
 * makes one hold, and its text. A stub signature keyed by a key's first
 * byte, as contact_devices_test's, since what is tested is which key
 * signed, not the curve. */

#include "../contact_card.h"

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                       \
	do {                                                                                    \
		checks++;                                                                       \
		if (!(cond)) {                                                                  \
			failures++;                                                             \
			fprintf(stderr, "  FAIL contact_card_test.c:%d: %s\n", __LINE__, what); \
		}                                                                               \
	} while (0)

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


static uint8_t owner[32], host[32], other[32];
static fzn_cap_id_t member;

/* A card for `host`, owned by `owner` by a one-hop chain, reached at an
 * address, with a seed and a name, signed by the host. */
static void card_of(fzn_contact_card_t *c)
{
	uint8_t agree[FZN_PREKEY_LEN];

	memset(c, 0, sizeof(*c));
	memcpy(c->host.owner, owner, 32u);
	memset(agree, 0x5a, sizeof(agree));
	signing_as = host[0];
	(void)fzn_prekey_issue(host, agree, 1000u, &SIGN, c->host.record);
	signing_as = owner[0];
	c->host.hop_count = fzn_chain_mint(owner, host, &member, 100u, FZN_NO_EXPIRY, 0, &SIGN,
	                                   c->host.hops[0])
	                                    == FZN_CHAIN_OK
	                            ? 1u
	                            : 0u;
	memcpy(c->host.address, "10.0.0.1", 8u);
	c->host.address_len = 8u;
	c->host.port = 47000u;
	memcpy(c->seeds[0].address, "host.example", 12u);
	c->seeds[0].address_len = 12u;
	c->seeds[0].port = 47001u;
	c->seeds[0].transport = 1u;
	c->seeds[0].metric = 10u;
	c->n_seeds = 1u;
	memcpy(c->name, "alice", 5u);
	c->name_len = 5u;
	signing_as = host[0];
}

static void test_a_card_round_trips_and_holds(void)
{
	static fzn_contact_card_t c, back;
	static uint8_t bytes[FZN_CONTACT_CARD_MAX];
	size_t len = 0;

	card_of(&c);
	CHECK(fzn_contact_card_sign(&c, &SIGN) == FZN_CONTACT_CARD_OK
	              && fzn_contact_card_encode(&c, bytes, sizeof(bytes), &len) == FZN_CONTACT_CARD_OK
	              && fzn_contact_card_decode(bytes, len, &back) == FZN_CONTACT_CARD_OK
	              && back.n_seeds == 1u && back.seeds[0].port == 47001u
	              && back.seeds[0].metric == 10u && back.name_len == 5u
	              && memcmp(back.name, "alice", 5u) == 0
	              && memcmp(fzn_contact_device_key(&back.host), host, 32u) == 0
	              && fzn_contact_card_verify(&back, &SIGN, &member, 2000u) == FZN_CONTACT_CARD_OK,
	      "a signed card decodes to itself and holds");
	CHECK(fzn_contact_card_decode(bytes, len - 1u, &back) == FZN_CONTACT_CARD_ERR_SHAPE
	              && (bytes[len] = 0, fzn_contact_card_decode(bytes, len + 1u, &back))
	                         == FZN_CONTACT_CARD_ERR_SHAPE,
	      "a card a byte short or long decodes");
	bytes[1] ^= 1u;
	CHECK(fzn_contact_card_decode(bytes, len, &back) == FZN_CONTACT_CARD_ERR_SHAPE,
	      "another object's tag decodes as a card");
	bytes[1] ^= 1u;

	back.name[0] = 'b';
	CHECK(fzn_contact_card_verify(&back, &SIGN, &member, 2000u) == FZN_CONTACT_CARD_ERR_REFUSED,
	      "a card whose name was changed after signing held");
	back.name[0] = 'a';
	back.seeds[0].metric = 11u;
	CHECK(fzn_contact_card_verify(&back, &SIGN, &member, 2000u) == FZN_CONTACT_CARD_ERR_REFUSED,
	      "a card whose seed was changed after signing held");
	back.seeds[0].metric = 10u;

	/* SIGNED BY ANOTHER KEY: not the host it names. */
	card_of(&c);
	signing_as = other[0];
	CHECK(fzn_contact_card_sign(&c, &SIGN) == FZN_CONTACT_CARD_OK
	              && fzn_contact_card_verify(&c, &SIGN, &member, 2000u)
	                         == FZN_CONTACT_CARD_ERR_REFUSED,
	      "a card signed by a key other than its host's held");

	/* A HOST THE ROOT DID NOT MAKE A MEMBER. */
	card_of(&c);
	c.host.hop_count = 0u;
	CHECK(fzn_contact_card_sign(&c, &SIGN) == FZN_CONTACT_CARD_OK
	              && fzn_contact_card_verify(&c, &SIGN, &member, 2000u)
	                         == FZN_CONTACT_CARD_ERR_REFUSED,
	      "a card whose host has no chain from its owner held");

	card_of(&c);
	c.expires_at = 1500u;
	CHECK(fzn_contact_card_sign(&c, &SIGN) == FZN_CONTACT_CARD_OK
	              && fzn_contact_card_verify(&c, &SIGN, &member, 2000u)
	                         == FZN_CONTACT_CARD_ERR_EXPIRED
	              && fzn_contact_card_verify(&c, &SIGN, &member, 1400u) == FZN_CONTACT_CARD_OK,
	      "expiry is not read: past it held, or before it did not");
}

static void test_what_a_card_may_say(void)
{
	static fzn_contact_card_t c;

	card_of(&c);
	memcpy(c.name, "al ice", 6u);
	c.name_len = 6u;
	CHECK(fzn_contact_card_sign(&c, &SIGN) == FZN_CONTACT_CARD_ERR_MALFORMED,
	      "a name that is no contact name was signed");
	card_of(&c);
	c.name_len = 0u;
	CHECK(fzn_contact_card_sign(&c, &SIGN) == FZN_CONTACT_CARD_OK, "no name was refused");
	card_of(&c);
	c.seeds[0].port = 0u;
	CHECK(fzn_contact_card_sign(&c, &SIGN) == FZN_CONTACT_CARD_ERR_MALFORMED,
	      "a seed with no port was signed");
	card_of(&c);
	c.n_seeds = 5u;
	CHECK(fzn_contact_card_sign(&c, &SIGN) == FZN_CONTACT_CARD_ERR_MALFORMED,
	      "five seeds were signed");
	card_of(&c);
	c.host.port = 0u;
	c.host.address_len = 0u;
	c.n_seeds = 0u;
	CHECK(fzn_contact_card_sign(&c, &SIGN) == FZN_CONTACT_CARD_ERR_MALFORMED,
	      "a card with nowhere to reach its host was signed");
	c.n_seeds = 1u;
	CHECK(fzn_contact_card_sign(&c, &SIGN) == FZN_CONTACT_CARD_OK,
	      "a host with no address but a seed was refused");
}

static void test_a_card_as_text(void)
{
	static fzn_contact_card_t c, back;
	static uint8_t bytes[FZN_CONTACT_CARD_MAX], again[FZN_CONTACT_CARD_MAX];
	static char text[FZN_CONTACT_CARD_TEXT_MAX + 2u];
	size_t len = 0, back_len = 0, n;

	card_of(&c);
	CHECK(fzn_contact_card_sign(&c, &SIGN) == FZN_CONTACT_CARD_OK
	              && fzn_contact_card_encode(&c, bytes, sizeof(bytes), &len) == FZN_CONTACT_CARD_OK
	              && fzn_contact_card_text(bytes, len, text, sizeof(text)) == FZN_CONTACT_CARD_OK
	              && strncmp(text, "FZC1:", 5u) == 0,
	      "fixture: a card as text");
	n = strlen(text);
	CHECK(fzn_contact_card_from_text(text, n, again, sizeof(again), &back_len)
	                      == FZN_CONTACT_CARD_OK
	              && back_len == len && memcmp(again, bytes, len) == 0
	              && fzn_contact_card_decode(again, back_len, &back) == FZN_CONTACT_CARD_OK,
	      "text did not read back to the same card");
	text[n] = 'A';
	text[n + 1u] = '\0';
	/* A CHARACTER TOO MANY is either refused or names other bytes -- a
	 * byte longer, which no card decodes -- never this card again. */
	CHECK(fzn_contact_card_from_text(text, n + 1u, again, sizeof(again), &back_len)
	                      != FZN_CONTACT_CARD_OK
	              || (back_len != len
	                  && fzn_contact_card_decode(again, back_len, &back)
	                             == FZN_CONTACT_CARD_ERR_SHAPE),
	      "a character too many read back as the same card: two strings for one");
	text[n] = '\0';
	text[6] = (char)(text[6] - 'A' + 'a');
	CHECK(fzn_contact_card_from_text(text, n, again, sizeof(again), &back_len)
	              == FZN_CONTACT_CARD_ERR_SHAPE,
	      "lowercase was read");
	text[6] = (char)(text[6] - 'a' + 'A');
	text[1] = 'X';
	CHECK(fzn_contact_card_from_text(text, n, again, sizeof(again), &back_len)
	              == FZN_CONTACT_CARD_ERR_SHAPE,
	      "another prefix was read");
	text[1] = 'Z';
	/* THE LAST CHARACTER'S SPARE BITS: some must be set for this card's
	 * length, or the check has nothing to see. */
	if ((len * 8u) % 5u) {
		char *last = &text[n - 1u];

		*last = *last == '7' ? '6' : (char)(*last == 'Z' ? '2' : *last + 1);
		CHECK(fzn_contact_card_from_text(text, n, again, sizeof(again), &back_len)
		              == FZN_CONTACT_CARD_ERR_SHAPE,
		      "a last character with spare bits set was read");
	}
}

/* ONE STRING PER BYTE STRING, at the lengths where a character too many
 * adds no byte: 10, 11 and 13 bytes leave 0, 2 and 1 spare bits, so a
 * sixth-bit character appended decodes to the same bytes unless the length
 * is checked. */
static void test_a_character_too_many_at_every_remainder(void)
{
	static const size_t lens[] = { 10u, 11u, 13u };
	uint8_t bytes[16], back[32];
	char text[64];
	size_t i, n, back_len = 0;

	for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
		memset(bytes, 0x5c, sizeof(bytes));
		CHECK(fzn_contact_card_text(bytes, lens[i], text, sizeof(text)) == FZN_CONTACT_CARD_OK
		              && fzn_contact_card_from_text(text, strlen(text), back, sizeof(back),
		                                            &back_len)
		                         == FZN_CONTACT_CARD_OK
		              && back_len == lens[i],
		      "fixture: bytes as text and back");
		n = strlen(text);
		text[n] = 'A';
		text[n + 1u] = '\0';
		CHECK(fzn_contact_card_from_text(text, n + 1u, back, sizeof(back), &back_len)
		              == FZN_CONTACT_CARD_ERR_SHAPE,
		      "a character too many read: two strings for one byte string");
	}
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	CHECK(0, "deliberate");
	CHECK(failures == before + 1, "a failure counts");
	failures = before;
	checks -= 1;
}

int main(void)
{
	memset(owner, 0x11, sizeof(owner));
	memset(host, 0x22, sizeof(host));
	memset(other, 0x33, sizeof(other));
	memset(member.b, 0x44, sizeof(member.b));
	test_the_suite_can_tell_pass_from_fail();
	test_a_card_round_trips_and_holds();
	test_what_a_card_may_say();
	test_a_card_as_text();
	test_a_character_too_many_at_every_remainder();
	if (failures) {
		fprintf(stderr, "node contact_card_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("node contact_card_test: all %d checks passed\n", checks);
	return 0;
}
