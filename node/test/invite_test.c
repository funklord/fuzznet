/* node invite_test -- an invite, sec 896: its text, the exchange's two boxes'
 * contents, and what a host keeps of it.
 */

#include "../invite.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
static int checks;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL invite_test.c:%d: %s\n", __LINE__, what);       \
		}                                                                              \
	} while (0)

static void a_invite(fzn_invite_t *in)
{
	memset(in, 0, sizeof(*in));
	memset(in->host, 0x11, sizeof(in->host));
	memset(in->agree, 0x22, sizeof(in->agree));
	memset(in->secret, 0x33, sizeof(in->secret));
	memcpy(in->where, "192.168.1.20", 12u);
	in->where_len = 12u;
	in->port = 7001u;
}

static void test_text(void)
{
	fzn_invite_t in, back;
	char text[FZN_INVITE_TEXT_MAX], other[FZN_INVITE_TEXT_MAX];
	size_t n, i;

	a_invite(&in);
	n = fzn_invite_text(&in, text, sizeof(text));
	CHECK(n > FZN_INVITE_TEXT_PREFIX_LEN && n == strlen(text), "an invite writes as text");
	CHECK(memcmp(text, "FZI1:", 5u) == 0, "under its prefix");
	for (i = 0; i < n; i++)
		if (!strchr("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567:FI1", text[i]))
			break;
	CHECK(i == n, "in what a QR code's alphanumeric mode takes");
	CHECK(fzn_invite_parse(text, n, &back) && memcmp(&in, &back, sizeof(in)) == 0,
	      "and reads back whole");
	printf("invite_test: a text of %zu characters for a 12 byte address\n", n);

	/* THE LONGEST. */
	memset(in.where, 'a', FZN_INVITE_WHERE_MAX);
	in.where_len = FZN_INVITE_WHERE_MAX;
	n = fzn_invite_text(&in, text, sizeof(text));
	CHECK(n && n + 1u <= FZN_INVITE_TEXT_MAX && fzn_invite_parse(text, n, &back)
	              && back.where_len == FZN_INVITE_WHERE_MAX,
	      "the longest address fits its bound");

	/* REFUSED TO WRITE. */
	a_invite(&in);
	in.port = 0;
	CHECK(fzn_invite_text(&in, text, sizeof(text)) == 0, "no port, no invite");
	a_invite(&in);
	in.where[0] = ' ';
	CHECK(fzn_invite_text(&in, text, sizeof(text)) == 0, "an address out of shape");
	a_invite(&in);
	in.where_len = 0;
	CHECK(fzn_invite_text(&in, text, sizeof(text)) == 0, "no address");

	/* REFUSED TO READ. */
	a_invite(&in);
	n = fzn_invite_text(&in, text, sizeof(text));
	CHECK(!fzn_invite_parse("FZN4:AAAA", 9u, &back), "a card is no invite");
	CHECK(!fzn_invite_parse(text, FZN_INVITE_TEXT_PREFIX_LEN, &back), "the prefix alone");
	CHECK(!fzn_invite_parse(text, 40u, &back), "a text cut short");
	memcpy(other, text, n + 1u);
	other[20] = 'a';
	CHECK(!fzn_invite_parse(other, n, &back), "a letter out of the alphabet");
	other[20] = '\0';
	CHECK(!fzn_invite_parse(other, n, &back), "a NUL inside");
	memcpy(other, text, n + 1u);
	other[n] = 'A';
	other[n + 1u] = 'A';
	CHECK(!fzn_invite_parse(other, n + 2u, &back) || back.where_len == in.where_len + 1u,
	      "a text grown reads as nothing, or as its own address");
}

static void test_exchange(void)
{
	uint8_t secret[FZN_INVITE_SECRET_LEN], wrong[FZN_INVITE_SECRET_LEN];
	uint8_t record[FZN_PREKEY_LEN_TOTAL], ask[FZN_INVITE_ASK_LEN];
	uint8_t answer[FZN_INVITE_ANSWER_MAX];
	static uint8_t card[2000];
	static fzn_invite_card_t got;
	size_t i, n;

	memset(secret, 0x55, sizeof(secret));
	memset(wrong, 0x56, sizeof(wrong));
	memset(record, 0x66, sizeof(record));
	for (i = 0; i < sizeof(card); i++)
		card[i] = (uint8_t)(i * 7u);
	fzn_invite_ask(secret, record, ask);
	CHECK(fzn_invite_kind(ask, sizeof(ask)) == 1, "an ask is one");
	CHECK(fzn_invite_kind(ask, sizeof(ask) - 1u) == 0, "cut short it is nothing");
	CHECK(fzn_invite_kind((const uint8_t *)"\x01\x02\x03\x04", 4u) == 0, "nor is anything else");

	n = fzn_invite_answer(secret, card, sizeof(card), 2u, answer);
	CHECK(n == FZN_INVITE_ANSWER_HEAD + 200u && fzn_invite_kind(answer, n) == 2,
	      "the last part is what is left");
	CHECK(fzn_invite_answer(secret, card, sizeof(card), 3u, answer) == 0, "and none follows");
	CHECK(!fzn_invite_card_take(&got, wrong, answer, n), "another invite's answer is not taken");
	CHECK(got.parts == 0u, "and changes nothing");
	CHECK(!fzn_invite_card_take(&got, secret, answer, n), "out of order, it waits");
	n = fzn_invite_answer(secret, card, sizeof(card), 0u, answer);
	CHECK(!fzn_invite_card_take(&got, secret, answer, n), "for the rest");
	CHECK(!fzn_invite_card_take(&got, secret, answer, n), "and a part sent twice is one part");
	n = fzn_invite_answer(secret, card, sizeof(card), 1u, answer);
	CHECK(fzn_invite_card_take(&got, secret, answer, n) && got.len == sizeof(card)
	              && memcmp(got.bytes, card, sizeof(card)) == 0,
	      "whole, in any order");

	memset(&got, 0, sizeof(got));
	n = fzn_invite_answer(secret, card, 100u, 0u, answer);
	CHECK(fzn_invite_card_take(&got, secret, answer, n) && got.len == 100u,
	      "a small card is one part");
	/* A PART PAST THE ROOM, a stranger's numbers. */
	memset(&got, 0, sizeof(got));
	n = fzn_invite_answer(secret, card, 1000u, 0u, answer);
	answer[FZN_INVITE_MARK_LEN + FZN_INVITE_SECRET_LEN] = 200u;
	answer[FZN_INVITE_MARK_LEN + FZN_INVITE_SECRET_LEN + 1u] = 255u;
	CHECK(!fzn_invite_card_take(&got, secret, answer, n) && got.parts == 0u,
	      "a part past the room is refused");
	answer[FZN_INVITE_MARK_LEN + FZN_INVITE_SECRET_LEN] = 3u;
	answer[FZN_INVITE_MARK_LEN + FZN_INVITE_SECRET_LEN + 1u] = 2u;
	CHECK(!fzn_invite_card_take(&got, secret, answer, n), "a part past its own count too");
	answer[FZN_INVITE_MARK_LEN + FZN_INVITE_SECRET_LEN] = 0u;
	answer[FZN_INVITE_MARK_LEN + FZN_INVITE_SECRET_LEN + 1u] = 0u;
	CHECK(!fzn_invite_card_take(&got, secret, answer, n), "no parts at all too");
}

static void test_table(void)
{
	static fzn_invites_t t;
	uint8_t s[FZN_INVITE_SECRET_LEN], dev[FZN_PUBKEY_LEN], other[FZN_PUBKEY_LEN];
	fzn_invite_open_t *r;
	size_t i;

	memset(s, 1, sizeof(s));
	memset(dev, 2, sizeof(dev));
	memset(other, 3, sizeof(other));
	r = fzn_invites_add(&t, s, 1, 0, 100u, 700u);
	CHECK(r && r->delegable && fzn_invites_live(&t, 100u) == 1u, "an invite is open");
	CHECK(fzn_invites_find(&t, s, dev, 699u) == r, "found within its life");
	CHECK(fzn_invites_find(&t, s, dev, 700u) == NULL, "and not past it");
	r->claimed = 1;
	memcpy(r->device, dev, sizeof(dev));
	CHECK(fzn_invites_find(&t, s, dev, 900u) == r, "its device may ask again, even late");
	CHECK(fzn_invites_find(&t, s, other, 200u) == NULL, "ONE USE: another device may not");
	CHECK(fzn_invites_live(&t, 200u) == 0u, "and it is no longer open");

	memset(s, 9, sizeof(s));
	CHECK(fzn_invites_find(&t, s, dev, 200u) == NULL, "a secret nobody issued");

	/* AS MANY AS ARE MADE, sec 903. */
	for (i = 0; i < 5000u; i++) {
		s[0] = (uint8_t)i;
		s[1] = (uint8_t)(i >> 8);
		s[2] = 0xeeu;
		CHECK(fzn_invites_add(&t, s, 0, 0, 100u, 700u) != NULL, "room for every invite");
	}
	s[0] = 7u;
	s[1] = 0u;
	CHECK(fzn_invites_find(&t, s, dev, 200u) != NULL, "and the first still found past a growth");
	CHECK(fzn_invites_live(&t, 200u) == 5000u, "all of them open");
	{
		size_t cap = t.cap;

		s[2] = 0xddu;
		CHECK(fzn_invites_add(&t, s, 0, 0, 800u, 900u) != NULL && t.cap == cap,
		      "a lapsed one gives way before the table grows");
	}
	CHECK(fzn_invites_clear(&t, 800u) == 1u && fzn_invites_live(&t, 800u) == 0u
	              && fzn_invites_find(&t, s, dev, 800u) == NULL,
	      "ended, nothing answers");
}

/* A DEVICE WAITING ON A PERSON. */
static void test_confirmed(void)
{
	static fzn_invites_t t;
	uint8_t s[FZN_INVITE_SECRET_LEN], dev[FZN_PUBKEY_LEN], other[FZN_PUBKEY_LEN];
	fzn_invite_open_t *r;

	memset(s, 4, sizeof(s));
	memset(dev, 5, sizeof(dev));
	memset(other, 6, sizeof(other));
	r = fzn_invites_add(&t, s, 1, 1, 100u, 700u);
	CHECK(r && r->confirm && !r->approved, "a confirmed invite is open");
	CHECK(fzn_invites_waiting(&t, dev, 100u) == NULL, "and nobody waits on it yet");
	r->asked = 1;
	memcpy(r->device, dev, sizeof(dev));
	CHECK(fzn_invites_waiting(&t, dev, 200u) == r, "a device that asked waits");
	CHECK(fzn_invites_waiting(&t, other, 200u) == NULL, "no other does");
	CHECK(fzn_invites_find(&t, s, dev, 200u) == r, "it may go on asking");
	CHECK(fzn_invites_find(&t, s, other, 200u) == NULL, "and another may not ask past it");
	CHECK(fzn_invites_waiting(&t, dev, 700u) == NULL && fzn_invites_find(&t, s, dev, 700u) == NULL,
	      "a wait ends with the invite's life");
}

int main(void)
{
	test_confirmed();
	test_text();
	test_exchange();
	test_table();
	printf("invite_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
