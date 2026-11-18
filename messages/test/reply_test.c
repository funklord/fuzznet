/* reply_test -- a line about another line, sec 1282: a reply and a
 * reaction written with the id of the line they name, read back, and every
 * spelling but the one refused, so an ordinary line is never taken for
 * either. */
#include "../reply.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL reply_test.c:%d: %s\n", line, what);
	}
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

#define ID "00112233445566778899aabbccddeeff"

static const uint8_t THE_ID[FZN_MESSAGE_ID_LEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	                                                 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

static int is_reply(const char *text)
{
	uint8_t id[FZN_MESSAGE_ID_LEN];
	size_t at = 0;

	return fzn_message_reply_parse(text, strlen(text), id, &at);
}

static int is_reaction(const char *text)
{
	uint8_t id[FZN_MESSAGE_ID_LEN];
	size_t at = 0, n = 0;

	return fzn_message_reaction_parse(text, strlen(text), id, &at, &n);
}

static void test_a_reply(void)
{
	char out[FZN_MESSAGE_TEXT_MAX + 1u];
	uint8_t id[FZN_MESSAGE_ID_LEN];
	size_t n, at = 0;

	n = fzn_message_reply_write(THE_ID, "see you there", 13u, out, sizeof(out));
	CHECK(n == FZN_MESSAGE_REPLY_HEAD_LEN + 13u && !strcmp(out, "fzn:reply/" ID " see you there"),
	      "a reply was not written as fzn:reply/ID TEXT");
	CHECK(fzn_message_reply_parse(out, n, id, &at) && !memcmp(id, THE_ID, sizeof(id)) && at == FZN_MESSAGE_REPLY_HEAD_LEN
	              && !strcmp(out + at, "see you there"),
	      "a reply did not read back with its id and its text");
	CHECK(!fzn_message_reply_write(THE_ID, "", 0u, out, sizeof(out)), "a reply of no text was written");
	CHECK(!fzn_message_reply_write(THE_ID, "see you there", 13u, out, FZN_MESSAGE_REPLY_HEAD_LEN + 13u),
	      "a reply was written past its room");
	CHECK(fzn_message_reply_write(THE_ID, "see you there", 13u, out, FZN_MESSAGE_REPLY_HEAD_LEN + 14u) == FZN_MESSAGE_REPLY_HEAD_LEN + 13u,
	      "a reply that fits exactly was refused");
	/* A STICKER IN REPLY is a reply whose text is the reference. */
	CHECK(is_reply("fzn:reply/" ID " fzn:sticker/aa/bb/1/2"), "a sticker sent in reply was not a reply");
}

static void test_what_a_reply_is_not(void)
{
	static const char *const NOT[] = {
		"fzn:reply/" ID,                                         /* no text */
		"fzn:reply/" ID " ",                                     /* a space, nothing after */
		"fzn:reply/" ID "x hello",                               /* no space after the id */
		"fzn:reply/00112233445566778899AABBCCDDEEFF hello",      /* upper case */
		"fzn:reply/00112233445566778899aabbccddee hello",        /* short */
		"fzn:reply/g0112233445566778899aabbccddeeff hello",      /* not hex */
		"fzn:reply/",                                            /* nothing */
		"reply/" ID " hello",                                    /* no scheme */
		"Fzn:reply/" ID " hello",                                /* a scheme spelt otherwise */
		"hello fzn:reply/" ID " there",                          /* not at the start */
	};
	size_t i;

	for (i = 0; i < sizeof(NOT) / sizeof(NOT[0]); i++)
		CHECK(!is_reply(NOT[i]), NOT[i]);
}

static void test_a_reaction(void)
{
	char out[FZN_MESSAGE_TEXT_MAX + 1u], big[FZN_MESSAGE_REACTION_MAX + 2u];
	uint8_t id[FZN_MESSAGE_ID_LEN];
	size_t n, at = 0, r = 0;

	n = fzn_message_reaction_write(THE_ID, "\xf0\x9f\x91\x8d", 4u, out, sizeof(out));
	CHECK(n && !strcmp(out, "fzn:react/" ID " \xf0\x9f\x91\x8d"), "a reaction was not written as fzn:react/ID R");
	CHECK(fzn_message_reaction_parse(out, n, id, &at, &r) && !memcmp(id, THE_ID, sizeof(id)) && r == 4u
	              && !memcmp(out + at, "\xf0\x9f\x91\x8d", 4u),
	      "a reaction did not read back with its id and itself");
	/* TAKEN BACK: no reaction at all. */
	n = fzn_message_reaction_write(THE_ID, NULL, 0u, out, sizeof(out));
	CHECK(n && !strcmp(out, "fzn:react/" ID) && fzn_message_reaction_parse(out, n, id, &at, &r) && r == 0u,
	      "a reaction taken back was not written as fzn:react/ID and read as none");
	memset(big, 'w', sizeof(big));
	CHECK(fzn_message_reaction_write(THE_ID, big, FZN_MESSAGE_REACTION_MAX, out, sizeof(out)),
	      "a reaction of the longest was refused");
	CHECK(!fzn_message_reaction_write(THE_ID, big, FZN_MESSAGE_REACTION_MAX + 1u, out, sizeof(out)),
	      "a reaction past the longest was written");
	CHECK(!fzn_message_reaction_write(THE_ID, "two words", 9u, out, sizeof(out)), "a reaction with a space was written");
	CHECK(!is_reaction("fzn:react/" ID " "), "a reaction of a space alone was read");
	CHECK(!is_reaction("fzn:react/" ID " two words"), "a reaction with a space was read");
	CHECK(!is_reaction("fzn:react/" ID "x"), "a reaction with no space after the id was read");
	CHECK(!is_reaction("fzn:reply/" ID " ok"), "a reply was read as a reaction");
	CHECK(!is_reply("fzn:react/" ID " ok"), "a reaction was read as a reply");
}

/* AN UNSEND, sec 1284: written and read back exactly, nothing after it. */
static void test_an_unsend(void)
{
	char out[FZN_MESSAGE_TEXT_MAX + 1u];
	uint8_t id[FZN_MESSAGE_ID_LEN];
	size_t n = fzn_message_unsend_write(THE_ID, out, sizeof(out));

	CHECK(n == FZN_MESSAGE_UNSEND_LEN && !strcmp(out, "fzn:unsend/" ID)
	              && fzn_message_unsend_parse(out, n, id) && !memcmp(id, THE_ID, sizeof(id)),
	      "an unsend was not written as fzn:unsend/ID and read back");
	CHECK(!fzn_message_unsend_write(THE_ID, out, FZN_MESSAGE_UNSEND_LEN), "an unsend was written past its room");
	CHECK(!fzn_message_unsend_parse("fzn:unsend/" ID " ", n + 1u, id), "an unsend with more after it was read");
	CHECK(!fzn_message_unsend_parse("fzn:react/" ID, n - 1u, id), "a reaction was read as an unsend");
	CHECK(!fzn_message_unsend_parse("fzn:unsend/00112233445566778899AABBCCDDEEFF", n, id),
	      "an unsend in upper case was read");
}

int main(void)
{
	test_a_reply();
	test_what_a_reply_is_not();
	test_a_reaction();
	test_an_unsend();
	/* THE SUITE CAN FAIL: a check that cannot fail proves nothing. */
	{
		const int before = failures;

		CHECK(0, "deliberate");
		if (failures != before + 1) {
			printf("reply_test: the suite cannot fail\n");
			return 1;
		}
		failures = before;
	}
	if (failures) {
		printf("reply_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("reply_test: all %d checks passed\n", checks - 1);
	return 0;
}
