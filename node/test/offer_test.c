/* offer_test -- join by request's discovery, sec 1288: a probe and an answer
 * written and read back; an answer never past its probe, the longest name
 * and code included; an answer to another probe, or carrying no invite,
 * refused; a probe with anything in its padding refused. */
#include "../offer.h"

#include <stdio.h>
#include <string.h>

static int failures, checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL offer_test.c:%d: %s\n", line, what);
	}
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static size_t code_of(char *out, size_t where_len)
{
	fzn_invite_t in;

	memset(&in, 0, sizeof(in));
	memset(in.host, 0x11, sizeof(in.host));
	memset(in.agree, 0x22, sizeof(in.agree));
	memset(in.secret, 0x33, sizeof(in.secret));
	memset(in.where, '9', where_len);
	memcpy(in.where, "10.0.0.2", where_len < 8u ? where_len : 8u);
	in.where_len = where_len;
	in.port = 7001u;
	return fzn_invite_text(&in, out, FZN_INVITE_TEXT_MAX);
}

int main(void)
{
	static const uint8_t NONCE[FZN_OFFER_NONCE_LEN] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	uint8_t probe[FZN_OFFER_PROBE_LEN], nonce[FZN_OFFER_NONCE_LEN], answer[FZN_OFFER_PROBE_LEN];
	fzn_offer_t o, back;
	size_t n;

	fzn_offer_probe(NONCE, probe);
	CHECK(probe[0] == FZN_OFFER_PROBE_MARK && fzn_offer_probe_read(probe, sizeof(probe), nonce)
	              && !memcmp(nonce, NONCE, sizeof(nonce)),
	      "a probe did not read back with its nonce");
	CHECK(!fzn_offer_probe_read(probe, sizeof(probe) - 1u, nonce), "a short probe was read");
	probe[300] = 1;
	CHECK(!fzn_offer_probe_read(probe, sizeof(probe), nonce), "a probe with something in its padding was read");

	memset(&o, 0, sizeof(o));
	memcpy(o.nonce, NONCE, sizeof(NONCE));
	memcpy(o.name, "the kitchen laptop", 18u);
	o.name_len = 18u;
	o.code_len = code_of(o.code, 8u);
	n = fzn_offer_answer(&o, answer, sizeof(answer));
	CHECK(n && answer[0] == FZN_OFFER_ANSWER_MARK && fzn_offer_answer_read(answer, n, NONCE, &back)
	              && back.name_len == 18u && !memcmp(back.name, o.name, 18u) && back.code_len == o.code_len
	              && !memcmp(back.code, o.code, o.code_len),
	      "an answer did not read back with its name and code");
	CHECK(!fzn_offer_answer_read(answer, n, (const uint8_t *)"otherone", &back),
	      "an answer to another probe was taken");
	CHECK(!fzn_offer_answer_read(answer, n - 1u, NONCE, &back), "an answer cut short was taken");
	/* THE LONGEST NAME AND CODE stay within the probe: no amplification. */
	memset(o.name, 'n', FZN_OFFER_NAME_MAX);
	o.name_len = FZN_OFFER_NAME_MAX;
	o.code_len = code_of(o.code, FZN_INVITE_WHERE_MAX);
	n = fzn_offer_answer(&o, answer, sizeof(answer));
	CHECK(o.code_len && n && n <= FZN_OFFER_PROBE_LEN && fzn_offer_answer_read(answer, n, NONCE, &back),
	      "the longest answer was refused or ran past its probe");
	/* NOTHING THAT IS NOT AN INVITE, and no name past its bound. */
	memcpy(o.code, "FZI1:NOTACODE", 13u);
	o.code_len = 13u;
	CHECK(!fzn_offer_answer(&o, answer, sizeof(answer)), "an answer carrying no invite was written");
	o.code_len = code_of(o.code, 8u);
	o.name_len = FZN_OFFER_NAME_MAX + 1u;
	CHECK(!fzn_offer_answer(&o, answer, sizeof(answer)), "a name past its bound was written");
	o.name_len = 3u;
	memcpy(o.name, "a\nb", 3u);
	CHECK(!fzn_offer_answer(&o, answer, sizeof(answer)), "a name with a line break was written");
	{
		const int before = failures;

		CHECK(0, "deliberate");
		if (failures != before + 1) {
			printf("offer_test: the suite cannot fail\n");
			return 1;
		}
		failures = before;
	}
	if (failures) {
		printf("offer_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("offer_test: all %d checks passed\n", checks - 1);
	return 0;
}
