/* The chain memo -- sec 4.7c's one latency win, and sec 354.
 *
 * A CACHE IS A PLACE TO PUT A WRONG ANSWER, so this suite is mostly about what
 * it refuses. The property that matters is not that a hit is fast; it is that
 * a hit is never wrong, and the two ways it could be are a revocation landing
 * since the verdict and the chain expiring since the verdict. sec 4.7c names
 * the first and not the second.
 */

#include "../memo.h"

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
	fprintf(stderr, "  FAIL memo_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

static uint8_t ROOT[FZN_PUBKEY_LEN];
static uint8_t PEER[FZN_PUBKEY_LEN];
static uint8_t OTHER[FZN_PUBKEY_LEN];
static fzn_cap_id_t CAP;
static fzn_cap_id_t CAP2;

#define GEN  7u
#define NOW  1000u

static fzn_chain_t verdict_for(const uint8_t *grantee, const fzn_cap_id_t *cap,
                               uint64_t expires_at)
{
	fzn_chain_t v;

	memset(&v, 0, sizeof(v));
	memcpy(v.root, ROOT, sizeof(v.root));
	memcpy(v.grantee, grantee, FZN_PUBKEY_LEN);
	v.capability = *cap;
	v.hop_count = 1;
	v.expires_at = expires_at;
	return v;
}

int main(void)
{
	fzn_chain_memo_entry_t entries[4];
	fzn_chain_memo_t memo;
	fzn_chain_t v;

	memset(ROOT, 0xa0, sizeof(ROOT));
	memset(PEER, 0xb1, sizeof(PEER));
	memset(OTHER, 0xc2, sizeof(OTHER));
	memset(CAP.b, 0xd3, sizeof(CAP.b));
	memset(CAP2.b, 0xe4, sizeof(CAP2.b));

	CHECK(fzn_chain_memo_init(&memo, entries, 4) == FZN_CHAIN_OK,
	      "the memo would not initialise");

	/* A COLD MEMO NEVER HITS, and an entry left zero by init must not be
	 * mistaken for one recorded at generation zero. */
	CHECK(!fzn_chain_memo_allows(&memo, ROOT, PEER, &CAP, GEN, NOW),
	      "a cold memo hit");
	CHECK(!fzn_chain_memo_allows(&memo, ROOT, PEER, &CAP, 0, NOW),
	      "a generation of zero matched an empty slot");
	CHECK(memo.hits == 0 && memo.misses == 2, "the counters did not move");

	/* THE CONTROL: a recorded verdict hits at its own generation. Without
	 * it every refusal below is satisfied by a memo that never hits. */
	v = verdict_for(PEER, &CAP, FZN_NO_EXPIRY);
	CHECK(fzn_chain_memo_record(&memo, &v, GEN) == FZN_CHAIN_OK,
	      "an affirmative verdict would not record");
	CHECK(fzn_chain_memo_allows(&memo, ROOT, PEER, &CAP, GEN, NOW),
	      "a recorded verdict did not hit");
	CHECK(memo.hits == 1, "the hit was not counted");
	CHECK(fzn_chain_memo_live(&memo, GEN) == 1, "the entry is not live");

	/* A REVOCATION LANDING INVALIDATES EVERYTHING AT ONCE, which is what
	 * the generation is for. */
	CHECK(!fzn_chain_memo_allows(&memo, ROOT, PEER, &CAP, GEN + 1u, NOW),
	      "a verdict survived a revocation landing");
	CHECK(fzn_chain_memo_live(&memo, GEN + 1u) == 0,
	      "the table did not go stale with the generation");
	/* And the old generation still hits, so the miss above is about the
	 * generation and not about the entry having been destroyed. */
	CHECK(fzn_chain_memo_allows(&memo, ROOT, PEER, &CAP, GEN, NOW),
	      "the entry was destroyed rather than made stale");

	/* A DIFFERENT TRIPLE IS A DIFFERENT QUESTION. */
	CHECK(!fzn_chain_memo_allows(&memo, ROOT, OTHER, &CAP, GEN, NOW),
	      "another peer hit this peer's verdict");
	CHECK(!fzn_chain_memo_allows(&memo, ROOT, PEER, &CAP2, GEN, NOW),
	      "another capability hit this capability's verdict");
	CHECK(!fzn_chain_memo_allows(&memo, PEER, PEER, &CAP, GEN, NOW),
	      "another root hit this root's verdict");

	/* THE HALF sec 4.7c DOES NOT NAME: a verdict is a function of `now`
	 * too, so a chain that has expired since it was verified must not hit
	 * -- and no revocation need ever land for that to happen. */
	{
		fzn_chain_memo_entry_t e2[2];
		fzn_chain_memo_t m2;

		fzn_chain_memo_init(&m2, e2, 2);
		v = verdict_for(PEER, &CAP, NOW + 10u);
		CHECK(fzn_chain_memo_record(&m2, &v, GEN) == FZN_CHAIN_OK,
		      "an expiring verdict would not record");
		/* The control: before the expiry, it hits. */
		CHECK(fzn_chain_memo_allows(&m2, ROOT, PEER, &CAP, GEN, NOW),
		      "a live chain did not hit");
		CHECK(fzn_chain_memo_allows(&m2, ROOT, PEER, &CAP, GEN,
		                            NOW + 9u),
		      "a chain one second from expiry did not hit");
		/* At the expiry, and past it. */
		CHECK(!fzn_chain_memo_allows(&m2, ROOT, PEER, &CAP, GEN,
		                             NOW + 10u),
		      "an expired chain hit AT its expiry -- the generation "
		      "alone cannot see this");
		CHECK(!fzn_chain_memo_allows(&m2, ROOT, PEER, &CAP, GEN,
		                             NOW + 1000u),
		      "an expired chain hit past its expiry");
	}

	/* A FULL MEMO OVERWRITES RATHER THAN REFUSING: a cache that stops
	 * caching when it fills stops working when it is busiest. */
	{
		fzn_chain_memo_entry_t e3[2];
		fzn_chain_memo_t m3;
		uint8_t who[FZN_PUBKEY_LEN];
		size_t i;

		fzn_chain_memo_init(&m3, e3, 2);
		for (i = 0; i < 5; i++) {
			memset(who, (int)(0x10u + i), sizeof(who));
			v = verdict_for(who, &CAP, FZN_NO_EXPIRY);
			CHECK(fzn_chain_memo_record(&m3, &v, GEN)
			          == FZN_CHAIN_OK,
			      "a full memo refused to record");
		}
		CHECK(fzn_chain_memo_live(&m3, GEN) == 2,
		      "a two-slot memo holds %u entries",
		      (unsigned)fzn_chain_memo_live(&m3, GEN));
		/* The most recent survived; the oldest did not. */
		memset(who, 0x14, sizeof(who));
		CHECK(fzn_chain_memo_allows(&m3, ROOT, who, &CAP, GEN, NOW),
		      "the newest entry was evicted");
		memset(who, 0x10, sizeof(who));
		CHECK(!fzn_chain_memo_allows(&m3, ROOT, who, &CAP, GEN, NOW),
		      "the oldest entry survived a full memo");
	}

	/* Recording the same triple twice refreshes rather than filling. */
	{
		fzn_chain_memo_entry_t e4[2];
		fzn_chain_memo_t m4;

		fzn_chain_memo_init(&m4, e4, 2);
		v = verdict_for(PEER, &CAP, FZN_NO_EXPIRY);
		fzn_chain_memo_record(&m4, &v, GEN);
		fzn_chain_memo_record(&m4, &v, GEN);
		fzn_chain_memo_record(&m4, &v, GEN);
		CHECK(fzn_chain_memo_live(&m4, GEN) == 1,
		      "one triple recorded three times took %u slots",
		      (unsigned)fzn_chain_memo_live(&m4, GEN));
	}

	/* A zero capacity is legal and never hits -- the honest shape for a
	 * consumer that wants the code path without the memory. */
	{
		fzn_chain_memo_t m5;

		CHECK(fzn_chain_memo_init(&m5, NULL, 0) == FZN_CHAIN_OK,
		      "a zero-capacity memo was an error");
		v = verdict_for(PEER, &CAP, FZN_NO_EXPIRY);
		CHECK(fzn_chain_memo_record(&m5, &v, GEN) == FZN_CHAIN_OK,
		      "recording into a zero-capacity memo was an error");
		CHECK(!fzn_chain_memo_allows(&m5, ROOT, PEER, &CAP, GEN, NOW),
		      "a zero-capacity memo hit");
	}

	/* Nulls and a generation of zero are refused rather than crashing. */
	CHECK(fzn_chain_memo_record(&memo, &v, 0) == FZN_CHAIN_ERR_MALFORMED,
	      "a generation of zero recorded");
	CHECK(fzn_chain_memo_record(NULL, &v, GEN) == FZN_CHAIN_ERR_MALFORMED,
	      "a null memo recorded");
	CHECK(fzn_chain_memo_record(&memo, NULL, GEN) == FZN_CHAIN_ERR_MALFORMED,
	      "a null verdict recorded");
	CHECK(!fzn_chain_memo_allows(NULL, ROOT, PEER, &CAP, GEN, NOW),
	      "a null memo hit");
	CHECK(fzn_chain_memo_init(NULL, entries, 4) == FZN_CHAIN_ERR_MALFORMED,
	      "a null memo initialised");

	printf("memo_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
