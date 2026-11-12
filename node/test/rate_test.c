/* rate_test -- `node/rate.h`, sec 1034: a value offered faster than its name's
 * window is coalesced, the newest standing, and handed back once a window;
 * the floor and the burst hold whatever is declared; a name's holding is said
 * once; a full table gives way. */
#include "../rate.h"

#include <stdio.h>
#include <string.h>

static int failures, checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (ok)
		return;
	failures++;
	fprintf(stderr, "  FAIL rate_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, what)

static unsigned dues;
static char last_value[FZN_RATE_VALUE_MAX + 1];
static unsigned long last_held;

static void on_due(void *ctx, const uint8_t *key, size_t key_len, const uint8_t *value,
                   size_t value_len, unsigned long held)
{
	(void)ctx;
	(void)key;
	(void)key_len;
	dues++;
	memcpy(last_value, value, value_len);
	last_value[value_len] = '\0';
	last_held = held;
}

static fzn_rate_verdict_t offer(fzn_rate_t *r, const char *key, const char *value,
                                uint64_t every_ms, uint64_t now_ms, int *first)
{
	return fzn_rate_offer(r, (const uint8_t *)key, strlen(key), (const uint8_t *)value,
	                      strlen(value), every_ms, now_ms, first);
}

/* A THOUSAND WRITES IN A SECOND: one passes, the rest are one held value, the
 * last; said once; handed back once its window has gone by. */
static void test_a_flood(void)
{
	static fzn_rate_slot_t slots[4];
	fzn_rate_t r;
	unsigned i, now_count = 0, firsts = 0;
	char v[16];

	fzn_rate_init(&r, slots, 4u);
	dues = 0;
	for (i = 0; i < 1000u; i++) {
		int first = 0;

		snprintf(v, sizeof(v), "%u", i);
		now_count += offer(&r, "lamp", v, 2000u, 10000u + i, &first) == FZN_RATE_NOW;
		firsts += (unsigned)first;
	}
	CHECK(now_count == 1u, "a flood passed more than its first value");
	CHECK(firsts == 1u, "a flood's holding was said other than once");
	CHECK(fzn_rate_due(&r, 11999u, on_due, NULL) == 0u && dues == 0u,
	      "a held value was handed back inside its window");
	CHECK(fzn_rate_due(&r, 12000u, on_due, NULL) == 1u && dues == 1u
	              && strcmp(last_value, "999") == 0 && last_held == 999u,
	      "the window's end did not hand back the newest value, once, with its count");
	CHECK(fzn_rate_due(&r, 20000u, on_due, NULL) == 0u, "a value was handed back twice");
	/* STILL FLOODING after the flush: held again, and not said again. */
	{
		int first = 1;

		CHECK(offer(&r, "lamp", "x", 2000u, 12500u, &first) == FZN_RATE_HELD && first == 0,
		      "a flood said again after a window's flush, before passing freely");
	}
	/* PASSING FREELY ONCE MORE: said again at the next holding. */
	CHECK(fzn_rate_due(&r, 14000u, on_due, NULL) == 1u, "the second window's value was lost");
	{
		int first = 0;

		CHECK(offer(&r, "lamp", "y", 2000u, 20000u, &first) == FZN_RATE_NOW,
		      "a write after a quiet window was held");
		CHECK(offer(&r, "lamp", "z", 2000u, 20001u, &first) == FZN_RATE_HELD && first == 1,
		      "a new flood after a free pass was not said");
	}
}

/* THE CEILINGS: a declared window of 0 held to the floor; many names at once
 * held to the burst, the rest handed back on later passes. */
static void test_ceilings(void)
{
	static fzn_rate_slot_t slots[FZN_RATE_BURST * 2u];
	fzn_rate_t r;
	unsigned i, now_count = 0;
	char key[16];

	fzn_rate_init(&r, slots, FZN_RATE_BURST * 2u);
	CHECK(offer(&r, "fast", "1", 0u, 5000u, NULL) == FZN_RATE_NOW
	              && offer(&r, "fast", "2", 0u, 5000u + FZN_RATE_FLOOR_MS - 1u, NULL)
	                         == FZN_RATE_HELD
	              && offer(&r, "fast", "3", 0u, 5000u + 2u * FZN_RATE_FLOOR_MS, NULL)
	                         == FZN_RATE_HELD,
	      "a window declared 0 was not held to the floor");
	fzn_rate_init(&r, slots, FZN_RATE_BURST * 2u);
	for (i = 0; i < FZN_RATE_BURST * 2u; i++) {
		snprintf(key, sizeof(key), "k%u", i);
		now_count += offer(&r, key, "v", 1000u, 9000u, NULL) == FZN_RATE_NOW;
	}
	CHECK(now_count == FZN_RATE_BURST, "many names at once passed more than the burst");
	dues = 0;
	CHECK(fzn_rate_due(&r, 9500u, on_due, NULL) == 0u,
	      "the names held by the burst were handed back while it was spent");
	CHECK(fzn_rate_due(&r, 9000u + FZN_RATE_BURST_MS, on_due, NULL) == FZN_RATE_BURST,
	      "the names held by the burst were not handed back on the next burst");
}

/* MALFORMED, AND A FULL TABLE: refused; the least recently offered name with
 * nothing held gives way. */
static void test_room(void)
{
	static fzn_rate_slot_t slots[2];
	fzn_rate_t r;
	uint8_t big[FZN_RATE_VALUE_MAX + 1];

	memset(big, 'a', sizeof(big));
	fzn_rate_init(&r, slots, 2u);
	CHECK(fzn_rate_offer(&r, (const uint8_t *)"k", 1u, big, sizeof(big), 1000u, 1u, NULL)
	              == FZN_RATE_REFUSED,
	      "a value past its room was taken");
	CHECK(offer(&r, "a", "1", 1000u, 100u, NULL) == FZN_RATE_NOW
	              && offer(&r, "b", "1", 1000u, 200u, NULL) == FZN_RATE_NOW
	              && offer(&r, "b", "2", 1000u, 300u, NULL) == FZN_RATE_HELD
	              && offer(&r, "c", "1", 1000u, 400u, NULL) == FZN_RATE_NOW,
	      "a full table did not give way the name with nothing held");
	CHECK(offer(&r, "d", "1", 1000u, 500u, NULL) == FZN_RATE_NOW
	              && offer(&r, "b", "3", 1000u, 600u, NULL) == FZN_RATE_HELD,
	      "a name with a value held was given way");
}

int main(void)
{
	test_a_flood();
	test_ceilings();
	test_room();
	printf("rate_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
