/* rate_test -- `node/rate.h`, sec 1034: a name passes a few values at once and
 * then one a window, the rest coalesced, the newest standing and handed back as
 * it earns a pass;
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

/* A THOUSAND WRITES IN A SECOND: the name's few passes go, the rest are one held
 * value, the last; said once; handed back as the name earns its next pass. */
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
	CHECK(now_count == FZN_RATE_NAME_BURST, "a flood passed other than its name's few passes");
	CHECK(firsts == 1u, "a flood's holding was said other than once");
	CHECK(fzn_rate_due(&r, 11999u, NULL, 0u, on_due, NULL) == 0u && dues == 0u,
	      "a held value was handed back before its name earned a pass");
	CHECK(fzn_rate_due(&r, 12000u, NULL, 0u, on_due, NULL) == 1u && dues == 1u
	              && strcmp(last_value, "999") == 0
	              && last_held == 1000u - FZN_RATE_NAME_BURST,
	      "a window's pass did not hand back the newest value, once, with its count");
	CHECK(fzn_rate_due(&r, 20000u, NULL, 0u, on_due, NULL) == 0u, "a value was handed back twice");
	/* STILL FLOODING after the hand-back: held again, and not said again. */
	{
		int first = 1;

		CHECK(offer(&r, "lamp", "x", 2000u, 12500u, &first) == FZN_RATE_HELD && first == 0,
		      "a flood said again after a hand-back, before passing freely");
	}
	CHECK(fzn_rate_due(&r, 14000u, NULL, 0u, on_due, NULL) == 1u,
	      "the next window's value was lost");
	/* QUIET A WHILE: passes earned back, one a window, and a new flood said. */
	{
		int first = 0;

		CHECK(offer(&r, "lamp", "y", 2000u, 20000u, &first) == FZN_RATE_NOW
		              && offer(&r, "lamp", "y", 2000u, 20000u, &first) == FZN_RATE_NOW
		              && offer(&r, "lamp", "y", 2000u, 20000u, &first) == FZN_RATE_NOW,
		      "three quiet windows did not earn three passes");
		CHECK(offer(&r, "lamp", "z", 2000u, 20001u, &first) == FZN_RATE_HELD && first == 1,
		      "a name past its earned passes was not held, or not said");
	}
}

/* THE CEILINGS: a window declared 0 earns at the floor; many names at once
 * are held to the burst, the rest handed back on later passes. */
static void test_ceilings(void)
{
	static fzn_rate_slot_t slots[FZN_RATE_BURST * 2u];
	fzn_rate_t r;
	unsigned i, now_count = 0;
	char key[16];

	fzn_rate_init(&r, slots, FZN_RATE_BURST * 2u);
	for (i = 0; i < FZN_RATE_NAME_BURST; i++)
		(void)offer(&r, "fast", "1", 0u, 5000u, NULL);
	CHECK(offer(&r, "fast", "2", 0u, 5000u, NULL) == FZN_RATE_HELD
	              && fzn_rate_due(&r, 5000u + FZN_RATE_FLOOR_MS - 1u, NULL, 0u, NULL, NULL) == 0u
	              && fzn_rate_due(&r, 5000u + FZN_RATE_FLOOR_MS, NULL, 0u, NULL, NULL) == 1u,
	      "a window declared 0 did not earn its passes at the floor");
	fzn_rate_init(&r, slots, FZN_RATE_BURST * 2u);
	for (i = 0; i < FZN_RATE_BURST * 2u; i++) {
		snprintf(key, sizeof(key), "k%u", i);
		now_count += offer(&r, key, "v", 1000u, 9000u, NULL) == FZN_RATE_NOW;
	}
	CHECK(now_count == FZN_RATE_BURST, "many names at once passed more than the burst");
	dues = 0;
	CHECK(fzn_rate_due(&r, 9500u, NULL, 0u, on_due, NULL) == 0u,
	      "the names held by the burst were handed back while it was spent");
	CHECK(fzn_rate_due(&r, 9000u + FZN_RATE_BURST_MS, NULL, 0u, on_due, NULL) == FZN_RATE_BURST,
	      "the names held by the burst were not handed back on the next burst");
}

/* MALFORMED, AND A FULL TABLE: refused; the least recently offered name with
 * nothing held gives way. */
static void test_room(void)
{
	static fzn_rate_slot_t slots[2];
	fzn_rate_t r;
	uint8_t big[FZN_RATE_VALUE_MAX + 1];
	unsigned i;

	memset(big, 'a', sizeof(big));
	fzn_rate_init(&r, slots, 2u);
	CHECK(fzn_rate_offer(&r, (const uint8_t *)"k", 1u, big, sizeof(big), 1000u, 1u, NULL)
	              == FZN_RATE_REFUSED,
	      "a value past its room was taken");
	(void)offer(&r, "a", "1", 1000u, 100u, NULL);
	for (i = 0; i < FZN_RATE_NAME_BURST; i++)
		(void)offer(&r, "b", "1", 1000u, 200u, NULL);
	CHECK(offer(&r, "b", "2", 1000u, 300u, NULL) == FZN_RATE_HELD
	              && offer(&r, "c", "1", 1000u, 400u, NULL) == FZN_RATE_NOW,
	      "a full table did not give way the name with nothing held");
	CHECK(offer(&r, "d", "1", 1000u, 500u, NULL) == FZN_RATE_NOW
	              && offer(&r, "b", "3", 1000u, 600u, NULL) == FZN_RATE_HELD,
	      "a name with a value held was given way");
}

/* ONE GATE, TWO KINDS: a pass for one kind's names leaves the other's held value
 * held, for its own pass -- not counted passed and lost. */
static void test_kinds(void)
{
	static fzn_rate_slot_t slots[4];
	fzn_rate_t r;
	unsigned i;

	fzn_rate_init(&r, slots, 4u);
	for (i = 0; i < FZN_RATE_NAME_BURST; i++) {
		(void)offer(&r, "object/lamp", "on", 1000u, 100u, NULL);
		(void)offer(&r, "setting/x", "1", 1000u, 100u, NULL);
	}
	(void)offer(&r, "object/lamp", "off", 1000u, 200u, NULL);
	(void)offer(&r, "setting/x", "2", 1000u, 200u, NULL);
	dues = 0;
	CHECK(fzn_rate_due(&r, 1100u, (const uint8_t *)"object/", 7u, on_due, NULL) == 1u
	              && dues == 1u && strcmp(last_value, "off") == 0,
	      "a kind's pass did not hand back its own held value");
	CHECK(fzn_rate_due(&r, 1300u, (const uint8_t *)"setting/", 8u, on_due, NULL) == 1u
	              && dues == 2u && strcmp(last_value, "2") == 0,
	      "another kind's pass lost the value it left held");
}

int main(void)
{
	test_a_flood();
	test_ceilings();
	test_room();
	test_kinds();
	printf("rate_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
