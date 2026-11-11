/* reach_test -- `node/reach.h`, sec 1036: a host's candidate pairs, and the one
 * rule that chooses among them, holding each order the readers it replaces kept
 * -- the contact round's, `session_ask`'s -- and what lapses, ties and a full
 * table do. */
#include "../reach.h"

#include <stdio.h>
#include <string.h>

static int failures, checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (ok)
		return;
	failures++;
	fprintf(stderr, "  FAIL reach_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, what)

static fzn_udp_addr_t at(unsigned char tag)
{
	fzn_udp_addr_t a;

	memset(&a, 0, sizeof(a));
	a.storage[0] = tag;
	a.len = 16u;
	return a;
}

static int picks(const fzn_reach_t *r, const uint8_t *host, uint64_t now, unsigned char tag,
                 fzn_reach_local_t local)
{
	fzn_reach_pair_t p;

	return fzn_reach_best(r, host, now, &p) && p.remote.storage[0] == tag && p.local == local;
}

/* THE CONTACT ROUND'S ORDER, sec 697 and 698: a hello, else an introduction, else
 * the advertised address -- and each as its hold lapses. */
static void test_contact_order(void)
{
	static fzn_reach_pair_t pairs[8];
	fzn_reach_t r;
	uint8_t b[FZN_PUBKEY_LEN];
	fzn_udp_addr_t adv = at(1), intro = at(2), hello = at(3);

	memset(b, 0xbb, sizeof(b));
	fzn_reach_init(&r, pairs, 8u);
	CHECK(!fzn_reach_best(&r, b, 100u, NULL), "a host nothing was learnt of had a way");
	fzn_reach_learn(&r, b, FZN_REACH_TARGET, &adv, FZN_REACH_ADVERTISED, 100u);
	fzn_reach_learn(&r, b, FZN_REACH_TARGET, &intro, FZN_REACH_INTRODUCED, 100u);
	fzn_reach_learn(&r, b, FZN_REACH_SERVING, &hello, FZN_REACH_HELLO, 100u);
	CHECK(picks(&r, b, 101u, 3u, FZN_REACH_SERVING),
	      "a fresh hello was not chosen, from the serving socket");
	CHECK(picks(&r, b, 100u + FZN_REACH_HELLO_S, 2u, FZN_REACH_TARGET),
	      "a lapsed hello did not give way to the introduction");
	CHECK(picks(&r, b, 100u + FZN_REACH_INTRODUCED_S, 1u, FZN_REACH_TARGET),
	      "with both lapsed, the advertised address was not chosen");
}

/* SESSION_ASK'S ORDER, sec 1031: where it said hello, from the serving socket,
 * over a manifest's address; and a session's frame over a told address. */
static void test_ask_order(void)
{
	static fzn_reach_pair_t pairs[8];
	fzn_reach_t r;
	uint8_t b[FZN_PUBKEY_LEN];
	fzn_udp_addr_t told = at(4), framed = at(5), hello = at(6);

	memset(b, 0xbc, sizeof(b));
	fzn_reach_init(&r, pairs, 8u);
	fzn_reach_learn(&r, b, FZN_REACH_TARGET, &told, FZN_REACH_MANIFEST, 50u);
	fzn_reach_learn(&r, b, FZN_REACH_SERVING, &framed, FZN_REACH_SESSION, 50u);
	CHECK(picks(&r, b, 51u, 5u, FZN_REACH_SERVING), "a session's frame lost to a told address");
	fzn_reach_learn(&r, b, FZN_REACH_SERVING, &hello, FZN_REACH_HELLO, 60u);
	CHECK(picks(&r, b, 61u, 6u, FZN_REACH_SERVING), "a hello lost to a session's frame");
}

/* TIES, DEMOTION AND ROOM: the newer of one source; a told address repeating a
 * proven one leaves it proven; another host's ways are not this one's; a full
 * table gives a lapsed pair way first, then the oldest. */
static void test_rules(void)
{
	static fzn_reach_pair_t pairs[3];
	fzn_reach_t r;
	uint8_t b[FZN_PUBKEY_LEN], c[FZN_PUBKEY_LEN];
	fzn_udp_addr_t one = at(7), two = at(8), three = at(9);
	fzn_reach_pair_t p;

	memset(b, 0xbd, sizeof(b));
	memset(c, 0xcd, sizeof(c));
	fzn_reach_init(&r, pairs, 3u);
	fzn_reach_learn(&r, b, FZN_REACH_SERVING, &one, FZN_REACH_HELLO, 10u);
	fzn_reach_learn(&r, b, FZN_REACH_SERVING, &two, FZN_REACH_HELLO, 20u);
	CHECK(picks(&r, b, 21u, 8u, FZN_REACH_SERVING), "of two hellos the older was chosen");
	fzn_reach_learn(&r, b, FZN_REACH_SERVING, &two, FZN_REACH_ADVERTISED, 30u);
	CHECK(fzn_reach_best(&r, b, 31u, &p) && p.source == FZN_REACH_HELLO
	              && p.until == 20u + FZN_REACH_HELLO_S,
	      "a told address demoted the hello that proved the same way");
	CHECK(!fzn_reach_best(&r, c, 31u, NULL), "another host's ways were this one's");
	/* FULL: c's pair takes the third slot; a fourth way takes a lapsed one. */
	fzn_reach_learn(&r, c, FZN_REACH_TARGET, &three, FZN_REACH_ADVERTISED, 40u);
	fzn_reach_learn(&r, c, FZN_REACH_SERVING, &one, FZN_REACH_HELLO, 10u + FZN_REACH_HELLO_S);
	CHECK(picks(&r, c, 11u + FZN_REACH_HELLO_S, 7u, FZN_REACH_SERVING)
	              && picks(&r, b, 11u + FZN_REACH_HELLO_S, 8u, FZN_REACH_SERVING)
	              && fzn_reach_best(&r, c, 11u + FZN_REACH_HELLO_S, &p),
	      "a full table did not give its lapsed pair way, keeping the held ones");
}

int main(void)
{
	test_contact_order();
	test_ask_order();
	test_rules();
	printf("reach_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
