/* node relay_test -- relaying's two tables, sec 622: a route back for a
 * forwarded frame's answers, and where each peer last said hello. */

#include "../relay.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

static int checks, failures;

#define CHECK(cond, what)                                                                  \
	do {                                                                               \
		checks++;                                                                  \
		if (!(cond)) {                                                             \
			failures++;                                                        \
			fprintf(stderr, "  FAIL relay_test.c:%d: %s\n", __LINE__, what);   \
		}                                                                          \
	} while (0)

static fzn_udp_addr_t addr_of(const char *host, uint16_t port)
{
	fzn_udp_addr_t a;

	memset(&a, 0, sizeof(a));
	(void)fzn_udp_resolve(AF_INET, host, port, &a);
	return a;
}

static int same(const fzn_udp_addr_t *a, const fzn_udp_addr_t *b)
{
	return a->len == b->len && memcmp(a->storage, b->storage, a->len) == 0;
}

static void test_routes_back(void)
{
	static fzn_node_relay_t r;
	uint8_t t[32], other[32], key[32];
	fzn_udp_addr_t a = addr_of("127.0.0.1", 4000u), b = addr_of("127.0.0.1", 4001u), got;
	size_t i;

	fzn_node_relay_init(&r);
	memset(t, 0x11, sizeof(t));
	memset(other, 0x22, sizeof(other));
	fzn_node_relay_route(&r, t, 5u, &a, 100u);
	CHECK(fzn_node_relay_back(&r, t, 5u, 105u, &got) && same(&got, &a),
	      "an answer within the route's life did not go back");
	CHECK(fzn_node_relay_back(&r, t, 5u, 106u, &got) && same(&got, &a),
	      "the route did not stand for a second frame of the answer");
	CHECK(!fzn_node_relay_back(&r, t, 5u, 100u + FZN_NODE_RELAY_ROUTE_S, &got),
	      "an answer past the route's life went back");
	CHECK(!fzn_node_relay_back(&r, t, 6u, 105u, &got)
	              && !fzn_node_relay_back(&r, other, 5u, 105u, &got),
	      "a frame of another message or another sender went back");
	fzn_node_relay_route(&r, t, 5u, &b, 107u);
	CHECK(fzn_node_relay_back(&r, t, 5u, 108u, &got) && same(&got, &b),
	      "routing the same pair again did not replace the route");
	/* FULL: the route nearest its end gives way, not a fresh one. */
	fzn_node_relay_init(&r);
	for (i = 0; i < FZN_NODE_RELAY_ROUTES_MAX; i++) {
		memset(key, (int)(i + 1u), sizeof(key));
		/* EVERY ROUTE LIVE at 1009, eight to a second. */
		fzn_node_relay_route(&r, key, 1u, &a, 1000u + i / 8u);
	}
	fzn_node_relay_route(&r, other, 9u, &b, 1009u);
	memset(key, 1, sizeof(key));
	CHECK(!fzn_node_relay_back(&r, key, 1u, 1009u, &got)
	              && fzn_node_relay_back(&r, other, 9u, 1009u, &got),
	      "a full table did not give the route nearest its end way");
	memset(key, 2, sizeof(key));
	CHECK(fzn_node_relay_back(&r, key, 1u, 1009u, &got)
	              && fzn_node_relay_back(&r, other, 9u, 1009u, &got),
	      "a full table gave more than one route way");
}

static void test_where_peers_said_hello(void)
{
	static fzn_node_relay_t r;
	uint8_t key[32], first[32];
	fzn_udp_addr_t a = addr_of("127.0.0.1", 5000u), b = addr_of("127.0.0.1", 5001u), got;
	uint64_t when = 0;
	size_t i;

	fzn_node_relay_init(&r);
	memset(key, 0x33, sizeof(key));
	CHECK(!fzn_node_relay_where(&r, key, &got, &when), "a peer never seen was found");
	fzn_node_relay_saw(&r, key, &a, 10u);
	fzn_node_relay_saw(&r, key, &b, 20u);
	CHECK(fzn_node_relay_where(&r, key, &got, &when) && same(&got, &b) && when == 20u,
	      "a peer's latest hello did not replace its earlier");
	fzn_node_relay_init(&r);
	for (i = 0; i < FZN_NODE_RELAY_SEEN_MAX; i++) {
		memset(key, (int)(i + 1u), sizeof(key));
		fzn_node_relay_saw(&r, key, &a, 100u + i);
	}
	memset(key, 0xee, sizeof(key));
	fzn_node_relay_saw(&r, key, &b, 500u);
	memset(first, 1, sizeof(first));
	CHECK(fzn_node_relay_where(&r, key, &got, &when) && same(&got, &b)
	              && !fzn_node_relay_where(&r, first, &got, &when),
	      "a full table did not give its oldest hello way");
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
	test_the_suite_can_tell_pass_from_fail();
	test_routes_back();
	test_where_peers_said_hello();
	if (failures) {
		fprintf(stderr, "node relay_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("node relay_test: all %d checks passed\n", checks);
	return 0;
}
