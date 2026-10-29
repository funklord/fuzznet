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

/* GIVEN ROOM, sec 704: a relay told its tables are larger keeps what it
 * held, and every one of 100 devices' hellos, where its own 64 let the
 * oldest go. */
static void test_a_relay_given_room(void)
{
	static fzn_node_relay_t r;
	static fzn_node_relay_route_t routes[256];
	static fzn_node_relay_seen_t seen[4096];
	uint8_t key[32];
	fzn_udp_addr_t a = addr_of("127.0.0.1", 5000u), got;
	uint64_t when = 0;
	size_t i, found = 0;

	fzn_node_relay_init(&r);
	memset(key, 0x77, sizeof(key));
	fzn_node_relay_saw(&r, key, &a, 5u);
	CHECK(!fzn_node_relay_use(&r, routes, 16u, seen, 4096u)
	              && fzn_node_relay_use(&r, routes, 256u, seen, 4096u)
	              && fzn_node_relay_where(&r, key, &got, &when) && when == 5u,
	      "room smaller than the own was taken, or the move lost a hello");
	for (i = 0; i < 100u; i++) {
		memset(key, 0x10, sizeof(key));
		key[0] = (uint8_t)i;
		fzn_node_relay_saw(&r, key, &a, 100u + i);
	}
	for (i = 0; i < 100u; i++) {
		memset(key, 0x10, sizeof(key));
		key[0] = (uint8_t)i;
		found += (size_t)fzn_node_relay_where(&r, key, &got, &when);
	}
	CHECK(found == 100u, "a relay given room for 4096 did not keep 100 devices' hellos");
}

/* WHO MAY ASK, sec 762: journey 4's authorization bar, every request with
 * each wrong caller. The askers: a member, a host of contact X, a host of
 * contact Y, and neither -- a removed contact, or any host whose frame
 * opened and nothing more. Each allowed is NULL, each refused its reason,
 * as fuzznetd says and answers it. */
static int is(const char *got, const char *want)
{
	return want ? got && strcmp(got, want) == 0 : got == NULL;
}

static void test_who_may_ask(void)
{
	static const char *const NO_RELAY = "this host relays nothing",
	                         *const NOT_OURS = "relayed only for this estate and its contacts",
	                         *const TWO_HOPS = "relayed already: one hop and never two",
	                         *const NOT_OWN = "not a frame of the asker's own",
	                         *const NO_INTRO = "introductions only within this estate",
	                         *const NO_NOTIFY =
	                                 "only this estate, or a contact about its own, introduces",
	                         *const UNKNOWN = "not a host this one knows",
	                         *const NO_TIME = "clocks only for this estate and its contacts",
	                         *const OWN_USER = "where this host is reached is its own user's";
	fzn_node_relay_asker_t member, x, y, neither;
	const fzn_node_relay_asker_t *all[4] = { &member, &x, &y, &neither };
	size_t i;

	memset(&member, 0, sizeof(member));
	member.member = 1;
	memset(&x, 0, sizeof(x));
	x.contact = 1;
	memset(x.owner, 0x0a, sizeof(x.owner));
	y = x;
	memset(y.owner, 0x0b, sizeof(y.owner));
	memset(&neither, 0, sizeof(neither));

	/* THE RELAY: off for everyone; on, for the estate and its contacts,
	 * one hop, the asker's own frame. */
	for (i = 0; i < 4u; i++)
		CHECK(is(fzn_node_relay_refuse_relay(all[i], 0, 1u, 1), NO_RELAY),
		      "a relay that relays nothing relayed for someone");
	CHECK(is(fzn_node_relay_refuse_relay(&member, 1, 1u, 1), NULL)
	              && is(fzn_node_relay_refuse_relay(&x, 1, 1u, 1), NULL)
	              && is(fzn_node_relay_refuse_relay(&y, 1, 1u, 1), NULL),
	      "a member or a contact's host was refused a relay it may have");
	CHECK(is(fzn_node_relay_refuse_relay(&neither, 1, 1u, 1), NOT_OURS)
	              && is(fzn_node_relay_refuse_relay(NULL, 1, 1u, 1), NOT_OURS),
	      "a host neither of the estate nor a standing contact's was relayed for");
	CHECK(is(fzn_node_relay_refuse_relay(&member, 1, 0u, 1), TWO_HOPS)
	              && is(fzn_node_relay_refuse_relay(&x, 1, 0u, 1), TWO_HOPS),
	      "a frame relayed once was relayed again");
	CHECK(is(fzn_node_relay_refuse_relay(&member, 1, 1u, 0), NOT_OWN)
	              && is(fzn_node_relay_refuse_relay(&x, 1, 1u, 0), NOT_OWN),
	      "a frame another host sealed was relayed for its asker");

	/* AN INTRODUCTION: the estate's own. */
	CHECK(is(fzn_node_relay_refuse_introduce(&member), NULL),
	      "a member was refused an introduction");
	CHECK(is(fzn_node_relay_refuse_introduce(&x), NO_INTRO)
	              && is(fzn_node_relay_refuse_introduce(&y), NO_INTRO)
	              && is(fzn_node_relay_refuse_introduce(&neither), NO_INTRO)
	              && is(fzn_node_relay_refuse_introduce(NULL), NO_INTRO),
	      "a host outside the estate was told where one of its hosts is");

	/* A NOTIFY: a member about a host this one knows; a contact's host
	 * about another of the same contact's. */
	CHECK(is(fzn_node_relay_refuse_notify(&member, &member), NULL)
	              && is(fzn_node_relay_refuse_notify(&member, &x), NULL),
	      "a member's notify about a known host was refused");
	CHECK(is(fzn_node_relay_refuse_notify(&member, &neither), UNKNOWN),
	      "a member's notify about a host this one does not know was taken");
	CHECK(is(fzn_node_relay_refuse_notify(&x, &x), NULL),
	      "a contact's notify about its own other host was refused");
	CHECK(is(fzn_node_relay_refuse_notify(&x, &y), NO_NOTIFY)
	              && is(fzn_node_relay_refuse_notify(&x, &member), NO_NOTIFY)
	              && is(fzn_node_relay_refuse_notify(&x, &neither), NO_NOTIFY),
	      "a contact's notify about another user's host, or this estate's, was taken");
	for (i = 0; i < 4u; i++)
		CHECK(is(fzn_node_relay_refuse_notify(&neither, all[i]), NO_NOTIFY),
		      "a notify from a host neither of the estate nor a contact's was taken");

	/* A TIME ASK: the estate's and its contacts'. */
	CHECK(is(fzn_node_relay_refuse_time(&member), NULL)
	              && is(fzn_node_relay_refuse_time(&x), NULL),
	      "a member or a contact's host was refused this host's clock");
	CHECK(is(fzn_node_relay_refuse_time(&neither), NO_TIME)
	              && is(fzn_node_relay_refuse_time(NULL), NO_TIME),
	      "a host neither of the estate nor a standing contact's was told this host's clock");

	/* THE LOCAL VERBS: the node's own user alone, as `get relay` is. */
	CHECK(is(fzn_node_relay_refuse_local(FZN_ORIGIN_SAME_USER), NULL),
	      "this node's own user was refused its own reachability");
	CHECK(is(fzn_node_relay_refuse_local(FZN_ORIGIN_LOCAL), OWN_USER)
	              && is(fzn_node_relay_refuse_local(FZN_ORIGIN_REMOTE), OWN_USER)
	              && is(fzn_node_relay_refuse_local(FZN_ORIGIN_NONE), OWN_USER),
	      "another user, a remote origin or none was told who this host hears or where it is "
	      "reached");
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
	test_who_may_ask();
	test_the_suite_can_tell_pass_from_fail();
	test_routes_back();
	test_where_peers_said_hello();
	test_a_relay_given_room();
	if (failures) {
		fprintf(stderr, "node relay_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("node relay_test: all %d checks passed\n", checks);
	return 0;
}
