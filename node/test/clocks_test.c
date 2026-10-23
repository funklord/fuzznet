/* node/clocks.h, sec 717: a row a peer whose clock disagrees, refreshed
 * and turned, forgotten after its keeping, grown on ROOM, and `list clock`
 * paging every row once, with the refusals. */
#include "../clocks.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL clocks_test.c:%d: %s\n", line, what);
	}
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static char reply[FZN_REPLY_MAX];

static void key(uint8_t k[FZN_PUBKEY_LEN], uint8_t seed)
{
	memset(k, seed, FZN_PUBKEY_LEN);
}

static size_t listed(fzn_node_clocks_t *c, fzn_origin_t origin, const char *arg, uint64_t now)
{
	fzn_request_t req;

	memset(&req, 0, sizeof(req));
	req.parsed = FZN_VERB_LIST;
	req.arg = (const uint8_t *)arg;
	req.arg_len = strlen(arg);
	memset(reply, 0, sizeof(reply));
	return fzn_node_clocks_local(c, origin, &req, now, reply, sizeof(reply));
}

/* ROWS: new, refreshed, turned, forgotten; ROOM, and grown. */
static void test_the_rows(void)
{
	static fzn_node_clock_t small[1], big[4];
	fzn_node_clocks_t c;
	uint8_t a[FZN_PUBKEY_LEN], b[FZN_PUBKEY_LEN];

	key(a, 0xaa);
	key(b, 0xbb);
	fzn_node_clocks_init(&c, small, 1);
	CHECK(fzn_node_clocks_note(&c, a, 0, 400, 1000) == FZN_NODE_CLOCKS_NEW && c.used == 1u,
	      "a first refusal is not a new row");
	CHECK(fzn_node_clocks_note(&c, a, 0, 420, 1010) == FZN_NODE_CLOCKS_OK && c.used == 1u
	              && c.rows[0].seconds == 420u && c.rows[0].at == 1010u,
	      "the same peer the same way did not refresh its row");
	CHECK(fzn_node_clocks_note(&c, a, 1, 30, 1020) == FZN_NODE_CLOCKS_NEW && c.rows[0].ahead,
	      "a peer turned the other way is not said as new");
	CHECK(fzn_node_clocks_note(&c, b, 1, 90, 1030) == FZN_NODE_CLOCKS_ROOM && c.used == 1u,
	      "a second peer in a table of one was not ROOM");
	CHECK(fzn_node_clocks_use(&c, big, 4) && c.used == 1u
	              && memcmp(c.rows[0].peer, a, FZN_PUBKEY_LEN) == 0
	              && fzn_node_clocks_note(&c, b, 1, 90, 1030) == FZN_NODE_CLOCKS_NEW
	              && c.used == 2u,
	      "the move did not keep the row, or the second peer was not taken after it");
	CHECK(!fzn_node_clocks_use(&c, small, 1), "a move onto less than is held was taken");
	CHECK(fzn_node_clocks_note(&c, b, 1, 95, 1020 + FZN_NODE_CLOCKS_KEEP_S) == FZN_NODE_CLOCKS_OK
	              && c.used == 1u && memcmp(c.rows[0].peer, b, FZN_PUBKEY_LEN) == 0,
	      "a row past its keeping was not forgotten, or the one still kept was");
}

/* THE VERB: the rows in full, every one once over pages, the refusals. */
static void test_the_verb(void)
{
	static fzn_node_clock_t rows[40];
	static char seen[40];
	fzn_node_clocks_t c;
	uint8_t k[FZN_PUBKEY_LEN];
	size_t i, from = 0, total = 0, f = 0, pages = 0;
	char arg[32], want[200];

	fzn_node_clocks_init(&c, rows, 40);
	CHECK(listed(&c, FZN_ORIGIN_SAME_USER, "clock", 2000) > 0 && strcmp(reply, "ok 0 0\n") == 0,
	      "no rows is not ok 0 0");
	key(k, 0x11);
	(void)fzn_node_clocks_note(&c, k, 0, 412, 2000);
	snprintf(want, sizeof(want), "ok 1 0 %s,behind,412,2000\n",
	         "1111111111111111111111111111111111111111111111111111111111111111");
	CHECK(listed(&c, FZN_ORIGIN_SAME_USER, "clock", 2001) > 0 && strcmp(reply, want) == 0,
	      "a row is not its key in full, its direction, seconds and when");
	for (i = 1; i < 40; i++) {
		key(k, (uint8_t)(0x20 + i));
		(void)fzn_node_clocks_note(&c, k, (int)(i & 1u), i, 2000);
	}
	memset(seen, 0, sizeof(seen));
	for (;;) {
		char *at, *row;
		size_t got = 0;

		snprintf(arg, sizeof(arg), from ? "clock %zu" : "clock", from);
		if (!listed(&c, FZN_ORIGIN_SAME_USER, arg, 2001) || strlen(reply) >= sizeof(reply) - 1u
		    || sscanf(reply, "ok %zu %zu", &total, &f) != 2 || f != from)
			break;
		pages++;
		at = strchr(strchr(strchr(reply, ' ') + 1, ' ') + 1, ' ');
		for (row = at; row && *row == ' '; row = strchr(row + 1, ' ')) {
			unsigned v = 0;

			if (sscanf(row + 1, "%2x", &v) == 1) {
				size_t idx = v == 0x11u ? 0u : v - 0x20u;

				if (idx < 40u)
					seen[idx]++;
			}
			got++;
		}
		if (!got)
			break;
		from += got;
		if (pages > 40u)
			break;
	}
	for (i = 0; i < 40u && seen[i] == 1; i++)
		;
	CHECK(total == 40u && i == 40u && pages > 1u,
	      "over the pages, not every row once, or all in one reply");
	CHECK(listed(&c, FZN_ORIGIN_LOCAL, "clock", 2001) > 0 && strncmp(reply, "denied", 6u) == 0,
	      "another local user read the clocks");
	CHECK(listed(&c, FZN_ORIGIN_SAME_USER, "clock x", 2001) > 0
	              && strncmp(reply, "malformed", 9u) == 0,
	      "a malformed list clock was answered");
	CHECK(listed(NULL, FZN_ORIGIN_SAME_USER, "clock", 2001) > 0
	              && strncmp(reply, "error", 5u) == 0,
	      "a node keeping no clocks did not say so");
	CHECK(listed(&c, FZN_ORIGIN_SAME_USER, "clocks", 2001) == 0
	              && listed(&c, FZN_ORIGIN_SAME_USER, "contact", 2001) == 0,
	      "another subject was answered as list clock");
	CHECK(listed(&c, FZN_ORIGIN_SAME_USER, "clock", 2000 + FZN_NODE_CLOCKS_KEEP_S) > 0
	              && strcmp(reply, "ok 0 0\n") == 0,
	      "rows past their keeping are still listed");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	CHECK(0, "deliberate");
	CHECK(failures == before + 1, "a failing check did not count");
	failures = before;
	checks -= 1;
}

int main(void)
{
	test_the_rows();
	test_the_verb();
	test_the_suite_can_tell_pass_from_fail();

	printf("clocks_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
