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

/* THE PROBE, sec 719: an ask and its answer round trip; an answer to
 * another nonce, or bent, is not taken; the offset is the peer's time less
 * the midpoint, either sign. */
static void test_the_probe(void)
{
	uint8_t nonce[FZN_NODE_TIME_NONCE_LEN], other[FZN_NODE_TIME_NONCE_LEN];
	uint8_t ask[FZN_NODE_TIME_ASK_LEN], answer[FZN_NODE_TIME_ANSWER_LEN];
	int64_t offset = 0;
	uint64_t rtt = 0;
	size_t a, n;

	memset(nonce, 0x5c, sizeof(nonce));
	memset(other, 0x5d, sizeof(other));
	a = fzn_node_time_ask(nonce, ask, sizeof(ask));
	CHECK(a == FZN_NODE_TIME_ASK_LEN && fzn_node_time_is_ask(ask, a)
	              && !fzn_node_time_is_ask(ask, a - 1u),
	      "an ask is not one, or one cut short still is");
	n = fzn_node_time_answer(ask, a, 1000900000u, answer, sizeof(answer));
	CHECK(n == FZN_NODE_TIME_ANSWER_LEN
	              && fzn_node_time_take(answer, n, nonce, 1000000000u, 1000000020u, &offset, &rtt)
	              && offset == 899990 && rtt == 20u,
	      "a peer 900 s ahead, asked at 0 and answered at 20 ms, is not +899990 with 20");
	CHECK(fzn_node_time_take(answer, n, nonce, 1001800000u, 1001800010u, &offset, &rtt)
	              && offset == -900005 && rtt == 10u,
	      "a peer behind is not a negative offset");
	CHECK(!fzn_node_time_take(answer, n, other, 1000000000u, 1000000020u, &offset, &rtt),
	      "an answer to another nonce was taken");
	n = fzn_node_time_answer(ask, a, UINT64_MAX, answer, sizeof(answer));
	CHECK(!fzn_node_time_take(answer, n, nonce, 1000000000u, 1000000020u, &offset, &rtt),
	      "a time no clock keeps was taken, an offset past the signed range");
	n = fzn_node_time_answer(ask, a, 1000000010u + FZN_NODE_TIME_SPAN_MS, answer, sizeof(answer));
	CHECK(fzn_node_time_take(answer, n, nonce, 1000000000u, 1000000020u, &offset, &rtt)
	              && offset == (int64_t)FZN_NODE_TIME_SPAN_MS,
	      "a clock at the span's edge was not measured");
	answer[1] ^= 1u;
	CHECK(!fzn_node_time_take(answer, n, nonce, 1000000000u, 1000000020u, &offset, &rtt),
	      "an answer of another type was taken");
	CHECK(!fzn_node_time_take(answer, n, nonce, 20u, 10u, &offset, &rtt)
	              && fzn_node_time_answer(ask, a - 1u, 1u, answer, sizeof(answer)) == 0
	              && fzn_node_time_answer(ask, a, 1u, answer, n - 1u) == 0,
	      "a reply before its ask, a bad ask, or no room was answered");
}

/* OFFSETS: the filter takes the least round trip; rows forgotten; ROOM and
 * grown; `list offset` paged, signed, with the refusals. */
static void test_the_offsets(void)
{
	static fzn_node_offset_t small[1], big[64];
	fzn_node_offsets_t o;
	uint8_t a[FZN_PUBKEY_LEN], b[FZN_PUBKEY_LEN];
	int64_t off = 0;
	uint64_t rtt = 0;
	char want[200];
	size_t i;
	fzn_request_t req;

	key(a, 0xa1);
	key(b, 0xb2);
	fzn_node_offsets_init(&o, small, 1);
	CHECK(!fzn_node_offsets_of(&o, a, &off, &rtt) && fzn_node_offsets_at(&o, a) == 0u,
	      "a peer never sampled has an offset");
	CHECK(fzn_node_offsets_note(&o, a, 1, 5000, 40, 100) == FZN_NODE_CLOCKS_NEW
	              && fzn_node_offsets_note(&o, a, 1, 4990, 4, 101) == FZN_NODE_CLOCKS_OK
	              && fzn_node_offsets_note(&o, a, 1, 7000, 90, 102) == FZN_NODE_CLOCKS_OK
	              && fzn_node_offsets_of(&o, a, &off, &rtt) && off == 4990 && rtt == 4u
	              && fzn_node_offsets_at(&o, a) == 102u,
	      "the filter did not keep the sample of least round trip");
	for (i = 0; i < FZN_NODE_OFFSET_SAMPLES; i++)
		(void)fzn_node_offsets_note(&o, a, 1, 6000 + (int64_t)i, 50, 103);
	CHECK(fzn_node_offsets_of(&o, a, &off, &rtt) && off == 6007 && rtt == 50u,
	      "samples past the window were not let go, or of equals not the newest kept");
	CHECK(fzn_node_offsets_note(&o, b, 1, -2000, 3, 104) == FZN_NODE_CLOCKS_ROOM,
	      "a second peer in a table of one was not ROOM");
	CHECK(fzn_node_offsets_use(&o, big, 64)
	              && fzn_node_offsets_note(&o, b, 1, -2000, 3, 104) == FZN_NODE_CLOCKS_NEW,
	      "grown, the second peer was not taken");
	memset(&req, 0, sizeof(req));
	req.parsed = FZN_VERB_LIST;
	req.arg = (const uint8_t *)"offset";
	req.arg_len = 6u;
	snprintf(want, sizeof(want), "ok 2 0 %s,6007,50,103 %s,-2000,3,104\n",
	         "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
	         "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2");
	CHECK(fzn_node_offsets_local(&o, FZN_ORIGIN_SAME_USER, &req, 105, reply, sizeof(reply)) > 0
	              && strcmp(reply, want) == 0,
	      "list offset is not each peer, its offset signed, its round trip and when");
	CHECK(fzn_node_offsets_local(&o, FZN_ORIGIN_LOCAL, &req, 105, reply, sizeof(reply)) > 0
	              && strncmp(reply, "denied", 6u) == 0,
	      "another local user read the offsets");
	CHECK(fzn_node_offsets_local(&o, FZN_ORIGIN_SAME_USER, &req, 103 + FZN_NODE_CLOCKS_KEEP_S,
	                             reply, sizeof(reply)) > 0
	              && strncmp(reply, "ok 1 0 b2", 9u) == 0,
	      "a peer not sampled within the keeping is still listed");
}

/* ESTATE TIME, sec 719 stage 2: the median of this node's zero and its
 * estate devices' offsets; unsure under two others; a contact counts for
 * nothing; the holder's minute; and `get clock`. */
static void test_estate_time(void)
{
	static fzn_node_offset_t rows[8];
	fzn_node_offsets_t o;
	uint8_t k[FZN_PUBKEY_LEN];
	int64_t off = 0;
	size_t devices = 9;
	fzn_request_t req;

	fzn_node_offsets_init(&o, rows, 8);
	CHECK(fzn_node_clock_estate(&o, 100, &off, &devices) == FZN_NODE_CLOCK_UNSURE
	              && off == 0 && devices == 0u,
	      "a node with nothing measured is not unsure at zero");
	key(k, 0x01);
	(void)fzn_node_offsets_note(&o, k, 1, 900000, 5, 100);
	CHECK(fzn_node_clock_estate(&o, 100, &off, &devices) == FZN_NODE_CLOCK_UNSURE
	              && devices == 1u && off == 450000,
	      "one other device alone was not unsure, or the median of two not their mean");
	key(k, 0x02);
	(void)fzn_node_offsets_note(&o, k, 1, 899000, 5, 100);
	CHECK(fzn_node_clock_estate(&o, 100, &off, &devices) == FZN_NODE_CLOCK_WRONG
	              && devices == 2u && off == 899000,
	      "two devices 900 s ahead of this one did not make its clock wrong, at their median");
	key(k, 0x03);
	(void)fzn_node_offsets_note(&o, k, 0, -5000000, 5, 100);
	key(k, 0x04);
	(void)fzn_node_offsets_note(&o, k, 0, -5000000, 5, 100);
	CHECK(fzn_node_clock_estate(&o, 100, &off, &devices) == FZN_NODE_CLOCK_WRONG
	              && devices == 2u && off == 899000,
	      "a contact's clock moved estate time");
	key(k, 0x05);
	(void)fzn_node_offsets_note(&o, k, 1, 10, 5, 100);
	key(k, 0x06);
	(void)fzn_node_offsets_note(&o, k, 1, -20, 5, 100);
	CHECK(fzn_node_clock_estate(&o, 100, &off, &devices) == FZN_NODE_CLOCK_RIGHT
	              && devices == 4u && off == 10,
	      "with two devices agreeing and two 900 s ahead, this one is not right at the median, 10");
	fzn_node_offsets_init(&o, rows, 8);
	key(k, 0x07);
	(void)fzn_node_offsets_note(&o, k, 1, FZN_NODE_CLOCK_WRONG_MS, 5, 100);
	key(k, 0x08);
	(void)fzn_node_offsets_note(&o, k, 1, FZN_NODE_CLOCK_WRONG_MS, 5, 100);
	CHECK(fzn_node_clock_estate(&o, 100, &off, &devices) == FZN_NODE_CLOCK_RIGHT,
	      "a clock exactly a minute off was called wrong");
	fzn_node_offsets_init(&o, rows, 8);
	for (k[0] = 0x09; k[0] < 0x0c; k[0]++)
		(void)fzn_node_offsets_note(&o, k, 1, FZN_NODE_CLOCK_WRONG_MS + 1, 5, 100);
	CHECK(fzn_node_clock_estate(&o, 100, &off, &devices) == FZN_NODE_CLOCK_WRONG
	              && off == FZN_NODE_CLOCK_WRONG_MS + 1 && devices == 3u,
	      "three devices a minute and a millisecond ahead did not make this clock wrong");
	CHECK(fzn_node_clock_estate(&o, 100 + FZN_NODE_CLOCKS_KEEP_S, &off, &devices)
	              == FZN_NODE_CLOCK_UNSURE && devices == 0u,
	      "samples past their keeping still counted");
	{
		static fzn_node_offset_t behind_rows[4];
		fzn_node_offsets_t behind;

		fzn_node_offsets_init(&behind, behind_rows, 4);
		for (k[0] = 0x0c; k[0] < 0x0e; k[0]++)
			(void)fzn_node_offsets_note(&behind, k, 1, -FZN_NODE_CLOCK_WRONG_MS - 1, 5, 100);
		CHECK(fzn_node_clock_estate(&behind, 100, &off, &devices) == FZN_NODE_CLOCK_WRONG
		              && off == -FZN_NODE_CLOCK_WRONG_MS - 1 && devices == 2u,
		      "a clock a minute ahead of two devices was not wrong, at a negative offset");
	}
	memset(&req, 0, sizeof(req));
	req.parsed = FZN_VERB_GET;
	req.arg = (const uint8_t *)"clock";
	req.arg_len = 5u;
	CHECK(fzn_node_clock_local(&o, FZN_ORIGIN_SAME_USER, &req, 100, reply, sizeof(reply)) > 0
	              && strcmp(reply, "ok 60001 3 wrong\n") == 0,
	      "get clock is not the offset, the devices and the state");
	CHECK(fzn_node_clock_local(&o, FZN_ORIGIN_LOCAL, &req, 100, reply, sizeof(reply)) > 0
	              && strncmp(reply, "denied", 6u) == 0,
	      "another local user read this node's clock");
	req.arg = (const uint8_t *)"clock x";
	req.arg_len = 7u;
	CHECK(fzn_node_clock_local(&o, FZN_ORIGIN_SAME_USER, &req, 100, reply, sizeof(reply)) > 0
	              && strncmp(reply, "malformed", 9u) == 0,
	      "a malformed get clock was answered");
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
	test_the_probe();
	test_the_offsets();
	test_estate_time();
	test_the_suite_can_tell_pass_from_fail();

	printf("clocks_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
