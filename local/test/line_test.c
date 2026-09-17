/* The framing bound, and the two things about it that are not obvious.
 *
 * A line reader looks like a five-minute job and is where text protocols go
 * wrong: partial reads, several requests in one packet, a line that lands
 * exactly on the bound, and what to do when one does not.
 */

#include "../line.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check(int ok, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL: %s\n", what);
	}
}

static int line_is(const uint8_t *line, size_t len, const char *want)
{
	return len == strlen(want) && memcmp(line, want, len) == 0;
}

static fzn_line_err_t push_str(fzn_line_t *r, const char *s)
{
	return fzn_line_push(r, (const uint8_t *)s, strlen(s));
}

int main(void)
{
	uint8_t buf[32];
	fzn_line_t r;
	const uint8_t *line;
	size_t len;

	check(fzn_line_init(&r, buf, sizeof(buf)) == FZN_LINE_OK, "init refused");

	/* One line, arriving whole. */
	check(push_str(&r, "status\n") == FZN_LINE_OK, "a whole line was refused");
	check(fzn_line_next(&r, &line, &len) == 1, "a complete line was not offered");
	check(line_is(line, len, "status"), "the line came back wrong");
	check(fzn_line_next(&r, &line, &len) == 0, "a second line appeared from nowhere");

	/* SEVERAL IN ONE PUSH, which is what a socket read actually delivers.
	 * A reader that handled one per read would leave the rest sitting in
	 * the buffer until more traffic arrived, which on a request/response
	 * connection is a deadlock rather than a delay. */
	check(push_str(&r, "one\ntwo\nthree\n") == FZN_LINE_OK, "three lines were refused");
	check(fzn_line_next(&r, &line, &len) == 1 && line_is(line, len, "one"), "line 1");
	check(fzn_line_next(&r, &line, &len) == 1 && line_is(line, len, "two"), "line 2");
	check(fzn_line_next(&r, &line, &len) == 1 && line_is(line, len, "three"), "line 3");
	check(fzn_line_next(&r, &line, &len) == 0, "a fourth line appeared");

	/* A LINE SPLIT ACROSS PUSHES, byte by byte, which is the other thing a
	 * socket does and the case a length-prefixed reader never meets. */
	{
		static const char msg[] = "monitor\n";

		for (size_t i = 0; i < sizeof(msg) - 1u; i++) {
			char one[2] = { msg[i], 0 };

			check(push_str(&r, one) == FZN_LINE_OK, "a single byte was refused");
			if (i + 1u < sizeof(msg) - 1u)
				check(fzn_line_next(&r, &line, &len) == 0,
				      "a line was offered before its newline arrived");
		}
		check(fzn_line_next(&r, &line, &len) == 1 && line_is(line, len, "monitor"),
		      "a line assembled from single bytes came back wrong");
	}

	/* THE RETURNED LINE MUST SURVIVE UNTIL THE NEXT CALL, which is what
	 * the header promises and what the first version of line.c broke: it
	 * shifted the remainder down inside `next`, over the line it had just
	 * returned. Here the second request is already in the buffer, so a
	 * reader that compacted eagerly would have overwritten the first. */
	check(push_str(&r, "first\nsecond\n") == FZN_LINE_OK, "two lines were refused");
	check(fzn_line_next(&r, &line, &len) == 1, "the first line was not offered");
	check(line_is(line, len, "first"),
	      "the returned line was overwritten by the request behind it");

	/* An empty line is a line. Whether it is an error is the consumer's
	 * question, and answering it here would be a vocabulary decision. */
	check(fzn_line_next(&r, &line, &len) == 1 && line_is(line, len, "second"), "second");
	check(push_str(&r, "\n") == FZN_LINE_OK, "an empty line was refused");
	check(fzn_line_next(&r, &line, &len) == 1 && len == 0, "an empty line was not offered");

	/* EXACTLY AT THE BOUND. The newline is not kept, so a line of `cap`
	 * bytes plus its newline is one byte over -- which would be a
	 * miserable off-by-one to meet in production. Both sides are checked
	 * because only one of them is the obvious reading. */
	{
		uint8_t small[8];
		fzn_line_t s;
		char eight[] = "12345678\n";  /* 8 bytes then a newline */
		char seven[] = "1234567\n";   /* 7 bytes then a newline: 8 in all */

		check(fzn_line_init(&s, small, sizeof(small)) == FZN_LINE_OK, "init refused");
		check(push_str(&s, seven) == FZN_LINE_OK,
		      "a line filling the buffer with its newline was refused");
		check(fzn_line_next(&s, &line, &len) == 1 && line_is(line, len, "1234567"),
		      "a line at the bound came back wrong");

		check(fzn_line_init(&s, small, sizeof(small)) == FZN_LINE_OK, "re-init refused");
		check(push_str(&s, eight) == FZN_LINE_ERR_OVERLONG,
		      "a line one byte past the bound was accepted");
	}

	/* OVER-LONG IS STICKY AND DOES NOT RESYNCHRONISE. A reader that
	 * skipped to the next newline would let whoever sent the long line
	 * choose where the following request begins -- and on raidcfgd's shape
	 * the bytes may have come from a remote client behind the bridge
	 * rather than from the peer holding the socket. */
	{
		uint8_t small[8];
		fzn_line_t s;

		check(fzn_line_init(&s, small, sizeof(small)) == FZN_LINE_OK, "init refused");
		check(push_str(&s, "aaaaaaaaaaaaaaaa\ndestroy\n") == FZN_LINE_ERR_OVERLONG,
		      "an over-long line was accepted");
		check(fzn_line_next(&s, &line, &len) == 0,
		      "a refusing reader offered a line, which is the resynchronisation "
		      "that lets a long line choose the next request boundary");
		check(push_str(&s, "status\n") == FZN_LINE_ERR_OVERLONG,
		      "a refusing reader accepted more bytes");
		check(fzn_line_next(&s, &line, &len) == 0, "a refusing reader recovered");
	}

	/* A COMPLETE LINE ALREADY PENDING WHEN THE OVERFLOW ARRIVES, which is
	 * the only state in which the refusal inside `next` is reachable at
	 * all -- an over-long push appends nothing, so a reader that overflows
	 * from empty simply has nothing to offer.
	 *
	 * Found by sabotage: removing that guard changed no test result, which
	 * meant no test built this state. The rule it pins is worth pinning:
	 * once a connection is being dropped, nothing more is acted on from
	 * it. The pending line was framed before any ambiguity and could be
	 * argued for, but "drop the connection" is not a thing to do halfway,
	 * and a caller that acted on one more command from a peer it had just
	 * refused would be doing exactly that. */
	{
		uint8_t small[8];
		fzn_line_t s;

		check(fzn_line_init(&s, small, sizeof(small)) == FZN_LINE_OK, "init refused");
		check(push_str(&s, "ok\n") == FZN_LINE_OK, "a short line was refused");
		check(push_str(&s, "aaaaaaaaaaaaaaaa") == FZN_LINE_ERR_OVERLONG,
		      "an over-long push was accepted");
		check(fzn_line_next(&s, &line, &len) == 0,
		      "a line pending before the overflow was still handed out, so a "
		      "connection being dropped acted on one more command");
	}

	/* A push that would overflow takes nothing, so a caller cannot
	 * half-append a read and then repeat it. */
	{
		uint8_t small[8];
		fzn_line_t s;

		check(fzn_line_init(&s, small, sizeof(small)) == FZN_LINE_OK, "init refused");
		check(push_str(&s, "abc") == FZN_LINE_OK, "three bytes were refused");
		check(push_str(&s, "defghijkl") == FZN_LINE_ERR_OVERLONG,
		      "a push past the bound was accepted");
		check(s.used == 3, "a refused push consumed part of its input");
	}

	/* Arguments. */
	check(fzn_line_init(NULL, buf, sizeof(buf)) == FZN_LINE_ERR_MALFORMED, "a null reader");
	check(fzn_line_init(&r, NULL, sizeof(buf)) == FZN_LINE_ERR_MALFORMED, "a null buffer");
	check(fzn_line_init(&r, buf, 0) == FZN_LINE_ERR_MALFORMED, "a zero-length buffer");
	check(fzn_line_init(&r, buf, sizeof(buf)) == FZN_LINE_OK, "re-init refused");
	check(fzn_line_push(NULL, (const uint8_t *)"x", 1) == FZN_LINE_ERR_MALFORMED,
	      "a null reader was pushed to");
	check(fzn_line_push(&r, NULL, 1) == FZN_LINE_ERR_MALFORMED, "a null buffer was pushed");
	check(fzn_line_push(&r, NULL, 0) == FZN_LINE_OK, "an empty push was refused");
	check(fzn_line_next(NULL, &line, &len) == 0, "a null reader offered a line");
	check(fzn_line_next(&r, NULL, &len) == 0, "a null out was accepted");
	check(fzn_line_next(&r, &line, NULL) == 0, "a null length out was accepted");

	printf("line_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
