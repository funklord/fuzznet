/* ports_test -- the ports a host listens on, sec 1289: two spans of ten,
 * the order a scan tries them, and which ports are fuzznet's. */
#include "../ports.h"

#include <stdio.h>

static int failures, checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL ports_test.c:%d: %s\n", line, what);
	}
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

int main(void)
{
	uint16_t all[FZN_PORTS_ALL];
	size_t i, n = fzn_ports_scan(all);
	int in = 1;

	CHECK(fzn_ports_nth(1, 0) == 930u && fzn_ports_nth(1, 9) == 939u && fzn_ports_nth(0, 0) == 6280u
	              && fzn_ports_nth(0, 9) == 6289u && fzn_ports_nth(0, 10) == 0u,
	      "a span was not its ten ports");
	CHECK(fzn_ports_nth(1, 9) < 1024u && fzn_ports_nth(0, 0) >= 1024u,
	      "the root span is not below 1024, or the user span not above it");
	CHECK(n == 20u && all[0] == 6280u && all[9] == 6289u && all[10] == 930u && all[19] == 939u,
	      "a scan did not try the user span first, then the root span");
	for (i = 0; i < n; i++)
		in = in && fzn_ports_in_span(all[i]);
	CHECK(in && !fzn_ports_in_span(929u) && !fzn_ports_in_span(940u) && !fzn_ports_in_span(6279u)
	              && !fzn_ports_in_span(FZN_PORTS_DISCOVERY),
	      "a port was taken for a span's, or one of a span's was not");
	{
		const int before = failures;

		CHECK(0, "deliberate");
		if (failures != before + 1)
			return 1;
		failures = before;
	}
	if (failures) {
		printf("ports_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("ports_test: all %d checks passed\n", checks - 1);
	return 0;
}
