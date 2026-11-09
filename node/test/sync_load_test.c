/* SYNC-LOAD, sec 966: a queue the rounds drain, one they do not, rounds
 * running back to back, and what `get sync-load` says of each. */
#include "../sync_load.h"

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                      \
	do {                                                                   \
		checks++;                                                      \
		if (!(cond)) {                                                 \
			failures++;                                            \
			fprintf(stderr, "  FAIL sync_load_test.c:%d: %s\n", __LINE__, what); \
		}                                                              \
	} while (0)

static void rounds(fzn_sync_load_t *s, size_t n, uint64_t files, uint64_t step, uint64_t ms,
                   uint64_t period)
{
	size_t i;

	for (i = 0; i < n; i++) {
		uint64_t v[FZN_SYNC_QUEUES] = { 0 };

		v[FZN_SYNC_QUEUE_FILES] = files + i * step;
		v[FZN_SYNC_QUEUE_FILE_BYTES] = (files + i * step) * 1000u;
		v[FZN_SYNC_QUEUE_ROUND_MS] = ms;
		fzn_sync_load_sample(s, v, period);
	}
}

int main(void)
{
	fzn_sync_load_t s;
	fzn_sync_queue_t why = FZN_SYNC_QUEUES;
	char out[512];

	/* NOTHING YET: ok, and all 0. */
	memset(&s, 0, sizeof(s));
	CHECK(fzn_sync_load_verdict(&s, NULL) == FZN_SYNC_LOAD_OK && fzn_sync_load_now(&s) == 0
	              && fzn_sync_load_stat(&s, FZN_SYNC_QUEUE_FILES).peak == 0,
	      "an empty window said something");

	/* A QUEUE THE ROUNDS DRAIN: high, then falling to nothing, never growing. */
	rounds(&s, 4, 40, 0, 2000, 60000);
	{
		size_t i;

		for (i = 0; i < 12u; i++) {
			uint64_t v[FZN_SYNC_QUEUES] = { 0 };

			v[FZN_SYNC_QUEUE_FILES] = 40u > i * 4u ? 40u - i * 4u : 0u;
			v[FZN_SYNC_QUEUE_ROUND_MS] = 2000u;
			fzn_sync_load_sample(&s, v, 60000u);
		}
	}
	CHECK(fzn_sync_load_verdict(&s, NULL) == FZN_SYNC_LOAD_OK
	              && !fzn_sync_load_stat(&s, FZN_SYNC_QUEUE_FILES).growing
	              && fzn_sync_load_stat(&s, FZN_SYNC_QUEUE_FILES).peak == 40u
	              && fzn_sync_load_now(&s) == 3u,
	      "a queue the rounds drained read as growing, or its peak or the load was wrong");

	/* ONE THEY DO NOT: growing a file a round, through the window. */
	memset(&s, 0, sizeof(s));
	rounds(&s, FZN_SYNC_LOAD_SAMPLES - 1u, 10, 1, 2000, 60000);
	CHECK(fzn_sync_load_verdict(&s, NULL) == FZN_SYNC_LOAD_OK,
	      "a window not yet full gave a verdict");
	rounds(&s, 1, 10 + FZN_SYNC_LOAD_SAMPLES - 1u, 1, 2000, 60000);
	CHECK(fzn_sync_load_verdict(&s, &why) == FZN_SYNC_LOAD_GROWING && why == FZN_SYNC_QUEUE_FILES
	              && fzn_sync_load_stat(&s, FZN_SYNC_QUEUE_FILES).now == 25u
	              && fzn_sync_load_stat(&s, FZN_SYNC_QUEUE_FILES).mean == 17u,
	      "a queue growing every round was not said to grow, first by name");

	/* REFILLED after a deep fall: the rounds kept up once, not growing. */
	memset(&s, 0, sizeof(s));
	rounds(&s, 8, 10, 1, 2000, 60000);
	rounds(&s, 1, 2, 0, 2000, 60000);
	rounds(&s, 7, 18, 1, 2000, 60000);
	CHECK(!fzn_sync_load_stat(&s, FZN_SYNC_QUEUE_FILES).growing,
	      "a queue that fell deep on the way read as growing");

	/* AT REST, ONE UP AT THE END: asks out at one round's end, not a queue
	 * growing. */
	memset(&s, 0, sizeof(s));
	rounds(&s, FZN_SYNC_LOAD_SAMPLES - 1u, 0, 0, 2000, 60000);
	rounds(&s, 1, 1, 0, 2000, 60000);
	CHECK(!fzn_sync_load_stat(&s, FZN_SYNC_QUEUE_FILES).growing
	              && fzn_sync_load_verdict(&s, NULL) == FZN_SYNC_LOAD_OK,
	      "a queue at rest that ended one up read as growing");

	/* BACK TO BACK: every round as long as its period, and longer. */
	memset(&s, 0, sizeof(s));
	rounds(&s, FZN_SYNC_LOAD_SAMPLES, 5, 0, 61000, 60000);
	CHECK(fzn_sync_load_verdict(&s, &why) == FZN_SYNC_LOAD_BUSY && why == FZN_SYNC_QUEUE_ROUND_MS
	              && fzn_sync_load_now(&s) == 101u,
	      "rounds running back to back were not busy");
	rounds(&s, 1, 5, 0, 30000, 60000);
	CHECK(fzn_sync_load_verdict(&s, NULL) == FZN_SYNC_LOAD_OK,
	      "one round inside its period left the verdict busy");

	/* SAID: the load, the verdict, and each queue. */
	memset(&s, 0, sizeof(s));
	rounds(&s, FZN_SYNC_LOAD_SAMPLES, 10, 1, 1500, 60000);
	CHECK(fzn_sync_load_say(&s, out, sizeof(out)) > 0
	              && strcmp(out, "ok 2 growing files,25,25,17,growing "
	                             "file-bytes,25000,25000,17500,growing asks,0,0,0,steady "
	                             "round-ms,1500,1500,1500,steady\n")
	                         == 0,
	      "get sync-load did not say the load, the verdict and each queue");
	CHECK(fzn_sync_load_say(&s, out, 20u) == 0, "a reply past its room was said in part");

	if (failures) {
		fprintf(stderr, "node sync_load_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("node sync_load_test: all %d checks passed\n", checks);
	return 0;
}
