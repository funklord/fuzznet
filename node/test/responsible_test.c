/* node responsible_test -- who is responsible for a key, sec 820: the same
 * order whatever order the members are given in, a member joining moving
 * only what it now ranks first for, an even spread, and the verb. */

#include "../responsible.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                       \
	do {                                                                                    \
		checks++;                                                                       \
		if (!(cond)) {                                                                  \
			failures++;                                                             \
			fprintf(stderr, "  FAIL responsible_test.c:%d: %s\n", __LINE__, what);   \
		}                                                                               \
	} while (0)

static int mix_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint64_t h = 0x84222325cbf29ce4ull;
	size_t i;

	(void)ctx;
	for (i = 0; i < in_len; i++)
		h = (h ^ in[i]) * 0x100000001b3ull;
	for (i = 0; i < out_len; i++) {
		h = (h ^ (uint64_t)i) * 0x100000001b3ull;
		h ^= h >> 29;
		out[i] = (uint8_t)(h >> 40);
	}
	return 1;
}

static const fzn_hash_ops_t HASH = { mix_hash, NULL };

#define N 6u

static uint8_t members[N + 1u][32];

static void key_of(char *out, size_t cap, unsigned i)
{
	(void)snprintf(out, cap, "job/%u", i);
}

static void test_the_order(void)
{
	uint8_t shuffled[N][32];
	size_t order[N + 1u], again[N], i, j, firsts[N + 1u] = { 0 }, moved = 0, kept = 0;
	unsigned k;
	char key[32];

	for (i = 0; i < N + 1u; i++)
		memset(members[i], (int)(0x10u + i * 0x11u), 32u);
	/* THE SAME ORDER whatever order the members come in. */
	for (i = 0; i < N; i++)
		memcpy(shuffled[i], members[N - 1u - i], 32u);
	CHECK(fzn_responsible_order(&HASH, (const uint8_t *)"job/1", 5u,
	                            (const uint8_t (*)[32])members, N, order)
	              && fzn_responsible_order(&HASH, (const uint8_t *)"job/1", 5u,
	                                       (const uint8_t (*)[32])shuffled, N, again),
	      "the order was not made");
	for (i = 0; i < N; i++)
		CHECK(memcmp(members[order[i]], shuffled[again[i]], 32u) == 0,
		      "two members holding the set in another order ranked it differently");
	/* AN EVEN SPREAD, and A MEMBER JOINING moves only the keys it ranks
	 * first for; the rest keep their order of the six. */
	for (k = 0; k < 3000u; k++) {
		size_t six[N], seven[N + 1u], a, b;

		key_of(key, sizeof(key), k);
		if (!fzn_responsible_order(&HASH, (const uint8_t *)key, strlen(key),
		                           (const uint8_t (*)[32])members, N, six)
		    || !fzn_responsible_order(&HASH, (const uint8_t *)key, strlen(key),
		                              (const uint8_t (*)[32])members, N + 1u, seven)) {
			CHECK(0, "an order was not made");
			break;
		}
		firsts[six[0]]++;
		if (seven[0] == N) {
			moved++;
			continue;
		}
		for (a = 0, b = 0; a < N + 1u; a++) {
			if (seven[a] == N)
				continue;
			if (seven[a] != six[b++])
				break;
		}
		kept += a == N + 1u;
	}
	for (i = 0; i < N; i++)
		CHECK(firsts[i] > 3000u / N / 2u && firsts[i] < 3000u * 2u / N,
		      "the keys were not spread about evenly over the members");
	CHECK(moved > 3000u / (N + 1u) / 2u && moved < 3000u * 2u / (N + 1u)
	              && kept == 3000u - moved,
	      "a member joining moved other keys than the ones it now ranks first, or about a "
	      "seventh");
	/* THE KEY COUNTS WHOLE: a key and its prefix rank apart. */
	CHECK(fzn_responsible_order(&HASH, (const uint8_t *)"ab", 2u,
	                            (const uint8_t (*)[32])members, N, order)
	              && fzn_responsible_order(&HASH, (const uint8_t *)"a", 1u,
	                                       (const uint8_t (*)[32])members, N, again),
	      "fixture: two keys ranked");
	for (i = j = 0; i < N; i++)
		j += order[i] != again[i];
	CHECK(j > 0u, "a key and its prefix ranked the members alike");
	/* REFUSED: a key too long, no members to write into. */
	{
		uint8_t big[FZN_RESPONSIBLE_KEY_MAX + 1u];

		memset(big, 'k', sizeof(big));
		CHECK(!fzn_responsible_order(&HASH, big, sizeof(big), (const uint8_t (*)[32])members,
		                             N, order)
		              && fzn_responsible_order(&HASH, big, FZN_RESPONSIBLE_KEY_MAX,
		                                       (const uint8_t (*)[32])members, N, order)
		              && fzn_responsible_order(&HASH, big, 1u, NULL, 0u, NULL),
		      "a key past the bound was ranked, one at it was not, or no members failed");
	}
}

static size_t n_hosts;

static int host_at(void *ctx, size_t i, uint8_t host[32])
{
	(void)ctx;
	if (i >= n_hosts)
		return 0;
	memcpy(host, members[i], 32u);
	return 1;
}

static char reply[2048];

static size_t asked(const fzn_node_responsible_t *nr, fzn_origin_t origin, const char *line)
{
	fzn_request_t req;

	memset(reply, 0, sizeof(reply));
	if (!fzn_vocabulary_split((const uint8_t *)line, strlen(line), &req))
		return 0;
	return fzn_node_responsible_local(nr, origin, &req, reply, sizeof(reply));
}

static void test_the_verb(void)
{
	fzn_node_responsible_t nr = { &HASH, host_at, NULL };
	size_t order[N], total = 0, from = 0, shown = 0, i;
	int more = 1;
	char want[160];

	n_hosts = N;
	CHECK(fzn_responsible_order(&HASH, (const uint8_t *)"job/7", 5u,
	                            (const uint8_t (*)[32])members, N, order),
	      "fixture: job/7's order");
	(void)snprintf(want, sizeof(want), "ok 6 0 6 0 ");
	for (i = 0; i < 32u; i++)
		(void)snprintf(want + strlen(want), 3u, "%02x", members[order[0]][i]);
	CHECK(asked(&nr, FZN_ORIGIN_SAME_USER, "list responsible job/7")
	              && strncmp(reply, want, strlen(want)) == 0,
	      "the verb did not list every host, the one responsible first");
	CHECK(asked(&nr, FZN_ORIGIN_SAME_USER, "list responsible job%2F7")
	              && strncmp(reply, want, strlen(want)) == 0,
	      "an escaped key was not the same key");
	/* PAGED: forty hosts do not fit one reply. */
	n_hosts = N;
	CHECK(asked(&nr, FZN_ORIGIN_SAME_USER, "list responsible job/7 5")
	              && sscanf(reply, "ok %zu %zu %zu %d", &total, &from, &shown, &more) == 4
	              && total == 6u && from == 5u && shown == 1u && more == 0,
	      "the page from 5 was not the last host alone");
	CHECK(asked(&nr, FZN_ORIGIN_LOCAL, "list responsible job/7") && strncmp(reply, "denied", 6) == 0,
	      "another user was told who is responsible");
	CHECK(asked(&nr, FZN_ORIGIN_SAME_USER, "list responsible") && strncmp(reply, "malformed", 9) == 0
	              && asked(&nr, FZN_ORIGIN_SAME_USER, "list responsible a x")
	              && strncmp(reply, "malformed", 9) == 0,
	      "no key, or a FROM not a number, was answered");
	CHECK(!asked(&nr, FZN_ORIGIN_SAME_USER, "list leg"), "another verb was taken");
}

/* MORE HOSTS THAN ONE REPLY HOLDS: whole pages, MORE said. */
static uint8_t many[40][32];

static int many_at(void *ctx, size_t i, uint8_t host[32])
{
	(void)ctx;
	if (i >= 40u)
		return 0;
	memcpy(host, many[i], 32u);
	return 1;
}

static void test_many_hosts(void)
{
	fzn_node_responsible_t nr = { &HASH, many_at, NULL };
	size_t total = 0, from = 0, shown = 0, rest = 0, more_shown = 0, i;
	int more = 0, more2 = 1;
	char line[64];

	for (i = 0; i < 40u; i++)
		memset(many[i], (int)(i + 1u), 32u);
	CHECK(asked(&nr, FZN_ORIGIN_SAME_USER, "list responsible x")
	              && sscanf(reply, "ok %zu %zu %zu %d", &total, &from, &shown, &more) == 4
	              && total == 40u && more == 1 && shown > 0u && shown < 40u
	              && strlen(reply) <= FZN_REPLY_MAX,
	      "forty hosts did not page, or a page outgrew a reply");
	/* EVERY PAGE FROM FROM + SHOWN until MORE is 0: forty in all. */
	for (i = 0; i < 10u && more2; i++) {
		(void)snprintf(line, sizeof(line), "list responsible x %zu", shown + rest);
		if (!asked(&nr, FZN_ORIGIN_SAME_USER, line)
		    || sscanf(reply, "ok %zu %zu %zu %d", &total, &from, &more_shown, &more2) != 4)
			break;
		rest += more_shown;
	}
	CHECK(shown + rest == 40u && more2 == 0, "the pages after the first did not hold the rest");
}

int main(void)
{
	test_the_order();
	test_the_verb();
	test_many_hosts();
	if (failures) {
		fprintf(stderr, "node responsible_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("node responsible_test: all %d checks passed\n", checks);
	return 0;
}
