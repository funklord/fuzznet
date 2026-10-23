/* heard_test -- when this node last heard from each host, sec 601: kept
 * per host, read back, never moved earlier, and absent until first heard.
 *
 * An in-memory store; no files, no forks, fixed loops.
 */

#include "../heard.h"

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                \
	do {                                                                             \
		checks++;                                                                \
		if (!(cond)) {                                                           \
			failures++;                                                      \
			fprintf(stderr, "  FAIL heard_test.c:%d: %s\n", __LINE__, what); \
		}                                                                        \
	} while (0)

#define ROWS 8

static struct row {
	int used;
	fzn_persist_slot_t slot;
	uint8_t subject[32];
	uint8_t bytes[64];
	size_t len;
} rows[ROWS];

static struct row *row_of(fzn_persist_slot_t slot, const uint8_t *subject, int make)
{
	int i;

	for (i = 0; i < ROWS; i++)
		if (rows[i].used && rows[i].slot == slot && memcmp(rows[i].subject, subject, 32u) == 0)
			return &rows[i];
	for (i = 0; make && i < ROWS; i++)
		if (!rows[i].used) {
			rows[i].used = 1;
			rows[i].slot = slot;
			memcpy(rows[i].subject, subject, 32u);
			return &rows[i];
		}
	return NULL;
}

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	struct row *r = row_of(slot, subject, 0);

	(void)ctx;
	if (!r || r->len > cap)
		return 0;
	memcpy(out, r->bytes, r->len);
	*len = r->len;
	return 1;
}

static int fail_saves;

static int mem_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                    const uint8_t *bytes, size_t len)
{
	struct row *r;

	(void)ctx;
	if (fail_saves || !(r = row_of(slot, subject, 1)) || len > sizeof(r->bytes))
		return 0;
	memcpy(r->bytes, bytes, len);
	r->len = len;
	return 1;
}

static fzn_persist_ops_t STORE = { mem_load, mem_save, NULL, NULL, NULL, NULL };

int main(void)
{
	uint8_t a[32], b[32];
	uint64_t at = 9;
	struct row *r;

	memset(a, 0xaa, sizeof(a));
	memset(b, 0xbb, sizeof(b));
	CHECK(fzn_heard_when(&STORE, a, &at) == FZN_HEARD_ABSENT && at == 0u,
	      "a host never heard from was heard");
	CHECK(fzn_heard_mark(&STORE, a, 1000u) == FZN_HEARD_OK
	          && fzn_heard_when(&STORE, a, &at) == FZN_HEARD_OK && at == 1000u,
	      "a host heard at 1000 did not read back so");
	CHECK(fzn_heard_when(&STORE, b, &at) == FZN_HEARD_ABSENT,
	      "hearing one host made another heard");
	/* NEVER EARLIER: a clock stepped back leaves the later time. */
	CHECK(fzn_heard_mark(&STORE, a, 500u) == FZN_HEARD_OK
	          && fzn_heard_when(&STORE, a, &at) == FZN_HEARD_OK && at == 1000u,
	      "an earlier time moved a host's back");
	CHECK(fzn_heard_mark(&STORE, a, 2000u) == FZN_HEARD_OK
	          && fzn_heard_when(&STORE, a, &at) == FZN_HEARD_OK && at == 2000u,
	      "a later time did not move a host's on");
	/* IN ITS OWN SLOT, as `node/heard.situ` lays it out. */
	r = row_of(FZN_PERSIST_HOST_HEARD, a, 0);
	CHECK(r && r->len == 9u && r->bytes[0] == 1u && r->bytes[7] == 0x07u && r->bytes[8] == 0xd0u,
	      "the row is not version 1 and 2000 big-endian");
	/* A ROW NOT ONE IS NOT A TIME. */
	r->bytes[0] = 2u;
	CHECK(fzn_heard_when(&STORE, a, &at) == FZN_HEARD_ABSENT, "a version-2 row was read");
	r->bytes[0] = 1u;
	fail_saves = 1;
	CHECK(fzn_heard_mark(&STORE, b, 10u) == FZN_HEARD_BACKEND, "a refused write was OK");
	fail_saves = 0;
	CHECK(fzn_heard_mark(NULL, a, 1u) == FZN_HEARD_MALFORMED
	          && fzn_heard_when(&STORE, NULL, &at) == FZN_HEARD_MALFORMED,
	      "a missing store or host was not malformed");
	if (failures) {
		fprintf(stderr, "heard_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("heard_test: all %d checks passed\n", checks);
	return 0;
}
