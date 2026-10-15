/* node file_refs_test -- the references of the estate's files, sec 634:
 * kept under their root, read back, the first standing against a second
 * key under one root. A store in memory. */

#include "../file_refs.h"

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                  \
	do {                                                                               \
		checks++;                                                                  \
		if (!(cond)) {                                                             \
			failures++;                                                        \
			fprintf(stderr, "  FAIL file_refs_test.c:%d: %s\n", __LINE__, what); \
		}                                                                          \
	} while (0)

#define ROWS 8u

static struct {
	int used;
	uint8_t subject[32];
	uint8_t bytes[FZN_NODE_FILE_REF_LEN];
	size_t len;
} rows[ROWS];

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	size_t i;

	(void)ctx;
	for (i = 0; i < ROWS; i++)
		if (rows[i].used && slot == FZN_PERSIST_FILE_REF
		    && memcmp(rows[i].subject, subject, 32u) == 0 && rows[i].len <= cap) {
			memcpy(out, rows[i].bytes, rows[i].len);
			*len = rows[i].len;
			return 1;
		}
	return 0;
}

static int mem_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                    const uint8_t *bytes, size_t len)
{
	size_t i;

	(void)ctx;
	if (slot != FZN_PERSIST_FILE_REF || len > FZN_NODE_FILE_REF_LEN)
		return 0;
	for (i = 0; i < ROWS; i++)
		if (!rows[i].used || memcmp(rows[i].subject, subject, 32u) == 0) {
			rows[i].used = 1;
			memcpy(rows[i].subject, subject, 32u);
			memcpy(rows[i].bytes, bytes, len);
			rows[i].len = len;
			return 1;
		}
	return 0;
}

static const fzn_persist_ops_t STORE = { mem_load, mem_save, NULL, NULL, NULL };

static void test_a_reference_kept_and_the_first_standing(void)
{
	uint8_t ref[FZN_NODE_FILE_REF_LEN], other[FZN_NODE_FILE_REF_LEN], got[FZN_NODE_FILE_REF_LEN];
	uint8_t root[FZN_BLOB_HASH_LEN];

	memset(ref, 0x11, sizeof(ref));
	memset(ref + FZN_BLOB_HASH_LEN, 0x22, FZN_BLOB_KEY_LEN);
	memcpy(root, ref, sizeof(root));
	CHECK(!fzn_node_file_ref_get(&STORE, root, got), "a reference never kept was held");
	CHECK(fzn_node_file_ref_keep(&STORE, ref) && fzn_node_file_ref_get(&STORE, root, got)
	              && memcmp(got, ref, sizeof(ref)) == 0,
	      "a reference did not read back under its root");
	CHECK(fzn_node_file_ref_keep(&STORE, ref), "the same reference again was refused");
	memcpy(other, ref, sizeof(other));
	other[FZN_BLOB_HASH_LEN] ^= 1u; /* another key under the same root */
	CHECK(!fzn_node_file_ref_keep(&STORE, other) && fzn_node_file_ref_get(&STORE, root, got)
	              && memcmp(got, ref, sizeof(ref)) == 0,
	      "a second key under one root replaced the first");
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
	test_a_reference_kept_and_the_first_standing();
	if (failures) {
		fprintf(stderr, "node file_refs_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("node file_refs_test: all %d checks passed\n", checks);
	return 0;
}
