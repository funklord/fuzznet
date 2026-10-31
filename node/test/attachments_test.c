/* attachments_test -- what holds a file, and the attachment rules over a
 * conversation's files, sec 795: a hold claimed once and released once, a
 * file removed only at its last hold and only when nothing else names it,
 * and each, all together, a default and a policy weighed by the month. */
#include "../attachments.h"
#include "../file_holds.h"
#include "../../messages/line.h"
#include "../../session/hash_monocypher.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL attachments_test.c:%d: %s\n", line, what);
	}
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

/* ---- a store in memory ------------------------------------------------ */

#define ROWS 1024u

static struct row {
	int used;
	fzn_persist_slot_t slot;
	uint8_t subject[32];
	size_t len;
	uint8_t bytes[128];
} rows[ROWS];

static struct row *find(fzn_persist_slot_t slot, const uint8_t *subject)
{
	size_t i;

	for (i = 0; i < ROWS; i++)
		if (rows[i].used && rows[i].slot == slot && memcmp(rows[i].subject, subject, 32u) == 0)
			return &rows[i];
	return NULL;
}

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	struct row *r = subject ? find(slot, subject) : NULL;

	(void)ctx;
	if (!r || r->len > cap)
		return 0;
	memcpy(out, r->bytes, r->len);
	*len = r->len;
	return 1;
}

static int mem_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                    const uint8_t *bytes, size_t len)
{
	struct row *r = subject ? find(slot, subject) : NULL;
	size_t i;

	(void)ctx;
	if (!subject || len > sizeof(r->bytes))
		return 0;
	for (i = 0; !r && i < ROWS; i++)
		if (!rows[i].used)
			r = &rows[i];
	if (!r)
		return 0;
	r->used = 1;
	r->slot = slot;
	memcpy(r->subject, subject, 32u);
	memcpy(r->bytes, bytes, len);
	r->len = len;
	return 1;
}

static int mem_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	struct row *r = subject ? find(slot, subject) : NULL;

	(void)ctx;
	if (r)
		memset(r, 0, sizeof(*r));
	return 1;
}

static fzn_persist_ops_t STORE = { mem_load, mem_save, NULL, mem_remove, NULL, NULL };
static fzn_hash_ops_t HASH;
static fzn_attachments_t A;
static fzn_file_holds_t H;

/* ---- what the trim is told, and what it asks ------------------------- */

static uint8_t removed[16][32];
static size_t n_removed;
static uint8_t elsewhere[32];
static int refuse_removal;

static int held_elsewhere(void *ctx, const uint8_t root[32])
{
	(void)ctx;
	return memcmp(root, elsewhere, 32u) == 0;
}

static int remove_file(void *ctx, const uint8_t root[32])
{
	(void)ctx;
	if (refuse_removal || n_removed == 16u)
		return 0;
	memcpy(removed[n_removed++], root, 32u);
	return 1;
}

static int was_removed(uint8_t r)
{
	size_t i;

	for (i = 0; i < n_removed; i++)
		if (removed[i][0] == r)
			return 1;
	return 0;
}

static void fresh(void)
{
	memset(rows, 0, sizeof(rows));
	n_removed = 0;
	memset(elsewhere, 0xff, sizeof(elsewhere));
	refuse_removal = 0;
}

/* Contact `c`'s line `n`, of month `epoch`, sending file `r` of `size`. */
static int take(uint8_t c, uint8_t n, uint32_t epoch, uint8_t r, uint64_t size, int *added)
{
	uint8_t contact[32], id[16];
	fzn_attachment_t att;

	memset(contact, c, sizeof(contact));
	memset(id, n, sizeof(id));
	memset(&att, 0, sizeof(att));
	memset(att.root, r, sizeof(att.root));
	memset(att.key, 0x77, sizeof(att.key));
	att.size = size;
	memcpy(att.name, "f", 1u);
	att.name_len = 1u;
	return fzn_attachments_take(&A, contact, FZN_MESSAGE_IN, id, epoch, &att, added);
}

static fzn_retain_rule_t rule(const char *line)
{
	fzn_retain_rule_t r;

	if (fzn_retain_parse(line, strlen(line), &r) != FZN_RETAIN_OK)
		memset(&r, 0, sizeof(r));
	return r;
}

/* October 2026 is month 681: the 10th of it. */
static uint64_t now_ms(void)
{
	return fzn_message_epoch_start(681u) + 9ull * 86400000u;
}

static fzn_attachments_tally_t tally;

static int trim(const fzn_retain_rule_t *r, size_t n)
{
	return fzn_attachments_trim(&A, r, n, now_ms(), held_elsewhere, remove_file, NULL, &tally);
}

/* ---- cases ------------------------------------------------------------- */

static void test_a_hold_is_claimed_and_released_once(void)
{
	uint8_t root[32], other[32], id1[32], id2[32];
	uint64_t count = 9, left = 9;
	int added = -1;

	fresh();
	memset(root, 0x01, sizeof(root));
	memset(other, 0x02, sizeof(other));
	memset(id1, 0x11, sizeof(id1));
	memset(id2, 0x22, sizeof(id2));
	CHECK(!fzn_file_hold_count(&H, root, &count) && count == 0u,
	      "a file never held is not known to the record");
	CHECK(fzn_file_hold_claim(&H, root, FZN_FILE_HOLD_ATTACHMENT, id1, &added) && added == 1
	              && fzn_file_hold_claim(&H, root, FZN_FILE_HOLD_ATTACHMENT, id1, &added)
	              && added == 0 && fzn_file_hold_count(&H, root, &count) && count == 1u,
	      "a hold claimed twice is one hold");
	CHECK(fzn_file_hold_claim(&H, root, FZN_FILE_HOLD_ATTACHMENT, id2, &added) && added == 1
	              && fzn_file_hold_count(&H, root, &count) && count == 2u,
	      "a second line's hold is a second");
	CHECK(fzn_file_hold_release(&H, root, FZN_FILE_HOLD_ATTACHMENT, id1, &left) && left == 1u
	              && fzn_file_hold_release(&H, root, FZN_FILE_HOLD_ATTACHMENT, id1, &left)
	              && left == 1u && !fzn_file_hold_has(&H, root, FZN_FILE_HOLD_ATTACHMENT, id1)
	              && fzn_file_hold_has(&H, root, FZN_FILE_HOLD_ATTACHMENT, id2),
	      "released once, and released again changes nothing");
	CHECK(fzn_file_hold_release(&H, other, FZN_FILE_HOLD_ATTACHMENT, id1, &left) && left == 0u
	              && !fzn_file_hold_count(&H, other, &count),
	      "releasing a file not held writes nothing");
	CHECK(!fzn_file_holds_begun(&H) && fzn_file_holds_begin(&H) && fzn_file_holds_begun(&H),
	      "the record begins once, and says so");
}

static void test_a_line_noted_once(void)
{
	uint8_t contact[32];
	int added = -1;

	fresh();
	memset(contact, 0xc1, sizeof(contact));
	CHECK(take(0xc1, 1, 680u, 0x01, 10u, &added) && added == 1
	              && take(0xc1, 1, 680u, 0x01, 10u, &added) && added == 0
	              && fzn_attachments_count(&A, contact) == 1u,
	      "a line told twice is noted once");
}

/* x's attachments, ten bytes a month, August to October; a file of each. */
static int three_months(void)
{
	int added = 0;

	fresh();
	return take(0xc1, 1, 679u, 0x01, 10u, &added) && take(0xc1, 2, 680u, 0x02, 10u, &added)
	       && take(0xc1, 3, 681u, 0x03, 10u, &added);
}

static void test_the_rules_let_go_by_the_month(void)
{
	fzn_retain_rule_t r[2];
	uint64_t count = 9;
	uint8_t root[32];

	CHECK(three_months(), "fixture: x, ten bytes a month, August to October");
	r[0] = rule("prune attachments size 15");
	CHECK(trim(r, 1u) && tally.months == 1u && tally.removed == 1u && was_removed(0x01)
	              && !was_removed(0x02) && !was_removed(0x03),
	      "fifteen bytes reach into September: August's file goes, its last hold released");
	memset(root, 0x01, sizeof(root));
	CHECK(fzn_file_hold_count(&H, root, &count) && count == 0u,
	      "and nothing holds it any more");
	CHECK(trim(r, 1u) && tally.months == 0u && tally.released == 0u,
	      "trimming again finds nothing more");
	CHECK(three_months(), "fixture: again");
	r[0] = rule("prune attachments age 1d");
	CHECK(trim(r, 1u) && tally.months == 2u && !was_removed(0x03),
	      "the current month never goes, however old the rule says");
	CHECK(three_months(), "fixture: again");
	r[0] = rule("prune attachments size 0");
	CHECK(r[0].data == FZN_RETAIN_ATTACHMENTS && trim(r, 1u) && tally.months == 2u
	              && !was_removed(0x03),
	      "a limit of nothing prunes every month, and still the current one stays");
	CHECK(three_months(), "fixture: again");
	r[0] = rule("policy attachments drop");
	r[1] = rule("keep attachments age 20d");
	CHECK(trim(r, 2u) && tally.months == 1u && was_removed(0x01) && !was_removed(0x02),
	      "under drop a keep of 20 days holds September, ending nine days ago, and August goes");
	CHECK(three_months(), "fixture: again");
	r[0] = rule("prune messages size 1");
	CHECK(trim(r, 1u) && tally.months == 0u && n_removed == 0u,
	      "a message rule is not an attachment rule");
}

static void test_a_file_held_otherwise_stays(void)
{
	fzn_retain_rule_t r = rule("prune attachments size 15");
	uint8_t root[32], legacy[32];
	int added = 0;

	CHECK(three_months(), "fixture: x, ten bytes a month");
	memset(elsewhere, 0x01, sizeof(elsewhere));
	CHECK(trim(&r, 1u) && tally.months == 1u && tally.released == 1u && n_removed == 0u,
	      "a file the catalogue or a saved pack names is released and not removed");
	CHECK(three_months() && take(0xc2, 9, 681u, 0x01, 10u, &added) && added == 1,
	      "fixture: August's file also sent to y this month");
	CHECK(trim(&r, 1u) && tally.released == 1u && n_removed == 0u,
	      "a file another line still holds is released and not removed");
	CHECK(three_months(), "fixture: again");
	memset(root, 0x01, sizeof(root));
	memset(legacy, 0, sizeof(legacy));
	CHECK(fzn_file_hold_claim(&H, root, FZN_FILE_HOLD_LEGACY, legacy, &added) && added == 1,
	      "fixture: August's file held from before the record");
	CHECK(trim(&r, 1u) && tally.released == 1u && n_removed == 0u,
	      "a file held before the record began is never removed");
}

static void test_a_removal_that_cannot_run_waits(void)
{
	fzn_retain_rule_t r = rule("prune attachments size 15");

	CHECK(three_months(), "fixture: x, ten bytes a month");
	refuse_removal = 1;
	CHECK(trim(&r, 1u) && tally.waiting == 1u && tally.released == 0u,
	      "a file in a transfer is not removed, and its hold stays");
	refuse_removal = 0;
	CHECK(trim(&r, 1u) && tally.removed == 1u && was_removed(0x01),
	      "and the next trim removes it");
}

static void test_each_all_and_a_default(void)
{
	fzn_retain_rule_t r[2];
	char line[160];
	size_t i;
	int added = 0;

	/* x and y, ten bytes a month each, August to October. */
	CHECK(three_months() && take(0xc2, 4, 679u, 0x04, 10u, &added)
	              && take(0xc2, 5, 680u, 0x05, 10u, &added)
	              && take(0xc2, 6, 681u, 0x06, 10u, &added),
	      "fixture: x and y");
	r[0] = rule("prune attachments contact=all size 15");
	CHECK(trim(r, 1u) && tally.months == 4u && was_removed(0x01) && was_removed(0x02)
	              && was_removed(0x04) && was_removed(0x05) && !was_removed(0x03),
	      "all together: October's twenty bytes are past fifteen, so both lose September "
	      "and August");
	CHECK(three_months() && take(0xc2, 4, 679u, 0x04, 10u, &added), "fixture: x, and y in August");
	r[0] = rule("prune attachments default size 15");
	snprintf(line, sizeof(line), "keep attachments contact=");
	for (i = 0; i < 32u; i++)
		snprintf(line + strlen(line), 3u, "c1");
	snprintf(line + strlen(line), sizeof(line) - strlen(line), " count 100");
	r[1] = rule(line);
	CHECK(r[1].has_contact && trim(r, 2u) && !was_removed(0x01) && n_removed == 0u,
	      "x's own rule keeps its August; y's August is its newest and stays");
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
	fzn_hash_monocypher_init(&HASH);
	A.store = &STORE;
	A.hash = &HASH;
	H.store = &STORE;
	H.hash = &HASH;
	test_a_hold_is_claimed_and_released_once();
	test_a_line_noted_once();
	test_the_rules_let_go_by_the_month();
	test_a_file_held_otherwise_stays();
	test_a_removal_that_cannot_run_waits();
	test_each_all_and_a_default();
	test_the_suite_can_tell_pass_from_fail();
	printf("attachments_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
