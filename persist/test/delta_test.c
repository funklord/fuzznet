/* A store that goes on when its disk will not: persist/delta.h. The store
 * beneath is a table here, told when to refuse. */

#include "../delta.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures, checks;

#define CHECK(c, what)                                                       \
	do {                                                                     \
		checks++;                                                            \
		if (!(c)) {                                                          \
			failures++;                                                      \
			fprintf(stderr, "  FAIL delta_test.c:%d: %s\n", __LINE__, what); \
		}                                                                    \
	} while (0)

#define ROWS 64u

static struct {
	int used;
	fzn_persist_slot_t slot;
	uint8_t subject[FZN_PUBKEY_LEN];
	uint8_t bytes[256];
	size_t len;
} disk[ROWS];
static int refusing, refuse_after = -1, writes;

static int at(fzn_persist_slot_t slot, const uint8_t *subject)
{
	unsigned i;

	for (i = 0; i < ROWS; i++)
		if (disk[i].used && disk[i].slot == slot
		    && memcmp(disk[i].subject, subject, FZN_PUBKEY_LEN) == 0)
			return (int)i;
	return -1;
}

static int d_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                  size_t cap, size_t *len)
{
	int i = at(slot, subject);

	(void)ctx;
	if (i < 0 || disk[i].len > cap)
		return 0;
	memcpy(out, disk[i].bytes, disk[i].len);
	*len = disk[i].len;
	return 1;
}

static int d_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, const uint8_t *bytes,
                  size_t len)
{
	int i = at(slot, subject);
	unsigned k;

	(void)ctx;
	writes++;
	if (refusing || refuse_after == 0)
		return 0;
	if (refuse_after > 0)
		refuse_after--;
	if (i < 0)
		for (k = 0; k < ROWS && i < 0; k++)
			if (!disk[k].used)
				i = (int)k;
	disk[i].used = 1;
	disk[i].slot = slot;
	memcpy(disk[i].subject, subject, FZN_PUBKEY_LEN);
	memcpy(disk[i].bytes, bytes, len);
	disk[i].len = len;
	return 1;
}

static int d_list(void *ctx, fzn_persist_slot_t slot, uint8_t *out, size_t max, size_t *count)
{
	unsigned i;
	size_t n = 0;

	(void)ctx;
	for (i = 0; i < ROWS; i++)
		if (disk[i].used && disk[i].slot == slot) {
			if (n == max)
				return 0;
			memcpy(out + n++ * FZN_PUBKEY_LEN, disk[i].subject, FZN_PUBKEY_LEN);
		}
	*count = n;
	return 1;
}

static int d_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	int i = at(slot, subject);

	(void)ctx;
	if (refusing)
		return 0;
	if (i >= 0)
		disk[i].used = 0;
	return 1;
}

static const fzn_persist_ops_t BASE = { d_load, d_save, d_list, d_remove, NULL, NULL };

static void key(uint8_t *k, uint8_t n)
{
	memset(k, 0, FZN_PUBKEY_LEN);
	k[0] = n;
	k[31] = (uint8_t)(n * 3u);
}

static int reads(const fzn_persist_ops_t *o, fzn_persist_slot_t slot, uint8_t n, const char *want)
{
	uint8_t k[FZN_PUBKEY_LEN], out[256];
	size_t len = 0;

	key(k, n);
	if (!o->load(o->ctx, slot, k, out, sizeof(out), &len))
		return want == NULL;
	return want && len == strlen(want) && memcmp(out, want, len) == 0;
}

static int put(const fzn_persist_ops_t *o, fzn_persist_slot_t slot, uint8_t n, const char *v)
{
	uint8_t k[FZN_PUBKEY_LEN];

	key(k, n);
	return o->save(o->ctx, slot, k, (const uint8_t *)v, strlen(v));
}

static size_t walked_n;
static int walk_stop_at;

static int count_walk(void *arg, const uint8_t subject[FZN_PUBKEY_LEN])
{
	(void)arg;
	(void)subject;
	walked_n++;
	return !(walk_stop_at && (int)walked_n == walk_stop_at);
}

/* AN ALLOCATOR THAT REFUSES when told. */
static int alloc_refuses;

static void *alloc_maybe(size_t len)
{
	return alloc_refuses ? NULL : malloc(len);
}

int main(void)
{
	static fzn_persist_delta_t d;
	fzn_persist_ops_t o;
	fzn_persist_delta_status_t st;
	uint8_t k[FZN_PUBKEY_LEN], list[8 * FZN_PUBKEY_LEN];
	size_t n = 0;
	unsigned slot;

	fzn_persist_delta_init(&d, &BASE, 0u, &o);

	/* A WORKING STORE: straight through, nothing held. */
	CHECK(put(&o, FZN_PERSIST_SETTING, 1u, "one") && reads(&o, FZN_PERSIST_SETTING, 1u, "one"),
	      "a save through a working store did not read");
	fzn_persist_delta_status(&d, &st);
	CHECK(st.rows == 0u && !st.stuck, "a working store left rows held");

	/* REFUSED: held, read, and the store left alone after the first. */
	refusing = 1;
	writes = 0;
	CHECK(put(&o, FZN_PERSIST_SETTING, 1u, "two"), "a refused save was not held");
	CHECK(put(&o, FZN_PERSIST_SETTING, 2u, "new"), "a second was not held");
	CHECK(writes == 1, "the store was asked again after it refused");
	CHECK(reads(&o, FZN_PERSIST_SETTING, 1u, "two") && reads(&o, FZN_PERSIST_SETTING, 2u, "new"),
	      "what is held did not read over the store");
	CHECK(put(&o, FZN_PERSIST_SETTING, 1u, "three") && d.rows == 2u,
	      "a key saved again was not one row");

	/* REMOVED WHILE REFUSED: reads as gone, and lists as gone. */
	CHECK(put(&o, FZN_PERSIST_GRANT, 3u, "x") && o.remove(o.ctx, FZN_PERSIST_SETTING, (key(k, 2u), k)),
	      "a remove was not held");
	CHECK(reads(&o, FZN_PERSIST_SETTING, 2u, NULL), "a row removed here still read");
	refusing = 0;
	key(k, 9u);
	(void)d_save(NULL, FZN_PERSIST_SETTING, k, (const uint8_t *)"disk", 4u);
	refusing = 1;
	CHECK(o.remove(o.ctx, FZN_PERSIST_SETTING, k) && reads(&o, FZN_PERSIST_SETTING, 9u, NULL),
	      "a store's row removed here still read");
	n = 0;
	CHECK(o.list(o.ctx, FZN_PERSIST_SETTING, list, 8u, &n) && n == 1u
	              && list[0] == 1u,
	      "a list did not show the store less what was removed plus what is new");
	walked_n = 0;
	walk_stop_at = 0;
	CHECK(o.each(o.ctx, FZN_PERSIST_SETTING, count_walk, NULL) && walked_n == 1u,
	      "a walk did not agree with the list");
	key(k, 40u);
	CHECK(put(&o, FZN_PERSIST_SETTING, 40u, "a") && put(&o, FZN_PERSIST_SETTING, 41u, "b"),
	      "fixture: more held");
	walked_n = 0;
	walk_stop_at = 2;
	CHECK(o.each(o.ctx, FZN_PERSIST_SETTING, count_walk, NULL) && walked_n == 2u,
	      "a walk went on past a stop");
	walk_stop_at = 0;
	n = 0;
	CHECK(!o.list(o.ctx, FZN_PERSIST_SETTING, list, 2u, &n), "a short list was given as whole");

	/* FLUSHED: everything on the disk, in the order it came. */
	refusing = 0;
	CHECK(fzn_persist_delta_flush(&d) > 0u, "nothing flushed");
	fzn_persist_delta_status(&d, &st);
	CHECK(st.rows == 0u && !st.stuck, "a flush left rows or the store believed refusing");
	CHECK(at(FZN_PERSIST_SETTING, (key(k, 2u), k)) < 0, "a remove did not reach the store");
	CHECK(at(FZN_PERSIST_SETTING, (key(k, 9u), k)) < 0, "a remove of the store's row did not reach it");
	CHECK(at(FZN_PERSIST_SETTING, (key(k, 1u), k)) >= 0
	              && memcmp(disk[at(FZN_PERSIST_SETTING, k)].bytes, "three", 5u) == 0,
	      "the newest did not reach the store");

	/* A STORE THAT FILLS PARTWAY THROUGH A FLUSH: a prefix, and the rest held. */
	refusing = 1;
	(void)put(&o, FZN_PERSIST_SETTING, 20u, "a");
	(void)put(&o, FZN_PERSIST_SETTING, 21u, "b");
	(void)put(&o, FZN_PERSIST_SETTING, 22u, "c");
	refusing = 0;
	refuse_after = 1;
	CHECK(fzn_persist_delta_flush(&d) == 1u, "a flush went past a refusal");
	CHECK(at(FZN_PERSIST_SETTING, (key(k, 20u), k)) >= 0 && at(FZN_PERSIST_SETTING, (key(k, 21u), k)) < 0,
	      "not the oldest went first");
	CHECK(d.stuck && reads(&o, FZN_PERSIST_SETTING, 22u, "c"), "the rest were not still held");
	refuse_after = -1;
	(void)fzn_persist_delta_flush(&d);
	CHECK(d.rows == 0u, "the rest did not flush");
	fzn_persist_delta_free(&d);

	/* WHAT GOES FIRST: lowest rank, then oldest; control never. */
	fzn_persist_delta_init(&d, &BASE, 10u, &o);
	refusing = 1;
	CHECK(put(&o, FZN_PERSIST_ROUTING, 1u, "aaaa") && put(&o, FZN_PERSIST_GROUP_LINE, 2u, "bbbb"),
	      "fixture: a trace and a copy held");
	CHECK(put(&o, FZN_PERSIST_MESSAGE_LINE, 3u, "cccc"), "a user's row did not push out a trace");
	CHECK(reads(&o, FZN_PERSIST_ROUTING, 1u, NULL) && reads(&o, FZN_PERSIST_GROUP_LINE, 2u, "bbbb")
	              && d.dropped == 1u,
	      "not the lowest rank went first");
	CHECK(put(&o, FZN_PERSIST_MESSAGE_LINE, 4u, "dddd"), "a user's row did not push out a copy");
	CHECK(reads(&o, FZN_PERSIST_GROUP_LINE, 2u, NULL), "the copy stayed");
	CHECK(!put(&o, FZN_PERSIST_ROUTING, 5u, "eeeeeeee"), "a trace pushed out what outranks it");
	CHECK(reads(&o, FZN_PERSIST_MESSAGE_LINE, 3u, "cccc") && d.refused == 1u,
	      "a row was lost to one below it");
	CHECK(put(&o, FZN_PERSIST_SETTING, 6u, "a setting far past the budget") && put(&o, FZN_PERSIST_GRANT, 7u, "g"),
	      "control was refused for want of budget");
	CHECK(reads(&o, FZN_PERSIST_SETTING, 6u, "a setting far past the budget"), "control was shed");
	fzn_persist_delta_free(&d);

	/* THE ALLOCATOR REFUSES: what can go, goes; then it says no. */
	fzn_persist_delta_init(&d, &BASE, 0u, &o);
	d.alloc = alloc_maybe;
	(void)put(&o, FZN_PERSIST_SETTING, 1u, "kept");
	alloc_refuses = 1;
	CHECK(!put(&o, FZN_PERSIST_SETTING, 2u, "x"), "a row was claimed held with no memory");
	CHECK(reads(&o, FZN_PERSIST_SETTING, 1u, "kept") && d.rows == 1u, "a refusal cost a held row");
	alloc_refuses = 0;
	fzn_persist_delta_free(&d);
	refusing = 0;

	/* EVERY SLOT IS RANKED, and nothing that keeps an attacker out is sheddable. */
	for (slot = 1; slot < FZN_PERSIST_SLOT_END; slot++)
		if (fzn_persist_slot_is_core((fzn_persist_slot_t)slot)
		    && slot != FZN_PERSIST_NOTE_SHARE && slot != FZN_PERSIST_FILE_SHARE
		    && slot != FZN_PERSIST_FILE_REF && slot != FZN_PERSIST_NOTE_PURGED)
			CHECK(fzn_persist_slot_rank((fzn_persist_slot_t)slot) >= FZN_RANK_CONTROL,
			      "a core slot may be shed");
	CHECK(fzn_persist_slot_rank(FZN_PERSIST_OWN_IDENTITY) == FZN_RANK_IDENTITY
	              && fzn_persist_slot_rank((fzn_persist_slot_t)250) == FZN_RANK_IDENTITY,
	      "an identity, or a slot nobody ranked, was not kept highest");

	printf("delta_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
