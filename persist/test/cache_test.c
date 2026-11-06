/* cache_test -- `persist/cache.h`, sec 926: the first walk reads the slot, and from
 * then on nothing touches the store; a save and a remove follow what the store took;
 * a row that will not read, and no memory, cost speed and never an answer. */
#include "../cache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures, checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (ok)
		return;
	failures++;
	fprintf(stderr, "  FAIL cache_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, what)

#define ROWS 64u
#define SLOT FZN_PERSIST_CONTACT

/* The store beneath: rows by subject, each read counted. */
static struct {
	int live;
	uint8_t subject[FZN_PUBKEY_LEN];
	uint8_t bytes[FZN_PERSIST_MAX];
	size_t len;
} store[ROWS];
static unsigned loads, walks;
static int refuse_writes, unreadable = -1;

static int at(const uint8_t *subject)
{
	unsigned i;

	for (i = 0; i < ROWS; i++)
		if (store[i].live && memcmp(store[i].subject, subject, FZN_PUBKEY_LEN) == 0)
			return (int)i;
	return -1;
}

static int base_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                     size_t cap, size_t *len)
{
	int i = at(subject);

	(void)ctx;
	(void)slot;
	loads++;
	if (i < 0 || i == unreadable || store[i].len > cap)
		return 0;
	memcpy(out, store[i].bytes, store[i].len);
	*len = store[i].len;
	return 1;
}

static int base_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                     const uint8_t *bytes, size_t len)
{
	int i = at(subject);
	unsigned k;

	(void)ctx;
	(void)slot;
	if (refuse_writes)
		return 0;
	for (k = 0; i < 0 && k < ROWS; k++)
		if (!store[k].live)
			i = (int)k;
	if (i < 0)
		return 0;
	store[i].live = 1;
	memcpy(store[i].subject, subject, FZN_PUBKEY_LEN);
	memcpy(store[i].bytes, bytes, len);
	store[i].len = len;
	return 1;
}

static int base_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	int i = at(subject);

	(void)ctx;
	(void)slot;
	if (refuse_writes)
		return 0;
	if (i >= 0)
		store[i].live = 0;
	return 1;
}

static int base_each(void *ctx, fzn_persist_slot_t slot,
                     int (*fn)(void *arg, const uint8_t subject[FZN_PUBKEY_LEN]), void *arg)
{
	unsigned i;

	(void)ctx;
	(void)slot;
	walks++;
	for (i = 0; i < ROWS; i++)
		if (store[i].live && !fn(arg, store[i].subject))
			break;
	return 1;
}

static const fzn_persist_ops_t BASE = { base_load, base_save, NULL, base_remove, NULL, base_each };

static void key(uint8_t *k, uint8_t n)
{
	memset(k, n, FZN_PUBKEY_LEN);
}

static int counted(void *arg, const uint8_t subject[FZN_PUBKEY_LEN])
{
	(void)subject;
	(*(unsigned *)arg)++;
	return 1;
}

static unsigned count(const fzn_persist_ops_t *ops)
{
	unsigned n = 0;

	CHECK(fzn_persist_each(ops, SLOT, counted, &n), "a walk ended");
	return n;
}

static int reads(const fzn_persist_ops_t *ops, uint8_t n, uint8_t want)
{
	uint8_t k[FZN_PUBKEY_LEN], out[FZN_PERSIST_MAX];
	size_t len = 0;

	key(k, n);
	return ops->load(ops->ctx, SLOT, k, out, sizeof(out), &len) && len == 1u && out[0] == want;
}

static void *no_memory(size_t len)
{
	(void)len;
	return NULL;
}

int main(void)
{
	fzn_persist_cache_t c;
	fzn_persist_ops_t ops;
	uint8_t k[FZN_PUBKEY_LEN], v;
	unsigned i, before;

	for (i = 1; i <= 5u; i++) {
		key(k, (uint8_t)i);
		v = (uint8_t)(i + 100u);
		CHECK(BASE.save(NULL, SLOT, k, &v, 1u), "the store takes a row");
	}
	fzn_persist_cache_init(&c, &BASE, SLOT, &ops);

	/* NOTHING HELD: asked of the store. */
	CHECK(reads(&ops, 1u, 101u), "a row reads before any walk");
	CHECK(loads == 1u, "from the store");

	/* THE FIRST WALK FILLS; AFTER IT, NO STORE. */
	CHECK(count(&ops) == 5u, "the first walk sees every row");
	CHECK(c.whole && c.rows == 5u, "and holds them");
	before = loads;
	walks = 0;
	CHECK(count(&ops) == 5u && walks == 0u, "the next walk does not ask the store");
	CHECK(reads(&ops, 3u, 103u) && loads == before, "a load does not ask the store");
	CHECK(!reads(&ops, 9u, 0u) && loads == before, "nor does a row that is not there");

	/* A SAVE FOLLOWS WHAT THE STORE TOOK. */
	key(k, 3u);
	v = 200u;
	CHECK(ops.save(ops.ctx, SLOT, k, &v, 1u) && reads(&ops, 3u, 200u), "a save reads back");
	CHECK(store[at(k)].bytes[0] == 200u, "and reached the store");
	key(k, 9u);
	v = 109u;
	CHECK(ops.save(ops.ctx, SLOT, k, &v, 1u) && reads(&ops, 9u, 109u) && count(&ops) == 6u,
	      "a new row is held and walked");
	CHECK(ops.remove(ops.ctx, SLOT, k) && !reads(&ops, 9u, 109u) && count(&ops) == 5u
	              && at(k) < 0,
	      "a removed one goes from both");

	/* A STORE THAT REFUSES: this never says what it does not hold. */
	refuse_writes = 1;
	key(k, 2u);
	v = 222u;
	CHECK(!ops.save(ops.ctx, SLOT, k, &v, 1u), "a refused save is refused");
	CHECK(!c.whole, "and the cache knows no longer");
	refuse_writes = 0;
	CHECK(reads(&ops, 2u, 102u), "the store's own row reads");
	CHECK(count(&ops) == 5u && c.whole, "and the next walk makes it whole");
	refuse_writes = 1;
	CHECK(!ops.remove(ops.ctx, SLOT, k) && !c.whole, "a refused remove too");
	refuse_writes = 0;
	CHECK(reads(&ops, 2u, 102u), "and the row is still there");

	/* A ROW THAT WILL NOT READ: walked, and not called absent. */
	fzn_persist_cache_drop(&c);
	key(k, 4u);
	unreadable = at(k);
	CHECK(count(&ops) == 5u && !c.whole, "a walk past an unreadable row sees it, not whole");
	before = loads;
	CHECK(!reads(&ops, 4u, 104u) && loads > before, "and it is asked of the store");
	unreadable = -1;
	CHECK(reads(&ops, 4u, 104u), "so it reads when it can");

	/* NO MEMORY: only slower. */
	fzn_persist_cache_drop(&c);
	c.alloc = no_memory;
	CHECK(count(&ops) == 5u && reads(&ops, 1u, 101u) && !c.whole, "with no memory it all reads");
	key(k, 8u);
	v = 108u;
	CHECK(ops.save(ops.ctx, SLOT, k, &v, 1u) && reads(&ops, 8u, 108u), "and writes");
	c.alloc = NULL;

	/* ANOTHER SLOT IS NOT HELD. */
	key(k, 1u);
	before = loads;
	{
		uint8_t out[FZN_PERSIST_MAX];
		size_t len = 0;

		(void)ops.load(ops.ctx, FZN_PERSIST_TRUST, k, out, sizeof(out), &len);
	}
	CHECK(loads == before + 1u, "another slot goes to the store");
	fzn_persist_cache_drop(&c);

	printf("cache_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
