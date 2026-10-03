/* contact_test -- the contact list: names, one name per key, rename, remove,
 * order and bound, over `persist/`'s seam in memory. sec 435. */

#include "../contact.h"
#include "../group.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (ok)
		return;
	failures++;
	fprintf(stderr, "  FAIL contact_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, what)

#define MEM_ROWS 80u

struct row {
	int used;
	fzn_persist_slot_t slot;
	uint8_t subject[FZN_PUBKEY_LEN];
	uint8_t bytes[2200]; /* a full group: 64 members */
	size_t len;
};

static struct row rows[MEM_ROWS];
static int no_list;

static struct row *find(fzn_persist_slot_t slot, const uint8_t *subject)
{
	size_t i;

	for (i = 0; i < MEM_ROWS; i++)
		if (rows[i].used && rows[i].slot == slot && subject
		    && memcmp(rows[i].subject, subject, FZN_PUBKEY_LEN) == 0)
			return &rows[i];
	return NULL;
}

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	struct row *r = find(slot, subject);

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
	struct row *r = find(slot, subject);
	size_t i;

	(void)ctx;
	for (i = 0; !r && i < MEM_ROWS; i++)
		if (!rows[i].used)
			r = &rows[i];
	if (!r || !subject || len > sizeof(r->bytes))
		return 0;
	r->used = 1;
	r->slot = slot;
	memcpy(r->subject, subject, FZN_PUBKEY_LEN);
	memcpy(r->bytes, bytes, len);
	r->len = len;
	return 1;
}

static int mem_list(void *ctx, fzn_persist_slot_t slot, uint8_t *out, size_t max, size_t *count)
{
	size_t i, n = 0;

	(void)ctx;
	if (no_list)
		return 0;
	for (i = 0; i < MEM_ROWS; i++)
		if (rows[i].used && rows[i].slot == slot) {
			if (n == max)
				return 0;
			memcpy(out + (n * FZN_PUBKEY_LEN), rows[i].subject, FZN_PUBKEY_LEN);
			n++;
		}
	*count = n;
	return 1;
}

static int mem_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	struct row *r = find(slot, subject);

	(void)ctx;
	if (r)
		r->used = 0;
	return 1;
}

static const fzn_persist_ops_t OPS = { mem_load, mem_save, mem_list, mem_remove, NULL };

static void key_of(uint8_t k, uint8_t out[FZN_PUBKEY_LEN])
{
	memset(out, k, FZN_PUBKEY_LEN);
}

static int toy_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	size_t i;

	(void)ctx;
	memset(out, 0x5c, out_len);
	for (i = 0; i < in_len; i++)
		out[i % out_len] = (uint8_t)((out[i % out_len] * 31u) ^ in[i]);
	return 1; /* nonzero is success, as the seam says */
}

static const fzn_hash_ops_t HASH = { toy_hash, NULL };

static int failing_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	(void)ctx;
	(void)in;
	(void)in_len;
	memset(out, 0, out_len);
	return 0;
}

static const fzn_hash_ops_t FAILING = { failing_hash, NULL };

/* GROUPS, sec 471. */
static void test_groups(void)
{
	static fzn_group_t all[FZN_GROUPS_MAX];
	uint8_t a[FZN_PUBKEY_LEN], b[FZN_PUBKEY_LEN], id1[FZN_PUBKEY_LEN], id2[FZN_PUBKEY_LEN];
	uint8_t ids[4][FZN_PUBKEY_LEN];
	fzn_group_t g;
	size_t n = 0, i;
	int ok = 1;

	key_of(0x11, a);
	key_of(0x22, b);
	CHECK(fzn_group_id(&HASH, "family", 6u, id1) == FZN_CONTACT_OK
	              && fzn_group_id(&HASH, "family", 6u, id2) == FZN_CONTACT_OK
	              && memcmp(id1, id2, sizeof(id1)) == 0
	              && fzn_group_id(&HASH, "work", 4u, id2) == FZN_CONTACT_OK
	              && memcmp(id1, id2, sizeof(id1)) != 0,
	      "a group's id is its name's, the same each time and another name's another");
	CHECK(fzn_group_id(&FAILING, "family", 6u, id2) == FZN_CONTACT_ERR_MALFORMED
	              && fzn_group_add(&OPS, &FAILING, "family", 6u, 1u) == FZN_CONTACT_ERR_MALFORMED,
	      "a hash that fails makes no id and no group");
	CHECK(fzn_group_id(&HASH, "fam ily", 7u, id2) == FZN_CONTACT_ERR_NAME
	              && fzn_group_add(&OPS, &HASH, "@x", 2u, 1u) == FZN_CONTACT_ERR_NAME,
	      "a group's name is a contact name, with no space and no @");
	CHECK(fzn_group_add(&OPS, &HASH, "work", 4u, 5u) == FZN_CONTACT_OK
	              && fzn_group_add(&OPS, &HASH, "family", 6u, 6u) == FZN_CONTACT_OK
	              && fzn_group_add(&OPS, &HASH, "family", 6u, 7u) == FZN_CONTACT_ERR_TAKEN,
	      "two groups are made, and a third with a name held is refused");
	CHECK(fzn_group_join(&OPS, &HASH, "family", 6u, a) == FZN_CONTACT_OK
	              && fzn_group_join(&OPS, &HASH, "family", 6u, a) == FZN_CONTACT_OK
	              && fzn_group_join(&OPS, &HASH, "family", 6u, b) == FZN_CONTACT_OK
	              && fzn_group_join(&OPS, &HASH, "work", 4u, b) == FZN_CONTACT_OK
	              && fzn_group_find(&OPS, &HASH, "family", 6u, &g) == FZN_CONTACT_OK
	              && g.count == 2u && memcmp(g.members[0], a, sizeof(a)) == 0
	              && memcmp(g.id, id1, sizeof(id1)) == 0 && g.made_at_ms == 6u,
	      "members join, a second join keeps one, and the group reads back");
	CHECK(fzn_group_ids_of(&OPS, b, ids, 4u, &n) == FZN_CONTACT_OK && n == 2u
	              && fzn_group_ids_of(&OPS, a, ids, 4u, &n) == FZN_CONTACT_OK && n == 1u
	              && memcmp(ids[0], id1, sizeof(id1)) == 0,
	      "the groups a key is in: b in both, a in family alone");
	CHECK(fzn_group_list(&OPS, all, FZN_GROUPS_MAX, &n) == FZN_CONTACT_OK && n == 2u
	              && strcmp(all[0].name, "family") == 0 && strcmp(all[1].name, "work") == 0,
	      "groups list in name order");
	CHECK(fzn_group_leave(&OPS, &HASH, "family", 6u, a) == FZN_CONTACT_OK
	              && fzn_group_leave(&OPS, &HASH, "family", 6u, a) == FZN_CONTACT_ERR_ABSENT
	              && fzn_group_find(&OPS, &HASH, "family", 6u, &g) == FZN_CONTACT_OK
	              && g.count == 1u && memcmp(g.members[0], b, sizeof(b)) == 0,
	      "a member leaves, and leaving again is absent");
	for (i = 0; i < FZN_GROUP_MEMBERS_MAX && ok; i++) {
		uint8_t k[FZN_PUBKEY_LEN];

		memset(k, (int)(0x30 + i), sizeof(k));
		k[1] = (uint8_t)i;
		ok = fzn_group_join(&OPS, &HASH, "work", 4u, k) == FZN_CONTACT_OK
		     || (i == FZN_GROUP_MEMBERS_MAX - 1u);
	}
	CHECK(ok && fzn_group_find(&OPS, &HASH, "work", 4u, &g) == FZN_CONTACT_OK
	              && g.count == FZN_GROUP_MEMBERS_MAX,
	      "a group fills to its bound and reads back whole");
	key_of(0x99, a);
	CHECK(fzn_group_join(&OPS, &HASH, "work", 4u, a) == FZN_CONTACT_ERR_FULL,
	      "one past the bound is refused");
	CHECK(fzn_group_remove(&OPS, &HASH, "work", 4u) == FZN_CONTACT_OK
	              && fzn_group_find(&OPS, &HASH, "work", 4u, &g) == FZN_CONTACT_ERR_ABSENT
	              && fzn_group_remove(&OPS, &HASH, "work", 4u) == FZN_CONTACT_ERR_ABSENT,
	      "a group removed is gone, and removing it again is absent");
	(void)fzn_group_remove(&OPS, &HASH, "family", 6u);
}

int main(void)
{
	static fzn_contact_t all[FZN_CONTACTS_MAX + 4u];
	uint8_t a[FZN_PUBKEY_LEN], b[FZN_PUBKEY_LEN], c[FZN_PUBKEY_LEN];
	fzn_contact_t got;
	size_t n = 0, i;
	int ok = 1;

	test_groups();
	key_of(0xaa, a);
	key_of(0xbb, b);
	key_of(0xcc, c);

	/* ---- names */
	CHECK(fzn_contact_name_ok("alice_2", 7u) && !fzn_contact_name_ok("", 0u)
	              && !fzn_contact_name_ok("al ice", 6u) && !fzn_contact_name_ok("alice-2", 7u)
	              && !fzn_contact_name_ok("x", 0u)
	              && fzn_contact_name_ok("abcdefghijklmnopqrstuvwxyz012345", 32u)
	              && !fzn_contact_name_ok("abcdefghijklmnopqrstuvwxyz0123456", 33u),
	      "a name is 1 to 32 of [A-Za-z0-9_]");
	CHECK(fzn_contact_add(&OPS, a, "al ice", 6u, 1u) == FZN_CONTACT_ERR_NAME,
	      "a name with a space is refused");

	/* ---- add, get, find */
	CHECK(fzn_contact_add(&OPS, a, "alice", 5u, 100u) == FZN_CONTACT_OK, "alice is added");
	CHECK(fzn_contact_get(&OPS, a, &got) == FZN_CONTACT_OK && !strcmp(got.name, "alice")
	              && got.name_len == 5u && got.added_at_ms == 100u,
	      "and read back with when she was added");
	CHECK(fzn_contact_find(&OPS, "alice", 5u, &got) == FZN_CONTACT_OK
	              && memcmp(got.key, a, FZN_PUBKEY_LEN) == 0,
	      "and found by name");
	CHECK(fzn_contact_add(&OPS, b, "alice", 5u, 200u) == FZN_CONTACT_ERR_TAKEN,
	      "a second key under her name is refused");
	CHECK(fzn_contact_add(&OPS, b, "bob", 3u, 200u) == FZN_CONTACT_OK
	              && fzn_contact_add(&OPS, c, "carol", 5u, 300u) == FZN_CONTACT_OK,
	      "bob and carol are added");

	/* ---- rename keeps the time */
	CHECK(fzn_contact_add(&OPS, a, "aaron", 5u, 999u) == FZN_CONTACT_OK
	              && fzn_contact_get(&OPS, a, &got) == FZN_CONTACT_OK && !strcmp(got.name, "aaron")
	              && got.added_at_ms == 100u,
	      "a rename keeps when the contact was added");
	CHECK(fzn_contact_find(&OPS, "alice", 5u, &got) == FZN_CONTACT_ERR_ABSENT,
	      "and the old name is free");

	/* ---- order */
	CHECK(fzn_contact_list(&OPS, all, 8u, &n) == FZN_CONTACT_OK && n == 3u
	              && !strcmp(all[0].name, "aaron") && !strcmp(all[1].name, "bob")
	              && !strcmp(all[2].name, "carol"),
	      "the list is in name order");

	/* ---- remove */
	CHECK(fzn_contact_remove(&OPS, b) == FZN_CONTACT_OK
	              && fzn_contact_get(&OPS, b, &got) == FZN_CONTACT_ERR_ABSENT,
	      "bob is removed");
	CHECK(fzn_contact_remove(&OPS, b) == FZN_CONTACT_ERR_ABSENT,
	      "and removing him again says there is none");

	/* ---- the bound */
	for (i = 0; i < FZN_CONTACTS_MAX && ok; i++) {
		uint8_t k[FZN_PUBKEY_LEN];
		char name[8];

		memset(k, 0, sizeof(k));
		k[0] = 1u;
		k[1] = (uint8_t)i;
		snprintf(name, sizeof(name), "n%02zu", i);
		ok = fzn_contact_add(&OPS, k, name, strlen(name), 1u) == FZN_CONTACT_OK
		     || i >= FZN_CONTACTS_MAX - 2u;
	}
	CHECK(fzn_contact_list(&OPS, all, FZN_CONTACTS_MAX, &n) == FZN_CONTACT_OK
	              && n == FZN_CONTACTS_MAX,
	      "the list fills to its bound");
	CHECK(fzn_contact_add(&OPS, b, "bob", 3u, 1u) == FZN_CONTACT_ERR_FULL,
	      "and a contact past it is refused");
	CHECK(fzn_contact_add(&OPS, a, "aaron_r", 7u, 1u) == FZN_CONTACT_OK,
	      "though renaming one held still works");

	/* ---- damage and a store that cannot list */
	{
		struct row *r = find(FZN_PERSIST_CONTACT, c);

		if (r)
			r->bytes[FZN_PERSIST_HEAD_LEN] = 40u;
		CHECK(r && fzn_contact_get(&OPS, c, &got) == FZN_CONTACT_ERR_SHAPE,
		      "an entry whose name length lies is refused");
	}
	no_list = 1;
	CHECK(fzn_contact_add(&OPS, b, "bob", 3u, 1u) == FZN_CONTACT_ERR_BACKEND
	              && fzn_contact_list(&OPS, all, 8u, &n) == FZN_CONTACT_ERR_BACKEND,
	      "a store that cannot list refuses, rather than adding past names it cannot see");

	if (failures) {
		fprintf(stderr, "contact_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("contact_test: all %d checks passed\n", checks);
	return 0;
}
