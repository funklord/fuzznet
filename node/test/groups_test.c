/* node groups_test -- a group's epochs, sec 627: each host of a member
 * named in the log, the current epoch's secret drawn by one host and sealed
 * to every other, a later member backfilled newest first or not at all, a
 * removed member given nothing after, and a secret drawn on the losing side
 * of a fork forgotten. Three users, each its own host with its own store;
 * the sync between them stands in as copying acts across. Real X25519,
 * BLAKE2b and XChaCha20-Poly1305 for the boxes; stub signatures keyed by a
 * key's first byte, as group_log_test's. */

#include "../groups.h"
#include "../group_line.h"
#include "../group_lines.h"
#include "../../session/aead_monocypher.h"
#include "../../session/agree_monocypher.h"
#include "../../session/hash_monocypher.h"
#include "../../session/random_system.h"

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                               \
	do {                                                                            \
		checks++;                                                               \
		if (!(cond)) {                                                          \
			failures++;                                                     \
			fprintf(stderr, "  FAIL groups_test.c:%d: %s\n", __LINE__, what); \
		}                                                                       \
	} while (0)

static fzn_agree_ops_t AGREE;
static fzn_hash_ops_t HASH;
static fzn_aead_ops_t AEAD;
static fzn_random_ops_t RNG;

static void mac(uint8_t out[FZN_SIG_LEN], uint8_t key, const uint8_t *msg, size_t len)
{
	uint64_t h = 0xcbf29ce484222325ull ^ key;
	size_t i;

	for (i = 0; i < len; i++)
		h = (h ^ msg[i]) * 0x100000001b3ull;
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h = (h ^ (uint64_t)i) * 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 56);
	}
}

/* SIGNS AS the user whose key's first byte `ctx` points at. */
static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t len)
{
	mac(sig, *(const uint8_t *)ctx, msg, len);
	return 1;
}

static int stub_verify(void *ctx, const uint8_t pk[FZN_PUBKEY_LEN], const uint8_t *msg, size_t len,
                       const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	mac(want, pk[0], msg, len);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

static uint64_t fixed_clock(void)
{
	return 5000u;
}

/* ---- a store per host --------------------------------------------------- */

#define ROWS 160u
#define ROW_MAX 8192u

struct row {
	int used;
	fzn_persist_slot_t slot;
	uint8_t subject[32];
	uint8_t bytes[ROW_MAX];
	size_t len;
};

struct store {
	struct row rows[ROWS];
};

static struct row *find(struct store *m, fzn_persist_slot_t slot, const uint8_t *subject)
{
	size_t i;

	for (i = 0; i < ROWS; i++)
		if (m->rows[i].used && m->rows[i].slot == slot
		    && memcmp(m->rows[i].subject, subject, 32u) == 0)
			return &m->rows[i];
	return NULL;
}

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	struct row *r = find(ctx, slot, subject);

	if (!r || r->len > cap)
		return 0;
	memcpy(out, r->bytes, r->len);
	*len = r->len;
	return 1;
}

static int mem_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                    const uint8_t *bytes, size_t len)
{
	struct store *m = ctx;
	struct row *r = find(m, slot, subject);
	size_t i;

	if (len > ROW_MAX)
		return 0;
	for (i = 0; !r && i < ROWS; i++)
		if (!m->rows[i].used)
			r = &m->rows[i];
	if (!r)
		return 0;
	r->used = 1;
	r->slot = slot;
	memcpy(r->subject, subject, 32u);
	memcpy(r->bytes, bytes, len);
	r->len = len;
	return 1;
}

static int mem_list(void *ctx, fzn_persist_slot_t slot, uint8_t *out, size_t max, size_t *count)
{
	struct store *m = ctx;
	size_t i, n = 0;

	for (i = 0; i < ROWS; i++)
		if (m->rows[i].used && m->rows[i].slot == slot) {
			if (n == max)
				return 0;
			memcpy(out + 32u * n++, m->rows[i].subject, 32u);
		}
	*count = n;
	return 1;
}

/* REMOVALS LEFT TO FAIL, sec 746: a store that refuses the next ones. */
static int removes_failing;

static int mem_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	struct row *r = find(ctx, slot, subject);

	if (removes_failing > 0) {
		removes_failing--;
		return 0;
	}
	if (r)
		r->used = 0;
	return 1;
}

/* How many rows of `slot` the store holds. */
static size_t rows_of(const struct store *m, fzn_persist_slot_t slot)
{
	size_t i, n = 0;

	for (i = 0; i < ROWS; i++)
		n += m->rows[i].used && m->rows[i].slot == slot;
	return n;
}

/* ---- a user, its one host ----------------------------------------------- */

struct user {
	uint8_t first;
	struct store store;
	fzn_persist_ops_t ops;
	fzn_sign_ops_t sign;
	fzn_agree_secret_t agree_secret;
	fzn_contact_device_t device;
	fzn_node_groups_t groups;
};

static fzn_cap_id_t member;
static struct user users[3];

static int signer(void *ctx, fzn_contact_device_t *out)
{
	*out = ((struct user *)ctx)->device;
	return 1;
}

static void user_up(struct user *u, uint8_t first)
{
	uint8_t seed[FZN_AGREE_SECRET_LEN];

	memset(u, 0, sizeof(*u));
	u->first = first;
	u->ops = (fzn_persist_ops_t){ mem_load, mem_save, mem_list, mem_remove, &u->store };
	u->sign = (fzn_sign_ops_t){ stub_verify, stub_sign, &u->first };
	memset(seed, first ^ 0x3cu, sizeof(seed));
	(void)fzn_agree_secret_install(&u->agree_secret, &AGREE, seed);
	memset(u->device.owner, first, FZN_PUBKEY_LEN);
	(void)fzn_prekey_issue(u->device.owner, fzn_agree_secret_public(&u->agree_secret), 1000u,
	                       &u->sign, u->device.record);
	u->groups.log.store = &u->ops;
	u->groups.log.hash = &HASH;
	u->groups.log.sign = &u->sign;
	u->groups.log.member = &member;
	u->groups.host_sign = &u->sign;
	u->groups.signer = signer;
	u->groups.signer_ctx = u;
	u->groups.rng = &RNG;
	u->groups.clock = fixed_clock;
	u->groups.agree = &AGREE;
	u->groups.aead = &AEAD;
	u->groups.agree_secret = &u->agree_secret;
}

/* EVERY ACT `from` HOLDS OF GROUP `id`, offered to `to`, in order: what a
 * sync carries. */
static void sync(const struct user *from, struct user *to, const uint8_t *id)
{
	static uint8_t bytes[FZN_GROUP_ACT_MAX];
	static fzn_group_t g;
	fzn_group_offer_t did;
	size_t n = 0, dropped = 0;
	uint32_t s;

	if (fzn_group_log_get(&from->ops, id, &g) != FZN_GROUP_LOG_OK)
		return;
	for (s = 0; s < g.seq; s++)
		if (fzn_group_log_act(&from->groups.log, id, s, bytes, sizeof(bytes), &n)
		    == FZN_GROUP_LOG_OK)
			(void)fzn_group_log_offer(&to->groups.log, bytes, n, &did, &dropped);
}

static int same_secret(struct user *a, struct user *b, const uint8_t *id, uint32_t epoch)
{
	uint8_t x[FZN_GROUP_SECRET_LEN], y[FZN_GROUP_SECRET_LEN];

	return fzn_node_groups_secret(&a->groups, id, epoch, x) == FZN_GROUP_LOG_OK
	       && fzn_node_groups_secret(&b->groups, id, epoch, y) == FZN_GROUP_LOG_OK
	       && memcmp(x, y, sizeof(x)) == 0;
}

static int holds(struct user *u, const uint8_t *id, uint32_t epoch)
{
	uint8_t x[FZN_GROUP_SECRET_LEN];

	return fzn_node_groups_secret(&u->groups, id, epoch, x) == FZN_GROUP_LOG_OK;
}

static uint32_t epoch_of(struct user *u, const uint8_t *id)
{
	static fzn_group_t g;

	return fzn_group_log_get(&u->ops, id, &g) == FZN_GROUP_LOG_OK ? g.epoch : 0u;
}

static size_t tend(struct user *u, const uint8_t *id)
{
	size_t made = 0;

	CHECK(fzn_node_groups_tend(&u->groups, id, &made) == FZN_GROUP_LOG_OK, "a tend failed");
	return made;
}

/* ---- tests -------------------------------------------------------------- */

static void test_epochs_reach_members_and_no_one_else(void)
{
	struct user *a = &users[0], *b = &users[1], *c = &users[2];
	uint8_t id[FZN_GROUP_ID_LEN];

	user_up(a, 0x11u);
	user_up(b, 0x22u);
	user_up(c, 0x33u);
	CHECK(fzn_node_groups_act(&a->groups, FZN_GROUP_ACT_CREATE, NULL, NULL, 0u, 0u, id)
	              == FZN_GROUP_LOG_OK
	              && tend(a, id) == 1u && holds(a, id, 1u),
	      "the maker did not draw the first epoch's secret");
	CHECK(tend(a, id) == 0u, "a tend with nothing to do made an act");
	CHECK(fzn_node_groups_act(&a->groups, FZN_GROUP_ACT_ADD, id, b->device.owner, 0u, 0u, NULL)
	              == FZN_GROUP_LOG_OK
	              && epoch_of(a, id) == 2u && tend(a, id) == 1u && holds(a, id, 2u),
	      "adding a member did not start an epoch the maker drew");
	/* B LEARNS THE GROUP, names its host; A seals it the current epoch
	 * and backfills the first. */
	sync(a, b, id);
	CHECK(tend(b, id) == 1u && !holds(b, id, 2u), "B did not name its host, or held a secret");
	sync(b, a, id);
	CHECK(tend(a, id) == 2u, "A did not seal B the current epoch and backfill the first");
	sync(a, b, id);
	(void)tend(b, id);
	CHECK(same_secret(a, b, id, 2u) && same_secret(a, b, id, 1u),
	      "B did not open the secrets A sealed it");
	CHECK(tend(a, id) == 0u && tend(b, id) == 0u, "a host with nothing to do made an act");
	/* REMOVED: B is given nothing after. */
	CHECK(fzn_node_groups_act(&a->groups, FZN_GROUP_ACT_REMOVE, id, b->device.owner, 0u, 0u, NULL)
	              == FZN_GROUP_LOG_OK
	              && tend(a, id) == 1u && holds(a, id, 3u),
	      "a removal did not start an epoch the remaining member drew");
	sync(a, b, id);
	(void)tend(b, id);
	CHECK(!holds(b, id, 3u), "a removed member was given the epoch after its removal");
	/* BACKFILL OFF: C, added later, is given the current epoch alone. */
	CHECK(fzn_node_groups_act(&a->groups, FZN_GROUP_ACT_SET, id, NULL, FZN_GROUP_SETTING_BACKFILL,
	                          0u, NULL)
	                      == FZN_GROUP_LOG_OK
	              && fzn_node_groups_act(&a->groups, FZN_GROUP_ACT_ADD, id, c->device.owner, 0u, 0u,
	                                     NULL)
	                         == FZN_GROUP_LOG_OK,
	      "fixture: backfill off, C added");
	(void)tend(a, id);
	sync(a, c, id);
	(void)tend(c, id);
	sync(c, a, id);
	(void)tend(a, id);
	sync(a, c, id);
	(void)tend(c, id);
	CHECK(same_secret(a, c, id, 4u), "C was not given the current epoch");
	CHECK(!holds(c, id, 3u) && !holds(c, id, 1u), "C was backfilled with backfill off");
}

static void test_a_secret_drawn_on_a_lost_fork_is_let_go(void)
{
	struct user *a = &users[0], *b = &users[1];
	static fzn_group_t g;
	uint8_t id[FZN_GROUP_ID_LEN], subject[32], in[FZN_GROUP_ID_LEN + 4u], wrong[1u + 32u];

	user_up(a, 0x11u);
	user_up(b, 0x22u);
	(void)fzn_node_groups_act(&a->groups, FZN_GROUP_ACT_CREATE, NULL, NULL, 0u, 0u, id);
	(void)fzn_node_groups_act(&a->groups, FZN_GROUP_ACT_ADD, id, b->device.owner, 0u, 0u, NULL);
	sync(a, b, id);
	(void)tend(b, id);
	sync(b, a, id);
	(void)tend(a, id);
	sync(a, b, id);
	/* B HOLDS A SECRET of its own for the current epoch, as if it had
	 * drawn one and lost the fork to A's. */
	(void)fzn_group_log_get(&b->ops, id, &g);
	memcpy(in, id, FZN_GROUP_ID_LEN);
	in[FZN_GROUP_ID_LEN] = (uint8_t)(g.epoch >> 24);
	in[FZN_GROUP_ID_LEN + 1u] = (uint8_t)(g.epoch >> 16);
	in[FZN_GROUP_ID_LEN + 2u] = (uint8_t)(g.epoch >> 8);
	in[FZN_GROUP_ID_LEN + 3u] = (uint8_t)g.epoch;
	(void)HASH.hash(HASH.ctx, subject, sizeof(subject), in, sizeof(in));
	wrong[0] = 1u;
	memset(wrong + 1, 0x99, 32u);
	CHECK(mem_save(&b->store, FZN_PERSIST_GROUP_EPOCH, subject, wrong, sizeof(wrong)),
	      "fixture: B holds a wrong secret");
	(void)tend(b, id);
	CHECK(same_secret(a, b, id, g.epoch), "B kept the wrong secret over the one committed to");
}

/* A LINE written at one member's host, read at another's, sec 628. */
static void test_a_line_is_read_by_members_alone(void)
{
	struct user *a = &users[0], *b = &users[1], *c = &users[2];
	static fzn_group_t g;
	static fzn_group_line_t line, got;
	uint8_t id[FZN_GROUP_ID_LEN], secret[FZN_GROUP_SECRET_LEN], bytes[FZN_GROUP_LINE_MAX];
	size_t len = 0, i;
	uint32_t was;

	user_up(a, 0x11u);
	user_up(b, 0x22u);
	user_up(c, 0x33u);
	(void)fzn_node_groups_act(&a->groups, FZN_GROUP_ACT_CREATE, NULL, NULL, 0u, 0u, id);
	(void)fzn_node_groups_act(&a->groups, FZN_GROUP_ACT_ADD, id, b->device.owner, 0u, 0u, NULL);
	(void)tend(a, id);
	sync(a, b, id);
	(void)tend(b, id);
	sync(b, a, id);
	(void)tend(a, id);
	sync(a, b, id);
	(void)tend(b, id);
	(void)fzn_group_log_get(&a->ops, id, &g);
	CHECK(fzn_node_groups_secret(&a->groups, id, g.epoch, secret) == FZN_GROUP_LOG_OK,
	      "fixture: A holds the current epoch");
	memcpy(line.group, id, sizeof(line.group));
	line.epoch = g.epoch;
	memcpy(line.sender, a->device.owner, FZN_PUBKEY_LEN);
	memcpy(line.host, a->device.owner, FZN_PUBKEY_LEN);
	memset(line.id, 0x0d, sizeof(line.id));
	line.stime = 4321u;
	memcpy(line.text, "hello family", 12u);
	line.text_len = 12u;
	CHECK(fzn_group_line_seal(&line, secret, &HASH, &AEAD, &RNG, bytes, sizeof(bytes), &len)
	              == FZN_GROUP_LINE_OK,
	      "A did not seal a line");
	CHECK(fzn_group_line_peek(bytes, len, &got) == FZN_GROUP_LINE_OK && got.epoch == g.epoch
	              && memcmp(got.sender, line.sender, FZN_PUBKEY_LEN) == 0 && got.text_len == 0u,
	      "a line's clear head did not read back, or its text showed");
	CHECK(fzn_node_groups_secret(&b->groups, id, g.epoch, secret) == FZN_GROUP_LOG_OK
	              && fzn_group_line_open(bytes, len, secret, &HASH, &AEAD, &got)
	                         == FZN_GROUP_LINE_OK
	              && got.text_len == 12u && memcmp(got.text, "hello family", 12u) == 0
	              && got.stime == 4321u,
	      "B did not read A's line under the epoch's secret");
	CHECK(fzn_group_line_admit(&g, &got) == FZN_GROUP_LINE_OK, "A's own line was not admitted");
	/* EVERY BYTE BOUND. */
	for (i = 0; i < len; i++) {
		bytes[i] ^= 0x01u;
		if (fzn_group_line_open(bytes, len, secret, &HASH, &AEAD, &got) == FZN_GROUP_LINE_OK) {
			CHECK(0, "a line with a byte changed opened");
			bytes[i] ^= 0x01u;
			break;
		}
		bytes[i] ^= 0x01u;
	}
	CHECK(i == len, "every byte of a line is bound");
	CHECK(fzn_group_line_open(bytes, len - 1u, secret, &HASH, &AEAD, &got)
	              == FZN_GROUP_LINE_ERR_SHAPE,
	      "a line a byte short read");
	/* NAMING ANOTHER MEMBER from A's host: opens, and is not admitted. */
	memcpy(line.sender, b->device.owner, FZN_PUBKEY_LEN);
	(void)fzn_node_groups_secret(&a->groups, id, g.epoch, secret);
	(void)fzn_group_line_seal(&line, secret, &HASH, &AEAD, &RNG, bytes, sizeof(bytes), &len);
	CHECK(fzn_group_line_open(bytes, len, secret, &HASH, &AEAD, &got) == FZN_GROUP_LINE_OK
	              && fzn_group_line_admit(&g, &got) == FZN_GROUP_LINE_ERR_STRANGER,
	      "a line naming B, sealed by A's host, was admitted in the current epoch");
	/* A LATER EPOCH B never got: B cannot read it. */
	was = g.epoch;
	(void)fzn_node_groups_act(&a->groups, FZN_GROUP_ACT_REMOVE, id, b->device.owner, 0u, 0u, NULL);
	(void)tend(a, id);
	(void)fzn_group_log_get(&a->ops, id, &g);
	memcpy(line.sender, a->device.owner, FZN_PUBKEY_LEN);
	line.epoch = g.epoch;
	(void)fzn_node_groups_secret(&a->groups, id, g.epoch, secret);
	(void)fzn_group_line_seal(&line, secret, &HASH, &AEAD, &RNG, bytes, sizeof(bytes), &len);
	(void)fzn_node_groups_secret(&b->groups, id, was, secret);
	CHECK(g.epoch > was
	              && fzn_group_line_open(bytes, len, secret, &HASH, &AEAD, &got)
	                         == FZN_GROUP_LINE_ERR_OPEN,
	      "a removed member read a line of the epoch after it left");
	/* HISTORY: B's line of the earlier epoch is still admitted, B gone. */
	memcpy(line.sender, b->device.owner, FZN_PUBKEY_LEN);
	memcpy(line.host, b->device.owner, FZN_PUBKEY_LEN);
	line.epoch = was;
	CHECK(fzn_group_line_admit(&g, &line) == FZN_GROUP_LINE_OK,
	      "a departed member's line of an earlier epoch was refused");
	/* AHEAD OF THE GROUP, from a host the log does list: refused for the
	 * epoch, not for the host. */
	memcpy(line.sender, a->device.owner, FZN_PUBKEY_LEN);
	memcpy(line.host, a->device.owner, FZN_PUBKEY_LEN);
	line.epoch = g.epoch;
	CHECK(fzn_group_line_admit(&g, &line) == FZN_GROUP_LINE_OK, "fixture: A's current line");
	line.epoch = g.epoch + 1u;
	CHECK(fzn_group_line_admit(&g, &line) == FZN_GROUP_LINE_ERR_STRANGER,
	      "a line of an epoch the group has not reached was admitted");
	(void)c;
}

/* WHOSE A HOST IS, sec 630: a member's, in a group this user is in. */
static void test_a_members_host_is_its_members(void)
{
	struct user *a = &users[0], *b = &users[1], *c = &users[2];
	uint8_t id[FZN_GROUP_ID_LEN], owner[FZN_PUBKEY_LEN];

	user_up(a, 0x11u);
	user_up(b, 0x22u);
	user_up(c, 0x33u);
	(void)fzn_node_groups_act(&a->groups, FZN_GROUP_ACT_CREATE, NULL, NULL, 0u, 0u, id);
	(void)fzn_node_groups_act(&a->groups, FZN_GROUP_ACT_ADD, id, b->device.owner, 0u, 0u, NULL);
	sync(a, b, id);
	(void)tend(b, id);
	sync(b, a, id);
	CHECK(fzn_node_group_host_owner(&a->ops, a->device.owner, b->device.owner, owner)
	              && memcmp(owner, b->device.owner, FZN_PUBKEY_LEN) == 0,
	      "a member's host was not taken as its member's");
	CHECK(!fzn_node_group_host_owner(&a->ops, a->device.owner, c->device.owner, owner),
	      "a host no group lists was taken as a member's");
	CHECK(!fzn_node_group_host_owner(&a->ops, c->device.owner, b->device.owner, owner),
	      "a member's host was taken as such for a user not in the group");
	(void)fzn_node_groups_act(&a->groups, FZN_GROUP_ACT_REMOVE, id, b->device.owner, 0u, 0u, NULL);
	CHECK(!fzn_node_group_host_owner(&a->ops, a->device.owner, b->device.owner, owner),
	      "a removed member's host was still taken as a member's");
}

/* A HOST'S LINES HELD IN ORDER, sec 629, their senders kept. */
static void test_lines_are_held_in_order(void)
{
	struct user *a = &users[0];
	static fzn_group_line_t line;
	static fzn_group_line_head_t heads[4];
	fzn_group_lines_t l;
	fzn_group_line_head_t h;
	uint8_t group[32], host[32], other[32], secret[FZN_GROUP_SECRET_LEN];
	uint8_t one[FZN_GROUP_LINE_MAX], two[FZN_GROUP_LINE_MAX], got[FZN_GROUP_LINE_MAX];
	uint8_t filed[FZN_GROUP_LINE_ID_LEN], filed_other[FZN_GROUP_LINE_ID_LEN], who[32];
	size_t len1 = 0, len2 = 0, len = 0, n = 0;

	user_up(a, 0x11u);
	l.store = &a->ops;
	l.hash = &HASH;
	memset(group, 0x61, sizeof(group));
	memset(host, 0x62, sizeof(host));
	memset(other, 0x63, sizeof(other));
	memset(secret, 0x64, sizeof(secret));
	memcpy(line.group, group, 32u);
	memcpy(line.host, host, 32u);
	memcpy(line.sender, host, 32u);
	line.epoch = 1u;
	line.text_len = 3u;
	memcpy(line.text, "one", 3u);
	(void)fzn_group_line_seal(&line, secret, &HASH, &AEAD, &RNG, one, sizeof(one), &len1);
	memcpy(line.text, "two", 3u);
	(void)fzn_group_line_seal(&line, secret, &HASH, &AEAD, &RNG, two, sizeof(two), &len2);
	CHECK(fzn_group_lines_head(&l, group, host, &h) == FZN_GROUP_LINES_OK && h.have == 0u,
	      "a host with nothing held had a head");
	CHECK(fzn_group_lines_put(&l, 2u, two, len2) == FZN_GROUP_LINES_ERR_GAP,
	      "a line was held before the one before it");
	CHECK(fzn_group_lines_put(&l, 1u, one, len1) == FZN_GROUP_LINES_OK
	              && fzn_group_lines_put(&l, 1u, one, len1) == FZN_GROUP_LINES_ERR_HELD
	              && fzn_group_lines_put(&l, 2u, two, len2) == FZN_GROUP_LINES_OK,
	      "a host's lines were not held in order, once each");
	CHECK(fzn_group_lines_get(&l, group, host, 2u, got, sizeof(got), &len) == FZN_GROUP_LINES_OK
	              && len == len2 && memcmp(got, two, len) == 0
	              && fzn_group_lines_get(&l, group, host, 3u, got, sizeof(got), &len)
	                         == FZN_GROUP_LINES_ERR_ABSENT,
	      "a held line did not read back, or one past the head did");
	CHECK(fzn_group_lines_filed(&l, group, host, 3u) == FZN_GROUP_LINES_ERR_MALFORMED
	              && fzn_group_lines_filed(&l, group, host, 1u) == FZN_GROUP_LINES_OK
	              && fzn_group_lines_heads(&l, group, heads, 4u, &n) == FZN_GROUP_LINES_OK
	              && n == 1u && heads[0].have == 2u && heads[0].filed == 1u,
	      "the head did not say what is held and filed, or filed past what is held");
	CHECK(fzn_group_lines_filed_id(&HASH, host, line.id, filed)
	              && fzn_group_lines_filed_id(&HASH, other, line.id, filed_other)
	              && memcmp(filed, filed_other, sizeof(filed)) != 0,
	      "two hosts' lines of one id were filed under one id");
	CHECK(fzn_group_lines_sender(&l, group, filed, who) == FZN_GROUP_LINES_ERR_ABSENT
	              && fzn_group_lines_sender_keep(&l, group, filed, host) == FZN_GROUP_LINES_OK
	              && fzn_group_lines_sender(&l, group, filed, who) == FZN_GROUP_LINES_OK
	              && memcmp(who, host, 32u) == 0,
	      "a line's sender was not kept");
}

/* A TRIM, sec 664: lines up to a point gone and the base moved past them;
 * a host's first line given past its head taken from there, every later
 * one in order; a version 1 head read as base 0. */
static void test_lines_trimmed_from_a_base(void)
{
	struct user *a = &users[1];
	static fzn_group_line_t line;
	fzn_group_lines_t l;
	fzn_group_line_head_t h;
	uint8_t group[32], host[32], fresh[32], secret[FZN_GROUP_SECRET_LEN];
	static uint8_t sealed[5][FZN_GROUP_LINE_MAX];
	uint8_t got[FZN_GROUP_LINE_MAX];
	size_t lens[5], len = 0, removed = 9, k;

	user_up(a, 0x21u);
	l.store = &a->ops;
	l.hash = &HASH;
	memset(group, 0x71, sizeof(group));
	memset(host, 0x72, sizeof(host));
	memset(fresh, 0x73, sizeof(fresh));
	memset(secret, 0x74, sizeof(secret));
	memcpy(line.group, group, 32u);
	memcpy(line.sender, host, 32u);
	line.epoch = 1u;
	line.text_len = 1u;
	for (k = 0; k < 5u; k++) {
		memcpy(line.host, k < 4u ? host : fresh, 32u);
		line.text[0] = (uint8_t)('a' + k);
		(void)fzn_group_line_seal(&line, secret, &HASH, &AEAD, &RNG, sealed[k],
		                          sizeof(sealed[k]), &lens[k]);
	}
	for (k = 0; k < 3u; k++)
		CHECK(fzn_group_lines_put(&l, (uint32_t)k + 1u, sealed[k], lens[k]) == FZN_GROUP_LINES_OK,
		      "fixture: lines 1 to 3 held");
	CHECK(fzn_group_lines_trim(&l, group, host, 2u, &removed) == FZN_GROUP_LINES_OK
	              && removed == 2u && fzn_group_lines_head(&l, group, host, &h) == FZN_GROUP_LINES_OK
	              && h.base == 2u && h.have == 3u && h.filed == 2u,
	      "a trim to 2 did not remove two lines and move the base and filed past them");
	CHECK(fzn_group_lines_get(&l, group, host, 1u, got, sizeof(got), &len)
	                      == FZN_GROUP_LINES_ERR_ABSENT
	              && fzn_group_lines_get(&l, group, host, 3u, got, sizeof(got), &len)
	                         == FZN_GROUP_LINES_OK,
	      "a trimmed line was still held, or the line past it gone");
	CHECK(fzn_group_lines_put(&l, 4u, sealed[3], lens[3]) == FZN_GROUP_LINES_OK,
	      "the line after the head was not taken past a trim");
	CHECK(fzn_group_lines_trim(&l, group, host, 1u, &removed) == FZN_GROUP_LINES_OK
	              && removed == 0u && fzn_group_lines_head(&l, group, host, &h) == FZN_GROUP_LINES_OK
	              && h.base == 2u,
	      "a trim below the base moved it back");
	/* A REMOVAL REFUSED, sec 746: the base not moved past a line still on
	 * disk, so the next trim removes it. With the base saved first, the
	 * line was left below it for good, its text past its rule. */
	{
		size_t before = rows_of(&a->store, FZN_PERSIST_GROUP_LINE);

		removes_failing = 1;
		CHECK(fzn_group_lines_trim(&l, group, host, 4u, &removed) != FZN_GROUP_LINES_OK
		              && fzn_group_lines_head(&l, group, host, &h) == FZN_GROUP_LINES_OK
		              && h.base == 2u,
		      "a trim whose removal was refused moved the base past it");
		removes_failing = 0;
		CHECK(fzn_group_lines_trim(&l, group, host, 4u, &removed) == FZN_GROUP_LINES_OK
		              && fzn_group_lines_head(&l, group, host, &h) == FZN_GROUP_LINES_OK
		              && h.base == 4u
		              && rows_of(&a->store, FZN_PERSIST_GROUP_LINE) == before - 2u,
		      "a line whose removal was refused was left on disk below the base");
	}
	/* A FRESH HEAD given line 7 first: its sender trimmed 1 to 6. */
	CHECK(fzn_group_lines_put(&l, 7u, sealed[4], lens[4]) == FZN_GROUP_LINES_ERR_GAP,
	      "a strict put took a line past the head");
	CHECK(fzn_group_lines_put_from(&l, 7u, sealed[4], lens[4]) == FZN_GROUP_LINES_OK
	              && fzn_group_lines_head(&l, group, fresh, &h) == FZN_GROUP_LINES_OK
	              && h.base == 6u && h.have == 7u,
	      "a host's first line past its head was not taken from there");
	/* A VERSION 1 HEAD, as stored before sec 664, reads as base 0. */
	{
		uint8_t subject[32], v1[1u + 32u + 32u + 4u + 4u], in[1u + 32u + 32u + 4u];
		uint8_t other[32];

		memset(other, 0x75, sizeof(other));
		in[0] = 'h';
		memcpy(in + 1, group, 32u);
		memcpy(in + 33, other, 32u);
		memset(in + 65, 0, 4u);
		CHECK(HASH.hash(HASH.ctx, subject, 32u, in, sizeof(in)), "fixture: the head's subject");
		v1[0] = 1u;
		memcpy(v1 + 1, group, 32u);
		memcpy(v1 + 33, other, 32u);
		memset(v1 + 65, 0, 8u);
		v1[68] = 5u;
		v1[72] = 3u;
		CHECK(a->ops.save(a->ops.ctx, FZN_PERSIST_GROUP_LINE_HEAD, subject, v1, sizeof(v1))
		              && fzn_group_lines_head(&l, group, other, &h) == FZN_GROUP_LINES_OK
		              && h.have == 5u && h.filed == 3u && h.base == 0u,
		      "a version 1 head did not read with base 0");
	}
}

static size_t verb(struct user *u, const char *line, char *reply, size_t cap)
{
	fzn_request_t r;

	memset(reply, 0, cap);
	if (!fzn_vocabulary_split((const uint8_t *)line, strlen(line), &r))
		return 0;
	return fzn_node_groups_local(&u->groups, &r, reply, cap);
}

/* THE LAST ADMIN'S LEAVE, sec 688: refused with the two ways out, and let
 * through once another member is an admin. */
static void test_the_last_admin_is_told_the_ways_out(void)
{
	struct user *a = &users[0], *b = &users[1];
	uint8_t id[FZN_GROUP_ID_LEN];
	char reply[1024];
	size_t i;
	int read = 1;

	user_up(a, 0x11u);
	user_up(b, 0x22u);
	CHECK(verb(a, "add group fam", reply, sizeof(reply)) && strncmp(reply, "ok ", 3) == 0
	              && strlen(reply) >= 3u + 2u * FZN_GROUP_ID_LEN,
	      "fixture: a group made by the verb");
	for (i = 0; i < FZN_GROUP_ID_LEN; i++) {
		unsigned v = 0;

		read &= sscanf(reply + 3u + 2u * i, "%2x", &v) == 1;
		id[i] = (uint8_t)v;
	}
	CHECK(read && fzn_node_groups_act(&a->groups, FZN_GROUP_ACT_ADD, id, b->device.owner, 0u,
	                                  0u, NULL) == FZN_GROUP_LOG_OK,
	      "fixture: B added");
	CHECK(verb(a, "remove group fam", reply, sizeof(reply))
	              && strcmp(reply, "denied the last admin may not leave while others are in the "
	                               "group: make another member an admin, or remove the others, "
	                               "first\n") == 0,
	      "the last admin's leave was not refused with the ways out");
	CHECK(fzn_node_groups_act(&a->groups, FZN_GROUP_ACT_ADMIN_ADD, id, b->device.owner, 0u, 0u,
	                          NULL) == FZN_GROUP_LOG_OK
	              && verb(a, "remove group fam", reply, sizeof(reply))
	              && strcmp(reply, "ok\n") == 0,
	      "with another admin, the leave was still refused");
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
	fzn_agree_monocypher_init(&AGREE);
	fzn_hash_monocypher_init(&HASH);
	fzn_aead_monocypher_init(&AEAD);
	fzn_random_system_init(&RNG);
	memset(member.b, 0x44, sizeof(member.b));
	test_the_suite_can_tell_pass_from_fail();
	test_epochs_reach_members_and_no_one_else();
	test_a_secret_drawn_on_a_lost_fork_is_let_go();
	test_a_line_is_read_by_members_alone();
	test_lines_are_held_in_order();
	test_lines_trimmed_from_a_base();
	test_a_members_host_is_its_members();
	test_the_last_admin_is_told_the_ways_out();
	if (failures) {
		fprintf(stderr, "node groups_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("node groups_test: all %d checks passed\n", checks);
	return 0;
}
