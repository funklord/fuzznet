/* node group_log_test -- a group's log, sec 626: an act's encoding and
 * signature, who may do what, the admin set changed only by a majority, a
 * fork settled by the lower hash wherever it arrives first, and the log as
 * the store keeps it. A stub signature keyed by a key's first byte, as
 * contact_request_test's, and a stub hash. Each user's root is its own
 * host, so a signer's proof needs no chain. */

#include "../group_log.h"

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                  \
	do {                                                                               \
		checks++;                                                                  \
		if (!(cond)) {                                                             \
			failures++;                                                        \
			fprintf(stderr, "  FAIL group_log_test.c:%d: %s\n", __LINE__, what); \
		}                                                                          \
	} while (0)

static void mac(uint8_t *out, size_t out_len, uint64_t key, const uint8_t *msg, size_t len)
{
	uint64_t h = 0xcbf29ce484222325ull ^ key;
	size_t i;

	for (i = 0; i < len; i++)
		h = (h ^ msg[i]) * 0x100000001b3ull;
	for (i = 0; i < out_len; i++) {
		h = (h ^ (uint64_t)i) * 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 56);
	}
}

static uint8_t signing_as;

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t len)
{
	(void)ctx;
	mac(sig, FZN_SIG_LEN, signing_as, msg, len);
	return 1;
}

static int stub_verify(void *ctx, const uint8_t pk[FZN_PUBKEY_LEN], const uint8_t *msg, size_t len,
                       const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	mac(want, FZN_SIG_LEN, pk[0], msg, len);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	(void)ctx;
	mac(out, out_len, 0x1234u, in, in_len);
	return 1;
}

static const fzn_sign_ops_t SIGN = { stub_verify, stub_sign, NULL };
static const fzn_hash_ops_t HASH = { stub_hash, NULL };

/* ---- a store of every slot ---------------------------------------------- */

#define ROWS 64u
#define ROW_MAX 16384u

static struct {
	int used;
	fzn_persist_slot_t slot;
	uint8_t subject[32];
	uint8_t bytes[ROW_MAX];
	size_t len;
} rows[ROWS];

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	size_t i;

	(void)ctx;
	for (i = 0; i < ROWS; i++)
		if (rows[i].used && rows[i].slot == slot && memcmp(rows[i].subject, subject, 32u) == 0
		    && rows[i].len <= cap) {
			memcpy(out, rows[i].bytes, rows[i].len);
			*len = rows[i].len;
			return 1;
		}
	return 0;
}

static int mem_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                    const uint8_t *bytes, size_t len)
{
	size_t i, free_one = ROWS;

	(void)ctx;
	if (len > ROW_MAX)
		return 0;
	for (i = 0; i < ROWS; i++) {
		if (rows[i].used && rows[i].slot == slot && memcmp(rows[i].subject, subject, 32u) == 0)
			break;
		if (!rows[i].used && free_one == ROWS)
			free_one = i;
	}
	if (i == ROWS)
		i = free_one;
	if (i == ROWS)
		return 0;
	rows[i].used = 1;
	rows[i].slot = slot;
	memcpy(rows[i].subject, subject, 32u);
	memcpy(rows[i].bytes, bytes, len);
	rows[i].len = len;
	return 1;
}

static int mem_list(void *ctx, fzn_persist_slot_t slot, uint8_t *out, size_t max, size_t *count)
{
	size_t i, n = 0;

	(void)ctx;
	for (i = 0; i < ROWS; i++)
		if (rows[i].used && rows[i].slot == slot) {
			if (n == max)
				return 0;
			memcpy(out + 32u * n++, rows[i].subject, 32u);
		}
	*count = n;
	return 1;
}

static int mem_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	size_t i;

	(void)ctx;
	for (i = 0; i < ROWS; i++)
		if (rows[i].used && rows[i].slot == slot && memcmp(rows[i].subject, subject, 32u) == 0)
			rows[i].used = 0;
	return 1;
}

static const fzn_persist_ops_t STORE = { mem_load, mem_save, mem_list, mem_remove, NULL, NULL };

static size_t rows_in(fzn_persist_slot_t slot)
{
	size_t i, n = 0;

	for (i = 0; i < ROWS; i++)
		n += rows[i].used && rows[i].slot == slot;
	return n;
}

/* ---- fixtures ----------------------------------------------------------- */

static fzn_cap_id_t member;
static fzn_group_log_ops_t OPS;

/* THE ACTS A FORK DROPPED, as the log reports them. */
static size_t n_dropped;
static uint8_t first_dropped[32];

static void on_dropped(void *ctx, const uint8_t *bytes, size_t len)
{
	fzn_group_act_t a;

	(void)ctx;
	if (n_dropped++ == 0u && fzn_group_act_decode(bytes, len, &a) == FZN_GROUP_ACT_OK)
		(void)fzn_group_act_hash(&a, &HASH, first_dropped);
}

static void root_of(uint8_t out[32], uint8_t user)
{
	memset(out, user, 32u);
}

/* AN ACT by user `user` -- whose root is its own host -- of `kind` on
 * `subject`, at place `seq` after `prev`, in group `group`, signed. */
static void act(fzn_group_act_t *a, uint8_t kind, uint8_t user, const uint8_t *group, uint32_t seq,
                const uint8_t *prev, const uint8_t *subject)
{
	uint8_t agree[FZN_PREKEY_LEN];

	memset(a, 0, sizeof(*a));
	a->kind = kind;
	a->seq = seq;
	if (group)
		memcpy(a->group, group, 32u);
	if (prev)
		memcpy(a->prev, prev, 32u);
	if (subject)
		memcpy(a->subject, subject, 32u);
	a->at = 5000u;
	root_of(a->signer.owner, user);
	memset(agree, user ^ 0x5au, sizeof(agree));
	signing_as = user;
	(void)fzn_prekey_issue(a->signer.owner, agree, 1000u, &SIGN, a->signer.record);
	(void)fzn_group_act_sign(a, &SIGN);
}

static void hash_of(const fzn_group_act_t *a, uint8_t out[32])
{
	(void)fzn_group_act_hash(a, &HASH, out);
}

/* `a` applied to `g`, by hash. */
static fzn_group_log_err_t apply(fzn_group_t *g, const fzn_group_act_t *a)
{
	uint8_t h[32];

	hash_of(a, h);
	return fzn_group_apply(g, a, h);
}

/* `a` offered to the store. */
static fzn_group_log_err_t offer(const fzn_group_act_t *a, fzn_group_offer_t *did, size_t *dropped)
{
	uint8_t bytes[FZN_GROUP_ACT_MAX];
	size_t n = 0;

	(void)fzn_group_act_encode(a, bytes, sizeof(bytes), &n);
	return fzn_group_log_offer(&OPS, bytes, n, did, dropped);
}

/* THE NEXT ACT on `g`, by `user`. */
static fzn_group_log_err_t next(fzn_group_t *g, uint8_t kind, uint8_t user, const uint8_t *subject)
{
	fzn_group_act_t a;

	act(&a, kind, user, g->id, g->seq, g->head, subject);
	return apply(g, &a);
}

/* ---- tests -------------------------------------------------------------- */

static void test_an_act_is_its_signers(void)
{
	fzn_group_act_t a, back;
	uint8_t bytes[FZN_GROUP_ACT_MAX], nonce[32];
	size_t n = 0;

	memset(nonce, 0x99, sizeof(nonce));
	act(&a, FZN_GROUP_ACT_CREATE, 0x11u, NULL, 0u, NULL, nonce);
	CHECK(fzn_group_act_encode(&a, bytes, sizeof(bytes), &n) == FZN_GROUP_ACT_OK
	              && fzn_group_act_decode(bytes, n, &back) == FZN_GROUP_ACT_OK
	              && memcmp(&back.subject, nonce, 32u) == 0 && back.kind == a.kind
	              && memcmp(back.signer.owner, a.signer.owner, 32u) == 0,
	      "an act did not read back as itself");
	CHECK(fzn_group_act_verify(&back, &SIGN, &member) == FZN_GROUP_ACT_OK,
	      "an act signed by its signer's host did not hold");
	CHECK(fzn_group_act_decode(bytes, n - 1u, &back) == FZN_GROUP_ACT_ERR_SHAPE,
	      "an act a byte short read");
	bytes[3] ^= 1u; /* its place */
	CHECK(fzn_group_act_decode(bytes, n, &back) == FZN_GROUP_ACT_OK
	              && fzn_group_act_verify(&back, &SIGN, &member) == FZN_GROUP_ACT_ERR_REFUSED,
	      "an act altered after signing held");
	a.signer.owner[0] ^= 1u; /* claimed for another user */
	CHECK(fzn_group_act_verify(&a, &SIGN, &member) == FZN_GROUP_ACT_ERR_REFUSED,
	      "an act claimed for a user whose host did not sign it held");
	/* SIGNED WHOLE by a host that is not the user's: the signature holds,
	 * and only the proof -- the host is neither the root nor chained from
	 * it -- tells the act is not that user's. */
	act(&a, FZN_GROUP_ACT_CREATE, 0x11u, NULL, 0u, NULL, nonce);
	root_of(a.signer.owner, 0x22u);
	signing_as = 0x11u;
	(void)fzn_group_act_sign(&a, &SIGN);
	CHECK(fzn_group_act_verify(&a, &SIGN, &member) == FZN_GROUP_ACT_ERR_REFUSED,
	      "an act signed by a host with no proof for the user it names held");
}

static void test_who_may_do_what(void)
{
	static fzn_group_t g;
	fzn_group_act_t a;
	uint8_t nonce[32], u1[32], u2[32], u3[32];
	uint32_t epoch;

	root_of(u1, 0x11u);
	root_of(u2, 0x22u);
	root_of(u3, 0x33u);
	memset(nonce, 0x01, sizeof(nonce));
	act(&a, FZN_GROUP_ACT_CREATE, 0x11u, NULL, 0u, NULL, nonce);
	CHECK(apply(&g, &a) == FZN_GROUP_LOG_OK && g.seq == 1u && g.n_members == 1u
	              && fzn_group_is_admin(&g, u1) && g.backfill == 1u,
	      "a group made did not have its maker as member and admin, backfilling");
	hash_of(&a, nonce);
	CHECK(memcmp(g.id, nonce, 32u) == 0, "a group's id is not its create act's hash");
	epoch = g.epoch;
	CHECK(next(&g, FZN_GROUP_ACT_ADD, 0x11u, u2) == FZN_GROUP_LOG_OK
	              && fzn_group_is_member(&g, u2) && g.epoch == epoch + 1u,
	      "an admin's add did not add, or did not move the epoch");
	CHECK(next(&g, FZN_GROUP_ACT_ADD, 0x22u, u3) == FZN_GROUP_LOG_ERR_DENIED,
	      "a member who is not an admin added someone");
	CHECK(next(&g, FZN_GROUP_ACT_ADD, 0x11u, u2) == FZN_GROUP_LOG_ERR_MOOT,
	      "a member added twice");
	CHECK(next(&g, FZN_GROUP_ACT_LEAVE, 0x11u, u2) == FZN_GROUP_LOG_ERR_DENIED,
	      "one user left a group for another");
	CHECK(next(&g, FZN_GROUP_ACT_LEAVE, 0x11u, u1) == FZN_GROUP_LOG_ERR_DENIED,
	      "the last admin left");
	CHECK(next(&g, FZN_GROUP_ACT_SET, 0x22u, NULL) == FZN_GROUP_LOG_ERR_DENIED,
	      "a member who is not an admin set a setting");
	act(&a, FZN_GROUP_ACT_SET, 0x11u, g.id, g.seq, g.head, NULL);
	a.setting = FZN_GROUP_SETTING_BACKFILL;
	a.value = 0u;
	(void)fzn_group_act_sign(&a, &SIGN);
	CHECK(apply(&g, &a) == FZN_GROUP_LOG_OK && g.backfill == 0u,
	      "an admin did not turn backfill off");
	epoch = g.epoch;
	CHECK(next(&g, FZN_GROUP_ACT_LEAVE, 0x22u, u2) == FZN_GROUP_LOG_OK
	              && !fzn_group_is_member(&g, u2) && g.epoch == epoch + 1u,
	      "a member did not leave, or the epoch did not move");
	/* NOT AT THE HEAD: a stale place, or a head that is not this one. */
	act(&a, FZN_GROUP_ACT_ADD, 0x11u, g.id, g.seq - 1u, g.head, u3);
	CHECK(apply(&g, &a) == FZN_GROUP_LOG_ERR_NOT_NEXT, "an act at a stale place applied");
	act(&a, FZN_GROUP_ACT_ADD, 0x11u, g.id, g.seq, nonce, u3);
	CHECK(apply(&g, &a) == FZN_GROUP_LOG_ERR_NOT_NEXT, "an act after another head applied");
}

static void test_the_admins_change_by_a_majority(void)
{
	static fzn_group_t g;
	fzn_group_act_t a;
	uint8_t nonce[32], u1[32], u2[32], u3[32], proposal[32];

	root_of(u1, 0x11u);
	root_of(u2, 0x22u);
	root_of(u3, 0x33u);
	memset(nonce, 0x02, sizeof(nonce));
	act(&a, FZN_GROUP_ACT_CREATE, 0x11u, NULL, 0u, NULL, nonce);
	(void)apply(&g, &a);
	(void)next(&g, FZN_GROUP_ACT_ADD, 0x11u, u2);
	(void)next(&g, FZN_GROUP_ACT_ADD, 0x11u, u3);
	CHECK(next(&g, FZN_GROUP_ACT_ADMIN_ADD, 0x11u, u2) == FZN_GROUP_LOG_OK
	              && fzn_group_is_admin(&g, u2) && g.n_proposals == 0u,
	      "the only admin's proposal, a majority of one, did not carry");
	act(&a, FZN_GROUP_ACT_ADMIN_ADD, 0x11u, g.id, g.seq, g.head, u3);
	hash_of(&a, proposal);
	CHECK(apply(&g, &a) == FZN_GROUP_LOG_OK && !fzn_group_is_admin(&g, u3)
	              && g.n_proposals == 1u,
	      "one of two admins made an admin alone");
	CHECK(next(&g, FZN_GROUP_ACT_APPROVE, 0x11u, proposal) == FZN_GROUP_LOG_ERR_MOOT,
	      "an admin's approval of its own proposal counted twice");
	CHECK(next(&g, FZN_GROUP_ACT_APPROVE, 0x33u, proposal) == FZN_GROUP_LOG_ERR_DENIED,
	      "a member who is not an admin approved");
	CHECK(next(&g, FZN_GROUP_ACT_APPROVE, 0x22u, proposal) == FZN_GROUP_LOG_OK
	              && fzn_group_is_admin(&g, u3) && g.n_proposals == 0u,
	      "two of two admins did not make an admin");
	/* THREE ADMINS: removing one needs two. */
	CHECK(next(&g, FZN_GROUP_ACT_ADMIN_REMOVE, 0x11u, u3) == FZN_GROUP_LOG_OK
	              && fzn_group_is_admin(&g, u3),
	      "one of three admins removed an admin alone");
	CHECK(next(&g, FZN_GROUP_ACT_REMOVE, 0x11u, u3) == FZN_GROUP_LOG_ERR_DENIED,
	      "an admin was removed as a member, the admin set's side door");
	CHECK(next(&g, FZN_GROUP_ACT_ADMIN_REMOVE, 0x22u, u3) == FZN_GROUP_LOG_OK
	              && !fzn_group_is_admin(&g, u3) && fzn_group_is_member(&g, u3),
	      "the same removal proposed by a second admin did not carry as an approval");
	CHECK(next(&g, FZN_GROUP_ACT_REMOVE, 0x22u, u3) == FZN_GROUP_LOG_OK
	              && !fzn_group_is_member(&g, u3),
	      "a former admin could not be removed as a member");
	/* AN ADMIN LEAVING ends the open proposals: their majority is gone. */
	(void)next(&g, FZN_GROUP_ACT_ADD, 0x11u, u3);
	(void)next(&g, FZN_GROUP_ACT_ADMIN_ADD, 0x11u, u3);
	CHECK(g.n_proposals == 1u && next(&g, FZN_GROUP_ACT_LEAVE, 0x22u, u2) == FZN_GROUP_LOG_OK
	              && g.n_proposals == 0u && g.n_admins == 1u,
	      "an admin leaving did not end the open proposals");
}

static void test_a_fork_keeps_the_lower_hash(void)
{
	fzn_group_act_t create, add2, x, y, after;
	fzn_group_t g;
	fzn_group_offer_t did;
	uint8_t nonce[32], u2[32], u3[32], u4[32], id[32], hx[32], hy[32];
	const fzn_group_act_t *low, *high;
	size_t dropped = 0;
	int round;

	root_of(u2, 0x22u);
	root_of(u3, 0x33u);
	root_of(u4, 0x44u);
	for (round = 0; round < 2; round++) {
		memset(rows, 0, sizeof(rows));
		memset(nonce, 0x03, sizeof(nonce));
		act(&create, FZN_GROUP_ACT_CREATE, 0x11u, NULL, 0u, NULL, nonce);
		CHECK(offer(&create, &did, &dropped) == FZN_GROUP_LOG_OK && did == FZN_GROUP_OFFER_TAKEN,
		      "a create act was not taken");
		hash_of(&create, id);
		CHECK(fzn_group_log_get(&STORE, id, &g) == FZN_GROUP_LOG_OK
		              && offer(&create, &did, &dropped) == FZN_GROUP_LOG_OK
		              && did == FZN_GROUP_OFFER_HELD,
		      "a create act offered twice was not held");
		act(&add2, FZN_GROUP_ACT_ADD, 0x11u, id, 1u, g.head, u2);
		(void)offer(&add2, &did, &dropped);
		(void)fzn_group_log_get(&STORE, id, &g);
		(void)fzn_group_log_get(&STORE, id, &g);
		/* TWO ACTS AT PLACE 2, by the two admins once one is made. */
		act(&x, FZN_GROUP_ACT_ADD, 0x11u, id, 2u, g.head, u3);
		act(&y, FZN_GROUP_ACT_ADD, 0x11u, id, 2u, g.head, u4);
		hash_of(&x, hx);
		hash_of(&y, hy);
		low = memcmp(hx, hy, 32u) < 0 ? &x : &y;
		high = low == &x ? &y : &x;
		/* ROUND 0 sees the higher first, round 1 the lower. */
		CHECK(offer(round ? low : high, &did, &dropped) == FZN_GROUP_LOG_OK
		              && did == FZN_GROUP_OFFER_TAKEN,
		      "the first act at a place was not taken");
		(void)fzn_group_log_get(&STORE, id, &g);
		act(&after, FZN_GROUP_ACT_SET, 0x11u, id, 3u, g.head, NULL);
		after.setting = FZN_GROUP_SETTING_BACKFILL;
		after.value = 0u;
		signing_as = 0x11u;
		(void)fzn_group_act_sign(&after, &SIGN);
		CHECK(offer(&after, &did, &dropped) == FZN_GROUP_LOG_OK, "an act on the head was not taken");
		n_dropped = 0;
		if (round == 0) {
			CHECK(offer(low, &did, &dropped) == FZN_GROUP_LOG_OK
			              && did == FZN_GROUP_OFFER_REPLACED && dropped == 2u,
			      "the lower hash did not replace the higher and its tail");
			CHECK(rows_in(FZN_PERSIST_GROUP_ACT) == 3u,
			      "the lost tail was left in the store");
			CHECK(n_dropped == 2u && memcmp(first_dropped, high == &x ? hx : hy, 32u) == 0,
			      "the acts a fork dropped were not reported, the one it lost to first");
		} else {
			CHECK(offer(high, &did, &dropped) == FZN_GROUP_LOG_OK
			              && did == FZN_GROUP_OFFER_LOST,
			      "the higher hash did not lose to the lower already held");
		}
		(void)fzn_group_log_get(&STORE, id, &g);
		CHECK(fzn_group_is_member(&g, low->subject) && !fzn_group_is_member(&g, high->subject),
		      "the kept member was not the lower hash's");
	}
	/* PAST THE HEAD: a gap, to be filled first. */
	act(&x, FZN_GROUP_ACT_ADD, 0x11u, id, g.seq + 1u, g.head, u4);
	CHECK(offer(&x, &did, &dropped) == FZN_GROUP_LOG_ERR_GAP, "an act past the head was taken");
	x.subject[0] ^= 1u; /* unsigned change */
	CHECK(offer(&x, &did, &dropped) == FZN_GROUP_LOG_ERR_REFUSED, "an act forged was offered in");
}

/* A KEYS ACT by user `user` for `epoch`, committing to `commit`, with a box
 * for each of `n` hosts' keys -- the boxes are bytes here, the log does not
 * open them. */
static fzn_group_log_err_t keys_act(fzn_group_t *g, uint8_t user, uint32_t epoch,
                                    const uint8_t *commit, uint8_t (*hosts)[32], size_t n)
{
	fzn_group_act_t a;
	size_t i;

	act(&a, FZN_GROUP_ACT_KEYS, user, g->id, g->seq, g->head, commit);
	a.value = epoch;
	for (i = 0; i < n; i++) {
		memcpy(a.payload + i * FZN_GROUP_KEY_ENTRY_LEN, hosts[i], 32u);
		memset(a.payload + i * FZN_GROUP_KEY_ENTRY_LEN + 32u, 0x5b, FZN_GROUP_KEY_BOX_LEN);
	}
	a.payload_len = n * FZN_GROUP_KEY_ENTRY_LEN;
	signing_as = user;
	(void)fzn_group_act_sign(&a, &SIGN);
	return apply(g, &a);
}

static void test_an_epoch_is_sealed_to_listed_hosts(void)
{
	static fzn_group_t g;
	fzn_group_act_t a;
	uint8_t nonce[32], c1[32], c2[32], hosts[2][32];

	root_of(hosts[0], 0x11u);
	root_of(hosts[1], 0x22u);
	memset(c1, 0xc1, sizeof(c1));
	memset(c2, 0xc2, sizeof(c2));
	memset(nonce, 0x05, sizeof(nonce));
	act(&a, FZN_GROUP_ACT_CREATE, 0x11u, NULL, 0u, NULL, nonce);
	(void)apply(&g, &a);
	CHECK(g.n_hosts == 1u && fzn_group_host(&g, hosts[0]), "the maker's host was not the first");
	CHECK(keys_act(&g, 0x11u, 1u, c1, hosts, 1u) == FZN_GROUP_LOG_OK
	              && fzn_group_commit(&g, 1u) && memcmp(fzn_group_commit(&g, 1u), c1, 32u) == 0
	              && fzn_group_host(&g, hosts[0])->keyed_epoch == 1u,
	      "the first KEYS act did not fix the epoch's commitment");
	CHECK(keys_act(&g, 0x11u, 1u, c1, hosts, 1u) == FZN_GROUP_LOG_ERR_MOOT,
	      "a host sealed an epoch twice");
	CHECK(keys_act(&g, 0x11u, 1u, c2, hosts, 1u) == FZN_GROUP_LOG_ERR_DENIED,
	      "a second commitment to one epoch was taken");
	(void)next(&g, FZN_GROUP_ACT_ADD, 0x11u, hosts[1]);
	CHECK(keys_act(&g, 0x11u, 2u, c2, hosts, 2u) == FZN_GROUP_LOG_ERR_DENIED,
	      "a box for a host the log does not list was taken");
	CHECK(keys_act(&g, 0x22u, 2u, c2, hosts, 1u) == FZN_GROUP_LOG_ERR_DENIED,
	      "a member not among the hosts sealed an epoch");
	CHECK(next(&g, FZN_GROUP_ACT_HOST, 0x22u, hosts[1]) == FZN_GROUP_LOG_OK
	              && fzn_group_host(&g, hosts[1])->joined_epoch == 2u
	              && next(&g, FZN_GROUP_ACT_HOST, 0x22u, hosts[1]) == FZN_GROUP_LOG_ERR_MOOT,
	      "a member's host did not join once");
	CHECK(keys_act(&g, 0x11u, 2u, c2, hosts, 2u) == FZN_GROUP_LOG_OK,
	      "the current epoch was not sealed to both hosts");
	/* BACKFILL: the epoch before, under its own commitment. */
	CHECK(keys_act(&g, 0x11u, 1u, c2, &hosts[1], 1u)
	              == FZN_GROUP_LOG_ERR_DENIED,
	      "an older epoch was sealed under another commitment");
	CHECK(keys_act(&g, 0x11u, 1u, c1, &hosts[1], 1u) == FZN_GROUP_LOG_OK
	              && fzn_group_host(&g, hosts[1])->backfilled_to == 1u
	              && keys_act(&g, 0x11u, 1u, c1, &hosts[1], 1u)
	                         == FZN_GROUP_LOG_ERR_MOOT,
	      "a later host was not backfilled once");
	/* REMOVED: its hosts go with it. */
	CHECK(next(&g, FZN_GROUP_ACT_REMOVE, 0x11u, hosts[1]) == FZN_GROUP_LOG_OK
	              && !fzn_group_host(&g, hosts[1]) && g.n_hosts == 1u,
	      "a removed member's host stayed among the group's hosts");
}

static void test_a_backfill_goes_newest_first_and_not_when_off(void)
{
	static fzn_group_t g;
	fzn_group_act_t a;
	uint8_t nonce[32], c[4][32], hosts[2][32], third[32];
	uint32_t e;

	root_of(hosts[0], 0x11u);
	root_of(hosts[1], 0x22u);
	root_of(third, 0x33u);
	memset(nonce, 0x06, sizeof(nonce));
	act(&a, FZN_GROUP_ACT_CREATE, 0x11u, NULL, 0u, NULL, nonce);
	(void)apply(&g, &a);
	/* EPOCHS 1 TO 3 sealed to the maker, each ended by a change: B added,
	 * a third added, the third removed. B's host joins in epoch 4. */
	for (e = 1u; e <= 3u; e++) {
		memset(c[e], (int)(0xd0u + e), 32u);
		CHECK(keys_act(&g, 0x11u, e, c[e], hosts, 1u) == FZN_GROUP_LOG_OK,
		      "fixture: an epoch sealed to the maker");
		(void)next(&g, e == 3u ? FZN_GROUP_ACT_REMOVE : FZN_GROUP_ACT_ADD, 0x11u,
		           e == 1u ? hosts[1] : third);
	}
	(void)next(&g, FZN_GROUP_ACT_HOST, 0x22u, hosts[1]);
	CHECK(keys_act(&g, 0x11u, 2u, c[2], &hosts[1], 1u)
	              == FZN_GROUP_LOG_ERR_DENIED,
	      "a backfill skipped an epoch");
	CHECK(g.epoch == 4u, "fixture: epoch 4");
	CHECK(keys_act(&g, 0x11u, 3u, c[3], &hosts[1], 1u) == FZN_GROUP_LOG_OK,
	      "the newest older epoch was not backfilled first");
	act(&a, FZN_GROUP_ACT_SET, 0x11u, g.id, g.seq, g.head, NULL);
	a.setting = FZN_GROUP_SETTING_BACKFILL;
	a.value = 0u;
	signing_as = 0x11u;
	(void)fzn_group_act_sign(&a, &SIGN);
	(void)apply(&g, &a);
	CHECK(keys_act(&g, 0x11u, 2u, c[2], &hosts[1], 1u)
	              == FZN_GROUP_LOG_ERR_DENIED,
	      "an older epoch was sealed with backfill off");
}

static void test_the_log_reads_back(void)
{
	fzn_group_act_t create, a;
	fzn_group_t g;
	fzn_group_offer_t did;
	uint8_t nonce[32], id[32], ids[4][32], bytes[FZN_GROUP_ACT_MAX], u2[32];
	size_t n = 0, dropped;

	memset(rows, 0, sizeof(rows));
	root_of(u2, 0x22u);
	memset(nonce, 0x04, sizeof(nonce));
	act(&create, FZN_GROUP_ACT_CREATE, 0x11u, NULL, 0u, NULL, nonce);
	(void)offer(&create, &did, &dropped);
	hash_of(&create, id);
	(void)fzn_group_log_get(&STORE, id, &g);
	act(&a, FZN_GROUP_ACT_ADD, 0x11u, id, 1u, g.head, u2);
	(void)offer(&a, &did, &dropped);
	CHECK(fzn_group_log_get(&STORE, id, &g) == FZN_GROUP_LOG_OK && g.seq == 2u
	              && fzn_group_is_member(&g, u2) && g.n_members == 2u,
	      "the group kept did not say its log");
	CHECK(fzn_group_log_act(&OPS, id, 1u, bytes, sizeof(bytes), &n) == FZN_GROUP_LOG_OK
	              && fzn_group_act_decode(bytes, n, &a) == FZN_GROUP_ACT_OK
	              && memcmp(a.subject, u2, 32u) == 0,
	      "an act did not read back from its place");
	CHECK(fzn_group_log_act(&OPS, id, 2u, bytes, sizeof(bytes), &n) == FZN_GROUP_LOG_ERR_ABSENT,
	      "an act read from past the head");
	CHECK(fzn_group_log_list(&STORE, ids, 4u, &n) == FZN_GROUP_LOG_OK && n == 1u
	              && memcmp(ids[0], id, 32u) == 0,
	      "the groups held did not list");
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
	memset(member.b, 0x44, sizeof(member.b));
	OPS.store = &STORE;
	OPS.hash = &HASH;
	OPS.sign = &SIGN;
	OPS.member = &member;
	OPS.dropped = on_dropped;
	test_the_suite_can_tell_pass_from_fail();
	test_an_act_is_its_signers();
	test_who_may_do_what();
	test_the_admins_change_by_a_majority();
	test_a_fork_keeps_the_lower_hash();
	test_an_epoch_is_sealed_to_listed_hosts();
	test_a_backfill_goes_newest_first_and_not_when_off();
	test_the_log_reads_back();
	if (failures) {
		fprintf(stderr, "node group_log_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("node group_log_test: all %d checks passed\n", checks);
	return 0;
}
