/* roster_test -- a user's roster across the user's hosts. sec 388.
 *
 * Signing is a stub keyed by the first byte of the public key, as in
 * revocation_test: what is under test is which key a record is verified
 * under and what it then changes, not the curve.
 */

#include "../roster.h"
#include "../../chain/revocation.h"
#include "../../session/commitment.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		fprintf(stderr, "  FAIL roster_test.c:%d: %s\n", line, what);
	}
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, what)

/* ---- a stub signer: a 64-byte MAC over the message, keyed by one byte -- */

static void mac(uint8_t out[FZN_SIG_LEN], uint8_t key, const uint8_t *msg, size_t len)
{
	uint64_t h = 0xcbf29ce484222325ull ^ key;
	size_t i;

	for (i = 0; i < len; i++) {
		h ^= msg[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h ^= (uint64_t)i + 1u;
		h *= 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 56);
	}
}

static int stub_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	mac(want, pubkey[0], msg, msg_len);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	mac(sig, *(const uint8_t *)ctx, msg, msg_len);
	return 1;
}

static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint8_t full[FZN_SIG_LEN];

	(void)ctx;
	mac(full, 0x5au, in, in_len);
	if (out_len > sizeof(full))
		return 0;
	memcpy(out, full, out_len);
	return 1;
}

/* A signer for the key whose first byte is `id`. */
typedef struct who {
	uint8_t id;
	uint8_t key[FZN_PUBKEY_LEN];
	fzn_sign_ops_t sign;
} who_t;

static void who_init(who_t *w, uint8_t id)
{
	size_t i;

	w->id = id;
	for (i = 0; i < FZN_PUBKEY_LEN; i++)
		w->key[i] = (uint8_t)(id + i * 7u);
	w->sign.sign = stub_sign;
	w->sign.verify = stub_verify;
	w->sign.ctx = &w->id;
}

static void incarnation_of(uint8_t out[FZN_ROSTER_INCARNATION_LEN], uint8_t seed)
{
	size_t i;

	for (i = 0; i < FZN_ROSTER_INCARNATION_LEN; i++)
		out[i] = (uint8_t)(seed * 13u + i + 1u);
}

static who_t root, member, stranger, alice, bob;
static fzn_cap_id_t manage, other_cap;

/* A record in a buffer of its own, so a test can hold several. */
typedef struct rec {
	uint8_t bytes[FZN_ROSTER_MAX_LEN];
	size_t len;
} rec_t;

static fzn_roster_record_t view(const rec_t *r)
{
	fzn_roster_record_t v;

	v.base = r->bytes;
	v.len = r->len;
	return v;
}

static void add(rec_t *r, const who_t *writer, const who_t *subject, uint8_t inc, uint64_t seq)
{
	uint8_t incarnation[FZN_ROSTER_INCARNATION_LEN];

	incarnation_of(incarnation, inc);
	r->len = 0;
	if (fzn_roster_issue_add(writer->key, subject->key, incarnation, seq, &writer->sign,
	                         r->bytes, sizeof(r->bytes), &r->len) != FZN_ROSTER_OK)
		r->len = 0;
}

static void removal(rec_t *r, const who_t *writer, const who_t *subject, uint8_t inc,
                    uint64_t seq)
{
	uint8_t incarnation[FZN_ROSTER_INCARNATION_LEN];

	incarnation_of(incarnation, inc);
	r->len = 0;
	if (fzn_roster_issue_remove(writer->key, subject->key, incarnation, seq, &writer->sign,
	                            r->bytes, sizeof(r->bytes), &r->len) != FZN_ROSTER_OK)
		r->len = 0;
}

static fzn_roster_authority_t authority_now(uint64_t now,
                                            const fzn_revocation_store_t *revocations)
{
	fzn_roster_authority_t a;

	a.root = root.key;
	a.capability = &manage;
	a.sign = &root.sign;
	a.now = now;
	a.revocations = revocations;
	return a;
}

/* Which incarnation seed is active for `subject`, or 0 for none. */
static uint8_t active_seed(const fzn_roster_t *r, const who_t *subject)
{
	uint8_t got[FZN_ROSTER_INCARNATION_LEN], want[FZN_ROSTER_INCARNATION_LEN];
	unsigned seed;

	if (!fzn_roster_active(r, subject->key, got))
		return 0;
	for (seed = 1; seed < 256u; seed++) {
		incarnation_of(want, (uint8_t)seed);
		if (memcmp(got, want, sizeof(got)) == 0)
			return (uint8_t)seed;
	}
	return 255u;
}

static void test_the_record(void)
{
	rec_t r;
	fzn_roster_record_t v;
	uint8_t zero[FZN_ROSTER_INCARNATION_LEN] = { 0 };
	uint8_t body[FZN_ROSTER_BODY_MAX + 1u];
	uint8_t inc[FZN_ROSTER_INCARNATION_LEN];

	memset(body, 0x42, sizeof(body));
	incarnation_of(inc, 1);
	add(&r, &root, &alice, 1, 5);
	CHECK(r.len == FZN_ROSTER_MIN_LEN && fzn_roster_open(r.bytes, r.len, &v) == FZN_ROSTER_OK
	              && fzn_roster_object(v) == (uint8_t)FZN_OBJECT_ROSTER_ADD
	              && fzn_roster_seq(v) == 5u
	              && memcmp(fzn_roster_subject(v), alice.key, FZN_PUBKEY_LEN) == 0
	              && memcmp(fzn_roster_writer(v), root.key, FZN_PUBKEY_LEN) == 0,
	      "an add did not round-trip through its own parser");
	CHECK(r.bytes[FZN_ROSTER_OFF_OBJECT] == 135u && r.bytes[82] == 0u && r.bytes[89] == 5u,
	      "the add's object or seq is not where the header says");
	/* THE OFFSETS roster.situ STATES, as literals, so the header and the
	 * schema are two witnesses rather than one. */
	CHECK(FZN_ROSTER_OFF_WRITER == 2u && FZN_ROSTER_OFF_SUBJECT == 34u
	              && FZN_ROSTER_OFF_INCARNATION == 66u && FZN_ROSTER_OFF_SEQ == 82u
	              && FZN_ROSTER_OFF_SETTING == 90u && FZN_ROSTER_OFF_BODY_LEN == 92u
	              && FZN_ROSTER_MIN_LEN == 157u && FZN_ROSTER_MAX_LEN == 349u,
	      "the roster header's offsets are not the ones roster.situ states");
	CHECK(memcmp(r.bytes + 2, root.key, 32) == 0 && memcmp(r.bytes + 34, alice.key, 32) == 0
	              && memcmp(r.bytes + 66, inc, 16) == 0,
	      "the add's writer, subject or incarnation is not at 2, 34 or 66");

	CHECK(fzn_roster_issue_add(root.key, alice.key, zero, 1, &root.sign, r.bytes,
	                           sizeof(r.bytes), &r.len) == FZN_ROSTER_ERR_SHAPE,
	      "an all-zero incarnation was minted");
	CHECK(fzn_roster_issue_set(root.key, alice.key, inc, 1, 7, body, FZN_ROSTER_BODY_MAX + 1u,
	                           &root.sign, r.bytes, sizeof(r.bytes), &r.len)
	              == FZN_ROSTER_ERR_SHAPE,
	      "a setting body past the maximum was minted");
	CHECK(fzn_roster_issue_set(root.key, alice.key, inc, 1, 7, body, FZN_ROSTER_BODY_MAX,
	                           &root.sign, r.bytes, sizeof(r.bytes), &r.len) == FZN_ROSTER_OK
	              && r.len == FZN_ROSTER_MAX_LEN
	              && fzn_roster_open(r.bytes, r.len, &v) == FZN_ROSTER_OK,
	      "a setting at the maximum body would not mint or open");

	/* AN ADD CARRIES NO BODY AND NO SETTING: either is a second encoding. */
	add(&r, &root, &alice, 1, 5);
	r.bytes[FZN_ROSTER_OFF_SETTING + 1u] = 1u;
	CHECK(fzn_roster_open(r.bytes, r.len, &v) == FZN_ROSTER_ERR_SHAPE,
	      "an add carrying a setting number opened");
	add(&r, &root, &alice, 1, 5);
	r.bytes[FZN_ROSTER_OFF_OBJECT] = (uint8_t)FZN_OBJECT_WITHDRAWAL;
	CHECK(fzn_roster_open(r.bytes, r.len, &v) == FZN_ROSTER_ERR_SHAPE,
	      "a record carrying another object's tag opened");
	add(&r, &root, &alice, 1, 5);
	CHECK(fzn_roster_open(r.bytes, r.len - 1u, &v) == FZN_ROSTER_ERR_SHAPE,
	      "a record one byte short opened");
}

static void test_removal_is_for_good(void)
{
	static fzn_roster_entry_t entries[8];
	fzn_roster_t r;
	fzn_roster_authority_t a = authority_now(1000, NULL);
	rec_t add1, rm1, add1_other, add2, set1;
	uint8_t inc1[FZN_ROSTER_INCARNATION_LEN];
	uint8_t body[2] = { 1, 0 };

	incarnation_of(inc1, 1);
	CHECK(fzn_roster_init(&r, entries, 8) == FZN_ROSTER_OK, "fixture: init");
	add(&add1, &root, &alice, 1, 10);
	removal(&rm1, &root, &alice, 1, 11);
	add(&add1_other, &root, &alice, 1, 50);
	add(&add2, &root, &alice, 2, 12);

	CHECK(fzn_roster_admit(&r, view(&add1), NULL, 0, &a) == FZN_ROSTER_OK
	              && active_seed(&r, &alice) == 1u,
	      "the root's add did not make the incarnation active");
	CHECK(fzn_roster_admit(&r, view(&add1), NULL, 0, &a) == FZN_ROSTER_OK && r.used == 1u,
	      "the same add admitted twice was not idempotent");
	CHECK(fzn_roster_admit(&r, view(&rm1), NULL, 0, &a) == FZN_ROSTER_OK
	              && active_seed(&r, &alice) == 0u
	              && fzn_roster_removed(&r, alice.key, inc1),
	      "removal left the subject active");

	/* THE REPRODUCTION'S SHAPE: something newer about the removed
	 * incarnation arrives. A second add of it, at a far higher seq, is a
	 * contradiction and changes nothing; a setting on it is refused. */
	CHECK(fzn_roster_admit(&r, view(&add1_other), NULL, 0, &a) == FZN_ROSTER_ERR_CONFLICT
	              && active_seed(&r, &alice) == 0u,
	      "a newer add of a removed incarnation brought the subject back");
	CHECK(fzn_roster_issue_set(root.key, alice.key, inc1, 60, 1, body, sizeof(body),
	                           &root.sign, set1.bytes, sizeof(set1.bytes), &set1.len)
	                      == FZN_ROSTER_OK
	              && fzn_roster_admit(&r, view(&set1), NULL, 0, &a)
	                         == FZN_ROSTER_ERR_UNSUPPORTED
	              && active_seed(&r, &alice) == 0u,
	      "a setting on a removed incarnation was taken, or brought the subject back");

	/* A DELIBERATE RE-ADD is a new incarnation and a fresh subject. */
	CHECK(fzn_roster_admit(&r, view(&add2), NULL, 0, &a) == FZN_ROSTER_OK
	              && active_seed(&r, &alice) == 2u,
	      "re-adding the subject under a new incarnation did not make it active");
	CHECK(r.seq_seen == 12u, "the roster did not track the greatest seq it admitted");
}

static void test_removal_overtakes_add(void)
{
	static fzn_roster_entry_t entries[4];
	fzn_roster_t r;
	fzn_roster_authority_t a = authority_now(1000, NULL);
	rec_t add1, rm1;

	CHECK(fzn_roster_init(&r, entries, 4) == FZN_ROSTER_OK, "fixture: init");
	add(&add1, &root, &bob, 3, 20);
	removal(&rm1, &root, &bob, 3, 21);
	CHECK(fzn_roster_admit(&r, view(&rm1), NULL, 0, &a) == FZN_ROSTER_OK
	              && active_seed(&r, &bob) == 0u,
	      "a removal arriving before its add was not stored");
	CHECK(fzn_roster_admit(&r, view(&add1), NULL, 0, &a) == FZN_ROSTER_OK
	              && active_seed(&r, &bob) == 0u,
	      "an add arriving after its removal made the subject active");
}

static void test_two_live_incarnations(void)
{
	static fzn_roster_entry_t entries[4];
	fzn_roster_t r;
	fzn_roster_authority_t a = authority_now(1000, NULL);
	rec_t lo, hi, tie_root;
	uint8_t hops_bytes[1][FZN_HOP_LEN];
	fzn_chain_hop_t hops[1];

	CHECK(fzn_roster_init(&r, entries, 4) == FZN_ROSTER_OK, "fixture: init");
	add(&lo, &root, &alice, 4, 30);
	add(&hi, &root, &alice, 5, 31);
	CHECK(fzn_roster_admit(&r, view(&hi), NULL, 0, &a) == FZN_ROSTER_OK
	              && fzn_roster_admit(&r, view(&lo), NULL, 0, &a) == FZN_ROSTER_OK
	              && active_seed(&r, &alice) == 5u,
	      "of two live incarnations the greater seq was not active");

	/* AT EQUAL SEQ the writer's bytes decide. The member's key starts with
	 * a greater byte than the root's, so the member's add wins. */
	CHECK(fzn_chain_mint(root.key, member.key, &manage, 100, FZN_NO_EXPIRY, 0, &root.sign,
	                     hops_bytes[0]) == FZN_CHAIN_OK
	              && fzn_hop_open(hops_bytes[0], FZN_HOP_LEN, &hops[0]) == FZN_CHAIN_OK,
	      "fixture: the member's chain");
	add(&tie_root, &member, &alice, 6, 31);
	CHECK(member.key[0] > root.key[0]
	              && fzn_roster_admit(&r, view(&tie_root), hops, 1, &a) == FZN_ROSTER_OK
	              && active_seed(&r, &alice) == 6u,
	      "at equal seq the greater writer did not win");
}

static void test_standing(void)
{
	static fzn_roster_entry_t entries[8];
	static fzn_revocation_t rev_entries[4];
	fzn_roster_t r;
	fzn_revocation_store_t revoked;
	fzn_revocation_record_t revrec;
	fzn_hash_ops_t hash;
	uint8_t hop_ok[FZN_HOP_LEN], hop_cap[FZN_HOP_LEN], hop_else[FZN_HOP_LEN],
	        hop_exp[FZN_HOP_LEN], revbytes[FZN_REVOCATION_LEN];
	fzn_chain_hop_t ok[1], cap[1], elsewhere[1], expiring[1];
	fzn_roster_authority_t a = authority_now(1000, NULL);
	rec_t m_add, m_rm, s_add, x_add, x_rm, forged;

	hash.hash = stub_hash;
	hash.ctx = NULL;
	CHECK(fzn_roster_init(&r, entries, 8) == FZN_ROSTER_OK
	              && fzn_chain_mint(root.key, member.key, &manage, 100, FZN_NO_EXPIRY, 0,
	                                &root.sign, hop_ok) == FZN_CHAIN_OK
	              && fzn_chain_mint(root.key, member.key, &other_cap, 100, FZN_NO_EXPIRY, 0,
	                                &root.sign, hop_cap) == FZN_CHAIN_OK
	              && fzn_chain_mint(root.key, stranger.key, &manage, 100, FZN_NO_EXPIRY, 0,
	                                &root.sign, hop_else) == FZN_CHAIN_OK
	              && fzn_chain_mint(root.key, member.key, &manage, 100, 500, 0, &root.sign,
	                                hop_exp) == FZN_CHAIN_OK
	              && fzn_hop_open(hop_ok, FZN_HOP_LEN, &ok[0]) == FZN_CHAIN_OK
	              && fzn_hop_open(hop_cap, FZN_HOP_LEN, &cap[0]) == FZN_CHAIN_OK
	              && fzn_hop_open(hop_else, FZN_HOP_LEN, &elsewhere[0]) == FZN_CHAIN_OK
	              && fzn_hop_open(hop_exp, FZN_HOP_LEN, &expiring[0]) == FZN_CHAIN_OK,
	      "fixture: chains");

	add(&m_add, &member, &alice, 7, 40);
	removal(&m_rm, &member, &alice, 7, 41);
	add(&s_add, &stranger, &bob, 8, 42);
	CHECK(fzn_roster_admit(&r, view(&m_add), ok, 1, &a) == FZN_ROSTER_OK
	              && active_seed(&r, &alice) == 7u,
	      "a member with the roster's capability could not add");
	CHECK(fzn_roster_admit(&r, view(&s_add), NULL, 0, &a) == FZN_ROSTER_ERR_STANDING,
	      "a writer that is not the root and shows no chain was admitted");
	CHECK(fzn_roster_admit(&r, view(&m_add), cap, 1, &a) == FZN_ROSTER_ERR_STANDING,
	      "a chain for another capability gave standing");
	CHECK(fzn_roster_admit(&r, view(&m_add), elsewhere, 1, &a) == FZN_ROSTER_ERR_STANDING,
	      "a chain naming somebody else gave the writer standing");

	/* A FORGERY: the member's add re-signed by the stranger's key. */
	forged = m_add;
	mac(forged.bytes + forged.len - FZN_SIG_LEN, stranger.id, forged.bytes,
	    forged.len - FZN_SIG_LEN);
	CHECK(fzn_roster_admit(&r, view(&forged), ok, 1, &a) == FZN_ROSTER_ERR_SIGNATURE,
	      "a record not signed by its own writer was admitted");

	/* A LAPSED OR REVOKED GRANT: adds refused, removals still taken. */
	add(&x_add, &member, &bob, 9, 43);
	removal(&x_rm, &member, &bob, 9, 44);
	CHECK(fzn_roster_admit(&r, view(&x_add), expiring, 1, &a) == FZN_ROSTER_ERR_STANDING,
	      "an add under an expired grant was admitted");
	CHECK(fzn_roster_admit(&r, view(&x_rm), expiring, 1, &a) == FZN_ROSTER_OK
	              && fzn_roster_admit(&r, view(&x_add), ok, 1, &a) == FZN_ROSTER_OK
	              && active_seed(&r, &bob) == 0u,
	      "a removal under a since-expired grant was lost, and the subject came back");

	CHECK(fzn_revocation_store_init(&revoked, rev_entries, 4) == FZN_CHAIN_OK
	              && fzn_revocation_issue(root.key, &manage, member.key, 600, &root.sign,
	                                      revbytes) == FZN_CHAIN_OK
	              && fzn_revocation_open(revbytes, sizeof(revbytes), &revrec) == FZN_CHAIN_OK
	              && fzn_revocation_admit(&revoked, fzn_revocation_offer_root(revrec), root.key,
	                                      &root.sign, &hash, NULL) == FZN_CHAIN_OK,
	      "fixture: the root revokes the member's grant");
	a = authority_now(1000, &revoked);
	{
		static fzn_roster_entry_t e2[4];
		fzn_roster_t r2;
		rec_t y_add, y_rm;

		add(&y_add, &member, &alice, 10, 45);
		removal(&y_rm, &member, &alice, 10, 46);
		CHECK(fzn_roster_init(&r2, e2, 4) == FZN_ROSTER_OK
		              && fzn_roster_admit(&r2, view(&y_add), ok, 1, &a)
		                         == FZN_ROSTER_ERR_STANDING,
		      "a revoked writer's add was admitted");
		CHECK(fzn_roster_admit(&r2, view(&y_rm), ok, 1, &a) == FZN_ROSTER_OK,
		      "a revoked writer's removal was refused, which leaves a contact in place");
	}
	CHECK(fzn_roster_admit(&r, view(&m_rm), ok, 1, &a) == FZN_ROSTER_OK
	              && active_seed(&r, &alice) == 0u,
	      "the member's removal did not remove");
}

static void test_full(void)
{
	static fzn_roster_entry_t entries[1];
	fzn_roster_t r;
	fzn_roster_authority_t a = authority_now(1000, NULL);
	rec_t one, two;

	add(&one, &root, &alice, 11, 1);
	add(&two, &root, &bob, 12, 2);
	CHECK(fzn_roster_init(&r, entries, 1) == FZN_ROSTER_OK
	              && fzn_roster_admit(&r, view(&one), NULL, 0, &a) == FZN_ROSTER_OK
	              && fzn_roster_admit(&r, view(&two), NULL, 0, &a) == FZN_ROSTER_ERR_FULL
	              && fzn_roster_admit(&r, view(&one), NULL, 0, &a) == FZN_ROSTER_OK,
	      "a full roster did not refuse a new incarnation while still taking a held one");
	CHECK(fzn_roster_init(&r, entries, 0) == FZN_ROSTER_ERR_MALFORMED,
	      "a roster of no capacity was accepted");
}

/* THE PROPERTY THE DESIGN RESTS ON: what a host ends up with is a function of
 * the SET of records it admitted, never of their order. Every order of seven
 * records -- adds and removes over two subjects, three incarnations each side,
 * a removal ahead of its add among them -- must give the same active
 * incarnations and the same removals. 5040 orders. */
static void test_order_independence(void)
{
	static rec_t set[7];
	static fzn_roster_entry_t entries[8];
	fzn_roster_authority_t a = authority_now(1000, NULL);
	size_t perm[7] = { 0, 1, 2, 3, 4, 5, 6 };
	uint8_t want_alice = 0, want_bob = 0;
	int want_removed = -1, same = 1;
	unsigned long orders = 0;
	uint8_t inc2[FZN_ROSTER_INCARNATION_LEN];

	incarnation_of(inc2, 22);
	add(&set[0], &root, &alice, 21, 5);
	add(&set[1], &root, &alice, 22, 9);
	removal(&set[2], &root, &alice, 22, 10);
	add(&set[3], &root, &alice, 23, 7);
	add(&set[4], &root, &bob, 31, 3);
	removal(&set[5], &root, &bob, 31, 4);
	add(&set[6], &root, &bob, 32, 2);

	for (;;) {
		fzn_roster_t r;
		size_t i, j, k;
		int removed;

		(void)fzn_roster_init(&r, entries, 8);
		for (i = 0; i < 7; i++)
			if (fzn_roster_admit(&r, view(&set[perm[i]]), NULL, 0, &a) != FZN_ROSTER_OK)
				same = 0;
		removed = fzn_roster_removed(&r, alice.key, inc2);
		if (orders == 0) {
			want_alice = active_seed(&r, &alice);
			want_bob = active_seed(&r, &bob);
			want_removed = removed;
		} else if (active_seed(&r, &alice) != want_alice || active_seed(&r, &bob) != want_bob
		           || removed != want_removed) {
			same = 0;
		}
		orders++;

		/* next permutation, lexicographic */
		i = 6;
		while (i > 0 && perm[i - 1] >= perm[i])
			i--;
		if (i == 0)
			break;
		j = 6;
		while (perm[j] <= perm[i - 1])
			j--;
		k = perm[i - 1];
		perm[i - 1] = perm[j];
		perm[j] = k;
		for (j = 6; i < j; i++, j--) {
			k = perm[i];
			perm[i] = perm[j];
			perm[j] = k;
		}
	}
	CHECK(orders == 5040u, "the sweep did not walk every order of seven records");
	CHECK(same, "two orders of one record set gave different rosters");
	CHECK(want_alice == 23u && want_bob == 32u && want_removed == 1,
	      "the order-independent answer is not the right one");
}

int main(void)
{
	who_init(&root, 0x10u);
	who_init(&member, 0x20u);
	who_init(&stranger, 0x30u);
	who_init(&alice, 0x40u);
	who_init(&bob, 0x50u);
	memset(&manage, 0x61, sizeof(manage));
	memset(&other_cap, 0x62, sizeof(other_cap));

	test_the_record();
	test_removal_is_for_good();
	test_removal_overtakes_add();
	test_two_live_incarnations();
	test_standing();
	test_full();
	test_order_independence();

	printf("roster_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
