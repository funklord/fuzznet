/* roster_test -- a user's roster across the user's hosts. secs 388 and 394.
 *
 * Signing is a stub keyed by the first byte of the public key, as in
 * revocation_test: what is under test is which key a record is verified
 * under and what it then changes, not the curve.
 */

#include "../roster.h"
#include "../../chain/revocation.h"
#include "../../chain/root_log.h"
#include "../../chain/test/acts_stub.h"
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

static who_t root, member, member2, stranger, alice, bob;
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

static fzn_roster_authority_t authority(void)
{
	fzn_roster_authority_t a;

	memset(&a, 0, sizeof(a));
	a.root = root.key;
	a.capability = &manage;
	a.sign = &root.sign;
	return a;
}

/* A roster over caller-owned tables of its own. */
typedef struct held {
	fzn_roster_entry_t entries[8];
	fzn_roster_writer_t writers[4];
	fzn_roster_t r;
} held_t;

static int held_init(held_t *h)
{
	return fzn_roster_init(&h->r, h->entries, 8, h->writers, 4) == FZN_ROSTER_OK;
}

/* Which incarnation seed is active for `subject`, or 0 for none, judged
 * against `rev` with k = 2. */
static uint8_t active_seed(const fzn_roster_t *r, const who_t *subject,
                           const fzn_revocation_store_t *rev)
{
	uint8_t got[FZN_ROSTER_INCARNATION_LEN], want[FZN_ROSTER_INCARNATION_LEN];
	unsigned seed;

	if (!fzn_roster_active(r, subject->key, rev, 2, got))
		return 0;
	for (seed = 1; seed < 256u; seed++) {
		incarnation_of(want, (uint8_t)seed);
		if (memcmp(got, want, sizeof(got)) == 0)
			return (uint8_t)seed;
	}
	return 255u;
}

static fzn_roster_state_t state_of(const fzn_roster_t *r, const who_t *subject, uint8_t inc,
                                   const fzn_revocation_store_t *rev, size_t k)
{
	uint8_t incarnation[FZN_ROSTER_INCARNATION_LEN];

	incarnation_of(incarnation, inc);
	return fzn_roster_state(r, subject->key, incarnation, rev, k);
}

/* The member's one-hop chain from the root, delegable or not. */
static int member_chain(uint8_t bytes[FZN_HOP_LEN], fzn_chain_hop_t *hop, uint64_t expires)
{
	return fzn_chain_mint(root.key, member.key, &manage, 100, expires, 0, &root.sign, bytes)
	               == FZN_CHAIN_OK
	       && fzn_hop_open(bytes, FZN_HOP_LEN, hop) == FZN_CHAIN_OK;
}

/* A second member's one-hop chain from the root. Since sec 403 the root
 * retires alone, so the cases that need two ordinary removers use two
 * members rather than the root and one. */
static int member2_chain(uint8_t bytes[FZN_HOP_LEN], fzn_chain_hop_t *hop)
{
	return fzn_chain_mint(root.key, member2.key, &manage, 100, FZN_NO_EXPIRY, 0, &root.sign,
	                      bytes) == FZN_CHAIN_OK
	       && fzn_hop_open(bytes, FZN_HOP_LEN, hop) == FZN_CHAIN_OK;
}

/* The root revokes the member's grant into `store`. */
static int revoke_member(fzn_revocation_store_t *store, fzn_revocation_t *entries, size_t n)
{
	uint8_t bytes[FZN_REVOCATION_LEN];
	fzn_revocation_record_t rec;
	fzn_hash_ops_t hash;

	hash.hash = stub_hash;
	hash.ctx = NULL;
	return fzn_revocation_store_init(store, entries, n) == FZN_CHAIN_OK
	       && fzn_revocation_issue(root.key, &manage, member.key, 600, 0u, NULL, &root.sign, bytes)
	                  == FZN_CHAIN_OK
	       && fzn_revocation_open(bytes, sizeof(bytes), &rec) == FZN_CHAIN_OK
	       && fzn_revocation_admit(store, fzn_revocation_offer_root(rec), root.key, &root.sign,
	                               &hash, NULL) == FZN_CHAIN_OK;
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

/* ONE REMOVAL SUSPENDS; AN INCARNATION NEVER COMES BACK. sec 394. */
static void test_a_removal_suspends_for_good(void)
{
	static held_t h;
	fzn_roster_authority_t a = authority();
	rec_t add1, rm1, add1_other, add2, set1;
	uint8_t inc1[FZN_ROSTER_INCARNATION_LEN];
	uint8_t body[2] = { 1, 0 };
	uint8_t m2_bytes[FZN_HOP_LEN];
	fzn_chain_hop_t m2[1];

	incarnation_of(inc1, 1);
	CHECK(held_init(&h) && member2_chain(m2_bytes, &m2[0]), "fixture: init");
	add(&add1, &root, &alice, 1, 10);
	removal(&rm1, &member2, &alice, 1, 11);
	add(&add1_other, &root, &alice, 1, 50);
	add(&add2, &root, &alice, 2, 12);

	CHECK(fzn_roster_admit(&h.r, view(&add1), NULL, 0, &a) == FZN_ROSTER_OK
	              && active_seed(&h.r, &alice, NULL) == 1u
	              && state_of(&h.r, &alice, 1, NULL, 2) == FZN_ROSTER_ACTIVE,
	      "the root's add did not make the incarnation active");
	CHECK(fzn_roster_admit(&h.r, view(&add1), NULL, 0, &a) == FZN_ROSTER_OK && h.r.used == 1u,
	      "the same add admitted twice was not idempotent");
	CHECK(fzn_roster_admit(&h.r, view(&rm1), m2, 1, &a) == FZN_ROSTER_OK
	              && active_seed(&h.r, &alice, NULL) == 0u
	              && state_of(&h.r, &alice, 1, NULL, 2) == FZN_ROSTER_SUSPENDED,
	      "one removal did not suspend the subject");

	/* THE REPRODUCTION'S SHAPE: something newer about the removed
	 * incarnation arrives, and changes nothing. */
	CHECK(fzn_roster_admit(&h.r, view(&add1_other), NULL, 0, &a) == FZN_ROSTER_ERR_CONFLICT
	              && active_seed(&h.r, &alice, NULL) == 0u,
	      "a newer add of a removed incarnation brought the subject back");
	CHECK(fzn_roster_issue_set(root.key, alice.key, inc1, 60, 1, body, sizeof(body),
	                           &root.sign, set1.bytes, sizeof(set1.bytes), &set1.len)
	                      == FZN_ROSTER_OK
	              && fzn_roster_admit(&h.r, view(&set1), NULL, 0, &a)
	                         == FZN_ROSTER_ERR_UNSUPPORTED
	              && active_seed(&h.r, &alice, NULL) == 0u,
	      "a setting on a suspended incarnation was taken, or brought the subject back");

	/* A DELIBERATE RE-ADD is a new incarnation and a fresh subject. */
	CHECK(fzn_roster_admit(&h.r, view(&add2), NULL, 0, &a) == FZN_ROSTER_OK
	              && active_seed(&h.r, &alice, NULL) == 2u,
	      "re-adding the subject under a new incarnation did not make it active");
	CHECK(h.r.seq_seen == 12u, "the roster did not track the greatest seq it admitted -- a refused record must not move it");
}

static void test_removal_overtakes_add(void)
{
	static held_t h;
	fzn_roster_authority_t a = authority();
	rec_t add1, rm1;
	uint8_t m2_bytes[FZN_HOP_LEN];
	fzn_chain_hop_t m2[1];

	CHECK(held_init(&h) && member2_chain(m2_bytes, &m2[0]), "fixture: init");
	add(&add1, &root, &bob, 3, 20);
	removal(&rm1, &member2, &bob, 3, 21);
	CHECK(fzn_roster_admit(&h.r, view(&rm1), m2, 1, &a) == FZN_ROSTER_OK
	              && state_of(&h.r, &bob, 3, NULL, 2) == FZN_ROSTER_SUSPENDED,
	      "a removal arriving before its add was not stored");
	CHECK(fzn_roster_admit(&h.r, view(&add1), NULL, 0, &a) == FZN_ROSTER_OK
	              && active_seed(&h.r, &bob, NULL) == 0u,
	      "an add arriving after its removal made the subject active");
}

static void test_two_live_incarnations(void)
{
	static held_t h;
	fzn_roster_authority_t a = authority();
	rec_t lo, hi, tie;
	uint8_t hop_bytes[FZN_HOP_LEN];
	fzn_chain_hop_t hop[1];

	CHECK(held_init(&h) && member_chain(hop_bytes, &hop[0], FZN_NO_EXPIRY), "fixture");
	add(&lo, &root, &alice, 4, 30);
	add(&hi, &root, &alice, 5, 31);
	CHECK(fzn_roster_admit(&h.r, view(&hi), NULL, 0, &a) == FZN_ROSTER_OK
	              && fzn_roster_admit(&h.r, view(&lo), NULL, 0, &a) == FZN_ROSTER_OK
	              && active_seed(&h.r, &alice, NULL) == 5u,
	      "of two live incarnations the greater seq was not active");
	/* AT EQUAL SEQ the writer's bytes decide; the member's key sorts after
	 * the root's. */
	add(&tie, &member, &alice, 6, 31);
	CHECK(member.key[0] > root.key[0]
	              && fzn_roster_admit(&h.r, view(&tie), hop, 1, &a) == FZN_ROSTER_OK
	              && active_seed(&h.r, &alice, NULL) == 6u,
	      "at equal seq the greater writer did not win");
}

/* k DISTINCT WRITERS RETIRE; ONE WRITER TWICE IS ONE. sec 394. */
static void test_k_distinct_removers_retire(void)
{
	static held_t h;
	fzn_roster_authority_t a = authority();
	rec_t add1, rm_m2, rm_m2_again, rm_member;
	uint8_t hop_bytes[FZN_HOP_LEN];
	fzn_chain_hop_t hop[1];
	uint8_t m2_bytes[FZN_HOP_LEN];
	fzn_chain_hop_t m2[1];

	CHECK(held_init(&h) && member_chain(hop_bytes, &hop[0], FZN_NO_EXPIRY)
	              && member2_chain(m2_bytes, &m2[0]), "fixture");
	add(&add1, &root, &alice, 7, 40);
	removal(&rm_m2, &member2, &alice, 7, 41);
	removal(&rm_m2_again, &member2, &alice, 7, 42);
	removal(&rm_member, &member, &alice, 7, 43);

	CHECK(fzn_roster_admit(&h.r, view(&add1), NULL, 0, &a) == FZN_ROSTER_OK
	              && fzn_roster_admit(&h.r, view(&rm_m2), m2, 1, &a) == FZN_ROSTER_OK
	              && fzn_roster_admit(&h.r, view(&rm_m2_again), m2, 1, &a)
	                         == FZN_ROSTER_OK
	              && state_of(&h.r, &alice, 7, NULL, 2) == FZN_ROSTER_SUSPENDED,
	      "one writer removing twice counted as two");
	CHECK(state_of(&h.r, &alice, 7, NULL, 1) == FZN_ROSTER_RETIRED,
	      "with k = 1 one removal did not retire");
	CHECK(fzn_roster_admit(&h.r, view(&rm_member), hop, 1, &a) == FZN_ROSTER_OK
	              && state_of(&h.r, &alice, 7, NULL, 2) == FZN_ROSTER_RETIRED
	              && state_of(&h.r, &alice, 7, NULL, 0) == FZN_ROSTER_RETIRED,
	      "two distinct writers did not retire at k = 2, or 0 is not the default of 2");
	CHECK(state_of(&h.r, &alice, 7, NULL, 3) == FZN_ROSTER_SUSPENDED,
	      "two writers retired where the estate asks for three");
	/* ONE HOST UNDER TWO CHAINS IS ONE HOST: the member re-granted, and
	 * removing under each grant, is still one remover. */
	{
		static held_t h2;
		uint8_t second_bytes[2][FZN_HOP_LEN];
		fzn_chain_hop_t second[2];
		rec_t rm_again;

		/* A GRANT BY ANOTHER ROUTE, root -> stranger -> member, so the
		 * second chain is a different writer slot for the same key. */
		CHECK(held_init(&h2)
		              && fzn_chain_mint(root.key, stranger.key, &manage, 200, FZN_NO_EXPIRY, 1,
		                                &root.sign, second_bytes[0]) == FZN_CHAIN_OK
		              && fzn_chain_mint(stranger.key, member.key, &manage, 210, FZN_NO_EXPIRY,
		                                0, &stranger.sign, second_bytes[1]) == FZN_CHAIN_OK
		              && fzn_hop_open(second_bytes[0], FZN_HOP_LEN, &second[0]) == FZN_CHAIN_OK
		              && fzn_hop_open(second_bytes[1], FZN_HOP_LEN, &second[1]) == FZN_CHAIN_OK,
		      "fixture: the member's second grant, by another route");
		removal(&rm_again, &member, &alice, 7, 44);
		CHECK(fzn_roster_admit(&h2.r, view(&add1), NULL, 0, &a) == FZN_ROSTER_OK
		              && fzn_roster_admit(&h2.r, view(&rm_member), hop, 1, &a) == FZN_ROSTER_OK
		              && fzn_roster_admit(&h2.r, view(&rm_again), second, 2, &a)
		                         == FZN_ROSTER_OK
		              && h2.r.writers_used == 3u
		              && state_of(&h2.r, &alice, 7, NULL, 2) == FZN_ROSTER_SUSPENDED,
		      "one host removing under two grants counted as two writers");
	}
}

/* A REVOKED WRITER COUNTS FOR NOTHING, judged when the roster is read:
 * its add, its suspension and its share of a retirement. sec 394. */
static void test_a_revoked_writer_counts_for_nothing(void)
{
	static held_t h;
	static fzn_revocation_t rev_entries[4];
	fzn_revocation_store_t revoked = { 0 };
	fzn_roster_authority_t a = authority();
	rec_t m_add, m_rm, r_add, r_rm;
	uint8_t hop_bytes[FZN_HOP_LEN], exp_bytes[FZN_HOP_LEN];
	fzn_chain_hop_t hop[1], expiring[1];
	uint8_t m2_bytes[FZN_HOP_LEN];
	fzn_chain_hop_t m2[1];

	CHECK(held_init(&h) && member_chain(hop_bytes, &hop[0], FZN_NO_EXPIRY)
	              && revoke_member(&revoked, rev_entries, 4)
	              && member2_chain(m2_bytes, &m2[0]),
	      "fixture");
	add(&m_add, &member, &bob, 9, 50);
	removal(&m_rm, &member, &alice, 8, 51);
	add(&r_add, &root, &alice, 8, 52);
	removal(&r_rm, &member2, &alice, 8, 53);

	/* ADMITTED WITHOUT ASKING: arrival judges only signature and chain. */
	CHECK(fzn_roster_admit(&h.r, view(&m_add), hop, 1, &a) == FZN_ROSTER_OK
	              && fzn_roster_admit(&h.r, view(&r_add), NULL, 0, &a) == FZN_ROSTER_OK
	              && fzn_roster_admit(&h.r, view(&m_rm), hop, 1, &a) == FZN_ROSTER_OK,
	      "a record was judged against revocations on arrival");

	/* BEFORE THE HOST KNOWS: the member's add stands, its removal suspends. */
	CHECK(active_seed(&h.r, &bob, NULL) == 9u
	              && state_of(&h.r, &alice, 8, NULL, 2) == FZN_ROSTER_SUSPENDED,
	      "without revocations the member's records did not count");

	/* ONCE IT KNOWS, whatever order that came in: the add is gone and the
	 * suspension void, so alice is active again and bob absent. */
	CHECK(active_seed(&h.r, &bob, &revoked) == 0u
	              && state_of(&h.r, &bob, 9, &revoked, 2) == FZN_ROSTER_ABSENT,
	      "a revoked writer's add still made a subject active");
	CHECK(state_of(&h.r, &alice, 8, &revoked, 2) == FZN_ROSTER_ACTIVE
	              && active_seed(&h.r, &alice, &revoked) == 8u,
	      "a revoked writer's removal still suspended the subject");

	/* AND ITS SHARE OF A RETIREMENT: the two members retire at k = 2, and
	 * with the first revoked it falls back to the second's suspension. */
	CHECK(fzn_roster_admit(&h.r, view(&r_rm), m2, 1, &a) == FZN_ROSTER_OK
	              && state_of(&h.r, &alice, 8, NULL, 2) == FZN_ROSTER_RETIRED
	              && state_of(&h.r, &alice, 8, &revoked, 2) == FZN_ROSTER_SUSPENDED,
	      "a retirement kept counting a revoked writer");

	/* EXPIRY DOES NOT WITHDRAW: a writer whose grant lapsed after writing
	 * still counts; only revocation takes a writer out. */
	{
		static held_t h2;
		rec_t e_add;

		CHECK(held_init(&h2) && member_chain(exp_bytes, &expiring[0], 500), "fixture: expiring");
		add(&e_add, &member, &bob, 10, 54);
		CHECK(fzn_roster_admit(&h2.r, view(&e_add), expiring, 1, &a) == FZN_ROSTER_OK
		              && active_seed(&h2.r, &bob, NULL) == 10u,
		      "a writer whose grant has since expired was refused or did not count");
	}
}

/* THE ROOT RETIRES ALONE, sec 403: a root acts for the estate by itself, so
 * one removal by the root retires whatever k asks of everybody else. */
static void test_the_root_retires_alone(void)
{
	static held_t h;
	fzn_roster_authority_t a = authority();
	rec_t add1, rm1;

	CHECK(held_init(&h), "fixture: init");
	add(&add1, &root, &alice, 15, 80);
	removal(&rm1, &root, &alice, 15, 81);
	CHECK(fzn_roster_admit(&h.r, view(&add1), NULL, 0, &a) == FZN_ROSTER_OK
	              && fzn_roster_admit(&h.r, view(&rm1), NULL, 0, &a) == FZN_ROSTER_OK,
	      "fixture: the root adds and removes");
	CHECK(state_of(&h.r, &alice, 15, NULL, 2) == FZN_ROSTER_RETIRED
	              && state_of(&h.r, &alice, 15, NULL, 3) == FZN_ROSTER_RETIRED,
	      "the root's own removal did not retire at k = 2 and 3");
}

static void test_standing(void)
{
	static held_t h;
	fzn_roster_authority_t a = authority();
	uint8_t hop_ok[FZN_HOP_LEN], hop_cap[FZN_HOP_LEN], hop_else[FZN_HOP_LEN];
	fzn_chain_hop_t ok[1], cap[1], elsewhere[1];
	rec_t m_add, s_add, forged;

	CHECK(held_init(&h)
	              && fzn_chain_mint(root.key, member.key, &manage, 100, FZN_NO_EXPIRY, 0,
	                                &root.sign, hop_ok) == FZN_CHAIN_OK
	              && fzn_chain_mint(root.key, member.key, &other_cap, 100, FZN_NO_EXPIRY, 0,
	                                &root.sign, hop_cap) == FZN_CHAIN_OK
	              && fzn_chain_mint(root.key, stranger.key, &manage, 100, FZN_NO_EXPIRY, 0,
	                                &root.sign, hop_else) == FZN_CHAIN_OK
	              && fzn_hop_open(hop_ok, FZN_HOP_LEN, &ok[0]) == FZN_CHAIN_OK
	              && fzn_hop_open(hop_cap, FZN_HOP_LEN, &cap[0]) == FZN_CHAIN_OK
	              && fzn_hop_open(hop_else, FZN_HOP_LEN, &elsewhere[0]) == FZN_CHAIN_OK,
	      "fixture: chains");
	add(&m_add, &member, &alice, 11, 60);
	add(&s_add, &stranger, &bob, 12, 61);
	CHECK(fzn_roster_admit(&h.r, view(&m_add), ok, 1, &a) == FZN_ROSTER_OK,
	      "a member with the roster's capability could not add");
	CHECK(fzn_roster_admit(&h.r, view(&s_add), NULL, 0, &a) == FZN_ROSTER_ERR_STANDING,
	      "a writer that is not the root and shows no chain was admitted");
	CHECK(fzn_roster_admit(&h.r, view(&m_add), cap, 1, &a) == FZN_ROSTER_ERR_STANDING,
	      "a chain for another capability gave standing");
	CHECK(fzn_roster_admit(&h.r, view(&m_add), elsewhere, 1, &a) == FZN_ROSTER_ERR_STANDING,
	      "a chain naming somebody else gave the writer standing");
	forged = m_add;
	mac(forged.bytes + forged.len - FZN_SIG_LEN, stranger.id, forged.bytes,
	    forged.len - FZN_SIG_LEN);
	CHECK(fzn_roster_admit(&h.r, view(&forged), ok, 1, &a) == FZN_ROSTER_ERR_SIGNATURE,
	      "a record not signed by its own writer was admitted");
}

static void test_full(void)
{
	static fzn_roster_entry_t entries[1];
	static fzn_roster_writer_t writers[1];
	fzn_roster_t r;
	fzn_roster_authority_t a = authority();
	rec_t one, two, m_add;
	uint8_t hop_bytes[FZN_HOP_LEN];
	fzn_chain_hop_t hop[1];

	add(&one, &root, &alice, 13, 1);
	add(&two, &root, &bob, 14, 2);
	add(&m_add, &member, &alice, 13, 3);
	CHECK(member_chain(hop_bytes, &hop[0], FZN_NO_EXPIRY)
	              && fzn_roster_init(&r, entries, 1, writers, 1) == FZN_ROSTER_OK
	              && fzn_roster_admit(&r, view(&one), NULL, 0, &a) == FZN_ROSTER_OK
	              && fzn_roster_admit(&r, view(&two), NULL, 0, &a) == FZN_ROSTER_ERR_FULL
	              && fzn_roster_admit(&r, view(&one), NULL, 0, &a) == FZN_ROSTER_OK,
	      "a full roster did not refuse a new incarnation while still taking a held one");
	removal(&two, &member, &alice, 13, 4);
	CHECK(fzn_roster_admit(&r, view(&two), hop, 1, &a) == FZN_ROSTER_ERR_FULL,
	      "a full writer table took a writer it had no room for");
	CHECK(fzn_roster_init(&r, entries, 0, writers, 1) == FZN_ROSTER_ERR_MALFORMED
	              && fzn_roster_init(&r, entries, 1, writers, 0) == FZN_ROSTER_ERR_MALFORMED,
	      "a roster of no capacity was accepted");
}

/* THE PROPERTY THE DESIGN RESTS ON: what a host sees is a function of the
 * SETS it holds, records and revocations, never of arrival order. Every order
 * of seven records from three writers -- adds, a suspension, a retirement by
 * both, a removal ahead of its add -- judged with and without the member
 * revoked, gives one answer each time. 5040 orders. */
static void test_order_independence(void)
{
	static rec_t set[7];
	static held_t h;
	static fzn_revocation_t rev_entries[4];
	fzn_revocation_store_t revoked = { 0 };
	fzn_roster_authority_t a = authority();
	uint8_t hop_bytes[FZN_HOP_LEN];
	fzn_chain_hop_t hop[1];
	uint8_t m2_bytes[FZN_HOP_LEN];
	fzn_chain_hop_t m2[1];
	const fzn_chain_hop_t *chain_of[7];
	size_t perm[7] = { 0, 1, 2, 3, 4, 5, 6 };
	int want[4] = { -1, -1, -1, -1 }, same = 1;
	unsigned long orders = 0;

	CHECK(member_chain(hop_bytes, &hop[0], FZN_NO_EXPIRY)
	              && revoke_member(&revoked, rev_entries, 4)
	              && member2_chain(m2_bytes, &m2[0]), "fixture");
	add(&set[0], &root, &alice, 21, 5);
	add(&set[1], &member, &alice, 22, 9);
	removal(&set[2], &member2, &alice, 22, 10);
	removal(&set[3], &member, &alice, 22, 11);
	add(&set[4], &root, &bob, 31, 3);
	removal(&set[5], &member, &bob, 31, 4);
	add(&set[6], &member, &bob, 32, 2);
	chain_of[0] = NULL; chain_of[1] = hop; chain_of[2] = m2; chain_of[3] = hop;
	chain_of[4] = NULL; chain_of[5] = hop; chain_of[6] = hop;

	for (;;) {
		size_t i, j, k;
		int got[4];

		(void)held_init(&h);
		for (i = 0; i < 7; i++)
			if (fzn_roster_admit(&h.r, view(&set[perm[i]]), chain_of[perm[i]],
			                     chain_of[perm[i]] ? 1u : 0u, &a) != FZN_ROSTER_OK)
				same = 0;
		got[0] = (int)state_of(&h.r, &alice, 22, NULL, 2);
		got[1] = (int)state_of(&h.r, &alice, 22, &revoked, 2);
		got[2] = (int)active_seed(&h.r, &bob, NULL);
		got[3] = (int)active_seed(&h.r, &bob, &revoked);
		for (i = 0; i < 4; i++) {
			if (orders == 0)
				want[i] = got[i];
			else if (got[i] != want[i])
				same = 0;
		}
		orders++;

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
	CHECK(same, "two orders of one set of records and revocations gave different rosters");
	/* THE RIGHT ANSWERS: alice's 22 retired by both members, suspended by
	 * the second alone once the first is revoked; bob's 31 suspended by the member,
	 * so 32 (the member's) is active -- and with the member revoked, 31 is
	 * active again and 32 does not count. */
	CHECK(want[0] == (int)FZN_ROSTER_RETIRED && want[1] == (int)FZN_ROSTER_SUSPENDED
	              && want[2] == 32 && want[3] == 31,
	      "the order-independent answer is not the right one");
}

/* THE BUNDLE: a record and its writer's chain, as they travel, and the
 * restore path a host reads its own admitted records back through. */
static void test_bundle_and_restore(void)
{
	static held_t first, restart;
	static fzn_revocation_t rev_entries[4];
	static uint8_t packed[FZN_ROSTER_BUNDLE_MAX_LEN + 1u];
	uint8_t hop[1][FZN_HOP_LEN];
	fzn_revocation_store_t revoked = { 0 };
	fzn_roster_bundle_t b;
	fzn_roster_authority_t a = authority();
	rec_t m_add, m_rm;
	size_t len = 0;

	add(&m_add, &member, &bob, 40, 70);
	removal(&m_rm, &member, &bob, 40, 71);
	CHECK(fzn_chain_mint(root.key, member.key, &manage, 100, FZN_NO_EXPIRY, 0, &root.sign,
	                     hop[0]) == FZN_CHAIN_OK,
	      "fixture: the member's chain");

	/* ROUND TRIP, at the offsets roster.situ states: count at 0, length
	 * at 1, the record from 3, the hop after it. */
	CHECK(fzn_roster_bundle_pack(m_add.bytes, m_add.len, (const uint8_t (*)[FZN_HOP_LEN])hop, 1,
	                             packed, sizeof(packed), &len) == FZN_ROSTER_OK
	              && len == 3u + 157u + 179u && packed[0] == 1u && packed[1] == 0u
	              && packed[2] == 157u && memcmp(packed + 3, m_add.bytes, 157) == 0
	              && memcmp(packed + 160, hop[0], 179) == 0,
	      "a one-hop bundle is not laid out as roster.situ describes it");
	CHECK(FZN_ROSTER_BUNDLE_MAX_LEN == 1784u,
	      "the longest bundle is not the longest roster.situ allows");
	CHECK(fzn_roster_bundle_open(packed, len, &b) == FZN_ROSTER_OK && b.hop_count == 1u
	              && b.record.len == m_add.len && held_init(&first)
	              && fzn_roster_admit(&first.r, b.record, b.hops, b.hop_count, &a)
	                         == FZN_ROSTER_OK
	              && active_seed(&first.r, &bob, NULL) == 40u,
	      "a bundle would not open, or its record would not admit on its own chain");
	CHECK(fzn_roster_bundle_open(packed, len + 1u, &b) == FZN_ROSTER_ERR_SHAPE
	              && fzn_roster_bundle_open(packed, len - 1u, &b) == FZN_ROSTER_ERR_SHAPE,
	      "a bundle with a byte too many or too few opened");
	packed[0] = (uint8_t)(FZN_CHAIN_MAX_HOPS + 1u);
	CHECK(fzn_roster_bundle_open(packed, len, &b) == FZN_ROSTER_ERR_SHAPE,
	      "a bundle claiming more hops than a chain may have opened");
	packed[0] = 1u;
	CHECK(fzn_roster_bundle_open(packed, len, &b) == FZN_ROSTER_OK, "fixture: reopen");

	/* A RESTART REPRODUCES WHAT WAS HELD, AND THE READER DECIDES WHAT
	 * COUNTS. The member's removal is restored after the root revoked the
	 * member; it is held either way, and it suspends only while the
	 * member is not known to be revoked. */
	CHECK(revoke_member(&revoked, rev_entries, 4) && held_init(&restart)
	              && fzn_roster_restore(&restart.r, view(&m_add), b.hops, 1, &a) == FZN_ROSTER_OK
	              && fzn_roster_restore(&restart.r, view(&m_rm), b.hops, 1, &a) == FZN_ROSTER_OK
	              && state_of(&restart.r, &bob, 40, NULL, 2) == FZN_ROSTER_SUSPENDED
	              && state_of(&restart.r, &bob, 40, &revoked, 2) == FZN_ROSTER_ABSENT,
	      "restoring did not reproduce what was held, or the reader's revocations did not "
	      "decide what counts");

	/* AND RESTORE STILL VERIFIES: a record whose signature does not hold
	 * is refused. */
	m_rm.bytes[FZN_ROSTER_OFF_SEQ] ^= 1u;
	CHECK(held_init(&restart)
	              && fzn_roster_restore(&restart.r, view(&m_rm), b.hops, 1, &a)
	                         == FZN_ROSTER_ERR_SIGNATURE,
	      "restore admitted a record whose signature does not verify");
}

/* ---- several roots, sec 413 ------------------------------------------- */

static const fzn_hash_ops_t HASH = { stub_hash, NULL };

/* R, the genesis, adds S. With the set in the authority S writes as a root:
 * its add stands and its removal retires alone, and a chain S minted for M
 * is standing too. Without the set S is a stranger (the control). R then
 * removes S at the cut after S's logged add of alice: that add still counts,
 * S's removal of alice and the chain from S -- neither logged -- do not. With
 * no cut, nothing S did counts. */
static void test_several_roots_write(void)
{
	static fzn_root_change_t changes[8];
	static acts_stub_t log;
	static fzn_revocation_t rev_entries[4];
	static held_t h;
	fzn_act_log_ops_t acts;
	fzn_root_set_t set;
	fzn_root_view_t v;
	fzn_root_ops_t ops;
	fzn_revocation_store_t rev;
	fzn_roster_authority_t a = authority(), pinned = authority();
	who_t second;
	rec_t s_add, s_rem, m_add;
	uint8_t change[FZN_ROOT_REMOVE_LEN];
	uint8_t act[FZN_REVOCATION_ID_LEN], cut[FZN_ROOT_ACT_ID_LEN];
	uint8_t hop_bytes[FZN_HOP_LEN];
	fzn_chain_hop_t hop;

	who_init(&second, 0x70u);
	memset(&log, 0, sizeof(log));
	acts_stub_ops(&log, &acts);
	CHECK(fzn_root_set_init(&set, root.key, changes, 8) == FZN_ROOT_LOG_OK
	              && fzn_root_add_issue(root.key, second.key, &root.sign, change)
	                         == FZN_ROOT_LOG_OK
	              && fzn_root_set_admit(&set, change, FZN_ROOT_ADD_LEN, &root.sign, &HASH)
	                         == FZN_ROOT_LOG_OK
	              && fzn_root_view_init(&v, &set, &acts) == FZN_ROOT_LOG_OK
	              && fzn_revocation_store_init(&rev, rev_entries, 4) == FZN_CHAIN_OK,
	      "fixture: R's set with S in it");
	fzn_root_view_ops(&v, &ops);
	CHECK(fzn_revocation_store_set_roots(&rev, &ops, &HASH) == FZN_CHAIN_OK,
	      "fixture: the set attached to the reader's store");
	a.roots = &ops;
	a.hash = &HASH;

	add(&s_add, &second, &alice, 1, 1);
	removal(&s_rem, &second, &alice, 1, 2);
	add(&m_add, &member, &bob, 2, 3);
	CHECK(fzn_chain_mint(second.key, member.key, &manage, 100, 0, 0, &second.sign, hop_bytes)
	              == FZN_CHAIN_OK
	              && fzn_hop_open(hop_bytes, FZN_HOP_LEN, &hop) == FZN_CHAIN_OK,
	      "fixture: S's grant to M");

	CHECK(held_init(&h), "fixture: the roster");
	CHECK(fzn_roster_admit(&h.r, view(&s_add), NULL, 0, &pinned) == FZN_ROSTER_ERR_STANDING,
	      "the control: a root the pinned authority does not know wrote alone");
	CHECK(fzn_roster_admit(&h.r, view(&m_add), &hop, 1, &pinned) == FZN_ROSTER_ERR_STANDING,
	      "the control: a chain from a root the pinned authority does not know stood");
	a.hash = NULL;
	CHECK(fzn_roster_admit(&h.r, view(&s_add), NULL, 0, &a) == FZN_ROSTER_ERR_MALFORMED,
	      "a root set with no hash to name its acts was taken");
	a.hash = &HASH;

	CHECK(fzn_roster_admit(&h.r, view(&s_add), NULL, 0, &a) == FZN_ROSTER_OK
	              && fzn_roster_admit(&h.r, view(&m_add), &hop, 1, &a) == FZN_ROSTER_OK,
	      "a member root's add, or a chain from it, was refused");
	CHECK(state_of(&h.r, &alice, 1, &rev, 2) == FZN_ROSTER_ACTIVE
	              && state_of(&h.r, &bob, 2, &rev, 2) == FZN_ROSTER_ACTIVE,
	      "what a member root wrote, directly or by a chain, is not active");
	CHECK(fzn_roster_admit(&h.r, view(&s_rem), NULL, 0, &a) == FZN_ROSTER_OK
	              && state_of(&h.r, &alice, 1, &rev, 2) == FZN_ROSTER_RETIRED,
	      "a member root's removal did not retire alone");

	/* S LOGS ITS ADD OF ALICE, and R removes S at the cut after it. */
	CHECK(stub_hash(NULL, act, sizeof(act), s_add.bytes, s_add.len)
	              && acts_stub_log(&log, second.key, NULL, act, cut)
	              && fzn_root_remove_issue(root.key, second.key, cut, &root.sign, change)
	                         == FZN_ROOT_LOG_OK
	              && fzn_root_set_admit(&set, change, FZN_ROOT_REMOVE_LEN, &root.sign, &HASH)
	                         == FZN_ROOT_LOG_OK
	              && fzn_root_view_init(&v, &set, &acts) == FZN_ROOT_LOG_OK,
	      "fixture: S's log entry and R's removal of S at it");
	CHECK(state_of(&h.r, &alice, 1, &rev, 2) == FZN_ROSTER_ACTIVE,
	      "after S's removal, its logged add or its unlogged removal was judged wrongly");
	CHECK(state_of(&h.r, &bob, 2, &rev, 2) == FZN_ROSTER_ABSENT,
	      "a chain from a removed root, its first hop never logged, still counted");

	/* WITH NO CUT, nothing S did counts. */
	{
		static fzn_root_change_t c2[8];
		fzn_root_set_t set2;

		CHECK(fzn_root_set_init(&set2, root.key, c2, 8) == FZN_ROOT_LOG_OK
		              && fzn_root_add_issue(root.key, second.key, &root.sign, change)
		                         == FZN_ROOT_LOG_OK
		              && fzn_root_set_admit(&set2, change, FZN_ROOT_ADD_LEN, &root.sign, &HASH)
		                         == FZN_ROOT_LOG_OK
		              && fzn_root_remove_issue(root.key, second.key, NULL, &root.sign, change)
		                         == FZN_ROOT_LOG_OK
		              && fzn_root_set_admit(&set2, change, FZN_ROOT_REMOVE_LEN, &root.sign,
		                                    &HASH) == FZN_ROOT_LOG_OK
		              && fzn_root_view_init(&v, &set2, &acts) == FZN_ROOT_LOG_OK,
		      "fixture: S removed with nothing kept");
		CHECK(state_of(&h.r, &alice, 1, &rev, 2) == FZN_ROSTER_ABSENT,
		      "a root removed with no cut still had its add counted");
	}
}

/* A REVOKED MEMBER'S RECORDS STAND UP TO ITS CUT, sec 496. The member adds
 * alice, logged at seq 0, and then -- after a theft, say -- adds bob, logged
 * at seq 1. The root revokes the member with the cut at alice's entry: alice
 * stays active and bob is absent. With no act log, neither counts, which is
 * what a revocation meant before votes carried a cut. Withdrawn -- the
 * device found unharmed -- and both count again. */
static void test_a_revoked_writers_records_stand_to_the_cut(void)
{
	static held_t h;
	static fzn_revocation_t rev_entries[4];
	static acts_stub_t log;
	fzn_revocation_store_t rev;
	fzn_act_log_ops_t acts;
	fzn_roster_authority_t a = authority();
	rec_t m_alice, m_bob;
	uint8_t hop_bytes[FZN_HOP_LEN], bytes[FZN_REVOCATION_LEN];
	uint8_t act[FZN_REVOCATION_ID_LEN], at_alice[FZN_ROOT_ACT_ID_LEN];
	uint8_t at_bob[FZN_ROOT_ACT_ID_LEN], vote_id[FZN_REVOCATION_ID_LEN];
	fzn_revocation_record_t vote;
	fzn_chain_hop_t hop[1];

	a.hash = &HASH;
	memset(&log, 0, sizeof(log));
	CHECK(held_init(&h) && member_chain(hop_bytes, &hop[0], FZN_NO_EXPIRY)
	              && fzn_revocation_store_init(&rev, rev_entries, 4) == FZN_CHAIN_OK,
	      "fixture");
	add(&m_alice, &member, &alice, 1, 60);
	add(&m_bob, &member, &bob, 2, 61);
	CHECK(fzn_roster_admit(&h.r, view(&m_alice), hop, 1, &a) == FZN_ROSTER_OK
	              && fzn_roster_admit(&h.r, view(&m_bob), hop, 1, &a) == FZN_ROSTER_OK,
	      "the member's adds were refused with a hash and no root set");

	/* THE MEMBER'S LOG: alice, then bob. */
	CHECK(stub_hash(NULL, act, sizeof(act), m_alice.bytes, m_alice.len)
	              && acts_stub_log(&log, member.key, NULL, act, at_alice)
	              && stub_hash(NULL, act, sizeof(act), m_bob.bytes, m_bob.len)
	              && acts_stub_log(&log, member.key, at_alice, act, at_bob),
	      "fixture: the member's log");

	/* THE ROOT REVOKES THE MEMBER, trusting it up to alice. */
	CHECK(fzn_revocation_issue(root.key, &manage, member.key, 600, 0u, at_alice, &root.sign, bytes)
	              == FZN_CHAIN_OK
	              && fzn_revocation_open(bytes, sizeof(bytes), &vote) == FZN_CHAIN_OK
	              && fzn_revocation_admit(&rev, fzn_revocation_offer_root(vote), root.key,
	                                      &root.sign, &HASH, NULL) == FZN_CHAIN_OK
	              && stub_hash(NULL, vote_id, sizeof(vote_id), bytes, sizeof(bytes)),
	      "fixture: the root's vote with a cut");
	CHECK(state_of(&h.r, &alice, 1, &rev, 2) == FZN_ROSTER_ABSENT
	              && state_of(&h.r, &bob, 2, &rev, 2) == FZN_ROSTER_ABSENT,
	      "the control: with no act log a revoked member's add still counted");
	acts_stub_ops(&log, &acts);
	CHECK(fzn_revocation_store_set_acts(&rev, &acts) == FZN_CHAIN_OK, "fixture: the act log");
	CHECK(state_of(&h.r, &alice, 1, &rev, 2) == FZN_ROSTER_ACTIVE,
	      "a revoked member's add before its cut did not stand");
	CHECK(state_of(&h.r, &bob, 2, &rev, 2) == FZN_ROSTER_ABSENT,
	      "a revoked member's add after its cut stood");

	/* FOUND UNHARMED: the root withdraws, and bob is back. */
	CHECK(fzn_revocation_issue_withdrawal(root.key, &manage, member.key, 700, 0u, vote_id,
	                                      &root.sign, bytes) == FZN_CHAIN_OK
	              && fzn_revocation_open(bytes, sizeof(bytes), &vote) == FZN_CHAIN_OK
	              && fzn_revocation_admit(&rev, fzn_revocation_offer_root(vote), root.key,
	                                      &root.sign, &HASH, NULL) == FZN_CHAIN_OK,
	      "fixture: the root's withdrawal");
	CHECK(state_of(&h.r, &alice, 1, &rev, 2) == FZN_ROSTER_ACTIVE
	              && state_of(&h.r, &bob, 2, &rev, 2) == FZN_ROSTER_ACTIVE,
	      "undoing the revocation did not bring the member's records back");
	(void)at_bob;
}

/* A GRANT MADE BEFORE THE CUT KEEPS ITS DEVICE, sec 496. The member, on a
 * delegable grant, grants member2 and logs that hop; member2 adds bob. The
 * root revokes the member at the hop's entry: member2's add stands, since
 * what the revoked member did next in member2's chain -- the grant -- is
 * before the line. At a cut that keeps nothing, it falls. */
static void test_a_grant_before_the_cut_keeps_its_device(void)
{
	static held_t h;
	static fzn_revocation_t rev_entries[4];
	static acts_stub_t log;
	fzn_revocation_store_t rev;
	fzn_act_log_ops_t acts;
	fzn_roster_authority_t a = authority();
	rec_t d_bob;
	uint8_t hops_bytes[2][FZN_HOP_LEN], bytes[FZN_REVOCATION_LEN];
	uint8_t act[FZN_REVOCATION_ID_LEN], at_grant[FZN_ROOT_ACT_ID_LEN];
	uint8_t vote_id[FZN_REVOCATION_ID_LEN];
	fzn_revocation_record_t vote;
	fzn_chain_hop_t hops[2];

	a.hash = &HASH;
	CHECK(held_init(&h)
	              && fzn_chain_mint(root.key, member.key, &manage, 100, FZN_NO_EXPIRY, 1,
	                                &root.sign, hops_bytes[0]) == FZN_CHAIN_OK
	              && fzn_hop_open(hops_bytes[0], FZN_HOP_LEN, &hops[0]) == FZN_CHAIN_OK
	              && fzn_chain_mint(member.key, member2.key, &manage, 110, FZN_NO_EXPIRY, 0,
	                                &member.sign, hops_bytes[1]) == FZN_CHAIN_OK
	              && fzn_hop_open(hops_bytes[1], FZN_HOP_LEN, &hops[1]) == FZN_CHAIN_OK
	              && fzn_revocation_store_init(&rev, rev_entries, 4) == FZN_CHAIN_OK,
	      "fixture: root -> member -> member2");
	add(&d_bob, &member2, &bob, 3, 70);
	CHECK(fzn_roster_admit(&h.r, view(&d_bob), hops, 2, &a) == FZN_ROSTER_OK,
	      "member2's add on a two-hop chain was refused");
	memset(&log, 0, sizeof(log));
	CHECK(stub_hash(NULL, act, sizeof(act), hops_bytes[1], FZN_HOP_LEN)
	              && acts_stub_log(&log, member.key, NULL, act, at_grant),
	      "fixture: the member logs its grant");
	acts_stub_ops(&log, &acts);
	CHECK(fzn_revocation_store_set_acts(&rev, &acts) == FZN_CHAIN_OK, "fixture: the act log");
	CHECK(fzn_revocation_issue(root.key, &manage, member.key, 600, 0u, at_grant, &root.sign,
	                           bytes) == FZN_CHAIN_OK
	              && fzn_revocation_open(bytes, sizeof(bytes), &vote) == FZN_CHAIN_OK
	              && fzn_revocation_admit(&rev, fzn_revocation_offer_root(vote), root.key,
	                                      &root.sign, &HASH, NULL) == FZN_CHAIN_OK
	              && stub_hash(NULL, vote_id, sizeof(vote_id), bytes, sizeof(bytes)),
	      "fixture: the root revokes the member at its grant");
	CHECK(state_of(&h.r, &bob, 3, &rev, 2) == FZN_ROSTER_ACTIVE,
	      "a device granted before its grantor's cut lost its record");
	CHECK(fzn_revocation_reissue(root.key, &manage, member.key, 610, 0u, vote_id, NULL,
	                             &root.sign, bytes) == FZN_CHAIN_OK
	              && fzn_revocation_open(bytes, sizeof(bytes), &vote) == FZN_CHAIN_OK
	              && fzn_revocation_admit(&rev, fzn_revocation_offer_root(vote), root.key,
	                                      &root.sign, &HASH, NULL) == FZN_CHAIN_OK
	              && state_of(&h.r, &bob, 3, &rev, 2) == FZN_ROSTER_ABSENT,
	      "with the cut withdrawn to nothing, the device's record still counted");
}

int main(void)
{
	who_init(&root, 0x10u);
	who_init(&member, 0x20u);
	who_init(&member2, 0x28u);
	who_init(&stranger, 0x30u);
	who_init(&alice, 0x40u);
	who_init(&bob, 0x50u);
	memset(&manage, 0x61, sizeof(manage));
	memset(&other_cap, 0x62, sizeof(other_cap));

	test_the_record();
	test_a_removal_suspends_for_good();
	test_removal_overtakes_add();
	test_two_live_incarnations();
	test_k_distinct_removers_retire();
	test_a_revoked_writer_counts_for_nothing();
	test_the_root_retires_alone();
	test_standing();
	test_full();
	test_order_independence();
	test_bundle_and_restore();
	test_several_roots_write();
	test_a_revoked_writers_records_stand_to_the_cut();
	test_a_grant_before_the_cut_keeps_its_device();

	printf("roster_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
