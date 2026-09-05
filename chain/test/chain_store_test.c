/* Tests for chain/chain_store.c: where a verified chain lives.
 *
 * TWO PROPERTIES HERE ARE THE POINT AND NEITHER IS ABOUT STORAGE.
 *
 * The first is that finding a chain is not being authorised by it. The store
 * verifies on admission, and a revocation can arrive AFTERWARDS -- so a
 * chain admitted this morning and revoked at noon must still be handed back
 * by lookup and must still be refused by `fzn_chain_verify`. A store that
 * quietly dropped it would look safer and would be worse: the caller would
 * stop re-verifying, and then a revocation arriving later would change
 * nothing. The case below admits, revokes, and asserts BOTH halves.
 *
 * The second is that admitting a chain is not adopting an issuer. There is
 * no follow predicate to assert against -- `record/journal.h` exposes none --
 * so the case reads the door instead: a record from an unfollowed issuer is
 * refused with FZN_JOURNAL_ERR_UNKNOWN_ISSUER, and admitting a chain naming
 * that issuer must leave that refusal exactly where it was. project.md sec
 * 95 records why an identifier was not invented for this.
 */

#include "../chain_store.h"

#include "../../record/journal.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

#if defined(__GNUC__)
#define FZN_CHECK_PRINTF __attribute__((format(printf, 3, 4)))
#else
#define FZN_CHECK_PRINTF
#endif

static void check_at(int ok, int line, const char *fmt, ...) FZN_CHECK_PRINTF;

static void check_at(int ok, int line, const char *fmt, ...)
{
	va_list ap;

	checks++;
	if (ok)
		return;

	failures++;
	fprintf(stderr, "  FAIL chain_store_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)
#define REQUIRE(cond, ...)                                   \
	do {                                                 \
		int require_ok = (cond) ? 1 : 0;             \
		check_at(require_ok, __LINE__, __VA_ARGS__); \
		if (!require_ok)                             \
			return;                              \
	} while (0)

static uint8_t signing_as;

static void mac(uint8_t out[FZN_SIG_LEN], uint8_t identity, const uint8_t *msg, size_t len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	h ^= identity;
	h *= 0x100000001b3ull;
	for (i = 0; i < len; i++) {
		h ^= msg[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h ^= (uint64_t)i + 0x9e3779b97f4a7c15ull;
		h *= 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 24);
	}
}

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	(void)ctx;
	mac(sig, signing_as, msg, msg_len);
	return 1;
}

static int stub_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	mac(want, pubkey[0], msg, msg_len);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

static const fzn_sign_ops_t OPS = { stub_verify, stub_sign, NULL };

static void key(uint8_t out[FZN_PUBKEY_LEN], uint8_t seed)
{
	size_t i;

	for (i = 0; i < FZN_PUBKEY_LEN; i++)
		out[i] = (uint8_t)(seed + (i * 7u));
}

static void cap_id(fzn_cap_id_t *out, uint8_t seed)
{
	size_t i;

	for (i = 0; i < FZN_CAP_ID_LEN; i++)
		out->b[i] = (uint8_t)(seed + (i * 11u));
}


static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	(void)ctx;
	for (i = 0; i < in_len; i++) {
		h ^= in[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < out_len; i++) {
		h ^= (uint64_t)i + 0x9e3779b97f4a7c15ull;
		h *= 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 32);
	}
	return 1;
}

static const fzn_hash_ops_t HASH = { stub_hash, NULL };

struct fixture {
	uint8_t bytes[FZN_HOP_LEN];
	fzn_chain_hop_t hop;
	uint8_t root[FZN_PUBKEY_LEN];
	uint8_t grantee[FZN_PUBKEY_LEN];
	fzn_cap_id_t cap;
	fzn_revocation_store_t revs;
	fzn_revocation_t rev_storage[2];
	fzn_chain_store_t store;
	fzn_chain_entry_t storage[2];
};

/* A single-hop chain: the root grants `cap` to `grantee`, expiring at 5000. */
static int build(struct fixture *f)
{
	memset(f, 0, sizeof(*f));
	key(f->root, 0x11);
	key(f->grantee, 0x22);
	cap_id(&f->cap, 0x33);
	signing_as = 0x11;
	if (fzn_chain_mint(f->root, f->grantee, &f->cap, 100, 5000, 1, &OPS, f->bytes)
	    != FZN_CHAIN_OK)
		return 0;
	if (fzn_hop_open(f->bytes, FZN_HOP_LEN, &f->hop) != FZN_CHAIN_OK)
		return 0;
	if (fzn_revocation_store_init(&f->revs, f->rev_storage, 2) != FZN_CHAIN_OK)
		return 0;
	return fzn_chain_store_init(&f->store, f->storage, 2) == FZN_CHAIN_OK;
}

/* ---- the cases -------------------------------------------------------- */

static void test_init_refuses_what_cannot_hold_anything(void)
{
	fzn_chain_store_t s;
	fzn_chain_entry_t e[1];

	CHECK(fzn_chain_store_init(NULL, e, 1) == FZN_CHAIN_ERR_MALFORMED,
	      "init accepted a null store");
	CHECK(fzn_chain_store_init(&s, NULL, 1) == FZN_CHAIN_ERR_MALFORMED,
	      "init accepted null entries");
	/* A zero capacity records nothing and reports success while doing it,
	 * which is `fzn_revocation_store_init`'s argument inherited. */
	CHECK(fzn_chain_store_init(&s, e, 0) == FZN_CHAIN_ERR_MALFORMED,
	      "init accepted a capacity of zero");
	CHECK(fzn_chain_store_init(&s, e, 1) == FZN_CHAIN_OK, "init refused a sound store");
	CHECK(fzn_chain_store_count(&s) == 0u, "a fresh store already held something");
}

static void test_only_a_chain_that_verifies_is_kept(void)
{
	struct fixture f;
	uint8_t other_root[FZN_PUBKEY_LEN];
	fzn_cap_id_t other_cap;

	REQUIRE(build(&f), "the fixture does not build");
	key(other_root, 0x99);
	cap_id(&other_cap, 0x99);

	/* Verified against the WRONG root: the signature is real and the root
	 * is not the one that made it. */
	CHECK(fzn_chain_store_admit(&f.store, &f.hop, 1, other_root, &f.cap, 200, &OPS, NULL,
	                            NULL) != FZN_CHAIN_OK,
	      "a chain that does not verify against the given root was admitted");
	CHECK(fzn_chain_store_count(&f.store) == 0u,
	      "a refused admission still consumed an entry");

	/* And for a capability the chain does not carry. */
	CHECK(fzn_chain_store_admit(&f.store, &f.hop, 1, f.root, &other_cap, 200, &OPS, NULL,
	                            NULL) != FZN_CHAIN_OK,
	      "a chain for another capability was admitted");
	CHECK(fzn_chain_store_count(&f.store) == 0u,
	      "a refused admission still consumed an entry");

	CHECK(fzn_chain_store_admit(&f.store, &f.hop, 1, f.root, &f.cap, 200, &OPS, NULL, NULL)
	              == FZN_CHAIN_OK,
	      "a chain that verifies was refused");
	CHECK(fzn_chain_store_count(&f.store) == 1u, "an admitted chain was not counted");
}

static void test_what_goes_in_comes_back_out(void)
{
	struct fixture f;
	const uint8_t *bytes = NULL;
	size_t len = 0;
	fzn_chain_hop_t back[FZN_CHAIN_MAX_HOPS];
	size_t back_count = 0;

	REQUIRE(build(&f), "the fixture does not build");
	REQUIRE(fzn_chain_store_admit(&f.store, &f.hop, 1, f.root, &f.cap, 200, &OPS, NULL, NULL)
	                == FZN_CHAIN_OK,
	        "admit refused a sound chain");

	CHECK(fzn_chain_store_lookup(&f.store, f.root, &f.cap, f.grantee, 200, &bytes, &len),
	      "a chain just admitted was not found");
	/* THE BYTES ARE A VIEW INTO THE STORE, not a copy -- which is what
	 * lets a caller hand them straight on. */
	CHECK(bytes == f.storage[0].bytes, "lookup returned a copy rather than a view");
	CHECK(len == FZN_CHAIN_HEADER_LEN + FZN_HOP_LEN,
	      "the packed length is not a header and one hop");

	/* AND THEY PARSE BACK TO THE CHAIN THAT WENT IN, which is the round
	 * trip that matters: a store that kept bytes nothing could re-open
	 * would satisfy every other case here. */
	CHECK(fzn_chain_open(bytes, len, back, &back_count) == FZN_CHAIN_OK,
	      "the stored bytes did not re-open");
	CHECK(back_count == 1u, "the re-opened chain has a different hop count");
	CHECK(memcmp(back[0].base, f.hop.base, FZN_HOP_LEN) == 0,
	      "the re-opened hop is not the one that was admitted");
}

static void test_a_lookup_that_does_not_match_answers_nothing(void)
{
	struct fixture f;
	uint8_t other[FZN_PUBKEY_LEN];
	fzn_cap_id_t other_cap;
	const uint8_t *bytes = (const uint8_t *)1;
	size_t len = 99u;

	REQUIRE(build(&f), "the fixture does not build");
	key(other, 0x77);
	cap_id(&other_cap, 0x77);
	REQUIRE(fzn_chain_store_admit(&f.store, &f.hop, 1, f.root, &f.cap, 200, &OPS, NULL, NULL)
	                == FZN_CHAIN_OK,
	        "admit refused a sound chain");

	CHECK(!fzn_chain_store_lookup(&f.store, other, &f.cap, f.grantee, 200, &bytes, &len),
	      "a lookup under another root found a chain");
	/* THE OUT-PARAMETERS ARE CLEARED BEFORE ANY DECISION, so a caller who
	 * ignores the return value reads nothing rather than its own stack. */
	CHECK(bytes == NULL && len == 0u, "a refused lookup left the caller a pointer");

	bytes = (const uint8_t *)1;
	CHECK(!fzn_chain_store_lookup(&f.store, f.root, &other_cap, f.grantee, 200, &bytes, &len),
	      "a lookup for another capability found a chain");
	bytes = (const uint8_t *)1;
	CHECK(!fzn_chain_store_lookup(&f.store, f.root, &f.cap, other, 200, &bytes, &len),
	      "a lookup for another subject found a chain");
}

static void test_an_expired_chain_is_not_handed_back(void)
{
	struct fixture f;
	const uint8_t *bytes = NULL;
	size_t len = 0;

	REQUIRE(build(&f), "the fixture does not build");
	REQUIRE(fzn_chain_store_admit(&f.store, &f.hop, 1, f.root, &f.cap, 200, &OPS, NULL, NULL)
	                == FZN_CHAIN_OK,
	        "admit refused a sound chain");

	CHECK(fzn_chain_store_lookup(&f.store, f.root, &f.cap, f.grantee, 4999, &bytes, &len),
	      "a chain one tick before its expiry was withheld");
	CHECK(!fzn_chain_store_lookup(&f.store, f.root, &f.cap, f.grantee, 5000, &bytes, &len),
	      "a chain was handed back AT its expiry, which is not before it");
	CHECK(!fzn_chain_store_lookup(&f.store, f.root, &f.cap, f.grantee, 9000, &bytes, &len),
	      "an expired chain was handed back");
	/* It is still HELD -- expiry is a lookup judgement, not a deletion.
	 * A store that dropped it would lose the ability to say "I had one". */
	CHECK(fzn_chain_store_count(&f.store) == 1u,
	      "expiry removed the entry rather than withholding it");
}

static void test_a_second_chain_for_one_triple_replaces_the_first(void)
{
	struct fixture f;
	uint8_t again[FZN_HOP_LEN];
	fzn_chain_hop_t hop2;
	const uint8_t *bytes = NULL;
	size_t len = 0;

	REQUIRE(build(&f), "the fixture does not build");
	REQUIRE(fzn_chain_store_admit(&f.store, &f.hop, 1, f.root, &f.cap, 200, &OPS, NULL, NULL)
	                == FZN_CHAIN_OK,
	        "admit refused a sound chain");

	/* The same grant, re-minted later and expiring later, which is how a
	 * grant is extended before the first one runs out. */
	signing_as = 0x11;
	REQUIRE(fzn_chain_mint(f.root, f.grantee, &f.cap, 300, 9000, 1, &OPS, again)
	                == FZN_CHAIN_OK,
	        "the second mint failed");
	REQUIRE(fzn_hop_open(again, FZN_HOP_LEN, &hop2) == FZN_CHAIN_OK, "the second hop is bad");
	CHECK(fzn_chain_store_admit(&f.store, &hop2, 1, f.root, &f.cap, 400, &OPS, NULL, NULL)
	              == FZN_CHAIN_OK,
	      "re-admitting the same triple was refused");
	CHECK(fzn_chain_store_count(&f.store) == 1u,
	      "two chains for one triple are held, so lookup must answer 'which one'");
	/* The NEWER one is what is held: it outlives the first. */
	CHECK(fzn_chain_store_lookup(&f.store, f.root, &f.cap, f.grantee, 6000, &bytes, &len),
	      "the replacement did not outlive the chain it replaced");
}

static void test_a_full_store_refuses_rather_than_overwrites(void)
{
	struct fixture f;
	uint8_t two[FZN_HOP_LEN], three[FZN_HOP_LEN];
	fzn_chain_hop_t h2, h3;
	uint8_t g2[FZN_PUBKEY_LEN], g3[FZN_PUBKEY_LEN];

	REQUIRE(build(&f), "the fixture does not build");
	key(g2, 0x44);
	key(g3, 0x55);
	signing_as = 0x11;
	REQUIRE(fzn_chain_mint(f.root, g2, &f.cap, 100, 5000, 1, &OPS, two) == FZN_CHAIN_OK, "m2");
	REQUIRE(fzn_chain_mint(f.root, g3, &f.cap, 100, 5000, 1, &OPS, three) == FZN_CHAIN_OK, "m3");
	REQUIRE(fzn_hop_open(two, FZN_HOP_LEN, &h2) == FZN_CHAIN_OK, "h2");
	REQUIRE(fzn_hop_open(three, FZN_HOP_LEN, &h3) == FZN_CHAIN_OK, "h3");

	REQUIRE(fzn_chain_store_admit(&f.store, &f.hop, 1, f.root, &f.cap, 200, &OPS, NULL, NULL)
	                == FZN_CHAIN_OK, "first admit");
	REQUIRE(fzn_chain_store_admit(&f.store, &h2, 1, f.root, &f.cap, 200, &OPS, NULL, NULL)
	                == FZN_CHAIN_OK, "second admit");
	CHECK(fzn_chain_store_admit(&f.store, &h3, 1, f.root, &f.cap, 200, &OPS, NULL, NULL)
	              == FZN_CHAIN_ERR_STORE_FULL,
	      "a full store took a third chain");
	CHECK(fzn_chain_store_count(&f.store) == 2u, "a refused admission changed the count");
}

static void test_a_store_that_cannot_be_scanned_holds_nothing(void)
{
	fzn_chain_store_t s;
	fzn_chain_entry_t e[2];
	const uint8_t *bytes = NULL;
	size_t len = 0;
	uint8_t r[FZN_PUBKEY_LEN], g[FZN_PUBKEY_LEN];
	fzn_cap_id_t c;

	key(r, 0x11);
	key(g, 0x22);
	cap_id(&c, 0x33);
	REQUIRE(fzn_chain_store_init(&s, e, 2) == FZN_CHAIN_OK, "init");

	/* Neither state is reachable through `_init`, which refuses both. It
	 * is what a caller holds who restored a struct from a file and got
	 * the count without the array. */
	s.used = 3u;
	CHECK(fzn_chain_store_count(&s) == 0u, "a count past capacity was reported as held");
	CHECK(!fzn_chain_store_lookup(&s, r, &c, g, 100, &bytes, &len),
	      "a store counting more entries than it has room for answered a lookup");

	s.used = 1u;
	s.entries = NULL;
	CHECK(fzn_chain_store_count(&s) == 0u, "a store with no array reported a count");
	CHECK(!fzn_chain_store_lookup(&s, r, &c, g, 100, &bytes, &len),
	      "a store with no array answered a lookup");
	CHECK(fzn_chain_store_count(NULL) == 0u, "a null store reported a count");
}

/* THE PROPERTY THE HEADER RESTS ON: holding is not authorising.
 *
 * A chain verifies on admission and can be revoked afterwards. Both halves
 * are asserted together because either alone is misleading: that lookup
 * still returns it, AND that verification now refuses it. A store that
 * dropped revoked chains would look safer and would be worse -- the caller
 * would stop re-verifying, and the next revocation would change nothing. */
static void test_a_revoked_chain_is_still_held_and_no_longer_verifies(void)
{
	struct fixture f;
	uint8_t rev[FZN_REVOCATION_LEN];
	fzn_revocation_record_t record;
	const uint8_t *bytes = NULL;
	size_t len = 0;
	fzn_chain_t out;

	REQUIRE(build(&f), "the fixture does not build");
	REQUIRE(fzn_chain_store_admit(&f.store, &f.hop, 1, f.root, &f.cap, 200, &OPS, &f.revs,
	                              NULL) == FZN_CHAIN_OK,
	        "admit refused a sound chain");
	REQUIRE(fzn_chain_verify(&f.hop, 1, f.root, &f.cap, 200, &OPS, &f.revs, NULL, &out)
	                == FZN_CHAIN_OK,
	        "the chain does not verify before the revocation");

	/* The root withdraws the capability from the grantee. */
	signing_as = 0x11;
	REQUIRE(fzn_revocation_issue(f.root, &f.cap, f.grantee, 300, &OPS, rev) == FZN_CHAIN_OK,
	        "issuing the revocation failed");
	REQUIRE(fzn_revocation_open(rev, sizeof(rev), &record) == FZN_CHAIN_OK,
	        "the revocation does not open");
	REQUIRE(fzn_revocation_admit(&f.revs, fzn_revocation_offer_root(record), f.root, &OPS,
	                             &HASH, NULL) == FZN_CHAIN_OK,
	        "the revocation was not admitted");
	REQUIRE(fzn_revocation_covers(&f.revs, f.root, &f.cap, f.grantee) == 1,
	        "the revocation does not cover the pair it names");

	/* HALF ONE: the store still holds it and still hands it back. */
	CHECK(fzn_chain_store_lookup(&f.store, f.root, &f.cap, f.grantee, 400, &bytes, &len),
	      "the store dropped a revoked chain, so a caller has nothing left to re-verify "
	      "and a later revocation would change nothing");
	CHECK(fzn_chain_store_count(&f.store) == 1u, "the revoked chain left the store");

	/* HALF TWO: and it no longer authorises anybody. */
	CHECK(fzn_chain_verify(&f.hop, 1, f.root, &f.cap, 400, &OPS, &f.revs, NULL, &out)
	              != FZN_CHAIN_OK,
	      "a revoked chain still verified, so holding it WAS authorising after all");
}

/* THE OTHER PROPERTY: admitting a chain is not adopting an issuer.
 *
 * There is no follow predicate to assert against -- record/journal.h exposes
 * none -- so this reads the door instead. A record from an unfollowed issuer
 * is refused with FZN_JOURNAL_ERR_UNKNOWN_ISSUER, and that refusal must be
 * exactly where it was before a chain naming the issuer was admitted. */
static void test_admitting_a_chain_follows_nobody(void)
{
	struct fixture f;
	fzn_journal_t j;
	fzn_journal_entry_t entries[2];

	REQUIRE(build(&f), "the fixture does not build");
	REQUIRE(fzn_journal_init(&j, entries, 2) == FZN_JOURNAL_OK, "the journal does not init");

	REQUIRE(fzn_journal_admit(&j, f.grantee, 1, 1) == FZN_JOURNAL_ERR_UNKNOWN_ISSUER,
	        "the journal followed an issuer nobody anchored");

	REQUIRE(fzn_chain_store_admit(&f.store, &f.hop, 1, f.root, &f.cap, 200, &OPS, NULL, NULL)
	                == FZN_CHAIN_OK,
	        "admit refused a sound chain");

	CHECK(fzn_journal_admit(&j, f.grantee, 1, 1) == FZN_JOURNAL_ERR_UNKNOWN_ISSUER,
	      "admitting a chain made the journal follow its subject, so the chain store is "
	      "a second door into adoption beside fzn_journal_anchor");
	CHECK(fzn_journal_admit(&j, f.root, 1, 1) == FZN_JOURNAL_ERR_UNKNOWN_ISSUER,
	      "admitting a chain made the journal follow its root");
}

static void test_every_guard_refuses_its_own_argument(void)
{
	struct fixture f;
	const uint8_t *bytes = NULL;
	size_t len = 0;

	REQUIRE(build(&f), "the fixture does not build");

	CHECK(fzn_chain_store_admit(NULL, &f.hop, 1, f.root, &f.cap, 200, &OPS, NULL, NULL)
	              == FZN_CHAIN_ERR_MALFORMED, "admit accepted a null store");
	CHECK(fzn_chain_store_admit(&f.store, NULL, 1, f.root, &f.cap, 200, &OPS, NULL, NULL)
	              == FZN_CHAIN_ERR_MALFORMED, "admit accepted null hops");
	CHECK(fzn_chain_store_admit(&f.store, &f.hop, 1, NULL, &f.cap, 200, &OPS, NULL, NULL)
	              == FZN_CHAIN_ERR_MALFORMED, "admit accepted a null root");
	CHECK(fzn_chain_store_admit(&f.store, &f.hop, 1, f.root, NULL, 200, &OPS, NULL, NULL)
	              == FZN_CHAIN_ERR_MALFORMED, "admit accepted a null capability");
	{
		fzn_chain_store_t hollow = f.store;

		hollow.entries = NULL;
		CHECK(fzn_chain_store_admit(&hollow, &f.hop, 1, f.root, &f.cap, 200, &OPS, NULL,
		                            NULL) == FZN_CHAIN_ERR_MALFORMED,
		      "admit accepted a store whose entries are null");
		hollow = f.store;
		hollow.used = hollow.capacity + 1u;
		CHECK(fzn_chain_store_admit(&hollow, &f.hop, 1, f.root, &f.cap, 200, &OPS, NULL,
		                            NULL) == FZN_CHAIN_ERR_MALFORMED,
		      "admit accepted a store counting more entries than it has room for");
	}

	CHECK(!fzn_chain_store_lookup(NULL, f.root, &f.cap, f.grantee, 200, &bytes, &len),
	      "lookup accepted a null store");
	CHECK(!fzn_chain_store_lookup(&f.store, NULL, &f.cap, f.grantee, 200, &bytes, &len),
	      "lookup accepted a null root");
	CHECK(!fzn_chain_store_lookup(&f.store, f.root, NULL, f.grantee, 200, &bytes, &len),
	      "lookup accepted a null capability");
	CHECK(!fzn_chain_store_lookup(&f.store, f.root, &f.cap, NULL, 200, &bytes, &len),
	      "lookup accepted a null subject");
	CHECK(!fzn_chain_store_lookup(&f.store, f.root, &f.cap, f.grantee, 200, NULL, &len),
	      "lookup accepted a null out pointer");
	CHECK(!fzn_chain_store_lookup(&f.store, f.root, &f.cap, f.grantee, 200, &bytes, NULL),
	      "lookup accepted a null out length");
}

int main(void)
{
	test_init_refuses_what_cannot_hold_anything();
	test_only_a_chain_that_verifies_is_kept();
	test_what_goes_in_comes_back_out();
	test_a_lookup_that_does_not_match_answers_nothing();
	test_an_expired_chain_is_not_handed_back();
	test_a_second_chain_for_one_triple_replaces_the_first();
	test_a_full_store_refuses_rather_than_overwrites();
	test_a_store_that_cannot_be_scanned_holds_nothing();
	test_a_revoked_chain_is_still_held_and_no_longer_verifies();
	test_admitting_a_chain_follows_nobody();
	test_every_guard_refuses_its_own_argument();

	printf("chain_store_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
