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

	/* AND THE ONE `corrupt()` DOES NOT CATCH. Its second clause is
	 * `used > 0 && !entries`, so a store holding nothing and pointing at
	 * nothing is sound by that test and still cannot be scanned. The
	 * guard after it is what refuses, and nothing had reached it. */
	s.used = 0u;
	s.entries = NULL;
	CHECK(!fzn_chain_store_lookup(&s, r, &c, g, 100, &bytes, &len),
	      "an empty store with no array answered a lookup, which corrupt() does not "
	      "catch because it holds nothing");
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


/* THE THREE RULES THE SHAPE CARRIES, which `record/sync.h` argues and this
 * module inherits rather than re-deciding: a request naming nothing gets
 * nothing, a ceiling because the peer picks the count, and a zero cap
 * refused rather than read as unlimited. */
static void test_the_offer_keeps_the_three_rules(void)
{
	struct fixture f;
	fzn_chain_want_t wants[3];
	uint8_t holds[3];
	fzn_chain_offer_t plan;

	REQUIRE(build(&f), "the fixture does not build");
	REQUIRE(fzn_chain_store_admit(&f.store, &f.hop, 1, f.root, &f.cap, 200, &OPS, NULL, NULL)
	                == FZN_CHAIN_OK,
	        "admit refused a sound chain");

	memset(wants, 0, sizeof(wants));
	memcpy(wants[0].root, f.root, FZN_PUBKEY_LEN);
	wants[0].capability = f.cap;
	memcpy(wants[0].subject, f.grantee, FZN_PUBKEY_LEN);
	/* Two the host does not hold. */
	key(wants[1].root, 0x81);
	cap_id(&wants[1].capability, 0x82);
	key(wants[1].subject, 0x83);
	key(wants[2].root, 0x91);
	cap_id(&wants[2].capability, 0x92);
	key(wants[2].subject, 0x93);

	/* A verdict per want, parallel to the list rather than filtered. */
	memset(holds, 0xff, sizeof(holds));
	CHECK(fzn_chain_plan_offer(&f.store, wants, 3, holds, 3, 300, &plan) == FZN_CHAIN_OK,
	      "a sound offer was refused");
	CHECK(plan.examined == 3u, "not every want was examined");
	CHECK(plan.held == 1u, "the wrong number of wants was reported held");
	CHECK(plan.truncated == 0, "an unclipped request was reported truncated");
	CHECK(holds[0] == 1u, "the want this host holds was not marked");
	CHECK(holds[1] == 0u && holds[2] == 0u, "a want this host lacks was marked held");

	/* A REQUEST NAMING NOTHING GETS NOTHING, and is not an error and not
	 * read as "send everything". */
	CHECK(fzn_chain_plan_offer(&f.store, NULL, 0, holds, 3, 300, &plan) == FZN_CHAIN_OK,
	      "a request naming nothing was refused");
	CHECK(plan.examined == 0u && plan.held == 0u && plan.truncated == 0,
	      "a request naming nothing answered something");

	/* A CEILING, because the peer picks the count. The unexamined tail is
	 * not reported as not-held, which is a different answer a peer would
	 * act on. */
	memset(holds, 0xff, sizeof(holds));
	CHECK(fzn_chain_plan_offer(&f.store, wants, 3, holds, 1, 300, &plan) == FZN_CHAIN_OK,
	      "a clipped request was refused rather than clipped");
	CHECK(plan.examined == 1u, "the ceiling did not clip the request");
	CHECK(plan.truncated == 1, "a clipped request did not say so");
	CHECK(holds[1] == 0xffu && holds[2] == 0xffu,
	      "the unexamined tail was written, so a peer cannot tell 'not held' from "
	      "'not looked at'");

	/* ZERO IS REFUSED rather than meaning unlimited. */
	CHECK(fzn_chain_plan_offer(&f.store, wants, 3, holds, 0, 300, &plan)
	              == FZN_CHAIN_ERR_MALFORMED,
	      "a zero capacity was read as unlimited");
	CHECK(plan.examined == 0u && plan.held == 0u,
	      "a refused offer left counts behind");
}

/* Expiry counts as not held, and an unsound store is refused rather than
 * answered -- the two judgements that separate this from a plain array
 * scan. */
static void test_the_offer_refuses_rather_than_promising(void)
{
	struct fixture f;
	fzn_chain_want_t want;
	uint8_t holds[1];
	fzn_chain_offer_t plan;

	REQUIRE(build(&f), "the fixture does not build");
	REQUIRE(fzn_chain_store_admit(&f.store, &f.hop, 1, f.root, &f.cap, 200, &OPS, NULL, NULL)
	                == FZN_CHAIN_OK,
	        "admit refused a sound chain");

	memset(&want, 0, sizeof(want));
	memcpy(want.root, f.root, FZN_PUBKEY_LEN);
	want.capability = f.cap;
	memcpy(want.subject, f.grantee, FZN_PUBKEY_LEN);

	REQUIRE(fzn_chain_plan_offer(&f.store, &want, 1, holds, 1, 300, &plan) == FZN_CHAIN_OK,
	        "the offer failed before the expiry case");
	REQUIRE(holds[0] == 1u, "the chain is not held before its expiry");

	/* PAST ITS EXPIRY IT IS NOT OFFERED. Offering it would be offering
	 * bytes the peer will refuse, which this host already knows. */
	CHECK(fzn_chain_plan_offer(&f.store, &want, 1, holds, 1, 9000, &plan) == FZN_CHAIN_OK,
	      "the offer was refused rather than answering 'not held'");
	CHECK(holds[0] == 0u && plan.held == 0u,
	      "an expired chain was offered to a peer");

	/* AN UNSOUND STORE IS REFUSED, not answered. Promising to serve from a
	 * store nobody can scan is worse than saying nothing. */
	{
		fzn_chain_store_t hollow = f.store;

		hollow.used = hollow.capacity + 1u;
		CHECK(fzn_chain_plan_offer(&hollow, &want, 1, holds, 1, 300, &plan)
		              == FZN_CHAIN_ERR_MALFORMED,
		      "a store that cannot be scanned promised to serve a triple");
		hollow = f.store;
		hollow.entries = NULL;
		hollow.used = 1u;
		CHECK(fzn_chain_plan_offer(&hollow, &want, 1, holds, 1, 300, &plan)
		              == FZN_CHAIN_ERR_MALFORMED,
		      "a store with no array promised to serve a triple");
	}

	CHECK(fzn_chain_plan_offer(NULL, &want, 1, holds, 1, 300, &plan)
	              == FZN_CHAIN_ERR_MALFORMED, "offer accepted a null store");
	CHECK(fzn_chain_plan_offer(&f.store, NULL, 1, holds, 1, 300, &plan)
	              == FZN_CHAIN_ERR_MALFORMED,
	      "offer accepted a null list with a nonzero count");
	CHECK(fzn_chain_plan_offer(&f.store, &want, 1, NULL, 1, 300, &plan)
	              == FZN_CHAIN_ERR_MALFORMED, "offer accepted a null holds array");
	CHECK(fzn_chain_plan_offer(&f.store, &want, 1, holds, 1, 300, NULL)
	              == FZN_CHAIN_ERR_MALFORMED, "offer accepted a null plan");
}


/* A CHAIN THAT NEVER EXPIRES IS NEVER WITHHELD, which the expiry guard's
 * first operand exists for and which nothing reached: every chain the
 * fixture mints carries a real expiry, so the FZN_NO_EXPIRY side of that
 * comparison had never been taken either way.
 *
 * WHY IT MATTERS, CORRECTED. This first said FZN_NO_EXPIRY was the largest
 * value the field holds, so dropping the guard's first operand would withhold
 * an unexpiring chain "at exactly one clock value and nowhere else". It is
 * `0u` (chain.h), so the truth is the other way round and worse: `expires_at
 * <= now` alone is true for EVERY `now`, and an unexpiring chain would be
 * withheld always. The operand is load-bearing rather than marginal.
 *
 * So the ordinary-clock case below is the one holding the guard, and the
 * large-clock cases are breadth rather than the point. They stay because a
 * sentinel of zero is a thing a future change could move, and a case that
 * asks at several clocks survives that; the comment is what was wrong. */
static void test_a_chain_with_no_expiry_is_always_held(void)
{
	struct fixture f;
	uint8_t forever[FZN_HOP_LEN];
	fzn_chain_hop_t hop;
	const uint8_t *bytes = NULL;
	size_t len = 0;

	REQUIRE(build(&f), "the fixture does not build");
	signing_as = 0x11;
	REQUIRE(fzn_chain_mint(f.root, f.grantee, &f.cap, 100, FZN_NO_EXPIRY, 1, &OPS, forever)
	                == FZN_CHAIN_OK,
	        "minting an unexpiring chain failed");
	REQUIRE(fzn_hop_open(forever, FZN_HOP_LEN, &hop) == FZN_CHAIN_OK, "the hop is bad");
	REQUIRE(fzn_chain_store_admit(&f.store, &hop, 1, f.root, &f.cap, 200, &OPS, NULL, NULL)
	                == FZN_CHAIN_OK,
	        "admit refused an unexpiring chain");

	CHECK(fzn_chain_store_lookup(&f.store, f.root, &f.cap, f.grantee, 200, &bytes, &len),
	      "an unexpiring chain was withheld at an ordinary clock");
	CHECK(fzn_chain_store_lookup(&f.store, f.root, &f.cap, f.grantee, UINT64_MAX - 1u,
	                             &bytes, &len),
	      "an unexpiring chain was withheld near the top of the clock");
	/* And at the sentinel's own value, which is zero and therefore also
	 * the smallest clock any caller can pass. */
	CHECK(fzn_chain_store_lookup(&f.store, f.root, &f.cap, f.grantee, FZN_NO_EXPIRY,
	                             &bytes, &len),
	      "an unexpiring chain was withheld at a clock equal to the sentinel");
	{
		fzn_chain_want_t want;
		uint8_t holds[1];
		fzn_chain_offer_t plan;

		memset(&want, 0, sizeof(want));
		memcpy(want.root, f.root, FZN_PUBKEY_LEN);
		want.capability = f.cap;
		memcpy(want.subject, f.grantee, FZN_PUBKEY_LEN);
		CHECK(fzn_chain_plan_offer(&f.store, &want, 1, holds, 1, FZN_NO_EXPIRY, &plan)
		              == FZN_CHAIN_OK && holds[0] == 1u,
		      "an unexpiring chain was not offered at FZN_NO_EXPIRY");
	}
}


/* MULTI-HOP, WHERE `len` CHANGES ON REPLACEMENT AND NOTHING COULD SEE IT.
 *
 * Every other case in this file admits one hop, so `packed_len` is 181 both
 * sides of a replacement and the assignment of `len` is unobservable -- the
 * suite would pass byte-for-byte if `bytes[]` were declared `[181]`, and it
 * would pass if `admit` updated the verdict and never the bytes.
 *
 * The blind failure has an AUTHORISATION shape and it is the growing
 * direction. Replace `root -> leaf` (181 bytes) with `root -> mid -> leaf`
 * (360) while leaving `len` at 181, and `lookup` returns the first 181 bytes
 * of a two-hop container -- which re-opens cleanly as a ONE-hop chain
 * authorising `mid` rather than `leaf`, under `leaf`'s own key. It verifies.
 * Nothing in this file would have gone red.
 */
static void test_replacement_carries_the_bytes_and_the_length(void)
{
	struct fixture f;
	uint8_t mid[FZN_PUBKEY_LEN];
	uint8_t second[FZN_HOP_LEN];
	uint8_t to_mid[FZN_HOP_LEN];
	fzn_chain_hop_t pair[FZN_CHAIN_MAX_HOPS];
	const uint8_t *bytes = NULL;
	size_t len = 0;
	fzn_chain_hop_t back[FZN_CHAIN_MAX_HOPS];
	size_t back_count = 0;

	REQUIRE(build(&f), "the fixture does not build");
	key(mid, 0x44);

	/* root -> mid, delegable, then mid -> grantee on top of it. */
	signing_as = 0x11;
	REQUIRE(fzn_chain_mint(f.root, mid, &f.cap, 100, 5000, 1, &OPS, to_mid) == FZN_CHAIN_OK,
	        "minting root -> mid failed");
	REQUIRE(fzn_hop_open(to_mid, FZN_HOP_LEN, &pair[0]) == FZN_CHAIN_OK, "hop 0 is bad");
	signing_as = 0x44;
	/* `delegate` mints the NEW HOP only -- assembling it onto the chain is
	 * the caller's, which chain.h says and this case first assumed
	 * otherwise. */
	REQUIRE(fzn_chain_delegate(pair, 1, f.root, &f.cap, 200, f.grantee, 4000, 0,
	                           &OPS, NULL, second) == FZN_CHAIN_OK,
	        "delegating mid -> grantee failed");
	REQUIRE(fzn_hop_open(second, FZN_HOP_LEN, &pair[1]) == FZN_CHAIN_OK, "hop 1 is bad");

	/* One hop first, then the two-hop chain for the SAME triple. */
	REQUIRE(fzn_chain_store_admit(&f.store, &f.hop, 1, f.root, &f.cap, 300, &OPS, NULL, NULL)
	                == FZN_CHAIN_OK, "the one-hop admit failed");
	REQUIRE(fzn_chain_store_lookup(&f.store, f.root, &f.cap, f.grantee, 300, &bytes, &len),
	        "the one-hop chain was not held");
	REQUIRE(len == FZN_CHAIN_HEADER_LEN + FZN_HOP_LEN, "the one-hop length is wrong");

	REQUIRE(fzn_chain_store_admit(&f.store, pair, 2, f.root, &f.cap, 300, &OPS, NULL, NULL)
	                == FZN_CHAIN_OK, "the two-hop admit failed");
	CHECK(fzn_chain_store_count(&f.store) == 1u,
	      "the two-hop chain took a second slot rather than replacing");
	CHECK(fzn_chain_store_lookup(&f.store, f.root, &f.cap, f.grantee, 300, &bytes, &len),
	      "the replacement is not held");
	CHECK(len == FZN_CHAIN_HEADER_LEN + (2u * FZN_HOP_LEN),
	      "the length still describes the chain that was replaced, so the view is a "
	      "prefix of the new container");

	/* AND THE BYTES ARE THE NEW ONES. Asserted by re-opening rather than by
	 * comparing lengths, because the hazard is a container that opens as a
	 * SHORTER VALID CHAIN authorising somebody else. */
	CHECK(fzn_chain_open(bytes, len, back, &back_count) == FZN_CHAIN_OK,
	      "the stored replacement does not re-open");
	CHECK(back_count == 2u, "the re-opened chain is not the two-hop one");
	CHECK(memcmp(back[1].base, pair[1].base, FZN_HOP_LEN) == 0,
	      "the second hop is not the one admitted, so the bytes were not replaced");
}

/* THE ARGUMENTS `admit` PASSES THROUGH, which nothing held.
 *
 * Every admit in this file and in tool/consumer_check.c passed NULL for the
 * manifest, and the one that passed a revocation store did so while the store
 * was empty. So `fzn_chain_verify(..., NULL, NULL, ...)` in place of the real
 * arguments left the whole suite green, and the header's "nothing is
 * defaulted" rested on nobody. */
static void test_admit_passes_the_revocation_state_through(void)
{
	struct fixture f;
	uint8_t rev[FZN_REVOCATION_LEN];
	fzn_revocation_record_t record;

	REQUIRE(build(&f), "the fixture does not build");

	signing_as = 0x11;
	REQUIRE(fzn_revocation_issue(f.root, &f.cap, f.grantee, 300, &OPS, rev) == FZN_CHAIN_OK,
	        "issuing the revocation failed");
	REQUIRE(fzn_revocation_open(rev, sizeof(rev), &record) == FZN_CHAIN_OK,
	        "the revocation does not open");
	REQUIRE(fzn_revocation_admit(&f.revs, fzn_revocation_offer_root(record), f.root, &OPS,
	                             &HASH, NULL) == FZN_CHAIN_OK,
	        "the revocation was not admitted");

	/* A REVOKED CHAIN IS NOT ADMITTED AT ALL, and the code says which
	 * refusal it was rather than only that there was one. */
	CHECK(fzn_chain_store_admit(&f.store, &f.hop, 1, f.root, &f.cap, 400, &OPS, &f.revs,
	                            NULL) == FZN_CHAIN_ERR_REVOKED,
	      "a revoked chain was admitted, so the revocation store is not reaching verify");
	CHECK(fzn_chain_store_count(&f.store) == 0u, "a refused admit consumed an entry");

	/* Without the store it is admitted, which is what makes the case above
	 * evidence about the pass-through rather than about the chain. */
	CHECK(fzn_chain_store_admit(&f.store, &f.hop, 1, f.root, &f.cap, 400, &OPS, NULL, NULL)
	              == FZN_CHAIN_OK,
	      "the chain is refused even with no revocation store, so the case above proves "
	      "nothing about the argument being passed through");
}

/* `_init` ZEROES THE CALLER'S ARRAY, which project.md sec 39 settled for this
 * family and which this module did not do. Same shape as the four
 * determinism cases sec 39 names, poison and all. */
static void test_init_does_not_leave_the_callers_bytes(void)
{
	fzn_chain_store_t from_dirty, from_clean;
	static fzn_chain_entry_t dirty[2], clean[2];

	memset(dirty, 0xab, sizeof(dirty));
	memset(clean, 0, sizeof(clean));
	CHECK(fzn_chain_store_init(&from_dirty, dirty, 2) == FZN_CHAIN_OK,
	      "init refused a dirty array");
	CHECK(fzn_chain_store_init(&from_clean, clean, 2) == FZN_CHAIN_OK,
	      "init refused a clean array");
	CHECK(memcmp(dirty, clean, sizeof(dirty)) == 0,
	      "init left the caller's bytes in the entry array, so what a fresh store holds "
	      "depends on what its memory held -- and an entry here is a 1434-byte buffer "
	      "that lookup hands pointers into");
}

/* A LENGTH THIS FILE DID NOT WRITE. `corrupt()` reaches store-level shape and
 * says nothing about an entry, so a store restored from a file can be sound
 * by that test and carry a length past its own buffer. The header says the
 * view may go to a peer, and a write() does not check. */
static void test_a_length_past_the_buffer_is_not_handed_out(void)
{
	struct fixture f;
	const uint8_t *bytes = NULL;
	size_t len = 0;

	REQUIRE(build(&f), "the fixture does not build");
	REQUIRE(fzn_chain_store_admit(&f.store, &f.hop, 1, f.root, &f.cap, 200, &OPS, NULL, NULL)
	                == FZN_CHAIN_OK, "admit refused a sound chain");

	f.storage[0].len = (size_t)-1;
	CHECK(fzn_chain_store_count(&f.store) == 1u,
	      "the store is corrupt by the store-level test, which is not what this case is "
	      "about");
	CHECK(!fzn_chain_store_lookup(&f.store, f.root, &f.cap, f.grantee, 200, &bytes, &len),
	      "a length past the entry's own buffer was handed to a caller");
	CHECK(bytes == NULL && len == 0u, "a refused lookup left the caller a length");

	f.storage[0].len = FZN_CHAIN_MAX_LEN + 1u;
	CHECK(!fzn_chain_store_lookup(&f.store, f.root, &f.cap, f.grantee, 200, &bytes, &len),
	      "a length one past the buffer was handed to a caller");
}


/* A DEAD ENTRY IS SPENT BEFORE A LIVE CHAIN IS REFUSED, and only then.
 *
 * Expiry withholds at lookup and frees nothing, so a full store whose
 * entries have all expired used to answer STORE_FULL permanently while
 * holding nothing but corpses. The second half is what keeps this from
 * being a worse bug than the one it fixes: when every entry is LIVE the
 * refusal stands, because evicting a live grant would make which chain a
 * host holds depend on arrival order. */
static void test_a_dead_entry_is_spent_before_a_live_chain_is_refused(void)
{
	struct fixture f;
	uint8_t g2[FZN_PUBKEY_LEN], g3[FZN_PUBKEY_LEN];
	uint8_t two[FZN_HOP_LEN], three[FZN_HOP_LEN];
	fzn_chain_hop_t h2, h3;
	const uint8_t *bytes = NULL;
	size_t len = 0;

	REQUIRE(build(&f), "the fixture does not build");
	key(g2, 0x51);
	key(g3, 0x52);
	signing_as = 0x11;
	REQUIRE(fzn_chain_mint(f.root, g2, &f.cap, 100, 5000, 1, &OPS, two) == FZN_CHAIN_OK, "m2");
	REQUIRE(fzn_hop_open(two, FZN_HOP_LEN, &h2) == FZN_CHAIN_OK, "h2");
	REQUIRE(fzn_chain_mint(f.root, g3, &f.cap, 100, 9000, 1, &OPS, three) == FZN_CHAIN_OK, "m3");
	REQUIRE(fzn_hop_open(three, FZN_HOP_LEN, &h3) == FZN_CHAIN_OK, "h3");

	/* Fill it: both entries expire at 5000. */
	REQUIRE(fzn_chain_store_admit(&f.store, &f.hop, 1, f.root, &f.cap, 200, &OPS, NULL, NULL)
	                == FZN_CHAIN_OK, "first admit");
	REQUIRE(fzn_chain_store_admit(&f.store, &h2, 1, f.root, &f.cap, 200, &OPS, NULL, NULL)
	                == FZN_CHAIN_OK, "second admit");

	/* WHILE BOTH ARE LIVE THE REFUSAL STANDS. Checked first, because a
	 * case that only shows eviction cannot tell it from evicting
	 * anything at all. */
	CHECK(fzn_chain_store_admit(&f.store, &h3, 1, f.root, &f.cap, 300, &OPS, NULL, NULL)
	              == FZN_CHAIN_ERR_STORE_FULL,
	      "a live grant was evicted to make room, so which chain a host holds depends "
	      "on the order they arrived in");
	CHECK(fzn_chain_store_lookup(&f.store, f.root, &f.cap, f.grantee, 300, &bytes, &len),
	      "the first chain was evicted while live");
	CHECK(fzn_chain_store_lookup(&f.store, f.root, &f.cap, g2, 300, &bytes, &len),
	      "the second chain was evicted while live");

	/* Past their expiry the store holds two corpses -- still counted, and
	 * still withheld, because expiry alone deletes nothing. */
	CHECK(fzn_chain_store_count(&f.store) == 2u, "expiry deleted an entry on its own");
	CHECK(!fzn_chain_store_lookup(&f.store, f.root, &f.cap, f.grantee, 6000, &bytes, &len),
	      "an expired chain was handed back");

	/* AND NOW A LIVE CHAIN FITS. */
	CHECK(fzn_chain_store_admit(&f.store, &h3, 1, f.root, &f.cap, 6000, &OPS, NULL, NULL)
	              == FZN_CHAIN_OK,
	      "a live chain was refused by a store holding nothing but expired ones");
	CHECK(fzn_chain_store_count(&f.store) == 2u, "eviction grew the store");
	CHECK(fzn_chain_store_lookup(&f.store, f.root, &f.cap, g3, 6000, &bytes, &len),
	      "the chain that was admitted by eviction is not held");
	/* The FIRST dead slot went, which is the documented choice, so the
	 * second corpse is still there and the first is gone. */
	CHECK(!fzn_chain_store_lookup(&f.store, f.root, &f.cap, f.grantee, 6000, &bytes, &len),
	      "the evicted entry is somehow still held");

	/* AN UNEXPIRING CHAIN IS NEVER THE VICTIM. FZN_NO_EXPIRY is 0, so
	 * arithmetic on it rather than a test against it would make an
	 * unexpiring chain the first thing evicted every time. */
	{
		fzn_chain_store_t s;
		fzn_chain_entry_t slots[1];
		uint8_t forever[FZN_HOP_LEN], other[FZN_HOP_LEN];
		fzn_chain_hop_t hf, ho;

		REQUIRE(fzn_chain_store_init(&s, slots, 1) == FZN_CHAIN_OK, "init");
		signing_as = 0x11;
		REQUIRE(fzn_chain_mint(f.root, f.grantee, &f.cap, 100, FZN_NO_EXPIRY, 1, &OPS,
		                       forever) == FZN_CHAIN_OK, "mint forever");
		REQUIRE(fzn_hop_open(forever, FZN_HOP_LEN, &hf) == FZN_CHAIN_OK, "hf");
		/* THE INCOMING CHAIN MUST ITSELF BE LIVE AT THIS CLOCK. A first
		 * draft offered a chain expiring at 9000, which `fzn_chain_verify`
		 * refuses as expired long before eviction is consulted -- so the
		 * case would have reported the wrong refusal and proved nothing
		 * about the sentinel. */
		REQUIRE(fzn_chain_mint(f.root, g3, &f.cap, 100, FZN_NO_EXPIRY, 1, &OPS, other)
		                == FZN_CHAIN_OK, "mint the other");
		REQUIRE(fzn_hop_open(other, FZN_HOP_LEN, &ho) == FZN_CHAIN_OK, "ho");
		REQUIRE(fzn_chain_store_admit(&s, &hf, 1, f.root, &f.cap, 200, &OPS, NULL, NULL)
		                == FZN_CHAIN_OK, "admit forever");
		CHECK(fzn_chain_store_admit(&s, &ho, 1, f.root, &f.cap, UINT64_MAX - 1u, &OPS,
		                            NULL, NULL) == FZN_CHAIN_ERR_STORE_FULL,
		      "an unexpiring chain was evicted, so the sentinel is being compared "
		      "rather than tested for");
		CHECK(fzn_chain_store_lookup(&s, f.root, &f.cap, f.grantee, UINT64_MAX - 1u,
		                             &bytes, &len),
		      "the unexpiring chain is gone");
	}
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
	test_the_offer_keeps_the_three_rules();
	test_the_offer_refuses_rather_than_promising();
	test_a_chain_with_no_expiry_is_always_held();
	test_replacement_carries_the_bytes_and_the_length();
	test_admit_passes_the_revocation_state_through();
	test_init_does_not_leave_the_callers_bytes();
	test_a_length_past_the_buffer_is_not_handed_out();
	test_a_dead_entry_is_spent_before_a_live_chain_is_refused();

	printf("chain_store_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
