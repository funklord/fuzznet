/* Tests for chain/succession.c: one key succeeded by another. sec 498.
 *
 * THE STUBS ARE revocation_test's: a signature is a keyed mixing function
 * over the signed bytes, keyed by the first byte of the public key, so a
 * record verifies under exactly the key its signer was told to be and a
 * change to any signed byte refuses it. What is asked is whether the right
 * bytes reach the right call, not whether the primitive is Ed25519.
 */

#include "../succession.h"
#include "../revocation.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL succession_test.c:%d: %s\n", __LINE__, what);   \
		}                                                                              \
	} while (0)

static void mac(uint8_t out[FZN_SIG_LEN], uint8_t identity, const uint8_t *msg, size_t len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	h ^= (uint64_t)identity;
	h *= 0x100000001b3ull;
	for (i = 0; i < len; i++) {
		h ^= (uint64_t)msg[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h ^= (uint64_t)i + 1u;
		h *= 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 56);
	}
}

static uint8_t signing_as;

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
	(void)ctx;
	mac(sig, signing_as, msg, msg_len);
	return 1;
}

static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint64_t h = 0x84222325cbf29ce4ull;
	size_t i;

	(void)ctx;
	for (i = 0; i < in_len; i++)
		h = (h ^ in[i]) * 0x100000001b3ull;
	for (i = 0; i < out_len; i++) {
		h = (h ^ (uint64_t)i) * 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 40);
	}
	return 1;
}

static const fzn_sign_ops_t SIGN = { stub_verify, stub_sign, NULL };
static const fzn_hash_ops_t HASH = { stub_hash, NULL };

/* A key whose first byte is its seed and whose rest varies by position. */
static void key(uint8_t out[FZN_PUBKEY_LEN], uint8_t seed)
{
	size_t i;

	out[0] = seed;
	for (i = 1; i < FZN_PUBKEY_LEN; i++)
		out[i] = (uint8_t)(seed * 31u + i);
}

/* A succession, signed by `issuer`, from `old` to `next`. */
static int issue(uint8_t out[FZN_SUCCESSION_LEN], uint8_t issuer, uint8_t old, uint8_t next)
{
	uint8_t i[FZN_PUBKEY_LEN], o[FZN_PUBKEY_LEN], n[FZN_PUBKEY_LEN], cut[32];

	key(i, issuer);
	key(o, old);
	key(n, next);
	memset(cut, 0x5c, sizeof(cut));
	signing_as = issuer;
	return fzn_succession_issue(i, o, n, cut, &SIGN, out) == FZN_CHAIN_OK;
}

static uint8_t root[FZN_PUBKEY_LEN];

/* Whom `seed` resolves to, as a seed, or 0 when the way forks or cycles. */
static uint8_t resolved(const fzn_succession_set_t *set, const fzn_revocation_store_t *revs,
                        uint8_t seed)
{
	uint8_t k[FZN_PUBKEY_LEN], out[FZN_PUBKEY_LEN];

	key(k, seed);
	if (!fzn_succession_resolve(set, revs, root, k, out))
		return 0;
	return out[0];
}

static void test_the_record(void)
{
	uint8_t bytes[FZN_SUCCESSION_LEN], same[FZN_PUBKEY_LEN];
	fzn_succession_record_t r;

	CHECK(issue(bytes, 0x10, 0x21, 0x22)
	              && fzn_succession_open(bytes, sizeof(bytes), &r) == FZN_CHAIN_OK
	              && bytes[0] == 1u && bytes[1] == 146u && fzn_succession_issuer(r)[0] == 0x10
	              && fzn_succession_old(r)[0] == 0x21 && fzn_succession_new(r)[0] == 0x22
	              && fzn_succession_cut(r)[0] == 0x5c && bytes[2] == 0x10 && bytes[34] == 0x21
	              && bytes[66] == 0x22 && bytes[98] == 0x5c && bytes[129] == 0x5c,
	      "a succession did not lay out as the table says, or did not read back");
	CHECK(fzn_succession_open(bytes, sizeof(bytes) - 1u, &r) == FZN_CHAIN_ERR_SHAPE,
	      "a short succession opened");
	bytes[1] = 145u;
	CHECK(fzn_succession_open(bytes, sizeof(bytes), &r) == FZN_CHAIN_ERR_SHAPE,
	      "another object read as a succession");
	bytes[1] = 146u;
	memcpy(bytes + 66, bytes + 34, FZN_PUBKEY_LEN);
	CHECK(fzn_succession_open(bytes, sizeof(bytes), &r) == FZN_CHAIN_ERR_SHAPE,
	      "a key succeeded by itself opened");
	key(same, 0x21);
	CHECK(fzn_succession_issue(root, same, same, NULL, &SIGN, bytes) == FZN_CHAIN_ERR_MALFORMED,
	      "a key succeeded by itself was signed");
}

/* A ROOT'S SUCCESSIONS: admitted, counting alone, read through. */
static void test_a_roots_successions(void)
{
	static fzn_revocation_t rev_entries[4];
	static fzn_succession_t held[4];
	fzn_revocation_store_t revs;
	fzn_succession_set_t set;
	uint8_t a[FZN_SUCCESSION_LEN], b[FZN_SUCCESSION_LEN], c[FZN_SUCCESSION_LEN];

	CHECK(fzn_revocation_store_init(&revs, rev_entries, 4) == FZN_CHAIN_OK
	              && fzn_succession_set_init(&set, held, 3, &HASH) == FZN_CHAIN_OK,
	      "fixture");
	CHECK(resolved(&set, &revs, 0x21) == 0x21, "a key nothing succeeds did not resolve to itself");

	/* THE ROOT RE-KEYS 21 TO 22. */
	CHECK(issue(a, 0x00, 0x21, 0x22)
	              && fzn_succession_admit(&set, &revs, a, sizeof(a), NULL, 0, root, &SIGN)
	                         == FZN_CHAIN_OK
	              && set.used == 1u && fzn_succession_counts(&set, 0, &revs, root),
	      "the root's succession was not admitted, or did not count alone");
	CHECK(fzn_succession_admit(&set, &revs, a, sizeof(a), NULL, 0, root, &SIGN) == FZN_CHAIN_OK
	              && set.used == 1u,
	      "a succession admitted twice was kept twice");
	CHECK(resolved(&set, &revs, 0x21) == 0x22, "the old key did not read through to the new");

	/* REFUSALS: a stranger with no chain, and a signature that is not the
	 * issuer's. */
	CHECK(issue(b, 0x33, 0x21, 0x23)
	              && fzn_succession_admit(&set, &revs, b, sizeof(b), NULL, 0, root, &SIGN)
	                         == FZN_CHAIN_ERR_WRONG_ROOT,
	      "a stranger's succession was admitted");
	CHECK(issue(b, 0x00, 0x22, 0x23), "fixture: the root's second re-key");
	b[100] ^= 1u;
	CHECK(fzn_succession_admit(&set, &revs, b, sizeof(b), NULL, 0, root, &SIGN)
	              == FZN_CHAIN_ERR_CHAIN_INVALID,
	      "a succession whose signed bytes were changed was admitted");
	b[100] ^= 1u;

	/* A CHAIN OF TWO: 21 -> 22 -> 23 reads through to the newest. */
	CHECK(fzn_succession_admit(&set, &revs, b, sizeof(b), NULL, 0, root, &SIGN) == FZN_CHAIN_OK
	              && resolved(&set, &revs, 0x21) == 0x23 && resolved(&set, &revs, 0x22) == 0x23,
	      "two successions in a row did not read through to the newest key");

	/* A CYCLE NAMES NOBODY: 23 -> 21. */
	CHECK(issue(c, 0x00, 0x23, 0x21)
	              && fzn_succession_admit(&set, &revs, c, sizeof(c), NULL, 0, root, &SIGN)
	                         == FZN_CHAIN_OK
	              && resolved(&set, &revs, 0x21) == 0,
	      "a cycle of successions resolved to somebody");
	CHECK(issue(c, 0x00, 0x24, 0x25)
	              && fzn_succession_admit(&set, &revs, c, sizeof(c), NULL, 0, root, &SIGN)
	                         == FZN_CHAIN_ERR_STORE_FULL,
	      "a full set took another succession");
}

/* A FORK NAMES NOBODY: the same key re-keyed to two different keys. */
static void test_a_fork(void)
{
	static fzn_revocation_t rev_entries[4];
	static fzn_succession_t held[4];
	fzn_revocation_store_t revs;
	fzn_succession_set_t set;
	uint8_t a[FZN_SUCCESSION_LEN], b[FZN_SUCCESSION_LEN];

	CHECK(fzn_revocation_store_init(&revs, rev_entries, 4) == FZN_CHAIN_OK
	              && fzn_succession_set_init(&set, held, 4, &HASH) == FZN_CHAIN_OK
	              && issue(a, 0x00, 0x21, 0x22) && issue(b, 0x00, 0x21, 0x23)
	              && fzn_succession_admit(&set, &revs, a, sizeof(a), NULL, 0, root, &SIGN)
	                         == FZN_CHAIN_OK
	              && fzn_succession_admit(&set, &revs, b, sizeof(b), NULL, 0, root, &SIGN)
	                         == FZN_CHAIN_OK,
	      "fixture: two re-keys of one key");
	CHECK(resolved(&set, &revs, 0x21) == 0, "a forked re-key resolved to one of its branches");
}

/* AN ADMIN'S SUCCESSION AT k = 2: it needs one more admin who stands, or a
 * root; its own confirmation is not one; once its issuer is revoked it stops
 * counting. */
static void test_an_admins_succession(void)
{
	static fzn_revocation_t rev_entries[8];
	static fzn_revocation_admin_t admins[4];
	static fzn_revocation_confirm_t confirms[8];
	static fzn_succession_t held[4];
	fzn_revocation_store_t revs;
	fzn_succession_set_t set;
	fzn_cap_id_t adm;
	uint8_t s[FZN_SUCCESSION_LEN], hop7[FZN_HOP_LEN], hop8[FZN_HOP_LEN];
	uint8_t seven[FZN_PUBKEY_LEN], eight[FZN_PUBKEY_LEN], id[FZN_SUCCESSION_ID_LEN];
	uint8_t conf[FZN_ADMIN_CONFIRM_LEN], rev[FZN_REVOCATION_LEN];
	fzn_chain_hop_t h7, h8;
	fzn_revocation_record_t rr;

	memset(&adm, 0xad, sizeof(adm));
	key(seven, 7);
	key(eight, 8);
	signing_as = 0;
	CHECK(fzn_revocation_store_init(&revs, rev_entries, 8) == FZN_CHAIN_OK
	              && fzn_revocation_store_set_quorum(&revs, 2u, &adm, admins, 4) == FZN_CHAIN_OK
	              && fzn_revocation_store_set_confirmations(&revs, confirms, 8, &HASH)
	                         == FZN_CHAIN_OK
	              && fzn_succession_set_init(&set, held, 4, &HASH) == FZN_CHAIN_OK
	              && fzn_chain_mint(root, seven, &adm, 100, FZN_NO_EXPIRY, 1, &SIGN, hop7)
	                         == FZN_CHAIN_OK
	              && fzn_hop_open(hop7, FZN_HOP_LEN, &h7) == FZN_CHAIN_OK
	              && fzn_chain_mint(root, eight, &adm, 100, FZN_NO_EXPIRY, 1, &SIGN, hop8)
	                         == FZN_CHAIN_OK
	              && fzn_hop_open(hop8, FZN_HOP_LEN, &h8) == FZN_CHAIN_OK,
	      "fixture: a store at k = 2 with two admins of the root's");

	CHECK(issue(s, 7, 0x21, 0x22)
	              && fzn_succession_admit(&set, &revs, s, sizeof(s), NULL, 0, root, &SIGN)
	                         == FZN_CHAIN_ERR_WRONG_ROOT,
	      "an admin's succession was admitted without its chain");
	CHECK(fzn_succession_admit(&set, &revs, s, sizeof(s), &h7, 1, root, &SIGN) == FZN_CHAIN_OK
	              && !fzn_succession_counts(&set, 0, &revs, root)
	              && resolved(&set, &revs, 0x21) == 0x21,
	      "an admin's succession counted alone at k = 2");

	/* ITS OWN CONFIRMATION IS NOT ONE. */
	stub_hash(NULL, id, sizeof(id), s, sizeof(s));
	signing_as = 7;
	CHECK(fzn_admin_confirm_issue(seven, id, &SIGN, conf) == FZN_CHAIN_OK
	              && fzn_revocation_confirm_admit(&revs, conf, sizeof(conf), &h7, 1, root, &SIGN)
	                         == FZN_CHAIN_OK
	              && !fzn_succession_counts(&set, 0, &revs, root),
	      "an admin confirming its own succession made it count");

	/* ANOTHER ADMIN WHO STANDS: it counts. */
	signing_as = 8;
	CHECK(fzn_admin_confirm_issue(eight, id, &SIGN, conf) == FZN_CHAIN_OK
	              && fzn_revocation_confirm_admit(&revs, conf, sizeof(conf), &h8, 1, root, &SIGN)
	                         == FZN_CHAIN_OK
	              && fzn_succession_counts(&set, 0, &revs, root)
	              && resolved(&set, &revs, 0x21) == 0x22,
	      "a second admin's confirmation did not make the succession count");

	/* THE ISSUER REVOKED: its succession stops counting. */
	signing_as = 0;
	CHECK(fzn_revocation_issue(root, &adm, seven, 200, 0u, NULL, &SIGN, rev) == FZN_CHAIN_OK
	              && fzn_revocation_open(rev, sizeof(rev), &rr) == FZN_CHAIN_OK
	              && fzn_revocation_admit(&revs, fzn_revocation_offer_root(rr), root, &SIGN,
	                                      &HASH, NULL) == FZN_CHAIN_OK
	              && !fzn_succession_counts(&set, 0, &revs, root)
	              && resolved(&set, &revs, 0x21) == 0x21,
	      "a revoked admin's succession still counted");
}

/* A ROOT'S CONFIRMATION SETTLES AN ADMIN'S SUCCESSION, as it settles an admin
 * grant (sec 414). */
static void test_a_root_confirms(void)
{
	static fzn_revocation_t rev_entries[8];
	static fzn_revocation_admin_t admins[4];
	static fzn_revocation_confirm_t confirms[8];
	static fzn_succession_t held[4];
	fzn_revocation_store_t revs;
	fzn_succession_set_t set;
	fzn_cap_id_t adm;
	uint8_t s[FZN_SUCCESSION_LEN], hop7[FZN_HOP_LEN], seven[FZN_PUBKEY_LEN];
	uint8_t id[FZN_SUCCESSION_ID_LEN], conf[FZN_ADMIN_CONFIRM_LEN];
	fzn_chain_hop_t h7;

	memset(&adm, 0xad, sizeof(adm));
	key(seven, 7);
	signing_as = 0;
	CHECK(fzn_revocation_store_init(&revs, rev_entries, 8) == FZN_CHAIN_OK
	              && fzn_revocation_store_set_quorum(&revs, 3u, &adm, admins, 4) == FZN_CHAIN_OK
	              && fzn_revocation_store_set_confirmations(&revs, confirms, 8, &HASH)
	                         == FZN_CHAIN_OK
	              && fzn_succession_set_init(&set, held, 4, &HASH) == FZN_CHAIN_OK
	              && fzn_chain_mint(root, seven, &adm, 100, FZN_NO_EXPIRY, 1, &SIGN, hop7)
	                         == FZN_CHAIN_OK
	              && fzn_hop_open(hop7, FZN_HOP_LEN, &h7) == FZN_CHAIN_OK
	              && issue(s, 7, 0x21, 0x22)
	              && fzn_succession_admit(&set, &revs, s, sizeof(s), &h7, 1, root, &SIGN)
	                         == FZN_CHAIN_OK
	              && !fzn_succession_counts(&set, 0, &revs, root),
	      "fixture: an admin's succession at k = 3, counting for nothing yet");
	stub_hash(NULL, id, sizeof(id), s, sizeof(s));
	signing_as = 0;
	CHECK(fzn_admin_confirm_issue(root, id, &SIGN, conf) == FZN_CHAIN_OK
	              && fzn_revocation_confirm_admit(&revs, conf, sizeof(conf), NULL, 0, root, &SIGN)
	                         == FZN_CHAIN_OK
	              && fzn_succession_counts(&set, 0, &revs, root),
	      "the root's one confirmation did not settle an admin's succession at k = 3");
}

int main(void)
{
	key(root, 0);
	test_the_record();
	test_a_roots_successions();
	test_a_fork();
	test_an_admins_succession();
	test_a_root_confirms();
	if (failures) {
		fprintf(stderr, "succession_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("succession_test: all %d checks passed\n", checks);
	return 0;
}
