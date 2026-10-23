/* routing_test -- a user's routing manifest, sec 611: entries in canonical
 * order, signed by the root or by an admin through its chain, refused when
 * its document, statement or signer is not what it claims, one encoding per
 * manifest, and the newest kept.
 *
 * Stub crypto as apply_test's: a key is 32 bytes of one value, and a
 * signature a hash of that value and the message. An in-memory store. No
 * files, no forks, fixed loops.
 */

#include "../routing.h"

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                  \
	do {                                                                               \
		checks++;                                                                  \
		if (!(cond)) {                                                             \
			failures++;                                                        \
			fprintf(stderr, "  FAIL routing_test.c:%d: %s\n", __LINE__, what); \
		}                                                                          \
	} while (0)

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

static uint8_t signing_as;

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t len)
{
	(void)ctx;
	mac(sig, signing_as, msg, len);
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

static int mix_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
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
static const fzn_hash_ops_t HASH = { mix_hash, NULL };

/* ---- a store ------------------------------------------------------------ */

static struct {
	int used;
	uint8_t subject[32];
	uint8_t bytes[FZN_ROUTING_MAX];
	size_t len;
} rows[4];

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	size_t i;

	(void)ctx;
	for (i = 0; i < 4u; i++)
		if (rows[i].used && slot == FZN_PERSIST_ROUTING
		    && memcmp(rows[i].subject, subject, 32u) == 0 && rows[i].len <= cap) {
			memcpy(out, rows[i].bytes, rows[i].len);
			*len = rows[i].len;
			return 1;
		}
	return 0;
}

static int mem_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                    const uint8_t *bytes, size_t len)
{
	size_t i, free_one = 4u;

	(void)ctx;
	if (slot != FZN_PERSIST_ROUTING || len > sizeof(rows[0].bytes))
		return 0;
	for (i = 0; i < 4u; i++) {
		if (rows[i].used && memcmp(rows[i].subject, subject, 32u) == 0)
			break;
		if (!rows[i].used && free_one == 4u)
			free_one = i;
	}
	if (i == 4u)
		i = free_one;
	if (i == 4u)
		return 0;
	rows[i].used = 1;
	memcpy(rows[i].subject, subject, 32u);
	memcpy(rows[i].bytes, bytes, len);
	rows[i].len = len;
	return 1;
}

static const fzn_persist_ops_t STORE = { mem_load, mem_save, NULL, NULL, NULL, NULL };

static uint8_t root[32], admin[32], other[32];
static fzn_cap_id_t admin_cap, other_cap;

/* A manifest of three entries, out of order as given. */
static void three(fzn_routing_t *r)
{
	memset(r, 0, sizeof(*r));
	(void)fzn_routing_add(r, "b.example", 9u, 47000u, FZN_ROUTING_TRANSPORT_UDP, 20u);
	(void)fzn_routing_add(r, "a.example", 9u, 47001u, FZN_ROUTING_TRANSPORT_UDP, 20u);
	(void)fzn_routing_add(r, "10.0.0.3", 8u, 47000u, FZN_ROUTING_TRANSPORT_UDP, 5u);
}

static void test_canonical_entries(void)
{
	fzn_routing_t r;
	char big[300];
	int i;

	three(&r);
	CHECK(r.n == 3u && r.entries[0].metric == 5u && !strcmp(r.entries[1].address, "a.example")
	              && !strcmp(r.entries[2].address, "b.example"),
	      "the entries are not metric first, then address");
	CHECK(fzn_routing_add(&r, "a.example", 9u, 47001u, 1u, 99u) == FZN_ROUTING_ERR_MALFORMED,
	      "an address and port twice, at another metric, was taken");
	CHECK(fzn_routing_add(&r, "a example", 9u, 1u, 1u, 1u) == FZN_ROUTING_ERR_MALFORMED
	              && fzn_routing_add(&r, "", 0u, 1u, 1u, 1u) == FZN_ROUTING_ERR_MALFORMED
	              && fzn_routing_add(&r, "a.example", 9u, 0u, 1u, 1u) == FZN_ROUTING_ERR_MALFORMED,
	      "a space, an empty address or port 0 was taken");
	memset(big, 'a', sizeof(big));
	CHECK(fzn_routing_add(&r, big, 254u, 1u, 1u, 1u) == FZN_ROUTING_ERR_MALFORMED
	              && fzn_routing_add(&r, big, 253u, 1u, 1u, 1u) == FZN_ROUTING_OK,
	      "254 bytes of address was taken, or 253 was not");
	memset(&r, 0, sizeof(r));
	for (i = 0; i < (int)FZN_ROUTING_ENTRIES_MAX; i++)
		(void)fzn_routing_add(&r, "h.example", 9u, (uint16_t)(100 + i), 1u, 1u);
	CHECK(r.n == FZN_ROUTING_ENTRIES_MAX
	              && fzn_routing_add(&r, "h.example", 9u, 99u, 1u, 1u) == FZN_ROUTING_ERR_MALFORMED,
	      "an entry past the bound was taken");
}

static void test_signed_and_checked(void)
{
	static uint8_t bytes[FZN_ROUTING_MAX];
	fzn_routing_t r, back;
	size_t len = 0;

	three(&r);
	r.public_relay = 1;
	signing_as = root[0];
	CHECK(fzn_routing_sign(&r, &HASH, &SIGN, root, NULL, 0u, 7u, 1000u) == FZN_ROUTING_OK
	              && fzn_routing_verify(&r, &HASH, &SIGN, root, NULL, 2000u) == FZN_ROUTING_OK,
	      "the root's manifest did not verify against the root");
	CHECK(fzn_routing_encode(&r, bytes, sizeof(bytes), &len) == FZN_ROUTING_OK
	              && fzn_routing_decode(bytes, len, &back) == FZN_ROUTING_OK
	              && back.generation == 7u && back.timestamp_ms == 1000u && back.public_relay == 1
	              && back.n == 3u && back.entries[0].port == 47000u
	              && !strcmp(back.entries[0].address, "10.0.0.3")
	              && fzn_routing_verify(&back, &HASH, &SIGN, root, NULL, 2000u) == FZN_ROUTING_OK,
	      "the manifest did not decode to itself, verified");
	/* THE DOCUMENT IS BOUND: a metric moved fails the hash. */
	back.entries[0].metric = 1u;
	CHECK(fzn_routing_verify(&back, &HASH, &SIGN, root, NULL, 2000u) == FZN_ROUTING_ERR_REFUSED,
	      "a document edited after signing verified");
	back.entries[0].metric = 5u;
	back.public_relay = 0;
	CHECK(fzn_routing_verify(&back, &HASH, &SIGN, root, NULL, 2000u) == FZN_ROUTING_ERR_REFUSED,
	      "public_relay turned off after signing verified");
	back.public_relay = 1;
	/* THE STATEMENT IS SIGNED: a generation moved fails the signature. */
	back.generation = 8u;
	CHECK(fzn_routing_verify(&back, &HASH, &SIGN, root, NULL, 2000u) == FZN_ROUTING_ERR_REFUSED,
	      "a generation moved after signing verified");
	back.generation = 7u;
	CHECK(fzn_routing_verify(&back, &HASH, &SIGN, other, NULL, 2000u) == FZN_ROUTING_ERR_REFUSED,
	      "the root's manifest verified as another user's");
	/* BY AN ADMIN, its chain carried. */
	{
		uint8_t hop[1][FZN_HOP_LEN];

		signing_as = root[0];
		CHECK(fzn_chain_mint(root, admin, &admin_cap, 100u, FZN_NO_EXPIRY, 0, &SIGN, hop[0])
		              == FZN_CHAIN_OK,
		      "fixture: the root grants admin");
		three(&r);
		signing_as = admin[0];
		CHECK(fzn_routing_sign(&r, &HASH, &SIGN, admin, (const uint8_t (*)[FZN_HOP_LEN])hop, 1u,
		                       8u, 1100u)
		                      == FZN_ROUTING_OK
		              && fzn_routing_verify(&r, &HASH, &SIGN, root, &admin_cap, 2000u)
		                         == FZN_ROUTING_OK,
		      "an admin's manifest, its chain carried, did not verify");
		CHECK(fzn_routing_encode(&r, bytes, sizeof(bytes), &len) == FZN_ROUTING_OK
		              && fzn_routing_decode(bytes, len, &back) == FZN_ROUTING_OK
		              && back.hop_count == 1u
		              && fzn_routing_verify(&back, &HASH, &SIGN, root, &admin_cap, 2000u)
		                         == FZN_ROUTING_OK,
		      "an admin's manifest did not decode to itself, chain and all");
		CHECK(fzn_routing_verify(&r, &HASH, &SIGN, root, NULL, 2000u) == FZN_ROUTING_ERR_REFUSED
		              && fzn_routing_verify(&r, &HASH, &SIGN, root, &other_cap, 2000u)
		                         == FZN_ROUTING_ERR_REFUSED,
		      "an admin's manifest verified with no admin capability, or another");
		/* A CHAIN TO ONE KEY, SIGNED BY ANOTHER. */
		memcpy(r.signer, other, 32u);
		signing_as = other[0];
		CHECK(fzn_routing_sign(&r, &HASH, &SIGN, other, (const uint8_t (*)[FZN_HOP_LEN])hop, 1u,
		                       9u, 1200u)
		                      == FZN_ROUTING_OK
		              && fzn_routing_verify(&r, &HASH, &SIGN, root, &admin_cap, 2000u)
		                         == FZN_ROUTING_ERR_REFUSED,
		      "a manifest signed by a key the chain does not end at verified");
		/* NO CHAIN, AND NOT THE ROOT. */
		signing_as = admin[0];
		CHECK(fzn_routing_sign(&r, &HASH, &SIGN, admin, NULL, 0u, 9u, 1200u) == FZN_ROUTING_OK
		              && fzn_routing_verify(&r, &HASH, &SIGN, root, &admin_cap, 2000u)
		                         == FZN_ROUTING_ERR_REFUSED,
		      "a manifest signed by an admin with no chain verified");
	}
}

static void test_one_encoding(void)
{
	static uint8_t bytes[FZN_ROUTING_MAX];
	fzn_routing_t r, back;
	size_t len = 0, first;

	three(&r);
	signing_as = root[0];
	CHECK(fzn_routing_sign(&r, &HASH, &SIGN, root, NULL, 0u, 1u, 1u) == FZN_ROUTING_OK
	              && fzn_routing_encode(&r, bytes, sizeof(bytes), &len) == FZN_ROUTING_OK,
	      "fixture: a manifest encoded");
	/* The first entry starts after the statement, public_relay and count:
	 * 10.0.0.3's length byte. Swapped with the second, the order breaks. */
	first = FZN_ROUTING_STATEMENT_LEN + 2u;
	{
		uint8_t swapped[FZN_ROUTING_MAX];
		size_t e1 = 1u + 8u + 4u, e2 = 1u + 9u + 4u;

		memcpy(swapped, bytes, len);
		memcpy(swapped + first, bytes + first + e1, e2);
		memcpy(swapped + first + e2, bytes + first, e1);
		CHECK(fzn_routing_decode(swapped, len, &back) == FZN_ROUTING_ERR_SHAPE,
		      "entries out of order were decoded");
	}
	CHECK(fzn_routing_decode(bytes, len - 1u, &back) == FZN_ROUTING_ERR_SHAPE,
	      "a manifest cut short was decoded");
	{
		uint8_t longer[FZN_ROUTING_MAX + 1u];

		memcpy(longer, bytes, len);
		longer[len] = 0u;
		CHECK(fzn_routing_decode(longer, len + 1u, &back) == FZN_ROUTING_ERR_SHAPE,
		      "a manifest with a trailing byte was decoded");
	}
	bytes[1] = 2u;
	CHECK(fzn_routing_decode(bytes, len, &back) == FZN_ROUTING_ERR_SHAPE,
	      "a derivation version not known was decoded");
}

static void test_newest_kept(void)
{
	fzn_routing_t a, b, held;

	memset(rows, 0, sizeof(rows));
	three(&a);
	three(&b);
	signing_as = root[0];
	(void)fzn_routing_sign(&a, &HASH, &SIGN, root, NULL, 0u, 2u, 1u);
	(void)fzn_routing_sign(&b, &HASH, &SIGN, root, NULL, 0u, 1u, 999u);
	CHECK(fzn_routing_load(&STORE, root, &held) == FZN_ROUTING_ERR_ABSENT,
	      "a manifest was held before any was kept");
	CHECK(fzn_routing_keep(&STORE, root, &a) == FZN_ROUTING_OK
	              && fzn_routing_keep(&STORE, root, &b) == FZN_ROUTING_ERR_STALE
	              && fzn_routing_keep(&STORE, root, &a) == FZN_ROUTING_ERR_STALE,
	      "an older generation -- though signed later -- or the same one replaced the kept");
	CHECK(fzn_routing_load(&STORE, root, &held) == FZN_ROUTING_OK && held.generation == 2u,
	      "the kept manifest is not the newest");
	/* A TIE ON GENERATION: the greater signer stands. */
	(void)fzn_routing_sign(&b, &HASH, &SIGN, other, NULL, 0u, 2u, 1u);
	CHECK(fzn_routing_newer(&b, &a) == (memcmp(other, root, 32u) > 0)
	              && !fzn_routing_newer(&a, &a),
	      "a tie on generation was not broken by the signer, or a manifest was newer than itself");
	CHECK(fzn_routing_load(&STORE, other, &held) == FZN_ROUTING_ERR_ABSENT,
	      "one user's manifest was held as another's");
}

int main(void)
{
	memset(root, 0x91, 32u);
	memset(admin, 0x92, 32u);
	memset(other, 0x93, 32u);
	memset(&admin_cap, 0xad, sizeof(admin_cap));
	memset(&other_cap, 0x0c, sizeof(other_cap));
	test_canonical_entries();
	test_signed_and_checked();
	test_one_encoding();
	test_newest_kept();
	if (failures) {
		fprintf(stderr, "routing_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("routing_test: all %d checks passed\n", checks);
	return 0;
}
