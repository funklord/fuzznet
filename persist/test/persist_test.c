/* Tests for persist/persist.c: the format, and what a restart must not lose.
 *
 * THE ASSERTIONS THAT MATTER ARE THE ONES ABOUT PROVENANCE AND ABOUT TAGS.
 * A round trip that returns the right key is the easy half; what a consumer
 * would actually be harmed by is an anchor that comes back with its source
 * changed -- a host claiming a user confirmed a key nobody confirmed -- or a
 * blob restored into the wrong slot and parsed as something else.
 */

#include "../persist.h"

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
	fprintf(stderr, "  FAIL persist_test.c:%d: ", line);
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

static int stub_public(void *ctx, uint8_t out[FZN_AGREE_PUBLIC_LEN],
                       const uint8_t secret[FZN_AGREE_SECRET_LEN])
{
	unsigned i;

	(void)ctx;
	for (i = 0; i < FZN_AGREE_PUBLIC_LEN; i++)
		out[i] = (uint8_t)(secret[i] ^ 0x3cu);
	return 1;
}

static int stub_agree(void *ctx, uint8_t out[FZN_AGREE_SHARED_LEN],
                      const uint8_t secret[FZN_AGREE_SECRET_LEN],
                      const uint8_t peer[FZN_AGREE_PUBLIC_LEN])
{
	unsigned i;

	(void)ctx;
	for (i = 0; i < FZN_AGREE_SHARED_LEN; i++)
		out[i] = (uint8_t)(secret[i] ^ (peer[i] ^ 0x3cu));
	return 1;
}

static const fzn_agree_ops_t AGREE = { stub_public, stub_agree, NULL };

static void fill(uint8_t *p, size_t n, uint8_t seed)
{
	size_t i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)(seed + (i * 7u));
}

/* ---- the cases -------------------------------------------------------- */

static void test_an_anchor_comes_back_with_its_provenance(void)
{
	fzn_trust_t adopted, pinned, back;
	uint8_t root[FZN_PUBKEY_LEN];
	uint8_t blob[FZN_PERSIST_MAX];
	size_t len = 0;

	fill(root, sizeof(root), 0x21);

	/* ADOPTED MUST COME BACK ADOPTED. A host that took a key on faith and
	 * restarted claiming its user had confirmed one has laundered its own
	 * provenance through a file -- the same thing `prekey/` refuses on
	 * rotation, by a different route. */
	fzn_trust_init(&adopted);
	REQUIRE(fzn_trust_adopt(&adopted, root, 7777u) == FZN_TRUST_OK, "adopt refused");
	REQUIRE(fzn_persist_trust_pack(&adopted, blob, sizeof(blob), &len) == FZN_PERSIST_OK,
	        "packing an adopted anchor refused");
	REQUIRE(fzn_persist_trust_open(blob, len, &back) == FZN_PERSIST_OK, "opening refused");
	REQUIRE(fzn_trust_root(&back) != NULL, "the restored anchor is empty");
	CHECK(memcmp(fzn_trust_root(&back), root, FZN_PUBKEY_LEN) == 0,
	      "the restored root is not the one stored");
	CHECK(fzn_trust_source_of(&back) == FZN_TRUST_ADOPTED,
	      "an adopted anchor came back claiming it was confirmed out of band");
	CHECK(fzn_trust_adopted_at(&back) == 7777u, "the adoption time did not survive");

	/* And confirmed must come back confirmed, which is the same property
	 * pointed the other way: a host must not forget that its user did
	 * check, or it will ask again and train them to click through. */
	fzn_trust_init(&pinned);
	REQUIRE(fzn_trust_pin(&pinned, root) == FZN_TRUST_OK, "pin refused");
	REQUIRE(fzn_persist_trust_pack(&pinned, blob, sizeof(blob), &len) == FZN_PERSIST_OK,
	        "packing a pinned anchor refused");
	REQUIRE(fzn_persist_trust_open(blob, len, &back) == FZN_PERSIST_OK, "opening refused");
	CHECK(fzn_trust_source_of(&back) == FZN_TRUST_PINNED,
	      "a confirmed anchor came back as merely adopted");
}

static void test_an_empty_anchor_is_not_stored(void)
{
	fzn_trust_t empty;
	uint8_t blob[FZN_PERSIST_MAX];
	size_t len = 0;

	fzn_trust_init(&empty);
	/* STORING "NO ANCHOR" IS WORSE THAN STORING NOTHING. A caller that
	 * saves an unanchored trust over a real one has destroyed the thing
	 * this module exists to keep, and the file would then restore
	 * cleanly -- an absence that parses. */
	CHECK(fzn_persist_trust_pack(&empty, blob, sizeof(blob), &len) == FZN_PERSIST_ERR_MALFORMED,
	      "an unanchored trust was packed, so a save can erase an anchor and succeed");
}

static void test_a_prekey_secret_survives_with_its_generation(void)
{
	fzn_agree_secret_t sk, back;
	uint8_t secret[FZN_AGREE_SECRET_LEN];
	uint8_t blob[FZN_PERSIST_MAX];
	size_t len = 0;

	fill(secret, sizeof(secret), 0x31);
	memset(&sk, 0, sizeof(sk));
	REQUIRE(fzn_agree_secret_install(&sk, &AGREE, secret) == FZN_AGREE_OK, "install refused");
	REQUIRE(fzn_agree_secret_install(&sk, &AGREE, secret) == FZN_AGREE_OK, "rotate refused");
	REQUIRE(fzn_agree_secret_generation(&sk) == 1u, "the fixture is not at generation 1");

	REQUIRE(fzn_persist_secret_pack(&sk, blob, sizeof(blob), &len) == FZN_PERSIST_OK,
	        "packing refused");
	REQUIRE(fzn_persist_secret_open(blob, len, &AGREE, &back) == FZN_PERSIST_OK,
	        "opening refused");

	REQUIRE(fzn_agree_secret_public(&back) != NULL, "the restored secret is not live");
	CHECK(memcmp(fzn_agree_secret_public(&back), fzn_agree_secret_public(&sk),
	             FZN_AGREE_PUBLIC_LEN) == 0,
	      "the public half re-derived to something else, so peers hold a stale key");
	/* THE GENERATION IS THE ONE A NAIVE RESTORE LOSES, because installing
	 * counts as a rotation. A host back at generation 0 publishes a record
	 * that looks older than the one its peers already hold. */
	CHECK(fzn_agree_secret_generation(&back) == 1u,
	      "the generation reset on restore, so a restarted host looks older than it is");
}

static void test_a_pinned_peer_and_a_chain_round_trip(void)
{
	fzn_prekey_peer_t peer, peer_back;
	fzn_ratchet_chain_t chain, chain_back;
	uint8_t root[FZN_PUBKEY_LEN], prekey[FZN_PREKEY_LEN], key[FZN_CHAIN_KEY_LEN];
	uint8_t blob[FZN_PERSIST_MAX];
	size_t len = 0;

	fill(root, sizeof(root), 0x41);
	fill(prekey, sizeof(prekey), 0x51);
	fill(key, sizeof(key), 0x61);

	fzn_prekey_peer_init(&peer);
	REQUIRE(fzn_trust_adopt(&peer.trust, root, 5u) == FZN_TRUST_OK, "adopt refused");
	memcpy(peer.prekey, prekey, FZN_PREKEY_LEN);
	peer.created_at = 1234u;

	REQUIRE(fzn_persist_peer_pack(&peer, blob, sizeof(blob), &len) == FZN_PERSIST_OK,
	        "packing a peer refused");
	REQUIRE(fzn_persist_peer_open(blob, len, &peer_back) == FZN_PERSIST_OK,
	        "opening a peer refused");
	REQUIRE(fzn_trust_root(&peer_back.trust) != NULL, "the peer came back unanchored");
	CHECK(memcmp(fzn_trust_root(&peer_back.trust), root, FZN_PUBKEY_LEN) == 0,
	      "the peer's anchor did not survive");
	CHECK(memcmp(peer_back.prekey, prekey, FZN_PREKEY_LEN) == 0,
	      "the peer's prekey did not survive");
	CHECK(peer_back.created_at == 1234u,
	      "the peer's timestamp did not survive, so a replayed older record would be "
	      "accepted as a rotation");

	fzn_ratchet_init(&chain, key, 99u);
	REQUIRE(fzn_persist_chain_pack(&chain, blob, sizeof(blob), &len) == FZN_PERSIST_OK,
	        "packing a chain refused");
	REQUIRE(fzn_persist_chain_open(blob, len, &chain_back) == FZN_PERSIST_OK,
	        "opening a chain refused");
	CHECK(memcmp(chain_back.key, key, FZN_CHAIN_KEY_LEN) == 0, "the chain key did not survive");
	CHECK(chain_back.seq == 99u,
	      "the chain position did not survive, which is a key reused or a message lost");
}

static void test_a_blob_does_not_open_as_another_kind(void)
{
	fzn_trust_t trust, trust_back;
	fzn_ratchet_chain_t chain, chain_back;
	uint8_t root[FZN_PUBKEY_LEN], key[FZN_CHAIN_KEY_LEN];
	uint8_t trust_blob[FZN_PERSIST_MAX], chain_blob[FZN_PERSIST_MAX];
	size_t tlen = 0, clen = 0;

	fill(root, sizeof(root), 0x71);
	fill(key, sizeof(key), 0x81);
	fzn_trust_init(&trust);
	REQUIRE(fzn_trust_adopt(&trust, root, 1u) == FZN_TRUST_OK, "adopt refused");
	fzn_ratchet_init(&chain, key, 0);
	REQUIRE(fzn_persist_trust_pack(&trust, trust_blob, sizeof(trust_blob), &tlen)
	                == FZN_PERSIST_OK, "packing refused");
	REQUIRE(fzn_persist_chain_pack(&chain, chain_blob, sizeof(chain_blob), &clen)
	                == FZN_PERSIST_OK, "packing refused");

	/* A BACKEND CAN RETURN THE WRONG ROW. It keys however it likes -- a
	 * filename, a table index, a column -- and a caller can ask the wrong
	 * slot. Neither must produce a trust anchor parsed out of a ratchet
	 * chain, which is `wire/bytes.h`'s object tag at a boundary where the
	 * bytes are ours on both sides. */
	CHECK(fzn_persist_trust_open(chain_blob, clen, &trust_back) != FZN_PERSIST_OK,
	      "a chain blob opened as a trust anchor");
	CHECK(fzn_persist_chain_open(trust_blob, tlen, &chain_back) != FZN_PERSIST_OK,
	      "a trust blob opened as a ratchet chain");

	/* AND THE PAIR WHERE THE TAG IS THE ONLY DIFFERENCE, which is the case
	 * the first draft of this test missed and a mutation found.
	 *
	 * The four blobs are 43, 42, 83 and 42 bytes: a SECRET and a CHAIN are
	 * the same length, because both are a 32-byte key and an 8-byte
	 * number. Every other cross-open above is caught by the length check
	 * before the tag is consulted -- so deleting the tag check failed
	 * nothing, and the guard looked redundant while being the only thing
	 * separating these two.
	 *
	 * Constructing the case where they would differ is the whole
	 * technique; a pair chosen to confirm the answer would have passed
	 * either way. */
	{
		fzn_agree_secret_t sk, sk_back;
		uint8_t secret[FZN_AGREE_SECRET_LEN];
		uint8_t secret_blob[FZN_PERSIST_MAX];
		size_t slen = 0;

		fill(secret, sizeof(secret), 0xa1);
		memset(&sk, 0, sizeof(sk));
		REQUIRE(fzn_agree_secret_install(&sk, &AGREE, secret) == FZN_AGREE_OK,
		        "install refused");
		REQUIRE(fzn_persist_secret_pack(&sk, secret_blob, sizeof(secret_blob), &slen)
		                == FZN_PERSIST_OK, "packing a secret refused");
		REQUIRE(slen == clen,
		        "a secret blob and a chain blob are no longer the same length, so "
		        "this case no longer isolates the tag -- find another pair");

		CHECK(fzn_persist_chain_open(secret_blob, slen, &chain_back) != FZN_PERSIST_OK,
		      "a prekey secret opened as a ratchet chain, so a backend returning the "
		      "wrong row would seed a session from the host's own long-term secret");
		CHECK(fzn_persist_secret_open(chain_blob, clen, &AGREE, &sk_back)
		              != FZN_PERSIST_OK,
		      "a ratchet chain opened as the host's prekey secret");
	}

	/* A version nobody wrote, and a length one byte off, are both
	 * refusals rather than things to repair -- half an anchor is worse
	 * than none, because it parses. */
	trust_blob[0] = (uint8_t)(FZN_PERSIST_VERSION + 1u);
	CHECK(fzn_persist_trust_open(trust_blob, tlen, &trust_back) == FZN_PERSIST_ERR_SHAPE,
	      "a blob from a future version was opened");
	trust_blob[0] = (uint8_t)FZN_PERSIST_VERSION;
	CHECK(fzn_persist_trust_open(trust_blob, tlen - 1u, &trust_back) == FZN_PERSIST_ERR_SHAPE,
	      "a blob one byte short was opened");
	CHECK(fzn_persist_trust_open(trust_blob, tlen + 1u, &trust_back) == FZN_PERSIST_ERR_SHAPE,
	      "a blob with a trailing byte was opened, so the length is not exact");
}

static void test_every_guard_refuses_its_own_argument(void)
{
	fzn_trust_t t;
	uint8_t blob[FZN_PERSIST_MAX];
	size_t len = 0;
	uint8_t root[FZN_PUBKEY_LEN];

	fill(root, sizeof(root), 0x91);
	fzn_trust_init(&t);
	REQUIRE(fzn_trust_adopt(&t, root, 1u) == FZN_TRUST_OK, "adopt refused");

	CHECK(fzn_persist_trust_pack(NULL, blob, sizeof(blob), &len) == FZN_PERSIST_ERR_MALFORMED,
	      "null trust");
	CHECK(fzn_persist_trust_pack(&t, NULL, sizeof(blob), &len) == FZN_PERSIST_ERR_MALFORMED,
	      "null out");
	/* A buffer too small is the caller's bug and is refused BEFORE
	 * anything is written, so a short buffer cannot be left half filled. */
	CHECK(fzn_persist_trust_pack(&t, blob, 4u, &len) == FZN_PERSIST_ERR_MALFORMED,
	      "a buffer too small was written into");
	CHECK(fzn_persist_trust_open(NULL, 8u, &t) == FZN_PERSIST_ERR_MALFORMED, "null bytes");

	CHECK(strcmp(fzn_persist_err_str(FZN_PERSIST_OK), "ok") == 0, "ok does not render");
	CHECK(strcmp(fzn_persist_err_str((fzn_persist_err_t)66), "unknown") == 0,
	      "a value that is not an enumerator does not render as unknown");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	check_at(0, __LINE__, "deliberate");
	CHECK(failures == before + 1, "a failing check did not count");
	failures = before;
	checks -= 1;
}

int main(void)
{
	test_an_anchor_comes_back_with_its_provenance();
	test_an_empty_anchor_is_not_stored();
	test_a_prekey_secret_survives_with_its_generation();
	test_a_pinned_peer_and_a_chain_round_trip();
	test_a_blob_does_not_open_as_another_kind();
	test_every_guard_refuses_its_own_argument();
	test_the_suite_can_tell_pass_from_fail();

	printf("persist_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
