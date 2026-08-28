/* Tests for session/session.c: the canonical transcript and what it derives.
 *
 * THE CASE THIS FILE EXISTS FOR IS THE SYMMETRY. Two hosts must build
 * byte-identical transcripts from opposite points of view, without having
 * agreed who is the initiator. Everything else here is a guard; that one is
 * the design.
 *
 * THE TETHER. `session/session.h` repeats FZN_SESSION_IDENTITY_LEN rather
 * than including `chain/chain.h` for FZN_PUBKEY_LEN, so that `session/` stays
 * independent of the capability layer. The check is here, which is the
 * arrangement `chain/test/manifest_test.c` uses for FZN_MANIFEST_MAX_PAIRS:
 * `make test`, not `make`.
 */

#include "../session.h"

#include "../../chain/chain.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

_Static_assert(FZN_SESSION_IDENTITY_LEN == FZN_PUBKEY_LEN,
               "session/ and chain/ disagree about how long an identity key is");

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
	fprintf(stderr, "  FAIL session_test.c:%d: ", line);
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

static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	(void)ctx;
	h ^= (uint64_t)out_len;
	h *= 0x100000001b3ull;
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

/* Commutative toy agreement, so both sides reach the same shared secret --
 * which is what lets this file test the transcript rather than X25519.
 * session/test/agree_monocypher_test.c exercises the real thing. */
static int stub_public_of(void *ctx, uint8_t out[FZN_AGREE_PUBLIC_LEN],
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

static const fzn_hash_ops_t HASH = { stub_hash, NULL };
static const fzn_agree_ops_t AGREE = { stub_public_of, stub_agree, NULL };

static void fill(uint8_t *p, size_t n, uint8_t seed)
{
	size_t i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)(seed + (i * 13u));
}

/* ---- the cases -------------------------------------------------------- */

static void test_both_sides_build_the_same_transcript(void)
{
	uint8_t id_a[FZN_SESSION_IDENTITY_LEN], id_b[FZN_SESSION_IDENTITY_LEN];
	uint8_t pk_a[FZN_AGREE_PUBLIC_LEN], pk_b[FZN_AGREE_PUBLIC_LEN];
	uint8_t shared[FZN_AGREE_SHARED_LEN];
	uint8_t from_a[FZN_SESSION_TRANSCRIPT_LEN], from_b[FZN_SESSION_TRANSCRIPT_LEN];

	fill(id_a, sizeof(id_a), 0x10);
	fill(id_b, sizeof(id_b), 0x90);
	fill(pk_a, sizeof(pk_a), 0x20);
	fill(pk_b, sizeof(pk_b), 0xa0);
	fill(shared, sizeof(shared), 0x55);

	/* THE DESIGN, IN ONE ASSERTION. A builds it as (self=A, peer=B); B
	 * builds it as (self=B, peer=A); the bytes must be identical, with no
	 * role negotiated. A role-ordered transcript passes every other case
	 * in this file and fails this one. */
	REQUIRE(fzn_session_transcript(id_a, pk_a, id_b, pk_b, shared, from_a) == FZN_SESSION_OK,
	        "A could not build a transcript");
	REQUIRE(fzn_session_transcript(id_b, pk_b, id_a, pk_a, shared, from_b) == FZN_SESSION_OK,
	        "B could not build a transcript");
	CHECK(memcmp(from_a, from_b, FZN_SESSION_TRANSCRIPT_LEN) == 0,
	      "the two sides built different transcripts, so they derive different roots "
	      "and cannot talk");

	/* AND IT IS SYMMETRIC IN BOTH SORT DIRECTIONS. The pair above has A
	 * sorting first; swapping the seeds puts B first, which is the branch
	 * the case above never enters. */
	{
		uint8_t low[FZN_SESSION_IDENTITY_LEN], high[FZN_SESSION_IDENTITY_LEN];
		uint8_t x[FZN_SESSION_TRANSCRIPT_LEN], y[FZN_SESSION_TRANSCRIPT_LEN];

		fill(low, sizeof(low), 0x01);
		fill(high, sizeof(high), 0xf0);
		REQUIRE(fzn_session_transcript(high, pk_b, low, pk_a, shared, x) == FZN_SESSION_OK,
		        "the high-first build refused");
		REQUIRE(fzn_session_transcript(low, pk_a, high, pk_b, shared, y) == FZN_SESSION_OK,
		        "the low-first build refused");
		CHECK(memcmp(x, y, FZN_SESSION_TRANSCRIPT_LEN) == 0,
		      "the ordering is not symmetric when the caller is the higher key");
	}
}

static void test_a_prekey_is_not_interchangeable_with_the_others(void)
{
	uint8_t id_a[FZN_SESSION_IDENTITY_LEN], id_b[FZN_SESSION_IDENTITY_LEN];
	uint8_t pk_a[FZN_AGREE_PUBLIC_LEN], pk_b[FZN_AGREE_PUBLIC_LEN];
	uint8_t shared[FZN_AGREE_SHARED_LEN];
	uint8_t honest[FZN_SESSION_TRANSCRIPT_LEN], swapped[FZN_SESSION_TRANSCRIPT_LEN];

	fill(id_a, sizeof(id_a), 0x11);
	fill(id_b, sizeof(id_b), 0x91);
	fill(pk_a, sizeof(pk_a), 0x21);
	fill(pk_b, sizeof(pk_b), 0xa1);
	fill(shared, sizeof(shared), 0x56);

	REQUIRE(fzn_session_transcript(id_a, pk_a, id_b, pk_b, shared, honest) == FZN_SESSION_OK,
	        "the honest build refused");
	/* Pairing A's identity with B's prekey must not produce the same
	 * bytes.
	 *
	 * THIS CASE WAS NAMED FOR A PROPERTY IT DOES NOT TEST, and a mutation
	 * said so: regrouping the transcript as identity|identity|prekey|prekey
	 * failed nothing here, because BOTH layouts distinguish this swap. The
	 * interleaving is readability; the canonical order is what makes the
	 * assignment unambiguous. Renamed to what it checks -- that the two
	 * prekeys are not interchangeable -- which is a real property and is
	 * the one the assertion below expresses. */
	REQUIRE(fzn_session_transcript(id_a, pk_b, id_b, pk_a, shared, swapped) == FZN_SESSION_OK,
	        "the swapped build refused");
	CHECK(memcmp(honest, swapped, FZN_SESSION_TRANSCRIPT_LEN) != 0,
	      "pairing one host's identity with the other's prekey gave the same transcript");
}

static void test_every_input_reaches_the_transcript(void)
{
	uint8_t id_a[FZN_SESSION_IDENTITY_LEN], id_b[FZN_SESSION_IDENTITY_LEN];
	uint8_t pk_a[FZN_AGREE_PUBLIC_LEN], pk_b[FZN_AGREE_PUBLIC_LEN];
	uint8_t shared[FZN_AGREE_SHARED_LEN];
	uint8_t base[FZN_SESSION_TRANSCRIPT_LEN], bent[FZN_SESSION_TRANSCRIPT_LEN];
	size_t i;

	fill(id_a, sizeof(id_a), 0x12);
	fill(id_b, sizeof(id_b), 0x92);
	fill(pk_a, sizeof(pk_a), 0x22);
	fill(pk_b, sizeof(pk_b), 0xa2);
	fill(shared, sizeof(shared), 0x57);
	REQUIRE(fzn_session_transcript(id_a, pk_a, id_b, pk_b, shared, base) == FZN_SESSION_OK,
	        "the control refused");

	/* EVERY BYTE OF EVERY INPUT, one at a time. A transcript that read a
	 * prefix of any field would pass a test that bent only the first
	 * byte, and a prekey whose tail is ignored is a rotation that does
	 * not change the root -- which is the whole property gone. */
#define BENDS(buf, n, what)                                                              \
	do {                                                                             \
		for (i = 0; i < (n); i++) {                                              \
			(buf)[i] = (uint8_t)((buf)[i] ^ 0x01u);                          \
			CHECK(fzn_session_transcript(id_a, pk_a, id_b, pk_b, shared,      \
			                             bent) == FZN_SESSION_OK,            \
			      "the bent build refused");                                 \
			CHECK(memcmp(base, bent, FZN_SESSION_TRANSCRIPT_LEN) != 0,        \
			      "byte %zu of %s does not reach the transcript", i, what);   \
			(buf)[i] = (uint8_t)((buf)[i] ^ 0x01u);                          \
		}                                                                        \
	} while (0)

	BENDS(pk_a, FZN_AGREE_PUBLIC_LEN, "this host's prekey");
	BENDS(pk_b, FZN_AGREE_PUBLIC_LEN, "the peer's prekey");
	BENDS(shared, FZN_AGREE_SHARED_LEN, "the shared secret");
#undef BENDS
}

static void test_a_session_with_yourself_is_refused(void)
{
	uint8_t id[FZN_SESSION_IDENTITY_LEN];
	uint8_t pk[FZN_AGREE_PUBLIC_LEN];
	uint8_t shared[FZN_AGREE_SHARED_LEN];
	uint8_t out[FZN_SESSION_TRANSCRIPT_LEN];

	fill(id, sizeof(id), 0x33);
	fill(pk, sizeof(pk), 0x44);
	fill(shared, sizeof(shared), 0x58);

	/* The canonical order has no tie-break, so equal identities would
	 * make the layout depend on which branch happened to be taken. Its
	 * own code, because a caller has to tell it from its own bug. */
	CHECK(fzn_session_transcript(id, pk, id, pk, shared, out) == FZN_SESSION_ERR_SELF,
	      "a session with yourself was built");
}

static void test_two_hosts_establish_the_same_root(void)
{
	fzn_agree_secret_t sk_a, sk_b;
	uint8_t sec_a[FZN_AGREE_SECRET_LEN], sec_b[FZN_AGREE_SECRET_LEN];
	uint8_t id_a[FZN_SESSION_IDENTITY_LEN], id_b[FZN_SESSION_IDENTITY_LEN];
	uint8_t key_a[FZN_AEAD_KEY_LEN], key_b[FZN_AEAD_KEY_LEN];
	uint8_t ck_a[FZN_COMMITMENT_KEY_LEN], ck_b[FZN_COMMITMENT_KEY_LEN];

	memset(&sk_a, 0, sizeof(sk_a));
	memset(&sk_b, 0, sizeof(sk_b));
	fill(sec_a, sizeof(sec_a), 0x61);
	fill(sec_b, sizeof(sec_b), 0x71);
	fill(id_a, sizeof(id_a), 0x13);
	fill(id_b, sizeof(id_b), 0x93);

	REQUIRE(fzn_agree_secret_install(&sk_a, &AGREE, sec_a) == FZN_AGREE_OK, "install A");
	REQUIRE(fzn_agree_secret_install(&sk_b, &AGREE, sec_b) == FZN_AGREE_OK, "install B");
	REQUIRE(fzn_agree_secret_public(&sk_a) && fzn_agree_secret_public(&sk_b),
	        "an installed secret offered no public key");

	REQUIRE(fzn_session_establish(&sk_a, &AGREE, &HASH, id_a, id_b,
	                              fzn_agree_secret_public(&sk_b), key_a, ck_a)
	                == FZN_SESSION_OK, "A could not establish");
	REQUIRE(fzn_session_establish(&sk_b, &AGREE, &HASH, id_b, id_a,
	                              fzn_agree_secret_public(&sk_a), key_b, ck_b)
	                == FZN_SESSION_OK, "B could not establish");

	CHECK(memcmp(key_a, key_b, FZN_AEAD_KEY_LEN) == 0,
	      "the two hosts derived different AEAD keys");
	CHECK(memcmp(ck_a, ck_b, FZN_COMMITMENT_KEY_LEN) == 0,
	      "the two hosts derived different commitment keys");
	/* And the two halves are not the same bytes, which a derivation
	 * returning one buffer twice would also satisfy above. */
	CHECK(memcmp(key_a, ck_a, FZN_COMMITMENT_KEY_LEN) != 0,
	      "the AEAD key and the commitment key are the same bytes");
}

static void test_a_rotation_changes_the_root(void)
{
	fzn_agree_secret_t sk_a, sk_b;
	uint8_t sec_a[FZN_AGREE_SECRET_LEN], sec_b[FZN_AGREE_SECRET_LEN];
	uint8_t rotated[FZN_AGREE_SECRET_LEN];
	uint8_t id_a[FZN_SESSION_IDENTITY_LEN], id_b[FZN_SESSION_IDENTITY_LEN];
	uint8_t before[FZN_AEAD_KEY_LEN], after[FZN_AEAD_KEY_LEN];
	uint8_t ck[FZN_COMMITMENT_KEY_LEN];

	memset(&sk_a, 0, sizeof(sk_a));
	memset(&sk_b, 0, sizeof(sk_b));
	fill(sec_a, sizeof(sec_a), 0x62);
	fill(sec_b, sizeof(sec_b), 0x72);
	fill(rotated, sizeof(rotated), 0x82);
	fill(id_a, sizeof(id_a), 0x14);
	fill(id_b, sizeof(id_b), 0x94);

	REQUIRE(fzn_agree_secret_install(&sk_a, &AGREE, sec_a) == FZN_AGREE_OK, "install A");
	REQUIRE(fzn_agree_secret_install(&sk_b, &AGREE, sec_b) == FZN_AGREE_OK, "install B");
	REQUIRE(fzn_agree_secret_public(&sk_b) != NULL, "no public key");
	REQUIRE(fzn_session_establish(&sk_a, &AGREE, &HASH, id_a, id_b,
	                              fzn_agree_secret_public(&sk_b), before, ck)
	                == FZN_SESSION_OK, "the first establish refused");

	/* THE PROPERTY THE WHOLE DESIGN RESTS ON. Rotating B's prekey must
	 * change the root A derives, or a rotation buys nothing and the
	 * forward secrecy is a claim in a header. */
	REQUIRE(fzn_agree_secret_install(&sk_b, &AGREE, rotated) == FZN_AGREE_OK, "rotate B");
	REQUIRE(fzn_agree_secret_public(&sk_b) != NULL, "no public key after rotation");
	REQUIRE(fzn_session_establish(&sk_a, &AGREE, &HASH, id_a, id_b,
	                              fzn_agree_secret_public(&sk_b), after, ck)
	                == FZN_SESSION_OK, "the second establish refused");
	CHECK(memcmp(before, after, FZN_AEAD_KEY_LEN) != 0,
	      "rotating a prekey did not change the session root, so rotation buys nothing");
}

static void test_every_guard_refuses_its_own_argument(void)
{
	fzn_agree_secret_t sk;
	uint8_t buf[FZN_SESSION_TRANSCRIPT_LEN];
	uint8_t key[FZN_AEAD_KEY_LEN], ck[FZN_COMMITMENT_KEY_LEN];

	memset(&sk, 0, sizeof(sk));
	fill(buf, sizeof(buf), 0x15);

	CHECK(fzn_session_transcript(NULL, buf, buf, buf, buf, buf) == FZN_SESSION_ERR_MALFORMED,
	      "null self identity");
	CHECK(fzn_session_transcript(buf, NULL, buf, buf, buf, buf) == FZN_SESSION_ERR_MALFORMED,
	      "null self prekey");
	CHECK(fzn_session_transcript(buf, buf, buf, buf, buf, NULL) == FZN_SESSION_ERR_MALFORMED,
	      "null out");

	CHECK(fzn_session_establish(NULL, &AGREE, &HASH, buf, buf, buf, key, ck)
	              == FZN_SESSION_ERR_MALFORMED, "null prekey secret");
	CHECK(fzn_session_establish(&sk, &AGREE, &HASH, buf, buf, buf, NULL, ck)
	              == FZN_SESSION_ERR_MALFORMED, "null key out");
	/* An uninstalled secret is AGREE, not MALFORMED: it is a host that has
	 * not minted a prekey yet, which is a state rather than a bug. */
	CHECK(fzn_session_establish(&sk, &AGREE, &HASH, buf, buf, buf, key, ck)
	              == FZN_SESSION_ERR_AGREE, "an uninstalled prekey established a session");

	CHECK(strcmp(fzn_session_err_str(FZN_SESSION_OK), "ok") == 0, "ok does not render");
	CHECK(strcmp(fzn_session_err_str((fzn_session_err_t)77), "unknown") == 0,
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
	test_both_sides_build_the_same_transcript();
	test_a_prekey_is_not_interchangeable_with_the_others();
	test_every_input_reaches_the_transcript();
	test_a_session_with_yourself_is_refused();
	test_two_hosts_establish_the_same_root();
	test_a_rotation_changes_the_root();
	test_every_guard_refuses_its_own_argument();
	test_the_suite_can_tell_pass_from_fail();

	printf("session_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
