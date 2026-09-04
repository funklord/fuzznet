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
#include "../../ratchet/ratchet.h"

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

/* A BINDING THAT REFUSES, and it writes before it refuses -- which is what a
 * real one does. `fzn_agree_shared` computes into the caller's buffer and
 * only then finds the result degenerate, so a caller that ignores the return
 * code finds a plausible-looking secret sitting there. That is the whole
 * reason the propagation below is worth a test. */
static int refusing_agree(void *ctx, uint8_t out[FZN_AGREE_SHARED_LEN],
                          const uint8_t secret[FZN_AGREE_SECRET_LEN],
                          const uint8_t peer[FZN_AGREE_PUBLIC_LEN])
{
	(void)ctx;
	(void)secret;
	(void)peer;
	memset(out, 0x5e, FZN_AGREE_SHARED_LEN);
	return 0;
}

static const fzn_hash_ops_t HASH = { stub_hash, NULL };

/* A HASH THAT WRITES AND THEN REFUSES, on the call the fixture chooses.
 *
 * WRITING FIRST IS THE WHOLE POINT, and agree_test.c's degenerate binding
 * makes the same argument: a real binding computes into the caller's buffer
 * and only then finds it cannot certify the result. A stub that refuses
 * without writing leaves the caller's bytes untouched, so the wipe under
 * test has nothing to remove and the case would pass with it deleted --
 * a test that cannot fail for the defect it names.
 *
 * `fail_on` is 1-based and counts calls, because fzn_session_chains derives
 * TWO chains and the interesting refusals are at different depths: the first
 * call exercises chain_for's own wipe of `out`, the second exercises
 * fzn_session_chains wiping the send chain it had already produced. */
static unsigned refusing_calls;
static unsigned refusing_fail_on;

static int refusing_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in,
                         size_t in_len)
{
	refusing_calls++;
	(void)stub_hash(ctx, out, out_len, in, in_len);
	if (refusing_calls == refusing_fail_on)
		return 0;
	return 1;
}

static const fzn_hash_ops_t REFUSING = { refusing_hash, NULL };
static const fzn_agree_ops_t AGREE = { stub_public_of, stub_agree, NULL };
static const fzn_agree_ops_t DEGENERATE = { stub_public_of, refusing_agree, NULL };

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

static void test_the_two_directions_are_different_and_agree(void)
{
	uint8_t id_a[FZN_SESSION_IDENTITY_LEN], id_b[FZN_SESSION_IDENTITY_LEN];
	uint8_t root[FZN_AEAD_KEY_LEN];
	uint8_t a_send[FZN_CHAIN_KEY_LEN], a_recv[FZN_CHAIN_KEY_LEN];
	uint8_t b_send[FZN_CHAIN_KEY_LEN], b_recv[FZN_CHAIN_KEY_LEN];

	fill(id_a, sizeof(id_a), 0x16);
	fill(id_b, sizeof(id_b), 0x96);
	fill(root, sizeof(root), 0x27);

	REQUIRE(fzn_session_chains(&HASH, root, id_a, id_b, a_send, a_recv) == FZN_SESSION_OK,
	        "A could not derive its chains");
	REQUIRE(fzn_session_chains(&HASH, root, id_b, id_a, b_send, b_recv) == FZN_SESSION_OK,
	        "B could not derive its chains");

	/* THE MECHANISM. A's send chain and B's receive chain are the same
	 * key, and neither side had to say which it was -- both are keyed
	 * (A, B). Same the other way. */
	CHECK(memcmp(a_send, b_recv, FZN_CHAIN_KEY_LEN) == 0,
	      "A's send chain is not B's receive chain, so they cannot talk");
	CHECK(memcmp(b_send, a_recv, FZN_CHAIN_KEY_LEN) == 0,
	      "B's send chain is not A's receive chain");

	/* AND THE TWO DIRECTIONS DIFFER, which is the point of ordering by
	 * role here rather than canonically. A canonical order would give one
	 * chain for both directions -- and a message replayed back at its
	 * sender would then decrypt under the key that sender is waiting to
	 * receive under. */
	CHECK(memcmp(a_send, a_recv, FZN_CHAIN_KEY_LEN) != 0,
	      "the two directions share a chain, so a message can be replayed back at "
	      "its own sender");

	/* Neither is the root it came from. */
	CHECK(memcmp(a_send, root, FZN_CHAIN_KEY_LEN) != 0, "the send chain is the root");

	/* A different root gives different chains, so the derivation reads
	 * the root rather than only the identities. */
	{
		uint8_t other_root[FZN_AEAD_KEY_LEN];
		uint8_t other_send[FZN_CHAIN_KEY_LEN], other_recv[FZN_CHAIN_KEY_LEN];

		fill(other_root, sizeof(other_root), 0x37);
		REQUIRE(fzn_session_chains(&HASH, other_root, id_a, id_b, other_send,
		                           other_recv) == FZN_SESSION_OK, "refused");
		CHECK(memcmp(a_send, other_send, FZN_CHAIN_KEY_LEN) != 0,
		      "two different session roots gave the same send chain");
	}

	/* A host has no direction to itself. */
	CHECK(fzn_session_chains(&HASH, root, id_a, id_a, a_send, a_recv) == FZN_SESSION_ERR_SELF,
	      "a host derived a chain to itself");
}

/* And the seeds are what `ratchet/` takes, walked one step so the two modules
 * are shown to compose rather than merely to have compatible lengths. */
static void test_the_seeds_drive_a_ratchet(void)
{
	uint8_t id_a[FZN_SESSION_IDENTITY_LEN], id_b[FZN_SESSION_IDENTITY_LEN];
	uint8_t root[FZN_AEAD_KEY_LEN];
	uint8_t a_send[FZN_CHAIN_KEY_LEN], a_recv[FZN_CHAIN_KEY_LEN];
	uint8_t b_send[FZN_CHAIN_KEY_LEN], b_recv[FZN_CHAIN_KEY_LEN];
	fzn_ratchet_chain_t sender, receiver, moved;
	uint8_t mk_send[FZN_MESSAGE_KEY_LEN], mk_recv[FZN_MESSAGE_KEY_LEN];

	fill(id_a, sizeof(id_a), 0x17);
	fill(id_b, sizeof(id_b), 0x97);
	fill(root, sizeof(root), 0x28);

	REQUIRE(fzn_session_chains(&HASH, root, id_a, id_b, a_send, a_recv) == FZN_SESSION_OK,
	        "A could not derive its chains");
	REQUIRE(fzn_session_chains(&HASH, root, id_b, id_a, b_send, b_recv) == FZN_SESSION_OK,
	        "B could not derive its chains");

	/* A sends on its send chain; B receives on the chain it derived for
	 * that direction. The message keys must match, which is the whole
	 * composition in one assertion. */
	fzn_ratchet_init(&sender, a_send, 0);
	fzn_ratchet_init(&receiver, b_recv, 0);
	REQUIRE(fzn_ratchet_advance(&HASH, &sender, 0, mk_send, &moved, NULL, 0, NULL, NULL)
	                == FZN_RATCHET_OK, "the sender could not advance");
	REQUIRE(fzn_ratchet_advance(&HASH, &receiver, 0, mk_recv, &moved, NULL, 0, NULL, NULL)
	                == FZN_RATCHET_OK, "the receiver could not advance");
	CHECK(memcmp(mk_send, mk_recv, FZN_MESSAGE_KEY_LEN) == 0,
	      "a session's seed and the ratchet do not compose: the two sides derived "
	      "different message keys for the first message");
}

static void test_the_ephemeral_exchange_agrees_and_differs(void)
{
	fzn_agree_secret_t pre_a, pre_b, eph;
	uint8_t sec_a[FZN_AGREE_SECRET_LEN], sec_b[FZN_AGREE_SECRET_LEN];
	uint8_t sec_e[FZN_AGREE_SECRET_LEN];
	uint8_t id_a[FZN_SESSION_IDENTITY_LEN], id_b[FZN_SESSION_IDENTITY_LEN];
	uint8_t key_i[FZN_AEAD_KEY_LEN], key_r[FZN_AEAD_KEY_LEN], key_base[FZN_AEAD_KEY_LEN];
	uint8_t ck_i[FZN_COMMITMENT_KEY_LEN], ck_r[FZN_COMMITMENT_KEY_LEN];
	uint8_t ck_base[FZN_COMMITMENT_KEY_LEN];

	memset(&pre_a, 0, sizeof(pre_a));
	memset(&pre_b, 0, sizeof(pre_b));
	memset(&eph, 0, sizeof(eph));
	fill(sec_a, sizeof(sec_a), 0x63);
	fill(sec_b, sizeof(sec_b), 0x73);
	fill(sec_e, sizeof(sec_e), 0x83);
	fill(id_a, sizeof(id_a), 0x18);
	fill(id_b, sizeof(id_b), 0x98);

	REQUIRE(fzn_agree_secret_install(&pre_a, &AGREE, sec_a) == FZN_AGREE_OK, "install A");
	REQUIRE(fzn_agree_secret_install(&pre_b, &AGREE, sec_b) == FZN_AGREE_OK, "install B");
	REQUIRE(fzn_agree_secret_install(&eph, &AGREE, sec_e) == FZN_AGREE_OK, "install E");
	REQUIRE(fzn_agree_secret_public(&pre_a) && fzn_agree_secret_public(&pre_b)
	                && fzn_agree_secret_public(&eph), "an installed secret has no public");

	/* THE PROPERTY. A is the initiator and mints the ephemeral; B is the
	 * responder and mixes the ephemeral public with its own prekey
	 * secret. Both must land on the same root with no negotiation beyond
	 * knowing which of them started. */
	REQUIRE(fzn_session_establish_initiator(&pre_a, &eph, &AGREE, &HASH, id_a, id_b,
	                                        fzn_agree_secret_public(&pre_b), key_i, ck_i)
	                == FZN_SESSION_OK, "the initiator could not establish");
	REQUIRE(fzn_session_establish_responder(&pre_b, &AGREE, &HASH, id_b, id_a,
	                                        fzn_agree_secret_public(&pre_a),
	                                        fzn_agree_secret_public(&eph), key_r, ck_r)
	                == FZN_SESSION_OK, "the responder could not establish");
	CHECK(memcmp(key_i, key_r, FZN_AEAD_KEY_LEN) == 0,
	      "initiator and responder derived different keys");
	CHECK(memcmp(ck_i, ck_r, FZN_COMMITMENT_KEY_LEN) == 0,
	      "initiator and responder derived different commitment keys");

	/* AND IT IS NOT THE BASE SESSION'S ROOT. A host doing the ephemeral
	 * exchange and one doing the base exchange must fail to talk, loudly,
	 * rather than one of them silently getting less than it believed --
	 * which is what the version byte in the transcript is for. */
	REQUIRE(fzn_session_establish(&pre_a, &AGREE, &HASH, id_a, id_b,
	                              fzn_agree_secret_public(&pre_b), key_base, ck_base)
	                == FZN_SESSION_OK, "the base establish refused");
	CHECK(memcmp(key_i, key_base, FZN_AEAD_KEY_LEN) != 0,
	      "the ephemeral exchange and the base exchange give the same root, so a peer "
	      "doing one silently interoperates with a peer doing the other");

	/* A DIFFERENT EPHEMERAL GIVES A DIFFERENT ROOT, which is the whole of
	 * what the ephemeral buys: two sessions between the same pair, with
	 * the same prekeys, are unrelated. */
	{
		fzn_agree_secret_t eph2;
		uint8_t sec_e2[FZN_AGREE_SECRET_LEN];
		uint8_t key2[FZN_AEAD_KEY_LEN], ck2[FZN_COMMITMENT_KEY_LEN];

		memset(&eph2, 0, sizeof(eph2));
		fill(sec_e2, sizeof(sec_e2), 0x93);
		REQUIRE(fzn_agree_secret_install(&eph2, &AGREE, sec_e2) == FZN_AGREE_OK,
		        "install E2");
		REQUIRE(fzn_session_establish_initiator(&pre_a, &eph2, &AGREE, &HASH, id_a,
		                                        id_b, fzn_agree_secret_public(&pre_b),
		                                        key2, ck2) == FZN_SESSION_OK,
		        "the second establish refused");
		CHECK(memcmp(key_i, key2, FZN_AEAD_KEY_LEN) != 0,
		      "two sessions with different ephemerals share a root, so the ephemeral "
		      "buys nothing");
	}

	/* THE ROLES ARE NOT INTERCHANGEABLE. Running the initiator's half from
	 * B's point of view must not reproduce the same root -- if it did, the
	 * role-ordering would be decorative and either party could claim to
	 * have started. */
	{
		uint8_t swapped[FZN_AEAD_KEY_LEN], ck_s[FZN_COMMITMENT_KEY_LEN];

		REQUIRE(fzn_session_establish_initiator(&pre_b, &eph, &AGREE, &HASH, id_b, id_a,
		                                        fzn_agree_secret_public(&pre_a),
		                                        swapped, ck_s) == FZN_SESSION_OK,
		        "the swapped establish refused");
		CHECK(memcmp(key_i, swapped, FZN_AEAD_KEY_LEN) != 0,
		      "the two roles are interchangeable, so ordering by role is decorative");
	}

	/* And a host cannot run either half against itself. */
	CHECK(fzn_session_establish_initiator(&pre_a, &eph, &AGREE, &HASH, id_a, id_a,
	                                      fzn_agree_secret_public(&pre_b), key_i, ck_i)
	              == FZN_SESSION_ERR_SELF, "an initiator established with itself");
	CHECK(fzn_session_establish_responder(&pre_b, &AGREE, &HASH, id_b, id_b,
	                                      fzn_agree_secret_public(&pre_a),
	                                      fzn_agree_secret_public(&eph), key_r, ck_r)
	              == FZN_SESSION_ERR_SELF, "a responder established with itself");

	/* An uninstalled ephemeral is AGREE, not MALFORMED: a host that has
	 * not minted one yet is in a state rather than holding a bug. */
	{
		fzn_agree_secret_t empty;

		memset(&empty, 0, sizeof(empty));
		CHECK(fzn_session_establish_initiator(&pre_a, &empty, &AGREE, &HASH, id_a, id_b,
		                                      fzn_agree_secret_public(&pre_b), key_i,
		                                      ck_i) == FZN_SESSION_ERR_AGREE,
		      "an uninstalled ephemeral established a session");
	}
}

/* A REFUSED DERIVATION HANDS BACK NO KEY MATERIAL.
 *
 * Both wipes here were measured by `make sabotage` and neither was held by
 * anything: removing them left all 64 binaries green. They are not
 * defence in depth -- each clears a buffer the CALLER owns, on a path that
 * returns an error, so what they prevent is a caller who ignores the return
 * value hashing a half-derived chain key into a transcript.
 *
 * `session/agree.c` has the same shape and agree_test.c:241 already holds
 * it. This is the sibling case that was missing, which is the third time
 * today a module's guard turned out to be defended in one place and not in
 * the module next to it.
 *
 * THE BUFFERS ARE DIRTIED FIRST and the stub WRITES BEFORE IT REFUSES, or
 * neither case can fail: against a zeroed buffer, or a binding that refuses
 * without computing, a deleted wipe is indistinguishable from a working
 * one. */
/* An agreement that succeeds `n` times and then refuses, so that the SECOND
 * agreement in each v2 derivation can be made to fail on its own. A stub that
 * always refuses cannot reach it: the first call fails and the second is
 * never made. */
static unsigned agree_calls;
static unsigned agree_fail_on;

static int counting_agree(void *ctx, uint8_t out[FZN_AGREE_SHARED_LEN],
                          const uint8_t secret[FZN_AGREE_SECRET_LEN],
                          const uint8_t peer_public[FZN_AGREE_PUBLIC_LEN])
{
	agree_calls++;
	if (agree_calls == agree_fail_on)
		return 0;
	return stub_agree(ctx, out, secret, peer_public);
}

static const fzn_agree_ops_t COUNTING = { stub_public_of, counting_agree, NULL };

/*
 * A REFUSED AGREEMENT IS REPORTED AS ONE, INCLUDING THE SECOND OF TWO.
 *
 * Added 2026-09-04 from a coverage measurement rather than a hunch.
 * `session.c` had 21 branches never taken both ways, and among them were
 * exactly the second `fzn_agree_shared` in each v2 derivation -- lines 322 and
 * 371. The FIRST agreement's failure was already covered by the 2026-09-02
 * work `session.h` records; a stub that always refuses fails that one and
 * never reaches the other.
 *
 * The distinction is not bookkeeping. In the initiator the second agreement
 * is the EPHEMERAL one, which is the whole of what a later compromise of the
 * prekey cannot reproduce. A derivation that continued past its refusal would
 * produce a session with no forward secrecy in it and no way for either side
 * to tell -- the key would simply be one an attacker holding the prekey can
 * recompute.
 *
 * So the assertion is the observable half: a refusal at the second agreement
 * must surface as FZN_SESSION_ERR_AGREE, not as OK with a key the caller will
 * use. `session.h` already states, and the 2026-09-02 measurement already
 * showed, that neither output buffer is written on any refusal; this covers
 * the path that measurement could not reach.
 */
static void test_the_second_agreement_can_refuse_too(void)
{
	uint8_t id_a[FZN_SESSION_IDENTITY_LEN], id_b[FZN_SESSION_IDENTITY_LEN];
	uint8_t sec_a[FZN_AGREE_SECRET_LEN], sec_e[FZN_AGREE_SECRET_LEN];
	uint8_t peer_prekey[FZN_AGREE_PUBLIC_LEN], peer_eph[FZN_AGREE_PUBLIC_LEN];
	uint8_t key[FZN_AEAD_KEY_LEN], ckey[FZN_COMMITMENT_KEY_LEN];
	fzn_agree_secret_t sk_a, sk_e;

	fill(id_a, sizeof(id_a), 0x71);
	fill(id_b, sizeof(id_b), 0x72);
	fill(sec_a, sizeof(sec_a), 0x73);
	fill(sec_e, sizeof(sec_e), 0x74);
	fill(peer_prekey, sizeof(peer_prekey), 0x75);
	fill(peer_eph, sizeof(peer_eph), 0x76);

	REQUIRE(fzn_agree_secret_install(&sk_a, &COUNTING, sec_a) == FZN_AGREE_OK,
	        "the prekey secret did not install");
	REQUIRE(fzn_agree_secret_install(&sk_e, &COUNTING, sec_e) == FZN_AGREE_OK,
	        "the ephemeral secret did not install");

	/* THE CONTROL FIRST. With nothing failing, both derivations must
	 * SUCCEED -- otherwise the refusals below would be indistinguishable
	 * from a fixture that never worked. */
	agree_calls = 0;
	agree_fail_on = 0;
	CHECK(fzn_session_establish_initiator(&sk_a, &sk_e, &COUNTING, &HASH, id_a, id_b,
	                                      peer_prekey, key, ckey) == FZN_SESSION_OK,
	      "the initiator did not succeed with nothing failing");
	CHECK(agree_calls == 2u, "the initiator made %u agreements, wanted 2", agree_calls);

	agree_calls = 0;
	CHECK(fzn_session_establish_responder(&sk_a, &COUNTING, &HASH, id_a, id_b, peer_prekey,
	                                      peer_eph, key, ckey) == FZN_SESSION_OK,
	      "the responder did not succeed with nothing failing");
	CHECK(agree_calls == 2u, "the responder made %u agreements, wanted 2", agree_calls);

	/* NOW THE SECOND ONE REFUSES, in each direction. */
	agree_calls = 0;
	agree_fail_on = 2;
	memset(key, 0x33, sizeof(key));
	memset(ckey, 0x33, sizeof(ckey));
	CHECK(fzn_session_establish_initiator(&sk_a, &sk_e, &COUNTING, &HASH, id_a, id_b,
	                                      peer_prekey, key, ckey) == FZN_SESSION_ERR_AGREE,
	      "the initiator continued past a refused EPHEMERAL agreement");

	agree_calls = 0;
	agree_fail_on = 2;
	memset(key, 0x33, sizeof(key));
	memset(ckey, 0x33, sizeof(ckey));
	CHECK(fzn_session_establish_responder(&sk_a, &COUNTING, &HASH, id_a, id_b, peer_prekey,
	                                      peer_eph, key, ckey) == FZN_SESSION_ERR_AGREE,
	      "the responder continued past a refused second agreement");

	/* AND THE V1 PATH, whose refusal now leaves through the wipe label
	 * rather than returning past it. Observable only as the code; the wipe
	 * itself is a local and `session.c` says so. */
	agree_calls = 0;
	agree_fail_on = 1;
	memset(key, 0x33, sizeof(key));
	memset(ckey, 0x33, sizeof(ckey));
	CHECK(fzn_session_establish(&sk_a, &COUNTING, &HASH, id_a, id_b, peer_prekey, key,
	                            ckey) == FZN_SESSION_ERR_AGREE,
	      "v1 continued past a refused agreement");

	/*
	 * AND THE HASH SEAM REFUSING MID-ESTABLISHMENT, which was the other
	 * family in that coverage list -- lines 196 and 312, the
	 * `fzn_commitment_derive_root` failures in v1 and in the shared v2
	 * finisher. `REFUSING` existed and was pointed only at
	 * `fzn_session_chains`, so a hash that refuses while a session is
	 * being established had never happened.
	 *
	 * It is the same class as the agreement above and as project.md
	 * sec 75: a consumer's own backend failing. The seam CAN report it --
	 * `fzn_hash_ops.hash` returns an int, unlike `fzn_aead_ops.seal` --
	 * and what this asserts is that the report is not dropped on the way
	 * out. FZN_SESSION_ERR_HASH, distinct from ERR_AGREE, because a
	 * consumer told the wrong one looks in the wrong place.
	 */
	agree_fail_on = 0;
	refusing_calls = 0;
	refusing_fail_on = 1;
	memset(key, 0x33, sizeof(key));
	memset(ckey, 0x33, sizeof(ckey));
	CHECK(fzn_session_establish(&sk_a, &COUNTING, &REFUSING, id_a, id_b, peer_prekey, key,
	                            ckey) == FZN_SESSION_ERR_HASH,
	      "v1 continued past a refusing hash");

	refusing_calls = 0;
	refusing_fail_on = 1;
	memset(key, 0x33, sizeof(key));
	memset(ckey, 0x33, sizeof(ckey));
	CHECK(fzn_session_establish_initiator(&sk_a, &sk_e, &COUNTING, &REFUSING, id_a, id_b,
	                                      peer_prekey, key, ckey) == FZN_SESSION_ERR_HASH,
	      "the v2 initiator continued past a refusing hash");

	refusing_calls = 0;
	refusing_fail_on = 1;
	memset(key, 0x33, sizeof(key));
	memset(ckey, 0x33, sizeof(ckey));
	CHECK(fzn_session_establish_responder(&sk_a, &COUNTING, &REFUSING, id_a, id_b,
	                                      peer_prekey, peer_eph, key, ckey)
	              == FZN_SESSION_ERR_HASH,
	      "the v2 responder continued past a refusing hash");

	/* AND THE CONTROL AGAIN, because every case above asserts a REFUSAL and
	 * a stub that had stopped working would satisfy all of them. */
	refusing_calls = 0;
	refusing_fail_on = 0;
	CHECK(fzn_session_establish(&sk_a, &COUNTING, &REFUSING, id_a, id_b, peer_prekey, key,
	                            ckey) == FZN_SESSION_OK,
	      "the refusing hash refuses even when told not to, so the cases above pass "
	      "for the wrong reason");

	agree_fail_on = 0;
	refusing_fail_on = 0;
	fzn_agree_secret_wipe(&sk_a);
	fzn_agree_secret_wipe(&sk_e);
}

static void test_a_refused_derivation_leaves_no_key_with_the_caller(void)
{
	uint8_t root[FZN_AEAD_KEY_LEN];
	uint8_t id_a[FZN_SESSION_IDENTITY_LEN], id_b[FZN_SESSION_IDENTITY_LEN];
	uint8_t send[FZN_CHAIN_KEY_LEN], recv[FZN_CHAIN_KEY_LEN];
	int all_zero;
	size_t i;

	fill(root, sizeof(root), 0x5b);
	fill(id_a, sizeof(id_a), 0x11);
	fill(id_b, sizeof(id_b), 0x22);

	/* FIRST DERIVATION REFUSES: chain_for wipes the buffer it wrote. */
	refusing_calls = 0;
	refusing_fail_on = 1;
	memset(send, 0x33, sizeof(send));
	memset(recv, 0x33, sizeof(recv));
	CHECK(fzn_session_chains(&REFUSING, root, id_a, id_b, send, recv) ==
	              FZN_SESSION_ERR_HASH,
	      "a refusing hash was reported as success");
	all_zero = 1;
	for (i = 0; i < FZN_CHAIN_KEY_LEN; i++)
		if (send[i] != 0u)
			all_zero = 0;
	CHECK(all_zero, "a refused derivation left a partial chain key with the caller");

	/* SECOND DERIVATION REFUSES: the send chain succeeded and must not be
	 * handed back on its own. A caller holding a send chain and no receive
	 * chain ratchets forward into a conversation it cannot hear. */
	refusing_calls = 0;
	refusing_fail_on = 2;
	memset(send, 0x33, sizeof(send));
	memset(recv, 0x33, sizeof(recv));
	CHECK(fzn_session_chains(&REFUSING, root, id_a, id_b, send, recv) ==
	              FZN_SESSION_ERR_HASH,
	      "a hash refusing on the second chain was reported as success");
	all_zero = 1;
	for (i = 0; i < FZN_CHAIN_KEY_LEN; i++)
		if (send[i] != 0u)
			all_zero = 0;
	CHECK(all_zero, "half a chain pair was left with the caller");

	/* The control: the same fixture with an honest hash produces a real
	 * pair, so neither assertion above is satisfied by a call that never
	 * derives anything. */
	refusing_calls = 0;
	refusing_fail_on = 0;
	memset(send, 0x33, sizeof(send));
	CHECK(fzn_session_chains(&REFUSING, root, id_a, id_b, send, recv) == FZN_SESSION_OK,
	      "the control derivation was refused");
	all_zero = 1;
	for (i = 0; i < FZN_CHAIN_KEY_LEN; i++)
		if (send[i] != 0u)
			all_zero = 0;
	CHECK(!all_zero, "the control produced a zero chain key, so zero proves nothing");
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

/* A REFUSED KEY AGREEMENT MUST STOP SESSION ESTABLISHMENT, at every entry.
 *
 * `session/agree.c` refuses a peer public key whose shared secret is a value
 * the attacker chose -- the low-order / small-subgroup case -- and
 * `agree_test.c` proves the primitive detects it. **Nothing threaded that
 * refusal through session establishment.** `session.c` checks it at five call
 * sites, and until this test every one of them was unexercised: the stub here
 * always succeeded and `real_crypto_test.c` runs a genuine handshake between
 * well-formed keys, which by construction never refuses.
 *
 * WHAT WOULD HAVE BEEN MISSED. `fzn_agree_shared` wipes its output on
 * refusal, so a dropped or inverted check at any of those sites would hash a
 * KNOWN all-zero "shared secret" into the transcript, and an attacker
 * offering a crafted prekey or ephemeral could derive the session key from
 * public information alone. That is the exact attack the refusal exists to
 * stop, and the difference between having the check and having tested it.
 *
 * All three entry points, because they do not share one code path: the base
 * call agrees once, the initiator twice, the responder twice. */
static void test_a_refused_agreement_stops_establishment(void)
{
	fzn_agree_secret_t sk_a, sk_b, eph;
	uint8_t id_a[FZN_SESSION_IDENTITY_LEN], id_b[FZN_SESSION_IDENTITY_LEN];
	uint8_t secret_a[FZN_AGREE_SECRET_LEN], secret_b[FZN_AGREE_SECRET_LEN];
	uint8_t secret_e[FZN_AGREE_SECRET_LEN];
	uint8_t key[FZN_AEAD_KEY_LEN], ck[FZN_COMMITMENT_KEY_LEN];
	uint8_t untouched[FZN_AEAD_KEY_LEN];

	fill(id_a, sizeof(id_a), 0x11);
	fill(id_b, sizeof(id_b), 0x22);
	fill(secret_a, sizeof(secret_a), 0x33);
	fill(secret_b, sizeof(secret_b), 0x44);
	fill(secret_e, sizeof(secret_e), 0x55);
	memset(untouched, 0xA5, sizeof(untouched));

	REQUIRE(fzn_agree_secret_install(&sk_a, &AGREE, secret_a) == FZN_AGREE_OK,
	        "installing A's prekey");
	REQUIRE(fzn_agree_secret_install(&sk_b, &AGREE, secret_b) == FZN_AGREE_OK,
	        "installing B's prekey");
	REQUIRE(fzn_agree_secret_install(&eph, &AGREE, secret_e) == FZN_AGREE_OK,
	        "installing an ephemeral");

	/* THE BASE PATH. */
	memset(key, 0xA5, sizeof(key));
	memset(ck, 0xA5, sizeof(ck));
	CHECK(fzn_session_establish(&sk_a, &DEGENERATE, &HASH, id_a, id_b,
	                            fzn_agree_secret_public(&sk_b), key, ck)
	              == FZN_SESSION_ERR_AGREE,
	      "a refused agreement did not stop fzn_session_establish");
	/* AND NOTHING WAS WRITTEN. Measured rather than assumed: on refusal all
	 * 32 bytes are exactly what the caller left there. That is the right
	 * behaviour and better than wiping -- a wiped buffer looks like a key
	 * and an untouched one looks like whatever the caller had, so a caller
	 * that ignores the return code cannot mistake a refusal for success.
	 * The first draft of this test asserted the buffer was ZEROED, which
	 * `session.h` never promised and the code never does. */
	CHECK(memcmp(key, untouched, sizeof(key)) == 0,
	      "a refused establish wrote into the key buffer");

	/* THE INITIATOR, which agrees twice -- once on the peer's prekey and
	 * once on the ephemeral. Either refusal must stop it. */
	memset(key, 0xA5, sizeof(key));
	CHECK(fzn_session_establish_initiator(&sk_a, &eph, &DEGENERATE, &HASH,
	                                      id_a, id_b,
	                                      fzn_agree_secret_public(&sk_b),
	                                      key, ck) == FZN_SESSION_ERR_AGREE,
	      "a refused agreement did not stop the initiator");
	CHECK(memcmp(key, untouched, sizeof(key)) == 0,
	      "a refused initiator wrote into the key buffer");

	/* THE RESPONDER, which also agrees twice -- the peer's prekey and the
	 * peer's ephemeral. */
	memset(key, 0xA5, sizeof(key));
	CHECK(fzn_session_establish_responder(&sk_a, &DEGENERATE, &HASH,
	                                      id_a, id_b,
	                                      fzn_agree_secret_public(&sk_b),
	                                      fzn_agree_secret_public(&eph),
	                                      key, ck) == FZN_SESSION_ERR_AGREE,
	      "a refused agreement did not stop the responder");
	CHECK(memcmp(key, untouched, sizeof(key)) == 0,
	      "a refused responder wrote into the key buffer");

	/* THE POSITIVE CONTROL, without which every check above is satisfied by
	 * an establish that refuses everything. Same inputs, working seam. */
	memset(key, 0xA5, sizeof(key));
	CHECK(fzn_session_establish(&sk_a, &AGREE, &HASH, id_a, id_b,
	                            fzn_agree_secret_public(&sk_b), key, ck)
	              == FZN_SESSION_OK,
	      "the control: a working agreement still establishes");
	CHECK(memcmp(key, untouched, sizeof(key)) != 0,
	      "the control did not write a key at all");
}

/*
 * EVERY OPERAND OF EVERY GUARD, not the first one of each.
 *
 * The guards are conjunctions and the suite failed the first operand, so
 * `make coverage` reported the rest as never taken both ways while the guard
 * looked tested. sec 88 measured what an unreached operand is worth: the
 * operand after the first is what stands between a partially initialised
 * caller and a null dereference, and a vtable with a null member is what a
 * consumer has who filled it in two steps.
 */
static void test_the_operands_the_first_one_hides(void)
{
	uint8_t id_a[FZN_SESSION_IDENTITY_LEN], id_b[FZN_SESSION_IDENTITY_LEN];
	uint8_t pk_a[FZN_AGREE_PUBLIC_LEN], pk_b[FZN_AGREE_PUBLIC_LEN];
	uint8_t shared[FZN_AGREE_SHARED_LEN];
	uint8_t transcript[FZN_SESSION_TRANSCRIPT_LEN];
	uint8_t key[FZN_AEAD_KEY_LEN];
	uint8_t send_chain[FZN_CHAIN_KEY_LEN], recv_chain[FZN_CHAIN_KEY_LEN];
	fzn_hash_ops_t hollow = { NULL, NULL };

	memset(id_a, 0x51, sizeof(id_a));
	memset(id_b, 0x52, sizeof(id_b));
	memset(pk_a, 0x53, sizeof(pk_a));
	memset(pk_b, 0x54, sizeof(pk_b));
	memset(shared, 0x55, sizeof(shared));
	memset(key, 0x56, sizeof(key));

	/* transcript: six operands, and the suite only ever failed the first. */
	CHECK(fzn_session_transcript(NULL, pk_a, id_b, pk_b, shared, transcript)
	      == FZN_SESSION_ERR_MALFORMED, "transcript accepted a null self identity");
	CHECK(fzn_session_transcript(id_a, NULL, id_b, pk_b, shared, transcript)
	      == FZN_SESSION_ERR_MALFORMED, "transcript accepted a null self prekey");
	CHECK(fzn_session_transcript(id_a, pk_a, NULL, pk_b, shared, transcript)
	      == FZN_SESSION_ERR_MALFORMED, "transcript accepted a null peer identity");
	CHECK(fzn_session_transcript(id_a, pk_a, id_b, NULL, shared, transcript)
	      == FZN_SESSION_ERR_MALFORMED, "transcript accepted a null peer prekey");
	CHECK(fzn_session_transcript(id_a, pk_a, id_b, pk_b, NULL, transcript)
	      == FZN_SESSION_ERR_MALFORMED, "transcript accepted a null shared secret");
	CHECK(fzn_session_transcript(id_a, pk_a, id_b, pk_b, shared, NULL)
	      == FZN_SESSION_ERR_MALFORMED, "transcript accepted a null out");

	/* chains: five operands, then the hash seam, which has two of its own. */
	CHECK(fzn_session_chains(&HASH, NULL, id_a, id_b, send_chain, recv_chain)
	      == FZN_SESSION_ERR_MALFORMED, "chains accepted a null key");
	CHECK(fzn_session_chains(&HASH, key, NULL, id_b, send_chain, recv_chain)
	      == FZN_SESSION_ERR_MALFORMED, "chains accepted a null self identity");
	CHECK(fzn_session_chains(&HASH, key, id_a, NULL, send_chain, recv_chain)
	      == FZN_SESSION_ERR_MALFORMED, "chains accepted a null peer identity");
	CHECK(fzn_session_chains(&HASH, key, id_a, id_b, NULL, recv_chain)
	      == FZN_SESSION_ERR_MALFORMED, "chains accepted a null send chain out");
	CHECK(fzn_session_chains(&HASH, key, id_a, id_b, send_chain, NULL)
	      == FZN_SESSION_ERR_MALFORMED, "chains accepted a null recv chain out");
	CHECK(fzn_session_chains(NULL, key, id_a, id_b, send_chain, recv_chain)
	      == FZN_SESSION_ERR_HASH, "chains accepted a null hash");
	CHECK(fzn_session_chains(&hollow, key, id_a, id_b, send_chain, recv_chain)
	      == FZN_SESSION_ERR_HASH, "chains accepted a hash struct whose member is null");
}

/*
 * EVERY OPERAND OF EVERY GUARD, not the first one of each. sec 88 measured
 * what an unreached operand is worth: the operand after the first is what
 * stands between a partially initialised caller and a null dereference.
 */
static void test_the_establish_operands(void)
{
	uint8_t id_a[FZN_SESSION_IDENTITY_LEN], id_b[FZN_SESSION_IDENTITY_LEN];
	uint8_t pk_b[FZN_AGREE_PUBLIC_LEN], eph_b[FZN_AGREE_PUBLIC_LEN];
	uint8_t key[FZN_AEAD_KEY_LEN], ckey[FZN_COMMITMENT_KEY_LEN];
	fzn_agree_secret_t sk, eph;
	uint8_t raw[FZN_AGREE_SECRET_LEN];

	memset(id_a, 0xB1, sizeof(id_a));
	memset(id_b, 0xB2, sizeof(id_b));
	memset(pk_b, 0xB3, sizeof(pk_b));
	memset(eph_b, 0xB4, sizeof(eph_b));
	memset(raw, 0xB5, sizeof(raw));
	REQUIRE(fzn_agree_secret_install(&sk, &AGREE, raw) == FZN_AGREE_OK, "install refused");
	REQUIRE(fzn_agree_secret_install(&eph, &AGREE, raw) == FZN_AGREE_OK, "install refused");

	/* establish: six operands after the seams. */
	CHECK(fzn_session_establish(NULL, &AGREE, &HASH, id_a, id_b, pk_b, key, ckey)
	      == FZN_SESSION_ERR_MALFORMED, "establish accepted a null self prekey");
	CHECK(fzn_session_establish(&sk, &AGREE, &HASH, NULL, id_b, pk_b, key, ckey)
	      == FZN_SESSION_ERR_MALFORMED, "establish accepted a null self identity");
	CHECK(fzn_session_establish(&sk, &AGREE, &HASH, id_a, NULL, pk_b, key, ckey)
	      == FZN_SESSION_ERR_MALFORMED, "establish accepted a null peer identity");
	CHECK(fzn_session_establish(&sk, &AGREE, &HASH, id_a, id_b, NULL, key, ckey)
	      == FZN_SESSION_ERR_MALFORMED, "establish accepted a null peer prekey");
	CHECK(fzn_session_establish(&sk, &AGREE, &HASH, id_a, id_b, pk_b, NULL, ckey)
	      == FZN_SESSION_ERR_MALFORMED, "establish accepted a null key out");
	CHECK(fzn_session_establish(&sk, &AGREE, &HASH, id_a, id_b, pk_b, key, NULL)
	      == FZN_SESSION_ERR_MALFORMED, "establish accepted a null commitment key out");

	/* initiator: the same, with the ephemeral operand between them. */
	CHECK(fzn_session_establish_initiator(NULL, &eph, &AGREE, &HASH, id_a, id_b, pk_b, key,
	                                      ckey) == FZN_SESSION_ERR_MALFORMED,
	      "initiator accepted a null self prekey");
	CHECK(fzn_session_establish_initiator(&sk, NULL, &AGREE, &HASH, id_a, id_b, pk_b, key,
	                                      ckey) == FZN_SESSION_ERR_MALFORMED,
	      "initiator accepted a null ephemeral");
	CHECK(fzn_session_establish_initiator(&sk, &eph, &AGREE, &HASH, NULL, id_b, pk_b, key,
	                                      ckey) == FZN_SESSION_ERR_MALFORMED,
	      "initiator accepted a null self identity");
	CHECK(fzn_session_establish_initiator(&sk, &eph, &AGREE, &HASH, id_a, NULL, pk_b, key,
	                                      ckey) == FZN_SESSION_ERR_MALFORMED,
	      "initiator accepted a null peer identity");
	CHECK(fzn_session_establish_initiator(&sk, &eph, &AGREE, &HASH, id_a, id_b, NULL, key,
	                                      ckey) == FZN_SESSION_ERR_MALFORMED,
	      "initiator accepted a null peer prekey");
	CHECK(fzn_session_establish_initiator(&sk, &eph, &AGREE, &HASH, id_a, id_b, pk_b, NULL,
	                                      ckey) == FZN_SESSION_ERR_MALFORMED,
	      "initiator accepted a null key out");
	CHECK(fzn_session_establish_initiator(&sk, &eph, &AGREE, &HASH, id_a, id_b, pk_b, key,
	                                      NULL) == FZN_SESSION_ERR_MALFORMED,
	      "initiator accepted a null commitment key out");

	/* responder: peer_ephemeral is the operand the initiator does not have. */
	CHECK(fzn_session_establish_responder(NULL, &AGREE, &HASH, id_a, id_b, pk_b, eph_b, key,
	                                      ckey) == FZN_SESSION_ERR_MALFORMED,
	      "responder accepted a null self prekey");
	CHECK(fzn_session_establish_responder(&sk, &AGREE, &HASH, NULL, id_b, pk_b, eph_b, key,
	                                      ckey) == FZN_SESSION_ERR_MALFORMED,
	      "responder accepted a null self identity");
	CHECK(fzn_session_establish_responder(&sk, &AGREE, &HASH, id_a, NULL, pk_b, eph_b, key,
	                                      ckey) == FZN_SESSION_ERR_MALFORMED,
	      "responder accepted a null peer identity");
	CHECK(fzn_session_establish_responder(&sk, &AGREE, &HASH, id_a, id_b, NULL, eph_b, key,
	                                      ckey) == FZN_SESSION_ERR_MALFORMED,
	      "responder accepted a null peer prekey");
	CHECK(fzn_session_establish_responder(&sk, &AGREE, &HASH, id_a, id_b, pk_b, NULL, key,
	                                      ckey) == FZN_SESSION_ERR_MALFORMED,
	      "responder accepted a null peer ephemeral");
	CHECK(fzn_session_establish_responder(&sk, &AGREE, &HASH, id_a, id_b, pk_b, eph_b, NULL,
	                                      ckey) == FZN_SESSION_ERR_MALFORMED,
	      "responder accepted a null key out");
	CHECK(fzn_session_establish_responder(&sk, &AGREE, &HASH, id_a, id_b, pk_b, eph_b, key,
	                                      NULL) == FZN_SESSION_ERR_MALFORMED,
	      "responder accepted a null commitment key out");
}

int main(void)
{
	test_both_sides_build_the_same_transcript();
	test_a_prekey_is_not_interchangeable_with_the_others();
	test_every_input_reaches_the_transcript();
	test_a_session_with_yourself_is_refused();
	test_a_refused_agreement_stops_establishment();
	test_two_hosts_establish_the_same_root();
	test_a_rotation_changes_the_root();
	test_the_two_directions_are_different_and_agree();
	test_the_seeds_drive_a_ratchet();
	test_the_ephemeral_exchange_agrees_and_differs();
	test_a_refused_derivation_leaves_no_key_with_the_caller();
	test_the_second_agreement_can_refuse_too();
	test_every_guard_refuses_its_own_argument();
	test_the_suite_can_tell_pass_from_fail();

	test_the_operands_the_first_one_hides();

	test_the_establish_operands();

	printf("session_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
