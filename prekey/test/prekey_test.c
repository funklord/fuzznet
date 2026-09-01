/* Tests for prekey/prekey.c: the record, and the act of pinning one.
 *
 * THE SIGNER DEPENDS ON WHO SIGNS AS WELL AS ON WHAT, which is the property
 * this suite would be worthless without. A stub that returned the same bytes
 * for every key would make "verified under the host the record names" a claim
 * with no observable content -- and that is exactly the defect this
 * workspace's revocation harness was found to have, where every record
 * pointed at one shared literal.
 */

#include "../prekey.h"

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
	fprintf(stderr, "  FAIL prekey_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

/*
 * A check that ALSO ABANDONS THE CASE when it fails, for the one thing a
 * plain CHECK handles badly: a fixture that did not build.
 *
 * FOUND BY A MUTATION THAT SEGFAULTED INSTEAD OF FAILING. Shortening the
 * signed range so the signature covered 66 bytes instead of 74 made every
 * `build` fail -- which the suite reported, correctly, and then carried on
 * and dereferenced the uninitialised record it had just been told about.
 * A crash IS a failure, but it stops the run, names nothing, and buries the
 * one line that said what was actually wrong.
 *
 * The condition is evaluated ONCE, into a local. Writing this as
 * `CHECK(cond); if (!(cond)) return;` would build the fixture twice, which
 * is the sort of macro that works until the expression has an effect.
 */
#define REQUIRE(cond, ...)                                    \
	do {                                                  \
		int require_ok = (cond) ? 1 : 0;              \
		check_at(require_ok, __LINE__, __VA_ARGS__);  \
		if (!require_ok)                              \
			return;                               \
	} while (0)

/* Identity is the key's first byte; every key here carries its seed there. */
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

/* Whose key the signer holds. Set per case, because a record signed by the
 * wrong host is the case that matters most and cannot be built otherwise. */
static uint8_t signing_as;

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
	/* KEYED ON THE PUBLIC KEY'S FIRST BYTE, so a signature made by one
	 * host does not verify under another. Without that, "the record
	 * verifies under the host it names" is unfalsifiable. */
	mac(want, pubkey[0], msg, msg_len);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

static int refuse_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	(void)ctx;
	(void)sig;
	(void)msg;
	(void)msg_len;
	return 0;
}

static const fzn_sign_ops_t OPS = { stub_verify, stub_sign, NULL };
static const fzn_sign_ops_t REFUSER = { stub_verify, refuse_sign, NULL };

static void expand(uint8_t out[FZN_PUBKEY_LEN], uint8_t seed)
{
	size_t i;

	/* The seed in the FIRST byte, because that is what the stub verifier
	 * keys on, and spread through the rest so that two identities differ
	 * everywhere rather than in one place. */
	for (i = 0; i < FZN_PUBKEY_LEN; i++)
		out[i] = (uint8_t)(seed + (i * 7u));
}

struct fixture {
	uint8_t host[FZN_PUBKEY_LEN];
	uint8_t prekey[FZN_PREKEY_LEN];
	uint8_t bytes[FZN_PREKEY_LEN_TOTAL];
	fzn_prekey_record_t record;
};

static int build(struct fixture *f, uint8_t host_seed, uint8_t prekey_seed, uint64_t created_at)
{
	expand(f->host, host_seed);
	expand(f->prekey, prekey_seed);
	signing_as = host_seed;
	if (fzn_prekey_issue(f->host, f->prekey, created_at, &OPS, f->bytes) != FZN_PREKEY_OK)
		return 0;
	return fzn_prekey_open(f->bytes, sizeof(f->bytes), &f->record) == FZN_PREKEY_OK;
}

/* ---- the cases -------------------------------------------------------- */

static void test_the_layout_is_what_the_header_says(void)
{
	struct fixture f;

	REQUIRE(build(&f, 0x11, 0x22, 1000u), "the fixture does not build");
	CHECK(f.bytes[FZN_PREKEY_OFF_VERSION] == 1u, "version byte is %u, wanted 1",
	      f.bytes[FZN_PREKEY_OFF_VERSION]);
	/* The literal, not the enum: a test that reads the constant agrees
	 * with the encoder by construction and would not notice a renumber.
	 * 132 is the value in the library half of wire/bytes.h's registry. */
	CHECK(f.bytes[FZN_PREKEY_OFF_OBJECT] == 132u, "object byte is %u, wanted 132",
	      f.bytes[FZN_PREKEY_OFF_OBJECT]);
	CHECK(memcmp(f.record.host, f.host, FZN_PUBKEY_LEN) == 0, "the host did not survive");
	CHECK(memcmp(f.record.prekey, f.prekey, FZN_PREKEY_LEN) == 0,
	      "the prekey did not survive");
	CHECK(f.record.created_at == 1000u, "created_at is %llu, wanted 1000",
	      (unsigned long long)f.record.created_at);
	CHECK(fzn_prekey_verify(f.record, &OPS) == FZN_PREKEY_OK, "a fresh record does not "
	      "verify, so every refusal below proves nothing");
}

static void test_every_signed_byte_is_signed(void)
{
	struct fixture f;
	size_t i;

	REQUIRE(build(&f, 0x31, 0x41, 2000u), "the fixture does not build");

	/* EVERY BYTE OF THE BODY, one at a time. A signature over a prefix --
	 * or over a range that stopped before `created_at` -- would pass a
	 * test that bent only the host key, and the timestamp is precisely
	 * the field a rollback attack wants outside the signature. */
	for (i = 0; i < FZN_PREKEY_BODY_LEN; i++) {
		f.bytes[i] = (uint8_t)(f.bytes[i] ^ 0x01u);
		CHECK(fzn_prekey_verify(f.record, &OPS) != FZN_PREKEY_OK,
		      "byte %zu of the body is outside the signature", i);
		f.bytes[i] = (uint8_t)(f.bytes[i] ^ 0x01u);
	}
	CHECK(fzn_prekey_verify(f.record, &OPS) == FZN_PREKEY_OK,
	      "putting the bytes back did not restore the control");
}

static void test_a_record_signed_by_another_host_is_refused(void)
{
	struct fixture f;

	/* The record names host 0x51 and is signed by 0x99. Nothing about the
	 * bytes is malformed; only the key is wrong. */
	expand(f.host, 0x51);
	expand(f.prekey, 0x52);
	signing_as = 0x99;
	REQUIRE(fzn_prekey_issue(f.host, f.prekey, 3000u, &OPS, f.bytes) == FZN_PREKEY_OK,
	        "issuing refused");
	REQUIRE(fzn_prekey_open(f.bytes, sizeof(f.bytes), &f.record) == FZN_PREKEY_OK,
	        "the shape is fine and should open");
	CHECK(fzn_prekey_verify(f.record, &OPS) == FZN_PREKEY_ERR_SIGNATURE,
	      "a record signed by a key other than the host it names verified");
}

static void test_open_refuses_what_is_not_our_shape(void)
{
	struct fixture f;
	fzn_prekey_record_t rec;

	REQUIRE(build(&f, 0x61, 0x62, 4000u), "the fixture does not build");

	CHECK(fzn_prekey_open(f.bytes, FZN_PREKEY_LEN_TOTAL - 1u, &rec) == FZN_PREKEY_ERR_SHAPE,
	      "a record one byte short opened");
	CHECK(fzn_prekey_open(f.bytes, FZN_PREKEY_LEN_TOTAL + 1u, &rec) == FZN_PREKEY_ERR_SHAPE,
	      "a record with a trailing byte opened, so the length is not exact");
	CHECK(fzn_prekey_open(f.bytes, 0, &rec) == FZN_PREKEY_ERR_SHAPE, "an empty record opened");

	f.bytes[FZN_PREKEY_OFF_VERSION] = 2u;
	CHECK(fzn_prekey_open(f.bytes, sizeof(f.bytes), &rec) == FZN_PREKEY_ERR_SHAPE,
	      "a record claiming version 2 opened");
	f.bytes[FZN_PREKEY_OFF_VERSION] = 1u;

	/* THE OBJECT TAG EARNING ITS PLACE, and this record needs it more
	 * than most: it is self-signed, so its signer and its subject are the
	 * same key, and without the tag it is separated from anything else
	 * that key signs by nothing but its length. */
	f.bytes[FZN_PREKEY_OFF_OBJECT] = 130u; /* FZN_OBJECT_RECORD */
	CHECK(fzn_prekey_open(f.bytes, sizeof(f.bytes), &rec) == FZN_PREKEY_ERR_SHAPE,
	      "a prekey record tagged as a journal record opened as a prekey");
	f.bytes[FZN_PREKEY_OFF_OBJECT] = 132u;
	CHECK(fzn_prekey_open(f.bytes, sizeof(f.bytes), &rec) == FZN_PREKEY_OK,
	      "putting the tag back did not restore the control");
}

/* INIT IS TOTAL: the peer it produces does not depend on what the memory
 * held.
 *
 * `fzn_prekey_peer_init` zeroes the whole struct and then calls
 * `fzn_trust_init` on the trust half. The zeroing therefore contributes
 * exactly `prekey` and `created_at` -- and both are written before they are
 * read on every path through `fzn_prekey_pin`, so removing it leaves all 63
 * binaries green. It was measured that way before this test was written.
 *
 * That makes it defence in depth, and the reason to hold it to account
 * rather than delete it is what it defends: the "written before read"
 * argument above is a property of TODAY's `fzn_trust_t` and of
 * `fzn_trust_init` covering all of it. A field added to either that init
 * does not set would be caught by this zeroing and by nothing else, and
 * would surface as a peer that inherits a stale `created_at` -- which
 * `fzn_prekey_pin` reads as a rollback and refuses, so a legitimate
 * rotation would be dropped on a peer whose memory happened to be dirty.
 *
 * project.md sec 11 records the same shape in reassembly's `admit_first`,
 * where `release` already did the clearing: a guard that is correct, that
 * nothing holds to account, and that a later change quietly makes
 * load-bearing.
 *
 * The comparison is against a peer initialised from ZEROED memory, which is
 * the reference every caller of a `_init` believes it is getting. Asserting
 * the whole struct rather than the two fields is deliberate: naming them
 * would go stale the moment one is added, which is the failure this is
 * defending against in the first place. */
static void test_init_does_not_depend_on_what_the_memory_held(void)
{
	fzn_prekey_peer_t dirty, clean;

	memset(&dirty, 0xab, sizeof(dirty));
	memset(&clean, 0, sizeof(clean));

	fzn_prekey_peer_init(&dirty);
	fzn_prekey_peer_init(&clean);

	/* The control: 0xab must actually differ from what init writes, or an
	 * agreement below would be agreement between two copies of nothing. */
	CHECK(sizeof(dirty) > 0 && ((const unsigned char *)&clean)[0] != 0xab,
	      "the dirty pattern is what init writes, so this test cannot fail");
	CHECK(memcmp(&dirty, &clean, sizeof(dirty)) == 0,
	      "init left the caller's bytes behind, so a peer's state depends on "
	      "what its memory happened to hold");
}

static void test_first_use_pins_and_records_how(void)
{
	struct fixture f;
	fzn_prekey_peer_t peer;

	REQUIRE(build(&f, 0x71, 0x72, 5000u), "the fixture does not build");

	fzn_prekey_peer_init(&peer);
	CHECK(fzn_trust_root(&peer.trust) == NULL, "a fresh peer already has an anchor");
	REQUIRE(fzn_prekey_pin(&peer, f.record, &OPS, FZN_TRUST_ADOPTED, 111u) == FZN_PREKEY_OK,
	        "first use refused");
	REQUIRE(fzn_trust_root(&peer.trust) != NULL, "first use left no anchor");
	CHECK(memcmp(fzn_trust_root(&peer.trust), f.host, FZN_PUBKEY_LEN) == 0,
	      "the anchor is not the host the record named");
	CHECK(memcmp(peer.prekey, f.prekey, FZN_PREKEY_LEN) == 0, "the prekey was not kept");
	CHECK(peer.created_at == 5000u, "the timestamp was not kept");

	/* HOW IT ARRIVED IS KEPT, because it is what a consumer shows a user
	 * who asks why this peer is trusted -- trust/trust.h's whole reason
	 * for having a source at all. */
	CHECK(fzn_trust_source_of(&peer.trust) == FZN_TRUST_ADOPTED,
	      "an adopted anchor does not say it was adopted");

	fzn_prekey_peer_init(&peer);
	CHECK(fzn_prekey_pin(&peer, f.record, &OPS, FZN_TRUST_PINNED, 111u) == FZN_PREKEY_OK,
	      "an out-of-band pin refused");
	CHECK(fzn_trust_source_of(&peer.trust) == FZN_TRUST_PINNED,
	      "a confirmed anchor does not say it was confirmed");
}

/* A HOST THAT CAME BACK WITH ITS CLOCK BEHIND, which is the shattered-estate
 * case in project.md sec 46 and is NOT a defect in the rule above.
 *
 * The rollback rule is `record.created_at <= peer->created_at`, and it is
 * right: a replayed older record whose prekey has since leaked is the whole
 * attack, and a signature cannot catch it because nothing about the bytes is
 * wrong. What this case adds is the consequence when the host is honest.
 *
 * Hardware that is gone for a long time can come back with a clock that lost
 * time -- a dead RTC cell, a first boot before any time source is reachable.
 * It then issues a GENUINE prekey, with NEW key material, correctly signed,
 * carrying a `created_at` earlier than the one its peers already hold. Every
 * peer refuses it, and goes on offering the OLD prekey, which is the one the
 * returning host may no longer hold the secret for.
 *
 * THE HOST CANNOT SEE THIS. The refusal happens at each peer; from the
 * returning side the network is simply quiet. And it cannot compute a safe
 * floor from its own stored state either: `persist/` keeps the agreement
 * secret with a GENERATION COUNTER, while the record carries a TIMESTAMP, and
 * nothing links the two. That asymmetry is recorded in sec 46 -- it is the
 * strongest argument there for the healing story needing a step that asks a
 * person, since no automated recovery inside this library has the number it
 * would need.
 *
 * PINNED HERE so the consequence is exhibited rather than discovered, in the
 * spirit of `scenario_revocation_split`: this test passing means the library
 * still behaves this way, not that the behaviour is desirable. */
static void test_a_returning_host_with_a_clock_behind_cannot_rotate(void)
{
	struct fixture original, returned;
	fzn_prekey_peer_t peer;

	REQUIRE(build(&original, 0x41, 0x42, 5000u), "the fixture does not build");
	fzn_prekey_peer_init(&peer);
	REQUIRE(fzn_prekey_pin(&peer, original.record, &OPS, FZN_TRUST_ADOPTED, 1u)
	                == FZN_PREKEY_OK, "first use refused");

	/* Away for a long time. It returns with a clock reading earlier than
	 * when it last published, and rotates to key material it has never
	 * used before -- everything an honest host should do. */
	REQUIRE(build(&returned, 0x41, 0x99, 900u), "the fixture does not build");
	CHECK(memcmp(returned.prekey, original.prekey, FZN_PREKEY_LEN) != 0,
	      "the returning host offered the same prekey, so this tests nothing");

	CHECK(fzn_prekey_pin(&peer, returned.record, &OPS, FZN_TRUST_ADOPTED, 9000u)
	              == FZN_PREKEY_ERR_ROLLBACK,
	      "a genuine rotation from a host whose clock went backwards was accepted");

	/* AND THE PEER IS LEFT ON THE OLD KEY, which is the part that bites:
	 * the returning host is not merely un-rotated, it is unreachable at
	 * the only prekey anyone will use for it. */
	CHECK(memcmp(peer.prekey, original.prekey, FZN_PREKEY_LEN) == 0,
	      "the refused rotation moved the pin anyway");
	CHECK(peer.created_at == 5000u, "the refused rotation moved the timestamp");

	/* THE RECEIVER'S OWN CLOCK IS NOT WHAT DECIDES IT. 9000 was passed as
	 * `now` above, far ahead of both records, and the refusal is unchanged
	 * -- prekey.c says the comparison orders two statements by one key
	 * rather than gating on a clock, and this is that claim exercised. */
	CHECK(fzn_prekey_pin(&peer, returned.record, &OPS, FZN_TRUST_ADOPTED, 1u)
	              == FZN_PREKEY_ERR_ROLLBACK,
	      "the receiver's own clock changed the verdict");
}

static void test_a_rotation_is_accepted_and_a_rollback_is_not(void)
{
	struct fixture first, newer, older, same;
	fzn_prekey_peer_t peer;

	REQUIRE(build(&first, 0x81, 0x82, 6000u), "the fixture does not build");
	fzn_prekey_peer_init(&peer);
	REQUIRE(fzn_prekey_pin(&peer, first.record, &OPS, FZN_TRUST_ADOPTED, 1u)
	                == FZN_PREKEY_OK, "first use refused");

	/* A RE-DELIVERY IS NOT AN EVENT. The same record arriving twice is
	 * ordinary and must not have to satisfy a monotonicity rule. */
	REQUIRE(build(&same, 0x81, 0x82, 6000u), "the fixture does not build");
	CHECK(fzn_prekey_pin(&peer, same.record, &OPS, FZN_TRUST_ADOPTED, 2u) == FZN_PREKEY_OK,
	      "a re-delivery of the record already held was refused");

	/* A ROTATION: the same host, a new prekey, a newer timestamp. */
	REQUIRE(build(&newer, 0x81, 0x92, 7000u), "the fixture does not build");
	CHECK(fzn_prekey_pin(&peer, newer.record, &OPS, FZN_TRUST_ADOPTED, 3u) == FZN_PREKEY_OK,
	      "a legitimate rotation was refused");
	CHECK(memcmp(peer.prekey, newer.prekey, FZN_PREKEY_LEN) == 0,
	      "the rotation did not take");
	CHECK(peer.created_at == 7000u, "the rotation did not move the timestamp");

	/* THE ROLLBACK. `older` is a REAL record, correctly signed by the
	 * host, that the host has moved on from -- replayed by anyone who saw
	 * it. Nothing about the bytes is wrong, which is why the signature
	 * cannot catch it. If that prekey has since leaked, accepting it is
	 * the whole attack. */
	REQUIRE(build(&older, 0x81, 0x82, 6000u), "the fixture does not build");
	CHECK(fzn_prekey_verify(older.record, &OPS) == FZN_PREKEY_OK,
	      "the replayed record does not verify, so this case is testing the signature "
	      "rather than the rollback rule");
	CHECK(fzn_prekey_pin(&peer, older.record, &OPS, FZN_TRUST_ADOPTED, 4u)
	              == FZN_PREKEY_ERR_ROLLBACK,
	      "an older, genuine, correctly signed prekey was accepted over a newer one");
	CHECK(memcmp(peer.prekey, newer.prekey, FZN_PREKEY_LEN) == 0,
	      "the refused rollback moved the stored prekey anyway");
	CHECK(peer.created_at == 7000u, "the refused rollback moved the timestamp");

	/* AND EQUAL TIMESTAMPS WITH A DIFFERENT KEY ARE A ROLLBACK TOO. Two
	 * different prekeys claiming one instant is not a rotation anybody
	 * can order, so the safe answer is to keep what is held. */
	{
		struct fixture tie;

		REQUIRE(build(&tie, 0x81, 0xa2, 7000u), "the fixture does not build");
		CHECK(fzn_prekey_pin(&peer, tie.record, &OPS, FZN_TRUST_ADOPTED, 5u)
		              == FZN_PREKEY_ERR_ROLLBACK,
		      "a second prekey claiming the same instant replaced the stored one");
	}
}

static void test_a_rotation_does_not_launder_provenance(void)
{
	struct fixture first, newer;
	fzn_prekey_peer_t peer;

	REQUIRE(build(&first, 0xb1, 0xb2, 8000u), "the fixture does not build");
	fzn_prekey_peer_init(&peer);
	REQUIRE(fzn_prekey_pin(&peer, first.record, &OPS, FZN_TRUST_ADOPTED, 1u)
	                == FZN_PREKEY_OK, "first use refused");

	/* A ROTATION IS NOT A NEW FIRST USE. If it could raise ADOPTED to
	 * PINNED, a peer would be able to launder its own provenance by
	 * rotating -- and the consumer would afterwards tell a user "you
	 * verified this key" about a key nobody ever checked. */
	REQUIRE(build(&newer, 0xb1, 0xc2, 9000u), "the fixture does not build");
	CHECK(fzn_prekey_pin(&peer, newer.record, &OPS, FZN_TRUST_PINNED, 2u) == FZN_PREKEY_OK,
	      "the rotation refused");
	CHECK(fzn_trust_source_of(&peer.trust) == FZN_TRUST_ADOPTED,
	      "a rotation upgraded an adopted anchor to a confirmed one, so a peer can "
	      "launder its own provenance");
}

static void test_a_different_host_is_a_different_peer(void)
{
	struct fixture first, other;
	fzn_prekey_peer_t peer;

	REQUIRE(build(&first, 0xd1, 0xd2, 10000u), "the fixture does not build");
	fzn_prekey_peer_init(&peer);
	REQUIRE(fzn_prekey_pin(&peer, first.record, &OPS, FZN_TRUST_ADOPTED, 1u)
	                == FZN_PREKEY_OK, "first use refused");

	REQUIRE(build(&other, 0xe1, 0xe2, 11000u), "the fixture does not build");
	CHECK(fzn_prekey_pin(&peer, other.record, &OPS, FZN_TRUST_ADOPTED, 2u)
	              == FZN_PREKEY_ERR_WRONG_HOST,
	      "a record from a different host was accepted into a pinned peer");
	REQUIRE(fzn_trust_root(&peer.trust) != NULL, "the refused record cleared the anchor");
	CHECK(memcmp(fzn_trust_root(&peer.trust), first.host, FZN_PUBKEY_LEN) == 0,
	      "the refused record moved the anchor");
	CHECK(memcmp(peer.prekey, first.prekey, FZN_PREKEY_LEN) == 0,
	      "the refused record moved the prekey");
}

static void test_pinning_verifies_before_it_compares(void)
{
	struct fixture first, forged;
	fzn_prekey_peer_t peer;

	REQUIRE(build(&first, 0xf1, 0xf2, 12000u), "the fixture does not build");
	fzn_prekey_peer_init(&peer);
	REQUIRE(fzn_prekey_pin(&peer, first.record, &OPS, FZN_TRUST_ADOPTED, 1u)
	                == FZN_PREKEY_OK, "first use refused");

	/* A record naming the pinned host, with a newer timestamp and a new
	 * prekey -- everything a rotation needs except a valid signature. It
	 * must be refused as a SIGNATURE failure, not as a rotation, and it
	 * must not move anything. Verifying after comparing would reason
	 * about a stranger's bytes as though they were the peer's. */
	expand(forged.host, 0xf1);
	expand(forged.prekey, 0x03);
	signing_as = 0x02; /* not the host */
	REQUIRE(fzn_prekey_issue(forged.host, forged.prekey, 13000u, &OPS, forged.bytes)
	                == FZN_PREKEY_OK, "issuing refused");
	REQUIRE(fzn_prekey_open(forged.bytes, sizeof(forged.bytes), &forged.record)
	                == FZN_PREKEY_OK, "the shape is fine and should open");
	CHECK(fzn_prekey_pin(&peer, forged.record, &OPS, FZN_TRUST_ADOPTED, 2u)
	              == FZN_PREKEY_ERR_SIGNATURE,
	      "an unsigned rotation was accepted, or refused for the wrong reason");
	CHECK(memcmp(peer.prekey, first.prekey, FZN_PREKEY_LEN) == 0,
	      "an unverified record moved the stored prekey");
}

static void test_every_guard_refuses_its_own_argument(void)
{
	struct fixture f;
	fzn_prekey_peer_t peer;
	fzn_prekey_record_t rec;
	uint8_t out[FZN_PREKEY_LEN_TOTAL];

	REQUIRE(build(&f, 0x21, 0x23, 14000u), "the fixture does not build");
	fzn_prekey_peer_init(&peer);
	memset(&rec, 0, sizeof(rec));

	CHECK(fzn_prekey_issue(NULL, f.prekey, 0, &OPS, out) == FZN_PREKEY_ERR_MALFORMED,
	      "null host");
	CHECK(fzn_prekey_issue(f.host, NULL, 0, &OPS, out) == FZN_PREKEY_ERR_MALFORMED,
	      "null prekey");
	CHECK(fzn_prekey_issue(f.host, f.prekey, 0, &OPS, NULL) == FZN_PREKEY_ERR_MALFORMED,
	      "null out");
	CHECK(fzn_prekey_issue(f.host, f.prekey, 0, NULL, out) == FZN_PREKEY_ERR_SIGNER,
	      "null signer");
	CHECK(fzn_prekey_issue(f.host, f.prekey, 0, &REFUSER, out) == FZN_PREKEY_ERR_SIGNER,
	      "a refusing signer was not carried out");

	CHECK(fzn_prekey_open(NULL, FZN_PREKEY_LEN_TOTAL, &rec) == FZN_PREKEY_ERR_MALFORMED,
	      "null bytes");
	CHECK(fzn_prekey_open(f.bytes, sizeof(f.bytes), NULL) == FZN_PREKEY_ERR_MALFORMED,
	      "null out");

	CHECK(fzn_prekey_verify(rec, &OPS) == FZN_PREKEY_ERR_MALFORMED, "an empty record");
	CHECK(fzn_prekey_verify(f.record, NULL) == FZN_PREKEY_ERR_SIGNER, "null verifier");

	CHECK(fzn_prekey_pin(NULL, f.record, &OPS, FZN_TRUST_ADOPTED, 0) ==
	              FZN_PREKEY_ERR_MALFORMED, "null peer");
	CHECK(fzn_prekey_pin(&peer, rec, &OPS, FZN_TRUST_ADOPTED, 0) == FZN_PREKEY_ERR_MALFORMED,
	      "an empty record");
	/* FZN_TRUST_NONE is not a way to arrive; a caller that passes it has
	 * not decided, and this is not the place to decide for them. */
	CHECK(fzn_prekey_pin(&peer, f.record, &OPS, FZN_TRUST_NONE, 0) ==
	              FZN_PREKEY_ERR_MALFORMED, "a source of NONE");

	fzn_prekey_peer_init(NULL);

	CHECK(strcmp(fzn_prekey_err_str(FZN_PREKEY_OK), "ok") == 0, "ok does not render");
	CHECK(strcmp(fzn_prekey_err_str((fzn_prekey_err_t)88), "unknown") == 0,
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
	test_the_layout_is_what_the_header_says();
	test_every_signed_byte_is_signed();
	test_a_record_signed_by_another_host_is_refused();
	test_open_refuses_what_is_not_our_shape();
	test_init_does_not_depend_on_what_the_memory_held();
	test_first_use_pins_and_records_how();
	test_a_rotation_is_accepted_and_a_rollback_is_not();
	test_a_returning_host_with_a_clock_behind_cannot_rotate();
	test_a_rotation_does_not_launder_provenance();
	test_a_different_host_is_a_different_peer();
	test_pinning_verifies_before_it_compares();
	test_every_guard_refuses_its_own_argument();
	test_the_suite_can_tell_pass_from_fail();

	printf("prekey_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
