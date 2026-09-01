/*
 * TWO HOSTS HOLDING A CONVERSATION UNDER ALL FOUR REAL PRIMITIVES.
 *
 * Built only with the Monocypher bindings, like its four siblings -- and it
 * exists because those four are the reason it was missing. Each of them
 * proves ONE binding against its primitive: Ed25519 signs and checks,
 * BLAKE2b hashes, ChaCha20-Poly1305 seals and refuses, X25519 agrees. None
 * of them calls a single composition function in this library, and
 * `sim/test/network_test.c`, which calls all of them, runs entirely on
 * stubs. So the claim "a real host can complete a conversation" was held by
 * nothing, and this file holds it: prekey to session to chains to ratchet
 * to a sealed frame, on real keys, in one binary.
 *
 * WHAT IT DOES NOT DO, MEASURED, AND THE FIRST DRAFT OF THIS COMMENT SAID
 * OTHERWISE.
 *
 * It was written for a hazard one constant wide. `fzn_commitment_derive_root`
 * asks the hash seam for FZN_DERIVED_LEN bytes in one call; that is 64 today
 * and 64 is BLAKE2b's MAXIMUM, so `mono_hash` refuses anything larger while
 * the FNV stub will produce any length asked for, for ever. Grow the constant
 * and no real host can establish a session.
 *
 * That story was checked rather than told, by growing it -- and
 * `session/test/commitment_test.c:165` failed with Monocypher switched OFF.
 * The stub there is not a passive fake: it COUNTS WHAT IT WAS ASKED FOR and
 * asserts on the number. The hazard was already held, by a better instrument
 * than this file.
 *
 * The search was then widened rather than dropped, and it came back empty:
 * across five mutations -- the agreement binding's arguments swapped, the
 * hash binding's length cap raised, the derived length grown, a chain seed
 * asking for 65 bytes and one asking for zero -- NOT ONE is caught here and
 * missed by the rest of the suite. Each fell to the binding's own test, to
 * a stub that counts, or to the sanitizers. So this file currently has NO
 * unique catch, and anybody citing it as coverage should cite one of those
 * instead.
 *
 * WHY IT IS KEPT ANYWAY, stated as a judgement rather than as evidence. It
 * is a positive control for the COMPOSITION, which is the argument
 * `chain/test/sign_monocypher_test.c` already makes for a single seam -- a
 * seam that has only ever had a fake behind it is a seam nobody has checked
 * -- applied to the chain of seams rather than to one. The mismatch it would
 * catch is between two modules that each pass their own tests, and that is
 * exactly the defect no per-module suite can see. It costs one binary, and
 * it is the shape a consumer actually runs.
 *
 * If a later pass finds it still has no unique catch and wants the binary
 * back, that is a reasonable trade and this paragraph is the argument to
 * weigh -- not a green run, which it will have either way.
 */

#include "../../chain/sign_monocypher.h"
#include "../../session/aead_monocypher.h"
#include "../../session/agree_monocypher.h"
#include "../../session/hash_monocypher.h"
#include "../../session/random_system.h"

#include "../../prekey/prekey.h"
#include "../../ratchet/ratchet.h"
#include "../../session/session.h"
#include "../../wire/seal.h"

#include <monocypher.h>
#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check(int ok, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL: %s\n", what);
	}
}

/* Deterministic seeds. A test that drew its identities from the system pool
 * would be one whose failures could not be reproduced from the source. */
static void seed_bytes(uint8_t out[32], uint8_t v)
{
	memset(out, v, 32);
}

int main(void)
{
	fzn_sign_monocypher_t signer[2];
	fzn_sign_ops_t sign_ops[2];
	fzn_hash_ops_t hash_ops;
	fzn_aead_ops_t aead_ops;
	fzn_agree_ops_t agree_ops;
	fzn_random_ops_t rng_ops;
	uint8_t pubkey[2][FZN_PUBKEY_LEN];
	uint8_t seed[32];
	fzn_agree_secret_t sk[2];
	uint8_t raw[2][FZN_AGREE_SECRET_LEN];
	uint8_t record_bytes[2][FZN_PREKEY_LEN_TOTAL];
	fzn_prekey_record_t record[2];
	fzn_prekey_peer_t pinned[2];
	uint8_t key[2][FZN_AEAD_KEY_LEN], ckey[2][FZN_COMMITMENT_KEY_LEN];
	uint8_t send_chain[2][FZN_CHAIN_KEY_LEN], recv_chain[2][FZN_CHAIN_KEY_LEN];
	fzn_ratchet_chain_t sender, receiver, moved;
	uint8_t mk_send[FZN_MESSAGE_KEY_LEN], mk_recv[FZN_MESSAGE_KEY_LEN];
	unsigned h;

	fzn_hash_monocypher_init(&hash_ops);
	fzn_aead_monocypher_init(&aead_ops);
	fzn_agree_monocypher_init(&agree_ops);
	fzn_random_system_init(&rng_ops);

	/* IDENTITIES, REALLY ED25519. */
	for (h = 0; h < 2u; h++) {
		memset(&signer[h], 0, sizeof(signer[h]));
		seed_bytes(seed, (uint8_t)(0x31u + h));
		crypto_eddsa_key_pair(signer[h].secret_key, pubkey[h], seed);
		signer[h].can_sign = 1;
		fzn_sign_monocypher_init(&sign_ops[h], &signer[h]);
	}
	check(memcmp(pubkey[0], pubkey[1], FZN_PUBKEY_LEN) != 0,
	      "the two hosts were given the same identity, so nothing below "
	      "distinguishes them");

	/* PREKEYS, REALLY X25519. The derivation of a public key from a secret
	 * goes through the seam rather than being computed here, because a
	 * test that called crypto_x25519_public_key itself would be proving
	 * Monocypher rather than the binding. */
	for (h = 0; h < 2u; h++) {
		unsigned i;

		memset(&sk[h], 0, sizeof(sk[h]));
		fzn_prekey_peer_init(&pinned[h]);
		for (i = 0; i < FZN_AGREE_SECRET_LEN; i++)
			raw[h][i] = (uint8_t)((h * 89u) + (i * 17u) + 7u);
		check(fzn_agree_secret_install(&sk[h], &agree_ops, raw[h]) == FZN_AGREE_OK,
		      "a real X25519 secret would not install");
	}

	/* THE RECORD IS SIGNED AND REOPENED, so what is pinned below is bytes
	 * that survived a real signature rather than a struct filled in. */
	for (h = 0; h < 2u; h++) {
		check(fzn_prekey_issue(pubkey[h], fzn_agree_secret_public(&sk[h]), 1000u + h,
		                       &sign_ops[h], record_bytes[h]) == FZN_PREKEY_OK,
		      "a prekey record would not sign under real Ed25519");
		check(fzn_prekey_open(record_bytes[h], FZN_PREKEY_LEN_TOTAL, &record[h])
		              == FZN_PREKEY_OK,
		      "a real signed prekey record would not open");
	}

	/* PINNING VERIFIES THE OTHER HOST'S SIGNATURE, so each host is
	 * checking a key it did not make with a verifier it does not own. */
	check(fzn_prekey_pin(&pinned[0], record[1], &sign_ops[0], FZN_TRUST_ADOPTED, 1100u)
	              == FZN_PREKEY_OK, "host 0 could not pin a real record");
	check(fzn_prekey_pin(&pinned[1], record[0], &sign_ops[1], FZN_TRUST_ADOPTED, 1100u)
	              == FZN_PREKEY_OK, "host 1 could not pin a real record");

	/*
	 * THE SESSION, which is the call that asks BLAKE2b for FZN_DERIVED_LEN
	 * bytes in one go. The header above records that `commitment_test.c`
	 * already holds that length, so this is the composed path exercising
	 * it rather than the guard on it.
	 */
	check(fzn_session_establish(&sk[0], &agree_ops, &hash_ops, pubkey[0], pubkey[1],
	                            pinned[0].prekey, key[0], ckey[0]) == FZN_SESSION_OK,
	      "host 0 could not establish under real primitives -- if this is the only "
	      "failure, look at FZN_DERIVED_LEN against BLAKE2b's 64-byte maximum");
	check(fzn_session_establish(&sk[1], &agree_ops, &hash_ops, pubkey[1], pubkey[0],
	                            pinned[1].prekey, key[1], ckey[1]) == FZN_SESSION_OK,
	      "host 1 could not establish under real primitives");
	check(memcmp(key[0], key[1], FZN_AEAD_KEY_LEN) == 0,
	      "two hosts derived different session roots under a real X25519 agreement");
	check(memcmp(ckey[0], ckey[1], FZN_COMMITMENT_KEY_LEN) == 0,
	      "the two commitment keys differ under real primitives");

	/* THE DIRECTED SEEDS AND THE RATCHET, under BLAKE2b. */
	check(fzn_session_chains(&hash_ops, key[0], pubkey[0], pubkey[1], send_chain[0],
	                         recv_chain[0]) == FZN_SESSION_OK,
	      "host 0 could not derive chains under BLAKE2b");
	check(fzn_session_chains(&hash_ops, key[1], pubkey[1], pubkey[0], send_chain[1],
	                         recv_chain[1]) == FZN_SESSION_OK,
	      "host 1 could not derive chains under BLAKE2b");
	check(memcmp(send_chain[0], recv_chain[1], FZN_CHAIN_KEY_LEN) == 0,
	      "host 0's send chain is not host 1's receive chain under real primitives");
	check(memcmp(send_chain[0], recv_chain[0], FZN_CHAIN_KEY_LEN) != 0,
	      "the two directions share a chain under real primitives");

	fzn_ratchet_init(&sender, send_chain[0], 0);
	fzn_ratchet_init(&receiver, recv_chain[1], 0);
	check(fzn_ratchet_advance(&hash_ops, &sender, 0, mk_send, &moved, NULL, 0, NULL, NULL)
	              == FZN_RATCHET_OK, "the sender could not advance under BLAKE2b");
	sender = moved;
	check(fzn_ratchet_advance(&hash_ops, &receiver, 0, mk_recv, &moved, NULL, 0, NULL, NULL)
	              == FZN_RATCHET_OK, "the receiver could not advance under BLAKE2b");
	receiver = moved;
	check(memcmp(mk_send, mk_recv, FZN_MESSAGE_KEY_LEN) == 0,
	      "the two hosts derived different message keys under real primitives");

	/*
	 * AND A FRAME GOES ACROSS. Sealed with ChaCha20-Poly1305 under a key
	 * derived by BLAKE2b from an X25519 agreement between two Ed25519
	 * identities -- every seam in the library at once, which is the whole
	 * point of the file.
	 *
	 * The nonce comes from the SYSTEM entropy seam rather than a fixture,
	 * because `fzn_seal_build` draws it itself and refusing to let a
	 * caller supply one is deliberate.
	 */
	{
		static const uint8_t PAYLOAD[] = "a real datagram, sealed under real keys";
		uint8_t frame[FZN_SEAL_OVERHEAD + sizeof(PAYLOAD)];
		fzn_cap_id_t cap;
		size_t frame_len = 0;
		fzn_send_t what;
		fzn_opened_t got;

		memset(cap.b, 0x4c, sizeof(cap));
		memset(&what, 0, sizeof(what));
		what.sender = pubkey[0];
		what.capability = cap.b;
		what.payload = PAYLOAD;
		what.payload_len = sizeof(PAYLOAD);
		what.expires_at = 2000u;
		what.msg = 7u;
		what.index = 0u;
		what.chunks = 1u;
		what.kind = 1u;

		check(fzn_seal_build(frame, sizeof(frame), &frame_len, &what, key[0], ckey[0],
		                     &hash_ops, &rng_ops, &aead_ops) == FZN_SEAL_OK,
		      "a frame would not seal under real primitives");
		/* THE RECEIVER USES ITS OWN DERIVED KEY, not the sender's
		 * buffer. Opening with `key[0]` would pass against a session
		 * that never agreed. */
		check(fzn_seal_open(frame, frame_len, key[1], ckey[1], &hash_ops, &aead_ops,
		                    &got) == FZN_SEAL_OK,
		      "a real frame would not open under the receiver's own derived key");
		check(got.payload_len == sizeof(PAYLOAD)
		              && memcmp(got.payload, PAYLOAD, sizeof(PAYLOAD)) == 0,
		      "the payload did not survive a real seal and open");
		check(got.msg == 7u && got.kind == 1u && got.expires_at == 2000u,
		      "a header field did not survive a real round trip");

		/* AND A TAMPERED FRAME IS REFUSED BY POLY1305 RATHER THAN BY A
		 * stub agreeing with itself. Rebuilt first, because opening
		 * decrypts in place and the buffer is consumed. */
		check(fzn_seal_build(frame, sizeof(frame), &frame_len, &what, key[0], ckey[0],
		                     &hash_ops, &rng_ops, &aead_ops) == FZN_SEAL_OK,
		      "the frame would not rebuild");
		frame[frame_len - 1u] ^= 0x01u;
		check(fzn_seal_open(frame, frame_len, key[1], ckey[1], &hash_ops, &aead_ops,
		                    &got) != FZN_SEAL_OK,
		      "a frame with a flipped bit opened under real ChaCha20-Poly1305");
		/* Poly1305 is what refuses here. `wire/test/tamper_test.c`
		 * owns the per-field version of this against the stub; the
		 * value of doing it once more is that the refusal is a real
		 * MAC's rather than a toy agreeing with itself. */

		/* AND A WRONG KEY IS REFUSED, which is what says the agreement
		 * above did any work at all. */
		check(fzn_seal_build(frame, sizeof(frame), &frame_len, &what, key[0], ckey[0],
		                     &hash_ops, &rng_ops, &aead_ops) == FZN_SEAL_OK,
		      "the frame would not rebuild");
		{
			uint8_t wrong[FZN_AEAD_KEY_LEN];

			memcpy(wrong, key[1], sizeof(wrong));
			wrong[0] ^= 0x01u;
			check(fzn_seal_open(frame, frame_len, wrong, ckey[1], &hash_ops,
			                    &aead_ops, &got) != FZN_SEAL_OK,
			      "a frame opened under a key that is one bit wrong");
		}
	}

	for (h = 0; h < 2u; h++) {
		fzn_agree_secret_wipe(&sk[h]);
		fzn_sign_monocypher_wipe(&signer[h]);
	}

	printf("real_crypto_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
