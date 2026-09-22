/* The remote access method end to end, under real Monocypher primitives: two
 * identities agree a session from pinned prekeys (this library has no wire
 * handshake -- session/session.h), a root mints a capability to the client,
 * the client seals a request, and the node authenticates and authorises it.
 * This is real_crypto_test's provisioning composed with node/remote.c.
 *
 * A grant, a denial (no chain), and three drops -- a tampered seal, a wrong
 * sender, and a stale command -- are all driven, so the remote hop's
 * authenticate-then-authorise is exercised on every arm. */

#include "remote.h"

#include "../chunk/split.h"
#include "../net/udp.h"
#include "../chunk/reassembly.h"

#include "../chain/sign_monocypher.h"
#include "../session/aead_monocypher.h"
#include "../session/agree_monocypher.h"
#include "../session/hash_monocypher.h"
#include "../session/random_system.h"
#include "../prekey/prekey.h"
#include "../session/session.h"
#include "../trust/trust.h"

#include <monocypher.h>
#include <stdio.h>
#include <string.h>

static int checks;
static int failures;

static void ok(int cond, const char *what)
{
	checks++;
	if (!cond) {
		failures++;
		printf("  FAIL remote_test.c: %s\n", what);
	}
}

static const uint8_t PAYLOAD[] = { 'p', 'i', 'n', 'g' };

/* Seal one request from the client under its session key. Returns the frame
 * length, or 0 on failure. Rebuilt before every serve, since opening decrypts
 * in place. */
static size_t seal_request(uint8_t *frame, size_t cap, const uint8_t *client_pub,
                           const uint8_t *capb, const uint8_t *key,
                           const uint8_t *ckey, const fzn_hash_ops_t *hash,
                           const fzn_random_ops_t *rng, const fzn_aead_ops_t *aead,
                           uint64_t expires)
{
	fzn_send_t what;
	size_t len = 0;

	memset(&what, 0, sizeof(what));
	what.sender = client_pub;
	what.capability = capb;
	what.payload = PAYLOAD;
	what.payload_len = sizeof(PAYLOAD);
	what.expires_at = expires;
	what.msg = 7u;
	what.index = 0u;
	what.chunks = 1u;
	what.kind = FZN_KIND_UNIT;
	if (fzn_seal_build(frame, cap, &len, &what, key, ckey, hash, rng, aead)
	    != FZN_SEAL_OK)
		return 0;
	return len;
}

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
	fzn_cap_id_t cap;
	uint8_t hop_bytes[FZN_HOP_LEN];
	fzn_node_config_t config;
	fzn_node_peer_t peer;
	fzn_opened_t opened;
	uint8_t frame[512];
	uint8_t frame_copy[512];
	fzn_replay_entry_t replay_entries[16];
	fzn_replay_window_t replay;
	size_t frame_len;
	unsigned h, i;

	fzn_hash_monocypher_init(&hash_ops);
	fzn_aead_monocypher_init(&aead_ops);
	fzn_agree_monocypher_init(&agree_ops);
	fzn_random_system_init(&rng_ops);
	ok(fzn_replay_init(&replay, replay_entries, 16, 100000u) == FZN_FRESH_OK,
	   "the replay window initialises");

	for (h = 0; h < 2u; h++) {
		memset(&signer[h], 0, sizeof(signer[h]));
		seed_bytes(seed, (uint8_t)(0x51u + h));
		crypto_eddsa_key_pair(signer[h].secret_key, pubkey[h], seed);
		signer[h].can_sign = 1;
		fzn_sign_monocypher_init(&sign_ops[h], &signer[h]);
	}

	for (h = 0; h < 2u; h++) {
		memset(&sk[h], 0, sizeof(sk[h]));
		fzn_prekey_peer_init(&pinned[h]);
		for (i = 0; i < FZN_AGREE_SECRET_LEN; i++)
			raw[h][i] = (uint8_t)((h * 89u) + (i * 17u) + 7u);
		ok(fzn_agree_secret_install(&sk[h], &agree_ops, raw[h]) == FZN_AGREE_OK,
		   "an X25519 secret installs");
		ok(fzn_prekey_issue(pubkey[h], fzn_agree_secret_public(&sk[h]),
		                    1000u + h, &sign_ops[h], record_bytes[h]) ==
		   FZN_PREKEY_OK, "a prekey record signs");
		ok(fzn_prekey_open(record_bytes[h], FZN_PREKEY_LEN_TOTAL, &record[h])
		   == FZN_PREKEY_OK, "a prekey record opens");
	}
	ok(fzn_prekey_pin(&pinned[0], record[1], &sign_ops[0], FZN_TRUST_ADOPTED,
	                  1100u) == FZN_PREKEY_OK, "the node pins the client");
	ok(fzn_prekey_pin(&pinned[1], record[0], &sign_ops[1], FZN_TRUST_ADOPTED,
	                  1100u) == FZN_PREKEY_OK, "the client pins the node");

	ok(fzn_session_establish(&sk[0], &agree_ops, &hash_ops, pubkey[0],
	                         pubkey[1], pinned[0].prekey, key[0], ckey[0]) ==
	   FZN_SESSION_OK, "the node establishes a session");
	ok(fzn_session_establish(&sk[1], &agree_ops, &hash_ops, pubkey[1],
	                         pubkey[0], pinned[1].prekey, key[1], ckey[1]) ==
	   FZN_SESSION_OK, "the client establishes a session");
	ok(memcmp(key[0], key[1], FZN_AEAD_KEY_LEN) == 0,
	   "the two derived the same session key");

	memset(cap.b, 0x4c, sizeof(cap.b));
	ok(fzn_chain_mint(pubkey[0], pubkey[1], &cap, 500u, 0u, 0, &sign_ops[0],
	                  hop_bytes) == FZN_CHAIN_OK, "the root mints a capability");

	memset(&config, 0, sizeof(config));
	config.uid = 1000u;
	config.serves_remote = 1;
	config.remote_capability = cap;
	memcpy(config.root, pubkey[0], FZN_PUBKEY_LEN);

	memset(&peer, 0, sizeof(peer));
	memcpy(peer.sender, pubkey[1], FZN_PUBKEY_LEN);
	memcpy(peer.recv_key, key[0], FZN_AEAD_KEY_LEN);
	memcpy(peer.recv_ckey, ckey[0], FZN_COMMITMENT_KEY_LEN);
	{
		fzn_chain_hop_t tmp;

		ok(fzn_hop_open(hop_bytes, FZN_HOP_LEN, &tmp) == FZN_CHAIN_OK,
		   "the minted hop opens");
	}
	memcpy(peer.hop_bytes[0], hop_bytes, FZN_HOP_LEN);
	peer.hop_count = 1u;

	/* A provisioned, authorised request is granted, and the payload and
	 * sender survive. now is before the request's expiry. */
	frame_len = seal_request(frame, sizeof(frame), pubkey[1], cap.b, key[1],
	                         ckey[1], &hash_ops, &rng_ops, &aead_ops, 2000u);
	ok(frame_len != 0, "the client seals a request");
	memset(&opened, 0, sizeof(opened));
	ok(fzn_node_serve_datagram(&config, &peer, &hash_ops, &aead_ops,
	                           &sign_ops[0], &replay, 1000u, frame, frame_len, &opened)
	   == FZN_NODE_REMOTE_GRANTED,
	   "a capability-bearing remote request is granted");
	ok(opened.payload_len == sizeof(PAYLOAD) &&
	   memcmp(opened.payload, PAYLOAD, sizeof(PAYLOAD)) == 0,
	   "the request payload survived authentication");
	ok(memcmp(opened.sender, pubkey[1], FZN_PUBKEY_LEN) == 0,
	   "the opened sender is the client");

	/* The node seals a reply back, which the caller opens with the key it
	 * seals its own requests with -- the session key is symmetric. */
	{
		static const uint8_t PONG[] = { 'p', 'o', 'n', 'g' };
		uint8_t reply_frame[512];
		size_t reply_len = 0;
		fzn_opened_t reply_opened;

		ok(fzn_node_seal_reply(&peer, pubkey[0], PONG, sizeof(PONG), 7u, 0u,
		                       &hash_ops, &rng_ops, &aead_ops, reply_frame,
		                       sizeof(reply_frame), &reply_len) == 0,
		   "the node seals a reply");
		ok(fzn_seal_open(reply_frame, reply_len, key[1], ckey[1], &hash_ops,
		                 &aead_ops, &reply_opened) == FZN_SEAL_OK,
		   "the caller opens the reply");
		ok(reply_opened.payload_len == sizeof(PONG) &&
		   memcmp(reply_opened.payload, PONG, sizeof(PONG)) == 0,
		   "the reply payload survives");
		ok(memcmp(reply_opened.sender, pubkey[0], FZN_PUBKEY_LEN) == 0,
		   "the reply is sealed as from the node");
	}

	/* A REPLY LARGER THAN A FRAME, WHICH IS WHY THIS EXISTS.
	 *
	 * raidcfgd reported 2026-09-22 that their smallest `status` reading is
	 * 3,230 bytes against a 512-byte cap, so the consumer with most to say
	 * could not answer at all. 3,230 is the size driven here deliberately:
	 * a measured payload from a real consumer rather than a round number
	 * chosen to be awkward. It is four pieces at FZN_SPLIT_MAX_PAYLOAD,
	 * the last a remainder, which is the shape that catches an off-by-one
	 * at either end of the plan. */
	{
		static uint8_t big[3230];
		fzn_split_t plan;
		fzn_reasm_t table;
		fzn_partial_t slots[2];
		static uint8_t slot_buf[2][4096];
		fzn_partial_t *done = NULL;
		uint16_t piece;
		size_t k;
		int sealed_ok = 1, opened_ok = 1, kinds_ok = 1;

		for (k = 0; k < sizeof(big); k++)
			big[k] = (uint8_t)(k * 31u + 7u);

		ok(fzn_split_plan(sizeof(big), FZN_SPLIT_MAX_PAYLOAD, &plan)
		       == FZN_SPLIT_OK && plan.chunks == 4u,
		   "3,230 bytes did not plan as four pieces");

		ok(fzn_reasm_slot_init(&slots[0], slot_buf[0], sizeof(slot_buf[0]))
		       == FZN_REASM_OK &&
		   fzn_reasm_slot_init(&slots[1], slot_buf[1], sizeof(slot_buf[1]))
		       == FZN_REASM_OK &&
		   fzn_reasm_init(&table, slots, 2, 2u, 60u) == FZN_REASM_OK,
		   "the reassembly table would not initialise");

		for (piece = 0; piece < plan.chunks; piece++) {
			uint8_t f[FZN_UDP_DATAGRAM_MAX];
			size_t flen2 = 0, off = 0, len = 0;
			fzn_opened_t o;
			fzn_peek_t pk;

			if (fzn_split_at(&plan, piece, &off, &len) != FZN_SPLIT_OK) {
				sealed_ok = 0;
				break;
			}
			if (fzn_node_seal_reply_chunk(&peer, pubkey[0], big + off, len,
			                              99u, piece, plan.chunks, 0u,
			                              &hash_ops, &rng_ops, &aead_ops,
			                              f, sizeof(f), &flen2) != 0) {
				sealed_ok = 0;
				break;
			}
			/* The kind is derived, so four pieces must all say CHUNK. */
			if (fzn_seal_peek(f, flen2, &pk) != FZN_SEAL_OK ||
			    pk.kind != FZN_KIND_CHUNK || pk.index != piece ||
			    pk.chunks != plan.chunks)
				kinds_ok = 0;
			if (fzn_seal_open(f, flen2, key[1], ckey[1], &hash_ops,
			                  &aead_ops, &o) != FZN_SEAL_OK) {
				opened_ok = 0;
				break;
			}
			(void)fzn_reasm_accept(&table, o.sender, o.msg, o.index,
			                       o.chunks, o.payload, o.payload_len,
			                       0u, 1000u, &done);
		}
		ok(sealed_ok, "a piece of the reply would not seal");
		ok(kinds_ok,
		   "a piece did not seal as CHUNK with its own index and count, so a "
		   "receiver cannot tell what it is holding");
		ok(opened_ok, "a piece of the reply would not open");
		ok(done != NULL,
		   "four pieces were accepted and the message never completed");
		if (done)
			ok(done->bytes == sizeof(big) &&
			   memcmp(done->buf, big, sizeof(big)) == 0,
			   "the reassembled reply is not the bytes that went in");
		if (done)
			fzn_reasm_release(done);
	}

	/* THE WRAPPER STILL SEALS ONE PIECE OF ONE, and the kind follows the
	 * count rather than a parameter -- so a caller cannot build a CHUNK
	 * frame claiming to be alone, or a UNIT frame that is one of several. */
	{
		static const uint8_t ONE[] = { 'o', 'n', 'e' };
		uint8_t f[FZN_UDP_DATAGRAM_MAX];
		size_t flen2 = 0;
		fzn_peek_t pk;

		ok(fzn_node_seal_reply(&peer, pubkey[0], ONE, sizeof(ONE), 5u, 0u,
		                       &hash_ops, &rng_ops, &aead_ops, f, sizeof(f),
		                       &flen2) == 0 &&
		   fzn_seal_peek(f, flen2, &pk) == FZN_SEAL_OK &&
		   pk.kind == FZN_KIND_UNIT && pk.index == 0u && pk.chunks == 1u,
		   "the one-piece wrapper stopped sealing index 0 of 1 as UNIT");
		ok(fzn_node_seal_reply_chunk(&peer, pubkey[0], ONE, sizeof(ONE), 5u,
		                             0u, 1u, 0u, &hash_ops, &rng_ops,
		                             &aead_ops, f, sizeof(f), &flen2) == 0 &&
		   fzn_seal_peek(f, flen2, &pk) == FZN_SEAL_OK &&
		   pk.kind == FZN_KIND_UNIT,
		   "one piece of one did not seal as UNIT");

		/* A piece of nothing, and a piece that is not one of the pieces. */
		ok(fzn_node_seal_reply_chunk(&peer, pubkey[0], ONE, sizeof(ONE), 5u,
		                             0u, 0u, 0u, &hash_ops, &rng_ops,
		                             &aead_ops, f, sizeof(f), &flen2) != 0,
		   "a reply of zero pieces sealed");
		ok(fzn_node_seal_reply_chunk(&peer, pubkey[0], ONE, sizeof(ONE), 5u,
		                             3u, 3u, 0u, &hash_ops, &rng_ops,
		                             &aead_ops, f, sizeof(f), &flen2) != 0,
		   "a piece numbered past the count sealed");
	}

	/* Authenticated but unauthorised: the same peer with no chain is
	 * denied, not dropped -- the frame still opened. */
	{
		fzn_node_peer_t bare = peer;

		bare.hop_count = 0u;
		frame_len = seal_request(frame, sizeof(frame), pubkey[1], cap.b,
		                         key[1], ckey[1], &hash_ops, &rng_ops,
		                         &aead_ops, 2000u);
		ok(fzn_node_serve_datagram(&config, &bare, &hash_ops, &aead_ops,
		                           &sign_ops[0], &replay, 1000u, frame, frame_len,
		                           NULL) == FZN_NODE_REMOTE_DENIED,
		   "a remote request with no capability is denied");
	}

	/* A tampered seal does not authenticate: dropped, no reply. */
	frame_len = seal_request(frame, sizeof(frame), pubkey[1], cap.b, key[1],
	                         ckey[1], &hash_ops, &rng_ops, &aead_ops, 2000u);
	frame[frame_len - 1u] ^= 0x01u;
	ok(fzn_node_serve_datagram(&config, &peer, &hash_ops, &aead_ops,
	                           &sign_ops[0], &replay, 1000u, frame, frame_len, NULL)
	   == FZN_NODE_REMOTE_DROPPED,
	   "a tampered frame is dropped");

	/* A frame whose sender is not the routed peer's is dropped. */
	{
		fzn_node_peer_t other = peer;

		other.sender[0] ^= 0x01u;
		frame_len = seal_request(frame, sizeof(frame), pubkey[1], cap.b,
		                         key[1], ckey[1], &hash_ops, &rng_ops,
		                         &aead_ops, 2000u);
		ok(fzn_node_serve_datagram(&config, &other, &hash_ops, &aead_ops,
		                           &sign_ops[0], &replay, 1000u, frame, frame_len,
		                           NULL) == FZN_NODE_REMOTE_DROPPED,
		   "a frame from the wrong sender is dropped");
	}

	/* A stale command -- served after its expiry -- is dropped. */
	frame_len = seal_request(frame, sizeof(frame), pubkey[1], cap.b, key[1],
	                         ckey[1], &hash_ops, &rng_ops, &aead_ops, 2000u);
	ok(fzn_node_serve_datagram(&config, &peer, &hash_ops, &aead_ops,
	                           &sign_ops[0], &replay, 3000u, frame, frame_len, NULL)
	   == FZN_NODE_REMOTE_DROPPED,
	   "a command served after its expiry is dropped");

	/* The same authenticated frame served twice: the second is a replay.
	 * The seal opens in place, so the resend is a captured copy of the
	 * sealed bytes -- what a network attacker would resend. */
	frame_len = seal_request(frame, sizeof(frame), pubkey[1], cap.b, key[1],
	                         ckey[1], &hash_ops, &rng_ops, &aead_ops, 2000u);
	memcpy(frame_copy, frame, frame_len);
	ok(fzn_node_serve_datagram(&config, &peer, &hash_ops, &aead_ops,
	                           &sign_ops[0], &replay, 1000u, frame, frame_len,
	                           NULL) == FZN_NODE_REMOTE_GRANTED,
	   "a fresh frame is granted and its nonce recorded");
	ok(fzn_node_serve_datagram(&config, &peer, &hash_ops, &aead_ops,
	                           &sign_ops[0], &replay, 1000u, frame_copy,
	                           frame_len, NULL) == FZN_NODE_REMOTE_DROPPED,
	   "the same frame replayed is dropped");

	for (h = 0; h < 2u; h++)
		fzn_agree_secret_wipe(&sk[h]);

	printf("remote_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
