/* The remote hop provisioned end to end, under real Monocypher primitives and
 * over a real UDP socket. A node mints a device its capability and a pairing
 * card, the card survives the QR text round trip, the device provisions itself
 * from it, and the node provisions the device into a servable peer -- then the
 * device seals a request and sends it across loopback, and one turn of the
 * daemon loop authenticates, authorises and hands it up. Nothing is stubbed:
 * the keys are Ed25519 and X25519, the datagram is a real send and recv. */

#define _DEFAULT_SOURCE

#include "provision.h"
#include "serve.h"

#include "../chain/sign_monocypher.h"
#include "../session/aead_monocypher.h"
#include "../session/agree_monocypher.h"
#include "../session/hash_monocypher.h"
#include "../session/random_system.h"
#include "../provision/provision.h"
#include "../net/udp.h"

#include <arpa/inet.h>
#include <monocypher.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>

static int checks;
static int failures;

static void ok(int cond, const char *what)
{
	checks++;
	if (!cond) {
		failures++;
		printf("  FAIL provision_test.c: %s\n", what);
	}
}

static const uint8_t PAYLOAD[] = { 'p', 'i', 'n', 'g' };

static struct {
	int called;
	fzn_node_remote_result_t result;
	uint8_t payload[64];
	size_t payload_len;
} observed;

static const uint8_t PONG[] = { 'p', 'o', 'n', 'g' };

static size_t on_remote_cb(void *ctx, fzn_node_remote_result_t result,
                           const fzn_opened_t *req, uint8_t *reply,
                           size_t reply_cap)
{
	(void)ctx;
	observed.called = 1;
	observed.result = result;
	if (req && req->payload && req->payload_len <= sizeof(observed.payload)) {
		memcpy(observed.payload, req->payload, req->payload_len);
		observed.payload_len = req->payload_len;
	}
	/* Reply only to a granted caller, and only if it fits. */
	if (result == FZN_NODE_REMOTE_GRANTED && reply_cap >= sizeof(PONG)) {
		memcpy(reply, PONG, sizeof(PONG));
		return sizeof(PONG);
	}
	return 0;
}

static uint64_t test_now(void)
{
	return 1000u;
}

static uint16_t local_port(int fd)
{
	struct sockaddr_storage ss;
	socklen_t len = sizeof(ss);

	if (getsockname(fd, (struct sockaddr *)&ss, &len) != 0)
		return 0;
	return ntohs(((struct sockaddr_in *)&ss)->sin_port);
}

static void seed_bytes(uint8_t out[32], uint8_t v)
{
	memset(out, v, 32);
}

static size_t seal_request(uint8_t *frame, size_t cap, const uint8_t *client_pub,
                           const uint8_t *capb, const uint8_t *key,
                           const uint8_t *ckey, const fzn_hash_ops_t *hash,
                           const fzn_random_ops_t *rng, const fzn_aead_ops_t *aead)
{
	fzn_send_t what;
	size_t len = 0;

	memset(&what, 0, sizeof(what));
	what.sender = client_pub;
	what.capability = capb;
	what.payload = PAYLOAD;
	what.payload_len = sizeof(PAYLOAD);
	what.expires_at = 2000u;
	what.msg = 7u;
	what.index = 0u;
	what.chunks = 1u;
	what.kind = FZN_KIND_UNIT;
	if (fzn_seal_build(frame, cap, &len, &what, key, ckey, hash, rng, aead)
	    != FZN_SEAL_OK)
		return 0;
	return len;
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
	fzn_node_identity_t node_id, dev_id;
	fzn_cap_id_t cap;
	uint8_t card[FZN_PROVISION_LEN_TOTAL], card2[FZN_PROVISION_LEN_TOTAL];
	char text[FZN_PROVISION_TEXT_LEN];
	size_t card_len = 0, card2_len = 0;
	uint8_t send_key[FZN_AEAD_KEY_LEN], send_ckey[FZN_COMMITMENT_KEY_LEN];
	uint8_t root[FZN_PUBKEY_LEN];
	fzn_node_peer_t node_peer;
	fzn_node_state_t state;
	fzn_udp_addr_t node_addr;
	uint8_t frame[512];
	size_t frame_len;
	int node_udp = -1, dev_udp = -1;
	uint16_t port;
	unsigned h, i;

	fzn_hash_monocypher_init(&hash_ops);
	fzn_aead_monocypher_init(&aead_ops);
	fzn_agree_monocypher_init(&agree_ops);
	fzn_random_system_init(&rng_ops);

	/* Two identities: 0 is the node/root, 1 is the device. */
	for (h = 0; h < 2u; h++) {
		memset(&signer[h], 0, sizeof(signer[h]));
		seed_bytes(seed, (uint8_t)(0x71u + h));
		crypto_eddsa_key_pair(signer[h].secret_key, pubkey[h], seed);
		signer[h].can_sign = 1;
		fzn_sign_monocypher_init(&sign_ops[h], &signer[h]);
		memset(&sk[h], 0, sizeof(sk[h]));
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

	memset(&node_id, 0, sizeof(node_id));
	memcpy(node_id.pubkey, pubkey[0], FZN_PUBKEY_LEN);
	node_id.agree_secret = &sk[0];
	memcpy(node_id.prekey_record, record_bytes[0], FZN_PREKEY_LEN_TOTAL);
	node_id.sign = &sign_ops[0];
	node_id.hash = &hash_ops;
	node_id.agree = &agree_ops;

	memset(&dev_id, 0, sizeof(dev_id));
	memcpy(dev_id.pubkey, pubkey[1], FZN_PUBKEY_LEN);
	dev_id.agree_secret = &sk[1];
	memcpy(dev_id.prekey_record, record_bytes[1], FZN_PREKEY_LEN_TOTAL);
	dev_id.sign = &sign_ops[1];
	dev_id.hash = &hash_ops;
	dev_id.agree = &agree_ops;

	memset(cap.b, 0x4c, sizeof(cap.b));

	/* The node mints the device a card. */
	ok(fzn_node_make_card(&node_id, pubkey[1], &cap, 500u, 0u, 0u, card,
	                      sizeof(card), &card_len) == FZN_NODE_PROVISION_OK,
	   "the node builds a pairing card");

	/* The card survives the QR text round trip. */
	ok(fzn_provision_text(card, card_len, text, sizeof(text)) ==
	   FZN_PROVISION_OK, "the card encodes as text");
	ok(fzn_provision_from_text(text, card2, sizeof(card2), &card2_len) ==
	   FZN_PROVISION_OK, "the card decodes from text");
	ok(card2_len == card_len && memcmp(card, card2, card_len) == 0,
	   "the card is byte-identical across the text round trip");

	/* The device provisions itself from the decoded card. */
	ok(fzn_node_accept_card(&dev_id, card2, card2_len, 1000u, send_key,
	                        send_ckey, root, NULL) == FZN_NODE_PROVISION_OK,
	   "the device accepts the card");
	ok(memcmp(root, pubkey[0], FZN_PUBKEY_LEN) == 0,
	   "the device pinned the node as its root");

	/* The node provisions the device into a servable peer. */
	ok(fzn_node_provision_peer(&node_id, record[1], &cap, 500u, 0u, 1000u,
	                           &node_peer) == FZN_NODE_PROVISION_OK,
	   "the node provisions the device as a peer");
	ok(memcmp(node_peer.recv_key, send_key, FZN_AEAD_KEY_LEN) == 0,
	   "both sides derived the same session key");

	/* Real UDP loopback: the device sends, the node receives. */
	ok(fzn_udp_bind(AF_INET, "127.0.0.1", 0, &node_udp) == FZN_UDP_OK,
	   "the node binds a UDP socket");
	ok(fzn_udp_bind(AF_INET, "127.0.0.1", 0, &dev_udp) == FZN_UDP_OK,
	   "the device binds a UDP socket");
	port = local_port(node_udp);
	ok(port != 0, "the node has a port");
	ok(fzn_udp_resolve(AF_INET, "127.0.0.1", port, &node_addr) == FZN_UDP_OK,
	   "the device resolves the node");

	frame_len = seal_request(frame, sizeof(frame), pubkey[1], cap.b, send_key,
	                         send_ckey, &hash_ops, &rng_ops, &aead_ops);
	ok(frame_len != 0, "the device seals a request");
	ok(fzn_udp_send(dev_udp, &node_addr, frame, frame_len) == FZN_UDP_OK,
	   "the device sends the datagram");

	memset(&state, 0, sizeof(state));
	state.config.serves_remote = 1;
	state.config.remote_capability = cap;
	memcpy(state.config.root, pubkey[0], FZN_PUBKEY_LEN);
	state.listen_fd = -1;
	state.udp_fd = node_udp;
	state.peers = &node_peer;
	state.peer_count = 1u;
	state.hash = &hash_ops;
	state.aead = &aead_ops;
	state.sign = &sign_ops[0];
	state.clock = test_now;
	state.rng = &rng_ops;
	memcpy(state.node_pubkey, pubkey[0], FZN_PUBKEY_LEN);
	state.on_remote = on_remote_cb;

	observed.called = 0;
	ok(fzn_node_run_once(&state, 1000) == 1,
	   "one loop turn serves the datagram");
	ok(observed.called, "the handler was reached");
	ok(observed.result == FZN_NODE_REMOTE_GRANTED,
	   "the provisioned request was granted end to end");
	ok(observed.payload_len == sizeof(PAYLOAD) &&
	   memcmp(observed.payload, PAYLOAD, sizeof(PAYLOAD)) == 0,
	   "the request payload arrived intact");

	/* The node sealed a reply and sent it back to the device across the
	 * same loopback; the device opens it with the key it sealed with. */
	{
		struct timeval tv;
		uint8_t reply_frame[512];
		size_t reply_len = 0;
		fzn_opened_t reply_opened;

		tv.tv_sec = 2;
		tv.tv_usec = 0;
		(void)setsockopt(dev_udp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		ok(fzn_udp_recv(dev_udp, reply_frame, sizeof(reply_frame), &reply_len,
		                NULL) == FZN_UDP_OK,
		   "the device receives the sealed reply");
		ok(fzn_seal_open(reply_frame, reply_len, send_key, send_ckey, &hash_ops,
		                 &aead_ops, &reply_opened) == FZN_SEAL_OK,
		   "the device opens the reply");
		ok(reply_opened.payload_len == sizeof(PONG) &&
		   memcmp(reply_opened.payload, PONG, sizeof(PONG)) == 0,
		   "the reply payload round-tripped");
		ok(memcmp(reply_opened.sender, pubkey[0], FZN_PUBKEY_LEN) == 0,
		   "the reply is from the node");
	}

	fzn_udp_close(node_udp);
	fzn_udp_close(dev_udp);
	for (h = 0; h < 2u; h++)
		fzn_agree_secret_wipe(&sk[h]);

	printf("provision_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
