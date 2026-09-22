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
#include "../chunk/reassembly.h"
#include "caller.h"

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
		printf("  FAIL node/provision_test.c: %s\n", what);
	}
}

static const uint8_t PAYLOAD[] = { 'p', 'i', 'n', 'g' };

static struct {
	int called;
	fzn_node_remote_result_t result;
	uint8_t payload[64];
	size_t payload_len;
	size_t req_len;
	uint8_t req_first;
	uint8_t req_last;
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

/* A REPLY LARGER THAN ONE FRAME. 3,230 bytes is raidcfgd's measured smallest
 * `status` reading, reported 2026-09-22 -- a real consumer's payload rather
 * than a round number, and four pieces with a remainder last, which is the
 * shape that catches an off-by-one at either end of the plan. */
#define BIG_REPLY_LEN 3230u
static uint8_t big_reply[BIG_REPLY_LEN];

static size_t on_remote_big(void *ctx, fzn_node_remote_result_t result,
                            const fzn_opened_t *req, uint8_t *reply,
                            size_t reply_cap)
{
	(void)ctx;
	(void)req;
	observed.called = 1;
	observed.result = result;
	if (result != FZN_NODE_REMOTE_GRANTED || reply_cap < sizeof(big_reply))
		return 0;
	memcpy(reply, big_reply, sizeof(big_reply));
	return sizeof(big_reply);
}

/* A HANDLER THAT CLAIMS MORE THAN IT WAS GIVEN. Unlike the local seam's
 * version of this, the cost here is not a truncated reply: `fzn_split_plan`
 * would plan over a length the buffer does not have and the send loop would
 * read past it. So the guard is load-bearing rather than tidy, and this is
 * what reaches it. */
static size_t on_remote_overclaim(void *ctx, fzn_node_remote_result_t result,
                                  const fzn_opened_t *req, uint8_t *reply,
                                  size_t reply_cap)
{
	(void)ctx;
	(void)req;
	(void)reply;
	observed.called = 1;
	observed.result = result;
	return reply_cap + 1u;
}

/* Records the size and the ends of the request it was handed, so a chunked
 * one can be checked as a WHOLE rather than as "the handler ran". */
static size_t on_remote_measure(void *ctx, fzn_node_remote_result_t result,
                                const fzn_opened_t *req, uint8_t *reply,
                                size_t reply_cap)
{
	(void)ctx;
	(void)reply;
	(void)reply_cap;
	observed.called++;
	observed.result = result;
	observed.req_len = req ? req->payload_len : 0u;
	if (req && req->payload && req->payload_len) {
		observed.req_first = req->payload[0];
		observed.req_last = req->payload[req->payload_len - 1u];
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
	/* ROOMY BECAUSE THIS TEST NOW SENDS CHUNKS. Sixteen was ample while
	 * every case was one datagram; a chunked request spends one slot per
	 * piece, and a full window makes `fzn_replay_admit` refuse -- which
	 * arrives as DROPPED, so a case expecting DENIED sees its handler
	 * never called and blames the wrong guard. That is exactly how the
	 * denied-chunked case first failed. */
	static fzn_replay_entry_t replay_entries[256];
	fzn_replay_window_t replay;
	size_t frame_len;
	int node_udp = -1, dev_udp = -1;
	uint16_t port;
	unsigned h, i;

	fzn_hash_monocypher_init(&hash_ops);
	fzn_aead_monocypher_init(&aead_ops);
	fzn_agree_monocypher_init(&agree_ops);
	fzn_random_system_init(&rng_ops);
	ok(fzn_replay_init(&replay, replay_entries, 256, 100000u) == FZN_FRESH_OK,
	   "the replay window initialises");

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
	state.replay = &replay;
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

	/* The same datagram resent: its nonce is already in the window, so the
	 * node drops it and the handler is never reached. */
	observed.called = 0;
	ok(fzn_udp_send(dev_udp, &node_addr, frame, frame_len) == FZN_UDP_OK,
	   "the device re-sends the same datagram");
	ok(fzn_node_run_once(&state, 1000) == 1,
	   "the node receives the replayed datagram");
	ok(observed.called == 0,
	   "the replayed request was dropped, not served");

	/* THE LOOP'S OWN WIRING, WHICH sec 362 SHIPPED UNTESTED AND SAID SO.
	 *
	 * `remote_test` proved the planner and the sealer; nothing drove
	 * `fzn_node_run_once` against a UDP peer with an over-512 reply, so the
	 * buffer selection and the send loop were covered by construction. This
	 * is that gap closed: a real datagram in, four real datagrams out, and
	 * the bytes compared after reassembly. sec 363. */
	{
		static uint8_t reply_space[8192];
		fzn_reasm_t table;
		fzn_partial_t slots[2];
		static uint8_t slot_buf[2][8192];
		fzn_partial_t *done = NULL;
		struct timeval tv;
		size_t k;
		int opened_all = 1;
		unsigned got = 0;

		for (k = 0; k < sizeof(big_reply); k++)
			big_reply[k] = (uint8_t)(k * 17u + 3u);

		/* The consumer's buffer, which is the half the loop chooses
		 * between. Without it the node uses its own 512 bytes and the
		 * handler below refuses to answer at all. */
		state.reply = reply_space;
		state.reply_cap = sizeof(reply_space);
		state.on_remote = on_remote_big;

		ok(fzn_reasm_slot_init(&slots[0], slot_buf[0], sizeof(slot_buf[0]))
		       == FZN_REASM_OK &&
		   fzn_reasm_slot_init(&slots[1], slot_buf[1], sizeof(slot_buf[1]))
		       == FZN_REASM_OK &&
		   fzn_reasm_init(&table, slots, 2, 2u, 60u) == FZN_REASM_OK,
		   "the device's reassembly table would not initialise");

		/* A FRESH request: the previous frame's nonce is in the replay
		 * window, so re-sending it would be dropped and prove nothing. */
		frame_len = seal_request(frame, sizeof(frame), pubkey[1], cap.b,
		                         send_key, send_ckey, &hash_ops, &rng_ops,
		                         &aead_ops);
		observed.called = 0;
		ok(frame_len != 0 &&
		   fzn_udp_send(dev_udp, &node_addr, frame, frame_len) == FZN_UDP_OK,
		   "the device seals and sends a second request");
		ok(fzn_node_run_once(&state, 1000) == 1,
		   "one loop turn serves the datagram asking for a large reply");
		ok(observed.called, "the large-reply handler was reached");

		tv.tv_sec = 2;
		tv.tv_usec = 0;
		(void)setsockopt(dev_udp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		/* Four pieces, read until the message completes or the socket
		 * times out. Bounded by FZN_REASM_MAX_CHUNKS so a node that sent
		 * nothing ends the loop on the timeout rather than spinning. */
		while (done == NULL && got < FZN_REASM_MAX_CHUNKS) {
			uint8_t f[FZN_UDP_DATAGRAM_MAX];
			size_t flen2 = 0;
			fzn_opened_t o;

			if (fzn_udp_recv(dev_udp, f, sizeof(f), &flen2, NULL)
			    != FZN_UDP_OK)
				break;
			got++;
			if (fzn_seal_open(f, flen2, send_key, send_ckey, &hash_ops,
			                  &aead_ops, &o) != FZN_SEAL_OK) {
				opened_all = 0;
				break;
			}
			(void)fzn_reasm_accept(&table, o.sender, o.msg, o.index,
			                       o.chunks, o.payload, o.payload_len,
			                       0u, 1000u, &done);
		}
		ok(got == 4u,
		   "the node did not send four datagrams for a 3,230-byte reply");
		ok(opened_all, "a piece of the large reply would not open");
		ok(done != NULL,
		   "the pieces arrived and the message never completed -- which is "
		   "what all-zero indices look like from here");
		if (done)
			ok(done->bytes == sizeof(big_reply) &&
			   memcmp(done->buf, big_reply, sizeof(big_reply)) == 0,
			   "the reassembled reply is not the bytes the handler wrote");
		if (done)
			fzn_reasm_release(done);
	}

	/* AND A HANDLER THAT OVER-CLAIMS SENDS NOTHING. Without the bound the
	 * loop plans over bytes the buffer does not have. sec 363. */
	{
		struct timeval tv;
		uint8_t f[FZN_UDP_DATAGRAM_MAX];
		size_t flen2 = 0;

		state.on_remote = on_remote_overclaim;
		frame_len = seal_request(frame, sizeof(frame), pubkey[1], cap.b,
		                         send_key, send_ckey, &hash_ops, &rng_ops,
		                         &aead_ops);
		observed.called = 0;
		ok(frame_len != 0 &&
		   fzn_udp_send(dev_udp, &node_addr, frame, frame_len) == FZN_UDP_OK,
		   "the device sends a third request");
		ok(fzn_node_run_once(&state, 1000) == 1,
		   "one loop turn serves the over-claiming case");
		ok(observed.called, "the over-claiming handler was reached");

		/* Short, because the assertion is that nothing arrives and a
		 * two-second wait for silence is two seconds per run. */
		tv.tv_sec = 0;
		tv.tv_usec = 300000;
		(void)setsockopt(dev_udp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		ok(fzn_udp_recv(dev_udp, f, sizeof(f), &flen2, NULL) != FZN_UDP_OK,
		   "a handler claiming more than its buffer still had bytes sent, so "
		   "the loop planned over memory it was not given");
	}

	/* THE SAME EXCHANGE THROUGH `node/caller.h`, which is the point of sec
	 * 369: the twenty lines above -- seal, send, receive, open, feed
	 * reassembly, stop when it completes -- are what every consumer would
	 * write, and this is them written once. The node is unchanged; only
	 * the caller's side moves into the library.
	 *
	 * SEND AND RECEIVE ARE SEPARATE CALLS HERE, and that split exists
	 * because of this test. A single blocking `ask` cannot be driven
	 * against a node whose loop the same process turns by hand -- it would
	 * wait for a reply from a node that has not had its turn -- and the
	 * alternative was forking, which this suite deliberately does not do.
	 * The API a test can drive turned out to be the API a consumer with
	 * its own poll loop needs. */
	{
		fzn_caller_t caller;
		fzn_reasm_t ctable;
		fzn_partial_t cslots[2];
		static uint8_t cbuf[2][8192];
		static uint8_t answer[8192];
		size_t alen = 0;
		uint32_t asked = 0;

		state.on_remote = on_remote_big;

		ok(fzn_reasm_slot_init(&cslots[0], cbuf[0], sizeof(cbuf[0]))
		       == FZN_REASM_OK &&
		   fzn_reasm_slot_init(&cslots[1], cbuf[1], sizeof(cbuf[1]))
		       == FZN_REASM_OK &&
		   fzn_reasm_init(&ctable, cslots, 1, 1u, 60u) == FZN_REASM_OK,
		   "the caller's reassembly table would not initialise");
		/* ONE SLOT ON PURPOSE. With two, a reply that kept its slot
		 * still leaves one free and the next ask succeeds -- so the
		 * release below could not be shown to matter, and the sabotage
		 * run said so. One slot makes a leak the next ask's failure. */

		memset(&caller, 0, sizeof(caller));
		caller.fd = dev_udp;
		caller.node = node_addr;
		memcpy(caller.sender, pubkey[1], FZN_PUBKEY_LEN);
		caller.capability = cap;
		memcpy(caller.send_key, send_key, FZN_AEAD_KEY_LEN);
		memcpy(caller.send_ckey, send_ckey, FZN_COMMITMENT_KEY_LEN);
		caller.hash = &hash_ops;
		caller.aead = &aead_ops;
		caller.rng = &rng_ops;
		caller.reasm = &ctable;
		caller.next_msg = 100u;

		observed.called = 0;
		ok(fzn_caller_send(&caller, PAYLOAD, sizeof(PAYLOAD), 2000u, &asked)
		       == FZN_CALLER_OK, "the caller would not send");
		ok(asked == 100u, "the reported msg is not the one that went out");
		ok(fzn_node_run_once(&state, 1000) == 1,
		   "the node did not serve the caller's request");
		ok(observed.called, "the handler was not reached through the caller");
		ok(fzn_caller_recv(&caller, asked, answer, sizeof(answer), &alen,
		                   2000u) == FZN_CALLER_OK,
		   "the caller did not read the answer back");
		ok(alen == sizeof(big_reply) &&
		   memcmp(answer, big_reply, alen) == 0,
		   "what fzn_caller_recv returned is not the bytes the handler wrote");

		/* A REPLY THE CALLER'S BUFFER CANNOT HOLD IS REFUSED WHOLE, and
		 * the slot is released either way -- a refused answer that kept
		 * its slot would hold it until the table expired it, and the
		 * next ask would find the table full. */
		observed.called = 0;
		ok(fzn_caller_send(&caller, PAYLOAD, sizeof(PAYLOAD), 2000u, &asked)
		       == FZN_CALLER_OK, "the second send failed");
		ok(fzn_node_run_once(&state, 1000) == 1, "the node did not serve it");
		ok(fzn_caller_recv(&caller, asked, answer, 16u, &alen, 2000u)
		       == FZN_CALLER_ERR_REPLY_TOO_LONG,
		   "a reply larger than the caller's buffer was accepted");

		/* AND THE TABLE IS STILL USABLE, which is what proves the release
		 * above rather than asserting it. */
		observed.called = 0;
		ok(fzn_caller_send(&caller, PAYLOAD, sizeof(PAYLOAD), 2000u, &asked)
		       == FZN_CALLER_OK, "the third send failed");
		ok(fzn_node_run_once(&state, 1000) == 1, "the node did not serve it");
		ok(fzn_caller_recv(&caller, asked, answer, sizeof(answer), &alen,
		                   2000u) == FZN_CALLER_OK && alen == sizeof(big_reply),
		   "the ask after a refused reply failed, so the refused one kept "
		   "its reassembly slot");

		/* A LATE REPLY TO AN EARLIER QUESTION IS SKIPPED, not returned
		 * as this one's answer.
		 *
		 * THE REPLY HAS TO BE ON THE SOCKET for this to test anything.
		 * The first version asked for an unsent msg with nothing
		 * queued, so it timed out whether or not the check existed and
		 * the sabotage reported it MISSED. Here a real answer is
		 * produced and deliberately NOT collected, so recv for a
		 * different msg has something it could wrongly return. */
		observed.called = 0;
		ok(fzn_caller_send(&caller, PAYLOAD, sizeof(PAYLOAD), 2000u, &asked)
		       == FZN_CALLER_OK, "the stray-reply send failed");
		ok(fzn_node_run_once(&state, 1000) == 1, "the node did not serve it");
		ok(fzn_caller_recv(&caller, asked + 50u, answer, sizeof(answer),
		                   &alen, 200u) == FZN_CALLER_ERR_TIMEOUT,
		   "recv returned the answer to a DIFFERENT question, so a late "
		   "reply would be handed back as this one's");

		/* A CHUNKED REQUEST, END TO END. sec 370 gave the node step 8,
		 * so a request larger than a frame is planned, sent as pieces,
		 * authenticated and authorised piece by piece, and handed to the
		 * handler ONCE as a whole. */
		{
			static uint8_t big_req[2600];
			fzn_reasm_t ntable;
			fzn_partial_t nslots[2];
			static uint8_t nbuf[2][8192];
			size_t k;
			fzn_split_t rplan;

			for (k = 0; k < sizeof(big_req); k++)
				big_req[k] = (uint8_t)(k * 7u + 5u);
			ok(fzn_reasm_slot_init(&nslots[0], nbuf[0], sizeof(nbuf[0]))
			       == FZN_REASM_OK &&
			   fzn_reasm_slot_init(&nslots[1], nbuf[1], sizeof(nbuf[1]))
			       == FZN_REASM_OK &&
			   fzn_reasm_init(&ntable, nslots, 2, 2u, 60u) == FZN_REASM_OK,
			   "the node's reassembly table would not initialise");

			ok(fzn_split_plan(sizeof(big_req), FZN_SPLIT_MAX_PAYLOAD,
			                  &rplan) == FZN_SPLIT_OK && rplan.chunks == 3u,
			   "2,600 bytes did not plan as three pieces");

			/* WITHOUT A TABLE IT IS DROPPED, which is the control: a
			 * fragment is not the request anybody sent, so a node that
			 * takes no chunked requests must not hand one up. */
			state.reassembly = NULL;
			state.on_remote = on_remote_measure;
			observed.called = 0;
			ok(fzn_caller_send(&caller, big_req, sizeof(big_req), 2000u,
			                   &asked) == FZN_CALLER_OK,
			   "the chunked request would not send");
			for (k = 0; k < rplan.chunks; k++)
				(void)fzn_node_run_once(&state, 1000);
			ok(observed.called == 0,
			   "a node with no reassembly table handed a FRAGMENT to its "
			   "handler, so a partial command reaches a consumer");

			/* With one, the handler is called once, with the whole. */
			state.reassembly = &ntable;
			observed.called = 0;
			ok(fzn_caller_send(&caller, big_req, sizeof(big_req), 2000u,
			                   &asked) == FZN_CALLER_OK,
			   "the second chunked request would not send");
			for (k = 0; k < rplan.chunks; k++)
				ok(fzn_node_run_once(&state, 1000) == 1,
				   "the node did not take a piece of the request");
			ok(observed.called == 1,
			   "the handler ran a number of times other than once for one "
			   "chunked request");
			ok(observed.req_len == sizeof(big_req),
			   "the handler was handed a length other than the whole "
			   "request's");
			ok(observed.req_first == big_req[0] &&
			   observed.req_last == big_req[sizeof(big_req) - 1u],
			   "the reassembled request does not begin and end with the "
			   "bytes that were sent");
		}

		/* A DENIED CHUNKED REQUEST. Two guards meet here and neither
		 * could be reached by the granted cases above.
		 *
		 * A caller the node refuses must not be able to occupy
		 * reassembly slots by sending pieces -- so denied chunks are not
		 * reassembled -- and the handler is told ONCE, on the first
		 * piece, so it can answer a denial rather than one per chunk.
		 * And with no table at all a chunked request is dropped whole,
		 * denied or not: that is the only case where the table check is
		 * observable, because `fzn_reasm_accept` refuses a NULL table
		 * itself and the granted path returns either way. */
		{
			static uint8_t d_req[2600];
			size_t k;
			size_t saved_hops = node_peer.hop_count;

			for (k = 0; k < sizeof(d_req); k++)
				d_req[k] = (uint8_t)k;
			/* No chain: authenticated, and authorised by nothing. */
			node_peer.hop_count = 0u;
			state.on_remote = on_remote_measure;

			state.reassembly = NULL;
			observed.called = 0;
			ok(fzn_caller_send(&caller, d_req, sizeof(d_req), 2000u, &asked)
			       == FZN_CALLER_OK, "the denied chunked send failed");
			for (k = 0; k < 3u; k++)
				(void)fzn_node_run_once(&state, 1000);
			ok(observed.called == 0,
			   "a chunked request reached the handler with no table, so a "
			   "node that takes no chunked requests answers a fragment");

			{
				fzn_reasm_t dtable;
				fzn_partial_t dslots[2];
				static uint8_t dbuf[2][8192];

				ok(fzn_reasm_slot_init(&dslots[0], dbuf[0], sizeof(dbuf[0]))
				       == FZN_REASM_OK &&
				   fzn_reasm_slot_init(&dslots[1], dbuf[1], sizeof(dbuf[1]))
				       == FZN_REASM_OK &&
				   fzn_reasm_init(&dtable, dslots, 2, 2u, 60u)
				       == FZN_REASM_OK, "the denial table would not init");
				state.reassembly = &dtable;
				observed.called = 0;
				ok(fzn_caller_send(&caller, d_req, sizeof(d_req), 2000u,
				                   &asked) == FZN_CALLER_OK,
				   "the second denied chunked send failed");
				for (k = 0; k < 3u; k++)
					(void)fzn_node_run_once(&state, 1000);
				ok(observed.called == 1,
				   "a denied chunked request did not tell the handler "
				   "exactly once -- either it was reassembled, which lets "
				   "a refused caller fill the table, or it answered per "
				   "piece");
				ok(observed.result == FZN_NODE_REMOTE_DENIED,
				   "the handler was told something other than denied");
				/* THE DISCRIMINATOR, and the count above is not it.
				 * If denied pieces WERE reassembled the handler would
				 * still be called exactly once -- on the last piece,
				 * with the whole message -- so `called == 1` passes
				 * either way and the sabotage said so. What separates
				 * them is WHAT it was handed: the first piece alone,
				 * or the reassembled request a refused caller was
				 * allowed to build. */
				ok(observed.req_len > 0u &&
				   observed.req_len < sizeof(d_req),
				   "a denied caller's pieces were reassembled -- the "
				   "handler saw the whole request, so a refused peer can "
				   "fill the table by sending chunks");
				ok(fzn_reasm_held_by(&dtable, caller.sender) == 0,
				   "a refused caller's pieces occupy reassembly slots");
			}
			node_peer.hop_count = saved_hops;
			state.reassembly = NULL;
		}

		/* Past what a receiver will reassemble is refused rather than
		 * planned: fzn_split_plan caps the count, and a request that
		 * cannot be planned is one that cannot arrive. */
		{
			static uint8_t oversize[(FZN_SPLIT_MAX_PAYLOAD *
			                         FZN_REASM_MAX_CHUNKS) + 1u];

			ok(fzn_caller_send(&caller, oversize, sizeof(oversize), 2000u,
			                   &asked) == FZN_CALLER_ERR_REQUEST_TOO_LONG,
			   "a request past the reassembly ceiling was sent, so its "
			   "failure would arrive as a timeout rather than its own");
		}
		ok(fzn_caller_err_str((fzn_caller_err_t)-99) != NULL,
		   "an error value outside the enum rendered as NULL");
	}

	fzn_udp_close(node_udp);
	fzn_udp_close(dev_udp);
	for (h = 0; h < 2u; h++)
		fzn_agree_secret_wipe(&sk[h]);

	printf("node_provision_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
