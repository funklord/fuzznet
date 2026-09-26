/* node/pair.h under real Monocypher: a node pairs a device, and the pairing
 * holds on BOTH sides. sec 376.
 *
 * WHAT IS ASSERTED IS THE RELATIONSHIP, not the pieces. `provision_test`
 * already shows each step works; what this adds is that the steps as composed
 * leave a device holding keys that ARE the node's receive keys for it, a card
 * whose root IS the node, and a grant the NODE'S OWN authorisation check
 * accepts for the capability its remote hop requires -- and refuses for
 * another, which is the control that makes the acceptance mean something.
 * `fuzznetd` required an all-zero capability for weeks with every piece
 * passing its own test; this is the test that would have seen it.
 *
 * Two nodes, each with an identity from `node/identity.h` over an in-memory
 * store, so the fixture is built the way a real node builds itself.
 */

#include "../pair.h"
#include "../revoke.h"
#include "../admin.h"
#include "../../provision/provision.h"
#include "../identity.h"
#include "../node.h"
#include "../peer_persist.h"
#include "../../chain/service.h"
#include "../../constant_time/constant_time.h"
#include "../../chain/sign_monocypher.h"
#include "../../session/aead_monocypher.h"
#include "../../session/agree_monocypher.h"
#include "../../session/hash_monocypher.h"
#include "../../session/random_system.h"
#include "../serve.h"
#include "../caller.h"
#include "../../net/udp.h"
#include "../../chunk/reassembly.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL pair_test.c:%d: %s\n", line, what);
	}
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

/* ---- an in-memory store that can list, since loading peers needs it -- */

#define SLOTS 8
#define ENTRIES 4

struct mem_entry {
	int used;
	fzn_persist_slot_t slot;
	int has_subject;
	uint8_t subject[FZN_PUBKEY_LEN];
	uint8_t bytes[FZN_NODE_PEER_BLOB_MAX];
	size_t len;
};

struct mem_store {
	struct mem_entry e[SLOTS * ENTRIES];
	unsigned saves;
	int refuse_saves;
};

static struct mem_entry *find(struct mem_store *m, fzn_persist_slot_t slot,
                              const uint8_t *subject, int make)
{
	size_t i;
	struct mem_entry *free_one = NULL;

	for (i = 0; i < sizeof(m->e) / sizeof(m->e[0]); i++) {
		struct mem_entry *x = &m->e[i];

		if (!x->used) {
			if (!free_one)
				free_one = x;
			continue;
		}
		if (x->slot == slot && x->has_subject == (subject != NULL)
		    && (!subject || memcmp(x->subject, subject, FZN_PUBKEY_LEN) == 0))
			return x;
	}
	if (!make || !free_one)
		return NULL;
	memset(free_one, 0, sizeof(*free_one));
	free_one->used = 1;
	free_one->slot = slot;
	free_one->has_subject = subject != NULL;
	if (subject)
		memcpy(free_one->subject, subject, FZN_PUBKEY_LEN);
	return free_one;
}

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	struct mem_entry *x = find((struct mem_store *)ctx, slot, subject, 0);

	if (!x || x->len > cap)
		return 0;
	memcpy(out, x->bytes, x->len);
	*len = x->len;
	return 1;
}

static int mem_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                    const uint8_t *bytes, size_t len)
{
	struct mem_store *m = (struct mem_store *)ctx;
	struct mem_entry *x;

	if (m->refuse_saves || len > sizeof(x->bytes))
		return 0;
	x = find(m, slot, subject, 1);
	if (!x)
		return 0;
	memcpy(x->bytes, bytes, len);
	x->len = len;
	m->saves++;
	return 1;
}

static int mem_list(void *ctx, fzn_persist_slot_t slot, uint8_t *out, size_t max,
                    size_t *count)
{
	struct mem_store *m = (struct mem_store *)ctx;
	size_t i, n = 0;

	for (i = 0; i < sizeof(m->e) / sizeof(m->e[0]); i++) {
		if (!m->e[i].used || m->e[i].slot != slot || !m->e[i].has_subject)
			continue;
		if (n >= max)
			return 0;
		memcpy(out + (n * FZN_PUBKEY_LEN), m->e[i].subject, FZN_PUBKEY_LEN);
		n++;
	}
	*count = n;
	return 1;
}

static unsigned peers_held(struct mem_store *m)
{
	size_t i;
	unsigned n = 0;

	for (i = 0; i < sizeof(m->e) / sizeof(m->e[0]); i++)
		if (m->e[i].used && m->e[i].slot == FZN_PERSIST_NODE_PEER)
			n++;
	return n;
}

/* ---- one node: its store, its signer, its identity -------------------- */

struct node {
	struct mem_store store;
	fzn_persist_ops_t ops;
	fzn_sign_monocypher_t signer;
	fzn_sign_ops_t sign;
	fzn_sign_seat_t seat;
	fzn_agree_secret_t agree_secret;
	fzn_trust_t trust;
	fzn_node_identity_t id;
};

static fzn_hash_ops_t hash_ops;
static fzn_agree_ops_t agree_ops;
static fzn_random_ops_t rng_ops;

static int node_up(struct node *n)
{
	fzn_node_identity_env_t env;

	memset(n, 0, sizeof(*n));
	n->ops.load = mem_load;
	n->ops.save = mem_save;
	n->ops.list = mem_list;
	n->ops.ctx = &n->store;
	fzn_sign_monocypher_init(&n->sign, &n->signer);
	fzn_sign_monocypher_seat_init(&n->seat, &n->signer);
	fzn_trust_init(&n->trust);
	env.store = &n->ops;
	env.rng = &rng_ops;
	env.seat = &n->seat;
	env.sign = &n->sign;
	env.hash = &hash_ops;
	env.agree = &agree_ops;
	env.log = NULL;
	return fzn_node_identity_create(&env, 1000u, &n->agree_secret, &n->trust, &n->id)
	       == FZN_NODE_IDENTITY_OK;
}

static fzn_authz_verdict_t node_decides(const struct node *n, const fzn_cap_id_t *required,
                                        const fzn_node_peer_t *peer, uint64_t now)
{
	fzn_node_config_t config;
	fzn_chain_hop_t hops[FZN_CHAIN_MAX_HOPS];
	size_t i;

	memset(&config, 0, sizeof(config));
	config.serves_remote = 1;
	config.remote_capability = *required;
	memcpy(config.root, n->id.pubkey, FZN_PUBKEY_LEN);
	for (i = 0; i < peer->hop_count; i++)
		if (fzn_hop_open(peer->hop_bytes[i], FZN_HOP_LEN, &hops[i]) != FZN_CHAIN_OK)
			return FZN_AUTHZ_DENIED;
	return fzn_node_decide(&config, FZN_ORIGIN_REMOTE, hops, peer->hop_count, now, &n->sign,
	                       NULL, NULL);
}

/* ---- the exchange: a device asks through its stored pairing ----------- */

static const uint8_t PING[] = { 'p', 'i', 'n', 'g' };
static const uint8_t PONG[] = { 'p', 'o', 'n', 'g' };
static int handler_granted;
static int handler_denied;

static size_t answer(void *ctx, fzn_node_remote_result_t result, const fzn_opened_t *req,
                     uint8_t *reply, size_t reply_cap)
{
	(void)ctx;
	(void)req;
	if (result == FZN_NODE_REMOTE_DENIED)
		handler_denied = 1;
	if (result != FZN_NODE_REMOTE_GRANTED || reply_cap < sizeof(PONG))
		return 0;
	handler_granted = 1;
	memcpy(reply, PONG, sizeof(PONG));
	return sizeof(PONG);
}

static uint64_t fixed_clock(void)
{
	return 3000u;
}

static uint16_t port_of(int fd)
{
	struct sockaddr_storage ss;
	socklen_t len = sizeof(ss);

	if (getsockname(fd, (struct sockaddr *)&ss, &len) != 0)
		return 0;
	return ntohs(((struct sockaddr_in *)&ss)->sin_port);
}

/* THE WHOLE POINT OF PAIRING, asserted as itself: the device, holding only
 * what it stored, asks the node, holding only what IT stored, and is
 * answered. Every value on both sides came out of a store. */
static void test_paired_stores_talk(struct node *node, struct node *device,
                                    const fzn_cap_id_t *cap)
{
	static fzn_node_peer_t peers[2];
	static fzn_replay_entry_t entries[64];
	fzn_replay_window_t replay;
	fzn_node_pairing_t pairing;
	fzn_node_state_t state;
	fzn_caller_t caller;
	fzn_partial_t slots[1];
	static uint8_t slot_buf[1][2048];
	fzn_reasm_t table;
	fzn_aead_ops_t aead;
	fzn_udp_addr_t node_addr;
	uint8_t reply[FZN_NODE_REPLY_MAX];
	size_t reply_len = 0, loaded = 0;
	uint32_t msg = 0;
	int node_fd = -1, dev_fd = -1;

	fzn_aead_monocypher_init(&aead);
	CHECK(fzn_node_pairing_load(&device->ops, node->id.pubkey, &pairing) == FZN_PERSIST_OK,
	      "the device's stored pairing to the node would not load");
	CHECK(fzn_node_peers_load(&node->ops, peers, 2, &loaded) == FZN_PERSIST_OK && loaded == 1u,
	      "fixture: the node's stored peer would not load");
	CHECK(fzn_udp_bind(AF_INET, "127.0.0.1", 0, &node_fd) == FZN_UDP_OK
	              && fzn_udp_bind(AF_INET, "127.0.0.1", 0, &dev_fd) == FZN_UDP_OK
	              && fzn_udp_resolve(AF_INET, "127.0.0.1", port_of(node_fd), &node_addr)
	                         == FZN_UDP_OK,
	      "fixture: loopback sockets would not bind");
	CHECK(fzn_replay_init(&replay, entries, 64, 100000u) == FZN_FRESH_OK
	              && fzn_reasm_slot_init(&slots[0], slot_buf[0], sizeof(slot_buf[0]))
	                         == FZN_REASM_OK
	              && fzn_reasm_init(&table, slots, 1, 1u, 60u) == FZN_REASM_OK,
	      "fixture: replay window or reassembly table would not initialise");

	memset(&state, 0, sizeof(state));
	state.config.serves_remote = 1;
	state.config.remote_capability = *cap;
	memcpy(state.config.root, node->id.pubkey, FZN_PUBKEY_LEN);
	memcpy(state.node_pubkey, node->id.pubkey, FZN_PUBKEY_LEN);
	state.listen_fd = -1;
	state.udp_fd = node_fd;
	state.peers = peers;
	state.peer_count = loaded;
	state.hash = &hash_ops;
	state.aead = &aead;
	state.sign = &node->sign;
	state.rng = &rng_ops;
	state.clock = fixed_clock;
	state.replay = &replay;
	state.on_remote = answer;

	memset(&caller, 0, sizeof(caller));
	fzn_node_pairing_caller(&pairing, device->id.pubkey, &caller);
	caller.fd = dev_fd;
	caller.node = node_addr;
	caller.hash = &hash_ops;
	caller.aead = &aead;
	caller.rng = &rng_ops;
	caller.reasm = &table;
	caller.hops = 1u;

	handler_granted = 0;
	CHECK(fzn_caller_send(&caller, PING, sizeof(PING), 3500u, &msg) == FZN_CALLER_OK,
	      "the device could not send through its stored pairing");
	CHECK(fzn_node_run_once(&state, 1000) == 1, "the node did not serve the datagram");
	CHECK(handler_granted, "the node did not grant the paired device");
	CHECK(fzn_caller_recv(&caller, msg, reply, sizeof(reply), &reply_len, 2000u)
	              == FZN_CALLER_OK
	              && reply_len == sizeof(PONG) && memcmp(reply, PONG, sizeof(PONG)) == 0,
	      "the device was not answered, so the two stored halves of a pairing do not "
	      "make a working pair");

	/* ---- REVOKED: the same device, the same stored pairing, and now the
	 * node's own authorisation refuses it. sec 380. */
	{
		static fzn_revocation_t revoked_entries[8], fresh_entries[8];
		fzn_revocation_store_t revoked, fresh;
		size_t restored = 0;

		CHECK(fzn_revocation_store_init(&revoked, revoked_entries, 8) == FZN_CHAIN_OK
		              && fzn_revocation_store_init(&fresh, fresh_entries, 8) == FZN_CHAIN_OK,
		      "fixture: revocation stores");
		state.config.revocations = &revoked;
		CHECK(fzn_node_revoke(&node->id, node->id.pubkey, cap, device->id.pubkey, 3000u,
		                      &revoked, &node->ops) == FZN_NODE_REVOKE_OK,
		      "the node would not revoke the device it paired");
		CHECK(fzn_node_revoke(&node->id, node->id.pubkey, cap, device->id.pubkey, 3001u,
		                      &revoked, &node->ops) == FZN_NODE_REVOKE_ALREADY,
		      "revoking twice was not reported as already revoked");

		handler_granted = handler_denied = 0;
		CHECK(fzn_caller_send(&caller, PING, sizeof(PING), 3500u, &msg) == FZN_CALLER_OK
		              && fzn_node_run_once(&state, 1000) == 1,
		      "fixture: the revoked device's request was not served at all");
		CHECK(handler_denied && !handler_granted,
		      "a revoked device was granted: the node's decision does not consult the "
		      "revocations it holds");

		/* ---- AND IT SURVIVES A RESTART: a fresh store, filled only from
		 * what the node saved. */
		CHECK(fzn_node_revocations_load(&node->ops, &fresh, node->id.pubkey, &node->sign,
		                                &hash_ops, &restored) == FZN_PERSIST_OK
		              && restored == 1u,
		      "the node's revocation did not come back from its store");
		state.config.revocations = &fresh;
		handler_granted = handler_denied = 0;
		CHECK(fzn_caller_send(&caller, PING, sizeof(PING), 3500u, &msg) == FZN_CALLER_OK
		              && fzn_node_run_once(&state, 1000) == 1 && handler_denied
		              && !handler_granted,
		      "after a restart the node granted a device it had revoked");

		/* ---- THE CONTROL: the same node with no revocations grants it,
		 * so the refusals above were the revocation's. */
		state.config.revocations = NULL;
		handler_granted = handler_denied = 0;
		CHECK(fzn_caller_send(&caller, PING, sizeof(PING), 3500u, &msg) == FZN_CALLER_OK
		              && fzn_node_run_once(&state, 1000) == 1 && handler_granted,
		      "the control failed: without revocations the device was not granted, so "
		      "the refusals above prove nothing about revocation");
		(void)fzn_caller_recv(&caller, msg, reply, sizeof(reply), &reply_len, 500u);
	}

	/* ---- FUZZNET'S VERBS OVER THE REMOTE HOP, through the admin handler:
	 * the same grammar a local caller uses, read-only. sec 381. */
	{
		fzn_node_admin_t admin;
		char key[(FZN_PUBKEY_LEN * 2u) + 1u];
		char want[96];
		size_t k;
		const uint8_t *detail = NULL;
		size_t detail_len = 0;

		memset(&admin, 0, sizeof(admin));
		admin.state = &state;
		admin.peers = peers;
		admin.peers_cap = 2;
		admin.id = &node->id;
		admin.store = &node->ops;
		state.on_remote = fzn_node_admin_remote;
		state.on_remote_ctx = &admin;
		state.config.revocations = NULL;

		CHECK(fzn_caller_send(&caller, (const uint8_t *)"status", 6u, 3500u, &msg)
		              == FZN_CALLER_OK
		              && fzn_node_run_once(&state, 1000) == 1
		              && fzn_caller_recv(&caller, msg, reply, sizeof(reply), &reply_len, 2000u)
		                         == FZN_CALLER_OK
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK,
		      "a paired device asking status over the remote hop was not answered ok");

		for (k = 0; k < FZN_PUBKEY_LEN; k++)
			snprintf(key + (k * 2u), 3, "%02x", device->id.pubkey[k]);
		snprintf(want, sizeof(want), "ok 1 0 %s\n", key);
		CHECK(fzn_caller_send(&caller, (const uint8_t *)"list peer", 9u, 3500u, &msg)
		              == FZN_CALLER_OK
		              && fzn_node_run_once(&state, 1000) == 1
		              && fzn_caller_recv(&caller, msg, reply, sizeof(reply), &reply_len, 2000u)
		                         == FZN_CALLER_OK
		              && reply_len == strlen(want) && memcmp(reply, want, reply_len) == 0,
		      "list peer over the remote hop did not return the paired device, or did not "
		      "fit the remote path's reply buffer");

		CHECK(fzn_caller_send(&caller, (const uint8_t *)"remove peer 00", 14u, 3500u, &msg)
		              == FZN_CALLER_OK
		              && fzn_node_run_once(&state, 1000) == 1
		              && fzn_caller_recv(&caller, msg, reply, sizeof(reply), &reply_len, 2000u)
		                         == FZN_CALLER_OK
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_DENIED
		              && state.peer_count == 1u,
		      "a remote caller was allowed to change the node");
		/* ---- A REVOKED DEVICE HEARS NOTHING: the node calls the handler
		 * for DENIED too, and answering would tell a refused caller which
		 * node it reached. */
		{
			static fzn_revocation_t again_entries[4];
			fzn_revocation_store_t again;
			size_t restored = 0;

			CHECK(fzn_revocation_store_init(&again, again_entries, 4) == FZN_CHAIN_OK
			              && fzn_node_revocations_load(&node->ops, &again, node->id.pubkey,
			                                           &node->sign, &hash_ops, &restored)
			                         == FZN_PERSIST_OK
			              && restored == 1u,
			      "fixture: the device's revocation did not restore");
			state.config.revocations = &again;
			CHECK(fzn_caller_send(&caller, (const uint8_t *)"status", 6u, 3500u, &msg)
			              == FZN_CALLER_OK
			              && fzn_node_run_once(&state, 1000) == 1
			              && fzn_caller_recv(&caller, msg, reply, sizeof(reply), &reply_len,
			                                 300u)
			                         == FZN_CALLER_ERR_TIMEOUT,
			      "a revoked device was answered over the remote hop");
			state.config.revocations = NULL;
		}
		state.on_remote = answer;
		state.on_remote_ctx = NULL;
	}

	/* ---- A NODE THAT IS NOT ITS OWN ROOT DOES NOT REVOKE AS ONE. */
	{
		static fzn_revocation_t rs_entries[2];
		fzn_revocation_store_t rs;

		CHECK(fzn_revocation_store_init(&rs, rs_entries, 2) == FZN_CHAIN_OK
		              && fzn_node_revoke(&device->id, node->id.pubkey, cap, node->id.pubkey,
		                                 3000u, &rs, &device->ops)
		                         == FZN_NODE_REVOKE_NOT_ROOT,
		      "a node revoked under a root that is not its own key");
	}

	fzn_wipe(&pairing, sizeof(pairing));
	fzn_wipe(&caller, sizeof(caller));
	fzn_udp_close(node_fd);
	fzn_udp_close(dev_fd);
}

int main(void)
{
	static struct node node, device, stranger;
	fzn_prekey_record_t device_record;
	fzn_cap_id_t cap, other;
	uint8_t card[FZN_PROVISION_LEN_TOTAL];
	size_t card_len = 0;
	uint8_t send_key[FZN_AEAD_KEY_LEN], send_ckey[FZN_COMMITMENT_KEY_LEN];
	uint8_t root[FZN_PUBKEY_LEN];
	fzn_chain_hop_t device_hop;
	static fzn_node_peer_t peers[2];
	size_t loaded = 0;

	fzn_hash_monocypher_init(&hash_ops);
	fzn_agree_monocypher_init(&agree_ops);
	fzn_random_system_init(&rng_ops);

	CHECK(node_up(&node) && node_up(&device) && node_up(&stranger),
	      "fixture: three nodes would not come up");
	CHECK(fzn_prekey_open(device.id.prekey_record, FZN_PREKEY_LEN_TOTAL, &device_record)
	              == FZN_PREKEY_OK,
	      "fixture: the device's prekey record does not open");
	CHECK(fzn_service_capability(7u, 3u, NULL, 0, &hash_ops, &cap) == FZN_CHAIN_OK
	              && fzn_service_capability(7u, 4u, NULL, 0, &hash_ops, &other) == FZN_CHAIN_OK,
	      "fixture: capabilities would not derive");

	/* ---- THE PAIRING. */
	node.store.saves = 0;
	CHECK(fzn_node_pair(&node.id, node.id.pubkey, &cap, &node.ops, device_record, 2000u,
	                    2000u + 86400u, card, sizeof(card), &card_len) == FZN_NODE_PAIR_OK,
	      "a node would not pair a device");
	CHECK(card_len == FZN_PROVISION_LEN_TOTAL, "the card is not a whole card");

	/* ---- THE DEVICE'S SIDE: it accepts, and the root it learns is the node. */
	CHECK(fzn_node_accept_card(&device.id, card, card_len, 2100u, send_key, send_ckey, root,
	                           &device_hop) == FZN_NODE_PROVISION_OK,
	      "the device refused the node's card");
	CHECK(memcmp(root, node.id.pubkey, FZN_PUBKEY_LEN) == 0,
	      "the card names a root that is not the node");

	/* ---- THE NODE'S SIDE, read back through the loader the daemon uses. */
	CHECK(fzn_node_peers_load(&node.ops, peers, 2, &loaded) == FZN_PERSIST_OK && loaded == 1u,
	      "the node does not hold exactly one peer after pairing one device");
	CHECK(memcmp(peers[0].sender, device.id.pubkey, FZN_PUBKEY_LEN) == 0,
	      "the saved peer is not the device");
	CHECK(memcmp(peers[0].recv_key, send_key, FZN_AEAD_KEY_LEN) == 0
	              && memcmp(peers[0].recv_ckey, send_ckey, FZN_COMMITMENT_KEY_LEN) == 0,
	      "the device's send keys are not the node's receive keys for it, so nothing "
	      "the device seals will open");

	/* ---- AND THE NODE'S OWN CHECK GRANTS IT, for this capability only. */
	CHECK(node_decides(&node, &cap, &peers[0], 3000u) == FZN_AUTHZ_GRANTED_BY_CHAIN,
	      "the node's own authorisation check refuses the device it just paired");
	CHECK(node_decides(&node, &other, &peers[0], 3000u) == FZN_AUTHZ_DENIED,
	      "the control: the paired device was granted a capability it was not given");

	/* ---- THE DEVICE KEEPS ITS HALF, and a stranger cannot take it. */
	{
		fzn_node_pairing_t kept, back;
		uint8_t blob[FZN_NODE_PAIRING_BLOB_LEN];
		size_t blob_len = 0;

		stranger.store.saves = 0;
		CHECK(fzn_node_pairing_accept(&stranger.id, card, card_len, 2100u, &stranger.ops,
		                              &kept) == FZN_NODE_PAIR_REFUSED,
		      "a node accepted a card made for another device");
		CHECK(stranger.store.saves == 0u, "a refused card was saved");

		device.store.saves = 0;
		CHECK(fzn_node_pairing_accept(&device.id, card, card_len, 2100u, &device.ops, &kept)
		              == FZN_NODE_PAIR_OK,
		      "the device would not accept the node's card");
		CHECK(device.store.saves == 1u, "accepting did not store exactly one pairing");
		CHECK(memcmp(kept.root, node.id.pubkey, FZN_PUBKEY_LEN) == 0
		              && memcmp(kept.capability.b, cap.b, FZN_CAP_ID_LEN) == 0
		              && memcmp(kept.send_key, send_key, FZN_AEAD_KEY_LEN) == 0,
		      "the stored pairing is not the node, the grant and the session accepted");
		CHECK(fzn_node_pairing_load(&device.ops, node.id.pubkey, &back) == FZN_PERSIST_OK
		              && memcmp(&back, &kept, sizeof(back)) == 0,
		      "the pairing did not come back as it was stored");

		/* THE BYTES, AT THE OFFSETS persist.situ STATES: root at 2,
		 * capability at 34, keys at 66 and 98, hop at 130. */
		CHECK(fzn_node_pairing_pack(&kept, blob, sizeof(blob), &blob_len) == FZN_PERSIST_OK
		              && blob_len == 309u && blob[0] == 1u && blob[1] == 7u
		              && memcmp(blob + 2, kept.root, 32) == 0
		              && memcmp(blob + 34, kept.capability.b, 32) == 0
		              && memcmp(blob + 66, kept.send_key, 32) == 0
		              && memcmp(blob + 98, kept.send_ckey, 32) == 0
		              && memcmp(blob + 130, kept.hop, FZN_HOP_LEN) == 0,
		      "the pairing blob is not laid out as persist.situ describes it");

		/* TWO COPIES OF THE CAPABILITY MUST AGREE, or the blob has two
		 * encodings. */
		blob[34] ^= 0x01u;
		CHECK(fzn_node_pairing_open(blob, blob_len, &back) == FZN_PERSIST_ERR_SHAPE,
		      "a pairing whose capability disagrees with its own hop opened");
		blob[34] ^= 0x01u;

		/* FILED UNDER ONE NODE AND NAMING ANOTHER is refused. */
		CHECK(mem_save(&device.store, FZN_PERSIST_PAIRED_NODE, stranger.id.pubkey, blob,
		               blob_len)
		              && fzn_node_pairing_load(&device.ops, stranger.id.pubkey, &back)
		                         == FZN_PERSIST_ERR_SHAPE,
		      "a pairing filed under one node and naming another loaded");
		fzn_wipe(&kept, sizeof(kept));
		fzn_wipe(&back, sizeof(back));
	}

	test_paired_stores_talk(&node, &device, &cap);

	/* ---- A NODE THAT IS NOT ITS OWN ROOT PAIRS NOTHING, and writes nothing. */
	stranger.store.saves = 0;
	CHECK(fzn_node_pair(&stranger.id, node.id.pubkey, &cap, &stranger.ops, device_record,
	                    2000u, 0u, card, sizeof(card), &card_len) == FZN_NODE_PAIR_NOT_ROOT,
	      "a node whose root is another key paired a device");
	CHECK(stranger.store.saves == 0u && peers_held(&stranger.store) == 0u && card_len == 0u,
	      "a refused pairing saved a peer or left a card");

	/* ---- A PREKEY THAT DOES NOT VERIFY PAIRS NOTHING. */
	{
		uint8_t forged[FZN_PREKEY_LEN_TOTAL];
		fzn_prekey_record_t forged_record;

		memcpy(forged, device.id.prekey_record, sizeof(forged));
		forged[FZN_PREKEY_LEN_TOTAL - 1u] ^= 0x01u;
		CHECK(fzn_prekey_open(forged, sizeof(forged), &forged_record) == FZN_PREKEY_OK,
		      "fixture: the forged record no longer opens, so the case is about shape");
		stranger.store.saves = 0;
		CHECK(fzn_node_pair(&stranger.id, stranger.id.pubkey, &cap, &stranger.ops,
		                    forged_record, 2000u, 0u, card, sizeof(card), &card_len)
		              == FZN_NODE_PAIR_DEVICE,
		      "a device whose prekey signature is broken was paired");
		CHECK(stranger.store.saves == 0u && card_len == 0u,
		      "a refused device was saved or given a card");
	}

	/* ---- A STORE THAT REFUSES GETS NO CARD: no card for a device the node
	 * does not hold. */
	stranger.store.refuse_saves = 1;
	CHECK(fzn_node_pair(&stranger.id, stranger.id.pubkey, &cap, &stranger.ops, device_record,
	                    2000u, 0u, card, sizeof(card), &card_len) == FZN_NODE_PAIR_STORE,
	      "a pairing the store refused was reported as anything but the store's");
	CHECK(card_len == 0u, "a card was made for a device the node could not save");

	CHECK(fzn_node_pair(NULL, node.id.pubkey, &cap, &node.ops, device_record, 1u, 0u, card,
	                    sizeof(card), &card_len) == FZN_NODE_PAIR_MALFORMED,
	      "a null identity was accepted");
	CHECK(strcmp(fzn_node_pair_err_str(FZN_NODE_PAIR_STORE),
	             fzn_node_pair_err_str(FZN_NODE_PAIR_CARD)) != 0,
	      "two refusals share a sentence");

	fzn_sign_monocypher_wipe(&node.signer);
	fzn_sign_monocypher_wipe(&device.signer);
	fzn_sign_monocypher_wipe(&stranger.signer);
	printf("pair_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
