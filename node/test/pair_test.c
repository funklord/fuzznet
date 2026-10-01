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
#include "../roots.h"
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

/* A shelf's remote hook that knows one message: version byte 1. sec 424. */
static size_t text_remote_stub(void *ctx, const uint8_t *request, size_t request_len,
                               uint8_t *reply, size_t reply_cap)
{
	(void)ctx;
	if (request_len < 1u || request[0] != 1u || reply_cap < 4u)
		return 0;
	memcpy(reply, "blob", 4u);
	return 4u;
}

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
		CHECK(fzn_node_revoke(&node->id, node->id.pubkey, NULL, cap, device->id.pubkey, 3000u,
		                      &revoked, &node->ops) == FZN_NODE_REVOKE_OK,
		      "the node would not revoke the device it paired");
		CHECK(fzn_node_revoke(&node->id, node->id.pubkey, NULL, cap, device->id.pubkey, 3001u,
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
		CHECK(fzn_node_revocations_load(&node->ops, &fresh, node->id.pubkey, NULL, NULL, &node->sign,
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
		/* A BLOB MESSAGE REACHES THE SHELF'S HOOK, and a verb still
		 * reaches the verbs past it. sec 424. */
		{
			static const uint8_t blob_message[2] = { 1u, 1u };

			admin.text_remote = text_remote_stub;
			CHECK(fzn_caller_send(&caller, blob_message, sizeof(blob_message), 3500u, &msg)
			              == FZN_CALLER_OK
			              && fzn_node_run_once(&state, 1000) == 1
			              && fzn_caller_recv(&caller, msg, reply, sizeof(reply), &reply_len,
			                                 2000u) == FZN_CALLER_OK
			              && reply_len == 4u && memcmp(reply, "blob", 4u) == 0,
			      "a blob message over the remote hop did not reach the shelf's hook");
			CHECK(fzn_caller_send(&caller, (const uint8_t *)"status", 6u, 3500u, &msg)
			              == FZN_CALLER_OK
			              && fzn_node_run_once(&state, 1000) == 1
			              && fzn_caller_recv(&caller, msg, reply, sizeof(reply), &reply_len,
			                                 2000u) == FZN_CALLER_OK
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_OK,
			      "with the shelf's hook set, a verb over the remote hop was not answered");
			admin.text_remote = NULL;
		}
		/* ---- A REVOKED DEVICE HEARS NOTHING: the node calls the handler
		 * for DENIED too, and answering would tell a refused caller which
		 * node it reached. */
		{
			static fzn_revocation_t again_entries[4];
			fzn_revocation_store_t again = { 0 };
			size_t restored = 0;

			CHECK(fzn_revocation_store_init(&again, again_entries, 4) == FZN_CHAIN_OK
			              && fzn_node_revocations_load(&node->ops, &again, node->id.pubkey, NULL, NULL,
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
		fzn_revocation_store_t rs = { 0 };

		CHECK(fzn_revocation_store_init(&rs, rs_entries, 2) == FZN_CHAIN_OK
		              && fzn_node_revoke(&device->id, node->id.pubkey, NULL, cap, node->id.pubkey,
		                                 3000u, &rs, &device->ops)
		                         == FZN_NODE_REVOKE_NOT_ROOT,
		      "a node revoked under a root that is not its own key");
	}

	fzn_wipe(&pairing, sizeof(pairing));
	fzn_wipe(&caller, sizeof(caller));
	fzn_udp_close(node_fd);
	fzn_udp_close(dev_fd);
}

/* ---- one request, one answer: is `device` granted by `server` under
 * `root`? 1 granted, 0 denied, -1 when the exchange itself failed. Every value
 * on both sides comes out of the two nodes' stores. */
static int granted_by(struct node *server, const uint8_t root[FZN_PUBKEY_LEN],
                      struct node *device, const fzn_cap_id_t *cap,
                      const fzn_revocation_store_t *revocations)
{
	static fzn_node_peer_t peers[4];
	static fzn_replay_entry_t entries[16];
	fzn_replay_window_t replay;
	fzn_node_pairing_t pairing;
	fzn_node_state_t state;
	fzn_caller_t caller;
	fzn_partial_t slots[1];
	static uint8_t slot_buf[1][2048];
	fzn_reasm_t table;
	fzn_aead_ops_t aead;
	fzn_udp_addr_t addr;
	uint32_t msg = 0;
	size_t loaded = 0;
	int sfd = -1, dfd = -1, result = -1;

	fzn_aead_monocypher_init(&aead);
	if (fzn_node_pairing_load(&device->ops, server->id.pubkey, &pairing) != FZN_PERSIST_OK
	    || fzn_node_peers_load(&server->ops, peers, 4, &loaded) != FZN_PERSIST_OK
	    || fzn_udp_bind(AF_INET, "127.0.0.1", 0, &sfd) != FZN_UDP_OK
	    || fzn_udp_bind(AF_INET, "127.0.0.1", 0, &dfd) != FZN_UDP_OK
	    || fzn_udp_resolve(AF_INET, "127.0.0.1", port_of(sfd), &addr) != FZN_UDP_OK
	    || fzn_replay_init(&replay, entries, 16, 100000u) != FZN_FRESH_OK
	    || fzn_reasm_slot_init(&slots[0], slot_buf[0], sizeof(slot_buf[0])) != FZN_REASM_OK
	    || fzn_reasm_init(&table, slots, 1, 1u, 60u) != FZN_REASM_OK)
		goto out;

	memset(&state, 0, sizeof(state));
	state.config.serves_remote = 1;
	state.config.remote_capability = *cap;
	state.config.revocations = revocations;
	memcpy(state.config.root, root, FZN_PUBKEY_LEN);
	memcpy(state.node_pubkey, server->id.pubkey, FZN_PUBKEY_LEN);
	state.listen_fd = -1;
	state.udp_fd = sfd;
	state.peers = peers;
	state.peer_count = loaded;
	state.hash = &hash_ops;
	state.aead = &aead;
	state.sign = &server->sign;
	state.rng = &rng_ops;
	state.clock = fixed_clock;
	state.replay = &replay;
	state.on_remote = answer;

	memset(&caller, 0, sizeof(caller));
	fzn_node_pairing_caller(&pairing, device->id.pubkey, &caller);
	caller.fd = dfd;
	caller.node = addr;
	caller.hash = &hash_ops;
	caller.aead = &aead;
	caller.rng = &rng_ops;
	caller.reasm = &table;
	caller.hops = 1u;

	handler_granted = handler_denied = 0;
	if (fzn_caller_send(&caller, PING, sizeof(PING), 3500u, &msg) == FZN_CALLER_OK
	    && fzn_node_run_once(&state, 1000) == 1)
		result = handler_granted ? 1 : (handler_denied ? 0 : -1);
	fzn_wipe(&caller, sizeof(caller));
out:
	fzn_wipe(&pairing, sizeof(pairing));
	if (sfd >= 0)
		fzn_udp_close(sfd);
	if (dfd >= 0)
		fzn_udp_close(dfd);
	return result;
}

/* THE ROOT ANSWERS A MEMBER'S PULL: R serves `fzn_node_admin_remote` over
 * the remote hop, and N asks `get revocation` page by page through the
 * pairing it joined with, absorbing each answer. The loop is turned by hand
 * -- send, one turn of R, receive, absorb -- which is what
 * `fzn_node_revocations_absorb` is split out for. The pull err, or -99 when
 * the fixture failed. */
static int pulled_from_as(struct node *root, struct node *member, const fzn_cap_id_t *cap,
                          fzn_revocation_store_t *member_revs, size_t *learned,
                          fzn_node_vote_pull_t *votes, fzn_node_roots_t *roots)
{
	static fzn_node_peer_t peers[4];
	static fzn_replay_entry_t entries[16];
	static uint8_t reply[FZN_REPLY_MAX + 1u];
	fzn_replay_window_t replay;
	fzn_node_pairing_t pairing;
	fzn_node_state_t state;
	fzn_node_admin_t admin;
	fzn_caller_t caller;
	fzn_partial_t slots[1];
	static uint8_t slot_buf[1][2048];
	fzn_reasm_t table;
	fzn_aead_ops_t aead;
	fzn_udp_addr_t addr;
	size_t loaded = 0, from = 0, pages = 0;
	int sfd = -1, dfd = -1, result = -99;

	*learned = 0;
	fzn_aead_monocypher_init(&aead);
	if (fzn_node_pairing_load(&member->ops, root->id.pubkey, &pairing) != FZN_PERSIST_OK
	    || fzn_node_peers_load(&root->ops, peers, 4, &loaded) != FZN_PERSIST_OK
	    || fzn_udp_bind(AF_INET, "127.0.0.1", 0, &sfd) != FZN_UDP_OK
	    || fzn_udp_bind(AF_INET, "127.0.0.1", 0, &dfd) != FZN_UDP_OK
	    || fzn_udp_resolve(AF_INET, "127.0.0.1", port_of(sfd), &addr) != FZN_UDP_OK
	    || fzn_replay_init(&replay, entries, 16, 100000u) != FZN_FRESH_OK
	    || fzn_reasm_slot_init(&slots[0], slot_buf[0], sizeof(slot_buf[0])) != FZN_REASM_OK
	    || fzn_reasm_init(&table, slots, 1, 1u, 60u) != FZN_REASM_OK)
		goto out;

	memset(&state, 0, sizeof(state));
	state.config.serves_remote = 1;
	state.config.remote_capability = *cap;
	memcpy(state.config.root, root->id.pubkey, FZN_PUBKEY_LEN);
	memcpy(state.node_pubkey, root->id.pubkey, FZN_PUBKEY_LEN);
	state.listen_fd = -1;
	state.udp_fd = sfd;
	state.peers = peers;
	state.peer_count = loaded;
	state.hash = &hash_ops;
	state.aead = &aead;
	state.sign = &root->sign;
	state.rng = &rng_ops;
	state.clock = fixed_clock;
	state.replay = &replay;
	memset(&admin, 0, sizeof(admin));
	admin.state = &state;
	admin.id = &root->id;
	admin.store = &root->ops;
	state.on_remote = fzn_node_admin_remote;
	state.on_remote_ctx = &admin;

	memset(&caller, 0, sizeof(caller));
	fzn_node_pairing_caller(&pairing, member->id.pubkey, &caller);
	caller.fd = dfd;
	caller.node = addr;
	caller.hash = &hash_ops;
	caller.aead = &aead;
	caller.rng = &rng_ops;
	caller.reasm = &table;
	caller.hops = 1u;

	while (pages++ < 8u) {
		char ask[32];
		size_t reply_len = 0, next = 0, total = 0;
		uint32_t msg = 0;
		int n = snprintf(ask, sizeof(ask),
		                 roots ? "get root %zu" : votes ? "get vote %zu" : "get revocation %zu",
		                 from);

		if (fzn_caller_send(&caller, (const uint8_t *)ask, (size_t)n, 3500u, &msg)
		            != FZN_CALLER_OK
		    || fzn_node_run_once(&state, 1000) != 1
		    || fzn_caller_recv(&caller, msg, reply, sizeof(reply), &reply_len, 1000u)
		               != FZN_CALLER_OK)
			break;
		if (roots) {
			size_t refused = 0;

			result = fzn_node_roots_absorb(roots, &member->ops, reply, reply_len, from,
			                               &next, &total, learned, &refused);
		} else if (votes) {
			result = fzn_node_votes_absorb(votes, reply, reply_len, from,
			                               root->id.pubkey, &member->sign, &hash_ops,
			                               member_revs, &member->ops, &next, &total);
			*learned = votes->learned;
		} else {
			result = fzn_node_revocations_absorb(reply, reply_len, from, root->id.pubkey,
			                                     &member->sign, &hash_ops, member_revs,
			                                     &member->ops, learned, &next, &total);
		}
		if (result != FZN_NODE_PULL_OK || next >= total)
			break;
		from = next;
	}
	fzn_wipe(&caller, sizeof(caller));
out:
	fzn_wipe(&pairing, sizeof(pairing));
	if (sfd >= 0)
		fzn_udp_close(sfd);
	if (dfd >= 0)
		fzn_udp_close(dfd);
	return result;
}

static int pulled_from(struct node *root, struct node *member, const fzn_cap_id_t *cap,
                       fzn_revocation_store_t *member_revs, size_t *learned)
{
	return pulled_from_as(root, member, cap, member_revs, learned, NULL, NULL);
}

/* A reply line `ok TOTAL FROM HEX`, for the pages a real root would not send. */
static size_t page_of(char *out, size_t cap, size_t total, size_t from,
                      const uint8_t record[FZN_REVOCATION_LEN])
{
	static const char digits[] = "0123456789abcdef";
	int n = snprintf(out, cap, "ok %zu %zu ", total, from);
	size_t at, i;

	if (n < 0 || (size_t)n + FZN_REVOCATION_LEN * 2u + 2u > cap)
		return 0;
	at = (size_t)n;
	for (i = 0; i < FZN_REVOCATION_LEN; i++) {
		out[at++] = digits[record[i] >> 4];
		out[at++] = digits[record[i] & 15u];
	}
	out[at++] = '\n';
	out[at] = '\0';
	return at;
}

/* ---- AN ESTATE OF THREE: a root R, a node N that joins it, and a device D
 * that N pairs by extending the grant R gave it. sec 383. */
static void test_an_estate(const fzn_cap_id_t *cap)
{
	static struct node r, n, d, other;
	fzn_prekey_record_t n_rec, d_rec;
	fzn_node_pairing_t joined, d_pairing;
	fzn_node_authority_t authority = { 0 };
	uint8_t card[FZN_PROVISION_MAX_LEN];
	size_t card_len = 0, loaded = 0;
	static fzn_node_peer_t n_peers[4];

	CHECK(node_up(&r) && node_up(&n) && node_up(&d) && node_up(&other),
	      "fixture: the estate's nodes would not come up");
	CHECK(fzn_prekey_open(n.id.prekey_record, FZN_PREKEY_LEN_TOTAL, &n_rec) == FZN_PREKEY_OK
	              && fzn_prekey_open(d.id.prekey_record, FZN_PREKEY_LEN_TOTAL, &d_rec)
	                         == FZN_PREKEY_OK,
	      "fixture: prekey records");

	/* ---- A GRANT THAT CANNOT BE PASSED ON IS NOT A JOIN. */
	CHECK(fzn_node_pair(&r.id, r.id.pubkey, cap, NULL, 0, &r.ops, n_rec, 1000u, 0u, card,
	                    sizeof(card), &card_len) == FZN_NODE_PAIR_OK,
	      "fixture: R would not pair N");
	CHECK(fzn_node_join(&n.id, card, card_len, 1100u, &n.ops, &n.trust, &joined)
	              == FZN_NODE_PAIR_CANNOT_JOIN
	              && fzn_trust_source_of(&n.trust) == FZN_TRUST_SELF,
	      "a node joined on a grant it cannot pass on, or the refusal moved its anchor");

	/* ---- R PAIRS N WITH A DELEGABLE GRANT, AND N JOINS. */
	CHECK(fzn_node_pair(&r.id, r.id.pubkey, cap, NULL, 1, &r.ops, n_rec, 1000u, 0u, card,
	                    sizeof(card), &card_len) == FZN_NODE_PAIR_OK,
	      "R would not pair N with a delegable grant");
	CHECK(fzn_node_join(&n.id, card, card_len, 1100u, &n.ops, &n.trust, &joined)
	              == FZN_NODE_PAIR_OK,
	      "N would not join the estate R's card names");
	CHECK(fzn_trust_source_of(&n.trust) == FZN_TRUST_PINNED
	              && memcmp(fzn_trust_root(&n.trust), r.id.pubkey, FZN_PUBKEY_LEN) == 0,
	      "after joining, N is not pinned to R");

	/* ---- ONE ESTATE ONLY: a second root's card is refused. */
	{
		fzn_prekey_record_t again;
		fzn_node_pairing_t unused;

		CHECK(fzn_prekey_open(n.id.prekey_record, FZN_PREKEY_LEN_TOTAL, &again)
		              == FZN_PREKEY_OK
		              && fzn_node_pair(&other.id, other.id.pubkey, cap, NULL, 1, &other.ops,
		                               again, 1000u, 0u, card, sizeof(card), &card_len)
		                         == FZN_NODE_PAIR_OK,
		      "fixture: a second root would not pair N");
		CHECK(fzn_node_join(&n.id, card, card_len, 1100u, &n.ops, &n.trust, &unused)
		              == FZN_NODE_PAIR_CANNOT_JOIN
		              && memcmp(fzn_trust_root(&n.trust), r.id.pubkey, FZN_PUBKEY_LEN) == 0,
		      "a node in one estate joined a second, or the refusal moved its anchor");
	}

	/* ---- AN AUTHORITY THAT CANNOT BE PASSED ON, OR IS SOMEBODY ELSE'S, GRANTS
	 * NOTHING. Hops minted directly by R, so each case fails only its own
	 * check: the first verifies and names N and is not delegable; the second
	 * verifies and is delegable and names another node. */
	{
		uint8_t hop[FZN_HOP_LEN];
		fzn_node_authority_t bad = { 0 };

		bad.hops = (const uint8_t (*)[FZN_HOP_LEN])hop;
		bad.hop_count = 1u;
		CHECK(fzn_chain_mint(r.id.pubkey, n.id.pubkey, cap, 1000u, FZN_NO_EXPIRY, 0, &r.sign,
		                     hop) == FZN_CHAIN_OK
		              && fzn_node_pair(&n.id, r.id.pubkey, cap, &bad, 0, &n.ops, d_rec, 1200u,
		                               0u, card, sizeof(card), &card_len)
		                         == FZN_NODE_PAIR_NOT_ROOT,
		      "a node extended a grant that cannot be passed on");
		CHECK(fzn_chain_mint(r.id.pubkey, other.id.pubkey, cap, 1000u, FZN_NO_EXPIRY, 1,
		                     &r.sign, hop) == FZN_CHAIN_OK
		              && fzn_node_pair(&n.id, r.id.pubkey, cap, &bad, 0, &n.ops, d_rec, 1200u,
		                               0u, card, sizeof(card), &card_len)
		                         == FZN_NODE_PAIR_NOT_ROOT,
		      "a node extended a grant that names another node");
	}

	/* ---- N PAIRS D BY EXTENDING ITS GRANT, and D pairs with N. */
	authority.hops = (const uint8_t (*)[FZN_HOP_LEN])joined.chain;
	authority.hop_count = joined.hop_count;
	/* The root a joined node passes is the one it verifies against, R; with
	 * no chain of its own to extend it has nothing to grant with. */
	CHECK(fzn_node_pair(&n.id, r.id.pubkey, cap, NULL, 0, &n.ops, d_rec, 1200u, 0u, card,
	                    sizeof(card), &card_len) == FZN_NODE_PAIR_NOT_ROOT,
	      "a node paired under a root that is not its key, with no chain to extend");
	CHECK(fzn_node_pair(&n.id, r.id.pubkey, cap, &authority, 0, &n.ops, d_rec, 1200u, 0u,
	                    card, sizeof(card), &card_len) == FZN_NODE_PAIR_OK,
	      "N would not pair D through the grant R gave it");
	CHECK(fzn_node_pairing_accept(&d.id, card, card_len, 1300u, &d.ops, &d_pairing)
	              == FZN_NODE_PAIR_OK
	              && memcmp(d_pairing.node, n.id.pubkey, FZN_PUBKEY_LEN) == 0,
	      "D would not accept N's card, or the card does not name N");
	CHECK(fzn_node_peers_load(&n.ops, n_peers, 4, &loaded) == FZN_PERSIST_OK && loaded == 1u
	              && n_peers[0].hop_count == 2u,
	      "N does not hold D with the whole chain R -> N -> D");

	/* ---- AND N SERVES D UNDER R's ROOT, while R's revocation of D is what
	 * stops it -- the estate's authority reaching a node it did not pair. */
	CHECK(granted_by(&n, r.id.pubkey, &d, cap, NULL) == 1,
	      "N, verifying against R, did not grant the device it paired through R's grant");
	{
		static fzn_revocation_t entries[4];
		fzn_revocation_store_t revoked = { 0 };
		uint8_t record[FZN_REVOCATION_LEN];
		fzn_revocation_record_t rec;

		CHECK(fzn_revocation_store_init(&revoked, entries, 4) == FZN_CHAIN_OK
		              && fzn_revocation_issue(r.id.pubkey, cap, d.id.pubkey, 1400u, 0u, &r.sign,
		                                      record) == FZN_CHAIN_OK
		              && fzn_revocation_open(record, sizeof(record), &rec) == FZN_CHAIN_OK
		              && fzn_revocation_admit(&revoked, fzn_revocation_offer_root(rec),
		                                      r.id.pubkey, &n.sign, &hash_ops, NULL)
		                         == FZN_CHAIN_OK,
		      "N would not admit R's revocation of D");
		CHECK(granted_by(&n, r.id.pubkey, &d, cap, &revoked) == 0,
		      "N granted a device the estate root had revoked");
	}

	/* ---- N LEARNS R's REVOCATIONS BY ASKING R. sec 384. Before that, a
	 * record N issued as its own root before it joined, which the load must
	 * skip rather than fail on. */
	{
		static fzn_revocation_t r_entries[4], n_entries[4], l_entries[4];
		fzn_revocation_store_t r_revs, n_revs, reloaded;
		uint8_t record[FZN_REVOCATION_LEN];
		char page[FZN_REPLY_MAX + 1u];
		size_t learned = 0, count = 0, next = 0, total = 0, len;

		CHECK(fzn_revocation_store_init(&r_revs, r_entries, 4) == FZN_CHAIN_OK
		              && fzn_revocation_store_init(&n_revs, n_entries, 4) == FZN_CHAIN_OK
		              && fzn_revocation_store_init(&reloaded, l_entries, 4) == FZN_CHAIN_OK
		              && fzn_node_revoke(&n.id, n.id.pubkey, NULL, cap, other.id.pubkey, 1150u,
		                                 &n_revs, &n.ops) == FZN_NODE_REVOKE_OK
		              && fzn_revocation_store_init(&n_revs, n_entries, 4) == FZN_CHAIN_OK,
		      "fixture: revocation stores, or N's pre-join revocation");

		/* Nothing revoked yet: a pull of nothing is a pull, and learns
		 * nothing. */
		CHECK(pulled_from(&r, &n, cap, &n_revs, &learned) == FZN_NODE_PULL_OK
		              && learned == 0u,
		      "a pull from a root with nothing revoked failed, or learned something");

		CHECK(fzn_node_revoke(&r.id, r.id.pubkey, NULL, cap, d.id.pubkey, 1400u, &r_revs, &r.ops)
		              == FZN_NODE_REVOKE_OK,
		      "fixture: R would not revoke D");
		CHECK(pulled_from(&r, &n, cap, &n_revs, &learned) == FZN_NODE_PULL_OK
		              && learned == 1u,
		      "N did not learn R's revocation of D by asking R");
		CHECK(granted_by(&n, r.id.pubkey, &d, cap, &n_revs) == 0,
		      "N granted D after pulling R's revocation of it");
		CHECK(pulled_from(&r, &n, cap, &n_revs, &learned) == FZN_NODE_PULL_OK
		              && learned == 1u,
		      "pulling a revocation N already holds failed -- every periodic pull would");

		/* A RESTART with R unreachable: what N saved is what it denies by. */
		CHECK(fzn_node_revocations_load(&n.ops, &reloaded, r.id.pubkey, NULL, NULL, &n.sign, &hash_ops,
		                                &count) == FZN_PERSIST_OK
		              && count == 1u,
		      "N's restart did not reload exactly the one revocation it learned");
		CHECK(granted_by(&n, r.id.pubkey, &d, cap, &reloaded) == 0,
		      "after a restart N granted a device R had revoked");

		/* A RECORD R DID NOT SIGN admits nothing and is not saved. */
		CHECK(fzn_revocation_issue(other.id.pubkey, cap, d.id.pubkey, 1500u, 0u, &other.sign,
		                           record) == FZN_CHAIN_OK
		              && (len = page_of(page, sizeof(page), 1u, 0u, record)) != 0u,
		      "fixture: another root's record");
		learned = 0;
		CHECK(fzn_node_revocations_absorb((const uint8_t *)page, len, 0u, r.id.pubkey, &n.sign,
		                                  &hash_ops, &n_revs, &n.ops, &learned, &next, &total)
		                      == FZN_NODE_PULL_REFUSED
		              && learned == 0u,
		      "N admitted a revocation its root did not sign");

		/* A PAGE AT THE WRONG OFFSET, or one that promises more and
		 * carries nothing, is the root's grammar broken, not a pull done. */
		CHECK(fzn_node_revocations_absorb((const uint8_t *)page, len, 1u, r.id.pubkey, &n.sign,
		                                  &hash_ops, &n_revs, &n.ops, &learned, &next, &total)
		              == FZN_NODE_PULL_SHAPE,
		      "N absorbed a page answering an offset it did not ask for");
		len = (size_t)snprintf(page, sizeof(page), "ok 2 0\n");
		CHECK(fzn_node_revocations_absorb((const uint8_t *)page, len, 0u, r.id.pubkey, &n.sign,
		                                  &hash_ops, &n_revs, &n.ops, &learned, &next, &total)
		              == FZN_NODE_PULL_SHAPE,
		      "N took an empty page short of the total as a finished pull");
		len = (size_t)snprintf(page, sizeof(page), "denied\n");
		CHECK(fzn_node_revocations_absorb((const uint8_t *)page, len, 0u, r.id.pubkey, &n.sign,
		                                  &hash_ops, &n_revs, &n.ops, &learned, &next, &total)
		              == FZN_NODE_PULL_NO_ANSWER,
		      "N took a refusal as a page");
	}

	/* ---- A MEMBER REVOKES WHAT IT DELEGATED, through its chain. sec 385.
	 * N pairs E through R's grant, then cuts E off itself: the record is
	 * N's, admitted on the chain that makes N E's grantor, and it survives a
	 * restart that loads with the same chain. */
	{
		static struct node e;
		static fzn_revocation_t m_entries[8], l_entries[8];
		fzn_revocation_store_t mine, reloaded;
		fzn_prekey_record_t e_rec;
		fzn_node_pairing_t e_pairing;
		fzn_node_authority_t leaf = { 0 };
		size_t count = 0, learned = 0;

		CHECK(node_up(&e)
		              && fzn_prekey_open(e.id.prekey_record, FZN_PREKEY_LEN_TOTAL, &e_rec)
		                         == FZN_PREKEY_OK
		              && fzn_node_pair(&n.id, r.id.pubkey, cap, &authority, 0, &n.ops, e_rec,
		                               1600u, 0u, card, sizeof(card), &card_len)
		                         == FZN_NODE_PAIR_OK
		              && fzn_node_pairing_accept(&e.id, card, card_len, 1700u, &e.ops,
		                                         &e_pairing) == FZN_NODE_PAIR_OK
		              && fzn_revocation_store_init(&mine, m_entries, 8) == FZN_CHAIN_OK
		              && fzn_revocation_store_init(&reloaded, l_entries, 8) == FZN_CHAIN_OK,
		      "fixture: N would not pair E through R's grant");
		CHECK(granted_by(&n, r.id.pubkey, &e, cap, &mine) == 1,
		      "N did not grant E before revoking it");

		/* NO STANDING, NO RECORD: a member revoking as though it were
		 * root, or through a chain it may not pass on. */
		leaf.hops = (const uint8_t (*)[FZN_HOP_LEN])e_pairing.chain;
		leaf.hop_count = e_pairing.hop_count;
		CHECK(fzn_node_revoke(&n.id, r.id.pubkey, NULL, cap, e.id.pubkey, 1800u, &mine,
		                      &n.ops) == FZN_NODE_REVOKE_NOT_ROOT,
		      "a member revoked as though it were the estate's root");
		CHECK(fzn_node_revoke(&e.id, n.id.pubkey, &leaf, cap, d.id.pubkey, 1800u, &mine,
		                      &e.ops) == FZN_NODE_REVOKE_NOT_ROOT,
		      "a device revoked through a grant it may not pass on");

		CHECK(fzn_node_revoke(&n.id, r.id.pubkey, &authority, cap, e.id.pubkey, 1800u, &mine,
		                      &n.ops) == FZN_NODE_REVOKE_OK,
		      "N would not revoke the device it paired, through its own chain");
		CHECK(granted_by(&n, r.id.pubkey, &e, cap, &mine) == 0,
		      "N granted a device it had itself revoked");
		CHECK(fzn_node_revoke(&n.id, r.id.pubkey, &authority, cap, e.id.pubkey, 1801u, &mine,
		                      &n.ops) == FZN_NODE_REVOKE_ALREADY,
		      "a member's second revocation of one device was not reported as already");

		/* A RECORD OF N's FOR A CAPABILITY ITS CHAIN DOES NOT CARRY, written
		 * into the store by hand since `fzn_node_revoke` cannot produce one.
		 * It could never admit, so the load skips it rather than failing. */
		{
			fzn_cap_id_t elsewhere = *cap;
			uint8_t blob[FZN_PERSIST_HEAD_LEN + FZN_REVOCATION_LEN];

			elsewhere.b[0] ^= 1u;
			CHECK(fzn_revocation_issue(n.id.pubkey, &elsewhere, d.id.pubkey, 1850u, 0u,
			                           &n.sign, blob + FZN_PERSIST_HEAD_LEN) == FZN_CHAIN_OK
			              && fzn_persist_head_write(blob, sizeof(blob), FZN_REVOCATION_LEN,
			                                        FZN_PERSIST_BLOB_REVOCATION)
			                         == FZN_PERSIST_OK
			              && n.ops.save(n.ops.ctx, FZN_PERSIST_ISSUED_REVOCATION,
			                            d.id.pubkey, blob, sizeof(blob)),
			      "fixture: N's record for another capability");
		}

		/* THE RESTART: R's record it learned, its own of E, and the one it
		 * issued as its own root before joining -- its signed word still,
		 * admitted through the chain -- and not the one above. */
		CHECK(fzn_node_revocations_load(&n.ops, &reloaded, r.id.pubkey, &authority, NULL, &n.sign,
		                                &hash_ops, &count) == FZN_PERSIST_OK
		              && count == 3u,
		      "N's restart with its chain did not reload R's, its own, and its pre-join records");
		CHECK(granted_by(&n, r.id.pubkey, &e, cap, &reloaded) == 0,
		      "after a restart N granted a device it had itself revoked");

		/* ---- UNDONE, sec 386: E is granted again, a second undo has
		 * nothing to undo, a restart keeps it undone -- the withdrawal
		 * alone in slot 9 admits as a tombstone -- and a revocation after
		 * it supersedes the one undone and denies again. */
		{
			static fzn_revocation_t a_entries[8], b_entries[8], c_entries[8];
			fzn_revocation_store_t after, again, root_revs;

			CHECK(fzn_revocation_store_init(&after, a_entries, 8) == FZN_CHAIN_OK
			              && fzn_revocation_store_init(&again, b_entries, 8) == FZN_CHAIN_OK
			              && fzn_revocation_store_init(&root_revs, c_entries, 8)
			                         == FZN_CHAIN_OK,
			      "fixture: stores for the undo");
			CHECK(fzn_node_unrevoke(&n.id, r.id.pubkey, NULL, e.id.pubkey, 1900u, &mine,
			                        &n.ops) == FZN_NODE_REVOKE_NOT_ROOT,
			      "a member undid a revocation as though it were the root");
			CHECK(fzn_node_unrevoke(&n.id, r.id.pubkey, &authority, e.id.pubkey, 1900u, &mine,
			                        &n.ops) == FZN_NODE_REVOKE_OK,
			      "N would not undo its own revocation of E");
			CHECK(granted_by(&n, r.id.pubkey, &e, cap, &mine) == 1,
			      "N still denied E after undoing its revocation");
			CHECK(fzn_node_unrevoke(&n.id, r.id.pubkey, &authority, e.id.pubkey, 1901u, &mine,
			                        &n.ops) == FZN_NODE_REVOKE_NOT_REVOKED,
			      "undoing twice was not reported as nothing to undo");
			CHECK(fzn_node_revocations_load(&n.ops, &after, r.id.pubkey, &authority, NULL, &n.sign,
			                                &hash_ops, &count) == FZN_PERSIST_OK
			              && granted_by(&n, r.id.pubkey, &e, cap, &after) == 1,
			      "after a restart N denied E again, or would not load the withdrawal");
			CHECK(fzn_node_revoke(&n.id, r.id.pubkey, &authority, cap, e.id.pubkey, 1950u,
			                      &after, &n.ops) == FZN_NODE_REVOKE_OK
			              && granted_by(&n, r.id.pubkey, &e, cap, &after) == 0,
			      "revoking E again after the undo did not deny it");
			CHECK(fzn_node_revocations_load(&n.ops, &again, r.id.pubkey, &authority, NULL, &n.sign,
			                                &hash_ops, &count) == FZN_PERSIST_OK
			              && granted_by(&n, r.id.pubkey, &e, cap, &again) == 0,
			      "after a restart N granted E, revoked again after an undo");

			/* THE ROOT UNDOES, AND A MEMBER LEARNS IT BY PULLING: slot 9 at
			 * R now holds the withdrawal, so that is what `get revocation`
			 * serves, and it lands on the revocation N already holds. */
			CHECK(granted_by(&n, r.id.pubkey, &d, cap, &again) == 0,
			      "fixture: N does not hold R's revocation of D");
			CHECK(fzn_node_unrevoke(&r.id, r.id.pubkey, NULL, d.id.pubkey, 2000u, &root_revs,
			                        &r.ops) == FZN_NODE_REVOKE_OK,
			      "R would not undo its revocation of D");
			CHECK(pulled_from(&r, &n, cap, &again, &learned) == FZN_NODE_PULL_OK
			              && granted_by(&n, r.id.pubkey, &d, cap, &again) == 1,
			      "N did not learn by pulling that R had undone its revocation of D");
		}
		fzn_wipe(&e_pairing, sizeof(e_pairing));
	}
	fzn_wipe(&joined, sizeof(joined));
	fzn_wipe(&d_pairing, sizeof(d_pairing));
}

/* ---- VOTES TRAVEL, sec 399 ------------------------------------------- */

/* The whole vote stream `from` serves, absorbed into `into`, a page at a time
 * of at most `cap` bytes of items -- the serve and the absorb with no
 * transport between them, so a page can be made small enough to split a vote
 * from its chain. The pull err, or -99 when the fixture failed. */
static int stream_pull(struct node *from, const fzn_node_authority_t *authority,
                       struct node *into, const uint8_t root[FZN_PUBKEY_LEN],
                       fzn_revocation_store_t *revs, size_t cap, fzn_node_vote_pull_t *pull)
{
	static char body[FZN_REPLY_MAX];
	static char page[FZN_REPLY_MAX + 64u];
	size_t at = 0, pages = 0;

	memset(pull, 0, sizeof(*pull));
	while (pages++ < 64u) {
		size_t len = 0, total = 0, next = 0;
		int n, err;

		if (!fzn_node_votes_page(&from->ops, authority, NULL, at, body, cap, &len, &total))
			return -99;
		n = snprintf(page, sizeof(page), "ok %zu %zu", total, at);
		if (n < 0 || (size_t)n + len + 2u > sizeof(page))
			return -99;
		memcpy(page + n, body, len);
		page[(size_t)n + len] = '\n';
		err = fzn_node_votes_absorb(pull, (const uint8_t *)page, (size_t)n + len + 1u, at,
		                            root, &into->sign, &hash_ops, revs, &into->ops, &next,
		                            &total);
		if (err != FZN_NODE_PULL_OK || next >= total)
			return err;
		at = next;
	}
	return -99;
}

/* `stream_pull` with this node's admin chain as well. sec 416. */
static int stream_pull_as(struct node *from, const fzn_node_authority_t *authority,
                          const fzn_node_authority_t *admin, struct node *into,
                          const uint8_t root[FZN_PUBKEY_LEN], fzn_revocation_store_t *revs,
                          fzn_node_vote_pull_t *pull)
{
	static char body[FZN_REPLY_MAX];
	static char page[FZN_REPLY_MAX + 64u];
	size_t at = 0, pages = 0;

	memset(pull, 0, sizeof(*pull));
	while (pages++ < 64u) {
		size_t len = 0, total = 0, next = 0;
		int n, err;

		if (!fzn_node_votes_page(&from->ops, authority, admin, at, body, 800u, &len, &total))
			return -99;
		n = snprintf(page, sizeof(page), "ok %zu %zu", total, at);
		if (n < 0 || (size_t)n + len + 2u > sizeof(page))
			return -99;
		memcpy(page + n, body, len);
		page[(size_t)n + len] = '\n';
		err = fzn_node_votes_absorb(pull, (const uint8_t *)page, (size_t)n + len + 1u, at,
		                            root, &into->sign, &hash_ops, revs, &into->ops, &next,
		                            &total);
		if (err != FZN_NODE_PULL_OK || next >= total)
			return err;
		at = next;
	}
	return -99;
}

/* Whether `revs` revokes D on the chain R -> N -> D, at either hop. */
static int d_revoked(const fzn_revocation_store_t *revs, const struct node *r,
                     const struct node *n, const struct node *d, const fzn_cap_id_t *cap)
{
	uint8_t grantors[2][FZN_PUBKEY_LEN], grantees[2][FZN_PUBKEY_LEN];
	uint8_t revoked[FZN_CHAIN_MAX_HOPS];

	memcpy(grantors[0], r->id.pubkey, FZN_PUBKEY_LEN);
	memcpy(grantees[0], n->id.pubkey, FZN_PUBKEY_LEN);
	memcpy(grantors[1], n->id.pubkey, FZN_PUBKEY_LEN);
	memcpy(grantees[1], d->id.pubkey, FZN_PUBKEY_LEN);
	fzn_revocation_covers_links(revs, (const uint8_t (*)[FZN_PUBKEY_LEN])grantors,
	                            (const uint8_t (*)[FZN_PUBKEY_LEN])grantees, 2u, cap, revoked);
	return revoked[0] || revoked[1];
}

/* AT k = 2 THE ROOT ALONE CANNOT CUT D OFF, AND N ALONE CANNOT EITHER; both
 * can, and a third node that hears from only one of them hears both.
 *
 * R grants N, N grants D, R grants M. R and N each vote against D. N pulls
 * R's vote; M pulls from N and receives N's own vote with the chain that
 * makes N D's grantor AND R's vote, which N only relayed -- one peer serving
 * everything it holds is what lets a vote reach a host that never spoke to
 * its issuer. Then the latch holds across the network, a stranger's vote is
 * refused without stopping the pull, a restart keeps what was learned, and a
 * stale copy is not saved over the withdrawal that superseded it. */
static void test_votes_travel(const fzn_cap_id_t *cap)
{
	static struct node r, n, d, m, stranger;
	static fzn_revocation_t r_e[8], n_e[8], m_e[8], l_e[8];
	fzn_revocation_store_t r_revs, n_revs, m_revs, reloaded;
	fzn_prekey_record_t n_rec, d_rec, m_rec;
	fzn_node_pairing_t n_joined, m_joined, d_pairing;
	fzn_node_authority_t authority = { 0 };
	fzn_node_vote_pull_t pull;
	uint8_t card[FZN_PROVISION_MAX_LEN];
	size_t card_len = 0, count = 0, learned = 0;
	int err;

	CHECK(node_up(&r) && node_up(&n) && node_up(&d) && node_up(&m) && node_up(&stranger)
	              && fzn_prekey_open(n.id.prekey_record, FZN_PREKEY_LEN_TOTAL, &n_rec)
	                         == FZN_PREKEY_OK
	              && fzn_prekey_open(d.id.prekey_record, FZN_PREKEY_LEN_TOTAL, &d_rec)
	                         == FZN_PREKEY_OK
	              && fzn_prekey_open(m.id.prekey_record, FZN_PREKEY_LEN_TOTAL, &m_rec)
	                         == FZN_PREKEY_OK,
	      "fixture: the nodes would not come up");
	CHECK(fzn_node_pair(&r.id, r.id.pubkey, cap, NULL, 1, &r.ops, n_rec, 1000u, 0u, card,
	                    sizeof(card), &card_len) == FZN_NODE_PAIR_OK
	              && fzn_node_join(&n.id, card, card_len, 1100u, &n.ops, &n.trust, &n_joined)
	                         == FZN_NODE_PAIR_OK
	              && fzn_node_pair(&r.id, r.id.pubkey, cap, NULL, 1, &r.ops, m_rec, 1000u, 0u,
	                               card, sizeof(card), &card_len) == FZN_NODE_PAIR_OK
	              && fzn_node_join(&m.id, card, card_len, 1100u, &m.ops, &m.trust, &m_joined)
	                         == FZN_NODE_PAIR_OK,
	      "fixture: N and M would not join R's estate");
	authority.hops = (const uint8_t (*)[FZN_HOP_LEN])n_joined.chain;
	authority.hop_count = n_joined.hop_count;
	CHECK(fzn_node_pair(&n.id, r.id.pubkey, cap, &authority, 0, &n.ops, d_rec, 1200u, 0u, card,
	                    sizeof(card), &card_len) == FZN_NODE_PAIR_OK
	              && fzn_node_pairing_accept(&d.id, card, card_len, 1300u, &d.ops, &d_pairing)
	                         == FZN_NODE_PAIR_OK,
	      "fixture: N would not pair D");
	CHECK(fzn_revocation_store_init(&r_revs, r_e, 8) == FZN_CHAIN_OK
	              && fzn_revocation_store_init(&n_revs, n_e, 8) == FZN_CHAIN_OK
	              && fzn_revocation_store_init(&m_revs, m_e, 8) == FZN_CHAIN_OK
	              && fzn_revocation_store_init(&reloaded, l_e, 8) == FZN_CHAIN_OK
	              && fzn_revocation_store_set_quorum(&n_revs, 2u, NULL, NULL, 0u) == FZN_CHAIN_OK
	              && fzn_revocation_store_set_quorum(&m_revs, 2u, NULL, NULL, 0u) == FZN_CHAIN_OK
	              && fzn_revocation_store_set_quorum(&reloaded, 2u, NULL, NULL, 0u)
	                         == FZN_CHAIN_OK,
	      "fixture: stores at quorum 2");

	/* ---- AN EMPTY STREAM IS A STREAM. */
	CHECK(stream_pull(&r, NULL, &n, r.id.pubkey, &n_revs, 1000u, &pull) == FZN_NODE_PULL_OK
	              && pull.learned == 0u && pull.refused == 0u,
	      "pulling an empty stream failed, or learned something");

	/* ---- ONE VOTE EACH, and neither alone revokes. */
	CHECK(fzn_node_revoke(&r.id, r.id.pubkey, NULL, cap, d.id.pubkey, 1400u, &r_revs, &r.ops)
	              == FZN_NODE_REVOKE_OK
	              && fzn_node_revoke(&n.id, r.id.pubkey, &authority, cap, d.id.pubkey, 1400u,
	                                 &n_revs, &n.ops) == FZN_NODE_REVOKE_OK,
	      "R or N would not cast its vote against D");
	CHECK(!d_revoked(&n_revs, &r, &n, &d, cap), "one vote of two revoked D at N");

	/* ---- N PULLS R's VOTE, and at N the two make the quorum. */
	CHECK(stream_pull(&r, NULL, &n, r.id.pubkey, &n_revs, 1000u, &pull) == FZN_NODE_PULL_OK
	              && pull.learned == 1u && pull.refused == 0u,
	      "N did not learn R's vote");
	CHECK(d_revoked(&n_revs, &r, &n, &d, cap), "two votes of two did not revoke D at N");

	/* ---- M PULLS FROM N ONLY, a page per item, and receives both: N's own
	 * with its chain and R's that N relayed. A page of 430 bytes holds one
	 * record or one hop, so N's vote and its chain arrive on different pages
	 * and the vote is held across them. */
	err = stream_pull(&n, &authority, &m, r.id.pubkey, &m_revs, 430u, &pull);
	CHECK(err == FZN_NODE_PULL_OK && pull.learned == 2u && pull.refused == 0u,
	      "M did not learn both votes from N alone, a page an item");
	CHECK(d_revoked(&m_revs, &r, &n, &d, cap),
	      "M, holding both votes, did not revoke D -- a relayed vote did not count");

	/* ---- AGAIN, AND OVER THE WIRE: M holds a pairing to R, so it pulls
	 * `get vote` from R's running remote hop. What it already holds is
	 * learned again, not refused: every periodic pull would otherwise
	 * report refusals. */
	{
		fzn_node_vote_pull_t over;

		memset(&over, 0, sizeof(over));
		CHECK(pulled_from_as(&r, &m, cap, &m_revs, &learned, &over, NULL) == FZN_NODE_PULL_OK
		              && learned == 1u && over.refused == 0u,
		      "M did not pull R's vote with `get vote` over the remote hop");
	}

	/* AND ROOT RECORDS, the same way: R holds one root-add, and M pulls it
	 * with `get root` over the remote hop. sec 408. */
	{
		static fzn_node_roots_t r_roots, m_roots;
		uint8_t add[FZN_ROOT_ADD_LEN];

		CHECK(fzn_node_roots_init(&r_roots, r.id.pubkey, &r.sign, &hash_ops)
		              == FZN_NODE_ROOTS_OK
		              && fzn_node_roots_init(&m_roots, r.id.pubkey, &m.sign, &hash_ops)
		                         == FZN_NODE_ROOTS_OK
		              && fzn_root_add_issue(r.id.pubkey, stranger.id.pubkey, &r.sign, add)
		                         == FZN_ROOT_LOG_OK
		              && fzn_node_roots_learn(&r_roots, &r.ops, add, sizeof(add))
		                         == FZN_NODE_ROOTS_OK,
		      "fixture: R holds a root-add");
		learned = 0;
		CHECK(pulled_from_as(&r, &m, cap, &m_revs, &learned, NULL, &m_roots)
		                      == FZN_NODE_PULL_OK
		              && learned == 1u && fzn_root_view_member(&m_roots.view, stranger.id.pubkey),
		      "M did not pull R's root-add with `get root` over the remote hop");
	}

	/* ---- A STRANGER'S VOTE, written into R's learned votes by hand, is
	 * refused at M and counted, and the pull goes on past it. At R, which
	 * saved it without admitting it, the restart refuses: a learned vote
	 * that will not admit again is a store changed underneath the node. */
	{
		uint8_t blob[FZN_PERSIST_HEAD_LEN + FZN_REVOCATION_LEN + 1u];
		uint8_t subject[FZN_PUBKEY_LEN];

		memset(subject, 0x5a, sizeof(subject));
		CHECK(fzn_revocation_issue(stranger.id.pubkey, cap, d.id.pubkey, 1500u, 0u,
		                           &stranger.sign, blob + FZN_PERSIST_HEAD_LEN) == FZN_CHAIN_OK
		              && fzn_persist_head_write(blob, sizeof(blob), FZN_REVOCATION_LEN + 1u,
		                                        FZN_PERSIST_BLOB_VOTE) == FZN_PERSIST_OK
		              && (blob[FZN_PERSIST_HEAD_LEN + FZN_REVOCATION_LEN] = 0u, 1)
		              && r.ops.save(r.ops.ctx, FZN_PERSIST_VOTE, subject, blob, sizeof(blob)),
		      "fixture: a stranger's vote in R's store");
		CHECK(stream_pull(&r, NULL, &m, r.id.pubkey, &m_revs, 1000u, &pull)
		                      == FZN_NODE_PULL_OK
		              && pull.learned == 1u && pull.refused == 1u,
		      "a stranger's vote stopped the pull, or was not counted as refused");
		{
			static fzn_revocation_t s_e[8];
			fzn_revocation_store_t scratch;

			CHECK(fzn_revocation_store_init(&scratch, s_e, 8) == FZN_CHAIN_OK
			              && fzn_node_revocations_load(&r.ops, &scratch, r.id.pubkey, NULL, NULL,
			                                           &r.sign, &hash_ops, &count)
			                         == FZN_PERSIST_ERR_SHAPE,
			      "a restart admitted past a learned vote that will not admit");
		}
		CHECK(fzn_node_revocations_load(&m.ops, &reloaded, r.id.pubkey, NULL, NULL, &m.sign,
		                                &hash_ops, &count) == FZN_PERSIST_OK
		              && count == 2u,
		      "M's restart did not reload exactly the two votes it learned");
		CHECK(d_revoked(&reloaded, &r, &n, &d, cap), "after a restart M granted D again");
	}

	/* ---- THE LATCH ACROSS THE NETWORK. N withdraws; M learns it and D
	 * stays revoked, one withdrawal of two. R withdraws; N learns it, M
	 * learns it from N, and D is restored. */
	{
		static fzn_revocation_t a_e[8];
		fzn_revocation_store_t after;
		uint8_t old_vote[FZN_REVOCATION_LEN];

		CHECK(fzn_node_issued_revocation(&n.ops, d.id.pubkey, old_vote),
		      "fixture: N's vote as it was");

		/* N's OWN VOTE COMES BACK: pulled from M, it is kept in N's
		 * learned votes beside the one N issued. */
		CHECK(stream_pull(&m, NULL, &n, r.id.pubkey, &n_revs, 1000u, &pull)
		                      == FZN_NODE_PULL_OK
		              && pull.learned == 2u,
		      "N did not take its own vote and R's back from M");
		CHECK(fzn_node_unrevoke(&n.id, r.id.pubkey, &authority, d.id.pubkey, 1600u, &n_revs,
		                        &n.ops) == FZN_NODE_REVOKE_OK
		              && stream_pull(&n, &authority, &m, r.id.pubkey, &m_revs, 1000u, &pull)
		                         == FZN_NODE_PULL_OK,
		      "N would not withdraw, or M would not pull the withdrawal");
		CHECK(d_revoked(&m_revs, &r, &n, &d, cap),
		      "one withdrawal of two restored D at M: the latch did not travel");

		CHECK(fzn_node_unrevoke(&r.id, r.id.pubkey, NULL, d.id.pubkey, 1700u, &r_revs,
		                        &r.ops) == FZN_NODE_REVOKE_OK
		              && stream_pull(&r, NULL, &n, r.id.pubkey, &n_revs, 1000u, &pull)
		                         == FZN_NODE_PULL_OK
		              && stream_pull(&n, &authority, &m, r.id.pubkey, &m_revs, 1000u, &pull)
		                         == FZN_NODE_PULL_OK,
		      "R's withdrawal did not travel R -> N -> M");
		CHECK(!d_revoked(&n_revs, &r, &n, &d, cap) && !d_revoked(&m_revs, &r, &n, &d, cap),
		      "two withdrawals of two left D revoked");

		/* A STALE COPY of N's vote, offered to M after the withdrawal, is
		 * not saved over it: a restart still finds D restored. */
		{
			char page[FZN_REPLY_MAX + 1u];
			fzn_node_vote_pull_t stale;
			size_t next = 0, total = 0, at, i, h;
			static const char digits[] = "0123456789abcdef";

			memset(&stale, 0, sizeof(stale));
			at = (size_t)snprintf(page, sizeof(page), "ok 2 0 r");
			for (i = 0; i < FZN_REVOCATION_LEN; i++) {
				page[at++] = digits[old_vote[i] >> 4];
				page[at++] = digits[old_vote[i] & 15u];
			}
			page[at++] = ' ';
			page[at++] = 'h';
			for (h = 0; h < FZN_HOP_LEN; h++) {
				page[at++] = digits[n_joined.chain[0][h] >> 4];
				page[at++] = digits[n_joined.chain[0][h] & 15u];
			}
			page[at++] = '\n';
			CHECK(fzn_node_votes_absorb(&stale, (const uint8_t *)page, at, 0u, r.id.pubkey,
			                            &m.sign, &hash_ops, &m_revs, &m.ops, &next, &total)
			                      == FZN_NODE_PULL_OK
			              && stale.learned == 0u,
			      "a stale copy of a withdrawn vote was learned");
			CHECK(fzn_revocation_store_init(&after, a_e, 8) == FZN_CHAIN_OK
			              && fzn_revocation_store_set_quorum(&after, 2u, NULL, NULL, 0u)
			                         == FZN_CHAIN_OK
			              && fzn_node_revocations_load(&m.ops, &after, r.id.pubkey, NULL, NULL,
			                                           &m.sign, &hash_ops, &count)
			                         == FZN_PERSIST_OK
			              && !d_revoked(&after, &r, &n, &d, cap),
			      "after a stale copy and a restart, M revoked D again");
		}

		/* A COPY SUPERSEDED IN ANOTHER SLOT is skipped at a restart, not
		 * fatal. N takes its own withdrawal back from M, then revokes D
		 * again: slot 9 now holds a revocation superseding the one that
		 * withdrawal named, so the copy in slot 11 names a target that is
		 * gone and admission refuses it. The triple is already held. */
		{
			static fzn_revocation_t s_e[8];
			fzn_revocation_store_t scratch;

			CHECK(stream_pull(&m, NULL, &n, r.id.pubkey, &n_revs, 1000u, &pull)
			                      == FZN_NODE_PULL_OK
			              && fzn_node_revoke(&n.id, r.id.pubkey, &authority, cap, d.id.pubkey,
			                                 1800u, &n_revs, &n.ops) == FZN_NODE_REVOKE_OK,
			      "fixture: N's withdrawal back from M, then N revoking again");
			/* AND THAT VOTE IS IN EPOCH 1, read off the record N signed:
			 * both withdrew epoch 0 -- R's withdrawal is the root's undo of
			 * it since sec 403 -- so a vote cast in 0 would sit under the
			 * root's floor and count for nothing. sec 400. */
			{
				uint8_t again[FZN_REVOCATION_LEN];
				fzn_revocation_record_t again_rec;

				CHECK(fzn_node_issued_revocation(&n.ops, d.id.pubkey, again)
				              && fzn_revocation_open(again, sizeof(again), &again_rec)
				                         == FZN_CHAIN_OK
				              && fzn_revocation_epoch(again_rec) == 1u,
				      "N's vote after the root's undo was not cast in epoch 1, so it "
				      "counts for nothing");
			}
			CHECK(!d_revoked(&n_revs, &r, &n, &d, cap),
			      "one vote after a full undo revoked D at N: the node did not "
			      "cast it in the open epoch");
			CHECK(fzn_revocation_store_init(&scratch, s_e, 8) == FZN_CHAIN_OK
			              && fzn_node_revocations_load(&n.ops, &scratch, r.id.pubkey,
			                                           &authority, NULL, &n.sign, &hash_ops, &count)
			                         == FZN_PERSIST_OK,
			      "N's restart failed on its own withdrawal superseded by a re-revocation");
		}
	}

	/* ---- STREAMS THAT DO NOT PARSE: a whole, well-formed hop with no
	 * record before it; a page answering an offset nobody asked for; and a
	 * page promising items and carrying none. */
	{
		static char bad[FZN_REPLY_MAX + 1u];
		static const char digits[] = "0123456789abcdef";
		size_t next = 0, total = 0, at, h;

		at = (size_t)snprintf(bad, sizeof(bad), "ok 1 0 h");
		for (h = 0; h < FZN_HOP_LEN; h++) {
			bad[at++] = digits[n_joined.chain[0][h] >> 4];
			bad[at++] = digits[n_joined.chain[0][h] & 15u];
		}
		bad[at++] = '\n';
		memset(&pull, 0, sizeof(pull));
		CHECK(fzn_node_votes_absorb(&pull, (const uint8_t *)bad, at, 0u, r.id.pubkey, &m.sign,
		                            &hash_ops, &m_revs, &m.ops, &next, &total)
		              == FZN_NODE_PULL_SHAPE,
		      "a whole hop with no record before it was absorbed");

		at = (size_t)snprintf(bad, sizeof(bad), "ok 3 1 h");
		for (h = 0; h < FZN_HOP_LEN; h++) {
			bad[at++] = digits[n_joined.chain[0][h] >> 4];
			bad[at++] = digits[n_joined.chain[0][h] & 15u];
		}
		bad[at++] = '\n';
		memset(&pull, 0, sizeof(pull));
		pull.pending = 1;
		CHECK(fzn_node_votes_absorb(&pull, (const uint8_t *)bad, at, 0u, r.id.pubkey, &m.sign,
		                            &hash_ops, &m_revs, &m.ops, &next, &total)
		              == FZN_NODE_PULL_SHAPE,
		      "a vote page answering offset 1 was taken as the answer to 0");

		at = (size_t)snprintf(bad, sizeof(bad), "ok 2 0\n");
		memset(&pull, 0, sizeof(pull));
		CHECK(fzn_node_votes_absorb(&pull, (const uint8_t *)bad, at, 0u, r.id.pubkey, &m.sign,
		                            &hash_ops, &m_revs, &m.ops, &next, &total)
		              == FZN_NODE_PULL_SHAPE,
		      "an empty vote page short of its total was taken as a finished pull");
	}
	fzn_wipe(&n_joined, sizeof(n_joined));
	fzn_wipe(&m_joined, sizeof(m_joined));
	fzn_wipe(&d_pairing, sizeof(d_pairing));
}

/* ---- SEVERAL ROOTS AT A NODE, sec 407 --------------------------------- */

/* `signer` logs `record` as its act at `seq` after `prev`, into `entry`; the
 * entry's id into `id`. */
static int root_logs(struct node *signer, uint64_t seq, const uint8_t *prev,
                     const uint8_t *record, size_t len, uint8_t entry[FZN_ROOT_ACT_LEN],
                     uint8_t id[FZN_ROOT_ACT_ID_LEN])
{
	uint8_t act[FZN_ROOT_ACT_ID_LEN];

	return hash_ops.hash(hash_ops.ctx, act, sizeof(act), record, len)
	       && fzn_root_act_issue(signer->id.pubkey, seq, prev, (uint8_t)FZN_ROOT_ACT_GRANT, act,
	                             &signer->sign, entry) == FZN_ROOT_LOG_OK
	       && hash_ops.hash(hash_ops.ctx, id, FZN_ROOT_ACT_ID_LEN, entry, FZN_ROOT_ACT_LEN);
}

/* ROOT R ADDS ROOT B, which revokes device D; node N learns it all.
 *
 * B is nobody's ancestor on D's chain R -> N -> D. At k = 2, N's store with
 * the set attached takes B's revocation and D is revoked by B alone; a
 * restart from N's store alone says the same. R then removes B with no cut,
 * and B's revocation stops counting. A record claiming R's key and signed by
 * somebody else is refused and not saved. */
static void test_several_roots_at_a_node(const fzn_cap_id_t *cap)
{
	static struct node r, b, n, d, stranger;
	static fzn_node_roots_t roots, again;
	static fzn_revocation_t e1[8], e2[8];
	fzn_revocation_store_t revs, reloaded;
	uint8_t add[FZN_ROOT_ADD_LEN], rem[FZN_ROOT_REMOVE_LEN], rev[FZN_REVOCATION_LEN];
	uint8_t r_add[FZN_ROOT_ACT_LEN], r_rem[FZN_ROOT_ACT_LEN], b_rev[FZN_ROOT_ACT_LEN];
	uint8_t id_add[FZN_ROOT_ACT_ID_LEN], id_rem[FZN_ROOT_ACT_ID_LEN];
	uint8_t id_rev[FZN_ROOT_ACT_ID_LEN];
	fzn_revocation_record_t rec;
	size_t count = 0;

	CHECK(node_up(&r) && node_up(&b) && node_up(&n) && node_up(&d) && node_up(&stranger),
	      "fixture: the nodes");
	CHECK(fzn_revocation_store_init(&revs, e1, 8) == FZN_CHAIN_OK
	              && fzn_revocation_store_set_quorum(&revs, 2u, NULL, NULL, 0u) == FZN_CHAIN_OK
	              && fzn_node_roots_init(&roots, r.id.pubkey, &n.sign, &hash_ops)
	                         == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_attach(&roots, &revs) == FZN_NODE_ROOTS_OK,
	      "fixture: N's store with R's set attached");

	/* R ADDS B, and logs it; B revokes D, and logs it. */
	CHECK(fzn_root_add_issue(r.id.pubkey, b.id.pubkey, &r.sign, add) == FZN_ROOT_LOG_OK
	              && root_logs(&r, 0, NULL, add, sizeof(add), r_add, id_add)
	              && fzn_revocation_issue(b.id.pubkey, cap, d.id.pubkey, 1500u, 0u, &b.sign, rev)
	                         == FZN_CHAIN_OK
	              && fzn_revocation_open(rev, sizeof(rev), &rec) == FZN_CHAIN_OK
	              && root_logs(&b, 0, NULL, rev, sizeof(rev), b_rev, id_rev),
	      "fixture: the add, the revocation and their log entries");

	/* BEFORE N KNOWS OF B, B's revocation is another estate's. */
	CHECK(fzn_revocation_admit(&revs, fzn_revocation_offer_root(rec), r.id.pubkey, &n.sign,
	                           &hash_ops, NULL) == FZN_CHAIN_ERR_WRONG_ROOT,
	      "the control: B's revocation admitted before N knew B was a root");

	CHECK(fzn_node_roots_learn(&roots, &n.ops, add, sizeof(add)) == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_learn(&roots, &n.ops, r_add, sizeof(r_add))
	                         == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_learn(&roots, &n.ops, b_rev, sizeof(b_rev))
	                         == FZN_NODE_ROOTS_OK,
	      "N would not learn R's add of B or the log entries");
	CHECK(fzn_revocation_admit(&revs, fzn_revocation_offer_root(rec), r.id.pubkey, &n.sign,
	                           &hash_ops, NULL) == FZN_CHAIN_OK
	              && d_revoked(&revs, &r, &n, &d, cap),
	      "at k = 2 a second root's revocation did not revoke D alone");

	/* A RESTART from N's store alone. */
	CHECK(fzn_revocation_store_init(&reloaded, e2, 8) == FZN_CHAIN_OK
	              && fzn_revocation_store_set_quorum(&reloaded, 2u, NULL, NULL, 0u)
	                         == FZN_CHAIN_OK
	              && fzn_node_roots_init(&again, r.id.pubkey, &n.sign, &hash_ops)
	                         == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_load(&again, &n.ops, &count) == FZN_NODE_ROOTS_OK
	              && count == 3u
	              && fzn_node_roots_attach(&again, &reloaded) == FZN_NODE_ROOTS_OK
	              && fzn_revocation_admit(&reloaded, fzn_revocation_offer_root(rec),
	                                      r.id.pubkey, &n.sign, &hash_ops, NULL)
	                         == FZN_CHAIN_OK
	              && d_revoked(&reloaded, &r, &n, &d, cap),
	      "after a restart N no longer knew B, or D was not revoked");

	/* A STORE CHANGED UNDERNEATH: an entry filed as a change, and an entry
	 * whose signature no longer verifies. Each fails the load. */
	{
		static struct node x;
		static fzn_node_roots_t bad;
		uint8_t blob[FZN_PERSIST_HEAD_LEN + FZN_ROOT_ACT_LEN];
		uint8_t subject[FZN_PUBKEY_LEN];

		memset(subject, 0x33, sizeof(subject));
		CHECK(node_up(&x)
		              && fzn_persist_head_write(blob, sizeof(blob), FZN_ROOT_ACT_LEN,
		                                        FZN_PERSIST_BLOB_ROOT_ENTRY) == FZN_PERSIST_OK
		              && (memcpy(blob + FZN_PERSIST_HEAD_LEN, r_add, FZN_ROOT_ACT_LEN), 1)
		              && x.ops.save(x.ops.ctx, FZN_PERSIST_ROOT_CHANGE, subject, blob,
		                            sizeof(blob))
		              && fzn_node_roots_init(&bad, r.id.pubkey, &x.sign, &hash_ops)
		                         == FZN_NODE_ROOTS_OK
		              && fzn_node_roots_load(&bad, &x.ops, &count) == FZN_NODE_ROOTS_STORE,
		      "a root log entry filed as a root change was loaded");
		CHECK(node_up(&x)
		              && (blob[sizeof(blob) - 1u] ^= 1u, 1)
		              && x.ops.save(x.ops.ctx, FZN_PERSIST_ROOT_ENTRY, subject, blob,
		                            sizeof(blob))
		              && fzn_node_roots_init(&bad, r.id.pubkey, &x.sign, &hash_ops)
		                         == FZN_NODE_ROOTS_OK
		              && fzn_node_roots_load(&bad, &x.ops, &count) == FZN_NODE_ROOTS_STORE,
		      "a stored root log entry whose signature fails was loaded");
	}

	/* A FORGED CHANGE: R's key as signer, somebody else's signature. */
	{
		uint8_t forged[FZN_ROOT_ADD_LEN];

		CHECK(fzn_root_add_issue(r.id.pubkey, stranger.id.pubkey, &stranger.sign, forged)
		              == FZN_ROOT_LOG_OK
		              && fzn_node_roots_learn(&roots, &n.ops, forged, sizeof(forged))
		                         == FZN_NODE_ROOTS_REFUSED,
		      "a root-add signed by another key than the root it names was learned");
	}

	/* R REMOVES B WITH NO CUT: nothing B did counts. */
	CHECK(fzn_root_remove_issue(r.id.pubkey, b.id.pubkey, NULL, &r.sign, rem)
	              == FZN_ROOT_LOG_OK
	              && root_logs(&r, 1, id_add, rem, sizeof(rem), r_rem, id_rem)
	              && fzn_node_roots_learn(&roots, &n.ops, rem, sizeof(rem)) == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_learn(&roots, &n.ops, r_rem, sizeof(r_rem))
	                         == FZN_NODE_ROOTS_OK,
	      "N would not learn R's removal of B");
	CHECK(!d_revoked(&revs, &r, &n, &d, cap),
	      "a removed root's revocation still revoked D");

	/* CARRIED, sec 408: node M, knowing nothing, pulls N's root records a
	 * page per item and judges as N does -- B admitted as a root, and B's
	 * revocation not counting once R's removal of B arrives with it. */
	{
		static struct node m;
		static fzn_node_roots_t m_roots;
		static fzn_revocation_t e3[8];
		static char body[FZN_REPLY_MAX];
		static char page[FZN_REPLY_MAX + 64u];
		fzn_revocation_store_t m_revs;
		size_t at = 0, pages = 0, learned = 0, refused = 0, total = 0, next = 0, len = 0;
		int err = FZN_NODE_PULL_OK;

		CHECK(node_up(&m)
		              && fzn_revocation_store_init(&m_revs, e3, 8) == FZN_CHAIN_OK
		              && fzn_revocation_store_set_quorum(&m_revs, 2u, NULL, NULL, 0u)
		                         == FZN_CHAIN_OK
		              && fzn_node_roots_init(&m_roots, r.id.pubkey, &m.sign, &hash_ops)
		                         == FZN_NODE_ROOTS_OK
		              && fzn_node_roots_attach(&m_roots, &m_revs) == FZN_NODE_ROOTS_OK,
		      "fixture: M");
		while (pages++ < 16u && err == FZN_NODE_PULL_OK) {
			int w;

			if (!fzn_node_roots_page(&n.ops, at, body, 400u, &len, &total))
				break;
			w = snprintf(page, sizeof(page), "ok %zu %zu", total, at);
			memcpy(page + w, body, len);
			page[(size_t)w + len] = '\n';
			err = fzn_node_roots_absorb(&m_roots, &m.ops, (const uint8_t *)page,
			                            (size_t)w + len + 1u, at, &next, &total, &learned,
			                            &refused);
			if (next >= total)
				break;
			at = next;
		}
		CHECK(err == FZN_NODE_PULL_OK && learned == 5u && refused == 0u && pages > 2u,
		      "M did not learn N's five root records a page an item");
		CHECK(fzn_revocation_admit(&m_revs, fzn_revocation_offer_root(rec), r.id.pubkey,
		                           &m.sign, &hash_ops, NULL) == FZN_CHAIN_OK
		              && !d_revoked(&m_revs, &r, &n, &d, cap),
		      "M did not judge B's revocation as N does after the pull");

		/* PAGES THAT DO NOT PARSE: an answer to an offset nobody asked
		 * for, and an item whose letter names another kind than its
		 * record -- R's log entry sent as an `a`, a root-add. */
		{
			static const char digits[] = "0123456789abcdef";
			size_t h, w;

			w = (size_t)snprintf(page, sizeof(page), "ok 2 1 e");
			for (h = 0; h < FZN_ROOT_ACT_LEN; h++) {
				page[w++] = digits[r_add[h] >> 4];
				page[w++] = digits[r_add[h] & 15u];
			}
			page[w++] = '\n';
			CHECK(fzn_node_roots_absorb(&m_roots, &m.ops, (const uint8_t *)page, w, 0u,
			                            &next, &total, &learned, &refused)
			              == FZN_NODE_PULL_SHAPE,
			      "a root page answering offset 1 was taken as the answer to 0");
			w = (size_t)snprintf(page, sizeof(page), "ok 1 0 a");
			for (h = 0; h < FZN_ROOT_ADD_LEN; h++) {
				page[w++] = digits[r_add[h] >> 4];
				page[w++] = digits[r_add[h] & 15u];
			}
			page[w++] = '\n';
			CHECK(fzn_node_roots_absorb(&m_roots, &m.ops, (const uint8_t *)page, w, 0u,
			                            &next, &total, &learned, &refused)
			              == FZN_NODE_PULL_SHAPE,
			      "an item whose letter names another kind than its record was taken");
		}

		/* A REFUSED ITEM IS COUNTED AND THE PULL GOES ON: a peer holding a
		 * log entry whose signature fails. */
		{
			static struct node y;
			uint8_t blob[FZN_PERSIST_HEAD_LEN + FZN_ROOT_ACT_LEN];
			uint8_t subject[FZN_PUBKEY_LEN];
			int w;

			memset(subject, 0x44, sizeof(subject));
			CHECK(node_up(&y)
			              && fzn_persist_head_write(blob, sizeof(blob), FZN_ROOT_ACT_LEN,
			                                        FZN_PERSIST_BLOB_ROOT_ENTRY)
			                         == FZN_PERSIST_OK
			              && (memcpy(blob + FZN_PERSIST_HEAD_LEN, r_add, FZN_ROOT_ACT_LEN),
			                  blob[sizeof(blob) - 1u] ^= 1u, 1)
			              && y.ops.save(y.ops.ctx, FZN_PERSIST_ROOT_ENTRY, subject, blob,
			                            sizeof(blob))
			              && fzn_node_roots_page(&y.ops, 0, body, sizeof(body), &len, &total),
			      "fixture: a peer holding a forged entry");
			w = snprintf(page, sizeof(page), "ok %zu 0", total);
			memcpy(page + w, body, len);
			page[(size_t)w + len] = '\n';
			learned = refused = 0;
			CHECK(fzn_node_roots_absorb(&m_roots, &m.ops, (const uint8_t *)page,
			                            (size_t)w + len + 1u, 0u, &next, &total, &learned,
			                            &refused) == FZN_NODE_PULL_OK
			              && refused == 1u,
			      "a refused root record stopped the pull, or was not counted");
		}

	}
}

/* Every root record `from` holds, paged into `into` as a pull would. The
 * pull err, and the items learned into `*learned`. */
static int roots_sync(struct node *from, fzn_node_roots_t *into, struct node *into_node,
                      size_t *learned)
{
	static char body[FZN_REPLY_MAX];
	static char page[FZN_REPLY_MAX + 64u];
	size_t at = 0, pages = 0, refused = 0;
	int err = FZN_NODE_PULL_OK;

	*learned = 0;
	while (pages++ < 64u) {
		size_t len = 0, total = 0, next = 0;
		int w;

		if (!fzn_node_roots_page(&from->ops, at, body, 800u, &len, &total))
			return -99;
		w = snprintf(page, sizeof(page), "ok %zu %zu", total, at);
		memcpy(page + w, body, len);
		page[(size_t)w + len] = '\n';
		err = fzn_node_roots_absorb(into, &into_node->ops, (const uint8_t *)page,
		                            (size_t)w + len + 1u, at, &next, &total, learned,
		                            &refused);
		if (err != FZN_NODE_PULL_OK || next >= total)
			return err;
		at = next;
	}
	return -99;
}

/* A NODE ACTS AS A ROOT, sec 409. R, the genesis root, acts with its
 * identity. M makes a root key of its own, which is no root until R adds it;
 * once M has R's records, M acts as that key, and what M does is logged under
 * it. R then removes M's key at the cut after M's act, which keeps it, and
 * with no cut, which drops it. M's key reloads as the same key, a second key
 * is refused, and a root whose log has forked will not extend it. */
static void test_a_node_acts_as_a_root(void)
{
	static struct node r, m, x;
	static fzn_node_roots_t r_roots, m_roots, again;
	static fzn_sign_monocypher_t m_root_signer, again_signer;
	fzn_sign_ops_t m_root_sign, again_sign;
	fzn_sign_seat_t m_root_seat, again_seat;
	const uint8_t *as = NULL;
	const fzn_sign_ops_t *as_sign = NULL;
	size_t learned = 0;

	CHECK(node_up(&r) && node_up(&m) && node_up(&x), "fixture: the nodes");
	fzn_sign_monocypher_init(&m_root_sign, &m_root_signer);
	fzn_sign_monocypher_seat_init(&m_root_seat, &m_root_signer);
	CHECK(fzn_node_roots_init(&r_roots, r.id.pubkey, &r.sign, &hash_ops) == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_init(&m_roots, r.id.pubkey, &m.sign, &hash_ops)
	                         == FZN_NODE_ROOTS_OK,
	      "fixture: the roots");
	CHECK(fzn_node_roots_acting(&r_roots, r.id.pubkey, &r.sign, &as, &as_sign)
	              && memcmp(as, r.id.pubkey, FZN_PUBKEY_LEN) == 0,
	      "the genesis node did not act as a root with its identity");

	/* M'S OWN ROOT KEY: made, not yet a root. */
	CHECK(fzn_node_roots_key_create(&m_roots, &m.ops, &rng_ops, &m_root_seat, &m_root_sign)
	              == FZN_NODE_ROOTS_OK
	              && memcmp(m_roots.key, m.id.pubkey, FZN_PUBKEY_LEN) != 0,
	      "M could not make a root key, or it is M's identity");
	CHECK(fzn_node_roots_key_create(&m_roots, &m.ops, &rng_ops, &m_root_seat, &m_root_sign)
	              == FZN_NODE_ROOTS_HELD,
	      "a second root key was made on one node");
	CHECK(!fzn_node_roots_acting(&m_roots, m.id.pubkey, &m.sign, &as, &as_sign),
	      "M acted as a root before any root added its key");
	CHECK(fzn_node_roots_change(&m_roots, &m.ops, m.id.pubkey, &m.sign, 0, x.id.pubkey, NULL)
	              == FZN_NODE_ROOTS_NOT_ROOT,
	      "a node that stands as no root changed the root set");

	/* R ADDS M's KEY; M pulls R's records and acts as that key. */
	CHECK(fzn_node_roots_change(&r_roots, &r.ops, r.id.pubkey, &r.sign, 0, m_roots.key, NULL)
	              == FZN_NODE_ROOTS_OK
	              && r_roots.log.used == 1u,
	      "R could not add M's key, or did not log the add");
	CHECK(roots_sync(&r, &m_roots, &m, &learned) == FZN_NODE_PULL_OK
	              && learned == 2u
	              && fzn_node_roots_acting(&m_roots, m.id.pubkey, &m.sign, &as, &as_sign)
	              && memcmp(as, m_roots.key, FZN_PUBKEY_LEN) == 0,
	      "M did not act as its own root key once R had added it");

	/* M ADDS X, logged under M's key at seq 0. */
	CHECK(fzn_node_roots_change(&m_roots, &m.ops, m.id.pubkey, &m.sign, 0, x.id.pubkey, NULL)
	              == FZN_NODE_ROOTS_OK
	              && fzn_root_view_stands(&m_roots.view, x.id.pubkey),
	      "M, acting as a root, could not add X");
	{
		const fzn_root_log_entry_t *mine = NULL;
		uint8_t cut[FZN_ROOT_ACT_ID_LEN];
		size_t i;

		for (i = 0; i < m_roots.log.used; i++)
			if (memcmp(m_roots.log.entries[i].root, m_roots.key, FZN_PUBKEY_LEN) == 0)
				mine = &m_roots.log.entries[i];
		CHECK(mine && mine->seq == 0u, "M's act was not logged under its key at seq 0");
		if (!mine)
			return;
		memcpy(cut, mine->id, sizeof(cut));

		/* R REMOVES M's KEY AFTER THAT ACT, as seen from M: X stays. */
		CHECK(fzn_node_roots_change(&r_roots, &r.ops, r.id.pubkey, &r.sign, 1, m_roots.key,
		                            cut) == FZN_NODE_ROOTS_OK,
		      "R could not remove M's key at a cut");
		CHECK(roots_sync(&r, &m_roots, &m, &learned) == FZN_NODE_PULL_OK
		              && !fzn_node_roots_acting(&m_roots, m.id.pubkey, &m.sign, &as, &as_sign)
		              && fzn_root_view_stands(&m_roots.view, x.id.pubkey),
		      "after its removal at a cut M still acted as a root, or X fell");

		/* AND WITH NO CUT: nothing M's key did stands, so X is no root. */
		CHECK(fzn_node_roots_change(&r_roots, &r.ops, r.id.pubkey, &r.sign, 1, m_roots.key,
		                            NULL) == FZN_NODE_ROOTS_OK
		              && roots_sync(&r, &m_roots, &m, &learned) == FZN_NODE_PULL_OK
		              && !fzn_root_view_member(&m_roots.view, x.id.pubkey),
		      "under a removal with no cut, the root M's key added still stood");
	}

	/* M's KEY RELOADS AS THE SAME KEY. */
	fzn_sign_monocypher_init(&again_sign, &again_signer);
	fzn_sign_monocypher_seat_init(&again_seat, &again_signer);
	CHECK(fzn_node_roots_init(&again, r.id.pubkey, &m.sign, &hash_ops) == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_key_load(&again, &m.ops, &again_seat, &again_sign)
	                         == FZN_NODE_ROOTS_OK
	              && again.key_held && memcmp(again.key, m_roots.key, FZN_PUBKEY_LEN) == 0,
	      "M's root key did not reload as the same key");

	/* A FORKED LOG IS NOT EXTENDED: a second entry at R's seq 0, signed by
	 * hand, and R's next act is refused. */
	{
		uint8_t fork[FZN_ROOT_ACT_LEN], act[FZN_ROOT_ACT_ID_LEN];

		memset(act, 0x77, sizeof(act));
		CHECK(fzn_root_act_issue(r.id.pubkey, 0, NULL, (uint8_t)FZN_ROOT_ACT_GRANT, act,
		                         &r.sign, fork) == FZN_ROOT_LOG_OK
		              && fzn_node_roots_learn(&r_roots, &r.ops, fork, sizeof(fork))
		                         == FZN_NODE_ROOTS_OK
		              && fzn_node_roots_change(&r_roots, &r.ops, r.id.pubkey, &r.sign, 0,
		                                       x.id.pubkey, NULL) == FZN_NODE_ROOTS_FORKED,
		      "a root whose log had forked extended it");
	}
	fzn_sign_monocypher_wipe(&m_root_signer);
	fzn_sign_monocypher_wipe(&again_signer);
}

/* ---- a card that proves its root, sec 410 ----------------------------- */

static size_t rows_in(struct node *n, fzn_persist_slot_t slot)
{
	uint8_t subjects[8 * FZN_PUBKEY_LEN];
	size_t count = 0;

	return mem_list(&n->store, slot, subjects, 8, &count) ? count : (size_t)-1;
}

/* K is a root because the genesis R added it; K pairs D. The card names R --
 * the root D pins -- and carries R's add of K, and D accepts the chain from K
 * on that proof alone, saving the add BEFORE the pairing so its roots load
 * with K a member. The control is the same card with no proof: a chain from
 * a key R never added, refused, and nothing saved. */
static void test_a_card_proves_its_root(const fzn_cap_id_t *cap)
{
	static struct node r, k, d, e;
	static fzn_node_roots_t roots;
	uint8_t add[FZN_ROOT_ADD_LEN], hop[FZN_HOP_LEN], card[FZN_PROVISION_MAX_LEN];
	size_t card_len = 0, count = 0;
	fzn_node_pairing_t pairing;

	CHECK(node_up(&r) && node_up(&k) && node_up(&d) && node_up(&e), "fixture: the nodes");
	CHECK(fzn_root_add_issue(r.id.pubkey, k.id.pubkey, &r.sign, add) == FZN_ROOT_LOG_OK
	              && fzn_chain_mint(k.id.pubkey, d.id.pubkey, cap, 1000u, 0u, 0, &k.sign, hop)
	                         == FZN_CHAIN_OK,
	      "fixture: R's add of K, and K's hop to D");

	/* THE CONTROL FIRST: no proof, so the chain starts at a stranger to R. */
	CHECK(fzn_provision_pack(r.id.pubkey, (const uint8_t (*)[FZN_HOP_LEN])hop, 1u, NULL, 0,
	                         k.id.prekey_record, 0u, &k.sign, card, sizeof(card), &card_len)
	              == FZN_PROVISION_OK,
	      "fixture: the card without a proof");
	CHECK(fzn_node_pairing_accept(&e.id, card, card_len, 1300u, &e.ops, &pairing)
	              == FZN_NODE_PAIR_REFUSED
	              && rows_in(&e, FZN_PERSIST_ROOT_CHANGE) == 0u
	              && rows_in(&e, FZN_PERSIST_PAIRED_NODE) == 0u,
	      "the control: a chain from a key R never added was paired, or left a row");

	CHECK(fzn_provision_pack(r.id.pubkey, (const uint8_t (*)[FZN_HOP_LEN])hop, 1u,
	                         (const uint8_t (*)[FZN_PROVISION_PROOF_ITEM_LEN])add, 1u,
	                         k.id.prekey_record, 0u, &k.sign, card, sizeof(card), &card_len)
	              == FZN_PROVISION_OK
	              && card_len == FZN_PROVISION_LEN(1, 1),
	      "fixture: the card with R's add of K");
	CHECK(fzn_node_pairing_accept(&d.id, card, card_len, 1300u, &d.ops, &pairing)
	              == FZN_NODE_PAIR_OK
	              && memcmp(pairing.node, k.id.pubkey, FZN_PUBKEY_LEN) == 0,
	      "D refused a chain from K with the proof that K is R's root");
	CHECK(rows_in(&d, FZN_PERSIST_ROOT_CHANGE) == 1u,
	      "D did not save the root-add the card proved its root with");
	CHECK(fzn_node_roots_init(&roots, r.id.pubkey, &d.sign, &hash_ops) == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_load(&roots, &d.ops, &count) == FZN_NODE_ROOTS_OK
	              && count == 1u && roots.ops.member(roots.ops.ctx, k.id.pubkey),
	      "D's roots, loaded again, do not make K a root of R's estate");
}

/* ---- pairing through a root key, sec 411 ------------------------------- */

/* `by` adds `key` as a root, learned into `into` and saved in `store`. */
static int add_as(struct node *by, const uint8_t key[FZN_PUBKEY_LEN], fzn_node_roots_t *into,
                  struct node *store)
{
	uint8_t add[FZN_ROOT_ADD_LEN];

	return fzn_root_add_issue(by->id.pubkey, key, &by->sign, add) == FZN_ROOT_LOG_OK
	       && fzn_node_roots_learn(into, &store->ops, add, sizeof(add)) == FZN_NODE_ROOTS_OK;
}

static size_t grants_by(const fzn_node_roots_t *roots, const uint8_t key[FZN_PUBKEY_LEN])
{
	size_t i, n = 0;

	for (i = 0; i < roots->log.used; i++)
		if (memcmp(roots->log.entries[i].root, key, FZN_PUBKEY_LEN) == 0
		    && roots->log.entries[i].kind == (uint8_t)FZN_ROOT_ACT_GRANT)
			n++;
	return n;
}

/* M holds a root key K and has joined nothing. R, the genesis, adds Y and X;
 * X adds K. M pairs D through K: the card carries K's grant to M, M's to D,
 * and the adds R-X and X-K -- found past the dead end at Y, and not through
 * Q, whose add of K fell when R removed it -- and D, pinning
 * R, accepts it. K's grant is one act however often it is made, and a
 * revocation store with M's roots attached verifies D's chain where the
 * genesis pin alone refuses it. Before K stands there is no grant, and a key
 * four adds from the genesis has no proof a card can carry. */
static void test_a_node_pairs_through_its_root_key(const fzn_cap_id_t *cap)
{
	static struct node r, m, d, x, y, q, a, b, c;
	static fzn_node_roots_t r_roots, m_roots, deep;
	static fzn_sign_monocypher_t k_signer;
	static fzn_revocation_t entries[4];
	static fzn_node_peer_t peers[2];
	fzn_sign_ops_t k_sign;
	fzn_sign_seat_t k_seat;
	fzn_revocation_store_t revs;
	fzn_prekey_record_t d_rec;
	fzn_node_pairing_t d_pairing;
	fzn_node_authority_t through = { 0 };
	fzn_chain_hop_t views[2];
	fzn_chain_t verdict;
	uint8_t hop[FZN_HOP_LEN], again[FZN_HOP_LEN];
	uint8_t proof[FZN_PROVISION_PROOF_MAX][FZN_PROVISION_PROOF_ITEM_LEN];
	uint8_t card[FZN_PROVISION_MAX_LEN];
	size_t card_len = 0, learned = 0, loaded = 0, used;

	CHECK(node_up(&r) && node_up(&m) && node_up(&d) && node_up(&x) && node_up(&y)
	              && node_up(&q) && node_up(&a) && node_up(&b) && node_up(&c)
	              && fzn_prekey_open(d.id.prekey_record, FZN_PREKEY_LEN_TOTAL, &d_rec)
	                         == FZN_PREKEY_OK,
	      "fixture: the nodes");
	fzn_sign_monocypher_init(&k_sign, &k_signer);
	fzn_sign_monocypher_seat_init(&k_seat, &k_signer);
	CHECK(fzn_node_roots_init(&r_roots, r.id.pubkey, &r.sign, &hash_ops) == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_init(&m_roots, r.id.pubkey, &m.sign, &hash_ops)
	                         == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_key_create(&m_roots, &m.ops, &rng_ops, &k_seat, &k_sign)
	                         == FZN_NODE_ROOTS_OK,
	      "fixture: R's and M's roots, and M's key K");

	/* BEFORE K STANDS: no grant, and nothing logged. */
	CHECK(fzn_node_roots_self_grant(&m_roots, &m.ops, m.id.pubkey, cap, hop, proof, &through)
	              == FZN_NODE_ROOTS_NOT_ROOT
	              && m_roots.log.used == 0u,
	      "M granted as a root key no root had added");

	/* R ADDS Y, A DEAD END, AND Q, AND REMOVES Q WITH NOTHING KEPT; Q'S ADD OF
	 * K THEREFORE DOES NOT COUNT, and a proof through it would rest on a
	 * removed root. R ADDS X; X ADDS K. */
	CHECK(fzn_node_roots_change(&r_roots, &r.ops, r.id.pubkey, &r.sign, 0, y.id.pubkey, NULL)
	              == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_change(&r_roots, &r.ops, r.id.pubkey, &r.sign, 0,
	                                       q.id.pubkey, NULL) == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_change(&r_roots, &r.ops, r.id.pubkey, &r.sign, 1,
	                                       q.id.pubkey, NULL) == FZN_NODE_ROOTS_OK
	              && roots_sync(&r, &m_roots, &m, &learned) == FZN_NODE_PULL_OK
	              && add_as(&q, m_roots.key, &m_roots, &m)
	              && !fzn_root_view_stands(&m_roots.view, m_roots.key),
	      "fixture: K added only by a removed root, and not standing");
	CHECK(fzn_node_roots_change(&r_roots, &r.ops, r.id.pubkey, &r.sign, 0, x.id.pubkey, NULL)
	              == FZN_NODE_ROOTS_OK
	              && roots_sync(&r, &m_roots, &m, &learned) == FZN_NODE_PULL_OK
	              && add_as(&x, m_roots.key, &m_roots, &m)
	              && fzn_root_view_stands(&m_roots.view, m_roots.key),
	      "fixture: K standing through R's add of X and X's add of K");

	CHECK(fzn_node_roots_self_grant(&m_roots, &m.ops, m.id.pubkey, cap, hop, proof, &through)
	              == FZN_NODE_ROOTS_OK
	              && through.hop_count == 1u && through.proof_count == 2u
	              && memcmp(proof[0] + FZN_ROOT_SET_OFF_SUBJECT, x.id.pubkey, FZN_PUBKEY_LEN) == 0
	              && memcmp(proof[1] + FZN_ROOT_SET_OFF_SUBJECT, m_roots.key, FZN_PUBKEY_LEN)
	                         == 0,
	      "M's grant through K did not carry the proof R-X, X-K");
	CHECK(grants_by(&m_roots, m_roots.key) == 1u, "K's grant to M was not logged once");
	used = m_roots.log.used;
	CHECK(fzn_node_roots_self_grant(&m_roots, &m.ops, m.id.pubkey, cap, again, proof, &through)
	              == FZN_NODE_ROOTS_OK
	              && memcmp(hop, again, FZN_HOP_LEN) == 0 && m_roots.log.used == used,
	      "a second grant under one capability was another hop, or logged again");

	/* M PAIRS D THROUGH K, and D, pinning R, accepts. */
	CHECK(fzn_node_pair(&m.id, r.id.pubkey, cap, &through, 0, &m.ops, d_rec, 1200u,
	                    1200u + 86400u, card, sizeof(card), &card_len) == FZN_NODE_PAIR_OK
	              && card_len == FZN_PROVISION_LEN(2, 2),
	      "M could not pair D through its root key");
	CHECK(fzn_node_pairing_accept(&d.id, card, card_len, 1300u, &d.ops, &d_pairing)
	              == FZN_NODE_PAIR_OK
	              && memcmp(d_pairing.node, m.id.pubkey, FZN_PUBKEY_LEN) == 0,
	      "D, pinning R, refused the card M made through K");

	/* M VERIFIES D'S CHAIN with its roots, and not without them. */
	CHECK(fzn_node_peers_load(&m.ops, peers, 2, &loaded) == FZN_PERSIST_OK && loaded == 1u
	              && peers[0].hop_count == 2u
	              && fzn_hop_open(peers[0].hop_bytes[0], FZN_HOP_LEN, &views[0]) == FZN_CHAIN_OK
	              && fzn_hop_open(peers[0].hop_bytes[1], FZN_HOP_LEN, &views[1]) == FZN_CHAIN_OK
	              && fzn_revocation_store_init(&revs, entries, 4) == FZN_CHAIN_OK
	              && fzn_node_roots_attach(&m_roots, &revs) == FZN_NODE_ROOTS_OK,
	      "fixture: M's peer and a store with M's roots");
	CHECK(fzn_chain_verify(views, 2, r.id.pubkey, cap, 1400u, &m.sign, &revs, NULL, &verdict)
	              == FZN_CHAIN_OK
	              && memcmp(verdict.grantee, d.id.pubkey, FZN_PUBKEY_LEN) == 0,
	      "M's own roots do not verify the chain it paired D with");
	CHECK(fzn_chain_verify(views, 2, r.id.pubkey, cap, 1400u, &m.sign, NULL, NULL, &verdict)
	              == FZN_CHAIN_ERR_WRONG_ROOT,
	      "the control: the genesis pin alone took a chain from K");

	/* TOO DEEP FOR A CARD: R-A, A-B, B-C, C-K is four adds. */
	CHECK(fzn_node_roots_init(&deep, r.id.pubkey, &m.sign, &hash_ops) == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_key_load(&deep, &m.ops, &k_seat, &k_sign) == FZN_NODE_ROOTS_OK
	              && add_as(&r, a.id.pubkey, &deep, &a) && add_as(&a, b.id.pubkey, &deep, &a)
	              && add_as(&b, c.id.pubkey, &deep, &a) && add_as(&c, deep.key, &deep, &a)
	              && fzn_root_view_stands(&deep.view, deep.key),
	      "fixture: K four adds from R");
	CHECK(fzn_node_roots_self_grant(&deep, &a.ops, m.id.pubkey, cap, hop, proof, &through)
	              == FZN_NODE_ROOTS_NO_PROOF,
	      "a root key four adds from the genesis was given a proof");
}

/* ---- confirmations travel with the votes, sec 415 --------------------- */

/* S holds two confirmations: R's, as a root, and A's, shown with A's admin
 * chain R -> A. T pulls S's vote stream into a store with an admin
 * capability and a confirmation table: both admit and are saved in slot 15,
 * and a fresh store re-admits both from T's rows. U, whose store keeps no
 * table, counts both as refused and saves nothing. */
static void test_confirmations_travel(void)
{
	static struct node r, a, b, s, t, u;
	static fzn_revocation_t e1[4], e2[4], e3[4];
	static fzn_revocation_admin_t ad1[4], ad2[4];
	static fzn_revocation_confirm_t c1[4], c2[4];
	fzn_revocation_store_t into, fresh, plain;
	fzn_node_vote_pull_t pull;
	fzn_node_authority_t a_chain = { 0 };
	fzn_cap_id_t adm;
	uint8_t hop_a[FZN_HOP_LEN], hop_b[FZN_HOP_LEN], grant[FZN_REVOCATION_ID_LEN];
	uint8_t by_root[FZN_ADMIN_CONFIRM_LEN], by_a[FZN_ADMIN_CONFIRM_LEN];
	size_t count = 0;

	memset(&adm, 0xad, sizeof(adm));
	CHECK(node_up(&r) && node_up(&a) && node_up(&b) && node_up(&s) && node_up(&t)
	              && node_up(&u),
	      "fixture: the nodes");
	CHECK(fzn_chain_mint(r.id.pubkey, a.id.pubkey, &adm, 1000u, FZN_NO_EXPIRY, 0, &r.sign,
	                     hop_a) == FZN_CHAIN_OK
	              && fzn_chain_mint(r.id.pubkey, b.id.pubkey, &adm, 1000u, FZN_NO_EXPIRY, 1,
	                                &r.sign, hop_b) == FZN_CHAIN_OK
	              && hash_ops.hash(hash_ops.ctx, grant, sizeof(grant), hop_b, FZN_HOP_LEN)
	              && fzn_admin_confirm_issue(r.id.pubkey, grant, &r.sign, by_root)
	                         == FZN_CHAIN_OK
	              && fzn_admin_confirm_issue(a.id.pubkey, grant, &a.sign, by_a) == FZN_CHAIN_OK,
	      "fixture: the admin hops and the two confirmations");
	a_chain.hops = (const uint8_t (*)[FZN_HOP_LEN])hop_a;
	a_chain.hop_count = 1u;
	CHECK(fzn_node_confirm_save(&s.ops, &hash_ops, by_root, NULL) == FZN_NODE_REVOKE_OK
	              && fzn_node_confirm_save(&s.ops, &hash_ops, by_a, &a_chain)
	                         == FZN_NODE_REVOKE_OK
	              && rows_in(&s, FZN_PERSIST_ADMIN_CONFIRM) == 2u,
	      "S did not keep its two confirmations in slot 15");

	CHECK(fzn_revocation_store_init(&into, e1, 4) == FZN_CHAIN_OK
	              && fzn_revocation_store_set_quorum(&into, 2u, &adm, ad1, 4u) == FZN_CHAIN_OK
	              && fzn_revocation_store_set_confirmations(&into, c1, 4u, &hash_ops)
	                         == FZN_CHAIN_OK,
	      "fixture: T's store with both tables");
	CHECK(stream_pull(&s, NULL, &t, r.id.pubkey, &into, 800u, &pull) == FZN_NODE_PULL_OK
	              && pull.learned == 2u && pull.refused == 0u && into.confirms_used == 2u
	              && into.admins_used == 1u,
	      "T did not learn both confirmations, or did not take A as an admin from its chain");
	CHECK(rows_in(&t, FZN_PERSIST_ADMIN_CONFIRM) == 2u,
	      "T did not save the confirmations it learned");
	CHECK(fzn_revocation_store_init(&fresh, e2, 4) == FZN_CHAIN_OK
	              && fzn_revocation_store_set_quorum(&fresh, 2u, &adm, ad2, 4u) == FZN_CHAIN_OK
	              && fzn_revocation_store_set_confirmations(&fresh, c2, 4u, &hash_ops)
	                         == FZN_CHAIN_OK
	              && fzn_node_revocations_load(&t.ops, &fresh, r.id.pubkey, NULL, NULL, &t.sign,
	                                           &hash_ops, &count) == FZN_PERSIST_OK
	              && count == 2u && fresh.confirms_used == 2u,
	      "T's confirmations were not admitted again at start");

	/* A STORE WITH NO TABLE: counted and skipped, nothing saved. */
	CHECK(fzn_revocation_store_init(&plain, e3, 4) == FZN_CHAIN_OK
	              && stream_pull(&s, NULL, &u, r.id.pubkey, &plain, 800u, &pull)
	                         == FZN_NODE_PULL_OK
	              && pull.learned == 0u && pull.refused == 2u
	              && rows_in(&u, FZN_PERSIST_ADMIN_CONFIRM) == 0u,
	      "a store keeping no confirmation table took or saved a confirmation");
}

/* ---- admins at the node, sec 416 ------------------------------------- */

/* A store at k = 2 with the admin capability, both tables and `roots`. */
static int admin_store(fzn_revocation_store_t *revs, fzn_revocation_t *entries,
                       fzn_revocation_admin_t *admins, fzn_revocation_confirm_t *confirms,
                       const fzn_cap_id_t *adm, fzn_node_roots_t *roots)
{
	return fzn_revocation_store_init(revs, entries, 8) == FZN_CHAIN_OK
	       && fzn_revocation_store_set_quorum(revs, 2u, adm, admins, 8u) == FZN_CHAIN_OK
	       && fzn_revocation_store_set_confirmations(revs, confirms, 8u, &hash_ops)
	                  == FZN_CHAIN_OK
	       && (!roots || fzn_node_roots_attach(roots, revs) == FZN_NODE_ROOTS_OK);
}

/* R, the genesis, grants admin to A and to C, logging both; each installs its
 * chain, and B cannot install A's. A grants B through its own chain: two hops.
 * C confirms A's grant of B, and R confirms it as a root, logged; a node that
 * is neither is refused. B votes on its admin chain: the vote stream carries
 * that chain, a puller learns B as an admin from it, and a restart re-admits
 * B's vote on it. */
static void test_admins_at_the_node(const fzn_cap_id_t *cap)
{
	static struct node r, a, b, c, d, t;
	static fzn_node_roots_t r_roots;
	static fzn_revocation_t e[6][8];
	static fzn_revocation_admin_t ad[6][8];
	static fzn_revocation_confirm_t cf[6][8];
	static fzn_node_admin_chain_t a_chain, b_chain, c_chain, back;
	static uint8_t chain[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN], b_hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	fzn_revocation_store_t r_revs, a_revs, b_revs, c_revs, t_revs, fresh;
	fzn_node_vote_pull_t pull;
	fzn_cap_id_t adm;
	size_t n = 0, logged, count = 0;

	memset(&adm, 0xad, sizeof(adm));
	CHECK(node_up(&r) && node_up(&a) && node_up(&b) && node_up(&c) && node_up(&d) && node_up(&t)
	              && fzn_node_roots_init(&r_roots, r.id.pubkey, &r.sign, &hash_ops)
	                         == FZN_NODE_ROOTS_OK
	              && admin_store(&r_revs, e[0], ad[0], cf[0], &adm, &r_roots)
	              && admin_store(&a_revs, e[1], ad[1], cf[1], &adm, NULL)
	              && admin_store(&b_revs, e[2], ad[2], cf[2], &adm, NULL)
	              && admin_store(&c_revs, e[3], ad[3], cf[3], &adm, NULL)
	              && admin_store(&t_revs, e[4], ad[4], cf[4], &adm, NULL),
	      "fixture: the nodes and their stores");

	/* R GRANTS A, as a root, logged. */
	CHECK(fzn_node_admin_grant(&r_roots, &r.ops, &r.id, NULL, &adm, a.id.pubkey, 1000u, chain,
	                           &n) == FZN_NODE_REVOKE_OK
	              && n == 1u && r_roots.log.used == 1u
	              && r_roots.log.entries[0].kind == (uint8_t)FZN_ROOT_ACT_GRANT,
	      "R did not grant A admin as one logged hop");
	CHECK(fzn_node_admin_chain_set(&b.ops, &b_revs, &b.id, r.id.pubkey, &adm,
	                               (const uint8_t (*)[FZN_HOP_LEN])chain, n, 1100u, &back)
	              == FZN_NODE_REVOKE_NOT_ADMIN,
	      "the control: B installed a chain that names A");
	CHECK(fzn_node_admin_chain_set(&a.ops, &a_revs, &a.id, r.id.pubkey, &adm,
	                               (const uint8_t (*)[FZN_HOP_LEN])chain, n, 1100u, &a_chain)
	              == FZN_NODE_REVOKE_OK
	              && fzn_node_admin_chain_load(&a.ops, &back) == 1 && back.hop_count == 1u
	              && memcmp(back.hops[0], chain[0], FZN_HOP_LEN) == 0,
	      "A could not install R's grant, or it did not load back");
	CHECK(fzn_node_admin_chain_load(&c.ops, &back) == 0 && !fzn_node_admin_chain_view(&back),
	      "a node with no admin chain loaded one");
	/* A CHAIN THAT ENDS UNDELEGABLE cannot be held: it could neither grant
	 * onward nor, by `fzn_node_revoke`'s rule, vote. */
	CHECK(fzn_chain_mint(r.id.pubkey, c.id.pubkey, &adm, 1000u, FZN_NO_EXPIRY, 0, &r.sign,
	                     chain[0]) == FZN_CHAIN_OK
	              && fzn_node_admin_chain_set(&c.ops, &c_revs, &c.id, r.id.pubkey, &adm,
	                                          (const uint8_t (*)[FZN_HOP_LEN])chain, 1u, 1100u,
	                                          &back) == FZN_NODE_REVOKE_NOT_ADMIN,
	      "an admin chain ending undelegable was installed");

	/* R GRANTS C; C installs. A GRANTS B: A's chain and a hop more. */
	CHECK(fzn_node_admin_grant(&r_roots, &r.ops, &r.id, NULL, &adm, c.id.pubkey, 1000u, chain,
	                           &n) == FZN_NODE_REVOKE_OK
	              && fzn_node_admin_chain_set(&c.ops, &c_revs, &c.id, r.id.pubkey, &adm,
	                                          (const uint8_t (*)[FZN_HOP_LEN])chain, n, 1100u,
	                                          &c_chain) == FZN_NODE_REVOKE_OK,
	      "fixture: C, R's admin");
	CHECK(fzn_node_admin_grant(NULL, &a.ops, &a.id, &a_chain, &adm, b.id.pubkey, 1200u, b_hops,
	                           &n) == FZN_NODE_REVOKE_OK
	              && n == 2u && memcmp(b_hops[0], a_chain.hops[0], FZN_HOP_LEN) == 0
	              && fzn_node_admin_chain_set(&b.ops, &b_revs, &b.id, r.id.pubkey, &adm,
	                                          (const uint8_t (*)[FZN_HOP_LEN])b_hops, n, 1300u,
	                                          &b_chain) == FZN_NODE_REVOKE_OK,
	      "A's grant to B was not A's chain and a hop, or B could not install it");
	CHECK(fzn_node_admin_grant(NULL, &d.ops, &d.id, NULL, &adm, b.id.pubkey, 1200u, chain, &n)
	              == FZN_NODE_REVOKE_NOT_ROOT,
	      "a node neither root nor admin granted admin");

	/* CONFIRMATIONS: C as an admin, R as a root and logged, D not at all. */
	CHECK(fzn_node_admin_confirm(NULL, &c.ops, &c.id, &c_chain, r.id.pubkey, b_hops[1], &c_revs)
	              == FZN_NODE_REVOKE_OK
	              && c_revs.confirms_used == 1u && rows_in(&c, FZN_PERSIST_ADMIN_CONFIRM) == 1u,
	      "C's confirmation of A's grant was not admitted and saved");
	logged = r_roots.log.used;
	CHECK(fzn_node_admin_confirm(&r_roots, &r.ops, &r.id, NULL, r.id.pubkey, b_hops[1], &r_revs)
	              == FZN_NODE_REVOKE_OK
	              && r_revs.confirms_used == 1u && r_roots.log.used == logged + 1u,
	      "R's confirmation was not admitted, or not logged as its act");
	CHECK(fzn_node_admin_confirm(NULL, &d.ops, &d.id, NULL, r.id.pubkey, b_hops[1], &c_revs)
	              == FZN_NODE_REVOKE_NOT_ROOT,
	      "a node neither root nor admin confirmed");

	/* B VOTES ON ITS ADMIN CHAIN, and the chain travels and reloads with it. */
	CHECK(fzn_node_revoke(&b.id, r.id.pubkey, fzn_node_admin_chain_view(&b_chain), cap,
	                      d.id.pubkey, 1400u, &b_revs, &b.ops) == FZN_NODE_REVOKE_OK
	              && b_revs.admins_used == 1u,
	      "B could not vote on its admin chain, or was not taken as an admin");
	CHECK(stream_pull_as(&b, NULL, fzn_node_admin_chain_view(&b_chain), &t, r.id.pubkey,
	                     &t_revs, &pull) == FZN_NODE_PULL_OK
	              && pull.learned == 1u && t_revs.admins_used == 1u,
	      "B's vote did not travel on its admin chain");
	CHECK(admin_store(&fresh, e[5], ad[5], cf[5], &adm, NULL)
	              && fzn_node_revocations_load(&b.ops, &fresh, r.id.pubkey, NULL,
	                                           fzn_node_admin_chain_view(&b_chain), &b.sign,
	                                           &hash_ops, &count) == FZN_PERSIST_OK
	              && count == 1u && fresh.admins_used == 1u,
	      "B's vote was not admitted again on its admin chain at start");
}

/* ---- the estate's k, sec 418 ------------------------------------------ */

/* R, the genesis, sets k to 3 and then to 1, each logged as a setting and the
 * second replacing the first; M, no root, cannot set it; M pulls R's records
 * and reads 1; a restart of R reads 1 from its store. */
static void test_the_estates_k_travels(void)
{
	static struct node r, m;
	static fzn_node_roots_t r_roots, m_roots, again;
	size_t learned = 0, count = 0;

	CHECK(node_up(&r) && node_up(&m)
	              && fzn_node_roots_init(&r_roots, r.id.pubkey, &r.sign, &hash_ops)
	                         == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_init(&m_roots, r.id.pubkey, &m.sign, &hash_ops)
	                         == FZN_NODE_ROOTS_OK,
	      "fixture: the nodes and their roots");
	CHECK(fzn_node_roots_quorum(&r_roots, 2u) == 2u, "no setting did not read the fallback");
	CHECK(fzn_node_roots_set_quorum(&r_roots, &r.ops, r.id.pubkey, &r.sign, 3u)
	              == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_quorum(&r_roots, 2u) == 3u && r_roots.log.used == 1u
	              && r_roots.log.entries[0].kind == (uint8_t)FZN_ROOT_ACT_SETTING,
	      "R's setting of 3 did not take, or was not logged as a setting");
	CHECK(fzn_node_roots_set_quorum(&r_roots, &r.ops, r.id.pubkey, &r.sign, 1u)
	              == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_quorum(&r_roots, 2u) == 1u,
	      "R's lowering to 1 did not replace its 3");
	CHECK(fzn_node_roots_set_quorum(&m_roots, &m.ops, m.id.pubkey, &m.sign, 4u)
	              == FZN_NODE_ROOTS_NOT_ROOT,
	      "a node that stands as no root set k");
	CHECK(roots_sync(&r, &m_roots, &m, &learned) == FZN_NODE_PULL_OK
	              && fzn_node_roots_quorum(&m_roots, 2u) == 1u,
	      "M, having pulled R's records, does not read k = 1");
	CHECK(fzn_node_roots_init(&again, r.id.pubkey, &r.sign, &hash_ops) == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_load(&again, &r.ops, &count) == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_quorum(&again, 2u) == 1u,
	      "R's k did not come back from its store");
}

/* ---- pairing as a root by identity, sec 419 --------------------------- */

/* M's identity is no root until R, the genesis, adds it; R itself pairs as it
 * always has. Once added, M pairs D with one hop and R's add of M: D, pinning
 * R, accepts it, and M's roots verify D's chain where the genesis pin alone
 * refuses it. A proof ending at another key is refused before anything is
 * minted. */
static void test_a_node_pairs_as_a_root_by_identity(const fzn_cap_id_t *cap)
{
	static struct node r, m, d, x;
	static fzn_node_roots_t r_roots, m_roots;
	static fzn_revocation_t entries[4];
	static fzn_node_peer_t peers[2];
	uint8_t proof[FZN_PROVISION_PROOF_MAX][FZN_PROVISION_PROOF_ITEM_LEN];
	uint8_t card[FZN_PROVISION_MAX_LEN], wrong[FZN_ROOT_ADD_LEN];
	fzn_node_authority_t auth = { 0 }, bad = { 0 };
	fzn_revocation_store_t revs;
	fzn_prekey_record_t d_rec;
	fzn_node_pairing_t d_pairing;
	fzn_chain_hop_t view;
	fzn_chain_t verdict;
	size_t learned = 0, card_len = 0, loaded = 0;

	CHECK(node_up(&r) && node_up(&m) && node_up(&d) && node_up(&x)
	              && fzn_prekey_open(d.id.prekey_record, FZN_PREKEY_LEN_TOTAL, &d_rec)
	                         == FZN_PREKEY_OK
	              && fzn_node_roots_init(&r_roots, r.id.pubkey, &r.sign, &hash_ops)
	                         == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_init(&m_roots, r.id.pubkey, &m.sign, &hash_ops)
	                         == FZN_NODE_ROOTS_OK,
	      "fixture: the nodes and their roots");
	CHECK(fzn_node_roots_identity_root(&m_roots, &m.ops, m.id.pubkey, proof, &auth)
	              == FZN_NODE_ROOTS_NOT_ROOT
	              && fzn_node_roots_identity_root(&r_roots, &r.ops, r.id.pubkey, proof, &auth)
	                         == FZN_NODE_ROOTS_NOT_ROOT,
	      "M before any add, or R the genesis, was taken as a root by proof");
	CHECK(fzn_node_roots_change(&r_roots, &r.ops, r.id.pubkey, &r.sign, 0, m.id.pubkey, NULL)
	              == FZN_NODE_ROOTS_OK
	              && roots_sync(&r, &m_roots, &m, &learned) == FZN_NODE_PULL_OK
	              && fzn_node_roots_identity_root(&m_roots, &m.ops, m.id.pubkey, proof, &auth)
	                         == FZN_NODE_ROOTS_OK
	              && auth.hop_count == 0u && auth.proof_count == 1u,
	      "M, added by R, did not become a root by proof with R's add");

	/* A PROOF ENDING AT ANOTHER KEY is refused, and nothing is saved. */
	CHECK(fzn_root_add_issue(r.id.pubkey, x.id.pubkey, &r.sign, wrong) == FZN_ROOT_LOG_OK,
	      "fixture: R's add of X");
	bad.proof = (const uint8_t (*)[FZN_PROVISION_PROOF_ITEM_LEN])wrong;
	bad.proof_count = 1u;
	CHECK(fzn_node_pair(&m.id, r.id.pubkey, cap, &bad, 0, &m.ops, d_rec, 1200u, 1200u + 86400u,
	                    card, sizeof(card), &card_len) == FZN_NODE_PAIR_NOT_ROOT
	              && rows_in(&m, FZN_PERSIST_NODE_PEER) == 0u,
	      "a proof ending at X let M pair as a root");

	CHECK(fzn_node_pair(&m.id, r.id.pubkey, cap, &auth, 0, &m.ops, d_rec, 1200u, 1200u + 86400u,
	                    card, sizeof(card), &card_len) == FZN_NODE_PAIR_OK
	              && card_len == FZN_PROVISION_LEN(1, 1),
	      "M could not pair D as a root by proof, or the card is not one hop and one add");
	CHECK(fzn_node_pairing_accept(&d.id, card, card_len, 1300u, &d.ops, &d_pairing)
	              == FZN_NODE_PAIR_OK
	              && memcmp(d_pairing.node, m.id.pubkey, FZN_PUBKEY_LEN) == 0,
	      "D, pinning R, refused M's card");
	CHECK(fzn_node_peers_load(&m.ops, peers, 2, &loaded) == FZN_PERSIST_OK && loaded == 1u
	              && peers[0].hop_count == 1u
	              && fzn_hop_open(peers[0].hop_bytes[0], FZN_HOP_LEN, &view) == FZN_CHAIN_OK
	              && fzn_revocation_store_init(&revs, entries, 4) == FZN_CHAIN_OK
	              && fzn_node_roots_attach(&m_roots, &revs) == FZN_NODE_ROOTS_OK,
	      "fixture: M's peer and a store with M's roots");
	CHECK(fzn_chain_verify(&view, 1, r.id.pubkey, cap, 1400u, &m.sign, &revs, NULL, &verdict)
	              == FZN_CHAIN_OK
	              && fzn_chain_verify(&view, 1, r.id.pubkey, cap, 1400u, &m.sign, NULL, NULL,
	                                  &verdict) == FZN_CHAIN_ERR_WRONG_ROOT,
	      "M's roots do not verify D's chain, or the genesis pin alone took it");
}

int main(void)
{
	static struct node node, device, stranger;
	fzn_prekey_record_t device_record;
	fzn_cap_id_t cap, other;
	uint8_t card[FZN_PROVISION_MAX_LEN];
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
	CHECK(fzn_node_pair(&node.id, node.id.pubkey, &cap, NULL, 0, &node.ops, device_record, 2000u,
	                    2000u + 86400u, card, sizeof(card), &card_len) == FZN_NODE_PAIR_OK,
	      "a node would not pair a device");
	CHECK(card_len == FZN_PROVISION_LEN(1, 0), "the card is not a whole one-hop card");

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
		uint8_t blob[FZN_NODE_PAIRING_BLOB_MAX];
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
		CHECK(memcmp(kept.node, node.id.pubkey, FZN_PUBKEY_LEN) == 0
		              && memcmp(kept.capability.b, cap.b, FZN_CAP_ID_LEN) == 0
		              && memcmp(kept.send_key, send_key, FZN_AEAD_KEY_LEN) == 0,
		      "the stored pairing is not the node, the grant and the session accepted");
		CHECK(fzn_node_pairing_load(&device.ops, node.id.pubkey, &back) == FZN_PERSIST_OK
		              && memcmp(&back, &kept, sizeof(back)) == 0,
		      "the pairing did not come back as it was stored");

		/* THE BYTES, AT THE OFFSETS persist.situ STATES: node at 2,
		 * capability at 34, keys at 66 and 98, the hop count at 130 and
		 * the chain from 131. */
		CHECK(fzn_node_pairing_pack(&kept, blob, sizeof(blob), &blob_len) == FZN_PERSIST_OK
		              && blob_len == 310u && blob[0] == 1u && blob[1] == 7u
		              && memcmp(blob + 2, kept.node, 32) == 0
		              && memcmp(blob + 34, kept.capability.b, 32) == 0
		              && memcmp(blob + 66, kept.send_key, 32) == 0
		              && memcmp(blob + 98, kept.send_ckey, 32) == 0
		              && blob[130] == 1u
		              && memcmp(blob + 131, kept.chain[0], FZN_HOP_LEN) == 0,
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
	test_an_estate(&cap);
	test_votes_travel(&cap);
	test_several_roots_at_a_node(&cap);
	test_a_node_acts_as_a_root();
	test_a_card_proves_its_root(&cap);
	test_a_node_pairs_through_its_root_key(&cap);
	test_confirmations_travel();
	test_admins_at_the_node(&cap);
	test_the_estates_k_travels();
	test_a_node_pairs_as_a_root_by_identity(&cap);

	/* ---- A NODE THAT IS NOT ITS OWN ROOT PAIRS NOTHING, and writes nothing. */
	stranger.store.saves = 0;
	CHECK(fzn_node_pair(&stranger.id, node.id.pubkey, &cap, NULL, 0, &stranger.ops, device_record,
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
		CHECK(fzn_node_pair(&stranger.id, stranger.id.pubkey, &cap, NULL, 0, &stranger.ops,
		                    forged_record, 2000u, 0u, card, sizeof(card), &card_len)
		              == FZN_NODE_PAIR_DEVICE,
		      "a device whose prekey signature is broken was paired");
		CHECK(stranger.store.saves == 0u && card_len == 0u,
		      "a refused device was saved or given a card");
	}

	/* ---- A STORE THAT REFUSES GETS NO CARD: no card for a device the node
	 * does not hold. */
	stranger.store.refuse_saves = 1;
	CHECK(fzn_node_pair(&stranger.id, stranger.id.pubkey, &cap, NULL, 0, &stranger.ops, device_record,
	                    2000u, 0u, card, sizeof(card), &card_len) == FZN_NODE_PAIR_STORE,
	      "a pairing the store refused was reported as anything but the store's");
	CHECK(card_len == 0u, "a card was made for a device the node could not save");

	CHECK(fzn_node_pair(NULL, node.id.pubkey, &cap, NULL, 0, &node.ops, device_record, 1u, 0u, card,
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
