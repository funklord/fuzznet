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
#include "../roster.h"
#include "../succession.h"
#include "../journal.h"
#include "../apply.h"
#include "../../contact/contact.h"
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

/* A NODE'S RECORDS, in memory: what its journal keeps. sec 505. */
#define JOURNAL_SLOTS 96u

struct record_slot {
	int used;
	uint8_t issuer[FZN_PUBKEY_LEN];
	uint32_t stream;
	uint64_t seq;
	uint8_t bytes[FZN_RECORD_MAX_LEN];
	size_t len;
};

struct record_mem {
	struct record_slot slots[JOURNAL_SLOTS];
};

struct node {
	struct mem_store store;
	fzn_persist_ops_t ops;
	fzn_sign_monocypher_t signer;
	fzn_sign_ops_t sign;
	fzn_sign_seat_t seat;
	fzn_agree_secret_t agree_secret;
	fzn_trust_t trust;
	fzn_node_identity_t id;
	/* ITS JOURNAL, sec 505: over `records`, filled by the roots a case
	 * gives it (`journal_hook`) and from other nodes (`carry`). */
	struct record_mem records;
	fzn_record_store_ops_t record_ops;
	fzn_node_journal_t journal;
	/* ITS GRANT INDEX, kept across every apply context a case gives it:
	 * a grant is marked applied in the journal once, so the index that
	 * took it is the node's, as the daemon's one context is. */
	fzn_node_grant_t grants[FZN_NODE_APPLY_GRANTS_MAX];
	size_t grants_used;
};

static int record_put(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream,
                      uint64_t seq, const uint8_t *bytes, size_t len)
{
	struct record_mem *m = ctx;
	size_t i, free_one = JOURNAL_SLOTS;

	for (i = 0; i < JOURNAL_SLOTS; i++) {
		if (!m->slots[i].used) {
			if (free_one == JOURNAL_SLOTS)
				free_one = i;
			continue;
		}
		if (m->slots[i].stream == stream && m->slots[i].seq == seq
		    && memcmp(m->slots[i].issuer, issuer, FZN_PUBKEY_LEN) == 0) {
			free_one = i;
			break;
		}
	}
	if (free_one == JOURNAL_SLOTS || len > FZN_RECORD_MAX_LEN)
		return 0;
	m->slots[free_one].used = 1;
	memcpy(m->slots[free_one].issuer, issuer, FZN_PUBKEY_LEN);
	m->slots[free_one].stream = stream;
	m->slots[free_one].seq = seq;
	memcpy(m->slots[free_one].bytes, bytes, len);
	m->slots[free_one].len = len;
	return 1;
}

static int record_get(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream,
                      uint64_t seq, uint8_t *out, size_t cap, size_t *len_out, int *found_out)
{
	struct record_mem *m = ctx;
	size_t i;

	*found_out = 0;
	for (i = 0; i < JOURNAL_SLOTS; i++)
		if (m->slots[i].used && m->slots[i].stream == stream && m->slots[i].seq == seq
		    && memcmp(m->slots[i].issuer, issuer, FZN_PUBKEY_LEN) == 0) {
			*found_out = 1;
			if (m->slots[i].len > cap)
				return 0;
			memcpy(out, m->slots[i].bytes, m->slots[i].len);
			*len_out = m->slots[i].len;
			return 1;
		}
	return 0;
}

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
	n->record_ops.put = record_put;
	n->record_ops.get = record_get;
	n->record_ops.ctx = &n->records;
	return fzn_node_identity_create(&env, 1000u, &n->agree_secret, &n->trust, &n->id)
	               == FZN_NODE_IDENTITY_OK
	       && fzn_node_journal_init_store(&n->journal, &n->record_ops, &n->sign, &hash_ops)
	                  == FZN_NODE_JOURNAL_OK;
}

/* ---- the journal between test nodes, sec 505 ---------------------------- */

/* What a node's roots tell its journal: each act's object, as the daemon's
 * hook writes it. */
static int journal_logged(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN],
                          const fzn_sign_ops_t *sign, uint8_t kind,
                          const uint8_t act[FZN_ROOT_ACT_ID_LEN], const uint8_t *record,
                          size_t len)
{
	(void)kind;
	(void)act;
	return fzn_node_journal_append_object((fzn_node_journal_t *)ctx, pubkey, sign, record, len,
	                                      1000u, NULL)
	       == FZN_NODE_JOURNAL_OK;
}

/* `roots` log into `n`'s journal from here on. */
static void journal_hook(struct node *n, fzn_node_roots_t *roots)
{
	roots->logged = journal_logged;
	roots->logged_ctx = &n->journal;
}

/* `roots` for `n`, logging into its journal and, since sec 506, judging
 * cuts by it: what every node's roots do in this suite, as the daemon's do. */
static fzn_node_roots_err_t roots_of(fzn_node_roots_t *roots, const uint8_t genesis[FZN_PUBKEY_LEN],
                                     struct node *n)
{
	fzn_node_roots_err_t err = fzn_node_roots_init(roots, genesis, &n->sign, &hash_ops);

	if (err == FZN_NODE_ROOTS_OK) {
		journal_hook(n, roots);
		err = fzn_node_roots_set_journal(roots, &n->journal);
	}
	return err;
}

/* A grant `n` made, logged by `roots` as its act -- what the admin verb and
 * `fuzznetd --pair` do, and `fzn_node_pair` does not. */
static int log_grant_of(struct node *n, fzn_node_roots_t *roots, const uint8_t hop[FZN_HOP_LEN])
{
	return fzn_node_roots_log_signed(roots, &n->ops, n->id.pubkey, &n->sign, n->id.pubkey,
	                                 (uint8_t)FZN_ROOT_ACT_GRANT, hop, FZN_HOP_LEN)
	       == FZN_NODE_ROOTS_OK;
}

static int journal_ask(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
                       size_t reply_cap, size_t *reply_len)
{
	*reply_len = fzn_node_journal_answer((fzn_node_journal_t *)ctx, request, request_len, reply,
	                                     reply_cap);
	return *reply_len != 0u;
}

/* How far `n`'s journal holds `key`'s estate stream: 0 when not followed. */
static uint64_t received_of(const struct node *n, const uint8_t key[FZN_PUBKEY_LEN])
{
	size_t e;

	for (e = 0; e < n->journal.journal.used; e++)
		if (memcmp(n->journal.entries[e].issuer, key, FZN_PUBKEY_LEN) == 0)
			return n->journal.entries[e].received;
	return 0;
}

/* What a node applies its journal to: `revs` under root R, with member
 * grants of `cap`. */
static void apply_to(fzn_node_apply_t *ap, fzn_revocation_store_t *revs,
                     const uint8_t root[FZN_PUBKEY_LEN], const fzn_cap_id_t *cap)
{
	memset(ap, 0, sizeof(*ap));
	ap->revocations = revs;
	ap->root = root;
	ap->capability = cap;
}

/* THE ACT LOG IS THE JOURNAL, sec 508: every record `n` holds, of every
 * stream -- what a roots' log count was. */
static uint64_t journal_total(const struct node *n)
{
	uint64_t total = 0;
	size_t e;

	for (e = 0; e < n->journal.journal.used; e++)
		total += n->journal.entries[e].received;
	return total;
}

/* How many of `key`'s records `n` holds whose kind -- its object's tag -- is
 * `kind`. */
static size_t kinds_of(struct node *n, const uint8_t key[FZN_PUBKEY_LEN], uint32_t kind)
{
	static uint8_t buf[FZN_RECORD_MAX_LEN];
	uint64_t seq, top = received_of(n, key);
	size_t count = 0;

	for (seq = 1u; seq <= top; seq++) {
		fzn_record_t rec;

		if (fzn_record_store_get(&n->journal.store, key, FZN_NODE_JOURNAL_STREAM, seq, buf,
		                         sizeof(buf), &rec) == FZN_RECORD_STORE_OK
		    && fzn_record_kind(rec) == kind)
			count++;
	}
	return count;
}

/* `into` APPLIES WHAT IT HOLDS: `ap` names the subsystems; its journal is
 * set here. */
static int apply_at(struct node *into, fzn_node_apply_t *ap, fzn_node_apply_tally_t *t)
{
	int ok;

	ap->journal = &into->journal;
	ap->store = &into->ops;
	ap->sign = &into->sign;
	ap->hash = &hash_ops;
	memcpy(ap->grants, into->grants, sizeof(into->grants));
	ap->grants_used = into->grants_used;
	ok = fzn_node_apply_round(ap, t) == FZN_NODE_PULL_OK;
	memcpy(into->grants, ap->grants, sizeof(into->grants));
	into->grants_used = ap->grants_used;
	return ok;
}

/* CARRY: `into` follows every stream `from` holds, pulls them through the
 * exchange as a remote hop would carry it, and applies. */
static int carry(struct node *from, struct node *into, fzn_node_apply_t *ap,
                 fzn_node_apply_tally_t *t)
{
	static uint8_t reply[8192];
	fzn_exchange_tally_t xt;
	size_t e;

	for (e = 0; e < from->journal.journal.used; e++)
		if (fzn_node_journal_follow(&into->journal, from->journal.entries[e].issuer, NULL)
		    != FZN_NODE_JOURNAL_OK)
			return 0;
	if (fzn_node_journal_pull(&into->journal, journal_ask, &from->journal, reply, sizeof(reply),
	                          &xt) != FZN_EXCHANGE_OK || xt.refused || xt.forks)
		return 0;
	return apply_at(into, ap, t);
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
		CHECK(fzn_node_revoke(NULL, &node->id, node->id.pubkey, NULL, cap, device->id.pubkey, 3000u,
		                      &revoked, &node->ops) == FZN_NODE_REVOKE_OK,
		      "the node would not revoke the device it paired");
		CHECK(fzn_node_revoke(NULL, &node->id, node->id.pubkey, NULL, cap, device->id.pubkey, 3001u,
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
		              && fzn_node_revoke(NULL, &device->id, node->id.pubkey, NULL, cap, node->id.pubkey,
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

/* ---- AN ESTATE OF THREE: a root R, a node N that joins it, and a device D
 * that N pairs by extending the grant R gave it. sec 383. */
static void test_an_estate(const fzn_cap_id_t *cap)
{
	static struct node r, n, d, other;
	static fzn_node_roots_t r_roots;
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

	/* ---- THE SAME PAIRING FROM THE GRANT, sec 579: D builds it from the
	 * chain R -> N -> D and N's prekey, with no card, and it is the pairing
	 * the card gave -- the session above all. Parts that disagree are
	 * refused: a chain ending at N, another node's prekey, and D's chain
	 * taken by another device. */
	{
		fzn_node_pairing_t built;

		CHECK(fzn_node_pairing_from_grant(&d.id, r.id.pubkey,
		                                  (const uint8_t (*)[FZN_HOP_LEN])n_peers[0].hop_bytes,
		                                  2u, n.id.prekey_record, 1300u, &d.ops, &built)
		                      == FZN_NODE_PAIR_OK
		              && memcmp(built.node, d_pairing.node, FZN_PUBKEY_LEN) == 0
		              && memcmp(built.send_key, d_pairing.send_key, FZN_AEAD_KEY_LEN) == 0
		              && memcmp(built.send_ckey, d_pairing.send_ckey, FZN_COMMITMENT_KEY_LEN) == 0
		              && memcmp(built.capability.b, d_pairing.capability.b, FZN_CAP_ID_LEN) == 0
		              && built.hop_count == d_pairing.hop_count
		              && memcmp(built.chain, d_pairing.chain, 2u * FZN_HOP_LEN) == 0,
		      "the pairing D built from N's grant is not the one N's card gave");
		CHECK(fzn_node_pairing_from_grant(&d.id, r.id.pubkey,
		                                  (const uint8_t (*)[FZN_HOP_LEN])n_peers[0].hop_bytes,
		                                  1u, n.id.prekey_record, 1300u, &d.ops, &built)
		              == FZN_NODE_PAIR_REFUSED,
		      "a chain ending at N made D a pairing");
		CHECK(fzn_node_pairing_from_grant(&d.id, r.id.pubkey,
		                                  (const uint8_t (*)[FZN_HOP_LEN])n_peers[0].hop_bytes,
		                                  2u, other.id.prekey_record, 1300u, &d.ops, &built)
		              == FZN_NODE_PAIR_REFUSED,
		      "another node's prekey made D a pairing to N");
		CHECK(fzn_node_pairing_from_grant(&other.id, r.id.pubkey,
		                                  (const uint8_t (*)[FZN_HOP_LEN])n_peers[0].hop_bytes,
		                                  2u, n.id.prekey_record, 1300u, &other.ops, &built)
		              == FZN_NODE_PAIR_REFUSED,
		      "D's chain made another device a pairing");
	}

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
		              && fzn_revocation_issue(r.id.pubkey, cap, d.id.pubkey, 1400u, 0u, NULL, &r.sign,
		                                      record) == FZN_CHAIN_OK
		              && fzn_revocation_open(record, sizeof(record), &rec) == FZN_CHAIN_OK
		              && fzn_revocation_admit(&revoked, fzn_revocation_offer_root(rec),
		                                      r.id.pubkey, &n.sign, &hash_ops, NULL)
		                         == FZN_CHAIN_OK,
		      "N would not admit R's revocation of D");
		CHECK(granted_by(&n, r.id.pubkey, &d, cap, &revoked) == 0,
		      "N granted a device the estate root had revoked");
	}

	/* ---- N LEARNS R's REVOCATIONS FROM R's JOURNAL. sec 384, carried
	 * since sec 505. Before that, a record N issued as its own root before it
	 * joined, which the load must skip rather than fail on. */
	{
		static fzn_revocation_t r_entries[4], n_entries[4], l_entries[4];
		static fzn_node_apply_t n_ap;
		fzn_revocation_store_t r_revs, n_revs, reloaded;
		fzn_node_apply_tally_t t;
		uint8_t record[FZN_REVOCATION_LEN];
		size_t count = 0;

		CHECK(roots_of(&r_roots, r.id.pubkey, &r)
		              == FZN_NODE_ROOTS_OK
		              && fzn_revocation_store_init(&r_revs, r_entries, 4) == FZN_CHAIN_OK
		              && fzn_revocation_store_init(&n_revs, n_entries, 4) == FZN_CHAIN_OK
		              && fzn_revocation_store_init(&reloaded, l_entries, 4) == FZN_CHAIN_OK
		              && fzn_node_revoke(NULL, &n.id, n.id.pubkey, NULL, cap, other.id.pubkey, 1150u,
		                                 &n_revs, &n.ops) == FZN_NODE_REVOKE_OK
		              && fzn_revocation_store_init(&n_revs, n_entries, 4) == FZN_CHAIN_OK,
		      "fixture: revocation stores, or N's pre-join revocation");
		journal_hook(&r, &r_roots);
		apply_to(&n_ap, &n_revs, r.id.pubkey, cap);

		/* Nothing revoked yet: carrying an empty journal is a carry, and
		 * applies nothing. */
		CHECK(carry(&r, &n, &n_ap, &t) && t.applied == 0u && t.refused == 0u,
		      "carrying a root's empty journal failed, or applied something");

		CHECK(fzn_node_revoke(&r_roots, &r.id, r.id.pubkey, NULL, cap, d.id.pubkey, 1400u,
		                      &r_revs, &r.ops) == FZN_NODE_REVOKE_OK,
		      "fixture: R would not revoke D");
		CHECK(carry(&r, &n, &n_ap, &t) && t.applied == 1u,
		      "N did not apply R's revocation of D from R's journal");
		CHECK(granted_by(&n, r.id.pubkey, &d, cap, &n_revs) == 0,
		      "N granted D after carrying R's revocation of it");
		CHECK(carry(&r, &n, &n_ap, &t) && t.applied == 0u && t.refused == 0u,
		      "carrying a journal N already holds applied or refused something");

		/* A RESTART with R unreachable: what N saved is what it denies by. */
		CHECK(fzn_node_revocations_load(&n.ops, &reloaded, r.id.pubkey, NULL, NULL, &n.sign, &hash_ops,
		                                &count) == FZN_PERSIST_OK
		              && count == 1u,
		      "N's restart did not reload exactly the one revocation it learned");
		CHECK(granted_by(&n, r.id.pubkey, &d, cap, &reloaded) == 0,
		      "after a restart N granted a device R had revoked");

		/* A RECORD R DID NOT SIGN, in another root's journal, waits for a
		 * chain and admits nothing. */
		CHECK(fzn_revocation_issue(other.id.pubkey, cap, d.id.pubkey, 1500u, 0u, NULL, &other.sign,
		                           record) == FZN_CHAIN_OK
		              && fzn_node_journal_append_object(&other.journal, other.id.pubkey,
		                                                &other.sign, record, sizeof(record),
		                                                1500u, NULL) == FZN_NODE_JOURNAL_OK,
		      "fixture: another root's record in its journal");
		CHECK(carry(&other, &n, &n_ap, &t) && t.applied == 0u && t.waiting == 1u,
		      "N admitted a revocation its root did not sign");
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
		size_t count = 0;

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
		CHECK(fzn_node_revoke(NULL, &n.id, r.id.pubkey, NULL, cap, e.id.pubkey, 1800u, &mine,
		                      &n.ops) == FZN_NODE_REVOKE_NOT_ROOT,
		      "a member revoked as though it were the estate's root");
		CHECK(fzn_node_revoke(NULL, &e.id, n.id.pubkey, &leaf, cap, d.id.pubkey, 1800u, &mine,
		                      &e.ops) == FZN_NODE_REVOKE_NOT_ROOT,
		      "a device revoked through a grant it may not pass on");

		CHECK(fzn_node_revoke(NULL, &n.id, r.id.pubkey, &authority, cap, e.id.pubkey, 1800u, &mine,
		                      &n.ops) == FZN_NODE_REVOKE_OK,
		      "N would not revoke the device it paired, through its own chain");
		CHECK(granted_by(&n, r.id.pubkey, &e, cap, &mine) == 0,
		      "N granted a device it had itself revoked");
		CHECK(fzn_node_revoke(NULL, &n.id, r.id.pubkey, &authority, cap, e.id.pubkey, 1801u, &mine,
		                      &n.ops) == FZN_NODE_REVOKE_ALREADY,
		      "a member's second revocation of one device was not reported as already");

		/* A RECORD OF N's FOR A CAPABILITY ITS CHAIN DOES NOT CARRY, written
		 * into the store by hand since `fzn_node_revoke` cannot produce one.
		 * It could never admit, so the load skips it rather than failing. */
		{
			fzn_cap_id_t elsewhere = *cap;
			uint8_t blob[FZN_PERSIST_HEAD_LEN + FZN_REVOCATION_LEN];

			elsewhere.b[0] ^= 1u;
			CHECK(fzn_revocation_issue(n.id.pubkey, &elsewhere, d.id.pubkey, 1850u, 0u, NULL,
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
			static fzn_node_apply_t a_ap;
			fzn_revocation_store_t after, again, root_revs;
			fzn_node_apply_tally_t t;

			CHECK(fzn_revocation_store_init(&after, a_entries, 8) == FZN_CHAIN_OK
			              && fzn_revocation_store_init(&again, b_entries, 8) == FZN_CHAIN_OK
			              && fzn_revocation_store_init(&root_revs, c_entries, 8)
			                         == FZN_CHAIN_OK,
			      "fixture: stores for the undo");
			CHECK(fzn_node_unrevoke(NULL, &n.id, r.id.pubkey, NULL, e.id.pubkey, 1900u, &mine,
			                        &n.ops) == FZN_NODE_REVOKE_NOT_ROOT,
			      "a member undid a revocation as though it were the root");
			CHECK(fzn_node_unrevoke(NULL, &n.id, r.id.pubkey, &authority, e.id.pubkey, 1900u, &mine,
			                        &n.ops) == FZN_NODE_REVOKE_OK,
			      "N would not undo its own revocation of E");
			CHECK(granted_by(&n, r.id.pubkey, &e, cap, &mine) == 1,
			      "N still denied E after undoing its revocation");
			CHECK(fzn_node_unrevoke(NULL, &n.id, r.id.pubkey, &authority, e.id.pubkey, 1901u, &mine,
			                        &n.ops) == FZN_NODE_REVOKE_NOT_REVOKED,
			      "undoing twice was not reported as nothing to undo");
			CHECK(fzn_node_revocations_load(&n.ops, &after, r.id.pubkey, &authority, NULL, &n.sign,
			                                &hash_ops, &count) == FZN_PERSIST_OK
			              && granted_by(&n, r.id.pubkey, &e, cap, &after) == 1,
			      "after a restart N denied E again, or would not load the withdrawal");
			CHECK(fzn_node_revoke(NULL, &n.id, r.id.pubkey, &authority, cap, e.id.pubkey, 1950u,
			                      &after, &n.ops) == FZN_NODE_REVOKE_OK
			              && granted_by(&n, r.id.pubkey, &e, cap, &after) == 0,
			      "revoking E again after the undo did not deny it");
			CHECK(fzn_node_revocations_load(&n.ops, &again, r.id.pubkey, &authority, NULL, &n.sign,
			                                &hash_ops, &count) == FZN_PERSIST_OK
			              && granted_by(&n, r.id.pubkey, &e, cap, &again) == 0,
			      "after a restart N granted E, revoked again after an undo");

			/* THE ROOT UNDOES, AND A MEMBER LEARNS IT FROM THE JOURNAL:
			 * the withdrawal is R's next act, and it lands on the
			 * revocation N already holds. */
			CHECK(granted_by(&n, r.id.pubkey, &d, cap, &again) == 0,
			      "fixture: N does not hold R's revocation of D");
			CHECK(fzn_node_unrevoke(&r_roots, &r.id, r.id.pubkey, NULL, d.id.pubkey, 2000u,
			                        &root_revs, &r.ops) == FZN_NODE_REVOKE_OK,
			      "R would not undo its revocation of D");
			apply_to(&a_ap, &again, r.id.pubkey, cap);
			CHECK(carry(&r, &n, &a_ap, &t) && t.applied == 1u
			              && granted_by(&n, r.id.pubkey, &d, cap, &again) == 1,
			      "N did not learn from R's journal that R had undone its revocation of D");
		}
		fzn_wipe(&e_pairing, sizeof(e_pairing));
	}
	fzn_wipe(&joined, sizeof(joined));
	fzn_wipe(&d_pairing, sizeof(d_pairing));
}

/* ---- VOTES TRAVEL, sec 399 ------------------------------------------- */

/* ---- THE JOURNAL OVER THE REMOTE HOP, sec 505 ---------------------------- */

struct hop_asking {
	fzn_caller_t *caller;
	fzn_node_state_t *state;
};

/* One request over the hop: sent, one turn of the serving node, received. */
static int hop_ask(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
                   size_t reply_cap, size_t *reply_len)
{
	struct hop_asking *asking = ctx;
	uint32_t msg = 0;

	return fzn_caller_send(asking->caller, request, request_len, 3500u, &msg) == FZN_CALLER_OK
	       && fzn_node_run_once(asking->state, 1000) == 1
	       && fzn_caller_recv(asking->caller, msg, reply, reply_cap, reply_len, 1000u)
	                  == FZN_CALLER_OK;
}

static size_t hop_journal_remote(void *ctx, const uint8_t *request, size_t request_len,
                                 uint8_t *reply, size_t reply_cap)
{
	return fzn_node_journal_answer((fzn_node_journal_t *)ctx, request, request_len, reply,
	                               reply_cap);
}

/* CARRIED OVER THE HOP: `root` serves `fzn_node_admin_remote` with its
 * journal behind it, as fuzznetd does; `member` follows every stream `root`
 * holds and pulls them through the pairing it joined with, then applies. The
 * exchange tally lands in `xt`. 1 when the pull and the application ran. */
static int carried_over_hop(struct node *root, struct node *member, const fzn_cap_id_t *cap,
                            fzn_node_apply_t *ap, fzn_node_apply_tally_t *t,
                            fzn_exchange_tally_t *xt)
{
	static fzn_node_peer_t peers[4];
	static fzn_replay_entry_t entries[16];
	static uint8_t served[16384], reply[16384], slot_buf[1][16384];
	fzn_replay_window_t replay;
	fzn_node_pairing_t pairing;
	fzn_node_state_t state;
	fzn_node_admin_t admin;
	fzn_caller_t caller;
	fzn_partial_t slots[1];
	fzn_reasm_t table;
	fzn_aead_ops_t aead;
	fzn_udp_addr_t addr;
	struct hop_asking asking;
	size_t loaded = 0, e;
	int sfd = -1, dfd = -1, result = 0;

	memset(xt, 0, sizeof(*xt));
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
	state.reply = served;
	state.reply_cap = sizeof(served);
	memset(&admin, 0, sizeof(admin));
	admin.state = &state;
	admin.id = &root->id;
	admin.store = &root->ops;
	admin.journal_remote = hop_journal_remote;
	admin.journal_ctx = &root->journal;
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
	asking.caller = &caller;
	asking.state = &state;

	for (e = 0; e < root->journal.journal.used; e++)
		if (fzn_node_journal_follow(&member->journal, root->journal.entries[e].issuer, NULL)
		    != FZN_NODE_JOURNAL_OK)
			goto done;
	if (fzn_node_journal_pull(&member->journal, hop_ask, &asking, reply, sizeof(reply), xt)
	    == FZN_EXCHANGE_OK)
		result = apply_at(member, ap, t);
done:
	fzn_wipe(&caller, sizeof(caller));
out:
	fzn_wipe(&pairing, sizeof(pairing));
	if (sfd >= 0)
		fzn_udp_close(sfd);
	if (dfd >= 0)
		fzn_udp_close(dfd);
	return result;
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
 * R grants N, N grants D, R grants M, and R logs its two grants. R and N
 * each vote against D, each vote landing in its signer's journal. N carries
 * R's journal; M carries from N only and receives N's own vote AND R's,
 * which N only relayed, with the grant that gives N its chain -- one peer
 * serving every stream it holds is what lets a vote reach a host that never
 * spoke to its issuer. Then the journal over the remote hop, a restart that
 * replays the journal and applies it again, the latch across the network,
 * and a stranger's vote that waits for a chain without stopping anything.
 * sec 505: the journal carries what the vote stream carried. */
static void test_votes_travel(const fzn_cap_id_t *cap)
{
	static struct node r, n, d, m, stranger;
	static fzn_revocation_t r_e[8], n_e[8], m_e[8], l_e[8];
	static fzn_node_roots_t r_roots, n_roots;
	static fzn_node_apply_t n_ap, m_ap, l_ap;
	static fzn_node_journal_t replayed;
	fzn_revocation_store_t r_revs, n_revs, m_revs, reloaded;
	fzn_prekey_record_t n_rec, d_rec, m_rec;
	fzn_node_pairing_t n_joined, m_joined, d_pairing;
	fzn_node_authority_t authority = { 0 };
	fzn_node_apply_tally_t t;
	fzn_exchange_tally_t xt;
	uint8_t card[FZN_PROVISION_MAX_LEN];
	size_t card_len = 0;

	CHECK(node_up(&r) && node_up(&n) && node_up(&d) && node_up(&m) && node_up(&stranger)
	              && fzn_prekey_open(n.id.prekey_record, FZN_PREKEY_LEN_TOTAL, &n_rec)
	                         == FZN_PREKEY_OK
	              && fzn_prekey_open(d.id.prekey_record, FZN_PREKEY_LEN_TOTAL, &d_rec)
	                         == FZN_PREKEY_OK
	              && fzn_prekey_open(m.id.prekey_record, FZN_PREKEY_LEN_TOTAL, &m_rec)
	                         == FZN_PREKEY_OK,
	      "fixture: the nodes would not come up");
	CHECK(roots_of(&r_roots, r.id.pubkey, &r) == FZN_NODE_ROOTS_OK
	              && roots_of(&n_roots, r.id.pubkey, &n)
	                         == FZN_NODE_ROOTS_OK,
	      "fixture: R's and N's roots");
	journal_hook(&r, &r_roots);
	journal_hook(&n, &n_roots);
	CHECK(fzn_node_pair(&r.id, r.id.pubkey, cap, NULL, 1, &r.ops, n_rec, 1000u, 0u, card,
	                    sizeof(card), &card_len) == FZN_NODE_PAIR_OK
	              && fzn_node_join(&n.id, card, card_len, 1100u, &n.ops, &n.trust, &n_joined)
	                         == FZN_NODE_PAIR_OK
	              && fzn_node_pair(&r.id, r.id.pubkey, cap, NULL, 1, &r.ops, m_rec, 1000u, 0u,
	                               card, sizeof(card), &card_len) == FZN_NODE_PAIR_OK
	              && fzn_node_join(&m.id, card, card_len, 1100u, &m.ops, &m.trust, &m_joined)
	                         == FZN_NODE_PAIR_OK
	              && log_grant_of(&r, &r_roots, n_joined.chain[0])
	              && log_grant_of(&r, &r_roots, m_joined.chain[0]),
	      "fixture: N and M would not join R's estate, or R would not log the grants");
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
	apply_to(&n_ap, &n_revs, r.id.pubkey, cap);
	apply_to(&m_ap, &m_revs, r.id.pubkey, cap);

	/* ---- R's GRANTS ALONE carry and apply nothing but the index. */
	CHECK(carry(&r, &n, &n_ap, &t) && t.grants == 2u && t.applied == 0u && t.refused == 0u
	              && t.waiting == 0u,
	      "N did not index R's two grants, or applied something else");

	/* ---- ONE VOTE EACH, each in its signer's journal, and neither alone
	 * revokes. */
	CHECK(fzn_node_revoke(&r_roots, &r.id, r.id.pubkey, NULL, cap, d.id.pubkey, 1400u, &r_revs,
	                      &r.ops) == FZN_NODE_REVOKE_OK
	              && fzn_node_revoke(&n_roots, &n.id, r.id.pubkey, &authority, cap, d.id.pubkey,
	                                 1400u, &n_revs, &n.ops) == FZN_NODE_REVOKE_OK,
	      "R or N would not cast its vote against D");
	CHECK(received_of(&r, r.id.pubkey) == 3u && received_of(&n, n.id.pubkey) == 1u,
	      "R's journal does not hold its two grants and its vote, or N's its vote");
	CHECK(!d_revoked(&n_revs, &r, &n, &d, cap), "one vote of two revoked D at N");

	/* ---- N CARRIES R's JOURNAL, and at N the two make the quorum. N
	 * applies its own stream with it: its vote, which it holds already. */
	CHECK(carry(&r, &n, &n_ap, &t) && t.applied == 2u && t.refused == 0u,
	      "N did not apply R's vote and its own");
	CHECK(d_revoked(&n_revs, &r, &n, &d, cap), "two votes of two did not revoke D at N");

	/* ---- M CARRIES FROM N ONLY and receives both streams: N's own vote,
	 * and R's grants and vote, which N relayed. N's vote waits on the first
	 * pass if N's stream is read before R's grant, and applies on the next. */
	CHECK(carry(&n, &m, &m_ap, &t) && t.applied == 2u && t.refused == 0u && t.waiting == 0u,
	      "M did not apply both votes from N alone");
	CHECK(d_revoked(&m_revs, &r, &n, &d, cap),
	      "M, holding both votes, did not revoke D -- a relayed vote did not count");

	/* ---- AGAIN, AND OVER THE WIRE: M pulls R's journal through the
	 * pairing it joined with, from R's running remote hop. It holds R's
	 * stream already, so nothing is new and nothing is refused. */
	CHECK(carried_over_hop(&r, &m, cap, &m_ap, &t, &xt) && xt.refused == 0u && xt.forks == 0u
	              && xt.learned == 0u && t.applied == 0u,
	      "M's pull of R's journal over the remote hop failed, or took something twice");

	/* ---- A RESTART REPLAYS THE JOURNAL AND APPLIES IT AGAIN: a journal
	 * opened fresh over M's records, every stream followed, into a fresh
	 * store with a fresh index, revokes D as M did. */
	CHECK(fzn_node_journal_init_store(&replayed, &m.record_ops, &m.sign, &hash_ops)
	                      == FZN_NODE_JOURNAL_OK
	              && fzn_node_journal_follow(&replayed, r.id.pubkey, NULL) == FZN_NODE_JOURNAL_OK
	              && fzn_node_journal_follow(&replayed, n.id.pubkey, NULL) == FZN_NODE_JOURNAL_OK,
	      "fixture: M's journal replayed");
	apply_to(&l_ap, &reloaded, r.id.pubkey, cap);
	l_ap.journal = &replayed;
	l_ap.store = &m.ops;
	l_ap.sign = &m.sign;
	l_ap.hash = &hash_ops;
	CHECK(fzn_node_apply_round(&l_ap, &t) == FZN_NODE_PULL_OK && t.grants == 2u
	              && t.applied == 2u && t.refused == 0u,
	      "M's journal replayed did not apply its two grants and two votes again");
	CHECK(d_revoked(&reloaded, &r, &n, &d, cap), "after a restart M granted D again");

	/* ---- A FULL STORE STOPS THE ROUND, sec 506: Z, whose store holds one
	 * revocation, carries N's journal and meets the second vote with no
	 * room. The round fails, and that vote is left unmarked for the next
	 * one rather than skipped for ever. */
	{
		static struct node z;
		static fzn_revocation_t z_e[1];
		static fzn_node_apply_t z_ap;
		fzn_revocation_store_t z_revs;
		size_t e, short_of = 0;

		CHECK(node_up(&z) && fzn_revocation_store_init(&z_revs, z_e, 1) == FZN_CHAIN_OK,
		      "fixture: Z with room for one revocation");
		apply_to(&z_ap, &z_revs, r.id.pubkey, cap);
		CHECK(!carry(&n, &z, &z_ap, &t), "a round that met a full store reported success");
		for (e = 0; e < z.journal.journal.used; e++)
			if (z.journal.entries[e].applied < z.journal.entries[e].received)
				short_of++;
		CHECK(short_of == 1u, "the vote a full store had no room for was marked applied");
	}

	/* ---- A LEARNED VOTE THAT WILL NOT ADMIT AGAIN, written into a member
	 * Q's store by hand -- a stranger's -- fails Q's restart under R: a
	 * learned vote is saved only once admitted, so one that will not admit
	 * is a store changed underneath the node. sec 399. */
	{
		static struct node q;
		static fzn_revocation_t s_e[8];
		fzn_revocation_store_t scratch;
		uint8_t blob[FZN_PERSIST_HEAD_LEN + FZN_REVOCATION_LEN + 1u];
		uint8_t subject[FZN_PUBKEY_LEN];
		size_t count = 0;

		memset(subject, 0x5a, sizeof(subject));
		CHECK(node_up(&q)
		              && fzn_revocation_issue(stranger.id.pubkey, cap, d.id.pubkey, 1500u, 0u,
		                                      NULL, &stranger.sign, blob + FZN_PERSIST_HEAD_LEN)
		                         == FZN_CHAIN_OK
		              && fzn_persist_head_write(blob, sizeof(blob), FZN_REVOCATION_LEN + 1u,
		                                        FZN_PERSIST_BLOB_VOTE) == FZN_PERSIST_OK
		              && (blob[FZN_PERSIST_HEAD_LEN + FZN_REVOCATION_LEN] = 0u, 1)
		              && q.ops.save(q.ops.ctx, FZN_PERSIST_VOTE, subject, blob, sizeof(blob)),
		      "fixture: a stranger's vote in Q's store");
		CHECK(fzn_revocation_store_init(&scratch, s_e, 8) == FZN_CHAIN_OK
		              && fzn_node_revocations_load(&q.ops, &scratch, r.id.pubkey, NULL, NULL,
		                                           &q.sign, &hash_ops, &count)
		                         == FZN_PERSIST_ERR_SHAPE,
		      "a restart admitted past a learned vote that will not admit");
	}

	/* ---- A STRANGER'S VOTE, in its own journal, carried to M: its stream
	 * waits for a chain no grant gives it, nothing is refused, and D's
	 * standing is what it was. */
	{
		uint8_t vote[FZN_REVOCATION_LEN];

		CHECK(fzn_revocation_issue(stranger.id.pubkey, cap, d.id.pubkey, 1500u, 0u, NULL,
		                           &stranger.sign, vote) == FZN_CHAIN_OK
		              && fzn_node_journal_append_object(&stranger.journal, stranger.id.pubkey,
		                                                &stranger.sign, vote, sizeof(vote), 1500u,
		                                                NULL) == FZN_NODE_JOURNAL_OK,
		      "fixture: a stranger's vote in its journal");
		CHECK(carry(&stranger, &m, &m_ap, &t) && t.waiting == 1u && t.applied == 0u
		              && t.refused == 0u,
		      "a stranger's vote did not wait for a chain at M");
		CHECK(d_revoked(&m_revs, &r, &n, &d, cap), "a stranger's vote changed D at M");
	}

	/* ---- THE LATCH ACROSS THE NETWORK. N withdraws; M carries it from N
	 * and D stays revoked, one withdrawal of two. R withdraws; N carries it,
	 * M carries it from N, and D is restored. */
	{
		uint8_t old_vote[FZN_REVOCATION_LEN];

		CHECK(fzn_node_issued_revocation(&n.ops, d.id.pubkey, old_vote),
		      "fixture: N's vote as it was");
		/* N's OWN STREAM COMES BACK from M as it left: nothing new, and
		 * no fork. */
		CHECK(carry(&m, &n, &n_ap, &t) && t.applied == 0u && t.refused == 0u,
		      "N's own stream back from M was not the stream N wrote");
		CHECK(fzn_node_unrevoke(&n_roots, &n.id, r.id.pubkey, &authority, d.id.pubkey, 1600u,
		                        &n_revs, &n.ops) == FZN_NODE_REVOKE_OK
		              && carry(&n, &m, &m_ap, &t) && t.applied == 1u,
		      "N would not withdraw, or M would not apply the withdrawal");
		CHECK(d_revoked(&m_revs, &r, &n, &d, cap),
		      "one withdrawal of two restored D at M: the latch did not travel");

		CHECK(fzn_node_unrevoke(&r_roots, &r.id, r.id.pubkey, NULL, d.id.pubkey, 1700u, &r_revs,
		                        &r.ops) == FZN_NODE_REVOKE_OK
		              && carry(&r, &n, &n_ap, &t) && t.applied == 2u
		              && carry(&n, &m, &m_ap, &t) && t.applied == 1u,
		      "R's withdrawal did not travel R -> N -> M");
		CHECK(!d_revoked(&n_revs, &r, &n, &d, cap) && !d_revoked(&m_revs, &r, &n, &d, cap),
		      "two withdrawals of two left D revoked");

		/* A STALE COPY of N's vote, admitted at M after the withdrawal --
		 * as a restart replaying the journal into a store already loaded
		 * past it does -- is not saved over the withdrawal: a restart
		 * still finds D restored. sec 399. */
		{
			static fzn_node_vote_pull_t stale;
			static fzn_revocation_t a_e[8];
			fzn_revocation_store_t after;
			size_t count = 0;

			memset(&stale, 0, sizeof(stale));
			CHECK(fzn_node_votes_take(&stale, 'r', old_vote, sizeof(old_vote),
			                          (const uint8_t (*)[FZN_HOP_LEN])n_joined.chain, 1u,
			                          r.id.pubkey, &m.sign, &hash_ops, &m_revs, &m.ops)
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

		/* AN OBJECT N SIGNED THAT NO ADMISSION TAKES -- a vote for a
		 * capability its chain does not carry -- is refused at M and
		 * counted, and the next object in N's stream is still applied. */
		{
			uint8_t bogus[FZN_REVOCATION_LEN];
			fzn_cap_id_t elsewhere = *cap;

			elsewhere.b[0] ^= 1u;
			CHECK(fzn_revocation_issue(n.id.pubkey, &elsewhere, d.id.pubkey, 1750u, 0u, NULL,
			                           &n.sign, bogus) == FZN_CHAIN_OK
			              && fzn_node_journal_append_object(&n.journal, n.id.pubkey, &n.sign,
			                                                bogus, sizeof(bogus), 1750u, NULL)
			                         == FZN_NODE_JOURNAL_OK,
			      "fixture: N's vote for another capability, in its journal");
		}

		/* N REVOKES AGAIN, IN EPOCH 1, read off the record N signed: both
		 * withdrew epoch 0 -- R's withdrawal is the root's undo of it
		 * since sec 403 -- so a vote cast in 0 would sit under the root's
		 * floor and count for nothing. sec 400. And one vote of two, at N
		 * and at M, revokes nothing. */
		{
			uint8_t again[FZN_REVOCATION_LEN];
			fzn_revocation_record_t again_rec;

			CHECK(fzn_node_revoke(&n_roots, &n.id, r.id.pubkey, &authority, cap, d.id.pubkey,
			                      1800u, &n_revs, &n.ops) == FZN_NODE_REVOKE_OK
			              && fzn_node_issued_revocation(&n.ops, d.id.pubkey, again)
			              && fzn_revocation_open(again, sizeof(again), &again_rec)
			                         == FZN_CHAIN_OK
			              && fzn_revocation_epoch(again_rec) == 1u,
			      "N's vote after the root's undo was not cast in epoch 1, so it "
			      "counts for nothing");
		}
		CHECK(!d_revoked(&n_revs, &r, &n, &d, cap),
		      "one vote after a full undo revoked D at N: the node did not "
		      "cast it in the open epoch");
		CHECK(carry(&n, &m, &m_ap, &t) && t.refused == 1u && t.applied == 1u
		              && !d_revoked(&m_revs, &r, &n, &d, cap),
		      "N's refused object stopped the round at M, or N's vote in epoch 1 did not "
		      "reach M, or revoked D there alone");

		/* A COPY SUPERSEDED IN ANOTHER SLOT is skipped at a restart, not
		 * fatal: N applied its own withdrawal into its learned votes, then
		 * revoked again, so that copy names a target slot 9 no longer
		 * holds. sec 399. */
		{
			static fzn_revocation_t s_e[8];
			fzn_revocation_store_t scratch;
			size_t count = 0;

			CHECK(fzn_revocation_store_init(&scratch, s_e, 8) == FZN_CHAIN_OK
			              && fzn_node_revocations_load(&n.ops, &scratch, r.id.pubkey,
			                                           &authority, NULL, &n.sign, &hash_ops,
			                                           &count) == FZN_PERSIST_OK,
			      "N's restart failed on its own withdrawal superseded by a re-revocation");
		}
	}
	fzn_wipe(&n_joined, sizeof(n_joined));
	fzn_wipe(&m_joined, sizeof(m_joined));
	fzn_wipe(&d_pairing, sizeof(d_pairing));
}

/* ---- SEVERAL ROOTS AT A NODE, sec 407 --------------------------------- */

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
	fzn_revocation_record_t rec;
	size_t count = 0;

	CHECK(node_up(&r) && node_up(&b) && node_up(&n) && node_up(&d) && node_up(&stranger),
	      "fixture: the nodes");
	CHECK(fzn_revocation_store_init(&revs, e1, 8) == FZN_CHAIN_OK
	              && fzn_revocation_store_set_quorum(&revs, 2u, NULL, NULL, 0u) == FZN_CHAIN_OK
	              && roots_of(&roots, r.id.pubkey, &n)
	                         == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_attach(&roots, &revs) == FZN_NODE_ROOTS_OK,
	      "fixture: N's store with R's set attached");

	/* R ADDS B; B revokes D. */
	CHECK(fzn_root_add_issue(r.id.pubkey, b.id.pubkey, &r.sign, add) == FZN_ROOT_LOG_OK
	              && fzn_revocation_issue(b.id.pubkey, cap, d.id.pubkey, 1500u, 0u, NULL, &b.sign, rev)
	                         == FZN_CHAIN_OK
	              && fzn_revocation_open(rev, sizeof(rev), &rec) == FZN_CHAIN_OK,
	      "fixture: the add and the revocation");

	/* BEFORE N KNOWS OF B, B's revocation is another estate's. */
	CHECK(fzn_revocation_admit(&revs, fzn_revocation_offer_root(rec), r.id.pubkey, &n.sign,
	                           &hash_ops, NULL) == FZN_CHAIN_ERR_WRONG_ROOT,
	      "the control: B's revocation admitted before N knew B was a root");

	CHECK(fzn_node_roots_learn(&roots, &n.ops, add, sizeof(add)) == FZN_NODE_ROOTS_OK,
	      "N would not learn R's add of B");
	/* THE ROOTS THAT STAND, sec 450: R and B, R first. */
	{
		uint8_t standing[4][FZN_PUBKEY_LEN];

		CHECK(fzn_node_roots_standing(&roots, standing, 4u) == 2u
		              && !memcmp(standing[0], r.id.pubkey, FZN_PUBKEY_LEN)
		              && !memcmp(standing[1], b.id.pubkey, FZN_PUBKEY_LEN),
		      "R and B did not both stand");
		CHECK(fzn_node_roots_standing(&roots, standing, 1u) == 1u
		              && fzn_node_roots_standing(NULL, standing, 4u) == 0u,
		      "the standing roots overran their cap, or answered for no estate");
	}
	CHECK(fzn_revocation_admit(&revs, fzn_revocation_offer_root(rec), r.id.pubkey, &n.sign,
	                           &hash_ops, NULL) == FZN_CHAIN_OK
	              && d_revoked(&revs, &r, &n, &d, cap),
	      "at k = 2 a second root's revocation did not revoke D alone");

	/* A RESTART from N's store alone. */
	CHECK(fzn_revocation_store_init(&reloaded, e2, 8) == FZN_CHAIN_OK
	              && fzn_revocation_store_set_quorum(&reloaded, 2u, NULL, NULL, 0u)
	                         == FZN_CHAIN_OK
	              && roots_of(&again, r.id.pubkey, &n)
	                         == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_load(&again, &n.ops, &count) == FZN_NODE_ROOTS_OK
	              && count == 1u
	              && fzn_node_roots_attach(&again, &reloaded) == FZN_NODE_ROOTS_OK
	              && fzn_revocation_admit(&reloaded, fzn_revocation_offer_root(rec),
	                                      r.id.pubkey, &n.sign, &hash_ops, NULL)
	                         == FZN_CHAIN_OK
	              && d_revoked(&reloaded, &r, &n, &d, cap),
	      "after a restart N no longer knew B, or D was not revoked");

	/* A STORE CHANGED UNDERNEATH: a row in slot 13 that names no root
	 * record -- a root-log entry of before sec 508 would be one -- and a
	 * root-add whose signature no longer verifies. Each fails the load. */
	{
		static struct node x;
		static fzn_node_roots_t bad;
		uint8_t blob[FZN_PERSIST_HEAD_LEN + FZN_ROOT_ADD_LEN];
		uint8_t subject[FZN_PUBKEY_LEN];

		memset(subject, 0x33, sizeof(subject));
		CHECK(node_up(&x)
		              && fzn_persist_head_write(blob, sizeof(blob), FZN_ROOT_ADD_LEN,
		                                        FZN_PERSIST_BLOB_ROOT_ADD) == FZN_PERSIST_OK
		              && (memcpy(blob + FZN_PERSIST_HEAD_LEN, add, FZN_ROOT_ADD_LEN),
		                  blob[FZN_PERSIST_HEAD_LEN + 1u] = (uint8_t)FZN_OBJECT_REVOCATION, 1)
		              && x.ops.save(x.ops.ctx, FZN_PERSIST_ROOT_CHANGE, subject, blob,
		                            sizeof(blob))
		              && roots_of(&bad, r.id.pubkey, &x)
		                         == FZN_NODE_ROOTS_OK
		              && fzn_node_roots_load(&bad, &x.ops, &count) == FZN_NODE_ROOTS_STORE,
		      "a row naming no root record was loaded");
		CHECK(node_up(&x)
		              && (memcpy(blob + FZN_PERSIST_HEAD_LEN, add, FZN_ROOT_ADD_LEN),
		                  blob[sizeof(blob) - 1u] ^= 1u, 1)
		              && x.ops.save(x.ops.ctx, FZN_PERSIST_ROOT_CHANGE, subject, blob,
		                            sizeof(blob))
		              && roots_of(&bad, r.id.pubkey, &x)
		                         == FZN_NODE_ROOTS_OK
		              && fzn_node_roots_load(&bad, &x.ops, &count) == FZN_NODE_ROOTS_STORE,
		      "a stored root-add whose signature fails was loaded");
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
	              && fzn_node_roots_learn(&roots, &n.ops, rem, sizeof(rem)) == FZN_NODE_ROOTS_OK,
	      "N would not learn R's removal of B");
	CHECK(!d_revoked(&revs, &r, &n, &d, cap),
	      "a removed root's revocation still revoked D");
	{
		uint8_t standing[4][FZN_PUBKEY_LEN];

		CHECK(fzn_node_roots_standing(&roots, standing, 4u) == 1u
		              && !memcmp(standing[0], r.id.pubkey, FZN_PUBKEY_LEN),
		      "a removed root still stood, sec 450");
	}

	/* CARRIED, sec 408 and since sec 505 in the journal: node M, knowing
	 * nothing, carries R's and B's journals and judges as N does -- B's
	 * revocation counts once R's add of B is applied, and stops counting once
	 * R's removal of B arrives after it. */
	{
		static struct node m;
		static fzn_node_roots_t m_roots;
		static fzn_revocation_t e3[8];
		static fzn_node_apply_t m_ap;
		fzn_revocation_store_t m_revs;
		fzn_node_apply_tally_t t;

		CHECK(node_up(&m)
		              && fzn_revocation_store_init(&m_revs, e3, 8) == FZN_CHAIN_OK
		              && fzn_revocation_store_set_quorum(&m_revs, 2u, NULL, NULL, 0u)
		                         == FZN_CHAIN_OK
		              && roots_of(&m_roots, r.id.pubkey, &m) == FZN_NODE_ROOTS_OK
		              && fzn_node_roots_attach(&m_roots, &m_revs) == FZN_NODE_ROOTS_OK
		              && fzn_node_journal_append_object(&r.journal, r.id.pubkey, &r.sign, add,
		                                                sizeof(add), 1500u, NULL)
		                         == FZN_NODE_JOURNAL_OK
		              && fzn_node_journal_append_object(&b.journal, b.id.pubkey, &b.sign, rev,
		                                                sizeof(rev), 1500u, NULL)
		                         == FZN_NODE_JOURNAL_OK,
		      "fixture: M, and R's add and B's revocation in their journals");
		apply_to(&m_ap, &m_revs, r.id.pubkey, cap);
		m_ap.roots = &m_roots;
		CHECK(carry(&b, &m, &m_ap, &t) && t.waiting == 1u && t.applied == 0u
		              && !d_revoked(&m_revs, &r, &n, &d, cap),
		      "M took B's revocation before it knew B was a root");
		CHECK(carry(&r, &m, &m_ap, &t) && t.applied == 2u && t.waiting == 0u
		              && d_revoked(&m_revs, &r, &n, &d, cap),
		      "M, carrying R's add of B, did not count B's revocation");
		CHECK(fzn_node_journal_append_object(&r.journal, r.id.pubkey, &r.sign, rem, sizeof(rem),
		                                     1600u, NULL) == FZN_NODE_JOURNAL_OK
		              && carry(&r, &m, &m_ap, &t) && t.applied == 1u
		              && !d_revoked(&m_revs, &r, &n, &d, cap),
		      "M did not judge B's revocation as N does once R's removal arrived");
	}
}

/* Every root record `from`'s journal holds, carried into `into_node` and
 * applied to `into`, as the daemon's round does since sec 505. The pull err,
 * and the objects applied into `*learned`. */
static int roots_sync(struct node *from, fzn_node_roots_t *into, struct node *into_node,
                      size_t *learned)
{
	static fzn_node_apply_t ap;
	static fzn_revocation_t scratch_e[8];
	static fzn_revocation_store_t scratch;
	static const fzn_cap_id_t no_cap = { { 0 } };
	fzn_node_apply_tally_t t;

	*learned = 0;
	if (fzn_revocation_store_init(&scratch, scratch_e, 8) != FZN_CHAIN_OK)
		return -99;
	apply_to(&ap, into->revocations ? into->revocations : &scratch, from->id.pubkey, &no_cap);
	ap.roots = into;
	if (!carry(from, into_node, &ap, &t))
		return -99;
	*learned = t.applied;
	return FZN_NODE_PULL_OK;
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
	CHECK(roots_of(&r_roots, r.id.pubkey, &r) == FZN_NODE_ROOTS_OK
	              && roots_of(&m_roots, r.id.pubkey, &m)
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

	/* R ADDS M's KEY; M carries R's journal and acts as that key. The
	 * journal carries the add itself, one object, where the root stream
	 * carried it beside its act log entry. */
	CHECK(fzn_node_roots_change(&r_roots, &r.ops, r.id.pubkey, &r.sign, 0, m_roots.key, NULL)
	              == FZN_NODE_ROOTS_OK
	              && received_of(&r, r.id.pubkey) == 1u,
	      "R could not add M's key, or did not log the add");
	CHECK(roots_sync(&r, &m_roots, &m, &learned) == FZN_NODE_PULL_OK
	              && learned == 1u
	              && fzn_node_roots_acting(&m_roots, m.id.pubkey, &m.sign, &as, &as_sign)
	              && memcmp(as, m_roots.key, FZN_PUBKEY_LEN) == 0,
	      "M did not act as its own root key once R had added it");

	/* M ADDS X, logged under M's key at seq 0. */
	CHECK(fzn_node_roots_change(&m_roots, &m.ops, m.id.pubkey, &m.sign, 0, x.id.pubkey, NULL)
	              == FZN_NODE_ROOTS_OK
	              && fzn_root_view_stands(&m_roots.view, x.id.pubkey),
	      "M, acting as a root, could not add X");
	{
		uint8_t cut[FZN_ROOT_ACT_ID_LEN];

		/* THE CUT IS THE ACT'S RECORD in the key's stream, sec 506: the
		 * first and only one M's key has signed. */
		CHECK(received_of(&m, m_roots.key) == 1u
		              && fzn_node_journal_head(&m.journal, m_roots.key, cut),
		      "M's act was not the first record of its key's stream");

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
	CHECK(roots_of(&again, r.id.pubkey, &m) == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_key_load(&again, &m.ops, &again_seat, &again_sign)
	                         == FZN_NODE_ROOTS_OK
	              && again.key_held && memcmp(again.key, m_roots.key, FZN_PUBKEY_LEN) == 0,
	      "M's root key did not reload as the same key");

	/* A FORKED STREAM IS NOT EXTENDED: a second record at the head of R's
	 * stream, signed with R's key and offered to R's journal, and R's next
	 * act is refused. */
	{
		uint8_t subject[FZN_SUBJECT_LEN], body[2] = { 1u, 0x80u };
		uint8_t buf[FZN_RECORD_MAX_LEN], id[FZN_RECORD_ID_LEN];
		uint64_t at = received_of(&r, r.id.pubkey);
		size_t len = 0;

		memset(subject, 0x77, sizeof(subject));
		CHECK(at > 0u
		              && fzn_record_sign(r.id.pubkey, subject, FZN_NODE_JOURNAL_STREAM, 0x80u, at,
		                                 subject, 1800u, body, sizeof(body), &r.sign, buf,
		                                 sizeof(buf), &len) == FZN_RECORD_OK
		              && hash_ops.hash(hash_ops.ctx, id, sizeof(id), buf, len)
		              && fzn_journal_admit_chained(&r.journal.journal, r.id.pubkey,
		                                           FZN_NODE_JOURNAL_STREAM, at, subject, id)
		                         == FZN_JOURNAL_ERR_FORK
		              && fzn_node_roots_change(&r_roots, &r.ops, r.id.pubkey, &r.sign, 0,
		                                       x.id.pubkey, NULL) == FZN_NODE_ROOTS_FORKED,
		      "a root whose stream had forked extended it");
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
	CHECK(roots_of(&roots, r.id.pubkey, &d) == FZN_NODE_ROOTS_OK
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

static size_t grants_by(struct node *n, const uint8_t key[FZN_PUBKEY_LEN])
{
	return kinds_of(n, key, (uint32_t)FZN_OBJECT_HOP);
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
	CHECK(roots_of(&r_roots, r.id.pubkey, &r) == FZN_NODE_ROOTS_OK
	              && roots_of(&m_roots, r.id.pubkey, &m)
	                         == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_key_create(&m_roots, &m.ops, &rng_ops, &k_seat, &k_sign)
	                         == FZN_NODE_ROOTS_OK,
	      "fixture: R's and M's roots, and M's key K");

	/* BEFORE K STANDS: no grant, and nothing logged. */
	CHECK(fzn_node_roots_self_grant(&m_roots, &m.ops, m.id.pubkey, cap, hop, proof, &through)
	              == FZN_NODE_ROOTS_NOT_ROOT
	              && journal_total(&m) == 0u,
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
	CHECK(grants_by(&m, m_roots.key) == 1u, "K's grant to M was not logged once");
	used = (size_t)journal_total(&m);
	CHECK(fzn_node_roots_self_grant(&m_roots, &m.ops, m.id.pubkey, cap, again, proof, &through)
	              == FZN_NODE_ROOTS_OK
	              && memcmp(hop, again, FZN_HOP_LEN) == 0 && journal_total(&m) == used,
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
	CHECK(roots_of(&deep, r.id.pubkey, &m) == FZN_NODE_ROOTS_OK
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

/* Two confirmations in two journals: R's, as a root, and A's, under A's
 * admin chain R -> A, whose grant is R's act. T carries both journals into a
 * store with an admin capability and a confirmation table: both admit and
 * are saved in slot 15, and a fresh store re-admits both from T's rows. U,
 * whose store keeps no table, refuses both and saves nothing. Since sec 505
 * the journal carries them, where S's vote stream did. */
static void test_confirmations_travel(void)
{
	static struct node r, a, b, s, t, u;
	static fzn_revocation_t e1[4], e2[4], e3[4];
	static fzn_revocation_admin_t ad1[4], ad2[4];
	static fzn_revocation_confirm_t c1[4], c2[4];
	fzn_revocation_store_t into, fresh, plain;
	static fzn_node_apply_t t_ap, u_ap;
	fzn_node_apply_tally_t tally;
	fzn_node_authority_t a_chain = { 0 };
	fzn_cap_id_t adm, member;
	uint8_t hop_a[FZN_HOP_LEN], hop_b[FZN_HOP_LEN], grant[FZN_REVOCATION_ID_LEN];
	uint8_t by_root[FZN_ADMIN_CONFIRM_LEN], by_a[FZN_ADMIN_CONFIRM_LEN];
	size_t count = 0;

	memset(&adm, 0xad, sizeof(adm));
	memset(&member, 0x3e, sizeof(member));
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
	CHECK(fzn_node_journal_append_object(&r.journal, r.id.pubkey, &r.sign, hop_a, FZN_HOP_LEN,
	                                     1000u, NULL) == FZN_NODE_JOURNAL_OK
	              && fzn_node_journal_append_object(&r.journal, r.id.pubkey, &r.sign, by_root,
	                                                sizeof(by_root), 1000u, NULL)
	                         == FZN_NODE_JOURNAL_OK
	              && fzn_node_journal_append_object(&a.journal, a.id.pubkey, &a.sign, by_a,
	                                                sizeof(by_a), 1000u, NULL)
	                         == FZN_NODE_JOURNAL_OK,
	      "fixture: R's grant of A and confirmation, and A's, in their journals");

	CHECK(fzn_revocation_store_init(&into, e1, 4) == FZN_CHAIN_OK
	              && fzn_revocation_store_set_quorum(&into, 2u, &adm, ad1, 4u) == FZN_CHAIN_OK
	              && fzn_revocation_store_set_confirmations(&into, c1, 4u, &hash_ops)
	                         == FZN_CHAIN_OK,
	      "fixture: T's store with both tables");
	apply_to(&t_ap, &into, r.id.pubkey, &member);
	t_ap.admin_capability = &adm;
	CHECK(carry(&a, &t, &t_ap, &tally) && tally.waiting == 1u
	              && carry(&r, &t, &t_ap, &tally) && tally.applied == 2u
	              && tally.refused == 0u && tally.waiting == 0u && into.confirms_used == 2u
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
	              && (apply_to(&u_ap, &plain, r.id.pubkey, &member),
	                  u_ap.admin_capability = &adm, carry(&r, &u, &u_ap, &tally))
	              && carry(&a, &u, &u_ap, &tally)
	              && tally.applied == 0u && tally.refused == 1u
	              && rows_in(&u, FZN_PERSIST_ADMIN_CONFIRM) == 0u
	              && plain.confirms_used == 0u
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
	static fzn_node_roots_t r_roots, a_roots, b_roots, c_roots;
	static fzn_node_apply_t t_ap;
	static fzn_revocation_t e[6][8];
	static fzn_revocation_admin_t ad[6][8];
	static fzn_revocation_confirm_t cf[6][8];
	static fzn_node_admin_chain_t a_chain, b_chain, c_chain, back;
	static uint8_t chain[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN], b_hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	fzn_revocation_store_t r_revs, a_revs, b_revs, c_revs, t_revs, fresh;
	fzn_node_apply_tally_t tally;
	fzn_cap_id_t adm;
	size_t n = 0, logged, count = 0;

	memset(&adm, 0xad, sizeof(adm));
	CHECK(node_up(&r) && node_up(&a) && node_up(&b) && node_up(&c) && node_up(&d) && node_up(&t)
	              && roots_of(&r_roots, r.id.pubkey, &r)
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
	              && n == 1u && received_of(&r, r.id.pubkey) == 1u
	              && grants_by(&r, r.id.pubkey) == 1u,
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
	/* AND LOGGED UNDER A, an admin and no root, sec 497: a grant before
	 * A's line keeps B an admin after A is revoked. */
	CHECK(roots_of(&a_roots, r.id.pubkey, &a) == FZN_NODE_ROOTS_OK
	              && roots_of(&c_roots, r.id.pubkey, &c)
	                         == FZN_NODE_ROOTS_OK,
	      "fixture: A's and C's logs");
	CHECK(fzn_node_admin_grant(&a_roots, &a.ops, &a.id, &a_chain, &adm, b.id.pubkey, 1200u, b_hops,
	                           &n) == FZN_NODE_REVOKE_OK
	              && n == 2u && memcmp(b_hops[0], a_chain.hops[0], FZN_HOP_LEN) == 0
	              && journal_total(&a) == 1u && received_of(&a, a.id.pubkey) == 1u
	              && fzn_node_admin_chain_set(&b.ops, &b_revs, &b.id, r.id.pubkey, &adm,
	                                          (const uint8_t (*)[FZN_HOP_LEN])b_hops, n, 1300u,
	                                          &b_chain) == FZN_NODE_REVOKE_OK,
	      "A's grant to B was not A's chain and a hop, or B could not install it");
	CHECK(fzn_node_admin_grant(NULL, &d.ops, &d.id, NULL, &adm, b.id.pubkey, 1200u, chain, &n)
	              == FZN_NODE_REVOKE_NOT_ROOT,
	      "a node neither root nor admin granted admin");

	/* CONFIRMATIONS: C as an admin, R as a root and logged, D not at all. */
	CHECK(fzn_node_admin_confirm(&c_roots, &c.ops, &c.id, &c_chain, r.id.pubkey, b_hops[1],
	                             &c_revs) == FZN_NODE_REVOKE_OK
	              && c_revs.confirms_used == 1u && rows_in(&c, FZN_PERSIST_ADMIN_CONFIRM) == 1u
	              && journal_total(&c) == 1u && received_of(&c, c.id.pubkey) == 1u,
	      "C's confirmation of A's grant was not admitted, saved and logged under C");
	logged = (size_t)received_of(&r, r.id.pubkey);
	CHECK(fzn_node_admin_confirm(&r_roots, &r.ops, &r.id, NULL, r.id.pubkey, b_hops[1], &r_revs)
	              == FZN_NODE_REVOKE_OK
	              && r_revs.confirms_used == 1u && received_of(&r, r.id.pubkey) == logged + 1u,
	      "R's confirmation was not admitted, or not logged as its act");
	CHECK(fzn_node_admin_confirm(NULL, &d.ops, &d.id, NULL, r.id.pubkey, b_hops[1], &c_revs)
	              == FZN_NODE_REVOKE_NOT_ROOT,
	      "a node neither root nor admin confirmed");

	/* B VOTES ON ITS ADMIN CHAIN, and the chain reloads with it. T carries
	 * B's journal, which holds the vote, and rebuilds B's chain from the two
	 * grants in R's and A's: the vote waits until they are applied. */
	CHECK(roots_of(&b_roots, r.id.pubkey, &b) == FZN_NODE_ROOTS_OK
	              && fzn_node_revoke(&b_roots, &b.id, r.id.pubkey,
	                                 fzn_node_admin_chain_view(&b_chain), cap, d.id.pubkey, 1400u,
	                                 &b_revs, &b.ops) == FZN_NODE_REVOKE_OK
	              && b_revs.admins_used == 1u,
	      "B could not vote on its admin chain, or was not taken as an admin");
	apply_to(&t_ap, &t_revs, r.id.pubkey, cap);
	t_ap.admin_capability = &adm;
	CHECK(carry(&b, &t, &t_ap, &tally) && tally.waiting == 1u && tally.applied == 0u,
	      "B's vote was taken before any grant gave B a chain");
	CHECK(carry(&r, &t, &t_ap, &tally) && carry(&a, &t, &t_ap, &tally) && tally.waiting == 0u
	              && t_revs.admins_used == 1u && t_revs.used == 1u,
	      "B's vote did not travel on its admin chain, rebuilt from R's and A's grants");
	CHECK(admin_store(&fresh, e[5], ad[5], cf[5], &adm, NULL)
	              && fzn_node_revocations_load(&b.ops, &fresh, r.id.pubkey, NULL,
	                                           fzn_node_admin_chain_view(&b_chain), &b.sign,
	                                           &hash_ops, &count) == FZN_PERSIST_OK
	              && count == 1u && fresh.admins_used == 1u,
	      "B's vote was not admitted again on its admin chain at start");
}

/* ---- contacts as the user's roster, sec 489 --------------------------- */

/* R, the genesis, with N and M joined. N adds X as a contact; M pulls N's
 * stream and holds X; M removes X, and N, pulling, sees it suspended; N
 * removing too retires it at k = 2, which M then sees. A re-add is a new
 * incarnation. A stranger -- no root, no chain -- writes nothing, and its
 * record pulled by M is refused. A restart re-admits what was held, a
 * contact that arrived is named, and a contact from before is carried. */
/* A REVOKED MEMBER'S CONTACTS, TO THE LINE. sec 497. N joins R's estate and
 * adds X, the record logged under N. R holds N's log and record, and revokes
 * N with no cut named: the vote keeps what R had seen N do, so X stays. A
 * thief holding N's key then adds Y, logged after the line: at R, Y is
 * absent and X active. R's vote moved to keep nothing drops X as well; and
 * undone -- the device found unharmed -- both count again. */
static void test_a_revoked_members_contacts_to_the_line(const fzn_cap_id_t *cap)
{
	static struct node r, n, x, y;
	static fzn_node_roster_t n_ro, r_ro;
	static fzn_node_roots_t n_roots, r_roots;
	static fzn_node_admin_t n_admin;
	static fzn_revocation_t n_e[8], r_e[8];
	fzn_revocation_store_t n_revs, r_revs;
	fzn_prekey_record_t n_rec;
	fzn_node_pairing_t n_joined;
	fzn_node_authority_t n_auth = { 0 };
	static fzn_node_apply_t r_ap;
	fzn_node_apply_tally_t t;
	uint8_t card[FZN_PROVISION_MAX_LEN], cut[FZN_ROOT_ACT_ID_LEN];
	size_t card_len = 0;

	CHECK(node_up(&r) && node_up(&n) && node_up(&x) && node_up(&y)
	              && fzn_prekey_open(n.id.prekey_record, FZN_PREKEY_LEN_TOTAL, &n_rec)
	                         == FZN_PREKEY_OK
	              && fzn_node_pair(&r.id, r.id.pubkey, cap, NULL, 1, &r.ops, n_rec, 1000u, 0u,
	                               card, sizeof(card), &card_len) == FZN_NODE_PAIR_OK
	              && fzn_node_join(&n.id, card, card_len, 1100u, &n.ops, &n.trust, &n_joined)
	                         == FZN_NODE_PAIR_OK,
	      "fixture: N would not join R's estate");
	n_auth.hops = (const uint8_t (*)[FZN_HOP_LEN])n_joined.chain;
	n_auth.hop_count = n_joined.hop_count;
	CHECK(fzn_node_roster_init(&n_ro, r.id.pubkey, cap, &n.sign, NULL, &hash_ops)
	                      == FZN_NODE_ROSTER_OK
	              && fzn_node_roster_init(&r_ro, r.id.pubkey, cap, &r.sign, NULL, &hash_ops)
	                         == FZN_NODE_ROSTER_OK
	              && roots_of(&n_roots, r.id.pubkey, &n)
	                         == FZN_NODE_ROOTS_OK
	              && fzn_revocation_store_init(&n_revs, n_e, 8) == FZN_CHAIN_OK
	              && fzn_revocation_store_init(&r_revs, r_e, 8) == FZN_CHAIN_OK
	              /* R IN THE DAEMON'S ORDER, sec 508: attached first, the
	               * journal set after, as fuzznetd does at start -- so the
	               * store must be re-pointed at the journal to judge N's
	               * line at all. */
	              && fzn_node_roots_init(&r_roots, r.id.pubkey, &r.sign, &hash_ops)
	                         == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_attach(&r_roots, &r_revs) == FZN_NODE_ROOTS_OK
	              && (journal_hook(&r, &r_roots), 1)
	              && fzn_node_roots_set_journal(&r_roots, &r.journal) == FZN_NODE_ROOTS_OK,
	      "fixture: the rosters, the roots and the stores");
	memset(&n_admin, 0, sizeof(n_admin));
	n_admin.roots = &n_roots;
	n_admin.id = &n.id;
	n_admin.store = &n.ops;
	n_ro.wrote = fzn_node_admin_log_roster;
	n_ro.wrote_ctx = &n_admin;
	CHECK(log_grant_of(&r, &r_roots, n_joined.chain[0]), "fixture: R logs its grant of N");
	apply_to(&r_ap, &r_revs, r.id.pubkey, cap);
	r_ap.roots = &r_roots;
	r_ap.roster = &r_ro;

	/* N, A MEMBER, ADDS X, logged under its own key. */
	CHECK(fzn_node_roster_write(&n_ro, &n.ops, &n.id, &n_auth, &rng_ops, x.id.pubkey, 1, &n_revs,
	                            2u) == FZN_NODE_ROSTER_OK
	              && received_of(&n, n.id.pubkey) == 1u,
	      "a member's roster record was not logged under the member");

	/* R HOLDS N's STREAM, carried, and revokes N with no cut named: the
	 * head of N's stream, everything R had seen it do. Nothing of N's own
	 * store is read at R: since sec 506 the journal carries the line. */
	CHECK(carry(&n, &r, &r_ap, &t) && t.applied == 1u && t.waiting == 0u,
	      "fixture: R holds N's stream and its record");
	CHECK(fzn_node_roots_head(&r_roots, n.id.pubkey, cut)
	              && fzn_node_revoke_at(NULL, &r.id, r.id.pubkey, NULL, cap, n.id.pubkey, 1500u, cut,
	                                    &r_revs, &r.ops) == FZN_NODE_REVOKE_OK,
	      "R would not revoke N at the head of N's log");
	CHECK(fzn_node_roster_standing(&r_ro, x.id.pubkey, &r_revs, 2u) == FZN_ROSTER_ACTIVE,
	      "a revoked member's contact from before the line was dropped");

	/* THE THIEF, holding N's key, adds Y: logged after the line. */
	CHECK(fzn_node_roster_write(&n_ro, &n.ops, &n.id, &n_auth, &rng_ops, y.id.pubkey, 1, &n_revs,
	                            2u) == FZN_NODE_ROSTER_OK
	              && received_of(&n, n.id.pubkey) == 2u
	              && carry(&n, &r, &r_ap, &t) && t.applied == 1u,
	      "fixture: the thief's contact, logged and carried to R");
	CHECK(fzn_node_roster_standing(&r_ro, y.id.pubkey, &r_revs, 2u) == FZN_ROSTER_ABSENT,
	      "a contact the thief added after the line counted");
	/* THE HEAD MOVED WITH THE LOG: a vote cast now would keep Y. */
	{
		uint8_t now_head[FZN_ROOT_ACT_ID_LEN], latest[FZN_ROOT_ACT_ID_LEN];

		CHECK(fzn_node_roots_head(&r_roots, n.id.pubkey, now_head)
		              && fzn_node_journal_head(&n.journal, n.id.pubkey, latest)
		              && memcmp(now_head, latest, sizeof(now_head)) == 0,
		      "the head of N's stream at R is not N's latest record");
	}
	CHECK(fzn_node_roster_standing(&r_ro, x.id.pubkey, &r_revs, 2u) == FZN_ROSTER_ACTIVE,
	      "the contact from before the line fell with the thief's");
	CHECK(fzn_node_revoke_at(NULL, &r.id, r.id.pubkey, NULL, cap, n.id.pubkey, 1500u, cut, &r_revs,
	                         &r.ops) == FZN_NODE_REVOKE_ALREADY,
	      "revoking at the same line again was not answered already");

	/* MOVED TO KEEP NOTHING: X falls too. */
	CHECK(fzn_node_revoke_at(NULL, &r.id, r.id.pubkey, NULL, cap, n.id.pubkey, 1600u, NULL, &r_revs,
	                         &r.ops) == FZN_NODE_REVOKE_OK
	              && fzn_node_roster_standing(&r_ro, x.id.pubkey, &r_revs, 2u)
	                         == FZN_ROSTER_ABSENT,
	      "a vote moved to keep nothing kept the member's contact");

	/* FOUND UNHARMED: undone, and both count again. */
	CHECK(fzn_node_unrevoke(NULL, &r.id, r.id.pubkey, NULL, n.id.pubkey, 1700u, &r_revs, &r.ops)
	                      == FZN_NODE_REVOKE_OK
	              && fzn_node_roster_standing(&r_ro, x.id.pubkey, &r_revs, 2u)
	                         == FZN_ROSTER_ACTIVE
	              && fzn_node_roster_standing(&r_ro, y.id.pubkey, &r_revs, 2u)
	                         == FZN_ROSTER_ACTIVE,
	      "undoing the revocation did not bring every contact back");
	/* A FORKED STREAM HAS NO HEAD: a second record at the head of N's
	 * stream, signed with N's key, offered to R's journal, and no vote may
	 * default to either branch. */
	{
		uint8_t subject[FZN_SUBJECT_LEN], body[2] = { 1u, 0x80u }, h[FZN_ROOT_ACT_ID_LEN];
		uint8_t buf[FZN_RECORD_MAX_LEN], id[FZN_RECORD_ID_LEN];
		uint64_t at = received_of(&r, n.id.pubkey);
		size_t len = 0;

		memset(subject, 0x77, sizeof(subject));
		CHECK(at == 2u
		              && fzn_record_sign(n.id.pubkey, subject, FZN_NODE_JOURNAL_STREAM, 0x80u, at,
		                                 subject, 1800u, body, sizeof(body), &n.sign, buf,
		                                 sizeof(buf), &len) == FZN_RECORD_OK
		              && hash_ops.hash(hash_ops.ctx, id, sizeof(id), buf, len)
		              && fzn_journal_admit_chained(&r.journal.journal, n.id.pubkey,
		                                           FZN_NODE_JOURNAL_STREAM, at, subject, id)
		                         == FZN_JOURNAL_ERR_FORK
		              && fzn_node_journal_forked(&r.journal, n.id.pubkey)
		              && !fzn_node_roots_head(&r_roots, n.id.pubkey, h),
		      "a forked stream still offered a head to vote at");
	}
}

/* THE ROOTS' HOOK, sec 501: counts the acts it is told of, and refuses when
 * told to, as a journal that would not keep one does. */
static size_t hooked_acts;
static int hook_refuses;

static int count_logged(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const fzn_sign_ops_t *sign,
                        uint8_t kind, const uint8_t act[FZN_ROOT_ACT_ID_LEN],
                        const uint8_t *record, size_t len)
{
	/* THE ACT'S OWN BYTES, sec 502: a succession, whole. */
	if (!record || len != FZN_SUCCESSION_LEN || record[1] != (uint8_t)FZN_OBJECT_SUCCESSION)
		return 0;
	hooked_acts++;
	/* AND ON INTO THE NODE'S JOURNAL, `ctx`, as `roots_of` hooked it. */
	return !hook_refuses && (!ctx || journal_logged(ctx, pubkey, sign, kind, act, record, len));
}

/* A DEVICE RE-KEYED, sec 499. R, the root, pairs D. D's keys are taken; its
 * owner makes D2 and R mints "D is succeeded by D2", logged as R's act. D
 * reads through to D2 at R. M, a member, pulls R's votes and the succession
 * rides with them: M reads D through to D2 too, a pull with nowhere to put
 * successions refuses it, and a restart at M loads it back. A second
 * succession of D to another key forks it, and D then reads through to
 * nobody. */
static void test_a_device_rekeyed(const fzn_cap_id_t *cap)
{
	static struct node r, m, u, d, d2, d3;
	static fzn_node_roots_t r_roots;
	static fzn_node_apply_t m_ap, u_ap;
	static fzn_node_successions_t r_ns, m_ns, again;
	static fzn_revocation_t r_e[8], m_e[8];
	fzn_revocation_store_t r_revs, m_revs, u_revs;
	static fzn_revocation_t u_e[8];
	fzn_prekey_record_t m_rec, d_rec;
	fzn_node_pairing_t m_joined;
	fzn_node_apply_tally_t t;
	uint8_t card[FZN_PROVISION_MAX_LEN], now_key[FZN_PUBKEY_LEN], id[FZN_SUCCESSION_ID_LEN];
	size_t card_len = 0, loaded = 0;
	size_t logged;

	CHECK(node_up(&r) && node_up(&m) && node_up(&u) && node_up(&d) && node_up(&d2)
	              && node_up(&d3)
	              && fzn_prekey_open(m.id.prekey_record, FZN_PREKEY_LEN_TOTAL, &m_rec)
	                         == FZN_PREKEY_OK
	              && fzn_prekey_open(d.id.prekey_record, FZN_PREKEY_LEN_TOTAL, &d_rec)
	                         == FZN_PREKEY_OK
	              && fzn_node_pair(&r.id, r.id.pubkey, cap, NULL, 1, &r.ops, m_rec, 1000u, 0u,
	                               card, sizeof(card), &card_len) == FZN_NODE_PAIR_OK
	              && fzn_node_join(&m.id, card, card_len, 1100u, &m.ops, &m.trust, &m_joined)
	                         == FZN_NODE_PAIR_OK
	              && fzn_node_pair(&r.id, r.id.pubkey, cap, NULL, 0, &r.ops, d_rec, 1000u, 0u,
	                               card, sizeof(card), &card_len) == FZN_NODE_PAIR_OK,
	      "fixture: M joins R's estate and R pairs D");
	CHECK(roots_of(&r_roots, r.id.pubkey, &r) == FZN_NODE_ROOTS_OK
	              && fzn_revocation_store_init(&r_revs, r_e, 8) == FZN_CHAIN_OK
	              && fzn_revocation_store_init(&m_revs, m_e, 8) == FZN_CHAIN_OK
	              && fzn_revocation_store_init(&u_revs, u_e, 8) == FZN_CHAIN_OK
	              && fzn_node_successions_init(&r_ns, &hash_ops) == FZN_NODE_REVOKE_OK
	              && fzn_node_successions_init(&m_ns, &hash_ops) == FZN_NODE_REVOKE_OK,
	      "fixture: R's roots, the stores and the successions");

	/* R RE-KEYS D TO D2, as the root, logged -- and the hook told. */
	r_roots.logged = count_logged;
	hooked_acts = 0;
	logged = (size_t)received_of(&r, r.id.pubkey);
	CHECK(fzn_node_succession_issue(&r_ns, &r_roots, &r.ops, &r.id, NULL, &r_revs, r.id.pubkey,
	                                d.id.pubkey, d2.id.pubkey, NULL, id) == FZN_NODE_REVOKE_OK
	              && r_ns.set.used == 1u && rows_in(&r, FZN_PERSIST_SUCCESSION) == 1u
	              && received_of(&r, r.id.pubkey) == logged + 1u,
	      "R's succession of D was not kept, saved and logged");
	CHECK(hooked_acts == 1u, "the roots' hook was not told of the act R logged");
	CHECK(fzn_node_successions_resolve(&r_ns, &r_revs, r.id.pubkey, d.id.pubkey, now_key)
	              && memcmp(now_key, d2.id.pubkey, FZN_PUBKEY_LEN) == 0,
	      "D did not read through to D2 at R");
	CHECK(fzn_node_succession_issue(&r_ns, NULL, &r.ops, &r.id, NULL, &r_revs, r.id.pubkey,
	                                d.id.pubkey, d3.id.pubkey, NULL, NULL)
	              == FZN_NODE_REVOKE_NOT_ROOT,
	      "a node acting as no root and holding no admin chain re-keyed a device");

	/* THE JOURNAL CARRIES IT: refused at U, which has nowhere to put it,
	 * and applied at M. */
	apply_to(&u_ap, &u_revs, r.id.pubkey, cap);
	CHECK(carry(&r, &u, &u_ap, &t) && t.refused == 1u && rows_in(&u, FZN_PERSIST_SUCCESSION) == 0u,
	      "a node with nowhere to put a succession took it");
	apply_to(&m_ap, &m_revs, r.id.pubkey, cap);
	m_ap.successions = &m_ns;
	CHECK(carry(&r, &m, &m_ap, &t) && t.applied == 1u && rows_in(&m, FZN_PERSIST_SUCCESSION) == 1u
	              && fzn_node_successions_resolve(&m_ns, &m_revs, r.id.pubkey, d.id.pubkey,
	                                              now_key)
	              && memcmp(now_key, d2.id.pubkey, FZN_PUBKEY_LEN) == 0,
	      "M did not apply R's succession from R's journal, or did not read D through");

	/* A RESTART AT M. */
	CHECK(fzn_node_successions_init(&again, &hash_ops) == FZN_NODE_REVOKE_OK
	              && fzn_node_successions_load(&again, &m.ops, &m_revs, r.id.pubkey, &m.sign,
	                                           &loaded) == FZN_PERSIST_OK
	              && loaded == 1u
	              && fzn_node_successions_resolve(&again, &m_revs, r.id.pubkey, d.id.pubkey,
	                                              now_key)
	              && memcmp(now_key, d2.id.pubkey, FZN_PUBKEY_LEN) == 0,
	      "M's succession did not come back from its store");

	/* A FORK: R also re-keys D to D3, and D reads through to nobody. */
	CHECK(fzn_node_succession_issue(&r_ns, &r_roots, &r.ops, &r.id, NULL, &r_revs, r.id.pubkey,
	                                d.id.pubkey, d3.id.pubkey, NULL, NULL) == FZN_NODE_REVOKE_OK
	              && !fzn_node_successions_resolve(&r_ns, &r_revs, r.id.pubkey, d.id.pubkey,
	                                               now_key),
	      "a key re-keyed two ways still read through to one of them");

	/* A HOOK THAT REFUSES FAILS THE LOGGING: an act the journal would not
	 * keep must not pass for one recorded. */
	hook_refuses = 1;
	CHECK(fzn_node_succession_issue(&r_ns, &r_roots, &r.ops, &r.id, NULL, &r_revs, r.id.pubkey,
	                                d2.id.pubkey, d3.id.pubkey, NULL, NULL)
	              == FZN_NODE_REVOKE_NOT_SAVED,
	      "an act the hook refused was reported as logged");
	hook_refuses = 0;
	r_roots.logged = NULL;
}

static void test_contacts_travel(const fzn_cap_id_t *cap)
{
	static struct node r, n, m, u, x, stranger;
	static fzn_node_roster_t n_ro, m_ro, r_ro, again, s_ro;
	static fzn_node_roots_t r_log, n_log, m_log, s_log;
	static fzn_node_admin_t n_admin, m_admin, s_admin;
	static fzn_node_apply_t n_ap, m_ap, u_ap;
	static fzn_revocation_t n_e[8], m_e[8], u_e[8];
	fzn_revocation_store_t n_revs, m_revs, u_revs;
	fzn_prekey_record_t n_rec, m_rec;
	fzn_node_pairing_t n_joined, m_joined;
	fzn_node_authority_t n_auth = { 0 }, m_auth = { 0 };
	fzn_node_apply_tally_t t;
	uint8_t card[FZN_PROVISION_MAX_LEN];
	size_t card_len = 0, count = 0, named = 0, carried = 0;
	fzn_contact_t c;

	CHECK(node_up(&r) && node_up(&n) && node_up(&m) && node_up(&u) && node_up(&x)
	              && node_up(&stranger)
	              && fzn_prekey_open(n.id.prekey_record, FZN_PREKEY_LEN_TOTAL, &n_rec)
	                         == FZN_PREKEY_OK
	              && fzn_prekey_open(m.id.prekey_record, FZN_PREKEY_LEN_TOTAL, &m_rec)
	                         == FZN_PREKEY_OK
	              && fzn_node_pair(&r.id, r.id.pubkey, cap, NULL, 1, &r.ops, n_rec, 1000u, 0u,
	                               card, sizeof(card), &card_len) == FZN_NODE_PAIR_OK
	              && fzn_node_join(&n.id, card, card_len, 1100u, &n.ops, &n.trust, &n_joined)
	                         == FZN_NODE_PAIR_OK
	              && fzn_node_pair(&r.id, r.id.pubkey, cap, NULL, 1, &r.ops, m_rec, 1000u, 0u,
	                               card, sizeof(card), &card_len) == FZN_NODE_PAIR_OK
	              && fzn_node_join(&m.id, card, card_len, 1100u, &m.ops, &m.trust, &m_joined)
	                         == FZN_NODE_PAIR_OK,
	      "fixture: N and M would not join R's estate");
	n_auth.hops = (const uint8_t (*)[FZN_HOP_LEN])n_joined.chain;
	n_auth.hop_count = n_joined.hop_count;
	m_auth.hops = (const uint8_t (*)[FZN_HOP_LEN])m_joined.chain;
	m_auth.hop_count = m_joined.hop_count;
	/* EACH WRITER'S RECORDS LOGGED INTO ITS JOURNAL, as the daemon's are,
	 * and R's grants of N and M in R's, whence a reader rebuilds their
	 * chains. sec 505. */
	CHECK(roots_of(&r_log, r.id.pubkey, &r) == FZN_NODE_ROOTS_OK
	              && roots_of(&n_log, r.id.pubkey, &n) == FZN_NODE_ROOTS_OK
	              && roots_of(&m_log, r.id.pubkey, &m) == FZN_NODE_ROOTS_OK
	              && roots_of(&s_log, stranger.id.pubkey, &stranger) == FZN_NODE_ROOTS_OK
	              && log_grant_of(&r, &r_log, n_joined.chain[0])
	              && log_grant_of(&r, &r_log, m_joined.chain[0]),
	      "fixture: the logs, and R's grants logged");
	CHECK(fzn_node_roster_init(&n_ro, r.id.pubkey, cap, &n.sign, NULL, &hash_ops)
	                      == FZN_NODE_ROSTER_OK
	              && fzn_node_roster_init(&m_ro, r.id.pubkey, cap, &m.sign, NULL, &hash_ops)
	                         == FZN_NODE_ROSTER_OK
	              && fzn_node_roster_init(&r_ro, r.id.pubkey, cap, &r.sign, NULL, &hash_ops)
	                         == FZN_NODE_ROSTER_OK
	              && fzn_node_roster_init(&s_ro, r.id.pubkey, cap, &stranger.sign, NULL, &hash_ops)
	                         == FZN_NODE_ROSTER_OK
	              && fzn_revocation_store_init(&n_revs, n_e, 8) == FZN_CHAIN_OK
	              && fzn_revocation_store_init(&m_revs, m_e, 8) == FZN_CHAIN_OK
	              && fzn_revocation_store_set_quorum(&n_revs, 2u, NULL, NULL, 0u) == FZN_CHAIN_OK
	              && fzn_revocation_store_set_quorum(&m_revs, 2u, NULL, NULL, 0u) == FZN_CHAIN_OK
	              && fzn_revocation_store_init(&u_revs, u_e, 8) == FZN_CHAIN_OK,
	      "fixture: the rosters, and stores at k = 2");
	memset(&n_admin, 0, sizeof(n_admin));
	n_admin.roots = &n_log;
	n_admin.id = &n.id;
	n_admin.store = &n.ops;
	n_ro.wrote = fzn_node_admin_log_roster;
	n_ro.wrote_ctx = &n_admin;
	memset(&m_admin, 0, sizeof(m_admin));
	m_admin.roots = &m_log;
	m_admin.id = &m.id;
	m_admin.store = &m.ops;
	m_ro.wrote = fzn_node_admin_log_roster;
	m_ro.wrote_ctx = &m_admin;
	apply_to(&n_ap, &n_revs, r.id.pubkey, cap);
	n_ap.roster = &n_ro;
	apply_to(&m_ap, &m_revs, r.id.pubkey, cap);
	m_ap.roster = &m_ro;
	apply_to(&u_ap, &u_revs, r.id.pubkey, cap);

	CHECK(fzn_node_roster_write(&n_ro, &n.ops, &n.id, &n_auth, &rng_ops, x.id.pubkey, 1, &n_revs,
	                            2u) == FZN_NODE_ROSTER_OK
	              && rows_in(&n, FZN_PERSIST_ROSTER) == 1u
	              && fzn_node_roster_standing(&n_ro, x.id.pubkey, &n_revs, 2u)
	                         == FZN_ROSTER_ACTIVE,
	      "N, a member, did not add X on its chain");
	CHECK(fzn_node_roster_write(&n_ro, &n.ops, &n.id, &n_auth, &rng_ops, x.id.pubkey, 1, &n_revs,
	                            2u) == FZN_NODE_ROSTER_OK
	              && rows_in(&n, FZN_PERSIST_ROSTER) == 1u,
	      "adding X again wrote a second incarnation");
	CHECK(fzn_node_roster_write(&s_ro, &stranger.ops, &stranger.id, NULL, &rng_ops, x.id.pubkey,
	                            1, NULL, 2u) == FZN_NODE_ROSTER_NO_STANDING
	              && fzn_node_roster_write(&s_ro, &stranger.ops, &stranger.id, &n_auth, &rng_ops,
	                                       x.id.pubkey, 1, NULL, 2u)
	                         == FZN_NODE_ROSTER_NO_STANDING
	              && rows_in(&stranger, FZN_PERSIST_ROSTER) == 0u,
	      "a stranger with no chain, or with N's, wrote a contact");

	/* THE JOURNAL CARRIES IT, and R's carries the grant N's chain is
	 * rebuilt from. U, with no roster, refuses it. */
	CHECK(carry(&r, &u, &u_ap, &t) && carry(&n, &u, &u_ap, &t) && t.refused == 1u
	              && rows_in(&u, FZN_PERSIST_ROSTER) == 0u,
	      "a node with no roster took N's record rather than refusing it");
	CHECK(carry(&r, &n, &n_ap, &t) && carry(&r, &m, &m_ap, &t) && carry(&n, &m, &m_ap, &t)
	              && t.applied == 1u && rows_in(&m, FZN_PERSIST_ROSTER) == 1u
	              && fzn_node_roster_standing(&m_ro, x.id.pubkey, &m_revs, 2u)
	                         == FZN_ROSTER_ACTIVE,
	      "M did not apply N's contact from N's journal");
	CHECK(fzn_node_roster_name_arrivals(&m_ro, &m.ops, &m_revs, 2u, NULL, NULL, 2000u, &named)
	                      == FZN_NODE_ROSTER_OK
	              && named == 1u && fzn_contact_get(&m.ops, x.id.pubkey, &c) == FZN_CONTACT_OK
	              && c.name_len == 10u && memcmp(c.name, "c_", 2u) == 0
	              && fzn_node_roster_name_arrivals(&m_ro, &m.ops, &m_revs, 2u, NULL, NULL, 2000u,
	                                               &named) == FZN_NODE_ROSTER_OK
	              && named == 0u,
	      "the contact that arrived at M was not named once, c_ and eight digits");

	/* M REMOVES; N SEES IT SUSPENDED; N REMOVING TOO RETIRES IT. */
	CHECK(fzn_node_roster_write(&m_ro, &m.ops, &m.id, &m_auth, &rng_ops, x.id.pubkey, 0, &m_revs,
	                            2u) == FZN_NODE_ROSTER_OK
	              && fzn_node_roster_standing(&m_ro, x.id.pubkey, &m_revs, 2u)
	                         == FZN_ROSTER_SUSPENDED
	              && fzn_node_roster_write(&m_ro, &m.ops, &m.id, &m_auth, &rng_ops, x.id.pubkey, 0,
	                                       &m_revs, 2u) == FZN_NODE_ROSTER_ABSENT,
	      "M's removal did not suspend X, or M removed it twice");
	CHECK(carry(&m, &n, &n_ap, &t) && t.applied == 1u
	              && fzn_node_roster_standing(&n_ro, x.id.pubkey, &n_revs, 2u)
	                         == FZN_ROSTER_SUSPENDED,
	      "N, carrying M's journal, did not see X suspended");
	CHECK(fzn_node_roster_write(&n_ro, &n.ops, &n.id, &n_auth, &rng_ops, x.id.pubkey,
	                                       0, &n_revs, 2u) == FZN_NODE_ROSTER_OK
	              && fzn_node_roster_standing(&n_ro, x.id.pubkey, &n_revs, 2u)
	                         == FZN_ROSTER_RETIRED,
	      "N removing what M suspended did not retire it at k = 2");
	CHECK(carry(&n, &m, &m_ap, &t)
	              && fzn_node_roster_standing(&m_ro, x.id.pubkey, &m_revs, 2u)
	                         == FZN_ROSTER_RETIRED,
	      "M, carrying N's journal, did not see X retired");
	CHECK(fzn_node_roster_write(&m_ro, &m.ops, &m.id, &m_auth, &rng_ops, x.id.pubkey, 1, &m_revs,
	                            2u) == FZN_NODE_ROSTER_OK
	              && fzn_node_roster_standing(&m_ro, x.id.pubkey, &m_revs, 2u)
	                         == FZN_ROSTER_ACTIVE,
	      "adding X again after its retirement was not a new, active incarnation");

	/* A STRANGER'S RECORD, signed as its own root and in its journal,
	 * waits at M for a chain no grant gives it. */
	memset(&s_admin, 0, sizeof(s_admin));
	s_admin.roots = &s_log;
	s_admin.id = &stranger.id;
	s_admin.store = &stranger.ops;
	CHECK(fzn_node_roster_init(&s_ro, stranger.id.pubkey, cap, &stranger.sign, NULL, &hash_ops)
	                      == FZN_NODE_ROSTER_OK
	              && (s_ro.wrote = fzn_node_admin_log_roster, s_ro.wrote_ctx = &s_admin, 1)
	              && fzn_node_roster_write(&s_ro, &stranger.ops, &stranger.id, NULL, &rng_ops,
	                                       r.id.pubkey, 1, NULL, 2u) == FZN_NODE_ROSTER_OK
	              && received_of(&stranger, stranger.id.pubkey) == 1u
	              && carry(&stranger, &m, &m_ap, &t) && t.waiting == 1u && t.refused == 0u
	              && fzn_node_roster_standing(&m_ro, r.id.pubkey, &m_revs, 2u)
	                         == FZN_ROSTER_ABSENT,
	      "a record by a stranger, no root of this estate, was taken at M");

	/* A RESTART: what M holds comes back as it was judged. */
	CHECK(fzn_node_roster_init(&again, r.id.pubkey, cap, &m.sign, NULL, &hash_ops)
	                      == FZN_NODE_ROSTER_OK
	              && fzn_node_roster_load(&again, &m.ops, &count) == FZN_NODE_ROSTER_OK
	              && count == rows_in(&m, FZN_PERSIST_ROSTER) && count == 4u
	              && fzn_node_roster_standing(&again, x.id.pubkey, &m_revs, 2u)
	                         == FZN_ROSTER_ACTIVE,
	      "M's roster did not come back from its store whole");

	/* A CONTACT FROM BEFORE, named on R with no record, is carried -- and
	 * R, writing as the root, logs the record as its act, sec 413. */
	{
		static fzn_node_roots_t r_roots;
		static fzn_node_admin_t r_admin;
		size_t acts = 0;

		CHECK(roots_of(&r_roots, r.id.pubkey, &r)
		              == FZN_NODE_ROOTS_OK,
		      "fixture: R's roots");
		memset(&r_admin, 0, sizeof(r_admin));
		r_admin.roots = &r_roots;
		r_admin.id = &r.id;
		r_admin.store = &r.ops;
		r_ro.wrote = fzn_node_admin_log_roster;
		r_ro.wrote_ctx = &r_admin;
		CHECK(fzn_contact_add(&r.ops, x.id.pubkey, "xavier", 6u, 3000u) == FZN_CONTACT_OK
		              && fzn_node_roster_carry_names(&r_ro, &r.ops, &r.id, NULL, &rng_ops,
		                                             &carried) == FZN_NODE_ROSTER_OK,
		      "fixture: R's contact from before, carried");
		acts = kinds_of(&r, r.id.pubkey, (uint32_t)FZN_OBJECT_ROSTER_ADD)
		       + kinds_of(&r, r.id.pubkey, (uint32_t)FZN_OBJECT_ROSTER_SET);
		CHECK(acts == 1u, "R's roster record, written as the root, is not in its log");
		r_ro.wrote = NULL;
	}
	CHECK(carried == 1u
	              && fzn_node_roster_standing(&r_ro, x.id.pubkey, NULL, 2u) == FZN_ROSTER_ACTIVE
	              && fzn_node_roster_carry_names(&r_ro, &r.ops, &r.id, NULL, &rng_ops, &carried)
	                         == FZN_NODE_ROSTER_OK
	              && carried == 0u,
	      "R's contact from before was not carried onto the roster once");
}

/* ---- an admin's retention rules, sec 479 ------------------------------ */

/* R, the genesis, grants A admin. A, no root, sets an estate rule as an
 * admin; D, no admin, cannot set one on A's chain. T carries A's journal:
 * the rule counts on the chain rebuilt from R's grant; a restart of T
 * re-admits it. R revokes A's grant, T carries it, and A's rule stops
 * counting. And a root adding a rule it removed adds it again. */
static void test_an_admin_sets_retention(const fzn_cap_id_t *cap)
{
	static struct node r, a, d, t, u;
	static fzn_node_roots_t r_roots, a_roots, t_roots, t_again;
	static fzn_node_apply_t t_ap, u_ap, a_ap;
	static fzn_revocation_t e[6][8];
	static fzn_revocation_admin_t ad[6][8];
	static fzn_revocation_confirm_t cf[6][8];
	static fzn_node_admin_chain_t a_chain;
	static uint8_t chain[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	fzn_revocation_store_t r_revs, a_revs, d_revs, t_revs, u_revs, fresh;
	fzn_node_apply_tally_t tally;
	fzn_retain_rule_t rule, got[4];
	fzn_cap_id_t adm;
	size_t n = 0, unread = 0, learned = 0, count = 0;

	(void)cap;
	memset(&adm, 0xad, sizeof(adm));
	CHECK(node_up(&r) && node_up(&a) && node_up(&d) && node_up(&t) && node_up(&u)
	              && admin_store(&u_revs, e[5], ad[5], cf[5], &adm, NULL)
	              && roots_of(&r_roots, r.id.pubkey, &r)
	                         == FZN_NODE_ROOTS_OK
	              && roots_of(&a_roots, r.id.pubkey, &a)
	                         == FZN_NODE_ROOTS_OK
	              && roots_of(&t_roots, r.id.pubkey, &t)
	                         == FZN_NODE_ROOTS_OK
	              && admin_store(&r_revs, e[0], ad[0], cf[0], &adm, &r_roots)
	              && admin_store(&a_revs, e[1], ad[1], cf[1], &adm, &a_roots)
	              && admin_store(&d_revs, e[2], ad[2], cf[2], &adm, NULL)
	              && admin_store(&t_revs, e[3], ad[3], cf[3], &adm, &t_roots)
	              && fzn_retain_parse("prune * level=D age 2d", 22u, &rule) == FZN_RETAIN_OK,
	      "fixture: the nodes, their roots and stores, and a rule");
	CHECK(fzn_node_admin_grant(&r_roots, &r.ops, &r.id, NULL, &adm, a.id.pubkey, 1000u, chain,
	                           &n) == FZN_NODE_REVOKE_OK
	              && fzn_node_admin_chain_set(&a.ops, &a_revs, &a.id, r.id.pubkey, &adm,
	                                          (const uint8_t (*)[FZN_HOP_LEN])chain, n, 1100u,
	                                          &a_chain) == FZN_NODE_REVOKE_OK
	              && roots_sync(&r, &a_roots, &a, &learned) == FZN_NODE_PULL_OK
	              && roots_sync(&r, &t_roots, &t, &learned) == FZN_NODE_PULL_OK,
	      "fixture: A, R's admin, and R's log at A and T");

	CHECK(fzn_node_roots_set_retention(&a_roots, &a.ops, a.id.pubkey, &a.sign, &rule, 1)
	              == FZN_NODE_ROOTS_NOT_ROOT
	              && fzn_node_roots_set_retention_as_admin(
	                         &a_roots, &a.ops, a.id.pubkey, &a.sign,
	                         (const uint8_t (*)[FZN_HOP_LEN])a_chain.hops, a_chain.hop_count,
	                         r.id.pubkey, &rule, 1)
	                         == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_retention(&a_roots, got, 4u, &n, &unread) == FZN_NODE_ROOTS_OK
	              && n == 1u && rows_in(&a, FZN_PERSIST_ADMIN_RETENTION) == 1u,
	      "A, no root, did not set the rule as an admin, or it was not kept");
	CHECK(fzn_node_roots_set_retention_as_admin(
	              &a_roots, &a.ops, a.id.pubkey, &a.sign,
	              (const uint8_t (*)[FZN_HOP_LEN])a_chain.hops, a_chain.hop_count, r.id.pubkey,
	              &rule, 1)
	              == FZN_NODE_ROOTS_HELD,
	      "A set the rule twice");
	CHECK(fzn_node_roots_set_retention_as_admin(
	              &a_roots, &d.ops, d.id.pubkey, &d.sign,
	              (const uint8_t (*)[FZN_HOP_LEN])a_chain.hops, a_chain.hop_count, r.id.pubkey,
	              &rule, 0)
	              == FZN_NODE_ROOTS_REFUSED
	              && rows_in(&d, FZN_PERSIST_ADMIN_RETENTION) == 0u,
	      "D set a rule on a chain that names A");

	/* THE JOURNAL CARRIES IT, and R's the grant A's chain is rebuilt from.
	 * U, with no roots, refuses it. */
	apply_to(&u_ap, &u_revs, r.id.pubkey, cap);
	u_ap.admin_capability = &adm;
	CHECK(carry(&r, &u, &u_ap, &tally) && carry(&a, &u, &u_ap, &tally) && tally.refused == 1u
	              && rows_in(&u, FZN_PERSIST_ADMIN_RETENTION) == 0u,
	      "a node with no roots took A's record rather than refusing it");
	apply_to(&t_ap, &t_revs, r.id.pubkey, cap);
	t_ap.roots = &t_roots;
	t_ap.admin_capability = &adm;
	CHECK(carry(&a, &t, &t_ap, &tally) && tally.applied == 1u
	              && rows_in(&t, FZN_PERSIST_ADMIN_RETENTION) == 1u
	              && fzn_node_roots_retention(&t_roots, got, 4u, &n, &unread) == FZN_NODE_ROOTS_OK
	              && n == 1u && got[0].levels == (1u << FZN_ENTRY_DEBUG),
	      "T did not apply A's rule from A's journal");
	CHECK(roots_of(&t_again, r.id.pubkey, &t) == FZN_NODE_ROOTS_OK
	              && admin_store(&fresh, e[4], ad[4], cf[4], &adm, &t_again)
	              && roots_sync(&r, &t_again, &t, &learned) == FZN_NODE_PULL_OK
	              && fzn_node_roots_load_admin_retention(&t_again, &t.ops, r.id.pubkey, &count)
	                         == FZN_NODE_ROOTS_OK
	              && count == 1u
	              && fzn_node_roots_retention(&t_again, got, 4u, &n, &unread)
	                         == FZN_NODE_ROOTS_OK
	              && n == 1u,
	      "A's rule did not come back from T's store after a restart");

	/* R REVOKES A'S GRANT, and the rule stops counting at T. */
	CHECK(fzn_node_revoke(&r_roots, &r.id, r.id.pubkey, NULL, &adm, a.id.pubkey, 1500u, &r_revs,
	                      &r.ops) == FZN_NODE_REVOKE_OK
	              && carry(&r, &t, &t_ap, &tally) && tally.applied == 1u
	              && fzn_node_roots_retention(&t_roots, got, 4u, &n, &unread) == FZN_NODE_ROOTS_OK
	              && n == 0u,
	      "a revoked admin's rule still counted at T");
	apply_to(&a_ap, &a_revs, r.id.pubkey, cap);
	a_ap.roots = &a_roots;
	a_ap.admin_capability = &adm;
	CHECK(carry(&r, &a, &a_ap, &tally)
	              && fzn_retain_parse("prune * level=T age 1d", 22u, &rule) == FZN_RETAIN_OK
	              && fzn_node_roots_set_retention_as_admin(
	                         &a_roots, &a.ops, a.id.pubkey, &a.sign,
	                         (const uint8_t (*)[FZN_HOP_LEN])a_chain.hops, a_chain.hop_count,
	                         r.id.pubkey, &rule, 1)
	                         == FZN_NODE_ROOTS_NOT_ROOT
	              && rows_in(&a, FZN_PERSIST_ADMIN_RETENTION) == 1u,
	      "A, its grant revoked, set another rule");
	(void)fzn_retain_parse("prune * level=D age 2d", 22u, &rule);

	/* A ROOT ADDS AGAIN WHAT IT REMOVED. */
	CHECK(fzn_node_roots_set_retention(&r_roots, &r.ops, r.id.pubkey, &r.sign, &rule, 1)
	                      == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_set_retention(&r_roots, &r.ops, r.id.pubkey, &r.sign, &rule, 0)
	                         == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_retention(&r_roots, got, 4u, &n, &unread) == FZN_NODE_ROOTS_OK
	              && n == 0u
	              && fzn_node_roots_set_retention(&r_roots, &r.ops, r.id.pubkey, &r.sign, &rule, 1)
	                         == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_retention(&r_roots, got, 4u, &n, &unread) == FZN_NODE_ROOTS_OK
	              && n == 1u,
	      "a rule added again after its removal did not stand");
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
	              && roots_of(&r_roots, r.id.pubkey, &r)
	                         == FZN_NODE_ROOTS_OK
	              && roots_of(&m_roots, r.id.pubkey, &m)
	                         == FZN_NODE_ROOTS_OK,
	      "fixture: the nodes and their roots");
	CHECK(fzn_node_roots_quorum(&r_roots, 2u) == 2u, "no setting did not read the fallback");
	CHECK(fzn_node_roots_set_quorum(&r_roots, &r.ops, r.id.pubkey, &r.sign, 3u)
	              == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_quorum(&r_roots, 2u) == 3u && received_of(&r, r.id.pubkey) == 1u
	              && kinds_of(&r, r.id.pubkey, (uint32_t)FZN_OBJECT_QUORUM_SET) == 1u,
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
	CHECK(roots_of(&again, r.id.pubkey, &r) == FZN_NODE_ROOTS_OK
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
	              && roots_of(&r_roots, r.id.pubkey, &r)
	                         == FZN_NODE_ROOTS_OK
	              && roots_of(&m_roots, r.id.pubkey, &m)
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
	test_an_admin_sets_retention(&cap);
	test_contacts_travel(&cap);
	test_a_revoked_members_contacts_to_the_line(&cap);
	test_a_device_rekeyed(&cap);
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
