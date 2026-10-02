/* node/admin.h through the real local path: a request line over a socketpair,
 * `fzn_node_serve_local` with the admin handler, and the reply read back by
 * the client library. Under real Monocypher, with a node and a device built by
 * `node/identity.h`. sec 378.
 *
 * THE CASE THAT MATTERS is pairing into a RUNNING node: after `add peer`, the
 * state the loop reads holds the device, and the card in the reply is one the
 * device accepts. The reply is 685 bytes, past the 512 the grammar used to
 * allow, so this is also the test that the raised bound is real at both ends
 * -- the node's compose and the client's framer.
 */

#include "../admin.h"
#include "../roots.h"
#include "../identity.h"
#include "../peer_persist.h"
#include "../received.h"
#include "../members.h"
#include "../../notes/received.h"
#include "../../chain/service.h"
#include "../../chain/sign_monocypher.h"
#include "../../constant_time/constant_time.h"
#include "../../provision/provision.h"
#include "../../local/client.h"
#include "../../session/agree_monocypher.h"
#include "../../session/hash_monocypher.h"
#include "../../session/random_system.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL admin_test.c:%d: %s\n", line, what);
	}
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

/* ---- an in-memory store that can list, as pair_test's ---------------- */

struct mem_entry {
	int used;
	fzn_persist_slot_t slot;
	int has_subject;
	uint8_t subject[FZN_PUBKEY_LEN];
	uint8_t bytes[FZN_NODE_PEER_BLOB_MAX];
	size_t len;
};

struct mem_store {
	struct mem_entry e[64];
	unsigned saves;
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

	if (len > sizeof(x->bytes))
		return 0;
	x = find(m, slot, subject, 1);
	if (!x)
		return 0;
	memcpy(x->bytes, bytes, len);
	x->len = len;
	m->saves++;
	return 1;
}

static int mem_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	struct mem_entry *x = find((struct mem_store *)ctx, slot, subject, 0);

	if (x)
		memset(x, 0, sizeof(*x));
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
	n->ops.remove = mem_remove;
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

static uint64_t fixed_clock(void)
{
	return 2000u;
}

static void hex(const uint8_t *in, size_t len, char *out)
{
	static const char H[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < len; i++) {
		out[i * 2u] = H[in[i] >> 4];
		out[(i * 2u) + 1u] = H[in[i] & 0x0fu];
	}
	out[len * 2u] = '\0';
}

/* One request over a socketpair, served by the admin handler, the reply read
 * by the client library as a caller would. */
/* Whether a reply's detail, `len` bytes and not terminated, holds `what`. */
static int says(const uint8_t *detail, size_t len, const char *what)
{
	size_t n = strlen(what), i;

	for (i = 0; i + n <= len; i++)
		if (memcmp(detail + i, what, n) == 0)
			return 1;
	return 0;
}

/* A shelf's local hook that answers any `text` subject. sec 424. */
static size_t text_local_stub(void *ctx, fzn_origin_t origin, const fzn_request_t *request,
                              char *reply, size_t reply_cap)
{
	size_t len = 0;

	(void)ctx;
	(void)origin;
	if (!request->arg || request->arg_len < 4u || memcmp(request->arg, "text", 4u) != 0
	    || fzn_reply_compose((uint8_t *)reply, reply_cap, &len, FZN_REPLY_OK,
	                         (const uint8_t *)"stub", 4u) != FZN_COMPOSE_OK)
		return 0;
	return len;
}

/* A server of members over a peer table, answering in pages of `cap` bytes;
 * `forge` names a key whose hop has a byte flipped on the way. sec 445. */
struct members_peer {
	const fzn_node_config_t *config;
	const fzn_node_peer_t *peers;
	size_t count;
	size_t cap;
	const uint8_t *forge; /* the key whose hop is altered, or NULL */
	const uint8_t *rename_from, *rename_to; /* a key relabelled, its chain kept */
	unsigned asked;
};

static int members_ask(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
                       size_t reply_cap, size_t *reply_len)
{
	struct members_peer *mp = (struct members_peer *)ctx;

	mp->asked++;
	*reply_len = fzn_node_members_answer(mp->config, mp->peers, mp->count, request, request_len,
	                                     reply, mp->cap < reply_cap ? mp->cap : reply_cap);
	if (mp->forge) {
		size_t at = FZN_NODE_MEMBERS_HEAD_LEN;

		while (at + FZN_PUBKEY_LEN + 1u <= *reply_len) {
			size_t hops = reply[at + FZN_PUBKEY_LEN];

			if (memcmp(reply + at, mp->forge, FZN_PUBKEY_LEN) == 0)
				reply[at + FZN_PUBKEY_LEN + 1u + 90u] ^= 0x01u;
			at += FZN_PUBKEY_LEN + 1u + (hops * FZN_HOP_LEN);
		}
	}
	if (mp->rename_from) {
		size_t at = FZN_NODE_MEMBERS_HEAD_LEN;

		while (at + FZN_PUBKEY_LEN + 1u <= *reply_len) {
			size_t hops = reply[at + FZN_PUBKEY_LEN];

			if (memcmp(reply + at, mp->rename_from, FZN_PUBKEY_LEN) == 0)
				memcpy(reply + at, mp->rename_to, FZN_PUBKEY_LEN);
			at += FZN_PUBKEY_LEN + 1u + (hops * FZN_HOP_LEN);
		}
	}
	return *reply_len > 0u;
}

static int listed(uint8_t (*keys)[FZN_PUBKEY_LEN], size_t n, const uint8_t *key)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (memcmp(keys[i], key, FZN_PUBKEY_LEN) == 0)
			return 1;
	return 0;
}

/* A contact's text hook that records who asked and answers two bytes.
 * sec 438. */
static const uint8_t *text_shared_sender;

static size_t text_shared_stub(void *ctx, const uint8_t *sender, const uint8_t *request,
                               size_t request_len, uint8_t *reply, size_t reply_cap)
{
	(void)ctx;
	(void)request;
	(void)request_len;
	text_shared_sender = sender;
	if (reply_cap < 2u)
		return 0;
	reply[0] = 1u;
	reply[1] = 2u;
	return 2u;
}

/* A notes hook that records whether it was asked as a contact, and answers
 * a reply so the admin takes it. sec 436. */
static int notes_shared_seen = -1;

static size_t notes_remote_stub(void *ctx, const uint8_t *sender, int shared,
                                const uint8_t *request, size_t request_len, uint8_t *reply,
                                size_t reply_cap)
{
	(void)ctx;
	(void)sender;
	(void)request;
	(void)request_len;
	notes_shared_seen = shared;
	if (reply_cap < 2u)
		return 0;
	reply[0] = 2u;
	reply[1] = 9u;
	return 2u;
}

static int ask(fzn_node_admin_t *admin, const fzn_peer_t *who, const char *line,
               uint8_t *reply, size_t cap, size_t *reply_len)
{
	int sv[2];
	int ok;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		return 0;
	ok = write(sv[0], line, strlen(line)) == (ssize_t)strlen(line)
	     && write(sv[0], "\n", 1) == 1;
	if (ok)
		(void)fzn_node_serve_local(&admin->state->config, sv[1], who,
		                           fzn_node_admin_handle, admin);
	ok = ok && fzn_client_recv(sv[0], reply, cap, reply_len, 2000u) == FZN_CLIENT_OK;
	close(sv[0]);
	close(sv[1]);
	return ok;
}

int main(void)
{
	static struct node node, device;
	static fzn_node_peer_t peers[32];
	static uint8_t reply[FZN_REPLY_MAX + 1u];
	static char line[FZN_REQUEST_MAX];
	fzn_node_state_t state;
	fzn_node_admin_t admin;
	fzn_peer_t owner, member;
	fzn_node_pairing_t pairing;
	uint8_t card[FZN_PROVISION_MAX_LEN];
	char prekey_hex[(FZN_PREKEY_LEN_TOTAL * 2u) + 1u];
	const uint8_t *detail = NULL;
	size_t reply_len = 0, detail_len = 0, card_len = 0;

	fzn_hash_monocypher_init(&hash_ops);
	fzn_agree_monocypher_init(&agree_ops);
	fzn_random_system_init(&rng_ops);
	CHECK(node_up(&node) && node_up(&device), "fixture: the nodes would not come up");

	memset(&state, 0, sizeof(state));
	state.config.uid = 1000u;
	state.config.local_origins = FZN_ORIGIN_BIT(FZN_ORIGIN_SAME_USER)
	                             | FZN_ORIGIN_BIT(FZN_ORIGIN_LOCAL);
	state.config.has_service_gid = 1;
	state.config.service_gid = 77u;
	state.config.serves_remote = 1;
	memcpy(state.config.root, node.id.pubkey, FZN_PUBKEY_LEN);
	CHECK(fzn_service_capability(7u, 3u, NULL, 0, &hash_ops, &state.config.remote_capability)
	              == FZN_CHAIN_OK,
	      "fixture: capability");
	state.clock = fixed_clock;

	memset(&admin, 0, sizeof(admin));
	admin.state = &state;
	admin.peers = peers;
	admin.peers_cap = 32;
	admin.id = &node.id;
	admin.store = &node.ops;
	admin.card_lifetime = 86400u;
	{
		static fzn_revocation_t revoked_entries[8];
		static fzn_revocation_store_t revoked;

		static fzn_revocation_admin_t admins[8];
		static fzn_revocation_confirm_t confirms[8];

		/* THE ADMIN CAPABILITY AND ITS TABLES, sec 416, at quorum 1 so
		 * nothing else here changes. */
		CHECK(fzn_revocation_store_init(&revoked, revoked_entries, 8) == FZN_CHAIN_OK
		              && fzn_service_capability(7u, 3u, (const uint8_t *)FZN_NODE_ADMIN_NAME,
		                                        sizeof(FZN_NODE_ADMIN_NAME) - 1u, &hash_ops,
		                                        &state.config.admin_capability) == FZN_CHAIN_OK
		              && fzn_revocation_store_set_quorum(&revoked, 1u,
		                                                 &state.config.admin_capability,
		                                                 admins, 8u) == FZN_CHAIN_OK
		              && fzn_revocation_store_set_confirmations(&revoked, confirms, 8u,
		                                                        &hash_ops) == FZN_CHAIN_OK,
		      "fixture: revocation store");
		state.config.has_admin = 1;
		admin.revocations = &revoked;
		state.config.revocations = &revoked;
	}
	/* THE ESTATE'S ROOTS, this node the genesis root: its root acts are
	 * logged. sec 409. */
	static fzn_node_roots_t roots;

	CHECK(fzn_node_roots_init(&roots, node.id.pubkey, &node.sign, &hash_ops)
	              == FZN_NODE_ROOTS_OK
	              && fzn_node_roots_attach(&roots, admin.revocations) == FZN_NODE_ROOTS_OK,
	      "fixture: the roots");
	admin.roots = &roots;

	memset(&owner, 0, sizeof(owner));
	owner.pid = 1;
	owner.uid = 1000u;
	owner.primary_gid = 1000u;
	owner.groups_known = 1;
	member = owner;
	member.uid = 2000u;
	member.primary_gid = 2000u;
	member.groups[0] = 77u;
	member.group_count = 1;

	hex(device.id.prekey_record, FZN_PREKEY_LEN_TOTAL, prekey_hex);

	/* ---- A GROUP MEMBER MAY NOT CHANGE THE NODE. The count starts after
	 * the node's own identity was saved. */
	node.store.saves = 0;
	snprintf(line, sizeof(line), "add peer %s", prekey_hex);
	CHECK(ask(&admin, &member, line, reply, sizeof(reply), &reply_len)
	              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_DENIED,
	      "a service-group member was allowed to pair a device into the node");
	CHECK(node.store.saves == 0u && state.peer_count == 0u,
	      "a refused pairing changed the store or the running peer set");

	/* ---- THE NODE'S OWN USER PAIRS A DEVICE INTO THE RUNNING NODE. */
	CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
	              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK,
	      "the node's own user could not pair a device over the local socket");
	CHECK(reply_len > 512u,
	      "the pairing reply fit the old bound, so this does not show the new one is real");
	CHECK(state.peer_count == 1u && state.peers == peers
	              && memcmp(state.peers[0].sender, device.id.pubkey, FZN_PUBKEY_LEN) == 0,
	      "after pairing, the RUNNING node's peer set does not hold the device");

	/* ---- AND THE CARD IN THE REPLY IS ONE THE DEVICE ACCEPTS. */
	{
		char text[FZN_PROVISION_TEXT_MAX_LEN];

		CHECK(detail_len == FZN_PROVISION_TEXT_PREFIX_LEN
		                            + FZN_PROVISION_TEXT_BODY_LEN(FZN_PROVISION_LEN(1, 0)),
		      "the reply's detail is not a one-hop card");
		memcpy(text, detail, detail_len);
		text[detail_len] = '\0';
		CHECK(fzn_provision_from_text(text, card, sizeof(card), &card_len)
		              == FZN_PROVISION_OK
		              && fzn_node_pairing_accept(&device.id, card, card_len, 2100u,
		                                         &device.ops, &pairing)
		                         == FZN_NODE_PAIR_OK,
		      "the device would not accept the card the running node answered with");
		/* GUARDED ON THE COUNT, so a running set that never learned of the
		 * device fails the check above by name instead of crashing here and
		 * taking the buffered FAIL line with it -- which is how the reload
		 * sabotage was first "caught". */
		CHECK(state.peer_count == 1u
		              && memcmp(pairing.send_key, state.peers[0].recv_key, FZN_AEAD_KEY_LEN)
		                         == 0,
		      "the device's send key is not the running node's receive key for it");
		fzn_wipe(&pairing, sizeof(pairing));
	}

	/* ---- LISTED, BY ANYONE THE NODE SERVES: listing changes nothing. */
	{
		char want[160];
		char key[(FZN_PUBKEY_LEN * 2u) + 1u];

		hex(device.id.pubkey, FZN_PUBKEY_LEN, key);
		snprintf(want, sizeof(want), "ok 1 0 %s\n", key);
		CHECK(ask(&admin, &member, "list peer", reply, sizeof(reply), &reply_len)
		              && reply_len == strlen(want) - 1u
		              && memcmp(reply, want, reply_len) == 0,
		      "list peer did not answer the total, the offset and the one paired key");
	}

	/* ---- UN-PAIRED: A GROUP MEMBER MAY NOT, THE OWNER MAY, AND IT TAKES. */
	{
		char key[(FZN_PUBKEY_LEN * 2u) + 1u];

		hex(device.id.pubkey, FZN_PUBKEY_LEN, key);
		snprintf(line, sizeof(line), "remove peer %s", key);
		CHECK(ask(&admin, &member, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_DENIED
		              && state.peer_count == 1u,
		      "a service-group member un-paired a device");
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK,
		      "the node's own user could not un-pair a device");
		CHECK(state.peer_count == 0u,
		      "the un-paired device is still in the RUNNING node's peer set");
		{
			fzn_node_peer_t back[2];
			size_t n = 9;

			CHECK(fzn_node_peers_load(&node.ops, back, 2, &n) == FZN_PERSIST_OK && n == 0u,
			      "the un-paired device is still in the store, so a restart serves it");
		}
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_ERROR,
		      "un-pairing a device that is not paired was answered as if it were");
	}

	/* ---- A STORE THAT CANNOT FORGET SAYS SO, AND NOTHING CHANGES. */
	{
		char key[(FZN_PUBKEY_LEN * 2u) + 1u];

		snprintf(line, sizeof(line), "add peer %s", prekey_hex);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && state.peer_count == 1u,
		      "fixture: re-pairing the device failed");
		node.ops.remove = NULL;
		hex(device.id.pubkey, FZN_PUBKEY_LEN, key);
		snprintf(line, sizeof(line), "remove peer %s", key);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_ERROR
		              && state.peer_count == 1u,
		      "a store with no remove un-paired a device, or the refusal changed the set");
		node.ops.remove = mem_remove;
	}

	/* ---- PAGED, NOT CUT SHORT. Seventeen devices do not fit one line, so the
	 * pages are walked and every key must turn up exactly once, and the
	 * total must be stated on every page. */
	{
		static struct node more[16];
		size_t from = 0, got = 0, i, pages = 0;
		int ok = 1, every_key = 1;

		for (i = 0; i < 16u && ok; i++) {
			char h[(FZN_PREKEY_LEN_TOTAL * 2u) + 1u];

			ok = node_up(&more[i]);
			hex(more[i].id.prekey_record, FZN_PREKEY_LEN_TOTAL, h);
			snprintf(line, sizeof(line), "add peer %s", h);
			ok = ok && ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			     && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK;
		}
		CHECK(ok && state.peer_count == 17u, "fixture: seventeen devices would not pair");

		{
			int seen[17] = { 0 };

			while (ok && from < 17u && pages < 17u) {
				unsigned long total = 0, off = 0;
				char head[32];
				size_t head_len, at, on_page = 0;
				int consumed = 0;

				snprintf(line, sizeof(line), "list peer %zu", from);
				ok = ask(&admin, &member, line, reply, sizeof(reply), &reply_len)
				     && fzn_reply_of(reply, reply_len, &detail, &detail_len)
				                == FZN_REPLY_OK;
				if (!ok)
					break;
				head_len = detail_len < sizeof(head) - 1u ? detail_len
				                                          : sizeof(head) - 1u;
				memcpy(head, detail, head_len);
				head[head_len] = '\0';
				ok = sscanf(head, "%lu %lu%n", &total, &off, &consumed) == 2
				     && total == 17u && off == from;
				for (at = (size_t)consumed; ok && at + 65u <= detail_len; at += 65u) {
					size_t k;
					int matched = 0;

					for (k = 0; k < state.peer_count && k < 17u; k++) {
						char key[(FZN_PUBKEY_LEN * 2u) + 1u];

						hex(state.peers[k].sender, FZN_PUBKEY_LEN, key);
						if (detail[at] == ' '
						    && memcmp(detail + at + 1u, key, 64u) == 0) {
							/* A key listed twice is as wrong as
							 * one missed. */
							every_key = every_key && !seen[k];
							seen[k] = 1;
							matched = 1;
							break;
						}
					}
					every_key = every_key && matched;
					on_page++;
				}
				ok = ok && on_page > 0u;
				got += on_page;
				from += on_page;
				pages++;
			}
			for (i = 0; i < 17u; i++)
				every_key = every_key && seen[i];
		}
		CHECK(ok, "list peer did not state the total and the offset on every page");
		CHECK(ask(&admin, &member, "list peer 20", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_MALFORMED,
		      "an offset past the last peer was answered as an empty page");
		CHECK(got == 17u && every_key && pages >= 2u,
		      "walking list peer's pages did not return all seventeen keys exactly, "
		      "or fitted them on one page");
	}

	/* ---- REVOKED OVER THE SOCKET: by the owner only, and saying so when it
	 * already was. sec 380. */
	{
		char key[(FZN_PUBKEY_LEN * 2u) + 1u];
		char want[(FZN_PUBKEY_LEN * 2u) + 16u];

		hex(device.id.pubkey, FZN_PUBKEY_LEN, key);
		snprintf(line, sizeof(line), "revoke peer %s", key);
		CHECK(ask(&admin, &member, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_DENIED,
		      "a service-group member revoked a grant");
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && detail_len == 64u && memcmp(detail, key, 64u) == 0,
		      "the node's own user could not revoke a grant, or the answer did not name it");
		CHECK(roots.log.used == 1u, "the root's revocation was not logged");
		snprintf(want, sizeof(want), "%s already", key);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && detail_len == strlen(want) && memcmp(detail, want, detail_len) == 0,
		      "revoking again was not answered as already revoked");

		/* ---- AND UNDONE: by the owner only, once, and revocable again
		 * afterwards -- the re-revocation superseding the one undone. sec 386. */
		snprintf(line, sizeof(line), "remove revocation %s", key);
		CHECK(ask(&admin, &member, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_DENIED,
		      "a service-group member undid a revocation");
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && detail_len == 64u && memcmp(detail, key, 64u) == 0,
		      "the node's own user could not undo a revocation, or the answer did not name it");
		CHECK(roots.log.used == 2u, "the root's withdrawal was not logged");
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_ERROR,
		      "undoing a revocation already undone was answered ok");
		snprintf(line, sizeof(line), "revoke peer %s", key);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && detail_len == 64u,
		      "a grantee whose revocation was undone could not be revoked again");

		/* ---- AND SERVED AS A VOTE: `get vote` is not mutating, so a
		 * group member may read it, and it answers the one record this
		 * root holds as one item with no chain. sec 399. */
		CHECK(ask(&admin, &member, "get vote", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && detail_len == 5u + (FZN_REVOCATION_LEN * 2u)
		              && memcmp(detail, "1 0 r", 5u) == 0,
		      "get vote did not serve the node's one vote as one record item");
		CHECK(ask(&admin, &member, "get vote 2", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_MALFORMED,
		      "an offset past the last vote was answered as an empty page");

		/* ADD AND REMOVE A ROOT: the owner may, a group member may not, and
		 * a cut that is not an id is refused. sec 409. */
		snprintf(line, sizeof(line), "add root %s", key);
		CHECK(ask(&admin, &member, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_DENIED,
		      "a service-group member added a root");
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && fzn_root_view_stands(&roots.view, device.id.pubkey),
		      "the node's own user could not add a root");
		snprintf(line, sizeof(line), "remove root %s zz", key);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_MALFORMED,
		      "a removal naming a cut that is not an id was taken");
		snprintf(line, sizeof(line), "remove root %s", key);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && !fzn_root_view_stands(&roots.view, device.id.pubkey),
		      "the node's own user could not remove a root");

		/* AND ROOT RECORDS, served whole: five log entries -- the
		 * revocation, its withdrawal, the re-revocation, and the two root
		 * changes -- and the two changes themselves. sec 408. */
		CHECK(ask(&admin, &member, "get root", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && detail_len > 3u && memcmp(detail, "7 0 ", 4u) == 0,
		      "get root did not serve the seven root records this node holds");
	}

	/* ---- THROUGH A ROOT KEY THE CARD WILL NOT FIT A REPLY, and add peer
	 * says so before pairing anything. sec 411. Staged by hand: the node is
	 * made a member of another estate that holds a standing root key --
	 * its own identity, the one key this set already stands. */
	{
		uint8_t pinned[FZN_PUBKEY_LEN];
		unsigned saves;

		memcpy(pinned, state.config.root, FZN_PUBKEY_LEN);
		memcpy(state.config.root, device.id.pubkey, FZN_PUBKEY_LEN);
		memcpy(roots.key, node.id.pubkey, FZN_PUBKEY_LEN);
		roots.key_held = 1;
		saves = node.store.saves;
		snprintf(line, sizeof(line), "add peer %s", prekey_hex);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_ERROR
		              && says(detail, detail_len, "fuzznetd --pair")
		              && node.store.saves == saves,
		      "add peer through a root key was not refused before pairing");
		roots.key_held = 0;
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_ERROR
		              && !says(detail, detail_len, "fuzznetd --pair"),
		      "the control: a node holding no root key was sent to fuzznetd --pair");
		memcpy(state.config.root, pinned, FZN_PUBKEY_LEN);
	}

	/* ---- ADMINS, sec 416: a group member may not grant; the owner grants
	 * the device admin as this root, one hop, and confirms it, both logged;
	 * a hop of another capability is not a grant of admin. */
	{
		uint8_t hop[FZN_HOP_LEN];
		char key[(FZN_PUBKEY_LEN * 2u) + 1u], hop_hex[(FZN_HOP_LEN * 2u) + 1u];
		size_t logged = roots.log.used, k;

		for (k = 0; k < FZN_PUBKEY_LEN; k++)
			snprintf(key + (2u * k), 3u, "%02x", device.id.pubkey[k]);
		snprintf(line, sizeof(line), "grant admin %s", key);
		CHECK(ask(&admin, &member, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_DENIED,
		      "a service-group member granted admin");
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && detail_len == 1u + (FZN_HOP_LEN * 2u) && detail[0] == 'h'
		              && roots.log.used == logged + 1u,
		      "the owner's grant of admin was not one hop, or not logged");
		memcpy(hop_hex, detail + 1u, FZN_HOP_LEN * 2u);
		hop_hex[FZN_HOP_LEN * 2u] = '\0';
		snprintf(line, sizeof(line), "add confirm %s", hop_hex);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && admin.revocations->confirms_used == 1u
		              && roots.log.used == logged + 2u,
		      "the root's confirmation was not admitted, or not logged");
		CHECK(fzn_chain_mint(node.id.pubkey, device.id.pubkey,
		                     &state.config.remote_capability, 1000u, FZN_NO_EXPIRY, 0,
		                     &node.sign, hop) == FZN_CHAIN_OK,
		      "fixture: a hop of the remote capability");
		for (k = 0; k < FZN_HOP_LEN; k++)
			snprintf(hop_hex + (2u * k), 3u, "%02x", hop[k]);
		snprintf(line, sizeof(line), "add confirm %s", hop_hex);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_ERROR
		              && admin.revocations->confirms_used == 1u,
		      "a hop of another capability was confirmed as a grant of admin");
		CHECK(ask(&admin, &owner, "add confirm zz", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_MALFORMED,
		      "a confirmation of no hop was not answered malformed");
		/* THE ROOT VOTES AS THE ROOT even holding an admin chain: its
		 * revocation carries no chain, so no admin row is made. */
		{
			static fzn_node_admin_chain_t own;
			uint8_t chain[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
			size_t n = 0;

			CHECK(fzn_node_admin_grant(&roots, &node.ops, &node.id, NULL,
			                           &state.config.admin_capability, node.id.pubkey,
			                           1000u, chain, &n) == FZN_NODE_REVOKE_OK
			              && fzn_node_admin_chain_set(&node.ops, admin.revocations, &node.id,
			                                          node.id.pubkey,
			                                          &state.config.admin_capability,
			                                          (const uint8_t (*)[FZN_HOP_LEN])chain,
			                                          n, 1000u, &own) == FZN_NODE_REVOKE_OK,
			      "fixture: the root holding an admin chain of its own");
			admin.admin_chain = &own;
			for (k = 0; k < FZN_PUBKEY_LEN; k++)
				snprintf(key + (2u * k), 3u, "%02x", (unsigned)(0x60u + k));
			snprintf(line, sizeof(line), "revoke peer %s", key);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_OK
			              && admin.revocations->admins_used == 0u,
			      "the root voted on its admin chain rather than as the root");
			admin.admin_chain = NULL;
		}
	}

	/* ---- CONTACTS, sec 435: a key outside the estate, by a name. */
	{
		char key_hex[(FZN_PUBKEY_LEN * 2u) + 1u], own_hex[(FZN_PUBKEY_LEN * 2u) + 1u];
		size_t k;

		for (k = 0; k < FZN_PUBKEY_LEN; k++) {
			snprintf(key_hex + (2u * k), 3u, "%02x", (unsigned)(0x40u + k));
			snprintf(own_hex + (2u * k), 3u, "%02x", node.id.pubkey[k]);
		}
		snprintf(line, sizeof(line), "add contact alice %s", key_hex);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK,
		      "a contact was not added");
		CHECK(ask(&admin, &owner, "list contact", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && says(detail, detail_len, "1 0 alice,")
		              && says(detail, detail_len, key_hex),
		      "the contact was not listed by name and key");
		snprintf(line, sizeof(line), "add contact me %s", own_hex);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_ERROR,
		      "this node's own key was taken as a contact: a member is never one");
		/* ANOTHER ROOT OF THE ESTATE is a member too, not only the one this
		 * node joined through. */
		{
			static fzn_node_roots_t with_second;
			uint8_t add[FZN_ROOT_ADD_LEN], second[FZN_PUBKEY_LEN];
			char second_hex[(FZN_PUBKEY_LEN * 2u) + 1u];
			struct fzn_node_roots *was = admin.roots;

			memset(second, 0x5e, sizeof(second));
			hex(second, FZN_PUBKEY_LEN, second_hex);
			CHECK(fzn_node_roots_init(&with_second, node.id.pubkey, &node.sign, &hash_ops)
			                      == FZN_NODE_ROOTS_OK
			              && fzn_root_add_issue(node.id.pubkey, second, &node.sign, add)
			                         == FZN_ROOT_LOG_OK
			              && fzn_node_roots_learn(&with_second, &node.ops, add, sizeof(add))
			                         == FZN_NODE_ROOTS_OK,
			      "fixture: an estate with a second root");
			admin.roots = &with_second;
			snprintf(line, sizeof(line), "add contact second %s", second_hex);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_ERROR,
			      "a second root of the estate was taken as a contact");
			admin.roots = was;
		}
		snprintf(line, sizeof(line), "add contact al-ice %s", key_hex);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_MALFORMED,
		      "a name outside [A-Za-z0-9_] was not malformed");
		CHECK(ask(&admin, &member, "list contact", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_DENIED,
		      "another user read the contacts");
		CHECK(ask(&admin, &owner, "remove contact alice", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && ask(&admin, &owner, "list contact", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && says(detail, detail_len, "0 0"),
		      "a removed contact was still listed");
	}

	/* ---- SHARES, sec 436: `grant share` pairs a contact's node for the
	 * share capability, from this node's own key; the contact is then a
	 * peer and still no member, and its requests reach only the notes. */
	{
		static struct node outside;
		char key_hex[(FZN_PUBKEY_LEN * 2u) + 1u], dev_hex[(FZN_PUBKEY_LEN * 2u) + 1u];
		char out_prekey[(FZN_PREKEY_LEN_TOTAL * 2u) + 1u];
		const fzn_node_peer_t *granted = NULL;
		size_t before = state.peer_count, i;
		char text[FZN_PROVISION_TEXT_MAX_LEN];
		fzn_opened_t req;
		uint8_t out[256];
		size_t n;
		size_t k;

		for (k = 0; k < FZN_PUBKEY_LEN; k++)
			snprintf(key_hex + (2u * k), 3u, "%02x", (unsigned)(0x40u + k));
		CHECK(node_up(&outside), "fixture: a node outside the estate");
		hex(outside.id.pubkey, FZN_PUBKEY_LEN, dev_hex);
		hex(outside.id.prekey_record, FZN_PREKEY_LEN_TOTAL, out_prekey);
		snprintf(line, sizeof(line), "add contact bob %s", dev_hex);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK,
		      "fixture: the outside node as the contact bob");
		snprintf(line, sizeof(line), "add contact carol %s", key_hex);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK,
		      "fixture: another contact, carol");

		snprintf(line, sizeof(line), "grant share bob %s", out_prekey);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_ERROR
		              && state.peer_count == before,
		      "a node that does not share granted a share");
		CHECK(fzn_service_capability(7u, 3u, (const uint8_t *)"fuzznet.notes.share", 19u,
		                             &hash_ops, &state.config.share_capability)
		              == FZN_CHAIN_OK,
		      "fixture: the share capability");
		memcpy(state.config.share_root, node.id.pubkey, FZN_PUBKEY_LEN);
		state.config.has_share = 1;

		CHECK(ask(&admin, &member, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_DENIED
		              && state.peer_count == before,
		      "a service-group member granted a share");
		snprintf(line, sizeof(line), "grant share carol %s", out_prekey);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_ERROR
		              && state.peer_count == before,
		      "a share was granted to carol through bob's node's prekey");
		CHECK(ask(&admin, &owner, "grant share dave 00", reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
		                         == FZN_REPLY_MALFORMED,
		      "a grant with no prekey record was not malformed");
		snprintf(line, sizeof(line), "grant share dave %s", out_prekey);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_ERROR,
		      "a share was granted to a name that is no contact");

		snprintf(line, sizeof(line), "grant share bob %s", out_prekey);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && state.peer_count == before + 1u,
		      "the owner's grant did not pair bob's node as a contact");
		for (i = 0; i < state.peer_count; i++)
			if (memcmp(state.peers[i].sender, outside.id.pubkey, FZN_PUBKEY_LEN) == 0)
				granted = &state.peers[i];
		CHECK(granted && fzn_node_peer_contact(&state.config, granted),
		      "the granted peer is not a contact");

		memcpy(text, detail, detail_len);
		text[detail_len] = '\0';
		CHECK(fzn_provision_from_text(text, card, sizeof(card), &card_len) == FZN_PROVISION_OK
		              && fzn_node_pairing_accept(&outside.id, card, card_len, 2100u, &outside.ops,
		                                         &pairing)
		                         == FZN_NODE_PAIR_OK
		              && memcmp(pairing.capability.b, state.config.share_capability.b,
		                        FZN_CAP_ID_LEN)
		                         == 0,
		      "bob's node would not accept the card, or it carries another capability");
		fzn_wipe(&pairing, sizeof(pairing));
		{
			char marked[(FZN_PUBKEY_LEN * 2u) + 16u], page[32];

			snprintf(marked, sizeof(marked), "%s,contact", dev_hex);
			snprintf(page, sizeof(page), "list peer %zu",
			         granted ? (size_t)(granted - state.peers) : 0u);
			CHECK(ask(&admin, &owner, page, reply, sizeof(reply), &reply_len)
			              && says(reply, reply_len, marked),
			      "list peer did not mark the contact among the members");
		}
		snprintf(line, sizeof(line), "add contact bobby %s", dev_hex);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK,
		      "a contact holding a share grant was counted a member of the estate");

		/* ITS REQUESTS: the notes hook only, and told it is a contact. */
		memset(&req, 0, sizeof(req));
		req.capability = state.config.share_capability.b;
		req.sender = outside.id.pubkey;
		req.payload = (const uint8_t *)"list peer";
		req.payload_len = 9u;
		n = fzn_node_admin_remote(&admin, FZN_NODE_REMOTE_GRANTED, &req, out, sizeof(out));
		CHECK(n && fzn_reply_of(out, n, &detail, &detail_len) == FZN_REPLY_DENIED,
		      "a contact's verb was answered as a member's");
		/* A TEXT REQUEST reaches the scoped text hook, told who asks. */
		admin.text_shared = text_shared_stub;
		text_shared_sender = NULL;
		n = fzn_node_admin_remote(&admin, FZN_NODE_REMOTE_GRANTED, &req, out, sizeof(out));
		CHECK(n == 2u && text_shared_sender == outside.id.pubkey,
		      "a contact's request did not reach the text hook with its sender");
		admin.text_shared = NULL;
		admin.notes_remote = notes_remote_stub;
		notes_shared_seen = -1;
		n = fzn_node_admin_remote(&admin, FZN_NODE_REMOTE_GRANTED, &req, out, sizeof(out));
		CHECK(n && notes_shared_seen == 1,
		      "a contact's request did not reach the notes hook as shared");
		req.capability = state.config.remote_capability.b;
		notes_shared_seen = -1;
		n = fzn_node_admin_remote(&admin, FZN_NODE_REMOTE_GRANTED, &req, out, sizeof(out));
		CHECK(n && notes_shared_seen == 0,
		      "a member's request reached the notes hook as a contact's");
		admin.notes_remote = NULL;

		snprintf(line, sizeof(line), "remove peer %s", dev_hex);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && state.peer_count == before,
		      "fixture: bob's node un-paired");

		/* ---- RECEIVED, sec 437: the other way round. bob's node shares
		 * with this one; this node takes the card and records where to
		 * pull from. */
		{
			static char card_text[FZN_PROVISION_TEXT_MAX_LEN];
			uint8_t member_card[FZN_PROVISION_MAX_LEN];
			static char member_text[FZN_PROVISION_TEXT_MAX_LEN];
			size_t member_len = 0;
			fzn_prekey_record_t mine;
			fzn_node_pairing_t held;
			fzn_node_received_t row;
			fzn_persist_ops_t tree;
			fzn_notes_received_t seam;
			uint8_t blob[FZN_PERSIST_HEAD_LEN + 1u], claim[FZN_PUBKEY_LEN];
			size_t gone_len = 0;
			char card_path[64], member_path[64], junk_path[64];
			FILE *f;

			CHECK(fzn_prekey_open(node.id.prekey_record, FZN_PREKEY_LEN_TOTAL, &mine)
			                      == FZN_PREKEY_OK
			              && fzn_node_pair(&outside.id, outside.id.pubkey,
			                               &state.config.share_capability, NULL, 0,
			                               &outside.ops, mine, 2000u, 2000u + 86400u, card,
			                               sizeof(card), &card_len)
			                         == FZN_NODE_PAIR_OK
			              && fzn_provision_text(card, card_len, card_text, sizeof(card_text))
			                         == FZN_PROVISION_OK,
			      "fixture: bob's node grants this one a share");
			CHECK(fzn_node_pair(&outside.id, outside.id.pubkey,
			                    &state.config.remote_capability, NULL, 0, &outside.ops, mine,
			                    2000u, 2000u + 86400u, member_card, sizeof(member_card),
			                    &member_len)
			                      == FZN_NODE_PAIR_OK
			              && fzn_provision_text(member_card, member_len, member_text,
			                                    sizeof(member_text))
			                         == FZN_PROVISION_OK,
			      "fixture: and a card for another capability");
			/* THE CARDS AS FILES: a card's text is past one request line. */
			snprintf(card_path, sizeof(card_path), "/tmp/fzn-admin-card-%d", (int)getpid());
			snprintf(member_path, sizeof(member_path), "/tmp/fzn-admin-member-%d",
			         (int)getpid());
			snprintf(junk_path, sizeof(junk_path), "/tmp/fzn-admin-junk-%d", (int)getpid());
			CHECK((f = fopen(card_path, "w")) && fprintf(f, "%s\n", card_text) > 0
			              && fclose(f) == 0
			              && (f = fopen(member_path, "w")) && fputs(member_text, f) >= 0
			              && fclose(f) == 0
			              && (f = fopen(junk_path, "w")) && fputs("notacard", f) >= 0
			              && fclose(f) == 0,
			      "fixture: the cards written to files");

			state.config.has_share = 0;
			snprintf(line, sizeof(line), "add received bobby 127.0.0.1 7000 %s", card_path);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_ERROR,
			      "a node keeping no notes took a share");
			state.config.has_share = 1;
			CHECK(ask(&admin, &member, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_DENIED,
			      "a service-group member took a share");
			snprintf(line, sizeof(line), "add received carol 127.0.0.1 7000 %s", card_path);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_ERROR,
			      "bob's card was taken as carol's share");
			snprintf(line, sizeof(line), "add received bobby 127.0.0.1 7000 %s", member_path);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_ERROR,
			      "a card for another capability was taken as a share");
			snprintf(line, sizeof(line), "add received bobby 127.0.0.1 0 %s", card_path);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_MALFORMED,
			      "port 0 was taken");
			snprintf(line, sizeof(line), "add received bobby 127.0.0.1 7000 %s", junk_path);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_MALFORMED,
			      "a word that is no card was taken");
			CHECK(fzn_node_pairing_load(&node.ops, outside.id.pubkey, &held) != FZN_PERSIST_OK,
			      "a refused card left a pairing behind");
			CHECK(ask(&admin, &owner, "add received bobby 127.0.0.1 7000 /nonexistent/card",
			          reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_ERROR,
			      "a card file that cannot be read was not refused");

			admin.received_fresh = 0;
			snprintf(line, sizeof(line), "add received bobby 127.0.0.1 7000 %s", card_path);
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_OK
			              && admin.received_fresh,
			      "the owner could not take bob's share, or the daemon was not told");
			CHECK(fzn_node_pairing_load(&node.ops, outside.id.pubkey, &held) == FZN_PERSIST_OK
			              && memcmp(held.capability.b, state.config.share_capability.b,
			                        FZN_CAP_ID_LEN)
			                         == 0,
			      "the share's pairing was not kept, or is for another capability");
			fzn_wipe(&held, sizeof(held));
			CHECK(fzn_node_received_get(&node.ops, outside.id.pubkey, &row)
			                      == FZN_NODE_RECEIVED_OK
			              && row.port == 7000u && row.host_len == 9u
			              && memcmp(row.host, "127.0.0.1", 9u) == 0,
			      "the share's address was not recorded");
			CHECK(ask(&admin, &member, "list received", reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_DENIED,
			      "another user read the received shares");
			CHECK(ask(&admin, &owner, "list received", reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_OK
			              && says(detail, detail_len, "1 bobby,127.0.0.1,7000"),
			      "list received did not name the share by contact, host and port");

			/* A ROW OF bob's TREE, so forgetting can be seen to take it. */
			memset(claim, 0x3c, sizeof(claim));
			CHECK(fzn_notes_received_ops(&seam, &node.ops, &hash_ops, outside.id.pubkey, &tree)
			                      == FZN_NOTES_OK
			              && fzn_persist_head_write(blob, sizeof(blob), 1u,
			                                        FZN_PERSIST_BLOB_NOTE)
			                         == FZN_PERSIST_OK
			              && tree.save(tree.ctx, FZN_PERSIST_NOTE, claim, blob, sizeof(blob)),
			      "fixture: a note in bob's tree");
			admin.received_fresh = 0;
			CHECK(ask(&admin, &owner, "remove received bobby", reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_OK
			              && admin.received_fresh,
			      "the owner could not stop bob's share, or the daemon was not told");
			CHECK(!tree.load(tree.ctx, FZN_PERSIST_NOTE, claim, blob, sizeof(blob), &gone_len),
			      "what was pulled from bob stayed after the share was removed");
			CHECK(ask(&admin, &owner, "list received", reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_OK
			              && detail_len == 1u && detail[0] == '0',
			      "a removed share was still listed");
			CHECK(ask(&admin, &owner, "remove received bobby", reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_ERROR,
			      "removing it again was answered as if it were there");

			(void)unlink(card_path);
			(void)unlink(member_path);
			(void)unlink(junk_path);

			/* THE TABLE'S OWN RULES. */
			CHECK(!fzn_node_received_host_ok("a b", 3u) && !fzn_node_received_host_ok("", 0u)
			              && fzn_node_received_host_ok("example.org", 11u),
			      "a host with a space, or none, was taken; or a plain one refused");
			{
				uint8_t rk[FZN_PUBKEY_LEN];
				unsigned ri;

				for (ri = 0; ri < FZN_NODE_RECEIVED_MAX; ri++) {
					memset(rk, (int)(0x70u + ri), sizeof(rk));
					CHECK(fzn_node_received_add(&node.ops, rk, "h", 1u, 1u, 0u)
					              == FZN_NODE_RECEIVED_OK,
					      "fixture: a share up to the bound");
				}
				memset(rk, 0x7f, sizeof(rk));
				CHECK(fzn_node_received_add(&node.ops, rk, "h", 1u, 1u, 0u)
				              == FZN_NODE_RECEIVED_ERR_FULL,
				      "a share past the bound was taken");
				memset(rk, 0x70, sizeof(rk));
				CHECK(fzn_node_received_add(&node.ops, rk, "other", 5u, 2u, 0u)
				                      == FZN_NODE_RECEIVED_OK
				              && fzn_node_received_get(&node.ops, rk, &row)
				                         == FZN_NODE_RECEIVED_OK
				              && row.port == 2u,
				      "at the bound, a held share's address could not change");
				for (ri = 0; ri < FZN_NODE_RECEIVED_MAX; ri++) {
					memset(rk, (int)(0x70u + ri), sizeof(rk));
					(void)fzn_node_received_remove(&node.ops, rk);
				}
			}
		}
		state.config.has_share = 0;
		fzn_sign_monocypher_wipe(&outside.signer);
	}

	/* ---- TEXTS GO TO THE SHELF'S HOOK, sec 424, and what it does not take
	 * falls through to the verbs' own refusal. */
	admin.text_local = text_local_stub;
	CHECK(ask(&admin, &owner, "get text x", reply, sizeof(reply), &reply_len)
	              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
	              && says(detail, detail_len, "stub"),
	      "get text did not reach the shelf's hook");
	CHECK(ask(&admin, &owner, "get nothing", reply, sizeof(reply), &reply_len)
	              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
	                         == FZN_REPLY_UNSUPPORTED,
	      "what the shelf's hook does not take was not unsupported");
	admin.text_local = NULL;
	CHECK(ask(&admin, &owner, "get text x", reply, sizeof(reply), &reply_len)
	              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
	                         == FZN_REPLY_UNSUPPORTED,
	      "with no shelf, get text was not unsupported");

	/* ---- AS A ROOT BY IDENTITY, sec 419: the node is made a member of an
	 * estate whose genesis is the device's key and which has added the
	 * node's identity as a root; `add peer` then pairs with one hop and
	 * that add, a card that fits the reply. */
	{
		static fzn_node_roots_t other;
		uint8_t pinned[FZN_PUBKEY_LEN], add[FZN_ROOT_ADD_LEN];
		struct fzn_node_roots *was = admin.roots;

		memcpy(pinned, state.config.root, FZN_PUBKEY_LEN);
		CHECK(fzn_node_roots_init(&other, device.id.pubkey, &node.sign, &hash_ops)
		              == FZN_NODE_ROOTS_OK
		              && fzn_root_add_issue(device.id.pubkey, node.id.pubkey, &device.sign, add)
		                         == FZN_ROOT_LOG_OK
		              && fzn_node_roots_learn(&other, &node.ops, add, sizeof(add))
		                         == FZN_NODE_ROOTS_OK,
		      "fixture: an estate rooted at the device that added this node");
		memcpy(state.config.root, device.id.pubkey, FZN_PUBKEY_LEN);
		admin.roots = &other;
		snprintf(line, sizeof(line), "add peer %s", prekey_hex);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
		              && detail_len == FZN_PROVISION_TEXT_PREFIX_LEN
		                                       + FZN_PROVISION_TEXT_BODY_LEN(
		                                               FZN_PROVISION_LEN(1, 1)),
		      "a root by identity did not pair with one hop and its add");

		/* TWO ADDS AWAY, the card would not fit: refused, not cut short. */
		{
			static fzn_node_roots_t deep;
			static struct node middle;
			uint8_t first[FZN_ROOT_ADD_LEN], second[FZN_ROOT_ADD_LEN];

			CHECK(node_up(&middle)
			              && fzn_node_roots_init(&deep, device.id.pubkey, &node.sign,
			                                     &hash_ops) == FZN_NODE_ROOTS_OK
			              && fzn_root_add_issue(device.id.pubkey, middle.id.pubkey,
			                                    &device.sign, first) == FZN_ROOT_LOG_OK
			              && fzn_root_add_issue(middle.id.pubkey, node.id.pubkey,
			                                    &middle.sign, second) == FZN_ROOT_LOG_OK
			              && fzn_node_roots_learn(&deep, &node.ops, first, sizeof(first))
			                         == FZN_NODE_ROOTS_OK
			              && fzn_node_roots_learn(&deep, &node.ops, second, sizeof(second))
			                         == FZN_NODE_ROOTS_OK,
			      "fixture: an estate that reaches this node in two adds");
			admin.roots = &deep;
			CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
			              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
			                         == FZN_REPLY_ERROR,
			      "a root two adds away paired at the verb with a card past a reply");
		}
		admin.roots = was;
		memcpy(state.config.root, pinned, FZN_PUBKEY_LEN);
	}

	/* ---- THE ESTATE'S k, sec 418: the owner sets it as this root and the
	 * running store takes it; a group member may not; 0 is refused. */
	CHECK(ask(&admin, &member, "set quorum 3", reply, sizeof(reply), &reply_len)
	              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_DENIED,
	      "a service-group member set k");
	CHECK(ask(&admin, &owner, "set quorum 3", reply, sizeof(reply), &reply_len)
	              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK
	              && detail_len == 1u && detail[0] == '3' && admin.revocations->quorum == 3u,
	      "the owner's k of 3 was not answered, or the running store did not take it");
	CHECK(ask(&admin, &owner, "set quorum 0", reply, sizeof(reply), &reply_len)
	              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
	                         == FZN_REPLY_MALFORMED
	              && admin.revocations->quorum == 3u,
	      "a k of 0 was taken");

	/* ---- WHAT IT DOES NOT SERVE, IT SAYS SO. */
	CHECK(ask(&admin, &owner, "get peer", reply, sizeof(reply), &reply_len)
	              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
	                         == FZN_REPLY_UNSUPPORTED,
	      "a verb the node does not serve was not answered unsupported");
	CHECK(ask(&admin, &owner, "add peer 00", reply, sizeof(reply), &reply_len)
	              && fzn_reply_of(reply, reply_len, &detail, &detail_len)
	                         == FZN_REPLY_MALFORMED,
	      "a pairing request with no prekey record in it was not answered malformed");
	CHECK(ask(&admin, &member, "status", reply, sizeof(reply), &reply_len)
	              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK,
	      "status was not answered with the node's own status line");

	/* ---- THE ESTATE'S MEMBERS, sec 445: listed with their chains, admitted
	 * by a puller only on proof against its own root. */
	{
		static struct node m1, m2, m3, m4;
		static fzn_node_peer_t all[64];
		static uint8_t got[64][FZN_PUBKEY_LEN];
		fzn_prekey_record_t r;
		size_t loaded = 0, n = 0, refused = 0, i;
		uint8_t mcard[FZN_PROVISION_MAX_LEN];
		size_t mcard_len = 0;
		char m2_hex[(FZN_PUBKEY_LEN * 2u) + 1u];
		struct members_peer mp;

		CHECK(node_up(&m1) && node_up(&m2) && node_up(&m3) && node_up(&m4),
		      "fixture: four more nodes");
		CHECK(fzn_service_capability(7u, 3u, (const uint8_t *)"fuzznet.notes.share", 19u,
		                             &hash_ops, &state.config.share_capability)
		              == FZN_CHAIN_OK,
		      "fixture: the share capability");
		memcpy(state.config.share_root, node.id.pubkey, FZN_PUBKEY_LEN);
		state.config.has_share = 1;
		CHECK(fzn_prekey_open(m1.id.prekey_record, FZN_PREKEY_LEN_TOTAL, &r) == FZN_PREKEY_OK
		              && fzn_node_pair(&node.id, node.id.pubkey, &state.config.remote_capability,
		                               NULL, 0, &node.ops, r, 2000u, 2000u + 86400u, mcard,
		                               sizeof(mcard), &mcard_len)
		                         == FZN_NODE_PAIR_OK
		              && fzn_prekey_open(m2.id.prekey_record, FZN_PREKEY_LEN_TOTAL, &r)
		                         == FZN_PREKEY_OK
		              && fzn_node_pair(&node.id, node.id.pubkey, &state.config.remote_capability,
		                               NULL, 0, &node.ops, r, 2000u, 2000u + 86400u, mcard,
		                               sizeof(mcard), &mcard_len)
		                         == FZN_NODE_PAIR_OK,
		      "fixture: two members paired by the estate's root");
		CHECK(fzn_prekey_open(m3.id.prekey_record, FZN_PREKEY_LEN_TOTAL, &r) == FZN_PREKEY_OK
		              && fzn_node_pair(&node.id, node.id.pubkey, &state.config.share_capability,
		                               NULL, 0, &node.ops, r, 2000u, 2000u + 86400u, mcard,
		                               sizeof(mcard), &mcard_len)
		                         == FZN_NODE_PAIR_OK,
		      "fixture: a contact paired for a share");
		CHECK(fzn_prekey_open(m4.id.prekey_record, FZN_PREKEY_LEN_TOTAL, &r) == FZN_PREKEY_OK
		              && fzn_node_pair(&m1.id, m1.id.pubkey, &state.config.remote_capability,
		                               NULL, 0, &node.ops, r, 2000u, 2000u + 86400u, mcard,
		                               sizeof(mcard), &mcard_len)
		                         == FZN_NODE_PAIR_OK,
		      "fixture: a peer whose chain starts at another root");
		CHECK(fzn_node_peers_load(&node.ops, all, 64u, &loaded) == FZN_PERSIST_OK,
		      "fixture: the peers loaded");

		mp.config = &state.config;
		mp.peers = all;
		mp.count = loaded;
		mp.cap = 500u;
		mp.forge = NULL;
		mp.rename_from = NULL;
		mp.rename_to = NULL;
		mp.asked = 0;
		CHECK(fzn_node_members_pull(members_ask, &mp, node.id.pubkey,
		                            &state.config.remote_capability, 2100u, &node.sign,
		                            admin.revocations, got, 64u, &n, &refused)
		              == FZN_NODE_MEMBERS_OK,
		      "the members are pulled");
		CHECK(mp.asked > 1u, "a page of two members at most, so more than one was asked");
		CHECK(listed(got, n, m1.id.pubkey) && listed(got, n, m2.id.pubkey),
		      "both members the root paired are admitted");
		CHECK(!listed(got, n, m3.id.pubkey), "a contact paired for a share is not");
		{
			static uint8_t page[16384];
			uint8_t q[FZN_NODE_MEMBERS_QUERY_LEN] = { 2u, FZN_NODE_MEMBERS_QUERY, 0u, 0u };
			size_t len = fzn_node_members_answer(&state.config, all, loaded, q, sizeof(q), page,
			                                     sizeof(page)), at;
			int seen_contact = 0;

			for (at = 0; len && at + FZN_PUBKEY_LEN <= len; at++)
				seen_contact |= memcmp(page + at, m3.id.pubkey, FZN_PUBKEY_LEN) == 0;
			CHECK(len > FZN_NODE_MEMBERS_HEAD_LEN && !seen_contact,
			      "and its key is not even listed: a share is no membership to reveal");
		}
		CHECK(!listed(got, n, m4.id.pubkey) && refused >= 1u,
		      "a peer whose chain starts at another root is refused and counted");

		hex(m2.id.pubkey, FZN_PUBKEY_LEN, m2_hex);
		snprintf(line, sizeof(line), "revoke peer %s", m2_hex);
		CHECK(ask(&admin, &owner, line, reply, sizeof(reply), &reply_len)
		              && fzn_reply_of(reply, reply_len, &detail, &detail_len) == FZN_REPLY_OK,
		      "fixture: the second member's grant revoked");
		CHECK(fzn_node_members_pull(members_ask, &mp, node.id.pubkey,
		                            &state.config.remote_capability, 2100u, &node.sign,
		                            admin.revocations, got, 64u, &n, &refused)
		                      == FZN_NODE_MEMBERS_OK
		              && listed(got, n, m1.id.pubkey) && !listed(got, n, m2.id.pubkey),
		      "a member whose grant is revoked is no longer admitted");

		mp.rename_from = m1.id.pubkey;
		mp.rename_to = m4.id.pubkey;
		CHECK(fzn_node_members_pull(members_ask, &mp, node.id.pubkey,
		                            &state.config.remote_capability, 2100u, &node.sign, NULL, got,
		                            64u, &n, &refused)
		                      == FZN_NODE_MEMBERS_OK
		              && !listed(got, n, m4.id.pubkey),
		      "a key listed with another member's chain is not admitted: the chain names whom");
		mp.rename_from = NULL;
		mp.forge = m1.id.pubkey;
		CHECK(fzn_node_members_pull(members_ask, &mp, node.id.pubkey,
		                            &state.config.remote_capability, 2100u, &node.sign, NULL, got,
		                            64u, &n, &refused)
		                      == FZN_NODE_MEMBERS_OK
		              && !listed(got, n, m1.id.pubkey),
		      "an entry whose hop was altered does not prove");
		mp.forge = NULL;
		for (i = 0; i < loaded; i++)
			fzn_wipe(&all[i], sizeof(all[i]));
		state.config.has_share = 0;
		fzn_sign_monocypher_wipe(&m1.signer);
		fzn_sign_monocypher_wipe(&m2.signer);
		fzn_sign_monocypher_wipe(&m3.signer);
		fzn_sign_monocypher_wipe(&m4.signer);
	}

	fzn_sign_monocypher_wipe(&node.signer);
	fzn_sign_monocypher_wipe(&device.signer);
	printf("admin_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
